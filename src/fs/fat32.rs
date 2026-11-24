//! # Finding a file's sectors on a FAT32 volume (read only)
//!
//! The boot log ([`crate::arch::bootlog`]) is a file the firmware created, at its full size,
//! on the EFI system partition before `ExitBootServices`. After the takeover the kernel
//! writes the log into that file's clusters in place: the file's size and the FAT never
//! change, so the volume stays consistent whatever happens (a crash mid-write leaves only
//! the log text half old, half new). This module finds those clusters: it reads the boot
//! sector, walks the directories named in the path (8.3 names) and follows the file's
//! cluster chain. It never writes.
//!
//! Plain logic over a `read(offset, buf)` callback (offsets from the start of the
//! partition), so the host unit tests run it on a FAT32 image in memory.

use alloc::vec::Vec;

/// One piece of a file: `len` bytes of the file from byte `file_off` lie at byte
/// `part_off` of the partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// Where the piece starts in the file.
    pub file_off: u64,
    /// Where it starts on the partition.
    pub part_off: u64,
    /// Its length in bytes.
    pub len: u64,
}

/// A file found on the volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMap {
    /// The file's size (the directory entry's).
    pub size: u64,
    /// Where its bytes are, in file order, adjacent clusters merged (covering at least
    /// `size` bytes).
    pub extents: Vec<Extent>,
}

impl FileMap {
    /// The partition pieces holding file bytes `off..off + len` (clipped to the file's
    /// size): `(part_off, file_off, len)` each.
    pub fn pieces(&self, off: u64, len: u64) -> Vec<(u64, u64, u64)> {
        let end = (off + len).min(self.size);
        let mut out = Vec::new();
        for e in &self.extents {
            let (a, b) = (off.max(e.file_off), end.min(e.file_off + e.len));
            if a < b {
                out.push((e.part_off + (a - e.file_off), a, b - a));
            }
        }
        out
    }
}

/// The 11-byte directory form of an 8.3 name (`"boot001.txt"` -> `"BOOT001 TXT"`), or
/// `None` if `name` is not a plain 8.3 name.
pub fn short_name(name: &str) -> Option<[u8; 11]> {
    let mut out = [b' '; 11];
    let (base, ext) = match name.rfind('.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }
    let ok = |c: u8| c.is_ascii_alphanumeric() || b"_-~!#$%&'()@^{}".contains(&c);
    for (i, c) in base.bytes().enumerate() {
        if !ok(c) {
            return None;
        }
        out[i] = c.to_ascii_uppercase();
    }
    for (i, c) in ext.bytes().enumerate() {
        if !ok(c) {
            return None;
        }
        out[8 + i] = c.to_ascii_uppercase();
    }
    Some(out)
}

/// The volume's layout from its boot sector.
#[derive(Clone, Copy, Debug)]
struct Volume {
    /// Bytes per sector.
    sector: u64,
    /// Bytes per cluster.
    cluster: u64,
    /// Byte offset of the first FAT.
    fat: u64,
    /// Byte offset of cluster 2.
    data: u64,
    /// Cluster of the root directory.
    root: u32,
    /// Number of data clusters.
    clusters: u32,
}

fn le16(b: &[u8], at: usize) -> u64 {
    u16::from_le_bytes([b[at], b[at + 1]]) as u64
}

fn le32(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as u64
}

/// Reads the boot sector (only FAT32 volumes: what UEFI system partitions of this size
/// are, and what Hydra's tools make).
fn volume(read: &mut dyn FnMut(u64, &mut [u8]) -> bool) -> Result<Volume, &'static str> {
    let mut bs = [0u8; 512];
    if !read(0, &mut bs) {
        return Err("cannot read the boot sector");
    }
    if bs[510] != 0x55 || bs[511] != 0xAA {
        return Err("no FAT boot sector");
    }
    let sector = le16(&bs, 11);
    let per = bs[13] as u64;
    let reserved = le16(&bs, 14);
    let fats = bs[16] as u64;
    let root_entries = le16(&bs, 17);
    let fat16 = le16(&bs, 22);
    let fat32 = le32(&bs, 36);
    let total = match le16(&bs, 19) {
        0 => le32(&bs, 32),
        n => n,
    };
    if !matches!(sector, 512 | 1024 | 2048 | 4096) || per == 0 || !per.is_power_of_two() || fats == 0 || reserved == 0 {
        return Err("a broken FAT boot sector");
    }
    if root_entries != 0 || fat16 != 0 || fat32 == 0 {
        return Err("not FAT32");
    }
    let data_sector = reserved + fats * fat32;
    if total <= data_sector {
        return Err("a broken FAT boot sector");
    }
    Ok(Volume {
        sector,
        cluster: sector * per,
        fat: reserved * sector,
        data: data_sector * sector,
        root: (le32(&bs, 44) & 0x0FFF_FFFF) as u32,
        clusters: ((total - data_sector) / per) as u32,
    })
}

/// The cluster chain starting at `first`: at most `limit` clusters (`cut`: the first
/// `limit` are all that is needed; otherwise a longer chain is a loop in a broken FAT).
fn chain(read: &mut dyn FnMut(u64, &mut [u8]) -> bool, v: &Volume, first: u32, limit: usize, cut: bool) -> Result<Vec<u32>, &'static str> {
    let mut out = Vec::new();
    let mut c = first;
    let mut cached: (u64, [u8; 512]) = (u64::MAX, [0; 512]);
    loop {
        if c < 2 || c >= v.clusters + 2 {
            return Err("a broken cluster chain");
        }
        if out.len() >= limit {
            return if cut { Ok(out) } else { Err("a cluster chain loops") };
        }
        out.push(c);
        let at = v.fat + c as u64 * 4;
        let sec = at & !511;
        if cached.0 != sec {
            if !read(sec, &mut cached.1) {
                return Err("cannot read the FAT");
            }
            cached.0 = sec;
        }
        let next = (le32(&cached.1, (at - sec) as usize) & 0x0FFF_FFFF) as u32;
        if next >= 0x0FFF_FFF8 {
            return Ok(out);
        }
        c = next;
    }
}

/// The partition offset of cluster `c`.
fn cluster_at(v: &Volume, c: u32) -> u64 {
    v.data + (c as u64 - 2) * v.cluster
}

/// Looks for `name` (11-byte form) in the directory starting at cluster `dir`: its first
/// cluster, size and whether it is a directory.
fn find(read: &mut dyn FnMut(u64, &mut [u8]) -> bool, v: &Volume, dir: u32, name: &[u8; 11]) -> Result<Option<(u32, u64, bool)>, &'static str> {
    let clusters = chain(read, v, dir, 65536, false)?;
    let mut buf = alloc::vec![0u8; v.cluster as usize];
    for c in clusters {
        if !read(cluster_at(v, c), &mut buf) {
            return Err("cannot read a directory");
        }
        for e in buf.chunks_exact(32) {
            match e[0] {
                0 => return Ok(None),
                0xE5 => continue,
                _ => {}
            }
            let attr = e[11];
            if attr & 0x0F == 0x0F || attr & 0x08 != 0 {
                continue; // a long-name piece or the volume label
            }
            let mut n = [0u8; 11];
            n.copy_from_slice(&e[..11]);
            if n[0] == 0x05 {
                n[0] = 0xE5;
            }
            if n.eq_ignore_ascii_case(name) {
                let first = (le16(e, 20) << 16 | le16(e, 26)) as u32;
                return Ok(Some((first, le32(e, 28), attr & 0x10 != 0)));
            }
        }
    }
    Ok(None)
}

/// Finds the regular file at `path` (8.3 names from the root, e.g. `["logs", "boot001.txt"]`)
/// and where its bytes are.
pub fn locate(read: &mut dyn FnMut(u64, &mut [u8]) -> bool, path: &[&str]) -> Result<FileMap, &'static str> {
    let v = volume(read)?;
    let mut dir = v.root;
    for (i, part) in path.iter().enumerate() {
        let name = short_name(part).ok_or("not an 8.3 name")?;
        let (first, size, is_dir) = find(read, &v, dir, &name)?.ok_or("not found")?;
        let last = i + 1 == path.len();
        if !last {
            if !is_dir {
                return Err("not a directory");
            }
            dir = if first == 0 { v.root } else { first };
            continue;
        }
        if is_dir {
            return Err("a directory");
        }
        if size == 0 {
            return Ok(FileMap { size: 0, extents: Vec::new() });
        }
        let need = size.div_ceil(v.cluster) as usize;
        let clusters = chain(read, &v, first, need, true)?;
        if clusters.len() < need {
            return Err("the file's cluster chain is shorter than the file");
        }
        let mut extents: Vec<Extent> = Vec::new();
        for (k, &c) in clusters.iter().take(need).enumerate() {
            let part_off = cluster_at(&v, c);
            let file_off = k as u64 * v.cluster;
            match extents.last_mut() {
                Some(e) if e.part_off + e.len == part_off => e.len += v.cluster,
                _ => extents.push(Extent { file_off, part_off, len: v.cluster }),
            }
        }
        let _ = v.sector;
        return Ok(FileMap { size, extents });
    }
    Err("an empty path")
}
