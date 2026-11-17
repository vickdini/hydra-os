//! # Partition tables (GPT and MBR)
//!
//! Reads a disk's partition table: the GUID Partition Table (UEFI 2.x chapter 5) when the
//! disk has one, otherwise the four primary entries of a classic MBR. Shared by the kernel
//! (Linux block devices `/dev/sdXN`, the boot disk) and the Ring 3 disk drivers (`hydra-rt`
//! includes this file), so it needs only `alloc`.
//!
//! The caller provides a reader of whole 512-byte-addressed byte ranges; the table is
//! located at LBA 1 for 512-byte sectors and at byte 4096 for 4096-byte ("4Kn") sectors.

use alloc::string::String;
use alloc::vec::Vec;

/// A GUID in its on-disk (mixed-endian) byte order.
pub type Guid = [u8; 16];

/// Partition type of the EFI System Partition (C12A7328-F81F-11D2-BA4B-00A0C93EC93B).
pub const ESP_TYPE: Guid = guid(0xC12A7328, 0xF81F, 0x11D2, [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B]);

/// Partition type of a Hydra pool (7685A0B8-DF41-47EB-AF4F-02CE6FB01879).
pub const HYDRA_POOL_TYPE: Guid = guid(0x7685A0B8, 0xDF41, 0x47EB, [0xAF, 0x4F, 0x02, 0xCE, 0x6F, 0xB0, 0x18, 0x79]);

/// Builds an on-disk GUID from its textual fields.
pub const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]
}

/// The textual form (`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`, lower case) of an on-disk GUID.
pub fn guid_string(g: &Guid) -> String {
    let mut s = String::with_capacity(36);
    let hex = |s: &mut String, b: u8| {
        const H: &[u8; 16] = b"0123456789abcdef";
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    };
    for i in [3, 2, 1, 0] {
        hex(&mut s, g[i]);
    }
    s.push('-');
    for i in [5, 4] {
        hex(&mut s, g[i]);
    }
    s.push('-');
    for i in [7, 6] {
        hex(&mut s, g[i]);
    }
    s.push('-');
    for i in [8, 9] {
        hex(&mut s, g[i]);
    }
    s.push('-');
    for i in 10..16 {
        hex(&mut s, g[i]);
    }
    s
}

/// Parses the textual form of a GUID (either case) into its on-disk bytes.
pub fn parse_guid(s: &str) -> Option<Guid> {
    let s = s.trim();
    let digits: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
    if digits.len() != 32 || s.len() != 36 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, pair) in digits.chunks(2).enumerate() {
        let v = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        raw[i] = v(pair[0])? << 4 | v(pair[1])?;
    }
    // Text order: the first three fields big-endian; on disk little-endian
    Some([raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]])
}

/// Kind of partition table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// GUID Partition Table.
    Gpt,
    /// Classic DOS/MBR table.
    Mbr,
}

/// One partition.
#[derive(Clone, Debug)]
pub struct Part {
    /// Partition number (1-based, as Linux numbers them: the GPT entry index + 1, or the
    /// MBR slot + 1).
    pub number: u32,
    /// First byte on the disk.
    pub start: u64,
    /// Length in bytes.
    pub len: u64,
    /// Type GUID (GPT) or the MBR type byte in `type_guid[0]`.
    pub type_guid: Guid,
    /// Unique partition GUID (GPT; zero for MBR).
    pub part_guid: Guid,
    /// Partition name (GPT; empty for MBR).
    pub name: String,
    /// MBR type byte (0 on GPT).
    pub mbr_type: u8,
}

/// A disk's partition table.
#[derive(Clone, Debug)]
pub struct Table {
    /// GPT or MBR.
    pub kind: Kind,
    /// Disk GUID (GPT) or the 32-bit disk signature in the first four bytes (MBR).
    pub disk_guid: Guid,
    /// Partitions in number order.
    pub parts: Vec<Part>,
}

impl Table {
    /// The partition whose unique GUID is `g`.
    pub fn by_guid(&self, g: &Guid) -> Option<&Part> {
        self.parts.iter().find(|p| self.kind == Kind::Gpt && &p.part_guid == g)
    }

    /// The first partition of type `t` (GPT).
    pub fn by_type(&self, t: &Guid) -> Option<&Part> {
        self.parts.iter().find(|p| self.kind == Kind::Gpt && &p.type_guid == t)
    }
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn le64(b: &[u8], at: usize) -> u64 {
    le32(b, at) as u64 | (le32(b, at + 4) as u64) << 32
}

/// The CRC-32 (IEEE, reflected) the GPT uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Reads the partition table of a disk of `disk_bytes` bytes. `read(offset, buf)` fills
/// `buf` from byte `offset` of the disk (offsets and lengths are multiples of 512) and
/// returns whether it could. `None`: no (valid) table.
pub fn read_table(read: &mut dyn FnMut(u64, &mut [u8]) -> bool, disk_bytes: u64) -> Option<Table> {
    let mut first = alloc::vec![0u8; 8192];
    if disk_bytes < 8192 || !read(0, &mut first) {
        return None;
    }
    let mbr_ok = first[510] == 0x55 && first[511] == 0xAA;
    // A GPT header at LBA 1 (512-byte sectors) or at byte 4096 (4096-byte sectors)
    for sector in [512u64, 4096] {
        let h = &first[sector as usize..sector as usize + 92];
        if &h[0..8] != b"EFI PART" {
            continue;
        }
        let hsize = le32(h, 12) as usize;
        if !(92..=512).contains(&hsize) {
            continue;
        }
        let mut hdr = alloc::vec![0u8; hsize];
        hdr.copy_from_slice(&first[sector as usize..sector as usize + hsize]);
        let want = le32(&hdr, 16);
        hdr[16..20].fill(0);
        if crc32(&hdr) != want {
            continue;
        }
        let entries_lba = le64(h, 72);
        let count = le32(h, 80) as usize;
        let esize = le32(h, 84) as usize;
        if esize < 128 || esize > 4096 || count == 0 || count > 1024 {
            continue;
        }
        let bytes = (count * esize).div_ceil(512) * 512;
        let mut ent = alloc::vec![0u8; bytes];
        if entries_lba * sector + bytes as u64 > disk_bytes || !read(entries_lba * sector, &mut ent) {
            continue;
        }
        if crc32(&ent[..count * esize]) != le32(h, 88) {
            continue;
        }
        let mut disk_guid = [0u8; 16];
        disk_guid.copy_from_slice(&h[56..72]);
        let mut parts = Vec::new();
        for i in 0..count {
            let e = &ent[i * esize..(i + 1) * esize];
            let mut type_guid = [0u8; 16];
            type_guid.copy_from_slice(&e[0..16]);
            if type_guid == [0; 16] {
                continue;
            }
            let mut part_guid = [0u8; 16];
            part_guid.copy_from_slice(&e[16..32]);
            let (first_lba, last_lba) = (le64(e, 32), le64(e, 40));
            if last_lba < first_lba {
                continue;
            }
            let units: Vec<u16> = e[56..128].chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
            parts.push(Part {
                number: i as u32 + 1,
                start: first_lba * sector,
                len: (last_lba - first_lba + 1) * sector,
                type_guid,
                part_guid,
                name: String::from_utf16_lossy(&units),
                mbr_type: 0,
            });
        }
        return Some(Table { kind: Kind::Gpt, disk_guid, parts });
    }
    if !mbr_ok {
        return None;
    }
    let mut parts = Vec::new();
    let mut seen_protective = false;
    for slot in 0..4 {
        let e = &first[446 + slot * 16..446 + slot * 16 + 16];
        let ty = e[4];
        let (start, len) = (le32(e, 8) as u64, le32(e, 12) as u64);
        if ty == 0 || len == 0 {
            continue;
        }
        if ty == 0xEE {
            seen_protective = true;
            continue;
        }
        // Entries with a boot flag other than 0x00/0x80 mean this is no MBR (a FAT boot
        // sector also ends in 55 AA)
        if e[0] & 0x7F != 0 {
            return None;
        }
        let mut type_guid = [0u8; 16];
        type_guid[0] = ty;
        parts.push(Part { number: slot as u32 + 1, start: start * 512, len: len * 512, type_guid, part_guid: [0; 16], name: String::new(), mbr_type: ty });
    }
    if seen_protective && parts.is_empty() {
        return None; // a GPT whose header did not check out
    }
    // A FAT/NTFS file system directly on the disk ("superfloppy") has no table: its boot
    // code fills the bytes where the entries would be
    let fs_boot = &first[3..11] == b"NTFS    " || &first[82..87] == b"FAT32" || &first[54..59] == b"FAT16" || &first[54..59] == b"FAT12";
    if parts.is_empty() || fs_boot {
        return None;
    }
    let mut disk_guid = [0u8; 16];
    disk_guid[..4].copy_from_slice(&first[440..444]);
    Some(Table { kind: Kind::Mbr, disk_guid, parts })
}
