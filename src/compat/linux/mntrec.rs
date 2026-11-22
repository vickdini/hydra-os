//! # A mount namespace's whole table as bytes (wave 8, Group F)
//!
//! vfs-server decides the mount changes of the programs it serves (`mount`, `umount2`,
//! `pivot_root`); the kernel's table in [`super::mount`] is the write-through copy the
//! kernel's own code walks (and the switch back). The two exchange a namespace's whole
//! table in this format: `LX_FH_MNTGET` gives it to vfs-server, `LX_FH_MNTPUT` writes it
//! back. Plain Rust (`core` + `alloc`), shared with vfs-server by `#[path]` and tested on
//! the host (`tests/host-w8-f`).
//!
//! - **Slots** are the kernel's mount indices (1-based; slot `i` = mount `i + 1`); an empty
//!   slot stays empty (indices are never reused: handles name mounts by index).
//! - **Compare and set:** the head carries a hash of the table as it was read
//!   ([`MntTable::hash`], FNV-1a over the encoded slots, root and system root). A write is
//!   refused (`EAGAIN`) when the kernel's table no longer hashes to it: someone else (a FUSE
//!   mount, the new mount API, a namespace copy) changed it in between, whatever order its
//!   generation moved in.
//!
//! Layout (little endian): head `magic u32, n u32, gen u64, hash u64, root u32, pad u32,
//! system_root u64` (40 bytes), then `n` slots: `present u8` and, if 1, `id u32, parent
//! u32, kind u32, tmpfs u32, mountpoint u64, root u64, flags u64, propagation u64`, then four
//! strings `fstype, source, path, serves`, each `len u16` + bytes (`serves` absent:
//! `len = 0xFFFF`).

use alloc::string::String;
use alloc::vec::Vec;

/// The head's first word.
pub const MNT_MAGIC: u32 = 0x3154_4E4D; // "MNT1"
/// [`MntRec::kind`]: a tree of the pool (bind mount, namespace root, tmpfs, sysfs/devtmpfs,
/// FUSE).
pub const MK_TREE: u32 = 1;
/// [`MntRec::kind`]: a file system served by name (proc, devpts, cgroup2, mqueue, a bind of
/// a device served by name): listed, its files served where [`MntRec::serves`] says.
pub const MK_NAMED: u32 = 2;
/// The head's size.
pub const HEAD_LEN: usize = 40;
/// At most this many slots (the walk's mount numbers are 16 bits).
pub const MAX_SLOTS: usize = 65_000;
/// Longest string kept (a path, a source).
pub const MAX_STR: usize = 4096;

const EINVAL: i64 = -22;

/// One mount, as the kernel keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MntRec {
    /// Mount id (`mountinfo`).
    pub id: u32,
    /// The mount it is on (1-based; 0: none, the root).
    pub parent: u32,
    /// [`MK_TREE`] or [`MK_NAMED`].
    pub kind: u32,
    /// For a tree: its tmpfs id (0: not a tmpfs).
    pub tmpfs: u32,
    /// The directory it covers (an object of `parent`; 0 or `u64::MAX`: not located).
    pub mountpoint: u64,
    /// The root object of a tree (0 for a named mount).
    pub root: u64,
    /// Per-mount `MS_*` flags.
    pub flags: u64,
    /// Propagation `MS_*` flags (listed only).
    pub propagation: u64,
    /// File system type.
    pub fstype: String,
    /// Source (`mountinfo`).
    pub source: String,
    /// Mount point path in the namespace.
    pub path: String,
    /// For a named mount: where its files are served, if elsewhere than where it is listed.
    pub serves: Option<String>,
}

/// A namespace's table.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MntTable {
    /// The namespace's generation when it was read (informative).
    pub gen: u64,
    /// The hash of the table as read ([`hash_of`]): what a write compares against.
    pub hash: u64,
    /// The root mount (1-based).
    pub root: u32,
    /// The system root object (sysfs and devtmpfs mounts bind its `/sys` and `/dev`).
    pub system_root: u64,
    /// The slots (slot `i` is mount `i + 1`).
    pub slots: Vec<Option<MntRec>>,
}

impl MntTable {
    /// Mount `i` (1-based).
    pub fn get(&self, i: u32) -> Option<&MntRec> {
        self.slots.get((i as usize).checked_sub(1)?)?.as_ref()
    }

    /// Mount `i` (1-based), to change.
    pub fn get_mut(&mut self, i: u32) -> Option<&mut MntRec> {
        self.slots.get_mut((i as usize).checked_sub(1)?)?.as_mut()
    }

    /// Adds a mount at the end; its index.
    pub fn push(&mut self, m: MntRec) -> u32 {
        self.slots.push(Some(m));
        self.slots.len() as u32
    }

    /// The live mounts with their indices.
    pub fn live(&self) -> impl Iterator<Item = (u32, &MntRec)> {
        self.slots.iter().enumerate().filter_map(|(i, m)| m.as_ref().map(|m| (i as u32 + 1, m)))
    }

    /// Indices of `i` and every mount below it (parents before children).
    pub fn subtree(&self, i: u32) -> Vec<u32> {
        let mut out = alloc::vec![i];
        let mut k = 0;
        while k < out.len() {
            let p = out[k];
            for (j, m) in self.live() {
                if m.parent == p && !out.contains(&j) {
                    out.push(j);
                }
            }
            k += 1;
        }
        out
    }

    /// Checks what a decoded table must hold: a live root, parents inside the table, kinds
    /// known, no slot its own ancestor.
    pub fn check(&self) -> Result<(), i64> {
        if self.slots.len() > MAX_SLOTS || self.get(self.root).is_none() {
            return Err(EINVAL);
        }
        let n = self.slots.len() as u32;
        for (i, m) in self.live() {
            if m.kind != MK_TREE && m.kind != MK_NAMED {
                return Err(EINVAL);
            }
            if m.parent > n || m.parent == i || (m.parent != 0 && self.get(m.parent).is_none()) {
                return Err(EINVAL);
            }
            // (no cycle: following parents ends at 0 within n steps)
            let mut p = m.parent;
            let mut steps = 0u32;
            while p != 0 {
                steps += 1;
                if steps > n {
                    return Err(EINVAL);
                }
                p = self.get(p).map_or(0, |m| m.parent);
            }
        }
        Ok(())
    }
}

/// FNV-1a over `b`, continuing from `h`.
fn fnv(mut h: u64, b: &[u8]) -> u64 {
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn put_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(s) => {
            let b = &s.as_bytes()[..s.len().min(MAX_STR)];
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(b);
        }
        None => out.extend_from_slice(&0xFFFFu16.to_le_bytes()),
    }
}

/// The slots' bytes (what the hash covers, with the root and the system root).
fn encode_slots(t: &MntTable, out: &mut Vec<u8>) {
    for s in &t.slots {
        match s {
            None => out.push(0),
            Some(m) => {
                out.push(1);
                for w in [m.id, m.parent, m.kind, m.tmpfs] {
                    out.extend_from_slice(&w.to_le_bytes());
                }
                for w in [m.mountpoint, m.root, m.flags, m.propagation] {
                    out.extend_from_slice(&w.to_le_bytes());
                }
                put_str(out, Some(&m.fstype));
                put_str(out, Some(&m.source));
                put_str(out, Some(&m.path));
                put_str(out, m.serves.as_deref());
            }
        }
    }
}

/// The hash of table `t`'s contents (slots, root, system root; not `gen`/`hash`).
pub fn hash_of(t: &MntTable) -> u64 {
    let mut b = Vec::new();
    encode_slots(t, &mut b);
    let mut h = fnv(0xCBF2_9CE4_8422_2325, &b);
    h = fnv(h, &t.root.to_le_bytes());
    fnv(h, &t.system_root.to_le_bytes())
}

/// Table `t` as bytes (its `gen` and `hash` as they are).
pub fn encode(t: &MntTable) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD_LEN + t.slots.len() * 64);
    out.extend_from_slice(&MNT_MAGIC.to_le_bytes());
    out.extend_from_slice(&(t.slots.len() as u32).to_le_bytes());
    out.extend_from_slice(&t.gen.to_le_bytes());
    out.extend_from_slice(&t.hash.to_le_bytes());
    out.extend_from_slice(&t.root.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&t.system_root.to_le_bytes());
    encode_slots(t, &mut out);
    out
}

/// Reads bytes in order; any overrun makes the whole decode fail.
struct Rd<'a> {
    b: &'a [u8],
    at: usize,
}

impl Rd<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], i64> {
        let end = self.at.checked_add(n).ok_or(EINVAL)?;
        let s = self.b.get(self.at..end).ok_or(EINVAL)?;
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, i64> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, i64> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, i64> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, i64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn str(&mut self) -> Result<Option<String>, i64> {
        let n = self.u16()?;
        if n == 0xFFFF {
            return Ok(None);
        }
        if n as usize > MAX_STR {
            return Err(EINVAL);
        }
        let s = self.take(n as usize)?;
        Ok(Some(String::from(core::str::from_utf8(s).map_err(|_| EINVAL)?)))
    }
}

/// Bytes back to a table (`EINVAL`: not one, cut short, trailing bytes, or a table that
/// fails [`MntTable::check`]).
pub fn decode(b: &[u8]) -> Result<MntTable, i64> {
    let mut r = Rd { b, at: 0 };
    if r.u32()? != MNT_MAGIC {
        return Err(EINVAL);
    }
    let n = r.u32()? as usize;
    if n > MAX_SLOTS {
        return Err(EINVAL);
    }
    let gen = r.u64()?;
    let hash = r.u64()?;
    let root = r.u32()?;
    let _pad = r.u32()?;
    let system_root = r.u64()?;
    let mut slots = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        match r.u8()? {
            0 => slots.push(None),
            1 => {
                let (id, parent, kind, tmpfs) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
                let (mountpoint, root, flags, propagation) = (r.u64()?, r.u64()?, r.u64()?, r.u64()?);
                let fstype = r.str()?.ok_or(EINVAL)?;
                let source = r.str()?.ok_or(EINVAL)?;
                let path = r.str()?.ok_or(EINVAL)?;
                let serves = r.str()?;
                slots.push(Some(MntRec { id, parent, kind, tmpfs, mountpoint, root, flags, propagation, fstype, source, path, serves }));
            }
            _ => return Err(EINVAL),
        }
    }
    if r.at != b.len() {
        return Err(EINVAL);
    }
    let t = MntTable { gen, hash, root, system_root, slots };
    t.check()?;
    Ok(t)
}

/// The roots of the tree mounts of `t` (each mount once: two binds of one tree hold it twice).
pub fn tree_roots(t: &MntTable) -> Vec<u64> {
    t.live().filter(|(_, m)| m.kind == MK_TREE).map(|(_, m)| m.root).collect()
}

/// What changes between tables `old` and `new` for the objects held at mount roots:
/// `(take, release)`, each object as many times as its count changed.
pub fn root_changes(old: &[u64], new: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let mut o: Vec<u64> = old.to_vec();
    let mut take = Vec::new();
    for &r in new {
        match o.iter().position(|&x| x == r) {
            Some(i) => {
                o.swap_remove(i);
            }
            None => take.push(r),
        }
    }
    (take, o)
}
