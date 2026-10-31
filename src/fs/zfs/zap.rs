//! # ZFS Attribute Processor (ZAP) & Directories
//!
//! ## Subsystem Role & Architecture
//! This module provides the directory management implementation for Hydra's OpenZFS
//! filesystem layer. In OpenZFS, directories are specialized dnode objects whose data
//! payload is formatted as variable-length directory entries structured within 4 KiB
//! logical blocks.
//!
//! ## Architecture & Layout
//! A directory is an object whose data is a sequence of 4 KiB blocks of variable-length
//! entry records. Records never cross a block boundary:
//!
//! ```text
//! +--------+---------+----------+-------+----------------+---------+
//! | ino u64| len u16 | nlen u8  | type  | name[nlen]     | padding |
//! +--------+---------+----------+-------+----------------+---------+
//! ```
//!
//! `len` spans to the next record, so a record can carry free space after its name.
//! Removing a record merges it into the previous record of its block (or zeroes `ino`
//! when it is the first). An entry's byte offset in the object never changes while it
//! exists, which makes it a stable `readdir` cookie.
//!
//! Lookups use an in-memory index (`name -> entry`), built on first access and cached.
//!
//! ## Key Types & Interfaces
//! - [`DirEntry`]: Low-level directory record returned by [`Zap::readdir`].
//! - [`ZapEntry`]: Directory listing representation for user-space and shell commands.
//! - [`Zap`]: Main engine managing directory indexing, lookup, insertion, and deletion.
//!
//! ## Concurrency & Hardware Semantics
//! Directory operations mutate DMU object blocks. Consistency is guarded at higher layers
//! (ZPL / filesystem server mutexes) when committing transactional updates.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::dmu::{Dmu, DmuResult};
use super::spa::BLOCK;
use super::types::ZFS_BLOCK_SIZE;

const HEADER: usize = 12;
/// Longest file name (bytes), as on Linux.
pub const NAME_MAX: usize = 255;
/// Directory indexes kept cached before the cache is reset.
const INDEX_CACHE_LIMIT: usize = 1024;

fn rec_size(name_len: usize) -> usize {
    (HEADER + name_len + 7) & !7
}

struct Record {
    ino: u64,
    len: usize,
    name_len: usize,
    dtype: u8,
}

fn parse(block: &[u8; ZFS_BLOCK_SIZE], off: usize) -> Option<Record> {
    if off + HEADER > ZFS_BLOCK_SIZE {
        return None;
    }
    let ino = u64::from_le_bytes(block[off..off + 8].try_into().unwrap());
    let len = u16::from_le_bytes([block[off + 8], block[off + 9]]) as usize;
    let name_len = block[off + 10] as usize;
    if len < HEADER || off + len > ZFS_BLOCK_SIZE || (ino != 0 && rec_size(name_len) > len) {
        return None;
    }
    Some(Record { ino, len, name_len, dtype: block[off + 11] })
}

fn write_header(block: &mut [u8; ZFS_BLOCK_SIZE], off: usize, ino: u64, len: usize, name_len: usize, dtype: u8) {
    block[off..off + 8].copy_from_slice(&ino.to_le_bytes());
    block[off + 8..off + 10].copy_from_slice(&(len as u16).to_le_bytes());
    block[off + 10] = name_len as u8;
    block[off + 11] = dtype;
}

/// Largest record that could be inserted into `block`.
fn block_slack(block: &[u8; ZFS_BLOCK_SIZE]) -> u16 {
    let mut best = 0;
    let mut off = 0;
    while let Some(r) = parse(block, off) {
        let used = if r.ino == 0 { 0 } else { rec_size(r.name_len) };
        best = best.max(r.len - used);
        off += r.len;
    }
    best as u16
}

/// A directory entry as returned by [`Zap::readdir`].
pub struct DirEntry {
    /// File name bytes.
    pub name: Vec<u8>,
    /// Inode / object ID number.
    pub ino: u64,
    /// Dirent type indicator (e.g. `DT_DIR`, `DT_REG`).
    pub dtype: u8,
    /// Byte offset of this entry in the directory object.
    pub pos: u64,
    /// Byte offset to continue from after this entry.
    pub next_pos: u64,
}

/// A directory listing entry for shell commands (`ZfsClient::list_dir`).
#[derive(Debug, Clone)]
pub struct ZapEntry {
    /// Name of the directory entry.
    pub name: alloc::string::String,
    /// Inode / target object ID.
    pub object_id: u64,
    /// Dnode type representation (e.g. file, directory, symlink).
    pub obj_type: super::types::DnodeType,
    /// Whether this directory entry represents a valid record.
    pub is_valid: bool,
}

impl ZapEntry {
    /// Creates a new directory entry record.
    ///
    /// # Arguments
    /// * `name` - Raw byte slice of the file name.
    /// * `object_id` - Target object identifier.
    /// * `obj_type` - Dnode type of the target.
    pub fn new(name: &[u8], object_id: u64, obj_type: super::types::DnodeType) -> Self {
        Self {
            name: alloc::string::String::from_utf8_lossy(name).into_owned(),
            object_id,
            obj_type,
            is_valid: true,
        }
    }

    /// Returns a string slice of the entry name.
    pub fn name_str(&self) -> &str {
        &self.name
    }
}

struct DirIndex {
    names: BTreeMap<Vec<u8>, (u64, u8, u64)>,
    block_free: Vec<u16>,
}

/// Directory operations over the DMU, with a cache of directory indexes.
pub struct Zap {
    cache: BTreeMap<u64, DirIndex>,
}

impl Zap {
    /// Creates a new, empty directory index cache engine.
    pub const fn new() -> Self {
        Self { cache: BTreeMap::new() }
    }

    fn read_dir_block(dmu: &mut Dmu, dir: u64, b: u64) -> DmuResult<[u8; ZFS_BLOCK_SIZE]> {
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        dmu.read(dir, b * BLOCK, &mut block)?;
        Ok(block)
    }

    fn index(&mut self, dmu: &mut Dmu, dir: u64) -> DmuResult<&mut DirIndex> {
        if !self.cache.contains_key(&dir) {
            if self.cache.len() >= INDEX_CACHE_LIMIT {
                self.cache.clear();
            }
            let size = dmu.get_dnode(dir)?.size;
            let blocks = size / BLOCK;
            let mut idx = DirIndex {
                names: BTreeMap::new(),
                block_free: Vec::with_capacity(blocks as usize),
            };
            for b in 0..blocks {
                let block = Self::read_dir_block(dmu, dir, b)?;
                let mut off = 0;
                while let Some(r) = parse(&block, off) {
                    if r.ino != 0 {
                        let name = block[off + HEADER..off + HEADER + r.name_len].to_vec();
                        idx.names.insert(name, (r.ino, r.dtype, b * BLOCK + off as u64));
                    }
                    off += r.len;
                }
                idx.block_free.push(block_slack(&block));
            }
            self.cache.insert(dir, idx);
        }
        Ok(self.cache.get_mut(&dir).unwrap())
    }

    /// Forgets every cached directory index.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Forgets the cached index of a directory (after it is freed).
    pub fn forget(&mut self, dir: u64) {
        self.cache.remove(&dir);
    }

    /// Looks up `name`, returning (inode, d_type).
    pub fn lookup(&mut self, dmu: &mut Dmu, dir: u64, name: &[u8]) -> DmuResult<Option<(u64, u8)>> {
        Ok(self.index(dmu, dir)?.names.get(name).map(|&(ino, dtype, _)| (ino, dtype)))
    }

    /// Number of entries (excluding `.` and `..`).
    pub fn count(&mut self, dmu: &mut Dmu, dir: u64) -> DmuResult<usize> {
        Ok(self.index(dmu, dir)?.names.len())
    }

    /// Adds an entry. The caller guarantees `name` is not already present.
    pub fn insert(&mut self, dmu: &mut Dmu, dir: u64, name: &[u8], ino: u64, dtype: u8) -> DmuResult<()> {
        if name.is_empty() || name.len() > NAME_MAX {
            return Err("ZFS: invalid file name length");
        }
        let need = rec_size(name.len());
        let found = self.index(dmu, dir)?.block_free.iter().position(|&f| f as usize >= need);
        let (b, mut block) = match found {
            Some(b) => (b as u64, Self::read_dir_block(dmu, dir, b as u64)?),
            None => {
                let mut block = [0u8; ZFS_BLOCK_SIZE];
                write_header(&mut block, 0, 0, ZFS_BLOCK_SIZE, 0, 0);
                let b = self.index(dmu, dir)?.block_free.len() as u64;
                self.index(dmu, dir)?.block_free.push(ZFS_BLOCK_SIZE as u16);
                (b, block)
            }
        };

        let mut off = 0;
        let pos = loop {
            let r = parse(&block, off).ok_or("ZFS: corrupt directory block")?;
            if r.ino == 0 && r.len >= need {
                write_header(&mut block, off, ino, r.len, name.len(), dtype);
                break off;
            }
            let used = rec_size(r.name_len);
            if r.ino != 0 && r.len - used >= need {
                // Split: shrink this record to its own size, new entry takes the rest
                write_header(&mut block, off, r.ino, used, r.name_len, r.dtype);
                let new_off = off + used;
                write_header(&mut block, new_off, ino, r.len - used, name.len(), dtype);
                break new_off;
            }
            off += r.len;
        };
        block[pos + HEADER..pos + HEADER + name.len()].copy_from_slice(name);
        dmu.write(dir, b * BLOCK, &block)?;

        let idx = self.index(dmu, dir)?;
        idx.names.insert(name.to_vec(), (ino, dtype, b * BLOCK + pos as u64));
        idx.block_free[b as usize] = block_slack(&block);
        Ok(())
    }

    /// Removes an entry, returning its inode number.
    pub fn remove(&mut self, dmu: &mut Dmu, dir: u64, name: &[u8]) -> DmuResult<Option<u64>> {
        let (ino, pos) = match self.index(dmu, dir)?.names.get(name) {
            Some(&(ino, _, pos)) => (ino, pos),
            None => return Ok(None),
        };
        let b = pos / BLOCK;
        let target = (pos % BLOCK) as usize;
        let mut block = Self::read_dir_block(dmu, dir, b)?;
        let mut off = 0;
        let mut prev: Option<usize> = None;
        while off < target {
            let r = parse(&block, off).ok_or("ZFS: corrupt directory block")?;
            prev = Some(off);
            off += r.len;
        }
        let rec = parse(&block, target).ok_or("ZFS: corrupt directory block")?;
        match prev {
            Some(p) => {
                let pr = parse(&block, p).unwrap();
                write_header(&mut block, p, pr.ino, pr.len + rec.len, pr.name_len, pr.dtype);
            }
            None => write_header(&mut block, target, 0, rec.len, 0, 0),
        }
        dmu.write(dir, b * BLOCK, &block)?;

        let idx = self.index(dmu, dir)?;
        idx.names.remove(name);
        idx.block_free[b as usize] = block_slack(&block);
        Ok(Some(ino))
    }

    /// Points an existing entry at a different inode (used by rename over a target).
    pub fn replace(&mut self, dmu: &mut Dmu, dir: u64, name: &[u8], ino: u64, dtype: u8) -> DmuResult<()> {
        let pos = match self.index(dmu, dir)?.names.get(name) {
            Some(&(_, _, pos)) => pos,
            None => return self.insert(dmu, dir, name, ino, dtype),
        };
        let b = pos / BLOCK;
        let off = (pos % BLOCK) as usize;
        let mut block = Self::read_dir_block(dmu, dir, b)?;
        let r = parse(&block, off).ok_or("ZFS: corrupt directory block")?;
        write_header(&mut block, off, ino, r.len, r.name_len, dtype);
        dmu.write(dir, b * BLOCK, &block)?;
        self.index(dmu, dir)?.names.insert(name.to_vec(), (ino, dtype, pos));
        Ok(())
    }

    /// Returns up to `max` entries starting at byte offset `from`.
    pub fn readdir(&mut self, dmu: &mut Dmu, dir: u64, from: u64, max: usize) -> DmuResult<Vec<DirEntry>> {
        let size = dmu.get_dnode(dir)?.size;
        let mut out = Vec::new();
        let mut b = from / BLOCK;
        let mut start = (from % BLOCK) as usize;
        while b * BLOCK < size && out.len() < max {
            let block = Self::read_dir_block(dmu, dir, b)?;
            let mut off = 0;
            while let Some(r) = parse(&block, off) {
                let next = off + r.len;
                if off >= start && r.ino != 0 {
                    let next_pos = if next >= ZFS_BLOCK_SIZE { (b + 1) * BLOCK } else { b * BLOCK + next as u64 };
                    out.push(DirEntry {
                        name: block[off + HEADER..off + HEADER + r.name_len].to_vec(),
                        ino: r.ino,
                        dtype: r.dtype,
                        pos: b * BLOCK + off as u64,
                        next_pos,
                    });
                    if out.len() >= max {
                        return Ok(out);
                    }
                }
                off = next;
            }
            b += 1;
            start = 0;
        }
        Ok(out)
    }
}
