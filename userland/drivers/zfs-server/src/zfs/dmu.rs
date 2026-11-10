//! # Data Management Unit (DMU)
//!
//! Turns the block-level pool into numbered objects of arbitrary size. Each object is a
//! [`DnodePhys`] plus a tree of block pointers (3 top-level pointers, 64-way indirect
//! blocks, `nlevels` deep). Object N's dnode is stored at byte N * 512 of object 0, the
//! meta object, whose own dnode lives in the uberblock.
//!
//! ## Transaction Model
//!
//! Writes never touch the on-disk tree directly. Modified 4 KiB blocks are kept as dirty
//! frames keyed by (object, block id), truncations and object frees are recorded, and
//! reads overlay them on the committed tree. [`Dmu::sync`] then commits one transaction
//! group: every dirty block is written to a newly allocated location, indirect blocks are
//! rewritten bottom-up, dnodes are written into the meta object, the meta object's tree is
//! committed last, and the SPA writes the new uberblock. Replaced blocks are freed only
//! after that (see [`super::spa`]), unless a snapshot still references them.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::spa::{frame_bytes, Spa, BLOCK};
use super::types::*;
use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec};

/// Commit automatically once this many blocks are dirty (16 MiB).
pub const DIRTY_SYNC_THRESHOLD: usize = 4096;
/// Clean dnodes kept cached before the cache is trimmed.
const DNODE_CACHE_LIMIT: usize = 65_536;

/// Result type for DMU object layer operations returning static error strings on failure.
pub type DmuResult<T> = Result<T, &'static str>;

type Indirect = [BlockPointer; BP_PER_BLOCK];

/// Computes 64 raised to power `level`.
///
/// # Arguments
/// * `level` - Tree depth exponent.
///
/// # Returns
/// Computed 64^level value.
fn pow64(level: u32) -> u64 {
    1u64 << (6 * level)
}

/// Leaf blocks addressable by a tree of `nlevels` levels.
///
/// # Arguments
/// * `nlevels` - Tree height in levels.
///
/// # Returns
/// Total number of leaf blocks capacity.
fn capacity(nlevels: u8) -> u64 {
    DN_TOP_PTRS as u64 * pow64(nlevels as u32 - 1)
}

/// Copies an indirect block pointer array from a memory frame into a heap box.
///
/// # Arguments
/// * `frame` - Physical frame containing block pointers.
///
/// # Returns
/// Boxed array of 64 block pointers.
fn read_indirect(frame: PhysFrame<Size4KiB>) -> Box<Indirect> {
    let mut entries = Box::new([BlockPointer::HOLE; BP_PER_BLOCK]);
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.start_address().as_u64() as *const u8,
            entries.as_mut_ptr() as *mut u8,
            ZFS_BLOCK_SIZE,
        );
    }
    entries
}

/// The object layer of the pool.
pub struct Dmu {
    /// Storage Pool Allocator managing physical vdev block allocation.
    pub spa: Spa,
    /// Active uberblock anchoring the Merkle tree root.
    pub ub: Uberblock,
    /// Number of the currently active open transaction group.
    pub open_txg: u64,
    dnodes: BTreeMap<u64, DnodePhys>,
    dirty_dnodes: BTreeSet<u64>,
    dirty_data: BTreeMap<(u64, u64), PhysFrame<Size4KiB>>,
    truncated: BTreeMap<u64, u64>,
    freed_trees: Vec<DnodePhys>,
}

impl Dmu {
    /// Wraps an opened or freshly created pool.
    ///
    /// # Arguments
    /// * `spa` - Storage Pool Allocator instance.
    /// * `ub` - Uberblock anchoring the object set.
    ///
    /// # Returns
    /// Initialized [`Dmu`] instance.
    pub fn new(spa: Spa, ub: Uberblock) -> Self {
        Self {
            open_txg: ub.txg + 1,
            spa,
            ub,
            dnodes: BTreeMap::new(),
            dirty_dnodes: BTreeSet::new(),
            dirty_data: BTreeMap::new(),
            truncated: BTreeMap::new(),
            freed_trees: Vec::new(),
        }
    }

    /// An empty uberblock for a new pool (txg 0, no objects).
    ///
    /// # Returns
    /// Initialized [`Uberblock`] with default empty meta dnode.
    pub fn initial_uberblock() -> Uberblock {
        let mut meta = DnodePhys::empty();
        meta.obj_type = DnodeType::MasterNode as u8;
        Uberblock {
            magic: ZFS_UBERBLOCK_MAGIC,
            version: POOL_VERSION,
            txg: 0,
            timestamp: 0,
            meta_dnode: meta,
            next_obj: 1,
            free_obj_head: 0,
            root_obj: 0,
            datasets_obj: 0,
            allocated_blocks: 0,
            snapshot_txg: 0,
            checksum: Fletcher4::default(),
        }
    }

    // ------------------------------------------------------------------
    // Dnodes
    // ------------------------------------------------------------------

    /// Returns a copy of an object's dnode.
    ///
    /// # Arguments
    /// * `obj` - Object ID to query.
    ///
    /// # Returns
    /// Object's [`DnodePhys`] record on success.
    ///
    /// # Errors
    /// DMU error string if object does not exist.
    pub fn get_dnode(&mut self, obj: u64) -> DmuResult<DnodePhys> {
        if obj == 0 {
            return Ok(self.ub.meta_dnode);
        }
        if let Some(dn) = self.dnodes.get(&obj) {
            return Ok(*dn);
        }
        if obj >= self.ub.next_obj {
            return Err("ZFS: no such object");
        }
        let mut raw = [0u8; DNODE_SIZE];
        self.read(0, obj * DNODE_SIZE as u64, &mut raw)?;
        let dn = DnodePhys::from_bytes(&raw);
        if self.dnodes.len() >= DNODE_CACHE_LIMIT {
            let dirty = &self.dirty_dnodes;
            self.dnodes.retain(|k, _| dirty.contains(k));
        }
        self.dnodes.insert(obj, dn);
        Ok(dn)
    }

    /// Updates an object's dnode (written to disk at the next commit).
    ///
    /// # Arguments
    /// * `obj` - Object ID to update.
    /// * `dn` - New dnode record.
    pub fn put_dnode(&mut self, obj: u64, dn: DnodePhys) {
        if obj == 0 {
            self.ub.meta_dnode = dn;
        } else {
            self.dnodes.insert(obj, dn);
            self.dirty_dnodes.insert(obj);
        }
    }

    /// Allocates a new object number with an empty dnode of the given mode.
    ///
    /// # Arguments
    /// * `mode` - File mode and type bits.
    ///
    /// # Returns
    /// Allocated object ID on success.
    ///
    /// # Errors
    /// DMU error string on allocation failure.
    pub fn alloc_object(&mut self, mode: u32) -> DmuResult<u64> {
        let (obj, generation) = if self.ub.free_obj_head != 0 {
            let obj = self.ub.free_obj_head;
            let old = self.get_dnode(obj)?;
            self.ub.free_obj_head = old.next_free;
            (obj, old.generation + 1)
        } else {
            let obj = self.ub.next_obj;
            self.ub.next_obj += 1;
            (obj, 1)
        };
        let mut dn = DnodePhys::empty();
        dn.mode = mode;
        dn.obj_type = DnodeType::from_mode(mode) as u8;
        dn.generation = generation;
        dn.birth_txg = self.open_txg;
        self.put_dnode(obj, dn);
        Ok(obj)
    }

    /// Frees an object and (at the next commit) all of its blocks.
    ///
    /// # Arguments
    /// * `obj` - Object ID to free.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string if object does not exist.
    pub fn free_object(&mut self, obj: u64) -> DmuResult<()> {
        let old = self.get_dnode(obj)?;
        self.freed_trees.push(old);
        self.truncated.remove(&obj);
        self.drop_dirty_from(obj, 0);
        let mut dn = DnodePhys::empty();
        dn.generation = old.generation;
        dn.next_free = self.ub.free_obj_head;
        self.ub.free_obj_head = obj;
        self.put_dnode(obj, dn);
        Ok(())
    }

    /// Discards cached dirty frames belonging to `obj` starting at `first_blkid`.
    ///
    /// # Arguments
    /// * `obj` - Object ID.
    /// * `first_blkid` - Starting block index to discard.
    fn drop_dirty_from(&mut self, obj: u64, first_blkid: u64) {
        let keys: Vec<(u64, u64)> = self.dirty_data.range((obj, first_blkid)..=(obj, u64::MAX)).map(|(&k, _)| k).collect();
        for k in keys {
            if let Some(frame) = self.dirty_data.remove(&k) {
                frame_ref_dec(frame);
            }
        }
    }

    // ------------------------------------------------------------------
    // Reading
    // ------------------------------------------------------------------

    /// Finds the committed block pointer for leaf `blkid`.
    ///
    /// # Arguments
    /// * `dn` - Dnode representing the object.
    /// * `blkid` - Leaf block index.
    ///
    /// # Returns
    /// [`BlockPointer`] for the block, or [`BlockPointer::HOLE`].
    ///
    /// # Errors
    /// DMU error string on read failure.
    fn lookup_bp(&mut self, dn: &DnodePhys, blkid: u64) -> DmuResult<BlockPointer> {
        let levels = dn.nlevels.max(1) as u32;
        let top = blkid / pow64(levels - 1);
        if top >= DN_TOP_PTRS as u64 {
            return Ok(BlockPointer::HOLE);
        }
        let mut bp = dn.blkptr[top as usize];
        for level in (1..levels).rev() {
            if bp.is_hole() {
                return Ok(bp);
            }
            let frame = self.spa.read_bp(&bp)?;
            let idx = ((blkid / pow64(level - 1)) % BP_PER_BLOCK as u64) as usize;
            bp = unsafe { *(frame.start_address().as_u64() as *const BlockPointer).add(idx) };
        }
        Ok(bp)
    }

    /// Reads leaf block `blkid` of `obj` into `out`. Holes read as zeroes.
    ///
    /// # Arguments
    /// * `obj` - Object ID.
    /// * `dn` - Object dnode.
    /// * `blkid` - Block index to read.
    /// * `out` - Destination 4 KiB block buffer.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on read failure.
    fn read_block(&mut self, obj: u64, dn: &DnodePhys, blkid: u64, out: &mut [u8; ZFS_BLOCK_SIZE]) -> DmuResult<()> {
        if let Some(&frame) = self.dirty_data.get(&(obj, blkid)) {
            out.copy_from_slice(frame_bytes(frame));
            return Ok(());
        }
        if self.truncated.get(&obj).map_or(false, |&t| blkid >= t) {
            out.fill(0);
            return Ok(());
        }
        let bp = self.lookup_bp(dn, blkid)?;
        if bp.is_hole() {
            out.fill(0);
        } else {
            let frame = self.spa.read_bp(&bp)?;
            out.copy_from_slice(frame_bytes(frame));
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes at `offset`, bounded by the object size.
    ///
    /// # Arguments
    /// * `obj` - Object ID.
    /// * `offset` - Byte offset within object.
    /// * `buf` - Destination byte buffer.
    ///
    /// # Returns
    /// Number of bytes read on success.
    ///
    /// # Errors
    /// DMU error string on read failure.
    pub fn read(&mut self, obj: u64, offset: u64, buf: &mut [u8]) -> DmuResult<usize> {
        let dn = self.get_dnode(obj)?;
        if offset >= dn.size {
            return Ok(0);
        }
        let total = (buf.len() as u64).min(dn.size - offset) as usize;
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        let mut done = 0;
        while done < total {
            let pos = offset + done as u64;
            let in_block = (pos % BLOCK) as usize;
            let n = (ZFS_BLOCK_SIZE - in_block).min(total - done);
            self.read_block(obj, &dn, pos / BLOCK, &mut block)?;
            buf[done..done + n].copy_from_slice(&block[in_block..in_block + n]);
            done += n;
        }
        Ok(total)
    }

    // ------------------------------------------------------------------
    // Writing
    // ------------------------------------------------------------------

    /// Writes `data` at `offset`, growing the object if needed.
    ///
    /// # Arguments
    /// * `obj` - Object ID.
    /// * `offset` - Byte offset within object.
    /// * `data` - Source data slice.
    ///
    /// # Returns
    /// Number of bytes written on success.
    ///
    /// # Errors
    /// DMU error string on write or allocation failure.
    pub fn write(&mut self, obj: u64, offset: u64, data: &[u8]) -> DmuResult<usize> {
        let mut dn = self.get_dnode(obj)?;
        let mut done = 0;
        while done < data.len() {
            let pos = offset + done as u64;
            let blkid = pos / BLOCK;
            let in_block = (pos % BLOCK) as usize;
            let n = (ZFS_BLOCK_SIZE - in_block).min(data.len() - done);
            let frame = match self.dirty_data.get(&(obj, blkid)) {
                Some(&f) => f,
                None => {
                    let f = alloc_user_frame().ok_or("ZFS: out of memory for dirty data")?;
                    if n < ZFS_BLOCK_SIZE && blkid * BLOCK < dn.size {
                        let mut old = [0u8; ZFS_BLOCK_SIZE];
                        self.read_block(obj, &dn, blkid, &mut old)?;
                        frame_bytes(f).copy_from_slice(&old);
                    }
                    self.dirty_data.insert((obj, blkid), f);
                    f
                }
            };
            frame_bytes(frame)[in_block..in_block + n].copy_from_slice(&data[done..done + n]);
            done += n;
        }
        let end = offset + data.len() as u64;
        if end > dn.size {
            dn.size = end;
        }
        self.put_dnode(obj, dn);
        Ok(data.len())
    }

    /// Sets the object size, discarding data past the new end.
    ///
    /// # Arguments
    /// * `obj` - Object ID.
    /// * `new_size` - New size in bytes.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on failure.
    pub fn truncate(&mut self, obj: u64, new_size: u64) -> DmuResult<()> {
        let mut dn = self.get_dnode(obj)?;
        if new_size < dn.size {
            let first_gone = (new_size + BLOCK - 1) / BLOCK;
            self.drop_dirty_from(obj, first_gone);
            let t = self.truncated.entry(obj).or_insert(first_gone);
            *t = (*t).min(first_gone);
            // Zero the tail of a partially kept last block
            let tail = (new_size % BLOCK) as usize;
            if tail != 0 {
                let zeros = [0u8; ZFS_BLOCK_SIZE];
                let keep = dn.size;
                self.write(obj, new_size, &zeros[..ZFS_BLOCK_SIZE - tail])?;
                dn = self.get_dnode(obj)?;
                dn.size = keep;
            }
        }
        dn.size = new_size;
        self.put_dnode(obj, dn);
        Ok(())
    }

    /// Drops clean cached dnodes and all cached blocks (for verification and low memory).
    pub fn drop_caches(&mut self) {
        let dirty = &self.dirty_dnodes;
        self.dnodes.retain(|k, _| dirty.contains(k));
        self.spa.cache.clear();
    }

    /// Number of dirty blocks waiting for the next commit.
    ///
    /// # Returns
    /// Count of pending uncommitted dirty data blocks.
    pub fn dirty_blocks(&self) -> usize {
        self.dirty_data.len()
    }

    /// Returns true if uncommitted dirty blocks, dnodes, or truncations are pending commit.
    ///
    /// # Returns
    /// `true` if dirty changes exist, `false` otherwise.
    pub fn has_pending_changes(&self) -> bool {
        !self.dirty_data.is_empty() || !self.dirty_dnodes.is_empty() || !self.truncated.is_empty() || !self.freed_trees.is_empty()
    }

    // ------------------------------------------------------------------
    // Commit
    // ------------------------------------------------------------------

    /// Frees the physical block referenced by `bp` unless protected by a snapshot.
    ///
    /// # Arguments
    /// * `bp` - Block pointer to release.
    fn free_bp(&mut self, bp: &BlockPointer) {
        if bp.is_hole() {
            return;
        }
        if self.ub.snapshot_txg != 0 && bp.birth_txg <= self.ub.snapshot_txg {
            return; // still referenced by a snapshot
        }
        self.spa.free_deferred(bp.block);
    }

    /// Recursively frees all blocks in the indirect subtree rooted at `bp`.
    ///
    /// # Arguments
    /// * `bp` - Root block pointer of subtree.
    /// * `level` - Tree height level of the root.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on read failure.
    fn free_subtree(&mut self, bp: BlockPointer, level: u32) -> DmuResult<()> {
        if bp.is_hole() {
            return Ok(());
        }
        if level > 0 {
            // An unreadable (damaged) indirect block: the blocks below it cannot be found,
            // so they stay allocated (leaked, as ZFS does) rather than the commit failing
            let entries = match self.spa.read_bp(&bp) {
                Ok(frame) => read_indirect(frame),
                Err(e) => {
                    crate::println!("[zfs] freeing an object: indirect block {} unreadable ({}); the blocks below it are leaked", bp.block, e);
                    self.free_bp(&bp);
                    return Ok(());
                }
            };
            for e in entries.iter() {
                self.free_subtree(*e, level - 1)?;
            }
        }
        self.free_bp(&bp);
        Ok(())
    }

    /// Block pointer of the tree node at (`level`, `idx`), honouring dirty indirects.
    ///
    /// # Arguments
    /// * `dn` - Object dnode.
    /// * `ind` - Map of in-memory dirty indirect blocks.
    /// * `level` - Node level.
    /// * `idx` - Block pointer index.
    ///
    /// # Returns
    /// Resolved [`BlockPointer`] on success.
    ///
    /// # Errors
    /// DMU error string on read failure.
    fn get_entry(&mut self, dn: &DnodePhys, ind: &BTreeMap<(u32, u64), Box<Indirect>>, level: u32, idx: u64) -> DmuResult<BlockPointer> {
        let top_level = dn.nlevels as u32 - 1;
        if level == top_level {
            return Ok(if idx < DN_TOP_PTRS as u64 { dn.blkptr[idx as usize] } else { BlockPointer::HOLE });
        }
        let parent = (level + 1, idx / BP_PER_BLOCK as u64);
        let slot = (idx % BP_PER_BLOCK as u64) as usize;
        if let Some(entries) = ind.get(&parent) {
            return Ok(entries[slot]);
        }
        let pbp = self.get_entry(dn, ind, parent.0, parent.1)?;
        if pbp.is_hole() {
            return Ok(BlockPointer::HOLE);
        }
        let frame = self.spa.read_bp(&pbp)?;
        Ok(unsafe { *(frame.start_address().as_u64() as *const BlockPointer).add(slot) })
    }

    /// Loads indirect block (`level`, `idx`) into the dirty set for modification.
    ///
    /// # Arguments
    /// * `dn` - Object dnode.
    /// * `ind` - Map of in-memory dirty indirect blocks.
    /// * `level` - Node level.
    /// * `idx` - Block index at this level.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on read failure.
    fn load_indirect(&mut self, dn: &DnodePhys, ind: &mut BTreeMap<(u32, u64), Box<Indirect>>, level: u32, idx: u64) -> DmuResult<()> {
        if ind.contains_key(&(level, idx)) {
            return Ok(());
        }
        let bp = self.get_entry(dn, ind, level, idx)?;
        let entries = if bp.is_hole() {
            Box::new([BlockPointer::HOLE; BP_PER_BLOCK])
        } else {
            read_indirect(self.spa.read_bp(&bp)?)
        };
        ind.insert((level, idx), entries);
        Ok(())
    }

    /// Points tree slot (`level`, `idx`) at `bp`, freeing what it pointed to before.
    ///
    /// # Arguments
    /// * `dn` - Object dnode.
    /// * `ind` - Map of in-memory dirty indirect blocks.
    /// * `level` - Node level.
    /// * `idx` - Slot index.
    /// * `bp` - New block pointer to store.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on failure.
    fn set_entry(&mut self, dn: &mut DnodePhys, ind: &mut BTreeMap<(u32, u64), Box<Indirect>>, level: u32, idx: u64, bp: BlockPointer) -> DmuResult<()> {
        let top_level = dn.nlevels as u32 - 1;
        let old = if level == top_level {
            core::mem::replace(&mut dn.blkptr[idx as usize], bp)
        } else {
            let parent = (level + 1, idx / BP_PER_BLOCK as u64);
            self.load_indirect(dn, ind, parent.0, parent.1)?;
            let entries = ind.get_mut(&parent).unwrap();
            core::mem::replace(&mut entries[(idx % BP_PER_BLOCK as u64) as usize], bp)
        };
        if old != bp {
            self.free_bp(&old);
        }
        Ok(())
    }

    /// Frees every leaf at or past `first` in the subtree rooted at (`level`, `idx`).
    ///
    /// # Arguments
    /// * `dn` - Object dnode.
    /// * `ind` - Map of in-memory dirty indirect blocks.
    /// * `level` - Current node level.
    /// * `idx` - Current node index.
    /// * `first` - First leaf block index to truncate.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on failure.
    fn trunc_node(&mut self, dn: &mut DnodePhys, ind: &mut BTreeMap<(u32, u64), Box<Indirect>>, level: u32, idx: u64, first: u64) -> DmuResult<()> {
        let span = pow64(level);
        let start = idx * span;
        if start + span <= first {
            return Ok(());
        }
        if start >= first || level == 0 {
            let bp = self.get_entry(dn, ind, level, idx)?;
            if !bp.is_hole() {
                self.free_subtree(bp, level)?;
                // The subtree is gone; clear the slot without freeing the root twice
                let top_level = dn.nlevels as u32 - 1;
                if level == top_level {
                    dn.blkptr[idx as usize] = BlockPointer::HOLE;
                } else {
                    let parent = (level + 1, idx / BP_PER_BLOCK as u64);
                    self.load_indirect(dn, ind, parent.0, parent.1)?;
                    ind.get_mut(&parent).unwrap()[(idx % BP_PER_BLOCK as u64) as usize] = BlockPointer::HOLE;
                }
            }
            return Ok(());
        }
        // Partially truncated indirect: recurse into its children
        if self.get_entry(dn, ind, level, idx)?.is_hole() && !ind.contains_key(&(level, idx)) {
            return Ok(());
        }
        self.load_indirect(dn, ind, level, idx)?;
        for child in 0..BP_PER_BLOCK as u64 {
            self.trunc_node(dn, ind, level - 1, idx * BP_PER_BLOCK as u64 + child, first)?;
        }
        Ok(())
    }

    /// Writes all dirty state of one object into fresh blocks and updates its dnode.
    ///
    /// # Arguments
    /// * `obj` - Object ID being committed.
    /// * `dn` - Mutable reference to object's dnode.
    /// * `txg` - Committing transaction group number.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// DMU error string on write or allocation failure.
    fn commit_tree(&mut self, obj: u64, dn: &mut DnodePhys, txg: u64) -> DmuResult<()> {
        let mut ind: BTreeMap<(u32, u64), Box<Indirect>> = BTreeMap::new();
        let mut writes: Vec<(u64, PhysFrame<Size4KiB>)> = Vec::new();
        let mut owned_frames: Vec<PhysFrame<Size4KiB>> = Vec::new();

        if let Some(first) = self.truncated.remove(&obj) {
            let top_level = dn.nlevels as u32 - 1;
            for top in 0..DN_TOP_PTRS as u64 {
                self.trunc_node(dn, &mut ind, top_level, top, first)?;
            }
        }

        let keys: Vec<(u64, u64)> = self.dirty_data.range((obj, 0)..=(obj, u64::MAX)).map(|(&k, _)| k).collect();
        let leaves: Vec<(u64, PhysFrame<Size4KiB>)> = keys
            .iter()
            .map(|k| (k.1, self.dirty_data.remove(k).unwrap()))
            .collect();

        if let Some(&(max_blkid, _)) = leaves.last() {
            while capacity(dn.nlevels) <= max_blkid {
                // Grow: the old top pointers become the first entries of a new root indirect
                let new_level = dn.nlevels as u32;
                let mut entries = Box::new([BlockPointer::HOLE; BP_PER_BLOCK]);
                entries[..DN_TOP_PTRS].copy_from_slice(&dn.blkptr);
                ind.insert((new_level, 0), entries);
                dn.blkptr = [BlockPointer::HOLE; DN_TOP_PTRS];
                dn.nlevels += 1;
            }
        }

        for (blkid, frame) in leaves {
            let block = self.spa.alloc()?;
            let bp = BlockPointer {
                block,
                birth_txg: txg,
                checksum: Fletcher4::compute(frame_bytes(frame)),
                lsize: ZFS_BLOCK_SIZE as u32,
                level: 0,
                ..BlockPointer::HOLE
            };
            self.set_entry(dn, &mut ind, 0, blkid, bp)?;
            writes.push((block, frame));
            owned_frames.push(frame);
        }

        for level in 1..dn.nlevels as u32 {
            let keys: Vec<u64> = ind.range((level, 0)..=(level, u64::MAX)).map(|(&(_, i), _)| i).collect();
            for idx in keys {
                let entries = ind.remove(&(level, idx)).unwrap();
                let bp = if entries.iter().all(|e| e.is_hole()) {
                    BlockPointer::HOLE
                } else {
                    let frame = alloc_user_frame().ok_or("ZFS: out of memory during commit")?;
                    unsafe {
                        core::ptr::copy_nonoverlapping(entries.as_ptr() as *const u8, frame.start_address().as_u64() as *mut u8, ZFS_BLOCK_SIZE);
                    }
                    let block = self.spa.alloc()?;
                    writes.push((block, frame));
                    owned_frames.push(frame);
                    BlockPointer {
                        block,
                        birth_txg: txg,
                        checksum: Fletcher4::compute(frame_bytes(frame)),
                        lsize: ZFS_BLOCK_SIZE as u32,
                        level: level as u8,
                        ..BlockPointer::HOLE
                    }
                };
                self.set_entry(dn, &mut ind, level, idx, bp)?;
            }
        }

        let result = self.spa.write_blocks(writes);
        for frame in owned_frames {
            frame_ref_dec(frame);
        }
        result
    }

    /// Commits the open transaction group. Returns the committed txg.
    ///
    /// # Returns
    /// Committed transaction group number on success.
    ///
    /// # Errors
    /// DMU error string on commit failure.
    pub fn sync(&mut self) -> DmuResult<u64> {
        if !self.has_pending_changes() {
            return Ok(self.ub.txg);
        }
        let txg = self.open_txg;

        for dn in core::mem::take(&mut self.freed_trees) {
            for top in 0..DN_TOP_PTRS {
                self.free_subtree(dn.blkptr[top], dn.nlevels as u32 - 1)?;
            }
        }

        let mut objs: BTreeSet<u64> = self.dirty_dnodes.iter().copied().collect();
        objs.extend(self.dirty_data.keys().map(|k| k.0));
        objs.extend(self.truncated.keys().copied());
        objs.remove(&0);

        for obj in objs {
            let mut dn = self.get_dnode(obj)?;
            self.commit_tree(obj, &mut dn, txg)?;
            self.dnodes.insert(obj, dn);
            self.write(0, obj * DNODE_SIZE as u64, &dn.to_bytes())?;
        }
        self.dirty_dnodes.clear();

        let mut meta = self.ub.meta_dnode;
        self.commit_tree(0, &mut meta, txg)?;
        self.ub.meta_dnode = meta;

        let mut ub = self.ub;
        ub.txg = txg;
        ub.timestamp = crate::arch::rtc::now().0;
        self.spa.commit(&mut ub)?;
        self.ub = ub;
        self.open_txg = txg + 1;
        Ok(txg)
    }
}
