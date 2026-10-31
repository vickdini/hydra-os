//! # Storage Pool Allocator (SPA)
//!
//! ## Subsystem Role & Architecture
//! The Storage Pool Allocator (SPA) is the bottom layer of Hydra's OpenZFS implementation.
//! It abstracts physical storage into a virtual device ([`Vdev`]), manages block allocation
//! via a persistent space bitmap, maintains an in-memory physical frame cache ([`BlockCache`]),
//! and controls the uberblock ring for atomic commit semantics.
//!
//! ## Crash Consistency & Transaction Groups
//! Blocks freed in transaction group N are still referenced by uberblock N-1, so they are
//! only returned to the allocator after uberblock N is on disk, and only reach the on-disk
//! bitmap in the commit of txg N+1. A crash can therefore leak blocks allocated by an
//! unfinished commit, but never hands out a block the last valid uberblock still uses.
//!
//! ## Key Types & Interfaces
//! - [`Vdev`]: Abstraction over ATA drive or contiguous RAM disk backend.
//! - [`BlockCache`]: LRU physical frame cache avoiding redundant device read cycles.
//! - [`Spa`]: Storage Pool Allocator controlling allocation cursors, bitmaps, and labels.
//! - [`DiskContents`]: Detection state for disk inspection prior to pool import.
//!
//! ## Concurrency & Hardware Semantics
//! All disk I/O synchronizes against underlying ATA controller locks or atomic frame
//! refcounts. Allocations and frees are staged in transaction groups and committed atomically.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::types::{Fletcher4, Uberblock, VdevLabel, BlockPointer, UBERBLOCK_RING, ZFS_BLOCK_SIZE};
use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec, FRAME_ALLOCATOR};

/// Logical block size in bytes for SPA allocations (4 KiB).
pub const BLOCK: u64 = ZFS_BLOCK_SIZE as u64;
const SECTORS_PER_BLOCK: u64 = BLOCK / crate::arch::ata::ATA_SECTOR_SIZE as u64;
/// Largest number of blocks moved in one ATA command (255 sectors / 8 per block).
const MAX_RUN: usize = 31;
/// Size of the RAM-backed pool used when no ATA disk is present.
const RAM_POOL_BYTES: u64 = 64 * 1024 * 1024;
/// Default cap on cached blocks (128 MiB of frames).
const CACHE_BLOCKS: usize = 32 * 1024;

/// Returns the 4 KiB contents of a frame through the identity map.
pub fn frame_bytes(frame: PhysFrame<Size4KiB>) -> &'static mut [u8; ZFS_BLOCK_SIZE] {
    unsafe { &mut *(frame.start_address().as_u64() as *mut [u8; ZFS_BLOCK_SIZE]) }
}

enum Backend {
    Ata,
    Ram(*mut u8),
}

/// The block device under the pool.
pub struct Vdev {
    backend: Backend,
    /// Total addressable 4 KiB logical blocks on this virtual device.
    pub total_blocks: u64,
}

unsafe impl Send for Vdev {}

impl Vdev {
    /// Opens the primary ATA disk, or a RAM disk if none is attached.
    pub fn open() -> Self {
        if crate::arch::ata::is_drive_present() {
            let sectors = crate::arch::ata::PRIMARY_ATA.lock().as_ref().map_or(0, |d| d.total_sectors());
            if sectors >= SECTORS_PER_BLOCK * 64 {
                return Self {
                    backend: Backend::Ata,
                    total_blocks: sectors / SECTORS_PER_BLOCK,
                };
            }
        }
        let pages = (RAM_POOL_BYTES / BLOCK) as usize;
        let base = FRAME_ALLOCATOR
            .lock()
            .allocate_contiguous_frames(pages)
            .map(|f| f.start_address().as_u64() as *mut u8)
            .unwrap_or(core::ptr::null_mut());
        if !base.is_null() {
            unsafe { core::ptr::write_bytes(base, 0, RAM_POOL_BYTES as usize) };
        }
        Self {
            backend: Backend::Ram(base),
            total_blocks: if base.is_null() { 0 } else { RAM_POOL_BYTES / BLOCK },
        }
    }

    /// Returns true if this virtual device is backed by physical hardware (ATA disk) rather than RAM.
    pub fn is_hardware_backed(&self) -> bool {
        matches!(self.backend, Backend::Ata)
    }

    /// Reads `count` consecutive blocks starting at `block` into `buf`.
    pub fn read(&self, block: u64, buf: &mut [u8]) -> Result<(), &'static str> {
        let count = buf.len() / ZFS_BLOCK_SIZE;
        if block + count as u64 > self.total_blocks {
            return Err("ZFS: block read past end of vdev");
        }
        match self.backend {
            Backend::Ram(base) => unsafe {
                core::ptr::copy_nonoverlapping(base.add((block * BLOCK) as usize), buf.as_mut_ptr(), buf.len());
                Ok(())
            },
            Backend::Ata => {
                let mut guard = crate::arch::ata::PRIMARY_ATA.lock();
                let dev = guard.as_mut().ok_or("ZFS: ATA disk vanished")?;
                for (i, chunk) in buf.chunks_mut(ZFS_BLOCK_SIZE * MAX_RUN).enumerate() {
                    let lba = (block + (i * MAX_RUN) as u64) * SECTORS_PER_BLOCK;
                    let sectors = (chunk.len() / crate::arch::ata::ATA_SECTOR_SIZE) as u8;
                    dev.read_sectors(lba, sectors, chunk)?;
                }
                Ok(())
            }
        }
    }

    /// Writes `buf` (a whole number of blocks) starting at `block`.
    pub fn write(&mut self, block: u64, buf: &[u8]) -> Result<(), &'static str> {
        let count = buf.len() / ZFS_BLOCK_SIZE;
        if block + count as u64 > self.total_blocks {
            return Err("ZFS: block write past end of vdev");
        }
        match self.backend {
            Backend::Ram(base) => unsafe {
                core::ptr::copy_nonoverlapping(buf.as_ptr(), base.add((block * BLOCK) as usize), buf.len());
                Ok(())
            },
            Backend::Ata => {
                let mut guard = crate::arch::ata::PRIMARY_ATA.lock();
                let dev = guard.as_mut().ok_or("ZFS: ATA disk vanished")?;
                for (i, chunk) in buf.chunks(ZFS_BLOCK_SIZE * MAX_RUN).enumerate() {
                    let lba = (block + (i * MAX_RUN) as u64) * SECTORS_PER_BLOCK;
                    let sectors = (chunk.len() / crate::arch::ata::ATA_SECTOR_SIZE) as u8;
                    dev.write_sectors(lba, sectors, chunk)?;
                }
                Ok(())
            }
        }
    }

    /// Flushes hardware write caches to non-volatile storage.
    ///
    /// # Errors
    /// Returns an error if the underlying ATA controller command fails.
    pub fn flush(&mut self) -> Result<(), &'static str> {
        if let Backend::Ata = self.backend {
            if let Some(dev) = crate::arch::ata::PRIMARY_ATA.lock().as_mut() {
                dev.flush()?;
            }
        }
        Ok(())
    }
}

struct CacheEntry {
    frame: PhysFrame<Size4KiB>,
    last_use: u64,
}

/// Bounded cache of on-disk blocks, stored in physical frames.
pub struct BlockCache {
    map: BTreeMap<u64, CacheEntry>,
    clock: u64,
    capacity: usize,
    /// Number of successful block cache lookups.
    pub hits: u64,
    /// Number of cache lookup misses requiring disk reads.
    pub misses: u64,
}

impl BlockCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            clock: 0,
            capacity,
            hits: 0,
            misses: 0,
        }
    }

    fn get(&mut self, block: u64) -> Option<PhysFrame<Size4KiB>> {
        self.clock += 1;
        let clock = self.clock;
        self.map.get_mut(&block).map(|e| {
            e.last_use = clock;
            e.frame
        })
    }

    /// Stores a copy of `data` for `block`.
    fn put(&mut self, block: u64, data: &[u8; ZFS_BLOCK_SIZE]) {
        self.clock += 1;
        if let Some(e) = self.map.get_mut(&block) {
            frame_bytes(e.frame).copy_from_slice(data);
            e.last_use = self.clock;
            return;
        }
        if self.map.len() >= self.capacity {
            self.evict();
        }
        if let Some(frame) = alloc_user_frame() {
            frame_bytes(frame).copy_from_slice(data);
            self.map.insert(block, CacheEntry { frame, last_use: self.clock });
        }
    }

    /// Drops the least recently used eighth of the cache.
    fn evict(&mut self) {
        let mut ages: Vec<u64> = self.map.values().map(|e| e.last_use).collect();
        ages.sort_unstable();
        let cutoff = ages[ages.len() / 8];
        let victims: Vec<u64> = self.map.iter().filter(|(_, e)| e.last_use <= cutoff).map(|(&k, _)| k).collect();
        for k in victims {
            if let Some(e) = self.map.remove(&k) {
                frame_ref_dec(e.frame);
            }
        }
    }

    fn invalidate(&mut self, block: u64) {
        if let Some(e) = self.map.remove(&block) {
            frame_ref_dec(e.frame);
        }
    }

    /// Returns the number of blocks currently held in the block cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Discards every cached block (forces later reads to come from the device).
    pub fn clear(&mut self) {
        for (_, e) in core::mem::take(&mut self.map) {
            frame_ref_dec(e.frame);
        }
    }
}

/// What a device holds before import ([`Spa::probe`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DiskContents {
    /// Disk appears completely zeroed or unpartitioned.
    Blank,
    /// Disk contains a valid OpenZFS pool label.
    Pool,
    /// Disk contains foreign signatures or unsupported filesystem formats.
    Other,
}

/// Storage Pool Allocator.
pub struct Spa {
    /// Virtual block device providing raw storage.
    pub vdev: Vdev,
    /// On-disk pool configuration label.
    pub label: VdevLabel,
    /// In-memory cache of clean and dirty block frames.
    pub cache: BlockCache,
    bitmap: Vec<u64>,
    dirty_bitmap_blocks: BTreeMap<u64, ()>,
    pending_free: Vec<u64>,
    alloc_cursor: u64,
    /// Total count of blocks currently allocated in the space bitmap.
    pub allocated_blocks: u64,
    /// Human-readable pool name as a fixed-length null-padded byte array.
    pub pool_name: [u8; 32],
}

impl Spa {
    fn empty(vdev: Vdev, label: VdevLabel) -> Self {
        let words = ((label.total_blocks + 63) / 64) as usize;
        Self {
            vdev,
            label,
            cache: BlockCache::new(CACHE_BLOCKS),
            bitmap: alloc::vec![0u64; words],
            dirty_bitmap_blocks: BTreeMap::new(),
            pending_free: Vec::new(),
            alloc_cursor: label.data_start,
            allocated_blocks: 0,
            pool_name: label.pool_name,
        }
    }

    /// Lays out a brand-new pool on `vdev`. The caller commits the first uberblock.
    pub fn create(mut vdev: Vdev, name: &str) -> Result<Self, &'static str> {
        let total = vdev.total_blocks;
        if total < 256 {
            return Err("ZFS: device too small for a pool");
        }
        let bitmap_blocks = (total + BLOCK * 8 - 1) / (BLOCK * 8);
        let mut pool_name = [0u8; 32];
        let n = name.len().min(31);
        pool_name[..n].copy_from_slice(&name.as_bytes()[..n]);
        let mut label = VdevLabel {
            magic: super::types::VDEV_LABEL_MAGIC,
            version: super::types::POOL_VERSION,
            pool_guid: unsafe { core::arch::x86_64::_rdtsc() } ^ 0x4859_4452_4150_4f4f,
            total_blocks: total,
            bitmap_start: 1 + UBERBLOCK_RING,
            bitmap_blocks,
            ub_start: 1,
            ub_count: UBERBLOCK_RING,
            data_start: 1 + UBERBLOCK_RING + bitmap_blocks,
            pool_name,
            checksum: Fletcher4::default(),
        };
        label.seal();

        // Write the label and clear the uberblock ring and bitmap region
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(&label as *const VdevLabel as *const u8, block.as_mut_ptr(), core::mem::size_of::<VdevLabel>());
        }
        vdev.write(0, &block)?;
        let zeros = alloc::vec![0u8; ZFS_BLOCK_SIZE * MAX_RUN];
        let mut b = 1;
        while b < label.data_start {
            let n = ((label.data_start - b) as usize).min(MAX_RUN);
            vdev.write(b, &zeros[..n * ZFS_BLOCK_SIZE])?;
            b += n as u64;
        }

        let mut spa = Self::empty(vdev, label);
        for blk in 0..label.data_start {
            spa.mark(blk, true);
        }
        spa.allocated_blocks = label.data_start;
        spa.fence_tail();
        Ok(spa)
    }

    /// Probes block 0 of a device to determine its contents: nothing (all zeros), a pool
    /// label, or foreign data. Read errors are retried; returns `None` if device read fails.
    pub fn probe(vdev: &Vdev) -> Option<DiskContents> {
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        for _ in 0..3 {
            if vdev.read(0, &mut block).is_ok() {
                if block.iter().all(|&b| b == 0) {
                    return Some(DiskContents::Blank);
                }
                let label: VdevLabel = unsafe { core::ptr::read_unaligned(block.as_ptr() as *const VdevLabel) };
                return Some(if label.magic == super::types::VDEV_LABEL_MAGIC { DiskContents::Pool } else { DiskContents::Other });
            }
        }
        None
    }

    /// Opens an existing pool, returning it with its newest valid uberblock, or hands the
    /// device back if it holds no valid pool.
    ///
    /// # Arguments
    /// * `vdev` - Virtual block device to inspect and mount.
    ///
    /// # Returns
    /// Tuple of `(Spa, Uberblock)` on success, or `Err(vdev)` on failure.
    pub fn open(vdev: Vdev) -> Result<(Self, Uberblock), Vdev> {
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        if vdev.read(0, &mut block).is_err() {
            return Err(vdev);
        }
        let label: VdevLabel = unsafe { core::ptr::read_unaligned(block.as_ptr() as *const VdevLabel) };
        if !label.is_valid() || label.total_blocks > vdev.total_blocks {
            return Err(vdev);
        }

        let mut best: Option<Uberblock> = None;
        for slot in 0..label.ub_count {
            if vdev.read(label.ub_start + slot, &mut block).is_err() {
                continue;
            }
            let ub: Uberblock = unsafe { core::ptr::read_unaligned(block.as_ptr() as *const Uberblock) };
            if ub.is_valid() && best.map_or(true, |b| ub.txg > b.txg) {
                best = Some(ub);
            }
        }
        let ub = match best {
            Some(ub) => ub,
            None => return Err(vdev),
        };

        let mut spa = Self::empty(vdev, label);
        let mut buf = alloc::vec![0u8; ZFS_BLOCK_SIZE * MAX_RUN];
        let mut b = 0u64;
        while b < label.bitmap_blocks {
            let n = ((label.bitmap_blocks - b) as usize).min(MAX_RUN);
            if spa.vdev.read(label.bitmap_start + b, &mut buf[..n * ZFS_BLOCK_SIZE]).is_err() {
                return Err(spa.vdev);
            }
            for (i, word) in buf[..n * ZFS_BLOCK_SIZE].chunks_exact(8).enumerate() {
                let idx = (b as usize * ZFS_BLOCK_SIZE / 8) + i;
                if idx < spa.bitmap.len() {
                    spa.bitmap[idx] = u64::from_le_bytes(word.try_into().unwrap());
                }
            }
            b += n as u64;
        }
        let tail = spa.bitmap.len() as u64 * 64 - label.total_blocks;
        spa.fence_tail();
        spa.allocated_blocks = spa.bitmap.iter().map(|w| w.count_ones() as u64).sum::<u64>() - tail;
        Ok((spa, ub))
    }

    fn mark(&mut self, block: u64, used: bool) {
        let (w, bit) = ((block / 64) as usize, block % 64);
        if used {
            self.bitmap[w] |= 1 << bit;
        } else {
            self.bitmap[w] &= !(1 << bit);
        }
        self.dirty_bitmap_blocks.insert(block / (BLOCK * 8), ());
    }

    fn is_used(&self, block: u64) -> bool {
        self.bitmap[(block / 64) as usize] & (1 << (block % 64)) != 0
    }

    /// Allocates one data block, scanning the bitmap a word at a time from the cursor.
    pub fn alloc(&mut self) -> Result<u64, &'static str> {
        let words = self.bitmap.len();
        let start_word = (self.alloc_cursor.max(self.label.data_start) / 64) as usize % words;
        for i in 0..=words {
            let w = (start_word + i) % words;
            let word = self.bitmap[w];
            if word != u64::MAX {
                let b = w as u64 * 64 + (!word).trailing_zeros() as u64;
                self.mark(b, true);
                self.allocated_blocks += 1;
                self.alloc_cursor = b + 1;
                return Ok(b);
            }
        }
        Err("ZFS: pool is out of space")
    }

    /// Marks the bits past the end of the device in the last bitmap word as used so the
    /// allocator never returns them (in memory only; not counted as allocated).
    fn fence_tail(&mut self) {
        let total = self.label.total_blocks;
        if total % 64 != 0 {
            let last = self.bitmap.len() - 1;
            self.bitmap[last] |= !0u64 << (total % 64);
        }
    }

    /// Schedules a block to be freed once the current transaction group is on disk.
    pub fn free_deferred(&mut self, block: u64) {
        if block >= self.label.data_start {
            self.pending_free.push(block);
        }
    }

    /// Reads a block, verifying it against its block pointer, via the cache.
    pub fn read_bp(&mut self, bp: &BlockPointer) -> Result<PhysFrame<Size4KiB>, &'static str> {
        if let Some(frame) = self.cache.get(bp.block) {
            self.cache.hits += 1;
            return Ok(frame);
        }
        self.cache.misses += 1;
        let mut data = [0u8; ZFS_BLOCK_SIZE];
        self.vdev.read(bp.block, &mut data)?;
        if Fletcher4::compute(&data[..bp.lsize as usize]) != bp.checksum {
            return Err("ZFS Checksum verification failed (silent data corruption detected)");
        }
        self.cache.put(bp.block, &data);
        self.cache.get(bp.block).ok_or("ZFS: out of memory for block cache")
    }

    /// Writes a batch of freshly allocated blocks, coalescing consecutive block numbers
    /// into multi-block device writes, and caches them.
    pub fn write_blocks(&mut self, mut blocks: Vec<(u64, PhysFrame<Size4KiB>)>) -> Result<(), &'static str> {
        blocks.sort_unstable_by_key(|(b, _)| *b);
        let mut run: Vec<u8> = Vec::with_capacity(ZFS_BLOCK_SIZE * MAX_RUN);
        let mut i = 0;
        while i < blocks.len() {
            let start = blocks[i].0;
            run.clear();
            let mut n = 0;
            while i < blocks.len() && blocks[i].0 == start + n as u64 && n < MAX_RUN {
                run.extend_from_slice(frame_bytes(blocks[i].1));
                self.cache.put(blocks[i].0, frame_bytes(blocks[i].1));
                i += 1;
                n += 1;
            }
            self.vdev.write(start, &run)?;
        }
        Ok(())
    }

    /// Finishes a transaction group: persists dirty bitmap blocks, writes the uberblock,
    /// then releases blocks freed during the group.
    pub fn commit(&mut self, ub: &mut Uberblock) -> Result<(), &'static str> {
        // Blocks stay dirty until written, so a failed commit is redone by the next one
        let dirty: Vec<u64> = self.dirty_bitmap_blocks.keys().copied().collect();
        for idx in dirty {
            let mut block = [0u8; ZFS_BLOCK_SIZE];
            let first_word = idx as usize * ZFS_BLOCK_SIZE / 8;
            for (i, chunk) in block.chunks_exact_mut(8).enumerate() {
                if let Some(w) = self.bitmap.get(first_word + i) {
                    chunk.copy_from_slice(&w.to_le_bytes());
                }
            }
            self.vdev.write(self.label.bitmap_start + idx, &block)?;
            self.dirty_bitmap_blocks.remove(&idx);
        }
        self.vdev.flush()?;

        ub.allocated_blocks = self.allocated_blocks;
        ub.seal();
        let mut block = [0u8; ZFS_BLOCK_SIZE];
        unsafe {
            core::ptr::copy_nonoverlapping(ub as *const Uberblock as *const u8, block.as_mut_ptr(), core::mem::size_of::<Uberblock>());
        }
        self.vdev.write(self.label.ub_start + ub.txg % self.label.ub_count, &block)?;
        self.vdev.flush()?;

        // The new uberblock is durable: blocks freed in this group may now be reused
        let freed = core::mem::take(&mut self.pending_free);
        for b in freed {
            if b < self.label.total_blocks && self.is_used(b) {
                self.mark(b, false);
                self.allocated_blocks -= 1;
                self.cache.invalidate(b);
            }
        }
        Ok(())
    }

    /// Returns the pool name as a UTF-8 string slice.
    pub fn pool_name_str(&self) -> &str {
        let len = self.pool_name.iter().position(|&b| b == 0).unwrap_or(self.pool_name.len());
        core::str::from_utf8(&self.pool_name[..len]).unwrap_or("hydrapool")
    }

    /// Returns the total capacity of the pool in bytes.
    pub fn total_capacity_bytes(&self) -> u64 {
        self.label.total_blocks * BLOCK
    }

    /// Returns the total number of bytes currently allocated in the pool.
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_blocks * BLOCK
    }

    /// Returns the remaining free space in the pool in bytes.
    pub fn free_bytes(&self) -> u64 {
        self.total_capacity_bytes().saturating_sub(self.allocated_bytes())
    }

    /// Returns true if the pool's virtual device is backed by physical hardware.
    pub fn is_hardware_backed(&self) -> bool {
        self.vdev.is_hardware_backed()
    }
}
