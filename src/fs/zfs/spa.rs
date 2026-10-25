use uefi::boot::{allocate_pages, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::types::{BlockPointer, Fletcher4, Uberblock, ZFS_BLOCK_SIZE};

/// Total storage capacity of the default Hydra ZFS storage pool (32 MiB).
pub const POOL_CAPACITY_BYTES: usize = 32 * 1024 * 1024;
pub const POOL_TOTAL_BLOCKS: usize = POOL_CAPACITY_BYTES / ZFS_BLOCK_SIZE; // 8192 blocks
pub const SECTORS_PER_BLOCK: usize = ZFS_BLOCK_SIZE / crate::arch::ata::ATA_SECTOR_SIZE; // 8 sectors per 4 KiB block

/// Number of system metadata blocks reserved at the start of the pool (Blocks 0..28).
/// - Block 0: VdevLabel & Active Uberblock
/// - Blocks 1..4: Dnode Object Table (64 * 256 bytes = 16 KiB)
/// - Blocks 5..28: Directory ZAP Structures (64 * 1544 bytes = 96 KiB)
pub const RESERVED_METADATA_BLOCKS: usize = 32;

/// Virtual Device (vdev) storage backing the ZFS pool.
/// Operates on physical/virtual ATA hard disks via programmed I/O with automatic
/// write-through caching to an allocated RAM buffer.
pub struct VdevStorage {
    base_ptr: *mut u8,
    _capacity_bytes: usize,
    has_ata: bool,
}

unsafe impl Send for VdevStorage {}
unsafe impl Sync for VdevStorage {}

impl VdevStorage {
    pub fn new() -> Self {
        let pages = (POOL_CAPACITY_BYTES + 4095) / 4096;
        let ptr = match allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages) {
            Ok(p) => p.as_ptr(),
            Err(_) => core::ptr::null_mut(),
        };

        if !ptr.is_null() {
            unsafe {
                core::ptr::write_bytes(ptr, 0, POOL_CAPACITY_BYTES);
            }
        }

        let has_ata = crate::arch::ata::is_drive_present();

        Self {
            base_ptr: ptr,
            _capacity_bytes: POOL_CAPACITY_BYTES,
            has_ata,
        }
    }

    /// Returns true if this vdev is backed by a physical or virtual ATA hard drive.
    pub fn is_hardware_backed(&self) -> bool {
        self.has_ata
    }

    /// Reads a 4 KiB block from the storage device.
    pub fn read_block(&self, block_index: usize, out_buf: &mut [u8]) -> Result<(), &'static str> {
        if block_index >= POOL_TOTAL_BLOCKS {
            return Err("Block index out of bounds");
        }

        // 1. Try reading from physical/virtual ATA hard disk if active
        if self.has_ata {
            let mut ata_guard = crate::arch::ata::PRIMARY_ATA.lock();
            if let Some(ref mut dev) = *ata_guard {
                let start_lba = (block_index as u64) * (SECTORS_PER_BLOCK as u64);
                let mut temp_block = [0u8; ZFS_BLOCK_SIZE];
                if dev.read_sectors(start_lba, SECTORS_PER_BLOCK as u8, &mut temp_block).is_ok() {
                    let copy_len = out_buf.len().min(ZFS_BLOCK_SIZE);
                    out_buf[..copy_len].copy_from_slice(&temp_block[..copy_len]);

                    // Update L1 cache in memory
                    if !self.base_ptr.is_null() {
                        unsafe {
                            let dst = self.base_ptr.add(block_index * ZFS_BLOCK_SIZE);
                            core::ptr::copy_nonoverlapping(temp_block.as_ptr(), dst, ZFS_BLOCK_SIZE);
                        }
                    }
                    return Ok(());
                }
            }
        }

        // 2. Fallback to in-memory backing buffer
        if self.base_ptr.is_null() {
            return Err("Vdev storage uninitialized");
        }
        let offset = block_index * ZFS_BLOCK_SIZE;
        let copy_len = if out_buf.len() < ZFS_BLOCK_SIZE { out_buf.len() } else { ZFS_BLOCK_SIZE };
        unsafe {
            let src = self.base_ptr.add(offset);
            core::ptr::copy_nonoverlapping(src, out_buf.as_mut_ptr(), copy_len);
        }
        Ok(())
    }

    /// Writes a 4 KiB block to the storage device with write-through disk persistence.
    pub fn write_block(&mut self, block_index: usize, in_buf: &[u8]) -> Result<(), &'static str> {
        if block_index >= POOL_TOTAL_BLOCKS {
            return Err("Block index out of bounds");
        }

        // 1. Update in-memory cache
        let copy_len = if in_buf.len() < ZFS_BLOCK_SIZE { in_buf.len() } else { ZFS_BLOCK_SIZE };
        if !self.base_ptr.is_null() {
            let offset = block_index * ZFS_BLOCK_SIZE;
            unsafe {
                let dst = self.base_ptr.add(offset);
                core::ptr::copy_nonoverlapping(in_buf.as_ptr(), dst, copy_len);
                if copy_len < ZFS_BLOCK_SIZE {
                    core::ptr::write_bytes(dst.add(copy_len), 0, ZFS_BLOCK_SIZE - copy_len);
                }
            }
        }

        // 2. Persist to physical/virtual ATA hard disk sectors
        if self.has_ata {
            let mut ata_guard = crate::arch::ata::PRIMARY_ATA.lock();
            if let Some(ref mut dev) = *ata_guard {
                let start_lba = (block_index as u64) * (SECTORS_PER_BLOCK as u64);
                let mut full_block = [0u8; ZFS_BLOCK_SIZE];
                full_block[..copy_len].copy_from_slice(&in_buf[..copy_len]);
                dev.write_sectors(start_lba, SECTORS_PER_BLOCK as u8, &full_block)?;
            }
        }

        Ok(())
    }

    /// Flushes hardware disk write caches.
    pub fn flush(&mut self) -> Result<(), &'static str> {
        if self.has_ata {
            let mut ata_guard = crate::arch::ata::PRIMARY_ATA.lock();
            if let Some(ref mut dev) = *ata_guard {
                dev.flush()?;
            }
        }
        Ok(())
    }
}

/// Storage Pool Allocator (SPA)
/// Tracks block allocations, transaction groups (TXG), and active Uberblock.
pub struct Spa {
    pub vdev: VdevStorage,
    pub block_bitmap: [u64; POOL_TOTAL_BLOCKS / 64],
    pub active_uberblock: Uberblock,
    pub pool_name: [u8; 16],
    pub allocated_blocks: usize,
}

impl Spa {
    pub fn new(name: &str) -> Self {
        let mut pool_name = [0u8; 16];
        let bytes = name.as_bytes();
        let len = if bytes.len() > 15 { 15 } else { bytes.len() };
        for i in 0..len {
            pool_name[i] = bytes[i];
        }

        let initial_ub = Uberblock::new(1, BlockPointer::empty(), pool_name);

        let mut spa = Self {
            vdev: VdevStorage::new(),
            block_bitmap: [0u64; POOL_TOTAL_BLOCKS / 64],
            active_uberblock: initial_ub,
            pool_name,
            allocated_blocks: 0,
        };

        // Reserve blocks 0..RESERVED_METADATA_BLOCKS for Vdev Label, dnodes, and ZAP tables
        for b in 0..RESERVED_METADATA_BLOCKS {
            spa.mark_block(b, true);
        }
        spa.allocated_blocks = RESERVED_METADATA_BLOCKS;

        spa
    }

    /// Returns true if this storage pool is backed by persistent physical/virtual ATA hardware.
    pub fn is_hardware_backed(&self) -> bool {
        self.vdev.is_hardware_backed()
    }

    /// Flushes all persistent writes to physical storage media.
    pub fn flush(&mut self) -> Result<(), &'static str> {
        self.vdev.flush()
    }

    fn mark_block(&mut self, block: usize, used: bool) {
        let word_idx = block / 64;
        let bit_idx = block % 64;
        if used {
            self.block_bitmap[word_idx] |= 1u64 << bit_idx;
        } else {
            self.block_bitmap[word_idx] &= !(1u64 << bit_idx);
        }
    }

    fn is_block_used(&self, block: usize) -> bool {
        let word_idx = block / 64;
        let bit_idx = block % 64;
        (self.block_bitmap[word_idx] & (1u64 << bit_idx)) != 0
    }

    /// Frees a previously allocated block in the SPA block bitmap.
    pub fn free_block(&mut self, block: usize) {
        if block >= RESERVED_METADATA_BLOCKS && block < POOL_TOTAL_BLOCKS && self.is_block_used(block) {
            self.mark_block(block, false);
            self.allocated_blocks = self.allocated_blocks.saturating_sub(1);
        }
    }

    /// Allocates a new block using Copy-On-Write (CoW) allocation,
    /// writes the data into the allocated block, and computes the Fletcher-4 checksum.
    pub fn cow_allocate_block(&mut self, data: &[u8]) -> Result<BlockPointer, &'static str> {
        let mut target_block = None;

        // Linear scan for first free block after reserved metadata area
        for b in RESERVED_METADATA_BLOCKS..POOL_TOTAL_BLOCKS {
            if !self.is_block_used(b) {
                target_block = Some(b);
                break;
            }
        }

        let block_idx = match target_block {
            Some(idx) => idx,
            None => return Err("Storage pool is out of space (metaslabs full)"),
        };

        // Mark block as allocated
        self.mark_block(block_idx, true);
        self.allocated_blocks += 1;

        // Write block payload
        self.vdev.write_block(block_idx, data)?;

        // Compute Fletcher-4 checksum for end-to-end data integrity
        let checksum = Fletcher4::compute(data);

        let bp = BlockPointer {
            vdev_id: 0,
            offset: (block_idx * ZFS_BLOCK_SIZE) as u64,
            logical_size: data.len() as u32,
            physical_size: ZFS_BLOCK_SIZE as u32,
            birth_txg: self.active_uberblock.txg,
            checksum,
            is_allocated: true,
        };

        Ok(bp)
    }

    /// Reads data from a BlockPointer and verifies its Fletcher-4 checksum.
    pub fn read_and_verify_block(&self, bp: &BlockPointer, out: &mut [u8]) -> Result<usize, &'static str> {
        if !bp.is_allocated {
            return Err("Attempted to read unallocated block pointer");
        }

        let block_idx = (bp.offset as usize) / ZFS_BLOCK_SIZE;
        self.vdev.read_block(block_idx, out)?;

        // Verify checksum on valid slice
        let valid_len = if (bp.logical_size as usize) < out.len() {
            bp.logical_size as usize
        } else {
            out.len()
        };

        let calculated_checksum = Fletcher4::compute(&out[..valid_len]);
        if calculated_checksum != bp.checksum {
            return Err("ZFS Checksum verification failed (silent data corruption detected)");
        }

        Ok(valid_len)
    }

    /// Advances transaction group (TXG) and commits the new root Uberblock.
    pub fn commit_txg(&mut self, root_bp: BlockPointer) -> u64 {
        let new_txg = self.active_uberblock.txg + 1;
        self.active_uberblock = Uberblock::new(new_txg, root_bp, self.pool_name);
        new_txg
    }

    pub fn pool_name_str(&self) -> &str {
        let mut len = 0;
        while len < self.pool_name.len() && self.pool_name[len] != 0 {
            len += 1;
        }
        core::str::from_utf8(&self.pool_name[..len]).unwrap_or("hydrapool")
    }

    pub fn total_capacity_bytes(&self) -> usize {
        POOL_CAPACITY_BYTES
    }

    pub fn allocated_bytes(&self) -> usize {
        self.allocated_blocks * ZFS_BLOCK_SIZE
    }

    pub fn free_bytes(&self) -> usize {
        POOL_CAPACITY_BYTES.saturating_sub(self.allocated_bytes())
    }
}
