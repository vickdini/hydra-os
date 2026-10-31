//! # Memory Subsystem: Physical Frame Allocator
//!
//! Manages physical RAM at 4 KiB page frame granularity, providing bump allocation over UEFI
//! conventional memory regions, an intrusive O(1) free list for recycled frames, and a 16-bit
//! per-frame reference count table for shared and copy-on-write user pages.
//!
//! ## Architectural Role & Design Rationale
//!
//! Physical memory is the lowest layer of the memory hierarchy. Rather than relying on dynamic
//! heap structures that do not yet exist during early boot, `PhysicalMemoryManager` stores
//! up to 64 contiguous memory descriptors harvested from the UEFI memory map and allocates
//! single or contiguous frames via a bump pointer. When managed user frames are freed, their
//! first 8 bytes (accessible via the kernel's identity map) store the next-pointer of an
//! intrusive singly-linked free list so subsequent allocations reuse freed frames in O(1) time.
//!
//! ## Key Types & Interfaces
//!
//! - `MemoryRegion`: Descriptor for a contiguous range of usable physical page frames.
//! - `PhysicalMemoryManager`: Core frame allocator and reference-count tracker.
//! - `FRAME_ALLOCATOR`: Global spinlock-protected `PhysicalMemoryManager` instance.
//! - `alloc_user_frame`, `frame_ref_inc`, `frame_ref_dec`: High-level helpers for reference-counted frames.
//!
//! ## Hardware & Dependency Context
//!
//! - **Page Granularity**: Standard x86_64 4 KiB (`4096`-byte) frames (`Size4KiB`).
//! - **Low Memory Reservation**: Physical addresses below `0x100000` (1 MiB) are reserved to protect
//!   legacy BIOS/UEFI structures and prevent null physical frame allocation.
//! - **Direct Physical Access**: Relies on the identity mapping of physical RAM to read/write intrusive
//!   free-list pointers and the contiguous reference-count array.

use spin::Mutex;
use uefi::mem::memory_map::MemoryMap;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

/// Size of a standard x86_64 physical page frame in bytes (4 KiB).
pub const PAGE_SIZE: u64 = 4096;
/// Maximum number of discontiguous UEFI conventional memory regions tracked.
const MAX_REGIONS: usize = 64;

/// Describes a contiguous region of usable physical RAM discovered from the firmware memory map.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting physical address of the memory region (4 KiB aligned).
    pub start: PhysAddr,
    /// Number of 4 KiB page frames contained within this region.
    pub page_count: u64,
}

/// Physical frame manager.
///
/// Frames are carved from UEFI conventional memory with a bump pointer; frames returned
/// through [`ref_dec`](Self::ref_dec) go onto an intrusive free list (the next-pointer
/// is stored in the first 8 bytes of the freed frame, which is reachable through the
/// identity map) and are reused first.
///
/// Every frame handed out by [`allocate_frame`](Self::allocate_frame) carries a 16-bit
/// reference count so that user pages can be shared (page cache, copy-on-write, shared
/// mappings). A count of 0 means "unmanaged": contiguous allocations (kernel heap, DMA
/// buffers) and firmware memory are never reference counted or freed.
pub struct PhysicalMemoryManager {
    /// Fixed table of usable physical memory regions registered at boot.
    regions: [Option<MemoryRegion>; MAX_REGIONS],
    /// Number of valid entries currently populated in `regions`.
    region_count: usize,
    /// Index of the region currently being carved by the bump allocator.
    current_region_idx: usize,
    /// Page offset within `regions[current_region_idx]` for the next bump allocation.
    next_page_in_region: u64,
    /// Total usable conventional RAM in bytes across all registered regions.
    total_usable_bytes: u64,
    /// Total number of 4 KiB frames currently allocated and in use.
    allocated_frames_count: u64,
    /// Physical address of the head of the intrusive free list (`0` when empty).
    free_list_head: u64,
    /// Number of frames currently linked in the intrusive free list.
    free_list_len: u64,
    /// Pointer to the base of the 16-bit per-frame reference count table in identity-mapped RAM.
    refcounts: *mut u16,
    /// Total number of frame entries covered by the `refcounts` array.
    refcount_entries: u64,
}

unsafe impl Send for PhysicalMemoryManager {}

impl PhysicalMemoryManager {
    /// Creates an empty, uninitialized physical memory manager with no regions registered.
    ///
    /// # Returns
    ///
    /// A new `PhysicalMemoryManager` ready to receive memory regions via [`Self::add_region`].
    pub const fn new() -> Self {
        Self {
            regions: [None; MAX_REGIONS],
            region_count: 0,
            current_region_idx: 0,
            next_page_in_region: 0,
            total_usable_bytes: 0,
            allocated_frames_count: 0,
            free_list_head: 0,
            free_list_len: 0,
            refcounts: core::ptr::null_mut(),
            refcount_entries: 0,
        }
    }

    /// Registers a contiguous region of usable conventional physical memory.
    ///
    /// # Arguments
    ///
    /// * `start` - Starting physical address of the usable region.
    /// * `page_count` - Number of 4 KiB pages in the region.
    pub fn add_region(&mut self, start: PhysAddr, page_count: u64) {
        if self.region_count < MAX_REGIONS && page_count > 0 {
            self.regions[self.region_count] = Some(MemoryRegion { start, page_count });
            self.region_count += 1;
            self.total_usable_bytes += page_count * PAGE_SIZE;
        }
    }

    /// Allocates the per-frame reference count table covering every registered region.
    /// Must run once, after all regions are added and before any frame is allocated.
    pub fn init_refcounts(&mut self) {
        let mut max_end = 0u64;
        for region in self.regions.iter().flatten() {
            max_end = max_end.max(region.start.as_u64() + region.page_count * PAGE_SIZE);
        }
        let entries = max_end / PAGE_SIZE;
        let table_pages = ((entries * 2 + PAGE_SIZE - 1) / PAGE_SIZE) as usize;
        if let Some(frame) = self.allocate_contiguous_frames(table_pages) {
            let ptr = frame.start_address().as_u64() as *mut u16;
            unsafe {
                core::ptr::write_bytes(ptr as *mut u8, 0, table_pages * PAGE_SIZE as usize);
            }
            self.refcounts = ptr;
            self.refcount_entries = entries;
        }
    }

    /// Resolves the mutable pointer to the 16-bit reference count slot for `frame`.
    fn refcount_slot(&self, frame: PhysFrame<Size4KiB>) -> Option<*mut u16> {
        let idx = frame.start_address().as_u64() / PAGE_SIZE;
        if self.refcounts.is_null() || idx >= self.refcount_entries {
            None
        } else {
            Some(unsafe { self.refcounts.add(idx as usize) })
        }
    }

    /// Returns the reference count of a frame (`0` = unmanaged).
    ///
    /// # Arguments
    ///
    /// * `frame` - The 4 KiB physical frame to query.
    ///
    /// # Returns
    ///
    /// The current reference count, or `0` if the frame is unmanaged or out of range.
    pub fn refcount(&self, frame: PhysFrame<Size4KiB>) -> u16 {
        self.refcount_slot(frame).map(|p| unsafe { *p }).unwrap_or(0)
    }

    /// Adds a reference to a managed frame. Unmanaged frames are left untouched.
    ///
    /// # Arguments
    ///
    /// * `frame` - The managed 4 KiB physical frame whose reference count should be incremented.
    pub fn ref_inc(&mut self, frame: PhysFrame<Size4KiB>) {
        if let Some(p) = self.refcount_slot(frame) {
            unsafe {
                if *p != 0 && *p != u16::MAX {
                    *p += 1;
                }
            }
        }
    }

    /// Drops a reference to a managed frame, returning it to the free list when the last
    /// reference goes away. Unmanaged frames are never freed.
    ///
    /// # Arguments
    ///
    /// * `frame` - The managed 4 KiB physical frame whose reference count should be decremented.
    pub fn ref_dec(&mut self, frame: PhysFrame<Size4KiB>) {
        if let Some(p) = self.refcount_slot(frame) {
            unsafe {
                match *p {
                    0 | u16::MAX => {}
                    1 => {
                        *p = 0;
                        self.push_free(frame);
                    }
                    _ => *p -= 1,
                }
            }
        }
    }

    /// Pushes an unreferenced 4 KiB frame onto the head of the intrusive free list.
    fn push_free(&mut self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        unsafe {
            *(addr as *mut u64) = self.free_list_head;
        }
        self.free_list_head = addr;
        self.free_list_len += 1;
        self.allocated_frames_count = self.allocated_frames_count.saturating_sub(1);
    }

    /// Allocates a managed frame (reference count 1) and fills it with zeroes.
    ///
    /// # Returns
    ///
    /// `Some(frame)` on success, or `None` if physical memory is exhausted.
    pub fn allocate_zeroed_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.allocate_frame()?;
        unsafe {
            core::ptr::write_bytes(frame.start_address().as_u64() as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(frame)
    }

    /// Returns the total usable physical memory registered in bytes.
    pub fn total_usable_memory(&self) -> u64 {
        self.total_usable_bytes
    }

    /// Returns the total physical memory currently allocated in bytes.
    pub fn allocated_memory(&self) -> u64 {
        self.allocated_frames_count * PAGE_SIZE
    }

    /// Returns the remaining free physical memory in bytes.
    pub fn free_memory(&self) -> u64 {
        self.total_usable_bytes.saturating_sub(self.allocated_memory())
    }

    /// Allocates a single 4 KiB physical frame and initializes its reference count to `1`.
    ///
    /// # Returns
    ///
    /// `Some(frame)` if a free or bump-allocated frame is available, or `None` if out of memory.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.allocate_frame_raw()?;
        if let Some(p) = self.refcount_slot(frame) {
            unsafe {
                *p = 1;
            }
        }
        Some(frame)
    }

    /// Pops a frame from the intrusive free list or carves one from the current bump region.
    fn allocate_frame_raw(&mut self) -> Option<PhysFrame<Size4KiB>> {
        if self.free_list_head != 0 {
            let addr = self.free_list_head;
            self.free_list_head = unsafe { *(addr as *const u64) };
            self.free_list_len -= 1;
            self.allocated_frames_count += 1;
            return Some(PhysFrame::containing_address(PhysAddr::new(addr)));
        }
        while self.current_region_idx < self.region_count {
            if let Some(region) = self.regions[self.current_region_idx] {
                if self.next_page_in_region < region.page_count {
                    let frame_addr = region.start + (self.next_page_in_region * PAGE_SIZE);
                    self.next_page_in_region += 1;
                    self.allocated_frames_count += 1;
                    return Some(PhysFrame::containing_address(frame_addr));
                }
            }
            self.current_region_idx += 1;
            self.next_page_in_region = 0;
        }
        None
    }

    /// Allocates a contiguous block of physical frames (e.g. for the kernel heap or DMA buffers).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of contiguous 4 KiB frames required.
    ///
    /// # Returns
    ///
    /// The starting [`PhysFrame`] of the contiguous block, or `None` if no region has sufficient space.
    pub fn allocate_contiguous_frames(&mut self, count: usize) -> Option<PhysFrame<Size4KiB>> {
        let count_u64 = count as u64;
        while self.current_region_idx < self.region_count {
            if let Some(region) = self.regions[self.current_region_idx] {
                let remaining = region.page_count.saturating_sub(self.next_page_in_region);
                if remaining >= count_u64 {
                    let frame_addr = region.start + (self.next_page_in_region * PAGE_SIZE);
                    self.next_page_in_region += count_u64;
                    self.allocated_frames_count += count_u64;
                    return Some(PhysFrame::containing_address(frame_addr));
                }
            }
            self.current_region_idx += 1;
            self.next_page_in_region = 0;
        }
        None
    }
}

unsafe impl FrameAllocator<Size4KiB> for PhysicalMemoryManager {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_frame()
    }
}

/// Global spinlock-protected physical memory manager instance.
pub static FRAME_ALLOCATOR: Mutex<PhysicalMemoryManager> = Mutex::new(PhysicalMemoryManager::new());

/// Harvests usable `CONVENTIONAL` memory regions from the UEFI boot services memory map
/// and initializes the global `FRAME_ALLOCATOR` and its per-frame reference count table.
pub fn init_memory_from_uefi() {
    let mut allocator = FRAME_ALLOCATOR.lock();

    if let Ok(memory_map) = uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA) {
        for desc in memory_map.entries() {
            // Conventional memory is free memory available for operating system allocation
            if desc.ty == uefi::boot::MemoryType::CONVENTIONAL {
                // Reserve the first 1 MiB (0x100000) to protect IVT/BDA and avoid null pointer frame (0x0)
                if desc.phys_start < 0x100000 {
                    let end = desc.phys_start + desc.page_count * PAGE_SIZE;
                    if end > 0x100000 {
                        let skipped_pages = (0x100000 - desc.phys_start) / PAGE_SIZE;
                        let remaining_pages = desc.page_count.saturating_sub(skipped_pages);
                        if remaining_pages > 0 {
                            allocator.add_region(PhysAddr::new(0x100000), remaining_pages);
                        }
                    }
                } else {
                    allocator.add_region(PhysAddr::new(desc.phys_start), desc.page_count);
                }
            }
        }
    }
    allocator.init_refcounts();
}

/// Allocates a zeroed, reference-counted frame from the global allocator.
///
/// # Returns
///
/// `Some(frame)` with reference count 1 and zeroed contents, or `None` if out of memory.
pub fn alloc_user_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().allocate_zeroed_frame()
}

/// Adds a reference to a frame in the global allocator.
///
/// # Arguments
///
/// * `frame` - Physical frame whose reference count should be incremented.
pub fn frame_ref_inc(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().ref_inc(frame);
}

/// Drops a reference to a frame in the global allocator, freeing it at zero.
///
/// # Arguments
///
/// * `frame` - Physical frame whose reference count should be decremented.
pub fn frame_ref_dec(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().ref_dec(frame);
}

/// Returns a frame's reference count (`0` = unmanaged).
///
/// # Arguments
///
/// * `frame` - Physical frame to query.
///
/// # Returns
///
/// Current 16-bit reference count for `frame`.
pub fn frame_refcount(frame: PhysFrame<Size4KiB>) -> u16 {
    FRAME_ALLOCATOR.lock().refcount(frame)
}
