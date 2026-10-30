use spin::Mutex;
use uefi::mem::memory_map::MemoryMap;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

pub const PAGE_SIZE: u64 = 4096;
const MAX_REGIONS: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub page_count: u64,
}

/// Physical frame manager.
///
/// Frames are carved from UEFI conventional memory with a bump pointer; frames returned
/// through [`free_frame`](Self::free_frame) go onto an intrusive free list (the next-pointer
/// is stored in the first 8 bytes of the freed frame, which is reachable through the
/// identity map) and are reused first.
///
/// Every frame handed out by [`allocate_frame`](Self::allocate_frame) carries a 16-bit
/// reference count so that user pages can be shared (page cache, copy-on-write, shared
/// mappings). A count of 0 means "unmanaged": contiguous allocations (kernel heap, DMA
/// buffers) and firmware memory are never reference counted or freed.
pub struct PhysicalMemoryManager {
    regions: [Option<MemoryRegion>; MAX_REGIONS],
    region_count: usize,
    current_region_idx: usize,
    next_page_in_region: u64,
    total_usable_bytes: u64,
    allocated_frames_count: u64,
    free_list_head: u64,
    free_list_len: u64,
    refcounts: *mut u16,
    refcount_entries: u64,
}

unsafe impl Send for PhysicalMemoryManager {}

impl PhysicalMemoryManager {
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

    fn refcount_slot(&self, frame: PhysFrame<Size4KiB>) -> Option<*mut u16> {
        let idx = frame.start_address().as_u64() / PAGE_SIZE;
        if self.refcounts.is_null() || idx >= self.refcount_entries {
            None
        } else {
            Some(unsafe { self.refcounts.add(idx as usize) })
        }
    }

    /// Returns the reference count of a frame (0 = unmanaged).
    pub fn refcount(&self, frame: PhysFrame<Size4KiB>) -> u16 {
        self.refcount_slot(frame).map(|p| unsafe { *p }).unwrap_or(0)
    }

    /// Adds a reference to a managed frame. Unmanaged frames are left untouched.
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
    pub fn allocate_zeroed_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.allocate_frame()?;
        unsafe {
            core::ptr::write_bytes(frame.start_address().as_u64() as *mut u8, 0, PAGE_SIZE as usize);
        }
        Some(frame)
    }

    pub fn total_usable_memory(&self) -> u64 {
        self.total_usable_bytes
    }

    pub fn allocated_memory(&self) -> u64 {
        self.allocated_frames_count * PAGE_SIZE
    }

    pub fn free_memory(&self) -> u64 {
        self.total_usable_bytes.saturating_sub(self.allocated_memory())
    }

    pub fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = self.allocate_frame_raw()?;
        if let Some(p) = self.refcount_slot(frame) {
            unsafe {
                *p = 1;
            }
        }
        Some(frame)
    }

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

pub static FRAME_ALLOCATOR: Mutex<PhysicalMemoryManager> = Mutex::new(PhysicalMemoryManager::new());

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
pub fn alloc_user_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().allocate_zeroed_frame()
}

/// Adds a reference to a frame in the global allocator.
pub fn frame_ref_inc(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().ref_inc(frame);
}

/// Drops a reference to a frame in the global allocator, freeing it at zero.
pub fn frame_ref_dec(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().ref_dec(frame);
}

/// Returns a frame's reference count (0 = unmanaged).
pub fn frame_refcount(frame: PhysFrame<Size4KiB>) -> u16 {
    FRAME_ALLOCATOR.lock().refcount(frame)
}
