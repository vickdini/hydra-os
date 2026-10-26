use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::LockedHeap;
use uefi::boot::{allocate_pages, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::frame_allocator::{FRAME_ALLOCATOR, PAGE_SIZE};

/// Default kernel heap size: 128 MiB (accommodates Debian repository indexes, Wayland compositors, and ZFS cache)
pub const HEAP_SIZE: usize = 128 * 1024 * 1024;

/// Global allocator for Hydra kernel (`extern crate alloc`).
#[global_allocator]
pub static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static HEAP_START_ADDR: AtomicU64 = AtomicU64::new(0);
static HEAP_TOTAL_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Diagnostic information about the kernel heap.
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub start_address: u64,
    pub total_bytes: usize,
    pub used_bytes: usize,
    pub free_bytes: usize,
    pub is_initialized: bool,
}

/// Initializes the global dynamic heap allocator.
///
/// It first attempts to allocate a contiguous physical chunk from the
/// Hydra Physical Memory Manager (conventional memory). If that is not
/// yet available, it falls back to UEFI boot services page allocation.
pub fn init() -> Result<HeapStats, &'static str> {
    if HEAP_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(stats());
    }

    let page_count = (HEAP_SIZE + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
    let mut heap_start_ptr: Option<*mut u8> = None;

    // Strategy 1: Allocate contiguous physical frames from Hydra's frame allocator
    {
        let mut alloc = FRAME_ALLOCATOR.lock();
        if let Some(frame) = alloc.allocate_contiguous_frames(page_count) {
            heap_start_ptr = Some(frame.start_address().as_u64() as *mut u8);
        }
    }

    // Strategy 2: Fall back to UEFI Boot Services loader data allocation
    if heap_start_ptr.is_none() {
        if let Ok(ptr) = allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, page_count) {
            heap_start_ptr = Some(ptr.as_ptr());
        }
    }

    let start_ptr = heap_start_ptr.ok_or("Failed to allocate contiguous memory pages for kernel heap")?;

    unsafe {
        // Zero-initialize heap memory to ensure clean initial state
        core::ptr::write_bytes(start_ptr, 0, HEAP_SIZE);
        // Initialize the linked-list allocator
        HEAP_ALLOCATOR.lock().init(start_ptr, HEAP_SIZE);
    }

    HEAP_START_ADDR.store(start_ptr as u64, Ordering::SeqCst);
    HEAP_TOTAL_SIZE.store(HEAP_SIZE, Ordering::SeqCst);
    HEAP_INITIALIZED.store(true, Ordering::SeqCst);

    Ok(stats())
}

/// Returns true if the kernel heap is initialized and ready for allocations.
pub fn is_initialized() -> bool {
    HEAP_INITIALIZED.load(Ordering::SeqCst)
}

/// Returns real-time statistics of the kernel heap.
pub fn stats() -> HeapStats {
    if !is_initialized() {
        return HeapStats {
            start_address: 0,
            total_bytes: 0,
            used_bytes: 0,
            free_bytes: 0,
            is_initialized: false,
        };
    }

    let heap = HEAP_ALLOCATOR.lock();
    HeapStats {
        start_address: HEAP_START_ADDR.load(Ordering::SeqCst),
        total_bytes: heap.size(),
        used_bytes: heap.used(),
        free_bytes: heap.free(),
        is_initialized: true,
    }
}

/// Runs a verification suite to ensure dynamic allocation (`Box`, `Vec`, `String`, etc.)
/// and deallocation are operating correctly without leaks.
pub fn self_test() -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("Heap is not initialized");
    }

    let initial_used = stats().used_bytes;

    // Test 1: Box allocation & pointer dereference
    {
        let boxed_val = alloc::boxed::Box::new(0xCAFE_BABE_DEAD_BEEF_u64);
        if *boxed_val != 0xCAFE_BABE_DEAD_BEEF_u64 {
            return Err("Boxed value did not match expected value");
        }
    }

    // Test 2: Dynamic Vector reallocation across multiple capacity growth steps
    {
        let mut test_vec = alloc::vec::Vec::new();
        for i in 0..1000 {
            test_vec.push(i * 3);
        }
        for (i, &val) in test_vec.iter().enumerate() {
            if val != i * 3 {
                return Err("Vec content corrupted during dynamic reallocation");
            }
        }
    }

    // Test 3: String formatting & concatenation
    {
        let s = alloc::format!("Hydra OS dynamic string: 0x{:X}", 42);
        if !s.starts_with("Hydra OS") {
            return Err("String formatting failed");
        }
    }

    // Test 4: Verify memory deallocation (RAII drop returns used bytes to baseline)
    let final_used = stats().used_bytes;
    if final_used != initial_used {
        return Err("Heap memory leak detected: used bytes did not return to baseline after drops");
    }

    Ok(())
}
