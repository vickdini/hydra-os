//! # Memory Subsystem: Kernel Dynamic Heap Allocator
//!
//! Configures and manages the global Rust `alloc` dynamic memory allocator (`#[global_allocator]`)
//! for the Hydra kernel, enabling standard collection types (`Box`, `Vec`, `String`, `BTreeMap`, `Arc`).
//!
//! ## Architectural Role & Design Rationale
//!
//! Kernel subsystems such as the VFS, scheduler, capability table, and Linux compatibility layer
//! require dynamic memory allocation. `init` reserves a contiguous physical memory arena—preferring
//! up to `HEAP_SIZE` (512 MiB) carved directly from `FRAME_ALLOCATOR` and scaling down gracefully
//! to `MIN_HEAP_SIZE` (128 MiB) or falling back to UEFI `allocate_pages` when necessary—and backs
//! `HEAP_ALLOCATOR` (`linked_list_allocator::LockedHeap`) with that zero-initialized region.
//!
//! ## Key Types & Interfaces
//!
//! - `HEAP_ALLOCATOR`: The `#[global_allocator]` spinlock-protected linked-list heap.
//! - `HeapStats`: Real-time diagnostic snapshot of heap capacity, usage, and free bytes.
//! - `init`: Allocates the backing arena and initializes `HEAP_ALLOCATOR`.
//! - `stats` & `self_test`: Runtime inspection and integrity verification of heap operations.
//!
//! ## Hardware & Dependency Context
//!
//! - **Backing Memory**: Identity-mapped physical frames from `FRAME_ALLOCATOR` or UEFI `LOADER_DATA`.
//! - **Synchronization**: Internal `spin::Mutex` inside `LockedHeap` plus atomic state flags.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::LockedHeap;
use uefi::boot::{allocate_pages, AllocateType};
use uefi::mem::memory_map::MemoryType;

use super::frame_allocator::{FRAME_ALLOCATOR, PAGE_SIZE};

/// Preferred kernel heap size: 512 MiB (room to unpack root filesystem archives in memory).
pub const HEAP_SIZE: usize = 512 * 1024 * 1024;
/// Smallest heap accepted when memory is short.
const MIN_HEAP_SIZE: usize = 128 * 1024 * 1024;

/// Global allocator for Hydra kernel (`extern crate alloc`).
#[global_allocator]
pub static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Tracks whether the global kernel heap has been initialized.
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Starting virtual/physical address of the initialized kernel heap arena.
static HEAP_START_ADDR: AtomicU64 = AtomicU64::new(0);
/// Total size in bytes of the initialized kernel heap arena.
static HEAP_TOTAL_SIZE: AtomicUsize = AtomicUsize::new(0);

/// Diagnostic information about the kernel heap.
#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    /// Base memory address of the heap arena.
    pub start_address: u64,
    /// Total capacity of the heap in bytes.
    pub total_bytes: usize,
    /// Number of bytes currently allocated from the heap.
    pub used_bytes: usize,
    /// Number of bytes currently available for allocation.
    pub free_bytes: usize,
    /// Whether the heap has been initialized and is ready for use.
    pub is_initialized: bool,
}

/// Initializes the global dynamic heap allocator.
///
/// It first attempts to allocate a contiguous physical chunk from the
/// Hydra Physical Memory Manager (conventional memory). If that is not
/// yet available, it falls back to UEFI boot services page allocation.
///
/// # Returns
///
/// `Ok(HeapStats)` describing the newly initialized heap, or an error string if allocation failed.
///
/// # Errors
///
/// Returns `Err` if neither the physical frame allocator nor UEFI boot services can supply at least
/// `MIN_HEAP_SIZE` bytes of contiguous memory.
pub fn init() -> Result<HeapStats, &'static str> {
    if HEAP_INITIALIZED.load(Ordering::SeqCst) {
        return Ok(stats());
    }

    // Use at most a quarter of usable RAM, halving down to the minimum if no region fits
    let usable = FRAME_ALLOCATOR.lock().total_usable_memory() as usize;
    let mut size = HEAP_SIZE.min((usable / 4).max(MIN_HEAP_SIZE));
    let mut heap_start_ptr: Option<*mut u8> = None;
    while heap_start_ptr.is_none() && size >= MIN_HEAP_SIZE {
        let page_count = (size + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;

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
        if heap_start_ptr.is_none() {
            size /= 2;
        }
    }

    let start_ptr = heap_start_ptr.ok_or("Failed to allocate contiguous memory pages for kernel heap")?;

    unsafe {
        // Zero-initialize heap memory to ensure clean initial state
        core::ptr::write_bytes(start_ptr, 0, size);
        // Initialize the linked-list allocator
        HEAP_ALLOCATOR.lock().init(start_ptr, size);
    }

    HEAP_START_ADDR.store(start_ptr as u64, Ordering::SeqCst);
    HEAP_TOTAL_SIZE.store(size, Ordering::SeqCst);
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
