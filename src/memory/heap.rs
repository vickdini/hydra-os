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

/// Preferred kernel heap size: 1024 MiB (room to unpack large root filesystem archives in memory).
pub const HEAP_SIZE: usize = 1024 * 1024 * 1024;
/// Smallest heap accepted when memory is short.
const MIN_HEAP_SIZE: usize = 128 * 1024 * 1024;

/// The linked-list heap behind [`KERNEL_HEAP`]: large blocks, and the memory the
/// small-object lists are carved from.
pub static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Global allocator for Hydra kernel (`extern crate alloc`).
#[global_allocator]
static KERNEL_HEAP: SizeClassHeap = SizeClassHeap::new();

/// Block sizes served from free lists (powers of two, each block aligned to its size).
const CLASS_SIZES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
/// Bytes requested from the linked-list heap when a class runs out.
const REFILL_BYTES: usize = 16 * 1024;

/// A free block of a size class (the link lives in the free block itself).
struct FreeBlock {
    next: *mut FreeBlock,
}

struct FreeList(*mut FreeBlock);

unsafe impl Send for FreeList {}

/// Small allocations come from per-size free lists in O(1); freed small blocks go back to
/// their list (they are never returned to the linked-list heap). The linked-list heap's
/// first-fit search is linear in the number of holes, which small blocks would otherwise
/// multiply.
pub struct SizeClassHeap {
    classes: [spin::Mutex<FreeList>; 8],
}

impl SizeClassHeap {
    const fn new() -> Self {
        Self { classes: [const { spin::Mutex::new(FreeList(core::ptr::null_mut())) }; 8] }
    }

    /// Determines the best-fit size class index for a given allocation layout.
    ///
    /// # Arguments
    ///
    /// * `layout` - The memory layout containing size and alignment constraints.
    ///
    /// # Returns
    ///
    /// `Some(index)` into `CLASS_SIZES` if the layout fits a size class; `None` if it exceeds 2048 bytes.
    fn class_of(layout: &core::alloc::Layout) -> Option<usize> {
        let need = layout.size().max(layout.align());
        CLASS_SIZES.iter().position(|&c| c >= need)
    }
}

unsafe impl core::alloc::GlobalAlloc for SizeClassHeap {
    /// Allocates memory adhering to `layout` using size-class pools or the fallback heap.
    ///
    /// # Arguments
    ///
    /// * `layout` - Requested size and alignment.
    ///
    /// # Returns
    ///
    /// Non-null raw pointer to allocated memory on success; null pointer on failure.
    ///
    /// # Safety
    ///
    /// Caller must satisfy global allocator invariants and deallocate with matching layout.
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let class = match Self::class_of(&layout) {
            Some(c) => c,
            None => return HEAP_ALLOCATOR.alloc(layout),
        };
        let mut list = self.classes[class].lock();
        if list.0.is_null() {
            // Carve a run of blocks out of the linked-list heap
            let size = CLASS_SIZES[class];
            let chunk = match core::alloc::Layout::from_size_align(REFILL_BYTES, size) {
                Ok(l) => HEAP_ALLOCATOR.alloc(l),
                Err(_) => core::ptr::null_mut(),
            };
            if chunk.is_null() {
                return core::ptr::null_mut();
            }
            for i in (0..REFILL_BYTES / size).rev() {
                let block = chunk.add(i * size) as *mut FreeBlock;
                (*block).next = list.0;
                list.0 = block;
            }
        }
        let block = list.0;
        list.0 = (*block).next;
        block as *mut u8
    }

    /// Recycles previously allocated memory back to the size-class pool or linked-list heap.
    ///
    /// # Arguments
    ///
    /// * `ptr` - Pointer previously returned by `alloc`.
    /// * `layout` - Exact layout used during allocation.
    ///
    /// # Safety
    ///
    /// Pointer must have been allocated by this allocator and not yet freed.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        match Self::class_of(&layout) {
            Some(class) => {
                let mut list = self.classes[class].lock();
                let block = ptr as *mut FreeBlock;
                (*block).next = list.0;
                list.0 = block;
            }
            None => HEAP_ALLOCATOR.dealloc(ptr, layout),
        }
    }
}

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

    // Use at most half of usable RAM, halving down to the minimum if no region fits
    let usable = FRAME_ALLOCATOR.lock().total_usable_memory() as usize;
    let mut size = HEAP_SIZE.min((usable / 2).max(MIN_HEAP_SIZE));
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

/// Checks whether the kernel dynamic heap is initialized and ready for allocations.
///
/// # Returns
///
/// `true` if `init_heap()` has completed successfully; `false` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn is_initialized() -> bool {
    HEAP_INITIALIZED.load(Ordering::SeqCst)
}

/// Computes real-time utilization metrics for the dynamic kernel heap.
///
/// Acquires the allocator mutex to compute exact total, used, and free byte metrics.
///
/// # Returns
///
/// A populated `HeapStats` descriptor with current heap metrics.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
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

/// Retrieves heap statistics without waiting for the allocator mutex.
///
/// Safe for invocation within interrupt service routines and the kernel panic handler.
///
/// # Returns
///
/// `Some(HeapStats)` if the heap is initialized and the lock is acquired immediately; `None` otherwise.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn try_stats() -> Option<HeapStats> {
    if !is_initialized() {
        return None;
    }
    let heap = HEAP_ALLOCATOR.try_lock()?;
    Some(HeapStats {
        start_address: HEAP_START_ADDR.load(Ordering::SeqCst),
        total_bytes: heap.size(),
        used_bytes: heap.used(),
        free_bytes: heap.free(),
        is_initialized: true,
    })
}

/// Runs a verification test suite to ensure heap allocation and deallocation function correctly.
///
/// Tests `Box`, `Vec`, and `String` allocations, verifies data integrity, and checks for memory leaks.
///
/// # Returns
///
/// `Ok(())` if all allocator tests pass; `Err(&'static str)` if an assertion fails.
///
/// # Errors
///
/// Returns an error message if the heap is uninitialized or if memory corruption / leaks are detected.
///
/// # Panics
///
/// *Guaranteed to never panic under normal execution.*
pub fn self_test() -> Result<(), &'static str> {
    if !is_initialized() {
        return Err("Heap is not initialized");
    }

    // One round warms the small-block lists (freed small blocks stay there for reuse);
    // repeating it must then not grow the heap
    let round = || -> Result<(), &'static str> {
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

        Ok(())
    };
    round()?;
    let initial_used = stats().used_bytes;
    round()?;

    // Test 4: Verify memory deallocation (RAII drop returns used bytes to baseline)
    let final_used = stats().used_bytes;
    if final_used != initial_used {
        return Err("Heap memory leak detected: used bytes did not return to baseline after drops");
    }

    Ok(())
}
