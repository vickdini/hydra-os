//! The heap of Hydra's Ring 3 programs.
//!
//! Blocks of up to 4 KiB come from free lists, one per power-of-two size class, filled
//! 64 KiB at a time from a first-fit list that serves the larger blocks. A first-fit list
//! alone walks every hole on each allocation and each free: in the file server, whose block
//! cache takes and drops page-sized buffers and whose maps and vectors come and go with
//! every request, the list held thousands of holes and the walks took 70% of its time.
//! Small blocks are never handed back to the first-fit list (a size class keeps what it took).

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{null_mut, NonNull};
use linked_list_allocator::Heap;
use spin::Mutex;

/// The smallest class: 16 bytes (room for the free list link, and malloc's alignment).
const MIN_SHIFT: usize = 4;
/// The largest class: 4 KiB.
const MAX_SHIFT: usize = 12;
const CLASSES: usize = MAX_SHIFT - MIN_SHIFT + 1;
/// What a class takes from the first-fit list when its free list is empty.
const CHUNK: usize = 64 * 1024;

/// The global allocator of a Ring 3 program.
pub struct RtHeap {
    inner: Mutex<Inner>,
}

struct Inner {
    /// Blocks larger than 4 KiB, and the chunks the classes take.
    large: Heap,
    /// Free blocks per class: each holds the address of the next (0 ends the list).
    free: [usize; CLASSES],
    /// Bytes the classes took from `large`.
    small: usize,
}

/// The size class of `layout`: its size and alignment rounded up to a power of two.
fn class_of(layout: &Layout) -> Option<usize> {
    let size = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    if size > 1 << MAX_SHIFT {
        return None;
    }
    Some(size.next_power_of_two().trailing_zeros() as usize - MIN_SHIFT)
}

impl RtHeap {
    /// An allocator with no memory yet ([`RtHeap::init`] gives it its heap).
    pub const fn empty() -> Self {
        Self { inner: Mutex::new(Inner { large: Heap::empty(), free: [0; CLASSES], small: 0 }) }
    }

    /// Gives the allocator the `size` bytes at `bottom`.
    ///
    /// # Safety
    /// The memory must be unused, writable and stay mapped for the program's life.
    pub unsafe fn init(&self, bottom: *mut u8, size: usize) {
        self.inner.lock().large.init(bottom, size);
    }

    /// Heap bytes `(used, free)`: blocks the size classes hold count as used.
    pub fn usage(&self) -> (usize, usize) {
        let h = self.inner.lock();
        (h.large.used(), h.large.free())
    }
}

unsafe impl GlobalAlloc for RtHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut h = self.inner.lock();
        let Some(c) = class_of(&layout) else {
            return h.large.allocate_first_fit(layout).map_or(null_mut(), |p| p.as_ptr());
        };
        if h.free[c] == 0 {
            // Chunks are page-aligned, so every block is aligned to its size
            let Ok(chunk) = h.large.allocate_first_fit(Layout::from_size_align_unchecked(CHUNK, 4096)) else {
                return null_mut();
            };
            let size = 1usize << (c + MIN_SHIFT);
            let base = chunk.as_ptr() as usize;
            for i in (0..CHUNK / size).rev() {
                let b = base + i * size;
                *(b as *mut usize) = h.free[c];
                h.free[c] = b;
            }
            h.small += CHUNK;
        }
        let b = h.free[c];
        h.free[c] = *(b as *const usize);
        b as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut h = self.inner.lock();
        match class_of(&layout) {
            Some(c) => {
                *(ptr as *mut usize) = h.free[c];
                h.free[c] = ptr as usize;
            }
            None => h.large.deallocate(NonNull::new_unchecked(ptr), layout),
        }
    }
}
