//! 4 KiB buffers for the block cache and dirty data (the kernel's frame allocator, as
//! heap pages): `crate::memory::frame_allocator`.

use alloc::alloc::{alloc_zeroed, Layout};
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};
use x86_64::PhysAddr;

static REFS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());

/// Free buffers, reused before new ones are taken from the heap. The block cache
/// and dirty data take and drop 4 KiB buffers all the time: through the heap's
/// first-fit free list each of them, and every other allocation, walked thousands
/// of page-sized holes (a cold read spent more time there than on the disk).
static FREE: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// Buffers taken from the heap at a time when none is free (1 MiB).
const CHUNK_PAGES: usize = 256;

/// Computes memory layout for `pages` 4 KiB frames.
///
/// # Arguments
/// * `pages` - Number of 4 KiB pages.
///
/// # Returns
/// Page-aligned [`Layout`].
fn layout(pages: usize) -> Layout {
    Layout::from_size_align(pages * 4096, 4096).unwrap()
}

/// A zeroed buffer with one reference.
///
/// # Returns
/// `Some(PhysFrame)` containing allocated buffer on success, or `None`.
pub fn alloc_user_frame() -> Option<PhysFrame<Size4KiB>> {
    let mut free = FREE.lock();
    if free.is_empty() {
        // Fresh heap pages are zero
        let chunk = unsafe { alloc_zeroed(layout(CHUNK_PAGES)) };
        if chunk.is_null() {
            return None;
        }
        free.extend((0..CHUNK_PAGES as u64).rev().map(|i| (chunk as u64 + i * 4096) | 1));
    }
    let entry = free.pop()?;
    drop(free);
    // Bit 0: not used since it came from the heap (still zero)
    let p = entry & !1;
    if entry & 1 == 0 {
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, 4096) };
    }
    REFS.lock().insert(p, 1);
    Some(PhysFrame::containing_address(PhysAddr::new(p as u64)))
}

/// Adds a reference to a buffer.
///
/// # Arguments
/// * `frame` - Physical frame representation of buffer.
pub fn frame_ref_inc(frame: PhysFrame<Size4KiB>) {
    if let Some(r) = REFS.lock().get_mut(&frame.start_address().as_u64()) {
        *r += 1;
    }
}

/// Drops a reference; the buffer is freed with the last one.
///
/// # Arguments
/// * `frame` - Physical frame representation of buffer.
pub fn frame_ref_dec(frame: PhysFrame<Size4KiB>) {
    let addr = frame.start_address().as_u64();
    let mut refs = REFS.lock();
    let last = match refs.get_mut(&addr) {
        Some(r) if *r > 1 => {
            *r -= 1;
            false
        }
        Some(_) => true,
        None => false,
    };
    if last {
        refs.remove(&addr);
        drop(refs);
        FREE.lock().push(addr);
    }
}

/// Contiguous buffers (the RAM disk used when there is no disk).
pub struct Contiguous;

impl Contiguous {
    /// Allocates `pages` contiguous zeroed pages (never freed).
    ///
    /// # Arguments
    /// * `pages` - Number of contiguous 4 KiB pages to allocate.
    ///
    /// # Returns
    /// `Some(PhysFrame)` pointing to base of range, or `None`.
    pub fn allocate_contiguous_frames(&mut self, pages: usize) -> Option<PhysFrame<Size4KiB>> {
        let p = unsafe { alloc_zeroed(layout(pages)) };
        (!p.is_null()).then(|| PhysFrame::containing_address(PhysAddr::new(p as u64)))
    }
}

/// The kernel's frame allocator, as far as the pool uses it.
pub static FRAME_ALLOCATOR: Mutex<Contiguous> = Mutex::new(Contiguous);
