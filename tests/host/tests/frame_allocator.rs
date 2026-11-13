//! Tests for the physical frame allocator in `src/memory/frame_allocator.rs`.
//!
//! The kernel identity-maps RAM, so the allocator writes through physical
//! addresses directly: free-list links live in the first 8 bytes of a free
//! frame, and the refcount table holds one `u16` per page from address 0.
//! Tests that touch either therefore need real memory at a low address. An
//! [`Arena`] reserves it with `VirtualAlloc`/`mmap` at a fixed address just
//! above `LOW_USER_END` (1 GiB), where the kernel's own regions start.
//!
//! Tests that only check the bump-allocation arithmetic use made-up
//! addresses and never dereference them.

use hydra_hosttests::memory::frame_allocator::{phys_to_virt, PhysicalMemoryManager, DIRECT_MAP_BASE, PAGE_SIZE};
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

mod common;
use common::Arena;

type Frame = PhysFrame<Size4KiB>;

use common::GIB;

fn frame(addr: u64) -> Frame {
    PhysFrame::containing_address(PhysAddr::new(addr))
}

fn addr(f: Frame) -> u64 {
    f.start_address().as_u64()
}

/// Allocator over an arena with refcounting enabled.
fn manager(a: &Arena) -> PhysicalMemoryManager {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(a.base), a.size / PAGE_SIZE);
    m.init_refcounts();
    m
}

// --------------------------------------------- bump allocation (no memory)

#[test]
fn new_manager_is_empty() {
    let mut m = PhysicalMemoryManager::new();
    assert_eq!((m.total_usable_memory(), m.allocated_memory(), m.free_memory()), (0, 0, 0));
    assert!(m.allocate_frame().is_none());
    assert!(m.allocate_contiguous_frames(1).is_none());
}

#[test]
fn add_region_accounts_usable_memory_and_ignores_empty_regions() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 10);
    m.add_region(PhysAddr::new(2 * GIB), 0);
    m.add_region(PhysAddr::new(3 * GIB), 6);
    assert_eq!(m.total_usable_memory(), 16 * PAGE_SIZE);
    assert_eq!(m.free_memory(), 16 * PAGE_SIZE);
}

#[test]
fn region_table_is_capped_at_64() {
    let mut m = PhysicalMemoryManager::new();
    for i in 0..70 {
        m.add_region(PhysAddr::new(GIB + i * 0x10_0000), 1);
    }
    assert_eq!(m.total_usable_memory(), 64 * PAGE_SIZE);
    let mut n = 0;
    while m.allocate_frame().is_some() {
        n += 1;
    }
    assert_eq!(n, 64);
}

#[test]
fn frames_come_out_in_order_across_regions() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 2);
    m.add_region(PhysAddr::new(2 * GIB), 1);
    let got: Vec<u64> = std::iter::from_fn(|| m.allocate_frame()).map(addr).collect();
    assert_eq!(got, vec![GIB, GIB + PAGE_SIZE, 2 * GIB]);
    assert_eq!(m.allocated_memory(), 3 * PAGE_SIZE);
    assert_eq!(m.free_memory(), 0);
}

#[test]
fn frame_allocator_trait_delegates() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 1);
    let f = FrameAllocator::<Size4KiB>::allocate_frame(&mut m).unwrap();
    assert_eq!(addr(f), GIB);
    assert!(FrameAllocator::<Size4KiB>::allocate_frame(&mut m).is_none());
}

#[test]
fn contiguous_allocation_is_one_run() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 10);
    m.allocate_frame().unwrap();
    let run = m.allocate_contiguous_frames(4).unwrap();
    assert_eq!(addr(run), GIB + PAGE_SIZE);
    assert_eq!(m.allocated_memory(), 5 * PAGE_SIZE);
    assert_eq!(addr(m.allocate_frame().unwrap()), GIB + 5 * PAGE_SIZE, "bump continues after the run");
}

#[test]
fn contiguous_allocation_moves_to_a_region_that_fits() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 3);
    m.add_region(PhysAddr::new(2 * GIB), 8);
    assert_eq!(addr(m.allocate_contiguous_frames(5).unwrap()), 2 * GIB);
}

#[test]
fn failed_contiguous_request_does_not_exhaust_the_allocator() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 10);
    m.add_region(PhysAddr::new(2 * GIB), 10);
    assert!(m.allocate_contiguous_frames(100).is_none());
    assert!(m.allocate_frame().is_some(), "20 free pages, yet no frame can be allocated");
}

#[test]
fn skipped_region_remainder_is_still_allocatable() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 4);
    m.add_region(PhysAddr::new(2 * GIB), 8);
    m.allocate_contiguous_frames(6).unwrap(); // only fits in region 2
    let rest: Vec<u64> = std::iter::from_fn(|| m.allocate_frame()).map(addr).collect();
    assert!(rest.contains(&GIB), "the 4 pages of region 1 were leaked: got {rest:x?}");
}

// --------------------------------------- refcounts and free list (memory)

#[test]
fn init_refcounts_takes_its_table_from_the_first_region() {
    let a = Arena::new(0);
    let m = manager(&a);
    let table_pages = m.allocated_memory() / PAGE_SIZE;
    let expected = ((a.base + a.size) / PAGE_SIZE * 2).div_ceil(PAGE_SIZE);
    assert_eq!(table_pages, expected);
    assert_eq!(m.refcount(frame(a.base)), 0, "table frames are not refcounted");
}

#[test]
fn allocated_frames_start_with_refcount_one() {
    let a = Arena::new(1);
    let mut m = manager(&a);
    let f = m.allocate_frame().unwrap();
    assert!(addr(f) >= a.base && addr(f) < a.base + a.size);
    assert_eq!(m.refcount(f), 1);
}

#[test]
fn refcount_inc_dec_and_free_on_last_reference() {
    let a = Arena::new(2);
    let mut m = manager(&a);
    let f = m.allocate_frame().unwrap();
    let used = m.allocated_memory();

    m.ref_inc(f);
    m.ref_inc(f);
    assert_eq!(m.refcount(f), 3);
    m.ref_dec(f);
    m.ref_dec(f);
    assert_eq!(m.refcount(f), 1);
    assert_eq!(m.allocated_memory(), used, "still in use");

    m.ref_dec(f);
    assert_eq!(m.refcount(f), 0);
    assert_eq!(m.allocated_memory(), used - PAGE_SIZE, "freed on last reference");
    assert_eq!(m.allocate_frame(), Some(f), "free list hands the frame straight back");
    assert_eq!(m.refcount(f), 1);
}

#[test]
fn double_free_is_ignored() {
    let a = Arena::new(3);
    let mut m = manager(&a);
    let f = m.allocate_frame().unwrap();
    m.ref_dec(f);
    m.ref_dec(f); // already free: must not push it on the free list twice
    let x = m.allocate_frame().unwrap();
    let y = m.allocate_frame().unwrap();
    assert_eq!(x, f);
    assert_ne!(y, f, "a double free would hand out the same frame twice");
}

#[test]
fn ref_inc_on_a_free_frame_does_not_resurrect_it() {
    let a = Arena::new(4);
    let mut m = manager(&a);
    let f = m.allocate_frame().unwrap();
    m.ref_dec(f);
    m.ref_inc(f);
    assert_eq!(m.refcount(f), 0);
}

#[test]
fn free_list_is_lifo_and_survives_many_frames() {
    let a = Arena::new(5);
    let mut m = manager(&a);
    let frames: Vec<Frame> = (0..50).map(|_| m.allocate_frame().unwrap()).collect();
    let used = m.allocated_memory();
    for f in &frames {
        m.ref_dec(*f);
    }
    assert_eq!(m.allocated_memory(), used - 50 * PAGE_SIZE);
    let back: Vec<Frame> = (0..50).map(|_| m.allocate_frame().unwrap()).collect();
    let mut expected = frames.clone();
    expected.reverse();
    assert_eq!(back, expected);
    let fresh = m.allocate_frame().unwrap();
    assert!(!frames.contains(&fresh), "after the free list, bump allocation resumes");
}

#[test]
fn refcount_saturates_and_pins_the_frame() {
    let a = Arena::new(6);
    let mut m = manager(&a);
    let f = m.allocate_frame().unwrap();
    for _ in 0..u16::MAX as u32 + 10 {
        m.ref_inc(f);
    }
    assert_eq!(m.refcount(f), u16::MAX);
    let used = m.allocated_memory();
    m.ref_dec(f);
    assert_eq!(m.refcount(f), u16::MAX, "a saturated count can no longer be trusted, so it sticks");
    assert_eq!(m.allocated_memory(), used, "and the frame is never freed");
}

#[test]
fn adopt_starts_counting_untracked_frames() {
    let a = Arena::new(7);
    let mut m = manager(&a);
    let run = m.allocate_contiguous_frames(3).unwrap();
    let second = frame(addr(run) + PAGE_SIZE);
    assert_eq!(m.refcount(second), 0, "contiguous frames are not refcounted");
    m.ref_inc(second);
    assert_eq!(m.refcount(second), 0, "inc on an untracked frame is ignored");
    m.adopt(second);
    assert_eq!(m.refcount(second), 1);
    m.adopt(second);
    assert_eq!(m.refcount(second), 1, "adopting twice does not add a reference");
    m.ref_dec(second);
    assert_eq!(m.allocate_frame(), Some(second), "adopted frames are freed normally");
}

#[test]
fn frames_beyond_the_refcount_table_are_ignored() {
    let a = Arena::new(8);
    let mut m = manager(&a);
    let far = frame(64 * GIB);
    assert_eq!(m.refcount(far), 0);
    m.ref_inc(far);
    m.adopt(far);
    m.ref_dec(far); // would write through 64 GiB if it were not bounds-checked
    assert_eq!(m.refcount(far), 0);
}

#[test]
fn zeroed_frame_has_no_free_list_residue() {
    let a = Arena::new(9);
    let mut m = manager(&a);
    let f1 = m.allocate_frame().unwrap();
    let f2 = m.allocate_frame().unwrap();
    unsafe { std::ptr::write_bytes(addr(f2) as *mut u8, 0xAB, PAGE_SIZE as usize) };
    m.ref_dec(f1);
    m.ref_dec(f2); // f2's first word now links to f1
    let z = m.allocate_zeroed_frame().unwrap();
    assert_eq!(z, f2);
    let bytes = unsafe { std::slice::from_raw_parts(addr(z) as *const u8, PAGE_SIZE as usize) };
    assert!(bytes.iter().all(|&b| b == 0));
    assert_eq!(m.allocate_frame(), Some(f1), "free list intact after zeroing");
}

#[test]
fn exhausting_memory_returns_none_and_freeing_recovers() {
    let a = Arena::new(10);
    let mut m = manager(&a);
    let mut all = Vec::new();
    while let Some(f) = m.allocate_frame() {
        all.push(f);
    }
    assert_eq!(m.free_memory(), 0);
    m.ref_dec(all[17]);
    assert_eq!(m.allocate_frame(), Some(all[17]));
    assert!(m.allocate_frame().is_none());
}

// ------------------------------------------------- high runs and direct map

#[test]
fn contiguous_high_takes_the_top_of_the_highest_region() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 10);
    m.add_region(PhysAddr::new(2 * GIB), 10);
    assert_eq!(m.max_phys_end(), 2 * GIB + 10 * PAGE_SIZE);
    let run = m.allocate_contiguous_high(3, 0).unwrap();
    assert_eq!(addr(run), 2 * GIB + 7 * PAGE_SIZE);
    assert_eq!(m.allocated_memory(), 3 * PAGE_SIZE);
    let rest: Vec<u64> = std::iter::from_fn(|| m.allocate_frame()).map(addr).collect();
    assert_eq!(rest.len(), 17, "the bump allocator never reaches the pages taken from the top");
    assert!(rest.iter().all(|&a| a < 2 * GIB + 7 * PAGE_SIZE));
}

#[test]
fn contiguous_high_respects_min_addr_and_pages_already_handed_out() {
    let mut m = PhysicalMemoryManager::new();
    m.add_region(PhysAddr::new(GIB), 10);
    m.add_region(PhysAddr::new(2 * GIB), 4);
    assert_eq!(m.allocate_contiguous_high(5, 0).map(addr), Some(GIB + 5 * PAGE_SIZE), "only the first region is big enough");
    assert_eq!(m.allocate_contiguous_high(1, 3 * GIB), None, "nothing at or above min_addr");
    assert_eq!(m.allocate_contiguous_high(4, 2 * GIB).map(addr), Some(2 * GIB));

    let mut n = PhysicalMemoryManager::new();
    n.add_region(PhysAddr::new(GIB), 4);
    for _ in 0..3 {
        n.allocate_frame().unwrap();
    }
    assert_eq!(n.allocate_contiguous_high(2, 0), None, "one page left");
    assert_eq!(n.allocate_contiguous_high(1, 0).map(addr), Some(GIB + 3 * PAGE_SIZE));
    assert_eq!(n.allocate_frame(), None);
}

#[test]
fn physical_addresses_are_identity_until_the_direct_map_is_enabled() {
    // The tests never enable it: the kernel does at boot, once it runs in the higher half
    assert_eq!(phys_to_virt(0x1234_5000) as u64, 0x1234_5000);
    assert_eq!(DIRECT_MAP_BASE, 0xFFFF_8000_0000_0000, "PML4 slot 256, as on Linux");
}
