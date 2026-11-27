//! `memory/frame_allocator.rs`: regions, the bump cursor and the free list, reference
//! counts, contiguous blocks (high and anywhere), and the global helpers.

mod common;

use common::Arena;
use hydra_hosttests_t32::memory::frame_allocator::{self as fa, PhysicalMemoryManager, PAGE_SIZE};
use x86_64::structures::paging::{FrameAllocator, PhysFrame};
use x86_64::PhysAddr;

fn frame(pa: u64) -> PhysFrame {
    PhysFrame::containing_address(PhysAddr::new(pa))
}

#[test]
fn bump_free_list_and_refcounts() {
    let arena = Arena::new(1);
    let mut m = PhysicalMemoryManager::new();
    assert_eq!(m.allocate_frame(), None, "no memory yet");
    // Two regions; an empty one is ignored
    let half = arena.size / 2;
    m.add_region(PhysAddr::new(arena.base), half / PAGE_SIZE);
    m.add_region(PhysAddr::new(arena.base + half), 0);
    m.add_region(PhysAddr::new(arena.base + half), half / PAGE_SIZE);
    assert_eq!(m.total_usable_memory(), arena.size);
    assert_eq!(m.max_phys_end(), arena.base + arena.size);
    m.init_refcounts();
    // The refcount table (2 bytes per frame up to the end) came from the first region
    let table = ((arena.base + arena.size) / PAGE_SIZE * 2).div_ceil(PAGE_SIZE);
    assert_eq!(m.allocated_memory(), table * PAGE_SIZE);
    let a = m.allocate_frame().unwrap();
    assert_eq!(a.start_address().as_u64(), arena.base + table * PAGE_SIZE, "after the table");
    assert_eq!(m.refcount(a), 1);
    m.ref_inc(a);
    assert_eq!(m.refcount(a), 2);
    m.ref_dec(a);
    m.ref_dec(a);
    assert_eq!(m.refcount(a), 0, "freed");
    assert_eq!(m.free_memory(), m.total_usable_memory() - m.allocated_memory());
    // A free frame is not revived by ref_inc, and freeing it again does nothing
    m.ref_inc(a);
    m.ref_dec(a);
    assert_eq!(m.refcount(a), 0);
    // The free list first
    let b = m.allocate_zeroed_frame().unwrap();
    assert_eq!(b, a);
    assert!(unsafe { core::slice::from_raw_parts(b.start_address().as_u64() as *const u8, 4096) }.iter().all(|&x| x == 0), "zeroed (the free list link too)");
    // Adopting a frame allocated before the counts existed
    let c = frame(arena.base);
    m.adopt(c);
    assert_eq!(m.refcount(c), 1);
    m.adopt(c);
    assert_eq!(m.refcount(c), 1, "only from 0");
    // Frames outside the table: no count
    assert_eq!(m.refcount(frame(0x7FFF_0000_0000)), 0);
    m.ref_inc(frame(0x7FFF_0000_0000));
    // Through the trait
    let d = FrameAllocator::allocate_frame(&mut m).unwrap();
    assert_ne!(d, b);
    // Exhaust: both regions, then None
    let mut n = 0;
    while m.allocate_frame().is_some() {
        n += 1;
    }
    assert!(n > 0);
    assert_eq!(m.free_memory(), 0);
    assert!(m.allocate_frame().is_none());
}

#[test]
fn contiguous_blocks() {
    let arena = Arena::new(2);
    let mut m = PhysicalMemoryManager::new();
    let q = arena.size / 4;
    // Region 0: one quarter; region 1: three quarters
    m.add_region(PhysAddr::new(arena.base), q / PAGE_SIZE);
    m.add_region(PhysAddr::new(arena.base + q), 3 * q / PAGE_SIZE);
    // High: the highest fitting block, taken from the top of its region
    let h = m.allocate_contiguous_high(4, 0).unwrap();
    assert_eq!(h.start_address().as_u64(), arena.base + arena.size - 4 * PAGE_SIZE);
    let h2 = m.allocate_contiguous_high(4, 0).unwrap();
    assert_eq!(h2.start_address().as_u64(), arena.base + arena.size - 8 * PAGE_SIZE);
    // Above a floor nothing fits
    assert!(m.allocate_contiguous_high(4, arena.base + arena.size).is_none());
    assert!(m.allocate_contiguous_high((arena.size / PAGE_SIZE) as usize, 0).is_none(), "larger than any region");
    // Anywhere: from the cursor's region if it fits, else a later one's start
    let a = m.allocate_contiguous_frames(2).unwrap();
    assert_eq!(a.start_address().as_u64(), arena.base);
    let big = (q / PAGE_SIZE) as usize; // no longer fits region 0 (2 pages used)
    let b = m.allocate_contiguous_frames(big).unwrap();
    assert_eq!(b.start_address().as_u64(), arena.base + q, "region 1's start");
    // The single-frame cursor carries on in region 0
    assert_eq!(m.allocate_frame().unwrap().start_address().as_u64(), arena.base + 2 * PAGE_SIZE);
    assert!(m.allocate_contiguous_frames(1 << 30).is_none());
    // Region 1 now starts after the block; single frames reach it after region 0
    let mut last = 0;
    while let Some(f) = m.allocate_frame() {
        last = f.start_address().as_u64();
    }
    assert_eq!(last, arena.base + arena.size - 9 * PAGE_SIZE, "below the two high blocks");
}

#[test]
fn global_helpers() {
    common::global_frames();
    let f = fa::alloc_user_frame().unwrap();
    assert_eq!(fa::frame_refcount(f), 1);
    fa::frame_ref_inc(f);
    assert_eq!(fa::frame_refcount(f), 2);
    fa::frame_ref_dec(f);
    fa::frame_ref_dec(f);
    assert_eq!(fa::frame_refcount(f), 0);
    // Identity until the direct map is turned on (never on the host)
    assert_eq!(fa::phys_to_virt(0x1234) as u64, 0x1234);
}

// wave11 GK begin
/// `early_grow`'s capacity stop (`fwmem=new`): no block from the firmware when the region
/// table is full (it could not be recorded) or after `ExitBootServices`.
#[test]
fn early_grow_stops_at_a_full_region_table() {
    let mut m = PhysicalMemoryManager::new();
    assert!(fa::may_grow_early(true, &m), "room, boot services run");
    assert!(!fa::may_grow_early(false, &m), "after ExitBootServices: never");
    for i in 0..fa::REGION_SLOTS as u64 - 1 {
        m.add_region(PhysAddr::new(0x1000_0000 + i * 0x2000), 1);
    }
    assert!(fa::may_grow_early(true, &m), "one slot left");
    m.add_region(PhysAddr::new(0x3000_0000), 1);
    assert!(!fa::may_grow_early(true, &m), "table full: stop");
    // A region past the table is not recorded either (add_region's own stop)
    let total = m.total_usable_memory();
    m.add_region(PhysAddr::new(0x4000_0000), 16);
    assert_eq!(m.total_usable_memory(), total);
    assert!(!fa::may_grow_early(true, &m));
    // Not early: no firmware block whatever the table
    assert!(!fa::is_early());
}
/// The free RAM under the low layout's floor kept for after the direct map: clipped to
/// [1 MiB, floor), nothing when the floor is 1 MiB (the higher half).
#[test]
fn low_parts_clip_to_the_floor() {
    const G: u64 = 1 << 30;
    let regions = [(0x8_0000u64, 0x100u64), (0x20_0000, 0x1000), (G - 0x1000, 0x100), (G + 0x1000, 0x10)];
    let p = fa::low_parts(regions.iter().copied(), G);
    assert_eq!(p, vec![(0x10_0000, 0x80), (0x20_0000, 0x1000), (G - 0x1000, 1)]);
    assert!(fa::low_parts(regions.iter().copied(), 0x10_0000).is_empty(), "higher half: floor at 1 MiB");
}
// wave11 GK end

// wave12 GV begin: the late path's floor
#[test]
fn the_late_paths_floor() {
    use hydra_hosttests_t32::memory::frame_allocator as fa;
    // QEMU 2.5 GB: free RAM below and above 2 GiB; only what lies above counts
    let regions = [(0x10_0000u64, 0x3FF00u64), (0x4000_0000, 0x40000), (0x8000_0000, 0x10000), (0x9000_0000, 0x8000)];
    assert_eq!(fa::free_above(regions.iter().copied(), 2 << 30), (0x10000 + 0x8000) * 4096);
    // a region across 2 GiB counts from 2 GiB on
    assert_eq!(fa::free_above([(0x7000_0000u64, 0x20000u64)].into_iter(), 2 << 30), 0x1000_0000);
    assert_eq!(fa::free_above(core::iter::empty(), 2 << 30), 0);
    // enough room above 2 GiB: frames from 2 GiB on; else the old 1 GiB floor
    assert_eq!(fa::late_floor(192 << 20), 2 << 30);
    assert_eq!(fa::late_floor(4 << 30), 2 << 30);
    assert_eq!(fa::late_floor((192 << 20) - 4096), 1 << 30);
    assert_eq!(fa::late_floor(0), 1 << 30);
}
// wave12 GV end
