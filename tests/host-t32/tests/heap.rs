//! `memory/heap.rs`: placing the kernel heap (frame allocator first, preferring high
//! memory), its statistics and self-test, and the size-class allocator in front of the
//! linked-list heap. The heap is global and set up once: one test does it in order.

mod common;

use core::alloc::{GlobalAlloc, Layout};

use common::Arena;
use hydra_hosttests_t32::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests_t32::memory::heap;

#[test]
fn heap_life() {
    // Before init
    assert!(!heap::is_initialized());
    assert!(!heap::stats().is_initialized);
    assert_eq!(heap::stats().total_bytes, 0);
    assert!(heap::try_stats().is_none());
    assert_eq!(heap::self_test(), Err("Heap is not initialized"));

    // 200 MiB of RAM, all below 2 GiB: the high placements fail and shrink (3/4 at a
    // time) down to half, then the full size is taken from anywhere
    let arena = Arena::at(0x5000_0000, 200 << 20);
    {
        let mut fa = FRAME_ALLOCATOR.lock();
        fa.add_region(x86_64::PhysAddr::new(arena.base), arena.size / 4096);
        fa.init_refcounts();
    }
    let s = heap::init().unwrap();
    assert!(s.is_initialized && heap::is_initialized());
    assert_eq!(s.total_bytes, 128 << 20, "the minimum size: half of RAM is less");
    assert!(s.start_address >= arena.base && s.start_address + (128 << 20) <= arena.base + arena.size);
    assert_eq!(heap::range(), (s.start_address, s.start_address + (128 << 20)));
    assert!(!heap::in_direct_map());
    // Again: already done
    assert_eq!(heap::init().unwrap().start_address, s.start_address);

    // The size classes: blocks of 16..2048 bytes from 16 KiB runs; freed blocks come back
    let h = heap::kernel_heap();
    unsafe {
        let used0 = heap::stats().used_bytes;
        let l16 = Layout::from_size_align(10, 8).unwrap();
        let a = h.alloc(l16);
        let b = h.alloc(l16);
        assert!(!a.is_null() && !b.is_null());
        assert_eq!(b as usize - a as usize, 16, "neighbours in one run");
        assert_eq!(heap::stats().used_bytes - used0, 16 * 1024, "one run carved");
        h.dealloc(a, l16);
        assert_eq!(h.alloc(l16), a, "last freed, first reused");
        // Alignment picks the class: 8 bytes aligned to 256 come from the 256-byte class
        let al = Layout::from_size_align(8, 256).unwrap();
        let c = h.alloc(al);
        assert_eq!(c as usize % 256, 0);
        h.dealloc(c, al);
        // Every class
        for size in [16usize, 32, 64, 128, 256, 512, 1024, 2048] {
            let l = Layout::from_size_align(size, 8).unwrap();
            let p = h.alloc(l);
            assert_eq!(p as usize % size, 0, "class blocks are aligned to their size");
            core::ptr::write_bytes(p, 0xAB, size);
            h.dealloc(p, l);
        }
        // A whole run, and one more block: a second run
        let l2k = Layout::from_size_align(2048, 8).unwrap();
        let mut blocks: Vec<*mut u8> = (0..9).map(|_| h.alloc(l2k)).collect();
        blocks.sort();
        blocks.dedup();
        assert_eq!(blocks.len(), 9, "all distinct");
        for p in blocks {
            h.dealloc(p, l2k);
        }
        // Bigger than the classes: straight from the linked-list heap
        let big = Layout::from_size_align(5000, 16).unwrap();
        let before = heap::stats().used_bytes;
        let p = h.alloc(big);
        assert!(!p.is_null());
        assert!(heap::stats().used_bytes >= before + 5000);
        h.dealloc(p, big);
        assert_eq!(heap::stats().used_bytes, before);
        // Out of memory: a big allocation fails with null
        assert!(h.alloc(Layout::from_size_align(256 << 20, 16).unwrap()).is_null());
        h.dealloc(b, l16);
    }

    // Statistics agree; the lock taken elsewhere makes try_stats give up
    let st = heap::stats();
    assert_eq!(st.used_bytes + st.free_bytes, st.total_bytes);
    assert_eq!(heap::try_stats().unwrap().used_bytes, st.used_bytes);
    {
        let _l = heap::HEAP_ALLOCATOR.lock();
        assert!(heap::try_stats().is_none());
    }

    // The boot self-test: boxes, vectors and strings, without growth on a second round
    // (the host's allocator serves those; the test still checks its own accounting)
    assert_eq!(heap::self_test(), Ok(()));

    // Last (it breaks the 512-byte list): the size-class lists do not check frees (without
    // POISON_FREE), so a block freed twice comes back from two allocations. Not a bug in
    // itself, but what a double free in kernel code turns into: two owners of one block.
    unsafe {
        let l = Layout::from_size_align(512, 8).unwrap();
        let a = h.alloc(l);
        h.dealloc(a, l);
        h.dealloc(a, l);
        let x = h.alloc(l);
        let y = h.alloc(l);
        assert_eq!((x, y), (a, a));
    }
}
