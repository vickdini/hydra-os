//! Tests for per-process address spaces (`src/memory/vm.rs`): VMAs, mmap,
//! munmap, mprotect, brk, mremap, page faults, copy-on-write fork, file
//! (object) mappings, userfaultfd ranges and `/proc/<pid>/maps` text.
//!
//! This is the real `Mm`, building real x86-64 page tables. Its "physical"
//! memory is a 64 MiB arena at 2 GiB (`common::global_frames`), identity
//! mapped as in the kernel, so tests read page-table entries and user pages
//! directly. TLB flushes go to the counting shim in `shim/x86_64`.
//!
//! Every test holds `common::serial()` and checks that the frame pool returns
//! to its starting level when everything is dropped, which catches leaked
//! frames and double frees.

mod common;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use hydra_hosttests::fake;
use hydra_hosttests::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests::memory::vm::*;
use x86_64::structures::paging::PageTableFlags as F;

const P: u64 = PAGE_SIZE;
const RW: u32 = PROT_READ | PROT_WRITE;
const RX: u32 = PROT_READ | PROT_EXEC;
/// A fixed address in the main user window, used for MAP_FIXED tests.
const A: u64 = USER_SPACE_START + 0x1000_0000;
const EINVAL: i64 = -22;
const EEXIST: i64 = -17;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;

fn used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

/// Run `f` with a fresh `Mm`, and check no frame leaks once it is dropped.
fn with_mm(f: impl FnOnce(&mut Mm)) {
    let _g = common::serial();
    common::global_frames();
    fake::reset();
    let before = used();
    {
        let mut mm = Mm::new().unwrap();
        f(&mut mm);
    }
    assert_eq!(used(), before, "frames leaked (or freed twice) by this test");
}

fn anon(mm: &mut Mm, addr: u64, len: u64, prot: u32) -> u64 {
    mm.mmap(addr, len, prot, false, true, false, Backing::Anon).unwrap()
}

/// Leaf PTE flags for `addr`, read straight from the page tables.
fn pte(mm: &Mm, addr: u64) -> Option<F> {
    let mut table = mm.cr3();
    for shift in [39, 30, 21] {
        let e = unsafe { *(table as *const u64).add(((addr >> shift) & 0x1FF) as usize) };
        if e & 1 == 0 {
            return None;
        }
        table = e & 0x000F_FFFF_FFFF_F000;
    }
    let e = unsafe { *(table as *const u64).add(((addr >> 12) & 0x1FF) as usize) };
    (e != 0).then(|| F::from_bits_truncate(e))
}

/// Read user memory through the page tables (faulting nothing in).
fn read(mm: &mut Mm, addr: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let phys = mm.translate(addr + i).expect("page not present");
            unsafe { *(phys.as_u64() as *const u8) }
        })
        .collect()
}

fn vmas(mm: &Mm) -> Vec<(u64, u64, u32)> {
    mm.vmas().map(|v| (v.start, v.end, v.prot)).collect()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
}

// ------------------------------------------------------------ user ranges

#[test]
fn user_range_boundaries() {
    let _g = common::serial(); // the low layout is global; layout tests change it
    assert!(is_user_range(USER_SPACE_START, P));
    assert!(!is_user_range(USER_SPACE_START - P, P));
    assert!(is_user_range(USER_SPACE_END - P, P));
    assert!(!is_user_range(USER_SPACE_END - P, P + 1));
    assert!(is_user_range(LOW_USER_START, LOW_USER_END - LOW_USER_START), "low window for fixed-address programs");
    assert!(!is_user_range(0, P), "page 0 stays unmapped");
    assert!(!is_user_range(LOW_USER_END - P, 2 * P), "low window does not run into the kernel's identity map");
    assert!(!is_user_range(0xFFFF_8000_0000_0000, P), "kernel half");
    assert!(!is_user_range(u64::MAX - P, 2 * P), "overflow");
    assert!(PIE_BASE >= USER_SPACE_START && STACK_TOP <= USER_SPACE_END && MMAP_TOP < STACK_TOP - STACK_SIZE);
}

// ------------------------------------------------------------------- mmap

#[test]
fn new_and_drop_address_space() {
    with_mm(|mm| {
        assert_eq!(mm.vmas().count(), 0);
        assert_eq!(mm.cr3() % P, 0);
        assert!(mm.find_vma(A).is_none());
    });
}

#[test]
fn mmap_places_areas_top_down_below_mmap_top() {
    with_mm(|mm| {
        let a = mm.mmap(0, 3 * P, RW, false, false, false, Backing::Anon).unwrap();
        assert_eq!(a, MMAP_TOP - 3 * P);
        let b = mm.mmap(0, 100, PROT_READ, false, false, false, Backing::Anon).unwrap();
        assert_eq!(b, a - P, "length rounds up to a page; next area directly below");
        assert_eq!(vmas(mm), vec![(b, a, PROT_READ), (a, MMAP_TOP, RW)]);
    });
}

#[test]
fn mmap_uses_a_free_hint_and_ignores_a_busy_one() {
    with_mm(|mm| {
        assert_eq!(mm.mmap(A + 5, P, RW, false, false, false, Backing::Anon), Ok(A), "hint rounded down");
        let other = mm.mmap(A, P, PROT_READ, false, false, false, Backing::Anon).unwrap();
        assert_ne!(other, A, "busy hint is not an error, just ignored");
    });
}

#[test]
fn mmap_argument_checks() {
    with_mm(|mm| {
        assert_eq!(mm.mmap(A, 0, RW, false, true, false, Backing::Anon), Err(EINVAL));
        assert_eq!(mm.mmap(A + 1, P, RW, false, true, false, Backing::Anon), Err(EINVAL), "unaligned MAP_FIXED");
        assert_eq!(mm.mmap(0xFFFF_8000_0000_0000, P, RW, false, true, false, Backing::Anon), Err(EINVAL), "kernel");
        assert_eq!(mm.mmap(0, P, RW, false, true, false, Backing::Anon), Err(EINVAL), "page 0");
        assert_eq!(mm.mmap(0x40_0000, P, RW, false, true, false, Backing::Anon), Ok(0x40_0000), "low window");
    });
}

#[test]
fn map_fixed_replaces_and_noreplace_refuses() {
    with_mm(|mm| {
        anon(mm, A, 2 * P, RW);
        mm.write_bytes(A, b"old").unwrap();
        assert_eq!(mm.mmap(A, P, RW, false, false, true, Backing::Anon), Err(EEXIST));
        assert_eq!(read(mm, A, 3), b"old", "NOREPLACE left the mapping alone");
        assert_eq!(mm.mmap(A, P, PROT_READ, false, true, false, Backing::Anon), Ok(A));
        assert!(mm.translate(A).is_none(), "old page was unmapped");
        assert_eq!(vmas(mm), vec![(A, A + P, PROT_READ), (A + P, A + 2 * P, RW)]);
    });
}

#[test]
fn adjacent_compatible_areas_merge() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        anon(mm, A + P, P, RW);
        anon(mm, A + 3 * P, P, RW); // gap at A+2P
        assert_eq!(vmas(mm), vec![(A, A + 2 * P, RW), (A + 3 * P, A + 4 * P, RW)]);
        anon(mm, A + 2 * P, P, RW);
        assert_eq!(vmas(mm), vec![(A, A + 4 * P, RW)], "filling the gap merges all three");
        anon(mm, A + 4 * P, P, RX);
        assert_eq!(mm.vmas().count(), 2, "different protection does not merge");
        mm.mmap(A + 5 * P, P, RX, true, true, false, Backing::Anon).unwrap();
        assert_eq!(mm.vmas().count(), 3, "shared does not merge with private");
    });
}

#[test]
fn find_vma_boundaries() {
    with_mm(|mm| {
        anon(mm, A, 2 * P, RW);
        assert!(mm.find_vma(A - 1).is_none());
        assert_eq!(mm.find_vma(A).unwrap().start, A);
        assert_eq!(mm.find_vma(A + 2 * P - 1).unwrap().start, A);
        assert!(mm.find_vma(A + 2 * P).is_none(), "end is exclusive");
    });
}

#[test]
fn mmap_huge_length_fails_cleanly() {
    with_mm(|mm| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mm.mmap(0, u64::MAX - 10, RW, false, false, false, Backing::Anon)
        }));
        assert!(matches!(r, Ok(Err(_))), "expected an error, got {:?}", r.map(|x| x.ok()));
        assert_eq!(mm.vmas().count(), 0);
    });
}

// ----------------------------------------------------------- page faults

#[test]
fn anonymous_pages_are_demand_zero() {
    with_mm(|mm| {
        anon(mm, A, 4 * P, RW);
        assert!(mm.translate(A).is_none(), "nothing mapped until touched");
        mm.handle_fault(A + P + 8, false, false).unwrap();
        assert!(mm.translate(A + P).is_some());
        assert!(mm.translate(A).is_none(), "only the faulting page");
        assert_eq!(read(mm, A + P, P as usize), vec![0; P as usize]);
    });
}

#[test]
fn faults_respect_protection() {
    with_mm(|mm| {
        anon(mm, A, P, PROT_READ);
        anon(mm, A + P, P, 0); // PROT_NONE guard page
        assert_eq!(mm.handle_fault(A, true, false), Err(FaultError::Segv), "write to read-only");
        assert_eq!(mm.handle_fault(A, false, true), Err(FaultError::Segv), "exec of non-exec");
        assert_eq!(mm.handle_fault(A + P, false, false), Err(FaultError::Segv), "PROT_NONE");
        assert_eq!(mm.handle_fault(A + 2 * P, false, false), Err(FaultError::Segv), "unmapped");
        assert_eq!(mm.handle_fault(A, false, false), Ok(()));
    });
}

#[test]
fn pte_bits_follow_protection() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        anon(mm, A + P, P, RX);
        anon(mm, A + 2 * P, P, PROT_READ);
        for i in 0..3 {
            mm.handle_fault(A + i * P, false, false).unwrap();
        }
        let rw = pte(mm, A).unwrap();
        assert!(rw.contains(F::PRESENT | F::USER_ACCESSIBLE | F::WRITABLE | F::NO_EXECUTE));
        let rx = pte(mm, A + P).unwrap();
        assert!(rx.contains(F::PRESENT | F::USER_ACCESSIBLE) && !rx.contains(F::WRITABLE) && !rx.contains(F::NO_EXECUTE));
        let ro = pte(mm, A + 2 * P).unwrap();
        assert!(!ro.contains(F::WRITABLE) && ro.contains(F::NO_EXECUTE));
    });
}

#[test]
fn no_nx_bit_when_the_cpu_lacks_it() {
    with_mm(|mm| {
        fake::NX_ENABLED.set(false);
        anon(mm, A, P, RW);
        mm.handle_fault(A, false, false).unwrap();
        assert!(!pte(mm, A).unwrap().contains(F::NO_EXECUTE), "NX in a PTE without EFER.NXE faults");
    });
}

#[test]
fn write_bytes_spans_pages_and_faults_them_in() {
    with_mm(|mm| {
        anon(mm, A, 3 * P, RW);
        let data = pattern(P as usize + 100, 3);
        mm.write_bytes(A + P - 50, &data).unwrap();
        assert_eq!(read(mm, A + P - 50, data.len()), data);
        assert!(mm.translate(A).is_some() && mm.translate(A + 2 * P).is_some());
    });
}

#[test]
fn write_bytes_refuses_read_only_and_unmapped() {
    with_mm(|mm| {
        anon(mm, A, P, PROT_READ);
        assert_eq!(mm.write_bytes(A, b"x"), Err(FaultError::Segv));
        assert_eq!(mm.write_bytes(A + 10 * P, b"x"), Err(FaultError::Segv));
    });
}

#[test]
fn force_write_pokes_read_only_private_memory() {
    // ptrace(PTRACE_POKEDATA) into a program's text.
    with_mm(|mm| {
        anon(mm, A, P, RX);
        mm.force_write(A + 4, b"\xCC").unwrap();
        assert_eq!(read(mm, A + 4, 1), b"\xCC");
        assert!(!pte(mm, A).unwrap().contains(F::WRITABLE), "page stays read-only");

        mm.mmap(A + P, P, PROT_READ, true, true, false, Backing::Anon).unwrap();
        assert_eq!(mm.force_write(A + P, b"x"), Err(FaultError::Segv), "never into shared read-only memory");
        anon(mm, A + 2 * P, P, 0);
        assert_eq!(mm.force_write(A + 2 * P, b"x"), Err(FaultError::Segv));
    });
}

#[test]
fn prefault_and_discard() {
    with_mm(|mm| {
        anon(mm, A, 4 * P, RW);
        mm.prefault(A + 10, 2 * P, true).unwrap();
        for i in 0..3 {
            assert!(pte(mm, A + i * P).unwrap().contains(F::WRITABLE), "page {i}");
        }
        assert!(mm.translate(A + 3 * P).is_none());
        assert_eq!(mm.prefault(A, 0, false), Ok(()));
        assert_eq!(mm.prefault(A, u64::MAX, false), Err(FaultError::Segv), "overflow");
        assert_eq!(mm.prefault(A + 3 * P, 2 * P, false), Err(FaultError::Segv), "runs off the area");

        mm.write_bytes(A, b"gone").unwrap();
        mm.discard(A, A + P); // madvise(MADV_DONTNEED)
        assert!(mm.translate(A).is_none());
        mm.handle_fault(A, false, false).unwrap();
        assert_eq!(read(mm, A, 4), [0; 4], "anonymous memory reads back as zero");
        assert!(mm.find_vma(A).is_some(), "the area itself stays");
    });
}

// ----------------------------------------------------------------- munmap

#[test]
fn unmap_middle_splits_the_area_and_frees_its_pages() {
    with_mm(|mm| {
        anon(mm, A, 4 * P, RW);
        let data = pattern(4 * P as usize, 1);
        mm.write_bytes(A, &data).unwrap();
        let before = used();
        mm.unmap(A + P, A + 3 * P);
        assert_eq!(used(), before - 2 * P, "two frames returned");
        assert_eq!(vmas(mm), vec![(A, A + P, RW), (A + 3 * P, A + 4 * P, RW)]);
        assert_eq!(read(mm, A, P as usize), &data[..P as usize]);
        assert_eq!(read(mm, A + 3 * P, P as usize), &data[3 * P as usize..]);
        assert!(mm.translate(A + P).is_none());
    });
}

#[test]
fn unmap_across_several_areas_and_holes() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        anon(mm, A + 2 * P, P, RX);
        anon(mm, A + 4 * P, 2 * P, RW);
        mm.unmap(A, A + 5 * P);
        assert_eq!(vmas(mm), vec![(A + 5 * P, A + 6 * P, RW)]);
        mm.unmap(A + 100 * P, A + 200 * P); // nothing there: no-op
        assert_eq!(mm.vmas().count(), 1);
    });
}

// --------------------------------------------------------------- mprotect

#[test]
fn mprotect_splits_updates_ptes_and_flushes() {
    with_mm(|mm| {
        anon(mm, A, 3 * P, RW);
        mm.write_bytes(A, &[1; 3 * P as usize]).unwrap();
        let flushes = x86_64::TLB_FLUSHES.load(Ordering::Relaxed);
        mm.mprotect(A + P, P, PROT_READ).unwrap();
        assert_eq!(vmas(mm), vec![(A, A + P, RW), (A + P, A + 2 * P, PROT_READ), (A + 2 * P, A + 3 * P, RW)]);
        assert!(!pte(mm, A + P).unwrap().contains(F::WRITABLE));
        assert!(pte(mm, A).unwrap().contains(F::WRITABLE));
        assert!(x86_64::TLB_FLUSHES.load(Ordering::Relaxed) > flushes, "stale writable TLB entry must go");
        assert_eq!(mm.write_bytes(A + P, b"x"), Err(FaultError::Segv));

        mm.mprotect(A + P, P, RW).unwrap();
        assert_eq!(vmas(mm), vec![(A, A + 3 * P, RW)], "areas merge back");
    });
}

#[test]
fn prot_none_keeps_the_data() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        mm.write_bytes(A, b"secret").unwrap();
        mm.mprotect(A, P, 0).unwrap();
        let flags = pte(mm, A).unwrap();
        assert!(!flags.contains(F::PRESENT), "PROT_NONE page must not be accessible");
        assert_eq!(mm.handle_fault(A, false, false), Err(FaultError::Segv));
        mm.mprotect(A, P, PROT_READ).unwrap();
        assert_eq!(read(mm, A, 6), b"secret", "frame was held, not freed");
    });
}

#[test]
fn mprotect_argument_checks() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        assert_eq!(mm.mprotect(A + 1, P, PROT_READ), Err(EINVAL));
        assert_eq!(mm.mprotect(A, 2 * P, PROT_READ), Err(ENOMEM), "second page is unmapped");
        assert_eq!(vmas(mm), vec![(A, A + P, RW)], "failed call changes nothing");
        assert_eq!(mm.mprotect(A, 0, PROT_READ), Ok(()));
    });
}

#[test]
fn mprotect_huge_length_fails_cleanly() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| mm.mprotect(A, u64::MAX - 2 * P, PROT_READ)));
        assert!(matches!(r, Ok(Err(_))), "expected an error, not a panic or success");
    });
}

// -------------------------------------------------------------------- brk

#[test]
fn brk_grows_and_shrinks_the_heap() {
    with_mm(|mm| {
        mm.brk_start = A;
        mm.brk = A;
        assert_eq!(mm.set_brk(A + 5000), A + 5000);
        let heap = mm.find_vma(A).unwrap();
        assert_eq!((heap.start, heap.end, heap.prot), (A, A + 2 * P, RW));
        assert_eq!(heap.name.as_deref(), Some("[heap]"));
        mm.write_bytes(A + 4999, b"z").unwrap();

        assert_eq!(mm.set_brk(A + 100), A + 100);
        assert_eq!(vmas(mm), vec![(A, A + P, RW)], "shrinking unmaps whole pages above the new break");
        assert_eq!(mm.set_brk(0), A + 100, "brk(0) queries");
        assert_eq!(mm.set_brk(A - 1), A + 100, "cannot go below the start");
    });
}

#[test]
fn brk_does_not_grow_into_other_mappings() {
    with_mm(|mm| {
        mm.brk_start = A;
        mm.brk = A;
        anon(mm, A + 2 * P, P, PROT_READ);
        assert_eq!(mm.set_brk(A + 3 * P), A, "refused, old break returned");
        assert_eq!(mm.set_brk(A + 2 * P), A + 2 * P, "up to the neighbour is fine");
    });
}

// ----------------------------------------------------------------- mremap

#[test]
fn mremap_shrinks_in_place() {
    with_mm(|mm| {
        anon(mm, A, 4 * P, RW);
        mm.write_bytes(A, &[9; 4 * P as usize]).unwrap();
        assert_eq!(mm.mremap(A, 4 * P, P, false, None), Ok(A));
        assert_eq!(vmas(mm), vec![(A, A + P, RW)]);
        assert!(mm.translate(A + P).is_none());
    });
}

#[test]
fn mremap_grows_in_place_when_free() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        assert_eq!(mm.mremap(A, P, 3 * P, false, None), Ok(A));
        assert_eq!(vmas(mm), vec![(A, A + 3 * P, RW)]);
    });
}

#[test]
fn mremap_moves_pages_when_blocked() {
    with_mm(|mm| {
        anon(mm, A, 2 * P, RW);
        anon(mm, A + 2 * P, P, PROT_READ); // blocks growth
        let data = pattern(2 * P as usize, 5);
        mm.write_bytes(A, &data).unwrap();
        assert_eq!(mm.mremap(A, 2 * P, 4 * P, false, None), Err(ENOMEM), "may not move");
        let frames = (mm.translate(A).unwrap(), mm.translate(A + P).unwrap());
        let to = mm.mremap(A, 2 * P, 4 * P, true, None).unwrap();
        assert_ne!(to, A);
        assert_eq!(read(mm, to, data.len()), data);
        assert_eq!((mm.translate(to).unwrap(), mm.translate(to + P).unwrap()), frames, "frames moved, not copied");
        assert!(mm.find_vma(A).is_none());
        assert_eq!(mm.find_vma(to).unwrap().end, to + 4 * P);
    });
}

#[test]
fn mremap_fixed_destination() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        mm.write_bytes(A, b"move me").unwrap();
        let dest = A + 64 * P;
        anon(mm, dest, P, PROT_READ); // replaced, like MAP_FIXED
        assert_eq!(mm.mremap(A, P, P, true, Some(dest)), Ok(dest));
        assert_eq!(read(mm, dest, 7), b"move me");
        assert_eq!(mm.find_vma(dest).unwrap().prot, RW);
        assert_eq!(mm.mremap(dest, P, P, true, Some(A + 1)), Err(EINVAL), "unaligned target");
    });
}

#[test]
fn mremap_argument_checks() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        assert_eq!(mm.mremap(A + 1, P, P, true, None), Err(EINVAL));
        assert_eq!(mm.mremap(A, P, 0, true, None), Err(EINVAL));
        assert_eq!(mm.mremap(A + 8 * P, P, P, true, None), Err(EFAULT), "nothing mapped there");
        assert_eq!(mm.mremap(A, 2 * P, 2 * P, true, None), Err(EFAULT), "old range runs past the area");
    });
}

#[test]
#[ignore = "BUG: mremap with MREMAP_FIXED onto a destination that overlaps the source unmaps \
            part of the source before moving it, losing data; Linux returns EINVAL \
            (src/memory/vm.rs, mremap)"]
fn mremap_rejects_overlapping_fixed_destination() {
    with_mm(|mm| {
        anon(mm, A, 4 * P, RW);
        let data = pattern(4 * P as usize, 2);
        mm.write_bytes(A, &data).unwrap();
        assert_eq!(mm.mremap(A, 4 * P, 4 * P, true, Some(A + 2 * P)), Err(EINVAL));
        assert_eq!(read(mm, A, data.len()), data, "source must be intact");
    });
}

#[test]
fn mremap_huge_old_length_fails_cleanly() {
    with_mm(|mm| {
        anon(mm, A, P, RW);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| mm.mremap(A, u64::MAX - 2 * P, P, false, None)));
        assert!(matches!(r, Ok(Err(_))), "expected an error, not a panic or success");
    });
}

// ------------------------------------------------------------------ fork

#[test]
fn fork_shares_private_pages_copy_on_write() {
    with_mm(|parent| {
        anon(parent, A, 2 * P, RW);
        parent.write_bytes(A, b"before fork").unwrap();
        let alls = x86_64::TLB_FLUSH_ALLS.load(Ordering::Relaxed);
        let mut child = parent.fork().unwrap();
        assert!(x86_64::TLB_FLUSH_ALLS.load(Ordering::Relaxed) > alls, "parent PTEs lost their write bit");

        assert_eq!(parent.translate(A), child.translate(A), "same frame after fork");
        assert!(!pte(parent, A).unwrap().contains(F::WRITABLE));
        assert!(!pte(&child, A).unwrap().contains(F::WRITABLE));

        parent.write_bytes(A, b"parent!").unwrap();
        assert_ne!(parent.translate(A), child.translate(A), "write took a private copy");
        assert_eq!(read(&mut child, A, 11), b"before fork");
        assert_eq!(read(parent, A, 11), b"parent!fork");

        child.write_bytes(A, b"child").unwrap();
        assert!(pte(&child, A).unwrap().contains(F::WRITABLE), "last owner writes in place");
        assert_eq!(read(&mut child, A, 5), b"child");
        assert!(child.translate(A + P).is_none(), "untouched pages stay unmapped in both");
    });
}

#[test]
fn fork_keeps_shared_mappings_shared() {
    with_mm(|parent| {
        parent.mmap(A, P, RW, true, true, false, Backing::Anon).unwrap();
        parent.write_bytes(A, b"one").unwrap();
        let mut child = parent.fork().unwrap();
        assert!(pte(&child, A).unwrap().contains(F::WRITABLE));
        child.write_bytes(A, b"two").unwrap();
        assert_eq!(read(parent, A, 3), b"two", "MAP_SHARED writes are visible to both");
    });
}

#[test]
fn fork_copies_metadata_but_not_userfaultfd() {
    with_mm(|parent| {
        anon(parent, A, P, RW);
        parent.set_uffd(A, A + P, 7, None).unwrap();
        parent.brk_start = A + 16 * P;
        parent.brk = A + 17 * P;
        parent.auxv = vec![1, 2, 3];
        let child = parent.fork().unwrap();
        assert_eq!((child.brk_start, child.brk, child.auxv.clone()), (A + 16 * P, A + 17 * P, vec![1, 2, 3]));
        assert_eq!(child.find_vma(A).unwrap().uffd, 0);
        assert_eq!(parent.find_vma(A).unwrap().uffd, 7);
    });
}

#[test]
fn dropping_the_parent_first_leaves_the_child_intact() {
    with_mm(|_| {});
    let _g = common::serial();
    common::global_frames();
    let before = used();
    {
        let mut parent = Mm::new().unwrap();
        anon(&mut parent, A, P, RW);
        parent.write_bytes(A, b"survives").unwrap();
        let mut child = parent.fork().unwrap();
        drop(parent);
        assert_eq!(read(&mut child, A, 8), b"survives");
        child.write_bytes(A, b"S").unwrap(); // sole owner now: no copy needed
        assert_eq!(read(&mut child, A, 8), b"Survives");
    }
    assert_eq!(used(), before);
}

// ------------------------------------------------------- object mappings

fn object(pages: usize) -> Arc<BufferObject> {
    BufferObject::new(pattern(pages * P as usize, 11).into_boxed_slice())
}

#[test]
fn private_file_mapping_reads_object_and_copies_on_write() {
    with_mm(|mm| {
        let obj = object(3);
        let backing = Backing::Object { obj: obj.clone(), pgoff: 1 };
        mm.mmap(A, 2 * P, RW, false, true, false, backing).unwrap();
        mm.handle_fault(A, false, false).unwrap();
        let page1 = obj.get_page(1).unwrap().start_address();
        assert_eq!(mm.translate(A).unwrap(), page1, "read maps the object's page itself");
        assert!(!pte(mm, A).unwrap().contains(F::WRITABLE), "read-only until written");
        assert_eq!(read(mm, A, 16), &obj.bytes()[P as usize..P as usize + 16], "pgoff honoured");

        mm.write_bytes(A, b"private").unwrap();
        assert_ne!(mm.translate(A).unwrap(), page1, "write took a copy");
        let original = unsafe { std::slice::from_raw_parts(page1.as_u64() as *const u8, 7) };
        assert_eq!(original, &obj.bytes()[P as usize..P as usize + 7], "file page untouched");
    });
}

#[test]
fn shared_file_mapping_writes_through() {
    with_mm(|mm| {
        let obj = object(1);
        mm.mmap(A, P, RW, true, true, false, Backing::Object { obj: obj.clone(), pgoff: 0 }).unwrap();
        mm.write_bytes(A, b"shared").unwrap();
        let page = obj.get_page(0).unwrap().start_address().as_u64();
        assert_eq!(unsafe { std::slice::from_raw_parts(page as *const u8, 6) }, b"shared");
    });
}

#[test]
fn file_mapping_past_the_object_is_sigbus() {
    with_mm(|mm| {
        let obj = object(1);
        mm.mmap(A, 3 * P, PROT_READ, false, true, false, Backing::Object { obj, pgoff: 0 }).unwrap();
        assert_eq!(mm.handle_fault(A, false, false), Ok(()));
        assert_eq!(mm.handle_fault(A + 2 * P, false, false), Err(FaultError::Bus));
    });
}

#[test]
fn splitting_a_file_mapping_keeps_offsets() {
    with_mm(|mm| {
        let obj = object(4);
        mm.mmap(A, 4 * P, RW, false, true, false, Backing::Object { obj: obj.clone(), pgoff: 0 }).unwrap();
        mm.mprotect(A + 2 * P, P, PROT_READ).unwrap();
        mm.handle_fault(A + 3 * P, false, false).unwrap();
        assert_eq!(read(mm, A + 3 * P, 8), &obj.bytes()[3 * P as usize..3 * P as usize + 8]);
        mm.mprotect(A + 2 * P, P, RW).unwrap();
        assert_eq!(mm.vmas().count(), 1, "consecutive file pages merge back");
    });
}

#[test]
fn buffer_object_pages() {
    with_mm(|_| {
        let obj = BufferObject::new(vec![7u8; P as usize + 10].into_boxed_slice());
        assert_eq!(obj.len(), P as usize + 10);
        let p1 = obj.get_page(1).unwrap();
        assert_eq!(obj.get_page(1), Some(p1), "cached");
        let tail = unsafe { std::slice::from_raw_parts(p1.start_address().as_u64() as *const u8, P as usize) };
        assert_eq!(&tail[..10], &[7; 10]);
        assert!(tail[10..].iter().all(|&b| b == 0), "partial last page is zero-filled");
        assert!(obj.get_page(2).is_none());
    });
}

// ------------------------------------------------------------- userfaultfd

#[test]
fn userfaultfd_ranges() {
    with_mm(|mm| {
        anon(mm, A, 2 * P, RW);
        assert_eq!(mm.set_uffd(A, A + 2 * P, 5, None), Ok(()));
        assert_eq!(mm.uffd_missing(A + 100), Some(5));
        assert_eq!(mm.fill_page(A, Some(b"filled"), 6), Err(-2), "wrong descriptor");
        assert_eq!(mm.fill_page(A, Some(b"filled"), 5), Ok(()));
        assert_eq!(read(mm, A, 6), b"filled");
        assert_eq!(mm.uffd_missing(A), None, "page now present");
        assert_eq!(mm.fill_page(A, None, 5), Err(-17), "UFFDIO_COPY onto a present page");
        assert_eq!(mm.fill_page(A + P, None, 5), Ok(()), "UFFDIO_ZEROPAGE");
        assert_eq!(read(mm, A + P, 4), [0; 4]);

        assert_eq!(mm.set_uffd(A, A + P, 9, None), Err(-16), "registered to another descriptor: EBUSY");
        assert_eq!(mm.set_uffd(A, A + 3 * P, 5, None), Err(EINVAL), "hole in the range");
        assert_eq!(mm.set_uffd(A, A + 2 * P, 0, None), Ok(()), "unregister");
        assert_eq!(mm.uffd_missing(A + P), None);
    });
}

#[test]
fn userfaultfd_needs_anonymous_memory() {
    with_mm(|mm| {
        mm.mmap(A, P, RW, false, true, false, Backing::Object { obj: object(1), pgoff: 0 }).unwrap();
        assert_eq!(mm.set_uffd(A, A + P, 1, None), Err(EINVAL));
    });
}

// ------------------------------------------------------------ /proc maps

#[test]
fn maps_text_matches_linux_format() {
    with_mm(|mm| {
        anon(mm, A, 2 * P, RW);
        mm.mmap(A + 4 * P, P, RX, false, true, false, Backing::Object { obj: object(4), pgoff: 3 }).unwrap();
        mm.set_name(A + 4 * P, A + 5 * P, Some("/usr/lib/libc.so.6"));
        mm.mmap(A + 8 * P, P, PROT_READ, true, true, false, Backing::Anon).unwrap();
        let text = mm.maps_text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], format!("{:08x}-{:08x} rw-p 00000000 00:00 0", A, A + 2 * P));
        assert!(lines[1].starts_with(&format!("{:08x}-{:08x} r-xp {:08x} 00:00 0", A + 4 * P, A + 5 * P, 3 * P)));
        assert_eq!(lines[1].find('/'), Some(73), "path column");
        assert!(lines[1].ends_with(" /usr/lib/libc.so.6"));
        assert!(lines[2].contains(" r--s "));
    });
}

#[test]
fn set_name_splits_and_relabels() {
    with_mm(|mm| {
        anon(mm, A, 3 * P, RW);
        mm.set_name(A + P, A + 2 * P, Some("[anon:jit]"));
        let names: Vec<Option<String>> = mm.vmas().map(|v| v.name.as_deref().map(String::from)).collect();
        assert_eq!(names, vec![None, Some("[anon:jit]".into()), None]);
        mm.set_name(A + P, A + 2 * P, None);
        assert_eq!(mm.vmas().count(), 1, "unnamed again: merges back");
    });
}

// --------------------------------------------------- low address-space slots

const GIB: u64 = common::GIB;

#[test]
fn by_default_programs_get_only_the_first_gib_below_the_main_area() {
    let _g = common::serial();
    assert!(!kernel_low_slot(0));
    assert!((1..512).all(kernel_low_slot));
    assert!(!kernel_low_slot(512), "past the low area");
    assert_eq!(low_user_end(), LOW_USER_END);
}

#[test]
fn the_layout_gives_programs_the_slots_the_kernel_does_not_use() {
    let _g = common::serial();
    // The kernel image, firmware and devices between 2 and 5 GiB, as on a typical PC
    let _l = common::LowLayout::kernel_at(&[(2 * GIB, 5 * GIB)]);
    assert!(!kernel_low_slot(1) && kernel_low_slot(2) && kernel_low_slot(4) && !kernel_low_slot(5));
    assert_eq!(low_user_end(), 2 * GIB, "the first 2 GiB");
    assert!(is_user_range(GIB, GIB), "slot 1");
    assert!(!is_user_range(2 * GIB - P, 2 * P), "running into a kernel slot");
    assert!(!is_user_range(3 * GIB, P), "inside one");
    assert!(is_user_range(5 * GIB, 100 * GIB), "above the kernel's slots");
    assert!(is_user_range(USER_SPACE_START - P, 2 * P), "from the low area into the main user area");
}

#[test]
fn slot_0_is_never_the_kernels_and_ranges_outside_the_low_area_are_ignored() {
    let _g = common::serial();
    let _l = common::LowLayout::kernel_at(&[(0, 0x1000), (USER_SPACE_START, USER_SPACE_START + GIB), (7 * GIB, 7 * GIB)]);
    assert!(!kernel_low_slot(0), "slot 0 always belongs to programs (0x400000 executables)");
    assert!((1..512).all(|i| !kernel_low_slot(i)), "empty or out-of-area ranges mark nothing");
    assert_eq!(low_user_end(), 2 * GIB, "the MAP_32BIT window still ends at 2 GiB");
}

#[test]
fn mappings_in_freed_low_slots_work_and_their_tables_are_released() {
    let _g = common::serial();
    common::global_frames();
    fake::reset();
    let _l = common::LowLayout::kernel_at(&[(2 * GIB, 5 * GIB)]);
    let before = used();
    {
        let mut mm = Mm::new().unwrap();
        assert_eq!(mm.mmap(GIB + P, P, RW, false, true, false, Backing::Anon), Ok(GIB + P), "slot 1");
        assert_eq!(mm.mmap(6 * GIB, P, RW, false, true, false, Backing::Anon), Ok(6 * GIB), "slot 6");
        mm.write_bytes(GIB + P, b"slot one").unwrap();
        mm.write_bytes(6 * GIB, b"slot six").unwrap();
        assert_eq!(read(&mut mm, GIB + P, 8), b"slot one");
        assert_eq!(read(&mut mm, 6 * GIB, 8), b"slot six");
        assert_eq!(mm.mmap(3 * GIB, P, RW, false, false, true, Backing::Anon), Err(EEXIST), "a kernel slot looks taken");
        assert_eq!(mm.mmap(3 * GIB, P, RW, false, true, false, Backing::Anon), Err(ENOMEM), "and MAP_FIXED cannot replace it");
    }
    assert_eq!(used(), before, "page tables built in the program's low slots are freed with it");
}

#[test]
fn find_free_in_searches_a_window_top_down() {
    with_mm(|mm| {
        let (lo, hi) = (A, A + 16 * P);
        assert_eq!(mm.find_free_in(P, lo, hi), Some(hi - P));
        anon(mm, hi - 2 * P, 2 * P, RW);
        assert_eq!(mm.find_free_in(2 * P, lo, hi), Some(hi - 4 * P), "below the area at the top");
        assert_eq!(mm.find_free_in(100, lo, hi), Some(hi - 3 * P), "the length rounds up to a page");
        anon(mm, lo, 13 * P, RW);
        assert_eq!(mm.find_free_in(P, lo, hi), Some(lo + 13 * P), "the one free page");
        assert_eq!(mm.find_free_in(2 * P, lo, hi), None, "no gap big enough");
        anon(mm, hi, P, RW);
        anon(mm, lo - P, P, RW);
        assert_eq!(mm.find_free_in(P, lo, hi), Some(lo + 13 * P), "areas outside the window change nothing");
    });
}
