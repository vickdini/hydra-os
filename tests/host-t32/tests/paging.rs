//! `memory/paging.rs`: page-table walks, edits and address-space construction on fake
//! frames (an arena of committed memory at fixed addresses, so physical = virtual).

mod common;

use std::sync::{Mutex, MutexGuard};

use common::Arena;
use hydra_hosttests_t32::host;
use hydra_hosttests_t32::memory::frame_allocator::PhysicalMemoryManager;
use hydra_hosttests_t32::memory::paging::{self, AddressSpace};
use x86_64::hw;
use x86_64::structures::paging::{Page, PageTable, PageTableFlags as F, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    g
}

/// A frame allocator over `arena` (minus the refcount table it keeps at its start).
fn frames(arena: &Arena) -> PhysicalMemoryManager {
    let mut fa = PhysicalMemoryManager::new();
    fa.add_region(PhysAddr::new(arena.base), arena.size / 4096);
    fa.init_refcounts();
    fa
}

fn table<'a>(pa: u64) -> &'a mut PageTable {
    unsafe { &mut *(pa as *mut PageTable) }
}

fn page(va: u64) -> Page<Size4KiB> {
    Page::containing_address(VirtAddr::new(va))
}

fn frame(pa: u64) -> PhysFrame<Size4KiB> {
    PhysFrame::containing_address(PhysAddr::new(pa))
}

/// An empty top-level table from `fa`.
fn space(fa: &mut PhysicalMemoryManager) -> AddressSpace {
    AddressSpace::from_pml4(fa.allocate_zeroed_frame().unwrap().start_address())
}

#[test]
fn map_translate_update_unmap() {
    let _g = serial();
    let arena = Arena::new(1);
    let mut fa = frames(&arena);
    let mut s = space(&mut fa);
    let va = 0x0000_7F00_1234_5000u64;
    let pa = arena.base + 0x30_0000;
    let used = fa.allocated_memory();
    unsafe {
        assert_eq!(s.translate_addr(VirtAddr::new(va)), None);
        assert!(s.translate_page(page(va)).is_none());
        s.map_page(page(va), frame(pa), F::WRITABLE | F::USER_ACCESSIBLE, &mut fa).unwrap();
        assert_eq!(fa.allocated_memory() - used, 3 * 4096, "PDPT, PD and PT made");
        assert_eq!(s.translate_addr(VirtAddr::new(va + 0x123)), Some(PhysAddr::new(pa + 0x123)));
        let (f, fl) = s.translate_page(page(va)).unwrap();
        assert_eq!(f, frame(pa));
        assert!(fl.contains(F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE));
        // Intermediate tables are user-accessible and writable (the leaf decides)
        let p4 = table(s.pml4_physical_address().as_u64());
        assert!(p4[page(va).p4_index()].flags().contains(F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE));
        // The TLB entry was flushed
        assert_eq!(hw::FLUSHED.with_borrow(|f| *f.last().unwrap()), va);
        assert_eq!(s.map_page(page(va), frame(pa), F::empty(), &mut fa), Err("Page is already mapped"));
        // A neighbour shares the tables
        s.map_page(page(va + 0x1000), frame(pa + 0x1000), F::empty(), &mut fa).unwrap();
        assert_eq!(fa.allocated_memory() - used, 3 * 4096);
        // Flags
        s.update_flags(page(va), F::NO_EXECUTE).unwrap();
        let (_, fl) = s.translate_page(page(va)).unwrap();
        assert_eq!(fl, F::PRESENT | F::NO_EXECUTE);
        assert_eq!(s.leaf_entry(va).unwrap().flags(), F::PRESENT | F::NO_EXECUTE);
        // Unmap
        assert_eq!(s.unmap_page(page(va)), Ok(frame(pa)));
        assert_eq!(s.translate_addr(VirtAddr::new(va)), None);
        assert_eq!(s.unmap_page(page(va)), Err("Page table entry not present"));
        assert_eq!(s.update_flags(page(va), F::empty()), Err("Page table entry not present"));
        assert!(s.leaf_entry(va).unwrap().is_unused());
        // Missing levels
        let far = 0x0000_1000_0000_0000u64;
        assert_eq!(s.unmap_page(page(far)), Err("PML4 entry not present"));
        assert_eq!(s.update_flags(page(far), F::empty()), Err("PML4 entry not present"));
        assert!(s.leaf_entry(far).is_none());
        let other_gib = va + (1 << 30);
        assert_eq!(s.unmap_page(page(other_gib)), Err("PDPT entry not present"));
        assert_eq!(s.update_flags(page(other_gib), F::empty()), Err("PDPT entry not present"));
        assert!(s.leaf_entry(other_gib).is_none());
        let other_2m = va + (2 << 20);
        assert_eq!(s.unmap_page(page(other_2m)), Err("PD entry not present"));
        assert_eq!(s.update_flags(page(other_2m), F::empty()), Err("PD entry not present"));
        assert!(s.leaf_entry(other_2m).is_none());
        assert_eq!(s.translate_addr(VirtAddr::new(other_2m)), None);
        assert!(s.translate_page(page(other_2m)).is_none());
        assert!(s.translate_page(page(other_gib)).is_none());
        assert!(s.translate_page(page(far)).is_none());
        assert_eq!(s.translate_addr(VirtAddr::new(other_gib)), None);
    }
}

#[test]
fn huge_pages() {
    let _g = serial();
    let arena = Arena::new(2);
    let mut fa = frames(&arena);
    let mut s = space(&mut fa);
    let pdpt = fa.allocate_zeroed_frame().unwrap().start_address().as_u64();
    let pd = fa.allocate_zeroed_frame().unwrap().start_address().as_u64();
    let p4 = table(s.pml4_physical_address().as_u64());
    p4[1].set_addr(PhysAddr::new(pdpt), F::PRESENT | F::WRITABLE);
    // GiB 0 of this PDPT: a 1 GiB page; GiB 1: a PD whose first entry is a 2 MiB page
    table(pdpt)[0].set_addr(PhysAddr::new(0x4000_0000), F::PRESENT | F::WRITABLE | F::HUGE_PAGE | F::GLOBAL);
    table(pdpt)[1].set_addr(PhysAddr::new(pd), F::PRESENT | F::WRITABLE);
    table(pd)[0].set_addr(PhysAddr::new(0x20_0000), F::PRESENT | F::WRITABLE | F::HUGE_PAGE | F::NO_EXECUTE | F::GLOBAL);
    let g = 1u64 << 39;
    unsafe {
        assert_eq!(s.translate_addr(VirtAddr::new(g + 0x1234_5678)), Some(PhysAddr::new(0x4000_0000 + 0x1234_5678)));
        assert_eq!(s.translate_addr(VirtAddr::new(g + (1 << 30) + 0x12_3456)), Some(PhysAddr::new(0x20_0000 + 0x12_3456)));
        assert!(s.translate_page(page(g)).is_none(), "4 KiB view of a 1 GiB page");
        assert!(s.translate_page(page(g + (1 << 30))).is_none(), "4 KiB view of a 2 MiB page");
        assert_eq!(s.map_page(page(g + 0x1000), frame(arena.base), F::empty(), &mut fa), Err("Cannot traverse into huge page"));
        assert_eq!(s.unmap_page(page(g)), Err("Cannot unmap 4 KiB page within 1 GiB huge page"));
        assert_eq!(s.unmap_page(page(g + (1 << 30))), Err("Cannot unmap 4 KiB page within 2 MiB huge page"));
        assert!(s.leaf_entry(g).is_none());
        assert!(s.leaf_entry(g + (1 << 30)).is_none());
        // Made user-accessible: GLOBAL dropped on both, NX dropped on the 2 MiB page
        s.make_user_accessible(VirtAddr::new(g), 4096).unwrap();
        s.make_user_accessible(VirtAddr::new(g + (1 << 30)), 4096).unwrap();
    }
    let f1 = table(pdpt)[0].flags();
    let f2 = table(pd)[0].flags();
    assert!(f1.contains(F::USER_ACCESSIBLE | F::WRITABLE) && !f1.contains(F::GLOBAL));
    assert!(f2.contains(F::USER_ACCESSIBLE) && !f2.contains(F::GLOBAL) && !f2.contains(F::NO_EXECUTE));
    assert!(p4[1].flags().contains(F::USER_ACCESSIBLE));
    assert_eq!(host::WP_TOGGLES.get(), (2, 2), "CR0.WP off and on around each");
}

#[test]
fn make_user_accessible_walks_4k_pages() {
    let _g = serial();
    let arena = Arena::new(3);
    let mut fa = frames(&arena);
    let mut s = space(&mut fa);
    let va = 0x40_0000u64;
    unsafe {
        for i in 0..3 {
            s.map_page(page(va + i * 4096), frame(arena.base + i * 4096), F::GLOBAL, &mut fa).unwrap();
        }
        hw::FLUSHED.with_borrow_mut(|f| f.clear());
        // Four pages asked, three mapped (the fourth is skipped), from an unaligned start
        s.make_user_accessible(VirtAddr::new(va + 0x10), 4 * 4096 - 0x10).unwrap();
        for i in 0..3 {
            let (_, fl) = s.translate_page(page(va + i * 4096)).unwrap();
            assert!(fl.contains(F::USER_ACCESSIBLE | F::WRITABLE) && !fl.contains(F::GLOBAL));
        }
        assert_eq!(hw::FLUSHED.with_borrow(|f| f.len()), 3);
        // Nothing at all there: every level skipped
        s.make_user_accessible(VirtAddr::new(0x0000_6000_0000_0000), 4096).unwrap();
        s.make_user_accessible(VirtAddr::new(va + (1 << 30)), 4096).unwrap();
        s.make_user_accessible(VirtAddr::new(va + (4 << 20)), 4096).unwrap();
        let wp = host::WP_TOGGLES.get();
        s.make_user_accessible(VirtAddr::new(va), 0).unwrap();
        assert_eq!(host::WP_TOGGLES.get(), wp, "size 0: nothing done");
    }
}

#[test]
fn map_range_identity_and_out_of_memory() {
    let _g = serial();
    let arena = Arena::new(4);
    let mut fa = frames(&arena);
    let mut s = space(&mut fa);
    let start = arena.base + 0x20_0000;
    unsafe {
        s.map_range(page(0x80_0000), frame(start), 4, F::WRITABLE, &mut fa).unwrap();
        for i in 0..4 {
            assert_eq!(s.translate_addr(VirtAddr::new(0x80_0000 + i * 4096)), Some(PhysAddr::new(start + i * 4096)));
        }
        assert_eq!(s.map_range(page(0x80_3000), frame(start), 2, F::WRITABLE, &mut fa), Err("Page is already mapped"));
        s.identity_map(frame(start + 0x10_0000), F::WRITABLE, &mut fa).unwrap();
        assert_eq!(s.translate_addr(VirtAddr::new(start + 0x10_0000)), Some(PhysAddr::new(start + 0x10_0000)));
    }
    // An allocator with nothing left: the new table cannot be made
    let mut empty = PhysicalMemoryManager::new();
    unsafe {
        assert_eq!(
            s.map_page(page(0x0000_5000_0000_0000), frame(start), F::empty(), &mut empty),
            Err("Out of physical memory: failed to allocate page table frame")
        );
    }
    assert!(AddressSpace::create_user_space(&mut empty).is_err());
    assert!(AddressSpace::create_kernel_space(&mut empty).is_err());
}

/// Boot tables like the firmware's: PML4 entry 0 -> a PDPT identity-mapping GiB 0..4 with
/// 1 GiB pages. CR3 points at them.
fn boot_tables(fa: &mut PhysicalMemoryManager) -> u64 {
    let pml4 = fa.allocate_zeroed_frame().unwrap().start_address().as_u64();
    let pdpt = fa.allocate_zeroed_frame().unwrap().start_address().as_u64();
    table(pml4)[0].set_addr(PhysAddr::new(pdpt), F::PRESENT | F::WRITABLE);
    for g in 0..4 {
        table(pdpt)[g].set_addr(PhysAddr::new((g as u64) << 30), F::PRESENT | F::WRITABLE | F::HUGE_PAGE);
    }
    hw::set_cr(3, pml4);
    pml4
}

#[test]
fn kernel_space_gets_the_direct_map() {
    let _g = serial();
    let arena = Arena::new(5);
    let mut fa = frames(&arena);
    let boot = boot_tables(&mut fa);
    assert_eq!(AddressSpace::active().pml4_physical_address().as_u64(), boot);
    let k = AddressSpace::create_kernel_space(&mut fa).unwrap();
    let p4 = table(k.pml4_physical_address().as_u64());
    assert_eq!(p4[0].addr().as_u64(), table(boot)[0].addr().as_u64(), "boot entries copied");
    // The direct map: 4 GiB at least (this RAM is below), 2 MiB pages, kernel-only, NX
    assert!(p4[256].flags().contains(F::PRESENT));
    let pdpt = table(p4[256].addr().as_u64());
    for g in 0..4 {
        let pd = table(pdpt[g].addr().as_u64());
        assert_eq!(pd[3].addr().as_u64(), ((g as u64) << 30) + (3 << 21));
        let f = pd[3].flags();
        assert!(f.contains(F::HUGE_PAGE | F::NO_EXECUTE | F::WRITABLE) && !f.contains(F::USER_ACCESSIBLE));
    }
    assert!(pdpt[4].is_unused());
    unsafe {
        assert_eq!(k.translate_addr(VirtAddr::new(0xFFFF_8000_0000_0000 + 0x1234_5678)), Some(PhysAddr::new(0x1234_5678)));
    }
    // Without NX in EFER: executable direct map
    host::NX.set(false);
    let k2 = AddressSpace::create_kernel_space(&mut fa).unwrap();
    let pd = table(table(table(k2.pml4_physical_address().as_u64())[256].addr().as_u64())[0].addr().as_u64());
    assert!(!pd[0].flags().contains(F::NO_EXECUTE));
    host::NX.set(true);
    // Boot tables that have the direct map already (arch::relocate built it): kept as is
    hw::set_cr(3, k.pml4_physical_address().as_u64());
    let used = fa.allocated_memory();
    let k3 = AddressSpace::create_kernel_space(&mut fa).unwrap();
    assert_eq!(fa.allocated_memory() - used, 4096, "only the PML4");
    assert_eq!(table(k3.pml4_physical_address().as_u64())[256].addr(), p4[256].addr());
}

#[test]
fn user_space_shares_the_kernel_half() {
    let _g = serial();
    let arena = Arena::new(6);
    let mut fa = frames(&arena);
    boot_tables(&mut fa);
    let k = AddressSpace::create_kernel_space(&mut fa).unwrap();
    hw::set_cr(3, k.pml4_physical_address().as_u64());
    let u = AddressSpace::create_user_space(&mut fa).unwrap();
    let (kp, up) = (table(k.pml4_physical_address().as_u64()), table(u.pml4_physical_address().as_u64()));
    for i in 256..512 {
        assert_eq!(up[i].addr(), kp[i].addr());
    }
    // Entry 0: a private PDPT, user-accessible; the slots the kernel keeps (GiB 2..4 by
    // the default layout) shared, the rest free for the program
    assert_ne!(up[0].addr(), kp[0].addr());
    assert!(up[0].flags().contains(F::USER_ACCESSIBLE));
    let (upd, kpd) = (table(up[0].addr().as_u64()), table(kp[0].addr().as_u64()));
    use hydra_hosttests_t32::memory::vm::kernel_low_slot;
    for i in 1..512 {
        if kernel_low_slot(i) {
            assert_eq!(upd[i].addr(), kpd[i].addr(), "slot {i} shared");
        } else {
            assert!(upd[i].is_unused(), "slot {i} free");
        }
    }
    assert!(upd[0].is_unused(), "GiB 0 always the program's");
}

#[test]
fn kernel_space_switching() {
    let _g = serial();
    let arena = Arena::new(8);
    let mut fa = frames(&arena);
    let boot = boot_tables(&mut fa);
    host::set_cpu(3);
    let pml4 = paging::init_kernel_space(&mut fa).unwrap();
    assert_eq!(paging::KERNEL_SPACE.lock().as_ref().unwrap().pml4_physical_address(), pml4);
    // Not yet the kernel's for good: nothing loaded
    paging::load_kernel_tables_for_good();
    assert_eq!(hw::cr(3), boot);
    paging::KERNEL_PML4.store(pml4.as_u64(), std::sync::atomic::Ordering::SeqCst);
    // Briefly: the kernel's tables, then the program's again, interrupts off meanwhile
    let seen = paging::with_kernel_tables(|| (hw::cr(3), hw::if_flag()));
    assert_eq!(seen, (pml4.as_u64(), false));
    assert_eq!(hw::cr(3), boot);
    paging::load_kernel_tables_for_good();
    assert_eq!(hw::cr(3), pml4.as_u64());
    unsafe { AddressSpace::from_pml4(PhysAddr::new(boot)).switch() };
    assert_eq!(hw::cr(3), boot);
    // The global helper edits the kernel's tables when they exist...
    let mut k = paging::KERNEL_SPACE.lock();
    unsafe { k.as_mut().unwrap().map_page(page(0x0000_4000_0000_0000), frame(arena.base), F::empty(), &mut fa).unwrap() };
    drop(k);
    paging::make_user_accessible(VirtAddr::new(0x0000_4000_0000_0000), 4096).unwrap();
    let k = paging::KERNEL_SPACE.lock();
    let (_, fl) = unsafe { k.as_ref().unwrap().translate_page(page(0x0000_4000_0000_0000)).unwrap() };
    assert!(fl.contains(F::USER_ACCESSIBLE));
    drop(k);
    // ...and the active ones without them
    *paging::KERNEL_SPACE.lock() = None;
    hw::set_cr(3, pml4.as_u64());
    paging::make_user_accessible(VirtAddr::new(0x0000_4000_0000_0000), 4096).unwrap();
    paging::KERNEL_PML4.store(0, std::sync::atomic::Ordering::SeqCst);
}
