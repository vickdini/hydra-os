//! `arch/pcid.rs`: the per-CPU PCID slots (hits, take-overs, stale marks), local and remote
//! flush decisions with and without INVPCID, and global kernel pages (with
//! `memory/paging.rs`'s `mark_kernel_global` on real tables). PCID state is global: every
//! test holds [`serial`] and plays its own CPU.

mod common;

use std::sync::{Mutex, MutexGuard};

use hydra_hosttests_t32::arch::{pcid, smp};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;
use x86_64::structures::paging::{PageTable, PageTableFlags as F};

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    g
}

const NOFLUSH: u64 = 1 << 63;

/// The kernel's slot hash (`slot_of`): the PCID an address space gets.
fn slot(pml4: u64) -> u64 {
    (((pml4 >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) % 4095) + 1
}

/// PCID on (with or without INVPCID), this thread playing CPU `cpu`.
fn on(cpu: usize, invpcid: bool) {
    host::set_cpu(cpu);
    hw::set_cr(3, 0x1000 | 0x5); // the firmware left low bits set
    pcid::init_with(true, invpcid);
    assert!(pcid::enabled());
    host::CR3_WRITES.with_borrow_mut(|w| w.clear());
    host::INVPCID.with_borrow_mut(|w| w.clear());
}

#[test]
fn init_turns_pcid_on() {
    let _g = serial();
    // (a CPU without PCID only logs it: init runs once, and other tests turned it on)
    pcid::init_with(false, false);
    assert!(stubs::take_log()[0].contains("the CPU does not have it"));
    hw::set_cr(3, 0x7000 | 0x18);
    hw::set_cr(4, 0x6A0);
    pcid::init_with(true, false);
    assert!(pcid::enabled());
    assert_eq!(hw::cr(3), 0x7000, "CR3's low bits cleared first");
    assert_eq!(hw::cr(4) & (1 << 17), 1 << 17, "CR4.PCIDE");
    assert!(stubs::take_log()[0].contains("INVPCID no (CR3/CR4 fallback)"));
    pcid::init_with(true, true);
    assert!(stubs::take_log()[0].contains("4095 IDs per CPU, INVPCID yes"));
    assert!(pcid::summary().contains("PCID on (INVPCID yes)"));
}

#[test]
fn switching_address_spaces_keeps_or_flushes_ids() {
    let _g = serial();
    on(2, true);
    let (a, b) = (0x10_0000u64, 0x20_0000u64);
    pcid::load_cr3(a);
    assert_eq!(smp::LOADED_CR3[2].load(std::sync::atomic::Ordering::SeqCst), a);
    // First load: the slot is taken over, the ID flushed (no bit 63)
    assert_eq!(hw::cr(3), a | slot(a));
    pcid::load_cr3(b);
    assert_eq!(hw::cr(3), b | slot(b));
    // Back to A: its ID still holds A's entries
    pcid::load_cr3(a);
    assert_eq!(hw::cr(3), a | slot(a) | NOFLUSH);
    // The same tables again: nothing written
    let n = host::CR3_WRITES.with_borrow(|w| w.len());
    pcid::load_cr3(a);
    assert_eq!(host::CR3_WRITES.with_borrow(|w| w.len()), n);
    // Another CPU marked A stale (a shootdown while this CPU ran B): the next load flushes
    pcid::load_cr3(b);
    pcid::mark_remote(2, a);
    pcid::load_cr3(a);
    assert_eq!(hw::cr(3), a | slot(a), "stale: flushed");
    pcid::load_cr3(b);
    pcid::load_cr3(a);
    assert_eq!(hw::cr(3), a | slot(a) | NOFLUSH, "and kept again after");
    // A different address space hashing to A's slot takes it over: A's next load flushes
    let mut c = a + 0x1000;
    while slot(c) != slot(a) {
        c += 0x1000;
    }
    pcid::load_cr3(c);
    assert_eq!(hw::cr(3), c | slot(a));
    pcid::load_cr3(a);
    assert_eq!(hw::cr(3), a | slot(a), "taken over: flushed");
    // forget (an address space freed): every CPU's slot for it is cleared
    pcid::load_cr3(b);
    pcid::forget(a);
    pcid::load_cr3(a);
    assert_eq!(hw::cr(3), a | slot(a), "forgotten: flushed");
    let s = pcid::summary();
    assert!(s.contains("kept the TLB") && s.contains("a stale ID"), "{s}");
}

#[test]
fn local_shootdowns() {
    let _g = serial();
    on(3, true);
    let (a, b) = (0x30_0000u64, 0x40_0000u64);
    pcid::load_cr3(b);
    pcid::load_cr3(a);
    // The loaded space: invlpg, or a CR3 write without bit 63 for all of it
    hw::FLUSHED.with_borrow_mut(|f| f.clear());
    pcid::shoot_local(a, Some(0x7000));
    assert_eq!(hw::FLUSHED.with_borrow(|f| f.clone()), vec![0x7000]);
    hw::set_cr(3, a | slot(a) | NOFLUSH);
    pcid::shoot_local(a, None);
    assert_eq!(hw::cr(3), a | slot(a), "bit 63 off: the ID flushed");
    // Another space cached here: INVPCID of its ID
    pcid::shoot_local(b, Some(0x9000));
    pcid::shoot_local(b, None);
    assert_eq!(host::INVPCID.with_borrow(|v| v.clone()), vec![(slot(b) as u16, Some(0x9000)), (slot(b) as u16, None)]);
    // Not cached here: nothing
    pcid::shoot_local(0x50_0000, None);
    assert_eq!(host::INVPCID.with_borrow(|v| v.len()), 2);
    // Without INVPCID: the slot is marked stale instead (flushed at its next load)
    pcid::without_invpcid(|| pcid::shoot_local(b, Some(0x9000)));
    pcid::load_cr3(b);
    assert_eq!(hw::cr(3), b | slot(b), "stale mark: flushed on load");
    assert_eq!(host::INVPCID.with_borrow(|v| v.len()), 2);
    // Everything: INVPCID type 2, or toggling CR4.PGE twice
    pcid::flush_all_ids();
    assert_eq!(host::INVPCID.with_borrow(|v| *v.last().unwrap()), (0xFFFF, None));
    hw::CR_WRITES.with_borrow_mut(|w| w.clear());
    let cr4 = hw::cr(4);
    pcid::without_invpcid(pcid::flush_all_ids);
    assert_eq!(hw::CR_WRITES.with_borrow(|w| w.clone()), vec![(4, cr4 ^ (1 << 7)), (4, cr4)]);
    assert!(pcid::summary().contains("INVPCID single-ID flushes"));
}

/// Kernel tables at fixed addresses (an arena): PML4 entry 256 -> PDPT with one 1 GiB
/// page, one PD with a 2 MiB page and a PT with two 4 KiB pages, one of them a user page;
/// entry 0 (user half) with a 1 GiB page that must not be touched.
fn kernel_tables(base: u64) -> u64 {
    let t = |i: u64| unsafe { &mut *((base + i * 4096) as *mut PageTable) };
    let (pml4, pdpt, pd, pt, low) = (0, 1, 2, 3, 4);
    let k = F::PRESENT | F::WRITABLE;
    t(pml4)[256].set_addr(x86_64::PhysAddr::new(base + 4096 * pdpt), k);
    t(pml4)[0].set_addr(x86_64::PhysAddr::new(base + 4096 * low), k | F::USER_ACCESSIBLE);
    t(low)[0].set_addr(x86_64::PhysAddr::new(0), k | F::HUGE_PAGE);
    t(pdpt)[0].set_addr(x86_64::PhysAddr::new(0x4000_0000), k | F::HUGE_PAGE);
    t(pdpt)[1].set_addr(x86_64::PhysAddr::new(base + 4096 * pd), k);
    t(pd)[0].set_addr(x86_64::PhysAddr::new(0x20_0000), k | F::HUGE_PAGE);
    t(pd)[1].set_addr(x86_64::PhysAddr::new(base + 4096 * pt), k);
    t(pt)[0].set_addr(x86_64::PhysAddr::new(0x9000), k);
    t(pt)[1].set_addr(x86_64::PhysAddr::new(0xA000), k | F::USER_ACCESSIBLE);
    base
}

#[test]
fn global_kernel_pages() {
    let _g = serial();
    let arena = common::Arena::new(1);
    let pml4 = kernel_tables(arena.base);
    host::set_cpu(5);
    hw::set_cr(3, pml4 | 0x3);
    hw::set_cr(4, 0x6A0);
    pcid::enable_global();
    assert!(pcid::global_enabled());
    let log = stubs::take_log();
    assert!(log[0].contains("global kernel pages on: 1 1 GiB, 1 2 MiB and 1 4 KiB kernel entries"), "{log:?}");
    let e = |t: u64, i: usize| unsafe { (&*((arena.base + t * 4096) as *const PageTable))[i].flags() };
    assert!(e(1, 0).contains(F::GLOBAL));
    assert!(e(2, 0).contains(F::GLOBAL));
    assert!(e(3, 0).contains(F::GLOBAL));
    assert!(!e(3, 1).contains(F::GLOBAL), "user page");
    assert!(!e(4, 0).contains(F::GLOBAL), "user half untouched");
    // PGE turned off then on: every cached entry flushed
    let w = hw::CR_WRITES.with_borrow(|w| w.clone());
    assert_eq!(&w[w.len() - 2..], &[(4, 0x6A0 & !(1 << 7)), (4, 0x6A0 | (1 << 7))]);
    assert!(pcid::summary().contains("global kernel pages on"));
    pcid::disable_global("a test");
    assert!(!pcid::global_enabled());
    assert_eq!(hw::cr(4) & (1 << 7), 0);
    assert!(stubs::take_log()[0].contains("turned off: a test"));
    // Once off by a reason, enabling again says so
    pcid::enable_global();
    assert!(!pcid::global_enabled());
    assert!(stubs::take_log()[0].contains("turned off by a test"));
}
