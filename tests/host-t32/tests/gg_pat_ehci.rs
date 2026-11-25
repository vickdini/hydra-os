//! wave11 GG: `arch/pat.rs` (the write-combining memory type, the console's view of the
//! framebuffer in the direct map) and `arch/ehci.rs` (EHCI controllers taken from the
//! firmware and stopped before the IOMMU translates).

mod common;

use std::collections::BTreeMap;

use hydra_hosttests_t32::arch::ehci::{self, Hw, Outcome};
use hydra_hosttests_t32::arch::pat;
use hydra_hosttests_t32::memory::frame_allocator::{DIRECT_MAP_BASE, FRAME_ALLOCATOR};
use hydra_hosttests_t32::memory::paging::KERNEL_PML4;

const POWER_ON_PAT: u64 = 0x0007_0406_0007_0406;
const P: u64 = 1;
const W: u64 = 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const PS: u64 = 1 << 7;
const G: u64 = 1 << 8;
const NX: u64 = 1 << 63;

// ---- pat.rs: plain logic ----

#[test]
fn entry_one_becomes_write_combining_and_nothing_else_changes() {
    let v = pat::with_wc(POWER_ON_PAT);
    assert_eq!(v, 0x0007_0406_0007_0106);
    for i in [0u64, 2, 3, 4, 5, 6, 7] {
        assert_eq!((v >> (i * 8)) & 0xFF, (POWER_ON_PAT >> (i * 8)) & 0xFF, "entry {i}");
    }
    // A firmware that set its own layout keeps it, except entry 1
    assert_eq!(pat::with_wc(0x0505_0505_0505_0505), 0x0505_0505_0505_0105);
}

#[test]
fn memory_types_follow_the_entry_bits() {
    let v = pat::with_wc(POWER_ON_PAT);
    assert_eq!(pat::type_of_4k(v, P | W), pat::MT_WB);
    assert_eq!(pat::type_of_4k(v, P | W | PWT), pat::MT_WC, "PWT alone selects entry 1");
    assert_eq!(pat::type_of_4k(v, P | PCD | PWT), pat::MT_UC);
    assert_eq!(pat::type_of_4k(POWER_ON_PAT, P | PWT), pat::MT_WT, "before: write-through");
    assert_eq!(pat::type_of_4k(v, pat::make_wc(P | W | PCD | (1 << 7) | G | NX)), pat::MT_WC);
    assert_eq!(pat::make_wc(P | W | PCD | (1 << 7) | G | NX), P | W | PWT | G | NX);
}

#[test]
fn large_pages_split_into_the_same_memory() {
    // A 2 MiB leaf at 0xe0000000: 512 4 KiB leaves, rights, global and NX kept
    let e = 0xE000_0000 | P | W | PS | G | NX;
    let s = pat::split_large(e, 1 << 21);
    for (i, x) in s.iter().enumerate() {
        assert_eq!(*x, (0xE000_0000 + i as u64 * 4096) | P | W | G | NX, "entry {i}");
    }
    // Its PAT bit (bit 12 in a large leaf) moves to bit 7
    let s = pat::split_large(0x4000_0000 | P | PS | (1 << 12) | PWT, 1 << 21);
    assert_eq!(s[3], (0x4000_0000 + 3 * 4096) | P | PWT | (1 << 7));
    // A 1 GiB leaf: 512 2 MiB leaves
    let s = pat::split_large(0xC000_0000 | P | W | PS | NX, 1 << 30);
    assert_eq!(s[0], 0xC000_0000 | P | W | PS | NX);
    assert_eq!(s[511], (0xC000_0000 + 511 * (1 << 21)) | P | W | PS | NX);
}

// ---- pat.rs: the MSR and the direct map ----

fn alloc() -> u64 {
    FRAME_ALLOCATOR.lock().allocate_zeroed_frame().unwrap().start_address().as_u64()
}

fn at(table: u64, i: u64) -> *mut u64 {
    (table as *mut u64).wrapping_add(i as usize)
}

fn rd(table: u64, i: u64) -> u64 {
    unsafe { at(table, i).read() }
}

/// Kernel tables with the direct map's GiB slot 3 (0xc0000000..) in 2 MiB pages (`huge2m`)
/// or as one 1 GiB page. Returns (pml4, pdpt).
fn tables(huge1g: bool) -> (u64, u64) {
    let (pml4, pdpt) = (alloc(), alloc());
    unsafe { at(pml4, (DIRECT_MAP_BASE >> 39) & 511).write(pdpt | P | W) };
    if huge1g {
        unsafe { at(pdpt, 3).write(0xC000_0000 | P | W | PS | G | NX) };
    } else {
        let pd = alloc();
        for i in 0..512u64 {
            unsafe { at(pd, i).write((0xC000_0000 + (i << 21)) | P | W | PS | G | NX) };
        }
        unsafe { at(pdpt, 3).write(pd | P | W) };
    }
    (pml4, pdpt)
}

/// The 4 KiB leaf of direct-map address `DIRECT_MAP_BASE + phys` (None if a large page).
fn leaf(pdpt: u64, phys: u64) -> Option<u64> {
    let e3 = rd(pdpt, (phys >> 30) & 511);
    if e3 & PS != 0 {
        return None;
    }
    let e2 = rd(e3 & 0x000F_FFFF_FFFF_F000, (phys >> 21) & 511);
    if e2 & PS != 0 {
        return None;
    }
    Some(rd(e2 & 0x000F_FFFF_FFFF_F000, (phys >> 12) & 511))
}

#[test]
fn the_framebuffer_gets_a_write_combining_view_of_its_own_pages_only() {
    let _g = common::serial();
    common::global_frames();
    hydra_hosttests_t32::host::wrmsr(pat::IA32_PAT, POWER_ON_PAT);
    pat::init_bsp();
    assert!(pat::enabled());
    assert_eq!(hydra_hosttests_t32::host::rdmsr(pat::IA32_PAT), 0x0007_0406_0007_0106);
    assert!(pat::wc_flags().contains(x86_64::structures::paging::PageTableFlags::WRITE_THROUGH));
    // An application processor copies the value
    hydra_hosttests_t32::host::wrmsr(pat::IA32_PAT, POWER_ON_PAT);
    pat::init_ap();
    assert_eq!(hydra_hosttests_t32::host::rdmsr(pat::IA32_PAT), 0x0007_0406_0007_0106);

    for huge1g in [false, true] {
        let (pml4, pdpt) = tables(huge1g);
        KERNEL_PML4.store(pml4, std::sync::atomic::Ordering::SeqCst);
        // The NUC's framebuffer: 1920x1080x4 rounded up, 0x7e9000 bytes
        let (fb, len) = (0xE000_0000u64, 0x7E_9000u64);
        assert_eq!(pat::alias_wc(fb, len), Some(DIRECT_MAP_BASE + fb));
        for (off, wc) in [(0, true), (0x7E_8000, true), (0x7E_9000, false), (0x7F_F000, false)] {
            let e = leaf(pdpt, fb + off).expect("split to 4 KiB");
            assert_eq!(e & 0x000F_FFFF_FFFF_F000, fb + off, "same memory at {off:#x}");
            assert_eq!(e & PWT != 0, wc, "write-combining at {off:#x}");
            assert_eq!(e & (P | W | G | NX), P | W | G | NX, "rights kept at {off:#x}");
        }
        // Memory outside the framebuffer's 2 MiB pages stays as it was
        if huge1g {
            let e2 = rd(rd(pdpt, 3) & 0x000F_FFFF_FFFF_F000, 0);
            assert_eq!(e2, 0xC000_0000 | P | W | PS | G | NX);
        } else {
            assert!(leaf(pdpt, 0xE080_0000).is_none(), "the next 2 MiB page is not split");
        }
        // Not covered by the direct map: no view
        assert_eq!(pat::alias_wc(0x1_0000_0000, 4096), None);
        // Unaligned: no view
        assert_eq!(pat::alias_wc(fb + 8, 4096), None);
    }
    KERNEL_PML4.store(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(pat::alias_wc(0xE000_0000, 4096), None, "no kernel tables yet");
}

// ---- ehci.rs ----

/// A simulated EHCI controller: configuration space, registers, and a firmware that
/// lets go of it after `release_after` delays (never if `None`).
struct Fake {
    cfg: BTreeMap<u8, u32>,
    mmio: BTreeMap<usize, u32>,
    release_after: Option<u32>,
    delays: u32,
    halt_after: Option<u32>,
    log: Vec<String>,
}

const EECP: u8 = 0x68;
const CAPLEN: usize = 0x20;

impl Fake {
    fn new(bios_owned: bool, running: bool) -> Fake {
        let mut cfg = BTreeMap::new();
        cfg.insert(0x04, 0x0006); // memory decoding + bus mastering
        cfg.insert(EECP, 1 | if bios_owned { 1 << 16 } else { 0 });
        cfg.insert(EECP + 4, 0xE000_003F); // SMI enables and status
        let mut mmio = BTreeMap::new();
        mmio.insert(0x00, 0x0100_0000 | CAPLEN as u32);
        mmio.insert(0x08, (EECP as u32) << 8);
        mmio.insert(CAPLEN, if running { 0x0001_0031 } else { 0x0001_0000 });
        mmio.insert(CAPLEN + 4, if running { 0 } else { 1 << 12 });
        Fake { cfg, mmio, release_after: Some(3), delays: 0, halt_after: Some(2), log: Vec::new() }
    }
}

impl Hw for Fake {
    fn cfg_r32(&mut self, off: u8) -> u32 {
        *self.cfg.get(&off).unwrap_or(&0)
    }
    fn cfg_w32(&mut self, off: u8, v: u32) {
        self.log.push(format!("cfg {off:#x}={v:#x}"));
        self.cfg.insert(off, v);
    }
    fn mmio_r32(&mut self, off: usize) -> u32 {
        *self.mmio.get(&off).unwrap_or(&0)
    }
    fn mmio_w32(&mut self, off: usize, v: u32) {
        self.log.push(format!("mmio {off:#x}={v:#x}"));
        if off == CAPLEN + 4 {
            return; // status: write 1 to clear (nothing to clear in the fake)
        }
        self.mmio.insert(off, v);
    }
    fn delay_us(&mut self, _us: u64) {
        self.delays += 1;
        let os = self.cfg[&EECP] & (1 << 24) != 0;
        if os && self.release_after.is_some_and(|n| self.delays >= n) {
            let v = self.cfg[&EECP] & !(1 << 16);
            self.cfg.insert(EECP, v);
        }
        if self.mmio[&CAPLEN] & 1 == 0 && self.halt_after.is_some_and(|n| self.delays >= n) {
            let v = self.mmio[&(CAPLEN + 4)] | 1 << 12;
            self.mmio.insert(CAPLEN + 4, v);
        }
    }
}

#[test]
fn a_running_firmware_controller_is_handed_over_halted_and_kept_from_dma() {
    let mut f = Fake::new(true, true);
    let o = ehci::quiesce(&mut f);
    assert_eq!(o, Outcome { reachable: true, bios_owned: true, forced: false, was_running: true, halted: true });
    assert_eq!(f.cfg[&EECP] & (1 << 24 | 1 << 16), 1 << 24, "OS owned, BIOS let go");
    assert_eq!(f.cfg[&(EECP + 4)], 1 << 13, "SMIs off but the ownership one");
    assert_eq!(f.mmio[&CAPLEN] & 0x31, 0, "run and both schedules off");
    assert_eq!(f.mmio[&(CAPLEN + 8)], 0, "interrupts off");
    assert_eq!(f.cfg[&0x04] & 4, 0, "bus mastering off");
    assert_eq!(f.cfg[&0x04] & 2, 2, "memory decoding kept");
    // The handoff came before the halt
    let own = f.log.iter().position(|l| l.starts_with("cfg 0x68=")).unwrap();
    let halt = f.log.iter().position(|l| l.starts_with("mmio 0x20=")).unwrap();
    assert!(own < halt);
    assert!(ehci::describe("00:1d.0", &o).contains("was running: halted; the firmware handed it over"));
}

#[test]
fn a_firmware_that_does_not_let_go_loses_the_controller_by_force() {
    let mut f = Fake::new(true, false);
    f.release_after = None;
    let o = ehci::quiesce(&mut f);
    assert!(o.bios_owned && o.forced && o.halted && !o.was_running);
    assert_eq!(f.cfg[&EECP] & (1 << 24 | 1 << 16), 1 << 24);
    assert!(f.delays >= 1000, "a second for the firmware ({} waits)", f.delays);
    assert!(ehci::describe("00:1a.0", &o).contains("taken by force"));
}

#[test]
fn a_controller_that_never_halts_is_reported_and_still_loses_bus_mastering() {
    let mut f = Fake::new(false, true);
    f.halt_after = None;
    let o = ehci::quiesce(&mut f);
    assert!(!o.bios_owned && o.was_running && !o.halted);
    assert_eq!(f.cfg[&0x04] & 4, 0);
    assert!(ehci::describe("00:1d.0", &o).contains("DID NOT HALT"));
}

#[test]
fn an_unreachable_controller_only_loses_bus_mastering() {
    let mut f = Fake::new(true, true);
    f.cfg.insert(0x04, 0x0004); // decoding off: its registers do not answer
    let o = ehci::quiesce(&mut f);
    assert_eq!(o, Outcome::default());
    assert_eq!(f.cfg[&0x04], 0);
    assert!(!f.log.iter().any(|l| l.starts_with("mmio")));
    assert!(ehci::describe("00:1d.0", &o).contains("not reachable"));
    // Registers reading all ones (a controller gone): same
    let mut f = Fake::new(false, false);
    f.mmio.insert(0, u32::MAX);
    assert!(!ehci::quiesce(&mut f).reachable);
}

#[test]
fn the_capability_walk_skips_other_capabilities_and_stops_at_bad_pointers() {
    // A vendor capability (id 0x0A) first, then legacy support at 0x70
    let mut f = Fake::new(false, false);
    f.cfg.insert(EECP, 0x0A | 0x70 << 8);
    f.cfg.insert(0x70, 1 | 1 << 16);
    let o = ehci::quiesce(&mut f);
    assert!(o.bios_owned, "found behind the vendor capability"); // (the fake firmware only lets go at 0x68)
    assert_eq!(f.cfg[&0x70] & (1 << 24), 1 << 24);
    // A pointer into the header (below 0x40): no handoff
    let mut f = Fake::new(false, false);
    f.mmio.insert(0x08, 0x10 << 8);
    let o = ehci::quiesce(&mut f);
    assert!(!o.bios_owned && o.reachable);
}

// ---- memory/vm.rs: an object's write-combining pages ----

/// Two pages of RAM standing in for a screen: page 0 is "the framebuffer" (WC), page 1
/// "the status page" (normal memory).
struct Screenish {
    frames: [x86_64::structures::paging::PhysFrame; 2],
}

impl hydra_hosttests_t32::memory::vm::MappedObject for Screenish {
    fn get_page(&self, pgoff: u64) -> Option<x86_64::structures::paging::PhysFrame> {
        self.frames.get(pgoff as usize).copied()
    }
    fn write_combining(&self, frame: x86_64::structures::paging::PhysFrame) -> bool {
        frame == self.frames[0]
    }
}

/// The 4 KiB leaf entry of `va` in the tables at `cr3` (physical = virtual in the tests).
fn walk(cr3: u64, va: u64) -> u64 {
    let mut t = cr3 & 0x000F_FFFF_FFFF_F000;
    for shift in [39u64, 30, 21] {
        t = rd(t, (va >> shift) & 511) & 0x000F_FFFF_FFFF_F000;
    }
    rd(t, (va >> 12) & 511)
}

#[test]
fn a_screen_mapping_gets_write_combining_on_its_framebuffer_pages_only() {
    let _g = common::serial();
    common::global_frames();
    common::boot_cr3();
    hydra_hosttests_t32::host::wrmsr(pat::IA32_PAT, POWER_ON_PAT);
    pat::init_bsp();
    use hydra_hosttests_t32::memory::vm::{Backing, Mm, PROT_READ, PROT_WRITE};
    let frames = [0, 1].map(|_| FRAME_ALLOCATOR.lock().allocate_zeroed_frame().unwrap());
    let obj: std::sync::Arc<dyn hydra_hosttests_t32::memory::vm::MappedObject> = std::sync::Arc::new(Screenish { frames });
    let mut m = Mm::new().unwrap();
    let a = m.mmap(0, 0x2000, PROT_READ | PROT_WRITE, true, false, false, Backing::Object { obj, pgoff: 0 }).unwrap();
    m.handle_fault(a, true, false).unwrap();
    m.handle_fault(a + 0x1000, false, false).unwrap();
    let (fb, status) = (walk(m.cr3(), a), walk(m.cr3(), a + 0x1000));
    assert_eq!(fb & 0x000F_FFFF_FFFF_F000, frames[0].start_address().as_u64());
    assert_eq!(pat::type_of_4k(pat::with_wc(POWER_ON_PAT), fb), pat::MT_WC, "framebuffer page: {fb:#x}");
    assert_eq!(pat::type_of_4k(pat::with_wc(POWER_ON_PAT), status), pat::MT_WB, "status page: {status:#x}");
}
