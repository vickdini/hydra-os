//! The host side of the kernel's hardware seams (Group 32).
//!
//! A few kernel files of `src/arch` and `src/memory` execute instructions a normal
//! process may not (reading `gs:[8]`, `rdmsr`, `mov cr0`, debug registers). Each such spot
//! has a `#[cfg(not(target_os = "uefi"))]` twin that calls in here instead; the kernel
//! (target `x86_64-unknown-uefi`) never compiles those twins. The state is per thread,
//! like the shimmed `x86_64` crate's (`x86_64::hw`), so tests run in parallel.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

thread_local! {
    /// The CPU this thread plays (`percpu::cpu()`).
    pub static CPU: Cell<usize> = const { Cell::new(0) };
    /// Model-specific registers written or preset (`rdmsr` of an absent one gives 0,
    /// except EFER, which reports NX unless `NX` is false).
    pub static MSRS: RefCell<BTreeMap<u32, u64>> = const { RefCell::new(BTreeMap::new()) };
    /// Every `wrmsr`, in order.
    pub static MSR_WRITES: RefCell<Vec<(u32, u64)>> = const { RefCell::new(Vec::new()) };
    pub static NX: Cell<bool> = const { Cell::new(true) };
    /// The per-CPU words the kernel reaches through `gs` (`gs:[16]` kernel stack, the
    /// leaving mark), as this thread's CPU last wrote them.
    pub static GS_KERNEL_RSP: Cell<u64> = const { Cell::new(0) };
    /// Debug registers DR0-DR7 (DR4/5 unused).
    pub static DR: RefCell<[u64; 8]> = const { RefCell::new([0; 8]) };
    /// Number of DR7 writes.
    pub static DR7_WRITES: Cell<usize> = const { Cell::new(0) };
    /// CR0.WP toggles by `paging` (off, on).
    pub static WP_TOGGLES: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    /// Single-PCID flushes: (pcid, Some(addr) / None for the whole ID).
    pub static INVPCID: RefCell<Vec<(u16, Option<u64>)>> = const { RefCell::new(Vec::new()) };
    /// What CPUID reports for INVPCID / PCID support.
    pub static CPUID_PCID: Cell<(bool, bool)> = const { Cell::new((false, false)) };
}

pub fn cpu() -> usize {
    CPU.get()
}
pub fn set_cpu(c: usize) {
    CPU.set(c)
}

/// `rdmsr` stand-in.
pub fn rdmsr(msr: u32) -> u64 {
    if let Some(v) = MSRS.with_borrow(|m| m.get(&msr).copied()) {
        return v;
    }
    match msr {
        0xC000_0080 if NX.get() => 1 << 11,
        _ => 0,
    }
}
/// `wrmsr` stand-in.
pub fn wrmsr(msr: u32, v: u64) {
    MSRS.with_borrow_mut(|m| m.insert(msr, v));
    MSR_WRITES.with_borrow_mut(|w| w.push((msr, v)));
}

pub fn write_dr(i: usize, v: u64) {
    DR.with_borrow_mut(|d| d[i] = v);
    if i == 7 {
        DR7_WRITES.set(DR7_WRITES.get() + 1);
    }
}
pub fn read_dr(i: usize) -> u64 {
    DR.with_borrow(|d| d[i])
}

pub fn wp(on: bool) {
    let (off_n, on_n) = WP_TOGGLES.get();
    WP_TOGGLES.set(if on { (off_n, on_n + 1) } else { (off_n + 1, on_n) });
}

/// Restores this thread's fake CPU to its initial state.
pub fn reset() {
    CPU.set(0);
    MSRS.with_borrow_mut(|m| m.clear());
    MSR_WRITES.with_borrow_mut(|m| m.clear());
    NX.set(true);
    GS_KERNEL_RSP.set(0);
    DR.with_borrow_mut(|d| *d = [0; 8]);
    DR7_WRITES.set(0);
    WP_TOGGLES.set((0, 0));
    INVPCID.with_borrow_mut(|v| v.clear());
    x86_64::hw::clear_ports();
    x86_64::hw::set_if(true);
}

thread_local! {
    /// Every CR3 write by `pcid`, in order.
    pub static CR3_WRITES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

/// CR3 of this thread's fake CPU (the shim's, so `x86_64::registers::control::Cr3` agrees).
pub fn read_cr3() -> u64 {
    x86_64::hw::cr(3)
}
pub fn write_cr3(v: u64) {
    CR3_WRITES.with_borrow_mut(|w| w.push(v));
    x86_64::hw::set_cr(3, v)
}
/// `invpcid` stand-in: recorded as (pcid, Some(addr)) for kind 0, (pcid, None) for kind 1,
/// (0xFFFF, None) for kind 2 (everything).
pub fn invpcid(kind: u64, pcid: u64, addr: u64) {
    let e = match kind {
        0 => (pcid as u16, Some(addr)),
        1 => (pcid as u16, None),
        _ => (0xFFFF, None),
    };
    INVPCID.with_borrow_mut(|v| v.push(e));
}

/// The fake time stamp counter: global (the clock it drives is), and it moves on by
/// [`TSC_STEP`] cycles at every read, so waiting loops end.
pub static TSC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_000_000);
pub static TSC_STEP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
pub fn rdtsc() -> u64 {
    use std::sync::atomic::Ordering::SeqCst;
    TSC.fetch_add(TSC_STEP.load(SeqCst), SeqCst)
}

thread_local! {
    /// Segment registers of this thread's fake CPU (cs, ss, ds, es, fs, gs, ldtr).
    pub static SEGS: RefCell<BTreeMap<&'static str, u16>> = const { RefCell::new(BTreeMap::new()) };
    /// Every segment register load, in order.
    pub static SEG_LOADS: RefCell<Vec<(&'static str, u16)>> = const { RefCell::new(Vec::new()) };
}
pub fn read_seg(r: &'static str) -> u16 {
    SEGS.with_borrow(|s| s.get(r).copied().unwrap_or(0))
}
pub fn load_seg(r: &'static str, v: u16) {
    SEGS.with_borrow_mut(|s| s.insert(r, v));
    SEG_LOADS.with_borrow_mut(|l| l.push((r, v)));
    // A selector load sets the hidden base: zero for a null or flat one (the kernel then
    // writes the base MSR itself)
    match r {
        "fs" => wrmsr_quiet(0xC000_0100, 0),
        "gs" => wrmsr_quiet(0xC000_0102, 0),
        _ => {}
    }
}
fn wrmsr_quiet(msr: u32, v: u64) {
    MSRS.with_borrow_mut(|m| m.insert(msr, v));
}

thread_local! {
    /// Whether CPUID reports a hypervisor (vmmouse).
    pub static HYPERVISOR: Cell<bool> = const { Cell::new(false) };
    /// The VMware backdoor: (cmd, arg) -> (eax, ebx, ecx, edx).
    pub static VMWARE: RefCell<Option<Box<dyn FnMut(u32, u32) -> (u32, u32, u32, u32)>>> = RefCell::new(None);
}
/// The backdoor `in` (no handler: what real hardware without it gives back, the magic).
pub fn vmware_call(cmd: u32, arg: u32) -> (u32, u32, u32, u32) {
    let h = VMWARE.with_borrow_mut(|h| h.take());
    match h {
        Some(mut f) => {
            let r = f(cmd, arg);
            VMWARE.with_borrow_mut(|s| {
                if s.is_none() {
                    *s = Some(f)
                }
            });
            r
        }
        None => (0x564D_5868, arg, cmd, 0x5658),
    }
}
