//! # User segment state: data selectors, TLS descriptors and the LDT
//!
//! 64-bit programs never use segments except through the FS and GS base registers, but
//! 32-bit code does: Wine runs 32-bit Windows programs in a 64-bit process by switching to
//! the 32-bit code segment ([`super::gdt::USER32_CS`]), with `fs` holding a selector whose
//! descriptor's base is the Windows thread block. This module keeps that state per thread
//! and puts it in the CPU at a context switch, as Linux's `__switch_to` does:
//!
//! - the `ds`, `es`, `fs` and `gs` selectors a thread loaded, and its GS base (the user's,
//!   held in `IA32_KERNEL_GS_BASE` while the kernel runs, after `swapgs`);
//! - the thread's three `set_thread_area` descriptors (GDT entries 12-14 of the CPU);
//! - the process's Local Descriptor Table (`modify_ldt`).
//!
//! ## Safety rules
//! - Selectors are loaded in ring 0 only after [`loadable`] checked their descriptor in
//!   the tables just installed: a bad one would fault in the kernel. A thread's saved
//!   selectors may refer to descriptors deleted since (by another thread) and are then
//!   loaded as null, as Linux's fault fixups do.
//! - The saved `ss` of an interrupted thread is checked the same way at a switch
//!   ([`sanitize_frame`]): `iretq` with a stale `ss` would fault in ring 0.
//! - LDTs are immutable once published; `modify_ldt` installs a modified copy. A CPU keeps
//!   only a raw pointer to the table it loaded, and a table whose last reference goes away
//!   while some CPU still has it loaded is retired rather than freed ([`Ldt`]'s `Drop`), so
//!   the CPU never reads descriptors from freed memory.
//! - Only 32-bit data segments are accepted (no code segments, no 16-bit segments), which
//!   keeps the kernel's `iretq` frames limited to Hydra's own code segments.
//! - Nothing here allocates or frees on the context-switch path.
//!
//! ## Hardware & Dependency Context
//! - **CPU Privilege Level**: Ring 0.
//! - **Hardware Interaction**: segment register loads, `lldt`, `swapgs`, `IA32_FS_BASE` and
//!   `IA32_KERNEL_GS_BASE`, each CPU's GDT ([`super::gdt::CPU_GDT`]).
//! - **Concurrency**: Switch-time code runs with interrupts off on its own CPU. An LDT
//!   holder's lock is taken with interrupts off, so it is never held across a switch.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use spin::Mutex;

use super::gdt::{CPU_GDT, TLS_ENTRIES, TLS_ENTRY_MIN};
use super::smp::MAX_CPUS;
use super::syscall::{rdmsr, wrmsr};

/// `IA32_FS_BASE`.
const FS_BASE: u32 = 0xC000_0100;
/// `IA32_KERNEL_GS_BASE`: the user's GS base while the kernel runs.
const KERNEL_GS_BASE: u32 = 0xC000_0102;
/// GDT entry (two slots) of the CPU's LDT descriptor.
const LDT_ENTRY: usize = 10;
/// Selector of the LDT descriptor.
const LDT_SEL: u16 = (LDT_ENTRY as u16) << 3;
/// Most entries an LDT may have (Linux `LDT_ENTRIES`).
pub const LDT_ENTRIES: usize = 8192;

/// A thread's segment state outside the general registers.
#[derive(Clone, Copy, Default, Debug)]
pub struct UserSegs {
    /// User GS base (`arch_prctl(ARCH_SET_GS)`), used while `gs` is null.
    pub gs_base: u64,
    /// `ds` selector.
    pub ds: u16,
    /// `es` selector.
    pub es: u16,
    /// `fs` selector; null means the base is the task's `fs_base`.
    pub fs: u16,
    /// `gs` selector; null means the base is `gs_base`.
    pub gs: u16,
    /// The `set_thread_area` descriptors (GDT entries 12-14).
    pub tls: [u64; TLS_ENTRIES],
}

/// One version of a process's LDT: raw 8-byte descriptors, never changed once published.
pub struct Ldt {
    entries: Box<[u64]>,
}

impl Ldt {
    /// A table with these descriptors.
    pub fn new(entries: Box<[u64]>) -> Ldt {
        Ldt { entries }
    }

    /// The descriptors.
    pub fn entries(&self) -> &[u64] {
        &self.entries
    }
}

impl Drop for Ldt {
    fn drop(&mut self) {
        // A CPU that loaded this table may still read it: keep the memory until it has
        // moved on (see collect_retired)
        if loaded_anywhere(self.entries.as_ptr()) {
            RETIRED.lock().push(core::mem::take(&mut self.entries));
        }
    }
}

/// A process's LDT, shared by its threads (and by processes sharing its address space).
pub type SharedLdt = Arc<Mutex<Option<Arc<Ldt>>>>;

/// LDT memory some CPU may still have loaded, freed by [`collect_retired`].
static RETIRED: Mutex<Vec<Box<[u64]>>> = Mutex::new(Vec::new());

/// The descriptors each CPU's `LDTR` points at (null: no LDT) and how many there are.
static CPU_LDT: [AtomicPtr<u64>; MAX_CPUS] = [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];
static CPU_LDT_LEN: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];

/// Whether some CPU has the table at `p` loaded.
fn loaded_anywhere(p: *const u64) -> bool {
    CPU_LDT.iter().any(|c| c.load(Ordering::SeqCst) as *const u64 == p)
}

/// Frees retired LDT memory no CPU has loaded any more. Process context only.
pub fn collect_retired() {
    let done: Vec<Box<[u64]>> = {
        let mut r = RETIRED.lock();
        let (keep, done): (Vec<_>, Vec<_>) = core::mem::take(&mut *r).into_iter().partition(|e| loaded_anywhere(e.as_ptr()));
        *r = keep;
        done
    };
    drop(done);
}

// ---- Descriptors: Linux's struct user_desc ----

/// `struct user_desc` as programs pass it (16 bytes).
#[derive(Clone, Copy, Default, Debug, PartialEq)]
pub struct UserDesc {
    /// GDT (12-14, or -1) or LDT entry number.
    pub entry_number: u32,
    /// Segment base (32 bits).
    pub base_addr: u32,
    /// Segment limit (20 bits; in pages with `limit_in_pages`).
    pub limit: u32,
    /// 32-bit segment (D/B bit).
    pub seg_32bit: bool,
    /// 0 data, 1 expand-down data, 2 code, 3 conforming code.
    pub contents: u32,
    /// Read-only data, or execute-only code.
    pub read_exec_only: bool,
    /// Limit counted in 4 KiB pages (G bit).
    pub limit_in_pages: bool,
    /// Not present (P bit clear).
    pub seg_not_present: bool,
    /// Available to software (AVL bit).
    pub useable: bool,
    /// 64-bit code segment (L bit; never set by Hydra or Linux).
    pub lm: bool,
}

impl UserDesc {
    /// Parses the 16 bytes of a `struct user_desc`.
    pub fn parse(b: &[u8]) -> UserDesc {
        let w = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let f = w(12);
        UserDesc {
            entry_number: w(0),
            base_addr: w(4),
            limit: w(8),
            seg_32bit: f & 1 != 0,
            contents: (f >> 1) & 3,
            read_exec_only: f & 8 != 0,
            limit_in_pages: f & 0x10 != 0,
            seg_not_present: f & 0x20 != 0,
            useable: f & 0x40 != 0,
            lm: f & 0x80 != 0,
        }
    }

    /// The 16 bytes of this `struct user_desc`.
    pub fn bytes(&self) -> [u8; 16] {
        let f = self.seg_32bit as u32
            | self.contents << 1
            | (self.read_exec_only as u32) << 3
            | (self.limit_in_pages as u32) << 4
            | (self.seg_not_present as u32) << 5
            | (self.useable as u32) << 6
            | (self.lm as u32) << 7;
        let mut b = [0u8; 16];
        for (i, v) in [self.entry_number, self.base_addr, self.limit, f].iter().enumerate() {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    /// Linux's `LDT_empty`: the way to ask for "no segment".
    pub fn is_empty(&self) -> bool {
        self.base_addr == 0
            && self.limit == 0
            && self.contents == 0
            && self.read_exec_only
            && !self.seg_32bit
            && !self.limit_in_pages
            && self.seg_not_present
            && !self.useable
    }

    /// Linux's `LDT_zero`: all zero but the entry number, also taken as "no segment".
    pub fn is_zero(&self) -> bool {
        self.base_addr == 0
            && self.limit == 0
            && self.contents == 0
            && !self.read_exec_only
            && !self.seg_32bit
            && !self.limit_in_pages
            && !self.seg_not_present
            && !self.useable
    }

    /// Whether Hydra accepts this segment: 32-bit data only (contents 0 or 1). Linux
    /// also takes code and 16-bit segments in the LDT; Hydra's `iretq` paths are kept to
    /// its own code segments, and 16-bit stacks would leak kernel stack bits (espfix).
    pub fn supported(&self) -> bool {
        self.seg_32bit && self.contents <= 1
    }

    /// The hardware descriptor (Linux's `fill_ldt`): DPL 3, accessed, never long mode.
    pub fn descriptor(&self) -> u64 {
        let base = self.base_addr as u64;
        let limit = self.limit as u64;
        let ty = ((!self.read_exec_only) as u64) << 1 | (self.contents as u64) << 2 | 1;
        (limit & 0xffff)
            | (base & 0xff_ffff) << 16
            | ty << 40
            | 1 << 44
            | 3 << 45
            | ((!self.seg_not_present) as u64) << 47
            | ((limit >> 16) & 0xf) << 48
            | (self.useable as u64) << 52
            | (self.seg_32bit as u64) << 54
            | (self.limit_in_pages as u64) << 55
            | (base >> 24) << 56
    }

    /// The `user_desc` describing descriptor `d` of entry `idx` (Linux's `fill_user_desc`).
    pub fn from_descriptor(idx: u32, d: u64) -> UserDesc {
        UserDesc {
            entry_number: idx,
            base_addr: (((d >> 16) & 0xff_ffff) | (d >> 56) << 24) as u32,
            limit: ((d & 0xffff) | ((d >> 48) & 0xf) << 16) as u32,
            seg_32bit: d >> 54 & 1 != 0,
            contents: ((d >> 42) & 3) as u32,
            read_exec_only: d >> 41 & 1 == 0,
            limit_in_pages: d >> 55 & 1 != 0,
            seg_not_present: d >> 47 & 1 == 0,
            useable: d >> 52 & 1 != 0,
            lm: d >> 53 & 1 != 0,
        }
    }
}

// ---- Segment registers ----

macro_rules! read_seg {
    ($name:ident, $reg:literal) => {
        #[inline]
        fn $name() -> u16 {
            let v: u16;
            unsafe { core::arch::asm!(concat!("mov {0:x}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }
    };
}
read_seg!(read_ds, "ds");
read_seg!(read_es, "es");
read_seg!(read_fs, "fs");
read_seg!(read_gs, "gs");

/// Loads `ds`. The selector must be null or [`loadable`].
unsafe fn load_ds(s: u16) {
    core::arch::asm!("mov ds, {0:x}", in(reg) s, options(nostack, preserves_flags));
}
/// Loads `es`. The selector must be null or [`loadable`].
unsafe fn load_es(s: u16) {
    core::arch::asm!("mov es, {0:x}", in(reg) s, options(nostack, preserves_flags));
}
/// Loads `fs` (and with a non-null selector, the FS base from its descriptor).
unsafe fn load_fs(s: u16) {
    core::arch::asm!("mov fs, {0:x}", in(reg) s, options(nostack, preserves_flags));
}
/// Loads the user's `gs` (Linux's `load_gs_index`): the load sets the active GS base,
/// which in the kernel is the per-CPU block, so it happens between two `swapgs`. With
/// interrupts off; an NMI in between would see the user's GS base.
unsafe fn load_gs(s: u16) {
    core::arch::asm!("swapgs", "mov gs, {0:x}", "swapgs", in(reg) s, options(nostack, preserves_flags));
}

/// The descriptor selector `sel` names on this CPU (its GDT, or the LDT it loaded).
fn descriptor(sel: u16) -> Option<u64> {
    let cpu = super::percpu::cpu();
    let idx = (sel >> 3) as usize;
    if sel & 4 != 0 {
        let p = CPU_LDT[cpu].load(Ordering::Relaxed);
        if p.is_null() || idx >= CPU_LDT_LEN[cpu].load(Ordering::Relaxed) {
            return None;
        }
        Some(unsafe { *p.add(idx) })
    } else {
        let g = CPU_GDT[cpu].load(Ordering::Relaxed);
        if g.is_null() {
            return None;
        }
        unsafe { (*g).0.get(idx).copied() }
    }
}

/// Whether the kernel can load `sel` into a data segment register without a fault: null,
/// or RPL 3 naming a present DPL-3 data or readable code segment.
pub fn loadable(sel: u16) -> bool {
    if sel & !3 == 0 {
        return true;
    }
    if sel & 3 != 3 {
        return false;
    }
    let Some(d) = descriptor(sel) else { return false };
    let present = d >> 47 & 1 == 1;
    let user_seg = d >> 44 & 1 == 1;
    let dpl3 = (d >> 45) & 3 == 3;
    let code = d >> 43 & 1 == 1;
    let readable = d >> 41 & 1 == 1;
    present && user_seg && dpl3 && (!code || readable)
}

/// Whether `iretq` can load `sel` into `ss`: Hydra's user data segment, or a present
/// writable DPL-3 data segment.
fn stack_ok(sel: u16) -> bool {
    if sel == super::gdt::USER_DS {
        return true;
    }
    if sel & 3 != 3 {
        return false;
    }
    let Some(d) = descriptor(sel) else { return false };
    d >> 47 & 1 == 1 && d >> 44 & 1 == 1 && (d >> 45) & 3 == 3 && d >> 43 & 1 == 0 && d >> 41 & 1 == 1
}

/// Makes an interrupted user context safe to resume with `iretq` on this CPU once its
/// tables are installed: Hydra's code segments only, and an `ss` whose descriptor still
/// exists (another thread may have deleted it). A context that fails resumes at a kernel
/// address, so the thread takes a page fault (SIGSEGV) in user mode instead of the kernel
/// faulting on `iretq`.
pub fn sanitize_frame(cs: &mut u64, ss: &mut u64, rip: &mut u64) {
    // 32-bit code: iretq checks RIP against the 4 GiB segment limit
    let cs_ok = *cs as u16 == super::gdt::USER_CS || (*cs as u16 == super::gdt::USER32_CS && *rip <= u32::MAX as u64);
    if cs_ok && stack_ok(*ss as u16) {
        return;
    }
    *cs = super::gdt::USER_CS as u64;
    *ss = super::gdt::USER_DS as u64;
    *rip = 0xFFFF_8000_0000_0000;
}

// ---- Context switch ----

/// Reads the outgoing user thread's segment state from the CPU: its selectors, and its
/// GS base (in `IA32_KERNEL_GS_BASE` while the kernel runs). Interrupts off.
pub fn save(s: &mut UserSegs) {
    s.ds = read_ds();
    s.es = read_es();
    s.fs = read_fs();
    s.gs = read_gs();
    s.gs_base = unsafe { rdmsr(KERNEL_GS_BASE) };
}

/// Makes `ldt` this CPU's LDT (`None`: none). Interrupts off.
fn install_ldt(ldt: Option<&Ldt>) {
    let cpu = super::percpu::cpu();
    let (p, n) = match ldt {
        Some(l) if !l.entries.is_empty() => (l.entries.as_ptr() as *mut u64, l.entries.len()),
        _ => (core::ptr::null_mut(), 0),
    };
    if CPU_LDT[cpu].load(Ordering::Relaxed) == p {
        return;
    }
    let g = CPU_GDT[cpu].load(Ordering::Relaxed);
    if g.is_null() {
        return;
    }
    unsafe {
        if p.is_null() {
            core::arch::asm!("lldt {0:x}", in(reg) 0u16, options(nostack, preserves_flags));
        } else {
            // 16-byte system descriptor: type 2 (LDT), present, DPL 0
            let base = p as u64;
            let limit = (n * 8 - 1) as u64;
            (*g).0[LDT_ENTRY] =
                (limit & 0xffff) | (base & 0xff_ffff) << 16 | 2 << 40 | 1 << 47 | ((limit >> 16) & 0xf) << 48 | ((base >> 24) & 0xff) << 56;
            (*g).0[LDT_ENTRY + 1] = base >> 32;
            core::arch::asm!("lldt {0:x}", in(reg) LDT_SEL, options(nostack, preserves_flags));
        }
    }
    CPU_LDT_LEN[cpu].store(n, Ordering::Relaxed);
    CPU_LDT[cpu].store(p, Ordering::SeqCst);
}

/// Installs the LDT `holder` currently holds on this CPU. Interrupts off.
fn install_from(holder: Option<&SharedLdt>) {
    match holder {
        Some(h) => {
            let cur = h.lock();
            install_ldt(cur.as_deref());
        }
        None => install_ldt(None),
    }
}

/// Puts the incoming user thread's segment state in the CPU: its TLS descriptors, its
/// process's LDT, its selectors (each checked; a stale one is loaded as null), and its FS
/// and GS bases when the selectors are null. Interrupts off.
pub fn load(s: &UserSegs, fs_base: u64, ldt: Option<&SharedLdt>) {
    let cpu = super::percpu::cpu();
    let g = CPU_GDT[cpu].load(Ordering::Relaxed);
    if !g.is_null() {
        unsafe { (&mut (*g).0)[TLS_ENTRY_MIN..TLS_ENTRY_MIN + TLS_ENTRIES].copy_from_slice(&s.tls) };
    }
    install_from(ldt);
    let checked = |sel: u16| if loadable(sel) { sel } else { 0 };
    unsafe {
        let ds = checked(s.ds);
        if read_ds() != ds {
            load_ds(ds);
        }
        let es = checked(s.es);
        if read_es() != es {
            load_es(es);
        }
        let fs = checked(s.fs);
        if fs != 0 {
            load_fs(fs);
        } else {
            if read_fs() != 0 {
                load_fs(0);
            }
            wrmsr(FS_BASE, fs_base);
        }
        let gs = checked(s.gs);
        if gs != 0 {
            load_gs(gs);
        } else {
            if read_gs() != 0 {
                load_gs(0);
            }
            wrmsr(KERNEL_GS_BASE, s.gs_base);
        }
    }
}

/// Reloads the current thread's selectors that refer to `sel` after its descriptor
/// changed (Linux does this in `set_thread_area` and `modify_ldt`): a stale descriptor
/// cache would keep the old base. The thread's saved copy is read back from the CPU at
/// its next switch. Interrupts off.
fn refresh(sel: u16) {
    let checked = if loadable(sel) { sel } else { 0 };
    unsafe {
        if read_ds() == sel {
            load_ds(checked);
        }
        if read_es() == sel {
            load_es(checked);
        }
        if read_fs() == sel {
            load_fs(checked);
        }
        if read_gs() == sel {
            load_gs(checked);
        }
    }
}

/// Sets TLS entry `idx` (12-14) of the current thread to `desc` (0: none) and refreshes
/// the CPU: its GDT entry, and any segment register using it. Interrupts off.
pub fn set_current_tls(s: &mut UserSegs, idx: usize, desc: u64) {
    s.tls[idx - TLS_ENTRY_MIN] = desc;
    let g = CPU_GDT[super::percpu::cpu()].load(Ordering::Relaxed);
    if !g.is_null() {
        unsafe { (*g).0[idx] = desc };
    }
    refresh((idx as u16) << 3 | 3);
}

/// Publishes `new` as the LDT `holder` holds, installs it on this CPU and refreshes the
/// current thread's segment registers using entry `changed`. Other CPUs running threads of
/// the process load it at their next switch. Process context, no scheduler lock held.
pub fn publish_ldt(holder: &SharedLdt, new: Arc<Ldt>, changed: usize) {
    let old = x86_64::instructions::interrupts::without_interrupts(|| {
        let old = {
            let mut cur = holder.lock();
            let old = cur.replace(new);
            install_ldt(cur.as_deref());
            old
        };
        refresh((changed as u16) << 3 | 4 | 3);
        old
    });
    // Freed (or retired) outside the lock
    drop(old);
    collect_retired();
}

/// Sets the current thread's FS base (`arch_prctl(ARCH_SET_FS)`): `fs` becomes null.
/// Interrupts off.
pub fn set_fs_base(s: &mut UserSegs, base: u64) {
    unsafe {
        if read_fs() != 0 {
            load_fs(0);
        }
        wrmsr(FS_BASE, base);
    }
    s.fs = 0;
}

/// Sets the current thread's GS base (`arch_prctl(ARCH_SET_GS)`): `gs` becomes null.
/// Interrupts off.
pub fn set_gs_base(s: &mut UserSegs, base: u64) {
    unsafe {
        if read_gs() != 0 {
            load_gs(0);
        }
        wrmsr(KERNEL_GS_BASE, base);
    }
    s.gs = 0;
    s.gs_base = base;
}

/// The current thread's FS and GS bases as the CPU has them (`ARCH_GET_FS`/`GS`).
pub fn current_bases() -> (u64, u64) {
    unsafe { (rdmsr(FS_BASE), rdmsr(KERNEL_GS_BASE)) }
}

/// Clears the current thread's segment state in the CPU for a new program (`execve`):
/// null selectors, zero bases, no TLS descriptors, no LDT. Interrupts off.
pub fn reset_current() {
    let s = UserSegs::default();
    load(&s, 0, None);
}
