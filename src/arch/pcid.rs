//! # PCID: tagged TLB entries, and the one place CR3 is loaded
//!
//! Without PCID every write of CR3 (every switch between address spaces: task switches,
//! calls into Ring 3 servers and drivers) throws the whole TLB away. With PCID
//! (process-context identifiers, `CR4.PCIDE`) the CPU tags each TLB entry with the 12-bit
//! ID in CR3's low bits, and a CR3 write with bit 63 set keeps the entries: switching back
//! to an address space finds its translations still cached.
//!
//! ## The CR3 helper
//!
//! [`load_cr3`] is the only way CR3 is loaded once the kernel runs on its own tables (the
//! raw writes left are the boot paths before that: `main.asm`, `relocate.rs`, the AP
//! trampoline). It records the root in [`crate::arch::smp::LOADED_CR3`] first, then
//! picks the calling CPU's ID for the root and keeps the cached entries only when they are
//! known to be valid.
//!
//! ## IDs: a per-CPU cache of roots
//!
//! Each CPU has 4095 slots (IDs 1..=4095; ID 0 is the boot tables' and is never reused
//! without a flush). A root (the physical address of a top-level table) hashes to exactly
//! one slot, and its ID on that CPU is the slot number. A slot holds the root whose
//! entries the ID's TLB entries belong to, plus a STALE bit:
//!
//! - slot = root: the entries tagged with the ID match the root's page tables: load with
//!   bit 63 (no flush);
//! - slot = root | STALE: some change of the root's tables was not flushed on this CPU:
//!   load without bit 63 (the CPU flushes that one ID) and clear the bit;
//! - anything else (empty, another root that hashes to the same slot): the slot is taken
//!   over, the ID flushed on load. With more address spaces than slots, colliding roots
//!   just take turns: that is the recycling, and it always flushes before reuse.
//!
//! The hash makes each root's ID fixed per CPU, so marking and forgetting touch one slot
//! per CPU, without searching.
//!
//! ## Keeping the TLB correct (`arch::smp::shootdown`)
//!
//! A change to an address space's page tables (unmap, protection change, copy-on-write)
//! must reach every CPU that may still cache the old entry, which with PCID includes CPUs
//! that ran the address space earlier and switched away:
//!
//! - the CPU making the change flushes the address (`invlpg`) if the root is loaded; if
//!   not, and its slot holds the root, it flushes that ID with `INVPCID`, or marks the
//!   slot STALE where there is no `INVPCID`;
//! - every other CPU whose slot holds the root gets the slot marked STALE (its next load
//!   of the root flushes), and every CPU that has the root loaded *now* is interrupted and
//!   flushes its current ID at once (as before PCID).
//!
//! The loading CPU writes `LOADED_CR3` before it reads the slot, and the changing CPU
//! marks slots before it reads `LOADED_CR3` (both sequentially consistent): whichever way
//! they interleave, either the loader sees STALE, or the changer sees the root loaded and
//! interrupts that CPU.
//!
//! Changes to the kernel's shared tables (`shootdown(None, ..)`: the kernel half and the
//! identity map every address space shares) flush every ID on every CPU (`INVPCID`
//! "all contexts", or a toggle of `CR4.PGE`).
//!
//! An address space that ends ([`forget`], from `Mm`'s teardown, before its frames are
//! freed) is taken out of every CPU's slot, so a new root at the same physical address
//! never inherits its entries.
//!
//! ## Off switches
//!
//! PCID is used when CPUID reports it (leaf 1, ECX bit 17); `INVPCID` when leaf 7 reports
//! it (EBX bit 10). It is turned off on purpose by:
//!
//! - the boot entry's load option `nopcid` (or `pcid=off`);
//! - a file `\hydra\nopcid` on the EFI system partition;
//! - QEMU's `-fw_cfg name=opt/hydra/pcid,string=off`.
//!
//! Off, CR3 writes flush everything and shootdowns work as before PCID.
//!
//! ## Global kernel pages (wave 4)
//!
//! The kernel half of every address space is the same (the PML4 entries 256..512 point at
//! shared tables), so its TLB entries need not be refilled after a CR3 write. With
//! `CR4.PGE` and the G bit on the kernel half's leaf entries ([`enable_global`]), they are
//! global: kept across every CR3 write, with or without PCID, and shared by all IDs.
//!
//! - **Flushing them:** only a change of the kernel's shared tables can make one stale, and
//!   every such change goes through `shootdown(None, ..)`: `invlpg` (which drops a global
//!   entry of that address) or, for everything, `INVPCID` type 2 (all contexts *including*
//!   globals) or a toggle of `CR4.PGE`, on every CPU. A plain CR3 write never drops them.
//! - **Never user visible:** entries with the USER bit are not marked, and
//!   `make_user_accessible` clears G where it adds USER. The low half (the user area, the
//!   identity slots) is never marked.
//! - **Off switch:** the boot option `noglobal` (or `pge=off`), a file `\hydra\noglobal`
//!   on the EFI partition, or QEMU's `-fw_cfg name=opt/hydra/pge,string=off`
//!   (`tools/hydra_run.py --global-off`): then CR4.PGE stays clear and the G bits are
//!   never set, exactly as before.
//! - **Self-test:** `memory::vm::global_self_test` (boot, one CPU) checks that a global
//!   entry survives a CR3 switch and that each kind of kernel shootdown removes it; a
//!   failure turns global pages off again.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::smp::MAX_CPUS;

/// IDs per CPU besides 0 (the boot tables' ID).
const SLOTS: usize = 4095;
/// The slot's root has changes this CPU has not flushed.
const STALE: u64 = 1;
/// CR3 bit 63: keep the ID's cached entries.
const NOFLUSH: u64 = 1 << 63;
/// The root's bits in CR3.
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Whether CR4.PCIDE is on (on every CPU: the application processors copy the boot
/// processor's CR4).
static ENABLED: AtomicBool = AtomicBool::new(false);
/// Whether the CPU has `INVPCID`.
static INVPCID: AtomicBool = AtomicBool::new(false);
/// What turned PCID off on purpose (read before `ExitBootServices`).
static OFF_BY: Mutex<Option<&'static str>> = Mutex::new(None);
/// Whether CR4.PGE is on with the kernel half's leaf entries global.
static GLOBAL: AtomicBool = AtomicBool::new(false);
/// What turned global pages off on purpose (or why they are off).
static GLOBAL_OFF_BY: Mutex<Option<&'static str>> = Mutex::new(None);

/// Per CPU: slot `i` (ID `i`, 1..=4095) holds the root its entries belong to (0: none),
/// possibly with [`STALE`].
static SLOT: [[AtomicU64; SLOTS + 1]; MAX_CPUS] = [const { [const { AtomicU64::new(0) }; SLOTS + 1] }; MAX_CPUS];

/// Counters per CPU (a cache line each).
#[repr(align(64))]
struct Counters {
    /// CR3 loads that kept the cached entries.
    hits: AtomicU64,
    /// Loads that took a slot over (a new root, or a hash collision).
    misses: AtomicU64,
    /// Loads that found the root's slot marked STALE.
    stale: AtomicU64,
    /// Slots of other CPUs marked STALE by this CPU's shootdowns.
    marked: AtomicU64,
    /// Single-ID flushes of a root not loaded here (`INVPCID`).
    invpcid: AtomicU64,
    /// Flushes of every ID (kernel-table changes).
    flush_all: AtomicU64,
}

static COUNTERS: [Counters; MAX_CPUS] = [const {
    Counters {
        hits: AtomicU64::new(0),
        misses: AtomicU64::new(0),
        stale: AtomicU64::new(0),
        marked: AtomicU64::new(0),
        invpcid: AtomicU64::new(0),
        flush_all: AtomicU64::new(0),
    }
}; MAX_CPUS];

/// Whether PCID is in use.
#[inline(always)]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The slot (and ID) of root `pml4` on every CPU.
#[inline(always)]
fn slot_of(pml4: u64) -> usize {
    (((pml4 >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) % SLOTS as u64) as usize + 1
}

#[inline(always)]
fn read_cr3() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

#[inline(always)]
unsafe fn write_cr3(v: u64) {
    core::arch::asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags));
}

/// `INVPCID` of `kind` (0: one address of `pcid`, 1: all of `pcid`, 2: everything,
/// global entries too).
#[inline(always)]
unsafe fn invpcid(kind: u64, pcid: u64, addr: u64) {
    let desc: [u64; 2] = [pcid, addr];
    core::arch::asm!("invpcid {}, [{}]", in(reg) kind, in(reg) desc.as_ptr(), options(nostack, preserves_flags));
}

/// Reads the off switches. Called while the firmware's boot services still run.
pub fn discover() {
    let mut cfg = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/pcid", &mut cfg).map(|n| &cfg[..n]);
    if fw.is_some_and(|v| v.starts_with(b"off")) {
        *OFF_BY.lock() = Some("QEMU fw_cfg opt/hydra/pcid=off");
    } else if crate::arch::iommu::load_options_say(&[b"pcid=off", b"nopcid"]) {
        *OFF_BY.lock() = Some("boot option nopcid");
    } else if crate::fs::bootfs::file_exists("\\hydra\\nopcid") {
        *OFF_BY.lock() = Some("file \\hydra\\nopcid on the EFI partition");
    }
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/pge", &mut cfg).map(|n| &cfg[..n]);
    if fw.is_some_and(|v| v.starts_with(b"off")) {
        *GLOBAL_OFF_BY.lock() = Some("QEMU fw_cfg opt/hydra/pge=off");
    } else if crate::arch::iommu::load_options_say(&[b"pge=off", b"noglobal"]) {
        *GLOBAL_OFF_BY.lock() = Some("boot option noglobal");
    } else if crate::fs::bootfs::file_exists("\\hydra\\noglobal") {
        *GLOBAL_OFF_BY.lock() = Some("file \\hydra\\noglobal on the EFI partition");
    }
}

/// Whether the kernel half's pages are global (CR4.PGE on).
#[inline(always)]
pub fn global_enabled() -> bool {
    GLOBAL.load(Ordering::Relaxed)
}

/// Marks the kernel half's leaf entries global and turns CR4.PGE on (see the module
/// comment), unless an off switch says no. Called on the boot processor with the kernel's
/// own tables loaded and the direct map on, before the other processors start (they copy
/// this CPU's CR4) and before any program runs.
pub fn enable_global() {
    use x86_64::registers::control::Cr4;
    if let Some(why) = *GLOBAL_OFF_BY.lock() {
        crate::kprintln!("[pge] global kernel pages off: turned off by {}", why);
        return;
    }
    let pml4 = read_cr3() & ADDR_MASK;
    let space = crate::memory::paging::AddressSpace::from_pml4(x86_64::PhysAddr::new(pml4));
    let (g1, g2, g4) = x86_64::instructions::interrupts::without_interrupts(|| {
        let n = space.mark_kernel_global();
        // On, and every cached entry (marked or not) flushed: a change of PGE flushes all
        let cr4 = Cr4::read_raw();
        unsafe {
            Cr4::write_raw(cr4 & !(1 << 7));
            Cr4::write_raw(cr4 | (1 << 7));
        }
        n
    });
    GLOBAL.store(true, Ordering::SeqCst);
    crate::kprintln!("[pge] global kernel pages on: {} 1 GiB, {} 2 MiB and {} 4 KiB kernel entries kept across address-space switches", g1, g2, g4);
}

/// Turns global pages off again on the boot processor (the self-test failed), before the
/// other processors start: CR4.PGE cleared (which flushes every entry; the G bits are then
/// ignored by the CPU).
pub fn disable_global(why: &'static str) {
    use x86_64::registers::control::Cr4;
    x86_64::instructions::interrupts::without_interrupts(|| unsafe { Cr4::write_raw(Cr4::read_raw() & !(1 << 7)) });
    GLOBAL.store(false, Ordering::SeqCst);
    *GLOBAL_OFF_BY.lock() = Some(why);
    crate::kprintln!("[pge] global kernel pages turned off: {}", why);
}

/// Turns PCID on on the boot processor, if the CPU has it and nothing turned it off.
/// Called with the kernel's own tables loaded (CR3's low bits clear), before the other
/// processors start (they copy this CPU's CR4).
pub fn init() {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let leaf1 = __cpuid(1);
    let has_pcid = leaf1.ecx & (1 << 17) != 0;
    let max = __cpuid(0).eax;
    let has_invpcid = max >= 7 && __cpuid_count(7, 0).ebx & (1 << 10) != 0;
    if !has_pcid {
        crate::kprintln!("[pcid] PCID off: the CPU does not have it (every address-space switch flushes the TLB)");
        return;
    }
    if let Some(why) = *OFF_BY.lock() {
        crate::kprintln!("[pcid] PCID off: turned off by {} (every address-space switch flushes the TLB)", why);
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let cr3 = read_cr3();
        if cr3 & 0xFFF != 0 {
            // CR4.PCIDE may only be set with CR3's low 12 bits clear
            unsafe { write_cr3(cr3 & ADDR_MASK) };
        }
        INVPCID.store(has_invpcid, Ordering::Relaxed);
        unsafe { x86_64::registers::control::Cr4::write_raw(x86_64::registers::control::Cr4::read_raw() | (1 << 17)) };
        ENABLED.store(true, Ordering::SeqCst);
    });
    crate::kprintln!(
        "[pcid] PCID on: tagged TLB, {} IDs per CPU, INVPCID {}",
        SLOTS,
        if has_invpcid { "yes" } else { "no (CR3/CR4 fallback)" }
    );
}

/// Loads page table root `pml4` (physical address of the top-level table, no flag bits)
/// on the calling CPU. THE way to write CR3 (see the module comment): it records the root
/// in `smp::LOADED_CR3` first, then keeps the root's cached TLB entries when they are
/// still valid. Nothing happens if `pml4` is loaded already. Takes no lock and never
/// waits; disables interrupts meanwhile if they are on.
pub fn load_cr3(pml4: u64) {
    debug_assert!(pml4 & !ADDR_MASK == 0);
    x86_64::instructions::interrupts::without_interrupts(|| {
        let me = super::percpu::cpu();
        if read_cr3() & ADDR_MASK == pml4 {
            super::smp::LOADED_CR3[me].store(pml4, Ordering::SeqCst);
            return;
        }
        // First the record (shootdowns read it), then the slot: see the module comment
        super::smp::LOADED_CR3[me].store(pml4, Ordering::SeqCst);
        if !enabled() {
            unsafe { write_cr3(pml4) };
            return;
        }
        let id = slot_of(pml4);
        let slot = &SLOT[me][id];
        let v = slot.load(Ordering::SeqCst);
        let c = &COUNTERS[me];
        let value = if v == pml4 {
            c.hits.fetch_add(1, Ordering::Relaxed);
            pml4 | id as u64 | NOFLUSH
        } else {
            if v == pml4 | STALE {
                c.stale.fetch_add(1, Ordering::Relaxed);
            } else {
                c.misses.fetch_add(1, Ordering::Relaxed);
            }
            // A STALE mark set after this store is for a change made before it, which
            // the flush below (a CR3 write without bit 63) covers
            slot.store(pml4, Ordering::SeqCst);
            pml4 | id as u64
        };
        unsafe { write_cr3(value) };
    });
}

/// Flushes the calling CPU's cached translations of the CURRENT ID (all of them, or just
/// `addr`). Interrupts off.
pub fn flush_current(addr: Option<u64>) {
    match addr {
        Some(a) => x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(a)),
        // A CR3 write without bit 63 flushes the ID it names
        None => unsafe { write_cr3(read_cr3() & !NOFLUSH) },
    }
}

/// Flushes every ID's translations on the calling CPU, global entries too.
pub fn flush_all_ids() {
    COUNTERS[super::percpu::cpu()].flush_all.fetch_add(1, Ordering::Relaxed);
    if INVPCID.load(Ordering::Relaxed) {
        unsafe { invpcid(2, 0, 0) };
    } else {
        // Any change of CR4.PGE flushes all IDs: toggle it twice
        use x86_64::registers::control::Cr4;
        let cr4 = Cr4::read_raw();
        unsafe {
            Cr4::write_raw(cr4 ^ (1 << 7));
            Cr4::write_raw(cr4);
        }
    }
}

/// The calling CPU's part of a shootdown of root `pml4` (`addr`, or everything): flushes
/// it if loaded; if not, flushes its ID (`INVPCID`) or marks its slot STALE. Interrupts
/// off.
pub fn shoot_local(pml4: u64, addr: Option<u64>) {
    if read_cr3() & ADDR_MASK == pml4 {
        flush_current(addr);
        return;
    }
    let me = super::percpu::cpu();
    let id = slot_of(pml4);
    let slot = &SLOT[me][id];
    if slot.load(Ordering::SeqCst) != pml4 {
        return; // nothing cached for it, or marked already
    }
    if INVPCID.load(Ordering::Relaxed) {
        COUNTERS[me].invpcid.fetch_add(1, Ordering::Relaxed);
        unsafe {
            match addr {
                Some(a) => invpcid(0, id as u64, a),
                None => invpcid(1, id as u64, 0),
            }
        }
    } else {
        let _ = slot.compare_exchange(pml4, pml4 | STALE, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Marks root `pml4`'s slot on CPU `cpu` STALE if it holds the root (part of a shootdown,
/// before reading whether `cpu` has the root loaded).
pub fn mark_remote(cpu: usize, pml4: u64) {
    let slot = &SLOT[cpu][slot_of(pml4)];
    if slot.load(Ordering::SeqCst) == pml4
        && slot.compare_exchange(pml4, pml4 | STALE, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    {
        COUNTERS[super::percpu::cpu()].marked.fetch_add(1, Ordering::Relaxed);
    }
}

/// Root `pml4` is going away (its address space is torn down, loaded nowhere): every CPU
/// forgets it, so a later root at the same address starts with a flush. Call before the
/// table's frames can be reused.
pub fn forget(pml4: u64) {
    if !enabled() {
        return;
    }
    let id = slot_of(pml4);
    for cpu in SLOT.iter() {
        let slot = &cpu[id];
        let _ = slot.compare_exchange(pml4, 0, Ordering::SeqCst, Ordering::SeqCst);
        let _ = slot.compare_exchange(pml4 | STALE, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// Turns PCID off again on the boot processor (the self-test failed), before the other
/// processors start: CR3 back to ID 0, then CR4.PCIDE cleared (which flushes every ID).
pub fn disable(why: &'static str) {
    x86_64::instructions::interrupts::without_interrupts(|| {
        ENABLED.store(false, Ordering::SeqCst);
        unsafe {
            write_cr3(read_cr3() & ADDR_MASK);
            x86_64::registers::control::Cr4::write_raw(x86_64::registers::control::Cr4::read_raw() & !(1 << 17));
        }
    });
    *OFF_BY.lock() = Some(why);
    crate::kprintln!("[pcid] PCID turned off: {} (every address-space switch flushes the TLB)", why);
}

/// Runs `f` as if the CPU had no `INVPCID` (the boot self-test, before the other
/// processors start).
pub fn without_invpcid<R>(f: impl FnOnce() -> R) -> R {
    let had = INVPCID.swap(false, Ordering::SeqCst);
    let r = f();
    INVPCID.store(had, Ordering::SeqCst);
    r
}

/// One line about PCID and its counters since boot (all CPUs).
pub fn summary() -> alloc::string::String {
    let pge = if global_enabled() { "global kernel pages on" } else { "global kernel pages off" };
    if !enabled() {
        let why = OFF_BY.lock().unwrap_or("the CPU does not have it");
        return alloc::format!("PCID off ({}), {}", why, pge);
    }
    let sum = |f: fn(&Counters) -> &AtomicU64| COUNTERS.iter().map(|c| f(c).load(Ordering::Relaxed)).sum::<u64>();
    alloc::format!(
        "{}; PCID on (INVPCID {}): CR3 loads kept the TLB {} times, flushed a taken-over ID {} times, a stale ID {} times; {} remote slots marked stale, {} INVPCID single-ID flushes, {} all-ID flushes",
        pge,
        if INVPCID.load(Ordering::Relaxed) { "yes" } else { "no" },
        sum(|c| &c.hits),
        sum(|c| &c.misses),
        sum(|c| &c.stale),
        sum(|c| &c.marked),
        sum(|c| &c.invpcid),
        sum(|c| &c.flush_all),
    )
}
