//! # Architecture Layer: `x86_64` CPU Control Register Inspection
//!
//! Captures point-in-time snapshots of the processor's architectural control registers
//! (`CR0`, `CR2`, `CR3`, and `CR4`) for diagnostics, shell inspection, and fault reporting.
//!
//! ## Architectural Role & Design Rationale
//!
//! In `x86_64` Long Mode, the CPU control registers govern fundamental execution behavior:
//! - `CR0` controls protected mode (`PE`), paging (`PG`), write protection (`WP`), and FPU emulation.
//! - `CR2` holds the faulting linear virtual address after a Page Fault (`#PF`, Vector 14).
//! - `CR3` holds the physical base address of the root 4-level page table (`PML4`).
//! - `CR4` enables Physical Address Extension (`PAE`), Page Global Enable (`PGE`), and SSE/FXSAVE (`OSFXSR`).
//!
//! `read_state` packages these registers into a safe `CpuState` structure so kernel commands
//! and diagnostic routines can inspect hardware state without inline assembly.
//!
//! ## Key Types & Interfaces
//!
//! - `CpuState`: Snapshot of `CR0`, `CR2`, `CR3` physical frame address, and `CR4` flags.
//! - `read_state`: Reads the current processor control registers and returns a `CpuState`.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (reading `CR0`, `CR2`, `CR3`, `CR4` in Ring 3 triggers `#GP`).
//! - **Hardware Interaction**: Direct `mov` reads from `CR0`, `CR2`, `CR3`, and `CR4`.
//! - **Concurrency**: Pure per-core register reads; lock-free and interrupt-safe.

use x86_64::registers::control::{Cr0, Cr0Flags, Cr2, Cr3, Cr4, Cr4Flags};
use x86_64::PhysAddr;

/// Snapshot of the `x86_64` processor's architectural control registers.
///
/// # Concurrency & Thread Safety
/// Plain `Copy` value type representing the state of the calling CPU core at the instant `read_state` was invoked.
#[derive(Debug, Clone, Copy)]
pub struct CpuState {
    /// Active flags in Control Register 0 (`CR0`, e.g., `PROTECTED_MODE_ENABLE`, `PAGING`, `WRITE_PROTECT`).
    pub cr0: Cr0Flags,
    /// Linear virtual address stored in Control Register 2 (`CR2`) from the most recent Page Fault (`#PF`).
    pub cr2: u64,
    /// Physical base address of the active 4-level `PML4` page table frame in Control Register 3 (`CR3`).
    pub cr3_frame: PhysAddr,
    /// Active feature flags in Control Register 4 (`CR4`, e.g., `PHYSICAL_ADDRESS_EXTENSION`, `OSFXSR`).
    pub cr4: Cr4Flags,
}

/// Reads the current CPU control registers (`CR0`, `CR2`, `CR3`, `CR4`) and returns them as a `CpuState`.
///
/// # Returns
///
/// A `CpuState` snapshot populated with the current hardware control register values.
pub fn read_state() -> CpuState {
    let (cr3_frame, _) = Cr3::read();
    CpuState {
        cr0: Cr0::read(),
        cr2: Cr2::read_raw(),
        cr3_frame: cr3_frame.start_address(),
        cr4: Cr4::read(),
    }
}

// wave11 GG begin: NUC run 12, reserved-bit page faults (err 0x9) on CPU 0
//
// The application processors set EFER.NXE in their start-up code; the boot processor kept
// whatever the firmware left, and the NUC's firmware leaves NXE clear. `vm::nx_enabled()`
// reads EFER on the CPU that builds an entry, so pages mapped on an AP carried NX (bit 63)
// and faulted with a reserved-bit error when CPU 0 walked them. [`enable_nx`] now sets
// NXE on the boot processor first thing, and the checks below report any entry that a CPU
// would refuse.

/// Execute-disable (EFER.NXE, bit 11).
const EFER_NXE: u64 = 1 << 11;
/// IA32_EFER.
const IA32_EFER: u32 = 0xC000_0080;

/// Sets EFER.NXE on this CPU when the CPU has execute-disable (CPUID 0x8000_0001 EDX bit
/// 20). The boot processor calls it before any page table is built.
///
/// # Returns
/// Whether NXE is on now.
pub fn enable_nx() -> bool {
    // SAFETY: CPUID is always available in long mode; EFER is read and written whole
    unsafe {
        let ext = core::arch::x86_64::__cpuid(0x8000_0000).eax;
        if ext < 0x8000_0001 || core::arch::x86_64::__cpuid(0x8000_0001).edx & (1 << 20) == 0 {
            return false;
        }
        let efer = crate::arch::syscall::rdmsr(IA32_EFER);
        if efer & EFER_NXE == 0 {
            crate::arch::syscall::wrmsr(IA32_EFER, efer | EFER_NXE);
        }
        crate::arch::syscall::rdmsr(IA32_EFER) & EFER_NXE != 0
    }
}

// wave11 GH begin: the NUC's state without the fix, under QEMU (nxe=fw-off nxe=nofix)
use crate::memory::vm::NX_SIM_OFF;

/// With the simulation on: EFER.NXE off on the boot processor for real, once its own
/// tables are loaded (the firmware's, which use NX, are gone); `vm::nx_enabled()` reads
/// EFER again from here, so the APs (which set NXE) build entries with NX, as on the NUC.
pub fn sim_nx_off_now() {
    if NX_SIM_OFF.load(core::sync::atomic::Ordering::SeqCst) {
        // SAFETY: EFER read and written whole; no entry the boot processor built has NX
        unsafe {
            let efer = crate::arch::syscall::rdmsr(IA32_EFER);
            crate::arch::syscall::wrmsr(IA32_EFER, efer & !EFER_NXE);
        }
        NX_SIM_OFF.store(false, core::sync::atomic::Ordering::SeqCst);
        crate::kprintln!("[cpu] nxe=fw-off nxe=nofix: EFER.NXE off on the boot processor (the NUC without the fix)");
    }
}
// wave11 GH end

/// EFER.NXE as the firmware left it on the boot processor (before [`enable_nx`]).
pub static BSP_FIRMWARE_EFER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The physical address width (MAXPHYADDR, CPUID 0x8000_0008 EAX bits 0-7; 36 without it).
pub fn max_phys_bits() -> u32 {
    if core::arch::x86_64::__cpuid(0x8000_0000).eax < 0x8000_0008 {
        return 36;
    }
    core::arch::x86_64::__cpuid(0x8000_0008).eax & 0xFF
}

/// Prints this CPU's paging state once: MAXPHYADDR, EFER, CR4 (and for the boot processor
/// the EFER the firmware left).
pub fn paging_report(cpu: usize) {
    // SAFETY: reading EFER
    let efer = unsafe { crate::arch::syscall::rdmsr(IA32_EFER) };
    let fw = if cpu == 0 { alloc::format!(", firmware EFER {:#x}", BSP_FIRMWARE_EFER.load(core::sync::atomic::Ordering::Relaxed)) } else { alloc::string::String::new() };
    crate::kprintln!(
        "[cpu] cpu {}: MAXPHYADDR {}, EFER {:#x} (NXE {}){}, CR4 {:#x}",
        cpu,
        max_phys_bits(),
        efer,
        if efer & EFER_NXE != 0 { "on" } else { "OFF" },
        fw,
        Cr4::read_raw()
    );
}

/// Why a CPU with `max_phys` address bits and EFER.NXE `nxe` refuses page-table entry `e`
/// at `level` (4 = PML4E, 3 = PDPTE, 2 = PDE, 1 = PTE) with a reserved-bit fault, or
/// `None`. Not-present entries are never refused.
pub fn reserved_reason(e: u64, level: u32, max_phys: u32, nxe: bool) -> Option<&'static str> {
    if e & 1 == 0 {
        return None;
    }
    let max_phys = max_phys.clamp(32, 52);
    // Bits MAXPHYADDR..51 of the address field are reserved
    let high = if max_phys >= 52 { 0 } else { ((1u64 << 52) - 1) & !((1u64 << max_phys) - 1) };
    if e & high != 0 {
        return Some("address bits at or above MAXPHYADDR");
    }
    if e & (1 << 63) != 0 && !nxe {
        return Some("NX (bit 63) while EFER.NXE is off");
    }
    let ps = e & (1 << 7) != 0;
    match level {
        4 if ps => Some("PS in a PML4 entry"),
        3 if ps && e & 0x3FFF_E000 != 0 => Some("reserved bits 13-29 of a 1 GiB page"),
        2 if ps && e & 0x1F_E000 != 0 => Some("reserved bits 13-20 of a 2 MiB page"),
        _ => None,
    }
}

/// A fixed-size text buffer (no allocation: usable in a fault handler).
pub struct FixedText {
    buf: [u8; 1024],
    len: usize,
}

impl FixedText {
    /// An empty buffer.
    pub const fn new() -> Self {
        Self { buf: [0; 1024], len: 0 }
    }

    /// The text so far.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("?")
    }
}

impl core::fmt::Write for FixedText {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Writes the whole walk of `va` in the tables at `cr3` (all four levels, each entry
/// checked with [`reserved_reason`] for this CPU) into `out`. Reads the tables through the
/// direct map; allocates nothing.
pub fn write_walk(out: &mut FixedText, cr3: u64, va: u64) {
    use core::fmt::Write;
    const ADDR: u64 = 0x000F_FFFF_FFFF_F000;
    // SAFETY: reading EFER
    let efer = unsafe { crate::arch::syscall::rdmsr(IA32_EFER) };
    let (max_phys, nxe) = (max_phys_bits(), efer & EFER_NXE != 0);
    let _ = write!(out, "walk of {:#x} at cr3 {:#x} (cpu {}, MAXPHYADDR {}, EFER {:#x}):", va, cr3, crate::arch::percpu::cpu(), max_phys, efer);
    let mut table = cr3 & ADDR;
    for (i, shift) in [39u64, 30, 21, 12].into_iter().enumerate() {
        let level = 4 - i as u32;
        if table == 0 {
            break;
        }
        // SAFETY: a page table, through the direct map
        let e = unsafe { (crate::memory::frame_allocator::phys_to_virt(table) as *const u64).add(((va >> shift) & 511) as usize).read_volatile() };
        let _ = write!(out, " L{} [{}] {:#x}", level, (va >> shift) & 511, e);
        if let Some(why) = reserved_reason(e, level, max_phys, nxe) {
            let _ = write!(out, " RESERVED ({})", why);
        }
        if e & 1 == 0 || level == 1 || (level < 4 && e & (1 << 7) != 0) {
            break;
        }
        table = e & ADDR;
    }
}

/// Reserved-bit page faults reported so far ([`report_rsvd_fault`]).
static RSVD_REPORTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A page fault with the reserved-bit error (bit 3): the first 8 per boot print the whole
/// walk of the faulting address on the serial port (no allocation, no locks).
pub fn report_rsvd_fault(cr2: u64, error: u64, rip: u64) {
    use core::fmt::Write;
    let n = RSVD_REPORTS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if n >= 8 {
        return;
    }
    let mut t = FixedText::new();
    let _ = write!(t, "[paging] reserved-bit fault {}: err {:#x} at rip {:#x}: ", n + 1, error, rip);
    let cr3 = Cr3::read().0.start_address().as_u64();
    write_walk(&mut t, cr3, cr2);
    let _ = t.write_str("\n");
    crate::console::serial_write(t.as_str());
}
// wave11 GG end

// wave11 GG begin: a boot-time check of the kernel's page tables against this CPU's rules
/// Checks every present entry of the tables at `cr3` (all levels) with [`reserved_reason`]
/// for this CPU; prints the first 8 refused entries and a summary line. Run once at boot on
/// the kernel's tables, before the other processors start.
pub fn check_tables(cr3: u64) {
    const ADDR: u64 = 0x000F_FFFF_FFFF_F000;
    let t0 = unsafe { core::arch::x86_64::_rdtsc() }; // wave11 GH: its cost at boot
    // SAFETY: reading EFER
    let efer = unsafe { crate::arch::syscall::rdmsr(IA32_EFER) };
    let (max_phys, nxe) = (max_phys_bits(), efer & EFER_NXE != 0);
    let (mut checked, mut bad) = (0u64, 0u64);
    let note = |level: u32, va: u64, e: u64, checked: &mut u64, bad: &mut u64| {
        *checked += 1;
        if let Some(why) = reserved_reason(e, level, max_phys, nxe) {
            if *bad < 8 {
                crate::kprintln!("[paging] RESERVED entry L{} for {:#x}: {:#x} ({})", level, va, e, why);
            }
            *bad += 1;
            return false;
        }
        true
    };
    let read = |t: u64, i: u64| -> u64 {
        // SAFETY: a page table, through the direct map
        unsafe { (crate::memory::frame_allocator::phys_to_virt(t) as *const u64).add(i as usize).read_volatile() }
    };
    let sign = |va: u64| if va & (1 << 47) != 0 { va | 0xFFFF_0000_0000_0000 } else { va };
    let l4 = cr3 & ADDR;
    for i4 in 0..512u64 {
        let e4 = read(l4, i4);
        if e4 & 1 == 0 || !note(4, sign(i4 << 39), e4, &mut checked, &mut bad) {
            continue;
        }
        for i3 in 0..512u64 {
            let e3 = read(e4 & ADDR, i3);
            let va3 = sign(i4 << 39 | i3 << 30);
            if e3 & 1 == 0 || !note(3, va3, e3, &mut checked, &mut bad) || e3 & (1 << 7) != 0 {
                continue;
            }
            for i2 in 0..512u64 {
                let e2 = read(e3 & ADDR, i2);
                let va2 = va3 | i2 << 21;
                if e2 & 1 == 0 || !note(2, va2, e2, &mut checked, &mut bad) || e2 & (1 << 7) != 0 {
                    continue;
                }
                for i1 in 0..512u64 {
                    let e1 = read(e2 & ADDR, i1);
                    if e1 & 1 != 0 {
                        note(1, va2 | i1 << 12, e1, &mut checked, &mut bad);
                    }
                }
            }
        }
    }
    // wave11 GH: how long it took (TSC through the PIT's calibration; cycles without it)
    let cycles = unsafe { core::arch::x86_64::_rdtsc() } - t0;
    let mult = crate::arch::pit::clock_state().3;
    let us = if mult != 0 { ((cycles as u128 * mult as u128) >> 32) as u64 / 1000 } else { 0 };
    crate::kprintln!("[paging] kernel tables checked: {} entries, {} refused by this CPU (MAXPHYADDR {}, NXE {}) in {} us ({} cycles)", checked, bad, max_phys, if nxe { "on" } else { "off" }, us, cycles);
}
// wave11 GG end
