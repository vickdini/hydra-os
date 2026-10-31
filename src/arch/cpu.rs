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
