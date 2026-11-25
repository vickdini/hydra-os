//! # Architecture Subsystem: `x86_64` Bare-Metal Hardware Abstraction Layer
//!
//! Encapsulates all processor-specific and legacy PC platform drivers for `x86_64` Long Mode,
//! including descriptor tables, interrupt controllers, timers, storage/bus drivers, and
//! fast hardware system call trampolines.
//!
//! ## Architectural Role & Design Rationale
//!
//! Hydra OS isolates all low-level `x86_64` CPU register manipulation, assembly interrupt/syscall
//! stubs, and I/O port drivers inside `crate::arch`. This keeps higher-level microkernel
//! subsystems (scheduling, virtual memory, capability tables, IPC, and OpenZFS storage) portable
//! and cleanly separated from hardware specifics.
//!
//! ## Key Types & Interfaces
//!
//! - `boot_services`: Orchestrates `ExitBootServices` and transitions the system from UEFI firmware to autonomous kernel control.
//! - `gdt` / `idt`: Manages the 64-bit Global Descriptor Table, Task State Segment (TSS), and 256-gate Interrupt Descriptor Table.
//! - [`syscall`]: Configures `IA32_EFER`, `IA32_STAR`, `IA32_LSTAR`, and `IA32_FMASK` MSRs for Ring 3 `syscall`/`sysretq` transitions.
//! - `pic` / `pit` / `rtc`: Drives the dual-8259 PIC, 8254 PIT preemptive timer, and MC146818 CMOS Real-Time Clock.
//! - `keyboard` / `mouse`: Handles 8042 PS/2 keyboard scancodes and 3-byte auxiliary mouse motion packets.
//! - `pci` / `ata`: Enumerates the PCI configuration space and drives ATA/IDE disks via PIO and Bus-Master DMA.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (Kernel supervisor mode), servicing traps and syscalls from Ring 3.
//! - **Hardware Interaction**: Control registers (`CR0`..`CR4`), MSRs, `GDTR`/`IDTR`/`TR`, and legacy/PCI x86 I/O ports.
//! - **Concurrency**: Interrupt-safe spinlocks (`spin::Mutex`) and lock-free atomic state variables.

/// UEFI Boot Services termination and full bare-metal hardware takeover sequence.
pub mod boot_services;
// wave11 GH begin
/// ACPI power-off and reset values from the FADT and DSDT (plain logic).
pub mod acpi_s5;
/// The boot log on the EFI partition.
#[cfg(target_os = "uefi")]
pub mod bootlog;
/// Host builds (unit tests): the boot log does nothing.
#[cfg(not(target_os = "uefi"))]
pub mod bootlog {
    pub fn append(_text: &[u8]) {}
    pub fn at_power(_what: &'static str) {}
    pub fn boot_disk() -> Option<usize> {
        None
    }
    pub fn disk_present(_idx: usize, _sector: &mut [u8; 512]) -> bool {
        true
    }
    pub fn after_panic() {}
}
/// The boot words and the start menu.
pub mod bootopts;
/// Boot breadcrumbs on the boot volume (diagnostic stick).
#[cfg(target_os = "uefi")]
pub mod crumb;
/// Host builds (unit tests): no breadcrumbs.
#[cfg(not(target_os = "uefi"))]
pub mod crumb {
    pub fn step(_name: &str) {}
    pub fn want_high() -> bool {
        true
    }
    pub fn end(_name: &str) {}
    pub fn prepare_arrival() {}
    pub fn high_arrived() {}
    pub fn step_fmt(_args: core::fmt::Arguments) {}
    pub fn quiet_fmt(_args: core::fmt::Arguments) {}
    pub fn force_line(_args: core::fmt::Arguments) {}
    pub fn screen_only_from_now() {}
    pub fn machine_state() {}
    pub fn fw_ptr_ok(_p: *const u8, _what: &str) -> bool {
        true
    }
    pub fn pick_gop() -> Option<uefi::Handle> {
        None
    }
}
/// The boot words' plain logic.
pub mod bootwords;
/// The boot log's memory (plain logic).
pub mod logring;
// wave11 GH end
pub mod bootdisk;
/// Boot stage timing ([`boottime::mark`], printed by [`boottime::report`]).
pub mod boottime;
/// `x86_64` control register (`CR0`, `CR2`, `CR3`, `CR4`) state inspection.
pub mod cpu;
pub mod debugregs;
/// The ACPI DMAR table and VT-d I/O page tables (hardware-independent part of the IOMMU).
pub mod dmar;
/// QEMU firmware configuration values (`-fw_cfg`): the boot mode test harnesses choose.
pub mod fwcfg;
/// 64-bit Global Descriptor Table (GDT) and Task State Segment (TSS) management.
pub mod gdt;
/// 256-entry Interrupt Descriptor Table (IDT), CPU exception handlers, and IRQ trampolines.
pub mod idt;
/// Intel VT-d DMA remapping: each driver's device reaches only its own DMA memory.
pub mod iommu;
/// 8042 PS/2 keyboard controller and Scancode Set 1 decoder.
pub mod keyboard;
/// 8042 PS/2 auxiliary pointing device (mouse) 3-byte packet driver.
pub mod mouse;
/// VMware's absolute pointer behind QEMU's PS/2 mouse (the guest pointer follows the host's).
pub mod vmmouse;
/// USB keyboards and pointers: the kernel side of the Ring 3 USB driver.
pub mod usb_input;
/// Peripheral Component Interconnect (PCI) bus enumeration and configuration space access.
pub mod pci;
/// PCID (tagged TLB entries) and the one helper that loads CR3.
pub mod pcid;
// wave11 GG begin
/// The page attribute table: write-combining memory for the framebuffer.
pub mod pat;
/// EHCI USB controllers: taken from the firmware and stopped before the IOMMU translates.
pub mod ehci;
// wave11 GG end
pub mod percpu;
/// Dual 8259 Programmable Interrupt Controller (PIC) initialization and IRQ masking.
pub mod pic;
/// 8254 Programmable Interval Timer (PIT) driver and system uptime accounting.
pub mod pit;
pub mod power;
/// Kernel CSPRNG (ChaCha20) for /dev/urandom and getrandom(2).
pub mod random;
pub mod raw_serial;
/// The kernel image moved to the higher half at entry.
pub mod relocate;
/// MC146818 CMOS Real-Time Clock (RTC) wall-clock epoch initialization.
pub mod rtc;
/// User segment state (selectors, TLS descriptors, LDT) put in the CPU at a context switch.
pub mod segments;
pub mod smp;
/// Fast `x86_64` MSR-based `syscall`/`sysretq` entry stub and kernel system call dispatcher.
pub mod syscall;
pub mod vdso;

