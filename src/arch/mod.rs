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

/// Bare-metal ATA/IDE PIO and Bus-Master DMA hard disk driver.
pub mod ata;
/// UEFI Boot Services termination and full bare-metal hardware takeover sequence.
pub mod boot_services;
/// `x86_64` control register (`CR0`, `CR2`, `CR3`, `CR4`) state inspection.
pub mod cpu;
/// 64-bit Global Descriptor Table (GDT) and Task State Segment (TSS) management.
pub mod gdt;
/// 256-entry Interrupt Descriptor Table (IDT), CPU exception handlers, and IRQ trampolines.
pub mod idt;
/// 8042 PS/2 keyboard controller and Scancode Set 1 decoder.
pub mod keyboard;
/// 8042 PS/2 auxiliary pointing device (mouse) 3-byte packet driver.
pub mod mouse;
/// Peripheral Component Interconnect (PCI) bus enumeration and configuration space access.
pub mod pci;
/// Dual 8259 Programmable Interrupt Controller (PIC) initialization and IRQ masking.
pub mod pic;
/// 8254 Programmable Interval Timer (PIT) driver and system uptime accounting.
pub mod pit;
/// MC146818 CMOS Real-Time Clock (RTC) wall-clock epoch initialization.
pub mod rtc;
/// Fast `x86_64` MSR-based `syscall`/`sysretq` entry stub and kernel system call dispatcher.
pub mod syscall;

