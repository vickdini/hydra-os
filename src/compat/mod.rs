//! # Compatibility Layer: Foreign Operating System Binary Translation
//!
//! Provides binary translation and ABI compatibility layers for foreign operating systems,
//! enabling unmodified userland applications to execute directly on the Hydra Microkernel.
//!
//! ## Architectural Role & Design Rationale
//! Rather than requiring all software to be recompiled against a proprietary microkernel API,
//! the compatibility subsystem intercepts architectural system calls (`SYSCALL`) and maps foreign
//! ABI conventions, data structures, and virtual filesystem paths onto native Hydra primitives
//! (tasks, virtual memory, ZFS storage, and IPC channels).
//!
//! ## Key Types & Interfaces
//! - `linux`: Full Linux `x86_64` ABI translation layer supporting `musl`, `glibc`, BusyBox,
//!   Wayland clients, and Qt6/KDE runtimes.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel syscall handler entry) serving Ring 3 (Userland) binaries
//! - Hardware Interaction: Model-Specific Registers (`IA32_FS_BASE`, `STAR`, `LSTAR`), Page Tables (`CR3`)
//! - Concurrency: Per-subsystem fine-grained [`spin::Mutex`] and lock-free atomic counters

/// Linux `x86_64` ABI compatibility layer and system call translation engine.
pub mod linux;

