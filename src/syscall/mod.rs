//! # System Call Subsystem: ABI Definitions & Userland Invocation
//!
//! Exposes system call numbers, frame definitions, statistics, and inline assembly wrappers
//! for executing system calls from unprivileged Ring 3 userland processes.
//!
//! ## Architectural Role & Design Rationale
//!
//! This module acts as the public API boundary for system calls in Hydra OS. It re-exports
//! low-level constants and types defined in [`crate::arch::syscall`] while providing safe and
//! inline-assembly wrappers in `user` that Ring 3 userland code or test routines can call directly.
//!
//! ## Key Types & Interfaces
//!
//! - `user`: Userland system call stubs (`sys_yield`, `sys_write`, `sys_open`, `sys_ipc_send`, etc.).
//! - `SyscallFrame`: Architectural register context passed to the kernel dispatcher.
//! - `SyscallStats`: Global performance and diagnostic telemetry for system calls.

/// Userland system call wrappers and inline assembly invocation helpers.
pub mod user;

pub use crate::arch::syscall::{
    SyscallFrame, SyscallStats, SYSCALL_STATS,
    SYS_EXIT, SYS_GETPID, SYS_IPC_RECV, SYS_IPC_SEND, SYS_SLEEP, SYS_UPTIME, SYS_WRITE, SYS_YIELD,
};
pub use user::*;
