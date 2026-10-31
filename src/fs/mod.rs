//! # Filesystem Subsystem: Virtual File Layer, Pipes, and OpenZFS Integration
//!
//! Coordinates per-process file descriptor management, anonymous streaming pipes,
//! and client/server access to Hydra OS's copy-on-write OpenZFS storage pool.
//!
//! ## Architectural Role & Design Rationale
//! In Hydra OS's microkernel-inspired architecture, userland processes and kernel
//! subsystems interact with storage and I/O channels through uniform file descriptor
//! indices (`FdTable`) or path-level RPC facade calls (`ZfsClient`). This root
//! module re-exports the core primitives needed by the system call dispatcher, ELF
//! loader, and interactive shell without exposing low-level storage internals.
//!
//! ## Key Types & Interfaces
//! - `ZfsClient`: High-level path and inode facade for querying and mutating the ZFS pool.
//! - `FdTable` & `FileDescriptor`: Per-process descriptor table and polymorphic I/O handle.
//! - `PipeBuffer`: Lock-protected ring buffer backing unidirectional POSIX pipes.
//! - `ZfsServer` & `init_server`: Singleton OpenZFS storage server and its bootstrap routine.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Indirectly drives ATA PIO/DMA disk sectors and UEFI boot media via `zfs`.
//! - Concurrency: Spinlock-synchronized global server (`ZFS_SERVER`) and shared `Arc<Mutex<...>>` descriptors.

pub mod client;
pub mod fd;
pub mod pipe;
pub mod zfs;

pub use client::ZfsClient;
pub use fd::{FdTable, FileDescriptor, SharedFdTable, MAX_FDS};
pub use pipe::{PipeBuffer, PIPE_BUFFER_SIZE};
pub use zfs::{init_server, ZfsServer, ZFS_SERVER};


