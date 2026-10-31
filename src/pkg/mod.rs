//! # Package & Archive Subsystem: Container Demuxers and Rootfs Installer
//!
//! Provides archive processing primitives for Unix `ar` (`.deb` containers), POSIX `tar`
//! archives, and complete Linux root filesystem installation into OpenZFS.
//!
//! ## Architectural Role & Design Rationale
//! To support installing standard Linux distributions (such as Ubuntu base images) and
//! Debian `.deb` packages without external userland tools during early boot or rescue
//! shell sessions, the kernel includes native zero-copy demuxers (`ArArchive`, `TarArchive`)
//! and a full-featured POSIX tar installer (`rootfs::install`).
//!
//! ## Key Types & Interfaces
//! - `ArArchive` & `ArEntry`: Zero-copy reader for Unix `ar` archives and `.deb` packages.
//! - `TarArchive` & `TarExtractSummary`: Streaming extractor for basic UStar/POSIX `.tar` archives.
//! - `rootfs::install`: Full-fidelity Linux rootfs unpacker supporting permissions, symlinks, hardlinks, and device nodes.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Writes extracted files and metadata into the OpenZFS pool via [`crate::fs::ZfsClient`].
//! - Concurrency: Acquires the global ZFS server lock per filesystem operation during extraction.

pub mod ar;
pub mod rootfs;
pub mod tar;

pub use ar::{ArArchive, ArEntry};
pub use tar::{TarArchive, TarExtractSummary};
