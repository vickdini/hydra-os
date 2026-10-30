//! # Archive Subsystem
//!
//! Provides archive processing primitives (Unix AR and POSIX TAR)
//! for inspecting and extracting payloads in Hydra OS.

pub mod ar;
pub mod rootfs;
pub mod tar;

pub use ar::{ArArchive, ArEntry};
pub use tar::{TarArchive, TarExtractSummary};
