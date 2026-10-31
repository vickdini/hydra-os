//! # OpenZFS Storage Engine: Module Root & Subsystem Exports
//!
//! Integrates a clean-room, `no_std` implementation of the OpenZFS copy-on-write
//! transactional object and filesystem architecture into Hydra OS.
//!
//! ## Architectural Role & Design Rationale
//! Rather than layering a traditional overwrite-in-place filesystem over a block device,
//! Hydra OS implements ZFS's end-to-end stack: the Storage Pool Allocator ([`Spa`]),
//! Data Management Unit ([`Dmu`]), ZAP directory engine ([`zap::Zap`]), and ZFS POSIX
//! Layer ([`zpl`]). Every block pointer carries a 256-bit [`Fletcher4`] checksum, and
//! every mutation is staged in memory before being atomically committed in a transaction
//! group (TXG) via an updated [`Uberblock`].
//!
//! ## Key Types & Interfaces
//! - [`ZfsServer`] & `init_server`: Global microkernel file server singleton and initialization entry point.
//! - [`Spa`]: Storage Pool Allocator managing physical/RAM vdevs, space bitmaps, and block caching.
//! - [`Dmu`]: Transactional object store mapping object IDs to copy-on-write block trees.
//! - [`DnodePhys`], [`BlockPointer`], [`Uberblock`], [`Fletcher4`]: Core on-disk format v2 structures.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Primary ATA disk (PIO/DMA) with automatic 64 MiB RAM disk fallback.
//! - Concurrency: Synchronized through the global [`ZFS_SERVER`] spinlock mutex.

pub mod dmu;
pub mod selftest;
pub mod server;
pub mod spa;
pub mod types;
pub mod zap;
pub mod zpl;

pub use dmu::Dmu;
pub use server::{init_server, with_server, ZfsServer, ENDPOINT_ZFS_SERVER, ZFS_SERVER};
pub use spa::Spa;
pub use types::{BlockPointer, DnodePhys, DnodeType, Fletcher4, Uberblock, ZFS_BLOCK_SIZE};
