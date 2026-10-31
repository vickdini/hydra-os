//! # Compression Subsystem: Archive & Payload Decompression
//!
//! Provides pure-Rust `no_std` decompression routines for DEFLATE (RFC 1951),
//! Gzip (RFC 1952), and XZ / LZMA2 compressed streams.
//!
//! ## Architectural Role & Design Rationale
//! System packages (`.deb`), root filesystem tarballs (`.tar.gz`, `.tar.xz`), and
//! kernel assets are distributed in compressed containers to minimize boot media and
//! network transfer footprints. This subsystem exposes unified, memory-safe decompression
//! primitives that operate directly on in-memory slices using the kernel heap.
//!
//! ## Key Types & Interfaces
//! - `inflate` & `inflate_with_capacity`: Raw RFC 1951 DEFLATE bitstream decompressor.
//! - `gunzip`: RFC 1952 Gzip container parser and CRC32-verifying decompressor.
//! - `unxz`: XZ / LZMA2 stream decompressor used for Debian package payloads.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (purely computational, operating on RAM buffers via `alloc`).
//! - Concurrency: Stateless functions; completely thread-safe and re-entrant.

pub mod deflate;
pub mod gzip;

pub use deflate::{inflate, inflate_with_capacity};
pub use gzip::decompress as gunzip;

/// Decompresses an XZ (`.xz` / LZMA2) compressed byte slice into a newly allocated buffer.
///
/// Wraps `patina_lzma_rs` with an in-memory cursor to decode LZMA2 dictionary streams
/// commonly found in modern Debian binary packages (`data.tar.xz`).
///
/// # Arguments
///
/// * `data` - Raw byte slice containing a complete `.xz` stream header, blocks, and footer.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Dynamically allocated vector holding the uncompressed payload.
///
/// # Errors
///
/// * `Err("XZ / LZMA2 decompression failed")` - If the stream magic is invalid, truncated, or corrupt.
pub fn unxz(data: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let mut input = patina_lzma_rs::io::Cursor::new(data);
    let mut output = alloc::vec::Vec::new();
    patina_lzma_rs::xz_decompress(&mut input, &mut output).map_err(|_| "XZ / LZMA2 decompression failed")?;
    Ok(output)
}
