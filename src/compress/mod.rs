//! # Compression Subsystem
//!
//! Provides pure-Rust `no_std` decompression routines for DEFLATE (RFC 1951) and Gzip (RFC 1952).

pub mod deflate;
pub mod gzip;

pub use deflate::{inflate, inflate_with_capacity};
pub use gzip::decompress as gunzip;

/// Decompresses an XZ (.xz / LZMA2) compressed payload into uncompressed bytes.
pub fn unxz(data: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let mut input = patina_lzma_rs::io::Cursor::new(data);
    let mut output = alloc::vec::Vec::new();
    patina_lzma_rs::xz_decompress(&mut input, &mut output).map_err(|_| "XZ / LZMA2 decompression failed")?;
    Ok(output)
}
