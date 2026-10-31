//! # Compression Subsystem: RFC 1952 Gzip Container Decompressor
//!
//! Parses RFC 1952 Gzip headers, optional extra fields, filenames, and comments,
//! delegates inner bitstream decompression to [`super::deflate::inflate_with_capacity()`],
//! and verifies the trailing IEEE 802.3 CRC32 checksum and uncompressed `ISIZE`.
//!
//! ## Architectural Role & Design Rationale
//! Distribution rootfs images (e.g., `ubuntu-base.tar.gz`) and Debian package control/data
//! members wrap DEFLATE payloads inside a Gzip container. By reading the 32-bit `ISIZE`
//! footer prior to decompression, this module pre-allocates the exact output buffer size
//! up front (up to `128 MiB`), eliminating repeated heap reallocations during extraction.
//!
//! ## Key Types & Interfaces
//! - [`decompress()`]: Unpacks and verifies a complete `.gz` byte slice.
//! - [`crc32()`]: Table-driven IEEE 802.3 CRC32 checksum calculator.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (purely in-memory computation and `alloc` vector allocation).
//! - Concurrency: Stateless functions using a compile-time `const` lookup table; thread-safe.

extern crate alloc;

use super::deflate::inflate_with_capacity;
use alloc::vec::Vec;

/// First magic byte of a Gzip header (`0x1F`).
const GZIP_ID1: u8 = 0x1F;
/// Second magic byte of a Gzip header (`0x8B`).
const GZIP_ID2: u8 = 0x8B;
/// Gzip compression method identifier for DEFLATE (`8`).
const GZIP_CM_DEFLATE: u8 = 8;

/// Gzip flag bit (`0x01`): payload is probably ASCII texthint.
#[allow(dead_code)]
const FLAG_FTEXT: u8 = 0x01;
/// Gzip flag bit (`0x02`): a 16-bit header CRC (`FHCRC`) precedes the compressed blocks.
const FLAG_FHCRC: u8 = 0x02;
/// Gzip flag bit (`0x04`): variable-length extra fields (`FEXTRA`) are present.
const FLAG_FEXTRA: u8 = 0x04;
/// Gzip flag bit (`0x08`): an original zero-terminated filename (`FNAME`) is present.
const FLAG_FNAME: u8 = 0x08;
/// Gzip flag bit (`0x10`): a zero-terminated file comment (`FCOMMENT`) is present.
const FLAG_FCOMMENT: u8 = 0x10;

/// Generates the standard 256-entry IEEE 802.3 CRC32 lookup table (polynomial `0xEDB88320`) at compile time.
///
/// # Returns
///
/// A 256-element `u32` array mapping each byte value to its reflected CRC32 remainder.
const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Precomputed IEEE 802.3 CRC32 lookup table.
const CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Computes the standard IEEE 802.3 32-bit cyclic redundancy check (CRC32) over `data`.
///
/// Uses the compile-time [`CRC32_TABLE`] for single-byte table-driven lookups with initial
/// value `0xFFFF_FFFF` and final bitwise inversion.
///
/// # Arguments
///
/// * `data` - Byte slice over which to compute the checksum.
///
/// # Returns
///
/// The 32-bit CRC32 digest.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

/// Decompresses a complete RFC 1952 Gzip (`.gz`) archive slice and verifies its integrity.
///
/// Validates the 10-byte header and optional flag sections, extracts the inner DEFLATE
/// stream, and confirms that both the 32-bit uncompressed length (`ISIZE`) and [`crc32()`]
/// match the 8-byte trailer.
///
/// # Arguments
///
/// * `gz_data` - Slice containing the complete Gzip member (minimum 18 bytes).
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Verified uncompressed payload bytes.
///
/// # Errors
///
/// * `Err("Gzip archive too short (minimum 18 bytes required)")` - Input is smaller than header + footer.
/// * `Err("Invalid Gzip magic identifier (expected 0x1F, 0x8B)")` - Header magic bytes do not match.
/// * `Err("Unsupported Gzip compression method (only DEFLATE supported)")` - Compression method is not `8`.
/// * `Err("Truncated Gzip FEXTRA header")` / `Err("Truncated Gzip compressed payload")` - Malformed header fields.
/// * `Err("Gzip ISIZE mismatch in footer")` - Decompressed length modulo $2^{32}$ does not match trailer.
/// * `Err("Gzip CRC32 checksum verification failed")` - Decompressed payload failed CRC32 check.
pub fn decompress(gz_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if gz_data.len() < 18 {
        return Err("Gzip archive too short (minimum 18 bytes required)");
    }

    if gz_data[0] != GZIP_ID1 || gz_data[1] != GZIP_ID2 {
        return Err("Invalid Gzip magic identifier (expected 0x1F, 0x8B)");
    }

    if gz_data[2] != GZIP_CM_DEFLATE {
        return Err("Unsupported Gzip compression method (only DEFLATE supported)");
    }

    let flags = gz_data[3];
    let mut offset = 10; // Header fixed size

    // Skip FEXTRA
    if (flags & FLAG_FEXTRA) != 0 {
        if offset + 2 > gz_data.len() {
            return Err("Truncated Gzip FEXTRA header");
        }
        let xlen = (gz_data[offset] as usize) | ((gz_data[offset + 1] as usize) << 8);
        offset += 2 + xlen;
    }

    // Skip FNAME (zero-terminated ASCII string)
    if (flags & FLAG_FNAME) != 0 {
        while offset < gz_data.len() && gz_data[offset] != 0 {
            offset += 1;
        }
        offset += 1; // skip null terminator
    }

    // Skip FCOMMENT (zero-terminated ASCII string)
    if (flags & FLAG_FCOMMENT) != 0 {
        while offset < gz_data.len() && gz_data[offset] != 0 {
            offset += 1;
        }
        offset += 1; // skip null terminator
    }

    // Skip FHCRC (2-byte header CRC16)
    if (flags & FLAG_FHCRC) != 0 {
        offset += 2;
    }

    if offset + 8 > gz_data.len() {
        return Err("Truncated Gzip compressed payload");
    }

    let deflate_end = gz_data.len() - 8;
    let deflate_stream = &gz_data[offset..deflate_end];

    // Read footer CRC32 and ISIZE ahead of decompression
    let expected_crc = (gz_data[deflate_end] as u32)
        | ((gz_data[deflate_end + 1] as u32) << 8)
        | ((gz_data[deflate_end + 2] as u32) << 16)
        | ((gz_data[deflate_end + 3] as u32) << 24);

    let expected_isize = (gz_data[deflate_end + 4] as u32)
        | ((gz_data[deflate_end + 5] as u32) << 8)
        | ((gz_data[deflate_end + 6] as u32) << 16)
        | ((gz_data[deflate_end + 7] as u32) << 24);

    // Pre-allocate output vector exactly using Gzip ISIZE to prevent costly vector resizing/doubling
    let capacity_hint = if expected_isize > 0 && (expected_isize as usize) <= 128 * 1024 * 1024 {
        expected_isize as usize
    } else {
        deflate_stream.len().saturating_mul(3)
    };

    // Decompress inner DEFLATE stream
    let decompressed = inflate_with_capacity(deflate_stream, capacity_hint)?;

    if (decompressed.len() as u32) != expected_isize {
        return Err("Gzip ISIZE mismatch in footer");
    }

    let actual_crc = crc32(&decompressed);
    if actual_crc != expected_crc {
        return Err("Gzip CRC32 checksum verification failed");
    }

    Ok(decompressed)
}
