//! # RFC 1952 Gzip Decompressor
//!
//! Parses Gzip container headers, flags, extra fields, and file names,
//! feeds the inner compressed stream to the DEFLATE decompressor, and verifies CRC32 and ISIZE.

extern crate alloc;

use super::deflate::inflate_with_capacity;
use alloc::vec::Vec;

const GZIP_ID1: u8 = 0x1F;
const GZIP_ID2: u8 = 0x8B;
const GZIP_CM_DEFLATE: u8 = 8;

#[allow(dead_code)]
const FLAG_FTEXT: u8 = 0x01;
const FLAG_FHCRC: u8 = 0x02;
const FLAG_FEXTRA: u8 = 0x04;
const FLAG_FNAME: u8 = 0x08;
const FLAG_FCOMMENT: u8 = 0x10;

/// Generates the standard IEEE 802.3 CRC32 lookup table at compile time.
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

const CRC32_TABLE: [u32; 256] = make_crc32_table();

/// Fast table-driven standard IEEE 802.3 CRC32 calculation.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ (b as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    !crc
}

/// Decompresses a complete Gzip (.gz) archive payload into uncompressed bytes.
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
