//! Tests for `src/compress`: the DEFLATE bit reader and decoder, gzip framing
//! and CRC-32, and the XZ wrapper.
//!
//! Compressed inputs come from `flate2` (zlib's format, independently
//! implemented), so a passing round trip means Hydra's decoder agrees with a
//! reference encoder, not merely with itself.

use std::io::Write;

use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::{Compression, GzBuilder};
use hydra_hosttests::compress::deflate::{inflate, inflate_with_capacity, BitReader};
use hydra_hosttests::compress::gzip::{crc32, decompress};
use hydra_hosttests::compress::{gunzip, unxz};

fn deflate(data: &[u8], level: u32) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(level));
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Deterministic pseudo-random bytes (LCG), so failures reproduce.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut s = seed;
    (0..len)
        .map(|_| {
            s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (s >> 16) as u8
        })
        .collect()
}

/// Text-like input with lots of repetition: drives back-references and,
/// at higher levels, dynamic Huffman blocks.
fn prose(len: usize) -> Vec<u8> {
    let words = ["hydra ", "kernel ", "zfs ", "capability ", "endpoint ", "\n", "scheduler "];
    let mut out = Vec::with_capacity(len);
    let mut i = 0usize;
    while out.len() < len {
        out.extend_from_slice(words[(i * 7 + i / 3) % words.len()].as_bytes());
        i += 1;
    }
    out.truncate(len);
    out
}

fn btype(stream: &[u8]) -> u8 {
    (stream[0] >> 1) & 0b11
}

// ---------------------------------------------------------------- BitReader

#[test]
fn bit_reader_reads_lsb_first() {
    let mut r = BitReader::new(&[0b1011_0101, 0xFF]);
    assert_eq!(r.read_bits(3), Ok(0b101));
    assert_eq!(r.read_bits(5), Ok(0b10110));
    assert_eq!(r.read_bits(8), Ok(0xFF));
}

#[test]
fn bit_reader_spans_byte_boundaries() {
    let mut r = BitReader::new(&[0x34, 0x12, 0x78, 0x56]);
    assert_eq!(r.read_bits(4), Ok(0x4));
    assert_eq!(r.read_bits(16), Ok(0x8123));
    assert_eq!(r.read_bits(12), Ok(0x567));
}

#[test]
fn bit_reader_zero_width_read_consumes_nothing() {
    let mut r = BitReader::new(&[0xAB]);
    assert_eq!(r.read_bits(0), Ok(0));
    assert_eq!(r.read_bits(8), Ok(0xAB));
}

#[test]
fn bit_reader_errors_at_end_of_input() {
    let mut r = BitReader::new(&[0x01]);
    assert!(r.read_bits(8).is_ok());
    assert!(r.read_bits(1).is_err());
    assert!(BitReader::new(&[]).read_bits(1).is_err());
}

#[test]
fn bit_reader_align_then_read_bytes() {
    let data = [0x01, 0xAA, 0xBB, 0xCC];
    let mut r = BitReader::new(&data);
    assert_eq!(r.read_bits(1), Ok(1));
    r.align_to_byte();
    assert_eq!(r.read_bytes(2), Ok(&[0xAA, 0xBB][..]));
    assert_eq!(r.read_bits(8), Ok(0xCC));
}

#[test]
fn bit_reader_read_bytes_aligns_implicitly() {
    let data = [0xF0, 0x11, 0x22];
    let mut r = BitReader::new(&data);
    r.read_bits(4).unwrap();
    assert_eq!(r.read_bytes(2), Ok(&[0x11, 0x22][..]));
}

#[test]
fn bit_reader_read_bytes_past_end_is_error() {
    let mut r = BitReader::new(&[1, 2, 3]);
    assert!(r.read_bytes(4).is_err());
    assert_eq!(r.read_bytes(3), Ok(&[1, 2, 3][..]));
    assert_eq!(r.read_bytes(0), Ok(&[][..]));
}

// ------------------------------------------------------------------ inflate

#[test]
fn inflate_empty_fixed_block() {
    // BFINAL=1, BTYPE=01, then the 7-bit end-of-block code 0000000.
    assert_eq!(inflate(&[0x03, 0x00]), Ok(Vec::new()));
}

#[test]
fn inflate_known_fixed_block() {
    // Raw DEFLATE of "a" as emitted by zlib.
    assert_eq!(inflate(&[0x4B, 0x04, 0x00]), Ok(b"a".to_vec()));
}

#[test]
fn inflate_stored_blocks() {
    let data = noise(70_000, 1); // > 65535, so the encoder must split into several stored blocks
    let stream = deflate(&data, 0);
    assert_eq!(btype(&stream), 0, "level 0 should produce stored blocks");
    assert_eq!(inflate(&stream).unwrap(), data);
}

#[test]
fn inflate_handcrafted_stored_block() {
    // BFINAL=1 BTYPE=00, pad to byte, LEN=3, NLEN=!3, then the raw bytes.
    let stream = [0x01, 0x03, 0x00, 0xFC, 0xFF, b'x', b'y', b'z'];
    assert_eq!(inflate(&stream), Ok(b"xyz".to_vec()));
}

#[test]
fn inflate_dynamic_huffman_blocks() {
    let data = prose(50_000);
    let stream = deflate(&data, 9);
    assert_eq!(btype(&stream), 2, "expected the encoder to choose dynamic Huffman");
    assert_eq!(inflate(&stream).unwrap(), data);
}

#[test]
fn inflate_round_trips_every_level_and_shape() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"x".to_vec(),
        vec![0u8; 100_000],                // long runs: max-length (258) matches
        (0..=255u8).collect(),             // every literal once
        noise(30_000, 7),                  // incompressible
        prose(20_000),                     // matches at many distances
        [noise(40_000, 3), noise(40_000, 3)].concat(), // match distance near 32 KiB window
    ];
    for (i, data) in inputs.iter().enumerate() {
        for level in 0..=9 {
            let stream = deflate(data, level);
            let out = inflate(&stream).unwrap_or_else(|e| panic!("input {i}, level {level}: {e}"));
            assert_eq!(&out, data, "input {i}, level {level}");
        }
    }
}

#[test]
fn inflate_multiple_blocks_from_flushes() {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    let mut expected = Vec::new();
    for chunk in 0..5u32 {
        let part = prose(3_000 + chunk as usize * 500);
        enc.write_all(&part).unwrap();
        enc.flush().unwrap(); // sync flush: ends a block, adds an empty stored block
        expected.extend_from_slice(&part);
    }
    let stream = enc.finish().unwrap();
    assert_eq!(inflate(&stream).unwrap(), expected);
}

#[test]
fn inflate_with_capacity_ignores_hint_for_correctness() {
    let data = prose(10_000);
    let stream = deflate(&data, 6);
    for cap in [0, 1, 10_000, 1 << 20] {
        assert_eq!(inflate_with_capacity(&stream, cap).unwrap(), data);
    }
}

#[test]
fn inflate_rejects_reserved_block_type() {
    // BFINAL=1, BTYPE=11.
    assert!(inflate(&[0x07, 0x00]).is_err());
}

#[test]
fn inflate_rejects_stored_len_nlen_mismatch() {
    assert!(inflate(&[0x01, 0x05, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn inflate_rejects_truncated_streams() {
    assert!(inflate(&[]).is_err());
    let stream = deflate(&prose(5_000), 6);
    for cut in [1, stream.len() / 2, stream.len() - 1] {
        assert!(inflate(&stream[..cut]).is_err(), "truncated at {cut}");
    }
    // Stored block that promises more bytes than present.
    assert!(inflate(&[0x01, 0x05, 0x00, 0xFA, 0xFF, b'a']).is_err());
}

#[test]
fn inflate_rejects_back_reference_before_start() {
    // Fixed block: length symbol 257 (code 0000001) then distance code 0,
    // i.e. "copy 3 bytes from 1 back" with nothing yet decoded.
    let err = inflate(&[0x03, 0x02, 0x00]).unwrap_err();
    assert!(err.contains("distance"), "{err}");
}

#[test]
fn inflate_rejects_distance_codes_30_and_31() {
    // Fixed block: length symbol 257 then distance code 30 (11110), which
    // RFC 1951 reserves.
    assert_eq!(inflate(&[0x03, 0x3E, 0x00]), Err("Distance code out of range"));
}

#[test]
fn inflate_never_panics_on_corrupted_input() {
    let stream = deflate(&prose(4_000), 9);
    for i in 0..stream.len() {
        for flip in [0x01u8, 0x10, 0x80, 0xFF] {
            let mut bad = stream.clone();
            bad[i] ^= flip;
            let _ = inflate(&bad); // Ok or Err are both fine; panicking is not
        }
    }
}

// -------------------------------------------------------------------- crc32

#[test]
fn crc32_known_vectors() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
}

// --------------------------------------------------------------------- gzip

#[test]
fn gunzip_round_trip() {
    for data in [Vec::new(), b"hello".to_vec(), prose(80_000), noise(20_000, 9)] {
        assert_eq!(decompress(&gzip(&data)).unwrap(), data);
        assert_eq!(gunzip(&gzip(&data)).unwrap(), data, "re-export should match");
    }
}

#[test]
fn gunzip_skips_optional_header_fields() {
    let data = prose(4_000);
    let mut enc = GzBuilder::new()
        .filename("hello.txt")
        .comment("built by the host test suite")
        .extra(vec![b'H', b'Y', 3, 0, 1, 2, 3])
        .write(Vec::new(), Compression::best());
    enc.write_all(&data).unwrap();
    let gz = enc.finish().unwrap();
    assert_eq!(gz[3] & 0x1C, 0x1C, "FEXTRA, FNAME and FCOMMENT should all be set");
    assert_eq!(decompress(&gz).unwrap(), data);
}

#[test]
fn gunzip_skips_header_crc() {
    let data = b"header crc present".to_vec();
    let plain = gzip(&data);
    let mut gz = plain[..10].to_vec();
    gz[3] |= 0x02; // FHCRC
    gz.extend_from_slice(&[0xAB, 0xCD]); // CRC16 value (not verified by the kernel)
    gz.extend_from_slice(&plain[10..]);
    assert_eq!(decompress(&gz).unwrap(), data);
}

#[test]
fn gunzip_rejects_bad_framing() {
    let good = gzip(b"payload");
    assert!(decompress(&good[..17]).is_err(), "shorter than the 18-byte minimum");

    let mut bad_magic = good.clone();
    bad_magic[1] = 0x8C;
    assert!(decompress(&bad_magic).is_err());

    let mut bad_method = good.clone();
    bad_method[2] = 7;
    assert!(decompress(&bad_method).is_err());
}

#[test]
fn gunzip_verifies_footer() {
    let good = gzip(b"checksummed payload");
    let n = good.len();

    let mut bad_crc = good.clone();
    bad_crc[n - 8] ^= 1;
    assert_eq!(decompress(&bad_crc), Err("Gzip CRC32 checksum verification failed"));

    let mut bad_size = good.clone();
    bad_size[n - 4] ^= 1;
    assert_eq!(decompress(&bad_size), Err("Gzip ISIZE mismatch in footer"));
}

#[test]
fn gunzip_rejects_header_fields_running_past_end() {
    // FNAME flag set but the name is never terminated.
    let mut gz = vec![0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 3];
    gz.extend_from_slice(b"unterminated-file-name");
    assert!(decompress(&gz).is_err());

    // FEXTRA length larger than the remaining data.
    let mut gz = vec![0x1F, 0x8B, 8, 0x04, 0, 0, 0, 0, 0, 3, 0xFF, 0xFF];
    gz.extend_from_slice(&[0u8; 16]);
    assert!(decompress(&gz).is_err());
}

// ----------------------------------------------------------------------- xz

/// `printf 'hello hydra\n' | xz -c`
const HELLO_XZ: &[u8] = &[
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01,
    0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3, 0x01, 0x00, 0x0b, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x20, 0x68, 0x79, 0x64, 0x72, 0x61, 0x0a, 0x00, 0x6b, 0x52, 0xc7, 0x75, 0x7a, 0x40, 0x01, 0x5d,
    0x00, 0x01, 0x24, 0x0c, 0xa6, 0x18, 0xd8, 0xd8, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x59, 0x5a,
];

#[test]
fn unxz_decodes_reference_stream() {
    assert_eq!(unxz(HELLO_XZ).unwrap(), b"hello hydra\n");
}

#[test]
fn unxz_rejects_garbage_and_corruption() {
    assert!(unxz(b"not an xz stream").is_err());
    assert!(unxz(&[]).is_err());
    let mut bad = HELLO_XZ.to_vec();
    bad[30] ^= 0xFF; // inside the compressed data; the block CRC must catch it
    assert!(unxz(&bad).is_err());
}
