//! Gzip containers and DEFLATE streams (`src/compress`): header fields, footer checks,
//! truncation, against streams made by flate2; and the xz entry point.

use std::io::Write;

use hydra_hosttests_t33::compress::{deflate, gzip, unxz};

fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A gzip member with every optional header field: FEXTRA, FNAME, FCOMMENT, FHCRC.
fn gz_all_fields(data: &[u8]) -> Vec<u8> {
    let plain = gz(data);
    let body = &plain[10..];
    let mut v = vec![0x1F, 0x8B, 8, 0x04 | 0x08 | 0x10 | 0x02, 0, 0, 0, 0, 0, 3];
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(b"XY\x00\x00");
    v.extend_from_slice(b"name.txt\0");
    v.extend_from_slice(b"a comment\0");
    v.extend_from_slice(&[0xAB, 0xCD]);
    v.extend_from_slice(body);
    v
}

#[test]
fn gzip_members_with_and_without_optional_fields() {
    let data: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 251) as u8).collect();
    assert_eq!(gzip::decompress(&gz(&data)).unwrap(), data);
    assert_eq!(gzip::decompress(&gz_all_fields(&data)).unwrap(), data);
    assert_eq!(gzip::decompress(&gz(b"")).unwrap(), b"");
    assert_eq!(gzip::crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn gzip_refuses_bad_members() {
    let good = gz(b"hello hello hello");
    assert!(gzip::decompress(&good[..10]).unwrap_err().contains("too short"));
    let mut magic = good.clone();
    magic[0] = 0;
    assert!(gzip::decompress(&magic).unwrap_err().contains("magic"));
    let mut method = good.clone();
    method[2] = 7;
    assert!(gzip::decompress(&method).unwrap_err().contains("compression method"));
    // FEXTRA running past the end
    let mut extra = vec![0x1F, 0x8B, 8, 0x04, 0, 0, 0, 0, 0, 3];
    extra.extend_from_slice(&[0u8; 8]);
    extra.truncate(18);
    let mut ex2 = extra.clone();
    ex2[10] = 0xFF;
    ex2[11] = 0xFF;
    assert!(gzip::decompress(&ex2).unwrap_err().contains("Truncated"));
    // A name that never ends
    let mut name = vec![0x1F, 0x8B, 8, 0x08, 0, 0, 0, 0, 0, 3];
    name.extend_from_slice(&[b'a'; 10]);
    assert!(gzip::decompress(&name).unwrap_err().contains("Truncated"));
    // Footer: wrong CRC, wrong size
    let mut crc = good.clone();
    let n = crc.len();
    crc[n - 8] ^= 1;
    assert!(gzip::decompress(&crc).unwrap_err().contains("CRC32"));
    let mut size = good.clone();
    size[n - 4] ^= 1;
    assert!(gzip::decompress(&size).unwrap_err().contains("ISIZE"));
    // A huge declared size falls back to an estimate (then mismatches)
    let mut huge = good.clone();
    huge[n - 1] = 0xFF;
    assert!(gzip::decompress(&huge).is_err());
    // A broken stream
    let mut broken = good.clone();
    for b in broken[10..n - 8].iter_mut() {
        *b = 0xFF;
    }
    assert!(gzip::decompress(&broken).is_err());
}

#[test]
fn raw_deflate_and_xz() {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(b"abcabcabcabcabc-deflate").unwrap();
    let raw = e.finish().unwrap();
    assert_eq!(deflate::inflate(&raw).unwrap(), b"abcabcabcabcabc-deflate");
    // A stored block
    let mut s = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::none());
    s.write_all(b"stored bytes").unwrap();
    assert_eq!(deflate::inflate(&s.finish().unwrap()).unwrap(), b"stored bytes");
    assert!(deflate::inflate(&[0xFF; 4]).is_err());
    assert!(unxz(b"not xz").is_err());
}
