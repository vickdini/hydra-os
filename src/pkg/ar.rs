//! # Unix AR Archive Demuxer
//!
//! Implements a zero-copy Unix `ar` archive reader for parsing Debian `.deb` package containers.
//! Debian packages conform to the common `ar` archive format (`!<arch>\n`) containing:
//! 1. `debian-binary`: Package format version string (e.g. `2.0\n`).
//! 2. `control.tar.gz` (or `.xz`): Package control metadata and scripts.
//! 3. `data.tar.gz` (or `.xz`): Filesystem payload to be installed.

use core::str;

/// Global magic identifier for standard Unix AR archives: `!<arch>\n`
pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

/// Fixed size of an AR member header in bytes.
pub const AR_HEADER_SIZE: usize = 60;

/// Represents a single member file extracted from an AR archive.
#[derive(Debug, Clone, Copy)]
pub struct ArEntry<'a> {
    /// File identifier / name (trimmed of spaces and trailing `/`).
    pub name: &'a str,
    /// Size of the payload in bytes.
    pub size: usize,
    /// Slice pointing directly to the member's raw payload data.
    pub data: &'a [u8],
}

/// Zero-copy parser for Unix AR archives.
pub struct ArArchive<'a> {
    data: &'a [u8],
}

impl<'a> ArArchive<'a> {
    /// Validates the AR magic header and initializes an `ArArchive` reader.
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < AR_MAGIC.len() {
            return Err("Data too short for AR archive");
        }
        if &data[..AR_MAGIC.len()] != AR_MAGIC {
            return Err("Invalid AR magic signature (expected '!<arch>\\n')");
        }
        Ok(Self { data })
    }

    /// Returns an iterator over all member files in the AR archive.
    pub fn entries(&self) -> ArIterator<'a> {
        ArIterator {
            data: self.data,
            offset: AR_MAGIC.len(),
        }
    }

    /// Finds a member entry by matching its name prefix or exact name.
    /// E.g. finding `"debian-binary"`, `"control.tar"`, or `"data.tar"`.
    pub fn get_entry(&self, name: &str) -> Option<ArEntry<'a>> {
        for entry in self.entries() {
            if entry.name == name || entry.name.starts_with(name) {
                return Some(entry);
            }
        }
        None
    }
}

/// Iterator over entries in an AR archive.
pub struct ArIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for ArIterator<'a> {
    type Item = ArEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + AR_HEADER_SIZE > self.data.len() {
            return None;
        }

        let header = &self.data[self.offset..self.offset + AR_HEADER_SIZE];

        // Member trailer check: "`\n" at bytes 58..60
        if header[58] != b'`' || header[59] != b'\n' {
            return None;
        }

        // File name: 16 bytes (offset 0..16)
        let raw_name = str::from_utf8(&header[0..16]).unwrap_or("");
        let name = raw_name.trim().trim_end_matches('/');

        // File size: 10 bytes (offset 48..58)
        let raw_size = str::from_utf8(&header[48..58]).unwrap_or("");
        let size = parse_decimal_ascii(raw_size.trim())?;

        let data_start = self.offset + AR_HEADER_SIZE;
        let data_end = data_start.checked_add(size)?;

        if data_end > self.data.len() {
            return None;
        }

        let entry_data = &self.data[data_start..data_end];

        // 2-byte alignment padding: if size is odd, an extra '\n' padding byte is present
        let pad = if size % 2 != 0 { 1 } else { 0 };
        self.offset = data_end + pad;

        Some(ArEntry {
            name,
            size,
            data: entry_data,
        })
    }
}

/// Parses an ASCII decimal string into a usize without standard library helpers.
fn parse_decimal_ascii(s: &str) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut val: usize = 0;
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(val)
}
