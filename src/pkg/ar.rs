//! # Package & Archive Subsystem: Unix AR Archive Demuxer
//!
//! Implements a zero-copy Unix `ar` archive reader for parsing Debian `.deb` package
//! containers (`!<arch>\n`).
//!
//! ## Architectural Role & Design Rationale
//! Debian binary packages (`.deb`) are standard Unix `ar` archives containing three
//! sequential members:
//! 1. `debian-binary`: Package format version string (e.g., `2.0\n`).
//! 2. `control.tar.gz` (or `.xz`): Package metadata, dependencies, and maintainer scripts.
//! 3. `data.tar.gz` (or `.xz`): Filesystem tree to be unpacked into the target root.
//!
//! [`ArArchive`] slices directly into the backing memory buffer without heap allocations,
//! yielding `ArEntry` views that can be passed straight to [`crate::compress`].
//!
//! ## Key Types & Interfaces
//! - [`ArArchive`]: Zero-copy parser validating the 8-byte `!<arch>\n` signature.
//! - `ArEntry`: Borrowed descriptor and payload slice for an individual archive member.
//! - [`ArIterator`]: Sequential iterator over 60-byte aligned member headers.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (zero-copy over in-memory byte slices; `core`-only).
//! - Concurrency: Immutable borrows (`&'a [u8]`); completely thread-safe.

use core::str;

/// Global magic identifier at byte 0 of standard Unix `ar` archives (`!<arch>\n`).
pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

/// Fixed size of an `ar` member header in bytes (`60` bytes).
pub const AR_HEADER_SIZE: usize = 60;

/// Represents a single member file borrowed from an [`ArArchive`].
///
/// # Concurrency & Thread Safety
/// Contains only immutable references with lifetime `'a` into the parent archive slice.
#[derive(Debug, Clone, Copy)]
pub struct ArEntry<'a> {
    /// Member file identifier / name (trimmed of trailing spaces and GNU `/` terminators).
    pub name: &'a str,
    /// Size of the member payload in bytes.
    pub size: usize,
    /// Zero-copy slice pointing directly to the member's raw payload bytes.
    pub data: &'a [u8],
}

/// Zero-copy parser for Unix `ar` archives and Debian `.deb` packages.
///
/// # Concurrency & Thread Safety
/// Wraps an immutable byte slice `&'a [u8]` and performs no internal mutation.
pub struct ArArchive<'a> {
    /// Raw bytes of the complete `ar` archive starting with [`AR_MAGIC`].
    data: &'a [u8],
}

impl<'a> ArArchive<'a> {
    /// Validates the 8-byte [`AR_MAGIC`] header and initializes an [`ArArchive`] reader.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw byte slice containing the Unix `ar` archive.
    ///
    /// # Returns
    ///
    /// * `Ok(ArArchive)` - Validated archive handle ready for iteration.
    ///
    /// # Errors
    ///
    /// * `Err("Data too short for AR archive")` - Slice is shorter than 8 bytes.
    /// * `Err("Invalid AR magic signature (expected '!<arch>\\n')")` - Leading bytes do not match [`AR_MAGIC`].
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < AR_MAGIC.len() {
            return Err("Data too short for AR archive");
        }
        if &data[..AR_MAGIC.len()] != AR_MAGIC {
            return Err("Invalid AR magic signature (expected '!<arch>\\n')");
        }
        Ok(Self { data })
    }

    /// Returns an [`ArIterator`] over all member files in the archive.
    ///
    /// # Returns
    ///
    /// An iterator positioned immediately after the 8-byte global magic header.
    pub fn entries(&self) -> ArIterator<'a> {
        ArIterator {
            data: self.data,
            offset: AR_MAGIC.len(),
        }
    }

    /// Searches the archive for a member whose name matches `name` exactly or starts with `name`.
    ///
    /// Prefix matching allows locating `"control.tar"` or `"data.tar"` regardless of whether
    /// the member is compressed with `.gz`, `.xz`, or `.zst`.
    ///
    /// # Arguments
    ///
    /// * `name` - Exact member name or prefix to search for (e.g., `"debian-binary"`, `"data.tar"`).
    ///
    /// # Returns
    ///
    /// * `Some(ArEntry)` - The first matching member entry.
    /// * `None` - If no matching member is found before the end of the archive.
    pub fn get_entry(&self, name: &str) -> Option<ArEntry<'a>> {
        for entry in self.entries() {
            if entry.name == name || entry.name.starts_with(name) {
                return Some(entry);
            }
        }
        None
    }
}

/// Sequential iterator over member entries in an [`ArArchive`].
///
/// # Concurrency & Thread Safety
/// Holds an immutable slice borrow and a local byte offset cursor.
pub struct ArIterator<'a> {
    /// Underlying archive byte slice.
    data: &'a [u8],
    /// Current byte offset of the next 60-byte member header.
    offset: usize,
}

impl<'a> Iterator for ArIterator<'a> {
    type Item = ArEntry<'a>;

    /// Parses the next 60-byte `ar` member header and advances the cursor past its 2-byte aligned payload.
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

/// Parses an ASCII decimal string into a `usize` with overflow checking.
///
/// # Arguments
///
/// * `s` - Trimmed ASCII decimal string from the `ar` size field.
///
/// # Returns
///
/// * `Some(usize)` - Parsed non-negative integer.
/// * `None` - If `s` is empty, contains non-digit characters, or overflows `usize`.
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
