//! # UStar / POSIX TAR Archive Extractor
//!
//! Implements a streaming reader and unpacker for UStar/POSIX `.tar` archives.
//! Extracts files and directories directly into Hydra OS's persistent OpenZFS filesystem.

use core::str;
use alloc::string::String;
use crate::fs::client::ZfsClient;

/// Size of each block in a TAR archive (512 bytes).
pub const TAR_BLOCK_SIZE: usize = 512;

/// Type flags recognized in TAR header records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarType {
    RegularFile,
    HardLink,
    SymLink,
    Directory,
    GnuLongName,
    Other(u8),
}

/// Statistics reported after unpacking a TAR archive into ZFS.
#[derive(Debug, Clone, Copy, Default)]
pub struct TarExtractSummary {
    pub files_extracted: usize,
    pub dirs_created: usize,
    pub symlinks_recorded: usize,
    pub total_bytes: usize,
}

/// Streaming parser for TAR archives.
pub struct TarArchive<'a> {
    data: &'a [u8],
}

impl<'a> TarArchive<'a> {
    /// Initializes a new TAR archive reader over a memory slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Unpacks all directories and regular files from this TAR archive directly
    /// into Hydra OS's persistent OpenZFS storage.
    pub fn extract_to_zfs(&self) -> Result<TarExtractSummary, &'static str> {
        let mut summary = TarExtractSummary::default();
        let mut offset = 0;
        let mut gnu_long_name_buf: Option<String> = None;

        while offset + TAR_BLOCK_SIZE <= self.data.len() {
            let header = &self.data[offset..offset + TAR_BLOCK_SIZE];

            // Check for end-of-archive marker (block filled with all zeros)
            if header.iter().all(|&b| b == 0) {
                break;
            }

            // Extract file name (offset 0..100) or check UStar prefix (345..500)
            let mut raw_name = extract_null_terminated_str(&header[0..100]);
            let mut full_path_string = String::new();

            // If GNU Long Name header was received in previous block, override path
            if let Some(long_name) = gnu_long_name_buf.take() {
                full_path_string = long_name;
                raw_name = full_path_string.as_str();
            } else if &header[257..262] == b"ustar" {
                // Check POSIX ustar prefix
                let prefix = extract_null_terminated_str(&header[345..500]);
                if !prefix.is_empty() {
                    full_path_string.push_str(prefix);
                    full_path_string.push('/');
                    full_path_string.push_str(raw_name);
                    raw_name = full_path_string.as_str();
                }
            }

            // Size: offset 124..136 (octal string)
            let size = parse_octal(&header[124..136]);
            let type_flag_byte = header[156];
            let type_flag = match type_flag_byte {
                b'0' | 0 => TarType::RegularFile,
                b'1' => TarType::HardLink,
                b'2' => TarType::SymLink,
                b'5' => TarType::Directory,
                b'L' => TarType::GnuLongName,
                other => TarType::Other(other),
            };

            let data_offset = offset + TAR_BLOCK_SIZE;
            let aligned_data_len = ((size + TAR_BLOCK_SIZE - 1) / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
            let next_offset = data_offset + aligned_data_len;

            if next_offset > self.data.len() && size > 0 {
                return Err("Truncated TAR archive data");
            }

            let entry_data = if size > 0 && data_offset + size <= self.data.len() {
                &self.data[data_offset..data_offset + size]
            } else {
                &[]
            };

            // Handle GNU long filename header
            if type_flag == TarType::GnuLongName {
                let name_str = extract_null_terminated_str(entry_data);
                gnu_long_name_buf = Some(String::from(name_str));
                offset = next_offset;
                continue;
            }

            // Normalize path: strip leading "./", ".", or "/"
            let clean_path = raw_name
                .trim_start_matches('.')
                .trim_start_matches('/')
                .trim_end_matches('/');

            if !clean_path.is_empty() {
                // Form absolute path for ZFS: e.g. "/usr/bin/busybox"
                let mut zfs_path = String::with_capacity(clean_path.len() + 1);
                zfs_path.push('/');
                zfs_path.push_str(clean_path);

                match type_flag {
                    TarType::Directory => {
                        let _ = ZfsClient::create_dir_all(&zfs_path);
                        summary.dirs_created += 1;
                    }
                    TarType::RegularFile => {
                        match ZfsClient::write_file_by_path_batch(&zfs_path, entry_data) {
                            Ok(_) => {
                                summary.files_extracted += 1;
                                summary.total_bytes += entry_data.len();
                                if summary.files_extracted <= 3 || (summary.files_extracted % 15) == 0 {
                                    crate::println!("  -> Extracted: {} ({} bytes)", zfs_path, entry_data.len());
                                }
                            }
                            Err(_) => {
                                // Ignore non-critical write failures
                            }
                        }
                    }
                    TarType::SymLink => {
                        let link_target = extract_null_terminated_str(&header[157..257]);
                        // Record symlink target as a text reference in ZFS
                        let _ = ZfsClient::write_file_by_path_batch(&zfs_path, link_target.as_bytes());
                        summary.symlinks_recorded += 1;
                    }
                    _ => {}
                }
            }

            offset = next_offset;
        }

        // Flush all written files and metadata to persistent storage in a single transaction
        let _ = ZfsClient::sync();

        Ok(summary)
    }
}

/// Helper function to parse an octal byte slice into a usize.
fn parse_octal(bytes: &[u8]) -> usize {
    let mut val: usize = 0;
    for &b in bytes {
        if (b'0'..=b'7').contains(&b) {
            val = val * 8 + (b - b'0') as usize;
        } else if b == 0 || b == b' ' {
            if val > 0 {
                break;
            }
        }
    }
    val
}

/// Extracts a null-terminated UTF-8 string from a byte slice.
fn extract_null_terminated_str(bytes: &[u8]) -> &str {
    let mut len = 0;
    while len < bytes.len() && bytes[len] != 0 {
        len += 1;
    }
    str::from_utf8(&bytes[..len]).unwrap_or("").trim()
}
