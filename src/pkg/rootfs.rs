//! # Package & Archive Subsystem: Linux Root Filesystem Installer
//!
//! Unpacks a complete Linux root filesystem archive (`.tar` or `.tar.gz`, such as Ubuntu's
//! `ubuntu-base-*.tar.gz`) into a target directory of the OpenZFS pool while preserving
//! permissions, ownership, modification times, symbolic links, hard links, device nodes, and FIFOs.
//!
//! ## Architectural Role & Design Rationale
//! Running unmodified Linux distributions under Hydra OS's Linux compatibility layer requires
//! faithfully materializing `/bin`, `/lib`, `/etc`, and `/dev` metadata—including setuid bits,
//! long symbolic links, deferred hard links, and character/block device major/minor numbers.
//! This installer supports POSIX `ustar` prefixes, GNU long name/link extensions (`L`/`K`),
//! GNU base-256 numeric fields, and POSIX `pax` extended headers (`x`).
//!
//! ## Key Types & Interfaces
//! - [`InstallSummary`]: Statistics structure tallying extracted files, directories, links, devices, and bytes.
//! - [`install()`]: Top-level installer entry point that decompresses (if `.gz`), extracts, and commits to ZFS.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Commits extracted objects to the OpenZFS pool via [`crate::fs::zfs::server::with_server`].
//! - Concurrency: Acquires the global ZFS server lock per entry and flushes the transaction group at completion.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::client::{resolve_in, resolve_parent_in};
use crate::fs::zfs::server::{with_server, ZfsServer};
use crate::fs::zfs::types::{S_IFBLK, S_IFCHR, S_IFIFO};
use crate::fs::zfs::zpl::{self, SetAttr};

/// Standard 512-byte TAR block size.
const BLOCK: usize = 512;

/// Summary counts reported after unpacking a root filesystem archive via [`install()`].
///
/// # Concurrency & Thread Safety
/// Plain value struct (`Copy`, `Clone`) returned to the caller upon completion.
#[derive(Debug, Default, Clone, Copy)]
pub struct InstallSummary {
    /// Total number of regular files created and written.
    pub files: usize,
    /// Total number of directories created or updated.
    pub dirs: usize,
    /// Total number of symbolic links created.
    pub symlinks: usize,
    /// Total number of hard links linked.
    pub hardlinks: usize,
    /// Total number of character devices, block devices, and FIFOs created via `mknod`.
    pub devices: usize,
    /// Total uncompressed payload bytes written across all regular files.
    pub bytes: u64,
    /// Count of entries skipped due to unsupported type flags or directory conflicts.
    pub skipped: usize,
}

/// Decodes an octal ASCII or GNU base-256 binary numeric header field into a `u64`.
///
/// If the high bit (`0x80`) of the first byte is set, interprets the remaining bytes as
/// big-endian base-256 (GNU tar extension for large files/timestamps).
fn octal(field: &[u8]) -> u64 {
    // GNU base-256 encoding for large values
    if field.first().map_or(false, |&b| b & 0x80 != 0) {
        let mut v: u64 = (field[0] & 0x7F) as u64;
        for &b in &field[1..] {
            v = (v << 8) | b as u64;
        }
        return v;
    }
    let mut v = 0u64;
    for &b in field {
        match b {
            b'0'..=b'7' => v = v * 8 + (b - b'0') as u64,
            b' ' | 0 => {
                if v != 0 {
                    break;
                }
            }
            _ => break,
        }
    }
    v
}

/// Returns the sub-slice of `field` up to the first NUL (`0`) byte.
fn cstr(field: &[u8]) -> &[u8] {
    let n = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..n]
}

/// Parses POSIX `pax` extended header records (`"<len> key=value\n"`), returning `(path, linkpath)` overrides.
fn parse_pax(data: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let (mut path, mut link) = (None, None);
    let mut rest = data;
    while !rest.is_empty() {
        let sp = match rest.iter().position(|&b| b == b' ') {
            Some(i) => i,
            None => break,
        };
        let len: usize = core::str::from_utf8(&rest[..sp]).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        if len == 0 || len > rest.len() {
            break;
        }
        let record = &rest[sp + 1..len - 1];
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            match &record[..eq] {
                b"path" => path = Some(record[eq + 1..].to_vec()),
                b"linkpath" => link = Some(record[eq + 1..].to_vec()),
                _ => {}
            }
        }
        rest = &rest[len..];
    }
    (path, link)
}

/// Creates or replaces a single archive entry under the root directory object `root`.
#[allow(clippy::too_many_arguments)]
fn install_entry(
    s: &mut ZfsServer,
    root: u64,
    name: &[u8],
    kind: u8,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    rdev: u64,
    link: &[u8],
    data: &[u8],
    sum: &mut InstallSummary,
) -> Result<(), i64> {
    let trimmed: Vec<u8> = {
        let mut n = name;
        while n.starts_with(b"./") {
            n = &n[2..];
        }
        let mut v = n.to_vec();
        while v.last() == Some(&b'/') {
            v.pop();
        }
        v
    };
    if trimmed.is_empty() || trimmed == b"." {
        return Ok(());
    }
    let (parent, leaf) = resolve_parent_in(s, root, root, &trimmed)?;
    let perm = mode & 0o7777;

    let existing = s.lookup(parent, &leaf).ok();
    let ino = match kind {
        b'5' => {
            sum.dirs += 1;
            match existing {
                Some(ino) if s.getattr(ino)?.is_dir() => ino,
                Some(_) => {
                    s.unlink(parent, &leaf)?;
                    s.mkdir(parent, &leaf, perm, uid, gid)?
                }
                None => s.mkdir(parent, &leaf, perm, uid, gid)?,
            }
        }
        _ => {
            if let Some(old) = existing {
                if s.getattr(old)?.is_dir() {
                    sum.skipped += 1;
                    return Ok(()); // never replace a directory with a non-directory
                }
                s.unlink(parent, &leaf)?;
            }
            match kind {
                b'0' | 0 | b'7' => {
                    sum.files += 1;
                    sum.bytes += data.len() as u64;
                    let ino = s.create(parent, &leaf, perm, uid, gid)?;
                    if !data.is_empty() {
                        s.write(ino, 0, data)?;
                    }
                    ino
                }
                b'1' => {
                    sum.hardlinks += 1;
                    let target = resolve_in(s, root, root, link, false)?;
                    s.link(target, parent, &leaf)?;
                    return Ok(());
                }
                b'2' => {
                    sum.symlinks += 1;
                    s.symlink(parent, &leaf, link, uid, gid)?
                }
                b'3' | b'4' | b'6' => {
                    sum.devices += 1;
                    let fmt = match kind {
                        b'3' => S_IFCHR,
                        b'4' => S_IFBLK,
                        _ => S_IFIFO,
                    };
                    s.mknod(parent, &leaf, fmt | perm, rdev, uid, gid)?
                }
                _ => {
                    sum.skipped += 1;
                    return Ok(());
                }
            }
        }
    };
    let set = SetAttr {
        mode: if kind == b'2' { None } else { Some(perm) },
        uid: Some(uid),
        gid: Some(gid),
        mtime: Some((mtime, 0)),
        atime: Some((mtime, 0)),
        ..SetAttr::default()
    };
    s.setattr(ino, set)?;
    Ok(())
}

/// Unpacks a `.tar` or `.tar.gz` root filesystem archive into `dest`, creating `dest` if needed.
///
/// Automatically detects Gzip magic (`0x1F, 0x8B`), decompresses the archive in memory,
/// processes all TAR records (including deferred forward hard links and directory `mtime`
/// restoration), and performs a final [`crate::fs::ZfsClient::sync()`].
///
/// # Arguments
///
/// * `archive` - Raw bytes of the `.tar` or `.tar.gz` archive.
/// * `dest` - Absolute ZFS destination path (e.g., `"/"` or `"/ubuntu"`).
///
/// # Returns
///
/// * `Ok(InstallSummary)` - Breakdown of extracted files, directories, links, devices, and bytes.
///
/// # Errors
///
/// * `Err(String)` - If Gzip decompression fails, the TAR archive is truncated, `dest` cannot be
///   created, or the final ZFS transaction commit fails.
pub fn install(archive: &[u8], dest: &str) -> Result<InstallSummary, String> {
    let tar: Vec<u8>;
    let data: &[u8] = if archive.starts_with(&[0x1F, 0x8B]) {
        crate::println!("[rootfs] Decompressing {} KiB gzip archive...", archive.len() / 1024);
        tar = crate::compress::gzip::decompress(archive).map_err(String::from)?;
        &tar
    } else {
        archive
    };
    crate::println!("[rootfs] Unpacking {} KiB tar archive into {}...", data.len() / 1024, dest);

    crate::fs::ZfsClient::create_dir_all(dest).map_err(String::from)?;
    let root = crate::fs::ZfsClient::resolve(0, dest.as_bytes(), true).map_err(|e| alloc::format!("errno {}", e))?;

    let mut sum = InstallSummary::default();
    let mut off = 0;
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;
    let mut entries = 0usize;
    // Hard links whose target appears later in the archive are retried at the end
    let mut deferred: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    // Directory times are restored last: adding entries updates them (as GNU tar does)
    let mut dir_times: Vec<(Vec<u8>, i64)> = Vec::new();

    while off + BLOCK <= data.len() {
        let h = &data[off..off + BLOCK];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let size = octal(&h[124..136]) as usize;
        let kind = h[156];
        let body_start = off + BLOCK;
        let body_end = body_start + size;
        if body_end > data.len() {
            return Err(String::from("truncated tar archive"));
        }
        let body = &data[body_start..body_end];
        off = body_start + (size + BLOCK - 1) / BLOCK * BLOCK;

        match kind {
            b'L' => {
                long_name = Some(cstr(body).to_vec());
                continue;
            }
            b'K' => {
                long_link = Some(cstr(body).to_vec());
                continue;
            }
            b'x' => {
                let (p, l) = parse_pax(body);
                if p.is_some() {
                    long_name = p;
                }
                if l.is_some() {
                    long_link = l;
                }
                continue;
            }
            b'g' => continue,
            _ => {}
        }

        let name = long_name.take().unwrap_or_else(|| {
            let prefix = cstr(&h[345..500]);
            let base = cstr(&h[0..100]);
            if &h[257..262] == b"ustar" && !prefix.is_empty() {
                let mut v = prefix.to_vec();
                v.push(b'/');
                v.extend_from_slice(base);
                v
            } else {
                base.to_vec()
            }
        });
        let link = long_link.take().unwrap_or_else(|| cstr(&h[157..257]).to_vec());
        let mode = octal(&h[100..108]) as u32;
        let uid = octal(&h[108..116]) as u32;
        let gid = octal(&h[116..124]) as u32;
        let mtime = octal(&h[136..148]) as i64;
        let rdev = (octal(&h[329..337]) << 8) | octal(&h[337..345]);

        if kind == b'5' {
            dir_times.push((name.clone(), mtime));
        }
        let res = with_server(|s| install_entry(s, root, &name, kind, mode, uid, gid, mtime, rdev, &link, body, &mut sum));
        match res {
            Ok(()) => {}
            Err(zpl::ENOENT) if kind == b'1' => deferred.push((name, link)),
            Err(e) => {
                crate::println!("[rootfs] warning: {} (errno {})", String::from_utf8_lossy(&name), e);
                sum.skipped += 1;
            }
        }
        entries += 1;
        if entries % 500 == 0 {
            crate::println!("[rootfs]   {} entries, {} MiB written", entries, sum.bytes / (1024 * 1024));
        }
    }

    for (name, link) in deferred {
        let r = with_server(|s| install_entry(s, root, &name, b'1', 0, 0, 0, 0, 0, &link, &[], &mut sum));
        if r.is_err() {
            sum.skipped += 1;
        }
    }

    for (name, mtime) in dir_times {
        let _ = with_server(|s| {
            let ino = resolve_in(s, root, root, &name, false)?;
            s.setattr(ino, SetAttr { mtime: Some((mtime, 0)), atime: Some((mtime, 0)), ..SetAttr::default() })?;
            Ok(())
        });
    }

    crate::println!("[rootfs] Committing to disk...");
    crate::fs::ZfsClient::sync().map_err(String::from)?;
    Ok(sum)
}
