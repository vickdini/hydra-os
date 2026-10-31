//! # Filesystem Subsystem: ZFS Client Interface & Path Resolution Engine
//!
//! Provides path-based and inode-level access to the OpenZFS file server for kernel subsystems,
//! shell commands, and the Linux system call compatibility layer.
//!
//! ## Architectural Role & Design Rationale
//! While [`super::zfs::zpl`] implements single-directory-component POSIX operations on raw inode
//! numbers, higher layers work with hierarchical paths (`/bin/hello.elf`, `../etc/passwd`),
//! `chroot` jails, relative directory descriptors (`openat`), and symbolic links. This module
//! implements the iterative path walker ([`resolve_in`], following up to [`SYMLOOP_MAX`] symlinks)
//! and wraps the global [`ZFS_SERVER`] lock in ergonomic helper methods on [`ZfsClient`].
//!
//! ## Key Types & Interfaces
//! - [`ZfsClient`]: Stateless facade offering path-based and inode-based ZFS operations.
//! - [`FileStat`]: Detailed file/directory metadata and block checksum summary for shell inspection.
//! - [`resolve_at()`] & [`resolve_in()`]: Iterative path walkers with symlink and `chroot` support.
//! - [`normalize_path()`]: Lexical path canonicalizer for shell working directory tracking.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Accesses the ZFS storage pool via [`with_server`] and UEFI boot media in [`ZfsClient::sync_boot_binaries`].
//! - Concurrency: Acquires the global [`ZFS_SERVER`] spinlock for the duration of each operation.

use alloc::vec::Vec;

use super::zfs::server::{with_server, ZfsServer, ZFS_SERVER};
use super::zfs::types::DnodeType;
use super::zfs::zap::ZapEntry;
use super::zfs::zpl::{self, Attr, ReaddirEntry, SetAttr};
use crate::capability::Capability;
use uefi::proto::media::file::File;

/// Maximum number of symbolic links followed while resolving a single path (`40`, matching Linux `MAXSYMLINKS`).
pub const SYMLOOP_MAX: usize = 40;
/// Linux negative errno returned when symbolic link resolution exceeds [`SYMLOOP_MAX`] (`-ELOOP = -40`).
const ELOOP: i64 = -40;

/// Detailed file or directory metadata and Fletcher-4 checksum returned by [`ZfsClient::file_stat()`].
///
/// # Concurrency & Thread Safety
/// Plain data snapshot (`Copy`, `Clone`) copied out while holding the ZFS server lock.
#[derive(Debug, Clone, Copy)]
pub struct FileStat {
    /// ZFS object / inode number.
    pub obj_id: u64,
    /// Object classification ([`DnodeType::PlainFile`], [`DnodeType::Directory`], etc.).
    pub obj_type: DnodeType,
    /// Logical file size in bytes.
    pub size: u64,
    /// Transaction group (TXG) in which this object was originally created.
    pub birth_txg: u64,
    /// 256-bit Fletcher-4 checksum words (`[a, b, c, d]`) of the object's first top-level block pointer.
    pub checksum: [u64; 4],
    /// Whether the object has at least one physical block allocated on disk (`!bp[0].is_hole()`).
    pub is_allocated: bool,
    /// Null-padded basename of the queried path (up to 31 ASCII/UTF-8 bytes).
    pub name: [u8; 32],
    /// Full POSIX `st_mode` (file type + permission bits).
    pub mode: u32,
    /// Owner user ID (`uid`).
    pub uid: u32,
    /// Owner group ID (`gid`).
    pub gid: u32,
    /// Hard link count (`st_nlink`).
    pub nlink: u32,
    /// Last modification timestamp in seconds since the Unix epoch.
    pub mtime: i64,
}

impl FileStat {
    /// Extracts the NUL-terminated basename stored in [`FileStat::name`] as a UTF-8 string slice.
    ///
    /// # Returns
    ///
    /// The file's basename, or `"<unknown>"` if the bytes are not valid UTF-8.
    pub fn name_str(&self) -> &str {
        let mut len = 0;
        while len < self.name.len() && self.name[len] != 0 {
            len += 1;
        }
        core::str::from_utf8(&self.name[..len]).unwrap_or("<unknown>")
    }
}

/// Lexically normalizes `path` against current working directory `cwd` into the caller-supplied buffer `out`.
///
/// Resolves `.` and `..` components, converts backslashes to forward slashes, and writes a clean
/// absolute path (such as `"/bin/readme.txt"` or `"/"`) without touching the filesystem.
///
/// # Arguments
///
/// * `cwd` - Current working directory string (e.g., `"/home/hydra"`).
/// * `path` - Relative or absolute input path string.
/// * `out` - Scratch byte buffer of 128 bytes to hold the normalized output.
///
/// # Returns
///
/// A UTF-8 string slice borrowing the normalized prefix of `out`.
pub fn normalize_path<'a>(cwd: &str, path: &str, out: &'a mut [u8; 128]) -> &'a str {
    let mut parts: [&str; 16] = [""; 16];
    let mut count = 0;

    let is_absolute = path.starts_with('/') || path.starts_with('\\');

    if !is_absolute {
        for token in cwd.split(['/', '\\']) {
            if !token.is_empty() && token != "." {
                if count < parts.len() {
                    parts[count] = token;
                    count += 1;
                }
            }
        }
    }

    for token in path.split(['/', '\\']) {
        if token.is_empty() || token == "." {
            continue;
        } else if token == ".." {
            if count > 0 {
                count -= 1;
            }
        } else if count < parts.len() {
            parts[count] = token;
            count += 1;
        }
    }

    if count == 0 {
        out[0] = b'/';
        return core::str::from_utf8(&out[..1]).unwrap_or("/");
    }

    let mut pos = 0;
    for part in parts.iter().take(count) {
        if pos < out.len() {
            out[pos] = b'/';
            pos += 1;
        }
        let b = part.as_bytes();
        let len = b.len().min(out.len().saturating_sub(pos));
        out[pos..pos + len].copy_from_slice(&b[..len]);
        pos += len;
    }

    core::str::from_utf8(&out[..pos]).unwrap_or("/")
}

/// Splits a raw byte path on `'/'`, discarding empty and `"."` segments.
fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&c| c == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
}

/// Resolves `path` relative to directory inode `base` (or the pool root when `path` starts with `'/'`).
///
/// Symbolic links are expanded in every intermediate component, and in the final component
/// when `follow_last` is `true` or `path` ends with a trailing `'/'`.
///
/// # Arguments
///
/// * `s` - Active mutable reference to the [`ZfsServer`].
/// * `base` - Starting directory object ID for relative paths.
/// * `path` - Raw byte slice of the path to resolve.
/// * `follow_last` - Whether to dereference a symlink if the final component is a symlink.
///
/// # Returns
///
/// * `Ok(u64)` - Resolved target inode number.
///
/// # Errors
///
/// * `-ENOENT`, `-ENOTDIR`, `-ELOOP`, or `-EIO` on resolution failure.
pub fn resolve_at(s: &mut ZfsServer, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    let root = s.root_obj();
    resolve_in(s, root, base, path, follow_last)
}

/// Resolves `path` within a specific `root` directory (`chroot` jail) relative to `base`.
///
/// Absolute paths and absolute symlink targets reset the walk to `root`, and `".."` at `root`
/// remains at `root` so resolution can never escape above the jail root.
///
/// # Arguments
///
/// * `s` - Active mutable reference to the [`ZfsServer`].
/// * `root` - Jail root directory object ID.
/// * `base` - Starting directory object ID for relative paths.
/// * `path` - Raw byte slice of the path to resolve.
/// * `follow_last` - Whether to dereference a symlink if the final component is a symlink.
///
/// # Returns
///
/// * `Ok(u64)` - Resolved target inode number.
///
/// # Errors
///
/// * `Err(zpl::ENOENT)` - Empty path or a component does not exist.
/// * `Err(zpl::ENOTDIR)` - An intermediate component (or trailing-slash target) is not a directory.
/// * `Err(ELOOP)` - More than [`SYMLOOP_MAX`] symbolic links were encountered.
pub fn resolve_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
    if path.is_empty() {
        return Err(zpl::ENOENT);
    }
    let follow_last = follow_last || path.ends_with(b"/");
    let mut cur = if path[0] == b'/' { root } else { base };
    let mut pending: Vec<Vec<u8>> = components(path);
    pending.reverse();
    let mut links = 0;
    while let Some(comp) = pending.pop() {
        if comp == b".." {
            cur = if cur == root { root } else { s.lookup(cur, b"..")? };
            continue;
        }
        let next = s.lookup(cur, &comp)?;
        let is_last = pending.is_empty();
        let attr = s.getattr(next)?;
        if attr.kind() == DnodeType::Symlink && (!is_last || follow_last) {
            links += 1;
            if links > SYMLOOP_MAX {
                return Err(ELOOP);
            }
            let target = s.readlink(next)?;
            if target.first() == Some(&b'/') {
                cur = root;
            }
            let mut more = components(&target);
            more.reverse();
            pending.extend(more);
            continue;
        }
        if !is_last && !attr.is_dir() {
            return Err(zpl::ENOTDIR);
        }
        cur = next;
    }
    if path.ends_with(b"/") && !s.getattr(cur)?.is_dir() {
        return Err(zpl::ENOTDIR);
    }
    Ok(cur)
}

/// Resolves the parent directory of `path` relative to `base` and returns `(parent_ino, child_name)`.
///
/// # Arguments
///
/// * `s` - Active mutable reference to the [`ZfsServer`].
/// * `base` - Starting directory object ID for relative paths.
/// * `path` - Path whose parent directory and final filename component should be separated.
///
/// # Returns
///
/// * `Ok((u64, Vec<u8>))` - Tuple of `(parent_dir_ino, final_component_bytes)`.
///
/// # Errors
///
/// * `Err(zpl::EEXIST)` - If `path` is empty or `"/"`.
/// * Any error from [`resolve_in()`] while resolving the parent directory prefix.
pub fn resolve_parent_at(s: &mut ZfsServer, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
    let root = s.root_obj();
    resolve_parent_in(s, root, base, path)
}

/// Resolves the parent directory and final component name of `path` within jail root `root`.
///
/// # Arguments
///
/// * `s` - Active mutable reference to the [`ZfsServer`].
/// * `root` - Jail root directory object ID.
/// * `base` - Starting directory object ID for relative paths.
/// * `path` - Path to split and resolve.
///
/// # Returns
///
/// * `Ok((u64, Vec<u8>))` - Tuple of `(parent_dir_ino, final_component_bytes)`.
///
/// # Errors
///
/// * `Err(zpl::EEXIST)` - If the trimmed child name is empty or `"/"`.
/// * Any negative errno from [`resolve_in()`] if the parent path cannot be resolved.
pub fn resolve_parent_in(s: &mut ZfsServer, root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
    let trimmed = {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        &path[..end]
    };
    let (dir_part, name) = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(i) => (&trimmed[..i.max(1)], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if name.is_empty() || name == b"/" {
        return Err(zpl::EEXIST);
    }
    let dir_path: &[u8] = if dir_part.is_empty() { b"/" } else { dir_part };
    let parent = if dir_path == b"." { base } else { resolve_in(s, root, base, dir_path, true)? };
    Ok((parent, name.to_vec()))
}

/// Translates a negative ZPL/Linux errno into a human-readable static error string.
fn errno_str(e: i64) -> &'static str {
    match e {
        zpl::ENOENT => "File or directory not found",
        zpl::EEXIST => "File or directory already exists",
        zpl::ENOTDIR => "Path component is not a directory",
        zpl::EISDIR => "Target is a directory",
        zpl::ENOTEMPTY => "Directory is not empty",
        zpl::ENOSPC => "Storage pool is out of space",
        zpl::EINVAL => "Invalid argument",
        zpl::ENAMETOOLONG => "File name too long",
        ELOOP => "Too many levels of symbolic links",
        _ => "ZFS I/O error",
    }
}

/// Resolves an absolute path (following symlinks) and returns its `(object_id, DnodeType)`.
///
/// # Arguments
///
/// * `path` - Path string to look up from the pool root.
///
/// # Returns
///
/// * `Ok((u64, DnodeType))` - Target object number and its [`DnodeType`].
///
/// # Errors
///
/// Returns a static error string if the path does not exist or symlink resolution fails.
pub fn resolve_path(path: &str) -> Result<(u64, DnodeType), &'static str> {
    with_server(|s| {
        let root = s.root_obj();
        let ino = resolve_at(s, root, path.as_bytes(), true)?;
        Ok((ino, s.getattr(ino)?.kind()))
    })
    .map_err(errno_str)
}

/// Resolves the parent directory object ID and borrows the final component slice of `path`.
///
/// # Arguments
///
/// * `path` - Target path string (must not be `"/"`).
///
/// # Returns
///
/// * `Ok((u64, &str))` - Parent directory object ID and child entry name.
///
/// # Errors
///
/// * `Err("Cannot target root directory as a child")` - If `path` has no child component.
/// * Any error from [`resolve_parent_at()`] mapped to a human-readable string.
pub fn resolve_parent_and_name(path: &str) -> Result<(u64, &str), &'static str> {
    let name = path.trim_end_matches('/').rsplit('/').next().unwrap_or("");
    if name.is_empty() {
        return Err("Cannot target root directory as a child");
    }
    let parent = with_server(|s| {
        let root = s.root_obj();
        Ok(resolve_parent_at(s, root, path.as_bytes())?.0)
    })
    .map_err(errno_str)?;
    Ok((parent, name))
}

/// Stateless client facade providing path-based and inode-based operations over [`ZFS_SERVER`].
///
/// # Concurrency & Thread Safety
/// All methods acquire the global [`ZFS_SERVER`] spinlock via [`with_server`] for the duration
/// of the call, making [`ZfsClient`] safe to invoke from any kernel thread or syscall handler.
pub struct ZfsClient;

impl ZfsClient {
    /// Queries the ZFS server for the highest committed transaction group (TXG) number.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Current committed uberblock TXG number.
    ///
    /// # Errors
    ///
    /// * `Err("ZFS I/O error")` - If the ZFS server has not been initialized.
    pub fn ping() -> Result<u64, &'static str> {
        with_server(|s| Ok(s.dmu.ub.txg)).map_err(errno_str)
    }

    /// Queries storage pool capacity and transaction status.
    ///
    /// # Returns
    ///
    /// * `Ok((total_mib, allocated_kib, free_kib, committed_txg))` - Pool usage metrics and active TXG.
    ///
    /// # Errors
    ///
    /// * `Err("ZFS I/O error")` - If the ZFS server is not mounted.
    pub fn pool_status() -> Result<(u64, u64, u64, u64), &'static str> {
        with_server(|s| {
            Ok((
                s.dmu.spa.total_capacity_bytes() / (1024 * 1024),
                s.dmu.spa.allocated_bytes() / 1024,
                s.dmu.spa.free_bytes() / 1024,
                s.dmu.ub.txg,
            ))
        })
        .map_err(errno_str)
    }

    /// Resolves `path` from the pool root, returning its `(object_id, DnodeType)`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path string to resolve.
    ///
    /// # Returns
    ///
    /// * `Ok((u64, DnodeType))` - Object ID and type of the resolved target.
    ///
    /// # Errors
    ///
    /// Returns a static error description if the path cannot be resolved.
    pub fn lookup(path: &str) -> Result<(u64, DnodeType), &'static str> {
        resolve_path(path)
    }

    /// Reads an object's contents starting from byte offset `0` into `out_buf`.
    ///
    /// # Arguments
    ///
    /// * `obj_id` - ZFS object / inode number to read.
    /// * `out_buf` - Destination buffer.
    /// * `_cap` - Optional security capability token (reserved for capability enforcement).
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes read into `out_buf`.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `obj_id` is a directory, does not exist, or fails checksum verification.
    pub fn read_file(obj_id: u64, out_buf: &mut [u8], _cap: Option<Capability>) -> Result<usize, &'static str> {
        with_server(|s| s.read(obj_id, 0, out_buf)).map_err(errno_str)
    }

    /// Truncates `obj_id` to `0` and replaces its entire contents with `data` in the open transaction group.
    ///
    /// # Arguments
    ///
    /// * `obj_id` - Target regular file object ID.
    /// * `data` - New file payload bytes.
    /// * `_cap` - Optional security capability token.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The open transaction group number (`open_txg`) holding the staged write.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `obj_id` is a directory or the pool runs out of space.
    pub fn write_file(obj_id: u64, data: &[u8], _cap: Option<Capability>) -> Result<u64, &'static str> {
        with_server(|s| {
            s.setattr(obj_id, SetAttr { size: Some(0), ..SetAttr::default() })?;
            s.write(obj_id, 0, data)?;
            Ok(s.dmu.open_txg)
        })
        .map_err(errno_str)
    }

    /// Looks up a regular file by `path` and reads its contents from offset `0` into `out_buf`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the regular file.
    /// * `out_buf` - Destination buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes read.
    ///
    /// # Errors
    ///
    /// * `Err("Target path is not a regular file")` - Resolved object is not [`DnodeType::PlainFile`].
    /// * Any lookup or read error.
    pub fn read_file_by_path(path: &str, out_buf: &mut [u8]) -> Result<usize, &'static str> {
        let (obj_id, obj_type) = Self::lookup(path)?;
        if obj_type != DnodeType::PlainFile {
            return Err("Target path is not a regular file");
        }
        Self::read_file(obj_id, out_buf, None)
    }

    /// Writes `data` to `path` (creating the file and any missing parent directories) and commits the transaction group.
    ///
    /// # Arguments
    ///
    /// * `path` - Destination file path.
    /// * `data` - File contents to write.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - The newly committed TXG number.
    ///
    /// # Errors
    ///
    /// Returns a static error string if path resolution, writing, or disk sync fails.
    pub fn write_file_by_path(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        Self::write_file_by_path_batch(path, data)?;
        Self::sync()?;
        Ok(Self::ping()?)
    }

    /// Writes `data` to `path` (creating the file and parent directories if needed) without forcing an immediate TXG commit.
    ///
    /// Ideal for batch operations such as archive extraction where [`ZfsClient::sync()`] is called once at the end.
    ///
    /// # Arguments
    ///
    /// * `path` - Destination file path.
    /// * `data` - File contents to stage in the open transaction group.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Open TXG number in which the write was staged.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the target is a directory or the pool is out of space.
    pub fn write_file_by_path_batch(path: &str, data: &[u8]) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let ino = match resolve_at(s, root, path.as_bytes(), true) {
                Ok(ino) => {
                    if s.getattr(ino)?.is_dir() {
                        return Err(zpl::EISDIR);
                    }
                    s.setattr(ino, SetAttr { size: Some(0), ..SetAttr::default() })?;
                    ino
                }
                Err(zpl::ENOENT) => {
                    let parent_path = path.trim_end_matches('/').rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    mkdir_all(s, parent_path)?;
                    let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
                    s.create(parent, &name, 0o644, 0, 0)?
                }
                Err(e) => return Err(e),
            };
            s.write(ino, 0, data)?;
            Ok(s.dmu.open_txg)
        })
        .map_err(errno_str)
    }

    /// Creates an empty regular file (`0o644`) at `path`, or updates `atime`/`mtime` to the current RTC time if it exists.
    ///
    /// # Arguments
    ///
    /// * `path` - File path to touch.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Object ID of the created or updated file.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the parent directory does not exist or cannot be modified.
    pub fn touch_file(path: &str) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            match resolve_at(s, root, path.as_bytes(), true) {
                Ok(ino) => {
                    let t = crate::arch::rtc::now();
                    let t = (t.0 as i64, t.1);
                    s.setattr(ino, SetAttr { atime: Some(t), mtime: Some(t), ..SetAttr::default() })?;
                    Ok(ino)
                }
                Err(zpl::ENOENT) => {
                    let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
                    s.create(parent, &name, 0o644, 0, 0)
                }
                Err(e) => Err(e),
            }
        })
        .map_err(errno_str)
    }

    /// Creates a new directory (`0o755`) at `path` (`mkdir`).
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the directory to create.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Object ID of the newly created directory.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `path` already exists or its parent directory is missing.
    pub fn create_dir(path: &str) -> Result<u64, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.mkdir(parent, &name, 0o755, 0, 0)
        })
        .map_err(errno_str)
    }

    /// Recursively creates a directory and all missing parent components along `path` (`mkdir -p`).
    ///
    /// # Arguments
    ///
    /// * `path` - Target directory path.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Object ID of the final directory.
    ///
    /// # Errors
    ///
    /// Returns a static error string if any component along `path` is a non-directory file.
    pub fn create_dir_all(path: &str) -> Result<u64, &'static str> {
        with_server(|s| mkdir_all(s, path)).map_err(errno_str)
    }

    /// Removes an empty directory at `path` (`rmdir`).
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path to remove.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Directory was empty and has been unlinked.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the target is not a directory, is not empty, or does not exist.
    pub fn remove_dir(path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.rmdir(parent, &name)
        })
        .map_err(errno_str)
    }

    /// Unlinks a non-directory file or symbolic link at `path`.
    ///
    /// # Arguments
    ///
    /// * `path` - Path of the file or symlink to remove.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Entry was unlinked.
    ///
    /// # Errors
    ///
    /// Returns a static error string if the target does not exist or is a directory.
    pub fn remove_file(path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (parent, name) = resolve_parent_at(s, root, path.as_bytes())?;
            s.unlink(parent, &name)
        })
        .map_err(errno_str)
    }

    /// Commits all pending dirty data and metadata in the open transaction group to disk.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Transaction group was durably committed (or had no pending changes).
    ///
    /// # Errors
    ///
    /// Returns a static error string if the disk write or flush fails.
    pub fn sync() -> Result<(), &'static str> {
        with_server(|s| s.sync().map(|_| ())).map_err(errno_str)
    }

    /// Opportunistically commits pending changes if the [`ZFS_SERVER`] lock is uncontended and the DMU has dirty state.
    ///
    /// Called every few seconds by the `txgd` task ([`start_txg_sync`]).
    pub fn sync_if_dirty() {
        if let Some(mut guard) = ZFS_SERVER.try_lock() {
            if let Some(s) = guard.as_mut() {
                if s.dmu.has_pending_changes() {
                    let _ = s.sync();
                }
            }
        }
    }

    /// Copies the contents of regular file `src_path` to `dst_path` and commits the transaction.
    ///
    /// # Arguments
    ///
    /// * `src_path` - Existing source file path.
    /// * `dst_path` - Destination file path.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Committed TXG number after writing `dst_path`.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `src_path` cannot be read or `dst_path` cannot be written.
    pub fn copy_file(src_path: &str, dst_path: &str) -> Result<u64, &'static str> {
        let st = Self::file_stat(src_path)?;
        let mut buf = alloc::vec![0u8; st.size as usize];
        let n = Self::read_file_by_path(src_path, &mut buf)?;
        Self::write_file_by_path(dst_path, &buf[..n])
    }

    /// Atomically renames or moves `src_path` to `dst_path`.
    ///
    /// # Arguments
    ///
    /// * `src_path` - Existing entry path.
    /// * `dst_path` - New target path.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Entry was renamed.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `src_path` is missing or `dst_path` conflicts with an incompatible type.
    pub fn move_entry(src_path: &str, dst_path: &str) -> Result<(), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let (sdir, sname) = resolve_parent_at(s, root, src_path.as_bytes())?;
            let (ddir, dname) = resolve_parent_at(s, root, dst_path.as_bytes())?;
            s.rename(sdir, &sname, ddir, &dname)
        })
        .map_err(errno_str)
    }

    /// Retrieves detailed metadata and top-level block pointer checksum information for `path` (following symlinks).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to inspect.
    ///
    /// # Returns
    ///
    /// * `Ok(FileStat)` - Populated [`FileStat`] structure.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `path` does not exist.
    pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let ino = resolve_at(s, root, path.as_bytes(), true)?;
            let a = s.getattr(ino)?;
            let dn = s.dmu.get_dnode(ino).map_err(|_| zpl::EIO)?;
            let bp = dn.blkptr[0];
            let mut name = [0u8; 32];
            let base = path.trim_end_matches('/').rsplit('/').next().unwrap_or("/");
            let n = base.len().min(31);
            name[..n].copy_from_slice(&base.as_bytes()[..n]);
            Ok(FileStat {
                obj_id: ino,
                obj_type: a.kind(),
                size: a.size,
                birth_txg: a.birth_txg,
                checksum: [bp.checksum.a, bp.checksum.b, bp.checksum.c, bp.checksum.d],
                is_allocated: !bp.is_hole(),
                name,
                mode: a.mode,
                uid: a.uid,
                gid: a.gid,
                nlink: a.nlink,
                mtime: a.mtime.0,
            })
        })
        .map_err(errno_str)
    }

    /// Creates a point-in-time snapshot of the dataset at `dataset_id` named `"snap<rtc_seconds>"`.
    ///
    /// # Arguments
    ///
    /// * `dataset_id` - Index of the non-snapshot dataset in [`ZfsServer::datasets`].
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Transaction group number captured by the snapshot.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `dataset_id` is out of range or the commit fails.
    pub fn snapshot(dataset_id: usize) -> Result<u64, &'static str> {
        let name = alloc::format!("snap{}", crate::arch::rtc::now().0);
        with_server(|s| s.snapshot(dataset_id, &name)).map_err(errno_str)
    }

    /// Lists all entries in the directory at `path` (excluding `"."` and `".."`).
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path to enumerate.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<ZapEntry>, usize, &'static str))` - Tuple of `(entries, entry_count, dataset_name)`.
    ///
    /// # Errors
    ///
    /// Returns a static error string if `path` does not exist or is not a directory.
    pub fn list_dir(path: &str) -> Result<(Vec<ZapEntry>, usize, &'static str), &'static str> {
        with_server(|s| {
            let root = s.root_obj();
            let dir = resolve_at(s, root, path.as_bytes(), true)?;
            let mut out = Vec::new();
            let mut cookie = 2;
            loop {
                let batch = s.readdir(dir, cookie, 256)?;
                if batch.is_empty() {
                    break;
                }
                for e in batch {
                    cookie = e.next_cookie;
                    let kind = s.getattr(e.ino).map(|a| a.kind()).unwrap_or(DnodeType::None);
                    out.push(ZapEntry::new(&e.name, e.ino, kind));
                }
            }
            let n = out.len();
            Ok((out, n, "hydrapool/root"))
        })
        .map_err(errno_str)
    }

    // --------------------------------------------------------------
    // Inode-level access used by the VFS / Linux layer
    // --------------------------------------------------------------

    /// Resolves `path` relative to directory inode `base` (`0` = pool root).
    ///
    /// # Arguments
    ///
    /// * `base` - Starting directory inode (`0` defaults to the pool root).
    /// * `path` - Raw byte slice of the path.
    /// * `follow_last` - Whether to dereference a final symlink component.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Resolved inode number, or negative Linux errno on failure.
    pub fn resolve(base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            resolve_at(s, base, path, follow_last)
        })
    }

    /// Resolves `path` within jail root directory `root` (`0` = pool root), relative to `base` (`0` = `root`).
    ///
    /// # Arguments
    ///
    /// * `root` - Jail root directory inode (`0` defaults to the pool root).
    /// * `base` - Starting directory inode (`0` defaults to `root`).
    /// * `path` - Raw byte slice of the path.
    /// * `follow_last` - Whether to dereference a final symlink component.
    ///
    /// # Returns
    ///
    /// * `Ok(u64)` - Resolved inode number, or negative Linux errno on failure.
    pub fn resolve_in(root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            resolve_in(s, root, base, path, follow_last)
        })
    }

    /// Resolves the parent directory inode and final component name of `path` within jail root `root`.
    ///
    /// # Arguments
    ///
    /// * `root` - Jail root directory inode (`0` defaults to the pool root).
    /// * `base` - Starting directory inode (`0` defaults to `root`).
    /// * `path` - Raw byte slice of the path.
    ///
    /// # Returns
    ///
    /// * `Ok((u64, Vec<u8>))` - `(parent_ino, child_name)`, or negative Linux errno on failure.
    pub fn resolve_parent_in(root: u64, base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let root = if root == 0 { s.root_obj() } else { root };
            let base = if base == 0 { root } else { base };
            resolve_parent_in(s, root, base, path)
        })
    }

    /// Resolves the parent directory inode and final component name of `path` relative to `base` (`0` = pool root).
    ///
    /// # Arguments
    ///
    /// * `base` - Starting directory inode (`0` defaults to the pool root).
    /// * `path` - Raw byte slice of the path.
    ///
    /// # Returns
    ///
    /// * `Ok((u64, Vec<u8>))` - `(parent_ino, child_name)`, or negative Linux errno on failure.
    pub fn resolve_parent(base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
        with_server(|s| {
            let base = if base == 0 { s.root_obj() } else { base };
            resolve_parent_at(s, base, path)
        })
    }

    /// Returns the object number of the pool's root directory (`"/"`), or `0` if unmounted.
    pub fn root_ino() -> u64 {
        with_server(|s| Ok(s.root_obj())).unwrap_or(0)
    }

    /// Queries the POSIX attributes ([`Attr`]) of inode `ino`.
    ///
    /// # Returns
    ///
    /// * `Ok(Attr)` - Inode attributes, or negative Linux errno (`-ENOENT`) on failure.
    pub fn getattr(ino: u64) -> Result<Attr, i64> {
        with_server(|s| s.getattr(ino))
    }

    /// Updates attributes (`mode`, `uid`, `gid`, `size`, `atime`, `mtime`) on inode `ino`.
    ///
    /// # Returns
    ///
    /// * `Ok(Attr)` - Updated inode attributes, or negative Linux errno on failure.
    pub fn setattr(ino: u64, set: SetAttr) -> Result<Attr, i64> {
        with_server(|s| s.setattr(ino, set))
    }

    /// Reads up to `buf.len()` bytes from inode `ino` starting at `offset`.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes read, or negative Linux errno on failure.
    pub fn read_at(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        with_server(|s| s.read(ino, offset, buf))
    }

    /// Writes `data` to inode `ino` starting at `offset`.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written, or negative Linux errno on failure.
    pub fn write_at(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        with_server(|s| s.write(ino, offset, data))
    }

    /// Reads up to `max` directory entries from directory inode `ino` starting at `cookie`.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<ReaddirEntry>)` - Batch of directory entries, or negative Linux errno on failure.
    pub fn readdir(ino: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
        with_server(|s| s.readdir(ino, cookie, max))
    }

    /// Reads the target path bytes of symbolic link inode `ino`.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - Symlink target bytes, or negative Linux errno (`-EINVAL`, `-ENOENT`) on failure.
    pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
        with_server(|s| s.readlink(ino))
    }

    /// Increments the active open-handle count on `ino` so unlinked files stay allocated until closed.
    pub fn open_ref(ino: u64) {
        let _ = with_server(|s| {
            s.open_ref(ino);
            Ok(())
        });
    }

    /// Emits an `inotify` `IN_CLOSE_WRITE` event when a writable [`super::fd::OpenFile`] is dropped.
    pub fn notify_close_write(ino: u64) {
        if crate::compat::linux::inotify::active() {
            let _ = with_server(|s| {
                s.notify_file(ino, crate::compat::linux::inotify::IN_CLOSE_WRITE);
                Ok(())
            });
        }
    }

    /// Decrements the active open-handle count on `ino`, freeing the object if it was unlinked while open.
    pub fn release(ino: u64) {
        let _ = with_server(|s| {
            s.release(ino);
            Ok(())
        });
    }

    /// Imports userland ELF test binaries and configuration files from the UEFI boot volume into the ZFS pool.
    ///
    /// Must be called while UEFI Boot Services are still active (prior to `ExitBootServices`).
    /// Skips files that already exist in ZFS with identical byte contents, and commits the pool
    /// if at least one file was imported or updated.
    ///
    /// # Returns
    ///
    /// The number of newly imported or updated files written into ZFS.
    pub fn sync_boot_binaries() -> usize {
        if crate::console::is_hardware_mode() {
            return 0;
        }

        let mut root = match crate::shell::fs::open_root_volume() {
            Ok(r) => r,
            Err(_) => return 0,
        };

        let fixed_files = [
            ("\\bin\\hello.elf", "/bin/hello.elf"),
            ("\\bin\\counter.elf", "/bin/counter.elf"),
            ("\\bin\\linuxapp.elf", "/bin/linuxapp.elf"),
            ("\\bin\\linux_app.elf", "/bin/linux_app.elf"),
            ("\\bin\\thread_test.elf", "/bin/thread_test.elf"),
            ("\\bin\\threadtest.elf", "/bin/threadtest.elf"),
            ("\\bin\\roletest.elf", "/bin/roletest.elf"),
            ("\\bin\\socktest.elf", "/bin/socktest.elf"),
            ("\\bin\\epolltest.elf", "/bin/epolltest.elf"),
            ("\\bin\\shmtest.elf", "/bin/shmtest.elf"),
            ("\\bin\\wlclient.elf", "/bin/wlclient.elf"),
            ("\\bin\\wlseat.elf", "/bin/wlseat.elf"),
            ("\\bin\\dynclient.elf", "/bin/dynclient.elf"),
            ("\\bin\\vmtest.elf", "/bin/vmtest.elf"),
            ("\\bin\\fstest.elf", "/bin/fstest.elf"),
            ("\\bin\\plasmashell.elf", "/bin/plasmashell.elf"),
            ("\\bin\\krunner.elf", "/bin/krunner.elf"),
            ("\\bin\\ld-hydra.so", "/lib64/ld-hydra.so"),
            ("\\etc\\passwd", "/etc/passwd"),
            ("\\etc\\group", "/etc/group"),
        ];

        // Every executable in the boot volume's \bin directory is imported too
        let mut candidate_files: Vec<(alloc::string::String, alloc::string::String)> = fixed_files
            .iter()
            .map(|&(f, z)| (alloc::string::String::from(f), alloc::string::String::from(z)))
            .collect();
        if let Some(cstr) = crate::shell::fs::path_to_cstr16(r"\bin", &mut [0u16; 16]) {
            if let Ok(handle) = root.open(cstr, uefi::proto::media::file::FileMode::Read, uefi::proto::media::file::FileAttribute::empty()) {
                if let Some(mut dir) = handle.into_directory() {
                    let mut entry_buf = [0u8; 512];
                    while let Ok(Some(info)) = dir.read_entry(&mut entry_buf) {
                        let name = alloc::format!("{}", info.file_name());
                        if name.ends_with(".elf") && !candidate_files.iter().any(|(_, z)| z.ends_with(&alloc::format!("/{}", name))) {
                            candidate_files.push((alloc::format!(r"\bin\{}", name), alloc::format!("/bin/{}", name)));
                        }
                    }
                }
            }
        }

        let mut imported_count = 0;
        let mut path_u16 = [0u16; 128];

        for (fat_path, zfs_path) in candidate_files.iter() {
            let (fat_path, zfs_path) = (fat_path.as_str(), zfs_path.as_str());
            let cstr = match crate::shell::fs::path_to_cstr16(fat_path, &mut path_u16) {
                Some(c) => c,
                None => continue,
            };
            let handle = match root.open(cstr, uefi::proto::media::file::FileMode::Read, uefi::proto::media::file::FileAttribute::empty()) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let mut file = match handle.into_regular_file() {
                Some(f) => f,
                None => continue,
            };
            let mut info_buf = [0u8; 256];
            let file_size = file
                .get_info::<uefi::proto::media::file::FileInfo>(&mut info_buf)
                .map(|i| i.file_size() as usize)
                .unwrap_or(0);
            let mut file_buf = alloc::vec![0u8; file_size];
            let mut total_read = 0;
            while total_read < file_buf.len() {
                match file.read(&mut file_buf[total_read..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total_read += n,
                }
            }
            let data = &file_buf[..total_read];

            // Skip files already imported with identical contents
            if let Ok(st) = Self::file_stat(zfs_path) {
                if st.size == data.len() as u64 {
                    let mut existing = alloc::vec![0u8; data.len()];
                    if Self::read_file_by_path(zfs_path, &mut existing).is_ok() && existing == data {
                        continue;
                    }
                }
            }

            let is_elf = data.len() >= 4 && data[..4] == crate::task::elf::ELF_MAGIC;
            let is_config = !data.is_empty() && zfs_path.starts_with("/etc/");
            if (is_elf || is_config) && Self::write_file_by_path_batch(zfs_path, data).is_ok() {
                if is_elf {
                    let _ = with_server(|s| {
                        let root = s.root_obj();
                        let ino = resolve_at(s, root, zfs_path.as_bytes(), true)?;
                        s.setattr(ino, SetAttr { mode: Some(0o755), ..SetAttr::default() })?;
                        Ok(())
                    });
                }
                imported_count += 1;
                crate::console::set_color(uefi::proto::console::text::Color::LightGreen, uefi::proto::console::text::Color::Black);
                crate::println!("[+] Imported '{}' from boot media into ZFS '{}' ({} bytes)", fat_path, zfs_path, total_read);
            }
        }

        if imported_count > 0 {
            let _ = Self::sync();
        }
        imported_count
    }
}

/// Recursively creates `path` and any missing parent directories under the pool root, returning the final directory inode.
fn mkdir_all(s: &mut ZfsServer, path: &str) -> Result<u64, i64> {
    let mut cur = s.root_obj();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        cur = match s.lookup(cur, part.as_bytes()) {
            Ok(_) => {
                let ino = resolve_at(s, cur, part.as_bytes(), true)?;
                if !s.getattr(ino)?.is_dir() {
                    return Err(zpl::ENOTDIR);
                }
                ino
            }
            Err(zpl::ENOENT) => s.mkdir(cur, part.as_bytes(), 0o755, 0, 0)?,
            Err(e) => return Err(e),
        };
    }
    Ok(cur)
}

/// Seconds between automatic commits of pending changes (OpenZFS's `zfs_txg_timeout`).
const TXG_TIMEOUT_SECS: u64 = 5;

static TXG_SYNC_RUNNING: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Starts the `txgd` kernel task, which commits pending changes every few seconds so a
/// power-off loses at most that much work (otherwise only full transaction groups,
/// `fsync` and `sync` reach the disk).
pub fn start_txg_sync() {
    if TXG_SYNC_RUNNING.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return;
    }
    crate::task::spawn("txgd", txgd_main, crate::task::TaskPriority::Normal);
}

fn txgd_main() {
    loop {
        crate::task::sleep_ms(TXG_TIMEOUT_SECS * 1000);
        ZfsClient::sync_if_dirty();
    }
}
