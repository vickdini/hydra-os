//! # ZFS POSIX Layer (ZPL)
//!
//! ## Subsystem Role & Architecture
//! This module implements the POSIX filesystem abstraction layer on top of Hydra's OpenZFS
//! storage stack. It provides standard file and directory semantics (creation, deletion,
//! links, truncation, read, write, permissions, and directory iteration) operating directly
//! on dnode objects. Errors are returned as negative Linux errno values.
//!
//! ## Key Types & Interfaces
//! - [`Attr`]: Inode attribute descriptor matching Linux `struct stat` semantics.
//! - [`SetAttr`]: Modification mask for changing permissions, sizes, and timestamps.
//! - [`ReaddirEntry`]: Iteration element returned during directory listings.
//! - [`ZplResult`]: Canonical Result type encoding negative POSIX error codes.
//!
//! ## Concurrency & Safety
//! The ZPL operates under the [`super::server::ZFS_SERVER`] spinlock or VFS synchronization
//! primitives. Modifications increment transaction groups and synchronize blocks via the DMU.

use alloc::vec::Vec;

use super::server::ZfsServer;
use super::spa::BLOCK;
use super::types::*;

pub use super::fsproto::{EEXIST, EFBIG, EINVAL, EIO, EISDIR, EMLINK, ENAMETOOLONG, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY, EPERM, EXDEV};
pub use super::fsproto::{Attr, ReaddirEntry, SetAttr};

/// Result type returned by ZPL operations, encoding negative Linux errnos on failure.
pub type ZplResult<T> = Result<T, i64>;

/// Translates internal error messages into POSIX error numbers (`ENOSPC` or `EIO`).
///
/// # Arguments
/// * `e` - Error string message to translate.
///
/// # Returns
/// Linux errno as a negative integer.
fn io(e: &'static str) -> i64 {
    crate::kprintln!("[zfs] {}", e);
    if e.contains("out of space") {
        ENOSPC
    } else {
        EIO
    }
}


/// Returns the current real-time clock timestamp in seconds and nanoseconds.
///
/// # Returns
/// Tuple of `(seconds, nanoseconds)`.
fn now() -> (i64, u32) {
    let (s, ns) = crate::arch::rtc::now();
    (s as i64, ns)
}

/// Validates a directory entry name for illegal characters or excessive length.
///
/// # Arguments
/// * `name` - Filename byte slice to validate.
///
/// # Returns
/// `Ok(())` if valid, or `Err(EINVAL)` / `Err(ENAMETOOLONG)`.
fn check_name(name: &[u8]) -> ZplResult<()> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0) {
        return Err(EINVAL);
    }
    if name.len() > super::zap::NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    Ok(())
}

impl ZfsServer {
    /// Reports a change of `ino` to inotify: to the inode's own watches and, under its
    /// name, to its directory's watches.
    ///
    /// # Arguments
    /// * `ino` - Inode number undergoing changes.
    /// * `mask` - Inotify event mask flags.
    pub fn notify_file(&mut self, ino: u64, mask: u32) {
        if !crate::compat::linux::inotify::active() {
            return;
        }
        let dn = match self.dnode(ino) {
            Ok(d) => d,
            Err(_) => return,
        };
        let mask = mask | if dn.mode & S_IFMT == S_IFDIR { crate::compat::linux::inotify::IN_ISDIR } else { 0 };
        crate::compat::linux::inotify::event(ino, mask, 0, b"");
        let parent = dn.parent;
        if parent == 0 || parent == ino || !crate::compat::linux::inotify::watched(parent) {
            return;
        }
        if let Some(name) = self.name_in(parent, ino) {
            crate::compat::linux::inotify::event(parent, mask, 0, &name);
        }
    }

    /// The name under which directory `dir` holds `ino` (a scan; only for notification).
    ///
    /// # Arguments
    /// * `dir` - Directory inode number to search within.
    /// * `ino` - Child inode number to resolve.
    ///
    /// # Returns
    /// `Some(Vec<u8>)` containing the entry name if found, or `None`.
    fn name_in(&mut self, dir: u64, ino: u64) -> Option<Vec<u8>> {
        let mut pos = 0;
        loop {
            let batch = self.zap.readdir(&mut self.dmu, dir, pos, 64).ok()?;
            let last = batch.last()?.next_pos;
            if let Some(e) = batch.into_iter().find(|e| e.ino == ino) {
                return Some(e.name);
            }
            pos = last;
        }
    }

    /// Reports an entry change in directory `dir`.
    ///
    /// # Arguments
    /// * `dir` - Directory inode number.
    /// * `mask` - Inotify event mask.
    /// * `cookie` - Correlation cookie for paired events (e.g. rename).
    /// * `name` - Filename byte slice.
    /// * `is_dir` - Whether the target entry is a directory.
    fn notify_entry(&self, dir: u64, mask: u32, cookie: u32, name: &[u8], is_dir: bool) {
        if crate::compat::linux::inotify::active() {
            crate::compat::linux::inotify::event(dir, mask | if is_dir { crate::compat::linux::inotify::IN_ISDIR } else { 0 }, cookie, name);
        }
    }

    /// Fetches the on-disk dnode structure for `ino`, verifying it is not unlinked.
    ///
    /// # Arguments
    /// * `ino` - Target inode number.
    ///
    /// # Returns
    /// Cloned [`DnodePhys`] object on success, or `Err(ENOENT)`.
    fn dnode(&mut self, ino: u64) -> ZplResult<DnodePhys> {
        let dn = self.dmu.get_dnode(ino).map_err(|_| ENOENT)?;
        if dn.mode == 0 {
            return Err(ENOENT);
        }
        Ok(dn)
    }

    /// Fetches the on-disk dnode structure for `ino` and asserts that it is a directory.
    ///
    /// # Arguments
    /// * `ino` - Target directory inode number.
    ///
    /// # Returns
    /// Directory [`DnodePhys`] on success, or `Err(ENOTDIR)`.
    fn dir_dnode(&mut self, ino: u64) -> ZplResult<DnodePhys> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(dn)
    }

    /// Updates modification and/or change timestamps on `ino`.
    ///
    /// # Arguments
    /// * `ino` - Target inode number.
    /// * `m` - Whether to update `mtime`.
    /// * `c` - Whether to update `ctime`.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error code.
    fn touch(&mut self, ino: u64, m: bool, c: bool) -> ZplResult<()> {
        let mut dn = self.dnode(ino)?;
        let t = now();
        if m {
            dn.mtime = t.0;
            dn.mtime_ns = t.1;
        }
        if c {
            dn.ctime = t.0;
            dn.ctime_ns = t.1;
        }
        self.dmu.put_dnode(ino, dn);
        Ok(())
    }

    /// Returns the attributes of an inode.
    ///
    /// # Arguments
    /// * `ino` - Target inode number.
    ///
    /// # Returns
    /// Populated [`Attr`] descriptor on success, or `Err(ENOENT)`.
    pub fn getattr(&mut self, ino: u64) -> ZplResult<Attr> {
        let dn = self.dnode(ino)?;
        Ok(Attr {
            ino,
            mode: dn.mode,
            nlink: dn.nlink,
            uid: dn.uid,
            gid: dn.gid,
            rdev: dn.rdev,
            size: dn.size,
            blocks: (dn.size + BLOCK - 1) / BLOCK * (BLOCK / 512),
            atime: (dn.atime, dn.atime_ns),
            mtime: (dn.mtime, dn.mtime_ns),
            ctime: (dn.ctime, dn.ctime_ns),
            generation: dn.generation,
            birth_txg: dn.birth_txg,
        })
    }

    /// Looks up `name` in directory `dir` (handles `.` and `..`).
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Filename byte slice to search for.
    ///
    /// # Returns
    /// Resolved child inode number on success, or `Err(ENOENT)` / `Err(ENOTDIR)`.
    pub fn lookup(&mut self, dir: u64, name: &[u8]) -> ZplResult<u64> {
        let dn = self.dir_dnode(dir)?;
        match name {
            b"" | b"." => Ok(dir),
            b".." => Ok(if dn.parent != 0 { dn.parent } else { dir }),
            _ => match self.zap.lookup(&mut self.dmu, dir, name).map_err(io)? {
                Some((ino, _)) => Ok(ino),
                None => Err(ENOENT),
            },
        }
    }

    /// Allocates an inode and links it into `dir` as `name`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Filename byte slice.
    /// * `mode` - File type and permission bits.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    /// * `rdev` - Special device identifier for device nodes.
    ///
    /// # Returns
    /// Newly allocated inode number on success, or an error code.
    fn make_node(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, rdev: u64) -> ZplResult<u64> {
        if name == b"." || name == b".." {
            // Always present in a directory (`mkdir .` fails with EEXIST on Linux)
            return Err(EEXIST);
        }
        check_name(name)?;
        self.dir_dnode(dir)?;
        if self.zap.lookup(&mut self.dmu, dir, name).map_err(io)?.is_some() {
            return Err(EEXIST);
        }
        let ino = self.dmu.alloc_object(mode).map_err(io)?;
        let mut dn = self.dmu.get_dnode(ino).map_err(io)?;
        let t = now();
        dn.uid = uid;
        dn.gid = gid;
        dn.rdev = rdev;
        dn.parent = dir;
        dn.nlink = if mode & S_IFMT == S_IFDIR { 2 } else { 1 };
        dn.atime = t.0;
        dn.mtime = t.0;
        dn.ctime = t.0;
        dn.atime_ns = t.1;
        dn.mtime_ns = t.1;
        dn.ctime_ns = t.1;
        self.dmu.put_dnode(ino, dn);
        self.zap.insert(&mut self.dmu, dir, name, ino, dtype_from_mode(mode)).map_err(io)?;
        self.touch(dir, true, true)?;
        self.notify_entry(dir, crate::compat::linux::inotify::IN_CREATE, 0, name, mode & S_IFMT == S_IFDIR);
        self.maybe_sync();
        Ok(ino)
    }

    /// Creates a regular file.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Filename byte slice.
    /// * `perm` - Permission bits.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    /// Newly allocated file inode number on success, or an error code.
    pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> ZplResult<u64> {
        self.make_node(dir, name, S_IFREG | (perm & 0o7777), uid, gid, 0)
    }

    /// Creates a device node, FIFO, socket or regular file from a full `st_mode`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Filename byte slice.
    /// * `mode` - File mode specifying type and permissions.
    /// * `rdev` - Device major/minor number encoding.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    /// Newly created inode number on success, or `Err(EINVAL)` if attempting directory/symlink creation.
    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> ZplResult<u64> {
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        if mode & S_IFMT == S_IFDIR || mode & S_IFMT == S_IFLNK {
            return Err(EINVAL);
        }
        self.make_node(dir, name, mode, uid, gid, rdev)
    }

    /// Creates a directory.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Subdirectory name byte slice.
    /// * `perm` - Permission bits.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    /// Newly allocated directory inode number on success, or an error code.
    pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> ZplResult<u64> {
        let ino = self.make_node(dir, name, S_IFDIR | (perm & 0o7777), uid, gid, 0)?;
        let mut parent = self.dnode(dir)?;
        parent.nlink += 1;
        self.dmu.put_dnode(dir, parent);
        Ok(ino)
    }

    /// Creates a symbolic link pointing at `target`.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Symlink name byte slice.
    /// * `target` - Target destination path byte slice.
    /// * `uid` - Owner user ID.
    /// * `gid` - Owner group ID.
    ///
    /// # Returns
    /// Newly allocated symlink inode number on success, or an error code.
    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> ZplResult<u64> {
        if target.is_empty() || target.len() > 4095 {
            return Err(if target.is_empty() { ENOENT } else { ENAMETOOLONG });
        }
        let ino = self.make_node(dir, name, S_IFLNK | 0o777, uid, gid, 0)?;
        let mut dn = self.dnode(ino)?;
        if target.len() <= DNODE_BONUS_SIZE {
            dn.bonus[..target.len()].copy_from_slice(target);
            dn.flags |= DNODE_FLAG_INLINE;
            dn.size = target.len() as u64;
            self.dmu.put_dnode(ino, dn);
        } else {
            self.dmu.write(ino, 0, target).map_err(io)?;
        }
        Ok(ino)
    }

    /// Returns a symbolic link's target.
    ///
    /// # Arguments
    /// * `ino` - Target symlink inode number.
    ///
    /// # Returns
    /// Target path byte vector on success, or `Err(EINVAL)` if not a symlink.
    pub fn readlink(&mut self, ino: u64) -> ZplResult<Vec<u8>> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT != S_IFLNK {
            return Err(EINVAL);
        }
        if dn.flags & DNODE_FLAG_INLINE != 0 {
            return Ok(dn.bonus[..dn.size as usize].to_vec());
        }
        let mut buf = alloc::vec![0u8; dn.size as usize];
        let n = self.dmu.read(ino, 0, &mut buf).map_err(io)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Adds a hard link `dir/name` to `ino`.
    ///
    /// # Arguments
    /// * `ino` - Existing source inode number.
    /// * `dir` - Target parent directory inode number.
    /// * `name` - Hard link name byte slice.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error code if target is a directory or link count exceeded.
    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8]) -> ZplResult<()> {
        check_name(name)?;
        let mut dn = self.dnode(ino)?;
        if dn.mode & S_IFMT == S_IFDIR {
            return Err(EPERM);
        }
        if dn.nlink >= 65_000 {
            return Err(EMLINK);
        }
        self.dir_dnode(dir)?;
        if self.zap.lookup(&mut self.dmu, dir, name).map_err(io)?.is_some() {
            return Err(EEXIST);
        }
        self.zap.insert(&mut self.dmu, dir, name, ino, dtype_from_mode(dn.mode)).map_err(io)?;
        dn.nlink += 1;
        let t = now();
        dn.ctime = t.0;
        dn.ctime_ns = t.1;
        self.dmu.put_dnode(ino, dn);
        self.touch(dir, true, true)?;
        self.notify_entry(dir, crate::compat::linux::inotify::IN_CREATE, 0, name, false);
        if crate::compat::linux::inotify::active() {
            crate::compat::linux::inotify::event(ino, crate::compat::linux::inotify::IN_ATTRIB, 0, b"");
        }
        Ok(())
    }

    /// Drops one link to `ino`, freeing it when no links and no open handles remain.
    ///
    /// # Arguments
    /// * `ino` - Inode number whose link count is decremented.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error code.
    fn drop_link(&mut self, ino: u64) -> ZplResult<()> {
        let mut dn = self.dnode(ino)?;
        let is_dir = dn.mode & S_IFMT == S_IFDIR;
        dn.nlink = if is_dir { 0 } else { dn.nlink.saturating_sub(1) };
        let t = now();
        dn.ctime = t.0;
        dn.ctime_ns = t.1;
        self.dmu.put_dnode(ino, dn);
        if dn.nlink == 0 {
            if self.open_counts.get(&ino).copied().unwrap_or(0) > 0 {
                self.orphans.insert(ino);
            } else {
                if is_dir {
                    self.zap.forget(ino);
                }
                self.dmu.free_object(ino).map_err(io)?;
            }
        }
        Ok(())
    }

    /// Removes a non-directory entry.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Filename byte slice to unlink.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(EISDIR)` if entry is a directory.
    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> ZplResult<()> {
        let ino = self.lookup(dir, name)?;
        if self.dnode(ino)?.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        self.zap.remove(&mut self.dmu, dir, name).map_err(io)?;
        self.touch(dir, true, true)?;
        self.notify_entry(dir, crate::compat::linux::inotify::IN_DELETE, 0, name, false);
        let last = self.dnode(ino).map_or(true, |d| d.nlink <= 1);
        self.drop_link(ino)?;
        if crate::compat::linux::inotify::active() {
            crate::compat::linux::inotify::event(ino, if last { crate::compat::linux::inotify::IN_DELETE_SELF } else { crate::compat::linux::inotify::IN_ATTRIB }, 0, b"");
        }
        self.maybe_sync();
        Ok(())
    }

    /// Removes an empty directory.
    ///
    /// # Arguments
    /// * `dir` - Parent directory inode number.
    /// * `name` - Subdirectory name byte slice to remove.
    ///
    /// # Returns
    /// `Ok(())` on success, or `Err(ENOTEMPTY)` if directory contains entries.
    pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> ZplResult<()> {
        if name == b"." {
            return Err(EINVAL);
        }
        if name == b".." {
            return Err(ENOTEMPTY);
        }
        let ino = self.lookup(dir, name)?;
        self.dir_dnode(ino)?;
        if self.zap.count(&mut self.dmu, ino).map_err(io)? != 0 {
            return Err(ENOTEMPTY);
        }
        self.zap.remove(&mut self.dmu, dir, name).map_err(io)?;
        let mut parent = self.dnode(dir)?;
        parent.nlink = parent.nlink.saturating_sub(1);
        self.dmu.put_dnode(dir, parent);
        self.touch(dir, true, true)?;
        self.notify_entry(dir, crate::compat::linux::inotify::IN_DELETE, 0, name, true);
        if crate::compat::linux::inotify::active() {
            crate::compat::linux::inotify::event(ino, crate::compat::linux::inotify::IN_DELETE_SELF | crate::compat::linux::inotify::IN_ISDIR, 0, b"");
        }
        self.drop_link(ino)
    }

    /// Renames `sdir/sname` to `ddir/dname`, replacing a compatible existing target.
    ///
    /// # Arguments
    /// * `sdir` - Source parent directory inode number.
    /// * `sname` - Source entry name byte slice.
    /// * `ddir` - Destination parent directory inode number.
    /// * `dname` - Destination entry name byte slice.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error code.
    pub fn rename(&mut self, sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> ZplResult<()> {
        check_name(dname)?;
        let ino = self.lookup(sdir, sname)?;
        let src = self.dnode(ino)?;
        let src_is_dir = src.mode & S_IFMT == S_IFDIR;
        self.dir_dnode(ddir)?;

        if sdir == ddir && sname == dname {
            return Ok(());
        }
        // A directory may not move into its own subtree
        if src_is_dir {
            let mut cur = ddir;
            loop {
                if cur == ino {
                    return Err(EINVAL);
                }
                let parent = self.dnode(cur)?.parent;
                if parent == cur || parent == 0 {
                    break;
                }
                cur = parent;
            }
        }

        let existing = self.zap.lookup(&mut self.dmu, ddir, dname).map_err(io)?;
        if let Some((target, _)) = existing {
            if target == ino {
                // Both names are links to the same file: POSIX says rename does nothing
                return Ok(());
            }
            let tdn = self.dnode(target)?;
            let target_is_dir = tdn.mode & S_IFMT == S_IFDIR;
            if src_is_dir && !target_is_dir {
                return Err(ENOTDIR);
            }
            if !src_is_dir && target_is_dir {
                return Err(EISDIR);
            }
            if target_is_dir && self.zap.count(&mut self.dmu, target).map_err(io)? != 0 {
                return Err(ENOTEMPTY);
            }
            self.zap.replace(&mut self.dmu, ddir, dname, ino, dtype_from_mode(src.mode)).map_err(io)?;
            if target_is_dir {
                let mut d = self.dnode(ddir)?;
                d.nlink = d.nlink.saturating_sub(1);
                self.dmu.put_dnode(ddir, d);
            }
            self.drop_link(target)?;
        } else {
            self.zap.insert(&mut self.dmu, ddir, dname, ino, dtype_from_mode(src.mode)).map_err(io)?;
        }
        self.zap.remove(&mut self.dmu, sdir, sname).map_err(io)?;

        if src_is_dir && sdir != ddir {
            let mut s = self.dnode(sdir)?;
            s.nlink = s.nlink.saturating_sub(1);
            self.dmu.put_dnode(sdir, s);
            let mut d = self.dnode(ddir)?;
            d.nlink += 1;
            self.dmu.put_dnode(ddir, d);
        }
        let mut moved = self.dnode(ino)?;
        moved.parent = ddir;
        let t = now();
        moved.ctime = t.0;
        moved.ctime_ns = t.1;
        self.dmu.put_dnode(ino, moved);
        self.touch(sdir, true, true)?;
        self.touch(ddir, true, true)?;
        if crate::compat::linux::inotify::active() {
            let cookie = crate::compat::linux::inotify::cookie();
            self.notify_entry(sdir, crate::compat::linux::inotify::IN_MOVED_FROM, cookie, sname, src_is_dir);
            self.notify_entry(ddir, crate::compat::linux::inotify::IN_MOVED_TO, cookie, dname, src_is_dir);
            crate::compat::linux::inotify::event(ino, crate::compat::linux::inotify::IN_MOVE_SELF, 0, b"");
        }
        self.maybe_sync();
        Ok(())
    }

    /// Reads file data at `offset`.
    ///
    /// # Arguments
    /// * `ino` - File inode number to read.
    /// * `offset` - Byte offset within the file.
    /// * `buf` - Destination buffer to receive file bytes.
    ///
    /// # Returns
    /// Number of bytes read on success, or `Err(EISDIR)` if target is a directory.
    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> ZplResult<usize> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        self.dmu.read(ino, offset, buf).map_err(io)
    }

    /// Writes file data at `offset`.
    ///
    /// # Arguments
    /// * `ino` - File inode number to write to.
    /// * `offset` - Byte offset within the file.
    /// * `data` - Payload byte slice to append or overwrite.
    ///
    /// # Returns
    /// Number of bytes written on success, or `Err(EFBIG)` / `Err(EISDIR)`.
    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> ZplResult<usize> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        if offset.checked_add(data.len() as u64).map_or(true, |e| e > (1u64 << 46)) {
            return Err(EFBIG);
        }
        let n = self.dmu.write(ino, offset, data).map_err(io)?;
        self.touch(ino, true, true)?;
        self.notify_file(ino, crate::compat::linux::inotify::IN_MODIFY);
        self.maybe_sync();
        Ok(n)
    }

    /// Changes attributes (chmod, chown, truncate, utimens).
    ///
    /// # Arguments
    /// * `ino` - Target inode number.
    /// * `set` - Attribute modifications to apply.
    ///
    /// # Returns
    /// Updated inode [`Attr`] descriptor on success, or an error code.
    pub fn setattr(&mut self, ino: u64, set: SetAttr) -> ZplResult<Attr> {
        let mut dn = self.dnode(ino)?;
        if let Some(size) = set.size {
            if dn.mode & S_IFMT == S_IFDIR {
                return Err(EISDIR);
            }
            self.dmu.truncate(ino, size).map_err(io)?;
            dn = self.dnode(ino)?;
            let t = now();
            dn.mtime = t.0;
            dn.mtime_ns = t.1;
        }
        if let Some(mode) = set.mode {
            dn.mode = (dn.mode & S_IFMT) | (mode & 0o7777);
        }
        if let Some(uid) = set.uid {
            dn.uid = uid;
        }
        if let Some(gid) = set.gid {
            dn.gid = gid;
        }
        if let Some((s, ns)) = set.atime {
            dn.atime = s;
            dn.atime_ns = ns;
        }
        if let Some((s, ns)) = set.mtime {
            dn.mtime = s;
            dn.mtime_ns = ns;
        }
        let t = now();
        dn.ctime = t.0;
        dn.ctime_ns = t.1;
        self.dmu.put_dnode(ino, dn);
        // Truncation is a modification; ownership, mode and time changes are attributes
        self.notify_file(ino, if set.size.is_some() { crate::compat::linux::inotify::IN_MODIFY } else { crate::compat::linux::inotify::IN_ATTRIB });
        self.getattr(ino)
    }

    /// Lists a directory from `cookie` (0 starts with `.`, 1 is `..`).
    ///
    /// # Arguments
    /// * `dir` - Directory inode number.
    /// * `cookie` - Cursor position token.
    /// * `max` - Maximum number of entries to return.
    ///
    /// # Returns
    /// Vector of [`ReaddirEntry`] items on success, or an error code.
    pub fn readdir(&mut self, dir: u64, cookie: u64, max: usize) -> ZplResult<Vec<ReaddirEntry>> {
        let dn = self.dir_dnode(dir)?;
        let mut out = Vec::new();
        if cookie == 0 && out.len() < max {
            out.push(ReaddirEntry { name: b".".to_vec(), ino: dir, dtype: DT_DIR, next_cookie: 1 });
        }
        if cookie <= 1 && out.len() < max {
            let parent = if dn.parent != 0 { dn.parent } else { dir };
            out.push(ReaddirEntry { name: b"..".to_vec(), ino: parent, dtype: DT_DIR, next_cookie: 2 });
        }
        if out.len() < max {
            let from = cookie.saturating_sub(2);
            let entries = self.zap.readdir(&mut self.dmu, dir, from, max - out.len()).map_err(io)?;
            for e in entries {
                out.push(ReaddirEntry { name: e.name, ino: e.ino, dtype: e.dtype, next_cookie: e.next_pos + 2 });
            }
        }
        Ok(out)
    }

    /// Records an open handle on `ino` (keeps unlinked files alive until closed).
    ///
    /// # Arguments
    /// * `ino` - Inode number being opened.
    pub fn open_ref(&mut self, ino: u64) {
        *self.open_counts.entry(ino).or_insert(0) += 1;
    }

    /// Releases an open handle, freeing the inode if it was unlinked meanwhile.
    ///
    /// # Arguments
    /// * `ino` - Inode number whose open handle count is decremented.
    pub fn release(&mut self, ino: u64) {
        if let Some(c) = self.open_counts.get_mut(&ino) {
            *c -= 1;
            if *c == 0 {
                self.open_counts.remove(&ino);
                if self.orphans.remove(&ino) {
                    let _ = self.dmu.free_object(ino);
                }
            }
        }
    }

    /// Pool usage: (total blocks, free blocks, objects in use).
    ///
    /// # Returns
    /// 3-tuple of `(total_blocks, free_blocks, objects_in_use)`.
    pub fn statfs(&self) -> (u64, u64, u64) {
        let total = self.dmu.spa.label.total_blocks;
        let free = total.saturating_sub(self.dmu.spa.allocated_blocks);
        (total, free, self.dmu.ub.next_obj)
    }
}
