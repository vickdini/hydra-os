//! # ZFS POSIX Layer (ZPL)
//!
//! Inode-level POSIX file operations on top of the DMU and directory layer, returning
//! Linux errno values (negative) on failure. Path walking, mount points and permission
//! checks belong to the VFS above; the ZPL works on inode numbers and single names.

use alloc::vec::Vec;

use super::server::ZfsServer;
use super::spa::BLOCK;
use super::types::*;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EIO: i64 = -5;
pub const EEXIST: i64 = -17;
pub const EXDEV: i64 = -18;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EFBIG: i64 = -27;
pub const ENOSPC: i64 = -28;
pub const EMLINK: i64 = -31;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOTEMPTY: i64 = -39;

pub type ZplResult<T> = Result<T, i64>;

fn io(e: &'static str) -> i64 {
    if e.contains("out of space") {
        ENOSPC
    } else {
        EIO
    }
}

/// Attributes of an inode (the fields of Linux `struct stat`).
#[derive(Debug, Clone, Copy)]
pub struct Attr {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    /// Allocated size in 512-byte units.
    pub blocks: u64,
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    pub generation: u64,
    pub birth_txg: u64,
}

impl Attr {
    pub fn kind(&self) -> DnodeType {
        DnodeType::from_mode(self.mode)
    }

    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// Attribute changes for [`ZfsServer::setattr`]; `None` leaves a field unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<(i64, u32)>,
    pub mtime: Option<(i64, u32)>,
}

/// One entry returned by [`ZfsServer::readdir`].
pub struct ReaddirEntry {
    pub name: Vec<u8>,
    pub ino: u64,
    pub dtype: u8,
    /// Cookie to pass to `readdir` to continue after this entry.
    pub next_cookie: u64,
}

fn now() -> (i64, u32) {
    let (s, ns) = crate::arch::rtc::now();
    (s as i64, ns)
}

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
    fn dnode(&mut self, ino: u64) -> ZplResult<DnodePhys> {
        let dn = self.dmu.get_dnode(ino).map_err(|_| ENOENT)?;
        if dn.mode == 0 {
            return Err(ENOENT);
        }
        Ok(dn)
    }

    fn dir_dnode(&mut self, ino: u64) -> ZplResult<DnodePhys> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(dn)
    }

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
    fn make_node(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, rdev: u64) -> ZplResult<u64> {
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
        self.maybe_sync();
        Ok(ino)
    }

    /// Creates a regular file.
    pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> ZplResult<u64> {
        self.make_node(dir, name, S_IFREG | (perm & 0o7777), uid, gid, 0)
    }

    /// Creates a device node, FIFO, socket or regular file from a full `st_mode`.
    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> ZplResult<u64> {
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        if mode & S_IFMT == S_IFDIR || mode & S_IFMT == S_IFLNK {
            return Err(EINVAL);
        }
        self.make_node(dir, name, mode, uid, gid, rdev)
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> ZplResult<u64> {
        let ino = self.make_node(dir, name, S_IFDIR | (perm & 0o7777), uid, gid, 0)?;
        let mut parent = self.dnode(dir)?;
        parent.nlink += 1;
        self.dmu.put_dnode(dir, parent);
        Ok(ino)
    }

    /// Creates a symbolic link pointing at `target`.
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
        self.touch(dir, true, true)
    }

    /// Drops one link to `ino`, freeing it when no links and no open handles remain.
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
    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> ZplResult<()> {
        let ino = self.lookup(dir, name)?;
        if self.dnode(ino)?.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        self.zap.remove(&mut self.dmu, dir, name).map_err(io)?;
        self.touch(dir, true, true)?;
        self.drop_link(ino)?;
        self.maybe_sync();
        Ok(())
    }

    /// Removes an empty directory.
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
        self.drop_link(ino)
    }

    /// Renames `sdir/sname` to `ddir/dname`, replacing a compatible existing target.
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
        self.maybe_sync();
        Ok(())
    }

    /// Reads file data at `offset`.
    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> ZplResult<usize> {
        let dn = self.dnode(ino)?;
        if dn.mode & S_IFMT == S_IFDIR {
            return Err(EISDIR);
        }
        self.dmu.read(ino, offset, buf).map_err(io)
    }

    /// Writes file data at `offset`.
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
        self.maybe_sync();
        Ok(n)
    }

    /// Changes attributes (chmod, chown, truncate, utimens).
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
        self.getattr(ino)
    }

    /// Lists a directory from `cookie` (0 starts with `.`, 1 is `..`).
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
    pub fn open_ref(&mut self, ino: u64) {
        *self.open_counts.entry(ino).or_insert(0) += 1;
    }

    /// Releases an open handle, freeing the inode if it was unlinked meanwhile.
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
    pub fn statfs(&self) -> (u64, u64, u64) {
        let total = self.dmu.spa.label.total_blocks;
        let free = total.saturating_sub(self.dmu.spa.allocated_blocks);
        (total, free, self.dmu.ub.next_obj)
    }
}
