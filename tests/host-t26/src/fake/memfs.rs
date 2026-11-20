//! An in-memory pool: what the ZFS file server keeps (directories, files, symbolic links,
//! device and FIFO nodes, extended attributes), with its errors. Inode numbers are unique
//! across the whole test binary (the code under test caches by inode), and every change
//! moves the change time forward.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::cell::RefCell;

use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

pub const ENOENT: i64 = -2;
pub const EIO: i64 = -5;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EPERM: i64 = -1;
pub const ENOTEMPTY: i64 = -39;
pub const ENODATA: i64 = -61;
pub const ELOOP: i64 = -40;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

pub enum Kind {
    Dir(BTreeMap<Vec<u8>, u64>),
    File(Vec<u8>),
    Link(Vec<u8>),
    /// Device, FIFO or socket node.
    Node,
}

pub struct Inode {
    pub attr: Attr,
    pub kind: Kind,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// The directory it was made in (for `..`).
    pub parent: u64,
}

#[derive(Default)]
pub struct MemFs {
    pub inodes: BTreeMap<u64, Inode>,
    pub root: u64,
    /// `open_ref` minus `release` per inode.
    pub refs: BTreeMap<u64, i64>,
    /// Operations that fail with an errno (`"create"`, `"getattr"`, `"setxattr"`...).
    pub fail: BTreeMap<&'static str, i64>,
}

static NEXT_INO: AtomicU64 = AtomicU64::new(1000);
static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);

fn now() -> (i64, u32) {
    (CLOCK.fetch_add(1, Ordering::Relaxed), 0)
}

thread_local! {
    pub static FS: RefCell<MemFs> = RefCell::new(MemFs::default());
}

pub fn reset() {
    FS.with_borrow_mut(|fs| {
        *fs = MemFs::default();
        let root = fs.alloc(S_IFDIR | 0o755, 0, 0, Kind::Dir(BTreeMap::new()), 0);
        fs.inodes.get_mut(&root).unwrap().parent = root;
        fs.root = root;
    });
}

/// Runs `f` on the pool.
pub fn with<R>(f: impl FnOnce(&mut MemFs) -> R) -> R {
    FS.with_borrow_mut(f)
}

/// The pool's root directory.
pub fn root() -> u64 {
    with(|fs| fs.root)
}

/// Makes operation `op` fail with `errno` (0: works again).
pub fn fail(op: &'static str, errno: i64) {
    with(|fs| {
        if errno == 0 {
            fs.fail.remove(op);
        } else {
            fs.fail.insert(op, errno);
        }
    });
}

/// The injected error of `op`, if any.
pub fn failing(op: &'static str) -> Result<(), i64> {
    with(|fs| fs.fail.get(op).map_or(Ok(()), |&e| Err(e)))
}

impl MemFs {
    fn alloc(&mut self, mode: u32, uid: u32, gid: u32, kind: Kind, parent: u64) -> u64 {
        let ino = NEXT_INO.fetch_add(1, Ordering::Relaxed);
        let t = now();
        let attr = Attr { ino, mode, nlink: 1, uid, gid, atime: t, mtime: t, ctime: t, generation: 1, ..Attr::default() };
        self.inodes.insert(ino, Inode { attr, kind, xattrs: BTreeMap::new(), parent });
        ino
    }

    pub fn node(&self, ino: u64) -> Result<&Inode, i64> {
        self.inodes.get(&ino).ok_or(ENOENT)
    }

    fn node_mut(&mut self, ino: u64) -> Result<&mut Inode, i64> {
        self.inodes.get_mut(&ino).ok_or(ENOENT)
    }

    fn children(&self, dir: u64) -> Result<&BTreeMap<Vec<u8>, u64>, i64> {
        match &self.node(dir)?.kind {
            Kind::Dir(c) => Ok(c),
            _ => Err(ENOTDIR),
        }
    }

    fn children_mut(&mut self, dir: u64) -> Result<&mut BTreeMap<Vec<u8>, u64>, i64> {
        match &mut self.node_mut(dir)?.kind {
            Kind::Dir(c) => Ok(c),
            _ => Err(ENOTDIR),
        }
    }

    fn touch(&mut self, ino: u64) {
        if let Some(n) = self.inodes.get_mut(&ino) {
            n.attr.ctime = now();
            n.attr.mtime = n.attr.ctime;
        }
    }

    pub fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64, i64> {
        let c = self.children(dir)?;
        match name {
            b"" | b"." => Ok(dir),
            b".." => Ok(self.node(dir)?.parent),
            n => c.get(n).copied().ok_or(ENOENT),
        }
    }

    pub fn getattr(&self, ino: u64) -> Result<Attr, i64> {
        let n = self.node(ino)?;
        let mut a = n.attr;
        a.has_xattr = !n.xattrs.is_empty();
        a.size = match &n.kind {
            Kind::File(d) => d.len() as u64,
            Kind::Link(t) => t.len() as u64,
            Kind::Dir(c) => 2 + c.len() as u64,
            Kind::Node => 0,
        };
        a.blocks = a.size.div_ceil(512);
        Ok(a)
    }

    pub fn setattr(&mut self, ino: u64, set: SetAttr) -> Result<Attr, i64> {
        let n = self.node_mut(ino)?;
        if let Some(m) = set.mode {
            n.attr.mode = (n.attr.mode & S_IFMT) | (m & 0o7777);
        }
        if let Some(u) = set.uid {
            n.attr.uid = u;
        }
        if let Some(g) = set.gid {
            n.attr.gid = g;
        }
        if let Some(s) = set.size {
            match &mut n.kind {
                Kind::File(d) => d.resize(s as usize, 0),
                Kind::Dir(_) => return Err(EISDIR),
                _ => return Err(EINVAL),
            }
        }
        if let Some(t) = set.atime {
            n.attr.atime = t;
        }
        if let Some(t) = set.mtime {
            n.attr.mtime = t;
        }
        if set.kill_suid && n.attr.mode & S_IFMT != S_IFDIR {
            n.attr.mode &= !0o4000;
            if n.attr.mode & 0o010 != 0 {
                n.attr.mode &= !0o2000;
            }
        }
        n.attr.ctime = now();
        self.getattr(ino)
    }

    fn add(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, kind: Kind) -> Result<u64, i64> {
        if self.children(dir)?.contains_key(name) || name == b"." || name == b".." {
            return Err(EEXIST);
        }
        let is_dir = matches!(kind, Kind::Dir(_));
        let ino = self.alloc(mode, uid, gid, kind, dir);
        if is_dir {
            self.inodes.get_mut(&ino).unwrap().attr.nlink = 2;
        }
        self.children_mut(dir)?.insert(name.to_vec(), ino);
        self.touch(dir);
        Ok(ino)
    }

    pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        self.add(dir, name, S_IFREG | (perm & 0o7777), uid, gid, Kind::File(Vec::new()))
    }

    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> Result<u64, i64> {
        let kind = if mode & S_IFMT == S_IFREG || mode & S_IFMT == 0 { Kind::File(Vec::new()) } else { Kind::Node };
        let mode = if mode & S_IFMT == 0 { mode | S_IFREG } else { mode };
        let ino = self.add(dir, name, mode, uid, gid, kind)?;
        self.inodes.get_mut(&ino).unwrap().attr.rdev = rdev;
        Ok(ino)
    }

    pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        self.add(dir, name, S_IFDIR | (perm & 0o7777), uid, gid, Kind::Dir(BTreeMap::new()))
    }

    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64, i64> {
        self.add(dir, name, S_IFLNK | 0o777, uid, gid, Kind::Link(target.to_vec()))
    }

    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
        if matches!(self.node(ino)?.kind, Kind::Dir(_)) {
            return Err(EPERM);
        }
        if self.children(dir)?.contains_key(name) {
            return Err(EEXIST);
        }
        self.children_mut(dir)?.insert(name.to_vec(), ino);
        let n = self.node_mut(ino)?;
        n.attr.nlink += 1;
        n.attr.ctime = now();
        Ok(())
    }

    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        let ino = *self.children(dir)?.get(name).ok_or(ENOENT)?;
        if matches!(self.node(ino)?.kind, Kind::Dir(_)) {
            return Err(EISDIR);
        }
        self.children_mut(dir)?.remove(name);
        self.touch(dir);
        let n = self.node_mut(ino)?;
        n.attr.nlink = n.attr.nlink.saturating_sub(1);
        n.attr.ctime = now();
        Ok(())
    }

    pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        let ino = *self.children(dir)?.get(name).ok_or(ENOENT)?;
        match &self.node(ino)?.kind {
            Kind::Dir(c) if !c.is_empty() => return Err(ENOTEMPTY),
            Kind::Dir(_) => {}
            _ => return Err(ENOTDIR),
        }
        self.children_mut(dir)?.remove(name);
        self.touch(dir);
        self.node_mut(ino)?.attr.nlink = 0;
        Ok(())
    }

    pub fn rename(&mut self, sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
        let src = *self.children(sdir)?.get(sname).ok_or(ENOENT)?;
        self.children(ddir)?;
        let src_dir = matches!(self.node(src)?.kind, Kind::Dir(_));
        if let Some(&dst) = self.children(ddir)?.get(dname) {
            if dst == src {
                return Ok(());
            }
            match (&self.node(dst)?.kind, src_dir) {
                (Kind::Dir(c), true) if !c.is_empty() => return Err(ENOTEMPTY),
                (Kind::Dir(_), false) => return Err(EISDIR),
                (_, true) if !matches!(self.node(dst)?.kind, Kind::Dir(_)) => return Err(ENOTDIR),
                _ => {}
            }
            self.node_mut(dst)?.attr.nlink = 0;
        }
        self.children_mut(sdir)?.remove(sname);
        self.children_mut(ddir)?.insert(dname.to_vec(), src);
        self.node_mut(src)?.parent = ddir;
        self.touch(sdir);
        self.touch(ddir);
        Ok(())
    }

    /// Cookie 0 is `.`, 1 `..`, then the entries in name order from 2.
    pub fn readdir(&self, dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
        let c = self.children(dir)?;
        let parent = self.node(dir)?.parent;
        let mut all: Vec<(Vec<u8>, u64)> = alloc::vec![(b".".to_vec(), dir), (b"..".to_vec(), parent)];
        all.extend(c.iter().map(|(n, &i)| (n.clone(), i)));
        let mut out = Vec::new();
        for (i, (name, ino)) in all.into_iter().enumerate().skip(cookie as usize) {
            if out.len() >= max {
                break;
            }
            let dtype = crate::fs::zfs::types::dtype_from_mode(self.node(ino).map(|n| n.attr.mode).unwrap_or(0));
            out.push(ReaddirEntry { name, ino, dtype, next_cookie: i as u64 + 1 });
        }
        Ok(out)
    }

    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, i64> {
        match &self.node(ino)?.kind {
            Kind::Link(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }

    pub fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        match &self.node(ino)?.kind {
            Kind::File(d) => {
                let start = (offset as usize).min(d.len());
                let n = buf.len().min(d.len() - start);
                buf[..n].copy_from_slice(&d[start..start + n]);
                Ok(n)
            }
            Kind::Dir(_) => Err(EISDIR),
            _ => Err(EINVAL),
        }
    }

    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        let n = self.node_mut(ino)?;
        match &mut n.kind {
            Kind::File(d) => {
                let end = offset as usize + data.len();
                if d.len() < end {
                    d.resize(end, 0);
                }
                d[offset as usize..end].copy_from_slice(data);
            }
            Kind::Dir(_) => return Err(EISDIR),
            _ => return Err(EINVAL),
        }
        n.attr.mtime = now();
        Ok(data.len())
    }

    pub fn getxattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
        self.node(ino)?.xattrs.get(name).cloned().ok_or(ENODATA)
    }

    pub fn setxattr(&mut self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
        let n = self.node_mut(ino)?;
        let exists = n.xattrs.contains_key(name);
        if flags & 1 != 0 && exists {
            return Err(EEXIST);
        }
        if flags & 2 != 0 && !exists {
            return Err(ENODATA);
        }
        n.xattrs.insert(name.to_vec(), value.to_vec());
        n.attr.ctime = now();
        Ok(())
    }

    pub fn listxattr(&self, ino: u64) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        for k in self.node(ino)?.xattrs.keys() {
            out.extend_from_slice(k);
            out.push(0);
        }
        Ok(out)
    }

    pub fn removexattr(&mut self, ino: u64, name: &[u8]) -> Result<(), i64> {
        let n = self.node_mut(ino)?;
        n.xattrs.remove(name).ok_or(ENODATA)?;
        n.attr.ctime = now();
        Ok(())
    }
}

// --------------------------------------------------------------- test helpers

fn split_path(path: &str) -> (Vec<&str>, &str) {
    let mut comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let last = comps.pop().unwrap_or("");
    (comps, last)
}

/// Makes directory `path` and its parents (owned by root, mode 0755); returns its inode.
pub fn mkdir_p(path: &str) -> u64 {
    with(|fs| {
        let mut cur = fs.root;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            cur = match fs.lookup(cur, c.as_bytes()) {
                Ok(i) => i,
                Err(_) => fs.mkdir(cur, c.as_bytes(), 0o755, 0, 0).unwrap(),
            };
        }
        cur
    })
}

fn parent_of(path: &str) -> (u64, String) {
    let (dirs, last) = split_path(path);
    (mkdir_p(&dirs.join("/")), String::from(last))
}

/// Makes regular file `path` (mode 0644, root's) holding `data`; returns its inode.
pub fn mkfile(path: &str, data: &[u8]) -> u64 {
    let (dir, name) = parent_of(path);
    with(|fs| {
        let ino = fs.create(dir, name.as_bytes(), 0o644, 0, 0).unwrap();
        fs.write(ino, 0, data).unwrap();
        ino
    })
}

/// Makes symbolic link `path` to `target`; returns its inode.
pub fn mklink(path: &str, target: &str) -> u64 {
    let (dir, name) = parent_of(path);
    with(|fs| fs.symlink(dir, name.as_bytes(), target.as_bytes(), 0, 0).unwrap())
}

/// Makes a device, FIFO or socket node `path` of `mode` (with type bits); returns its inode.
pub fn mknode(path: &str, mode: u32, rdev: u64) -> u64 {
    let (dir, name) = parent_of(path);
    with(|fs| fs.mknod(dir, name.as_bytes(), mode, rdev, 0, 0).unwrap())
}

/// The inode at absolute `path` (symbolic links not followed), if any.
pub fn lookup(path: &str) -> Option<u64> {
    with(|fs| {
        let mut cur = fs.root;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            cur = fs.lookup(cur, c.as_bytes()).ok()?;
        }
        Some(cur)
    })
}

/// Sets the permission bits of `ino`.
pub fn chmod(ino: u64, perm: u32) {
    with(|fs| {
        let a = &mut fs.inodes.get_mut(&ino).unwrap().attr;
        a.mode = (a.mode & S_IFMT) | perm;
    });
}

/// Sets the owner of `ino`.
pub fn chown(ino: u64, uid: u32, gid: u32) {
    with(|fs| {
        let a = &mut fs.inodes.get_mut(&ino).unwrap().attr;
        (a.uid, a.gid) = (uid, gid);
    });
}

/// The attributes of `ino` (panics if it is gone).
pub fn attr(ino: u64) -> Attr {
    with(|fs| fs.getattr(ino).unwrap())
}

/// The contents of regular file `ino`.
pub fn data(ino: u64) -> Vec<u8> {
    with(|fs| match &fs.inodes[&ino].kind {
        Kind::File(d) => d.clone(),
        _ => panic!("not a file"),
    })
}

/// Extended attribute `name` of `ino`.
pub fn xattr(ino: u64, name: &[u8]) -> Option<Vec<u8>> {
    with(|fs| fs.getxattr(ino, name).ok())
}

/// Sets extended attribute `name` of `ino`.
pub fn set_xattr(ino: u64, name: &[u8], value: &[u8]) {
    with(|fs| fs.setxattr(ino, name, value, 0).unwrap());
}

/// `open_ref` minus `release` for `ino`.
pub fn refs(ino: u64) -> i64 {
    with(|fs| fs.refs.get(&ino).copied().unwrap_or(0))
}
