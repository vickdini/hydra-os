//! *stub* `crate::fs::zfs::ZfsServer`: the file server's operations on the in-memory pool
//! ([`crate::fake::memfs`]), with its path walk (symbolic links, `..` kept inside the root,
//! mount tables) and, like the kernel's client, every operation on a FUSE inode sent to
//! `fuse.rs`.

use alloc::vec::Vec;
use std::cell::Cell;

use crate::compat::linux::fuse;
use crate::fake::memfs::{self, Kind, ELOOP, ENOENT, ENOTDIR};
use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

const EIO: i64 = -5;
const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;

thread_local! {
    /// Whether the file server is running.
    pub static UP: Cell<bool> = const { Cell::new(true) };
}

pub fn reset() {
    UP.set(true);
}

/// The file server, as the kernel calls it.
pub struct ZfsServer;

/// Runs `f` with the file server, or fails with `EIO` when it is down.
pub fn with_server<R>(f: impl FnOnce(&mut ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
    if !UP.get() {
        return Err(EIO);
    }
    f(&mut ZfsServer)
}

/// Where a walk through the pool stopped.
enum Step {
    Done(u64, usize),
    /// Entered a FUSE mount's root `(root, mount)` with the rest of the path.
    Fuse(u64, usize, Vec<u8>),
}

fn join(stack: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in stack.iter().rev() {
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

/// The server's walk of `path` from `(cur, mnt)` through the pool, crossing the mounts
/// of `mounts` (`(mountpoint, root, parent mount)`, 1-based) and collecting in `dirs` the
/// directories walked through that not everyone may search.
#[allow(clippy::too_many_arguments)]
fn walk_pool(root: u64, root_mnt: usize, cur: u64, mnt: usize, path: &[u8], follow: bool, mounts: &[(u64, u64, usize)], dirs: &mut Vec<u64>, links: &mut u32) -> Result<Step, i64> {
    let (mut cur, mut mnt) = if path.first() == Some(&b'/') { (root, root_mnt) } else { (cur, mnt) };
    let mut stack: Vec<Vec<u8>> = path.split(|&b| b == b'/').map(|c| c.to_vec()).collect();
    stack.reverse();
    while let Some(c) = stack.pop() {
        if c.is_empty() || c == b"." {
            continue;
        }
        if c == b".." {
            if (cur, mnt) == (root, root_mnt) {
                continue;
            }
            if mnt != 0 && mounts.get(mnt - 1).is_some_and(|m| m.1 == cur) {
                let m = mounts[mnt - 1];
                (cur, mnt) = (m.0, m.2);
                stack.push(c);
                if fuse::is_fuse(cur) {
                    return Ok(Step::Fuse(cur, mnt, join(&stack)));
                }
                continue;
            }
            cur = memfs::with(|fs| fs.lookup(cur, b".."))?;
            continue;
        }
        let dattr = memfs::with(|fs| fs.getattr(cur))?;
        if dattr.mode & S_IFMT != 0o040000 {
            return Err(ENOTDIR);
        }
        if dattr.mode & 0o111 != 0o111 && !dirs.contains(&cur) {
            dirs.push(cur);
        }
        let next = memfs::with(|fs| fs.lookup(cur, &c))?;
        let last = stack.iter().all(|r| r.is_empty() || r == b".");
        let target = memfs::with(|fs| match &fs.node(next)?.kind {
            Kind::Link(t) => Ok(Some(t.clone())),
            _ => Ok::<_, i64>(None),
        })?;
        if let Some(t) = target {
            if !last || follow || stack.iter().any(|r| r.is_empty()) {
                *links += 1;
                if *links > 40 {
                    return Err(ELOOP);
                }
                let mut more: Vec<Vec<u8>> = t.split(|&b| b == b'/').map(|c| c.to_vec()).collect();
                more.reverse();
                stack.extend(more);
                if t.first() == Some(&b'/') {
                    (cur, mnt) = (root, root_mnt);
                }
                continue;
            }
        }
        let (mut n, mut m) = (next, mnt);
        for _ in 0..=mounts.len() {
            match mounts.iter().rposition(|x| x.0 == n && x.2 == m) {
                Some(i) => {
                    n = mounts[i].1;
                    m = i + 1;
                }
                None => break,
            }
        }
        if fuse::is_fuse(n) {
            return Ok(Step::Fuse(n, m, join(&stack)));
        }
        (cur, mnt) = (n, m);
    }
    Ok(Step::Done(cur, mnt))
}

impl ZfsServer {
    pub fn root_obj(&self) -> u64 {
        memfs::root()
    }

    pub fn lookup(&mut self, dir: u64, name: &[u8]) -> Result<u64, i64> {
        if fuse::is_fuse(dir) {
            return fuse::lookup(dir, name);
        }
        memfs::failing("lookup")?;
        memfs::with(|fs| fs.lookup(dir, name))
    }

    pub fn resolve_in(&mut self, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<u64, i64> {
        self.resolve_in_dirs(root, base, path, follow_last).map(|r| r.0)
    }

    pub fn resolve_in_dirs(&mut self, root: u64, base: u64, path: &[u8], follow_last: bool) -> Result<(u64, Vec<u64>), i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        memfs::failing("resolve")?;
        if fuse::ns0_any() || fuse::is_fuse(base) || fuse::is_fuse(root) {
            let list = fuse::ns0_list();
            return self.resolve_mnt(root, fuse::ns0_mnt_of(root), base, fuse::ns0_mnt_of(base), path, follow_last, &list).map(|r| (r.0, Vec::new()));
        }
        let mut dirs = Vec::new();
        let mut links = 0;
        let follow = follow_last || path.ends_with(b"/");
        match walk_pool(root, 0, base, 0, path, follow, &[], &mut dirs, &mut links)? {
            Step::Done(i, _) => {
                self.trailing_dir(path, (i, 0))?;
                Ok((i, dirs))
            }
            Step::Fuse(..) => Err(EIO),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resolve_mnt(&mut self, root: u64, root_mnt: usize, base: u64, base_mnt: usize, path: &[u8], follow_last: bool, mounts: &[(u64, u64, usize)]) -> Result<(u64, usize), i64> {
        if path.is_empty() {
            return Err(ENOENT);
        }
        let follow = follow_last || path.ends_with(b"/");
        let (mut cur, mut mnt) = if path[0] == b'/' { (root, root_mnt) } else { (base, base_mnt) };
        let mut rest = path.to_vec();
        let mut links = 0u32;
        let mut dirs = Vec::new();
        for _ in 0..64 {
            let stopped = if fuse::is_fuse(cur) {
                match fuse::walk(cur, mnt, &rest, follow, mounts, root, root_mnt, &mut links)? {
                    fuse::Walk::Done(i, m) => return self.trailing_dir(path, (i, m)),
                    fuse::Walk::Out(i, m, r) => (i, m, r),
                }
            } else {
                match walk_pool(root, root_mnt, cur, mnt, &rest, follow, mounts, &mut dirs, &mut links)? {
                    Step::Done(i, m) => return self.trailing_dir(path, (i, m)),
                    Step::Fuse(i, m, r) => (i, m, r),
                }
            };
            (cur, mnt, rest) = stopped;
            if rest.is_empty() {
                return self.trailing_dir(path, (cur, mnt));
            }
        }
        Err(ELOOP)
    }

    fn trailing_dir(&mut self, path: &[u8], found: (u64, usize)) -> Result<(u64, usize), i64> {
        if path.ends_with(b"/") && !self.getattr(found.0)?.is_dir() {
            return Err(ENOTDIR);
        }
        Ok(found)
    }

    pub fn getattr(&mut self, ino: u64) -> Result<Attr, i64> {
        if fuse::is_fuse(ino) {
            return fuse::getattr(ino);
        }
        memfs::failing("getattr")?;
        memfs::with(|fs| fs.getattr(ino))
    }

    pub fn setattr(&mut self, ino: u64, set: SetAttr) -> Result<Attr, i64> {
        if fuse::is_fuse(ino) {
            return fuse::setattr(ino, set);
        }
        memfs::failing("setattr")?;
        crate::fake::count("setattr");
        memfs::with(|fs| fs.setattr(ino, set))
    }

    pub fn read(&mut self, ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        if fuse::is_fuse(ino) {
            return fuse::read(ino, offset, buf);
        }
        memfs::with(|fs| fs.read(ino, offset, buf))
    }

    pub fn write(&mut self, ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        if fuse::is_fuse(ino) {
            return fuse::write(ino, offset, data);
        }
        memfs::with(|fs| fs.write(ino, offset, data))
    }

    pub fn create(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        if fuse::is_fuse(dir) {
            return fuse::create(dir, name, perm);
        }
        memfs::failing("create")?;
        memfs::with(|fs| fs.create(dir, name, perm, uid, gid))
    }

    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32) -> Result<u64, i64> {
        if fuse::is_fuse(dir) {
            return fuse::mknod(dir, name, mode, rdev);
        }
        memfs::failing("mknod")?;
        memfs::with(|fs| fs.mknod(dir, name, mode, rdev, uid, gid))
    }

    pub fn mkdir(&mut self, dir: u64, name: &[u8], perm: u32, uid: u32, gid: u32) -> Result<u64, i64> {
        if fuse::is_fuse(dir) {
            return fuse::mkdir(dir, name, perm);
        }
        memfs::failing("mkdir")?;
        memfs::with(|fs| fs.mkdir(dir, name, perm, uid, gid))
    }

    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32) -> Result<u64, i64> {
        if fuse::is_fuse(dir) {
            return fuse::symlink(dir, name, target);
        }
        memfs::with(|fs| fs.symlink(dir, name, target, uid, gid))
    }

    pub fn getxattr(&mut self, ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
        if fuse::is_fuse(ino) {
            return fuse::getxattr(ino, name);
        }
        memfs::with(|fs| fs.getxattr(ino, name))
    }

    pub fn setxattr(&mut self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
        if fuse::is_fuse(ino) {
            return fuse::setxattr(ino, name, value, flags);
        }
        memfs::failing("setxattr")?;
        memfs::with(|fs| fs.setxattr(ino, name, value, flags))
    }

    pub fn listxattr(&mut self, ino: u64) -> Result<Vec<u8>, i64> {
        if fuse::is_fuse(ino) {
            return fuse::listxattr(ino);
        }
        memfs::with(|fs| fs.listxattr(ino))
    }

    pub fn removexattr(&mut self, ino: u64, name: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(ino) {
            return fuse::removexattr(ino, name);
        }
        memfs::failing("removexattr")?;
        memfs::with(|fs| fs.removexattr(ino, name))
    }

    pub fn readlink(&mut self, ino: u64) -> Result<Vec<u8>, i64> {
        if fuse::is_fuse(ino) {
            return fuse::readlink(ino);
        }
        memfs::with(|fs| fs.readlink(ino))
    }

    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(ino) || fuse::is_fuse(dir) {
            return fuse::link(ino, dir, name);
        }
        memfs::with(|fs| fs.link(ino, dir, name))
    }

    pub fn unlink(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(dir) {
            return fuse::unlink(dir, name);
        }
        memfs::failing("unlink")?;
        memfs::with(|fs| fs.unlink(dir, name))
    }

    pub fn rmdir(&mut self, dir: u64, name: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(dir) {
            return fuse::rmdir(dir, name);
        }
        memfs::with(|fs| fs.rmdir(dir, name))
    }

    pub fn rename(&mut self, sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
        if fuse::is_fuse(sdir) || fuse::is_fuse(ddir) {
            return fuse::rename(sdir, sname, ddir, dname);
        }
        memfs::with(|fs| fs.rename(sdir, sname, ddir, dname))
    }

    pub fn readdir(&mut self, dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
        if fuse::is_fuse(dir) {
            return fuse::readdir(dir, cookie, max);
        }
        memfs::failing("readdir")?;
        memfs::with(|fs| fs.readdir(dir, cookie, max))
    }

    /// (total blocks, free blocks, objects)
    pub fn statfs(&mut self) -> (u64, u64, u64) {
        (1_000_000, 500_000, memfs::with(|fs| fs.inodes.len() as u64))
    }

    pub fn open_ref(&mut self, ino: u64) {
        if fuse::is_fuse(ino) {
            return fuse::open_ref(ino);
        }
        memfs::with(|fs| *fs.refs.entry(ino).or_insert(0) += 1);
    }

    pub fn release(&mut self, ino: u64) {
        if fuse::is_fuse(ino) {
            return fuse::release(ino);
        }
        memfs::with(|fs| *fs.refs.entry(ino).or_insert(0) -= 1);
    }
}
