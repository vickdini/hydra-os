//! # tmpfs: a memory file system in vfs-server (wave 7, Group 7-3)
//!
//! The **directory tree** of each `tmpfs` instance lives here, in plain data structures;
//! the **file data** lives in kernel anonymous memory objects (`src/lx/mem.rs`,
//! `LX_MEM_ANON`), reached through the [`DataStore`] trait. So a regular file's pages are
//! kernel memory that a program's file handle and `mmap` can name directly, and that
//! survives a vfs-server restart; the tree survives it through [`Tmpfs::encode`] in the
//! kept-state object (Group 7-6, decision 21).
//!
//! Everything here is pure: no system calls, no clock (each change takes `now`), no
//! permission policy (owner, mode and ACL checks are the caller's, as for every back end;
//! what is the file system's own — set-group-ID directories, the sticky bit's *storage*,
//! link counts, `ENOSPC` — is here).
//!
//! - Inode numbers are never reused within an instance (the root is 1, as on Linux).
//! - Directory listings: each entry gets a sequence number when it is made; a
//!   `getdents64` cookie is "after sequence N", so listings stay stable while entries come
//!   and go (0 = `.`, 1 = `..`, then entries from 2 up).
//! - A removed file whose handles are still open lives on until the last
//!   [`Tmpfs::release`] (as on Linux).
//! - Limits: `size=` (bytes of file data, counted in pages), `nr_inodes=`, 255-byte names,
//!   1 GiB per file (the largest memory object, `LX_MEM_MAX`). Unlike Linux, a file is
//!   charged for its whole size, holes included (the server does not see which pages
//!   exist): a sparse file can hit `ENOSPC` earlier than on Linux.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::mtab::{seal, unseal, Dec, Enc};

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENFILE: i64 = -23;
pub const EFBIG: i64 = -27;
pub const ENOSPC: i64 = -28;
pub const EMLINK: i64 = -31;
pub const ERANGE: i64 = -34;
pub const E2BIG: i64 = -7;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOTEMPTY: i64 = -39;
pub const ENODATA: i64 = -61;
pub const EOPNOTSUPP: i64 = -95;

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;

pub const RENAME_NOREPLACE: u32 = 1;
pub const RENAME_EXCHANGE: u32 = 2;
pub const RENAME_WHITEOUT: u32 = 4;

pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

/// The root directory's inode number.
pub const ROOT: u64 = 1;
/// `statfs`'s `f_type`.
pub const TMPFS_MAGIC: u64 = 0x0102_1994;
pub const PAGE: u64 = 4096;
/// Largest file: the largest memory object.
pub const MAX_FILE: u64 = 1 << 30;
pub const NAME_MAX: usize = 255;
pub const LINK_MAX: u32 = 65000;
/// Linux tmpfs's directory size per entry (`BOGO_DIRENT_SIZE`).
const DIRENT_SIZE: u64 = 20;
/// Largest symbolic link target (`PATH_MAX`).
const SYMLINK_MAX: usize = 4095;
/// Largest xattr value, and all xattrs of one inode together.
const XATTR_SIZE_MAX: usize = 65536;

/// A time stamp: seconds and nanoseconds.
pub type Ts = (i64, u32);

/// File data in kernel memory objects. vfs-server's implementation makes one anonymous
/// object per file (sparse: pages appear when written); the host tests use a map.
pub trait DataStore {
    /// A new, empty (all-zero) data object; its key (never 0).
    fn create(&mut self) -> Result<u64, i64>;
    /// Writes `data` at byte `off`.
    fn write(&mut self, key: u64, off: u64, data: &[u8]) -> Result<(), i64>;
    /// Fills `buf` from byte `off` (zeros where nothing was written).
    fn read(&mut self, key: u64, off: u64, buf: &mut [u8]) -> Result<(), i64>;
    /// Bytes `[size, old)` must read as zeros again (the file shrank from `old`, or grows
    /// past `size` within the page it ended in); pages wholly past `size` may be freed.
    fn truncate(&mut self, key: u64, size: u64, old: u64) -> Result<(), i64>;
    /// The object is no longer needed.
    fn free(&mut self, key: u64);
}

/// Mount options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TmpfsOpts {
    /// The root directory's permission bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    /// Most bytes of file data (0: no limit).
    pub size: u64,
    /// Most inodes (0: no limit).
    pub nr_inodes: u64,
}

impl TmpfsOpts {
    /// Parses mount data (`size=` with `k`/`m`/`g` or `%` of `mem`, `nr_inodes=` with
    /// `k`/`m`/`g`, `mode=` octal, `uid=`, `gid=`; Linux's other options are accepted and
    /// ignored). The root belongs to the mounter `(euid, egid)` unless they say otherwise.
    /// Defaults, as on Linux: half of `mem` and half as many inodes as `mem` has pages.
    pub fn parse(data: &str, euid: u32, egid: u32, mem: u64) -> Result<TmpfsOpts, i64> {
        let mut o = TmpfsOpts { mode: 0o1777, uid: euid, gid: egid, size: mem / 2 / PAGE * PAGE, nr_inodes: mem / PAGE / 2 };
        for opt in data.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (k, v) = opt.split_once('=').unwrap_or((opt, ""));
            match k {
                "size" => {
                    o.size = if let Some(p) = v.strip_suffix('%') {
                        let pct: u64 = p.parse().map_err(|_| EINVAL)?;
                        if pct > 100 {
                            return Err(EINVAL);
                        }
                        // (0%: no limit, as `size=0`; rounded up to whole pages)
                        ((mem as u128 * pct as u128 / 100) as u64).checked_add(PAGE - 1).ok_or(EINVAL)? / PAGE * PAGE
                    } else {
                        // Rounded up to whole pages, as on Linux
                        let b = parse_size(v)?;
                        b.checked_add(PAGE - 1).ok_or(EINVAL)? / PAGE * PAGE
                    }
                }
                "nr_blocks" => o.size = parse_size(v)?.checked_mul(PAGE).ok_or(EINVAL)?,
                "nr_inodes" => o.nr_inodes = parse_size(v)?,
                "mode" => o.mode = u32::from_str_radix(v, 8).map_err(|_| EINVAL)? & 0o7777,
                "uid" => o.uid = v.parse().map_err(|_| EINVAL)?,
                "gid" => o.gid = v.parse().map_err(|_| EINVAL)?,
                _ => {} // huge=, mpol=, inode64, noswap, ...: accepted
            }
        }
        Ok(o)
    }

    /// The options as `mountinfo` shows them (Linux's order and units).
    pub fn show(&self) -> String {
        let mut s = String::new();
        if self.size != 0 {
            s.push_str(&format!("size={}k", self.size / 1024));
        }
        if self.nr_inodes != 0 {
            if !s.is_empty() {
                s.push(',');
            }
            s.push_str(&format!("nr_inodes={}", self.nr_inodes));
        }
        if !s.is_empty() {
            s.push(',');
        }
        s.push_str(&format!("mode={:03o}", self.mode));
        if self.uid != 0 {
            s.push_str(&format!(",uid={}", self.uid));
        }
        if self.gid != 0 {
            s.push_str(&format!(",gid={}", self.gid));
        }
        s
    }
}

/// A number with an optional `k`, `m`, `g` (powers of 1024) suffix.
fn parse_size(v: &str) -> Result<u64, i64> {
    let (num, mul) = match v.as_bytes().last() {
        Some(b'k' | b'K') => (&v[..v.len() - 1], 1u64 << 10),
        Some(b'm' | b'M') => (&v[..v.len() - 1], 1 << 20),
        Some(b'g' | b'G') => (&v[..v.len() - 1], 1 << 30),
        _ => (v, 1),
    };
    num.parse::<u64>().map_err(|_| EINVAL)?.checked_mul(mul).ok_or(EINVAL)
}

/// What an inode is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Dir {
        /// Name -> (inode, sequence number).
        entries: BTreeMap<Vec<u8>, (u64, u64)>,
        /// Sequence number -> name (the listing order).
        order: BTreeMap<u64, Vec<u8>>,
        next_seq: u64,
        parent: u64,
    },
    /// A regular file; `data` is its [`DataStore`] key (0: no data written yet).
    File { data: u64 },
    Symlink(Vec<u8>),
    /// A device, FIFO or socket node (what it is: the mode's type bits).
    Special,
}

/// One inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    /// Type and permission bits.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    /// Bytes (files, symbolic links); directories: [`DIRENT_SIZE`] per entry.
    pub size: u64,
    pub rdev: u64,
    pub atime: Ts,
    pub mtime: Ts,
    pub ctime: Ts,
    pub btime: Ts,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Open handles (kernel file handles hold one each; kept across a restart).
    pub open: u32,
}

/// Attributes, as the pool's `Attr` has them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub size: u64,
    /// 512-byte units.
    pub blocks: u64,
    pub atime: Ts,
    pub mtime: Ts,
    pub ctime: Ts,
    pub btime: Ts,
}

impl Attr {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
}

/// What `setattr` changes (`None`: unchanged).
#[derive(Clone, Copy, Debug, Default)]
pub struct SetAttr {
    /// Permission bits (the type bits are kept).
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<Ts>,
    pub mtime: Option<Ts>,
}

/// One directory entry of [`Tmpfs::readdir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dirent {
    pub ino: u64,
    /// The cookie that continues the listing after this entry.
    pub next: u64,
    /// `DT_*` type.
    pub dtype: u8,
    pub name: Vec<u8>,
}

/// `statfs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatFs {
    pub bsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub files: u64,
    pub ffree: u64,
    pub namelen: u64,
}

/// One `tmpfs` instance (one superblock; every mount of it shows this tree).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tmpfs {
    pub id: u32,
    pub opts: TmpfsOpts,
    /// (crate-visible for the host tests, which damage trees on purpose)
    pub(crate) nodes: BTreeMap<u64, Node>,
    next_ino: u64,
    /// Pages of file data counted against `size=`.
    used_pages: u64,
}

fn dtype(mode: u32) -> u8 {
    ((mode & S_IFMT) >> 12) as u8
}

fn check_name(name: &[u8]) -> Result<(), i64> {
    if name.is_empty() {
        return Err(ENOENT);
    }
    if name.len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    if name.contains(&b'/') || name.contains(&0) {
        return Err(EINVAL);
    }
    Ok(())
}

fn pages(size: u64) -> u64 {
    size.div_ceil(PAGE)
}

/// A file grows from `old` to `new` bytes: the rest of the page `old` ends in may hold
/// bytes a program wrote through a shared mapping past the end of the file; they must read
/// as zeros now. (Mappings never reach further pages past the end: the kernel's tmpfs
/// handles stop them there.)
fn grow_tail(store: &mut dyn DataStore, data: u64, old: u64, new: u64) -> Result<(), i64> {
    let tail_end = (old.div_ceil(PAGE) * PAGE).min(new);
    if old % PAGE != 0 && tail_end > old {
        store.truncate(data, old, tail_end)?;
    }
    Ok(())
}

impl Tmpfs {
    /// A new instance with an empty root directory.
    pub fn new(id: u32, opts: TmpfsOpts, now: Ts) -> Tmpfs {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            ROOT,
            Node {
                kind: Kind::Dir { entries: BTreeMap::new(), order: BTreeMap::new(), next_seq: 2, parent: ROOT },
                mode: S_IFDIR | opts.mode,
                uid: opts.uid,
                gid: opts.gid,
                nlink: 2,
                size: 0,
                rdev: 0,
                atime: now,
                mtime: now,
                ctime: now,
                btime: now,
                xattrs: BTreeMap::new(),
                open: 0,
            },
        );
        Tmpfs { id, opts, nodes, next_ino: ROOT + 1, used_pages: 0 }
    }

    fn node(&self, ino: u64) -> Result<&Node, i64> {
        self.nodes.get(&ino).ok_or(ENOENT)
    }

    fn node_mut(&mut self, ino: u64) -> Result<&mut Node, i64> {
        self.nodes.get_mut(&ino).ok_or(ENOENT)
    }

    /// Whether `more` pages would pass `size=` (checked arithmetic).
    fn over_limit(&self, more: u64) -> bool {
        self.opts.size != 0 && self.used_pages.checked_add(more).is_none_or(|u| u > self.opts.size / PAGE)
    }

    /// Number of inodes in use.
    pub fn inodes(&self) -> usize {
        self.nodes.len()
    }

    /// Whether any handle of this instance is open (an unmounted instance stays until
    /// then).
    pub fn has_open(&self) -> bool {
        self.nodes.values().any(|n| n.open > 0)
    }

    /// Attributes of `ino`.
    pub fn getattr(&self, ino: u64) -> Result<Attr, i64> {
        let n = self.node(ino)?;
        let blocks = match n.kind {
            Kind::File { .. } => pages(n.size) * (PAGE / 512),
            _ => 0,
        };
        Ok(Attr { ino, mode: n.mode, nlink: n.nlink, uid: n.uid, gid: n.gid, rdev: n.rdev, size: n.size, blocks, atime: n.atime, mtime: n.mtime, ctime: n.ctime, btime: n.btime })
    }

    /// The entry `name` of directory `dir` (`.` and `..` included).
    pub fn lookup(&self, dir: u64, name: &[u8]) -> Result<u64, i64> {
        let d = self.node(dir)?;
        let Kind::Dir { entries, parent, .. } = &d.kind else { return Err(ENOTDIR) };
        match name {
            b"." => Ok(dir),
            // (a removed directory's parent may be gone too)
            b".." if d.nlink == 0 && !self.nodes.contains_key(parent) => Err(ENOENT),
            b".." => Ok(*parent),
            _ => {
                if name.len() > NAME_MAX {
                    return Err(ENAMETOOLONG);
                }
                entries.get(name).map(|e| e.0).ok_or(ENOENT)
            }
        }
    }

    /// The parent directory of directory `dir` (the root is its own).
    pub fn parent(&self, dir: u64) -> Result<u64, i64> {
        self.lookup(dir, b"..")
    }

    /// Checks that `name` can be made in `dir`.
    fn can_add(&self, dir: u64, name: &[u8]) -> Result<(), i64> {
        if name == b"." || name == b".." {
            return Err(EEXIST);
        }
        check_name(name)?;
        let d = self.node(dir)?;
        let Kind::Dir { entries, .. } = &d.kind else { return Err(ENOTDIR) };
        if d.nlink == 0 {
            return Err(ENOENT); // a removed directory
        }
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        if self.opts.nr_inodes != 0 && self.nodes.len() as u64 >= self.opts.nr_inodes {
            return Err(ENOSPC);
        }
        Ok(())
    }

    /// Adds entry `name` -> `ino` to `dir` (and the directory times).
    fn add_entry(&mut self, dir: u64, name: &[u8], ino: u64, now: Ts) {
        let d = self.nodes.get_mut(&dir).expect("checked");
        if let Kind::Dir { entries, order, next_seq, .. } = &mut d.kind {
            let seq = *next_seq;
            *next_seq += 1;
            entries.insert(name.to_vec(), (ino, seq));
            order.insert(seq, name.to_vec());
        }
        d.size += DIRENT_SIZE;
        d.mtime = now;
        d.ctime = now;
    }

    /// Removes entry `name` from `dir`; its inode.
    fn remove_entry(&mut self, dir: u64, name: &[u8], now: Ts) -> Result<u64, i64> {
        let d = self.node_mut(dir)?;
        let Kind::Dir { entries, order, .. } = &mut d.kind else { return Err(ENOTDIR) };
        let (ino, seq) = entries.remove(name).ok_or(ENOENT)?;
        order.remove(&seq);
        d.size -= DIRENT_SIZE;
        d.mtime = now;
        d.ctime = now;
        Ok(ino)
    }

    /// Makes a new inode in `dir`: the owner, and the group of a set-group-ID directory
    /// (whose subdirectories inherit the bit).
    fn make(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, kind: Kind, now: Ts) -> Result<u64, i64> {
        self.can_add(dir, name)?;
        let parent = self.node(dir)?;
        let (gid, mode) = if parent.mode & S_ISGID != 0 {
            (parent.gid, if mode & S_IFMT == S_IFDIR { mode | S_ISGID } else { mode })
        } else {
            (gid, mode)
        };
        let is_dir = matches!(kind, Kind::Dir { .. });
        let size = if let Kind::Symlink(t) = &kind { t.len() as u64 } else { 0 };
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(
            ino,
            Node { kind, mode, uid, gid, nlink: if is_dir { 2 } else { 1 }, size, rdev: 0, atime: now, mtime: now, ctime: now, btime: now, xattrs: BTreeMap::new(), open: 0 },
        );
        self.add_entry(dir, name, ino, now);
        if is_dir {
            self.node_mut(dir)?.nlink += 1;
        }
        Ok(ino)
    }

    /// `mknod`/`open(O_CREAT)`: a regular file (type bits 0 or `S_IFREG`), a device, FIFO
    /// or socket node in `dir`. `mode` carries the type and permission bits (the caller
    /// applied the umask).
    #[allow(clippy::too_many_arguments)]
    pub fn mknod(&mut self, dir: u64, name: &[u8], mode: u32, rdev: u64, uid: u32, gid: u32, now: Ts) -> Result<u64, i64> {
        let (kind, mode) = match mode & S_IFMT {
            0 | S_IFREG => (Kind::File { data: 0 }, S_IFREG | (mode & 0o7777)),
            S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => (Kind::Special, mode & (S_IFMT | 0o7777)),
            S_IFDIR => return Err(EPERM),
            _ => return Err(EINVAL),
        };
        let ino = self.make(dir, name, mode, uid, gid, kind, now)?;
        if mode & S_IFMT == S_IFCHR || mode & S_IFMT == S_IFBLK {
            self.node_mut(ino)?.rdev = rdev;
        }
        Ok(ino)
    }

    /// `mkdir`.
    pub fn mkdir(&mut self, dir: u64, name: &[u8], mode: u32, uid: u32, gid: u32, now: Ts) -> Result<u64, i64> {
        if !self.is_dir(dir) {
            return Err(if self.nodes.contains_key(&dir) { ENOTDIR } else { ENOENT });
        }
        if self.node(dir)?.nlink >= LINK_MAX {
            return Err(EMLINK);
        }
        let kind = Kind::Dir { entries: BTreeMap::new(), order: BTreeMap::new(), next_seq: 2, parent: dir };
        self.make(dir, name, S_IFDIR | (mode & 0o7777), uid, gid, kind, now)
    }

    /// `symlink`.
    pub fn symlink(&mut self, dir: u64, name: &[u8], target: &[u8], uid: u32, gid: u32, now: Ts) -> Result<u64, i64> {
        if target.is_empty() {
            return Err(ENOENT);
        }
        if target.len() > SYMLINK_MAX {
            return Err(ENAMETOOLONG);
        }
        self.make(dir, name, S_IFLNK | 0o777, uid, gid, Kind::Symlink(target.to_vec()), now)
    }

    /// `readlink`.
    pub fn readlink(&self, ino: u64) -> Result<Vec<u8>, i64> {
        match &self.node(ino)?.kind {
            Kind::Symlink(t) => Ok(t.clone()),
            _ => Err(EINVAL),
        }
    }

    /// `link`: a new name for `ino` (not a directory) in `dir`.
    pub fn link(&mut self, ino: u64, dir: u64, name: &[u8], now: Ts) -> Result<(), i64> {
        let n = self.node(ino)?;
        if matches!(n.kind, Kind::Dir { .. }) {
            return Err(EPERM);
        }
        if n.nlink == 0 && n.open > 0 {
            // linkat(AT_EMPTY_PATH) of an O_TMPFILE-style removed file is allowed on
            // Linux only for O_TMPFILE; keep it simple: refuse
            return Err(ENOENT);
        }
        if n.nlink >= LINK_MAX {
            return Err(EMLINK);
        }
        // An entry does not count against nr_inodes: check the name only
        if name == b"." || name == b".." {
            return Err(EEXIST);
        }
        check_name(name)?;
        let d = self.node(dir)?;
        let Kind::Dir { entries, .. } = &d.kind else { return Err(ENOTDIR) };
        if d.nlink == 0 {
            return Err(ENOENT); // a removed directory
        }
        if entries.contains_key(name) {
            return Err(EEXIST);
        }
        self.add_entry(dir, name, ino, now);
        let n = self.node_mut(ino)?;
        n.nlink += 1;
        n.ctime = now;
        Ok(())
    }

    /// One link of `ino` is gone; frees it when no link and no handle is left.
    fn drop_link(&mut self, ino: u64, store: &mut dyn DataStore, now: Ts) {
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.nlink = n.nlink.saturating_sub(1);
            n.ctime = now;
        }
        self.maybe_free(ino, store);
    }

    fn maybe_free(&mut self, ino: u64, store: &mut dyn DataStore) {
        let gone = self.nodes.get(&ino).is_some_and(|n| n.open == 0 && n.nlink == 0);
        if !gone || ino == ROOT {
            return;
        }
        if let Some(n) = self.nodes.remove(&ino) {
            if let Kind::File { data } = n.kind {
                self.used_pages -= pages(n.size);
                if data != 0 {
                    store.free(data);
                }
            }
        }
    }

    /// `unlink` (not of a directory).
    pub fn unlink(&mut self, dir: u64, name: &[u8], store: &mut dyn DataStore, now: Ts) -> Result<(), i64> {
        let ino = self.lookup(dir, name)?;
        if name == b"." || name == b".." || matches!(self.node(ino)?.kind, Kind::Dir { .. }) {
            return Err(EISDIR);
        }
        self.remove_entry(dir, name, now)?;
        self.drop_link(ino, store, now);
        Ok(())
    }

    /// `rmdir` of an empty directory.
    pub fn rmdir(&mut self, dir: u64, name: &[u8], store: &mut dyn DataStore, now: Ts) -> Result<(), i64> {
        match name {
            b"." => return Err(EINVAL),
            b".." => return Err(ENOTEMPTY),
            _ => {}
        }
        let ino = self.lookup(dir, name)?;
        let Kind::Dir { entries, .. } = &self.node(ino)?.kind else { return Err(ENOTDIR) };
        if !entries.is_empty() {
            return Err(ENOTEMPTY);
        }
        self.remove_entry(dir, name, now)?;
        self.node_mut(dir)?.nlink -= 1;
        let n = self.node_mut(ino)?;
        n.nlink = 0;
        n.ctime = now;
        self.maybe_free(ino, store);
        Ok(())
    }

    /// Whether directory `a` is `b` or below it (`true` too if the parents do not end:
    /// the caller refuses then).
    fn is_within(&self, mut a: u64, b: u64) -> bool {
        for _ in 0..=self.nodes.len() {
            if a == b {
                return true;
            }
            match self.nodes.get(&a).map(|n| &n.kind) {
                Some(Kind::Dir { parent, .. }) if *parent != a => a = *parent,
                _ => return false,
            }
        }
        true
    }

    fn is_dir(&self, ino: u64) -> bool {
        self.nodes.get(&ino).is_some_and(|n| matches!(n.kind, Kind::Dir { .. }))
    }

    fn set_parent(&mut self, ino: u64, new_parent: u64) {
        if let Some(Node { kind: Kind::Dir { parent, .. }, .. }) = self.nodes.get_mut(&ino) {
            *parent = new_parent;
        }
    }

    /// `renameat2(odir, oname, ndir, nname, flags)` (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`).
    #[allow(clippy::too_many_arguments)]
    pub fn rename(&mut self, odir: u64, oname: &[u8], ndir: u64, nname: &[u8], flags: u32, store: &mut dyn DataStore, now: Ts) -> Result<(), i64> {
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 || flags & RENAME_WHITEOUT != 0 {
            return Err(EINVAL);
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(EINVAL);
        }
        // As Linux: a last component of `.` or `..` is busy
        if [oname, nname].iter().any(|n| *n == b"." || *n == b"..") {
            return Err(EBUSY);
        }
        self.node(odir)?;
        self.node(ndir)?;
        if !self.is_dir(ndir) || !self.is_dir(odir) {
            return Err(ENOTDIR);
        }
        let src = self.lookup(odir, oname)?;
        check_name(nname)?;
        if self.node(ndir)?.nlink == 0 {
            return Err(ENOENT);
        }
        let target = self.lookup(ndir, nname).ok();
        let src_dir = self.is_dir(src);
        if flags & RENAME_EXCHANGE != 0 {
            let dst = target.ok_or(ENOENT)?;
            if odir == ndir && oname == nname {
                return Ok(());
            }
            let dst_dir = self.is_dir(dst);
            if (src_dir && self.is_within(ndir, src)) || (dst_dir && self.is_within(odir, dst)) {
                return Err(EINVAL);
            }
            // A directory for a non-directory: the receiving parent gains a link
            if odir != ndir && src_dir != dst_dir {
                let gains = if src_dir { ndir } else { odir };
                if self.node(gains)?.nlink >= LINK_MAX {
                    return Err(EMLINK);
                }
            }
            self.replace_entry(odir, oname, dst, now)?;
            self.replace_entry(ndir, nname, src, now)?;
            if odir != ndir {
                if src_dir {
                    self.set_parent(src, ndir);
                    self.node_mut(odir)?.nlink -= 1;
                    self.node_mut(ndir)?.nlink += 1;
                }
                if dst_dir {
                    self.set_parent(dst, odir);
                    self.node_mut(ndir)?.nlink -= 1;
                    self.node_mut(odir)?.nlink += 1;
                }
            }
            self.node_mut(src)?.ctime = now;
            self.node_mut(dst)?.ctime = now;
            return Ok(());
        }
        if let Some(dst) = target {
            if flags & RENAME_NOREPLACE != 0 {
                return Err(EEXIST);
            }
            if dst == src {
                return Ok(()); // two names of one file: nothing happens
            }
            let dst_dir = self.is_dir(dst);
            if src_dir && !dst_dir {
                return Err(ENOTDIR);
            }
            if !src_dir && dst_dir {
                return Err(EISDIR);
            }
            if src_dir && self.is_within(ndir, src) {
                return Err(EINVAL);
            }
            if let Some(Node { kind: Kind::Dir { entries, .. }, .. }) = self.nodes.get(&dst) {
                if !entries.is_empty() {
                    return Err(ENOTEMPTY);
                }
            }
            // The target goes; the source takes its entry
            self.replace_entry(ndir, nname, src, now)?;
            if dst_dir {
                self.node_mut(ndir)?.nlink -= 1;
                let n = self.node_mut(dst)?;
                n.nlink = 0;
                n.ctime = now;
                self.maybe_free(dst, store);
            } else {
                self.drop_link(dst, store, now);
            }
        } else {
            if src_dir && self.is_within(ndir, src) {
                return Err(EINVAL);
            }
            if src_dir && odir != ndir && self.node(ndir)?.nlink >= LINK_MAX {
                return Err(EMLINK);
            }
            self.add_entry(ndir, nname, src, now);
        }
        self.remove_entry(odir, oname, now)?;
        if src_dir && odir != ndir {
            self.set_parent(src, ndir);
            self.node_mut(odir)?.nlink -= 1;
            self.node_mut(ndir)?.nlink += 1;
        }
        self.node_mut(src)?.ctime = now;
        Ok(())
    }

    /// Points the existing entry `name` of `dir` at `ino` (keeping its place in listings).
    fn replace_entry(&mut self, dir: u64, name: &[u8], ino: u64, now: Ts) -> Result<(), i64> {
        let d = self.node_mut(dir)?;
        let Kind::Dir { entries, .. } = &mut d.kind else { return Err(ENOTDIR) };
        entries.get_mut(name).ok_or(ENOENT)?.0 = ino;
        d.mtime = now;
        d.ctime = now;
        Ok(())
    }

    /// `getdents64` from `cookie` (0 at the start): at most `max` entries.
    pub fn readdir(&self, dir: u64, cookie: u64, max: usize) -> Result<Vec<Dirent>, i64> {
        let d = self.node(dir)?;
        let Kind::Dir { entries, order, parent, .. } = &d.kind else { return Err(ENOTDIR) };
        let mut out = Vec::new();
        if d.nlink == 0 {
            return Ok(out); // a removed directory lists nothing, as on Linux
        }
        if cookie == 0 && out.len() < max {
            out.push(Dirent { ino: dir, next: 1, dtype: 4, name: b".".to_vec() });
        }
        if cookie <= 1 && out.len() < max {
            out.push(Dirent { ino: *parent, next: 2, dtype: 4, name: b"..".to_vec() });
        }
        for (seq, name) in order.range(cookie.max(2)..) {
            if out.len() >= max {
                break;
            }
            let ino = entries[name].0;
            let dt = self.nodes.get(&ino).map_or(0, |n| dtype(n.mode));
            out.push(Dirent { ino, next: seq + 1, dtype: dt, name: name.clone() });
        }
        Ok(out)
    }

    /// `chmod`, `chown`, `utimensat`, `truncate` in one: what `a` sets. The change time is
    /// always updated; a size change updates the modification time too.
    pub fn setattr(&mut self, ino: u64, a: &SetAttr, store: &mut dyn DataStore, now: Ts) -> Result<Attr, i64> {
        if let Some(size) = a.size {
            self.truncate(ino, size, store, now)?;
        }
        let n = self.node_mut(ino)?;
        if let Some(m) = a.mode {
            n.mode = (n.mode & S_IFMT) | (m & 0o7777);
        }
        if let Some(u) = a.uid {
            n.uid = u;
        }
        if let Some(g) = a.gid {
            n.gid = g;
        }
        if let Some(t) = a.atime {
            n.atime = t;
        }
        if let Some(t) = a.mtime {
            n.mtime = t;
        }
        n.ctime = now;
        self.getattr(ino)
    }

    /// Sets the size of regular file `ino` (data past it reads as zeros).
    pub fn truncate(&mut self, ino: u64, size: u64, store: &mut dyn DataStore, now: Ts) -> Result<(), i64> {
        if size > MAX_FILE {
            return Err(EFBIG);
        }
        let n = self.node(ino)?;
        let Kind::File { data } = n.kind else { return Err(if matches!(n.kind, Kind::Dir { .. }) { EISDIR } else { EINVAL }) };
        let old = n.size;
        let (op, np) = (pages(old), pages(size));
        if np > op && self.over_limit(np - op) {
            return Err(ENOSPC);
        }
        if size < old && data != 0 {
            store.truncate(data, size, old)?;
        } else if size > old && data != 0 {
            grow_tail(store, data, old, size)?;
        }
        self.used_pages = self.used_pages + np - op;
        let n = self.node_mut(ino)?;
        n.size = size;
        n.mtime = now;
        n.ctime = now;
        Ok(())
    }

    /// Writes `buf` at `off` into regular file `ino`; the bytes written.
    pub fn write(&mut self, ino: u64, off: u64, buf: &[u8], store: &mut dyn DataStore, now: Ts) -> Result<usize, i64> {
        let n = self.node(ino)?;
        let Kind::File { data } = n.kind else { return Err(if matches!(n.kind, Kind::Dir { .. }) { EISDIR } else { EINVAL }) };
        if buf.is_empty() {
            return Ok(0);
        }
        let end = off.checked_add(buf.len() as u64).ok_or(EFBIG)?;
        if end > MAX_FILE {
            return Err(EFBIG);
        }
        let old = n.size;
        let new_size = old.max(end);
        let (op, np) = (pages(old), pages(new_size));
        if np > op && self.over_limit(np - op) {
            return Err(ENOSPC);
        }
        let data = if data == 0 {
            let k = store.create()?;
            if let Kind::File { data } = &mut self.node_mut(ino)?.kind {
                *data = k;
            }
            k
        } else {
            data
        };
        if off > old {
            grow_tail(store, data, old, off)?;
        }
        store.write(data, off, buf)?;
        self.used_pages = self.used_pages + np - op;
        let n = self.node_mut(ino)?;
        n.size = new_size;
        n.mtime = now;
        n.ctime = now;
        Ok(buf.len())
    }

    /// Reads at most `len` bytes from `off` of regular file `ino`.
    pub fn read(&self, ino: u64, off: u64, len: usize, store: &mut dyn DataStore) -> Result<Vec<u8>, i64> {
        let n = self.node(ino)?;
        let Kind::File { data } = n.kind else { return Err(if matches!(n.kind, Kind::Dir { .. }) { EISDIR } else { EINVAL }) };
        if off >= n.size {
            return Ok(Vec::new());
        }
        let len = (len as u64).min(n.size - off) as usize;
        let mut out = vec![0u8; len];
        if data != 0 {
            store.read(data, off, &mut out)?;
        }
        Ok(out)
    }

    /// The data key of regular file `ino` (made now if it has none), for a kernel file
    /// handle or an `mmap` answer.
    pub fn data_key(&mut self, ino: u64, store: &mut dyn DataStore) -> Result<u64, i64> {
        let n = self.node_mut(ino)?;
        let Kind::File { data } = &mut n.kind else { return Err(EINVAL) };
        if *data == 0 {
            *data = store.create()?;
        }
        Ok(*data)
    }

    /// A handle on `ino` was opened.
    pub fn open(&mut self, ino: u64) -> Result<(), i64> {
        let n = self.node_mut(ino)?;
        n.open = n.open.checked_add(1).ok_or(ENFILE)?;
        Ok(())
    }

    /// A handle on `ino` was closed; a removed inode goes with its last handle.
    pub fn release(&mut self, ino: u64, store: &mut dyn DataStore) {
        if let Some(n) = self.nodes.get_mut(&ino) {
            n.open = n.open.saturating_sub(1);
        }
        self.maybe_free(ino, store);
    }

    /// `statfs`.
    pub fn statfs(&self) -> StatFs {
        let blocks = self.opts.size / PAGE;
        let files = self.opts.nr_inodes;
        StatFs {
            bsize: PAGE,
            blocks,
            bfree: blocks.saturating_sub(self.used_pages),
            files,
            ffree: files.saturating_sub(self.nodes.len() as u64),
            namelen: NAME_MAX as u64,
        }
    }

    /// `getxattr`.
    pub fn getxattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
        self.node(ino)?.xattrs.get(name).cloned().ok_or(ENODATA)
    }

    /// `listxattr`: the names, each followed by a NUL.
    pub fn listxattr(&self, ino: u64) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        for k in self.node(ino)?.xattrs.keys() {
            out.extend_from_slice(k);
            out.push(0);
        }
        Ok(out)
    }

    /// `setxattr` (`XATTR_CREATE`, `XATTR_REPLACE`): the `user.`, `trusted.` and
    /// `security.` name spaces (permission checks on them are the caller's).
    pub fn setxattr(&mut self, ino: u64, name: &[u8], value: &[u8], flags: u32, now: Ts) -> Result<(), i64> {
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == XATTR_CREATE | XATTR_REPLACE || name.contains(&0) {
            return Err(EINVAL);
        }
        if name.is_empty() || name.len() > NAME_MAX {
            return Err(ERANGE);
        }
        // (and the POSIX ACLs, whose meaning is the permission checks')
        let acl = name == b"system.posix_acl_access" || name == b"system.posix_acl_default";
        let ns_len = if acl { 0 } else { [&b"user."[..], b"trusted.", b"security."].iter().find(|p| name.starts_with(p)).map(|p| p.len()).ok_or(EOPNOTSUPP)? };
        if name.len() == ns_len {
            return Err(EINVAL); // a name space without a name
        }
        if value.len() > XATTR_SIZE_MAX {
            return Err(E2BIG);
        }
        let n = self.node_mut(ino)?;
        if name.starts_with(b"user.") && !matches!(n.kind, Kind::File { .. } | Kind::Dir { .. }) {
            return Err(EPERM);
        }
        let exists = n.xattrs.contains_key(name);
        if flags & XATTR_CREATE != 0 && exists {
            return Err(EEXIST);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(ENODATA);
        }
        let total: usize = n.xattrs.iter().filter(|(k, _)| k.as_slice() != name).map(|(k, v)| k.len() + v.len()).sum();
        if total + name.len() + value.len() > XATTR_SIZE_MAX {
            return Err(ENOSPC);
        }
        n.xattrs.insert(name.to_vec(), value.to_vec());
        n.ctime = now;
        Ok(())
    }

    /// `removexattr`.
    pub fn removexattr(&mut self, ino: u64, name: &[u8], now: Ts) -> Result<(), i64> {
        let n = self.node_mut(ino)?;
        n.xattrs.remove(name).ok_or(ENODATA)?;
        n.ctime = now;
        Ok(())
    }

    /// The instance goes (no mount and no open handle left): frees every data object.
    pub fn destroy(self, store: &mut dyn DataStore) {
        for n in self.nodes.into_values() {
            if let Kind::File { data } = n.kind {
                if data != 0 {
                    store.free(data);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Kept state (Group 7-6)
    // ------------------------------------------------------------------

    /// The instance as a sealed byte string. Data keys are written as they are: the data
    /// objects must outlive the server instance (see the notes in `NOTES.md`).
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        e.u32(self.id);
        e.u32(self.opts.mode);
        e.u32(self.opts.uid);
        e.u32(self.opts.gid);
        e.u64(self.opts.size);
        e.u64(self.opts.nr_inodes);
        e.u64(self.next_ino);
        e.u64(self.used_pages);
        e.u64(self.nodes.len() as u64);
        for (ino, n) in &self.nodes {
            e.u64(*ino);
            match &n.kind {
                Kind::Dir { entries, next_seq, parent, .. } => {
                    e.u8(0);
                    e.u64(*parent);
                    e.u64(*next_seq);
                    e.u32(entries.len() as u32);
                    for (name, (child, seq)) in entries {
                        e.bytes(name);
                        e.u64(*child);
                        e.u64(*seq);
                    }
                }
                Kind::File { data } => {
                    e.u8(1);
                    e.u64(*data);
                }
                Kind::Symlink(t) => {
                    e.u8(2);
                    e.bytes(t);
                }
                Kind::Special => e.u8(3),
            }
            e.u32(n.mode);
            e.u32(n.uid);
            e.u32(n.gid);
            e.u32(n.nlink);
            e.u64(n.size);
            e.u64(n.rdev);
            for t in [n.atime, n.mtime, n.ctime, n.btime] {
                e.i64(t.0);
                e.u32(t.1);
            }
            e.u32(n.xattrs.len() as u32);
            for (k, v) in &n.xattrs {
                e.bytes(k);
                e.bytes(v);
            }
            e.u32(n.open);
        }
        seal(TMPFS_MAGIC_KEPT, TMPFS_VERSION, &e.buf)
    }

    /// Reads back what [`Self::encode`] wrote, and checks the tree (`EINVAL` if damaged).
    pub fn decode(b: &[u8]) -> Result<Tmpfs, i64> {
        let body = unseal(TMPFS_MAGIC_KEPT, TMPFS_VERSION, b)?;
        let mut d = Dec::new(body);
        let id = d.u32()?;
        let opts = TmpfsOpts { mode: d.u32()?, uid: d.u32()?, gid: d.u32()?, size: d.u64()?, nr_inodes: d.u64()? };
        let next_ino = d.u64()?;
        let used_pages = d.u64()?;
        let count = d.u64()?;
        if count as usize > d.remaining() {
            return Err(EINVAL);
        }
        let mut nodes = BTreeMap::new();
        for _ in 0..count {
            let ino = d.u64()?;
            let kind = match d.u8()? {
                0 => {
                    let parent = d.u64()?;
                    let next_seq = d.u64()?;
                    let n = d.u32()? as usize;
                    if n > d.remaining() {
                        return Err(EINVAL);
                    }
                    let mut entries = BTreeMap::new();
                    let mut order = BTreeMap::new();
                    for _ in 0..n {
                        let name = d.bytes()?;
                        let child = d.u64()?;
                        let seq = d.u64()?;
                        if order.insert(seq, name.clone()).is_some() || entries.insert(name, (child, seq)).is_some() {
                            return Err(EINVAL);
                        }
                    }
                    Kind::Dir { entries, order, next_seq, parent }
                }
                1 => Kind::File { data: d.u64()? },
                2 => Kind::Symlink(d.bytes()?),
                3 => Kind::Special,
                _ => return Err(EINVAL),
            };
            let mode = d.u32()?;
            let uid = d.u32()?;
            let gid = d.u32()?;
            let nlink = d.u32()?;
            let size = d.u64()?;
            let rdev = d.u64()?;
            let mut ts = [(0i64, 0u32); 4];
            for t in ts.iter_mut() {
                *t = (d.i64()?, d.u32()?);
            }
            let nx = d.u32()? as usize;
            if nx > d.remaining() {
                return Err(EINVAL);
            }
            let mut xattrs = BTreeMap::new();
            for _ in 0..nx {
                let k = d.bytes()?;
                if xattrs.insert(k, d.bytes()?).is_some() {
                    return Err(EINVAL);
                }
            }
            let open = d.u32()?;
            if nodes.insert(ino, Node { kind, mode, uid, gid, nlink, size, rdev, atime: ts[0], mtime: ts[1], ctime: ts[2], btime: ts[3], xattrs, open }).is_some() {
                return Err(EINVAL);
            }
        }
        if !d.done() {
            return Err(EINVAL);
        }
        let t = Tmpfs { id, opts, nodes, next_ino, used_pages };
        t.check()?;
        Ok(t)
    }

    /// Consistency of the tree, for kept state read back: the root, every live directory
    /// reachable from it once (no cycles, one entry each), link counts that match the
    /// entries, removed inodes only while open, names, sizes, data keys used once, the
    /// listing order, inode numbers below `next_ino`, the page count.
    pub fn check(&self) -> Result<(), i64> {
        let root = self.nodes.get(&ROOT).ok_or(EINVAL)?;
        match &root.kind {
            Kind::Dir { parent, .. } if *parent == ROOT && root.nlink >= 2 => {}
            _ => return Err(EINVAL),
        }
        // Extended attributes: valid names, within the size bound
        for n in self.nodes.values() {
            let mut total = 0usize;
            for (k, v) in &n.xattrs {
                if k.is_empty() || k.len() > NAME_MAX || k.contains(&0) || v.len() > XATTR_SIZE_MAX {
                    return Err(EINVAL);
                }
                total += k.len() + v.len();
            }
            if total > XATTR_SIZE_MAX {
                return Err(EINVAL);
            }
        }
        // Entries per inode, and subdirectories per directory
        let mut refs: BTreeMap<u64, u64> = BTreeMap::new();
        let mut used = 0u64;
        let mut keys = alloc::collections::BTreeSet::new();
        for (ino, n) in &self.nodes {
            if *ino >= self.next_ino || *ino == 0 {
                return Err(EINVAL);
            }
            let ty = n.mode & S_IFMT;
            match &n.kind {
                Kind::Dir { entries, order, next_seq, .. } => {
                    if ty != S_IFDIR || order.len() != entries.len() || *next_seq < 2 {
                        return Err(EINVAL);
                    }
                    for (name, (child, seq)) in entries {
                        if check_name(name).is_err() || name == b"." || name == b".." || *seq < 2 || seq >= next_seq || order.get(seq) != Some(name) {
                            return Err(EINVAL);
                        }
                        if *child == ROOT || !self.nodes.contains_key(child) {
                            return Err(EINVAL);
                        }
                        *refs.entry(*child).or_insert(0) += 1;
                    }
                }
                Kind::File { data } => {
                    if ty != S_IFREG || n.size > MAX_FILE || (*data != 0 && !keys.insert(*data)) {
                        return Err(EINVAL);
                    }
                    used = used.checked_add(pages(n.size)).ok_or(EINVAL)?;
                }
                Kind::Symlink(t) => {
                    if ty != S_IFLNK || t.is_empty() || t.len() > SYMLINK_MAX || t.contains(&0) || n.size != t.len() as u64 {
                        return Err(EINVAL);
                    }
                }
                Kind::Special => {
                    if !matches!(ty, S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK) {
                        return Err(EINVAL);
                    }
                }
            }
        }
        // Link counts; removed inodes only while a handle holds them
        for (ino, n) in &self.nodes {
            let r = refs.get(ino).copied().unwrap_or(0);
            if n.nlink == 0 && (n.open == 0 || r != 0) {
                return Err(EINVAL);
            }
            match &n.kind {
                Kind::Dir { entries, .. } => {
                    if n.nlink == 0 {
                        if !entries.is_empty() {
                            return Err(EINVAL);
                        }
                        continue;
                    }
                    let subdirs = entries.values().filter(|e| self.is_dir(e.0)).count() as u64;
                    let want_refs = if *ino == ROOT { 0 } else { 1 };
                    if r != want_refs || n.nlink as u64 != 2 + subdirs {
                        return Err(EINVAL);
                    }
                }
                _ => {
                    if n.nlink as u64 != r {
                        return Err(EINVAL);
                    }
                }
            }
        }
        // Every live directory is reached from the root, through its parent's entries
        let live_dirs = self.nodes.iter().filter(|(_, n)| matches!(n.kind, Kind::Dir { .. }) && n.nlink > 0).count();
        let mut seen = 0usize;
        let mut todo = vec![ROOT];
        while let Some(d) = todo.pop() {
            seen += 1;
            if seen > live_dirs {
                return Err(EINVAL);
            }
            if let Some(Node { kind: Kind::Dir { entries, .. }, .. }) = self.nodes.get(&d) {
                for (child, _) in entries.values() {
                    if let Some(Node { kind: Kind::Dir { parent, .. }, .. }) = self.nodes.get(child) {
                        if *parent != d {
                            return Err(EINVAL);
                        }
                        todo.push(*child);
                    }
                }
            }
        }
        if seen != live_dirs || used != self.used_pages {
            return Err(EINVAL);
        }
        Ok(())
    }
}

const TMPFS_MAGIC_KEPT: u32 = 0x544d_5046; // "TMPF"
const TMPFS_VERSION: u32 = 1;

/// Every `tmpfs` instance of the server, by instance number (the mount table's
/// `Backend::Tmpfs(n)`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TmpfsSet {
    pub all: BTreeMap<u32, Tmpfs>,
    next: u32,
}

impl TmpfsSet {
    pub fn new() -> TmpfsSet {
        TmpfsSet { all: BTreeMap::new(), next: 1 }
    }

    /// A new instance from mount data; `(instance, root inode)`.
    pub fn create(&mut self, data: &str, euid: u32, egid: u32, mem: u64, now: Ts) -> Result<(u32, u64), i64> {
        let opts = TmpfsOpts::parse(data, euid, egid, mem)?;
        let n = self.next.max(1);
        if self.all.contains_key(&n) || n == u32::MAX {
            return Err(ENFILE); // (four billion instances: the numbers ran out)
        }
        self.next = n + 1;
        self.all.insert(n, Tmpfs::new(n, opts, now));
        Ok((n, ROOT))
    }

    pub fn get(&self, n: u32) -> Option<&Tmpfs> {
        self.all.get(&n)
    }

    pub fn get_mut(&mut self, n: u32) -> Option<&mut Tmpfs> {
        self.all.get_mut(&n)
    }

    /// Instances the mount tables no longer mount (`Effects::tmpfs_gone`, or any unmounted
    /// one when `mounted` says so): dropped once none of their handles is open. The
    /// instances kept for open handles are dropped by a later call.
    pub fn reap(&mut self, mounted: &dyn Fn(u32) -> bool, store: &mut dyn DataStore) -> Vec<u32> {
        let gone: Vec<u32> = self.all.iter().filter(|(n, t)| !mounted(**n) && !t.has_open()).map(|(n, _)| *n).collect();
        for n in &gone {
            if let Some(t) = self.all.remove(n) {
                t.destroy(store);
            }
        }
        gone
    }

    /// Every instance, sealed.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        e.u32(self.next);
        e.u32(self.all.len() as u32);
        for t in self.all.values() {
            e.bytes(&t.encode());
        }
        seal(TMPFS_SET_MAGIC, TMPFS_VERSION, &e.buf)
    }

    pub fn decode(b: &[u8]) -> Result<TmpfsSet, i64> {
        let body = unseal(TMPFS_SET_MAGIC, TMPFS_VERSION, b)?;
        let mut d = Dec::new(body);
        let next = d.u32()?;
        let n = d.u32()? as usize;
        if n > d.remaining() {
            return Err(EINVAL);
        }
        let mut all = BTreeMap::new();
        for _ in 0..n {
            let t = Tmpfs::decode(&d.bytes()?)?;
            if t.id >= next {
                return Err(EINVAL);
            }
            if t.id == 0 || all.insert(t.id, t).is_some() {
                return Err(EINVAL);
            }
        }
        if !d.done() {
            return Err(EINVAL);
        }
        Ok(TmpfsSet { all, next })
    }
}

const TMPFS_SET_MAGIC: u32 = 0x544d_5053; // "TMPS"
