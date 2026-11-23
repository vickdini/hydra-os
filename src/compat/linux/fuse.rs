//! # FUSE
//!
//! File systems served by user-space daemons through `/dev/fuse` (char 10:229), with the
//! Linux FUSE protocol (7.14): the daemon reads requests from its descriptor and writes the
//! replies back. `fusermount3` mounts a connection (`mount(2)` with `fd=N`); the files below
//! the mount point are then the daemon's.
//!
//! A daemon's files have inode numbers of their own: [`FUSE_BIT`], the connection and an
//! index into the connection's node table (`1` is the root). The file server client
//! ([`crate::fs::zfs::ZfsServer`]) sends every operation on such an inode here, and path
//! lookups cross between the pool and FUSE mounts at mount points ([`walk`]).
//!
//! Since wave 9 (Group 6b-2) vfs-server is the FUSE client: `/dev/fuse` is its object, it
//! speaks the protocol, keeps the node tables and the daemon's handles. Its files' inode
//! numbers carry a connection of [`super::fuse_svc`] (`FUSE_SVC_CONN` and above), and every
//! operation on one that reaches the kernel (handle I/O, calls vfs-server sends back) is
//! forwarded there. Wave 9's closing (Group 9-C) deleted the kernel's own client (protocol
//! engine, node tables, its `/dev/fuse`; the switch back `lx.fuse=kernel`/`lx.vfs=kernel`).
//! Left here: the inode numbering, the initial namespace's FUSE mount list, the walk across
//! FUSE mounts, `mount(2)` of a vfs-server connection, and the forwarders.

use alloc::string::String;
use alloc::vec::Vec;

use spin::Mutex;

use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

const EBADF: i64 = -9;
const EXDEV: i64 = -18;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const ELOOP: i64 = -40;
const ENOTCONN: i64 = -107;

/// Marks a FUSE inode (bit 63 clear: `u64::MAX` and its neighbours are Hydra's own).
pub const FUSE_BIT: u64 = 1 << 62;
const CONN_SHIFT: u32 = 40;
const LOCAL_MASK: u64 = (1 << CONN_SHIFT) - 1;

/// `/dev/fuse`.
pub const RDEV: u64 = super::chardev::makedev(10, 229);

// setattr `valid` bits
const FATTR_MODE: u32 = 1;
const FATTR_UID: u32 = 2;
const FATTR_GID: u32 = 4;
const FATTR_SIZE: u32 = 8;
const FATTR_ATIME: u32 = 16;
const FATTR_MTIME: u32 = 32;

const S_IFMT: u32 = 0o170000;
const S_IFLNK: u32 = 0o120000;
const S_IFDIR: u32 = 0o040000;


/// Whether `ino` is a file of a FUSE daemon.
pub fn is_fuse(ino: u64) -> bool {
    ino >> 62 == 1
}

fn split(ino: u64) -> (u16, u64) {
    (((ino & !FUSE_BIT) >> CONN_SHIFT) as u16, ino & LOCAL_MASK)
}

// ----------------------------------------------------------------------
// Mounts in the initial namespace (other namespaces keep theirs in their tables)
// ----------------------------------------------------------------------

/// A FUSE mount of the initial mount namespace.
#[derive(Clone)]
pub struct Ns0Mount {
    /// The directory mounted on.
    pub mountpoint: u64,
    /// The mount's root inode.
    pub root: u64,
    /// Mount point path.
    pub path: String,
    /// File system type (`fuse.<name>`).
    pub fstype: String,
    /// Source (the daemon's name).
    pub source: String,
    /// Options as `/proc/mounts` shows them.
    pub opts: String,
}

static NS0: Mutex<Vec<Ns0Mount>> = Mutex::new(Vec::new());

/// The initial namespace's FUSE mounts as a mount list for the file server:
/// `(mountpoint, root, parent mount 0)`.
pub fn ns0_list() -> Vec<(u64, u64, usize)> {
    NS0.lock().iter().map(|m| (m.mountpoint, m.root, 0)).collect()
}

/// Whether the initial namespace has FUSE mounts.
pub fn ns0_any() -> bool {
    !NS0.lock().is_empty()
}

/// The mount (1-based index in [`ns0_list`]) a FUSE inode of the initial namespace lies in.
pub fn ns0_mnt_of(ino: u64) -> usize {
    if !is_fuse(ino) {
        return 0;
    }
    let c = split(ino).0;
    NS0.lock().iter().position(|m| split(m.root).0 == c).map_or(0, |i| i + 1)
}

/// The initial namespace's FUSE mounts.
pub fn ns0_snapshot() -> Vec<Ns0Mount> {
    NS0.lock().clone()
}

/// Records a FUSE mount of the initial namespace.
pub fn ns0_add(m: Ns0Mount) {
    NS0.lock().push(m);
    super::mount::bump(0); // wave7 G7-7: vfs-server's copy follows
}

/// Unmounts the initial namespace's FUSE mount whose root is `root`; the daemon's reads
/// end with `ENODEV`.
pub fn ns0_remove(root: u64) -> bool {
    let mut l = NS0.lock();
    let Some(i) = l.iter().position(|m| m.root == root) else { return false };
    l.remove(i);
    drop(l);
    super::mount::bump(0); // wave7 G7-7: vfs-server's copy follows
    super::fuse_svc::abort(split(root).0); // wave9 G6b-2
    true
}

/// `/proc/mounts` lines of the initial namespace's FUSE mounts.
pub fn ns0_mounts_text() -> String {
    let mut out = String::new();
    for m in NS0.lock().iter() {
        out.push_str(&alloc::format!("{} {} {} {} 0 0\n", m.source, m.path, m.fstype, m.opts));
    }
    out
}

/// `/proc/self/mountinfo` lines of the initial namespace's FUSE mounts.
pub fn ns0_mountinfo_text() -> String {
    let mut out = String::new();
    for (i, m) in NS0.lock().iter().enumerate() {
        let id = 4000 + i;
        out.push_str(&alloc::format!("{} 2069 0:{} / {} {} - {} {} {}\n", id, 60 + split(m.root).0 as u32, m.path, m.opts.split(',').take(4).collect::<Vec<_>>().join(","), m.fstype, m.source, m.opts));
    }
    out
}

/// The directory a FUSE inode was found in and its name there (`None` for a root).
pub fn name_of(ino: u64) -> Option<(u64, Vec<u8>)> {
    if super::fuse_svc::is_remote(ino) {
        return super::fuse_svc::name_of(ino); // wave9 G6b-2
    }
    None
}

/// The mount point of the initial namespace's FUSE mount whose root is `ino`.
pub fn ns0_mountpoint(ino: u64) -> Option<u64> {
    NS0.lock().iter().find(|m| m.root == ino).map(|m| m.mountpoint)
}

/// Device number `stat` reports for a FUSE file.
pub fn dev(ino: u64) -> u64 {
    super::chardev::makedev(0, 60 + split(ino).0 as u64)
}

/// The inode number the daemon gave `ino`.
pub fn user_ino(ino: u64) -> u64 {
    if super::fuse_svc::is_remote(ino) {
        return super::fuse_svc::user_ino(ino); // wave9 G6b-2
    }
    split(ino).1
}

// ----------------------------------------------------------------------
// Path lookup across FUSE mounts
// ----------------------------------------------------------------------

/// How a walk in a FUSE file system ended.
pub enum Walk {
    /// At `(ino, mount)`.
    Done(u64, usize),
    /// It left the file system: go on from `(ino, mount)` (a pool directory) with `rest`.
    Out(u64, usize, Vec<u8>),
}

fn components(path: &[u8]) -> Vec<Vec<u8>> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".").map(|c| c.to_vec()).collect()
}

fn join(stack: &[Vec<u8>]) -> Vec<u8> {
    // `stack` is reversed (the next component last)
    let mut out = Vec::new();
    for c in stack.iter().rev() {
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(c);
    }
    out
}

/// Walks `rest` from FUSE directory `(cur, mnt)` within mount list `mounts`
/// (`(mountpoint, root, parent)`, 1-based). `..` at a mount's root leaves the mount; a
/// symbolic link to an absolute path goes on from `(root, root_mnt)`.
#[allow(clippy::too_many_arguments)]
pub fn walk(cur: u64, mnt: usize, rest: &[u8], follow: bool, mounts: &[(u64, u64, usize)], root: u64, root_mnt: usize, links: &mut u32) -> Result<Walk, i64> {
    let (mut cur, mut mnt) = (cur, mnt);
    let mut stack = components(rest);
    stack.reverse();
    while let Some(c) = stack.pop() {
        if c == b".." {
            if (cur, mnt) == (root, root_mnt) {
                continue;
            }
            if mnt != 0 && mounts.get(mnt - 1).is_some_and(|m| m.1 == cur) {
                let m = mounts[mnt - 1];
                stack.push(c);
                if !is_fuse(m.0) {
                    return Ok(Walk::Out(m.0, m.2, join(&stack)));
                }
                cur = m.0;
                mnt = m.2;
                continue;
            }
            cur = parent(cur)?;
            continue;
        }
        let (next, attr) = lookup_attr(cur, &c)?;
        let last = stack.is_empty();
        if attr.mode & S_IFMT == S_IFLNK && (!last || follow) {
            *links += 1;
            if *links > 40 {
                return Err(ELOOP);
            }
            let target = readlink(next)?;
            let mut more = components(&target);
            more.reverse();
            if target.first() == Some(&b'/') {
                stack.extend(more);
                return Ok(Walk::Out(root, root_mnt, join(&stack)));
            }
            stack.extend(more);
            continue;
        }
        if !last && attr.mode & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
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
        if !is_fuse(n) {
            return Ok(Walk::Out(n, m, join(&stack)));
        }
        cur = n;
        mnt = m;
    }
    Ok(Walk::Done(cur, mnt))
}

fn parent(ino: u64) -> Result<u64, i64> {
    remote(ino)?;
    super::fuse_svc::parent(ino) // wave9 G6b-2
}

/// `ENOTCONN` for a FUSE inode that is not of a vfs-server connection (wave9 G9-C: the
/// kernel's own client is gone, so no such inode is handed out any more).
fn remote(ino: u64) -> Result<(), i64> {
    if super::fuse_svc::is_remote(ino) { Ok(()) } else { Err(ENOTCONN) }
}

// ----------------------------------------------------------------------
// Operations
// ----------------------------------------------------------------------

pub(super) fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4).map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub(super) fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8).map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// `struct fuse_attr` at `b` as Hydra's attributes of inode `ino`.
pub(super) fn attr_of(ino: u64, b: &[u8]) -> Attr {
    Attr {
        ino,
        size: u64_at(b, 8),
        blocks: u64_at(b, 16),
        atime: (u64_at(b, 24) as i64, u32_at(b, 48)),
        mtime: (u64_at(b, 32) as i64, u32_at(b, 52)),
        ctime: (u64_at(b, 40) as i64, u32_at(b, 56)),
        mode: u32_at(b, 60),
        nlink: u32_at(b, 64),
        uid: u32_at(b, 68),
        gid: u32_at(b, 72),
        rdev: u32_at(b, 76) as u64,
        ..Attr::default()
    }
}

/// Looks `name` up in FUSE directory `dir`: the inode and its attributes.
pub fn lookup_attr(dir: u64, name: &[u8]) -> Result<(u64, Attr), i64> {
    remote(dir)?;
    super::fuse_svc::lookup_attr(dir, name) // wave9 G6b-2
}

/// Looks `name` up in FUSE directory `dir`.
pub fn lookup(dir: u64, name: &[u8]) -> Result<u64, i64> {
    lookup_attr(dir, name).map(|r| r.0)
}

/// Attributes of FUSE inode `ino`.
pub fn getattr(ino: u64) -> Result<Attr, i64> {
    remote(ino)?;
    super::fuse_svc::getattr(ino) // wave9 G6b-2
}

/// Changes attributes of FUSE inode `ino`; returns the new ones.
pub fn setattr(ino: u64, set: SetAttr) -> Result<Attr, i64> {
    remote(ino)?;
    super::fuse_svc::setattr(ino, &setattr_in(set)) // wave9 G6b-2
}

/// `struct fuse_setattr_in` for `set`.
fn setattr_in(set: SetAttr) -> Vec<u8> {
    let mut valid = 0;
    let mode = set.mode.map(|m| {
        valid |= FATTR_MODE;
        m
    });
    let uid = set.uid.map(|u| {
        valid |= FATTR_UID;
        u
    });
    let gid = set.gid.map(|g| {
        valid |= FATTR_GID;
        g
    });
    let size = set.size.map(|s| {
        valid |= FATTR_SIZE;
        s
    });
    let atime = set.atime.map(|t| {
        valid |= FATTR_ATIME;
        t
    });
    let mtime = set.mtime.map(|t| {
        valid |= FATTR_MTIME;
        t
    });
    let mut a = Vec::with_capacity(88);
    a.extend_from_slice(&valid.to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // fh
    a.extend_from_slice(&size.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // lock_owner
    a.extend_from_slice(&(atime.map_or(0, |t| t.0) as u64).to_le_bytes());
    a.extend_from_slice(&(mtime.map_or(0, |t| t.0) as u64).to_le_bytes());
    a.extend_from_slice(&0u64.to_le_bytes()); // ctime
    a.extend_from_slice(&atime.map_or(0, |t| t.1).to_le_bytes());
    a.extend_from_slice(&mtime.map_or(0, |t| t.1).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes()); // ctimensec
    a.extend_from_slice(&mode.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    a.extend_from_slice(&uid.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&gid.unwrap_or(0).to_le_bytes());
    a.extend_from_slice(&0u32.to_le_bytes());
    a
}

/// Target of FUSE symbolic link `ino`.
pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
    remote(ino)?;
    super::fuse_svc::readlink(ino) // wave9 G6b-2
}

/// Reads `ino` at `offset` into `buf`.
pub fn read(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    remote(ino)?;
    super::fuse_svc::read(ino, offset, buf) // wave9 G6b-2
}

/// Writes `data` to `ino` at `offset`.
pub fn write(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
    remote(ino)?;
    super::fuse_svc::write(ino, offset, data) // wave9 G6b-2
}

/// Up to `max` entries of directory `dir` from `cookie` (the daemon's offset) on.
pub fn readdir(dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
    remote(dir)?;
    super::fuse_svc::readdir(dir, cookie, max) // wave9 G6b-2
}

/// The daemon's `fuse_dirent` records `r` as entries (at most `max`).
pub(super) fn dirents(r: &[u8], max: usize) -> Vec<ReaddirEntry> {
    let mut out = Vec::new();
    let mut o = 0;
    while o + 24 <= r.len() && out.len() < max {
        let ino = u64_at(&r, o);
        let off = u64_at(&r, o + 8);
        let namelen = u32_at(&r, o + 16) as usize;
        let dtype = u32_at(&r, o + 20) as u8;
        if o + 24 + namelen > r.len() {
            break;
        }
        out.push(ReaddirEntry { name: r[o + 24..o + 24 + namelen].to_vec(), ino, dtype, next_cookie: off });
        o += (24 + namelen + 7) & !7;
    }
    out
}

/// A file created in `dir`: the daemon's `create` (keeping the handle for writing), or
/// `mknod` when it has none.
pub fn create(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    remote(dir)?;
    super::fuse_svc::create(dir, name, perm) // wave9 G6b-2
}

/// A node made in `dir`.
pub fn mknod(dir: u64, name: &[u8], mode: u32, rdev: u64) -> Result<u64, i64> {
    remote(dir)?;
    super::fuse_svc::mknod(dir, name, mode, rdev) // wave9 G6b-2
}

/// A directory made in `dir`.
pub fn mkdir(dir: u64, name: &[u8], perm: u32) -> Result<u64, i64> {
    remote(dir)?;
    super::fuse_svc::mkdir(dir, name, perm) // wave9 G6b-2
}

/// A symbolic link made in `dir`.
pub fn symlink(dir: u64, name: &[u8], to: &[u8]) -> Result<u64, i64> {
    remote(dir)?;
    super::fuse_svc::symlink(dir, name, to) // wave9 G6b-2
}

/// A hard link to `ino` made in `dir` (same file system only).
pub fn link(ino: u64, dir: u64, name: &[u8]) -> Result<(), i64> {
    if super::fuse_svc::is_remote(ino) && super::fuse_svc::is_remote(dir) {
        return super::fuse_svc::link(ino, dir, name); // wave9 G6b-2
    }
    Err(EXDEV)
}

/// Removes `name` from `dir`.
pub fn unlink(dir: u64, name: &[u8]) -> Result<(), i64> {
    remote(dir)?;
    super::fuse_svc::unlink(dir, name) // wave9 G6b-2
}

/// Removes directory `name` from `dir`.
pub fn rmdir(dir: u64, name: &[u8]) -> Result<(), i64> {
    remote(dir)?;
    super::fuse_svc::rmdir(dir, name) // wave9 G6b-2
}

/// Renames within one FUSE file system.
pub fn rename(sdir: u64, sname: &[u8], ddir: u64, dname: &[u8]) -> Result<(), i64> {
    if super::fuse_svc::is_remote(sdir) && super::fuse_svc::is_remote(ddir) {
        return super::fuse_svc::rename(sdir, sname, ddir, dname); // wave9 G6b-2
    }
    Err(EXDEV)
}

/// Extended attribute `name` of `ino`.
pub fn getxattr(ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
    remote(ino)?;
    super::fuse_svc::getxattr(ino, name) // wave9 G6b-2
}

/// Names of `ino`'s extended attributes.
pub fn listxattr(ino: u64) -> Result<Vec<u8>, i64> {
    remote(ino)?;
    super::fuse_svc::listxattr(ino) // wave9 G6b-2
}

/// Sets extended attribute `name` of `ino`.
pub fn setxattr(ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), i64> {
    remote(ino)?;
    super::fuse_svc::setxattr(ino, name, value, flags) // wave9 G6b-2
}

/// Removes extended attribute `name` of `ino`.
pub fn removexattr(ino: u64, name: &[u8]) -> Result<(), i64> {
    remote(ino)?;
    super::fuse_svc::removexattr(ino, name) // wave9 G6b-2
}

/// The file system `ino` is in as `statfs` reports it (`struct statfs`, 120 bytes); a
/// daemon without `statfs` gets Linux's defaults.
pub fn statfs(ino: u64) -> Result<[u8; 120], i64> {
    remote(ino)?;
    super::fuse_svc::statfs(ino) // wave9 G6b-2
}

/// `struct statfs` of `ino`'s file system from the daemon's `fuse_statfs_out` `r` (empty:
/// Linux's defaults).
pub(super) fn statfs_of(ino: u64, r: &[u8]) -> [u8; 120] {
    let bsize = match u32_at(r, 40) {
        0 => 512,
        b => b,
    };
    let namelen = match u32_at(r, 44) {
        0 => 255,
        n => n,
    };
    let frsize = match u32_at(r, 48) {
        0 => bsize,
        f => f,
    };
    let vals: [u64; 7] = [0x6573_5546, bsize as u64, u64_at(r, 0), u64_at(r, 8), u64_at(r, 16), u64_at(r, 24), u64_at(r, 32)];
    let mut b = [0u8; 120];
    for (i, v) in vals.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[56..60].copy_from_slice(&(dev(ino) as u32).to_le_bytes()); // f_fsid
    b[64..72].copy_from_slice(&(namelen as u64).to_le_bytes());
    b[72..80].copy_from_slice(&(frsize as u64).to_le_bytes());
    b
}

/// A descriptor opened `ino`.
pub fn open_ref(ino: u64) {
    if super::fuse_svc::is_remote(ino) {
        super::fuse_svc::open_ref(ino); // wave9 G6b-2
    }
}

/// A descriptor of `ino` closed: with the last, the daemon's handles are released (without
/// waiting for the daemon).
pub fn release(ino: u64) {
    if super::fuse_svc::is_remote(ino) {
        super::fuse_svc::release(ino); // wave9 G6b-2
    }
}

// ----------------------------------------------------------------------
// mount
// ----------------------------------------------------------------------

/// Options of a FUSE mount: `(fd, rootmode, user_id, group_id, allow_other)`.
fn options(data: &str) -> Result<(i32, u32, u32, u32, bool), i64> {
    let (mut fd, mut rootmode, mut uid, mut gid, mut other) = (None, None, None, None, false);
    for o in data.split(',') {
        let (k, v) = o.split_once('=').unwrap_or((o, ""));
        match k {
            "fd" => fd = v.parse::<i32>().ok(),
            "rootmode" => rootmode = u32::from_str_radix(v, 8).ok(),
            "user_id" => uid = v.parse::<u32>().ok(),
            "group_id" => gid = v.parse::<u32>().ok(),
            "allow_other" => other = true,
            _ => {}
        }
    }
    match (fd, rootmode, uid, gid) {
        (Some(f), Some(r), Some(u), Some(g)) => Ok((f, r, u, g, other)),
        _ => Err(EINVAL),
    }
}

/// The connection behind descriptor `fd` (an open `/dev/fuse`).
// wave9 G6b-2 begin
/// The slot of descriptor `fd` when it is an open `/dev/fuse` of vfs-server's (`None`: some
/// other descriptor, the kernel's own client decides).
fn remote_slot_of_fd(fd: i32) -> Result<u64, i64> {
    let d = crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
        _ => None,
    })
    .ok_or(EBADF)?;
    // (wave9 G9-C: only vfs-server's `/dev/fuse`; the kernel's own is gone)
    let Some(o) = d.as_server() else { return Err(EINVAL) };
    if o.kind() != crate::ipc::protocol::LX_OBJ_KIND_FUSE {
        return Err(EINVAL);
    }
    o.slot().map(|s| s as u64).ok_or(EBADF)
}
// wave9 G6b-2 end

/// Mounts the connection named by `data`'s `fd=` on `(path, mountpoint)`.
///
/// # Returns
/// The connection's root directory, to enter in the caller's mount table (initial
/// namespace: `ns0` records the mount here).
pub fn mount(path: &str, mountpoint: u64, fstype: &str, source: &str, flags: u64, data: &str, ns0: bool) -> Result<u64, i64> {
    let (fd, _rootmode, uid, gid, other) = options(data)?;
    // wave9 G6b-2: a /dev/fuse of vfs-server's: it starts the connection (INIT)
    let slot = remote_slot_of_fd(fd);
    if let Err(e) = slot {
        crate::kprintln!("[fuse] mount: fd {} is not a /dev/fuse: {}", fd, e);
    }
    let id = super::fuse_svc::mount(slot?, uid, gid, other)?;
    let root = super::fuse_svc::root_of(id);
    if ns0 {
        let mut opts = String::from(if flags & 1 != 0 { "ro" } else { "rw" });
        for (bit, name) in [(2u64, "nosuid"), (4, "nodev"), (8, "noexec")] {
            if flags & bit != 0 {
                opts.push(',');
                opts.push_str(name);
            }
        }
        opts.push_str(&alloc::format!(",relatime,user_id={},group_id={}", uid, gid));
        if other {
            opts.push_str(",allow_other");
        }
        ns0_add(Ns0Mount { mountpoint, root, path: String::from(path), fstype: String::from(fstype), source: String::from(source), opts });
    }
    Ok(root)
}

/// Whether `fstype` is a FUSE file system type (`fuse`, `fuse.<name>`).
pub fn is_fuse_type(fstype: &str) -> bool {
    fstype == "fuse" || fstype.starts_with("fuse.")
}
