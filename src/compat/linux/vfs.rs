//! # Linux File System Calls (VFS layer)
//!
//! Implements the Linux file and directory system calls on top of the ZFS POSIX layer:
//! path resolution relative to `AT_FDCWD` or a directory descriptor, symbolic links,
//! `stat`/`statx`, `getdents64`, permission checks against the caller's credentials,
//! `umask`, and the per-process working directory. Character-device inodes and the
//! fixed `/dev` and `/proc` paths are served by the pseudo files in [`super::fs`].
//!
//! [`dispatch`] returns `None` for system calls (or descriptor kinds) it does not own, so
//! the caller falls back to the remaining handlers in [`super::dispatch_linux_syscall`].

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::fs::fd::{FileDescriptor, OpenFile, O_ACCMODE, O_APPEND, O_RDONLY, O_WRONLY};
use crate::fs::zfs::types::{dtype_from_mode, S_IFCHR, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use crate::fs::zfs::zpl::{Attr, SetAttr};
use crate::fs::ZfsClient;
use crate::memory::vm::prefault_current;

// System call numbers handled here
const NR_OPEN: u64 = 2;
const NR_STAT: u64 = 4;
const NR_FSTAT: u64 = 5;
const NR_LSTAT: u64 = 6;
const NR_LSEEK: u64 = 8;
const NR_ACCESS: u64 = 21;
const NR_DUP: u64 = 32;
const NR_DUP2: u64 = 33;
const NR_FCNTL: u64 = 72;
const NR_FSYNC: u64 = 74;
const NR_FDATASYNC: u64 = 75;
const NR_TRUNCATE: u64 = 76;
const NR_FTRUNCATE: u64 = 77;
const NR_GETCWD: u64 = 79;
const NR_CHDIR: u64 = 80;
const NR_FCHDIR: u64 = 81;
const NR_RENAME: u64 = 82;
const NR_MKDIR: u64 = 83;
const NR_RMDIR: u64 = 84;
const NR_CREAT: u64 = 85;
const NR_LINK: u64 = 86;
const NR_UNLINK: u64 = 87;
const NR_SYMLINK: u64 = 88;
const NR_READLINK: u64 = 89;
const NR_CHMOD: u64 = 90;
const NR_FCHMOD: u64 = 91;
const NR_CHOWN: u64 = 92;
const NR_FCHOWN: u64 = 93;
const NR_LCHOWN: u64 = 94;
const NR_UMASK: u64 = 95;
const NR_MKNOD: u64 = 133;
const NR_STATFS: u64 = 137;
const NR_FSTATFS: u64 = 138;
const NR_SYNC: u64 = 162;
const NR_GETDENTS64: u64 = 217;
const NR_OPENAT: u64 = 257;
const NR_MKDIRAT: u64 = 258;
const NR_MKNODAT: u64 = 259;
const NR_FCHOWNAT: u64 = 260;
const NR_NEWFSTATAT: u64 = 262;
const NR_UNLINKAT: u64 = 263;
const NR_RENAMEAT: u64 = 264;
const NR_LINKAT: u64 = 265;
const NR_SYMLINKAT: u64 = 266;
const NR_READLINKAT: u64 = 267;
const NR_FCHMODAT: u64 = 268;
const NR_FACCESSAT: u64 = 269;
const NR_UTIMENSAT: u64 = 280;
const NR_DUP3: u64 = 292;
const NR_SYNCFS: u64 = 306;
const NR_RENAMEAT2: u64 = 316;
const NR_STATX: u64 = 332;
const NR_FACCESSAT2: u64 = 439;

// errno
const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EISDIR: i64 = -21;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENXIO: i64 = -6;
const ERANGE: i64 = -34;
const ELOOP: i64 = -40;
const EOPNOTSUPP: i64 = -95;

// open flags
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_NOCTTY: u32 = 0o400;
const O_NONBLOCK: u32 = 0o4000;
const O_DIRECTORY: u32 = 0o200000;
const O_NOFOLLOW: u32 = 0o400000;
const O_CLOEXEC: u32 = 0o2000000;
const O_PATH: u32 = 0o10000000;
const O_TMPFILE_MASK: u32 = 0o20000000;

// *at flags
const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EACCESS: u64 = 0x200;
const AT_SYMLINK_FOLLOW: u64 = 0x400;
const AT_EMPTY_PATH: u64 = 0x1000;

const RENAME_NOREPLACE: u64 = 1;
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// Device number reported for files on the ZFS pool.
const ZFS_DEV: u64 = 0x0801;
const ZFS_SUPER_MAGIC: i64 = 0x2fc1_2fc1;

// ----------------------------------------------------------------------
// User memory helpers
// ----------------------------------------------------------------------

/// Copies a NUL-terminated string (at most `PATH_MAX`) from user memory.
pub(crate) fn user_cstr(ptr: u64) -> Result<Vec<u8>, i64> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let mut out = Vec::new();
    let mut addr = ptr;
    loop {
        let page_end = (addr | 0xFFF) + 1;
        if !prefault_current(addr, page_end - addr, false) {
            return Err(EFAULT);
        }
        while addr < page_end {
            let b = unsafe { *(addr as *const u8) };
            if b == 0 {
                return Ok(out);
            }
            out.push(b);
            if out.len() >= 4096 {
                return Err(-36); // ENAMETOOLONG
            }
            addr += 1;
        }
    }
}

pub(crate) fn user_path(ptr: u64) -> Result<Vec<u8>, i64> {
    let p = user_cstr(ptr)?;
    if p.is_empty() {
        return Err(ENOENT);
    }
    Ok(p)
}

/// Copies `data` to user memory at `ptr`.
pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
    if ptr == 0 || !prefault_current(ptr, data.len() as u64, true) {
        return Err(EFAULT);
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    Ok(())
}

pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
    if ptr == 0 || !prefault_current(ptr, len as u64, false) {
        return Err(EFAULT);
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Ok(v)
}

// ----------------------------------------------------------------------
// Process context
// ----------------------------------------------------------------------

pub(crate) struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
}

pub(crate) fn creds() -> Creds {
    crate::task::with_current_task_mut(|t| Creds { uid: t.uid, gid: t.gid, euid: t.euid, egid: t.egid }).unwrap_or(Creds {
        uid: 0,
        gid: 0,
        euid: 0,
        egid: 0,
    })
}

fn umask() -> u32 {
    crate::task::with_current_fds_mut(|fds| fds.umask)
}

/// The process root directory (0 = pool root).
pub(crate) fn proc_root() -> u64 {
    crate::task::with_current_fds_mut(|fds| fds.root_ino)
}

pub(crate) fn resolve(base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
    ZfsClient::resolve_in(proc_root(), base, path, follow)
}

/// Lookup key of a Unix socket path: the process root and the absolute path, so the
/// same name means the same socket to every process sharing that root.
pub(crate) fn socket_key(path: &[u8]) -> Result<Vec<u8>, i64> {
    let (_, base_path) = base_dir(AT_FDCWD, path)?;
    let abs = join_path(&base_path, path);
    let mut key = alloc::format!("{}:", proc_root()).into_bytes();
    key.extend_from_slice(abs.as_bytes());
    Ok(key)
}

/// Creates the socket node `bind` makes for a path name (mode 0777 minus the umask).
pub(crate) fn make_socket_node(path: &[u8]) -> Result<(), i64> {
    const S_IFSOCK: u32 = 0o140000;
    let (base, _) = base_dir(AT_FDCWD, path)?;
    let (dir, name) = resolve_parent(base, path)?;
    let c = creds();
    let pattr = ZfsClient::getattr(dir)?;
    if !may_access(&pattr, c.euid, c.egid, 2 | 1) {
        return Err(EACCES);
    }
    let mode = S_IFSOCK | (0o777 & !umask());
    zfs(|s| s.mknod(dir, &name, mode, 0, c.euid, c.egid).map(|_| ()))
}

/// Resolves a user path to (inode, is a directory) for the caller.
pub(crate) fn lookup_path(path_ptr: u64, follow: bool) -> Result<(u64, bool), i64> {
    let path = user_path(path_ptr)?;
    let (base, _) = base_dir(AT_FDCWD, &path)?;
    let ino = resolve(base, &path, follow)?;
    Ok((ino, ZfsClient::getattr(ino)?.is_dir()))
}

/// True if `path` names an existing file.
pub(crate) fn path_exists(path: &[u8]) -> bool {
    base_dir(AT_FDCWD, path).and_then(|(base, _)| resolve(base, path, true)).is_ok()
}

fn resolve_parent(base: u64, path: &[u8]) -> Result<(u64, Vec<u8>), i64> {
    ZfsClient::resolve_parent_in(proc_root(), base, path)
}

/// The directory a path is resolved against: (inode, absolute path). Inode 0 means the
/// process root.
pub(crate) fn base_dir(dirfd: i64, path: &[u8]) -> Result<(u64, String), i64> {
    if path.first() == Some(&b'/') {
        return Ok((0, String::from("/")));
    }
    if dirfd as i32 == AT_FDCWD as i32 {
        return Ok(crate::task::with_current_fds_mut(|fds| (fds.cwd_ino, fds.cwd_path.clone())));
    }
    match fd_vnode(dirfd as i32) {
        Some(f) => {
            let f = f.lock();
            Ok((f.ino, f.path.clone()))
        }
        None => Err(if fd_exists(dirfd as i32) { ENOTDIR } else { EBADF }),
    }
}

fn fd_vnode(fd: i32) -> Option<Arc<Mutex<OpenFile>>> {
    if fd < 0 {
        return None;
    }
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(FileDescriptor::Vnode(f)) => Some(f.clone()),
        _ => None,
    })
}

fn inet_of(fd: usize) -> Option<Arc<Mutex<super::inet::InetSocket>>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::Inet(s)) => Some(s.clone()),
        _ => None,
    })
}

fn fd_exists(fd: i32) -> bool {
    fd >= 0 && crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).is_some())
}

/// Lexically joins and normalises `path` onto absolute directory `base`.
pub(crate) fn join_path(base: &str, path: &[u8]) -> String {
    let mut parts: Vec<&[u8]> = Vec::new();
    let path_abs = path.first() == Some(&b'/');
    if !path_abs {
        parts.extend(base.as_bytes().split(|&c| c == b'/').filter(|c| !c.is_empty()));
    }
    for c in path.split(|&c| c == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            _ => parts.push(c),
        }
    }
    let mut out = String::from("/");
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&String::from_utf8_lossy(p));
    }
    out
}

fn is_pseudo(abs: &str) -> bool {
    super::fs::match_pseudo_path(abs).is_some()
}

/// Pseudo file path served for a character device number.
fn chardev_path(rdev: u64) -> Option<&'static str> {
    let (major, minor) = ((rdev >> 8) & 0xFFF, (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00));
    match (major, minor) {
        (1, 3) => Some("/dev/null"),
        (1, 5) => Some("/dev/zero"),
        (1, 8) | (1, 9) => Some("/dev/urandom"),
        _ => None,
    }
}

/// Path of a pseudo-terminal device node by device number (`/dev/ptmx`, `/dev/pts/N`,
/// and `/dev/tty`, 5:0, which names the caller's controlling terminal).
fn pty_chardev_path(rdev: u64) -> Option<String> {
    let (major, minor) = ((rdev >> 8) & 0xFFF, (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00));
    match (major, minor) {
        (5, 0) => Some(String::from("/dev/tty")),
        (5, 2) => Some(String::from("/dev/ptmx")),
        (136..=143, _) => Some(alloc::format!("/dev/pts/{}", ((major - 136) << 8) | minor)),
        _ => None,
    }
}

/// Opens `/dev/ptmx`, a `/dev/pts/N` slave, or `/dev/tty` when the caller's controlling
/// terminal is a pseudo-terminal. `None` for other paths.
fn open_pty_path(abs: &str, flags: u32) -> Result<Option<FileDescriptor>, i64> {
    let nonblock = flags & O_NONBLOCK != 0;
    if abs == "/dev/ptmx" {
        return Ok(Some(FileDescriptor::Pty(super::pty::open_master(creds().euid, nonblock))));
    }
    if let Some(index) = super::pty::slave_index(abs) {
        return super::pty::open_slave(index, nonblock, flags & O_NOCTTY != 0).map(|f| Some(FileDescriptor::Pty(f)));
    }
    if abs == "/dev/tty" {
        return Ok(super::pty::open_controlling(nonblock).map(FileDescriptor::Pty));
    }
    Ok(None)
}

pub(crate) fn may_access(attr: &Attr, uid: u32, gid: u32, want: u32) -> bool {
    if uid == 0 {
        // root may read/write anything and execute anything with an x bit (or a directory)
        return want & 1 == 0 || attr.mode & 0o111 != 0 || attr.is_dir();
    }
    let bits = if attr.uid == uid {
        (attr.mode >> 6) & 7
    } else if attr.gid == gid {
        (attr.mode >> 3) & 7
    } else {
        attr.mode & 7
    };
    bits & want == want
}

// ----------------------------------------------------------------------
// stat structures
// ----------------------------------------------------------------------

fn fill_stat(attr: &Attr) -> super::types::LinuxStat {
    let mut st = super::types::LinuxStat::default();
    st.st_dev = ZFS_DEV;
    st.st_ino = attr.ino;
    st.st_nlink = attr.nlink as u64;
    st.st_mode = attr.mode;
    st.st_uid = attr.uid;
    st.st_gid = attr.gid;
    st.st_rdev = attr.rdev;
    st.st_size = attr.size as i64;
    st.st_blksize = 4096;
    st.st_blocks = attr.blocks as i64;
    st.st_atime = attr.atime.0;
    st.st_atime_nsec = attr.atime.1 as i64;
    st.st_mtime = attr.mtime.0;
    st.st_mtime_nsec = attr.mtime.1 as i64;
    st.st_ctime = attr.ctime.0;
    st.st_ctime_nsec = attr.ctime.1 as i64;
    st
}

/// stat of the Hydra console (`/dev/tty1`, char device 4:1, and its aliases): what
/// `fstat` on a console descriptor reports, so `ttyname` can match the two.
fn console_stat() -> super::types::LinuxStat {
    let mut st = super::types::LinuxStat::default();
    st.st_dev = super::pty::PTS_DEV + 1;
    st.st_ino = 0x401;
    st.st_mode = 0o020620;
    st.st_nlink = 1;
    st.st_gid = 5; // tty
    st.st_rdev = super::pty::makedev(4, 1);
    st.st_blksize = 1024;
    st
}

fn is_console_path(abs: &str) -> bool {
    matches!(abs, "/dev/tty1" | "/dev/tty0" | "/dev/console")
}

fn pseudo_stat(abs: &str) -> super::types::LinuxStat {
    let mut st = super::types::LinuxStat::default();
    if let Some(p) = super::fs::match_pseudo_path(abs) {
        p.stat(&mut st);
    }
    st
}

fn write_stat(ptr: u64, st: &super::types::LinuxStat) -> i64 {
    let bytes = unsafe {
        core::slice::from_raw_parts(st as *const _ as *const u8, core::mem::size_of::<super::types::LinuxStat>())
    };
    match copy_out(ptr, bytes) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn write_statx(ptr: u64, st: &super::types::LinuxStat) -> i64 {
    let mut b = [0u8; 256];
    let put32 = |b: &mut [u8; 256], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    let put64 = |b: &mut [u8; 256], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put32(&mut b, 0, 0x17FF); // STATX_BASIC_STATS | STATX_MNT_ID
    // One mount per device number (the pool, devpts, the console, devices)
    put64(&mut b, 144, 20 + (st.st_dev & 0xFFFF));
    put32(&mut b, 4, st.st_blksize as u32);
    put32(&mut b, 16, st.st_nlink as u32);
    put32(&mut b, 20, st.st_uid);
    put32(&mut b, 24, st.st_gid);
    b[28..30].copy_from_slice(&(st.st_mode as u16).to_le_bytes());
    put64(&mut b, 32, st.st_ino);
    put64(&mut b, 40, st.st_size as u64);
    put64(&mut b, 48, st.st_blocks as u64);
    for (off, (s, ns)) in [
        (64, (st.st_atime, st.st_atime_nsec)),
        (80, (st.st_ctime, st.st_ctime_nsec)),
        (96, (st.st_ctime, st.st_ctime_nsec)),
        (112, (st.st_mtime, st.st_mtime_nsec)),
    ] {
        put64(&mut b, off, s as u64);
        put32(&mut b, off + 8, ns as u32);
    }
    put32(&mut b, 128, ((st.st_rdev >> 8) & 0xFFF) as u32);
    put32(&mut b, 132, (st.st_rdev & 0xFF) as u32);
    put32(&mut b, 136, ((st.st_dev >> 8) & 0xFFF) as u32);
    put32(&mut b, 140, (st.st_dev & 0xFF) as u32);
    match copy_out(ptr, &b) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ----------------------------------------------------------------------
// Path-based operations
// ----------------------------------------------------------------------

/// Resolves `dirfd`/`path` to a stat buffer, honouring pseudo files.
fn stat_at(dirfd: i64, path_ptr: u64, flags: u64) -> Result<super::types::LinuxStat, i64> {
    let path = user_cstr(path_ptr)?;
    if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ENOENT);
        }
        return fstat_fd(dirfd as i32).ok_or(EBADF)?;
    }
    let (base, base_path) = base_dir(dirfd, &path)?;
    let abs = join_path(&base_path, &path);
    if let Some(st) = super::pty::stat_path(&abs) {
        return st;
    }
    if is_console_path(&abs) {
        return Ok(console_stat());
    }
    if is_pseudo(&abs) {
        return Ok(pseudo_stat(&abs));
    }
    let ino = resolve(base, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    Ok(fill_stat(&ZfsClient::getattr(ino)?))
}

/// stat of an open descriptor, or `None` if the descriptor is not a file this layer owns.
fn fstat_fd(fd: i32) -> Option<Result<super::types::LinuxStat, i64>> {
    if fd < 0 {
        return Some(Err(EBADF));
    }
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).cloned());
    match desc {
        Some(FileDescriptor::Vnode(f)) => {
            let ino = f.lock().ino;
            Some(ZfsClient::getattr(ino).map(|a| fill_stat(&a)))
        }
        Some(FileDescriptor::File { path, .. }) if is_pseudo(&path) => Some(Ok(pseudo_stat(&path))),
        Some(FileDescriptor::Pty(p)) => Some(Ok(p.stat())),
        Some(FileDescriptor::Device(d)) => Some(Ok(d.stat())),
        Some(FileDescriptor::Unix(s)) => {
            let mut st = super::types::LinuxStat::default();
            st.st_dev = 0x8;
            st.st_ino = s.ino();
            st.st_mode = 0o140777;
            st.st_nlink = 1;
            st.st_blksize = 4096;
            Some(Ok(st))
        }
        Some(FileDescriptor::ConsoleIn) | Some(FileDescriptor::ConsoleOut) | Some(FileDescriptor::ConsoleErr) => {
            Some(Ok(console_stat()))
        }
        None => Some(Err(EBADF)),
        _ => None,
    }
}

fn open_at(dirfd: i64, path_ptr: u64, flags: u32, mode: u32) -> i64 {
    let path = match user_path(path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match open_path(dirfd, &path, flags, mode) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

/// Opens a path for the current process, returning the new descriptor.
pub fn open_path(dirfd: i64, path: &[u8], flags: u32, mode: u32) -> Result<usize, i64> {
    if flags & O_TMPFILE_MASK != 0 {
        return Err(EOPNOTSUPP);
    }
    let (base, base_path) = base_dir(dirfd, path)?;
    let abs = join_path(&base_path, path);
    let acc = flags & O_ACCMODE;
    let wants_write = acc != O_RDONLY || flags & O_TRUNC != 0;

    if let Some(desc) = open_pty_path(&abs, flags)? {
        return install(desc, flags);
    }
    if let Some(target) = fd_link(&abs).or_else(|| super::fs::proc_link(&abs)) {
        // Magic links (/proc/self/exe, /proc/self/fd/N) open what they point at
        if target.starts_with('/') && target != abs {
            return open_path(AT_FDCWD, target.as_bytes(), flags, mode);
        }
    }
    if matches!(abs.as_str(), "/dev/tty" | "/dev/console" | "/dev/tty0" | "/dev/tty1") {
        return install(FileDescriptor::ConsoleOut, flags);
    }
    if is_pseudo(&abs) {
        return install(
            FileDescriptor::File {
                path: abs,
                cursor: 0,
                readable: acc != O_WRONLY,
                writable: acc != O_RDONLY,
                append: false,
            },
            flags,
        );
    }

    let c = creds();
    let follow = flags & O_NOFOLLOW == 0;
    let ino = if flags & O_CREAT != 0 {
        match resolve(base, path, follow) {
            Ok(ino) => {
                if flags & O_EXCL != 0 {
                    return Err(EEXIST);
                }
                ino
            }
            Err(ENOENT) => {
                let (parent, name) = resolve_parent(base, path)?;
                let pattr = ZfsClient::getattr(parent)?;
                if !may_access(&pattr, c.euid, c.egid, 2 | 1) {
                    return Err(EACCES);
                }
                let perm = mode & 0o7777 & !umask();
                crate::fs::zfs::with_server(|s| s.create(parent, &name, perm, c.euid, c.egid))?
            }
            Err(e) => return Err(e),
        }
    } else {
        resolve(base, path, follow)?
    };

    let attr = ZfsClient::getattr(ino)?;
    let ftype = attr.mode & S_IFMT;
    if ftype == S_IFLNK && flags & O_PATH == 0 {
        return Err(ELOOP);
    }
    if flags & O_DIRECTORY != 0 && ftype != S_IFDIR {
        return Err(ENOTDIR);
    }
    if ftype == S_IFDIR && acc != O_RDONLY {
        return Err(EISDIR);
    }
    if flags & O_PATH == 0 {
        let want = match acc {
            O_RDONLY => 4,
            O_WRONLY => 2,
            _ => 6,
        };
        if !may_access(&attr, c.euid, c.egid, if wants_write { want | 2 } else { want }) {
            return Err(EACCES);
        }
    }
    if ftype == S_IFCHR {
        if let Some(dev) = super::chardev::open(attr.rdev, flags) {
            return install(FileDescriptor::Device(dev?), flags);
        }
        if let Some(path) = pty_chardev_path(attr.rdev) {
            if let Some(desc) = open_pty_path(&path, flags)? {
                return install(desc, flags);
            }
        }
        let dev = chardev_path(attr.rdev).ok_or(ENXIO)?;
        return install(
            FileDescriptor::File {
                path: String::from(dev),
                cursor: 0,
                readable: acc != O_WRONLY,
                writable: acc != O_RDONLY,
                append: false,
            },
            flags,
        );
    }
    if flags & O_TRUNC != 0 && ftype == S_IFREG && acc != O_RDONLY {
        ZfsClient::setattr(ino, SetAttr { size: Some(0), ..SetAttr::default() })?;
    }
    let keep = flags & (O_ACCMODE | O_APPEND | O_NONBLOCK | O_DIRECTORY | O_PATH);
    install(FileDescriptor::Vnode(OpenFile::new(ino, keep, abs)), flags)
}

fn install(desc: FileDescriptor, flags: u32) -> Result<usize, i64> {
    crate::task::with_current_fds_mut(|fds| {
        let fd = fds.alloc_fd(desc).map_err(|_| EMFILE)?;
        fds.set_cloexec(fd, flags & O_CLOEXEC != 0);
        Ok(fd)
    })
}

fn getdents64(fd: i32, buf: u64, count: usize) -> i64 {
    let file = match fd_vnode(fd) {
        Some(f) => f,
        None => return if fd_exists(fd) { ENOTDIR } else { EBADF },
    };
    let (ino, cookie) = {
        let f = file.lock();
        (f.ino, f.offset)
    };
    match ZfsClient::getattr(ino) {
        Ok(a) if a.is_dir() => {}
        Ok(_) => return ENOTDIR,
        Err(e) => return e,
    }
    let entries = match ZfsClient::readdir(ino, cookie, (count / 24).max(1)) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let mut out: Vec<u8> = Vec::with_capacity(count);
    let mut next = cookie;
    for e in entries {
        let reclen = (19 + e.name.len() + 1 + 7) & !7;
        if out.len() + reclen > count {
            break;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(e.next_cookie as i64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(e.dtype);
        out.extend_from_slice(&e.name);
        out.resize(start + reclen, 0);
        next = e.next_cookie;
    }
    if out.is_empty() && next != cookie {
        return EINVAL;
    }
    if out.is_empty() {
        // Either the end of the directory or a buffer too small for the next entry
        let more = ZfsClient::readdir(ino, cookie, 1).map(|v| !v.is_empty()).unwrap_or(false);
        return if more { EINVAL } else { 0 };
    }
    if let Err(e) = copy_out(buf, &out) {
        return e;
    }
    file.lock().offset = next;
    out.len() as i64
}

fn lseek(fd: i32, offset: i64, whence: u32) -> Option<i64> {
    let file = fd_vnode(fd)?;
    let mut f = file.lock();
    let attr = match ZfsClient::getattr(f.ino) {
        Ok(a) => a,
        Err(e) => return Some(e),
    };
    if attr.is_dir() {
        // Directory streams can only be rewound or restored to a telldir cookie
        return Some(match whence {
            0 if offset >= 0 => {
                f.offset = offset as u64;
                offset
            }
            1 if offset == 0 => f.offset as i64,
            _ => EINVAL,
        });
    }
    let size = attr.size as i64;
    let new = match whence {
        0 => offset,
        1 => f.offset as i64 + offset,
        2 => size + offset,
        3 => {
            // SEEK_DATA: files have no holes as far as callers are concerned
            if offset >= size {
                return Some(ENXIO);
            }
            offset
        }
        4 => {
            // SEEK_HOLE: the only hole is past the end
            if offset >= size {
                return Some(ENXIO);
            }
            size
        }
        _ => return Some(EINVAL),
    };
    if new < 0 {
        return Some(EINVAL);
    }
    f.offset = new as u64;
    Some(new)
}

fn access_at(dirfd: i64, path_ptr: u64, mode: u32, flags: u64) -> i64 {
    let path = match user_path(path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let r: Result<(), i64> = (|| {
        let (base, base_path) = base_dir(dirfd, &path)?;
        if is_pseudo(&join_path(&base_path, &path)) {
            return Ok(());
        }
        let ino = resolve(base, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
        if mode & 7 == 0 {
            return Ok(());
        }
        let attr = ZfsClient::getattr(ino)?;
        let c = creds();
        let (uid, gid) = if flags & AT_EACCESS != 0 { (c.euid, c.egid) } else { (c.uid, c.gid) };
        if may_access(&attr, uid, gid, mode & 7) {
            Ok(())
        } else {
            Err(EACCES)
        }
    })();
    r.err().unwrap_or(0)
}

/// Target of `/proc/self/fd/N` (also `/proc/<own pid>/fd/N`): what descriptor N refers to.
fn fd_link(abs: &str) -> Option<String> {
    let rest = abs.strip_prefix("/proc/")?;
    let (who, fd) = rest.split_once("/fd/")?;
    let (_, pid) = super::proc::current_ids();
    if who != "self" && who.parse::<u64>().ok() != Some(pid) {
        return None;
    }
    let fd: usize = fd.parse().ok()?;
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd).cloned())?;
    Some(match desc {
        FileDescriptor::Pty(p) => p.path(),
        FileDescriptor::Vnode(f) => f.lock().path.clone(),
        FileDescriptor::File { path, .. } => path,
        FileDescriptor::ConsoleIn | FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr => String::from("/dev/tty1"),
        FileDescriptor::PipeRead(p) | FileDescriptor::PipeWrite(p) => {
            alloc::format!("pipe:[{}]", Arc::as_ptr(&p) as usize as u64 & 0xFFFF_FFFF)
        }
        FileDescriptor::Socket(s) => alloc::format!("socket:[{}]", Arc::as_ptr(&s) as usize as u64 & 0xFFFF_FFFF),
        FileDescriptor::Inet(s) => alloc::format!("socket:[{}]", Arc::as_ptr(&s) as usize as u64 & 0xFFFF_FFFF),
        FileDescriptor::Unix(s) => alloc::format!("socket:[{}]", s.ino()),
        FileDescriptor::TimerFd(_) => String::from("anon_inode:[timerfd]"),
        FileDescriptor::Inotify(_) => String::from("anon_inode:inotify"),
        FileDescriptor::PidFd(_) => String::from("anon_inode:[pidfd]"),
        FileDescriptor::Epoll(_) => String::from("anon_inode:[eventpoll]"),
        FileDescriptor::EventFd(_) => String::from("anon_inode:[eventfd]"),
        FileDescriptor::SignalFd(_) => String::from("anon_inode:[signalfd]"),
        FileDescriptor::MemFd(_) => String::from("/memfd: (deleted)"),
        FileDescriptor::Device(d) => d.path(),
    })
}

fn readlink_at(dirfd: i64, path_ptr: u64, buf: u64, size: usize) -> i64 {
    if size == 0 {
        return EINVAL;
    }
    let path = match user_path(path_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let r: Result<i64, i64> = (|| {
        let (base, base_path) = base_dir(dirfd, &path)?;
        let abs = join_path(&base_path, &path);
        if let Some(target) = fd_link(&abs) {
            let n = target.len().min(size);
            copy_out(buf, &target.as_bytes()[..n])?;
            return Ok(n as i64);
        }
        if let Some(target) = super::fs::proc_link(&abs) {
            let n = target.len().min(size);
            copy_out(buf, &target.as_bytes()[..n])?;
            return Ok(n as i64);
        }
        let ino = resolve(base, &path, false)?;
        let target = ZfsClient::readlink(ino)?;
        let n = target.len().min(size);
        copy_out(buf, &target[..n])?;
        Ok(n as i64)
    })();
    r.unwrap_or_else(|e| e)
}

/// Runs `f` on the parent directory and final name of `dirfd`/`path`, after checking that
/// the caller may modify the parent.
fn with_parent(dirfd: i64, path_ptr: u64, f: impl FnOnce(u64, &[u8], &Creds) -> Result<i64, i64>) -> i64 {
    let r: Result<i64, i64> = (|| {
        let path = user_path(path_ptr)?;
        let (base, _) = base_dir(dirfd, &path)?;
        let (parent, name) = resolve_parent(base, &path)?;
        let c = creds();
        let pattr = ZfsClient::getattr(parent)?;
        if !pattr.is_dir() {
            return Err(ENOTDIR);
        }
        if !may_access(&pattr, c.euid, c.egid, 2 | 1) {
            return Err(EACCES);
        }
        f(parent, &name, &c)
    })();
    r.unwrap_or_else(|e| e)
}

fn zfs<R>(f: impl FnOnce(&mut crate::fs::zfs::ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
    crate::fs::zfs::with_server(f)
}

fn rename_at(olddir: i64, oldp: u64, newdir: i64, newp: u64, flags: u64) -> i64 {
    if flags & !RENAME_NOREPLACE != 0 {
        return EINVAL; // RENAME_EXCHANGE / RENAME_WHITEOUT are not supported
    }
    let r: Result<i64, i64> = (|| {
        let op = user_path(oldp)?;
        let np = user_path(newp)?;
        let (ob, _) = base_dir(olddir, &op)?;
        let (nb, _) = base_dir(newdir, &np)?;
        let (sdir, sname) = resolve_parent(ob, &op)?;
        let (ddir, dname) = resolve_parent(nb, &np)?;
        let c = creds();
        for d in [sdir, ddir] {
            if !may_access(&ZfsClient::getattr(d)?, c.euid, c.egid, 3) {
                return Err(EACCES);
            }
        }
        zfs(|s| {
            if flags & RENAME_NOREPLACE != 0 && s.lookup(ddir, &dname).is_ok() {
                return Err(EEXIST);
            }
            s.rename(sdir, &sname, ddir, &dname).map(|_| 0)
        })
    })();
    r.unwrap_or_else(|e| e)
}

fn link_at(olddir: i64, oldp: u64, newdir: i64, newp: u64, flags: u64) -> i64 {
    let r: Result<i64, i64> = (|| {
        let op = user_cstr(oldp)?;
        let ino = if op.is_empty() {
            if flags & AT_EMPTY_PATH == 0 {
                return Err(ENOENT);
            }
            fd_vnode(olddir as i32).ok_or(EBADF)?.lock().ino
        } else {
            let (ob, _) = base_dir(olddir, &op)?;
            resolve(ob, &op, flags & AT_SYMLINK_FOLLOW != 0)?
        };
        Ok(with_parent(newdir, newp, |dir, name, _| zfs(|s| s.link(ino, dir, name).map(|_| 0))))
    })();
    r.unwrap_or_else(|e| e)
}

/// Applies an attribute change to `dirfd`/`path` (or the descriptor itself for an empty
/// path with `AT_EMPTY_PATH`), after an ownership/permission check by `check`.
fn setattr_at(dirfd: i64, path_ptr: u64, follow: bool, empty_ok: bool, set: SetAttr, check: impl FnOnce(&Attr, &Creds) -> bool) -> i64 {
    let r: Result<i64, i64> = (|| {
        let path = if path_ptr == 0 { Vec::new() } else { user_cstr(path_ptr)? };
        let ino = if path.is_empty() {
            if !empty_ok {
                return Err(ENOENT);
            }
            fd_vnode(dirfd as i32).ok_or(EBADF)?.lock().ino
        } else {
            let (base, base_path) = base_dir(dirfd, &path)?;
            let abs = join_path(&base_path, &path);
            if let Some(r) = super::pty::setattr_path(&abs, creds().euid, set.mode, set.uid, set.gid) {
                return if r < 0 { Err(r) } else { Ok(0) };
            }
            if is_pseudo(&abs) {
                return Ok(0);
            }
            resolve(base, &path, follow)?
        };
        let attr = ZfsClient::getattr(ino)?;
        if !check(&attr, &creds()) {
            return Err(EPERM);
        }
        ZfsClient::setattr(ino, set)?;
        Ok(0)
    })();
    r.unwrap_or_else(|e| e)
}

fn owner_or_root(a: &Attr, c: &Creds) -> bool {
    c.euid == 0 || c.euid == a.uid
}

fn chown_set(uid: u64, gid: u64) -> SetAttr {
    SetAttr {
        uid: if uid as u32 == u32::MAX { None } else { Some(uid as u32) },
        gid: if gid as u32 == u32::MAX { None } else { Some(gid as u32) },
        ..SetAttr::default()
    }
}

fn utimens(dirfd: i64, path_ptr: u64, times_ptr: u64, flags: u64) -> i64 {
    let now = crate::arch::rtc::now();
    let now = (now.0 as i64, now.1);
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        let raw = match copy_in(times_ptr, 32) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let ts = |off: usize| {
            let s = i64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
            let ns = i64::from_le_bytes(raw[off + 8..off + 16].try_into().unwrap());
            match ns {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                _ => Some((s, ns as u32)),
            }
        };
        (ts(0), ts(16))
    };
    let set = SetAttr { atime, mtime, ..SetAttr::default() };
    setattr_at(dirfd, path_ptr, flags & AT_SYMLINK_NOFOLLOW == 0, true, set, |a, c| c.euid == 0 || c.euid == a.uid || times_ptr == 0)
}

/// `f_type` of the devpts file system (glibc checks it before using `/dev/ptmx`).
const DEVPTS_SUPER_MAGIC: i64 = 0x1cd1;

/// The file system type `statfs` reports for an absolute path: the pseudo file systems
/// Linux mounts at `/proc`, `/sys` and `/dev/pts` (programs such as libudev check their
/// magic numbers), the pool for everything else.
fn fs_magic(abs: &str) -> i64 {
    let under = |dir: &str| abs == dir || abs.starts_with(&alloc::format!("{}/", dir));
    if under("/dev/pts") || abs == "/dev/ptmx" {
        DEVPTS_SUPER_MAGIC
    } else if under("/proc") {
        0x9fa0 // PROC_SUPER_MAGIC
    } else if under("/sys") {
        0x6265_6572 // SYSFS_MAGIC
    } else {
        ZFS_SUPER_MAGIC
    }
}

fn statfs_out(ptr: u64, magic: i64) -> i64 {
    let (total, free, objs) = match zfs(|s| Ok(s.statfs())) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut b = [0u8; 120];
    let vals: [i64; 7] = if magic != ZFS_SUPER_MAGIC {
        [magic, if magic == DEVPTS_SUPER_MAGIC { 1024 } else { 4096 }, 0, 0, 0, 0, 0]
    } else {
        [ZFS_SUPER_MAGIC, 4096, total as i64, free as i64, free as i64, (objs + 1_000_000) as i64, 1_000_000]
    };
    for (i, v) in vals.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    b[64..72].copy_from_slice(&255i64.to_le_bytes()); // f_namelen
    b[72..80].copy_from_slice(&4096i64.to_le_bytes()); // f_frsize
    match copy_out(ptr, &b) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Physical absolute path (inside the process root) of a directory inode, built by
/// walking `..` upwards.
fn dir_path(ino: u64) -> Result<String, i64> {
    let root = match proc_root() {
        0 => ZfsClient::root_ino(),
        r => r,
    };
    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut cur = ino;
    while cur != root {
        let parent = resolve(cur, b"..", true)?;
        let mut cookie = 2;
        let mut found = None;
        'scan: loop {
            let batch = ZfsClient::readdir(parent, cookie, 128)?;
            if batch.is_empty() {
                break;
            }
            for e in batch {
                cookie = e.next_cookie;
                if e.ino == cur {
                    found = Some(e.name);
                    break 'scan;
                }
            }
        }
        names.push(found.ok_or(ENOENT)?);
        cur = parent;
        if names.len() > 256 {
            return Err(ELOOP);
        }
    }
    let mut out = String::new();
    for n in names.iter().rev() {
        out.push('/');
        out.push_str(&String::from_utf8_lossy(n));
    }
    if out.is_empty() {
        out.push('/');
    }
    Ok(out)
}

fn chdir_to(ino: u64) -> i64 {
    let attr = match ZfsClient::getattr(ino) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if !attr.is_dir() {
        return ENOTDIR;
    }
    let c = creds();
    if !may_access(&attr, c.euid, c.egid, 1) {
        return EACCES;
    }
    let path = match dir_path(ino) {
        Ok(p) => p,
        Err(e) => return e,
    };
    crate::task::with_current_fds_mut(|fds| {
        fds.cwd_ino = ino;
        fds.cwd_path = path;
    });
    0
}

fn fcntl(fd: i32, cmd: u64, arg: u64) -> Option<i64> {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5;
    const F_SETLK: u64 = 6;
    const F_SETLKW: u64 = 7;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_ADD_SEALS: u64 = 1033;
    const F_GET_SEALS: u64 = 1034;
    if !fd_exists(fd) {
        return Some(EBADF);
    }
    let fd = fd as usize;
    Some(match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => crate::task::with_current_fds_mut(|fds| match fds.dup_from(fd, arg as usize) {
            Ok(n) => {
                fds.set_cloexec(n, cmd == F_DUPFD_CLOEXEC);
                n as i64
            }
            Err(_) => EMFILE,
        }),
        F_GETFD => crate::task::with_current_fds_mut(|fds| fds.cloexec(fd) as i64),
        F_SETFD => crate::task::with_current_fds_mut(|fds| {
            fds.set_cloexec(fd, arg & 1 != 0);
            0
        }),
        F_GETFL | F_SETFL if inet_of(fd).is_some() => {
            let s = inet_of(fd).unwrap();
            let mut s = s.lock();
            if cmd == F_SETFL {
                s.nonblock = arg as u32 & O_NONBLOCK != 0;
                0
            } else {
                2 | if s.nonblock { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if crate::task::with_current_fds_mut(|fds| fds.get(fd).map_or(false, is_tty)) => {
            if cmd == F_SETFL {
                super::tty::set_nonblock(arg as u32 & O_NONBLOCK != 0);
                0
            } else {
                2 | if super::tty::nonblock() { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if event_obj_of(fd).is_some() => {
            let desc = event_obj_of(fd).unwrap();
            let on = arg as u32 & O_NONBLOCK != 0;
            let nb = match &desc {
                FileDescriptor::EventFd(e) => {
                    let mut e = e.lock();
                    if cmd == F_SETFL {
                        e.nonblocking = on;
                    }
                    e.nonblocking
                }
                FileDescriptor::TimerFd(t) => {
                    if cmd == F_SETFL {
                        t.set_nonblock(on);
                    }
                    t.get_nonblock()
                }
                FileDescriptor::Inotify(i) => {
                    if cmd == F_SETFL {
                        i.set_nonblock(on);
                    }
                    i.get_nonblock()
                }
                _ => false,
            };
            if cmd == F_SETFL {
                0
            } else {
                2 | if nb { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if device_of(fd).is_some() => {
            let d = device_of(fd).unwrap();
            if cmd == F_SETFL {
                d.set_nonblock(arg as u32 & O_NONBLOCK != 0);
                0
            } else {
                2 | if d.nonblock() { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if unix_of(fd).is_some() => {
            let s = unix_of(fd).unwrap();
            if cmd == F_SETFL {
                s.set_nonblock(arg as u32 & O_NONBLOCK != 0);
                0
            } else {
                2 | if s.get_nonblock() { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if signalfd_of(fd).is_some() => {
            let s = signalfd_of(fd).unwrap();
            if cmd == F_SETFL {
                s.set_nonblock(arg as u32 & O_NONBLOCK != 0);
                0
            } else {
                if s.get_nonblock() { O_NONBLOCK as i64 } else { 0 } // O_RDONLY
            }
        }
        F_GETFL | F_SETFL if pty_of(fd).is_some() => {
            let p = pty_of(fd).unwrap();
            if cmd == F_SETFL {
                p.set_nonblock(arg as u32 & O_NONBLOCK != 0);
                0
            } else {
                2 | if p.get_nonblock() { O_NONBLOCK as i64 } else { 0 } // O_RDWR
            }
        }
        F_GETFL | F_SETFL if pipe_of(fd).is_some() => {
            let (pipe, write_end) = pipe_of(fd).unwrap();
            let mut p = pipe.lock();
            let flag = if write_end { &mut p.write_nonblock } else { &mut p.read_nonblock };
            if cmd == F_SETFL {
                *flag = arg as u32 & O_NONBLOCK != 0;
                0
            } else {
                (if write_end { 1 } else { 0 }) | if *flag { O_NONBLOCK as i64 } else { 0 }
            }
        }
        F_GETFL => match fd_vnode(fd as i32) {
            Some(f) => f.lock().flags as i64,
            None => return None,
        },
        F_SETFL => match fd_vnode(fd as i32) {
            Some(f) => {
                let mut f = f.lock();
                f.flags = (f.flags & !(O_APPEND | O_NONBLOCK)) | (arg as u32 & (O_APPEND | O_NONBLOCK));
                0
            }
            None => return None,
        },
        F_GETLK => {
            // No other process holds locks: report the region as unlocked (l_type = F_UNLCK)
            match copy_out(arg, &2i16.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        F_SETLK | F_SETLKW => 0,
        F_ADD_SEALS | F_GET_SEALS => 0,
        _ => return None,
    })
}

fn is_tty(d: &FileDescriptor) -> bool {
    matches!(d, FileDescriptor::ConsoleIn | FileDescriptor::ConsoleOut | FileDescriptor::ConsoleErr)
}

/// The eventfd, timerfd or inotify object behind descriptor `fd`.
fn event_obj_of(fd: usize) -> Option<FileDescriptor> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(d @ (FileDescriptor::EventFd(_) | FileDescriptor::TimerFd(_) | FileDescriptor::Inotify(_))) => Some(d.clone()),
        _ => None,
    })
}

/// The character device behind descriptor `fd`.
fn device_of(fd: usize) -> Option<Arc<dyn super::chardev::CharDevice>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::Device(d)) => Some(d.clone()),
        _ => None,
    })
}

/// The Unix socket behind descriptor `fd`.
fn unix_of(fd: usize) -> Option<Arc<super::unix::UnixSocket>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::Unix(s)) => Some(s.clone()),
        _ => None,
    })
}

/// The signalfd behind descriptor `fd`.
fn signalfd_of(fd: usize) -> Option<Arc<super::signalfd::SignalFd>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::SignalFd(s)) => Some(s.clone()),
        _ => None,
    })
}

/// The pseudo-terminal end behind descriptor `fd`.
fn pty_of(fd: usize) -> Option<Arc<super::pty::PtyFile>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::Pty(p)) => Some(p.clone()),
        _ => None,
    })
}

/// The pipe behind descriptor `fd` and whether it is the write end.
fn pipe_of(fd: usize) -> Option<(Arc<Mutex<crate::fs::PipeBuffer>>, bool)> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
        Some(FileDescriptor::PipeRead(p)) => Some((p.clone(), false)),
        Some(FileDescriptor::PipeWrite(p)) => Some((p.clone(), true)),
        _ => None,
    })
}

/// Read from a pipe: waits for data (unless `O_NONBLOCK`), or returns 0 once every
/// writer is gone.
fn pipe_read(pipe: &Arc<Mutex<crate::fs::PipeBuffer>>, buf: &mut [u8]) -> i64 {
    let waits = pipe_wait_set(pipe);
    loop {
        waits.register();
        {
            let mut p = pipe.lock();
            if p.available_read() > 0 {
                return p.read(buf) as i64;
            }
            if p.writers_count() == 0 {
                return 0;
            }
            if p.read_nonblock {
                return EAGAIN;
            }
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        waits.wait(None);
    }
}

/// Wait set of a pipe's readers and writers.
fn pipe_wait_set(pipe: &Arc<Mutex<crate::fs::PipeBuffer>>) -> crate::task::wait::WaitSet {
    let mut waits = crate::task::wait::WaitSet::new();
    waits.add(crate::task::wait::QueueRef::Shared(pipe.lock().wq.clone()));
    waits
}

/// Blocking write to a pipe: waits for space; `EPIPE` (and `SIGPIPE`) without readers.
fn pipe_write(pipe: &Arc<Mutex<crate::fs::PipeBuffer>>, data: &[u8]) -> i64 {
    let mut done = 0;
    let waits = pipe_wait_set(pipe);
    while done < data.len() {
        waits.register();
        let wrote = {
            let mut p = pipe.lock();
            if p.readers_count() == 0 {
                None
            } else if p.available_write() > 0 {
                Some(p.write(&data[done..]).unwrap_or(0))
            } else {
                Some(0)
            }
        };
        match wrote {
            None => {
                let (tid, pid) = super::proc::current_ids();
                super::proc::post_thread(pid, tid, super::proc::SIGPIPE);
                return if done > 0 { done as i64 } else { -32 };
            }
            Some(0) => {
                if pipe.lock().write_nonblock {
                    return if done > 0 { done as i64 } else { EAGAIN };
                }
                if super::proc::signal_pending() {
                    return if done > 0 { done as i64 } else { super::proc::ERESTARTSYS };
                }
                waits.wait(None);
            }
            Some(n) => done += n,
        }
    }
    done as i64
}

/// Terminal and pipe I/O, which may block. `None` for other descriptor kinds.
fn stream_io(num: u64, a: [u64; 6]) -> Option<i64> {
    let fd = a[0] as usize;
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd).cloned())?;
    let stream = is_tty(&desc)
        || matches!(desc, FileDescriptor::PipeRead(_) | FileDescriptor::PipeWrite(_) | FileDescriptor::Inet(_) | FileDescriptor::Pty(_) | FileDescriptor::SignalFd(_) | FileDescriptor::Unix(_)
            | FileDescriptor::EventFd(_) | FileDescriptor::TimerFd(_) | FileDescriptor::Inotify(_) | FileDescriptor::Device(_));
    if !stream {
        return None;
    }
    // (buffer, length) pairs: one for read/write, the iovec array for readv/writev
    let iov: Vec<(u64, u64)> = match num {
        0 | 1 => alloc::vec![(a[1], a[2])],
        _ => {
            let raw = match copy_in(a[1], a[2] as usize * 16) {
                Ok(r) => r,
                Err(e) => return Some(e),
            };
            raw.chunks_exact(16)
                .map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap())))
                .filter(|&(_, l)| l > 0)
                .collect()
        }
    };
    let reading = num == 0 || num == 19;
    let mut total = 0i64;
    for (ptr, len) in iov {
        if !prefault_current(ptr, len, reading) {
            return Some(if total > 0 { total } else { EFAULT });
        }
        let r = if reading {
            let buf = unsafe { core::slice::from_raw_parts_mut(ptr as *mut u8, len as usize) };
            match &desc {
                FileDescriptor::PipeRead(p) => pipe_read(p, buf),
                FileDescriptor::PipeWrite(_) => EBADF,
                FileDescriptor::Inet(s) => super::inet::read(s, buf),
                FileDescriptor::Pty(p) => p.read(buf),
                FileDescriptor::SignalFd(s) => s.read(buf),
                FileDescriptor::Unix(s) => s.read(buf),
                FileDescriptor::EventFd(e) => super::eventfd::read(e, buf),
                FileDescriptor::TimerFd(t) => t.read(buf),
                FileDescriptor::Inotify(i) => i.read(buf),
                FileDescriptor::Device(d) => d.read(buf),
                _ => super::tty::read(buf, super::tty::nonblock()),
            }
        } else {
            let data = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
            match &desc {
                FileDescriptor::PipeWrite(p) => pipe_write(p, data),
                FileDescriptor::PipeRead(_) => EBADF,
                FileDescriptor::Inet(s) => super::inet::write(s, data),
                FileDescriptor::Pty(p) => p.write(data),
                FileDescriptor::SignalFd(_) => EINVAL,
                FileDescriptor::Unix(s) => s.write(data),
                FileDescriptor::EventFd(e) => super::eventfd::write(e, data),
                FileDescriptor::TimerFd(_) | FileDescriptor::Inotify(_) => EINVAL,
                FileDescriptor::Device(d) => d.write(data),
                _ => super::tty::write(data) as i64,
            }
        };
        if r < 0 {
            return Some(if total > 0 { total } else { r });
        }
        total += r;
        if reading && (r as u64) < len {
            break; // short read: don't wait for the next buffer
        }
    }
    Some(total)
}

/// Handles the file-system system calls. Returns `None` when the call (or the kind of
/// descriptor it targets) belongs to another handler.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    let r = match num {
        0 | 1 | 19 | 20 => return stream_io(num, a),
        16 => {
            // ioctl: terminal requests on the console; ENOTTY for terminal requests elsewhere
            let desc = crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned());
            match desc {
                Some(ref d) if is_tty(d) => super::tty::ioctl(a[1], a[2]),
                Some(FileDescriptor::Unix(ref s)) => super::unix::ioctl(s, a[1], a[2]),
                Some(FileDescriptor::Device(ref d)) => match a[1] {
                    0x5421 => match copy_in(a[2], 4) {
                        // FIONBIO
                        Ok(v) => {
                            d.set_nonblock(v.iter().any(|&b| b != 0));
                            0
                        }
                        Err(e) => e,
                    },
                    _ => d.ioctl(a[1], a[2]),
                },
                Some(FileDescriptor::Inotify(ref i)) if a[1] == 0x541B => {
                    // FIONREAD: bytes of queued events
                    match copy_out(a[2], &(i.pending_bytes() as i32).to_le_bytes()) {
                        Ok(()) => 0,
                        Err(e) => e,
                    }
                }
                Some(FileDescriptor::Pty(ref p)) => match a[1] {
                    0x5421 => match copy_in(a[2], 4) {
                        // FIONBIO
                        Ok(v) => {
                            p.set_nonblock(v.iter().any(|&b| b != 0));
                            0
                        }
                        Err(e) => e,
                    },
                    _ => p.ioctl(a[1], a[2], &|peer, flags| match install(FileDescriptor::Pty(peer), flags) {
                        Ok(fd) => fd as i64,
                        Err(e) => e,
                    }),
                },
                Some(FileDescriptor::Inet(ref s)) => match a[1] {
                    0x5421 => {
                        // FIONBIO
                        match copy_in(a[2], 4) {
                            Ok(v) => {
                                s.lock().nonblock = v.iter().any(|&b| b != 0);
                                0
                            }
                            Err(e) => e,
                        }
                    }
                    0x541B => {
                        // FIONREAD
                        let n = super::inet::pending_bytes(s) as i32;
                        match copy_out(a[2], &n.to_le_bytes()) {
                            Ok(()) => 0,
                            Err(e) => e,
                        }
                    }
                    r if r & 0xFF00 == 0x5400 => super::tty::NOT_A_TTY,
                    _ => EINVAL,
                },
                Some(FileDescriptor::Vnode(_)) | Some(FileDescriptor::PipeRead(_)) | Some(FileDescriptor::PipeWrite(_))
                    if a[1] & 0xFF00 == 0x5400 =>
                {
                    super::tty::NOT_A_TTY
                }
                None => EBADF,
                _ => return None,
            }
        }
        NR_OPEN => open_at(AT_FDCWD, a[0], a[1] as u32, a[2] as u32),
        NR_CREAT => open_at(AT_FDCWD, a[0], O_CREAT | O_WRONLY | O_TRUNC, a[1] as u32),
        NR_OPENAT => open_at(a[0] as i64, a[1], a[2] as u32, a[3] as u32),

        NR_STAT | NR_LSTAT => match stat_at(AT_FDCWD, a[0], if num == NR_LSTAT { AT_SYMLINK_NOFOLLOW } else { 0 }) {
            Ok(st) => write_stat(a[1], &st),
            Err(e) => e,
        },
        NR_NEWFSTATAT => match stat_at(a[0] as i64, a[1], a[3]) {
            Ok(st) => write_stat(a[2], &st),
            Err(e) => e,
        },
        NR_STATX => match stat_at(a[0] as i64, a[1], a[2]) {
            Ok(st) => write_statx(a[4], &st),
            Err(e) => e,
        },
        NR_FSTAT => match fstat_fd(a[0] as i32)? {
            Ok(st) => write_stat(a[1], &st),
            Err(e) => e,
        },

        NR_LSEEK => lseek(a[0] as i32, a[1] as i64, a[2] as u32)?,
        NR_GETDENTS64 => getdents64(a[0] as i32, a[1], a[2] as usize),

        NR_ACCESS => access_at(AT_FDCWD, a[0], a[1] as u32, 0),
        NR_FACCESSAT => access_at(a[0] as i64, a[1], a[2] as u32, 0),
        NR_FACCESSAT2 => access_at(a[0] as i64, a[1], a[2] as u32, a[3]),

        NR_READLINK => readlink_at(AT_FDCWD, a[0], a[1], a[2] as usize),
        NR_READLINKAT => readlink_at(a[0] as i64, a[1], a[2], a[3] as usize),

        NR_MKDIR | NR_MKDIRAT => {
            let (dirfd, p, mode) = if num == NR_MKDIR { (AT_FDCWD, a[0], a[1]) } else { (a[0] as i64, a[1], a[2]) };
            let mask = umask();
            with_parent(dirfd, p, |dir, name, c| zfs(|s| s.mkdir(dir, name, mode as u32 & 0o7777 & !mask, c.euid, c.egid).map(|_| 0)))
        }
        NR_MKNOD | NR_MKNODAT => {
            let (dirfd, p, mode, dev) = if num == NR_MKNOD { (AT_FDCWD, a[0], a[1], a[2]) } else { (a[0] as i64, a[1], a[2], a[3]) };
            let mask = umask();
            with_parent(dirfd, p, |dir, name, c| {
                let mode = (mode as u32 & S_IFMT) | (mode as u32 & 0o7777 & !mask);
                let devnode = matches!(dtype_from_mode(mode), 2 | 6); // DT_CHR, DT_BLK
                if devnode && c.euid != 0 {
                    return Err(EPERM);
                }
                zfs(|s| s.mknod(dir, name, mode, dev, c.euid, c.egid).map(|_| 0))
            })
        }
        NR_SYMLINK | NR_SYMLINKAT => {
            let (target_ptr, dirfd, p) = if num == NR_SYMLINK { (a[0], AT_FDCWD, a[1]) } else { (a[0], a[1] as i64, a[2]) };
            match user_path(target_ptr) {
                Ok(target) => with_parent(dirfd, p, |dir, name, c| zfs(|s| s.symlink(dir, name, &target, c.euid, c.egid).map(|_| 0))),
                Err(e) => e,
            }
        }
        NR_LINK => link_at(AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        NR_LINKAT => link_at(a[0] as i64, a[1], a[2] as i64, a[3], a[4]),

        NR_UNLINK => with_parent(AT_FDCWD, a[0], |dir, name, _| zfs(|s| s.unlink(dir, name).map(|_| 0))),
        NR_RMDIR => with_parent(AT_FDCWD, a[0], |dir, name, _| zfs(|s| s.rmdir(dir, name).map(|_| 0))),
        NR_UNLINKAT => {
            let rmdir = a[2] & AT_REMOVEDIR != 0;
            with_parent(a[0] as i64, a[1], |dir, name, _| {
                zfs(|s| if rmdir { s.rmdir(dir, name) } else { s.unlink(dir, name) }.map(|_| 0))
            })
        }

        NR_RENAME => rename_at(AT_FDCWD, a[0], AT_FDCWD, a[1], 0),
        NR_RENAMEAT => rename_at(a[0] as i64, a[1], a[2] as i64, a[3], 0),
        NR_RENAMEAT2 => rename_at(a[0] as i64, a[1], a[2] as i64, a[3], a[4]),

        NR_CHMOD => setattr_at(AT_FDCWD, a[0], true, false, SetAttr { mode: Some(a[1] as u32), ..SetAttr::default() }, owner_or_root),
        NR_FCHMODAT => setattr_at(a[0] as i64, a[1], true, false, SetAttr { mode: Some(a[2] as u32), ..SetAttr::default() }, owner_or_root),
        NR_FCHMOD => {
            fd_vnode(a[0] as i32)?;
            setattr_at(a[0] as i64, 0, true, true, SetAttr { mode: Some(a[1] as u32), ..SetAttr::default() }, owner_or_root)
        }
        NR_CHOWN => setattr_at(AT_FDCWD, a[0], true, false, chown_set(a[1], a[2]), |_, c| c.euid == 0),
        NR_LCHOWN => setattr_at(AT_FDCWD, a[0], false, false, chown_set(a[1], a[2]), |_, c| c.euid == 0),
        NR_FCHOWNAT => setattr_at(a[0] as i64, a[1], a[4] & AT_SYMLINK_NOFOLLOW == 0, a[4] & AT_EMPTY_PATH != 0, chown_set(a[2], a[3]), |_, c| c.euid == 0),
        NR_FCHOWN => {
            fd_vnode(a[0] as i32)?;
            setattr_at(a[0] as i64, 0, true, true, chown_set(a[1], a[2]), |_, c| c.euid == 0)
        }
        NR_UTIMENSAT => utimens(a[0] as i64, a[1], a[2], a[3]),

        NR_TRUNCATE => setattr_at(AT_FDCWD, a[0], true, false, SetAttr { size: Some(a[1]), ..SetAttr::default() }, |at, c| may_access(at, c.euid, c.egid, 2)),
        NR_FTRUNCATE => {
            let f = fd_vnode(a[0] as i32)?;
            let (ino, writable) = {
                let f = f.lock();
                (f.ino, f.flags & O_ACCMODE != O_RDONLY)
            };
            if !writable {
                EINVAL
            } else {
                ZfsClient::setattr(ino, SetAttr { size: Some(a[1]), ..SetAttr::default() }).map(|_| 0).unwrap_or_else(|e| e)
            }
        }

        NR_FSYNC | NR_FDATASYNC | NR_SYNC | NR_SYNCFS => {
            let _ = ZfsClient::sync();
            0
        }
        NR_STATFS => match user_path(a[0]).and_then(|p| base_dir(AT_FDCWD, &p).map(|(_, base)| join_path(&base, &p))) {
            Ok(abs) => statfs_out(a[1], fs_magic(&abs)),
            Err(e) => e,
        },
        NR_FSTATFS => {
            let desc = crate::task::with_current_fds_mut(|fds| fds.get(a[0] as usize).cloned());
            let magic = match desc {
                Some(FileDescriptor::Pty(_)) => DEVPTS_SUPER_MAGIC,
                Some(FileDescriptor::Vnode(f)) => fs_magic(&f.lock().path),
                Some(FileDescriptor::File { path, .. }) => fs_magic(&path),
                Some(_) => ZFS_SUPER_MAGIC,
                None => return Some(EBADF),
            };
            statfs_out(a[1], magic)
        }

        NR_GETCWD => {
            let path = crate::task::with_current_fds_mut(|fds| fds.cwd_path.clone());
            let mut bytes = path.into_bytes();
            bytes.push(0);
            if (a[1] as usize) < bytes.len() {
                ERANGE
            } else {
                match copy_out(a[0], &bytes) {
                    Ok(()) => bytes.len() as i64,
                    Err(e) => e,
                }
            }
        }
        NR_CHDIR => match user_path(a[0]).and_then(|p| {
            let (base, _) = base_dir(AT_FDCWD, &p)?;
            resolve(base, &p, true)
        }) {
            Ok(ino) => chdir_to(ino),
            Err(e) => e,
        },
        NR_FCHDIR => match fd_vnode(a[0] as i32) {
            Some(f) => {
                let ino = f.lock().ino;
                chdir_to(ino)
            }
            None => EBADF,
        },
        NR_UMASK => crate::task::with_current_fds_mut(|fds| {
            let old = fds.umask;
            fds.umask = a[0] as u32 & 0o777;
            old as i64
        }),

        NR_DUP => crate::task::with_current_fds_mut(|fds| fds.dup_from(a[0] as usize, 0).map(|n| n as i64).unwrap_or(EBADF)),
        NR_DUP2 => crate::task::with_current_fds_mut(|fds| fds.dup2(a[0] as usize, a[1] as usize).map(|n| n as i64).unwrap_or(EBADF)),
        NR_DUP3 => {
            if a[0] == a[1] {
                EINVAL
            } else {
                crate::task::with_current_fds_mut(|fds| match fds.dup2(a[0] as usize, a[1] as usize) {
                    Ok(n) => {
                        fds.set_cloexec(n, a[2] as u32 & O_CLOEXEC != 0);
                        n as i64
                    }
                    Err(_) => EBADF,
                })
            }
        }
        NR_FCNTL => fcntl(a[0] as i32, a[1], a[2])?,

        436 => {
            // close_range(first, last, flags): CLOSE_RANGE_CLOEXEC (4) marks instead of closing;
            // CLOSE_RANGE_UNSHARE (2) needs nothing since every process has its own table
            let (first, last, flags) = (a[0] as u32 as usize, a[1] as u32 as usize, a[2]);
            if first > last || flags & !6 != 0 {
                EINVAL
            } else {
                let last = last.min(crate::fs::MAX_FDS - 1);
                crate::task::with_current_fds_mut(|fds| {
                    for fd in first..=last {
                        if flags & 4 != 0 {
                            if fds.get(fd).is_some() {
                                fds.set_cloexec(fd, true);
                            }
                        } else {
                            let _ = fds.close(fd);
                        }
                    }
                });
                0
            }
        }

        // Extended attributes: the pool stores none, so lists are empty and lookups miss
        188..=190 | 197..=199 => EOPNOTSUPP, // setxattr family, removexattr family
        191..=193 => -61,                    // getxattr family: ENODATA
        194..=196 => 0,                      // listxattr family: empty list

        _ => return None,
    };
    Some(r)
}
