//! Helpers shared by the tests (the integration test binaries and the unit tests in `src/unit`): system calls into the VFS with "user" pointers
//! (host memory), and readers for what they write back.

pub use crate::compat::linux as lx;
pub use crate::compat::linux::types::LinuxStat;
pub use crate::fake::memory::make_bad;
pub use crate::fake::{self, buf, cstr, memfs, read, read_i32, read_u32, read_u64, setup, task, write};
pub use crate::fs::{FileDescriptor, ZfsClient};
pub use lx::vfs;

pub const AT_FDCWD: u64 = -100i64 as u64;
pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EEXIST: i64 = -17;
pub const EXDEV: i64 = -18;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EPERM: i64 = -1;
pub const ELOOP: i64 = -40;
pub const ENOTEMPTY: i64 = -39;
pub const EOPNOTSUPP: i64 = -95;
pub const ERANGE: i64 = -34;
pub const ENODATA: i64 = -61;

pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_DIRECTORY: u64 = 0o200000;
pub const O_NOFOLLOW: u64 = 0o400000;
pub const O_CLOEXEC: u64 = 0o2000000;
pub const O_PATH: u64 = 0o10000000;

/// VFS system call `nr` (panics if the VFS does not handle it).
pub fn sys(nr: u64, a: &[u64]) -> i64 {
    let mut args = [0u64; 6];
    args[..a.len()].copy_from_slice(a);
    vfs::dispatch(nr, args).unwrap_or_else(|| panic!("call {} not handled", nr))
}

/// VFS system call `nr`, `None` when another handler owns it.
pub fn sys_opt(nr: u64, a: &[u64]) -> Option<i64> {
    let mut args = [0u64; 6];
    args[..a.len()].copy_from_slice(a);
    vfs::dispatch(nr, args)
}

pub fn openat(dirfd: u64, path: &str, flags: u64, mode: u64) -> i64 {
    sys(257, &[dirfd, cstr(path), flags, mode])
}

pub fn open(path: &str, flags: u64) -> i64 {
    openat(AT_FDCWD, path, flags, 0o644)
}

pub fn close(fd: i64) {
    task::with_current_fds_mut(|f| f.close(fd as usize)).unwrap();
}

/// The `struct stat` at `p`.
pub fn stat_at(p: u64) -> LinuxStat {
    unsafe { core::ptr::read(p as *const LinuxStat) }
}

/// `newfstatat(dirfd, path, flags)`: the stat or the errno.
pub fn fstatat(dirfd: u64, path: &str, flags: u64) -> Result<LinuxStat, i64> {
    let b = buf(256);
    match sys(262, &[dirfd, cstr(path), b, flags]) {
        0 => Ok(stat_at(b)),
        e => Err(e),
    }
}

pub fn stat(path: &str) -> Result<LinuxStat, i64> {
    fstatat(AT_FDCWD, path, 0)
}

pub fn lstat(path: &str) -> Result<LinuxStat, i64> {
    fstatat(AT_FDCWD, path, 0x100)
}

pub fn fstat(fd: i64) -> Result<LinuxStat, i64> {
    let b = buf(256);
    match sys(5, &[fd as u64, b]) {
        0 => Ok(stat_at(b)),
        e => Err(e),
    }
}

/// The descriptor at `fd` of the current task.
pub fn desc(fd: i64) -> Option<FileDescriptor> {
    task::with_current_fds_mut(|f| f.get(fd as usize).cloned())
}

/// Installs `d` in the current task's table; returns its number.
pub fn install(d: FileDescriptor) -> i64 {
    task::with_current_fds_mut(|f| f.alloc_fd(d).unwrap()) as i64
}

/// The open file description behind `fd`.
pub fn vnode(fd: i64) -> std::sync::Arc<spin::Mutex<crate::fs::fd::OpenFile>> {
    match desc(fd) {
        Some(FileDescriptor::Vnode(f)) => f,
        _ => panic!("fd {} is not a pool file", fd),
    }
}

/// Reads `fd`'s whole directory listing (names) through getdents64.
pub fn list_dir(fd: i64) -> Vec<String> {
    let mut names = Vec::new();
    loop {
        let b = buf(4096);
        let n = sys(217, &[fd as u64, b, 4096]);
        assert!(n >= 0, "getdents64: {}", n);
        if n == 0 {
            return names;
        }
        let data = read(b, n as usize);
        let mut o = 0;
        while o < data.len() {
            let reclen = u16::from_le_bytes([data[o + 16], data[o + 17]]) as usize;
            let name: Vec<u8> = data[o + 19..o + reclen].iter().take_while(|&&c| c != 0).copied().collect();
            names.push(String::from_utf8(name).unwrap());
            o += reclen;
        }
    }
}

/// Becomes an ordinary user `uid` (group `uid`) without capabilities.
pub fn become_user(uid: u32) {
    task::set_ids(uid, uid);
}
