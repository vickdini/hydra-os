//! # Linux ABI Data Types and Constants
//!
//! Standard x86_64 Linux C-ABI data structures matching GNU C Library and musl-libc definitions.

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

pub const PROT_NONE: u64 = 0x0;
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;

pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;

pub const S_IFMT: u32 = 0o0170000;
pub const S_IFDIR: u32 = 0o0040000;
pub const S_IFCHR: u32 = 0o0020000;
pub const S_IFBLK: u32 = 0o0060000;
pub const S_IFREG: u32 = 0o0100000;
pub const S_IFIFO: u32 = 0o0010000;
pub const S_IFLNK: u32 = 0o0120000;
pub const S_IFSOCK: u32 = 0o0140000;

// Standard Linux Errno codes (returned as -errno)
pub const EPERM: i64 = 1;
pub const ENOENT: i64 = 2;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const EIO: i64 = 5;
pub const ENXIO: i64 = 6;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const ENFILE: i64 = 23;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ENOSPC: i64 = 28;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const EPIPE: i64 = 32;
pub const ENOSYS: i64 = 38;
pub const EPROTONOSUPPORT: i64 = 93;
pub const EAFNOSUPPORT: i64 = 97;
pub const EADDRINUSE: i64 = 98;
pub const ECONNREFUSED: i64 = 111;

/// `struct utsname` layout on Linux x86_64.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LinuxUtsname {
    pub sysname: [u8; 65],
    pub nodename: [u8; 65],
    pub release: [u8; 65],
    pub version: [u8; 65],
    pub machine: [u8; 65],
    pub domainname: [u8; 65],
}

impl Default for LinuxUtsname {
    fn default() -> Self {
        let mut u = Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        };

        copy_str(&mut u.sysname, "Linux");
        copy_str(&mut u.nodename, "hydra");
        copy_str(&mut u.release, "6.8.0-hydra");
        copy_str(&mut u.version, "#1 SMP PREEMPT Hydra Microkernel");
        copy_str(&mut u.machine, "x86_64");
        copy_str(&mut u.domainname, "localdomain");
        u
    }
}

fn copy_str(dest: &mut [u8; 65], src: &str) {
    let bytes = src.as_bytes();
    let len = bytes.len().min(64);
    dest[..len].copy_from_slice(&bytes[..len]);
    dest[len] = 0;
}

/// Standard 64-bit `struct stat` for x86_64 Linux.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

/// Linux `struct timeval`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Linux `struct timespec`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxTimespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// Linux `struct iovec` for scatter/gather I/O.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxIovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

/// ELF Auxiliary Vector Entry (`Elf64_auxv_t`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuxvEntry {
    pub a_type: u64,
    pub a_val: u64,
}

pub const AT_NULL: u64 = 0;
pub const AT_IGNORE: u64 = 1;
pub const AT_EXECFD: u64 = 2;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_NOTELF: u64 = 10;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;

// Linux clone(2) flags
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

pub const SOL_SOCKET: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;


/// Linux `struct msghdr` for `sendmsg` and `recvmsg`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxMsghdr {
    pub msg_name: u64,
    pub msg_namelen: u32,
    pub msg_iov: *mut LinuxIovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: i32,
}

/// Linux `struct cmsghdr` for socket ancillary data.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxCmsghdr {
    pub cmsg_len: usize,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

