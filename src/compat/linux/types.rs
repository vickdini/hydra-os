//! # Linux Compatibility: ABI Data Types and Constants
//!
//! Defines standard x86_64 Linux C-ABI data structures, flag bitmasks, and error codes matching
//! GNU C Library (`glibc`) and `musl-libc` definitions.
//!
//! ## Architectural Role & Design Rationale
//! Binary compatibility with unmodified x86_64 Linux ELF executables requires exact byte-for-byte
//! layout equivalence (`#[repr(C)]`) for structures exchanged across the user-kernel boundary,
//! as well as matching numeric constants for `mmap` flags, file mode bits, auxiliary vectors,
//! `clone` flags, and POSIX `errno` values.
//!
//! ## Key Types & Interfaces
//! - [`LinuxUtsname`]: Kernel and machine identification returned by `uname(2)`.
//! - [`LinuxStat`]: 64-bit file metadata returned by `stat(2)`, `fstat(2)`, and `lstat(2)`.
//! - [`LinuxTimeval`] & [`LinuxTimespec`]: Time representations for clocks, timers, and polling.
//! - [`LinuxIovec`]: Scatter/gather I/O vector element for `readv`/`writev`/`sendmsg`/`recvmsg`.
//! - [`AuxvEntry`]: ELF auxiliary vector key-value pair placed on the initial user stack during `execve`.
//! - [`LinuxMsghdr`] & [`LinuxCmsghdr`]: Socket message and ancillary control message headers.
//!
//! ## Hardware & Dependency Context
//! - **Architecture**: x86_64 System V AMD64 ABI (LP64 data model, little-endian).
//! - **Dependencies**: Pure data definitions with no hardware or subsystem dependencies.

/// `arch_prctl` subfunction to set the 64-bit `GS` segment base address.
pub const ARCH_SET_GS: u64 = 0x1001;
/// `arch_prctl` subfunction to set the 64-bit `FS` segment base address (used for TLS).
pub const ARCH_SET_FS: u64 = 0x1002;
/// `arch_prctl` subfunction to read the current 64-bit `FS` segment base address.
pub const ARCH_GET_FS: u64 = 0x1003;
/// `arch_prctl` subfunction to read the current 64-bit `GS` segment base address.
pub const ARCH_GET_GS: u64 = 0x1004;

/// `mmap` / `mprotect` protection flag: pages may not be accessed.
pub const PROT_NONE: u64 = 0x0;
/// `mmap` / `mprotect` protection flag: pages may be read.
pub const PROT_READ: u64 = 0x1;
/// `mmap` / `mprotect` protection flag: pages may be written.
pub const PROT_WRITE: u64 = 0x2;
/// `mmap` / `mprotect` protection flag: pages may be executed.
pub const PROT_EXEC: u64 = 0x4;

/// `mmap` flag: share mapping updates with other processes mapping the same object.
pub const MAP_SHARED: u64 = 0x01;
/// `mmap` flag: create a private copy-on-write mapping.
pub const MAP_PRIVATE: u64 = 0x02;
/// `mmap` flag: place the mapping at the exact requested address.
pub const MAP_FIXED: u64 = 0x10;
/// `mmap` flag: mapping is not backed by any file; contents are initialized to zero.
pub const MAP_ANONYMOUS: u64 = 0x20;

/// Bitmask for the file type bit field in `st_mode`.
pub const S_IFMT: u32 = 0o0170000;
/// File type constant for a directory.
pub const S_IFDIR: u32 = 0o0040000;
/// File type constant for a character device.
pub const S_IFCHR: u32 = 0o0020000;
/// File type constant for a block device.
pub const S_IFBLK: u32 = 0o0060000;
/// File type constant for a regular file.
pub const S_IFREG: u32 = 0o0100000;
/// File type constant for a FIFO (named pipe).
pub const S_IFIFO: u32 = 0o0010000;
/// File type constant for a symbolic link.
pub const S_IFLNK: u32 = 0o0120000;
/// File type constant for a socket.
pub const S_IFSOCK: u32 = 0o0140000;

// Standard Linux Errno codes (returned as -errno)
/// Operation not permitted (`EPERM`).
pub const EPERM: i64 = 1;
/// No such file or directory (`ENOENT`).
pub const ENOENT: i64 = 2;
/// No such process (`ESRCH`).
pub const ESRCH: i64 = 3;
/// Interrupted system call (`EINTR`).
pub const EINTR: i64 = 4;
/// Input/output error (`EIO`).
pub const EIO: i64 = 5;
/// No such device or address (`ENXIO`).
pub const ENXIO: i64 = 6;
/// Bad file descriptor (`EBADF`).
pub const EBADF: i64 = 9;
/// Resource temporarily unavailable / operation would block (`EAGAIN` / `EWOULDBLOCK`).
pub const EAGAIN: i64 = 11;
/// Out of memory (`ENOMEM`).
pub const ENOMEM: i64 = 12;
/// Permission denied (`EACCES`).
pub const EACCES: i64 = 13;
/// Bad address (`EFAULT`).
pub const EFAULT: i64 = 14;
/// File exists (`EEXIST`).
pub const EEXIST: i64 = 17;
/// Not a directory (`ENOTDIR`).
pub const ENOTDIR: i64 = 20;
/// Is a directory (`EISDIR`).
pub const EISDIR: i64 = 21;
/// Invalid argument (`EINVAL`).
pub const EINVAL: i64 = 22;
/// Too many open files in system (`ENFILE`).
pub const ENFILE: i64 = 23;
/// Too many open files for the calling process (`EMFILE`).
pub const EMFILE: i64 = 24;
/// Inappropriate ioctl for device / not a typewriter (`ENOTTY`).
pub const ENOTTY: i64 = 25;
/// No space left on device (`ENOSPC`).
pub const ENOSPC: i64 = 28;
/// Illegal seek on a pipe or socket (`ESPIPE`).
pub const ESPIPE: i64 = 29;
/// Read-only file system (`EROFS`).
pub const EROFS: i64 = 30;
/// Broken pipe (`EPIPE`).
pub const EPIPE: i64 = 32;
/// Function / system call not implemented (`ENOSYS`).
pub const ENOSYS: i64 = 38;
/// Protocol not supported (`EPROTONOSUPPORT`).
pub const EPROTONOSUPPORT: i64 = 93;
/// Address family not supported by protocol (`EAFNOSUPPORT`).
pub const EAFNOSUPPORT: i64 = 97;
/// Address already in use (`EADDRINUSE`).
pub const EADDRINUSE: i64 = 98;
/// Connection refused (`ECONNREFUSED`).
pub const ECONNREFUSED: i64 = 111;

/// `struct utsname` layout on Linux x86_64, populated by `uname(2)`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LinuxUtsname {
    /// Operating system name (e.g., `"Linux"`).
    pub sysname: [u8; 65],
    /// Network node hostname (e.g., `"hydra"`).
    pub nodename: [u8; 65],
    /// Operating system release level (e.g., `"6.8.0-hydra"`).
    pub release: [u8; 65],
    /// Operating system version string.
    pub version: [u8; 65],
    /// Hardware architecture identifier (e.g., `"x86_64"`).
    pub machine: [u8; 65],
    /// NIS/YP domain name (e.g., `"localdomain"`).
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

/// Copies a UTF-8 string into a fixed 65-byte NUL-terminated `utsname` field.
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
    /// ID of device containing file.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// Number of hard links.
    pub st_nlink: u64,
    /// File type and mode permissions.
    pub st_mode: u32,
    /// User ID of owner.
    pub st_uid: u32,
    /// Group ID of owner.
    pub st_gid: u32,
    /// Alignment padding field required by the x86_64 ABI.
    pub __pad0: u32,
    /// Device ID (if special file).
    pub st_rdev: u64,
    /// Total size in bytes.
    pub st_size: i64,
    /// Block size for filesystem I/O.
    pub st_blksize: i64,
    /// Number of 512-byte blocks allocated.
    pub st_blocks: i64,
    /// Time of last access (seconds since Unix epoch).
    pub st_atime: i64,
    /// Nanosecond component of `st_atime`.
    pub st_atime_nsec: i64,
    /// Time of last modification (seconds since Unix epoch).
    pub st_mtime: i64,
    /// Nanosecond component of `st_mtime`.
    pub st_mtime_nsec: i64,
    /// Time of last status change (seconds since Unix epoch).
    pub st_ctime: i64,
    /// Nanosecond component of `st_ctime`.
    pub st_ctime_nsec: i64,
    /// Reserved trailing fields for future ABI extensions.
    pub __unused: [i64; 3],
}

/// Linux `struct timeval` representing elapsed time with microsecond resolution.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxTimeval {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Microseconds (`0..1_000_000`).
    pub tv_usec: i64,
}

/// Linux `struct timespec` representing elapsed or wall-clock time with nanosecond resolution.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxTimespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (`0..1_000_000_000`).
    pub tv_nsec: i64,
}

/// Linux `struct iovec` describing a contiguous user-space buffer for scatter/gather I/O.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxIovec {
    /// Starting user-space virtual address of the buffer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: u64,
}

/// ELF Auxiliary Vector Entry (`Elf64_auxv_t`) passed on the initial user stack.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuxvEntry {
    /// Auxiliary vector entry tag (`AT_*`).
    pub a_type: u64,
    /// Auxiliary vector entry integer or pointer value.
    pub a_val: u64,
}

/// Auxiliary vector tag: end of vector (`AT_NULL`).
pub const AT_NULL: u64 = 0;
/// Auxiliary vector tag: entry should be ignored (`AT_IGNORE`).
pub const AT_IGNORE: u64 = 1;
/// Auxiliary vector tag: file descriptor of program (`AT_EXECFD`).
pub const AT_EXECFD: u64 = 2;
/// Auxiliary vector tag: address of program headers in memory (`AT_PHDR`).
pub const AT_PHDR: u64 = 3;
/// Auxiliary vector tag: size of one program header entry (`AT_PHENT`).
pub const AT_PHENT: u64 = 4;
/// Auxiliary vector tag: number of program header entries (`AT_PHNUM`).
pub const AT_PHNUM: u64 = 5;
/// Auxiliary vector tag: system page size in bytes (`AT_PAGESZ`).
pub const AT_PAGESZ: u64 = 6;
/// Auxiliary vector tag: base address of the dynamic linker interpreter (`AT_BASE`).
pub const AT_BASE: u64 = 7;
/// Auxiliary vector tag: flags for the executable (`AT_FLAGS`).
pub const AT_FLAGS: u64 = 8;
/// Auxiliary vector tag: entry point virtual address of the executable (`AT_ENTRY`).
pub const AT_ENTRY: u64 = 9;
/// Auxiliary vector tag: nonzero if program is not ELF (`AT_NOTELF`).
pub const AT_NOTELF: u64 = 10;
/// Auxiliary vector tag: real user ID of the process (`AT_UID`).
pub const AT_UID: u64 = 11;
/// Auxiliary vector tag: effective user ID of the process (`AT_EUID`).
pub const AT_EUID: u64 = 12;
/// Auxiliary vector tag: real group ID of the process (`AT_GID`).
pub const AT_GID: u64 = 13;
/// Auxiliary vector tag: effective group ID of the process (`AT_EGID`).
pub const AT_EGID: u64 = 14;
/// Auxiliary vector tag: string identifying the CPU platform (`AT_PLATFORM`).
pub const AT_PLATFORM: u64 = 15;
/// Auxiliary vector tag: CPU hardware capability bitmask (`AT_HWCAP`).
pub const AT_HWCAP: u64 = 16;
/// Auxiliary vector tag: frequency of `times(2)` ticks (`AT_CLKTCK`).
pub const AT_CLKTCK: u64 = 17;
/// Auxiliary vector tag: nonzero if running in secure mode (`setuid`/`setgid`, `AT_SECURE`).
pub const AT_SECURE: u64 = 23;
/// Auxiliary vector tag: address of 16 random bytes for stack protector initialization (`AT_RANDOM`).
pub const AT_RANDOM: u64 = 25;
/// Auxiliary vector tag: extended CPU hardware capability bitmask (`AT_HWCAP2`).
pub const AT_HWCAP2: u64 = 26;
/// Auxiliary vector tag: address of the filename string passed to `execve` (`AT_EXECFN`).
pub const AT_EXECFN: u64 = 31;
/// Auxiliary vector tag: base address of the vDSO ELF header (`AT_SYSINFO_EHDR`).
pub const AT_SYSINFO_EHDR: u64 = 33;

// Linux clone(2) flags
/// `clone` flag: parent and child share the virtual memory address space.
pub const CLONE_VM: u64 = 0x0000_0100;
/// `clone` flag: parent and child share filesystem context (root, cwd, umask).
pub const CLONE_FS: u64 = 0x0000_0200;
/// `clone` flag: parent and child share the open file descriptor table.
pub const CLONE_FILES: u64 = 0x0000_0400;
/// `clone` flag: parent and child share signal handlers.
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
/// `clone` flag: child is placed in the same thread group as the calling process.
pub const CLONE_THREAD: u64 = 0x0001_0000;
/// `clone` flag: set a new thread-local storage (TLS) descriptor (`FS` base) for the child.
pub const CLONE_SETTLS: u64 = 0x0008_0000;
/// `clone` flag: store the child thread ID at `parent_tid` in parent memory.
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
/// `clone` flag: clear and futex-wake `child_tid` in user memory when the child thread exits.
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// `clone` flag: store the child thread ID at `child_tid` in child memory.
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

/// Socket option level for socket-layer options (`SOL_SOCKET`).
pub const SOL_SOCKET: i32 = 1;
/// Socket ancillary control message type for passing open file descriptors (`SCM_RIGHTS`).
pub const SCM_RIGHTS: i32 = 1;


/// Linux `struct msghdr` for `sendmsg` and `recvmsg`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxMsghdr {
    /// Optional user-space address of the peer socket name (`sockaddr`).
    pub msg_name: u64,
    /// Size of the address buffer at `msg_name` in bytes.
    pub msg_namelen: u32,
    /// Pointer to an array of scatter/gather I/O vectors ([`LinuxIovec`]).
    pub msg_iov: *mut LinuxIovec,
    /// Number of elements in the `msg_iov` array.
    pub msg_iovlen: usize,
    /// Pointer to ancillary control message data (`struct cmsghdr` sequence).
    pub msg_control: *mut u8,
    /// Length of the ancillary control message buffer in bytes.
    pub msg_controllen: usize,
    /// Flags on the received message (e.g., `MSG_TRUNC`, `MSG_CTRUNC`).
    pub msg_flags: i32,
}

/// Linux `struct cmsghdr` header preceding each socket ancillary data payload.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxCmsghdr {
    /// Data byte count, including the `cmsghdr` header itself.
    pub cmsg_len: usize,
    /// Originating protocol level (e.g., [`SOL_SOCKET`]).
    pub cmsg_level: i32,
    /// Protocol-specific control message type (e.g., [`SCM_RIGHTS`]).
    pub cmsg_type: i32,
}
