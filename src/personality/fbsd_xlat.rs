//! # FreeBSD personality: the pure translations the kernel keeps (wave 12, Group FK)
//!
//! Flag and constant translations of calls whose objects the kernel owns (decision 39:
//! the kernel keeps only mechanism), with no kernel state, so the host unit tests compile
//! this file as it is (`tests/host-w12-fk`):
//!
//! - `open`/`openat` flags and the `AT_*` flags on the way in ([`open_flags`], [`at_flags`]);
//! - `mmap` flags ([`mmap_plan`]: `MAP_ANON`, `MAP_STACK`, `MAP_GUARD`, `MAP_EXCL`,
//!   `MAP_ALIGNED(n)`, `MAP_32BIT`), `madvise`, `minherit`, `msync`;
//! - clock ids ([`clock_id`]), `RLIMIT_*` numbers and `RLIM_INFINITY` ([`rlimit_resource`]);
//! - `wait4` options and the wait status ([`wait_options`], [`wait_status`]);
//! - signal sets and `sigprocmask`'s `how`, `stack_t`, `siginfo_t`;
//! - the FreeBSD `mcontext_t` ([`Mcontext`]), shared by signal frames and
//!   `getcontext`/`setcontext`/`swapcontext`;
//! - `_umtx_op`'s numbers and its timeout argument ([`umtx`]).
//!
//! What a *service* owns (`stat`, `dirent`, `statfs`, `sysctl`) is not here: the few pieces
//! milestone 3 needs before stage 2 are in [`super::fbsd_tmp`], marked temporary.

use super::abi;

// ----------------------------------------------------------------------
// open and the AT_* flags
// ----------------------------------------------------------------------

/// FreeBSD `open` flags (`sys/fcntl.h`).
#[allow(missing_docs)]
pub mod o {
    pub const ACCMODE: u64 = 0x3;
    pub const NONBLOCK: u64 = 0x4;
    pub const APPEND: u64 = 0x8;
    pub const SHLOCK: u64 = 0x10;
    pub const EXLOCK: u64 = 0x20;
    pub const ASYNC: u64 = 0x40;
    pub const FSYNC: u64 = 0x80;
    pub const NOFOLLOW: u64 = 0x100;
    pub const CREAT: u64 = 0x200;
    pub const TRUNC: u64 = 0x400;
    pub const EXCL: u64 = 0x800;
    pub const NOCTTY: u64 = 0x8000;
    pub const DIRECT: u64 = 0x1_0000;
    pub const DIRECTORY: u64 = 0x2_0000;
    pub const EXEC: u64 = 0x4_0000;
    pub const TTY_INIT: u64 = 0x8_0000;
    pub const CLOEXEC: u64 = 0x10_0000;
    pub const VERIFY: u64 = 0x20_0000;
    pub const PATH: u64 = 0x40_0000;
    pub const RESOLVE_BENEATH: u64 = 0x80_0000;
    pub const DSYNC: u64 = 0x100_0000;
    pub const EMPTY_PATH: u64 = 0x200_0000;
}

/// Linux `open` flags.
#[allow(missing_docs)]
pub mod lo {
    pub const CREAT: u64 = 0o100;
    pub const EXCL: u64 = 0o200;
    pub const NOCTTY: u64 = 0o400;
    pub const TRUNC: u64 = 0o1000;
    pub const APPEND: u64 = 0o2000;
    pub const NONBLOCK: u64 = 0o4000;
    pub const DSYNC: u64 = 0o10000;
    pub const ASYNC: u64 = 0o20000;
    pub const DIRECT: u64 = 0o40000;
    pub const LARGEFILE: u64 = 0o100000;
    pub const DIRECTORY: u64 = 0o200000;
    pub const NOFOLLOW: u64 = 0o400000;
    pub const CLOEXEC: u64 = 0o2000000;
    pub const SYNC: u64 = 0o4010000;
    pub const PATH: u64 = 0o10000000;
}

/// FreeBSD `open` flags to Linux's. `O_EXEC`/`O_SEARCH` (an open for `fexecve` or a
/// directory to search) become `O_PATH` when no read or write access is asked for;
/// `O_SHLOCK`, `O_EXLOCK`, `O_TTY_INIT`, `O_VERIFY` and `O_RESOLVE_BENEATH` have no Linux
/// flag and are dropped (the locks are advisory; the rest are hints or checks Hydra does
/// not make).
pub fn open_flags(f: u64) -> u64 {
    const MAP: [(u64, u64); 14] = [
        (o::NONBLOCK, lo::NONBLOCK),
        (o::APPEND, lo::APPEND),
        (o::ASYNC, lo::ASYNC),
        (o::FSYNC, lo::SYNC),
        (o::NOFOLLOW, lo::NOFOLLOW),
        (o::CREAT, lo::CREAT),
        (o::TRUNC, lo::TRUNC),
        (o::EXCL, lo::EXCL),
        (o::NOCTTY, lo::NOCTTY),
        (o::DIRECT, lo::DIRECT),
        (o::DIRECTORY, lo::DIRECTORY),
        (o::CLOEXEC, lo::CLOEXEC),
        (o::PATH, lo::PATH),
        (o::DSYNC, lo::DSYNC),
    ];
    let mut l = f & o::ACCMODE | lo::LARGEFILE;
    for (b, lb) in MAP {
        if f & b != 0 {
            l |= lb;
        }
    }
    if f & o::EXEC != 0 && f & o::ACCMODE == 0 {
        l |= lo::PATH;
    }
    l
}

/// Linux file status flags (`F_GETFL`) to FreeBSD's.
pub fn open_flags_to_fbsd(l: u64) -> u64 {
    const MAP: [(u64, u64); 10] = [
        (lo::NONBLOCK, o::NONBLOCK),
        (lo::APPEND, o::APPEND),
        (lo::ASYNC, o::ASYNC),
        (lo::NOFOLLOW, o::NOFOLLOW),
        (lo::DIRECT, o::DIRECT),
        (lo::DIRECTORY, o::DIRECTORY),
        (lo::CLOEXEC, o::CLOEXEC),
        (lo::PATH, o::PATH),
        (lo::DSYNC, o::DSYNC),
        (lo::NOCTTY, o::NOCTTY),
    ];
    let mut f = l & o::ACCMODE;
    for (lb, b) in MAP {
        if l & lb == lb {
            f |= b;
        }
    }
    if l & lo::SYNC == lo::SYNC {
        // (Linux's O_SYNC holds the O_DSYNC bit: FreeBSD's O_FSYNC alone)
        f = (f & !o::DSYNC) | o::FSYNC;
    }
    f
}

/// FreeBSD `AT_*` flags (`sys/fcntl.h`).
#[allow(missing_docs)]
pub mod at {
    pub const FDCWD: i64 = -100;
    pub const EACCESS: u64 = 0x100;
    pub const SYMLINK_NOFOLLOW: u64 = 0x200;
    pub const SYMLINK_FOLLOW: u64 = 0x400;
    pub const REMOVEDIR: u64 = 0x800;
    pub const RESOLVE_BENEATH: u64 = 0x2000;
    pub const EMPTY_PATH: u64 = 0x4000;
}

/// FreeBSD `AT_*` flags to Linux's (each call takes the ones that apply to it; Linux's
/// `AT_EACCESS` and `AT_REMOVEDIR` share a value, the call tells them apart).
/// `AT_RESOLVE_BENEATH` is dropped (see [`open_flags`]).
pub fn at_flags(f: u64) -> u64 {
    let mut l = 0;
    if f & at::EACCESS != 0 {
        l |= 0x200;
    }
    if f & at::SYMLINK_NOFOLLOW != 0 {
        l |= 0x100;
    }
    if f & at::SYMLINK_FOLLOW != 0 {
        l |= 0x400;
    }
    if f & at::REMOVEDIR != 0 {
        l |= 0x200;
    }
    if f & at::EMPTY_PATH != 0 {
        l |= 0x1000;
    }
    l
}

/// The `fd` argument of an `*at` call: FreeBSD's `AT_FDCWD` is Linux's (-100), as a 32-bit
/// int sign-extended.
pub fn at_fd(fd: u64) -> u64 {
    fd as i32 as i64 as u64
}

// ----------------------------------------------------------------------
// fcntl commands (the descriptor ones; locks are stage 2's: `struct flock` is the file
// service's layout)
// ----------------------------------------------------------------------

/// What a FreeBSD `fcntl` command becomes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fcntl {
    /// A Linux `fcntl` command.
    Linux {
        /// The Linux command.
        cmd: u64,
        /// The argument is a file status flag word to translate (`F_SETFL`).
        setfl: bool,
        /// The result is one (`F_GETFL`).
        getfl: bool,
    },
    /// `F_DUP2FD(_CLOEXEC)`: `dup3(fd, arg, cloexec ? O_CLOEXEC : 0)` (or `dup2` when the
    /// two are equal).
    Dup2 {
        /// `F_DUP2FD_CLOEXEC`.
        cloexec: bool,
    },
    /// `F_ISUNIONSTACK`: 0 (no union mounts here).
    Zero,
    /// Not translated in the kernel (the lock commands, `F_KINFO`...).
    Unsupported,
}

/// FreeBSD `fcntl` command `cmd`.
pub fn fcntl_cmd(cmd: u64) -> Fcntl {
    let l = |cmd| Fcntl::Linux { cmd, setfl: false, getfl: false };
    match cmd {
        0 => l(0),  // F_DUPFD
        1 => l(1),  // F_GETFD
        2 => l(2),  // F_SETFD (FD_CLOEXEC is 1 in both)
        3 => Fcntl::Linux { cmd: 3, setfl: false, getfl: true },
        4 => Fcntl::Linux { cmd: 4, setfl: true, getfl: false },
        5 => l(9),  // F_GETOWN
        6 => l(8),  // F_SETOWN
        10 => Fcntl::Dup2 { cloexec: false },
        17 => l(1030), // F_DUPFD_CLOEXEC
        18 => Fcntl::Dup2 { cloexec: true },
        19 => l(1033), // F_ADD_SEALS
        20 => l(1034), // F_GET_SEALS
        21 => Fcntl::Zero,
        15 | 16 => Fcntl::Zero, // F_READAHEAD, F_RDAHEAD: hints
        _ => Fcntl::Unsupported,
    }
}

/// FreeBSD seal bits (`F_SEAL_SEAL 1, SHRINK 2, GROW 4, WRITE 8`) are Linux's.
pub const SEALS_SAME: bool = true;

// ----------------------------------------------------------------------
// mmap and friends
// ----------------------------------------------------------------------

/// FreeBSD `mmap` flags (`sys/mman.h`).
#[allow(missing_docs)]
pub mod map {
    pub const SHARED: u64 = 0x1;
    pub const PRIVATE: u64 = 0x2;
    pub const FIXED: u64 = 0x10;
    pub const RESERVED0080: u64 = 0x80;
    pub const RESERVED0100: u64 = 0x100;
    pub const HASSEMAPHORE: u64 = 0x200;
    pub const STACK: u64 = 0x400;
    pub const NOSYNC: u64 = 0x800;
    pub const ANON: u64 = 0x1000;
    pub const GUARD: u64 = 0x2000;
    pub const EXCL: u64 = 0x4000;
    pub const NOCORE: u64 = 0x2_0000;
    pub const PREFAULT_READ: u64 = 0x4_0000;
    pub const MAP_32BIT: u64 = 0x8_0000;
    pub const ALIGNMENT_SHIFT: u64 = 24;
    pub const ALIGNMENT_MASK: u64 = 0xff << ALIGNMENT_SHIFT;
    /// `MAP_ALIGNED_SUPER`: aligned for superpages (2 MiB here).
    pub const ALIGNED_SUPER: u64 = 1;
}

/// How a FreeBSD `mmap` is done with Linux's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MmapPlan {
    /// Linux flags.
    pub flags: u64,
    /// Linux protection.
    pub prot: u64,
    /// The address must be aligned to `1 << align` (0: no alignment asked for).
    pub align: u8,
}

/// Linux mmap flags used below.
#[allow(missing_docs)]
pub mod lmap {
    pub const SHARED: u64 = 0x1;
    pub const PRIVATE: u64 = 0x2;
    pub const FIXED: u64 = 0x10;
    pub const ANON: u64 = 0x20;
    pub const MAP_32BIT: u64 = 0x40;
    pub const NORESERVE: u64 = 0x4000;
    pub const POPULATE: u64 = 0x8000;
    pub const STACK: u64 = 0x2_0000;
    pub const FIXED_NOREPLACE: u64 = 0x10_0000;
}

/// FreeBSD `mmap(addr, len, prot, flags, fd, off)`'s protection and flags as Linux's, or
/// `Err(())` for `EINVAL` (FreeBSD's own checks: `MAP_GUARD` only with `PROT_NONE`, no
/// descriptor and no other flag but `MAP_FIXED`/`MAP_EXCL`; `MAP_EXCL` only with
/// `MAP_FIXED`; `MAP_STACK` read-write, without a descriptor, and anonymous by itself; one
/// of `MAP_SHARED`/`MAP_PRIVATE` unless anonymous or a guard). `PROT_MAX`
/// (bits 16-18 of `prot`) is dropped: Hydra has no maximum protection.
pub fn mmap_plan(prot: u64, flags: u64, fd: u64) -> Result<MmapPlan, ()> {
    let prot = prot & 0x7;
    let fd_none = fd as i32 == -1;
    let align_n = (flags & map::ALIGNMENT_MASK) >> map::ALIGNMENT_SHIFT;
    if flags & map::GUARD != 0 {
        if prot != 0 || !fd_none || flags & !(map::GUARD | map::FIXED | map::EXCL) != 0 {
            return Err(());
        }
        let mut l = lmap::PRIVATE | lmap::ANON | lmap::NORESERVE;
        if flags & map::FIXED != 0 {
            l |= if flags & map::EXCL != 0 { lmap::FIXED_NOREPLACE } else { lmap::FIXED };
        }
        return Ok(MmapPlan { flags: l, prot: 0, align: 0 });
    }
    if flags & map::EXCL != 0 && flags & map::FIXED == 0 {
        return Err(());
    }
    // MAP_STACK implies an anonymous read-write mapping (FreeBSD's kern_mmap); libthr's
    // thread stacks pass MAP_STACK alone
    let flags = if flags & map::STACK != 0 {
        if !fd_none || prot & 3 != 3 {
            return Err(());
        }
        flags | map::ANON
    } else {
        flags
    };
    if flags & map::SHARED != 0 && flags & map::PRIVATE != 0 {
        return Err(());
    }
    let anon = flags & map::ANON != 0;
    if anon && !fd_none {
        return Err(());
    }
    let mut l = 0;
    if flags & map::SHARED != 0 {
        l |= lmap::SHARED;
    } else if flags & map::PRIVATE != 0 || anon {
        // (FreeBSD takes an anonymous mapping without either as private)
        l |= lmap::PRIVATE;
    } else {
        return Err(());
    }
    if anon {
        l |= lmap::ANON;
    }
    if flags & map::FIXED != 0 {
        l |= if flags & map::EXCL != 0 { lmap::FIXED_NOREPLACE } else { lmap::FIXED };
    }
    if flags & map::MAP_32BIT != 0 {
        l |= lmap::MAP_32BIT;
    }
    if flags & map::PREFAULT_READ != 0 {
        l |= lmap::POPULATE;
    }
    // MAP_STACK: an ordinary anonymous region here (Linux's flag is a hint too)
    if flags & map::STACK != 0 {
        l |= lmap::STACK;
    }
    let align = match align_n {
        0 => 0,
        map::ALIGNED_SUPER => 21,
        n if (12..64).contains(&n) => n as u8,
        _ => return Err(()),
    };
    // A fixed address needs no alignment of ours (FreeBSD checks it; so does the caller's
    // own arithmetic)
    let align = if flags & map::FIXED != 0 { 0 } else { align };
    Ok(MmapPlan { flags: l, prot, align })
}

/// For [`MmapPlan::align`]: how many extra bytes to map so that an aligned region of `len`
/// bytes fits, and where it starts in a mapping at `base`.
pub fn aligned_start(base: u64, align: u8) -> u64 {
    let a = 1u64 << align;
    (base + a - 1) & !(a - 1)
}

/// FreeBSD `madvise` advice to Linux's; `None`: a no-op that succeeds (`MADV_NOSYNC`,
/// `MADV_AUTOSYNC`, `MADV_PROTECT`), `Some(Err)`: `EINVAL`.
pub fn madvise(advice: u64) -> Option<Result<u64, ()>> {
    match advice {
        0..=4 => Some(Ok(advice)), // NORMAL RANDOM SEQUENTIAL WILLNEED DONTNEED
        5 => Some(Ok(8)),          // MADV_FREE
        6 | 7 | 10 => None,        // NOSYNC AUTOSYNC PROTECT
        8 => Some(Ok(16)),         // NOCORE -> DONTDUMP
        9 => Some(Ok(17)),         // CORE -> DODUMP
        _ => Some(Err(())),
    }
}

/// FreeBSD `minherit` to a Linux `madvise` advice: `INHERIT_SHARE 0` (no Linux equivalent:
/// refused), `INHERIT_COPY 1` -> `MADV_DOFORK`, `INHERIT_NONE 2` -> `MADV_DONTFORK`,
/// `INHERIT_ZERO 3` -> `MADV_WIPEONFORK` (arc4random's state).
pub fn minherit(inherit: u64) -> Result<u64, ()> {
    match inherit {
        1 => Ok(11),
        2 => Ok(10),
        3 => Ok(18),
        _ => Err(()),
    }
}

/// FreeBSD `msync` flags (`MS_SYNC 0, MS_ASYNC 1, MS_INVALIDATE 2`) to Linux's
/// (`MS_ASYNC 1, MS_INVALIDATE 2, MS_SYNC 4`).
pub fn msync_flags(f: u64) -> u64 {
    let mut l = f & 0x3;
    if f & 1 == 0 {
        l |= 4;
    }
    l
}

// ----------------------------------------------------------------------
// Clocks and limits
// ----------------------------------------------------------------------

/// FreeBSD clock id to `(Linux clock id, whole seconds only)`; `None`: not a clock here
/// (`CLOCK_VIRTUAL` 1 and the encoded per-process CPU clocks).
pub fn clock_id(id: u64) -> Option<(u64, bool)> {
    Some(match id as i32 {
        0 | 9 => (0, false),   // REALTIME, REALTIME_PRECISE
        10 => (5, false),      // REALTIME_FAST -> REALTIME_COARSE
        2 | 15 => (2, false),  // PROF, PROCESS_CPUTIME_ID
        4 | 11 => (1, false),  // MONOTONIC, MONOTONIC_PRECISE
        12 => (6, false),      // MONOTONIC_FAST -> MONOTONIC_COARSE
        5 | 7 | 8 => (7, false), // UPTIME(_PRECISE, _FAST) -> BOOTTIME
        13 => (0, true),       // SECOND
        14 => (3, false),      // THREAD_CPUTIME_ID
        _ => return None,
    })
}

/// FreeBSD `RLIMIT_*` to Linux's; `None` for FreeBSD-only resources (`SBSIZE` 9, `NPTS`
/// 11, `SWAP` 12, `KQUEUES` 13, `UMTXP` 14, `PIPEBUF` 15: "unlimited", and setting them
/// is accepted and ignored).
pub fn rlimit_resource(r: u64) -> Option<u64> {
    Some(match r {
        0..=5 => r,   // CPU FSIZE DATA STACK CORE RSS
        6 => 8,       // MEMLOCK
        7 => 6,       // NPROC
        8 => 7,       // NOFILE
        10 => 9,      // AS (VMEM)
        _ => return None,
    })
}

/// FreeBSD's `RLIM_INFINITY` (`INT64_MAX`).
pub const FBSD_RLIM_INFINITY: u64 = i64::MAX as u64;

/// A Linux limit value to FreeBSD's (`RLIM_INFINITY` differs: all ones on Linux).
pub fn rlim_to_fbsd(v: u64) -> u64 {
    if v == u64::MAX || v > FBSD_RLIM_INFINITY {
        FBSD_RLIM_INFINITY
    } else {
        v
    }
}

/// A FreeBSD limit value to Linux's.
pub fn rlim_from_fbsd(v: u64) -> u64 {
    if v >= FBSD_RLIM_INFINITY {
        u64::MAX
    } else {
        v
    }
}

/// FreeBSD scheduling policy (`SCHED_FIFO 1, SCHED_OTHER 2, SCHED_RR 3`) to Linux's.
pub fn sched_policy(p: u64) -> Option<u64> {
    match p {
        1 => Some(1),
        2 => Some(0),
        3 => Some(2),
        _ => None,
    }
}

/// Linux scheduling policy to FreeBSD's.
pub fn sched_policy_to_fbsd(p: i64) -> i64 {
    match p {
        0 | 3 | 5 => 2,
        1 => 1,
        2 => 3,
        _ => p,
    }
}

// ----------------------------------------------------------------------
// wait4
// ----------------------------------------------------------------------

/// FreeBSD `wait4` options (`WNOHANG 1, WUNTRACED 2, WCONTINUED 4, WNOWAIT 8, WEXITED 16,
/// WTRAPPED 32, WLINUXCLONE 0x80000000`) to Linux's.
pub fn wait_options(f: u64) -> u64 {
    let mut l = f & 0x3; // WNOHANG, WUNTRACED
    if f & 4 != 0 {
        l |= 8; // WCONTINUED
    }
    if f & 8 != 0 {
        l |= 0x0100_0000; // WNOWAIT
    }
    if f & 16 != 0 {
        l |= 4; // WEXITED
    }
    if f & 0x8000_0000 != 0 {
        l |= 0x8000_0000; // __WCLONE
    }
    l
}

/// A Linux wait status to FreeBSD's: signal numbers translated, "continued" (Linux
/// `0xffff`) as FreeBSD's `0x13` (`_WSTOPPED` with `SIGCONT`... FreeBSD's `WIFCONTINUED`).
pub fn wait_status(st: u32) -> u32 {
    if st == 0xffff {
        return 0x13;
    }
    let low = st & 0x7f;
    if low == 0 {
        st // exited: the code in bits 8-15
    } else if low == 0x7f {
        // stopped: the signal in bits 8-15
        let sig = (st >> 8) & 0xff;
        (abi::internal_sig_to_freebsd(sig) << 8) | 0x7f | (st & !0xffff)
    } else {
        // killed: the signal in bits 0-6, core dump in bit 7
        abi::internal_sig_to_freebsd(low) | (st & 0x80)
    }
}

// ----------------------------------------------------------------------
// Signals
// ----------------------------------------------------------------------

/// A FreeBSD signal set (128 bits, signal `n` is bit `n - 1`) to the internal mask.
pub fn mask_from_freebsd(b: &[u8]) -> u64 {
    let mut m = 0u64;
    for n in 1..=128u64 {
        let i = (n - 1) as usize;
        if b.get(i / 8).is_some_and(|x| x & (1 << (i % 8)) != 0) {
            if let Some(s) = abi::freebsd_sig_to_internal(n) {
                m |= 1 << (s - 1);
            }
        }
    }
    m
}

/// The internal mask to a FreeBSD signal set.
pub fn mask_to_freebsd(m: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    for s in 1..=64u32 {
        if m & (1 << (s - 1)) != 0 {
            let n = abi::internal_sig_to_freebsd(s) as usize;
            if (1..=128).contains(&n) {
                b[(n - 1) / 8] |= 1 << ((n - 1) % 8);
            }
        }
    }
    b
}

/// FreeBSD `sigprocmask`'s `how` (`SIG_BLOCK 1, SIG_UNBLOCK 2, SIG_SETMASK 3`) to Linux's
/// (0, 1, 2).
pub fn sigprocmask_how(how: u64) -> Option<u64> {
    match how {
        1..=3 => Some(how - 1),
        _ => None,
    }
}

/// FreeBSD `stack_t` (`ss_sp, ss_size, int ss_flags`; `SS_ONSTACK 1, SS_DISABLE 4`) to
/// Linux's (`ss_sp, int ss_flags, ss_size`; `SS_ONSTACK 1, SS_DISABLE 2`).
pub fn stack_to_linux(b: &[u8; 24]) -> [u8; 24] {
    let sp = &b[0..8];
    let size = &b[8..16];
    let f = u32::from_le_bytes(b[16..20].try_into().unwrap());
    let lf = (f & 1) | if f & 4 != 0 { 2 } else { 0 };
    let mut l = [0u8; 24];
    l[0..8].copy_from_slice(sp);
    l[8..12].copy_from_slice(&lf.to_le_bytes());
    l[16..24].copy_from_slice(size);
    l
}

/// Linux `stack_t` to FreeBSD's.
pub fn stack_to_fbsd(l: &[u8; 24]) -> [u8; 24] {
    let lf = u32::from_le_bytes(l[8..12].try_into().unwrap());
    let f = (lf & 1) | if lf & 2 != 0 { 4 } else { 0 };
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&l[0..8]);
    b[8..16].copy_from_slice(&l[16..24]);
    b[16..20].copy_from_slice(&f.to_le_bytes());
    b
}

/// FreeBSD `si_code` values (`sys/signal.h`).
#[allow(missing_docs)]
pub mod si {
    pub const USER: i32 = 0x10001;
    pub const QUEUE: i32 = 0x10002;
    pub const TIMER: i32 = 0x10003;
    pub const ASYNCIO: i32 = 0x10004;
    pub const MESGQ: i32 = 0x10005;
    pub const KERNEL: i32 = 0x10006;
    pub const LWP: i32 = 0x10007;
}

/// A Linux `si_code` to FreeBSD's (the fault and child codes are the same numbers).
pub fn si_code_to_fbsd(c: i32) -> i32 {
    match c {
        0 => si::USER,
        -1 => si::QUEUE,
        -2 => si::TIMER,
        -3 => si::MESGQ,
        -4 => si::ASYNCIO,
        -6 => si::LWP,
        0x80 => si::KERNEL,
        _ => c,
    }
}

/// `sizeof(siginfo_t)` on FreeBSD/amd64.
pub const FBSD_SIGINFO: usize = 80;

/// A Linux `siginfo_t` (128 bytes) to FreeBSD's (80): `si_signo, si_errno, si_code, si_pid,
/// si_uid, si_status, si_addr, si_value`. Which union member Linux filled follows from the
/// signal and code: faults carry the address, `SIGCHLD` the status, the rest a sender
/// and a value.
pub fn siginfo_to_fbsd(l: &[u8]) -> [u8; FBSD_SIGINFO] {
    let i32_at = |o: usize| i32::from_le_bytes(l[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(l[o..o + 8].try_into().unwrap());
    let signo = i32_at(0) as u32;
    let code = i32_at(8);
    let mut b = [0u8; FBSD_SIGINFO];
    b[0..4].copy_from_slice(&(abi::internal_sig_to_freebsd(signo) as i32).to_le_bytes());
    b[4..8].copy_from_slice(&i32_at(4).to_le_bytes());
    b[8..12].copy_from_slice(&si_code_to_fbsd(code).to_le_bytes());
    let fault = code > 0 && code < 0x80 && matches!(signo, 4 | 5 | 7 | 8 | 11);
    if fault {
        b[24..32].copy_from_slice(&u64_at(16).to_le_bytes()); // si_addr
    } else {
        b[12..16].copy_from_slice(&i32_at(16).to_le_bytes()); // si_pid
        b[16..20].copy_from_slice(&i32_at(20).to_le_bytes()); // si_uid
        if signo == 17 {
            // SIGCHLD: the exit code or the (translated) signal
            let st = i32_at(24);
            let st = if code != 1 { abi::internal_sig_to_freebsd(st as u32) as i32 } else { st };
            b[20..24].copy_from_slice(&st.to_le_bytes());
        } else {
            b[32..40].copy_from_slice(&u64_at(24).to_le_bytes()); // si_value
        }
    }
    b
}

// ----------------------------------------------------------------------
// mcontext_t / ucontext_t
// ----------------------------------------------------------------------

/// `sizeof(mcontext_t)` (`mc_len`).
pub const MC_LEN: usize = 800;
/// `sizeof(ucontext_t)`.
pub const UC_LEN: usize = 880;
/// Offset of `uc_mcontext` in `ucontext_t`.
pub const UC_MCONTEXT: usize = 16;
/// Offset of `uc_link`, `uc_stack`, `uc_flags`.
pub const UC_LINK: usize = 816;
/// See [`UC_LINK`].
pub const UC_STACK: usize = 824;
/// See [`UC_LINK`].
pub const UC_FLAGS: usize = 848;
/// `mc_fpformat`: `_MC_FPFMT_XMM`.
pub const FPFMT_XMM: u64 = 0x10002;
/// `mc_ownedfp`: `_MC_FPOWNED_NONE`.
pub const FPOWNED_NONE: u64 = 0x20000;
/// `mc_ownedfp`: `_MC_FPOWNED_FPU`.
pub const FPOWNED_FPU: u64 = 0x20001;
/// `mc_ownedfp`: `_MC_FPOWNED_PCB`.
pub const FPOWNED_PCB: u64 = 0x20002;
/// `mc_flags`: `_MC_HASBASES` (`mc_fsbase`/`mc_gsbase` valid).
pub const MC_HASBASES: u32 = 0x2;
/// `mc_flags`: `_MC_HASTLSBASE` (`mc_tlsbase` valid).
pub const MC_HASTLSBASE: u32 = 0x8;

/// The machine state of a FreeBSD `mcontext_t` (what Hydra keeps of it).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Mcontext {
    /// `mc_onstack`.
    pub onstack: u64,
    /// `mc_rdi`, `mc_rsi`, `mc_rdx`, `mc_rcx`, `mc_r8`, `mc_r9`, `mc_rax`, `mc_rbx`,
    /// `mc_rbp`, `mc_r10`, `mc_r11`, `mc_r12`, `mc_r13`, `mc_r14`, `mc_r15` (offsets 8-120).
    pub gprs: [u64; 15],
    /// `mc_rip`.
    pub rip: u64,
    /// `mc_cs`.
    pub cs: u64,
    /// `mc_rflags`.
    pub rflags: u64,
    /// `mc_rsp`.
    pub rsp: u64,
    /// `mc_ss`.
    pub ss: u64,
    /// `mc_fsbase` (with `_MC_HASBASES`) and `mc_tlsbase` (with `_MC_HASTLSBASE`).
    pub fsbase: u64,
    /// `mc_flags`.
    pub flags: u32,
}

/// Index of `mc_rax` in [`Mcontext::gprs`].
pub const MC_RAX: usize = 6;
/// Index of `mc_rdx` in [`Mcontext::gprs`].
pub const MC_RDX: usize = 2;

impl Mcontext {
    /// Writes the context into `out` (an `mcontext_t`, [`MC_LEN`] bytes) with the FXSAVE
    /// area `fpu` (`None`: `_MC_FPOWNED_NONE`).
    pub fn pack(&self, fpu: Option<&[u8; 512]>, out: &mut [u8]) {
        let put = |out: &mut [u8], off: usize, v: u64| out[off..off + 8].copy_from_slice(&v.to_le_bytes());
        out[..MC_LEN].fill(0);
        put(out, 0, self.onstack);
        for (i, v) in self.gprs.iter().enumerate() {
            put(out, 8 + i * 8, *v);
        }
        out[144..148].copy_from_slice(&(self.flags | MC_HASBASES | MC_HASTLSBASE).to_le_bytes());
        put(out, 160, self.rip);
        put(out, 168, self.cs);
        put(out, 176, self.rflags);
        put(out, 184, self.rsp);
        put(out, 192, self.ss);
        put(out, 200, MC_LEN as u64);
        put(out, 208, FPFMT_XMM);
        match fpu {
            Some(f) => {
                put(out, 216, FPOWNED_FPU);
                out[224..736].copy_from_slice(f);
            }
            None => put(out, 216, FPOWNED_NONE),
        }
        put(out, 736, self.fsbase);
        put(out, 768, self.fsbase);
    }

    /// Reads an `mcontext_t` (`b`, at least [`MC_LEN`] bytes): the state and the FXSAVE area
    /// when it holds one. `Err(())` for `EINVAL` (a wrong `mc_len`).
    pub fn unpack(b: &[u8]) -> Result<(Self, Option<[u8; 512]>), ()> {
        if b.len() < MC_LEN {
            return Err(());
        }
        let get = |off: usize| u64::from_le_bytes(b[off..off + 8].try_into().unwrap());
        if get(200) != MC_LEN as u64 {
            return Err(());
        }
        let mut m = Mcontext { onstack: get(0), ..Default::default() };
        for i in 0..15 {
            m.gprs[i] = get(8 + i * 8);
        }
        m.flags = u32::from_le_bytes(b[144..148].try_into().unwrap());
        m.rip = get(160);
        m.cs = get(168);
        m.rflags = get(176);
        m.rsp = get(184);
        m.ss = get(192);
        m.fsbase = if m.flags & MC_HASTLSBASE != 0 { get(768) } else { get(736) };
        let own = get(216);
        let fpu = if own == FPOWNED_FPU || own == FPOWNED_PCB {
            let mut f = [0u8; 512];
            f.copy_from_slice(&b[224..736]);
            // MXCSR's reserved bits clear, or FXRSTOR faults
            let mxcsr = u32::from_le_bytes(f[24..28].try_into().unwrap()) & 0xFFFF;
            f[24..28].copy_from_slice(&mxcsr.to_le_bytes());
            Some(f)
        } else {
            None
        };
        Ok((m, fpu))
    }

    /// The flags user code may give itself back (arithmetic flags, TF, DF, AC, ID): IF
    /// stays set; IOPL, NT (0x4000: an `iretq` with it set would fault in ring 0) and RF
    /// (0x10000) clear, as Linux's `sigreturn` does.
    pub fn user_rflags(r: u64) -> u64 {
        (r & 0x0000_0000_0024_0DD5) | 0x202
    }
}

// ----------------------------------------------------------------------
// _umtx_op
// ----------------------------------------------------------------------

/// `_umtx_op`'s numbers and its argument shapes (`sys/umtx.h`, `sys/_umtx.h`).
pub mod umtx {
    #![allow(missing_docs)]
    pub const OP_LOCK: u64 = 0;
    pub const OP_UNLOCK: u64 = 1;
    pub const OP_WAIT: u64 = 2;
    pub const OP_WAKE: u64 = 3;
    pub const OP_MUTEX_TRYLOCK: u64 = 4;
    pub const OP_MUTEX_LOCK: u64 = 5;
    pub const OP_MUTEX_UNLOCK: u64 = 6;
    pub const OP_SET_CEILING: u64 = 7;
    pub const OP_CV_WAIT: u64 = 8;
    pub const OP_CV_SIGNAL: u64 = 9;
    pub const OP_CV_BROADCAST: u64 = 10;
    pub const OP_WAIT_UINT: u64 = 11;
    pub const OP_RW_RDLOCK: u64 = 12;
    pub const OP_RW_WRLOCK: u64 = 13;
    pub const OP_RW_UNLOCK: u64 = 14;
    pub const OP_WAIT_UINT_PRIVATE: u64 = 15;
    pub const OP_WAKE_PRIVATE: u64 = 16;
    pub const OP_MUTEX_WAIT: u64 = 17;
    pub const OP_MUTEX_WAKE: u64 = 18;
    pub const OP_SEM_WAIT: u64 = 19;
    pub const OP_SEM_WAKE: u64 = 20;
    pub const OP_NWAKE_PRIVATE: u64 = 21;
    pub const OP_MUTEX_WAKE2: u64 = 22;
    pub const OP_SEM2_WAIT: u64 = 23;
    pub const OP_SEM2_WAKE: u64 = 24;
    pub const OP_SHM: u64 = 25;
    pub const OP_ROBUST_LISTS: u64 = 26;
    pub const OP_GET_MIN_TIMEOUT: u64 = 27;
    pub const OP_SET_MIN_TIMEOUT: u64 = 28;
    /// Flag bits a 32-bit or i386 caller adds to the op (refused here).
    pub const OP_COMPAT_BITS: u64 = 0xC000_0000;

    pub const USYNC_PROCESS_SHARED: u32 = 0x1;
    pub const UMUTEX_PRIO_INHERIT: u32 = 0x4;
    pub const UMUTEX_PRIO_PROTECT: u32 = 0x8;
    pub const UMUTEX_ROBUST: u32 = 0x10;
    pub const UMUTEX_NONCONSISTENT: u32 = 0x20;
    pub const UMUTEX_UNOWNED: u32 = 0;
    pub const UMUTEX_CONTESTED: u32 = 0x8000_0000;
    pub const UMUTEX_RB_OWNERDEAD: u32 = UMUTEX_CONTESTED | 0x10;
    pub const UMUTEX_RB_NOTRECOV: u32 = UMUTEX_CONTESTED | 0x11;
    pub const URWLOCK_PREFER_READER: u32 = 0x2;
    pub const URWLOCK_WRITE_OWNER: u32 = 0x8000_0000;
    pub const URWLOCK_WRITE_WAITERS: u32 = 0x4000_0000;
    pub const URWLOCK_READ_WAITERS: u32 = 0x2000_0000;
    pub const URWLOCK_MAX_READERS: u32 = 0x1fff_ffff;
    pub const USEM_HAS_WAITERS: u32 = 0x8000_0000;
    pub const USEM_MAX_COUNT: u32 = 0x7fff_ffff;
    pub const UMTX_ABSTIME: u32 = 0x1;
    pub const CVWAIT_CHECK_UNPARKING: u64 = 0x1;
    pub const CVWAIT_ABSTIME: u64 = 0x2;
    pub const CVWAIT_CLOCKID: u64 = 0x4;

    /// Offsets: `struct umutex { m_owner; m_flags; ... }`, `struct ucond { c_has_waiters;
    /// c_flags; c_clockid; }`, `struct urwlock { rw_state; rw_flags; rw_blocked_readers;
    /// rw_blocked_writers; }`, `struct _usem2 { _count; _flags; }`.
    pub const M_OWNER: u64 = 0;
    pub const M_FLAGS: u64 = 4;
    pub const C_HAS_WAITERS: u64 = 0;
    pub const C_FLAGS: u64 = 4;
    pub const C_CLOCKID: u64 = 8;
    pub const RW_STATE: u64 = 0;
    pub const RW_FLAGS: u64 = 4;
    pub const RW_BLOCKED_READERS: u64 = 8;
    pub const RW_BLOCKED_WRITERS: u64 = 12;
    pub const SEM_COUNT: u64 = 0;
    pub const SEM_FLAGS: u64 = 4;

    /// A wait's timeout, as `umtx_copyin_umtx_time` reads it: a `struct timespec` alone
    /// (relative, `CLOCK_REALTIME`) when the size argument is at most 16, else a
    /// `struct _umtx_time { timespec; u32 flags; u32 clockid }`.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Timeout {
        pub sec: i64,
        pub nsec: i64,
        pub abs: bool,
        /// FreeBSD clock id.
        pub clock: u32,
    }

    /// How many bytes [`Timeout`] reads for size argument `size`.
    /// `None`: `EINVAL` (FreeBSD reads a `struct _umtx_time` only when the size says all
    /// of it is there, so 17 to 23 bytes are refused).
    pub fn timeout_len(size: u64) -> Option<usize> {
        match size {
            0..=16 => Some(16),
            17..=23 => None,
            _ => Some(24),
        }
    }

    /// Parses the bytes `b` ([`timeout_len`] of them); `Err(())` for `EINVAL` (a negative
    /// or out-of-range time).
    pub fn parse_timeout(b: &[u8]) -> Result<Timeout, ()> {
        let sec = i64::from_le_bytes(b[0..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(b[8..16].try_into().unwrap());
        if !(0..1_000_000_000).contains(&nsec) || sec < 0 {
            return Err(());
        }
        let (abs, clock) = if b.len() >= 24 {
            (u32::from_le_bytes(b[16..20].try_into().unwrap()) & UMTX_ABSTIME != 0, u32::from_le_bytes(b[20..24].try_into().unwrap()))
        } else {
            (false, 0)
        };
        Ok(Timeout { sec, nsec, abs, clock })
    }

    /// Whether FreeBSD clock `c` counts wall time (an absolute deadline on it moves with the
    /// clock); otherwise it is one of the monotonic clocks.
    pub fn clock_is_realtime(c: u32) -> bool {
        matches!(c, 0 | 9 | 10 | 13)
    }

    /// Whether a mutex word lets a `MUTEX_WAIT` return at once (`_UMUTEX_WAIT` mode: the
    /// lock is free, or its owner died).
    pub fn mutex_wait_done(owner: u32) -> bool {
        matches!(owner, UMUTEX_UNOWNED | UMUTEX_CONTESTED | UMUTEX_RB_OWNERDEAD | UMUTEX_RB_NOTRECOV)
    }

    /// The word an unlock leaves (`umtx_unlock_val`, never at a robust owner's death here):
    /// `UMUTEX_RB_NOTRECOV` for a robust mutex left inconsistent, else unowned; with the
    /// contested bit when more than one thread waits.
    pub fn unlock_value(mflags: u32, waiters: usize) -> u32 {
        let v = if mflags & UMUTEX_NONCONSISTENT != 0 { UMUTEX_RB_NOTRECOV } else { UMUTEX_UNOWNED };
        if waiters > 1 {
            v | UMUTEX_CONTESTED
        } else {
            v
        }
    }

    /// The bits that keep a reader out of a rwlock (`do_rw_rdlock`'s `wrflags`): a writer,
    /// and waiting writers unless readers are preferred (by the lock or the call).
    pub fn rd_block_mask(call_flags: u64, lock_flags: u32) -> u32 {
        if call_flags & URWLOCK_PREFER_READER as u64 != 0 || lock_flags & URWLOCK_PREFER_READER != 0 {
            URWLOCK_WRITE_OWNER
        } else {
            URWLOCK_WRITE_OWNER | URWLOCK_WRITE_WAITERS
        }
    }

    /// The reader count of a rwlock state.
    pub fn readers(state: u32) -> u32 {
        state & URWLOCK_MAX_READERS
    }

    /// Whom a rwlock unlock wakes, from the state before it: `Some((writers, n))`.
    pub fn rw_unlock_wakes(state: u32, lock_flags: u32) -> Option<(bool, usize)> {
        let w = state & URWLOCK_WRITE_WAITERS != 0;
        let r = state & URWLOCK_READ_WAITERS != 0;
        if lock_flags & URWLOCK_PREFER_READER == 0 {
            if w {
                Some((true, 1))
            } else if r {
                Some((false, usize::MAX))
            } else {
                None
            }
        } else if r {
            Some((false, usize::MAX))
        } else if w {
            Some((true, 1))
        } else {
            None
        }
    }

    /// The new state of a rwlock unlock by the caller, or `Err(())` for `EPERM` (neither a
    /// writer nor a reader holds it).
    pub fn rw_unlocked(state: u32) -> Result<u32, ()> {
        if state & URWLOCK_WRITE_OWNER != 0 {
            Ok(state & !URWLOCK_WRITE_OWNER)
        } else if readers(state) != 0 {
            Ok(state - 1)
        } else {
            Err(())
        }
    }
}

// ----------------------------------------------------------------------
// Device numbers
// ----------------------------------------------------------------------

/// A Linux `dev_t` (`major` in bits 8-19 and 32-63, `minor` in 0-7 and 20-31) to
/// FreeBSD's encoding (`makedev`: `((major & 0xffffff00) << 32) | ((major & 0xff) << 8) |
/// ((minor & 0xff00) << 24) | (minor & 0xffff00ff)`).
pub fn dev_to_fbsd(d: u64) -> u64 {
    let major = ((d >> 8) & 0xfff) | ((d >> 32) & !0xfff);
    let minor = (d & 0xff) | ((d >> 12) & !0xff);
    ((major & 0xffff_ff00) << 32) | ((major & 0xff) << 8) | ((minor & 0xff00) << 24) | (minor & 0xffff_00ff)
}

/// A FreeBSD `dev_t` to Linux's encoding.
pub fn dev_from_fbsd(d: u64) -> u64 {
    let major = ((d >> 32) & 0xffff_ff00) | ((d >> 8) & 0xff);
    let minor = ((d >> 24) & 0xff00) | (d & 0xffff_00ff);
    ((major & 0xfff) << 8) | ((major & !0xfff) << 32) | (minor & 0xff) | ((minor & !0xff) << 12)
}

// ----------------------------------------------------------------------
// The "D" calls
// ----------------------------------------------------------------------

/// The "D" calls: FreeBSD number, the Linux call with the same arguments and meaning.
pub const DIRECT: [(u16, u16); 106] = [
    (1, 231),   // _exit: the whole process
    (2, 57),    // fork
    (3, 0),     // read
    (4, 1),     // write
    (6, 3),     // close
    (9, 86),    // link
    (10, 87),   // unlink
    (12, 80),   // chdir
    (13, 81),   // fchdir
    (15, 90),   // chmod
    (16, 92),   // chown
    (23, 105),  // setuid
    (24, 102),  // getuid
    (25, 107),  // geteuid
    (33, 21),   // access
    (36, 162),  // sync
    (39, 110),  // getppid
    (41, 32),   // dup
    (43, 108),  // getegid
    (47, 104),  // getgid
    (51, 163),  // acct
    (57, 88),   // symlink
    (58, 89),   // readlink
    (59, 59),   // execve
    (60, 95),   // umask
    (61, 161),  // chroot
    (66, 58),   // vfork
    (73, 11),   // munmap
    (78, 27),   // mincore
    (81, 111),  // getpgrp
    (82, 109),  // setpgid
    (83, 38),   // setitimer
    (86, 36),   // getitimer
    (90, 33),   // dup2
    (93, 23),   // select
    (95, 74),   // fsync
    (96, 141),  // setpriority (PRIO_* are the same)
    (106, 50),  // listen
    (116, 96),  // gettimeofday
    (117, 98),  // getrusage (RUSAGE_* and struct rusage are the same)
    (120, 19),  // readv
    (121, 20),  // writev
    (122, 164), // settimeofday
    (123, 93),  // fchown
    (124, 91),  // fchmod
    (126, 113), // setreuid
    (127, 114), // setregid
    (128, 82),  // rename
    (131, 73),  // flock (LOCK_* are the same)
    (134, 48),  // shutdown
    (136, 83),  // mkdir
    (137, 84),  // rmdir
    (138, 235), // utimes
    (147, 112), // setsid
    (181, 106), // setgid
    (203, 149), // mlock
    (204, 150), // munlock
    (207, 121), // getpgid
    (209, 7),   // poll
    (221, 64),  // semget
    (222, 65),  // semop
    (225, 68),  // msgget
    (226, 69),  // msgsnd
    (227, 70),  // msgrcv
    (228, 30),  // shmat
    (230, 67),  // shmdt
    (231, 29),  // shmget
    (240, 35),  // nanosleep
    (254, 94),  // lchown
    (289, 295), // preadv
    (290, 296), // pwritev
    (310, 124), // getsid
    (311, 117), // setresuid
    (312, 119), // setresgid
    (321, 24),  // yield
    (324, 151), // mlockall
    (325, 152), // munlockall
    (327, 142), // sched_setparam
    (328, 143), // sched_getparam
    (331, 24),  // sched_yield
    (334, 148), // sched_rr_get_interval
    (360, 118), // getresuid
    (361, 120), // getresgid
    (458, 245), // kmq_setattr (struct mq_attr is the same)
    (459, 243), // kmq_timedreceive
    (460, 242), // kmq_timedsend
    (475, 17),  // pread
    (476, 18),  // pwrite
    (478, 8),   // lseek
    (479, 76),  // truncate
    (480, 77),  // ftruncate
    (494, 261), // futimesat
    (496, 258), // mkdirat
    (500, 267), // readlinkat
    (501, 264), // renameat
    (502, 266), // symlinkat
    (550, 75),  // fdatasync
    (563, 318), // getrandom
    (569, 326), // copy_file_range
    (575, 436), // close_range
    (584, 324), // membarrier
    (586, 287), // timerfd_gettime
    (587, 286), // timerfd_settime
    (594, 255), // inotify_rm_watch
    (595, 115), // getgroups
    (596, 116), // setgroups
];

// ----------------------------------------------------------------------
// Names
// ----------------------------------------------------------------------

/// FreeBSD 15.1's live system calls by number (`sys/kern/syscalls.master`, `STD`/`NOSTD`): the
/// names the log lines use.
pub const NAMES: &[(u16, &str)] = &[
    (0, "syscall"), (1, "_exit"), (2, "fork"), (3, "read"), (4, "write"), (5, "open"), (6, "close"),
    (7, "wait4"), (9, "link"), (10, "unlink"), (12, "chdir"), (13, "fchdir"), (15, "chmod"), (16, "chown"),
    (17, "break"), (20, "getpid"), (21, "mount"), (22, "unmount"), (23, "setuid"), (24, "getuid"),
    (25, "geteuid"), (26, "ptrace"), (27, "recvmsg"), (28, "sendmsg"), (29, "recvfrom"), (30, "accept"),
    (31, "getpeername"), (32, "getsockname"), (33, "access"), (34, "chflags"), (35, "fchflags"),
    (36, "sync"), (37, "kill"), (39, "getppid"), (41, "dup"), (43, "getegid"), (44, "profil"),
    (45, "ktrace"), (47, "getgid"), (49, "getlogin"), (50, "setlogin"), (51, "acct"), (53, "sigaltstack"),
    (54, "ioctl"), (55, "reboot"), (56, "revoke"), (57, "symlink"), (58, "readlink"), (59, "execve"),
    (60, "umask"), (61, "chroot"), (65, "msync"), (66, "vfork"), (73, "munmap"), (74, "mprotect"),
    (75, "madvise"), (78, "mincore"), (81, "getpgrp"), (82, "setpgid"), (83, "setitimer"), (85, "swapon"),
    (86, "getitimer"), (89, "getdtablesize"), (90, "dup2"), (92, "fcntl"), (93, "select"), (95, "fsync"),
    (96, "setpriority"), (97, "socket"), (98, "connect"), (100, "getpriority"), (104, "bind"),
    (105, "setsockopt"), (106, "listen"), (116, "gettimeofday"), (117, "getrusage"), (118, "getsockopt"),
    (120, "readv"), (121, "writev"), (122, "settimeofday"), (123, "fchown"), (124, "fchmod"),
    (126, "setreuid"), (127, "setregid"), (128, "rename"), (131, "flock"), (132, "mkfifo"), (133, "sendto"),
    (134, "shutdown"), (135, "socketpair"), (136, "mkdir"), (137, "rmdir"), (138, "utimes"),
    (140, "adjtime"), (147, "setsid"), (148, "quotactl"), (154, "nlm_syscall"), (155, "nfssvc"),
    (160, "lgetfh"), (161, "getfh"), (165, "sysarch"), (166, "rtprio"), (169, "semsys"), (170, "msgsys"),
    (171, "shmsys"), (175, "setfib"), (176, "ntp_adjtime"), (181, "setgid"), (182, "setegid"),
    (183, "seteuid"), (191, "pathconf"), (192, "fpathconf"), (194, "getrlimit"), (195, "setrlimit"),
    (198, "__syscall"), (202, "__sysctl"), (203, "mlock"), (204, "munlock"), (205, "undelete"),
    (206, "futimes"), (207, "getpgid"), (209, "poll"), (221, "semget"), (222, "semop"), (225, "msgget"),
    (226, "msgsnd"), (227, "msgrcv"), (228, "shmat"), (230, "shmdt"), (231, "shmget"),
    (232, "clock_gettime"), (233, "clock_settime"), (234, "clock_getres"), (235, "ktimer_create"),
    (236, "ktimer_delete"), (237, "ktimer_settime"), (238, "ktimer_gettime"), (239, "ktimer_getoverrun"),
    (240, "nanosleep"), (241, "ffclock_getcounter"), (242, "ffclock_setestimate"),
    (243, "ffclock_getestimate"), (244, "clock_nanosleep"), (247, "clock_getcpuclockid2"),
    (248, "ntp_gettime"), (250, "minherit"), (251, "rfork"), (253, "issetugid"), (254, "lchown"),
    (255, "aio_read"), (256, "aio_write"), (257, "lio_listio"), (274, "lchmod"), (276, "lutimes"),
    (289, "preadv"), (290, "pwritev"), (298, "fhopen"), (300, "modnext"), (301, "modstat"),
    (302, "modfnext"), (303, "modfind"), (304, "kldload"), (305, "kldunload"), (306, "kldfind"),
    (307, "kldnext"), (308, "kldstat"), (309, "kldfirstmod"), (310, "getsid"), (311, "setresuid"),
    (312, "setresgid"), (314, "aio_return"), (315, "aio_suspend"), (316, "aio_cancel"), (317, "aio_error"),
    (321, "yield"), (324, "mlockall"), (325, "munlockall"), (326, "__getcwd"), (327, "sched_setparam"),
    (328, "sched_getparam"), (329, "sched_setscheduler"), (330, "sched_getscheduler"), (331, "sched_yield"),
    (332, "sched_get_priority_max"), (333, "sched_get_priority_min"), (334, "sched_rr_get_interval"),
    (335, "utrace"), (337, "kldsym"), (338, "jail"), (339, "nnpfs_syscall"), (340, "sigprocmask"),
    (341, "sigsuspend"), (343, "sigpending"), (345, "sigtimedwait"), (346, "sigwaitinfo"),
    (347, "__acl_get_file"), (348, "__acl_set_file"), (349, "__acl_get_fd"), (350, "__acl_set_fd"),
    (351, "__acl_delete_file"), (352, "__acl_delete_fd"), (353, "__acl_aclcheck_file"),
    (354, "__acl_aclcheck_fd"), (355, "extattrctl"), (356, "extattr_set_file"), (357, "extattr_get_file"),
    (358, "extattr_delete_file"), (359, "aio_waitcomplete"), (360, "getresuid"), (361, "getresgid"),
    (362, "kqueue"), (371, "extattr_set_fd"), (372, "extattr_get_fd"), (373, "extattr_delete_fd"),
    (374, "__setugid"), (376, "eaccess"), (377, "afs3_syscall"), (378, "nmount"), (384, "__mac_get_proc"),
    (385, "__mac_set_proc"), (386, "__mac_get_fd"), (387, "__mac_get_file"), (388, "__mac_set_fd"),
    (389, "__mac_set_file"), (390, "kenv"), (391, "lchflags"), (392, "uuidgen"), (393, "sendfile"),
    (394, "mac_syscall"), (400, "ksem_close"), (401, "ksem_post"), (402, "ksem_wait"), (403, "ksem_trywait"),
    (404, "ksem_init"), (405, "ksem_open"), (406, "ksem_unlink"), (407, "ksem_getvalue"),
    (408, "ksem_destroy"), (409, "__mac_get_pid"), (410, "__mac_get_link"), (411, "__mac_set_link"),
    (412, "extattr_set_link"), (413, "extattr_get_link"), (414, "extattr_delete_link"),
    (415, "__mac_execve"), (416, "sigaction"), (417, "sigreturn"), (421, "getcontext"), (422, "setcontext"),
    (423, "swapcontext"), (425, "__acl_get_link"), (426, "__acl_set_link"), (427, "__acl_delete_link"),
    (428, "__acl_aclcheck_link"), (429, "sigwait"), (430, "thr_create"), (431, "thr_exit"),
    (432, "thr_self"), (433, "thr_kill"), (436, "jail_attach"), (437, "extattr_list_fd"),
    (438, "extattr_list_file"), (439, "extattr_list_link"), (441, "ksem_timedwait"), (442, "thr_suspend"),
    (443, "thr_wake"), (444, "kldunloadf"), (445, "audit"), (446, "auditon"), (447, "getauid"),
    (448, "setauid"), (449, "getaudit"), (450, "setaudit"), (451, "getaudit_addr"), (452, "setaudit_addr"),
    (453, "auditctl"), (454, "_umtx_op"), (455, "thr_new"), (456, "sigqueue"), (457, "kmq_open"),
    (458, "kmq_setattr"), (459, "kmq_timedreceive"), (460, "kmq_timedsend"), (461, "kmq_notify"),
    (462, "kmq_unlink"), (463, "abort2"), (464, "thr_set_name"), (465, "aio_fsync"), (466, "rtprio_thread"),
    (471, "sctp_peeloff"), (472, "sctp_generic_sendmsg"), (473, "sctp_generic_sendmsg_iov"),
    (474, "sctp_generic_recvmsg"), (475, "pread"), (476, "pwrite"), (477, "mmap"), (478, "lseek"),
    (479, "truncate"), (480, "ftruncate"), (481, "thr_kill2"), (483, "shm_unlink"), (484, "cpuset"),
    (485, "cpuset_setid"), (486, "cpuset_getid"), (487, "cpuset_getaffinity"), (488, "cpuset_setaffinity"),
    (489, "faccessat"), (490, "fchmodat"), (491, "fchownat"), (492, "fexecve"), (494, "futimesat"),
    (495, "linkat"), (496, "mkdirat"), (497, "mkfifoat"), (499, "openat"), (500, "readlinkat"),
    (501, "renameat"), (502, "symlinkat"), (503, "unlinkat"), (504, "posix_openpt"), (506, "jail_get"),
    (507, "jail_set"), (508, "jail_remove"), (510, "__semctl"), (511, "msgctl"), (512, "shmctl"),
    (513, "lpathconf"), (515, "__cap_rights_get"), (516, "cap_enter"), (517, "cap_getmode"), (518, "pdfork"),
    (519, "pdkill"), (520, "pdgetpid"), (522, "pselect"), (523, "getloginclass"), (524, "setloginclass"),
    (525, "rctl_get_racct"), (526, "rctl_get_rules"), (527, "rctl_get_limits"), (528, "rctl_add_rule"),
    (529, "rctl_remove_rule"), (530, "posix_fallocate"), (531, "posix_fadvise"), (532, "wait6"),
    (533, "cap_rights_limit"), (534, "cap_ioctls_limit"), (535, "cap_ioctls_get"), (536, "cap_fcntls_limit"),
    (537, "cap_fcntls_get"), (538, "bindat"), (539, "connectat"), (540, "chflagsat"), (541, "accept4"),
    (542, "pipe2"), (543, "aio_mlock"), (544, "procctl"), (545, "ppoll"), (546, "futimens"),
    (547, "utimensat"), (550, "fdatasync"), (551, "fstat"), (552, "fstatat"), (553, "fhstat"),
    (554, "getdirentries"), (555, "statfs"), (556, "fstatfs"), (557, "getfsstat"), (558, "fhstatfs"),
    (559, "mknodat"), (560, "kevent"), (561, "cpuset_getdomain"), (562, "cpuset_setdomain"),
    (563, "getrandom"), (564, "getfhat"), (565, "fhlink"), (566, "fhlinkat"), (567, "fhreadlink"),
    (568, "funlinkat"), (569, "copy_file_range"), (570, "__sysctlbyname"), (571, "shm_open2"),
    (572, "shm_rename"), (573, "sigfastblock"), (574, "__realpathat"), (575, "close_range"),
    (576, "rpctls_syscall"), (577, "__specialfd"), (578, "aio_writev"), (579, "aio_readv"),
    (580, "fspacectl"), (581, "sched_getcpu"), (582, "swapoff"), (583, "kqueuex"), (584, "membarrier"),
    (585, "timerfd_create"), (586, "timerfd_gettime"), (587, "timerfd_settime"), (588, "kcmp"),
    (589, "getrlimitusage"), (590, "fchroot"), (591, "setcred"), (592, "exterrctl"),
    (593, "inotify_add_watch_at"), (594, "inotify_rm_watch"), (595, "getgroups"), (596, "setgroups"),
    (597, "jail_attach_jd"), (598, "jail_remove_jd"), (600, "pdrfork"), (601, "pdwait"), (602, "renameat2"),
];

/// The name of FreeBSD call `nr` (`None`: not a live FreeBSD call).
pub fn name(nr: u64) -> Option<&'static str> {
    NAMES.binary_search_by_key(&nr, |e| e.0 as u64).ok().map(|i| NAMES[i].1)
}
