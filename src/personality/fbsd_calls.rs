//! # FreeBSD personality: the kernel-local calls (wave 12, Group FK)
//!
//! The handlers behind the table's `R_KERNEL` entries ([`super::freebsd::LOCAL`],
//! [`super::freebsd::STUBS`]): flag and constant translations onto the Linux calls (the pure
//! parts are in [`super::fbsd_xlat`]), the mechanism of design 2.8 (signals, contexts,
//! threads, `_umtx_op`, `sysarch`), and the temporary pieces of [`super::fbsd_tmp`].
//!
//! **Translated structures go through the caller's stack:** a call whose Linux form takes a
//! different structure (a 64-bit signal mask, Linux's `stack_t`, a `struct rlimit` with
//! Linux's infinity, ...) writes the translated copy just below the caller's stack pointer,
//! past the red zone ([`scratch`]), and passes that address to the Linux call. Nothing else
//! runs on that thread's stack during the call (signals are delivered on the way out).
//! Calls whose Linux result is smaller than FreeBSD's structure (`fstat`, `fstatfs`,
//! `getdirentries`) let Linux write into the caller's own buffer and convert in place.

use super::fbsd_tmp as tmp;
use super::fbsd_xlat as x;
use super::{linux_call, Ret};
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const ENOSYS: i64 = -38;
const EOPNOTSUPP: i64 = -95;

// Handler ids (the table's `arg` for R_KERNEL entries)
/// Handler id ([`local_call`]).
pub const L_GETPID: u16 = 1;
/// Handler id ([`local_call`]).
pub const L_KILL: u16 = 2;
/// Handler id ([`local_call`]).
pub const L_SIGACTION: u16 = 3;
/// Handler id ([`local_call`]).
pub const L_SIGRETURN: u16 = 4;
/// Handler id ([`local_call`]).
pub const L_THR_SELF: u16 = 5;
/// Handler id ([`local_call`]).
pub const L_OPEN: u16 = 6;
/// Handler id ([`local_call`]).
pub const L_OPENAT: u16 = 7;
/// Handler id ([`local_call`]).
pub const L_FACCESSAT: u16 = 8;
/// Handler id ([`local_call`]).
pub const L_FCHMODAT: u16 = 9;
/// Handler id ([`local_call`]).
pub const L_FCHOWNAT: u16 = 10;
/// Handler id ([`local_call`]).
pub const L_LINKAT: u16 = 11;
/// Handler id ([`local_call`]).
pub const L_UNLINKAT: u16 = 12;
/// Handler id ([`local_call`]).
pub const L_UTIMENSAT: u16 = 13;
/// Handler id ([`local_call`]).
pub const L_FUTIMENS: u16 = 14;
/// Handler id ([`local_call`]).
pub const L_MKNODAT: u16 = 15;
/// Handler id ([`local_call`]).
pub const L_MKFIFO: u16 = 16;
/// Handler id ([`local_call`]).
pub const L_MKFIFOAT: u16 = 17;
/// Handler id ([`local_call`]).
pub const L_EACCESS: u16 = 18;
/// Handler id ([`local_call`]).
pub const L_RENAMEAT2: u16 = 19;
/// Handler id ([`local_call`]).
pub const L_FUNLINKAT: u16 = 20;
/// Handler id ([`local_call`]).
pub const L_MMAP: u16 = 21;
/// Handler id ([`local_call`]).
pub const L_MPROTECT: u16 = 22;
/// Handler id ([`local_call`]).
pub const L_MADVISE: u16 = 23;
/// Handler id ([`local_call`]).
pub const L_MINHERIT: u16 = 24;
/// Handler id ([`local_call`]).
pub const L_MSYNC: u16 = 25;
/// Handler id ([`local_call`]).
pub const L_BREAK: u16 = 26;
/// Handler id ([`local_call`]).
pub const L_CLOCK_GETTIME: u16 = 27;
/// Handler id ([`local_call`]).
pub const L_CLOCK_SETTIME: u16 = 28;
/// Handler id ([`local_call`]).
pub const L_CLOCK_GETRES: u16 = 29;
/// Handler id ([`local_call`]).
pub const L_CLOCK_NANOSLEEP: u16 = 30;
/// Handler id ([`local_call`]).
pub const L_TIMERFD_CREATE: u16 = 31;
/// Handler id ([`local_call`]).
pub const L_GETRLIMIT: u16 = 32;
/// Handler id ([`local_call`]).
pub const L_SETRLIMIT: u16 = 33;
/// Handler id ([`local_call`]).
pub const L_GETDTABLESIZE: u16 = 34;
/// Handler id ([`local_call`]).
pub const L_WAIT4: u16 = 35;
/// Handler id ([`local_call`]).
pub const L_SIGPROCMASK: u16 = 36;
/// Handler id ([`local_call`]).
pub const L_SIGSUSPEND: u16 = 37;
/// Handler id ([`local_call`]).
pub const L_SIGPENDING: u16 = 38;
/// Handler id ([`local_call`]).
pub const L_SIGTIMEDWAIT: u16 = 39;
/// Handler id ([`local_call`]).
pub const L_SIGWAITINFO: u16 = 40;
/// Handler id ([`local_call`]).
pub const L_SIGWAIT: u16 = 41;
/// Handler id ([`local_call`]).
pub const L_SIGALTSTACK: u16 = 42;
/// Handler id ([`local_call`]).
pub const L_SIGQUEUE: u16 = 43;
/// Handler id ([`local_call`]).
pub const L_THR_KILL: u16 = 44;
/// Handler id ([`local_call`]).
pub const L_THR_KILL2: u16 = 45;
/// Handler id ([`local_call`]).
pub const L_GETCONTEXT: u16 = 46;
/// Handler id ([`local_call`]).
pub const L_SETCONTEXT: u16 = 47;
/// Handler id ([`local_call`]).
pub const L_SWAPCONTEXT: u16 = 48;
/// Handler id ([`local_call`]).
pub const L_THR_NEW: u16 = 49;
/// Handler id ([`local_call`]).
pub const L_THR_EXIT: u16 = 50;
/// Handler id ([`local_call`]).
pub const L_THR_SET_NAME: u16 = 51;
/// Handler id ([`local_call`]).
pub const L_THR_SUSPEND: u16 = 52;
/// Handler id ([`local_call`]).
pub const L_THR_WAKE: u16 = 53;
/// Handler id ([`local_call`]).
pub const L_UMTX_OP: u16 = 54;
/// Handler id ([`local_call`]).
pub const L_SYSARCH: u16 = 55;
/// Handler id ([`local_call`]).
pub const L_ISSETUGID: u16 = 56;
/// Handler id ([`local_call`]).
pub const L_GETCWD: u16 = 57;
/// Handler id ([`local_call`]).
pub const L_SYSCTL: u16 = 60;
/// Handler id ([`local_call`]).
pub const L_SYSCTLBYNAME: u16 = 61;
/// Handler id ([`local_call`]).
pub const L_FSTAT: u16 = 62;
/// Handler id ([`local_call`]).
pub const L_FSTATAT: u16 = 63;
/// Handler id ([`local_call`]).
pub const L_GETDIRENTRIES: u16 = 64;
/// Handler id ([`local_call`]).
pub const L_FSTATFS: u16 = 65;
/// Handler id ([`local_call`]).
pub const L_FCNTL: u16 = 66;
/// Handler id ([`local_call`]).
pub const L_PIPE2: u16 = 67;
/// Handler id ([`local_call`]).
pub const L_GETPRIORITY: u16 = 68;
/// Handler id ([`local_call`]).
pub const L_POSIX_FALLOCATE: u16 = 69;
/// Handler id ([`local_call`]).
pub const L_POSIX_FADVISE: u16 = 70;
/// Handler id ([`local_call`]).
pub const L_SCHED_GETCPU: u16 = 71;
/// Handler id ([`local_call`]).
pub const L_KMQ_OPEN: u16 = 72;
/// Handler id ([`local_call`]).
pub const L_KMQ_UNLINK: u16 = 73;
/// Handler id ([`local_call`]).
pub const L_PPOLL: u16 = 74;
/// Handler id ([`local_call`]).
pub const L_PSELECT: u16 = 75;
/// Handler id ([`local_call`]).
pub const L_SETEUID: u16 = 76;
/// Handler id ([`local_call`]).
pub const L_SETEGID: u16 = 77;
/// Handler id ([`local_call`]).
pub const L_CPUSET_GETAFFINITY: u16 = 78;
/// Handler id ([`local_call`]).
pub const L_SCHED_SETSCHEDULER: u16 = 79;
/// Handler id ([`local_call`]).
pub const L_SCHED_GETSCHEDULER: u16 = 80;
/// Handler id ([`local_call`]).
pub const L_SCHED_GET_PRIORITY_MAX: u16 = 81;
/// Handler id ([`local_call`]).
pub const L_SCHED_GET_PRIORITY_MIN: u16 = 82;
// Fixed answers
/// Handler id ([`local_call`]).
pub const L_ZERO: u16 = 200;
/// Handler id ([`local_call`]).
pub const L_EPERM: u16 = 201;
/// Handler id ([`local_call`]).
pub const L_ENOENT: u16 = 202;
/// Handler id ([`local_call`]).
pub const L_EOPNOTSUPP: u16 = 203;
/// Handler id ([`local_call`]).
pub const L_ENOSYS_QUIET: u16 = 204;

/// Shorthand: the Linux call `nr`.
fn lx(nr: u64, a: [u64; 6]) -> i64 {
    linux_call(nr, a)
}

/// A FreeBSD "POSIX-style" result (`kern_posix_error`: the error number is the value, the
/// carry flag stays clear): `posix_fallocate`, `posix_fadvise`, `clock_nanosleep`,
/// `sigwait`. Restart codes stay internal.
fn posix(r: i64) -> i64 {
    if (-511..0).contains(&r) {
        super::abi::bsd_errno(&super::abi::FREEBSD_ERRNO, (-r) as u64) as i64
    } else {
        r
    }
}

/// Room for `len` bytes on the caller's stack, below its red zone (see the module page).
fn scratch(f: &SyscallFrame, len: usize) -> u64 {
    (f.rsp.wrapping_sub(512 + len as u64)) & !0xF
}

/// Writes `b` at `addr`, `EFAULT` on failure.
fn put(addr: u64, b: &[u8]) -> Result<(), i64> {
    copy_out(addr, b).map_err(|_| EFAULT)
}

/// Reads `n` bytes at `addr`, `EFAULT` on failure.
fn get(addr: u64, n: usize) -> Result<alloc::vec::Vec<u8>, i64> {
    copy_in(addr, n).map_err(|_| EFAULT)
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// A copy of frame `f` (the registers a Linux call runs with when it needs the caller's
/// own stack pointer and flags, or starts a thread from them).
fn frame_copy(f: &SyscallFrame) -> SyscallFrame {
    SyscallFrame {
        r9: f.r9,
        r8: f.r8,
        r10: f.r10,
        rdx: f.rdx,
        rsi: f.rsi,
        rdi: f.rdi,
        rax: f.rax,
        r15: f.r15,
        r14: f.r14,
        r13: f.r13,
        r12: f.r12,
        rbp: f.rbp,
        rbx: f.rbx,
        rip: f.rip,
        rflags: f.rflags,
        rsp: f.rsp,
    }
}

/// The Linux call `nr` with the caller's stack pointer and flags (`sigaltstack` looks at the
/// stack pointer).
fn lx_at(f: &SyscallFrame, nr: u64, a: [u64; 6]) -> i64 {
    let mut g = frame_copy(f);
    [g.rax, g.rdi, g.rsi, g.rdx, g.r10, g.r8, g.r9] = [nr, a[0], a[1], a[2], a[3], a[4], a[5]];
    crate::compat::linux::dispatch_linux_syscall(&mut g)
}

fn ok(r: Result<i64, i64>) -> Ret {
    Ret::of(match r {
        Ok(v) => v,
        Err(e) => e,
    })
}

/// A kernel-local FreeBSD call (`id`, see the constants above).
pub fn local_call(id: u16, f: &mut SyscallFrame, a: [u64; 6]) -> Ret {
    let fd = x::at_fd;
    match id {
        L_GETPID => return Ret { r: lx(39, [0; 6]), r2: Some(lx(110, [0; 6]) as u64) },
        L_KILL => ok(kill(a[0], a[1])),
        L_SIGACTION => Ret::of(super::freebsd::sigaction(a[0], a[1], a[2])),
        L_SIGRETURN => Ret::of(super::freebsd::sigreturn(f, a[0])),
        L_THR_SELF => {
            let (tid, _) = crate::compat::linux::proc::current_ids();
            ok(put(a[0], &tid.to_le_bytes()).map(|_| 0))
        }
        // --- paths and the AT_* flags ---
        L_OPEN => Ret::of(lx(2, [a[0], x::open_flags(a[1]), a[2], 0, 0, 0])),
        L_OPENAT => Ret::of(lx(257, [fd(a[0]), a[1], x::open_flags(a[2]), a[3], 0, 0])),
        L_FACCESSAT => Ret::of(faccessat(fd(a[0]), a[1], a[2], x::at_flags(a[3]))),
        L_EACCESS => Ret::of(faccessat(fd(x::at::FDCWD as u64), a[0], a[1], 0x200)),
        L_FCHMODAT => Ret::of(if a[3] & x::at::SYMLINK_NOFOLLOW != 0 { EOPNOTSUPP } else { lx(268, [fd(a[0]), a[1], a[2], 0, 0, 0]) }),
        L_FCHOWNAT => Ret::of(lx(260, [fd(a[0]), a[1], a[2], a[3], x::at_flags(a[4]), 0])),
        L_LINKAT => Ret::of(lx(265, [fd(a[0]), a[1], fd(a[2]), a[3], x::at_flags(a[4]), 0])),
        L_UNLINKAT => Ret::of(lx(263, [fd(a[0]), a[1], x::at_flags(a[2]), 0, 0, 0])),
        L_FUNLINKAT => Ret::of(lx(263, [fd(a[0]), a[1], x::at_flags(a[3]), 0, 0, 0])),
        L_RENAMEAT2 => Ret::of(lx(316, [fd(a[0]), a[1], fd(a[2]), a[3], a[4] & 1, 0])),
        L_MKNODAT => Ret::of(lx(259, [fd(a[0]), a[1], a[2], x::dev_from_fbsd(a[3]) & 0xffff_ffff, 0, 0])),
        L_MKFIFO => Ret::of(lx(259, [fd(x::at::FDCWD as u64), a[0], (a[1] & 0o7777) | 0o010000, 0, 0, 0])),
        L_MKFIFOAT => Ret::of(lx(259, [fd(a[0]), a[1], (a[2] & 0o7777) | 0o010000, 0, 0, 0])),
        L_UTIMENSAT => ok(utimens(f, fd(a[0]), a[1], a[2], x::at_flags(a[3]))),
        L_FUTIMENS => ok(utimens(f, fd(a[0]), 0, a[1], 0)),
        // --- memory ---
        L_MMAP => ok(mmap(a)),
        L_MPROTECT => Ret::of(lx(10, [a[0], a[1], a[2] & 7, 0, 0, 0])),
        L_MADVISE => Ret::of(match x::madvise(a[2]) {
            None => 0,
            Some(Ok(l)) => lx(28, [a[0], a[1], l, 0, 0, 0]),
            Some(Err(())) => EINVAL,
        }),
        L_MINHERIT => Ret::of(match x::minherit(a[2]) {
            // (INHERIT_ZERO: arc4random's state; a kernel without MADV_WIPEONFORK keeps it
            // across fork instead of failing the C library's start)
            Ok(l) => match lx(28, [a[0], a[1], l, 0, 0, 0]) {
                EINVAL => 0,
                r => r,
            },
            Err(()) => EINVAL,
        }),
        L_MSYNC => Ret::of(lx(26, [a[0], a[1], x::msync_flags(a[2]), 0, 0, 0])),
        L_BREAK => Ret::of({
            let r = lx(12, [a[0], 0, 0, 0, 0, 0]);
            if r as u64 == a[0] {
                0
            } else {
                ENOMEM
            }
        }),
        // --- clocks ---
        L_CLOCK_GETTIME => ok(clock_gettime(a[0], a[1])),
        L_CLOCK_SETTIME => Ret::of(match x::clock_id(a[0]) {
            Some((l, _)) => lx(227, [l, a[1], 0, 0, 0, 0]),
            None => EINVAL,
        }),
        L_CLOCK_GETRES => Ret::of(match x::clock_id(a[0]) {
            Some((_, true)) if a[1] != 0 => match put(a[1], &[1u64.to_le_bytes(), 0u64.to_le_bytes()].concat()) {
                Ok(()) => 0,
                Err(e) => e,
            },
            Some((l, _)) => lx(229, [l, a[1], 0, 0, 0, 0]),
            None => EINVAL,
        }),
        L_CLOCK_NANOSLEEP => Ret::of(match x::clock_id(a[0]) {
            Some((l, _)) => posix(lx(230, [l, a[1] & 1, a[2], a[3], 0, 0])),
            None => posix(EINVAL),
        }),
        L_TIMERFD_CREATE => Ret::of(match x::clock_id(a[0]) {
            Some((l, _)) => lx(283, [l, tfd_flags(a[1]), 0, 0, 0, 0]),
            None => EINVAL,
        }),
        // --- limits, waits, scheduling ---
        L_GETRLIMIT => ok(getrlimit(f, a[0], a[1])),
        L_SETRLIMIT => ok(setrlimit(f, a[0], a[1])),
        L_GETDTABLESIZE => ok({
            let s = scratch(f, 16);
            match lx(97, [7, s, 0, 0, 0, 0]) {
                0 => get(s, 8).map(|b| u64_at(&b, 0).min(i32::MAX as u64) as i64),
                e => Err(e),
            }
        }),
        L_WAIT4 => ok(wait4(a)),
        L_GETPRIORITY => Ret::of(match lx(140, [a[0], a[1], 0, 0, 0, 0]) {
            r if r >= 0 => 20 - r,
            e => e,
        }),
        L_POSIX_FALLOCATE => Ret::of(posix(lx(285, [a[0], 0, a[1], a[2], 0, 0]))),
        L_POSIX_FADVISE => Ret::of(posix(lx(221, [a[0], a[1], a[2], a[3], 0, 0]))),
        L_SCHED_GETCPU => ok({
            let s = scratch(f, 8);
            match lx(309, [s, 0, 0, 0, 0, 0]) {
                0 => get(s, 4).map(|b| u32::from_le_bytes(b[0..4].try_into().unwrap()) as i64),
                e => Err(e),
            }
        }),
        L_SCHED_SETSCHEDULER => Ret::of(match x::sched_policy(a[1]) {
            Some(p) => lx(144, [a[0], p, a[2], 0, 0, 0]),
            None => EINVAL,
        }),
        L_SCHED_GETSCHEDULER => Ret::of(match lx(145, [a[0], 0, 0, 0, 0, 0]) {
            r if r >= 0 => x::sched_policy_to_fbsd(r),
            e => e,
        }),
        L_SCHED_GET_PRIORITY_MAX | L_SCHED_GET_PRIORITY_MIN => Ret::of(match x::sched_policy(a[0]) {
            Some(p) => lx(if id == L_SCHED_GET_PRIORITY_MAX { 146 } else { 147 }, [p, 0, 0, 0, 0, 0]),
            None => EINVAL,
        }),
        L_CPUSET_GETAFFINITY => ok(cpuset_getaffinity(a)),
        L_SETEUID => Ret::of(lx(117, [u64::MAX, a[0], u64::MAX, 0, 0, 0])),
        L_SETEGID => Ret::of(lx(119, [u64::MAX, a[0], u64::MAX, 0, 0, 0])),
        L_ISSETUGID => Ret::of({
            let (u, eu, g, eg) = (lx(102, [0; 6]), lx(107, [0; 6]), lx(104, [0; 6]), lx(108, [0; 6]));
            (u != eu || g != eg) as i64
        }),
        L_GETCWD => Ret::of(match lx(79, [a[0], a[1], 0, 0, 0, 0]) {
            r if r > 0 => 0,
            e => e,
        }),
        // --- descriptors ---
        L_FCNTL => ok(fcntl(a[0], a[1], a[2])),
        L_PIPE2 => Ret::of(lx(293, [a[0], pipe_flags(a[1]), 0, 0, 0, 0])),
        L_KMQ_OPEN => ok(mq_name(a[0]).map(|p| lx(240, [p, x::open_flags(a[1]) & !x::lo::LARGEFILE, a[2], a[3], 0, 0]))),
        L_KMQ_UNLINK => ok(mq_name(a[0]).map(|p| lx(241, [p, 0, 0, 0, 0, 0]))),
        L_PPOLL => ok(ppoll(f, a)),
        L_PSELECT => ok(pselect(f, a)),
        // --- signals ---
        L_SIGPROCMASK => ok(sigprocmask(f, a[0], a[1], a[2])),
        L_SIGSUSPEND => ok(with_mask(f, a[0]).map(|s| lx(130, [s, 8, 0, 0, 0, 0]))),
        L_SIGPENDING => ok({
            let s = scratch(f, 8);
            match lx(127, [s, 8, 0, 0, 0, 0]) {
                0 => get(s, 8).and_then(|b| put(a[0], &x::mask_to_freebsd(u64_at(&b, 0))).map(|_| 0)),
                e => Err(e),
            }
        }),
        L_SIGTIMEDWAIT => ok(sigtimedwait(f, a[0], a[1], a[2])),
        L_SIGWAITINFO => ok(sigtimedwait(f, a[0], a[1], 0)),
        L_SIGWAIT => Ret::of(match sigtimedwait(f, a[0], 0, 0) {
            Ok(sig) => match put(a[1], &(sig as i32).to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => posix(e),
            },
            Err(e) => posix(e),
        }),
        L_SIGALTSTACK => ok(sigaltstack(f, a[0], a[1])),
        L_SIGQUEUE => ok(sigqueue(f, a[0], a[1], a[2])),
        L_THR_KILL => {
            let (_, pid) = crate::compat::linux::proc::current_ids();
            ok(thr_kill(pid, a[0], a[1]))
        }
        L_THR_KILL2 => ok(thr_kill(a[0], a[1], a[2])),
        // --- contexts and threads ---
        L_GETCONTEXT => ok(super::fbsd_thr::getcontext(f, a[0])),
        L_SETCONTEXT => Ret::of(super::fbsd_thr::setcontext(a[0])),
        L_SWAPCONTEXT => Ret::of(match super::fbsd_thr::getcontext(f, a[0]) {
            Ok(_) => super::fbsd_thr::setcontext(a[1]),
            Err(e) => e,
        }),
        L_THR_NEW => ok(super::fbsd_thr::thr_new(f, a[0], a[1])),
        L_THR_EXIT => Ret::of(super::fbsd_thr::thr_exit(a[0])),
        L_THR_SET_NAME => Ret::of(super::fbsd_thr::thr_set_name(a[0], a[1])),
        L_THR_SUSPEND => Ret::of(super::umtx::thr_suspend(a[0])),
        L_THR_WAKE => Ret::of(super::umtx::thr_wake(a[0])),
        L_UMTX_OP => Ret::of(super::umtx::op(a[0], a[1], a[2], a[3], a[4])),
        L_SYSARCH => ok(sysarch(a[0], a[1])),
        // --- temporary (stage 2 moves them into the services) ---
        L_SYSCTL => ok(super::fbsd_sysctl::sysctl(f, a)),
        L_SYSCTLBYNAME => ok(super::fbsd_sysctl::sysctlbyname(f, a)),
        L_FSTAT => ok(fstat(a[1], lx(5, [a[0], a[1], 0, 0, 0, 0]))),
        L_FSTATAT => ok(fstat(a[2], lx(262, [fd(a[0]), a[1], a[2], x::at_flags(a[3]), 0, 0]))),
        L_FSTATFS => ok(fstatfs(a[0], a[1])),
        L_GETDIRENTRIES => ok(getdirentries(a[0], a[1], a[2], a[3])),
        // --- fixed answers ---
        L_ZERO => Ret::of(0),
        L_EPERM => Ret::of(EPERM),
        L_ENOENT => Ret::of(ENOENT),
        L_EOPNOTSUPP => Ret::of(EOPNOTSUPP),
        L_ENOSYS_QUIET => Ret::of(ENOSYS),
        _ => Ret::of(ENOSYS),
    }
}

// ----------------------------------------------------------------------
// Paths
// ----------------------------------------------------------------------

/// `faccessat` with Linux flags: `faccessat2` when flags are given (`faccessat` has none).
fn faccessat(dfd: u64, path: u64, mode: u64, flags: u64) -> i64 {
    if flags == 0 {
        return lx(269, [dfd, path, mode, 0, 0, 0]);
    }
    match lx(439, [dfd, path, mode, flags, 0, 0]) {
        ENOSYS if flags == 0x200 => lx(269, [dfd, path, mode, 0, 0, 0]),
        r => r,
    }
}

/// `utimensat`/`futimens`: FreeBSD's `UTIME_NOW` (-1) and `UTIME_OMIT` (-2) are Linux's
/// `(1 << 30) - 1` and `(1 << 30) - 2`.
fn utimens(f: &SyscallFrame, dfd: u64, path: u64, times: u64, flags: u64) -> Result<i64, i64> {
    let t = if times != 0 {
        let mut b = get(times, 32)?;
        for i in [8usize, 24] {
            let ns = u64_at(&b, i) as i64;
            let l: i64 = match ns {
                -1 => (1 << 30) - 1,
                -2 => (1 << 30) - 2,
                v => v,
            };
            b[i..i + 8].copy_from_slice(&l.to_le_bytes());
        }
        let s = scratch(f, 32);
        put(s, &b)?;
        s
    } else {
        0
    };
    Ok(lx(280, [dfd, path, t, flags, 0, 0]))
}

// ----------------------------------------------------------------------
// Memory
// ----------------------------------------------------------------------

/// FreeBSD `mmap`: the flags translated ([`x::mmap_plan`]); `MAP_ALIGNED(n)` by mapping a
/// larger reservation and placing the mapping at its aligned start.
fn mmap(a: [u64; 6]) -> Result<i64, i64> {
    let [addr, len, prot, flags, fd, off] = a;
    let plan = x::mmap_plan(prot, flags, fd).map_err(|_| EINVAL)?;
    let fdl = if flags & (x::map::ANON | x::map::GUARD | x::map::STACK) != 0 { u64::MAX } else { fd as i32 as i64 as u64 };
    if plan.align == 0 || len == 0 {
        return Ok(lx(9, [addr, len, plan.prot, plan.flags, fdl, off]));
    }
    let extra = 1u64 << plan.align;
    let total = len.checked_add(extra).ok_or(ENOMEM)?;
    let base = lx(9, [addr, total, 0, x::lmap::PRIVATE | x::lmap::ANON | x::lmap::NORESERVE, u64::MAX, 0]);
    if base < 0 {
        return Ok(base);
    }
    let base = base as u64;
    let start = x::aligned_start(base, plan.align);
    let r = lx(9, [start, len, plan.prot, plan.flags | x::lmap::FIXED, fdl, off]);
    if r < 0 {
        lx(11, [base, total, 0, 0, 0, 0]);
        return Ok(r);
    }
    let end = (start + len + 0xFFF) & !0xFFF;
    if start > base {
        lx(11, [base, start - base, 0, 0, 0, 0]);
    }
    if base + total > end {
        lx(11, [end, base + total - end, 0, 0, 0, 0]);
    }
    Ok(start as i64)
}

// ----------------------------------------------------------------------
// Clocks, limits, waits, scheduling
// ----------------------------------------------------------------------

fn clock_gettime(id: u64, ts: u64) -> Result<i64, i64> {
    let (l, whole) = x::clock_id(id).ok_or(EINVAL)?;
    let r = lx(228, [l, ts, 0, 0, 0, 0]);
    if r == 0 && whole {
        put(ts + 8, &0u64.to_le_bytes())?;
    }
    Ok(r)
}

/// `TFD_CLOEXEC` and `TFD_NONBLOCK` are FreeBSD's `O_CLOEXEC` and `O_NONBLOCK`.
fn tfd_flags(f: u64) -> u64 {
    (if f & x::o::CLOEXEC != 0 { x::lo::CLOEXEC } else { 0 }) | (if f & x::o::NONBLOCK != 0 { x::lo::NONBLOCK } else { 0 })
}

/// `pipe2`'s flags: `O_CLOEXEC`, `O_NONBLOCK`.
fn pipe_flags(f: u64) -> u64 {
    tfd_flags(f)
}

fn getrlimit(f: &SyscallFrame, res: u64, rlp: u64) -> Result<i64, i64> {
    let mut b = [0u8; 16];
    match x::rlimit_resource(res) {
        None if res <= 15 => {
            b[0..8].copy_from_slice(&x::FBSD_RLIM_INFINITY.to_le_bytes());
            b[8..16].copy_from_slice(&x::FBSD_RLIM_INFINITY.to_le_bytes());
        }
        None => return Err(EINVAL),
        Some(l) => {
            let s = scratch(f, 16);
            let r = lx(97, [l, s, 0, 0, 0, 0]);
            if r != 0 {
                return Ok(r);
            }
            let lb = get(s, 16)?;
            b[0..8].copy_from_slice(&x::rlim_to_fbsd(u64_at(&lb, 0)).to_le_bytes());
            b[8..16].copy_from_slice(&x::rlim_to_fbsd(u64_at(&lb, 8)).to_le_bytes());
        }
    }
    put(rlp, &b)?;
    Ok(0)
}

fn setrlimit(f: &SyscallFrame, res: u64, rlp: u64) -> Result<i64, i64> {
    let b = get(rlp, 16)?;
    match x::rlimit_resource(res) {
        None if res <= 15 => Ok(0),
        None => Err(EINVAL),
        Some(l) => {
            let mut lb = [0u8; 16];
            lb[0..8].copy_from_slice(&x::rlim_from_fbsd(u64_at(&b, 0)).to_le_bytes());
            lb[8..16].copy_from_slice(&x::rlim_from_fbsd(u64_at(&b, 8)).to_le_bytes());
            let s = scratch(f, 16);
            put(s, &lb)?;
            Ok(lx(160, [l, s, 0, 0, 0, 0]))
        }
    }
}

/// `wait4(pid, status, options, rusage)`: the options in, the status (signal numbers) out.
fn wait4(a: [u64; 6]) -> Result<i64, i64> {
    let r = lx(61, [a[0], a[1], x::wait_options(a[2]), a[3], 0, 0]);
    if r > 0 && a[1] != 0 {
        let b = get(a[1], 4)?;
        let st = x::wait_status(u32::from_le_bytes(b[0..4].try_into().unwrap()));
        put(a[1], &st.to_le_bytes())?;
    }
    Ok(r)
}

/// `cpuset_getaffinity(level, which, id, setsize, mask)` for a process or thread (`id`
/// -1: the caller): Linux's affinity, the rest of FreeBSD's larger set zeroed.
fn cpuset_getaffinity(a: [u64; 6]) -> Result<i64, i64> {
    let [level, which, id, size, mask, _] = a;
    // CPU_LEVEL_ROOT 1, CPU_LEVEL_CPUSET 2, CPU_LEVEL_WHICH 3; CPU_WHICH_TID 1, PID 2
    if !(1..=3).contains(&level) || (level == 3 && !(1..=2).contains(&which)) {
        return Err(EINVAL);
    }
    if size == 0 || size > 4096 {
        return Err(-34); // ERANGE
    }
    let pid = if id as i64 == -1 || level != 3 { 0 } else { id };
    let r = lx(204, [pid, size & !7, mask, 0, 0, 0]);
    if r < 0 {
        return Ok(if r == EINVAL { -34 } else { r });
    }
    if (r as u64) < size {
        put(mask + r as u64, &alloc::vec![0u8; (size - r as u64) as usize])?;
    }
    Ok(0)
}

// ----------------------------------------------------------------------
// Descriptors
// ----------------------------------------------------------------------

/// `fcntl`'s descriptor commands (the lock commands are stage 2's: `ENOSYS`, logged).
fn fcntl(fd: u64, cmd: u64, arg: u64) -> Result<i64, i64> {
    match x::fcntl_cmd(cmd) {
        x::Fcntl::Linux { cmd: lc, setfl, getfl } => {
            let la = if setfl { x::open_flags(arg) & !x::lo::LARGEFILE } else { arg };
            let r = lx(72, [fd, lc, la, 0, 0, 0]);
            Ok(if getfl && r >= 0 { x::open_flags_to_fbsd(r as u64) as i64 } else { r })
        }
        x::Fcntl::Dup2 { cloexec } => {
            if fd == arg {
                Ok(lx(33, [fd, arg, 0, 0, 0, 0]))
            } else {
                Ok(lx(292, [fd, arg, if cloexec { x::lo::CLOEXEC } else { 0 }, 0, 0, 0]))
            }
        }
        x::Fcntl::Zero => Ok(0),
        x::Fcntl::Unsupported => {
            super::note_missing(92, Some(cmd));
            Err(ENOSYS)
        }
    }
}

/// A message queue name: FreeBSD passes "/name", Linux's `mq_open` takes "name".
fn mq_name(p: u64) -> Result<u64, i64> {
    let b = get(p, 1)?;
    Ok(if b[0] == b'/' { p + 1 } else { p })
}

/// Writes the internal form of the FreeBSD signal set at `set` to the caller's stack;
/// answers its address.
fn with_mask(f: &SyscallFrame, set: u64) -> Result<u64, i64> {
    let b = get(set, 16)?;
    let s = scratch(f, 8);
    put(s, &x::mask_from_freebsd(&b).to_le_bytes())?;
    Ok(s)
}

fn ppoll(f: &SyscallFrame, a: [u64; 6]) -> Result<i64, i64> {
    let s = if a[3] != 0 { with_mask(f, a[3])? } else { 0 };
    Ok(lx(271, [a[0], a[1], a[2], s, 8, 0]))
}

/// `pselect(nd, in, ou, ex, ts, sigmask)`: Linux's `pselect6` takes the mask as
/// `{ mask pointer, size }` and changes its timeout (FreeBSD's is const: a copy goes).
fn pselect(f: &SyscallFrame, a: [u64; 6]) -> Result<i64, i64> {
    let s = scratch(f, 48);
    let mut b = [0u8; 48];
    if a[5] != 0 {
        b[0..8].copy_from_slice(&x::mask_from_freebsd(&get(a[5], 16)?).to_le_bytes());
        b[8..16].copy_from_slice(&s.to_le_bytes());
        b[16..24].copy_from_slice(&8u64.to_le_bytes());
    }
    if a[4] != 0 {
        b[32..48].copy_from_slice(&get(a[4], 16)?);
    }
    put(s, &b)?;
    Ok(lx(270, [a[0], a[1], a[2], a[3], if a[4] != 0 { s + 32 } else { 0 }, if a[5] != 0 { s + 8 } else { 0 }]))
}

// ----------------------------------------------------------------------
// Signals
// ----------------------------------------------------------------------

fn sig_in(sig: u64) -> Result<u64, i64> {
    if sig == 0 {
        return Ok(0);
    }
    super::abi::freebsd_sig_to_internal(sig).map(|s| s as u64).ok_or(EINVAL)
}

fn kill(pid: u64, sig: u64) -> Result<i64, i64> {
    Ok(lx(62, [pid, sig_in(sig)?, 0, 0, 0, 0]))
}

fn thr_kill(pid: u64, tid: u64, sig: u64) -> Result<i64, i64> {
    Ok(lx(234, [pid, tid, sig_in(sig)?, 0, 0, 0]))
}

fn sigprocmask(f: &SyscallFrame, how: u64, set: u64, oset: u64) -> Result<i64, i64> {
    let s = scratch(f, 16);
    let lhow = if set != 0 {
        let h = x::sigprocmask_how(how).ok_or(EINVAL)?;
        put(s, &x::mask_from_freebsd(&get(set, 16)?).to_le_bytes())?;
        h
    } else {
        0
    };
    let r = lx(14, [lhow, if set != 0 { s } else { 0 }, if oset != 0 { s + 8 } else { 0 }, 8, 0, 0]);
    if r == 0 && oset != 0 {
        let b = get(s + 8, 8)?;
        put(oset, &x::mask_to_freebsd(u64_at(&b, 0)))?;
    }
    Ok(r)
}

/// `sigtimedwait(set, info, timeout)`: the FreeBSD signal number taken, its `siginfo_t`.
fn sigtimedwait(f: &SyscallFrame, set: u64, info: u64, ts: u64) -> Result<i64, i64> {
    let s = with_mask(f, set)?;
    let si = scratch(f, 8 + 128 + 16) & !0xF;
    let r = lx(128, [s, if info != 0 { si } else { 0 }, ts, 8, 0, 0]);
    if r <= 0 {
        return if r < 0 { Err(r) } else { Ok(0) };
    }
    if info != 0 {
        let l = get(si, 128)?;
        put(info, &x::siginfo_to_fbsd(&l))?;
    }
    Ok(super::abi::internal_sig_to_freebsd(r as u32) as i64)
}

fn sigaltstack(f: &SyscallFrame, ss: u64, oss: u64) -> Result<i64, i64> {
    let s = scratch(f, 48);
    if ss != 0 {
        let b: [u8; 24] = get(ss, 24)?.try_into().unwrap();
        put(s, &x::stack_to_linux(&b))?;
    }
    let r = lx_at(f, 131, [if ss != 0 { s } else { 0 }, if oss != 0 { s + 24 } else { 0 }, 0, 0, 0, 0]);
    if r == 0 && oss != 0 {
        let l: [u8; 24] = get(s + 24, 24)?.try_into().unwrap();
        put(oss, &x::stack_to_fbsd(&l))?;
    }
    Ok(r)
}

/// `sigqueue(pid, signo, value)`: a Linux `siginfo_t` with `SI_QUEUE` and the value.
fn sigqueue(f: &SyscallFrame, pid: u64, sig: u64, value: u64) -> Result<i64, i64> {
    let s = sig_in(sig)?;
    if s == 0 {
        return Ok(lx(62, [pid, 0, 0, 0, 0, 0]));
    }
    let (_, me) = crate::compat::linux::proc::current_ids();
    let mut b = [0u8; 128];
    b[0..4].copy_from_slice(&(s as i32).to_le_bytes());
    b[8..12].copy_from_slice(&(-1i32).to_le_bytes()); // SI_QUEUE
    b[16..20].copy_from_slice(&(me as i32).to_le_bytes());
    b[20..24].copy_from_slice(&(lx(102, [0; 6]) as u32).to_le_bytes());
    b[24..32].copy_from_slice(&value.to_le_bytes());
    let p = scratch(f, 128);
    put(p, &b)?;
    Ok(lx(129, [pid, s, p, 0, 0, 0]))
}

// ----------------------------------------------------------------------
// sysarch
// ----------------------------------------------------------------------

/// `sysarch(op, parms)`: the FS and GS bases (the TLS base is the FS base here).
fn sysarch(op: u64, parms: u64) -> Result<i64, i64> {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match op {
        128 | 135 => {
            // AMD64_GET_FSBASE, AMD64_GET_TLSBASE (ESRCH before one was set)
            let v = crate::task::with_current_task_mut(|t| t.fs_base).unwrap_or(0);
            if op == 135 && v == 0 {
                return Err(ESRCH);
            }
            Ok(lx(158, [ARCH_GET_FS, parms, 0, 0, 0, 0]))
        }
        129 | 136 => {
            // AMD64_SET_FSBASE, AMD64_SET_TLSBASE: the value at parms
            let v = u64_at(&get(parms, 8)?, 0);
            Ok(lx(158, [ARCH_SET_FS, v, 0, 0, 0, 0]))
        }
        130 => Ok(lx(158, [ARCH_GET_GS, parms, 0, 0, 0, 0])),
        131 => Ok(lx(158, [ARCH_SET_GS, u64_at(&get(parms, 8)?, 0), 0, 0, 0, 0])),
        137 => Ok(0), // AMD64_DISABLE_TLSBASE
        _ => Err(EINVAL),
    }
}

// ----------------------------------------------------------------------
// Temporary: stat, statfs, dirent (stage 2: vfs-server)
// ----------------------------------------------------------------------

/// `fstat`/`fstatat`: Linux wrote its `struct stat` (144 bytes) into the caller's buffer
/// `sb` (224 bytes); it becomes FreeBSD's there.
// wave12 FK temporary: moves to vfs-server in stage 2
fn fstat(sb: u64, r: i64) -> Result<i64, i64> {
    if r != 0 {
        return Ok(r);
    }
    let l = get(sb, tmp::LINUX_STAT)?;
    put(sb, &tmp::stat_from_linux(&l))?;
    Ok(0)
}

/// `fstatfs(fd, buf)`: Linux's `struct statfs` (120 bytes) in the caller's buffer (2,344),
/// converted there.
// wave12 FK temporary: moves to vfs-server in stage 2
fn fstatfs(fd: u64, buf: u64) -> Result<i64, i64> {
    let r = lx(138, [fd, buf, 0, 0, 0, 0]);
    if r != 0 {
        return Ok(r);
    }
    let l = get(buf, tmp::LINUX_STATFS)?;
    let mut out = alloc::vec![0u8; tmp::FBSD_STATFS];
    tmp::statfs_from_linux(&l, &mut out);
    put(buf, &out)?;
    Ok(0)
}

/// `getdirentries(fd, buf, nbytes, basep)`: Linux's `getdents64` into the caller's buffer
/// (asking for 3/4 of it, so FreeBSD's longer records always fit), converted there; `*basep`
/// = the directory position before the read.
// wave12 FK temporary: moves to vfs-server in stage 2
fn getdirentries(fd: u64, buf: u64, nbytes: u64, basep: u64) -> Result<i64, i64> {
    let nbytes = nbytes.min(1 << 20) as usize;
    let ask = tmp::linux_dirent_budget(nbytes);
    if ask < 32 {
        return Err(EINVAL);
    }
    let pos = lx(8, [fd, 0, 1, 0, 0, 0]).max(0) as u64; // lseek(fd, 0, SEEK_CUR)
    let r = lx(217, [fd, buf, ask as u64, 0, 0, 0]);
    if r < 0 {
        return Ok(r);
    }
    let l = get(buf, r as usize)?;
    let mut out = alloc::vec::Vec::with_capacity(nbytes);
    tmp::dirents_from_linux(&l, &mut out, nbytes);
    put(buf, &out)?;
    if basep != 0 {
        put(basep, &pos.to_le_bytes())?;
    }
    Ok(out.len() as i64)
}
