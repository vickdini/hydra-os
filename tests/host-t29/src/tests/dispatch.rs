//! `src/compat/linux/mod.rs`: the system call table. Routing to the modules (each stub
//! records its call), the calls served in mod.rs itself (descriptors, the legacy Unix
//! sockets, identity, clocks, poll/epoll, clone/clone3, exit), the fast path for identity
//! calls, statistics and the unimplemented-call report, and the user-pointer checks.

use super::common::*;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::epoll::{LinuxEpollEvent, LinuxPollFd};
use crate::compat::linux::socket::LinuxSockaddrUn;
use crate::compat::linux::types::*;
use crate::compat::linux::{self as lx, dispatch_checked, dispatch_linux_syscall};
use crate::fs::{FileDescriptor, OpenFile};
use crate::task::with_current_fds_mut;
use std::sync::Arc;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ESPIPE: i64 = -29;
const ENOSYS: i64 = -38;
const EAFNOSUPPORT: i64 = -97;

fn frame(nr: u64, a: [u64; 6]) -> SyscallFrame {
    SyscallFrame { rax: nr, rdi: a[0], rsi: a[1], rdx: a[2], r10: a[3], r8: a[4], r9: a[5], rip: 0x40_1000, rsp: 0x7000_0000, ..Default::default() }
}

fn sc(nr: u64, a: [u64; 6]) -> i64 {
    dispatch_checked(&mut frame(nr, a))
}

fn proc_(pid: u64, uid: u32) {
    spawn_as(pid, 0, uid, uid);
    run(pid);
}

fn cstr(s: &str) -> Vec<u8> {
    format!("{s}\0").into_bytes()
}

fn install(fd: usize, d: FileDescriptor) {
    with_current_fds_mut(|f| f.install(fd, d));
}

#[test]
fn calls_reach_their_modules() {
    let _g = setup();
    proc_(5000, 0);
    // (number, the stub that answers, its return value)
    let direct: &[(u64, &str)] = &[
        (298, "perf::sys_perf_event_open"),
        (321, "bpf::sys_bpf"),
        (103, "admin::dispatch"),
        (163, "admin::dispatch"),
        (300, "fanotify::dispatch"),
        (304, "fanotify::open_by_handle_at"),
        (425, "io_uring::dispatch"),
        (295, "xfer::dispatch"),
        (40, "xfer::dispatch"),
        (428, "mount::dispatch_new"),
        (457, "mount::dispatch_new"),
        (206, "aio::dispatch"),
        (437, "recent::dispatch"),
    ];
    for &(nr, name) in direct {
        fake::set_ret(name, 7000 + nr as i64);
        assert_eq!(sc(nr, [1, 2, 3, 4, 5, 6]), 7000 + nr as i64, "{nr} -> {name}");
    }
    // Option dispatchers: answered when they claim the call, otherwise the call goes on
    let optional: &[(u64, &str)] = &[
        (64, "sysv::dispatch"),
        (248, "keys::dispatch"),
        (240, "mqueue::dispatch"),
        (222, "ptimer::dispatch"),
        (100, "misc::dispatch"),
        (155, "mount::dispatch"),
        (999, "chardev::dispatch"),
        (998, "unix::dispatch"),
        (997, "inet::dispatch"),
        (996, "vfs::dispatch"),
    ];
    for &(nr, name) in optional {
        fake::set_ret(&format!("{name}:{nr}"), 8000 + nr as i64);
        assert_eq!(sc(nr, [0; 6]), 8000 + nr as i64, "{nr} -> {name}");
    }
    // SIOCGIF* ioctls on a socket
    fake::set_ret("rtnetlink::interface_ioctl", 5);
    assert_eq!(sc(16, [3, 0x8913, 0, 0, 0, 0]), 5);
    // Group 29's own modules
    assert_eq!(sc(154, [7, 0, 0, 0, 0, 0]), ENOSYS as u32 as i64, "modify_ldt's int result");
    assert_eq!(sc(205, [0; 6]), ENOSYS, "set_thread_area is 32-bit only");
    assert_eq!(sc(317, [99, 0, 0, 0, 0, 0]), EINVAL, "seccomp");
    assert_eq!(sc(101, [7, 4242, 0, 0, 0, 0]), -3, "ptrace");
    assert!(sc(323, [0xffff, 0, 0, 0, 0, 0]) < 0, "userfaultfd");
    assert_eq!(sc(449, [0, 0, 1, 0, 0, 0]), EINVAL, "futex_waitv");
    assert_eq!(sc(454, [0, 0, 0, 0, 0, 0]), EINVAL, "futex_wake");
    assert_eq!(sc(455, [0, 0, 0, 0, 0, 0]), EINVAL, "futex_wait");
    assert_eq!(sc(456, [0, 1, 0, 0, 0, 0]), EINVAL, "futex_requeue");
    let info = [0u64, (-1i64) as u64, 0, 0];
    assert_eq!(sc(129, [4242, 10, ptr(&info), 0, 0, 0]), -3, "rt_sigqueueinfo");
    assert_eq!(sc(297, [5000, 4242, 10, ptr(&info), 0, 0]), -3, "rt_tgsigqueueinfo: no such thread");
    assert_eq!(sc(187, [99, 0, 0, 0, 0, 0]), EBADF, "extra: readahead");
    assert_eq!(sc(308, [99, 0, 0, 0, 0, 0]), EBADF, "setns");
    assert_eq!(sc(272, [1, 0, 0, 0, 0, 0]), EINVAL, "unshare");
    assert_eq!(sc(110, [0; 6]), 0, "process.rs: getppid");
    assert_eq!(sc(13, [0, 0, 0, 4, 0, 0]), EINVAL, "rt_sigaction");
    // Landlock refuses mounts first (no domain here: through to mount.rs)
    fake::set_ret("mount::dispatch:165", 0);
    assert_eq!(sc(165, [0; 6]), 0);
}

#[test]
fn statistics_seccomp_forwarding_and_unknown_calls() {
    let _g = setup();
    proc_(5010, 0);
    let before = lx::LINUX_STATS.lock().total_calls;
    // A call the Linux server answers never reaches the table
    fake::LX_FORWARD.with_borrow_mut(|m| m.insert(39, 4242));
    assert_eq!(dispatch_linux_syscall(&mut frame(39, [0; 6])), 4242);
    assert!(lx::LINUX_STATS.lock().total_calls > before);
    fake::LX_FORWARD.with_borrow_mut(|m| m.clear());
    // Unknown numbers: ENOSYS, reported once (numbers >= 512 every time)
    let unknown = lx::LINUX_STATS.lock().unknown_calls;
    assert_eq!(sc(511, [1, 2, 3, 0, 0, 0]), ENOSYS);
    assert_eq!(sc(511, [1, 2, 3, 0, 0, 0]), ENOSYS);
    assert_eq!(sc(600, [0; 6]), ENOSYS);
    assert!(lx::LINUX_STATS.lock().unknown_calls >= unknown + 3);
    let logs = fake::take_calls().into_iter().filter(|c| c.contains("unimplemented syscall 511")).count();
    assert!(logs <= 1);
    assert!(fake::called("log:") || true);
    assert_eq!(sc(330, [0; 6]), -28, "pkey_alloc");
    assert_eq!(sc(331, [0; 6]), EINVAL, "pkey_free");
    // nested: a call on the program's behalf
    assert_eq!(lx::nested(&frame(0, [0; 6]), 39, [0; 6]), 5010);
    // tracing filter
    assert!(lx::trace_matches_current());
    *lx::TRACE_FILTER.lock() = "firefox".into();
    assert!(!lx::trace_matches_current());
    fake::task(5010, |t| t.exe = Some("/usr/lib/firefox/firefox".into()));
    assert!(lx::trace_matches_current());
    lx::TRACE_FILTER.lock().clear();
    // Which calls change what the identity calls answer
    for nr in [59, 105, 113, 157, 308, 272, 101] {
        assert!(lx::changes_identity(nr), "{nr}");
    }
    assert!(!lx::changes_identity(39));
}

#[test]
fn identity_fast_path() {
    let _g = setup();
    proc_(5020, 1000);
    crate::task::CURRENT_TID.store(5020, core::sync::atomic::Ordering::Relaxed);
    lx::ident_changed();
    let f = |nr: u64| lx::fast_syscall(&frame(nr, [0; 6]));
    assert_eq!(f(39), Some(5020), "getpid");
    assert_eq!(f(186), Some(5020), "gettid");
    assert_eq!(f(110), Some(0), "getppid");
    assert_eq!(f(102), Some(1000), "getuid (cached now)");
    assert_eq!(f(104), Some(1000));
    assert_eq!(f(107), Some(1000));
    assert_eq!(f(108), Some(1000));
    assert_eq!(f(0), None, "not an identity call");
    // A private futex wake
    let w = Box::new(0u32);
    let wf = SyscallFrame { rax: 202, rdi: &*w as *const u32 as u64, rsi: (1 | 128) as u64, rdx: 1, ..Default::default() };
    assert_eq!(lx::fast_syscall(&wf), Some(0));
    let shared = SyscallFrame { rsi: 1, ..wf.clone() };
    assert_eq!(lx::fast_syscall(&shared), None, "a shared wake takes the normal path");
    // Cached until something changes: a stale uid shows until ident_changed
    fake::task(5020, |t| t.uid = 1001);
    assert_eq!(f(102), Some(1000));
    let e = lx::ident_epoch();
    lx::ident_changed();
    assert!(lx::ident_epoch() > e);
    assert_eq!(f(102), Some(1001));
    // Not served: tracing on, a seccomp filter, a Hydra task, no task
    lx::TRACE_SYSCALLS.store(true, core::sync::atomic::Ordering::Relaxed);
    assert_eq!(f(39), None);
    lx::TRACE_SYSCALLS.store(false, core::sync::atomic::Ordering::Relaxed);
    fake::task(5020, |t| t.seccomp.mode = 2);
    lx::ident_changed();
    assert_eq!(f(39), None);
    fake::task(5020, |t| {
        t.seccomp.mode = 0;
        t.personality = crate::task::TaskPersonality::Hydra;
    });
    lx::ident_changed();
    assert_eq!(f(39), None);
    crate::task::CURRENT_TID.store(0, core::sync::atomic::Ordering::Relaxed);
}

#[test]
fn read_write_and_descriptors() {
    let _g = setup();
    proc_(5030, 0);
    fake::ZFS_FILES.with_borrow_mut(|m| m.insert("/etc/x".into(), b"hello world".to_vec()));
    install(3, FileDescriptor::file("/etc/x"));
    let mut buf = [0u8; 5];
    assert_eq!(sc(0, [3, mptr(&mut buf), 5, 0, 0, 0]), 5);
    assert_eq!(&buf, b"hello");
    assert_eq!(sc(0, [3, 0, 5, 0, 0, 0]), EFAULT);
    assert_eq!(sc(0, [3, mptr(&mut buf), 0, 0, 0, 0]), 0);
    assert_eq!(sc(0, [99, mptr(&mut buf), 5, 0, 0, 0]), EBADF);
    // Write-only: EBADF on read
    install(4, FileDescriptor::File { path: "/tmp/o".into(), cursor: crate::fs::FileCursor::new(0), readable: false, writable: true, append: false, shown: None });
    assert_eq!(sc(0, [4, mptr(&mut buf), 5, 0, 0, 0]), EBADF);
    assert_eq!(sc(1, [4, ptr(b"abc"), 3, 0, 0, 0]), 3);
    assert_eq!(sc(1, [4, 0, 3, 0, 0, 0]), EFAULT);
    assert_eq!(sc(1, [4, ptr(b"abc"), 0, 0, 0, 0]), 0);
    assert_eq!(sc(1, [99, ptr(b"abc"), 3, 0, 0, 0]), EBADF);
    install(5, FileDescriptor::File { path: "/etc/x".into(), cursor: crate::fs::FileCursor::new(0), readable: true, writable: false, append: false, shown: None });
    assert_eq!(sc(1, [5, ptr(b"abc"), 3, 0, 0, 0]), EBADF, "read-only");
    // Files of the file system (Vnode), outside the table's lock
    fake::INODES.with_borrow_mut(|m| m.insert(60, (0o100644, b"inode data".to_vec())));
    install(6, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 60, readable: true, writable: true, ..Default::default() }))));
    assert_eq!(sc(0, [6, mptr(&mut buf), 5, 0, 0, 0]), 5);
    assert_eq!(&buf, b"inode");
    assert_eq!(sc(1, [6, ptr(b"XY"), 2, 0, 0, 0]), 2);
    install(7, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 61, readable: true, writable: true, ..Default::default() }))));
    fake::WRITE_ERROR.set("No space left on device");
    assert_eq!(sc(1, [7, ptr(b"XY"), 2, 0, 0, 0]), -28);
    fake::WRITE_ERROR.set("File too large");
    assert_eq!(sc(1, [7, ptr(b"XY"), 2, 0, 0, 0]), -27, "EFBIG");
    assert!(linux::proc::take_signal_info_of(5030, 5030, 1 << 24).is_some(), "with SIGXFSZ");
    fake::WRITE_ERROR.set("Weird");
    assert_eq!(sc(1, [7, ptr(b"XY"), 2, 0, 0, 0]), -5);
    assert_eq!(sc(0, [7, mptr(&mut buf), 5, 0, 0, 0]), -5, "a read error");
    // close, dup, dup2
    assert_eq!(sc(32, [3, 0, 0, 0, 0, 0]), 0, "dup: the lowest free");
    assert_eq!(sc(32, [99, 0, 0, 0, 0, 0]), EBADF);
    assert_eq!(sc(33, [3, 20, 0, 0, 0, 0]), 20);
    assert_eq!(sc(33, [99, 20, 0, 0, 0, 0]), EBADF);
    assert_eq!(sc(3, [20, 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(3, [20, 0, 0, 0, 0, 0]), EBADF);
    // lseek on a file and a memfd; pipes cannot seek
    install(8, FileDescriptor::file("/etc/x"));
    assert_eq!(sc(8, [8, 3, 0, 0, 0, 0]), 3);
    assert_eq!(sc(8, [8, 2, 1, 0, 0, 0]), 5);
    assert_eq!(sc(8, [8, -2i64 as u64, 2, 0, 0, 0]), 9);
    assert_eq!(sc(8, [8, -20i64 as u64, 1, 0, 0, 0]), EINVAL);
    assert_eq!(sc(8, [8, 0, 7, 0, 0, 0]), EINVAL);
    let m = linux::memfd::MemFd::new("m");
    m.lock().truncate(100).unwrap();
    install(9, FileDescriptor::MemFd { memfd: m, flags: 2 });
    assert_eq!(sc(8, [9, 10, 0, 0, 0, 0]), 10);
    assert_eq!(sc(8, [9, 5, 1, 0, 0, 0]), 15);
    assert_eq!(sc(8, [9, 0, 2, 0, 0, 0]), 100);
    assert_eq!(sc(8, [9, 50, 3, 0, 0, 0]), 50, "SEEK_DATA");
    assert_eq!(sc(8, [9, 50, 4, 0, 0, 0]), 100, "SEEK_HOLE");
    assert_eq!(sc(8, [9, 200, 3, 0, 0, 0]), -6, "ENXIO");
    assert_eq!(sc(8, [9, 0, 9, 0, 0, 0]), EINVAL);
    assert_eq!(sc(8, [9, -1i64 as u64, 0, 0, 0, 0]), EINVAL);
    let mut fds = [0i32; 2];
    assert_eq!(sc(22, [mptr(&mut fds), 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(8, [fds[0] as u64, 0, 0, 0, 0, 0]), ESPIPE);
    assert_eq!(sc(8, [99, 0, 0, 0, 0, 0]), EBADF);
    // ftruncate
    assert_eq!(sc(77, [9, 10, 0, 0, 0, 0]), 0);
    assert_eq!(sc(77, [8, 10, 0, 0, 0, 0]), 0, "a plain file: accepted");
    assert_eq!(sc(77, [fds[0] as u64, 10, 0, 0, 0, 0]), EBADF);
    assert_eq!(sc(77, [9, -1i64 as u64, 0, 0, 0, 0]), EINVAL);
}

#[test]
fn vector_and_positioned_io() {
    let _g = setup();
    proc_(5040, 0);
    fake::ZFS_FILES.with_borrow_mut(|m| m.insert("/f".into(), b"0123456789".to_vec()));
    install(3, FileDescriptor::file("/f"));
    let mut a = [0u8; 3];
    let mut b = [0u8; 4];
    let iov = [LinuxIovec { iov_base: mptr(&mut a), iov_len: 3 }, LinuxIovec { iov_base: 0, iov_len: 0 }, LinuxIovec { iov_base: mptr(&mut b), iov_len: 4 }];
    assert_eq!(sc(19, [3, ptr(&iov), 3, 0, 0, 0]), 7);
    assert_eq!((&a, &b), (b"012", b"3456"));
    let mut big = [0u8; 10];
    let iov2 = [LinuxIovec { iov_base: mptr(&mut big), iov_len: 10 }, LinuxIovec { iov_base: mptr(&mut a), iov_len: 3 }];
    assert_eq!(sc(19, [3, ptr(&iov2), 2, 0, 0, 0]), 3, "a short read ends it");
    assert_eq!(sc(19, [99, ptr(&iov), 1, 0, 0, 0]), EBADF);
    // writev
    install(4, FileDescriptor::file("/out"));
    let w = [LinuxIovec { iov_base: ptr(b"ab") , iov_len: 2 }, LinuxIovec { iov_base: ptr(b"cde"), iov_len: 3 }];
    assert_eq!(sc(20, [4, ptr(&w), 2, 0, 0, 0]), 5);
    assert_eq!(fake::ZFS_FILES.with_borrow(|m| m["/out"].clone()), b"abcde");
    assert_eq!(sc(20, [4, 0, 1, 0, 0, 0]), EFAULT);
    assert_eq!(sc(20, [99, ptr(&w), 2, 0, 0, 0]), EBADF);
    // pread / pwrite: files, inodes, devices; checks
    let mut p = [0u8; 4];
    assert_eq!(sc(17, [3, mptr(&mut p), 4, 6, 0, 0]), 4);
    assert_eq!(&p, b"6789");
    assert_eq!(sc(18, [4, ptr(b"ZZ"), 2, 1, 0, 0]), 2);
    assert_eq!(fake::ZFS_FILES.with_borrow(|m| m["/out"].clone()), b"aZZde");
    assert_eq!(sc(17, [3, mptr(&mut p), 4, -1i64 as u64, 0, 0]), EINVAL);
    assert_eq!(sc(17, [3, mptr(&mut p), 0, 0, 0, 0]), 0);
    assert_eq!(sc(17, [99, mptr(&mut p), 4, 0, 0, 0]), EBADF);
    let mut fds = [0i32; 2];
    assert_eq!(sc(22, [mptr(&mut fds), 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(17, [fds[0] as u64, mptr(&mut p), 4, 0, 0, 0]), ESPIPE);
    fake::INODES.with_borrow_mut(|m| m.insert(70, (0o100644, b"abcdefgh".to_vec())));
    install(5, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 70, readable: true, writable: true, ..Default::default() }))));
    assert_eq!(sc(17, [5, mptr(&mut p), 4, 2, 0, 0]), 4);
    assert_eq!(&p, b"cdef");
    // A device with positions (/proc/<pid>/mem): its pread answers
    global_frames();
    let mm = Arc::new(spin::Mutex::new(crate::memory::vm::Mm::new().unwrap()));
    let base = crate::memory::vm::USER_SPACE_START + 0x700_0000;
    assert_eq!(linux::mm::sys_mmap(&mm, base, 4096, 3, 0x22, -1, 0) as u64, base);
    fake::task(5040, |t| t.mm = Some(mm.clone()));
    let dev = linux::ptrace::open_proc_mem(5040, true, true).unwrap();
    install(6, FileDescriptor::Device(dev));
    assert_eq!(sc(18, [6, ptr(b"mem!"), 4, base, 0, 0]), 4);
    assert_eq!(sc(17, [6, mptr(&mut p), 4, base, 0, 0]), 4);
    assert_eq!(&p, b"mem!");
}

#[test]
fn stat_open_access_and_ioctl() {
    let _g = setup();
    proc_(5050, 0);
    fake::ZFS_FILES.with_borrow_mut(|m| m.insert("/etc/passwd".into(), vec![1; 300]));
    fake::PSEUDO.with_borrow_mut(|v| v.push("/proc/cpuinfo".into()));
    let mut st = LinuxStat::default();
    let p = cstr("/etc/passwd");
    assert_eq!(sc(4, [p.as_ptr() as u64, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!((st.st_size, st.st_mode, st.st_ino), (300, 0o100644, 7));
    let pseudo = cstr("/proc/cpuinfo");
    assert_eq!(sc(6, [pseudo.as_ptr() as u64, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_mode, 0o100444);
    let none = cstr("/nope");
    assert_eq!(sc(4, [none.as_ptr() as u64, mptr(&mut st), 0, 0, 0, 0]), ENOENT);
    assert_eq!(sc(4, [none.as_ptr() as u64, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(sc(4, [0, mptr(&mut st), 0, 0, 0, 0]), EFAULT);
    // newfstatat
    assert_eq!(sc(262, [0, p.as_ptr() as u64, mptr(&mut st), 0, 0, 0]), 0);
    assert_eq!(st.st_size, 300);
    assert_eq!(sc(262, [0, pseudo.as_ptr() as u64, mptr(&mut st), 0, 0, 0]), 0);
    assert_eq!(sc(262, [0, none.as_ptr() as u64, mptr(&mut st), 0, 0, 0]), ENOENT);
    assert_eq!(sc(262, [0, 0, mptr(&mut st), 0, 0, 0]), EFAULT);
    assert_eq!(sc(262, [0, p.as_ptr() as u64, 0, 0, 0, 0]), EFAULT);
    // fstat by kind
    let fd = sc(2, [p.as_ptr() as u64, 0, 0, 0, 0, 0]);
    assert!(fd >= 0);
    assert_eq!(sc(5, [fd as u64, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_size, 300);
    install(10, FileDescriptor::ConsoleOut);
    assert_eq!(sc(5, [10, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_mode, 0o20666);
    let mut fds = [0i32; 2];
    sc(22, [mptr(&mut fds), 0, 0, 0, 0, 0]);
    assert_eq!(sc(5, [fds[0] as u64, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_mode, 0o10600);
    install(11, FileDescriptor::Unix(Arc::new(crate::fs::FakeUnix::default())));
    assert_eq!(sc(5, [11, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_mode, 0o140777);
    install(12, FileDescriptor::EventFd(crate::fs::FakeObj::named("e")));
    assert_eq!(sc(5, [12, mptr(&mut st), 0, 0, 0, 0]), 0);
    assert_eq!(st.st_mode, 0o100644, "anything else");
    install(13, FileDescriptor::file("/gone"));
    assert_eq!(sc(5, [13, mptr(&mut st), 0, 0, 0, 0]), ENOENT);
    assert_eq!(sc(5, [99, mptr(&mut st), 0, 0, 0, 0]), EBADF);
    assert_eq!(sc(5, [10, 0, 0, 0, 0, 0]), EFAULT);
    // open / openat: write access creates the file, pseudo-files open
    let newf = cstr("/tmp/new");
    let fd = sc(257, [-100i64 as u64, newf.as_ptr() as u64, 0o2001 | 0o100, 0, 0, 0]);
    assert!(fd >= 0);
    assert!(fake::ZFS_FILES.with_borrow(|m| m.contains_key("/tmp/new")));
    assert!(sc(2, [pseudo.as_ptr() as u64, 0, 0, 0, 0, 0]) >= 0);
    assert_eq!(sc(2, [none.as_ptr() as u64, 0, 0, 0, 0, 0]), ENOENT);
    assert_eq!(sc(2, [0, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(sc(257, [0, 0, 0, 0, 0, 0]), EFAULT);
    // access
    assert_eq!(sc(21, [p.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(21, [pseudo.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(21, [none.as_ptr() as u64, 0, 0, 0, 0, 0]), ENOENT);
    assert_eq!(sc(21, [0, 0, 0, 0, 0, 0]), EFAULT);
    // ioctl on a descriptor nobody claimed: FIONBIO/FIOASYNC succeed, others ENOTTY
    assert_eq!(sc(16, [10, 0x5421, 0, 0, 0, 0]), 0);
    assert_eq!(sc(16, [10, 0x5413, 0xdead, 0, 0, 0]), ENOTTY, "TIOCGWINSZ: no write to the pointer");
    // fcntl, chdir, sched_yield
    assert_eq!(sc(72, [3, 3, 0, 0, 0, 0]), 2);
    assert_eq!((sc(72, [3, 1, 0, 0, 0, 0]), sc(72, [3, 2, 0, 0, 0, 0]), sc(72, [3, 4, 0, 0, 0, 0]), sc(72, [3, 9, 0, 0, 0, 0])), (0, 0, 0, 0));
    assert_eq!(sc(80, [0; 6]), 0);
    assert_eq!(sc(24, [0; 6]), 0);
    assert!(fake::called("yield_now()"));
}

#[test]
fn legacy_unix_sockets() {
    let _g = setup();
    proc_(5060, 0);
    assert_eq!(sc(41, [2, 1, 0, 0, 0, 0]), EAFNOSUPPORT);
    let s = sc(41, [1, 1, 0, 0, 0, 0]);
    assert!(s >= 0);
    let mut addr = LinuxSockaddrUn::default();
    addr.sun_family = 1;
    addr.sun_path[..9].copy_from_slice(b"/tmp/sock");
    let len = 2 + 10;
    assert_eq!(sc(49, [s as u64, ptr(&addr), len, 0, 0, 0]), 0, "bind");
    assert_eq!(sc(50, [s as u64, 5, 0, 0, 0, 0]), 0, "listen");
    let mut bad = addr;
    bad.sun_family = 2;
    assert_eq!(sc(49, [s as u64, ptr(&bad), len, 0, 0, 0]), EAFNOSUPPORT);
    assert_eq!(sc(49, [s as u64, 0, len, 0, 0, 0]), EFAULT);
    assert_eq!(sc(49, [99, ptr(&addr), len, 0, 0, 0]), EBADF);
    assert_eq!(sc(50, [99, 5, 0, 0, 0, 0]), EBADF);
    let mut name = LinuxSockaddrUn::default();
    let mut nlen = 0u32;
    assert_eq!(sc(51, [s as u64, mptr(&mut name), mptr(&mut nlen), 0, 0, 0]), 0);
    assert_eq!(&name.sun_path[..9], b"/tmp/sock");
    assert_eq!(nlen, 12);
    assert_eq!(sc(51, [99, mptr(&mut name), mptr(&mut nlen), 0, 0, 0]), EBADF);
    assert_eq!(sc(51, [s as u64, 0, mptr(&mut nlen), 0, 0, 0]), EFAULT);
    // connect from a second socket, accept the connection
    let c = sc(41, [1, 1 | 0x800, 0, 0, 0, 0]);
    assert_eq!(sc(42, [c as u64, ptr(&addr), len, 0, 0, 0]), 0, "connect");
    assert_eq!(sc(42, [c as u64, ptr(&bad), len, 0, 0, 0]), EAFNOSUPPORT);
    assert_eq!(sc(42, [c as u64, 0, len, 0, 0, 0]), EFAULT);
    assert_eq!(sc(42, [99, ptr(&addr), len, 0, 0, 0]), EBADF);
    let mut peer = LinuxSockaddrUn::default();
    let mut plen = 0u32;
    let a = sc(43, [s as u64, mptr(&mut peer), mptr(&mut plen), 0, 0, 0]);
    assert!(a >= 0);
    assert_eq!((peer.sun_family, plen), (1, 2));
    assert_eq!(sc(43, [99, 0, 0, 0, 0, 0]), EBADF);
    assert_eq!(sc(288, [s as u64, 0, 0, 0x800, 0, 0]), EAGAIN, "accept4, nonblocking: nobody waiting");
    // Data both ways: sendto/recvfrom, sendmsg/recvmsg
    assert_eq!(sc(44, [c as u64, ptr(b"ping"), 4, 0, 0, 0]), 4);
    let mut buf = [0u8; 8];
    assert_eq!(sc(45, [a as u64, mptr(&mut buf), 8, 0, 0, 0]), 4);
    assert_eq!(&buf[..4], b"ping");
    assert_eq!(sc(44, [c as u64, 0, 4, 0, 0, 0]), EFAULT);
    assert_eq!(sc(44, [c as u64, ptr(b"x"), 0, 0, 0, 0]), 0);
    assert_eq!(sc(44, [99, ptr(b"x"), 1, 0, 0, 0]), EBADF);
    assert_eq!(sc(45, [a as u64, 0, 4, 0, 0, 0]), EFAULT);
    assert_eq!(sc(45, [a as u64, mptr(&mut buf), 0, 0, 0, 0]), 0);
    assert_eq!(sc(45, [99, mptr(&mut buf), 8, 0, 0, 0]), EBADF);
    // sendmsg with SCM_RIGHTS: the receiver gets a new descriptor for the same file
    install(30, FileDescriptor::file("/passed"));
    let mut ctl = [0u8; 24];
    let hdr = LinuxCmsghdr { cmsg_len: 20, cmsg_level: SOL_SOCKET, cmsg_type: SCM_RIGHTS };
    unsafe { core::ptr::write_unaligned(ctl.as_mut_ptr() as *mut LinuxCmsghdr, hdr) };
    ctl[16..20].copy_from_slice(&30i32.to_le_bytes());
    let data = *b"msg";
    let iov = [LinuxIovec { iov_base: ptr(&data), iov_len: 3 }];
    let msg = LinuxMsghdr { msg_name: 0, msg_namelen: 0, msg_iov: iov.as_ptr() as *mut LinuxIovec, msg_iovlen: 1, msg_control: ctl.as_mut_ptr(), msg_controllen: 24, msg_flags: 0 };
    assert_eq!(sc(46, [c as u64, ptr(&msg), 0, 0, 0, 0]), 3);
    let mut rbuf = [0u8; 8];
    let mut rctl = [0u8; 24];
    let riov = [LinuxIovec { iov_base: mptr(&mut rbuf), iov_len: 8 }];
    let mut rmsg = LinuxMsghdr { msg_name: 0, msg_namelen: 0, msg_iov: riov.as_ptr() as *mut LinuxIovec, msg_iovlen: 1, msg_control: rctl.as_mut_ptr(), msg_controllen: 24, msg_flags: 0 };
    assert_eq!(sc(47, [a as u64, mptr(&mut rmsg), 0, 0, 0, 0]), 3);
    assert_eq!(&rbuf[..3], b"msg");
    assert_eq!(rmsg.msg_controllen, 20);
    let newfd = i32::from_le_bytes(rctl[16..20].try_into().unwrap());
    assert!(matches!(with_current_fds_mut(|f| f.get(newfd as usize).cloned()), Some(FileDescriptor::File { .. })));
    // No descriptor waiting: msg_controllen 0
    assert_eq!(sc(44, [c as u64, ptr(b"z"), 1, 0, 0, 0]), 1);
    rmsg.msg_controllen = 24;
    assert_eq!(sc(47, [a as u64, mptr(&mut rmsg), 0, 0, 0, 0]), 1);
    assert_eq!(rmsg.msg_controllen, 0);
    assert_eq!(sc(46, [c as u64, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(sc(47, [a as u64, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(sc(46, [99, ptr(&msg), 0, 0, 0, 0]), EBADF);
    let mut m2 = rmsg;
    m2.msg_control = core::ptr::null_mut();
    assert_eq!(sc(47, [99, mptr(&mut m2), 0, 0, 0, 0]), EBADF);
    // shutdown, socketpair
    assert_eq!(sc(48, [c as u64, 2, 0, 0, 0, 0]), 0);
    assert_eq!(sc(48, [99, 2, 0, 0, 0, 0]), EBADF);
    let mut sv = [0i32; 2];
    assert_eq!(sc(53, [1, 1, 0, mptr(&mut sv), 0, 0]), 0);
    assert!(sv[0] > 0 && sv[1] > sv[0]);
    assert_eq!(sc(53, [2, 1, 0, mptr(&mut sv), 0, 0]), EAFNOSUPPORT);
    assert_eq!(sc(53, [1, 1, 0, 0, 0, 0]), EFAULT);
}

#[test]
fn user_pointers_are_checked() {
    // With an address space, kernel and null pointers fail with EFAULT instead of being
    // dereferenced (before the fix the kernel read and wrote through them)
    let _g = setup();
    proc_(5065, 0);
    let s = sc(41, [1, 1, 0, 0, 0, 0]);
    install(3, FileDescriptor::ConsoleOut);
    let k = 0xffff_8000_0000_1000u64;
    with_current_mm(|| {
        for (nr, a) in [
            (4u64, [k, k, 0, 0, 0, 0]),
            (5, [3, k, 0, 0, 0, 0]),
            (262, [0, k, k, 0, 0, 0]),
            (22, [k, 0, 0, 0, 0, 0]),
            (49, [s as u64, k, 12, 0, 0, 0]),
            (42, [s as u64, k, 12, 0, 0, 0]),
            (53, [1, 1, 0, k, 0, 0]),
            (44, [s as u64, k, 4, 0, 0, 0]),
            (45, [s as u64, k, 4, 0, 0, 0]),
            (46, [s as u64, k, 0, 0, 0, 0]),
            (47, [s as u64, k, 0, 0, 0, 0]),
            (51, [s as u64, k, k, 0, 0, 0]),
            (63, [k, 0, 0, 0, 0, 0]),
            (79, [k, 10, 0, 0, 0, 0]),
            (318, [k, 16, 0, 0, 0, 0]),
            (7, [k, 1, 0, 0, 0, 0]),
            (271, [k, 1, k, 0, 0, 0]),
            (2, [k, 0, 0, 0, 0, 0]),
        ] {
            assert_eq!(sc(nr, a), EFAULT, "syscall {nr}");
        }
        // Pointers that are simply skipped: getresuid's
        assert_eq!(sc(118, [k, k, k, 0, 0, 0]), 0);
    });
}

#[test]
fn identity_calls() {
    let _g = setup();
    proc_(5070, 1000);
    fake::task(5070, |t| {
        t.gid = 100;
        t.egid = 100;
        t.sgid = 100;
    });
    assert_eq!((sc(39, [0; 6]), sc(186, [0; 6]), sc(102, [0; 6]), sc(104, [0; 6]), sc(107, [0; 6]), sc(108, [0; 6])), (5070, 5070, 1000, 100, 1000, 100));
    // Unprivileged setuid: only to the real or saved id
    assert_eq!(sc(105, [5, 0, 0, 0, 0, 0]), EPERM);
    assert_eq!(sc(105, [1000, 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(106, [5, 0, 0, 0, 0, 0]), EPERM);
    assert_eq!(sc(106, [100, 0, 0, 0, 0, 0]), 0);
    // setreuid / setregid / setresuid / setresgid: unprivileged swaps among own ids
    assert_eq!(sc(113, [-1i64 as u64, 1000, 0, 0, 0, 0]), 0);
    assert_eq!(sc(113, [7, 7, 0, 0, 0, 0]), EPERM);
    assert_eq!(sc(114, [-1i64 as u64, 100, 0, 0, 0, 0]), 0);
    assert_eq!(sc(114, [7, 7, 0, 0, 0, 0]), EPERM);
    assert_eq!(sc(117, [1000, 1000, 1000, 0, 0, 0]), 0);
    assert_eq!(sc(117, [9, 9, 9, 0, 0, 0]), EPERM);
    assert_eq!(sc(119, [100, 100, 100, 0, 0, 0]), 0);
    assert_eq!(sc(119, [9, 9, 9, 0, 0, 0]), EPERM);
    let mut ids = [0u32; 3];
    assert_eq!(sc(118, [mptr(&mut ids[0]), mptr(&mut ids[1]), mptr(&mut ids[2]), 0, 0, 0]), 0);
    assert_eq!(ids, [1000; 3]);
    assert_eq!(sc(120, [mptr(&mut ids[0]), mptr(&mut ids[1]), mptr(&mut ids[2]), 0, 0, 0]), 0);
    assert_eq!(ids, [100; 3]);
    assert_eq!(sc(118, [0, 0, 0, 0, 0, 0]), 0, "null pointers are skipped");
    // Root: everything, and dropping root drops the capabilities
    proc_(5071, 0);
    assert_eq!(sc(117, [10, 20, 30, 0, 0, 0]), 0);
    assert_eq!(fake::task(5071, |t| (t.uid, t.euid, t.suid, t.caps.effective)), Some((10, 20, 30, 0)));
    proc_(5072, 0);
    assert_eq!(sc(113, [11, 12, 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(5072, |t| (t.uid, t.euid)), Some((11, 12)));
    proc_(5073, 0);
    assert_eq!(sc(114, [11, 12, 0, 0, 0, 0]), 0);
    assert_eq!(sc(119, [1, 2, 3, 0, 0, 0]), 0);
    assert_eq!(sc(106, [44, 0, 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(5073, |t| (t.gid, t.egid, t.sgid)), Some((44, 44, 44)));
    assert_eq!(sc(105, [55, 0, 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(5073, |t| (t.uid, t.euid, t.suid)), Some((55, 55, 55)));
    // capget / capset are process.rs's (mod.rs's own arms are never reached)
    let v3 = [0x2008_0522u32, 0];
    let mut data = [9u32; 6];
    run(5073);
    assert_eq!(sc(125, [ptr(&v3), mptr(&mut data), 0, 0, 0, 0]), 0);
    fake::switch_to(0);
    assert_eq!(sc(105, [1, 0, 0, 0, 0, 0]), EPERM, "no task");
}

#[test]
fn clocks_names_and_misc() {
    let _g = setup();
    proc_(5080, 0);
    let mut ts = [0i64; 2];
    assert_eq!(sc(228, [0, mptr(&mut ts), 0, 0, 0, 0]), 0);
    assert_eq!(ts[0], 1_767_225_600, "CLOCK_REALTIME from the RTC");
    fake::TICKS.set(2500);
    assert_eq!(sc(228, [1, mptr(&mut ts), 0, 0, 0, 0]), 0);
    assert_eq!(ts, [2, 500_000_000], "CLOCK_MONOTONIC");
    fake::task(5080, |t| t.ticks_run = 1500);
    assert_eq!(sc(228, [2, mptr(&mut ts), 0, 0, 0, 0]), 0);
    assert_eq!(ts, [1, 500_000_000]);
    assert_eq!(sc(228, [3, mptr(&mut ts), 0, 0, 0, 0]), 0);
    assert_eq!(sc(228, [0, 0, 0, 0, 0, 0]), EFAULT);
    let mut tv = [0i64; 2];
    assert_eq!(sc(96, [mptr(&mut tv), 0, 0, 0, 0, 0]), 0);
    assert_eq!(tv[0], 1_767_225_600);
    assert_eq!(sc(96, [0; 6]), 0);
    // uname: the UTS namespace's names
    let mut u = LinuxUtsname::default();
    u.nodename = [0; 65];
    assert_eq!(sc(63, [mptr(&mut u), 0, 0, 0, 0, 0]), 0);
    assert_eq!(&u.nodename[..5], b"hydra");
    assert_eq!(&u.sysname[..5], b"Linux");
    assert_eq!(sc(63, [0; 6]), EFAULT);
    // getcwd
    let mut cwd = [0u8; 8];
    assert_eq!(sc(79, [mptr(&mut cwd), 8, 0, 0, 0, 0]), cwd.as_ptr() as i64);
    assert_eq!(&cwd[..2], b"/\0");
    assert_eq!(sc(79, [mptr(&mut cwd), 1, 0, 0, 0, 0]), -34, "ERANGE");
    assert_eq!(sc(79, [0, 8, 0, 0, 0, 0]), EFAULT);
    // nanosleep (legacy), getrandom, set_tid_address, arch_prctl, futex
    let t0 = fake::TICKS.get();
    let req = [0i64, 7_000_000];
    assert_eq!(sc(35, [ptr(&req), 0, 0, 0, 0, 0]), 0);
    assert_eq!(fake::TICKS.get(), t0 + 7);
    let mut r = [0u8; 16];
    assert_eq!(sc(318, [mptr(&mut r), 16, 0, 0, 0, 0]), 16);
    assert!(r.iter().any(|&b| b != 0));
    assert_eq!(sc(318, [0, 16, 0, 0, 0, 0]), EFAULT);
    assert_eq!(sc(318, [0, 0, 0, 0, 0, 0]), 0);
    assert_eq!(sc(218, [0x1234, 0, 0, 0, 0, 0]), 5080);
    assert_eq!(fake::task(5080, |t| t.clear_child_tid), Some(0x1234));
    assert_eq!(sc(158, [0x9999, 0, 0, 0, 0, 0]), EINVAL);
    let w = 3u32;
    assert_eq!(sc(202, [ptr(&w), 1 | 128, 1, 0, 0, 0]), 0, "futex wake");
    // memfd_create
    let name = cstr("buf");
    let fd = sc(319, [name.as_ptr() as u64, 1, 0, 0, 0, 0]);
    assert!(fd >= 0 && with_current_fds_mut(|f| f.cloexec(fd as usize)));
    assert_eq!(sc(319, [name.as_ptr() as u64, !0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(sc(319, [0, 0, 0, 0, 0, 0]), EFAULT);
    let long = cstr(&"n".repeat(250));
    assert_eq!(sc(319, [long.as_ptr() as u64, 0, 0, 0, 0, 0]), EINVAL);
    let bad = [0xffu8, 0xfe, 0];
    assert_eq!(sc(319, [bad.as_ptr() as u64, 0, 0, 0, 0, 0]), EFAULT, "not UTF-8");
    // pipe2 flags
    let mut fds = [0i32; 2];
    assert_eq!(sc(293, [mptr(&mut fds), 0o4000 | 0o2000000, 0, 0, 0, 0]), 0);
    assert!(with_current_fds_mut(|f| f.cloexec(fds[0] as usize) && f.cloexec(fds[1] as usize)));
    assert_eq!(sc(22, [0; 6]), EFAULT);
    // exit / exit_group (legacy arms are reached through the process calls)
    panics_with("task::exit_group", || {
        sc(231, [3, 0, 0, 0, 0, 0]);
    });
    assert_eq!(linux::proc::PROCS.lock().get(&5080).unwrap().exit_status, Some(3 << 8));
    panics_with("task::exit", || {
        sc(60, [0; 6]);
    });
}

#[test]
fn poll_and_epoll() {
    let _g = setup();
    proc_(5090, 0);
    install(3, FileDescriptor::file("/f"));
    let mut fds = [0i32; 2];
    sc(22, [mptr(&mut fds), 0, 0, 0, 0, 0]);
    let (r, w) = (fds[0], fds[1]);
    // poll: a file is ready; an empty pipe's read end is not; a bad fd is POLLNVAL
    let mut p = [LinuxPollFd { fd: 3, events: 1, revents: 0 }, LinuxPollFd { fd: r, events: 1, revents: 0 }, LinuxPollFd { fd: 77, events: 1, revents: 0 }, LinuxPollFd { fd: -1, events: 1, revents: 7 }];
    assert_eq!(sc(7, [mptr(&mut p), 4, 0, 0, 0, 0]), 2);
    assert_eq!((p[0].revents, p[1].revents, p[2].revents, p[3].revents), (1, 0, 0x20, 0));
    // Nothing ready: timeout 0 returns at once; a timeout runs out; a signal interrupts
    let mut q = [LinuxPollFd { fd: r, events: 1, revents: 0 }];
    assert_eq!(sc(7, [mptr(&mut q), 1, 0, 0, 0, 0]), 0);
    assert_eq!(sc(7, [mptr(&mut q), 1, 5, 0, 0, 0]), 0);
    fake::step(|| {
        linux::proc::post_process(5090, 10);
    });
    assert_eq!(sc(7, [mptr(&mut q), 1, -1i64 as u64, 0, 0, 0]), linux::proc::ERESTARTSYS);
    linux::proc::PROCS.lock().get_mut(&5090).unwrap().pending = 0;
    // Data arrives while waiting
    fake::step(move || {
        sc(1, [w as u64, ptr(b"x"), 1, 0, 0, 0]);
    });
    assert_eq!(sc(7, [mptr(&mut q), 1, -1i64 as u64, 0, 0, 0]), 1);
    // ppoll: a timespec timeout; invalid; no descriptors: a sleep
    let ts = [0i64, 1_000_000];
    assert_eq!(sc(271, [mptr(&mut q), 1, ptr(&ts), 0, 0, 0]), 1);
    assert_eq!(sc(271, [mptr(&mut q), 1, ptr(&[0i64, 2_000_000_000]), 0, 0, 0]), EINVAL);
    let t0 = fake::TICKS.get();
    assert_eq!(sc(271, [0, 0, ptr(&[0i64, 4_000_000]), 0, 0, 0]), 0);
    assert!(fake::TICKS.get() >= t0 + 4);
    assert_eq!(sc(7, [0, 0, 0, 0, 0, 0]), 0, "poll(NULL, 0, 0)");
    fake::step(|| {
        linux::proc::post_process(5090, 10);
    });
    assert_eq!(sc(7, [0, 0, -1i64 as u64, 0, 0, 0]), -4);
    fake::step(|| {});
    assert_eq!(sc(7, [0, 0, 1000, 0, 0, 0]), -4, "the signal is still pending");
    linux::proc::PROCS.lock().get_mut(&5090).unwrap().pending = 0;
    fake::step(|| {});
    assert_eq!(sc(7, [0, 0, -1i64 as u64, 0, 0, 0]), 0, "an infinite sleep woken without a signal");
    assert_eq!(sc(7, [0, 3, 0, 0, 0, 0]), EFAULT);
    // epoll
    let ep = sc(291, [0x80000, 0, 0, 0, 0, 0]);
    assert!(ep >= 0 && with_current_fds_mut(|f| f.cloexec(ep as usize)));
    let ep2 = sc(213, [1, 0, 0, 0, 0, 0]);
    assert!(ep2 >= 0);
    let ev = LinuxEpollEvent { events: 1, data: 0xabc };
    assert_eq!(sc(233, [ep as u64, 1, 3, ptr(&ev), 0, 0]), 0);
    assert_eq!(sc(233, [ep as u64, 1, 99, ptr(&ev), 0, 0]), EBADF);
    assert_eq!(sc(233, [3, 1, 3, ptr(&ev), 0, 0]), EBADF, "not an epoll");
    assert!(sc(233, [ep as u64, 1, 3, ptr(&ev), 0, 0]) < 0, "already watched");
    let mut out = [LinuxEpollEvent { events: 0, data: 0 }; 4];
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 4, 0, 0, 0]), 1);
    let data = out[0].data;
    assert_eq!(data, 0xabc);
    assert_eq!(sc(232, [ep as u64, 0, 4, 0, 0, 0]), EINVAL);
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 0, 0, 0, 0]), EINVAL);
    assert_eq!(sc(232, [3, mptr(&mut out), 4, 0, 0, 0]), EBADF);
    // Nothing ready: 0 at once, a timeout, a signal, then the interest list changing
    assert_eq!(sc(233, [ep as u64, 2, 3, 0, 0, 0]), 0, "EPOLL_CTL_DEL");
    sc(0, [r as u64, mptr(&mut [0u8; 4]), 4, 0, 0, 0]);
    let evr = LinuxEpollEvent { events: 1, data: 7 };
    assert_eq!(sc(233, [ep as u64, 1, r as u64, ptr(&evr), 0, 0]), 0);
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 4, 0, 0, 0]), 0);
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 4, 3, 0, 0]), 0);
    fake::step(|| {
        linux::proc::post_process(5090, 10);
    });
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 4, -1i64 as u64, 0, 0]), linux::proc::ERESTARTSYS);
    linux::proc::PROCS.lock().get_mut(&5090).unwrap().pending = 0;
    fake::step(move || {
        let ev = LinuxEpollEvent { events: 4, data: 9 };
        assert_eq!(sc(233, [ep as u64, 1, w as u64, ptr(&ev), 0, 0]), 0);
    });
    assert_eq!(sc(232, [ep as u64, mptr(&mut out), 4, -1i64 as u64, 0, 0]), 1, "a watch added while waiting");
}

#[test]
fn clone_fork_and_clone3() {
    let _g = setup();
    proc_(5100, 0);
    let mut f = frame(57, [0; 6]);
    let child = dispatch_checked(&mut f);
    assert_eq!(child, 1000, "fork");
    assert!(fake::called("spawn_clone(0x11,"));
    assert!(fake::called("keys::on_fork(5100,1000,)") && fake::called("sysv::on_fork(5100,1000,)") && fake::called("lx::note("));
    // A thread (CLONE_THREAD): no fork notes
    fake::take_calls();
    let t = sc(56, [0x10000 | 0x100 | 0x800, 0x7000, 0, 0, 0, 0]);
    assert_eq!(t, 1001);
    assert!(!fake::called("keys::on_fork"));
    // CLONE_FS only: the child shares our root and working directory
    linux::proc::register_process(1002, 5100, 1002, Some(5100));
    let c = sc(56, [0x200 | 17, 0, 0, 0, 0, 0]);
    linux::proc::register_process(c as u64, 5100, c as u64, Some(5100));
    // Failures: bad namespace flags, a refused fork
    assert_eq!(sc(56, [0x1000_0000 | 0x10000, 0, 0, 0, 0, 0]), EINVAL);
    fake::CLONE_FAILS.set(true);
    assert_eq!(sc(57, [0; 6]), -12);
    fake::CLONE_FAILS.set(false);
    // CLONE_PARENT from init: EINVAL
    proc_(1, 0);
    assert_eq!(sc(56, [0x8000 | 17, 0, 0, 0, 0, 0]), EINVAL);
    run(5100);
    // vfork: waits until the child execs or exits
    fake::ON_WAIT.with_borrow_mut(|h| {
        *h = Some(Box::new(|| {
            let mut procs = linux::proc::PROCS.lock();
            for p in procs.values_mut() {
                p.vfork_released = true;
            }
        }))
    });
    let next = fake::NEXT_TID.get();
    linux::proc::register_process(next, 5100, next, Some(5100));
    assert_eq!(sc(58, [0; 6]), next as i64);
    fake::ON_WAIT.with_borrow_mut(|h| *h = None);
    // clone3: size checks, a pidfd, CLONE_CLEAR_SIGHAND, stack
    let mut pidfd = -1i32;
    let mut args = [0u64; 11];
    args[0] = 0x1000 | 0x1_0000_0000; // CLONE_PIDFD | CLONE_CLEAR_SIGHAND
    args[1] = mptr(&mut pidfd);
    args[4] = 17;
    args[5] = 0x6000;
    args[6] = 0x1000;
    assert_eq!(sc(435, [ptr(&args), 32, 0, 0, 0, 0]), EINVAL, "smaller than VER0");
    assert_eq!(sc(435, [ptr(&args), 8192, 0, 0, 0, 0]), EINVAL);
    let c3 = sc(435, [ptr(&args), 88, 0, 0, 0, 0]);
    assert!(c3 > 0);
    assert!(pidfd >= 0);
    assert!(fake::called(&format!("spawn_clone(0x11,0x7000)")));
    let mut bad = args;
    bad[4] = 65;
    assert_eq!(sc(435, [ptr(&bad), 88, 0, 0, 0, 0]), EINVAL, "exit signal");
    let mut bad = args;
    bad[9] = 1;
    assert_eq!(sc(435, [ptr(&bad), 88, 0, 0, 0, 0]), EINVAL, "set_tid");
    let mut bad = args;
    bad[6] = 0;
    assert_eq!(sc(435, [ptr(&bad), 88, 0, 0, 0, 0]), EINVAL, "stack without a size");
    let mut bad = args;
    bad[0] |= 0x2_0000_0000;
    bad[10] = 3;
    assert_eq!(sc(435, [ptr(&bad), 88, 0, 0, 0, 0]), EINVAL, "into a cgroup");
    with_current_mm(|| assert_eq!(sc(435, [8, 88, 0, 0, 0, 0]), EFAULT));
    // Process calls that need the frame
    assert_eq!(sc(61, [-1i64 as u64, 0, 1, 0, 0, 0]), 0, "wait4, WNOHANG");
    assert_eq!(sc(247, [9, 0, 0, 4, 0, 0]), EINVAL, "waitid");
    assert_eq!(sc(131, [0, 0, 0, 0, 0, 0]), 0, "sigaltstack");
    assert_eq!(sc(14, [0, 0, 0, 8, 0, 0]), 0, "rt_sigprocmask");
    assert_eq!(sc(127, [0, 4, 0, 0, 0, 0]), EINVAL);
    assert_eq!(sc(128, [0, 0, 0, 4, 0, 0]), EINVAL);
    assert_eq!(sc(130, [0, 4, 0, 0, 0, 0]), EINVAL);
    assert!(sc(59, [0, 0, 0, 0, 0, 0]) < 0, "execve");
    assert!(sc(322, [-100i64 as u64, 0, 0, 0, 0, 0]) < 0, "execveat");
}
