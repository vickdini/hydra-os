//! The brief's files that `tests/host` already covers well (mm.rs, seccomp.rs,
//! userfaultfd.rs, types.rs): checks of them as this crate builds them, through the system
//! call table (mod.rs) and directly.

use super::common::*;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::{self as lx, dispatch_checked, dispatch_linux_syscall};
use crate::memory::vm::{Mm, PAGE_SIZE};
use std::sync::Arc;

fn sc(nr: u64, a: [u64; 6]) -> i64 {
    let mut f = SyscallFrame { rax: nr, rdi: a[0], rsi: a[1], rdx: a[2], r10: a[3], r8: a[4], r9: a[5], ..Default::default() };
    dispatch_checked(&mut f)
}

#[test]
fn memory_calls_go_to_the_address_space() {
    let _g = setup();
    global_frames();
    spawn(6000, 0);
    run(6000);
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(6000, |t| t.mm = Some(mm.clone()));
    let before = lx::LINUX_STATS.lock().memory_calls;
    let a = sc(9, [0, 3 * PAGE_SIZE, 3, 0x22, -1i64 as u64, 0]);
    assert!(a > 0 && a as u64 % PAGE_SIZE == 0, "mmap");
    assert!(mm.lock().find_vma(a as u64).is_some());
    assert_eq!(sc(10, [a as u64, PAGE_SIZE, 1, 0, 0, 0]), 0, "mprotect");
    assert_eq!(sc(28, [a as u64, PAGE_SIZE, 4, 0, 0, 0]), 0, "madvise(DONTNEED)");
    let mut vec = [9u8; 3];
    assert_eq!(sc(27, [a as u64, 3 * PAGE_SIZE, mptr(&mut vec), 0, 0, 0]), 0, "mincore");
    assert_eq!(sc(26, [a as u64, PAGE_SIZE, 4, 0, 0, 0]), 0, "msync");
    let b = sc(25, [a as u64 + PAGE_SIZE, 2 * PAGE_SIZE, 4 * PAGE_SIZE, 1, 0, 0]);
    assert!(b > 0, "mremap: {b}");
    assert_eq!(sc(11, [b as u64, 4 * PAGE_SIZE, 0, 0, 0, 0]), 0, "munmap");
    assert!(mm.lock().find_vma(b as u64).is_none());
    assert!(sc(12, [0, 0, 0, 0, 0, 0]) >= 0, "brk(0): the current break");
    assert_eq!(lx::LINUX_STATS.lock().memory_calls, before + 8);
    assert!(lx::mm::current_mm().is_some());
    // The legacy path of a task without an address space
    fake::task(6000, |t| t.mm = None);
    assert_eq!(sc(9, [0, 0, 3, 0x22, -1i64 as u64, 0]), -22);
    let p = sc(9, [0, 100, 3, 0x22, -1i64 as u64, 0]);
    assert!(p > 0);
    assert_eq!(fake::USER_RANGES.with_borrow(|v| v.last().copied()), Some((p as u64, 4096)));
    assert_eq!(sc(10, [0; 6]), 0);
    assert_eq!(sc(11, [0; 6]), 0);
    fake::task(6000, |t| t.brk = 0x1000);
    assert_eq!(sc(12, [0x3000, 0, 0, 0, 0, 0]), 0x3000);
    assert_eq!(sc(12, [0x2000, 0, 0, 0, 0, 0]), 0x3000, "never shrinks");
    assert_eq!(sc(13, [0; 6]), -22, "rt_sigaction goes to proc.rs first");
}

#[test]
fn seccomp_through_the_table() {
    let _g = setup();
    spawn(6010, 0);
    run(6010);
    // SECCOMP_SET_MODE_STRICT: afterwards only read/write/exit/sigreturn
    assert_eq!(sc(157, [38, 1, 0, 0, 0, 0]), 0, "no_new_privs");
    assert_eq!(lx::seccomp::status_of(6010).0, true);
    assert_eq!(sc(317, [0, 0, 0, 0, 0, 0]), 0, "strict mode");
    assert_eq!(lx::seccomp::status_of(6010).1, 1);
    let mut f = SyscallFrame { rax: 39, ..Default::default() };
    panics_with("task::exit_group", || {
        dispatch_linux_syscall(&mut f);
    });
    let mut w = SyscallFrame { rax: 1, rdi: 99, rsi: 0, rdx: 0, ..Default::default() };
    assert_eq!(dispatch_linux_syscall(&mut w), 0, "write is allowed (0 bytes)");
}

#[test]
fn userfaultfd_through_the_table() {
    let _g = setup();
    spawn(6020, 0);
    run(6020);
    assert_eq!(sc(323, [1 << 20, 0, 0, 0, 0, 0]), -22, "unknown flag");
    assert!(!lx::userfaultfd::active());
}

#[test]
fn abi_types() {
    let _g = setup();
    let u = lx::types::LinuxUtsname::default();
    assert_eq!(&u.sysname[..6], b"Linux\0");
    assert_eq!(&u.machine[..7], b"x86_64\0");
    assert_eq!(core::mem::size_of::<lx::types::LinuxStat>(), 144, "struct stat");
    assert_eq!(core::mem::size_of::<lx::types::LinuxIovec>(), 16);
    assert_eq!(core::mem::size_of::<lx::types::LinuxTimespec>(), 16);
    assert_eq!(core::mem::size_of::<lx::types::LinuxMsghdr>(), 56, "struct msghdr");
    let st = lx::types::LinuxStat::default();
    assert_eq!(st.st_size, 0);
}
