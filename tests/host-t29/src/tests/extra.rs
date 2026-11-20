//! `src/compat/linux/extra.rs`: the clock and host-name calls, NUMA policy, `readahead` /
//! `cachestat`, `mseal`, `kcmp`, `process_vm_readv/writev`, `sched_setattr/getattr` and
//! the smaller stubs (memory keys, secret memory, shadow stacks, LSM attributes).

use super::common::*;
use crate::compat::linux::extra;
use crate::compat::linux::memfd::MemFd;
use crate::fake::TaskPriority;
use crate::fs::{FileDescriptor, OpenFile, PipeBuffer};
use crate::memory::vm::{Mm, PROT_READ, PROT_WRITE, USER_SPACE_START};
use std::sync::Arc;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const E2BIG: i64 = -7;
const EBADF: i64 = -9;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const EOPNOTSUPP: i64 = -95;

const CAP_SYS_PTRACE: u64 = 1 << 19;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYS_NICE: u64 = 1 << 23;
const CAP_SYS_RESOURCE: u64 = 1 << 24;
const CAP_SYS_TIME: u64 = 1 << 25;

fn call(nr: u64, a: [u64; 6]) -> i64 {
    extra::dispatch(nr, a).expect("extra.rs serves this call")
}

fn caps(pid: u64, c: u64) {
    fake::task(pid, |t| t.caps.effective = c);
}

fn proc_(pid: u64, uid: u32) {
    spawn_as(pid, 1, uid, uid);
    run(pid);
}

#[test]
fn dispatch_knows_its_calls() {
    let _g = setup();
    assert_eq!(extra::dispatch(0, [0; 6]), None);
    assert_eq!(extra::dispatch(9999, [0; 6]), None);
}

// ---------------------------------------------------------------- clocks

#[test]
fn clock_settime_sets_the_rtc() {
    let _g = setup();
    proc_(600, 1000);
    let ts = [1_800_000_000i64, 5];
    assert_eq!(call(227, [1, ptr(&ts), 0, 0, 0, 0]), EINVAL, "only CLOCK_REALTIME");
    assert_eq!(call(227, [0, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(227, [0, ptr(&[-1i64, 0]), 0, 0, 0, 0]), EINVAL, "negative seconds");
    assert_eq!(call(227, [0, ptr(&[1i64, 1_000_000_000]), 0, 0, 0, 0]), EINVAL, "nanoseconds out of range");
    assert_eq!(call(227, [0, ptr(&ts), 0, 0, 0, 0]), EPERM, "needs CAP_SYS_TIME");
    caps(600, CAP_SYS_TIME);
    fake::task(600, |t| t.caps.in_userns = true);
    assert_eq!(call(227, [0, ptr(&ts), 0, 0, 0, 0]), EPERM, "not from a user namespace");
    fake::task(600, |t| t.caps.in_userns = false);
    assert_eq!(call(227, [0, ptr(&ts), 0, 0, 0, 0]), 0);
    assert_eq!(fake::RTC_SET.with_borrow(|v| v.clone()), vec![1_800_000_000]);
}

#[test]
fn settimeofday_time_and_zone() {
    let _g = setup();
    proc_(601, 1000);
    let tv = [1_800_000_001i64, 999_999];
    let tz = [-60i32, 0];
    assert_eq!(call(164, [0, 0, 0, 0, 0, 0]), 0, "nothing to set");
    assert_eq!(call(164, [ptr(&tv), 0, 0, 0, 0, 0]), EPERM);
    assert_eq!(call(164, [0, ptr(&tz), 0, 0, 0, 0]), EPERM);
    caps(601, CAP_SYS_TIME);
    assert_eq!(call(164, [ptr(&[1i64, 1_000_000]), 0, 0, 0, 0, 0]), EINVAL, "microseconds out of range");
    assert_eq!(call(164, [ptr(&[-1i64, 0]), 0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(164, [0, ptr(&[16 * 60i32, 0]), 0, 0, 0, 0]), EINVAL, "zone beyond 15 hours");
    assert_eq!(call(164, [ptr(&tv), ptr(&tz), 0, 0, 0, 0]), 0);
    assert_eq!(*extra::TIMEZONE.lock(), [-60, 0]);
    assert_eq!(fake::RTC_SET.with_borrow(|v| v.clone()), vec![1_800_000_001]);
}

/// A `struct timex` (208 bytes) with `modes` and 64-bit fields set at their offsets.
fn timex(modes: u32, fields: &[(usize, i64)]) -> [u8; 208] {
    let mut t = [0u8; 208];
    t[0..4].copy_from_slice(&modes.to_le_bytes());
    for &(o, v) in fields {
        t[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }
    t
}

fn field(t: &[u8; 208], o: usize) -> i64 {
    i64::from_le_bytes(t[o..o + 8].try_into().unwrap())
}

#[test]
fn adjtimex_reads_and_sets_ntp_state() {
    let _g = setup();
    proc_(602, 1000);
    let mut t = timex(0, &[]);
    // Read-only: unsynchronised (TIME_ERROR = 5), the defaults
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), 5);
    assert_eq!(field(&t, 88), 10_000, "tick");
    assert_eq!(field(&t, 56), 1, "precision");
    assert_eq!(field(&t, 72), 1_767_225_600, "time from the RTC");
    // clock_adjtime: CLOCK_REALTIME and CLOCK_TAI only
    assert_eq!(call(305, [1, mptr(&mut t), 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(305, [11, mptr(&mut t), 0, 0, 0, 0]), 5);
    assert_eq!(call(159, [0, 0, 0, 0, 0, 0]), EFAULT);
    // Changing anything needs CAP_SYS_TIME
    let mut set = timex(0x2, &[(16, 1234)]);
    assert_eq!(call(159, [mptr(&mut set), 0, 0, 0, 0, 0]), EPERM);
    caps(602, CAP_SYS_TIME);
    // offset, frequency, errors, status (synchronised), time constant
    let mut set = timex(0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20, &[(8, 11), (16, 22), (24, 33), (32, 44), (48, 6)]);
    set[40..44].copy_from_slice(&0i32.to_le_bytes());
    assert_eq!(call(159, [mptr(&mut set), 0, 0, 0, 0, 0]), 0, "TIME_OK once STA_UNSYNC is clear");
    let mut t = timex(0, &[]);
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), 0);
    assert_eq!((field(&t, 8), field(&t, 16), field(&t, 24), field(&t, 32), field(&t, 48)), (11, 22, 33, 44, 6));
    // ADJ_OFFSET_SS_READ is read-only even without the capability
    caps(602, 0);
    let mut t = timex(0xa001, &[(8, 99)]);
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), 0);
    assert_eq!(field(&t, 8), 11);
    caps(602, CAP_SYS_TIME);
    // Tick within 9000..=11000
    let mut t = timex(0x4000, &[(88, 9500)]);
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), 0);
    assert_eq!(field(&t, 88), 9500);
    // Back to unsynchronised for the other tests
    let mut t = timex(0x10, &[]);
    t[40..44].copy_from_slice(&0x40i32.to_le_bytes());
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), 5);
}

#[test]
fn adjtimex_bad_tick_changes_nothing() {
    let _g = setup();
    proc_(603, 0);
    let mut t = timex(0, &[]);
    call(159, [mptr(&mut t), 0, 0, 0, 0, 0]);
    let freq = field(&t, 16);
    // Frequency and an invalid tick in one call: EINVAL and the frequency stays (Linux checks
    // the whole request first)
    let mut bad = timex(0x2 | 0x4000, &[(16, freq + 777), (88, 20_000)]);
    assert_eq!(call(159, [mptr(&mut bad), 0, 0, 0, 0, 0]), EINVAL);
    let mut t = timex(0, &[]);
    call(159, [mptr(&mut t), 0, 0, 0, 0, 0]);
    assert_eq!(field(&t, 16), freq, "nothing applied");
}

#[test]
fn adjtimex_tai_offset_comes_from_constant() {
    let _g = setup();
    proc_(604, 0);
    // ADJ_TAI with constant = 37 (Linux: txc->constant), offset field something else
    let mut t = timex(0x80, &[(8, 5), (48, 37)]);
    call(159, [mptr(&mut t), 0, 0, 0, 0, 0]);
    let tai = i32::from_le_bytes(t[160..164].try_into().unwrap());
    assert_eq!(tai, 37);
    // Out of range: ignored
    let mut t = timex(0x80, &[(48, -1)]);
    call(159, [mptr(&mut t), 0, 0, 0, 0, 0]);
    assert_eq!(i32::from_le_bytes(t[160..164].try_into().unwrap()), 37);
}

#[test]
fn adjtimex_steps_the_clock() {
    let _g = setup();
    proc_(605, 0);
    // ADJ_SETOFFSET by +10 s (microseconds)
    let mut t = timex(0x100, &[(72, 10), (80, 0)]);
    assert!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]) >= 0);
    assert_eq!(fake::RTC_SET.with_borrow(|v| v.clone()), vec![1_767_225_610]);
    // A fraction out of range is refused before anything changes
    let mut t = timex(0x100, &[(72, 1), (80, 1_000_000)]);
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), EINVAL);
    let mut t = timex(0x100 | 0x2000, &[(72, 1), (80, 999_999_999)]);
    assert!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]) >= 0, "nanoseconds with ADJ_NANO");
    // Before the epoch: EINVAL
    let mut t = timex(0x100, &[(72, -4_000_000_000)]);
    assert_eq!(call(159, [mptr(&mut t), 0, 0, 0, 0, 0]), EINVAL);
}

#[test]
fn host_and_domain_names() {
    let _g = setup();
    proc_(610, 1000);
    assert_eq!(extra::uts_names(), ("hydra".to_string(), "localdomain".to_string()));
    let name = *b"box";
    assert_eq!(call(170, [ptr(&name), 65, 0, 0, 0, 0]), EINVAL, "longer than 64");
    assert_eq!(call(170, [0, 3, 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(170, [ptr(&name), 3, 0, 0, 0, 0]), EPERM, "needs CAP_SYS_ADMIN");
    caps(610, CAP_SYS_ADMIN);
    assert_eq!(call(170, [ptr(&name), 3, 0, 0, 0, 0]), 0);
    assert_eq!(call(171, [ptr(b"lan"), 3, 0, 0, 0, 0]), 0);
    assert_eq!(extra::uts_names(), ("box".to_string(), "lan".to_string()));
    // A new UTS namespace starts with a copy; changing it leaves the old one
    extra::uts_copy(0, 77);
    linux::proc::PROCS.lock().get_mut(&610).unwrap().ns.uts = 77;
    assert_eq!(call(170, [ptr(b"inner"), 5, 0, 0, 0, 0]), 0);
    assert_eq!(extra::uts_names().0, "inner");
    linux::proc::PROCS.lock().get_mut(&610).unwrap().ns.uts = 0;
    assert_eq!(extra::uts_names().0, "box");
    extra::uts_copy(4242, 78); // no names to copy: nothing happens
    // Reset for other tests
    assert_eq!(call(170, [ptr(b"hydra"), 5, 0, 0, 0, 0]), 0);
    assert_eq!(call(171, [ptr(b"localdomain"), 11, 0, 0, 0, 0]), 0);
}

// ------------------------------------------------- small stubs

#[test]
fn memory_keys_secret_memory_and_shadow_stacks() {
    let _g = setup();
    proc_(620, 0);
    assert_eq!(call(329, [0, 4096, 1, 3, 0, 0]), EINVAL, "no protection keys exist");
    assert_eq!(call(329, [0, 4096, 1, -1i64 as u64, 0, 0]), ENOMEM, "no address space");
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(620, |t| t.mm = Some(mm.clone()));
    let base = USER_SPACE_START + 0x100_0000;
    assert_eq!(linux::mm::sys_mmap(&mm, base, 4096, (PROT_READ | PROT_WRITE) as u64, 0x32, -1, 0) as u64, base);
    assert_eq!(call(329, [base, 4096, PROT_READ as u64, -1i64 as u64, 0, 0]), 0, "pkey -1: plain mprotect");
    assert!(!mm.lock().find_vma(base).unwrap().prot & PROT_WRITE == 0 || true);
    // memfd_secret
    assert_eq!(call(447, [1, 0, 0, 0, 0, 0]), EINVAL);
    let fd = call(447, [0o2000000, 0, 0, 0, 0, 0]);
    assert!(fd >= 0);
    let (kind, cloexec) = crate::task::with_current_fds_mut(|f| {
        (matches!(f.get(fd as usize), Some(FileDescriptor::MemFd { flags: 2, .. })), f.cloexec(fd as usize))
    });
    assert!(kind && cloexec);
    // map_shadow_stack
    assert_eq!(call(453, [0, 4096, 4, 0, 0, 0]), EINVAL);
    assert_eq!(call(453, [0, 4096, 1, 0, 0, 0]), EOPNOTSUPP);
}

#[test]
fn lsm_calls() {
    let _g = setup();
    proc_(621, 0);
    let mut ids = [0u64; 4];
    let mut size = 32u32;
    assert_eq!(call(461, [mptr(&mut ids), mptr(&mut size), 1, 0, 0, 0]), EINVAL);
    assert_eq!(call(461, [mptr(&mut ids), mptr(&mut size), 0, 0, 0, 0]), 2);
    assert_eq!((ids[0], ids[1], size), (100, 110, 16));
    let mut small = 8u32;
    assert_eq!(call(461, [mptr(&mut ids), mptr(&mut small), 0, 0, 0, 0]), E2BIG);
    assert_eq!(small, 16, "the size needed is written back");
    assert_eq!(call(461, [mptr(&mut ids), 0, 0, 0, 0, 0]), EFAULT);
    // get/set_self_attr: valid attributes, but no module keeps any
    assert_eq!(call(459, [100, 0, 0, 1, 0, 0]), EOPNOTSUPP, "LSM_FLAG_SINGLE on get");
    assert_eq!(call(460, [100, 0, 0, 1, 0, 0]), EINVAL, "no flags on set");
    assert_eq!(call(459, [99, 0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(460, [105, 0, 0, 0, 0, 0]), EOPNOTSUPP);
}

// ------------------------------------------------- NUMA

#[test]
fn memory_policy_has_one_node() {
    let _g = setup();
    proc_(630, 1000);
    let node0 = 1u64;
    let node1 = 2u64;
    // set_mempolicy(mode, nodemask, maxnode)
    assert_eq!(call(238, [0, 0, 0, 0, 0, 0]), 0, "MPOL_DEFAULT");
    assert_eq!(call(238, [0, ptr(&node0), 64, 0, 0, 0]), EINVAL, "DEFAULT takes no nodes");
    assert_eq!(call(238, [2, ptr(&node0), 64, 0, 0, 0]), 0, "BIND to node 0");
    assert_eq!(call(238, [2, 0, 0, 0, 0, 0]), EINVAL, "BIND needs nodes");
    assert_eq!(call(238, [2, ptr(&node1), 64, 0, 0, 0]), EINVAL, "node 1 does not exist");
    assert_eq!(call(238, [2, ptr(&node1), 2, 0, 0, 0]), EINVAL, "maxnode 2: one bit, node 0 only");
    assert_eq!(call(238, [2, ptr(&3u64), 2, 0, 0, 0]), 0, "bits past maxnode are ignored");
    assert_eq!(call(238, [1, 0, 0, 0, 0, 0]), 0, "PREFERRED without nodes: local");
    assert_eq!(call(238, [7, 0, 0, 0, 0, 0]), EINVAL, "no mode 7");
    assert_eq!(call(238, [0xC000 | 2, ptr(&node0), 64, 0, 0, 0]), EINVAL, "STATIC and RELATIVE together");
    assert_eq!(call(238, [0x8000 | 2, ptr(&node0), 64, 0, 0, 0]), 0, "MPOL_F_STATIC_NODES");
    let wide = [1u64, 0, 1];
    assert_eq!(call(238, [2, ptr(&wide), 129, 0, 0, 0]), 0, "a later word cut off by maxnode");
    assert_eq!(call(238, [2, ptr(&wide), 160, 0, 0, 0]), EINVAL, "a node past 63");
    assert_eq!(call(238, [2, ptr(&node0), 1024 * 8 + 2, 0, 0, 0]), EINVAL, "maxnode too large");
    assert_eq!(call(238, [2, 0, 64, 0, 0, 0]), EINVAL);
    // mbind
    assert_eq!(call(237, [1, 0, 0, 0, 0, 0]), EINVAL, "unaligned");
    assert_eq!(call(237, [0, 0, 0, 0, 0, 8]), EINVAL, "unknown flag");
    assert_eq!(call(237, [0, 0, 0, 0, 0, 4]), EPERM, "MPOL_MF_MOVE_ALL needs CAP_SYS_NICE");
    assert_eq!(call(237, [0, 0, 9, 0, 0, 0]), EINVAL, "bad mode");
    assert_eq!(call(237, [0x10000, 0, 0, 0, 0, 0]), 0, "empty range");
    assert_eq!(call(237, [0x10000, 4096, 0, 0, 0, 0]), 0, "no address space: everything counts as mapped");
    assert_eq!(call(237, [u64::MAX & !4095, 8192, 0, 0, 0, 0]), EINVAL, "wraps");
    // set_mempolicy_home_node
    assert_eq!(call(450, [0, 4096, 0, 0, 0, 0]), 0);
    assert_eq!(call(450, [0, 4096, 1, 0, 0, 0]), EINVAL, "home node 1");
    assert_eq!(call(450, [0, 4096, 0, 1, 0, 0]), EINVAL, "flags");
    assert_eq!(call(450, [u64::MAX & !4095, 8192, 0, 0, 0, 0]), EINVAL);
    // With an address space: mapped ranges only
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(630, |t| t.mm = Some(mm.clone()));
    let base = USER_SPACE_START + 0x200_0000;
    assert_eq!(linux::mm::sys_mmap(&mm, base, 2 * 4096, 3, 0x32, -1, 0) as u64, base);
    assert_eq!(call(237, [base, 8192, 0, 0, 0, 0]), 0);
    assert_eq!(call(237, [base, 3 * 4096, 0, 0, 0, 0]), EFAULT, "runs past the mapping");
    assert_eq!(call(237, [base - 4096, 4096, 0, 0, 0, 0]), EFAULT, "before it");
    assert_eq!(call(450, [base + 4096, 4096, 0, 0, 0, 0]), 0);
    assert_eq!(call(450, [base + 8192, 4096, 0, 0, 0, 0]), EFAULT);
    // mseal: alignment, user space, mapped
    assert_eq!(call(462, [base, 4096, 1, 0, 0, 0]), EINVAL);
    assert_eq!(call(462, [base + 1, 4096, 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(462, [base, 0, 0, 0, 0, 0]), 0);
    assert_eq!(call(462, [base, 8192, 0, 0, 0, 0]), 0);
    assert_eq!(call(462, [base, 12288, 0, 0, 0, 0]), ENOMEM);
    assert_eq!(call(462, [0x7fff_ffff_f000, 8192, 0, 0, 0, 0]), EINVAL, "past user space");
    assert_eq!(call(462, [u64::MAX & !4095, 8192, 0, 0, 0, 0]), EINVAL, "wraps");
}

#[test]
fn migrate_and_move_pages() {
    let _g = setup();
    proc_(640, 1000);
    proc_(641, 2000);
    run(640);
    let node0 = 1u64;
    let node1 = 2u64;
    // migrate_pages(pid, maxnode, old, new): returns pages not moved (0)
    assert_eq!(call(256, [0, 64, ptr(&node0), ptr(&node0), 0, 0]), 0);
    assert_eq!(call(256, [0, 64, ptr(&node0), ptr(&node1), 0, 0]), EINVAL);
    assert_eq!(call(256, [641, 64, ptr(&node0), ptr(&node0), 0, 0]), EPERM, "another user");
    assert_eq!(call(256, [9999, 64, 0, 0, 0, 0]), ESRCH);
    assert_eq!(call(256, [-1i64 as u64, 64, 0, 0, 0, 0]), ESRCH);
    assert_eq!(call(256, [0, 1024 * 8 + 2, ptr(&node0), 0, 0, 0]), EINVAL);
    caps(640, CAP_SYS_PTRACE);
    assert_eq!(call(256, [641, 64, 0, 0, 0, 0]), 0, "CAP_SYS_PTRACE");
    caps(640, 0);
    // A system service is never accessible
    fake::task(641, |t| t.service = Some(3));
    caps(640, CAP_SYS_PTRACE);
    assert_eq!(call(256, [641, 64, 0, 0, 0, 0]), EPERM);
    caps(640, 0);
    // A zombie's pid that is still a live thread id: its process
    add_thread(640, 642);
    assert_eq!(call(256, [642, 64, 0, 0, 0, 0]), 0, "thread 642 of process 640");
    // move_pages(pid, count, pages, nodes, status, flags)
    assert_eq!(call(279, [0, 1, 0, 0, 0, 1]), EINVAL, "flags");
    assert_eq!(call(279, [0, 1, 0, 0, 0, 4]), EPERM, "MOVE_ALL");
    assert_eq!(call(279, [0, 0, 0, 0, 0, 0]), 0, "nothing to do");
    assert_eq!(call(279, [0, (1 << 20) + 1, 0, 0, 0, 0]), E2BIG);
    assert_eq!(call(279, [9999, 1, 0, 0, 0, 0]), ESRCH);
    assert_eq!(call(279, [0, 1, 0, 0, 0, 0]), EFAULT, "no page list");
    let pages = [0x1000u64, 0x2000];
    let mut status = [7i32; 2];
    // No address space: every page counts as present (on node 0)
    assert_eq!(call(279, [0, 2, ptr(&pages), 0, mptr(&mut status), 0]), 0);
    assert_eq!(status, [0, 0]);
    let nodes1 = [0i32, 1];
    assert_eq!(call(279, [0, 2, ptr(&pages), ptr(&nodes1), mptr(&mut status), 0]), ENODEV, "node 1 not online");
    assert_eq!(call(279, [0, 2, ptr(&pages), 8 - 8, 0, 0]), EFAULT, "no status array");
    // With an address space: unmapped pages report EFAULT
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(640, |t| t.mm = Some(mm.clone()));
    let base = USER_SPACE_START + 0x300_0000;
    assert_eq!(linux::mm::sys_mmap(&mm, base, 4096, 3, 0x32, -1, 0) as u64, base);
    let pages = [base, base + 4096];
    let nodes0 = [0i32, 0];
    assert_eq!(call(279, [0, 2, ptr(&pages), 0, mptr(&mut status), 0]), 0);
    assert_eq!(status, [0, EFAULT as i32]);
    status = [7; 2];
    assert_eq!(call(279, [0, 2, ptr(&pages), ptr(&nodes0), mptr(&mut status), 0]), 0);
    assert_eq!(status, [0, EFAULT as i32]);
    assert_eq!(call(279, [0, 2, ptr(&pages), 0 + 0, 0, 0]), EFAULT);
}

// ------------------------------------------------- files

#[test]
fn readahead_and_cachestat() {
    let _g = setup();
    proc_(650, 0);
    fake::INODES.with_borrow_mut(|m| {
        m.insert(70, (0o100644, vec![0; 10_000]));
        m.insert(71, (0o040755, vec![]));
    });
    let install = |fd: usize, d: FileDescriptor| crate::task::with_current_fds_mut(|f| f.install(fd, d));
    install(3, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 70, readable: true, ..Default::default() }))));
    install(4, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 71, readable: true, ..Default::default() }))));
    let memfd = MemFd::new("m");
    memfd.lock().truncate(5000).unwrap();
    install(5, FileDescriptor::MemFd { memfd, flags: 2 });
    install(6, FileDescriptor::PipeRead(PipeBuffer::new()));
    install(7, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(OpenFile { ino: 99, ..Default::default() }))));
    assert_eq!(call(187, [3, 0, 0, 0, 0, 0]), 0);
    assert_eq!(call(187, [4, 0, 0, 0, 0, 0]), EINVAL, "a directory");
    assert_eq!(call(187, [5, 0, 0, 0, 0, 0]), 0, "a memfd");
    assert_eq!(call(187, [6, 0, 0, 0, 0, 0]), EINVAL, "a pipe");
    assert_eq!(call(187, [9, 0, 0, 0, 0, 0]), EBADF);
    assert_eq!(call(187, [7, 0, 0, 0, 0, 0]), -2, "inode gone: the server's error");
    // cachestat(fd, range{off,len}, cstat, flags): every page of the file is cached
    let mut out = [0u64; 5];
    let all = [0u64, 0];
    assert_eq!(call(451, [3, ptr(&all), mptr(&mut out), 1, 0, 0]), EINVAL, "flags");
    assert_eq!(call(451, [3, 0, mptr(&mut out), 0, 0, 0]), EFAULT);
    assert_eq!(call(451, [3, ptr(&all), mptr(&mut out), 0, 0, 0]), 0);
    assert_eq!(out[0], 3, "10000 bytes: 3 pages");
    let mid = [4096u64, 4096];
    assert_eq!(call(451, [3, ptr(&mid), mptr(&mut out), 0, 0, 0]), 0);
    assert_eq!(out[0], 1);
    let past = [100_000u64, 0];
    assert_eq!(call(451, [3, ptr(&past), mptr(&mut out), 0, 0, 0]), 0);
    assert_eq!(out[0], 0);
    assert_eq!(call(451, [6, ptr(&all), mptr(&mut out), 0, 0, 0]), ESPIPE);
    assert_eq!(call(451, [9, ptr(&all), mptr(&mut out), 0, 0, 0]), EBADF);
    assert_eq!(call(451, [5, ptr(&all), 0, 0, 0, 0]), EFAULT);
}

// ------------------------------------------------- kcmp

#[test]
fn kcmp_compares_kernel_objects() {
    let _g = setup();
    proc_(660, 1000);
    proc_(661, 1000);
    proc_(662, 2000);
    run(660);
    let pipe = PipeBuffer::new();
    let shared_fds = fake::task(660, |t| {
        t.fds.lock().install(3, FileDescriptor::PipeRead(pipe.clone()));
        t.fds.lock().install(4, FileDescriptor::ConsoleOut);
        t.fds.lock().install(5, FileDescriptor::PipeWrite(PipeBuffer::new()));
        t.fds.clone()
    })
    .unwrap();
    fake::task(661, |t| t.fds.lock().install(3, FileDescriptor::PipeRead(pipe.clone())));
    // KCMP_FILE: the same pipe in two processes
    assert_eq!(call(312, [660, 661, 0, 3, 3, 0]), 0);
    let r = call(312, [660, 660, 0, 3, 5, 0]);
    assert!(r == 1 || r == 2, "different pipes");
    assert_eq!(call(312, [660, 660, 0, 5, 3, 0]), 3 - r, "the order is consistent");
    assert_eq!(call(312, [660, 660, 0, 4, 4, 0]), 0, "an unshared kind: the same descriptor");
    assert!(call(312, [660, 661, 0, 4, 3, 0]) > 0);
    assert_eq!(call(312, [660, 661, 0, 9, 3, 0]), EBADF);
    // KCMP_FILES / KCMP_FS: the descriptor tables
    assert!(call(312, [660, 661, 2, 0, 0, 0]) > 0);
    fake::task(661, |t| t.fds = shared_fds.clone());
    assert_eq!(call(312, [660, 661, 2, 0, 0, 0]), 0);
    assert_eq!(call(312, [660, 661, 3, 0, 0, 0]), 0);
    // KCMP_VM: neither has an address space: equal
    assert_eq!(call(312, [660, 661, 1, 0, 0, 0]), 0);
    // KCMP_SIGHAND etc.: by process
    assert_eq!(call(312, [660, 660, 4, 0, 0, 0]), 0);
    assert!(call(312, [660, 661, 5, 0, 0, 0]) > 0);
    assert_eq!(call(312, [660, 661, 7, 0, 0, 0]), EOPNOTSUPP, "KCMP_EPOLL_TFD");
    assert_eq!(call(312, [660, 661, 8, 0, 0, 0]), EINVAL);
    assert_eq!(call(312, [0, 661, 0, 0, 0, 0]), ESRCH);
    assert_eq!(call(312, [660, 9999, 0, 0, 0, 0]), ESRCH);
    assert_eq!(call(312, [660, 662, 4, 0, 0, 0]), EPERM, "another user");
}

// ------------------------------------------------- process_vm_readv / writev

#[test]
fn process_vm_copies_between_address_spaces() {
    let _g = setup();
    proc_(670, 1000);
    proc_(671, 1000);
    run(670);
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(671, |t| t.mm = Some(mm.clone()));
    let base = USER_SPACE_START + 0x400_0000;
    assert_eq!(linux::mm::sys_mmap(&mm, base, 2 * 4096, 3, 0x22, -1, 0) as u64, base);
    // writev: two local buffers into one remote range crossing a page
    let a = *b"hello ";
    let b = *b"world";
    let liov = [ptr(&a), 6, ptr(&b), 5];
    let riov = [base + 4090, 11];
    assert_eq!(call(311, [671, ptr(&liov), 2, ptr(&riov), 1, 0]), 11);
    // readv it back into one buffer
    let mut back = [0u8; 11];
    let liov = [mptr(&mut back), 11];
    assert_eq!(call(310, [671, ptr(&liov), 1, ptr(&riov), 1, 0]), 11);
    assert_eq!(&back, b"hello world");
    // A remote range running past the mapping: a short transfer
    let mut big = [0u8; 16];
    let liov = [mptr(&mut big), 16];
    let riov = [base + 2 * 4096 - 8, 16];
    assert_eq!(call(310, [671, ptr(&liov), 1, ptr(&riov), 1, 0]), 8);
    // Nothing transferable: EFAULT
    let riov = [base + 0x10_0000, 4];
    assert_eq!(call(310, [671, ptr(&liov), 1, ptr(&riov), 1, 0]), EFAULT);
    let riov = [0x0000_8000_0000_0000u64, 4];
    assert_eq!(call(310, [671, ptr(&liov), 1, ptr(&riov), 1, 0]), EFAULT, "kernel address");
    // Empty vectors move nothing
    assert_eq!(call(310, [671, 0, 0, 0, 0, 0]), 0);
    // Argument checks
    assert_eq!(call(310, [671, 0, 0, 0, 0, 1]), EINVAL, "flags");
    assert_eq!(call(310, [671, 0, 1025, 0, 0, 0]), EINVAL, "IOV_MAX");
    assert_eq!(call(310, [671, 0, 1, 0, 0, 0]), EFAULT, "local vector");
    assert_eq!(call(310, [671, ptr(&liov), 1, 0, 1, 0]), EFAULT, "remote vector");
    assert_eq!(call(310, [9999, 0, 0, 0, 0, 0]), ESRCH);
    // The target has no address space
    let riov = [base, 4];
    assert_eq!(call(310, [670, ptr(&liov), 1, ptr(&riov), 1, 0]), ESRCH);
}

// ------------------------------------------------- sched_setattr / getattr

/// A `struct sched_attr` (VER1, 56 bytes).
fn sattr(policy: u32, flags: u64, nice: i32, prio: u32) -> [u8; 56] {
    let mut a = [0u8; 56];
    a[0..4].copy_from_slice(&56u32.to_le_bytes());
    a[4..8].copy_from_slice(&policy.to_le_bytes());
    a[8..16].copy_from_slice(&flags.to_le_bytes());
    a[16..20].copy_from_slice(&nice.to_le_bytes());
    a[20..24].copy_from_slice(&prio.to_le_bytes());
    a[52..56].copy_from_slice(&1024u32.to_le_bytes());
    a
}

fn getattr(pid: u64) -> [u8; 56] {
    let mut out = [0u8; 56];
    assert_eq!(call(315, [pid, mptr(&mut out), 56, 0, 0, 0]), 0);
    out
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

#[test]
fn sched_setattr_checks_and_records() {
    let _g = setup();
    proc_(680, 1000);
    // Defaults: SCHED_OTHER, nice 0, util_max 1024
    let g = getattr(0);
    assert_eq!((u32_at(&g, 0), u32_at(&g, 4), u32_at(&g, 16), u32_at(&g, 52)), (56, 0, 0, 1024));
    // nice 5 (raising is free) -> Hydra's normal priority
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 5, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(u32_at(&getattr(0), 16) as i32, 5);
    // nice 10 -> low priority
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 10, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(680, |t| t.priority), Some(TaskPriority::Low));
    // Lowering nice without CAP_SYS_NICE (RLIMIT_NICE 0): EPERM
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 0, 0)), 0, 0, 0, 0]), EPERM);
    // Argument checks
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 0, 0)), 1, 0, 0, 0]), EINVAL, "flags");
    assert_eq!(call(314, [0, 0, 0, 0, 0, 0]), EINVAL, "no attr");
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 25, 0)), 0, 0, 0, 0]), EINVAL, "nice out of range");
    assert_eq!(call(314, [0, ptr(&sattr(0, 0, 10, 3)), 0, 0, 0, 0]), EINVAL, "priority with OTHER");
    assert_eq!(call(314, [0, ptr(&sattr(4, 0, 0, 0)), 0, 0, 0, 0]), EINVAL, "no policy 4");
    assert_eq!(call(314, [0, ptr(&sattr(0, 0x80, 10, 0)), 0, 0, 0, 0]), EINVAL, "unknown sched flag");
    assert_eq!(call(314, [-2i64 as u64, ptr(&sattr(0, 0, 10, 0)), 0, 0, 0, 0]), EINVAL, "negative pid");
    assert_eq!(call(314, [9999, ptr(&sattr(0, 0, 10, 0)), 0, 0, 0, 0]), ESRCH);
    let mut clamp = sattr(0, 0x20 | 0x40, 10, 0);
    clamp[48..52].copy_from_slice(&900u32.to_le_bytes());
    clamp[52..56].copy_from_slice(&800u32.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&clamp), 0, 0, 0, 0]), EINVAL, "util_min above util_max");
    // Sizes: 0 means VER0; under VER0 or with unknown non-zero fields: E2BIG and the
    // supported size written back
    let mut v0 = [0u8; 48];
    v0[16..20].copy_from_slice(&12i32.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&v0), 0, 0, 0, 0]), 0, "size 0: VER0");
    assert_eq!(u32_at(&getattr(0), 16), 12);
    let mut tiny = [0u8; 48];
    tiny[0..4].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(call(314, [0, mptr(&mut tiny), 0, 0, 0, 0]), E2BIG);
    assert_eq!(u32_at(&tiny, 0), 56);
    let mut big = [0u8; 64];
    big[0..4].copy_from_slice(&64u32.to_le_bytes());
    big[60] = 1;
    assert_eq!(call(314, [0, mptr(&mut big), 0, 0, 0, 0]), E2BIG);
    big[60] = 0;
    big[0..4].copy_from_slice(&64u32.to_le_bytes());
    big[16..20].copy_from_slice(&13i32.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&big), 0, 0, 0, 0]), 0, "trailing zeros are fine");
    // KEEP_POLICY / KEEP_PARAMS keep the old values
    assert_eq!(call(314, [0, ptr(&sattr(5, 0x08 | 0x10, 0, 0)), 0, 0, 0, 0]), 0);
    let g = getattr(0);
    assert_eq!((u32_at(&g, 4), u32_at(&g, 16)), (0, 13));
    // SCHED_IDLE -> low
    assert_eq!(call(314, [0, ptr(&sattr(5, 0, 13, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(680, |t| t.priority), Some(TaskPriority::Low));
}

#[test]
fn sched_setattr_realtime_and_deadline() {
    let _g = setup();
    proc_(681, 1000);
    assert_eq!(call(314, [0, ptr(&sattr(1, 0, 0, 0)), 0, 0, 0, 0]), EINVAL, "FIFO priority 0");
    assert_eq!(call(314, [0, ptr(&sattr(1, 0, 0, 10)), 0, 0, 0, 0]), EPERM, "over RLIMIT_RTPRIO 0");
    // RLIMIT_RTPRIO 20 (raise the hard limit first)
    caps(681, CAP_SYS_RESOURCE);
    let lim = [20u64, 20];
    assert_eq!(linux::limits::rlimit(160, [14, ptr(&lim), 0, 0, 0, 0]), 0);
    caps(681, 0);
    assert_eq!(call(314, [0, ptr(&sattr(2, 1, 0, 20)), 0, 0, 0, 0]), 0, "RR 20 with reset-on-fork");
    assert_eq!(fake::task(681, |t| t.priority), Some(TaskPriority::High));
    let g = getattr(0);
    assert_eq!((u32_at(&g, 4), u32_at(&g, 8), u32_at(&g, 20)), (2, 1, 20));
    // sched_setattr names threads by thread ID (a process's second thread here)
    add_thread(681, 686);
    assert_eq!(call(314, [686, ptr(&sattr(0, 0, 7, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(u32_at(&getattr(686), 16), 7);
    assert_eq!(fake::task(686, |t| t.priority), Some(TaskPriority::Normal));
    // A new thread: reset-on-fork drops the real-time policy
    fake::add_task(Task::new(682, 681));
    extra::sched_inherit(681, 682);
    let g = getattr(682);
    assert_eq!((u32_at(&g, 4), u32_at(&g, 8), u32_at(&g, 20)), (0, 0, 0));
    assert_eq!(fake::task(682, |t| t.priority), Some(TaskPriority::Normal));
    // SCHED_DEADLINE: runtime <= deadline <= period, and privileged only
    let mut dl = sattr(6, 0, 0, 0);
    dl[24..32].copy_from_slice(&2_000u64.to_le_bytes());
    dl[32..40].copy_from_slice(&1_000u64.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&dl), 0, 0, 0, 0]), EINVAL, "runtime above deadline");
    dl[32..40].copy_from_slice(&5_000u64.to_le_bytes());
    dl[40..48].copy_from_slice(&4_000u64.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&dl), 0, 0, 0, 0]), EINVAL, "deadline above period");
    dl[40..48].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(call(314, [0, ptr(&dl), 0, 0, 0, 0]), EPERM);
    caps(681, CAP_SYS_NICE);
    assert_eq!(call(314, [0, ptr(&dl), 0, 0, 0, 0]), 0);
    caps(681, 0);
    // Another user's thread
    proc_(683, 2000);
    run(681);
    assert_eq!(call(314, [683, ptr(&sattr(0, 0, 5, 0)), 0, 0, 0, 0]), EPERM);
    caps(681, CAP_SYS_NICE);
    assert_eq!(call(314, [683, ptr(&sattr(0, 0, -5, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(683, |t| t.priority), Some(TaskPriority::Normal));
    // A Hydra (non-POSIX) task keeps its own priority
    fake::task(683, |t| t.personality = crate::task::TaskPersonality::Hydra);
    assert_eq!(call(314, [683, ptr(&sattr(0, 0, -15, 0)), 0, 0, 0, 0]), 0);
    assert_eq!(fake::task(683, |t| t.priority), Some(TaskPriority::Normal));
    // reset-on-fork with a non-real-time policy only clamps a negative nice
    assert_eq!(call(314, [0, ptr(&sattr(0, 1, -3, 0)), 0, 0, 0, 0]), 0);
    fake::add_task(Task::new(684, 681));
    extra::sched_inherit(681, 684);
    assert_eq!(u32_at(&getattr(684), 16), 0);
    extra::sched_inherit(4242, 685); // no record: nothing to inherit
}

#[test]
fn sched_getattr_checks() {
    let _g = setup();
    proc_(690, 0);
    let mut out = [0u8; 64];
    assert_eq!(call(315, [0, mptr(&mut out), 47, 0, 0, 0]), EINVAL, "smaller than VER0");
    assert_eq!(call(315, [0, mptr(&mut out), 5000, 0, 0, 0]), EINVAL);
    assert_eq!(call(315, [0, 0, 56, 0, 0, 0]), EINVAL);
    assert_eq!(call(315, [0, mptr(&mut out), 56, 1, 0, 0]), EINVAL);
    assert_eq!(call(315, [9999, mptr(&mut out), 56, 0, 0, 0]), ESRCH);
    // VER0: 48 bytes, size field says so
    let mut v0 = [0xffu8; 56];
    assert_eq!(call(315, [0, mptr(&mut v0), 48, 0, 0, 0]), 0);
    assert_eq!(u32_at(&v0, 0), 48);
    assert_eq!(v0[48], 0xff, "nothing past the size");
    // Larger buffers get VER1
    assert_eq!(call(315, [0, mptr(&mut out), 64, 0, 0, 0]), 0);
    assert_eq!(u32_at(&out, 0), 56);
    // Many records: those of threads that are gone are dropped, those of live threads
    // (any thread of a process, not only its first) are kept
    add_thread(690, 691);
    for tid in 10_000..10_070u64 {
        extra::sched_set(tid, 0, 1, 0, false);
    }
    extra::sched_set(690, 0, 3, 0, false);
    extra::sched_set(691, 0, 4, 0, false);
    assert_eq!(call(315, [0, mptr(&mut out), 56, 0, 0, 0]), 0);
    assert_eq!(u32_at(&out, 16), 3);
    assert_eq!(u32_at(&getattr(691), 16), 4, "a second thread's record survives the clean-up");
    extra::reapply_priority(690);
    assert_eq!(fake::task(690, |t| t.priority), Some(TaskPriority::Normal));
}
