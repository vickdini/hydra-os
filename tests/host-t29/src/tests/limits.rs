//! `src/compat/linux/limits.rs`: resource limits (get/set/prlimit and their checks),
//! priorities (nice, scheduling policy and parameters, I/O priority), CPU affinity, the
//! mlock family and `/proc/<pid>/limits`.

use super::common::*;
use crate::compat::linux::limits;
use crate::memory::vm::{Mm, PROT_READ, PROT_WRITE, USER_SPACE_START};
use std::sync::Arc;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const INF: u64 = u64::MAX;

const GETRLIMIT: u64 = 97;
const SETRLIMIT: u64 = 160;
const PRLIMIT64: u64 = 302;
const RLIMIT_FSIZE: u64 = 1;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_NPROC: u64 = 6;
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_MEMLOCK: u64 = 8;
const RLIMIT_NICE: u64 = 13;
const RLIMIT_RTPRIO: u64 = 14;

const CAP_IPC_LOCK: u64 = 1 << 14;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYS_NICE: u64 = 1 << 23;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

/// A process `pid` with a fresh limits record, running.
fn proc_(pid: u64, uid: u32) {
    limits::on_exit(pid);
    spawn_as(pid, 1, uid, uid);
    run(pid);
}

fn get(res: u64) -> (u64, u64) {
    let mut v = [0u64; 2];
    assert_eq!(limits::rlimit(GETRLIMIT, [res, mptr(&mut v), 0, 0, 0, 0]), 0);
    (v[0], v[1])
}

fn set(res: u64, soft: u64, hard: u64) -> i64 {
    let v = [soft, hard];
    limits::rlimit(SETRLIMIT, [res, ptr(&v), 0, 0, 0, 0])
}

fn caps(pid: u64, effective: u64) {
    fake::task(pid, |t| t.caps.effective = effective);
}

#[test]
fn defaults_follow_ubuntu() {
    let _g = setup();
    proc_(500, 0);
    assert_eq!(get(RLIMIT_STACK), (8 << 20, INF));
    assert_eq!(get(RLIMIT_NOFILE), (1024, 1024));
    assert_eq!(get(RLIMIT_NPROC), (15_000, 15_000));
    assert_eq!(get(RLIMIT_NICE), (0, 0));
    assert_eq!(get(0), (INF, INF), "RLIMIT_CPU unlimited");
    assert_eq!(limits::rlimit(GETRLIMIT, [16, 0, 0, 0, 0, 0]), EINVAL, "resource out of range");
    assert_eq!(limits::rlimit(SETRLIMIT, [16, 0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(limits::rlimit(GETRLIMIT, [0, 0, 0, 0, 0, 0]), EFAULT, "null buffer");
    assert_eq!(limits::rlimit(SETRLIMIT, [0, 0, 0, 0, 0, 0]), EFAULT);
}

#[test]
fn setrlimit_checks() {
    let _g = setup();
    proc_(501, 1000);
    // Lowering is always allowed, raising the hard limit is not without CAP_SYS_RESOURCE
    assert_eq!(set(RLIMIT_FSIZE, 4096, 8192), 0);
    assert_eq!(get(RLIMIT_FSIZE), (4096, 8192));
    assert_eq!(set(RLIMIT_FSIZE, 4096, 9000), EPERM);
    assert_eq!(set(RLIMIT_FSIZE, 9000, 8192), EINVAL, "soft above hard");
    assert_eq!(set(RLIMIT_FSIZE, 8192, 8192), 0, "soft up to hard");
    caps(501, CAP_SYS_RESOURCE);
    assert_eq!(set(RLIMIT_FSIZE, INF, INF), 0);
    // RLIMIT_NOFILE never past the descriptor table, even with the capability
    assert_eq!(set(RLIMIT_NOFILE, 1024, 4096), EPERM);
    assert_eq!(set(RLIMIT_NOFILE, 512, 1024), 0);
    assert_eq!(limits::nofile(), 512);
}

#[test]
fn nofile_and_fsize_follow_the_current_process() {
    let _g = setup();
    // No current task: the table's size and no file size limit
    assert_eq!(limits::nofile(), 1024);
    assert_eq!(limits::fsize(), INF);
    proc_(502, 0);
    assert_eq!(limits::fsize(), INF, "no record yet: unlimited");
    assert_eq!(set(RLIMIT_FSIZE, 100, 200), 0);
    assert_eq!(limits::fsize(), 100);
    // While the scheduler lock is held (callers may hold it): the defaults
    let g = crate::task::SCHEDULER.lock();
    assert_eq!(limits::nofile(), 1024);
    assert_eq!(limits::fsize(), INF);
    drop(g);
}

#[test]
fn prlimit64_on_self_and_others() {
    let _g = setup();
    proc_(510, 1000);
    proc_(511, 1000);
    proc_(512, 2000);
    run(510);
    let new = [10u64, 20];
    let mut old = [0u64; 2];
    // Own process (pid 0): returns the old value and sets the new one
    assert_eq!(limits::rlimit(PRLIMIT64, [0, RLIMIT_FSIZE, ptr(&new), mptr(&mut old), 0, 0]), 0);
    assert_eq!(old, [INF, INF]);
    assert_eq!(get(RLIMIT_FSIZE), (10, 20));
    // Same user: allowed
    assert_eq!(limits::rlimit(PRLIMIT64, [511, RLIMIT_FSIZE, ptr(&new), 0, 0, 0]), 0);
    run(511);
    assert_eq!(get(RLIMIT_FSIZE), (10, 20));
    run(510);
    // Another user: EPERM, unless CAP_SYS_RESOURCE
    assert_eq!(limits::rlimit(PRLIMIT64, [512, RLIMIT_FSIZE, 0, mptr(&mut old), 0, 0]), EPERM);
    caps(510, CAP_SYS_RESOURCE);
    assert_eq!(limits::rlimit(PRLIMIT64, [512, RLIMIT_FSIZE, 0, mptr(&mut old), 0, 0]), 0);
    assert_eq!(old, [INF, INF]);
    // Bad arguments
    assert_eq!(limits::rlimit(PRLIMIT64, [999, RLIMIT_FSIZE, 0, 0, 0, 0]), ESRCH, "no such process");
    assert_eq!(limits::rlimit(PRLIMIT64, [-5i64 as u64, RLIMIT_FSIZE, 0, 0, 0, 0]), ESRCH, "negative pid");
    assert_eq!(limits::rlimit(PRLIMIT64, [0, 99, 0, 0, 0, 0]), EINVAL, "bad resource");
    let bad = [30u64, 20];
    assert_eq!(limits::rlimit(PRLIMIT64, [0, RLIMIT_FSIZE, ptr(&bad), 0, 0, 0]), EINVAL, "soft above hard");
}

#[test]
fn clone_exit_and_exec_carry_limits() {
    let _g = setup();
    proc_(520, 0);
    assert_eq!(set(RLIMIT_FSIZE, 1, 2), 0);
    limits::on_exit(521);
    limits::on_clone(520, 520, 521, 521, false);
    spawn(521, 520);
    run(521);
    assert_eq!(get(RLIMIT_FSIZE), (1, 2), "a child copies its parent's limits");
    // A thread (same process) does not get a record of its own
    limits::on_clone(521, 521, 522, 521, true);
    limits::on_exec(521);
    assert_eq!(get(RLIMIT_FSIZE), (1, 2), "limits survive execve");
    limits::on_exit(521);
    assert_eq!(get(RLIMIT_FSIZE), (INF, INF), "gone with the process");
}

#[test]
fn may_fork_counts_the_users_processes() {
    let _g = setup();
    proc_(530, 1000);
    assert!(limits::may_fork(), "far below the default");
    assert_eq!(set(RLIMIT_NPROC, 2, 2), 0);
    assert!(limits::may_fork(), "one process of 2");
    proc_(531, 1000);
    run(530);
    assert!(!limits::may_fork(), "two of 2");
    // Threads do not count as processes; dead tasks do not count at all
    fake::task(531, |t| t.state = TaskState::Dead);
    assert!(limits::may_fork());
    fake::task(531, |t| t.state = TaskState::Ready);
    // CAP_SYS_RESOURCE or CAP_SYS_ADMIN lifts the limit
    caps(530, CAP_SYS_ADMIN);
    assert!(limits::may_fork());
    caps(530, 0);
    assert_eq!(set(RLIMIT_NPROC, INF, INF), EPERM, "raising the hard limit");
    // Root is never limited
    proc_(532, 0);
    assert_eq!(set(RLIMIT_NPROC, 0, 0), 0);
    caps(532, 0);
    assert!(limits::may_fork());
}

#[test]
fn nice_values() {
    let _g = setup();
    proc_(540, 1000);
    // getpriority reports 20 - nice
    assert_eq!(limits::getpriority(0, 0), 20);
    assert_eq!(limits::setpriority(0, 0, 5), 0, "raising nice is free");
    assert_eq!(limits::getpriority(0, 0), 15);
    assert_eq!(limits::setpriority(0, 0, 100), 0, "clamped to 19");
    assert_eq!(limits::getpriority(0, 0), 1);
    assert_eq!(limits::setpriority(0, 0, 0), EACCES, "lowering needs CAP_SYS_NICE or RLIMIT_NICE");
    // RLIMIT_NICE 30 allows nice down to -10 (raising the soft limit within the hard one)
    caps(540, CAP_SYS_RESOURCE);
    assert_eq!(set(RLIMIT_NICE, 30, 30), 0);
    caps(540, 0);
    assert_eq!(limits::setpriority(0, 0, -10i64 as u64), 0);
    assert_eq!(limits::getpriority(0, 0), 30);
    assert_eq!(limits::setpriority(0, 0, -11i64 as u64), EACCES);
    caps(540, CAP_SYS_NICE);
    assert_eq!(limits::setpriority(0, 0, -50i64 as u64), 0, "clamped to -20");
    assert_eq!(limits::getpriority(0, 0), 40);
    // Bad selectors
    assert_eq!(limits::getpriority(7, 0), EINVAL);
    assert_eq!(limits::getpriority(0, 9999), ESRCH);
    assert_eq!(limits::setpriority(7, 0, 0), EINVAL);
}

#[test]
fn priority_of_groups_and_users() {
    let _g = setup();
    proc_(550, 1000);
    // A child: same process group
    limits::on_exit(551);
    spawn_as(551, 550, 1000, 1000);
    // PRIO_PGRP of our group: both processes' threads
    assert_eq!(limits::setpriority(1, 0, 7), 0);
    run(551);
    assert_eq!(limits::getpriority(0, 0), 13);
    assert_eq!(limits::getpriority(1, 550), 13);
    assert_eq!(limits::getpriority(1, 777), ESRCH, "empty group");
    // PRIO_USER: every thread of uid 1000
    assert_eq!(limits::setpriority(2, 1000, 3), EACCES, "lowering nice from 7 to 3");
    assert_eq!(limits::setpriority(2, 1000, 10), 0);
    assert_eq!(limits::getpriority(2, 0), 10);
    run(550);
    assert_eq!(limits::getpriority(0, 551), 10, "a thread named by id");
    assert_eq!(limits::getpriority(2, 4242), ESRCH, "nobody");
}

#[test]
fn sched_set_and_get() {
    let _g = setup();
    proc_(560, 1000);
    let prio = |p: i32| p;
    // sched_setscheduler(0, SCHED_OTHER, {0})
    assert_eq!(limits::sched_set(0, Some(0), ptr(&prio(0))), 0);
    assert_eq!(limits::sched_getscheduler(0), 0);
    assert_eq!(limits::sched_set(0, Some(0), ptr(&prio(1))), EINVAL, "priority must be 0");
    assert_eq!(limits::sched_set(0, Some(1), ptr(&prio(0))), EINVAL, "FIFO needs 1..99");
    assert_eq!(limits::sched_set(0, Some(1), ptr(&prio(10))), EPERM, "RLIMIT_RTPRIO 0");
    assert_eq!(limits::sched_set(0, Some(9), ptr(&prio(0))), EINVAL, "no such policy");
    assert_eq!(limits::sched_set(0, Some(0), 0), EFAULT);
    assert_eq!(limits::sched_set(-1i64 as u64, Some(0), ptr(&prio(0))), EINVAL);
    assert_eq!(limits::sched_set(9999, Some(0), ptr(&prio(0))), ESRCH);
    // RLIMIT_RTPRIO 20 (needs CAP_SYS_RESOURCE to raise the hard limit)
    caps(560, CAP_SYS_RESOURCE);
    assert_eq!(set(RLIMIT_RTPRIO, 20, 20), 0);
    caps(560, 0);
    assert_eq!(limits::sched_set(0, Some(2 | 0x4000_0000), ptr(&prio(20))), 0, "SCHED_RR with reset-on-fork");
    assert_eq!(limits::sched_getscheduler(0), 2 | 0x4000_0000);
    let mut out = 0i32;
    assert_eq!(limits::sched_getparam(0, mptr(&mut out)), 0);
    assert_eq!(out, 20);
    // sched_setparam keeps the policy
    assert_eq!(limits::sched_set(0, None, ptr(&prio(5))), 0);
    assert_eq!(limits::sched_getscheduler(0), 2 | 0x4000_0000);
    assert_eq!(limits::sched_getparam(0, mptr(&mut out)), 0);
    assert_eq!(out, 5);
    assert_eq!(limits::sched_getparam(0, 0), EFAULT);
    assert_eq!(limits::sched_getparam(9999, mptr(&mut out)), ESRCH);
    assert_eq!(limits::sched_getscheduler(9999), ESRCH);
    // A real-time thread runs at Hydra's high priority
    assert_eq!(fake::task(560, |t| t.priority), Some(crate::fake::TaskPriority::High));
}

#[test]
fn affinity_needs_an_online_cpu() {
    let _g = setup();
    proc_(570, 0);
    let one = 1u64;
    let two = 2u64;
    assert_eq!(limits::sched_setaffinity(0, 8, ptr(&one)), 0);
    assert_eq!(limits::sched_setaffinity(0, 8, ptr(&two)), EINVAL, "CPU 1 is not online");
    fake::ONLINE_CPUS.set(4);
    assert_eq!(limits::sched_setaffinity(0, 8, ptr(&two)), 0);
    fake::ONLINE_CPUS.set(64);
    let high = 1u64 << 63;
    assert_eq!(limits::sched_setaffinity(0, 8, ptr(&high)), 0, "64 CPUs: all bits");
    assert_eq!(limits::sched_setaffinity(0, 1, ptr(&one)), 0, "a 1-byte mask");
    assert_eq!(limits::sched_setaffinity(0, 0, ptr(&one)), EINVAL, "empty mask");
    assert_eq!(limits::sched_setaffinity(0, 8, 0), EFAULT);
    assert_eq!(limits::sched_setaffinity(9999, 8, ptr(&one)), ESRCH);
}

#[test]
fn io_priorities() {
    let _g = setup();
    proc_(580, 1000);
    const GET: u64 = 252;
    const SET: u64 = 251;
    // Never set: class none, level 4
    assert_eq!(limits::ioprio(GET, 1, 0, 0), 4);
    let be3 = (2 << 13) | 3;
    assert_eq!(limits::ioprio(SET, 1, 0, be3), 0);
    assert_eq!(limits::ioprio(GET, 1, 0, 0), be3 as i64);
    assert_eq!(limits::ioprio(SET, 1, 0, (2 << 13) | 8), EINVAL, "levels 0-7");
    assert_eq!(limits::ioprio(SET, 1, 0, 1 << 13), EPERM, "real-time class needs privilege");
    assert_eq!(limits::ioprio(SET, 1, 0, 3 << 13), 0, "idle class");
    assert_eq!(limits::ioprio(SET, 1, 0, 5 << 13), EINVAL, "no such class");
    assert_eq!(limits::ioprio(SET, 9, 0, 0), EINVAL, "bad which");
    assert_eq!(limits::ioprio(SET, 1, 9999, 0), ESRCH);
    caps(580, CAP_SYS_ADMIN);
    assert_eq!(limits::ioprio(SET, 1, 0, 1 << 13), 0);
    // By process group and by user
    assert_eq!(limits::ioprio(SET, 2, 0, be3), 0);
    assert_eq!(limits::ioprio(GET, 3, 0, 0), be3 as i64);
    assert_eq!(limits::ioprio(GET, 3, 4242, 0), ESRCH);
    // A new thread inherits the I/O priority
    limits::on_clone(580, 580, 581, 581, false);
    spawn(581, 580);
    run(581);
    assert_eq!(limits::ioprio(GET, 1, 0, 0), be3 as i64);
}

/// The current process gets an address space with `n` read-write pages at `base`.
fn map_pages(pid: u64, base: u64, n: u64) -> Arc<spin::Mutex<Mm>> {
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    let r = linux::mm::sys_mmap(&mm, base, n * 4096, (PROT_READ | PROT_WRITE) as u64, 0x22 | 0x10, -1, 0);
    assert_eq!(r as u64, base);
    fake::task(pid, |t| t.mm = Some(mm.clone()));
    mm
}

#[test]
fn mlock_family() {
    let _g = setup();
    proc_(590, 1000);
    let base = USER_SPACE_START + 0x1000_0000;
    let _mm = map_pages(590, base, 8);
    // Locking needs mapped memory and stays within RLIMIT_MEMLOCK (8 MiB)
    assert_eq!(limits::mlock(149, [base, 2 * 4096, 0, 0, 0, 0]), 0);
    assert_eq!(limits::locked_kib(590), 8);
    assert_eq!(limits::mlock(149, [base + 4096, 2 * 4096, 0, 0, 0, 0]), 0, "overlapping ranges merge");
    assert_eq!(limits::locked_kib(590), 12);
    assert_eq!(limits::mlock(149, [base + 100, 1, 0, 0, 0, 0]), 0, "page-rounded");
    assert_eq!(limits::locked_kib(590), 12);
    assert_eq!(limits::mlock(149, [base + 7 * 4096, 2 * 4096, 0, 0, 0, 0]), ENOMEM, "past the mapping");
    assert_eq!(limits::mlock(149, [base, 0, 0, 0, 0, 0]), 0, "empty range");
    assert_eq!(limits::mlock(149, [u64::MAX - 10, 100, 0, 0, 0, 0]), EINVAL, "wraps");
    // munlock splits a range
    assert_eq!(limits::mlock(150, [base + 4096, 4096, 0, 0, 0, 0]), 0);
    assert_eq!(limits::locked_kib(590), 8);
    // mlock2 accepts MLOCK_ONFAULT only
    assert_eq!(limits::mlock(325, [base + 4096, 4096, 1, 0, 0, 0]), 0);
    assert_eq!(limits::mlock(325, [base, 4096, 2, 0, 0, 0]), EINVAL);
    // A small limit
    assert_eq!(set(RLIMIT_MEMLOCK, 16384, 16384), 0);
    assert_eq!(limits::mlock(149, [base + 4 * 4096, 4 * 4096, 0, 0, 0, 0]), ENOMEM);
    assert_eq!(set(RLIMIT_MEMLOCK, 0, 0), 0);
    assert_eq!(limits::mlock(149, [base + 4 * 4096, 4096, 0, 0, 0, 0]), EPERM, "limit 0: EPERM");
    caps(590, CAP_IPC_LOCK);
    assert_eq!(limits::mlock(149, [base + 4 * 4096, 4096, 0, 0, 0, 0]), 0, "CAP_IPC_LOCK: no limit");
    caps(590, 0);
    // mlockall / munlockall
    assert_eq!(limits::mlock(151, [0, 0, 0, 0, 0, 0]), EINVAL);
    assert_eq!(limits::mlock(151, [4, 0, 0, 0, 0, 0]), EINVAL, "MCL_ONFAULT alone");
    assert_eq!(limits::mlock(151, [8, 0, 0, 0, 0, 0]), EINVAL, "unknown flag");
    assert_eq!(limits::mlock(151, [1, 0, 0, 0, 0, 0]), EPERM, "MCL_CURRENT over a 0 limit");
    assert_eq!(limits::mlock(151, [2, 0, 0, 0, 0, 0]), 0, "MCL_FUTURE alone");
    assert_eq!(limits::mlock(152, [0; 6]), 0);
    assert_eq!(limits::locked_kib(590), 0);
    caps(590, CAP_SYS_RESOURCE);
    assert_eq!(set(RLIMIT_MEMLOCK, 1 << 20, 1 << 20), 0);
    assert_eq!(set(RLIMIT_MEMLOCK, 4096, 1 << 20), 0);
    assert_eq!(limits::mlock(151, [1, 0, 0, 0, 0, 0]), ENOMEM, "MCL_CURRENT over a small limit");
    assert_eq!(set(RLIMIT_MEMLOCK, 1 << 20, 1 << 20), 0);
    assert_eq!(limits::mlock(151, [3, 0, 0, 0, 0, 0]), 0);
    assert_eq!(limits::locked_kib(590), 32, "every mapping");
    // execve drops the locks
    limits::on_exec(590);
    assert_eq!(limits::locked_kib(590), 0);
}

#[test]
fn mlock_without_an_address_space() {
    let _g = setup();
    proc_(595, 0);
    assert_eq!(limits::mlock(149, [0x10000, 4096, 0, 0, 0, 0]), ENOMEM);
    assert_eq!(limits::mlock(151, [1, 0, 0, 0, 0, 0]), ENOMEM);
    assert_eq!(limits::locked_kib(4242), 0);
}

#[test]
fn proc_limits_text() {
    let _g = setup();
    proc_(599, 0);
    assert_eq!(set(RLIMIT_FSIZE, 4096, INF), 0);
    let t = limits::limits_text(599);
    let lines: Vec<&str> = t.lines().collect();
    assert_eq!(lines.len(), 17);
    assert!(lines[0].starts_with("Limit"));
    assert!(lines[2].starts_with("Max file size") && lines[2].contains("4096") && lines[2].contains("unlimited"));
    assert!(lines[8].starts_with("Max open files") && lines[8].contains("1024"));
    assert!(lines[16].starts_with("Max realtime timeout") && lines[16].trim_end().ends_with("us"));
}
