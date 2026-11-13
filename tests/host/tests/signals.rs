//! Tests for signals and the process table (`src/compat/linux/proc.rs`, compiled as
//! `compat::linux::proc_real`): who may signal whom, queued real-time signals, and the
//! argument checks of tgkill, setpgid and sigaltstack. Expected values were checked on
//! Linux 5.15 (tests/linux/signals_test.c, which also runs under QEMU).
//!
//! The process table is global: each test registers its own pids. The caller is the
//! fake current task (`fake::IDS`, `UID`, `CREDS`, `CAPS`); other processes' credentials
//! come from tasks placed in `fake::SIBLINGS`.

use hydra_hosttests::compat::linux::proc_real as proc;
use hydra_hosttests::fake;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;

const SIGUSR1: u64 = 10;
const SIGTERM: u64 = 15;
const SIGCONT: u64 = 18;
const SIGRT: u32 = 34; // glibc's SIGRTMIN
const SI_QUEUE: i32 = -1;
const CAP_KILL: u64 = 1 << 5;

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

/// Becomes process `pid` (a new session) running as `uid` (effective `euid`), without
/// capabilities.
fn be(pid: u64, uid: u32, euid: u32) {
    proc::register_process(pid, 0, pid, None);
    fake::IDS.set((pid, pid));
    fake::UID.set(uid);
    fake::CREDS.set((euid, euid));
    fake::CAPS.set(Some(0));
}

/// Another process `pid` with real uid `uid` and saved uid `suid`; in the caller's
/// session when `same_session`.
fn other(pid: u64, uid: u32, suid: u32, same_session: bool) {
    let me = fake::IDS.get().1;
    proc::register_process(pid, 0, pid, same_session.then_some(me));
    let mut t = fake::Task::sibling(pid);
    t.tgid = pid;
    t.uid = uid;
    t.suid = suid;
    t.euid = uid;
    fake::SIBLINGS.with_borrow_mut(|v| v.push(t));
}

fn queued(pid: u64, sig: u64) -> bool {
    proc::signal_queued(pid, None, sig as u32)
}

#[test]
fn another_users_process_cannot_be_signalled() {
    be(8100, 1000, 1000);
    other(8101, 0, 0, false);
    assert_eq!(proc::sys_kill(8101, SIGTERM), EPERM);
    assert!(!queued(8101, SIGTERM), "nothing was sent");
    assert_eq!(proc::sys_kill(8101, 0), EPERM, "signal 0 is checked too");
    other(8102, 1000, 1000, false);
    assert_eq!(proc::sys_kill(8102, SIGTERM), 0, "a process of the same user");
    assert!(queued(8102, SIGTERM));
}

/// Linux: the caller's real or effective uid against the target's real or saved uid.
#[test]
fn the_uid_rules_follow_linux() {
    be(8110, 1000, 2000); // real 1000, effective 2000
    other(8111, 2000, 0, false); // real uid = our euid
    other(8112, 0, 1000, false); // saved uid = our uid
    other(8113, 2000 + 1, 2000 + 1, false);
    assert_eq!(proc::sys_kill(8111, SIGUSR1), 0);
    assert_eq!(proc::sys_kill(8112, SIGUSR1), 0);
    assert_eq!(proc::sys_kill(8113, SIGUSR1), EPERM);
    fake::CAPS.set(Some(CAP_KILL));
    assert_eq!(proc::sys_kill(8113, SIGUSR1), 0, "CAP_KILL may signal anyone");
}

#[test]
fn sigcont_is_allowed_within_the_session() {
    be(8120, 1000, 1000);
    other(8121, 0, 0, true);
    other(8122, 0, 0, false);
    assert_eq!(proc::sys_kill(8121, SIGCONT), 0, "same session");
    assert_eq!(proc::sys_kill(8121, SIGTERM), EPERM, "only SIGCONT");
    assert_eq!(proc::sys_kill(8122, SIGCONT), EPERM, "another session");
}

/// A group succeeds if any member got the signal; otherwise its last error.
#[test]
fn a_process_group_needs_one_permitted_member() {
    be(8130, 1000, 1000);
    other(8131, 0, 0, false);
    other(8132, 1000, 1000, false);
    other(8133, 0, 0, false);
    // 8131 leads group 8131 (its own session); put 8132 in it as a member would be
    proc::register_process(8134, 8131, 8134, Some(8131));
    let mut t = fake::Task::sibling(8134);
    (t.tgid, t.uid, t.suid) = (8134, 1000, 1000);
    fake::SIBLINGS.with_borrow_mut(|v| v.push(t));
    assert_eq!(proc::sys_kill(-8131, SIGUSR1), 0, "8134 is ours");
    assert!(queued(8134, SIGUSR1) && !queued(8131, SIGUSR1));
    assert_eq!(proc::sys_kill(-8133, SIGUSR1), EPERM, "a group of root's only");
}

#[test]
fn a_zombie_can_be_signalled_with_its_owners_permission() {
    be(8140, 1000, 1000);
    other(8141, 1000, 1000, false);
    other(8142, 0, 0, false);
    // Their last threads exit: zombies (parent 0 reaps later) keeping their credentials
    fake::SIBLINGS.with_borrow_mut(|v| v.clear());
    proc::thread_exited(8141, 8141, 0, 0, (1000, 1000));
    proc::thread_exited(8142, 8142, 0, 0, (0, 0));
    assert!(proc::process_exists(8141), "kept as a zombie for its parent");
    assert_eq!(proc::sys_kill(8141, 0), 0, "a zombie still exists");
    assert_eq!(proc::sys_kill(8142, 0), EPERM, "root's zombie");
}

#[test]
fn tgkill_needs_positive_ids() {
    be(8150, 1000, 1000);
    assert_eq!(proc::sys_tgkill(0, 8150, 0), EINVAL);
    assert_eq!(proc::sys_tgkill(8150, 0, 0), EINVAL);
    assert_eq!(proc::sys_tkill(0, 0), EINVAL);
    assert_eq!(proc::sys_tgkill(8150, 8159, 0), ESRCH, "no such thread");
    assert_eq!(proc::sys_tgkill(8150, 8150, 0), 0);
}

#[test]
fn setpgid_refuses_a_negative_group() {
    be(8160, 1000, 1000);
    assert_eq!(proc::setpgid(0, (-1i64) as u64), EINVAL);
}

/// `siginfo_t` for sigqueue: signo, errno, code, then pid/uid and the value.
fn queue_info(value: u64) -> [u64; 16] {
    let mut i = [0u64; 16];
    i[1] = SI_QUEUE as u32 as u64;
    i[3] = value;
    i
}

#[test]
fn real_time_signals_queue_each_instance_with_its_value() {
    be(8170, 1000, 1000);
    for v in 1..=3u64 {
        let info = queue_info(100 + v);
        assert_eq!(proc::sys_rt_sigqueueinfo(8170, None, SIGRT as u64, info.as_ptr() as u64), 0);
    }
    for v in 1..=3u64 {
        let s = proc::take_signal_info(bit(SIGRT)).expect("one more queued instance");
        assert_eq!((s.signo, s.code, s.value), (SIGRT, SI_QUEUE, 100 + v), "in order, each with its value");
    }
    assert!(proc::take_signal_info(bit(SIGRT)).is_none(), "three, not more");
    // A standard signal sent twice is pending once
    proc::sys_kill(8170, SIGUSR1);
    proc::sys_kill(8170, SIGUSR1);
    assert!(proc::take_signal_info(bit(SIGUSR1 as u32)).is_some());
    assert!(proc::take_signal_info(bit(SIGUSR1 as u32)).is_none());
}

#[test]
fn ignoring_a_signal_drops_its_queued_instances() {
    be(8180, 1000, 1000);
    for v in 1..=3u64 {
        let info = queue_info(v);
        proc::sys_rt_sigqueueinfo(8180, None, SIGRT as u64, info.as_ptr() as u64);
    }
    // struct sigaction: handler SIG_IGN (1), flags, restorer, mask
    let act: [u64; 4] = [1, 0, 0, 0];
    assert_eq!(proc::sys_rt_sigaction(SIGRT as u64, act.as_ptr() as u64, 0, 8), 0);
    assert!(proc::take_signal_info(bit(SIGRT)).is_none(), "every instance went");
}

/// `stack_t`: ss_sp, ss_flags (+ padding), ss_size.
fn stack_t(sp: u64, flags: u32, size: u64) -> [u64; 3] {
    [sp, flags as u64, size]
}

#[test]
fn sigaltstack_checks_size_flags_and_the_stack_in_use() {
    be(8190, 1000, 1000);
    let small = stack_t(0x10_0000, 0, 1024);
    assert_eq!(proc::sys_sigaltstack(small.as_ptr() as u64, 0, 0), ENOMEM, "below MINSIGSTKSZ");
    let bad = stack_t(0x10_0000, 0x1234, 65536);
    assert_eq!(proc::sys_sigaltstack(bad.as_ptr() as u64, 0, 0), EINVAL, "unknown flags");
    let good = stack_t(0x10_0000, 0, 65536);
    assert_eq!(proc::sys_sigaltstack(good.as_ptr() as u64, 0, 0), 0);
    // Running on it (the stack pointer inside it): reported, and it cannot be changed
    let on = 0x10_0000 + 4096;
    let mut old = [0u64; 3];
    assert_eq!(proc::sys_sigaltstack(0, old.as_mut_ptr() as u64, on), 0);
    assert_eq!(old[1] as u32 & 1, 1, "SS_ONSTACK while on it");
    assert_eq!(proc::sys_sigaltstack(good.as_ptr() as u64, 0, on), EPERM);
}
