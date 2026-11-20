//! `timerfd` (`src/compat/linux/timerfd.rs`): arming, expiry counting, periodic overruns,
//! absolute times on both clocks, blocking reads that end at the timer's deadline.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::timerfd::{sys_create, sys_gettime, sys_settime, TimerFd};
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::task::wait::Deadline;
use std::sync::Arc;

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const TFD_NONBLOCK: u64 = 0o4000;
const TFD_CLOEXEC: u64 = 0o2000000;
const ABSTIME: u64 = 1;

fn timer(fd: i64) -> Arc<TimerFd> {
    match fake::fd::get(fd) {
        Some(FileDescriptor::TimerFd(t)) => t,
        _ => panic!("fd {fd} is not a timerfd"),
    }
}

fn settime(fd: i64, flags: u64, spec: Spec) -> i64 {
    sys_settime(fd as u64, flags, ptr(&spec), 0)
}

fn gettime(fd: i64) -> Spec {
    let mut s = Spec::default();
    assert_eq!(sys_gettime(fd as u64, mptr(&mut s)), 0);
    s
}

fn read(t: &Arc<TimerFd>) -> Result<u64, i64> {
    let mut b = [0u8; 8];
    let r = t.read(&mut b);
    if r < 0 {
        Err(r)
    } else {
        assert_eq!(r, 8);
        Ok(u64::from_ne_bytes(b))
    }
}

#[test]
fn create_checks_clock_and_flags() {
    fake::reset();
    for bad in [2u64, 3, 4, 5, 6, 10, 99] {
        assert_eq!(sys_create(bad, 0), EINVAL, "clock {bad}");
    }
    assert_eq!(sys_create(1, 1), EINVAL, "unknown flag");
    for clock in [0u64, 1, 7, 8, 9] {
        assert!(sys_create(clock, 0) >= 3, "clock {clock}");
    }
    let fd = sys_create(1, TFD_NONBLOCK | TFD_CLOEXEC);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    assert!(timer(fd).get_nonblock());
    let plain = sys_create(1, 0);
    assert!(!fake::fd::FDS.with_borrow(|f| f.cloexec(plain as usize)));
    assert!(!timer(plain).get_nonblock());
    timer(plain).set_nonblock(true);
    assert!(timer(plain).get_nonblock());
}

#[test]
fn create_reports_a_full_table() {
    fake::reset();
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(sys_create(1, 0), EMFILE);
}

#[test]
fn one_shot_expires_once() {
    fake::reset();
    let fd = sys_create(1, TFD_NONBLOCK);
    let t = timer(fd);
    assert_eq!(read(&t), Err(EAGAIN), "disarmed");
    assert_eq!(t.poll_events(), 0);
    assert_eq!(t.next_ns(), None);
    assert_eq!(t.next_tick(), None);
    let waked = t.wq.wakes();
    assert_eq!(settime(fd, 0, Spec::new(0, 0, 0, 25 * MS)), 0);
    assert_eq!(t.wq.wakes(), waked + 1, "waiters recompute their deadline");
    let now = fake::now_ns();
    assert_eq!(t.next_ns(), Some(now + 25_000_000));
    assert_eq!(t.next_tick(), Some((now + 25_000_000).div_ceil(fake::TICK_NS)), "rounded up to a tick");
    assert_eq!(gettime(fd), Spec::new(0, 0, 0, 25 * MS));
    assert_eq!(read(&t), Err(EAGAIN), "not yet");
    fake::advance_ns(24_999_999);
    assert_eq!(t.poll_events(), 0);
    fake::advance_ns(1);
    assert_eq!(t.poll_events(), 1, "POLLIN once expired");
    assert_eq!(gettime(fd), Spec::new(0, 0, 0, 1), "expired but unread: 1 ns left, as Linux shows");
    assert_eq!(read(&t), Ok(1));
    assert_eq!(read(&t), Err(EAGAIN), "a one-shot timer fires once");
    assert_eq!(gettime(fd), Spec::default(), "and is disarmed");
}

#[test]
fn periodic_counts_missed_expirations() {
    fake::reset();
    let fd = sys_create(1, TFD_NONBLOCK);
    let t = timer(fd);
    assert_eq!(settime(fd, 0, Spec::new(0, 10 * MS, 0, 10 * MS)), 0);
    fake::advance_ns(35_000_000);
    assert_eq!(read(&t), Ok(3), "at 10, 20 and 30 ms");
    assert_eq!(gettime(fd), Spec::new(0, 10 * MS, 0, 5 * MS), "next at 40 ms");
    fake::advance_ns(5_000_000);
    assert_eq!(read(&t), Ok(1));
    assert_eq!(read(&t), Err(EAGAIN));
    // Disarming with a zero value
    assert_eq!(settime(fd, 0, Spec::new(0, 10 * MS, 0, 0)), 0);
    fake::advance_ns(100_000_000);
    assert_eq!(read(&t), Err(EAGAIN));
}

#[test]
fn absolute_times_on_both_clocks() {
    fake::reset();
    let mono = sys_create(1, TFD_NONBLOCK);
    let at = fake::now_ns() + 2_000_000_000;
    let spec = Spec::new(0, 0, (at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64);
    assert_eq!(settime(mono, ABSTIME, spec), 0);
    assert_eq!(timer(mono).next_ns(), Some(at));
    // CLOCK_REALTIME (and REALTIME_ALARM): the wall time is converted to the boot clock
    for clock in [0u64, 8] {
        let rt = sys_create(clock, TFD_NONBLOCK);
        let (s, ns) = fake::rtc_now();
        assert_eq!(settime(rt, ABSTIME, Spec::new(0, 0, s as i64 + 3, ns as i64)), 0);
        assert_eq!(timer(rt).next_ns(), Some(fake::now_ns() + 3_000_000_000), "clock {clock}");
        // A wall time in the past expires at once (never before boot)
        assert_eq!(settime(rt, ABSTIME, Spec::new(0, 0, 1, 0)), 0);
        assert_eq!(timer(rt).next_ns(), Some(0));
        assert_eq!(read(&timer(rt)), Ok(1));
    }
    // BOOTTIME's absolute time is taken as it is
    let boot = sys_create(7, TFD_NONBLOCK);
    assert_eq!(settime(boot, ABSTIME, Spec::new(0, 0, 0, 5)), 0);
    assert_eq!(timer(boot).next_ns(), Some(5));
}

#[test]
fn settime_returns_the_old_setting() {
    fake::reset();
    let fd = sys_create(1, 0);
    assert_eq!(settime(fd, 0, Spec::new(1, 0, 2, 500 * MS)), 0);
    fake::advance_ns(500_000_000);
    let mut old = Spec::default();
    let new = Spec::new(0, 0, 0, 0);
    assert_eq!(sys_settime(fd as u64, 0, ptr(&new), mptr(&mut old)), 0);
    assert_eq!(old, Spec::new(1, 0, 2, 0));
    // A bad old pointer fails before the timer changes
    assert_eq!(settime(fd, 0, Spec::new(0, 0, 9, 0)), 0);
    let mut bad = Spec::default();
    fake::bad_ptr(mptr(&mut bad), 32);
    assert_eq!(sys_settime(fd as u64, 0, ptr(&new), mptr(&mut bad)), EFAULT);
    assert_eq!(gettime(fd).value, Pair(9, 0), "unchanged");
}

#[test]
fn settime_and_gettime_reject_bad_arguments() {
    fake::reset();
    let fd = sys_create(1, 0);
    let ok = Spec::new(0, 0, 1, 0);
    assert_eq!(sys_settime(99, 0, ptr(&ok), 0), EINVAL, "not open");
    fake::fd::install(50, FileDescriptor::File { path: "/x".into(), readable: true, writable: true });
    assert_eq!(sys_settime(50, 0, ptr(&ok), 0), EINVAL, "not a timerfd");
    assert_eq!(sys_settime(fd as u64, 0, 0, 0), EFAULT);
    for bad in [Spec::new(0, 0, -1, 0), Spec::new(0, 0, 0, 1_000_000_000), Spec::new(-1, 0, 1, 0), Spec::new(0, -1, 1, 0)] {
        assert_eq!(settime(fd, 0, bad), EINVAL, "{bad:?}");
    }
    let mut s = Spec::default();
    assert_eq!(sys_gettime(99, mptr(&mut s)), EINVAL);
    assert_eq!(sys_gettime(fd as u64, 0), EFAULT);
}

#[test]
fn read_needs_eight_bytes() {
    fake::reset();
    let fd = sys_create(1, 0);
    let mut small = [0u8; 7];
    assert_eq!(timer(fd).read(&mut small), EINVAL);
}

#[test]
fn blocking_read_sleeps_until_the_deadline() {
    fake::reset();
    let fd = sys_create(1, 0);
    let t = timer(fd);
    assert_eq!(settime(fd, 0, Spec::new(0, 0, 0, 55 * MS)), 0);
    let due = fake::now_ns() + 55_000_000;
    assert_eq!(read(&t), Ok(1));
    assert_eq!(fake::WAITS.get(), 1, "one sleep");
    assert_eq!(fake::LAST_DEADLINE.get(), Some(due), "to the exact nanosecond");
    assert_eq!(fake::now_ns(), due);
}

#[test]
fn blocking_read_on_a_disarmed_timer_waits_for_a_signal() {
    fake::reset();
    let fd = sys_create(1, 0);
    let t = timer(fd);
    assert!(blocks(|| read(&t)), "nothing will ever expire");
    fake::reset();
    let fd = sys_create(1, 0);
    let t = timer(fd);
    fake::on_wait(|_| fake::SIGNAL_PENDING.set(true));
    assert_eq!(read(&t), Err(-512), "ERESTARTSYS");
    // Armed from "another thread" while asleep: the wait ends with the expiry
    fake::reset();
    let fd = sys_create(1, 0);
    let t = timer(fd);
    let spec = Spec::new(0, 0, 0, 10 * MS);
    let sp = ptr(&spec);
    fake::on_wait(move |n| {
        if n == 1 {
            assert_eq!(sys_settime(fd as u64, 0, sp, 0), 0);
            fake::advance_ns(10_000_000);
        }
    });
    assert_eq!(read(&t), Ok(1));
}
