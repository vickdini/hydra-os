//! Interval timers (`src/compat/linux/itimer.rs`: `alarm`, `setitimer`, `getitimer`) and
//! POSIX timers (`src/compat/linux/ptimer.rs`: `timer_create` and family), with their
//! daemons run on the fake clock.
//!
//! Both keep a global table by process and a daemon scans all of it, so every test here
//! holds `serial()` and uses its own process IDs.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::{itimer, ptimer};
use hydra_hosttests_t27::fake::proc::{OVERRUNS, POSTED, QUEUED, TIMER_SIGNALS};
use hydra_hosttests_t27::fake::task::{run_daemon, spawned, CPU_TICKS};

const EPERM: i64 = -1;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOTSUP: i64 = -95;

/// A test's process: clean fakes, its own pid.
fn process(pid: u64) {
    fake::reset();
    fake::IDS.set((pid, pid));
}

fn tick() -> i64 {
    fake::TICK_NS as i64
}

// ------------------------------------------------------------------ itimer

fn getitimer(which: u64) -> Spec {
    let mut s = Spec::default();
    assert_eq!(itimer::sys_getitimer(which, mptr(&mut s)), 0);
    s
}

fn setitimer(which: u64, spec: Spec) -> Spec {
    let mut old = Spec::default();
    assert_eq!(itimer::sys_setitimer(which, ptr(&spec), mptr(&mut old)), 0);
    old
}

/// Disarms the three timers of the current process and lets the daemon drop it.
fn itimer_cleanup() {
    for which in 0..3 {
        assert_eq!(itimer::sys_setitimer(which, 0, 0), 0);
    }
    if let Some(d) = spawned("itimerd") {
        run_daemon(d, 0);
    }
}

#[test]
fn alarm_returns_the_seconds_left() {
    let _g = serial();
    process(1101);
    assert_eq!(itimer::sys_alarm(3), 0, "nothing armed before");
    assert_eq!(getitimer(0), Spec::new(0, 0, 3, 0));
    fake::advance_ns(1_200_000_000);
    assert_eq!(itimer::sys_alarm(10), 2, "1.8 s left: rounded up");
    assert_eq!(itimer::sys_alarm(0), 10, "and disarmed");
    assert_eq!(getitimer(0), Spec::default());
    assert!(spawned("itimerd").is_some(), "the daemon started with the first timer");
    itimer_cleanup();
}

#[test]
fn setitimer_rounds_to_ticks_and_returns_the_old_value() {
    let _g = serial();
    process(1102);
    let old = setitimer(0, Spec::new(0, 500_000, 1, 1));
    assert_eq!(old, Spec::default());
    // 1 us rounds up to a 10 ms tick
    assert_eq!(getitimer(0), Spec::new(0, 500_000, 1, 10_000));
    fake::advance_ticks(50);
    let old = setitimer(0, Spec::new(0, 0, 0, 0));
    assert_eq!(old, Spec::new(0, 500_000, 0, 510_000));
    assert_eq!(getitimer(0), Spec::default(), "a zero value disarms");
    // A timer due now still shows a tick left
    setitimer(0, Spec::new(0, 0, 0, 10_000));
    fake::advance_ticks(5);
    assert_eq!(getitimer(0).value, Pair(0, 10_000));
    itimer_cleanup();
}

#[test]
fn itimer_argument_errors() {
    let _g = serial();
    process(1103);
    let ok = Spec::new(0, 0, 1, 0);
    let mut out = Spec::default();
    assert_eq!(itimer::sys_getitimer(3, mptr(&mut out)), EINVAL);
    assert_eq!(itimer::sys_setitimer(3, ptr(&ok), 0), EINVAL);
    assert_eq!(itimer::sys_getitimer(0, 0), EFAULT);
    let mut bad = Spec::default();
    fake::bad_ptr(mptr(&mut bad), 32);
    assert_eq!(itimer::sys_setitimer(0, mptr(&mut bad), 0), EFAULT);
    assert_eq!(itimer::sys_setitimer(0, ptr(&ok), mptr(&mut bad)), EFAULT);
    assert_eq!(getitimer(0), Spec::default(), "a failed setitimer arms nothing");
    for spec in [Spec::new(0, 0, -1, 0), Spec::new(0, 0, 0, 1_000_000), Spec::new(-1, 0, 1, 0), Spec::new(0, -1, 1, 0)] {
        assert_eq!(itimer::sys_setitimer(0, ptr(&spec), 0), EINVAL, "{spec:?}");
    }
    itimer_cleanup();
}

#[test]
fn cpu_time_timers_count_the_process_ticks() {
    let _g = serial();
    process(1104);
    CPU_TICKS.with_borrow_mut(|m| m.insert(1104, 100));
    setitimer(1, Spec::new(0, 0, 0, 50_000)); // ITIMER_VIRTUAL: 5 ticks
    setitimer(2, Spec::new(0, 20_000, 0, 30_000)); // ITIMER_PROF
    fake::advance_ticks(1000); // boot time does not matter
    assert_eq!(getitimer(1).value, Pair(0, 50_000));
    CPU_TICKS.with_borrow_mut(|m| m.insert(1104, 103));
    assert_eq!(getitimer(1).value, Pair(0, 20_000));
    assert_eq!(getitimer(2), Spec::new(0, 20_000, 0, 10_000));
    itimer_cleanup();
}

#[test]
fn itimerd_posts_the_signals() {
    let _g = serial();
    process(1105);
    // Make sure the daemon exists and the table holds only this test's timers
    setitimer(0, Spec::new(0, 0, 0, 10_000));
    itimer_cleanup();
    let daemon = spawned("itimerd").expect("itimerd");
    POSTED.with_borrow_mut(|p| p.clear());

    // ITIMER_REAL: one-shot in 30 ms, then a periodic one
    setitimer(0, Spec::new(0, 0, 0, 30_000));
    let start = fake::ticks();
    run_daemon(daemon, 0);
    assert!(POSTED.with_borrow(|p| p.is_empty()), "not due on the first pass");
    assert_eq!(fake::LAST_DEADLINE.get(), Some((start + 3) * fake::TICK_NS), "sleeps until the deadline");
    run_daemon(daemon, 1);
    assert_eq!(fake::ticks(), start + 3);
    assert_eq!(POSTED.with_borrow(|p| p.clone()), vec![(1105, 0, 14)], "SIGALRM");
    assert_eq!(getitimer(0), Spec::default(), "one-shot: disarmed");
    assert_eq!(fake::LAST_DEADLINE.get(), None, "nothing left to wait for");

    POSTED.with_borrow_mut(|p| p.clear());
    setitimer(0, Spec::new(0, 20_000, 0, 20_000));
    run_daemon(daemon, 2);
    assert_eq!(POSTED.with_borrow(|p| p.len()), 2, "at 20 and 40 ms");
    assert!(getitimer(0).value.1 > 0, "still armed");

    // CPU timers: checked every tick
    POSTED.with_borrow_mut(|p| p.clear());
    setitimer(0, Spec::default());
    CPU_TICKS.with_borrow_mut(|m| m.insert(1105, 0));
    setitimer(1, Spec::new(0, 0, 0, 10_000));
    setitimer(2, Spec::new(0, 10_000, 0, 10_000));
    let t = fake::ticks();
    run_daemon(daemon, 0);
    assert_eq!(fake::LAST_DEADLINE.get(), Some((t + 1) * fake::TICK_NS), "a tick later");
    assert!(POSTED.with_borrow(|p| p.is_empty()), "no CPU time used");
    CPU_TICKS.with_borrow_mut(|m| m.insert(1105, 1));
    run_daemon(daemon, 0);
    assert_eq!(POSTED.with_borrow(|p| p.clone()), vec![(1105, 0, 26), (1105, 0, 27)], "SIGVTALRM, SIGPROF");
    assert_eq!(getitimer(1), Spec::default());
    assert_eq!(getitimer(2).value, Pair(0, 10_000), "PROF reloaded");
    itimer_cleanup();
}

#[test]
fn itimerd_forgets_a_process_that_is_gone() {
    let _g = serial();
    process(1106);
    setitimer(0, Spec::new(0, 10_000, 0, 10_000));
    let daemon = spawned("itimerd").expect("itimerd");
    fake::proc::GONE.with_borrow_mut(|g| g.insert(1106));
    fake::advance_ticks(1);
    run_daemon(daemon, 0);
    assert_eq!(POSTED.with_borrow(|p| p.iter().filter(|e| e.0 == 1106).count()), 1);
    assert_eq!(getitimer(0), Spec::default(), "its timers went with it");
}

// ------------------------------------------------------------------ ptimer

/// `struct sigevent`: value, signo, notify, thread ID.
#[repr(C)]
struct Sigevent {
    value: u64,
    signo: i32,
    notify: i32,
    tid: i32,
    _pad: i32,
}

fn create(clock: u64, sev: Option<&Sigevent>) -> Result<i32, i64> {
    let mut id = -1i32;
    let r = ptimer::dispatch(222, [clock, sev.map_or(0, |s| ptr(s)), mptr(&mut id), 0, 0, 0]).unwrap();
    if r == 0 {
        Ok(id)
    } else {
        Err(r)
    }
}

fn settime(id: i32, flags: u64, spec: Spec) -> i64 {
    ptimer::dispatch(223, [id as u64, flags, ptr(&spec), 0, 0, 0]).unwrap()
}

fn gettime(id: i32) -> Spec {
    let mut s = Spec::default();
    assert_eq!(ptimer::dispatch(224, [id as u64, mptr(&mut s), 0, 0, 0, 0]), Some(0));
    s
}

fn overrun(id: i32) -> i64 {
    ptimer::dispatch(225, [id as u64, 0, 0, 0, 0, 0]).unwrap()
}

fn delete(id: i32) -> i64 {
    ptimer::dispatch(226, [id as u64, 0, 0, 0, 0, 0]).unwrap()
}

#[test]
fn timer_create_clocks_and_ids() {
    let _g = serial();
    process(2101);
    assert_eq!(create(8, None), Err(EPERM), "alarm clocks need CAP_WAKE_ALARM");
    assert_eq!(create(9, None), Err(EPERM));
    assert_eq!(create(3, None), Err(ENOTSUP), "thread CPU clock");
    assert_eq!(create(5, None), Err(EINVAL), "coarse clocks");
    assert_eq!(create(0, None), Ok(0));
    assert_eq!(create(1, None), Ok(1));
    assert_eq!(create(4, None), Ok(2));
    assert_eq!(create(7, None), Ok(3));
    assert_eq!(create(2, None), Ok(4));
    assert_eq!(delete(1), 0);
    assert_eq!(delete(1), EINVAL);
    assert_eq!(create(1, None), Ok(1), "the lowest free ID");
    assert_eq!(ptimer::dispatch(227, [0; 6]), None, "not a timer call");
    ptimer::forget_process(2101);
    assert_eq!(delete(0), EINVAL, "forgotten");
}

#[test]
fn timer_create_sigevents() {
    let _g = serial();
    process(2102);
    fake::proc::THREADS.with_borrow_mut(|t| t.insert(2102, vec![2102, 2103]));
    let none = Sigevent { value: 0, signo: 0, notify: 1, tid: 0, _pad: 0 };
    assert_eq!(create(1, Some(&none)), Ok(0), "SIGEV_NONE");
    let sig = Sigevent { value: 7, signo: 10, notify: 0, tid: 0, _pad: 0 };
    assert_eq!(create(1, Some(&sig)), Ok(1));
    let bad_sig = Sigevent { value: 7, signo: 65, notify: 0, tid: 0, _pad: 0 };
    assert_eq!(create(1, Some(&bad_sig)), Err(EINVAL));
    let thread = Sigevent { value: 9, signo: 12, notify: 4, tid: 2103, _pad: 0 };
    assert_eq!(create(1, Some(&thread)), Ok(2), "SIGEV_THREAD_ID");
    let thread2 = Sigevent { value: 9, signo: 12, notify: 4, tid: 2102, _pad: 0 };
    assert_eq!(create(1, Some(&thread2)), Ok(3));
    let stranger = Sigevent { value: 9, signo: 12, notify: 4, tid: 9999, _pad: 0 };
    assert_eq!(create(1, Some(&stranger)), Err(EINVAL), "not a thread of ours");
    let thread_bad_sig = Sigevent { value: 9, signo: 0, notify: 4, tid: 2103, _pad: 0 };
    assert_eq!(create(1, Some(&thread_bad_sig)), Err(EINVAL));
    let unknown = Sigevent { value: 0, signo: 10, notify: 99, tid: 0, _pad: 0 };
    assert_eq!(create(1, Some(&unknown)), Err(EINVAL));
    // Faults
    let mut id = 0i32;
    let unmapped = Sigevent { value: 0, signo: 10, notify: 0, tid: 0, _pad: 0 };
    fake::bad_ptr(ptr(&unmapped), 24);
    assert_eq!(ptimer::dispatch(222, [1, ptr(&unmapped), mptr(&mut id), 0, 0, 0]), Some(EFAULT), "sigevent");
    fake::bad_ptr(mptr(&mut id), 4);
    assert_eq!(ptimer::dispatch(222, [1, 0, mptr(&mut id), 0, 0, 0]), Some(EFAULT), "timer ID");
    fake::BAD_PTRS.with_borrow_mut(|v| v.clear());
    assert_eq!(create(1, None), Ok(4), "the failed one was removed again");
    ptimer::forget_process(2102);
}

#[test]
fn timer_create_has_a_limit() {
    let _g = serial();
    process(2103);
    for i in 0..4096 {
        assert_eq!(create(1, None), Ok(i));
    }
    assert_eq!(create(1, None), Err(EAGAIN));
    ptimer::forget_process(2103);
}

#[test]
fn settime_and_gettime() {
    let _g = serial();
    process(2104);
    let id = create(1, None).unwrap();
    assert_eq!(gettime(id), Spec::default(), "disarmed");
    assert_eq!(settime(id, 0, Spec::new(0, 25 * MS, 1, 5 * MS)), 0);
    // Tick resolution: 25 ms interval, 1.005 s rounds up to 1.01 s
    assert_eq!(gettime(id), Spec::new(0, 30 * MS, 1, 10 * MS));
    fake::advance_ticks(1);
    assert_eq!(gettime(id).value, Pair(1, 0));
    // The old setting comes back
    let mut old = Spec::default();
    let new = Spec::new(0, 0, 0, 0);
    assert_eq!(ptimer::dispatch(223, [id as u64, 0, ptr(&new), mptr(&mut old), 0, 0]), Some(0));
    assert_eq!(old, Spec::new(0, 30 * MS, 1, 0));
    assert_eq!(gettime(id), Spec::new(0, 0, 0, 0), "disarmed (interval 0 too)");
    // A tiny relative time still waits a tick
    assert_eq!(settime(id, 0, Spec::new(0, 0, 0, 1)), 0);
    assert_eq!(gettime(id).value, Pair(0, tick()));
    // Absolute on the boot clock: a time in the past expires now
    assert_eq!(settime(id, 1, Spec::new(0, 0, 0, 1)), 0);
    assert_eq!(gettime(id).value, Pair(0, tick()), "due: a tick shown");
    let at = fake::now_ns() + 2_000_000_000;
    assert_eq!(settime(id, 1, Spec::new(0, 0, (at / 1_000_000_000) as i64, (at % 1_000_000_000) as i64)), 0);
    assert_eq!(gettime(id).value, Pair(2, 0));
    ptimer::forget_process(2104);
}

#[test]
fn realtime_absolute_deadlines() {
    let _g = serial();
    process(2105);
    let id = create(0, None).unwrap();
    let (s, ns) = fake::rtc_now();
    assert_eq!(settime(id, 1, Spec::new(0, 0, s as i64 + 1, ns as i64 + 500_000_000)), 0);
    assert_eq!(gettime(id).value, Pair(1, 500 * MS));
    assert_eq!(settime(id, 1, Spec::new(0, 0, 100, 0)), 0, "long ago");
    assert_eq!(gettime(id).value, Pair(0, tick()), "due now");
    ptimer::forget_process(2105);
}

#[test]
fn settime_errors() {
    let _g = serial();
    process(2106);
    let id = create(1, None).unwrap();
    assert_eq!(ptimer::dispatch(223, [id as u64, 0, 0, 0, 0, 0]), Some(EFAULT));
    for spec in [Spec::new(-1, 0, 1, 0), Spec::new(0, 0, -1, 0), Spec::new(0, 1_000_000_000, 1, 0), Spec::new(0, 0, 1, -1)] {
        assert_eq!(settime(id, 0, spec), EINVAL, "{spec:?}");
    }
    assert_eq!(settime(77, 0, Spec::new(0, 0, 1, 0)), EINVAL, "no such timer");
    let mut bad = Spec::default();
    fake::bad_ptr(mptr(&mut bad), 32);
    let new = Spec::new(0, 0, 3, 0);
    assert_eq!(ptimer::dispatch(223, [id as u64, 0, ptr(&new), mptr(&mut bad), 0, 0]), Some(EFAULT));
    assert_eq!(gettime(id).value, Pair(3, 0), "armed anyway (as Linux)");
    assert_eq!(ptimer::dispatch(224, [id as u64, mptr(&mut bad), 0, 0, 0, 0]), Some(EFAULT));
    assert_eq!(ptimer::dispatch(224, [99, mptr(&mut bad), 0, 0, 0, 0]), Some(EINVAL));
    assert_eq!(overrun(99), EINVAL);
    ptimer::forget_process(2106);
}

/// Starts ptimerd (once per binary) and returns it, with an empty table.
fn ptimerd() -> fn() {
    if spawned("ptimerd").is_none() {
        let id = create(1, None).unwrap();
        settime(id, 0, Spec::new(0, 0, 1, 0));
        ptimer::forget_process(fake::IDS.get().1);
    }
    spawned("ptimerd").expect("ptimerd")
}

#[test]
fn ptimerd_sends_signals_with_the_timer_details() {
    let _g = serial();
    process(2107);
    let daemon = ptimerd();
    fake::proc::THREADS.with_borrow_mut(|t| t.insert(2107, vec![2107, 2108]));
    let a = create(1, None).unwrap(); // SIGALRM, value = ID
    let sev = Sigevent { value: 0xabc, signo: 12, notify: 4, tid: 2108, _pad: 0 };
    let b = create(1, Some(&sev)).unwrap();
    let quiet = Sigevent { value: 0, signo: 0, notify: 1, tid: 0, _pad: 0 };
    let c = create(1, Some(&quiet)).unwrap();
    assert_eq!(settime(a, 0, Spec::new(0, 0, 0, 20 * MS)), 0);
    assert_eq!(settime(b, 0, Spec::new(0, 10 * MS, 0, 10 * MS)), 0);
    assert_eq!(settime(c, 0, Spec::new(0, 0, 0, 10 * MS)), 0);
    run_daemon(daemon, 0); // nothing due yet
    assert!(TIMER_SIGNALS.with_borrow(|v| v.is_empty()));
    run_daemon(daemon, 2); // now, at 10 ms and at 20 ms
    let sent = TIMER_SIGNALS.with_borrow(|v| v.clone());
    assert_eq!(sent, vec![(2107, Some(2108), 12, b, 0, 0xabc), (2107, None, 14, a, 0, a as u64), (2107, Some(2108), 12, b, 0, 0xabc)]);
    assert_eq!(gettime(c), Spec::default(), "SIGEV_NONE expired quietly");
    assert_eq!(gettime(a), Spec::default());
    ptimer::forget_process(2107);
}

#[test]
fn ptimerd_counts_overruns() {
    let _g = serial();
    process(2109);
    let daemon = ptimerd();
    let id = create(1, None).unwrap();
    assert_eq!(settime(id, 0, Spec::new(0, 10 * MS, 0, 10 * MS)), 0);
    // A late wakeup: three periods missed
    fake::advance_ticks(4);
    run_daemon(daemon, 0);
    assert_eq!(TIMER_SIGNALS.with_borrow(|v| v.clone()), vec![(2109, None, 14, id, 3, id as u64)]);
    assert_eq!(overrun(id), 3);
    // While the signal is still queued, expiries are overruns of it
    QUEUED.with_borrow_mut(|q| q.insert((2109, 14)));
    fake::advance_ticks(1);
    run_daemon(daemon, 0);
    assert_eq!(OVERRUNS.with_borrow(|v| v.clone()), vec![(2109, None, 14, 1)]);
    assert_eq!(overrun(id), 3, "not delivered yet: the last count stands");
    // Delivered: the count moves over
    QUEUED.with_borrow_mut(|q| q.clear());
    assert_eq!(overrun(id), 1);
    assert_eq!(overrun(id), 1);
    // A SIGEV_NONE timer has no signal to wait for
    let quiet = Sigevent { value: 0, signo: 0, notify: 1, tid: 0, _pad: 0 };
    let q = create(1, Some(&quiet)).unwrap();
    assert_eq!(overrun(q), 0);
    ptimer::forget_process(2109);
}

#[test]
fn ptimerd_cpu_timers_and_dead_processes() {
    let _g = serial();
    process(2110);
    let daemon = ptimerd();
    CPU_TICKS.with_borrow_mut(|m| m.insert(2110, 50));
    let id = create(2, None).unwrap();
    assert_eq!(settime(id, 0, Spec::new(0, 0, 0, 20 * MS)), 0); // 2 CPU ticks
    assert_eq!(gettime(id).value, Pair(0, 20 * MS));
    let t = fake::ticks();
    run_daemon(daemon, 0);
    assert_eq!(fake::LAST_DEADLINE.get(), Some((t + 1) * fake::TICK_NS), "CPU timers: every tick");
    assert!(TIMER_SIGNALS.with_borrow(|v| v.is_empty()));
    CPU_TICKS.with_borrow_mut(|m| m.insert(2110, 52));
    fake::proc::GONE.with_borrow_mut(|g| g.insert(2110));
    run_daemon(daemon, 0);
    assert_eq!(TIMER_SIGNALS.with_borrow(|v| v.len()), 1);
    assert_eq!(delete(id), EINVAL, "the process is gone: its timers too");
}
