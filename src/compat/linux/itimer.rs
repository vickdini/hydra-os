//! # Interval Timers (`alarm`, `setitimer`, `getitimer`)
//!
//! Per-process timers that raise a signal: `ITIMER_REAL` (wall time, `SIGALRM`; also what
//! `alarm` sets), `ITIMER_VIRTUAL` (`SIGVTALRM`) and `ITIMER_PROF` (`SIGPROF`), the last
//! two counting the process's CPU time (Hydra does not separate user from system time,
//! so both count all of it).
//!
//! Signals cannot be posted from the timer interrupt (posting takes locks the interrupted
//! code may hold), so the `itimerd` kernel task, started on first use, sleeps until the
//! earliest expiry and posts them. Resolution is the scheduler tick (10 ms). Timers
//! survive `execve` and are not inherited across `fork`, as on Linux.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::task::wait::WaitQueue;

const EINVAL: i64 = -22;
const EFAULT: i64 = -14;

const ITIMER_REAL: u64 = 0;
const ITIMER_PROF: u64 = 2;

const US_PER_TICK: u64 = 10_000;

/// One timer: next expiry (in its clock's ticks) and reload interval (0 = one-shot).
#[derive(Clone, Copy, Default)]
struct Timer {
    next: u64,
    interval: u64,
}

#[derive(Default)]
struct ProcTimers {
    /// Indexed by `ITIMER_*`.
    t: [Option<Timer>; 3],
}

static TIMERS: Mutex<BTreeMap<u64, ProcTimers>> = Mutex::new(BTreeMap::new());
/// Wakes `itimerd` when a timer is set (its next deadline may be earlier).
static CHANGED: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);

fn now() -> u64 {
    crate::arch::pit::ticks()
}

/// CPU time of process `pid` in ticks.
fn cpu_ticks(pid: u64) -> u64 {
    crate::task::SCHEDULER.lock().process_ticks(pid)
}

/// The clock a timer counts on, in ticks.
fn clock(which: usize, pid: u64) -> u64 {
    if which == ITIMER_REAL as usize {
        now()
    } else {
        cpu_ticks(pid)
    }
}

fn signal_for(which: usize) -> u32 {
    match which {
        0 => super::proc::SIGALRM,
        1 => super::proc::SIGVTALRM,
        _ => super::proc::SIGPROF,
    }
}

fn itimerd_main() {
    loop {
        CHANGED.register();
        let mut fire: alloc::vec::Vec<(u64, u32)> = alloc::vec::Vec::new();
        let mut next_real: Option<u64> = None;
        let mut cpu_timers = false;
        {
            let pids: alloc::vec::Vec<u64> = TIMERS.lock().keys().copied().collect();
            for pid in pids {
                let cpu = cpu_ticks(pid);
                let mut all = TIMERS.lock();
                let p = match all.get_mut(&pid) {
                    Some(p) => p,
                    None => continue,
                };
                for which in 0..3 {
                    let at = if which == 0 { now() } else { cpu };
                    if let Some(t) = p.t[which].as_mut() {
                        if at >= t.next {
                            fire.push((pid, signal_for(which)));
                            if t.interval == 0 {
                                p.t[which] = None;
                            } else {
                                t.next = at + t.interval;
                            }
                        }
                    }
                    if let Some(t) = p.t[which] {
                        if which == 0 {
                            next_real = Some(next_real.map_or(t.next, |n| n.min(t.next)));
                        } else {
                            cpu_timers = true;
                        }
                    }
                }
                if p.t.iter().all(|t| t.is_none()) {
                    all.remove(&pid);
                }
            }
        }
        for (pid, sig) in fire {
            if !super::proc::post_process(pid, sig) {
                TIMERS.lock().remove(&pid); // the process is gone
            }
        }
        // CPU-time timers are checked every tick while any is armed
        let deadline = match (next_real, cpu_timers) {
            (_, true) => Some(now() + 1),
            (Some(n), false) => Some(n),
            (None, false) => None,
        };
        crate::task::wait::wait(deadline);
    }
}

fn ensure_started() {
    if !STARTED.swap(true, Ordering::AcqRel) {
        crate::task::spawn("itimerd", itimerd_main, crate::task::TaskPriority::High);
    }
}

/// (remaining, interval) of a timer in ticks.
fn get(pid: u64, which: usize) -> (u64, u64) {
    let t = TIMERS.lock().get(&pid).and_then(|p| p.t[which]);
    match t {
        Some(t) => (t.next.saturating_sub(clock(which, pid)).max(1), t.interval),
        None => (0, 0),
    }
}

/// Arms (`value` > 0) or disarms a timer; values in ticks.
fn set(pid: u64, which: usize, value: u64, interval: u64) {
    let base = clock(which, pid);
    let mut all = TIMERS.lock();
    let p = all.entry(pid).or_default();
    p.t[which] = if value == 0 { None } else { Some(Timer { next: base + value, interval }) };
    drop(all);
    if value != 0 {
        ensure_started();
    }
    CHANGED.wake_all();
}

fn ticks_from_timeval(sec: i64, usec: i64) -> Result<u64, i64> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    let us = sec as u64 * 1_000_000 + usec as u64;
    Ok((us + US_PER_TICK - 1) / US_PER_TICK)
}

/// Writes `struct itimerval` {interval, value} (ticks to timevals).
fn put_itimerval(ptr: u64, interval: u64, value: u64) -> i64 {
    if !crate::memory::vm::prefault_current(ptr, 32, true) {
        return EFAULT;
    }
    let tv = |t: u64| {
        let us = t * US_PER_TICK;
        [us / 1_000_000, us % 1_000_000]
    };
    let words = [tv(interval)[0], tv(interval)[1], tv(value)[0], tv(value)[1]];
    for (i, w) in words.iter().enumerate() {
        unsafe { core::ptr::write_unaligned((ptr + i as u64 * 8) as *mut u64, *w) };
    }
    0
}

/// `alarm(seconds)`: returns the seconds left on the previous alarm (rounded up).
pub fn sys_alarm(seconds: u64) -> i64 {
    let (_, pid) = super::proc::current_ids();
    let (left, _) = get(pid, 0);
    set(pid, 0, seconds.min(u32::MAX as u64) * 100, 0);
    ((left + 99) / 100) as i64
}

/// `getitimer(which, curr_value)`.
pub fn sys_getitimer(which: u64, ptr: u64) -> i64 {
    if which > ITIMER_PROF {
        return EINVAL;
    }
    let (_, pid) = super::proc::current_ids();
    let (value, interval) = get(pid, which as usize);
    put_itimerval(ptr, interval, value)
}

/// `setitimer(which, new_value, old_value)`.
pub fn sys_setitimer(which: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    if which > ITIMER_PROF {
        return EINVAL;
    }
    let (_, pid) = super::proc::current_ids();
    let (interval, value) = if new_ptr == 0 {
        (0, 0) // Linux treats a null new value as disarming
    } else {
        if !crate::memory::vm::prefault_current(new_ptr, 32, false) {
            return EFAULT;
        }
        let r = |i: u64| unsafe { core::ptr::read_unaligned((new_ptr + i * 8) as *const i64) };
        match (ticks_from_timeval(r(0), r(1)), ticks_from_timeval(r(2), r(3))) {
            (Ok(i), Ok(v)) => (i, v),
            _ => return EINVAL,
        }
    };
    if old_ptr != 0 {
        let (v, i) = get(pid, which as usize);
        let e = put_itimerval(old_ptr, i, v);
        if e != 0 {
            return e;
        }
    }
    set(pid, which as usize, value, interval);
    0
}
