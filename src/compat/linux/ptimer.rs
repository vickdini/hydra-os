//! # POSIX per-process timers (`timer_create` and family)
//!
//! A process creates any number of timers on `CLOCK_REALTIME`, `CLOCK_MONOTONIC`,
//! `CLOCK_BOOTTIME` (and their coarse variants, which Linux rejects only for timers: here
//! too) or `CLOCK_PROCESS_CPUTIME_ID`. On expiry a timer sends its signal to the process or
//! to one of its threads (`SIGEV_THREAD_ID`, which glibc's `SIGEV_THREAD` uses), with
//! `si_code` `SI_TIMER`, the timer ID, the overrun count and the creator's value; or does
//! nothing (`SIGEV_NONE`). While its signal is still pending, further expiries are counted
//! as overruns (`timer_getoverrun`) instead of sent again.
//!
//! Like the interval timers ([`super::itimer`]), a kernel task (`ptimerd`) waits for the
//! earliest deadline and posts the signals from task context. Timers have the timer tick's
//! resolution (10 ms). They are not inherited by `fork` and are deleted by `execve` and at
//! exit.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::task::wait::WaitQueue;

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const ENOTSUP: i64 = -95;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD_ID: i32 = 4;
/// `si_code` of a signal sent by a POSIX timer.
pub const SI_TIMER: i32 = -2;
/// `timer_settime` flag: the expiry is an absolute time on the timer's clock.
const TIMER_ABSTIME: u64 = 1;
/// Most timers one process may have.
const MAX_TIMERS: usize = 4096;

/// The clock a timer counts.
#[derive(Clone, Copy, PartialEq)]
enum Clock {
    /// Wall-clock time (absolute times are converted to ticks when armed).
    Realtime,
    /// Time since boot.
    Monotonic,
    /// The process's CPU time.
    ProcessCpu,
}

/// What a timer does when it expires.
#[derive(Clone, Copy)]
enum Notify {
    None,
    /// Send `sig` (to thread `tid`, or to the process) with `value`.
    Signal { sig: u32, tid: Option<u64>, value: u64 },
}

/// One timer.
struct Timer {
    clock: Clock,
    notify: Notify,
    /// Next expiry, in ticks of the timer's clock (boot ticks or CPU ticks).
    next: Option<u64>,
    /// Reload interval in ticks (0: one-shot).
    interval: u64,
    /// Expiries not sent because the signal was still pending.
    overrun: u32,
    /// Overruns of the last signal sent (`timer_getoverrun`).
    last_overrun: u32,
}

/// Timers by process, then by timer ID.
static TIMERS: Mutex<BTreeMap<u64, BTreeMap<i32, Timer>>> = Mutex::new(BTreeMap::new());
/// Wakes `ptimerd` when a timer changes.
static CHANGED: WaitQueue = WaitQueue::new();
static STARTED: AtomicBool = AtomicBool::new(false);

fn hz() -> u64 {
    crate::arch::pit::frequency_hz().max(1)
}

/// Current value of `clock` for process `pid`, in ticks.
fn now(clock: Clock, pid: u64) -> u64 {
    match clock {
        Clock::ProcessCpu => crate::task::SCHEDULER.lock().process_ticks(pid),
        _ => crate::arch::pit::ticks(),
    }
}

/// Converts a `(seconds, nanoseconds)` duration to ticks, rounding up.
fn to_ticks(sec: i64, nsec: i64) -> u64 {
    let ns = sec as u128 * 1_000_000_000 + nsec as u128;
    ((ns * hz() as u128).div_ceil(1_000_000_000)) as u64
}

/// Converts ticks to `(seconds, nanoseconds)`.
fn from_ticks(t: u64) -> (i64, i64) {
    let ns = t as u128 * 1_000_000_000 / hz() as u128;
    ((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as i64)
}

/// The clock of `clockid`, if timers may use it.
fn clock_of(clockid: u64) -> Result<Clock, i64> {
    match clockid as i32 {
        0 => Ok(Clock::Realtime),
        1 | 4 | 7 => Ok(Clock::Monotonic), // MONOTONIC, MONOTONIC_RAW, BOOTTIME
        2 => Ok(Clock::ProcessCpu),
        8 | 9 => Err(EPERM), // *_ALARM: need CAP_WAKE_ALARM
        3 => Err(ENOTSUP), // per-thread CPU-time timers are not offered
        _ => Err(EINVAL),
    }
}

/// Main loop of `ptimerd`: fires expired timers and sleeps until the next deadline.
fn ptimerd_main() {
    loop {
        CHANGED.register();
        let mut fire: Vec<(u64, i32, u32, Option<u64>, u64, u32)> = Vec::new();
        let mut next_boot: Option<u64> = None;
        let mut cpu = false;
        let pids: Vec<u64> = TIMERS.lock().keys().copied().collect();
        for pid in pids {
            let cpu_now = crate::task::SCHEDULER.lock().process_ticks(pid);
            let boot_now = crate::arch::pit::ticks();
            let mut all = TIMERS.lock();
            let Some(timers) = all.get_mut(&pid) else { continue };
            for (&id, t) in timers.iter_mut() {
                let at = if t.clock == Clock::ProcessCpu { cpu_now } else { boot_now };
                if let Some(next) = t.next {
                    if at >= next {
                        // Expiries missed since (a late wakeup, a short interval) are overruns
                        let missed = if t.interval > 0 { (at - next) / t.interval } else { 0 };
                        t.next = (t.interval > 0).then(|| next + (missed + 1) * t.interval);
                        if let Notify::Signal { sig, tid, value } = t.notify {
                            fire.push((pid, id, sig, tid, value, missed as u32));
                        }
                    }
                }
                if let Some(next) = t.next {
                    if t.clock == Clock::ProcessCpu {
                        cpu = true;
                    } else {
                        next_boot = Some(next_boot.map_or(next, |n: u64| n.min(next)));
                    }
                }
            }
        }
        for (pid, id, sig, tid, value, missed) in fire {
            let pending = super::proc::signal_queued(pid, tid, sig);
            let mut all = TIMERS.lock();
            let Some(t) = all.get_mut(&pid).and_then(|m| m.get_mut(&id)) else { continue };
            if pending {
                // Counted on the queued signal too: its handler reads si_overrun
                t.overrun = t.overrun.saturating_add(1 + missed);
                let overrun = t.overrun;
                drop(all);
                super::proc::set_timer_overrun(pid, tid, sig, overrun);
                continue;
            }
            let overrun = t.overrun.saturating_add(missed);
            t.last_overrun = overrun;
            t.overrun = 0;
            drop(all);
            if !super::proc::post_timer_signal(pid, tid, sig, id, overrun, value) {
                TIMERS.lock().remove(&pid); // the process is gone
            }
        }
        let deadline = if cpu { Some(crate::arch::pit::ticks() + 1) } else { next_boot };
        crate::task::wait::wait(deadline);
    }
}

fn ensure_started() {
    if !STARTED.swap(true, Ordering::AcqRel) {
        crate::task::spawn("ptimerd", ptimerd_main, crate::task::TaskPriority::High);
    }
}

/// Deletes every timer of process `pid` (exit, `execve`).
///
/// # Arguments
/// * `pid` - Process ID.
pub fn forget_process(pid: u64) {
    TIMERS.lock().remove(&pid);
}

/// `timer_create(2)`.
fn create(clockid: u64, sevp: u64, idp: u64) -> i64 {
    let clock = match clock_of(clockid) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (tid, pid) = super::proc::current_ids();
    let _ = tid;
    // struct sigevent: value (8), signo (4), notify (4), then the thread ID
    let notify = if sevp == 0 {
        None
    } else {
        let raw = match copy_in(sevp, 24) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let value = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let sig = i32::from_le_bytes(raw[8..12].try_into().unwrap());
        let how = i32::from_le_bytes(raw[12..16].try_into().unwrap());
        let thread = i32::from_le_bytes(raw[16..20].try_into().unwrap());
        let valid_sig = (1..=64).contains(&sig);
        Some(match how {
            SIGEV_NONE => Notify::None,
            SIGEV_SIGNAL if valid_sig => Notify::Signal { sig: sig as u32, tid: None, value },
            h if h == SIGEV_THREAD_ID || h == (SIGEV_SIGNAL | SIGEV_THREAD_ID) => {
                let t = super::ns::pid_from_caller(thread as u32 as u64);
                if !valid_sig || !super::proc::thread_ids_of(pid).contains(&t) {
                    return EINVAL;
                }
                Notify::Signal { sig: sig as u32, tid: Some(t), value }
            }
            _ => return EINVAL,
        })
    };
    let mut all = TIMERS.lock();
    let timers = all.entry(pid).or_default();
    if timers.len() >= MAX_TIMERS {
        return EAGAIN;
    }
    let id = (0..).find(|i| !timers.contains_key(i)).unwrap_or(0);
    // No sigevent: SIGALRM with the timer ID as the value
    let notify = notify.unwrap_or(Notify::Signal { sig: super::proc::SIGALRM, tid: None, value: id as u64 });
    timers.insert(id, Timer { clock, notify, next: None, interval: 0, overrun: 0, last_overrun: 0 });
    drop(all);
    if copy_out(idp, &id.to_le_bytes()).is_err() {
        TIMERS.lock().get_mut(&pid).map(|m| m.remove(&id));
        return EFAULT;
    }
    0
}

/// Remaining time and interval of a timer, as a `struct itimerspec`.
fn itimerspec(t: &Timer, pid: u64) -> [u8; 32] {
    let remaining = t.next.map_or(0, |n| n.saturating_sub(now(t.clock, pid)).max(1));
    let mut b = [0u8; 32];
    for (i, v) in [t.interval, remaining].into_iter().enumerate() {
        let (s, ns) = from_ticks(v);
        b[i * 16..i * 16 + 8].copy_from_slice(&s.to_le_bytes());
        b[i * 16 + 8..i * 16 + 16].copy_from_slice(&ns.to_le_bytes());
    }
    b
}

/// `timer_settime(2)`.
fn settime(id: i32, flags: u64, new: u64, old: u64) -> i64 {
    let raw = match copy_in(new, 32) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let field = |o: usize| i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
    let (isec, insec, vsec, vnsec) = (field(0), field(8), field(16), field(24));
    if [isec, vsec].iter().any(|&s| s < 0) || [insec, vnsec].iter().any(|&n| !(0..1_000_000_000).contains(&n)) {
        return EINVAL;
    }
    let (_, pid) = super::proc::current_ids();
    let clock = match TIMERS.lock().get(&pid).and_then(|m| m.get(&id)).map(|t| t.clock) {
        Some(c) => c,
        None => return EINVAL,
    };
    let base = now(clock, pid);
    let next = if vsec == 0 && vnsec == 0 {
        None
    } else if flags & TIMER_ABSTIME != 0 {
        Some(match clock {
            Clock::Realtime => {
                // Wall-clock deadline: the time left until it, from now
                let (s, ns) = crate::arch::rtc::now();
                let left = (vsec as i128 * 1_000_000_000 + vnsec as i128) - (s as i128 * 1_000_000_000 + ns as i128);
                base + if left > 0 { to_ticks((left / 1_000_000_000) as i64, (left % 1_000_000_000) as i64) } else { 0 }
            }
            _ => to_ticks(vsec, vnsec).max(base),
        })
    } else {
        Some(base + to_ticks(vsec, vnsec).max(1))
    };
    let mut all = TIMERS.lock();
    let Some(t) = all.get_mut(&pid).and_then(|m| m.get_mut(&id)) else { return EINVAL };
    let previous = itimerspec(t, pid);
    t.next = next;
    t.interval = to_ticks(isec, insec);
    t.overrun = 0;
    drop(all);
    if next.is_some() {
        ensure_started();
    }
    CHANGED.wake_all();
    if old != 0 && copy_out(old, &previous).is_err() {
        return EFAULT;
    }
    0
}

/// Handles `timer_create` (222), `timer_settime` (223), `timer_gettime` (224),
/// `timer_getoverrun` (225) and `timer_delete` (226).
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for these calls, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    let (_, pid) = super::proc::current_ids();
    let id = a[0] as i32;
    Some(match num {
        222 => create(a[0], a[1], a[2]),
        223 => settime(id, a[1], a[2], a[3]),
        224 => {
            let spec = TIMERS.lock().get(&pid).and_then(|m| m.get(&id)).map(|t| itimerspec(t, pid));
            match spec {
                Some(s) => {
                    if copy_out(a[1], &s).is_err() {
                        EFAULT
                    } else {
                        0
                    }
                }
                None => EINVAL,
            }
        }
        225 => {
            // Once the signal has been delivered, the expiries counted while it was pending
            // are its overruns (Linux counts them at delivery)
            let target = TIMERS.lock().get(&pid).and_then(|m| m.get(&id)).map(|t| match t.notify {
                Notify::Signal { sig, tid, .. } => Some((sig, tid)),
                Notify::None => None,
            });
            let Some(target) = target else { return Some(EINVAL) };
            let delivered = target.map_or(true, |(sig, tid)| !super::proc::signal_queued(pid, tid, sig));
            let mut all = TIMERS.lock();
            let Some(t) = all.get_mut(&pid).and_then(|m| m.get_mut(&id)) else { return Some(EINVAL) };
            if delivered && t.overrun > 0 {
                t.last_overrun = t.overrun;
                t.overrun = 0;
            }
            t.last_overrun.min(i32::MAX as u32) as i64
        }
        226 => {
            let removed = TIMERS.lock().get_mut(&pid).and_then(|m| m.remove(&id)).is_some();
            if removed {
                CHANGED.wake_all();
                0
            } else {
                EINVAL
            }
        }
        _ => return None,
    })
}
