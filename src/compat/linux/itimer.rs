//! # Linux Compatibility: Interval Timers (`alarm`, `setitimer`, `getitimer`)
//!
//! Implements per-process POSIX interval timers that periodically or once raise a signal
//! upon expiration (`ITIMER_REAL` -> `SIGALRM`, `ITIMER_VIRTUAL` -> `SIGVTALRM`,
//! `ITIMER_PROF` -> `SIGPROF`).
//!
//! ## Architectural Role & Design Rationale
//! Delivering a Linux signal requires acquiring process table and scheduler locks, which
//! cannot safely be done directly inside the hardware timer interrupt handler (IRQ 0)
//! because the interrupted context may already hold those locks. Instead, a dedicated
//! high-priority kernel daemon (`itimerd`), spawned lazily on first timer use, sleeps on
//! [`CHANGED`] until the earliest armed timer's deadline and posts the corresponding signal
//! from normal task context.
//!
//! `ITIMER_REAL` counts wall/boot ticks (10 ms resolution), while `ITIMER_VIRTUAL` and
//! `ITIMER_PROF` count the process's accumulated CPU ticks from the scheduler. Interval
//! timers survive `execve(2)` and are not inherited across `fork(2)`, matching Linux semantics.
//!
//! ## Key Types & Interfaces
//! - [`sys_alarm()`]: Implements `alarm(2)` in whole seconds on `ITIMER_REAL`.
//! - [`sys_getitimer()`]: Implements `getitimer(2)` returning current remaining and interval timevals.
//! - [`sys_setitimer()`]: Implements `setitimer(2)` arming or disarming any of the three process timers.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel syscall handlers and `itimerd` background daemon)
//! - Hardware Interaction: Reads PIT tick counter ([`crate::arch::pit::ticks`])
//! - Concurrency: Global [`TIMERS`] map guarded by [`spin::Mutex`] and coordinated with
//!   `itimerd` via the [`CHANGED`] wait queue.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::task::wait::WaitQueue;

/// Negative errno for invalid `which` timer index or out-of-range `timeval` field.
const EINVAL: i64 = -22;
/// Negative errno for invalid userland `struct itimerval` pointer.
const EFAULT: i64 = -14;

/// Timer index for real-time (wall-clock) countdown delivering `SIGALRM`.
const ITIMER_REAL: u64 = 0;
/// Maximum valid timer index (`ITIMER_PROF = 2`, delivering `SIGPROF`).
const ITIMER_PROF: u64 = 2;

/// Number of microseconds per scheduler PIT tick (10 ms = 10,000 us).
const US_PER_TICK: u64 = 10_000;

/// State of a single armed interval timer: next expiry (in its clock's ticks) and reload interval (`0` = one-shot).
#[derive(Clone, Copy, Default)]
struct Timer {
    /// Absolute tick value (on the timer's respective clock) at which the timer next expires.
    next: u64,
    /// Periodic reload interval in ticks (`0` for a single-shot timer).
    interval: u64,
}

/// Holds the three POSIX interval timers (`ITIMER_REAL`, `ITIMER_VIRTUAL`, `ITIMER_PROF`) for a single process.
#[derive(Default)]
struct ProcTimers {
    /// Array of timers indexed by `ITIMER_*` (`0..3`).
    t: [Option<Timer>; 3],
}

/// Global map from process ID (`tgid`) to its active [`ProcTimers`].
static TIMERS: Mutex<BTreeMap<u64, ProcTimers>> = Mutex::new(BTreeMap::new());
/// Wait queue waking `itimerd` whenever a process arms or updates a timer with a potentially earlier deadline.
static CHANGED: WaitQueue = WaitQueue::new();
/// Atomic flag ensuring the `itimerd` background kernel task is spawned at most once.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Returns the current boot tick count from the PIT.
fn now() -> u64 {
    crate::arch::pit::ticks()
}

/// Returns the total CPU time consumed by process `pid` in scheduler ticks.
fn cpu_ticks(pid: u64) -> u64 {
    crate::task::SCHEDULER.lock().process_ticks(pid)
}

/// Returns the current value of the clock backing timer `which` for process `pid`, in ticks.
fn clock(which: usize, pid: u64) -> u64 {
    if which == ITIMER_REAL as usize {
        now()
    } else {
        cpu_ticks(pid)
    }
}

/// Maps timer index `which` (`0..3`) to the Linux signal number it raises on expiry.
fn signal_for(which: usize) -> u32 {
    match which {
        0 => super::proc::SIGALRM,
        1 => super::proc::SIGVTALRM,
        _ => super::proc::SIGPROF,
    }
}

/// Main loop of the `itimerd` kernel daemon that checks armed interval timers and posts signals.
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

/// Lazily spawns the `itimerd` kernel thread on the first call to arm a timer.
fn ensure_started() {
    if !STARTED.swap(true, Ordering::AcqRel) {
        crate::task::spawn("itimerd", itimerd_main, crate::task::TaskPriority::High);
    }
}

/// Returns `(remaining_ticks, interval_ticks)` for timer `which` of process `pid`.
fn get(pid: u64, which: usize) -> (u64, u64) {
    let t = TIMERS.lock().get(&pid).and_then(|p| p.t[which]);
    match t {
        Some(t) => (t.next.saturating_sub(clock(which, pid)).max(1), t.interval),
        None => (0, 0),
    }
}

/// Arms (`value > 0`) or disarms (`value == 0`) timer `which` for process `pid` with values in ticks.
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

/// Validates a `(tv_sec, tv_usec)` pair and converts it into scheduler ticks (rounding up).
fn ticks_from_timeval(sec: i64, usec: i64) -> Result<u64, i64> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    let us = sec as u64 * 1_000_000 + usec as u64;
    Ok((us + US_PER_TICK - 1) / US_PER_TICK)
}

/// Writes a 32-byte `struct itimerval { it_interval, it_value }` to user address `ptr`.
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

/// System call handler for `alarm(seconds)` (`SYSCALL 37`).
///
/// Schedules a one-shot `SIGALRM` delivery in `seconds` seconds (or cancels any pending alarm
/// when `seconds == 0`), returning the number of seconds remaining on any previously armed alarm.
///
/// # Arguments
/// * `seconds` - Countdown duration in seconds (`0` disarms the alarm).
///
/// # Returns
/// Whole seconds remaining until the previous `ITIMER_REAL` timer would have expired (rounded up).
pub fn sys_alarm(seconds: u64) -> i64 {
    let (_, pid) = super::proc::current_ids();
    let (left, _) = get(pid, 0);
    set(pid, 0, seconds.min(u32::MAX as u64) * 100, 0);
    ((left + 99) / 100) as i64
}

/// System call handler for `getitimer(which, curr_value)` (`SYSCALL 36`).
///
/// # Arguments
/// * `which` - Timer selector: `ITIMER_REAL` (`0`), `ITIMER_VIRTUAL` (`1`), or `ITIMER_PROF` (`2`).
/// * `ptr` - User virtual address of the destination `struct itimerval`.
///
/// # Returns
/// `0` on success, `-EINVAL` if `which > 2`, or `-EFAULT` if `ptr` is unmapped.
pub fn sys_getitimer(which: u64, ptr: u64) -> i64 {
    if which > ITIMER_PROF {
        return EINVAL;
    }
    let (_, pid) = super::proc::current_ids();
    let (value, interval) = get(pid, which as usize);
    put_itimerval(ptr, interval, value)
}

/// System call handler for `setitimer(which, new_value, old_value)` (`SYSCALL 38`).
///
/// Arms or disarms the specified interval timer for the calling process and optionally
/// writes the previous timer setting to `old_ptr`.
///
/// # Arguments
/// * `which` - Timer selector: `ITIMER_REAL` (`0`), `ITIMER_VIRTUAL` (`1`), or `ITIMER_PROF` (`2`).
/// * `new_ptr` - User virtual address of the new `struct itimerval` (`0` disarms the timer).
/// * `old_ptr` - Optional user virtual address to receive the previous `struct itimerval` (`0` if unused).
///
/// # Returns
/// `0` on success, `-EINVAL` if `which > 2` or a `timeval` field is invalid, or `-EFAULT` on bad pointer.
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
