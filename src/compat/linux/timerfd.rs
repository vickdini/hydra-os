//! # `timerfd`
//!
//! Timers delivered through a descriptor: `timerfd_settime` arms a one-shot or periodic
//! timer, and reading returns the number of expirations since the last read (waiting for
//! the next one if there were none). `poll`/`epoll` waits end when the timer expires
//! ([`crate::task::wait::Deadline`]).
//!
//! Time has the scheduler tick's resolution (10 ms), the same clock `clock_gettime`
//! reports. `CLOCK_REALTIME` timers are converted to the tick clock when armed (a later
//! change of the wall clock does not move them).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::task::wait::{Deadline, QueueRef, WaitQueue, WaitSet};

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

const TFD_NONBLOCK: u64 = 0o4000;
const TFD_CLOEXEC: u64 = 0o2000000;
const TFD_TIMER_ABSTIME: u64 = 1;
const CLOCK_REALTIME: u64 = 0;

const NS_PER_TICK: u64 = 10_000_000;

#[derive(Default)]
struct Timer {
    /// Next expiry in nanoseconds of the tick clock (`None` = disarmed).
    next: Option<u64>,
    interval: u64,
}

/// Represents a Linux timer file descriptor (`timerfd`).
pub struct TimerFd {
    clock: u64,
    timer: Mutex<Timer>,
    nonblock: AtomicBool,
    /// Wait queue awakened on timer expiration events.
    pub wq: Arc<WaitQueue>,
}

fn now_ns() -> u64 {
    crate::arch::pit::ticks() * NS_PER_TICK
}

/// Wall-clock time minus the tick clock (to convert `CLOCK_REALTIME` deadlines).
fn realtime_offset_ns() -> i128 {
    let (s, ns) = crate::arch::rtc::now();
    (s as i128) * 1_000_000_000 + ns as i128 - now_ns() as i128
}

impl Deadline for TimerFd {
    fn next_tick(&self) -> Option<u64> {
        self.timer.lock().next.map(|n| (n + NS_PER_TICK - 1) / NS_PER_TICK)
    }
}

impl TimerFd {
    /// Expirations so far, advancing a periodic timer past now.
    fn expirations(&self) -> u64 {
        let mut t = self.timer.lock();
        let now = now_ns();
        match t.next {
            Some(next) if now >= next => {
                if t.interval == 0 {
                    t.next = None;
                    1
                } else {
                    let n = 1 + (now - next) / t.interval;
                    t.next = Some(next + n * t.interval);
                    n
                }
            }
            _ => 0,
        }
    }

    /// Polls readiness of this timer descriptor (returns `POLLIN` when expired).
    pub fn poll_events(&self) -> u32 {
        let t = self.timer.lock();
        match t.next {
            Some(next) if now_ns() >= next => 0x0001,
            _ => 0,
        }
    }

    /// Sets or clears non-blocking I/O mode on this timer descriptor.
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Queries whether non-blocking mode is currently enabled on this descriptor.
    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Reads the 8-byte unsigned integer count of expirations that occurred.
    pub fn read(self: &Arc<Self>, buf: &mut [u8]) -> i64 {
        if buf.len() < 8 {
            return EINVAL;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.wq.clone()));
        waits.add_deadline(self.clone());
        loop {
            waits.register();
            let n = self.expirations();
            if n > 0 {
                buf[..8].copy_from_slice(&n.to_ne_bytes());
                return 8;
            }
            if self.get_nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    /// (interval, remaining) in nanoseconds.
    fn current(&self) -> (u64, u64) {
        let t = self.timer.lock();
        (t.interval, t.next.map_or(0, |n| n.saturating_sub(now_ns()).max(1)))
    }
}

fn read_timespec(b: &[u8]) -> Result<u64, i64> {
    let s = i64::from_le_bytes(b[0..8].try_into().unwrap());
    let ns = i64::from_le_bytes(b[8..16].try_into().unwrap());
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    Ok(s as u64 * 1_000_000_000 + ns as u64)
}

fn put_itimerspec(ptr: u64, interval: u64, value: u64) -> i64 {
    if !crate::memory::vm::prefault_current(ptr, 32, true) {
        return EFAULT;
    }
    let words = [interval / 1_000_000_000, interval % 1_000_000_000, value / 1_000_000_000, value % 1_000_000_000];
    for (i, w) in words.iter().enumerate() {
        unsafe { core::ptr::write_unaligned((ptr + i as u64 * 8) as *mut u64, *w) };
    }
    0
}

fn timerfd_of(fd: u64) -> Option<Arc<TimerFd>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::TimerFd(t)) => Some(t.clone()),
        _ => None,
    })
}

/// `timerfd_create(clockid, flags)`.
pub fn sys_create(clock: u64, flags: u64) -> i64 {
    // REALTIME, MONOTONIC, BOOTTIME, REALTIME_ALARM, BOOTTIME_ALARM
    if !matches!(clock, 0 | 1 | 7 | 8 | 9) || flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return EINVAL;
    }
    let t = Arc::new(TimerFd {
        clock,
        timer: Mutex::new(Timer::default()),
        nonblock: AtomicBool::new(flags & TFD_NONBLOCK != 0),
        wq: WaitQueue::new_shared(),
    });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::TimerFd(t)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & TFD_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// `timerfd_settime(fd, flags, new, old)`.
pub fn sys_settime(fd: u64, flags: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    let t = match timerfd_of(fd) {
        Some(t) => t,
        None => return EINVAL,
    };
    if !crate::memory::vm::prefault_current(new_ptr, 32, false) {
        return EFAULT;
    }
    let mut raw = [0u8; 32];
    unsafe { core::ptr::copy_nonoverlapping(new_ptr as *const u8, raw.as_mut_ptr(), 32) };
    let (interval, value) = match (read_timespec(&raw[0..16]), read_timespec(&raw[16..32])) {
        (Ok(i), Ok(v)) => (i, v),
        _ => return EINVAL,
    };
    if old_ptr != 0 {
        let (i, v) = t.current();
        let r = put_itimerspec(old_ptr, i, v);
        if r != 0 {
            return r;
        }
    }
    let next = if value == 0 {
        None
    } else if flags & TFD_TIMER_ABSTIME != 0 {
        let at = if t.clock == CLOCK_REALTIME || t.clock == 8 {
            (value as i128 - realtime_offset_ns()).max(0) as u64
        } else {
            value
        };
        Some(at)
    } else {
        Some(now_ns() + value)
    };
    *t.timer.lock() = Timer { next, interval };
    t.wq.wake_all(); // waiters recompute their deadline
    0
}

/// `timerfd_gettime(fd, cur)`.
pub fn sys_gettime(fd: u64, cur_ptr: u64) -> i64 {
    match timerfd_of(fd) {
        Some(t) => {
            let (i, v) = t.current();
            put_itimerspec(cur_ptr, i, v)
        }
        None => EINVAL,
    }
}
