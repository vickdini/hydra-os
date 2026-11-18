//! # `timer_arm`: timers for linux-server (wave 5, Group 13)
//!
//! The server asks for a notification at a deadline of the kernel's monotonic clock
//! (`arch::pit::now_ns`): `SYS_LX_TIMER(LX_TIMER_ARM, cookie, ns)`. When the deadline
//! passes, the kernel posts [`LX_NOTE_TIMER`]`(cookie, deadline)` to the server's
//! notification ring and rings its main thread. The cookie is the server's own (a timerfd,
//! a blocked call's timeout, ...); arming a cookie again replaces its deadline.
//!
//! Deadlines are checked at every timer tick ([`on_tick`], 10 ms), the resolution of every
//! other timer in the kernel. The tick only compares the earliest deadline with the clock
//! ([`NEXT`]); the list is taken with `try_lock` (a busy list waits for the next tick).

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::protocol::{LX_NOTE_TIMER, LX_TIMER_ARM, LX_TIMER_CANCEL, LX_TIMER_NOW};

const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;

/// Most timers armed at once.
const MAX_TIMERS: usize = 8192;

/// The armed timers: `(deadline, cookie)` in order, and each cookie's deadline.
struct Timers {
    by_time: BTreeMap<(u64, u64), ()>,
    by_cookie: BTreeMap<u64, u64>,
}

static TIMERS: Mutex<Timers> = Mutex::new(Timers { by_time: BTreeMap::new(), by_cookie: BTreeMap::new() });
/// The earliest deadline (`u64::MAX`: none): all a tick looks at.
static NEXT: AtomicU64 = AtomicU64::new(u64::MAX);

fn with<R>(f: impl FnOnce(&mut Timers) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TIMERS.lock()))
}

fn set_next(t: &Timers) {
    NEXT.store(t.by_time.keys().next().map_or(u64::MAX, |k| k.0), Ordering::Release);
}

/// `SYS_LX_TIMER(op, cookie, ns)` (native 62), for linux-server only.
pub fn sys_timer(op: u64, cookie: u64, ns: u64) -> i64 {
    if let Err(e) = super::server_caller() {
        return e;
    }
    match op {
        LX_TIMER_ARM => with(|t| {
            if let Some(old) = t.by_cookie.insert(cookie, ns) {
                t.by_time.remove(&(old, cookie));
            } else if t.by_cookie.len() > MAX_TIMERS {
                t.by_cookie.remove(&cookie);
                return ENOSPC;
            }
            t.by_time.insert((ns, cookie), ());
            set_next(t);
            0
        }),
        LX_TIMER_CANCEL => with(|t| {
            if let Some(old) = t.by_cookie.remove(&cookie) {
                t.by_time.remove(&(old, cookie));
                set_next(t);
            }
            0
        }),
        LX_TIMER_NOW => crate::arch::pit::now_ns() as i64,
        _ => EINVAL,
    }
}

/// The earliest deadline (`u64::MAX`: none), for the idle loop's precise wait.
pub fn next_due() -> u64 {
    NEXT.load(Ordering::Relaxed)
}

/// Called at every timer tick, and by an idle CPU at the earliest deadline (interrupts
/// off): posts the timers whose deadline passed.
pub fn on_tick() {
    fire();
}

/// [`on_tick`]: `true` if a timer was posted (the server's main thread was woken).
pub fn fire() -> bool {
    let next = NEXT.load(Ordering::Acquire);
    if next == u64::MAX {
        return false;
    }
    let now = crate::arch::pit::now_ns();
    if now < next {
        return false;
    }
    // Another CPU changes the list: the next tick looks again
    let Some(mut t) = TIMERS.try_lock() else { return false };
    let mut fired = 0;
    while let Some((&(at, cookie), _)) = t.by_time.iter().next() {
        if at > now || fired >= 64 {
            break;
        }
        t.by_time.remove(&(at, cookie));
        t.by_cookie.remove(&cookie);
        super::note_quiet(LX_NOTE_TIMER, cookie, at, 0);
        fired += 1;
    }
    set_next(&t);
    drop(t);
    if fired > 0 {
        crate::ipc::service::notify(crate::ipc::protocol::ENDPOINT_LINUX_SERVER, crate::ipc::protocol::NOTIFY_LX_NOTES);
    }
    fired > 0
}

/// The server went away: its timers go with it.
pub(super) fn clear() {
    with(|t| {
        t.by_time.clear();
        t.by_cookie.clear();
        set_next(t);
    });
}
