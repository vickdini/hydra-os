//! # `timer_arm`: timers for linux-server (wave 5, Group 13)
//!
//! The server asks for a notification at a deadline of the kernel's monotonic clock
//! (`arch::pit::now_ns`): `SYS_LX_TIMER(LX_TIMER_ARM, cookie, ns)`. When the deadline
//! passes, the kernel posts [`LX_NOTE_TIMER`]`(cookie, deadline)` to the server's
//! notification ring and rings its main thread. The cookie is the server's own (a timerfd,
//! a blocked call's timeout, ...); arming a cookie again replaces its deadline. Each service
//! (host, wave 6) has its own cookies; a timer goes to the ring of the host that armed it.
//!
//! `LX_TIMER_VVAR` (wave 6, Group 25) maps the clock's state page (the vDSO's `[vvar]`) into
//! the server, read-only: it reads the clock as the vDSO does, without a system call.
//!
//! Deadlines are checked at every timer tick ([`on_tick`], 10 ms), the resolution of every
//! other timer in the kernel. The tick only compares the earliest deadline with the clock
//! ([`NEXT`]); the list is taken with `try_lock` (a busy list waits for the next tick).

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::ipc::protocol::{LX_NOTE_TIMER, LX_TIMER_ARM, LX_TIMER_CANCEL, LX_TIMER_NOW, LX_TIMER_VVAR};

const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const ENOMEM: i64 = -12;

/// Most timers armed at once.
const MAX_TIMERS: usize = 8192;

/// The armed timers: `(deadline, host, cookie)` in order, and each `(host, cookie)`'s
/// deadline.
struct Timers {
    by_time: BTreeMap<(u64, u8, u64), ()>,
    by_cookie: BTreeMap<(u8, u64), u64>,
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

/// `SYS_LX_TIMER(op, cookie, ns)` (native 62), for the services.
pub fn sys_timer(op: u64, cookie: u64, ns: u64) -> i64 {
    let h = match super::server_caller() {
        Ok((_, _, h)) => h,
        Err(e) => return e,
    };
    match op {
        LX_TIMER_ARM => with(|t| {
            if let Some(old) = t.by_cookie.insert((h, cookie), ns) {
                t.by_time.remove(&(old, h, cookie));
            } else if t.by_cookie.len() > MAX_TIMERS {
                t.by_cookie.remove(&(h, cookie));
                return ENOSPC;
            }
            t.by_time.insert((ns, h, cookie), ());
            set_next(t);
            0
        }),
        LX_TIMER_CANCEL => with(|t| {
            if let Some(old) = t.by_cookie.remove(&(h, cookie)) {
                t.by_time.remove(&(old, h, cookie));
                set_next(t);
            }
            0
        }),
        LX_TIMER_NOW => crate::arch::pit::now_ns() as i64,
        // Wave 6 (Group 25): the clock's state page, so the server reads the clock without
        // a system call (timerfd_settime made two: the clock and the arm)
        LX_TIMER_VVAR => {
            let Some(mm) = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten() else { return EINVAL };
            let r = crate::arch::vdso::map_vvar(&mut mm.lock()).map_or(ENOMEM, |a| a as i64);
            r
        }
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
    let mut hosts = 0u32;
    while let Some((&(at, h, cookie), _)) = t.by_time.iter().next() {
        if at > now || fired >= 64 {
            break;
        }
        t.by_time.remove(&(at, h, cookie));
        t.by_cookie.remove(&(h, cookie));
        if let Some(x) = super::svc::host(h) {
            super::note_quiet_to(x, LX_NOTE_TIMER, cookie, at, 0);
            hosts |= 1 << h;
        }
        fired += 1;
    }
    set_next(&t);
    drop(t);
    for h in 0..32u8 {
        if hosts & (1 << h) != 0 {
            if let Some(x) = super::svc::host(h) {
                crate::ipc::service::notify(x.endpoint.load(Ordering::Relaxed), crate::ipc::protocol::NOTIFY_LX_NOTES);
            }
        }
    }
    fired > 0
}

/// Host `h`'s process went away: its timers go with it.
pub(super) fn clear(h: u8) {
    with(|t| {
        t.by_time.retain(|k, _| k.1 != h);
        t.by_cookie.retain(|k, _| k.0 != h);
        set_next(t);
    });
}
