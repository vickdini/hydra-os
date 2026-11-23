//! timerfd (`timerfd_create`, `timerfd_settime`, `timerfd_gettime`), moved here from the
//! kernel's `src/compat/linux/timerfd.rs` (wave 5, step 4), on the kernel's `timer_arm`.
//!
//! A timer delivered through a descriptor: reading returns the expirations since the last
//! read (waiting for the next one if there were none); `poll`/`epoll` see it readable once
//! it expired. Each armed timer has one `timer_arm` deadline (`SYS_LX_TIMER`, cookie
//! [`TIMER_TAG`] | slot): when it passes, the kernel's `LX_NOTE_TIMER` makes the descriptor
//! readable and completes waiting reads; a periodic timer is armed again after each read.
//! Time is the kernel's monotonic clock with the scheduler tick's resolution (10 ms), as
//! before; `CLOCK_REALTIME` deadlines are converted when armed.
//!
//! Wave 6 (Group 25): `timerfd_settime` costs no system call of its own in the common case.
//! The clock is read from the kernel's clock page (`LX_TIMER_VVAR`, the vDSO's `[vvar]`),
//! and the kernel timer is armed lazily: a timer moved later (an event loop pushing its
//! timeout on) or stopped keeps the kernel deadline it has; when that earlier deadline
//! fires, [`fired`] arms the real one (or nothing). Only a deadline earlier than the armed
//! one, or the first, needs `LX_TIMER_ARM`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::fdio::kbuf;
use crate::kstore;
use crate::lock::YLock;

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ERESTARTSYS: i64 = -512;

const TFD_NONBLOCK: u64 = 0o4000;
const TFD_CLOEXEC: u64 = 0o2000000;
const TFD_TIMER_ABSTIME: u64 = 1;
const TFD_TIMER_CANCEL_ON_SET: u64 = 2;

/// The `timer_arm` cookies of timerfds: this tag | the slot.
pub const TIMER_TAG: u64 = 1 << 56;

struct Tfd {
    /// wave9 GX3: its id (`kstore` record).
    id: u64,
    /// Partial answers of waiting calls, published after the record write.
    pend: kstore::Pend,
    clock: u64,
    /// The next expiry (monotonic ns), and the period (0: one-shot).
    next: Option<u64>,
    interval: u64,
    /// The kernel timer's deadline as armed (it may be earlier than `next`, or the timer
    /// stopped: see the module's comment); `None`: not armed (or it fired).
    armed: Option<u64>,
    /// Readers waiting: `(call, buffer)`.
    readers: Vec<(LxCall, u64)>,
}

static T: YLock<BTreeMap<u32, Tfd>> = YLock::new(BTreeMap::new());

/// The kernel's clock page ([`LxVvar`]): 0 not mapped yet, 1 not available.
static VVAR: AtomicU64 = AtomicU64::new(0);

fn vvar() -> Option<&'static LxVvar> {
    let mut a = VVAR.load(Ordering::Acquire);
    if a == 0 {
        let r = sys::lx_timer(LX_TIMER_VVAR, 0, 0);
        a = if r > 0 { r as u64 } else { 1 };
        VVAR.store(a, Ordering::Release);
    }
    // SAFETY: the kernel mapped the page read-only for the life of the process
    (a > 1).then(|| unsafe { &*(a as *const LxVvar) })
}

/// The monotonic clock and the wall clock's offset from it (read as the vDSO does).
fn clock_page(v: &LxVvar) -> (u64, i64) {
    loop {
        // SAFETY: plain reads of the kernel's page
        let s = unsafe { core::ptr::read_volatile(&v.seq) };
        if s & 1 != 0 {
            core::hint::spin_loop();
            continue;
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        let (base, frac, base_tsc, mult, wall) = unsafe {
            (
                core::ptr::read_volatile(&v.base_ns),
                core::ptr::read_volatile(&v.base_frac),
                core::ptr::read_volatile(&v.base_tsc),
                core::ptr::read_volatile(&v.mult),
                core::ptr::read_volatile(&v.wall_ns),
            )
        };
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        if unsafe { core::ptr::read_volatile(&v.seq) } != s {
            continue;
        }
        if mult == 0 {
            return (base, wall);
        }
        let total = tsc.saturating_sub(base_tsc) as u128 * mult as u128 + frac as u128;
        return (base + (total >> 32) as u64, wall);
    }
}

fn now() -> u64 {
    match vvar() {
        Some(v) => clock_page(v).0,
        None => sys::lx_timer(LX_TIMER_NOW, 0, 0) as u64,
    }
}

/// Nanoseconds the real-time clock is ahead of the monotonic one.
fn realtime_offset(mono: u64) -> i128 {
    if let Some(v) = vvar() {
        return clock_page(v).1 as i128;
    }
    let (s, ns) = sys::clock();
    s as i128 * 1_000_000_000 + ns as i128 - mono as i128
}

impl Tfd {
    /// wave9 GX3: writes the record (clock, next expiry, period).
    fn persist(&self) {
        if kstore::kept(self.id) {
            let mut w = kstore::W::new(kstore::K_TFD);
            w.u64(self.clock).u64(self.next.map_or(0, |n| n.max(1))).u64(self.interval);
            kstore::put_logged(self.id, &w.0);
        }
    }

    /// Writes the record, then the waiting calls' answers.
    fn commit(&mut self) {
        self.persist();
        kstore::flush(&mut self.pend);
    }

    /// Expirations by `now`, moving `next` on (a periodic timer) or clearing it.
    fn expirations(&mut self, now: u64) -> u64 {
        match self.next {
            Some(next) if now >= next => {
                if self.interval == 0 {
                    self.next = None;
                    1
                } else {
                    let n = 1 + (now - next) / self.interval;
                    self.next = Some(next + n * self.interval);
                    n
                }
            }
            _ => 0,
        }
    }

    /// Arms the kernel timer for the next expiry (unless it is armed for that time or
    /// earlier already) and sets the readiness word. A stopped timer keeps its kernel
    /// timer, which [`fired`] then ignores.
    fn arm(&mut self, slot: u32, now: u64) {
        match self.next {
            Some(n) if n > now => {
                if self.armed.is_none_or(|a| a > n) {
                    sys::lx_timer(LX_TIMER_ARM, TIMER_TAG | slot as u64, n);
                    self.armed = Some(n);
                }
                crate::obj::set_ready(slot, 0, 0);
            }
            Some(_) => crate::obj::set_ready_ev(slot, 0x41, 0, true),
            None => crate::obj::set_ready(slot, 0, 0),
        }
    }
}

fn timespec(b: &[u8]) -> Result<u64, i64> {
    let s = i64::from_le_bytes(b[0..8].try_into().unwrap());
    let ns = i64::from_le_bytes(b[8..16].try_into().unwrap());
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    Ok(s as u64 * 1_000_000_000 + ns as u64)
}

fn itimerspec(interval: u64, value: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, w) in [interval / 1_000_000_000, interval % 1_000_000_000, value / 1_000_000_000, value % 1_000_000_000].iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// `timerfd_create(clock, flags)` (283).
pub fn create(cx: &Cx) -> (i64, u64) {
    let (clock, flags) = (cx.args[0], cx.args[1]);
    // REALTIME, MONOTONIC, BOOTTIME, REALTIME_ALARM, BOOTTIME_ALARM
    if !matches!(clock, 0 | 1 | 7 | 8 | 9) || flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return (EINVAL, 0);
    }
    let slot = match crate::obj::alloc(LX_OBJ_KIND_TIMERFD) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let id = kstore::id();
    let t = Tfd { id, pend: Vec::new(), clock, next: None, interval: 0, armed: None, readers: Vec::new() };
    t.persist();
    T.lock().insert(slot, t);
    match crate::obj::install_keyed(cx, slot, LX_OBJ_KIND_TIMERFD, flags as u32, 0o600, cx.c.euid, cx.c.egid, b"anon_inode:[timerfd]", 0, kstore::key(id)) {
        Ok(fd) => (fd, 0),
        Err(e) => {
            T.lock().remove(&slot);
            kstore::release(id);
            crate::obj::free(slot);
            (e, 0)
        }
    }
}

fn slot_of(cx: &Cx) -> Result<u32, i64> {
    if cx.c.obj == LX_OBJ_NONE || crate::obj::kind_of(cx.c.obj as u32) != LX_OBJ_KIND_TIMERFD {
        return Err(EINVAL);
    }
    Ok(cx.c.obj as u32)
}

/// `timerfd_settime(fd, flags, new, old)` (286).
pub fn settime(cx: &Cx) -> (i64, u64) {
    let slot = match slot_of(cx) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let flags = cx.args[1];
    // wave9 GX3: setting the same timer again does the same: always safe to send again
    kstore::resend_safe(cx.page(), cx.id, true);
    if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
        return (EINVAL, 0);
    }
    let raw = match cx.copy_in(cx.args[2], 32) {
        Ok(r) => r,
        Err(e) => return (e, 0),
    };
    let (interval, value) = match (timespec(&raw[0..16]), timespec(&raw[16..32])) {
        (Ok(i), Ok(v)) => (i, v),
        _ => return (EINVAL, 0),
    };
    let now = now();
    let mut done = Vec::new();
    let old = {
        let mut m = T.lock();
        let Some(t) = m.get_mut(&slot) else { return (EBADF, 0) };
        let old = itimerspec(t.interval, t.next.map_or(0, |n| n.saturating_sub(now).max(1)));
        t.next = if value == 0 {
            None
        } else if flags & TFD_TIMER_ABSTIME != 0 {
            Some(if t.clock == 0 || t.clock == 8 { (value as i128 - realtime_offset(now)).max(0) as u64 } else { value })
        } else {
            Some(now + value)
        };
        t.interval = interval;
        t.arm(slot, now);
        if t.next.is_some_and(|n| n <= now) {
            serve_readers(t, now, &mut done);
        }
        t.commit();
        old
    };
    finish(done);
    if cx.args[3] != 0 {
        if let Err(e) = cx.copy_out(cx.args[3], &old) {
            return (e, 0);
        }
    }
    (0, 0)
}

/// `timerfd_gettime(fd, cur)` (287).
pub fn gettime(cx: &Cx) -> (i64, u64) {
    let slot = match slot_of(cx) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    kstore::resend_safe(cx.page(), cx.id, true);
    let now = now();
    let cur = {
        let m = T.lock();
        let Some(t) = m.get(&slot) else { return (EBADF, 0) };
        itimerspec(t.interval, t.next.map_or(0, |n| n.saturating_sub(now).max(1)))
    };
    match cx.copy_out(cx.args[1], &cur) {
        Ok(()) => (0, 0),
        Err(e) => (e, 0),
    }
}

/// Completes the waiting readers of timer `t` (expired by `now`).
fn serve_readers(t: &mut Tfd, now: u64, done: &mut Vec<(u64, i64)>) {
    if t.readers.is_empty() {
        return;
    }
    let n = t.expirations(now);
    if n == 0 {
        return;
    }
    // The first reader gets the count; the others wait for the next expiry
    let (c, buf) = t.readers.remove(0);
    let r = match sys::lx_write(c.id, buf, &n.to_ne_bytes()) {
        Ok(()) => {
            t.pend.push((c.id, 8));
            8
        }
        Err(e) => e,
    };
    done.push((c.id, r));
}

fn finish(done: Vec<(u64, i64)>) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
}

/// `read` on a timerfd (slot `cx.c.obj`).
pub fn io(cx: &Cx) -> (i64, u64) {
    if cx.nr != 0 {
        return (EINVAL, 0);
    }
    if cx.args[2] < 8 {
        return (EINVAL, 0);
    }
    let slot = cx.c.obj as u32;
    let now = now();
    kstore::resend_safe(cx.page(), cx.id, true);
    let mut m = T.lock();
    let Some(t) = m.get_mut(&slot) else { return (EBADF, 0) };
    let n = t.expirations(now);
    if n > 0 {
        t.arm(slot, now);
        let r = match cx.copy_out(cx.args[1], &n.to_ne_bytes()) {
            Ok(()) => (8, 0),
            Err(e) => (e, 0),
        };
        t.persist();
        kstore::partial(cx.page(), cx.id, 8);
        return r;
    }
    if cx.nonblock() || kbuf(cx) {
        return (EAGAIN, 0);
    }
    t.readers.push((cx.c, cx.args[1]));
    (0, LX_REPLY_PENDING)
}

/// `LX_NOTE_TIMER` for a timerfd: it expired.
pub fn fired(cookie: u64) {
    let slot = (cookie & 0xFFFF_FFFF) as u32;
    let now = now();
    let mut done = Vec::new();
    {
        let mut m = T.lock();
        let Some(t) = m.get_mut(&slot) else { return };
        // The kernel timer fired: it is armed no more (arming it again is always safe)
        t.armed = None;
        match t.next {
            // (an old deadline: the timer was set again since)
            Some(n) if n > now => t.arm(slot, now),
            Some(_) => {
                crate::obj::set_ready_ev(slot, 0x41, 0, true);
                serve_readers(t, now, &mut done);
                if !done.is_empty() {
                    t.arm(slot, now);
                    t.commit();
                }
            }
            None => {}
        }
    }
    finish(done);
}

/// A signal for the caller of pending call `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    let found = {
        let mut m = T.lock();
        let mut f = false;
        for t in m.values_mut() {
            let n = t.readers.len();
            t.readers.retain(|(c, _)| c.id != id);
            if t.readers.len() != n {
                f = true;
                break;
            }
        }
        f
    };
    if found {
        let _ = sys::lx_complete(id, ERESTARTSYS);
    }
    found
}

/// Process `tgid` ended: its waiting calls are gone.
pub fn on_exit(tgid: u64) {
    for t in T.lock().values_mut() {
        t.readers.retain(|(c, _)| c.tgid != tgid);
    }
}

/// The last descriptor of timerfd `slot` went away.
pub fn closed(slot: u32) {
    if let Some(t) = T.lock().remove(&slot) {
        kstore::release(t.id);
        sys::lx_timer(LX_TIMER_CANCEL, TIMER_TAG | slot as u64, 0);
    }
}

/// wave9 GX3: a restarted lx-ipc takes timerfd `slot` back from record `rec` (id `id`):
/// its kernel timer went with the old instance, so it is armed again (or the descriptor is
/// readable at once if it expired meanwhile).
#[allow(dead_code)] // (linux-server never restores)
pub fn restore(slot: u32, id: u64, rec: &[u8]) -> bool {
    let mut r = kstore::R::new(rec);
    let (Some(kstore::K_TFD), Some(clock), Some(next), Some(interval)) = (r.u8(), r.u64(), r.u64(), r.u64()) else { return false };
    if !matches!(clock, 0 | 1 | 7 | 8 | 9) || !crate::obj::reserve(slot, LX_OBJ_KIND_TIMERFD) {
        return false;
    }
    let mut t = Tfd { id, pend: Vec::new(), clock, next: (next != 0).then_some(next), interval, armed: None, readers: Vec::new() };
    t.arm(slot, now());
    T.lock().insert(slot, t);
    true
}
