//! Sockets in linux-server (wave 5, Group 12): the dispatch of the socket calls, blocked
//! calls, and readiness.
//!
//! - **Dispatch** (the server's half of `src/lx`'s socket routing): `socket`/`socketpair`
//!   by address family ([`by_family`]); every call on a socket descriptor, and `read`,
//!   `write`, `readv`, `writev`, `ioctl` on one, by the kind of its server object
//!   ([`by_kind`]). Internet sockets are [`crate::inet`]'s, netlink sockets
//!   [`crate::netlink`]'s; Group 13 adds the AF_UNIX family and its kinds here.
//! - **Blocked calls**: a call that must wait (a `recv` with nothing to read, an `accept`
//!   with no connection, a `connect` in progress, a `send` with no room) answers
//!   "pending" and is kept here ([`Waiter`]) with what it did so far ([`Prog`]); no worker
//!   waits. It is tried again when its socket's readiness changes (net-server's doorbell,
//!   relayed by the main thread: [`notified`]) or something local happens ([`poke`]),
//!   and completed (`SYS_LX_COMPLETE`), at its deadline (`SO_RCVTIMEO`/`SO_SNDTIMEO`:
//!   [`tick`]), by a signal ([`interrupted`]), or dropped when its process ends.
//! - **No lost wake-ups**: every slot has an event count ([`SEQ`]) bumped before its
//!   waiters are tried again; a call that is about to wait checks, under the waiter list's
//!   lock, that the count did not move since its attempt began, and tries again if it did.
//! - **Readiness words**: after every call and every relayed event the socket's poll bits
//!   go to its object's readiness word (`obj::set_ready_ev`), which the kernel's `poll`,
//!   `select` and `epoll` read without asking us (waiters stay call-free).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;

pub const ERESTARTSYS: i64 = -512;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const ENOTSOCK: i64 = -88;
const EAFNOSUPPORT: i64 = -97;
const EOPNOTSUPP: i64 = -95;

/// What one attempt at a socket call came to.
pub enum Out {
    /// Answered.
    Done(i64),
    /// It must wait (only for a blocking call): try again on the socket's next event.
    Block,
}

/// What a blocking call did so far, kept across its attempts.
pub struct Prog {
    /// Bytes sent so far (a stream send goes on where it stopped).
    pub sent: usize,
    /// The deadline in ticks, fixed at the first wait (`Some(None)`: none).
    pub deadline: Option<Option<u64>>,
    /// The answer at the deadline (`EAGAIN`; a connect: `EINPROGRESS`).
    pub on_timeout: i64,
    /// The answer to a signal: `ERESTARTSYS` (restarted with `SA_RESTART`), `EINTR` for a
    /// call with a timeout, as Linux.
    pub on_signal: i64,
}

impl Prog {
    pub const fn new() -> Self {
        Self { sent: 0, deadline: None, on_timeout: EAGAIN, on_signal: ERESTARTSYS }
    }

    /// The call is about to wait, bounded by `timeout_ns` (fixed at the first wait).
    pub fn wait(&mut self, timeout_ns: Option<u64>) -> Out {
        if self.deadline.is_none() {
            self.deadline = Some(timeout_ns.map(|ns| sys::uptime_ticks() + ns.div_ceil(10_000_000).max(1)));
            if timeout_ns.is_some() {
                self.on_signal = EINTR;
            }
        }
        Out::Block
    }

    /// The answer when the wait ends without the call finishing (`why`): bytes already sent
    /// win.
    fn ended(&self, why: i64) -> i64 {
        if self.sent > 0 {
            self.sent as i64
        } else {
            why
        }
    }
}

/// A blocked call.
struct Waiter {
    c: LxCall,
    slot: u32,
    prog: Prog,
}

/// The blocked calls.
static WAITERS: YLock<Vec<Waiter>> = YLock::new(Vec::new());
/// Per slot: events seen (see "No lost wake-ups" above).
static SEQ: [AtomicU32; LX_OBJ_SLOTS] = [const { AtomicU32::new(0) }; LX_OBJ_SLOTS];
/// Slots with a local event whose waiters the main thread tries again.
static POKED: YLock<Vec<u32>> = YLock::new(Vec::new());
/// Signals for blocked calls that were being tried again (out of [`WAITERS`]) when the
/// signal's notification was taken: answered when they come back.
static LATE_INTR: YLock<Vec<u64>> = YLock::new(Vec::new());
/// Waiters out of [`WAITERS`] being tried again.
static RETRYING: AtomicU32 = AtomicU32::new(0);

/// One attempt at socket call `cx` on its object.
fn run(cx: &Cx, prog: &mut Prog) -> Out {
    match crate::obj::kind_of(cx.c.obj as u32) {
        LX_OBJ_KIND_INET => crate::inet::call(cx, prog),
        LX_OBJ_KIND_NETLINK => crate::netlink::call(cx, prog),
        _ => Out::Done(ENOTSOCK),
    }
}

/// Writes slot `slot`'s readiness word from its socket (`event`: something new happened).
fn refresh(slot: u32, event: bool) {
    match crate::obj::kind_of(slot) {
        LX_OBJ_KIND_INET => crate::inet::refresh(slot, event),
        LX_OBJ_KIND_NETLINK => crate::netlink::refresh(slot),
        _ => {}
    }
}

/// `socket` (41) and `socketpair` (53): by address family.
pub fn by_family(cx: &Cx) -> (i64, u64) {
    let r = match (cx.nr, cx.args[0]) {
        (41, 2 | 10) => crate::inet::socket(cx),
        (41, 16) => crate::netlink::socket(cx),
        (53, 2 | 10 | 16) => EOPNOTSUPP,
        _ => EAFNOSUPPORT,
    };
    (r, 0)
}

/// A call on a socket's server object (`cx.c.obj`): its owner by kind, waiting if it must.
pub fn by_kind(cx: &Cx) -> (i64, u64) {
    let slot = cx.c.obj as u32;
    if slot as usize >= LX_OBJ_SLOTS {
        return (ENOTSOCK, 0);
    }
    let mut prog = Prog::new();
    loop {
        let seq = SEQ[slot as usize].load(Ordering::Acquire);
        match run(cx, &mut prog) {
            Out::Done(r) => {
                refresh(slot, false);
                return (r, 0);
            }
            Out::Block => {
                let mut w = WAITERS.lock();
                if SEQ[slot as usize].load(Ordering::Acquire) != seq {
                    // Something happened since the attempt began: once more
                    continue;
                }
                let timed = prog.deadline.is_some_and(|d| d.is_some());
                w.push(Waiter { c: cx.c, slot, prog });
                drop(w);
                refresh(slot, false);
                if timed {
                    crate::timeout::kick();
                }
                return (0, LX_REPLY_PENDING);
            }
        }
    }
}

/// Tries the waiters of `slots` (all with `None`) again, completing those that finish.
fn retry(slots: Option<&[u32]>) {
    let taken: Vec<Waiter> = {
        let mut w = WAITERS.lock();
        let mut out = Vec::new();
        let mut i = 0;
        while i < w.len() {
            if slots.is_none_or(|s| s.contains(&w[i].slot)) {
                out.push(w.swap_remove(i));
            } else {
                i += 1;
            }
        }
        RETRYING.fetch_add(out.len() as u32, Ordering::AcqRel);
        out
    };
    for mut wt in taken {
        let slot = wt.slot as usize;
        let mut tries = 0;
        loop {
            let seq = SEQ[slot].load(Ordering::Acquire);
            let cx = Cx::from_call(&wt.c, core::ptr::null_mut());
            match run(&cx, &mut wt.prog) {
                Out::Done(r) => {
                    RETRYING.fetch_sub(1, Ordering::AcqRel);
                    let _ = sys::lx_complete(wt.c.id, r);
                    refresh(wt.slot, false);
                    break;
                }
                Out::Block => {
                    let mut w = WAITERS.lock();
                    tries += 1;
                    if SEQ[slot].load(Ordering::Acquire) != seq && tries < 8 {
                        continue;
                    }
                    let id = wt.c.id;
                    w.push(wt);
                    drop(w);
                    RETRYING.fetch_sub(1, Ordering::AcqRel);
                    let late = {
                        let mut l = LATE_INTR.lock();
                        let before = l.len();
                        l.retain(|&x| x != id);
                        l.len() != before
                    };
                    if late {
                        interrupted(id);
                    }
                    break;
                }
            }
        }
    }
}

/// A local event on slot `slot` (a shutdown, a netlink message for it): its waiters are
/// tried again by the main thread.
pub fn poke(slot: u32) {
    if (slot as usize) < LX_OBJ_SLOTS {
        SEQ[slot as usize].fetch_add(1, Ordering::AcqRel);
        POKED.lock().push(slot);
        let _ = sys::lx_ctl(LX_CTL_WAKE);
    }
}

/// The main thread, after waking: the notification bits the kernel raised (net-server's
/// doorbell, net-server gone) and the local events.
pub fn notified(bits: u64) {
    if bits & NOTIFY_LX_NET_GONE != 0 {
        crate::netc::gone();
        let slots = crate::inet::all_slots();
        for &s in &slots {
            SEQ[s as usize].fetch_add(1, Ordering::AcqRel);
            refresh(s, true);
        }
        retry(Some(&slots));
    }
    if bits & NOTIFY_LX_NET != 0 {
        let slots = match crate::netc::take_events() {
            Some(handles) => crate::inet::slots_of(&handles),
            None => crate::inet::all_slots(),
        };
        if !slots.is_empty() {
            for &s in &slots {
                SEQ[s as usize].fetch_add(1, Ordering::AcqRel);
                refresh(s, true);
            }
            retry(Some(&slots));
        }
    }
    let poked = core::mem::take(&mut *POKED.lock());
    if !poked.is_empty() {
        retry(Some(&poked));
    }
}

/// A signal arrived for the caller of pending request `id`: answered at once if it is one
/// of ours (`true`).
pub fn interrupted(id: u64) -> bool {
    let w = {
        let mut w = WAITERS.lock();
        match w.iter().position(|x| x.c.id == id) {
            Some(i) => w.swap_remove(i),
            None => {
                // Perhaps being tried again right now: answered when it comes back
                let mut l = LATE_INTR.lock();
                if RETRYING.load(Ordering::Acquire) != 0 && l.len() < 256 {
                    l.push(id);
                }
                return false;
            }
        }
    };
    let _ = sys::lx_complete(id, w.prog.ended(w.prog.on_signal));
    true
}

/// Process `tgid` ended: its blocked calls go (the kernel dropped them).
pub fn on_exit(tgid: u64) {
    WAITERS.lock().retain(|w| w.c.tgid != tgid);
    LATE_INTR.lock().clear();
}

/// The last descriptor of slot `slot` went (no call of it can be waiting: the kernel holds
/// a descriptor for each call in flight); leftovers go anyway.
pub fn closed(slot: u32) {
    WAITERS.lock().retain(|w| w.slot != slot);
}

/// Completes the blocked calls whose deadline passed; the earliest deadline still waiting.
pub fn tick(now: u64) -> Option<u64> {
    let due: Vec<Waiter> = {
        let mut w = WAITERS.lock();
        let mut out = Vec::new();
        let mut i = 0;
        while i < w.len() {
            if w[i].prog.deadline.flatten().is_some_and(|d| d <= now) {
                out.push(w.swap_remove(i));
            } else {
                i += 1;
            }
        }
        out
    };
    for w in due {
        let _ = sys::lx_complete(w.c.id, w.prog.ended(w.prog.on_timeout));
    }
    WAITERS.lock().iter().filter_map(|w| w.prog.deadline.flatten()).min()
}

/// Blocked socket calls now (for the server's status).
#[allow(dead_code)]
pub fn waiting() -> usize {
    WAITERS.lock().len()
}
