//! Sockets in linux-server (wave 5, Group 12): the dispatch of the socket calls, blocked
//! calls, and readiness.
//!
//! - **Dispatch** (the server's half of `src/lx`'s socket routing): `socket`/`socketpair`
//!   by address family ([`by_family`]); every call on a socket descriptor, and `read`,
//!   `write`, `readv`, `writev`, `ioctl` on one, by the kind of its server object
//!   ([`by_kind`]). Internet sockets are [`crate::inet`]'s, netlink sockets
//!   [`crate::netlink`]'s. (Wave 8: this file is lx-net's; AF_UNIX is lx-ipc's `unix`, which
//!   the program serving it dispatches before calling here.)
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
    /// The net-server handle the call waits on and its readiness word as the attempt saw it
    /// (for a net wait in the kernel, `LX_OBJ_NETWAIT`).
    pub wait_on: Option<(u32, u64)>,
}

impl Prog {
    pub const fn new() -> Self {
        Self { sent: 0, deadline: None, on_timeout: EAGAIN, on_signal: ERESTARTSYS, wait_on: None }
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
/// The kernel relays net-server's events to the main thread for [`WAITERS`]
/// (`LX_OBJ_RELAY`; switched on and off under that list's lock).
static RELAY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Switches the relay off once no call waits here (the main thread, after its work).
pub fn relay_check() {
    let w = WAITERS.lock();
    if w.is_empty() && RELAY.load(Ordering::Acquire) {
        RELAY.store(false, Ordering::Release);
        let _ = sys::lx_obj(LX_OBJ_RELAY, 0, 0, 0);
    }
    drop(w);
}
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
    // (AF_UNIX is lx-ipc's `unix::create`, dispatched before this; wave 8)
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
    // (Unix sockets keep their own waiters, in lx-ipc's `unix`: dispatched before this;
    // wave 8)
    // wave8 GX2: a receive, accept or send on an Internet socket has no effect until it
    // takes data or a connection from net-server or hands it bytes: until then
    // (`resend_safe(cx, false)` at that point) a restart of lx-net sends it again instead of
    // failing it
    if matches!(cx.nr, 0 | 19 | 45 | 47 | 43 | 288 | 1 | 20 | 44 | 46) && crate::obj::kind_of(slot) == LX_OBJ_KIND_INET {
        resend_safe(cx, true);
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
                // A wait on a net-server handle with no deadline and nothing done yet: the
                // kernel's net-server doorbell makes the call again (no hop through the main
                // thread); see "Net waits" in the kernel's src/lx
                if let (Some((h, snap)), Some(None), 0) = (prog.wait_on.take(), prog.deadline, prog.sent) {
                    match sys::lx_obj(LX_OBJ_NETWAIT, cx.id, h as u64, snap) {
                        // The handle changed since the attempt saw it: once more
                        Ok(1) => continue,
                        Ok(_) => {
                            net_waiting(cx.id, slot, cx.c.tgid);
                            refresh(slot, false);
                            return (0, LX_REPLY_PENDING);
                        }
                        Err(_) => {}
                    }
                }
                let mut w = WAITERS.lock();
                // net-server's events must reach the main thread while calls wait here (the
                // kernel then also has it catch up on what it missed: the event-count check
                // below sees it, or the main thread finds this waiter)
                if !RELAY.swap(true, Ordering::AcqRel) {
                    let _ = sys::lx_obj(LX_OBJ_RELAY, 1, 0, 0);
                }
                if SEQ[slot as usize].load(Ordering::Acquire) != seq {
                    // Something happened since the attempt began: once more
                    continue;
                }
                let timed = prog.deadline.is_some_and(|d| d.is_some());
                // wave8 GX2: a send waiting with bytes sent: their count is the answer if
                // lx-net dies while it waits (it is not sent again)
                if prog.sent > 0 && crate::sockkept::kept_active() {
                    let _ = sys::lx_obj(LX_OBJ_PARTIAL, cx.id, prog.sent as u64, 0);
                }
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

// wave8 GX2 begin
/// Marks the call being served (in the worker's syscall page, `LX_CALL_RESEND_OFF`) safe to
/// send again after a crash (`on`), or no longer: its effect begins. Nothing for a call
/// tried again by the main thread (no page: it is pending, sent again anyway).
pub fn resend_safe(cx: &Cx, on: bool) {
    let p = cx.page();
    if !p.is_null() {
        // SAFETY: the worker's own syscall page; the word lies after the call, before the
        // copy header
        unsafe { core::ptr::write_volatile(p.add(LX_CALL_RESEND_OFF) as *mut u64, if on { cx.id } else { 0 }) };
    }
}

/// Records that the call `cx` already did part of its work, and the answer for that part
/// (`done`: the bytes a stream send handed net-server): if lx-net dies now, the caller gets
/// it (a short write). A call being served writes it in the worker's syscall page
/// (`LX_CALL_PARTIAL_OFF`, no system call); a waiting call tried again by the main thread
/// tells the kernel (`LX_OBJ_PARTIAL`).
pub fn partial(cx: &Cx, done: usize) {
    if !crate::sockkept::kept_active() {
        return; // (linux-server: no Transparent restart)
    }
    let p = cx.page();
    if p.is_null() {
        let _ = sys::lx_obj(LX_OBJ_PARTIAL, cx.id, done as u64, 0);
        return;
    }
    // SAFETY: the worker's own syscall page; the words lie after the call
    unsafe {
        core::ptr::write_volatile(p.add(LX_CALL_PARTIAL_OFF + 8) as *mut i64, done as i64);
        core::ptr::write_volatile(p.add(LX_CALL_PARTIAL_OFF) as *mut u64, cx.id);
    }
}

/// A chunk is about to go to net-server: until it is known to be taken, the call's partial
/// answer in the page is withdrawn (a crash in between fails the call with EIO instead of
/// answering a count one chunk short, which a program would send again).
pub fn partial_in_flight(cx: &Cx) {
    let p = cx.page();
    if !p.is_null() {
        // SAFETY: as in `partial`
        unsafe { core::ptr::write_volatile(p.add(LX_CALL_PARTIAL_OFF) as *mut u64, 0) };
    }
}
// wave8 GX2 end

/// Calls waiting in the kernel on a net-server handle (`LX_OBJ_NETWAIT`): `(request id, slot,
/// process)`. The kernel completes them itself (`LX_RETRY`); an entry stays here until a
/// local event, a signal, its process's end or the list's size makes us look again, and
/// `LX_OBJ_NETCANCEL` then says whether the wait was still registered.
static NET_WAITING: YLock<Vec<(u64, u32, u64)>> = YLock::new(Vec::new());

/// Records a net wait (and withdraws all when the list grows long: those still registered
/// are made again, which is harmless).
fn net_waiting(id: u64, slot: u32, tgid: u64) {
    let old = {
        let mut n = NET_WAITING.lock();
        n.push((id, slot, tgid));
        if n.len() > 128 {
            core::mem::take(&mut *n)
        } else {
            Vec::new()
        }
    };
    for (i, _, _) in old {
        if i != id {
            unwait(i, LX_RETRY);
        }
    }
    // (the newest one stays registered either way)
}

/// Withdraws request `id`'s net wait; if it was still registered, answers it `result`.
fn unwait(id: u64, result: i64) -> bool {
    if sys::lx_obj(LX_OBJ_NETCANCEL, id, 0, 0) == Ok(1) {
        let _ = sys::lx_complete(id, result);
        true
    } else {
        false
    }
}

/// Takes the net waits matching `f` out of the list.
fn take_net_waiting(f: impl Fn(&(u64, u32, u64)) -> bool) -> Vec<(u64, u32, u64)> {
    let mut n = NET_WAITING.lock();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n.len() {
        if f(&n[i]) {
            out.push(n.swap_remove(i));
        } else {
            i += 1;
        }
    }
    out
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
    // Calls waiting in the kernel on this socket are made again
    for (id, _, _) in take_net_waiting(|w| w.1 == slot) {
        unwait(id, LX_RETRY);
    }
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
    // A net wait (no deadline: restarted with SA_RESTART, as Linux)
    if !take_net_waiting(|w| w.0 == id).is_empty() {
        unwait(id, ERESTARTSYS);
        return true;
    }
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
    for (id, _, _) in take_net_waiting(|w| w.2 == tgid) {
        let _ = sys::lx_obj(LX_OBJ_NETCANCEL, id, 0, 0);
    }
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
