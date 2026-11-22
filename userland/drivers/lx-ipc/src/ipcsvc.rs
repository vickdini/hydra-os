//! lx-ipc's calls (wave 8, Group X2): which forwarded calls are the IPC service's, and what
//! its main thread does. lx-ipc's `main.rs` and linux-server (which builds the same files for
//! `lx.ipc=linux`) both serve through these functions.
//!
//! The service (`LXS_IPC`) owns Unix sockets, pipes and FIFOs, eventfd, timerfd, signalfd,
//! pidfd, POSIX message queues and System V messages and semaphores.

use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::protocol::*;

use crate::client::Cx;

const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;

/// Whether `kind` is an object kind of this service.
pub fn owns_kind(kind: u32) -> bool {
    matches!(
        kind,
        LX_OBJ_KIND_MQ
            | LX_OBJ_KIND_EVENTFD
            | LX_OBJ_KIND_PIPE_R
            | LX_OBJ_KIND_PIPE_W
            | LX_OBJ_KIND_PIPE_RW
            | LX_OBJ_KIND_UNIX
            | LX_OBJ_KIND_PIDFD
            | LX_OBJ_KIND_SIGNALFD
            | LX_OBJ_KIND_TIMERFD
    )
}

/// Serves forwarded call `cx` if it is one of this service's: `Some((result, flags))`.
pub fn dispatch(cx: &Cx) -> Option<(i64, u64)> {
    let c = &cx.c;
    let kind = if c.obj != LX_OBJ_NONE { crate::obj::kind_of(c.obj as u32) } else { 0 };
    Some(match c.nr {
        // wave7 G7-5: vfs-server's open of a FIFO node, redirected to the IPC service
        2 | 257 if c.redirs != 0 && c.svc == LXS_IPC as u32 => crate::pipe::fifo_open_redirected(cx),
        // read, write, readv, writev, ioctl and the kernel's own calls on one of our objects
        0 | 1 | 16 | 19 | 20 | 276 | LX_KCALL_REOPEN | LX_KCALL_FCNTL | LX_KCALL_PSEEK | LX_KCALL_PREAD if owns_kind(kind) => object_io(cx, kind),
        // AF_UNIX sockets (Group 13)
        41 | 53 if cx.args[0] == 1 => crate::unix::create(cx),
        42..=52 | 54 | 55 | 288 | 299 | 307 if kind == LX_OBJ_KIND_UNIX => crate::unix::call(cx),
        // eventfd, pipes, FIFOs, pidfd, signalfd, timerfd (Group 13)
        284 | 290 => crate::eventfd::create(cx),
        22 | 293 => crate::pipe::create(cx),
        434 | LX_KCALL_PIDFD => crate::pidfd::open(cx),
        LX_KCALL_FIFO => crate::pipe::fifo_open(cx),
        282 | 289 => crate::signalfd::signalfd(cx),
        283 => crate::timerfd::create(cx),
        286 => crate::timerfd::settime(cx),
        287 => crate::timerfd::gettime(cx),
        240..=245 => crate::mqueue::dispatch(cx),
        64..=66 | 220 | 68..=71 => crate::sysv::dispatch(cx),
        _ => return None,
    })
}

/// `read`, `write`, `readv`, `writev`, `ioctl` (and the kernel's own calls) on our object of
/// `kind` in `cx.c.obj`.
fn object_io(cx: &Cx, kind: u32) -> (i64, u64) {
    match (kind, cx.nr) {
        (LX_OBJ_KIND_MQ, 0) => (crate::mqueue::read(cx), 0),
        (LX_OBJ_KIND_UNIX, _) => crate::unix::call(cx),
        (LX_OBJ_KIND_EVENTFD, _) => crate::eventfd::io(cx),
        (LX_OBJ_KIND_PIPE_R | LX_OBJ_KIND_PIPE_W | LX_OBJ_KIND_PIPE_RW, _) => crate::pipe::io(cx),
        (LX_OBJ_KIND_SIGNALFD, 0) => crate::signalfd::io(cx),
        (LX_OBJ_KIND_TIMERFD, 0) => crate::timerfd::io(cx),
        (_, 16) => (ENOTTY, 0),
        _ => (EINVAL, 0),
    }
}

/// The last descriptor of slot `slot` (an object of `kind`) went: `true` if it was ours.
pub fn closed(slot: u32, kind: u32) -> bool {
    match kind {
        LX_OBJ_KIND_MQ => crate::mqueue::closed(slot),
        LX_OBJ_KIND_EVENTFD => crate::eventfd::closed(slot),
        LX_OBJ_KIND_PIPE_R | LX_OBJ_KIND_PIPE_W | LX_OBJ_KIND_PIPE_RW => crate::pipe::closed(slot),
        LX_OBJ_KIND_UNIX => crate::unix::closed(slot),
        LX_OBJ_KIND_PIDFD => crate::pidfd::closed(slot),
        LX_OBJ_KIND_SIGNALFD => crate::signalfd::closed(slot),
        LX_OBJ_KIND_TIMERFD => crate::timerfd::closed(slot),
        _ => return false,
    }
    true
}

/// Process `tgid` ended.
pub fn on_exit(tgid: u64) {
    crate::mqueue::on_exit(tgid);
    crate::sysv::on_exit(tgid);
    crate::pipe::on_exit(tgid);
    crate::eventfd::on_exit(tgid);
    crate::unix::on_exit(tgid);
    crate::pidfd::on_exit(tgid);
    crate::signalfd::on_exit(tgid);
    crate::timerfd::on_exit(tgid);
}

/// A signal for the caller of pending request `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    crate::mqueue::interrupted(id)
        || crate::sysv::interrupted(id)
        || crate::pipe::interrupted(id)
        || crate::eventfd::interrupted(id)
        || crate::unix::interrupted(id)
        || crate::signalfd::interrupted(id)
        || crate::timerfd::interrupted(id)
}

/// A kernel timer fired (`LX_NOTE_TIMER` with cookie `cookie`): `true` if it was ours.
pub fn timer(cookie: u64) -> bool {
    if cookie >> 56 == crate::timerfd::TIMER_TAG >> 56 {
        crate::timerfd::fired(cookie);
        return true;
    }
    false
}

/// Blocked calls whose deadline passed are answered; the earliest deadline still waiting.
pub fn tick(now: u64) -> Option<u64> {
    [crate::mqueue::tick(now), crate::sysv::tick(now), crate::signalfd::tick(now)].into_iter().flatten().min()
}

/// When the main thread next collects Unix sockets in flight (ticks).
static NEXT_GC: AtomicU64 = AtomicU64::new(0);

/// The main thread, after waking: Unix sockets alive only in unreadable queues are
/// collected about once a second (Group 13).
pub fn main_work(now: u64) {
    if now >= NEXT_GC.load(Ordering::Relaxed) {
        NEXT_GC.store(now + 100, Ordering::Relaxed);
        crate::unix::gc_tick();
    }
}
