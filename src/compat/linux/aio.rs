//! # Linux native asynchronous I/O (`io_setup`, `io_submit`, `io_getevents` and family)
//!
//! Each operation runs when it is submitted, through the program's own `pread64`,
//! `pwrite64`, `preadv`, `pwritev`, `fsync` and `fdatasync` ([`super::nested`]), and its
//! completion is queued for `io_getevents`. (Linux too completes buffered file AIO during
//! submission; Hydra has no page cache or direct I/O to overlap.) A poll request that is not
//! ready yet stays pending and is checked again while `io_getevents` waits; `io_cancel`
//! cancels it. `IOCB_FLAG_RESFD` signals an eventfd on completion.
//!
//! The context ID is the address of a page mapped in the caller, like Linux's completion
//! ring; its header is zero, so libaio reaps through the system call rather than the ring.
//! Contexts belong to the process that made them: not inherited, destroyed at exit.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::arch::syscall::SyscallFrame;
use crate::task::wait::WaitQueue;

const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EINPROGRESS: i64 = -115;

const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_CMD_FSYNC: u16 = 2;
const IOCB_CMD_FDSYNC: u16 = 3;
const IOCB_CMD_POLL: u16 = 5;
const IOCB_CMD_NOOP: u16 = 6;
const IOCB_CMD_PREADV: u16 = 7;
const IOCB_CMD_PWRITEV: u16 = 8;
/// `aio_flags`: write 1 to the eventfd in `aio_resfd` on completion.
const IOCB_FLAG_RESFD: u32 = 1;

const NR_WRITE: u64 = 1;
const NR_POLL: u64 = 7;
const NR_RT_SIGPROCMASK: u64 = 14;
const NR_PREAD64: u64 = 17;
const NR_PWRITE64: u64 = 18;
const NR_FSYNC: u64 = 74;
const NR_FDATASYNC: u64 = 75;
const NR_PREADV: u64 = 295;
const NR_PWRITEV: u64 = 296;

/// A finished operation: `struct io_event` (data, obj, res, res2).
type Event = [u64; 4];

/// A poll request still waiting: (iocb address, data, fd, events, eventfd).
type PendingPoll = (u64, u64, i32, u16, Option<u64>);

/// One AIO context.
struct Ctx {
    pid: u64,
    max: usize,
    done: VecDeque<Event>,
    polls: Vec<PendingPoll>,
}

static CTXS: Mutex<BTreeMap<u64, Ctx>> = Mutex::new(BTreeMap::new());
/// Woken when an event is queued.
static DONE: WaitQueue = WaitQueue::new();

fn pid() -> u64 {
    super::proc::current_ids().1
}

/// The calling process's context `ctx`, as `(max events, events + pending)`.
fn usage(ctx: u64) -> Option<(usize, usize)> {
    let me = pid();
    CTXS.lock().get(&ctx).filter(|c| c.pid == me).map(|c| (c.max, c.done.len() + c.polls.len()))
}

/// Writes 1 to eventfd `fd`, through `scratch` (8 bytes of user memory).
fn signal_eventfd(frame: &SyscallFrame, fd: u64, scratch: u64) {
    if copy_out(scratch, &1u64.to_le_bytes()).is_ok() {
        super::nested(frame, NR_WRITE, [fd, scratch, 8, 0, 0, 0]);
    }
}

/// Polls `fd` for `events` now, through `scratch`; the ready events, or 0.
fn poll_now(frame: &SyscallFrame, fd: i32, events: u16, scratch: u64) -> u16 {
    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&fd.to_le_bytes());
    pfd[4..6].copy_from_slice(&events.to_le_bytes());
    if copy_out(scratch, &pfd).is_err() {
        return 0;
    }
    if super::nested(frame, NR_POLL, [scratch, 1, 0, 0, 0, 0]) <= 0 {
        return 0;
    }
    copy_in(scratch + 6, 2).map(|r| u16::from_le_bytes([r[0], r[1]])).unwrap_or(0)
}

/// `io_setup(nr_events, ctx_idp)`.
fn io_setup(nr: u64, ctxp: u64) -> i64 {
    match copy_in(ctxp, 8) {
        Ok(r) if r.iter().all(|&b| b == 0) => {}
        Ok(_) => return EINVAL,
        Err(e) => return e,
    }
    if nr == 0 || nr > 65536 {
        return EINVAL;
    }
    let Some(mm) = super::mm::current_mm() else { return EFAULT };
    // The "ring": a zeroed page (libaio finds no ring magic and uses io_getevents)
    let addr = super::mm::sys_mmap(&mm, 0, 4096, 1, 0x22, -1, 0);
    if addr < 0 {
        return addr;
    }
    if copy_out(ctxp, &(addr as u64).to_le_bytes()).is_err() {
        super::mm::sys_munmap(&mm, addr as u64, 4096);
        return EFAULT;
    }
    CTXS.lock().insert(addr as u64, Ctx { pid: pid(), max: nr as usize, done: VecDeque::new(), polls: Vec::new() });
    0
}

/// `io_destroy(ctx)`.
fn io_destroy(ctx: u64) -> i64 {
    let me = pid();
    let mut all = CTXS.lock();
    if !all.get(&ctx).is_some_and(|c| c.pid == me) {
        return EINVAL;
    }
    all.remove(&ctx);
    drop(all);
    if let Some(mm) = super::mm::current_mm() {
        super::mm::sys_munmap(&mm, ctx, 4096);
    }
    DONE.wake_all();
    0
}

/// `io_submit(ctx, nr, iocbpp)`: runs each request and queues its completion.
fn io_submit(frame: &SyscallFrame, ctx: u64, nr: u64, iocbpp: u64) -> i64 {
    if (nr as i64) < 0 {
        return EINVAL;
    }
    let Some((max, _)) = usage(ctx) else { return EINVAL };
    let scratch = match super::xfer::Bounce::new(4096) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut submitted = 0i64;
    for i in 0..nr {
        let fail = |e: i64| if submitted > 0 { submitted } else { e };
        let ptr = match copy_in(iocbpp + i * 8, 8) {
            Ok(r) => u64::from_le_bytes(r[..8].try_into().unwrap()),
            Err(e) => return fail(e),
        };
        let cb = match copy_in(ptr, 64) {
            Ok(r) => r,
            Err(e) => return fail(e),
        };
        let u64_at = |o: usize| u64::from_le_bytes(cb[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(cb[o..o + 4].try_into().unwrap());
        let data = u64_at(0);
        let opcode = u16::from_le_bytes([cb[16], cb[17]]);
        let fd = u32_at(20) as i32;
        let (buf, nbytes, offset) = (u64_at(24), u64_at(32), u64_at(40));
        let flags = u32_at(56);
        let resfd = (flags & IOCB_FLAG_RESFD != 0).then(|| u32_at(60) as i32 as i64 as u64);
        if u32_at(8) != 0 || u64_at(48) != 0 || flags & !(IOCB_FLAG_RESFD | 2) != 0 {
            return fail(EINVAL); // aio_key, reserved field, unknown flags
        }
        match usage(ctx) {
            Some((_, used)) if used < max => {}
            Some(_) => return fail(EAGAIN),
            None => return fail(EINVAL),
        }
        let f = fd as i64 as u64;
        let res = match opcode {
            IOCB_CMD_PREAD => super::nested(frame, NR_PREAD64, [f, buf, nbytes, offset, 0, 0]),
            IOCB_CMD_PWRITE => super::nested(frame, NR_PWRITE64, [f, buf, nbytes, offset, 0, 0]),
            IOCB_CMD_PREADV => super::nested(frame, NR_PREADV, [f, buf, nbytes, offset, 0, 0]),
            IOCB_CMD_PWRITEV => super::nested(frame, NR_PWRITEV, [f, buf, nbytes, offset, 0, 0]),
            IOCB_CMD_FSYNC => super::nested(frame, NR_FSYNC, [f, 0, 0, 0, 0, 0]),
            IOCB_CMD_FDSYNC => super::nested(frame, NR_FDATASYNC, [f, 0, 0, 0, 0, 0]),
            IOCB_CMD_NOOP => 0,
            IOCB_CMD_POLL => {
                let events = buf as u16;
                let ready = poll_now(frame, fd, events | 0x18, scratch.addr); // POLLERR | POLLHUP always
                if ready == 0 {
                    // Not ready: waits in the context until it is or is cancelled
                    if let Some(c) = CTXS.lock().get_mut(&ctx) {
                        c.polls.push((ptr, data, fd, events, resfd));
                    }
                    submitted += 1;
                    continue;
                }
                ready as i64
            }
            _ => return fail(EINVAL),
        };
        if let Some(c) = CTXS.lock().get_mut(&ctx) {
            c.done.push_back([data, ptr, res as u64, 0]);
        }
        if let Some(efd) = resfd {
            signal_eventfd(frame, efd, scratch.addr + 64);
        }
        submitted += 1;
    }
    DONE.wake_all();
    submitted
}

/// Completes the pending poll requests of `ctx` that are ready now.
fn check_polls(frame: &SyscallFrame, ctx: u64, scratch: u64) {
    let polls: Vec<PendingPoll> = CTXS.lock().get(&ctx).map(|c| c.polls.clone()).unwrap_or_default();
    for (ptr, data, fd, events, resfd) in polls {
        let ready = poll_now(frame, fd, events | 0x18, scratch);
        if ready == 0 {
            continue;
        }
        let mut all = CTXS.lock();
        let Some(c) = all.get_mut(&ctx) else { return };
        let Some(i) = c.polls.iter().position(|p| p.0 == ptr) else { continue };
        c.polls.remove(i);
        c.done.push_back([data, ptr, ready as u64, 0]);
        drop(all);
        if let Some(efd) = resfd {
            signal_eventfd(frame, efd, scratch + 64);
        }
    }
}

/// `io_getevents` / `io_pgetevents`: waits for at least `min_nr` completions (or the
/// relative timeout) and returns up to `nr`.
fn io_getevents(frame: &SyscallFrame, ctx: u64, min_nr: u64, nr: u64, events: u64, timeout: u64, sigmask: Option<u64>) -> i64 {
    if (min_nr as i64) < 0 || (nr as i64) < 0 || min_nr > nr {
        return EINVAL;
    }
    if usage(ctx).is_none() {
        return EINVAL;
    }
    let hz = crate::arch::pit::frequency_hz().max(1) as u128;
    let deadline = if timeout != 0 {
        let t = match copy_in(timeout, 16) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (s, ns) = (i64::from_le_bytes(t[0..8].try_into().unwrap()), i64::from_le_bytes(t[8..16].try_into().unwrap()));
        if s < 0 || !(0..1_000_000_000).contains(&ns) {
            return EINVAL;
        }
        Some(crate::arch::pit::ticks() + ((s as u128 * 1_000_000_000 + ns as u128) * hz).div_ceil(1_000_000_000) as u64)
    } else {
        None
    };
    let scratch = match super::xfer::Bounce::new(4096) {
        Ok(b) => b,
        Err(e) => return e,
    };
    // io_pgetevents: the given signal mask while waiting
    if let Some(mask) = sigmask {
        let r = super::nested(frame, NR_RT_SIGPROCMASK, [2, mask, scratch.addr + 128, 8, 0, 0]);
        if r < 0 {
            return r;
        }
    }
    let result = loop {
        DONE.register();
        check_polls(frame, ctx, scratch.addr);
        let (ready, pending) = {
            let all = CTXS.lock();
            let Some(c) = all.get(&ctx) else { break Err(EINVAL) };
            (c.done.len() as u64, !c.polls.is_empty())
        };
        if ready >= min_nr.max(1) || (min_nr == 0 && deadline.is_some_and(|d| crate::arch::pit::ticks() >= d)) {
            break Ok(());
        }
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            break Ok(());
        }
        if super::proc::signal_pending() {
            break Err(EINTR);
        }
        // Pending polls are checked again every tick
        let next = if pending { Some(crate::arch::pit::ticks() + 1) } else { None };
        let wake = match (deadline, next) {
            (Some(d), Some(n)) => Some(d.min(n)),
            (d, n) => d.or(n),
        };
        crate::task::wait::wait(wake);
    };
    DONE.unregister();
    if sigmask.is_some() {
        super::nested(frame, NR_RT_SIGPROCMASK, [2, scratch.addr + 128, 0, 8, 0, 0]);
    }
    if let Err(e) = result {
        return e;
    }
    let taken: Vec<Event> = {
        let mut all = CTXS.lock();
        let Some(c) = all.get_mut(&ctx) else { return EINVAL };
        let n = (nr as usize).min(c.done.len());
        c.done.drain(..n).collect()
    };
    let bytes: Vec<u8> = taken.iter().flat_map(|e| e.iter().flat_map(|v| v.to_le_bytes())).collect();
    if !bytes.is_empty() && copy_out(events, &bytes).is_err() {
        return EFAULT;
    }
    taken.len() as i64
}

/// `io_cancel(ctx, iocb, result)`: only a pending poll can be cancelled; its completion
/// (no events, as on Linux) is then queued.
fn io_cancel(ctx: u64, iocb: u64) -> i64 {
    let me = pid();
    let mut all = CTXS.lock();
    let Some(c) = all.get_mut(&ctx).filter(|c| c.pid == me) else { return EINVAL };
    let Some(i) = c.polls.iter().position(|p| p.0 == iocb) else { return EINVAL };
    let (ptr, data, ..) = c.polls.remove(i);
    // Linux completes a cancelled poll with no events
    c.done.push_back([data, ptr, 0, 0]);
    drop(all);
    DONE.wake_all();
    EINPROGRESS
}

/// Destroys a process's contexts (it exited).
///
/// # Arguments
/// * `pid` - Process ID.
pub fn forget_process(pid: u64) {
    CTXS.lock().retain(|_, c| c.pid != pid);
}

/// Handles the AIO calls: `io_setup` (206), `io_destroy` (207), `io_getevents` (208),
/// `io_submit` (209), `io_cancel` (210), `io_pgetevents` (333).
///
/// # Arguments
/// * `frame` - The caller's registers.
/// * `num` - System call number.
///
/// # Returns
/// The call's result or a negative errno.
pub fn dispatch(frame: &mut SyscallFrame, num: u64) -> i64 {
    let a = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    match num {
        206 => io_setup(a[0] as u32 as u64, a[1]),
        207 => io_destroy(a[0]),
        208 => io_getevents(frame, a[0], a[1], a[2], a[3], a[4], None),
        209 => io_submit(frame, a[0], a[1], a[2]),
        210 => io_cancel(a[0], a[1]),
        333 => {
            // usig: { const sigset_t *sigmask; size_t sigsetsize }
            let mask = if a[5] != 0 {
                match copy_in(a[5], 16) {
                    Ok(r) => {
                        let m = u64::from_le_bytes(r[0..8].try_into().unwrap());
                        (m != 0).then_some(m)
                    }
                    Err(e) => return e,
                }
            } else {
                None
            };
            io_getevents(frame, a[0], a[1], a[2], a[3], a[4], mask)
        }
        _ => -38,
    }
}
