//! Pipes (`pipe`, `pipe2`), moved here from the kernel's `src/fs/pipe.rs` (wave 5, step 4).
//!
//! A pipe is a 64 KiB byte queue with read ends and write ends; each end is a server
//! object (one slot per open end; `dup` and `fork` share the kernel's descriptor, so the
//! server sees one slot per end). `poll` and `epoll` read the ends' readiness words: a
//! read end is readable while bytes wait and hangs up when no write end is left; a write
//! end is writable while `PIPE_BUF` bytes fit and errs when no read end is left.
//!
//! **Blocking without tying up a worker:** a `read` of an empty pipe and a `write` that
//! does not fit answer "pending"; the write that brings bytes hands them straight to the
//! waiting readers (into their memory) and completes them, and the read that makes room
//! takes the waiting writers' bytes from their memory. A signal answers `ERESTARTSYS`
//! (restarted under `SA_RESTART`, as on Linux) or, for a writer that wrote part, the count.
//! A write to a pipe with no read end posts `SIGPIPE` and fails with `EPIPE`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::fdio::{kbuf, sigpipe, Iov};
use crate::lock::YLock;

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EPIPE: i64 = -32;
const EPERM: i64 = -1;
const EBUSY: i64 = -16;
const ENOTTY: i64 = -25;
const ERESTARTSYS: i64 = -512;

const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const O_DIRECT: u64 = 0o40000;
const O_ACCMODE: u64 = 3;

/// Writes of at most this many bytes are never split (`PIPE_BUF`).
const PIPE_BUF: usize = 4096;
/// The default capacity, and the most an unprivileged `F_SETPIPE_SZ` gives (Linux's
/// `/proc/sys/fs/pipe-max-size` is 1 MiB).
const DEFAULT_CAP: usize = 65536;
const MAX_CAP: usize = 1 << 20;

const POLLIN: u32 = 0x0001;
const POLLOUT: u32 = 0x0004;
const POLLERR: u32 = 0x0008;
const POLLHUP: u32 = 0x0010;
const POLLRDNORM: u32 = 0x0040;
const POLLWRNORM: u32 = 0x0100;

/// A reader waiting for bytes (its call is pending).
struct RWait {
    id: u64,
    tgid: u64,
    iov: Iov,
}

/// A writer waiting for room (its call is pending): `done` of its `total` bytes are in.
struct WWait {
    id: u64,
    tgid: u64,
    tid: u64,
    iov: Iov,
    total: usize,
    done: usize,
}

struct Pipe {
    buf: VecDeque<u8>,
    cap: usize,
    /// Open ends (slots).
    rslots: Vec<u32>,
    wslots: Vec<u32>,
    rwait: VecDeque<RWait>,
    wwait: VecDeque<WWait>,
    ino: u64,
    /// A FIFO (`mkfifo` node `ino`): found again by its node until no end is left.
    fifo: bool,
}

/// An `open` of a FIFO waiting for the other side (its end's slot is counted already, as
/// Linux counts a waiting reader or writer).
struct OWait {
    c: LxCall,
    slot: u32,
    kind: u32,
    pipe: u64,
}

struct Pipes {
    pipes: BTreeMap<u64, Pipe>,
    /// Slot -> (pipe, is a write end).
    ends: BTreeMap<u32, (u64, bool)>,
    next: u64,
    /// FIFO ends opened `O_RDWR` (in `ends` as read ends, in both slot lists).
    rw: alloc::collections::BTreeSet<u32>,
    /// FIFO node -> its pipe.
    fifos: BTreeMap<u64, u64>,
    /// FIFO opens waiting for the other side.
    owait: Vec<OWait>,
}

static PIPES: YLock<Pipes> = YLock::new(Pipes { pipes: BTreeMap::new(), ends: BTreeMap::new(), next: 1, rw: alloc::collections::BTreeSet::new(), fifos: BTreeMap::new(), owait: Vec::new() });

/// Answers to give once the lock is let go: `(request id, result)`.
type Done = Vec<(u64, i64)>;

impl Pipe {
    fn room(&self) -> usize {
        self.cap.saturating_sub(self.buf.len())
    }

    /// Sets the ends' readiness words (`arrived`: bytes came in; `left`: room was made).
    fn publish(&self, arrived: bool, left: bool) {
        let readable = !self.buf.is_empty();
        let mut rev = if readable { POLLIN | POLLRDNORM } else { 0 };
        if self.wslots.is_empty() {
            rev |= POLLHUP;
        }
        for &s in &self.rslots {
            crate::obj::set_ready_ev(s, rev, 0, arrived);
        }
        let mut wev = if self.room() >= PIPE_BUF.min(self.cap) { POLLOUT | POLLWRNORM } else { 0 };
        if self.rslots.is_empty() {
            wev |= POLLERR;
        }
        for &s in &self.wslots {
            crate::obj::set_ready_ev(s, wev, 0, left);
        }
    }

    /// Hands buffered bytes to waiting readers (each takes what is there, up to its size).
    fn feed_readers(&mut self, done: &mut Done) {
        while !self.buf.is_empty() {
            let Some(r) = self.rwait.pop_front() else { break };
            let n = r.iov.total().min(self.buf.len());
            let data: Vec<u8> = self.buf.drain(..n).collect();
            match r.iov.scatter_later(r.id, &data) {
                Ok(()) => done.push((r.id, n as i64)),
                Err(e) => {
                    // Its memory went bad: the bytes go back for the next reader
                    for (i, b) in data.into_iter().enumerate() {
                        self.buf.insert(i, b);
                    }
                    done.push((r.id, e));
                }
            }
        }
    }

    /// Takes waiting writers' bytes while there is room (oldest first; a write of at most
    /// `PIPE_BUF` bytes goes in whole or waits).
    fn feed_writers(&mut self, done: &mut Done) {
        loop {
            let room = self.room();
            let Some(w) = self.wwait.front_mut() else { break };
            let left = w.total - w.done;
            if room == 0 || (w.total <= PIPE_BUF && room < left) {
                break;
            }
            let n = left.min(room);
            match w.iov.gather_later(w.id, w.done, n) {
                Ok(data) => {
                    self.buf.extend(data);
                    w.done += n;
                    if w.done == w.total {
                        let w = self.wwait.pop_front().unwrap();
                        done.push((w.id, w.total as i64));
                    }
                }
                Err(e) => {
                    let w = self.wwait.pop_front().unwrap();
                    done.push((w.id, if w.done > 0 { w.done as i64 } else { e }));
                }
            }
        }
    }

    /// Moves bytes along after a change: writers' bytes in, readers' bytes out.
    fn settle(&mut self, done: &mut Done) {
        for _ in 0..64 {
            let before = (self.buf.len(), self.rwait.len(), self.wwait.len());
            self.feed_readers(done);
            self.feed_writers(done);
            if (self.buf.len(), self.rwait.len(), self.wwait.len()) == before {
                break;
            }
        }
    }
}

fn finish(done: Done) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
}

/// `pipe(fds)` (22) and `pipe2(fds, flags)` (293).
pub fn create(cx: &Cx) -> (i64, u64) {
    let flags = if cx.nr == 293 { cx.args[1] } else { 0 };
    if flags & !(O_NONBLOCK | O_CLOEXEC | O_DIRECT) != 0 {
        return (EINVAL, 0);
    }
    let r = match crate::obj::alloc(LX_OBJ_KIND_PIPE_R) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let w = match crate::obj::alloc(LX_OBJ_KIND_PIPE_W) {
        Ok(s) => s,
        Err(e) => {
            crate::obj::free(r);
            return (e, 0);
        }
    };
    let ino = {
        let mut p = PIPES.lock();
        let id = p.next;
        p.next += 1;
        let ino = 0x6000_0000 + id;
        p.pipes.insert(id, Pipe { buf: VecDeque::new(), cap: DEFAULT_CAP, rslots: alloc::vec![r], wslots: alloc::vec![w], rwait: VecDeque::new(), wwait: VecDeque::new(), ino, fifo: false });
        p.ends.insert(r, (id, false));
        p.ends.insert(w, (id, true));
        p.pipes[&id].publish(false, false);
        ino
    };
    let name = alloc::format!("pipe:[{}]", ino);
    let f = (flags & (O_NONBLOCK | O_CLOEXEC)) as u32;
    let fr = match crate::obj::install_tag(cx, r, LX_OBJ_KIND_PIPE_R, f, 0o10600, cx.c.euid, cx.c.egid, name.as_bytes(), ino) {
        Ok(fd) => fd,
        Err(e) => {
            forget(r);
            forget(w);
            return (e, 0);
        }
    };
    let fw = match crate::obj::install_tag(cx, w, LX_OBJ_KIND_PIPE_W, f, 0o10600, cx.c.euid, cx.c.egid, name.as_bytes(), ino) {
        Ok(fd) => fd,
        Err(e) => {
            // The read end is installed: closing it tells us (the kernel does on exit too);
            // the write end was never seen
            forget(w);
            return (e, 0);
        }
    };
    let mut sv = [0u8; 8];
    sv[0..4].copy_from_slice(&(fr as i32).to_le_bytes());
    sv[4..8].copy_from_slice(&(fw as i32).to_le_bytes());
    match cx.copy_out(cx.args[0], &sv) {
        Ok(()) => (0, 0),
        // (the descriptors stay, as on Linux: the caller's memory was bad)
        Err(e) => (if e == 0 { EFAULT } else { e }, 0),
    }
}

/// An end that never got a descriptor: as if closed.
fn forget(slot: u32) {
    closed(slot);
    crate::obj::set_ready(slot, 0, 0);
    crate::obj::free(slot);
}

/// `read`/`readv`/`write`/`writev`/`ioctl` on a pipe end (slot `cx.c.obj`).
pub fn io(cx: &Cx) -> (i64, u64) {
    let slot = cx.c.obj as u32;
    match cx.nr {
        0 | 19 => read(cx, slot),
        1 | 20 => write(cx, slot),
        16 => (ioctl(cx, slot), 0),
        276 => (tee(cx, slot), 0),
        LX_KCALL_REOPEN => reopen(cx, slot),
        LX_KCALL_FCNTL => (fcntl(cx, slot), 0),
        _ => (EINVAL, 0),
    }
}

fn read(cx: &Cx, slot: u32) -> (i64, u64) {
    let iov = match Iov::of_call(cx) {
        Ok(v) => v,
        Err(e) => return (e, 0),
    };
    let want = iov.total();
    let mut done = Done::new();
    let r = {
        let mut ps = PIPES.lock();
        let Some(&(id, false)) = ps.ends.get(&slot) else { return (EBADF, 0) };
        let p = ps.pipes.get_mut(&id).unwrap();
        if want == 0 {
            (0, 0)
        } else if !p.buf.is_empty() {
            let n = want.min(p.buf.len());
            let data: Vec<u8> = p.buf.iter().take(n).copied().collect();
            match iov.scatter(cx, &data) {
                Ok(()) => {
                    p.buf.drain(..n);
                    p.settle(&mut done);
                    p.publish(false, true);
                    (n as i64, 0)
                }
                Err(e) => (e, 0),
            }
        } else if p.wslots.is_empty() {
            (0, 0)
        } else if cx.nonblock() || kbuf(cx) {
            (EAGAIN, 0)
        } else {
            p.rwait.push_back(RWait { id: cx.id, tgid: cx.c.tgid, iov });
            (0, LX_REPLY_PENDING)
        }
    };
    finish(done);
    r
}

fn write(cx: &Cx, slot: u32) -> (i64, u64) {
    let iov = match Iov::of_call(cx) {
        Ok(v) => v,
        Err(e) => return (e, 0),
    };
    let total = iov.total();
    let mut done = Done::new();
    let r = {
        let mut ps = PIPES.lock();
        let id = match ps.ends.get(&slot) {
            Some(&(id, w)) if w || ps.rw.contains(&slot) => id,
            _ => return (EBADF, 0),
        };
        let p = ps.pipes.get_mut(&id).unwrap();
        if p.rslots.is_empty() {
            drop(ps);
            if !kbuf(cx) {
                sigpipe(cx.c.tgid, cx.c.tid);
            }
            return (EPIPE, 0);
        }
        if total == 0 {
            return (0, 0);
        }
        // Bytes go straight to waiting readers, then into the buffer (behind earlier
        // waiting writers, whose bytes come first)
        let room = if p.wwait.is_empty() { p.room() + p.rwait.iter().map(|r| r.iov.total()).sum::<usize>() } else { 0 };
        let atomic = total <= PIPE_BUF;
        let now = if atomic { if room >= total { total } else { 0 } } else { room.min(total) };
        let mut wrote = 0;
        if now > 0 {
            match iov.gather(cx, 0, now) {
                Ok(data) => {
                    p.buf.extend(data);
                    wrote = now;
                    p.settle(&mut done);
                    p.publish(true, false);
                }
                Err(e) => return (e, 0),
            }
        }
        if wrote == total {
            (total as i64, 0)
        } else if cx.nonblock() || kbuf(cx) {
            (if wrote > 0 { wrote as i64 } else { EAGAIN }, 0)
        } else {
            p.wwait.push_back(WWait { id: cx.id, tgid: cx.c.tgid, tid: cx.c.tid, iov, total, done: wrote });
            (0, LX_REPLY_PENDING)
        }
    };
    finish(done);
    r
}

fn ioctl(cx: &Cx, slot: u32) -> i64 {
    match cx.args[1] {
        0x541B => {
            // FIONREAD
            let n = {
                let ps = PIPES.lock();
                match ps.ends.get(&slot) {
                    Some(&(id, _)) => ps.pipes[&id].buf.len(),
                    None => return EBADF,
                }
            };
            match cx.copy_out(cx.args[2], &(n as i32).to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        0x5452 => 0, // FIOASYNC
        _ => ENOTTY,
    }
}

/// `tee(in, out, len, flags)` (the kernel put the write end's slot in `args[1]`): copies up
/// to `len` bytes of read end `slot`'s pipe into the other pipe without taking them;
/// `-EAGAIN` when nothing is there or nothing fits (the kernel waits).
fn tee(cx: &Cx, slot: u32) -> i64 {
    let out = cx.args[1] as u32;
    let mut done = Done::new();
    let r = {
        let mut ps = PIPES.lock();
        let (Some(&(src, false)), Some(&(dst, true))) = (ps.ends.get(&slot), ps.ends.get(&out)) else { return EINVAL };
        if src == dst {
            return EINVAL;
        }
        let s = &ps.pipes[&src];
        if s.buf.is_empty() {
            return if s.wslots.is_empty() { 0 } else { EAGAIN };
        }
        let d = &ps.pipes[&dst];
        if d.rslots.is_empty() {
            return EPIPE;
        }
        let n = s.buf.len().min(d.room()).min(cx.args[2] as usize);
        if n == 0 {
            return EAGAIN;
        }
        let data: Vec<u8> = s.buf.iter().take(n).copied().collect();
        let d = ps.pipes.get_mut(&dst).unwrap();
        d.buf.extend(data);
        d.settle(&mut done);
        d.publish(true, false);
        n as i64
    };
    finish(done);
    r
}

/// `fcntl` commands of pipes (`LX_KCALL_FCNTL(fd, cmd, arg)`): `F_GETPIPE_SZ` (1032),
/// `F_SETPIPE_SZ` (1031).
fn fcntl(cx: &Cx, slot: u32) -> i64 {
    let mut ps = PIPES.lock();
    let Some(&(id, _)) = ps.ends.get(&slot) else { return EBADF };
    let p = ps.pipes.get_mut(&id).unwrap();
    match cx.args[1] {
        1032 => p.cap as i64,
        1031 => {
            let want = cx.args[2] as usize;
            // Rounded up to a power of two of pages, as Linux does
            let size = want.max(4096).next_power_of_two();
            if size > MAX_CAP && !cx.has_cap(24) {
                return EPERM;
            }
            if size > 1 << 28 {
                return EINVAL;
            }
            if size < p.buf.len() {
                return EBUSY;
            }
            p.cap = size;
            let mut done = Done::new();
            p.settle(&mut done);
            p.publish(false, true);
            drop(ps);
            finish(done);
            size as i64
        }
        _ => EINVAL,
    }
}

/// `LX_KCALL_REOPEN(fd, flags)`: opening `/proc/self/fd/N` of a pipe end gives a new end
/// of the same pipe, of the access asked for.
fn reopen(cx: &Cx, slot: u32) -> (i64, u64) {
    let flags = cx.args[1];
    let write = match flags & O_ACCMODE {
        0 => false,
        1 => true,
        _ => return (EINVAL, 0),
    };
    let kind = if write { LX_OBJ_KIND_PIPE_W } else { LX_OBJ_KIND_PIPE_R };
    let new = match crate::obj::alloc(kind) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let ino = {
        let mut ps = PIPES.lock();
        let Some(&(id, _)) = ps.ends.get(&slot) else {
            crate::obj::free(new);
            return (EBADF, 0);
        };
        ps.ends.insert(new, (id, write));
        let p = ps.pipes.get_mut(&id).unwrap();
        if write {
            p.wslots.push(new);
        } else {
            p.rslots.push(new);
        }
        p.publish(false, false);
        p.ino
    };
    let name = alloc::format!("pipe:[{}]", ino);
    match crate::obj::install_tag(cx, new, kind, (flags & (O_NONBLOCK | O_CLOEXEC)) as u32, 0o10600, cx.c.euid, cx.c.egid, name.as_bytes(), ino) {
        Ok(fd) => (fd, 0),
        Err(e) => {
            forget(new);
            (e, 0)
        }
    }
}

/// The last descriptor of end `slot` went away.
pub fn closed(slot: u32) {
    let mut done = Done::new();
    let mut pipe_signals: Vec<(u64, u64)> = Vec::new();
    {
        let mut ps = PIPES.lock();
        let Some((id, write)) = ps.ends.remove(&slot) else { return };
        // (an O_RDWR FIFO end is a reader and a writer)
        let both = ps.rw.remove(&slot);
        let p = ps.pipes.get_mut(&id).unwrap();
        if both {
            p.wslots.retain(|&s| s != slot);
        }
        if write || both {
            p.wslots.retain(|&s| s != slot);
            if p.wslots.is_empty() {
                // End of file for every waiting reader
                for r in p.rwait.drain(..) {
                    done.push((r.id, 0));
                }
            }
        }
        if !write {
            p.rslots.retain(|&s| s != slot);
            if p.rslots.is_empty() {
                for w in p.wwait.drain(..) {
                    if w.done > 0 {
                        done.push((w.id, w.done as i64));
                    } else {
                        pipe_signals.push((w.tgid, w.tid));
                        done.push((w.id, EPIPE));
                    }
                }
            }
        }
        if p.rslots.is_empty() && p.wslots.is_empty() {
            if p.fifo {
                let ino = p.ino;
                ps.fifos.remove(&ino);
            }
            ps.pipes.remove(&id);
        } else {
            p.publish(false, false);
        }
    }
    for (tgid, tid) in pipe_signals {
        sigpipe(tgid, tid);
    }
    finish(done);
}

/// A signal arrived for the caller of pending call `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    // A FIFO open waiting for the other side: its end goes
    let ow = {
        let mut ps = PIPES.lock();
        ps.owait.iter().position(|w| w.c.id == id).map(|i| ps.owait.remove(i))
    };
    if let Some(w) = ow {
        forget(w.slot);
        let _ = sys::lx_complete(id, ERESTARTSYS);
        return true;
    }
    let r = {
        let mut ps = PIPES.lock();
        let mut found = None;
        for p in ps.pipes.values_mut() {
            if let Some(i) = p.rwait.iter().position(|r| r.id == id) {
                p.rwait.remove(i);
                found = Some(ERESTARTSYS);
                break;
            }
            if let Some(i) = p.wwait.iter().position(|w| w.id == id) {
                let w = p.wwait.remove(i).unwrap();
                found = Some(if w.done > 0 { w.done as i64 } else { ERESTARTSYS });
                break;
            }
        }
        found
    };
    match r {
        Some(v) => {
            let _ = sys::lx_complete(id, v);
            true
        }
        None => false,
    }
}

/// Process `tgid` ended: its waiting calls are gone.
pub fn on_exit(tgid: u64) {
    let gone: Vec<u32> = {
        let mut ps = PIPES.lock();
        let (g, keep): (Vec<OWait>, Vec<OWait>) = core::mem::take(&mut ps.owait).into_iter().partition(|w| w.c.tgid == tgid);
        ps.owait = keep;
        g.into_iter().map(|w| w.slot).collect()
    };
    for s in gone {
        forget(s);
    }
    let mut ps = PIPES.lock();
    for p in ps.pipes.values_mut() {
        p.rwait.retain(|r| r.tgid != tgid);
        p.wwait.retain(|w| w.tgid != tgid);
    }
}

/// Whether slot `slot` is a pipe end (for `fstat`-like questions of other modules).
#[allow(dead_code)]
pub fn is_pipe(slot: u32) -> bool {
    PIPES.lock().ends.contains_key(&slot)
}

// ----------------------------------------------------------------------
// FIFOs (`mkfifo` nodes)
// ----------------------------------------------------------------------

/// `LX_KCALL_FIFO(ino, flags)`: the kernel's `open` of FIFO node `ino` (permissions checked
/// already). As on Linux: a reader waits for a writer and a writer for a reader (unless
/// `O_NONBLOCK`: a reader goes on, a writer fails with `ENXIO`), `O_RDWR` never waits; the
/// pipe lives while any end is open, and its bytes go with it.
pub fn fifo_open(cx: &Cx) -> (i64, u64) {
    const ENXIO: i64 = -6;
    let (ino, flags) = (cx.args[0], cx.args[1]);
    let acc = flags & O_ACCMODE;
    let nonblock = flags & O_NONBLOCK != 0;
    let kind = match acc {
        0 => LX_OBJ_KIND_PIPE_R,
        1 => LX_OBJ_KIND_PIPE_W,
        2 => LX_OBJ_KIND_PIPE_RW,
        _ => return (EINVAL, 0),
    };
    let slot = match crate::obj::alloc(kind) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    let mut ready: Vec<OWait> = Vec::new();
    let wait = {
        let mut ps = PIPES.lock();
        let id = match ps.fifos.get(&ino) {
            Some(&id) => id,
            None => {
                let id = ps.next;
                ps.next += 1;
                ps.pipes.insert(id, Pipe { buf: VecDeque::new(), cap: DEFAULT_CAP, rslots: Vec::new(), wslots: Vec::new(), rwait: VecDeque::new(), wwait: VecDeque::new(), ino, fifo: true });
                ps.fifos.insert(ino, id);
                id
            }
        };
        let (readers, writers) = {
            let p = &ps.pipes[&id];
            (!p.rslots.is_empty(), !p.wslots.is_empty())
        };
        if kind == LX_OBJ_KIND_PIPE_W && !readers && nonblock {
            drop(ps);
            crate::obj::free(slot);
            // (a pipe made for nothing goes again)
            let mut ps = PIPES.lock();
            if ps.pipes.get(&id).is_some_and(|p| p.rslots.is_empty() && p.wslots.is_empty()) {
                ps.pipes.remove(&id);
                ps.fifos.remove(&ino);
            }
            return (ENXIO, 0);
        }
        let p = ps.pipes.get_mut(&id).unwrap();
        if kind != LX_OBJ_KIND_PIPE_W {
            p.rslots.push(slot);
        }
        if kind != LX_OBJ_KIND_PIPE_R {
            p.wslots.push(slot);
        }
        p.publish(false, false);
        ps.ends.insert(slot, (id, kind == LX_OBJ_KIND_PIPE_W));
        if kind == LX_OBJ_KIND_PIPE_RW {
            ps.rw.insert(slot);
        }
        // Opens waiting for this side go on
        let mut keep = Vec::new();
        for w in core::mem::take(&mut ps.owait) {
            let wakes = w.pipe == id && ((w.kind == LX_OBJ_KIND_PIPE_R && kind != LX_OBJ_KIND_PIPE_R) || (w.kind == LX_OBJ_KIND_PIPE_W && kind != LX_OBJ_KIND_PIPE_W));
            if wakes {
                ready.push(w);
            } else {
                keep.push(w);
            }
        }
        ps.owait = keep;
        let must_wait = !nonblock && ((kind == LX_OBJ_KIND_PIPE_R && !writers) || (kind == LX_OBJ_KIND_PIPE_W && !readers));
        if must_wait {
            ps.owait.push(OWait { c: cx.c, slot, kind, pipe: id });
        }
        must_wait
    };
    for w in ready {
        let wcx = Cx::from_call(&w.c, core::ptr::null_mut());
        let r = install_end(&wcx, w.slot, w.kind, w.c.args[1], ino);
        let _ = sys::lx_complete(w.c.id, r);
    }
    if wait {
        return (0, LX_REPLY_PENDING);
    }
    (install_end(cx, slot, kind, flags, ino), 0)
}

/// Gives FIFO end `slot` its descriptor in the caller's table (`forget` on failure).
fn install_end(cx: &Cx, slot: u32, kind: u32, flags: u64, ino: u64) -> i64 {
    let name = alloc::format!("pipe:[{}]", ino);
    match crate::obj::install_tag(cx, slot, kind, (flags & (O_NONBLOCK | O_CLOEXEC)) as u32, 0o10600, cx.c.euid, cx.c.egid, name.as_bytes(), ino) {
        Ok(fd) => fd,
        Err(e) => {
            forget(slot);
            e
        }
    }
}
