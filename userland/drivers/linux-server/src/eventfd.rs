//! eventfd (`eventfd`, `eventfd2`), moved here from the kernel's
//! `src/compat/linux/eventfd.rs` (wave 5, step 4).
//!
//! A 64-bit counter: a `write` of 8 bytes adds to it (waiting while the sum would pass
//! `u64::MAX - 1`), a `read` takes it all (or 1 in semaphore mode), waiting while it is 0.
//! `poll`/`epoll` read the readiness word; every write counts as an event for
//! edge-triggered watches, as Linux's wakeups do. A blocked read or write answers
//! "pending" and is completed by the write or read that unblocks it.

use alloc::collections::{BTreeMap, VecDeque};

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::fdio::kbuf;
use crate::lock::YLock;

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ERESTARTSYS: i64 = -512;

const EFD_SEMAPHORE: u64 = 1;
const EFD_NONBLOCK: u64 = 0o4000;
const EFD_CLOEXEC: u64 = 0o2000000;

const MAX: u64 = u64::MAX - 1;

struct Waiter {
    id: u64,
    tgid: u64,
    /// A reader's buffer, or a writer's value.
    arg: u64,
}

struct Efd {
    count: u64,
    semaphore: bool,
    readers: VecDeque<Waiter>,
    writers: VecDeque<Waiter>,
}

static EFDS: YLock<BTreeMap<u32, Efd>> = YLock::new(BTreeMap::new());

impl Efd {
    fn publish(&self, slot: u32, event: bool) {
        let mut ev = 0;
        if self.count > 0 {
            ev |= 0x0041; // POLLIN | POLLRDNORM
        }
        if self.count < MAX {
            ev |= 0x0104; // POLLOUT | POLLWRNORM
        }
        crate::obj::set_ready_ev(slot, ev, 0, event);
    }

    fn take(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        Some(if self.semaphore {
            self.count -= 1;
            1
        } else {
            core::mem::take(&mut self.count)
        })
    }

    /// Completes the waiters the counter now lets through: `(id, result)` to answer,
    /// readers' values already written to their memory.
    fn settle(&mut self, out: &mut alloc::vec::Vec<(u64, i64)>) {
        loop {
            let mut moved = false;
            while !self.readers.is_empty() && self.count > 0 {
                let w = self.readers.pop_front().unwrap();
                let v = self.take().unwrap();
                match sys::lx_write(w.id, w.arg, &v.to_ne_bytes()) {
                    Ok(()) => out.push((w.id, 8)),
                    Err(e) => {
                        self.count += v;
                        out.push((w.id, e));
                    }
                }
                moved = true;
            }
            while let Some(w) = self.writers.front() {
                if MAX - self.count < w.arg {
                    break;
                }
                let w = self.writers.pop_front().unwrap();
                self.count += w.arg;
                out.push((w.id, 8));
                moved = true;
            }
            if !moved {
                break;
            }
        }
    }
}

/// `eventfd(initval)` (284) and `eventfd2(initval, flags)` (290).
pub fn create(cx: &Cx) -> (i64, u64) {
    let flags = if cx.nr == 290 { cx.args[1] } else { 0 };
    if flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
        return (EINVAL, 0);
    }
    let slot = match crate::obj::alloc(LX_OBJ_KIND_EVENTFD) {
        Ok(s) => s,
        Err(e) => return (e, 0),
    };
    {
        let mut m = EFDS.lock();
        let e = Efd { count: cx.args[0] as u32 as u64, semaphore: flags & EFD_SEMAPHORE != 0, readers: VecDeque::new(), writers: VecDeque::new() };
        e.publish(slot, false);
        m.insert(slot, e);
    }
    match crate::obj::install(cx, slot, LX_OBJ_KIND_EVENTFD, (flags & (EFD_NONBLOCK | EFD_CLOEXEC)) as u32, 0o600, cx.c.euid, cx.c.egid, b"anon_inode:[eventfd]") {
        Ok(fd) => (fd, 0),
        Err(e) => {
            EFDS.lock().remove(&slot);
            crate::obj::set_ready(slot, 0, 0);
            crate::obj::free(slot);
            (e, 0)
        }
    }
}

/// `read`/`write`/`ioctl` on an eventfd (slot `cx.c.obj`).
pub fn io(cx: &Cx) -> (i64, u64) {
    let slot = cx.c.obj as u32;
    let len = cx.args[2];
    match cx.nr {
        0 | 1 if len < 8 => (EINVAL, 0),
        19 | 20 => (EINVAL, 0), // (readv/writev: rare; Linux allows them, Hydra did not)
        0 => {
            let mut done = alloc::vec::Vec::new();
            let r = {
                let mut m = EFDS.lock();
                let Some(e) = m.get_mut(&slot) else { return (EBADF, 0) };
                match e.take() {
                    Some(v) => match cx.copy_out(cx.args[1], &v.to_ne_bytes()) {
                        Ok(()) => {
                            e.settle(&mut done);
                            e.publish(slot, false);
                            (8, 0)
                        }
                        Err(err) => {
                            e.count += v;
                            (err, 0)
                        }
                    },
                    None if cx.nonblock() || kbuf(cx) => (EAGAIN, 0),
                    None => {
                        e.readers.push_back(Waiter { id: cx.id, tgid: cx.c.tgid, arg: cx.args[1] });
                        (0, LX_REPLY_PENDING)
                    }
                }
            };
            finish(done);
            r
        }
        1 => {
            let raw = match cx.copy_in(cx.args[1], 8) {
                Ok(r) => r,
                Err(e) => return (e, 0),
            };
            let v = u64::from_ne_bytes(raw[..8].try_into().unwrap());
            if v == u64::MAX {
                return (EINVAL, 0);
            }
            let mut done = alloc::vec::Vec::new();
            let r = {
                let mut m = EFDS.lock();
                let Some(e) = m.get_mut(&slot) else { return (EBADF, 0) };
                if MAX - e.count >= v && e.writers.is_empty() {
                    e.count += v;
                    e.settle(&mut done);
                    e.publish(slot, true);
                    (8, 0)
                } else if cx.nonblock() || kbuf(cx) {
                    (EAGAIN, 0)
                } else {
                    e.writers.push_back(Waiter { id: cx.id, tgid: cx.c.tgid, arg: v });
                    (0, LX_REPLY_PENDING)
                }
            };
            finish(done);
            r
        }
        16 => (ENOTTY, 0),
        _ => (EINVAL, 0),
    }
}

fn finish(done: alloc::vec::Vec<(u64, i64)>) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
}

/// The counter of eventfd `slot`, for `/proc/<pid>/fdinfo` (`eventfd-count`).
#[allow(dead_code)]
pub fn count(slot: u32) -> Option<u64> {
    EFDS.lock().get(&slot).map(|e| e.count)
}

/// The last descriptor of eventfd `slot` went away.
pub fn closed(slot: u32) {
    EFDS.lock().remove(&slot);
}

/// A signal for the caller of pending call `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    let found = {
        let mut m = EFDS.lock();
        let mut f = false;
        for e in m.values_mut() {
            let (r, w) = (e.readers.len(), e.writers.len());
            e.readers.retain(|x| x.id != id);
            e.writers.retain(|x| x.id != id);
            if e.readers.len() != r || e.writers.len() != w {
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
    let mut m = EFDS.lock();
    for e in m.values_mut() {
        e.readers.retain(|x| x.tgid != tgid);
        e.writers.retain(|x| x.tgid != tgid);
    }
}
