//! File locks: `flock`, POSIX record locks and open file description locks.
//!
//! - **`flock`** locks a whole file, shared or exclusive, for an open file description: its
//!   duplicates and forked copies share it, and it goes when the description's last
//!   descriptor closes. A conversion releases first, as on Linux.
//! - **POSIX record locks** (`F_SETLK`, `F_SETLKW`, `F_GETLK`) lock byte ranges for a
//!   process: its own ranges merge and split, and all of them on a file go when the process
//!   closes any descriptor of it, or exits.
//! - **Open file description locks** (`F_OFD_*`) are byte ranges owned by the description;
//!   they and POSIX locks conflict with each other, not with `flock`.
//! - Waits (`F_SETLKW`, blocking `flock`) end when the lock can be had or a signal comes
//!   (`EINTR`). `/proc/locks` lists them all. Locks are advisory, as on Linux.
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const EFAULT: i64 = -14;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    /// A process (POSIX record locks).
    Posix(u64),
    /// An open file description (OFD locks).
    Ofd(usize),
    /// An open file description (`flock`).
    Flock(usize),
}

impl Owner {
    fn whole_file(self) -> bool {
        matches!(self, Owner::Flock(_))
    }
}

#[derive(Clone, Copy)]
struct Lock {
    ino: u64,
    owner: Owner,
    write: bool,
    start: u64,
    /// Inclusive; `u64::MAX` reaches the end of the file however it grows.
    end: u64,
    /// Who took it (for `F_GETLK` and `/proc/locks`).
    pid: u64,
}

static LOCKS: Mutex<Vec<Lock>> = Mutex::new(Vec::new());
static WQ: WaitQueue = WaitQueue::new();
static ANY: AtomicBool = AtomicBool::new(false);

/// The first lock of another owner (of the same family: `flock`, or record locks) that
/// conflicts with taking `write` on `[start, end]` of `ino`.
fn conflict(locks: &[Lock], ino: u64, owner: Owner, write: bool, start: u64, end: u64) -> Option<Lock> {
    locks
        .iter()
        .find(|l| l.ino == ino && l.owner != owner && l.owner.whole_file() == owner.whole_file() && l.start <= end && start <= l.end && (write || l.write))
        .copied()
}

/// Removes `owner`'s locks on `[start, end]` of `ino` (splitting the ones reaching past).
fn cut(locks: &mut Vec<Lock>, ino: u64, owner: Owner, start: u64, end: u64) {
    let mut out = Vec::with_capacity(locks.len() + 1);
    for l in locks.drain(..) {
        if l.ino != ino || l.owner != owner || l.end < start || end < l.start {
            out.push(l);
            continue;
        }
        if l.start < start {
            out.push(Lock { end: start - 1, ..l });
        }
        if l.end > end {
            out.push(Lock { start: end + 1, ..l });
        }
    }
    *locks = out;
}

/// Adds a lock for `owner`, merging with its touching locks of the same kind.
fn add(locks: &mut Vec<Lock>, mut new: Lock) {
    cut(locks, new.ino, new.owner, new.start, new.end);
    loop {
        let touching = locks.iter().position(|l| {
            l.ino == new.ino && l.owner == new.owner && l.write == new.write && (l.end != u64::MAX && l.end + 1 == new.start || new.end != u64::MAX && new.end + 1 == l.start)
        });
        match touching {
            Some(i) => {
                let l = locks.remove(i);
                new.start = new.start.min(l.start);
                new.end = new.end.max(l.end);
            }
            None => break,
        }
    }
    locks.push(new);
    ANY.store(true, Ordering::Relaxed);
}

/// Waits until `take` succeeds (it returns `Some(result)`), or a signal (`EINTR`).
fn wait_for(mut take: impl FnMut() -> Option<i64>) -> i64 {
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Static(&WQ));
    loop {
        waits.register();
        if let Some(r) = take() {
            return r;
        }
        if super::proc::signal_pending() {
            return EINTR;
        }
        waits.wait(None);
    }
}

// ----------------------------------------------------------------------
// Releasing
// ----------------------------------------------------------------------

/// An open file description is gone: its `flock` and OFD locks go.
pub fn release_file(id: usize) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut l = LOCKS.lock();
    let before = l.len();
    l.retain(|x| x.owner != Owner::Flock(id) && x.owner != Owner::Ofd(id));
    if l.len() != before {
        WQ.wake_all();
    }
}

/// The calling process closed a descriptor of `ino`: its POSIX locks on it go.
pub fn closed(ino: u64) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let pid = super::proc::current_ids().1;
    let mut l = LOCKS.lock();
    let before = l.len();
    l.retain(|x| !(x.ino == ino && x.owner == Owner::Posix(pid)));
    if l.len() != before {
        WQ.wake_all();
    }
}

/// Process `pid` ended: its POSIX locks go.
pub fn process_exited(pid: u64) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut l = LOCKS.lock();
    let before = l.len();
    l.retain(|x| x.owner != Owner::Posix(pid));
    if l.len() != before {
        WQ.wake_all();
    }
}

// ----------------------------------------------------------------------
// The calls
// ----------------------------------------------------------------------

/// The open file description behind `fd`: `(ino, its identity, readable, writable)`.
fn file_of(fd: i32) -> Result<(u64, usize, bool, bool), i64> {
    let f = crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Vnode(f)) => Some(f.clone()),
        _ => None,
    })
    .ok_or(EBADF)?;
    let g = f.lock();
    if g.flags & crate::fs::fd::O_PATH != 0 {
        return Err(EBADF);
    }
    Ok((g.ino, &*g as *const crate::fs::fd::OpenFile as usize, g.readable(), g.writable()))
}

/// `flock(fd, operation)`.
pub fn flock(fd: u64, op: u64) -> i64 {
    const LOCK_SH: u64 = 1;
    const LOCK_EX: u64 = 2;
    const LOCK_NB: u64 = 4;
    const LOCK_UN: u64 = 8;
    let fd = fd as i32;
    let kind = op & !LOCK_NB;
    if !matches!(kind, LOCK_SH | LOCK_EX | LOCK_UN) {
        return EINVAL;
    }
    // Locks on other kinds of descriptor (pipes, sockets) have nobody to conflict with
    let (ino, id) = match file_of(fd) {
        Ok((ino, id, _, _)) => (ino, id),
        Err(_) => {
            let open = crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).is_some());
            return if open { 0 } else { EBADF };
        }
    };
    let owner = Owner::Flock(id);
    let pid = super::proc::current_ids().1;
    {
        // A conversion (or unlock) drops the current lock first
        let mut l = LOCKS.lock();
        let before = l.len();
        l.retain(|x| !(x.ino == ino && x.owner == owner));
        if l.len() != before {
            WQ.wake_all();
        }
    }
    if kind == LOCK_UN {
        return 0;
    }
    let write = kind == LOCK_EX;
    let try_take = || {
        let mut l = LOCKS.lock();
        if conflict(&l, ino, owner, write, 0, u64::MAX).is_some() {
            return None;
        }
        add(&mut l, Lock { ino, owner, write, start: 0, end: u64::MAX, pid });
        Some(0)
    };
    if op & LOCK_NB != 0 {
        return try_take().unwrap_or(EAGAIN);
    }
    wait_for(try_take)
}

/// `F_GETLK`, `F_SETLK`, `F_SETLKW` and their `F_OFD_` forms (`ofd`) on `fd` with the
/// `struct flock` at `arg`.
pub fn fcntl(fd: u64, cmd: u64, arg: u64, ofd: bool) -> i64 {
    const F_RDLCK: i16 = 0;
    const F_WRLCK: i16 = 1;
    const F_UNLCK: i16 = 2;
    let (ino, id, readable, writable) = match file_of(fd as i32) {
        Ok(v) => v,
        Err(e) => return e,
    };
    // struct flock { short l_type; short l_whence; off_t l_start; off_t l_len; pid_t l_pid; }
    let raw = match copy_in(arg, 32) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let kind = i16::from_le_bytes([raw[0], raw[1]]);
    let whence = i16::from_le_bytes([raw[2], raw[3]]);
    let start = i64::from_le_bytes(raw[8..16].try_into().unwrap());
    let len = i64::from_le_bytes(raw[16..24].try_into().unwrap());
    let l_pid = i32::from_le_bytes(raw[24..28].try_into().unwrap());
    if !matches!(kind, F_RDLCK | F_WRLCK | F_UNLCK) {
        return EINVAL;
    }
    if ofd && l_pid != 0 {
        return EINVAL;
    }
    // The range, from l_whence
    let base: i64 = match whence {
        0 => 0,
        1 => crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
            Some(crate::fs::FileDescriptor::Vnode(f)) => f.lock().offset as i64,
            _ => 0,
        }),
        2 => match crate::fs::ZfsClient::getattr(ino) {
            Ok(a) => a.size as i64,
            Err(e) => return e,
        },
        _ => return EINVAL,
    };
    let Some(mut s) = base.checked_add(start) else { return EINVAL };
    let mut e: i64 = if len == 0 { i64::MAX } else if len > 0 { s.saturating_add(len - 1) } else { s - 1 };
    if len < 0 {
        s += len;
    }
    if s < 0 || e < s {
        return EINVAL;
    }
    if len == 0 || e == i64::MAX {
        e = -1; // to the end of the file
    }
    let (start, end) = (s as u64, if e < 0 { u64::MAX } else { e as u64 });
    let pid = super::proc::current_ids().1;
    let owner = if ofd { Owner::Ofd(id) } else { Owner::Posix(pid) };
    let get = matches!(cmd, 5 | 36);
    if get {
        if kind == F_UNLCK {
            return EINVAL;
        }
        let found = conflict(&LOCKS.lock(), ino, owner, kind == F_WRLCK, start, end);
        let mut out = raw.clone();
        match found {
            Some(l) => {
                out[0..2].copy_from_slice(&(if l.write { F_WRLCK } else { F_RDLCK }).to_le_bytes());
                out[2..4].copy_from_slice(&0i16.to_le_bytes());
                out[8..16].copy_from_slice(&(l.start as i64).to_le_bytes());
                let len = if l.end == u64::MAX { 0 } else { (l.end - l.start + 1) as i64 };
                out[16..24].copy_from_slice(&len.to_le_bytes());
                let shown = match l.owner {
                    Owner::Posix(p) => super::ns::pid_to_caller(p) as i32,
                    _ => -1,
                };
                out[24..28].copy_from_slice(&shown.to_le_bytes());
            }
            None => out[0..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
        }
        return copy_out(arg, &out).map_or(EFAULT, |_| 0);
    }
    if kind == F_UNLCK {
        let mut l = LOCKS.lock();
        cut(&mut l, ino, owner, start, end);
        WQ.wake_all();
        return 0;
    }
    // The descriptor must allow the kind of lock asked for
    if (kind == F_RDLCK && !readable) || (kind == F_WRLCK && !writable) {
        return EBADF;
    }
    let write = kind == F_WRLCK;
    let try_take = || {
        let mut l = LOCKS.lock();
        if conflict(&l, ino, owner, write, start, end).is_some() {
            return None;
        }
        add(&mut l, Lock { ino, owner, write, start, end, pid });
        WQ.wake_all(); // a lock turning shared may let others in
        Some(0)
    };
    if matches!(cmd, 7 | 38) {
        wait_for(try_take)
    } else {
        try_take().unwrap_or(EAGAIN)
    }
}

/// `/proc/locks`.
pub fn proc_locks() -> String {
    let mut s = String::new();
    for (i, l) in LOCKS.lock().iter().enumerate() {
        let (class, pid) = match l.owner {
            Owner::Posix(_) => ("POSIX ", super::ns::pid_to_caller(l.pid) as i64),
            Owner::Ofd(_) => ("OFDLCK", -1),
            Owner::Flock(_) => ("FLOCK ", super::ns::pid_to_caller(l.pid) as i64),
        };
        let end = if l.end == u64::MAX { String::from("EOF") } else { alloc::format!("{}", l.end) };
        s.push_str(&alloc::format!("{}: {} ADVISORY  {} {} 08:01:{} {} {}\n", i + 1, class, if l.write { "WRITE" } else { "READ " }, pid, l.ino, l.start, end));
    }
    s
}
