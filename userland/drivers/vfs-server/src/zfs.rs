//! # zfs-server's client
//!
//! vfs-server is zfs-server's second client, next to the kernel. Its requests use the
//! protocol of `src/fs/zfs/fsproto.rs` unchanged, but sit in **vfs-server's own window**
//! (which zfs-server attaches: the supervisor's `allow_client(ENDPOINT_VFS_SERVER,
//! ENDPOINT_ZFS_SERVER)`), at [`FS_VFS_OFF`], with the reply data in the same place and the
//! events at [`FS_VFS_EVENTS`]; `args[1] = FS_CLIENT_VFS` says so. The kernel's use of
//! zfs-server's window is untouched.
//!
//! One request at a time (zfs-server serves one at a time anyway); the workers take turns
//! on a lock. zfs-server answers with `reply_recv`, so a request takes the kernel's direct
//! path both ways. A request that fails because zfs-server went away is made once more
//! after a pause (the supervisor restarts it), and the caches are forgotten: the restarted
//! server's objects are the same, but changes in flight may or may not have happened.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::fs::fsproto::*;
use crate::lock::YLock;
use crate::proto::ENDPOINT_ZFS_SERVER;
use hydra_rt::{sys, Message};

/// Ticks a request may take (zfs-server may be reading a cold disk).
const TIMEOUT_TICKS: u64 = 3000;

static WINDOW: AtomicU64 = AtomicU64::new(0);
static TURN: YLock<()> = YLock::new(());
/// Requests made since the start.
pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
/// Requests that failed because zfs-server was away.
pub static RETRIES: AtomicU64 = AtomicU64::new(0);
/// The pool root's object number (`FS_ROOT`), once known.
static ROOT: AtomicU64 = AtomicU64::new(0);

/// Sets vfs-server's window (from the service runtime).
pub fn init(window: *mut u8) {
    WINDOW.store(window as u64, Ordering::Release);
}

/// A reply.
pub struct Reply {
    /// The operation's value (an object number, a count, ...).
    pub value: u64,
    /// Its reply bytes.
    pub data: Vec<u8>,
    /// The inotify events it caused (7-2 hands them to the kernel's watchers).
    pub events: Vec<Event>,
}

/// `-ETIMEDOUT`: the request took too long (zfs-server may still be serving it).
const ETIMEDOUT: i64 = -110;
/// Times a request that changes nothing is made again while zfs-server restarts (300 ms
/// apart).
const RESTART_TRIES: usize = 20;

/// After a timed-out request (under `TURN`): waits until zfs-server has finished it, by
/// sending parameterless `FS_ROOT` requests until one is answered (they queue behind it);
/// gives up after about two minutes or when zfs-server is gone (its restart ends the old
/// request too).
fn drain() {
    for _ in 0..4 {
        match sys::svc_call(ENDPOINT_ZFS_SERVER, Message::new(FS_ROOT as u64, [0, FS_CLIENT_VFS, 0, 0]), TIMEOUT_TICKS) {
            Err(ETIMEDOUT) => continue,
            _ => return,
        }
    }
}

/// Our part of the window (`FS_VFS_OFF..FS_VFS_END`, offset 0 here), used only under
/// `TURN`, and never held as a slice across the call (zfs-server writes it meanwhile).
fn part() -> Result<*mut u8, i64> {
    let a = WINDOW.load(Ordering::Acquire);
    if a == 0 {
        return Err(EIO);
    }
    Ok((a as usize + FS_VFS_OFF) as *mut u8)
}

/// `len` bytes of our part from `off` on.
///
/// # Safety
/// Under `TURN`, with no zfs-server request in flight.
unsafe fn slice<'a>(p: *mut u8, off: usize, len: usize) -> &'a mut [u8] {
    core::slice::from_raw_parts_mut(p.add(off), len)
}

/// Whether request `op` changes nothing (it may be made again after zfs-server restarted).
fn idempotent(op: u32) -> bool {
    matches!(op, FS_ROOT | FS_LOOKUP | FS_RESOLVE | FS_RESOLVE_MNT | FS_GETATTR | FS_READ | FS_READLINK | FS_READDIR | FS_STATFS | FS_GETXATTR | FS_LISTXATTR | FS_OBJECT_INFO | FS_DATASETS | FS_POOL_STATUS)
}

/// Sends request `op` with the parameters `params` writes; returns its value, reply bytes
/// and events, or its error. A request that changes nothing is made once more if zfs-server
/// went away (not after a timeout: it may still be serving it); a change is not (`EIO`: it
/// may or may not have happened).
pub fn request(op: u32, params: impl Fn(&mut Writer)) -> Result<Reply, i64> {
    let _turn = TURN.lock();
    let p = part()?;
    const DATA: usize = FS_VFS_EVENTS - FS_VFS_OFF;
    const EVENTS: usize = FS_VFS_END - FS_VFS_EVENTS;
    for attempt in 0..=RESTART_TRIES {
        let len = {
            // SAFETY: under TURN, before the call
            let mut wr = Writer::new(unsafe { slice(p, 0, DATA) });
            params(&mut wr);
            wr.len()
        };
        // (a `Writer` drops what does not fit: parameters that filled our part may have
        // lost some; a request is never that large unless something is wrong)
        if len >= DATA - 64 {
            return Err(E2BIG);
        }
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let r = sys::svc_call(ENDPOINT_ZFS_SERVER, Message::new(op as u64, [len as u64, FS_CLIENT_VFS, 0, 0]), TIMEOUT_TICKS);
        match r {
            Ok(m) if m.label == FS_REPLY as u64 => {
                let status = m.args[0] as i64;
                if status < 0 {
                    return Err(status);
                }
                // (more reply bytes than our part holds: a broken answer, not a short one)
                if m.args[2] as usize > DATA {
                    return Err(EIO);
                }
                let n = m.args[2] as usize;
                // SAFETY: under TURN, after the answer
                let data = unsafe { slice(p, 0, n) }.to_vec();
                let mut events = Vec::new();
                if m.args[3] > 0 {
                    // SAFETY: as above
                    let mut rd = Reader::new(unsafe { slice(p, DATA, EVENTS) });
                    // (an event takes 20 bytes at least)
                    for _ in 0..m.args[3].min((EVENTS / 20) as u64) {
                        events.push(rd.event());
                    }
                }
                return Ok(Reply { value: m.args[1], data, events });
            }
            Ok(_) => return Err(EIO),
            Err(e) => {
                crate::cache::forget_all();
                if e == ETIMEDOUT {
                    // zfs-server may still be serving it and writing our part: keep the turn
                    // until a request without parameters has passed behind it (zfs-server
                    // serves one at a time), so nobody writes there meanwhile
                    drain();
                    return Err(EIO);
                }
                if !idempotent(op) || attempt == RESTART_TRIES {
                    return Err(EIO);
                }
                RETRIES.fetch_add(1, Ordering::Relaxed);
                // (zfs-server restarting: the pool import takes a while)
                sys::sleep_ms(300);
            }
        }
    }
    Err(EIO)
}

/// The pool root's object number.
pub fn root() -> Result<u64, i64> {
    let r = ROOT.load(Ordering::Acquire);
    if r != 0 {
        return Ok(r);
    }
    let v = request(FS_ROOT, |_| {})?.value;
    ROOT.store(v, Ordering::Release);
    Ok(v)
}

/// `name` in directory `dir`.
pub fn lookup(dir: u64, name: &[u8]) -> Result<u64, i64> {
    request(FS_LOOKUP, |w| {
        w.u64(dir);
        w.bytes(name);
    })
    .map(|r| r.value)
}

/// The attributes of `ino`.
pub fn getattr(ino: u64) -> Result<Attr, i64> {
    let r = request(FS_GETATTR, |w| {
        w.u64(ino);
    })?;
    // (an attribute record: 14 words)
    if r.data.len() < 14 * 8 {
        return Err(EIO);
    }
    Ok(Reader::new(&r.data).attr())
}

/// The target of symbolic link `ino`.
pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
    request(FS_READLINK, |w| {
        w.u64(ino);
    })
    .map(|r| r.data)
}

/// Up to `max` entries of directory `dir` from `cookie` on.
pub fn readdir(dir: u64, cookie: u64, max: usize) -> Result<Vec<ReaddirEntry>, i64> {
    let r = request(FS_READDIR, |w| {
        w.u64(dir);
        w.u64(cookie);
        w.u64(max as u64);
    })?;
    let mut rd = Reader::new(&r.data);
    // (an entry takes 28 bytes at least)
    let n = r.value.min(max as u64).min((r.data.len() / 28) as u64);
    Ok((0..n).map(|_| rd.entry()).collect())
}

/// Extended attribute `name` of `ino` (`ENODATA` if it has none of that name).
pub fn getxattr(ino: u64, name: &[u8]) -> Result<Vec<u8>, i64> {
    let r = request(FS_GETXATTR, |w| {
        w.u64(ino);
        w.bytes(name);
    })?;
    if r.value as usize > r.data.len() {
        return Err(E2BIG);
    }
    Ok(r.data)
}

/// The extended attribute names of `ino` (each NUL-terminated).
pub fn listxattr(ino: u64) -> Result<Vec<u8>, i64> {
    let r = request(FS_LISTXATTR, |w| {
        w.u64(ino);
    })?;
    if r.value as usize > r.data.len() {
        return Err(E2BIG);
    }
    Ok(r.data)
}

/// `(total blocks, free blocks, objects in use)`.
pub fn statfs() -> Result<(u64, u64, u64), i64> {
    let r = request(FS_STATFS, |_| {})?;
    if r.data.len() < 3 * 8 {
        return Err(EIO);
    }
    let mut rd = Reader::new(&r.data);
    Ok((rd.u64(), rd.u64(), rd.u64()))
}
