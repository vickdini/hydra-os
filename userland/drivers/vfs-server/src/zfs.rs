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

fn window() -> Result<&'static mut [u8], i64> {
    let a = WINDOW.load(Ordering::Acquire);
    if a == 0 {
        return Err(EIO);
    }
    // SAFETY: the mapped 256 KiB window; our part is used only under TURN
    Ok(unsafe { core::slice::from_raw_parts_mut(a as *mut u8, FS_VFS_END) })
}

/// Sends request `op` with the parameters `params` writes; returns its value, reply bytes
/// and events, or its error.
pub fn request(op: u32, params: impl Fn(&mut Writer)) -> Result<Reply, i64> {
    let _turn = TURN.lock();
    let w = window()?;
    for attempt in 0..2 {
        let len = {
            let mut wr = Writer::new(&mut w[FS_VFS_OFF..FS_VFS_EVENTS]);
            params(&mut wr);
            wr.len()
        };
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let r = sys::svc_call(ENDPOINT_ZFS_SERVER, Message::new(op as u64, [len as u64, FS_CLIENT_VFS, 0, 0]), TIMEOUT_TICKS);
        match r {
            Ok(m) if m.label == FS_REPLY as u64 => {
                let status = m.args[0] as i64;
                if status < 0 {
                    return Err(status);
                }
                let n = (m.args[2] as usize).min(FS_VFS_EVENTS - FS_VFS_OFF);
                let data = w[FS_VFS_OFF..FS_VFS_OFF + n].to_vec();
                let mut events = Vec::new();
                if m.args[3] > 0 {
                    let mut rd = Reader::new(&w[FS_VFS_EVENTS..FS_VFS_END]);
                    for _ in 0..m.args[3] {
                        events.push(rd.event());
                    }
                }
                return Ok(Reply { value: m.args[1], data, events });
            }
            Ok(_) => return Err(EIO),
            Err(_) => {
                RETRIES.fetch_add(1, Ordering::Relaxed);
                crate::cache::forget_all();
                if attempt == 0 {
                    sys::sleep_ms(200);
                }
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
    Ok((0..r.value).map(|_| rd.entry()).collect())
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
    let mut rd = Reader::new(&r.data);
    Ok((rd.u64(), rd.u64(), rd.u64()))
}
