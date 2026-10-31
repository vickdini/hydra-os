//! # `inotify`
//!
//! File-system change notification: a process adds watches on files and directories and
//! reads `struct inotify_event` records describing changes (GLib file monitors, KDE's
//! KDirWatch, dbus-daemon configuration reloads).
//!
//! The ZFS file layer reports changes by inode through [`event`]: entries created,
//! deleted or moved in a directory (with the entry's name), and modifications, attribute
//! changes and the final close after writing for files (to the file's own watches and,
//! with its name, to its directory's). This module never calls back into the file
//! system, so it can run under the file server's lock.
//!
//! Not reported: `IN_ACCESS`, `IN_OPEN` and `IN_CLOSE_NOWRITE`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_MOVE_SELF: u32 = 0x800;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
pub const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
const IN_ALL_EVENTS: u32 = 0xFFF;

const IN_NONBLOCK: u64 = 0o4000;
const IN_CLOEXEC: u64 = 0o2000000;

const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

/// Most queued events per instance (`max_queued_events`).
const MAX_QUEUED: usize = 16384;

struct Watch {
    ino: u64,
    mask: u32,
}

#[derive(Default)]
struct Inner {
    watches: BTreeMap<i32, Watch>,
    by_ino: BTreeMap<u64, i32>,
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    next_wd: i32,
}

pub struct Inotify {
    inner: Mutex<Inner>,
    nonblock: AtomicBool,
    pub wq: Arc<WaitQueue>,
}

static INSTANCES: Mutex<Vec<Weak<Inotify>>> = Mutex::new(Vec::new());
/// Watches in all instances (lets the file system skip notification work when zero).
static WATCHES: AtomicUsize = AtomicUsize::new(0);
static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

/// True if any watch exists anywhere.
pub fn active() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// A fresh cookie pairing `IN_MOVED_FROM` with `IN_MOVED_TO`.
pub fn cookie() -> u32 {
    NEXT_COOKIE.fetch_add(1, Ordering::Relaxed)
}

/// True if some instance watches inode `ino`.
pub fn watched(ino: u64) -> bool {
    active() && INSTANCES.lock().iter().filter_map(|w| w.upgrade()).any(|i| i.inner.lock().by_ino.contains_key(&ino))
}

fn record(wd: i32, mask: u32, cookie: u32, name: &[u8]) -> Vec<u8> {
    let len = if name.is_empty() { 0 } else { (name.len() + 1 + 15) & !15 };
    let mut r = Vec::with_capacity(16 + len);
    r.extend_from_slice(&wd.to_le_bytes());
    r.extend_from_slice(&mask.to_le_bytes());
    r.extend_from_slice(&cookie.to_le_bytes());
    r.extend_from_slice(&(len as u32).to_le_bytes());
    r.extend_from_slice(name);
    r.resize(16 + len, 0);
    r
}

impl Inner {
    fn push(&mut self, rec: Vec<u8>) {
        if self.queue.back() == Some(&rec) {
            return; // identical to the previous unread event: coalesced, as on Linux
        }
        if self.queue.len() >= MAX_QUEUED {
            let overflow = record(-1, IN_Q_OVERFLOW, 0, b"");
            if self.queue.back() != Some(&overflow) {
                self.bytes += overflow.len();
                self.queue.push_back(overflow);
            }
            return;
        }
        self.bytes += rec.len();
        self.queue.push_back(rec);
    }

    fn remove_watch(&mut self, wd: i32) -> bool {
        match self.watches.remove(&wd) {
            Some(w) => {
                self.by_ino.remove(&w.ino);
                WATCHES.fetch_sub(1, Ordering::Relaxed);
                self.push(record(wd, IN_IGNORED, 0, b""));
                true
            }
            None => false,
        }
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        WATCHES.fetch_sub(self.inner.lock().watches.len(), Ordering::Relaxed);
    }
}

/// Reports `mask` (with `name` for an entry of directory `ino`) to every watch on `ino`.
/// `IN_DELETE_SELF` also removes the watches (`IN_IGNORED` follows).
pub fn event(ino: u64, mask: u32, cookie: u32, name: &[u8]) {
    if !active() {
        return;
    }
    let instances: Vec<Arc<Inotify>> = INSTANCES.lock().iter().filter_map(|w| w.upgrade()).collect();
    for inst in instances {
        let mut inner = inst.inner.lock();
        let wd = match inner.by_ino.get(&ino) {
            Some(&wd) => wd,
            None => continue,
        };
        let wmask = inner.watches[&wd].mask;
        let wanted = wmask & mask & IN_ALL_EVENTS != 0;
        if wanted {
            inner.push(record(wd, mask, cookie, name));
        }
        if mask & IN_DELETE_SELF != 0 || (wanted && wmask & IN_ONESHOT != 0) {
            inner.remove_watch(wd);
        }
        drop(inner);
        inst.wq.wake_all();
    }
}

impl Inotify {
    pub fn poll_events(&self) -> u32 {
        if self.inner.lock().queue.is_empty() {
            0
        } else {
            0x0001
        }
    }

    /// Bytes of queued events (`FIONREAD`).
    pub fn pending_bytes(&self) -> usize {
        self.inner.lock().bytes
    }

    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Reads whole events; `EINVAL` if the first does not fit.
    pub fn read(&self, buf: &mut [u8]) -> i64 {
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.wq.clone()));
        loop {
            waits.register();
            {
                let mut inner = self.inner.lock();
                if let Some(first) = inner.queue.front() {
                    if first.len() > buf.len() {
                        return EINVAL;
                    }
                    let mut n = 0;
                    while let Some(rec) = inner.queue.front() {
                        if n + rec.len() > buf.len() {
                            break;
                        }
                        let rec = inner.queue.pop_front().unwrap();
                        buf[n..n + rec.len()].copy_from_slice(&rec);
                        n += rec.len();
                        inner.bytes -= rec.len();
                    }
                    return n as i64;
                }
            }
            if self.get_nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }
}

fn inotify_of(fd: u64) -> Option<Arc<Inotify>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Inotify(i)) => Some(i.clone()),
        _ => None,
    })
}

/// `inotify_init1(flags)` (and `inotify_init`).
pub fn sys_init1(flags: u64) -> i64 {
    if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
        return EINVAL;
    }
    let inst = Arc::new(Inotify {
        inner: Mutex::new(Inner { next_wd: 1, ..Inner::default() }),
        nonblock: AtomicBool::new(flags & IN_NONBLOCK != 0),
        wq: WaitQueue::new_shared(),
    });
    {
        let mut all = INSTANCES.lock();
        all.retain(|w| w.strong_count() > 0);
        all.push(Arc::downgrade(&inst));
    }
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Inotify(inst)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & IN_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// `inotify_add_watch(fd, path, mask)`: returns the watch descriptor (the existing one,
/// with its mask replaced or extended, if the inode is already watched).
pub fn sys_add_watch(fd: u64, path_ptr: u64, mask: u64) -> i64 {
    let inst = match inotify_of(fd) {
        Some(i) => i,
        None => return EINVAL,
    };
    let mask = mask as u32;
    if mask & IN_ALL_EVENTS == 0 || (mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0) {
        return EINVAL;
    }
    // Resolve before taking any inotify lock (the file system reports events under its own)
    let (ino, is_dir) = match super::vfs::lookup_path(path_ptr, mask & IN_DONT_FOLLOW == 0) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if mask & IN_ONLYDIR != 0 && !is_dir {
        return ENOTDIR;
    }
    let keep = mask & (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK);
    let mut inner = inst.inner.lock();
    if let Some(&wd) = inner.by_ino.get(&ino) {
        if mask & IN_MASK_CREATE != 0 {
            return EEXIST;
        }
        let w = inner.watches.get_mut(&wd).unwrap();
        w.mask = if mask & IN_MASK_ADD != 0 { w.mask | keep } else { keep };
        return wd as i64;
    }
    let wd = inner.next_wd;
    inner.next_wd += 1;
    inner.watches.insert(wd, Watch { ino, mask: keep });
    inner.by_ino.insert(ino, wd);
    WATCHES.fetch_add(1, Ordering::Relaxed);
    wd as i64
}

/// `inotify_rm_watch(fd, wd)`.
pub fn sys_rm_watch(fd: u64, wd: u64) -> i64 {
    let inst = match inotify_of(fd) {
        Some(i) => i,
        None => return EINVAL,
    };
    let removed = inst.inner.lock().remove_watch(wd as i32);
    if removed {
        inst.wq.wake_all();
        0
    } else {
        EINVAL
    }
}
