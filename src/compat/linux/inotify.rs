//! # Linux Compatibility: Filesystem Change Notification (`inotify`)
//!
//! Provides the `inotify` filesystem event monitoring facility (`inotify_init1`,
//! `inotify_add_watch`, `inotify_rm_watch`) used by GLib file monitors, KDE's `KDirWatch`,
//! and `dbus-daemon` configuration reloads.
//!
//! ## Architectural Role & Design Rationale
//! Processes register watches on ZFS inodes (files or directories) and read variable-length
//! `struct inotify_event` records describing filesystem mutations. The ZFS storage layer
//! reports mutations by inode via [`event()`]: entries created, deleted, or renamed inside a
//! directory (including the entry's filename), as well as file content modifications,
//! attribute changes, and the final close of a writable file descriptor.
//!
//! To prevent lock-order inversions between the filesystem and `inotify`, this module never
//! calls back into the VFS while holding an `inotify` lock; path resolution in
//! [`sys_add_watch()`] completes before acquiring `Inotify::inner`.
//!
//! ## Key Types & Interfaces
//! - [`Inotify`]: Kernel state of an open `inotify` descriptor holding watch tables and queued events.
//! - [`event()`]: Hook invoked by the VFS/ZFS layer whenever an inode is modified.
//! - [`active()`] / [`watched()`]: Fast atomic/lookup predicates allowing VFS paths to skip
//!   event construction when no watches are active.
//! - [`sys_init1()`], [`sys_add_watch()`], [`sys_rm_watch()`]: System call entry points.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None
//! - Concurrency: Global [`WATCHES`] atomic counter avoids lock acquisition when `inotify` is
//!   unused; per-instance state is guarded by [`spin::Mutex`] and signaled via [`WaitQueue`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

/// Event mask bit: watched file or file inside watched directory was modified (e.g., `write`, `truncate`).
pub const IN_MODIFY: u32 = 0x2;
/// Event mask bit: metadata changed (permissions, timestamps, link count, ownership).
pub const IN_ATTRIB: u32 = 0x4;
/// Event mask bit: file opened for writing was closed.
pub const IN_CLOSE_WRITE: u32 = 0x8;
/// Event mask bit: file or subdirectory was moved out of the watched directory.
pub const IN_MOVED_FROM: u32 = 0x40;
/// Event mask bit: file or subdirectory was moved into the watched directory.
pub const IN_MOVED_TO: u32 = 0x80;
/// Event mask bit: file or subdirectory was created inside the watched directory.
pub const IN_CREATE: u32 = 0x100;
/// Event mask bit: file or subdirectory was unlinked from the watched directory.
pub const IN_DELETE: u32 = 0x200;
/// Event mask bit: watched inode itself was deleted (automatically removes the watch).
pub const IN_DELETE_SELF: u32 = 0x400;
/// Event mask bit: watched inode itself was renamed/moved.
pub const IN_MOVE_SELF: u32 = 0x800;
/// Output event flag: event queue overflowed [`MAX_QUEUED`] (`wd` is `-1`).
const IN_Q_OVERFLOW: u32 = 0x4000;
/// Output event flag: watch was removed explicitly via `inotify_rm_watch` or automatically on delete/oneshot.
const IN_IGNORED: u32 = 0x8000;
/// Output event flag: the subject of the event is a directory.
pub const IN_ISDIR: u32 = 0x4000_0000;
/// Watch flag: only watch the target path if it is a directory (`-ENOTDIR` otherwise).
const IN_ONLYDIR: u32 = 0x0100_0000;
/// Watch flag: do not dereference the target path if it is a symbolic link.
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
/// Watch flag: exclude events on unlinked children.
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
/// Watch flag: fail with `-EEXIST` if the target inode is already watched by this instance.
const IN_MASK_CREATE: u32 = 0x1000_0000;
/// Watch flag: bitwise-OR the new event mask into an existing watch instead of replacing it.
const IN_MASK_ADD: u32 = 0x2000_0000;
/// Watch flag: monitor the inode for a single matching event, then automatically remove the watch.
const IN_ONESHOT: u32 = 0x8000_0000;
/// Bitmask of all supported user-subscribable `IN_*` event bits.
const IN_ALL_EVENTS: u32 = 0xFFF;

/// `inotify_init1` flag: set `O_NONBLOCK` on the new `inotify` file descriptor.
const IN_NONBLOCK: u64 = 0o4000;
/// `inotify_init1` flag: set `FD_CLOEXEC` on the new `inotify` file descriptor.
const IN_CLOEXEC: u64 = 0o2000000;

/// Negative errno for non-blocking read with no queued events.
const EAGAIN: i64 = -11;
/// Negative errno for `IN_MASK_CREATE` when a watch on the inode already exists.
const EEXIST: i64 = -17;
/// Negative errno for `IN_ONLYDIR` when the target inode is not a directory.
const ENOTDIR: i64 = -20;
/// Negative errno for invalid watch descriptor, mask, or buffer smaller than the next event.
const EINVAL: i64 = -22;
/// Negative errno for per-process open file descriptor table full.
const EMFILE: i64 = -24;

/// Maximum number of unread events queued per [`Inotify`] instance (`max_queued_events`).
const MAX_QUEUED: usize = 16384;

/// Internal representation of a single watch registered on a ZFS inode.
struct Watch {
    /// Watched ZFS inode number.
    ino: u64,
    /// Subscribed `IN_*` event bitmask (including `IN_ONESHOT`).
    mask: u32,
}

/// Mutable state of an [`Inotify`] instance protected by its spinlock.
#[derive(Default)]
struct Inner {
    /// Active watches indexed by watch descriptor (`wd`).
    watches: BTreeMap<i32, Watch>,
    /// Reverse lookup from ZFS inode number to watch descriptor (`wd`).
    by_ino: BTreeMap<u64, i32>,
    /// Queue of serialized `struct inotify_event` records waiting to be read.
    queue: VecDeque<Vec<u8>>,
    /// Total byte size of all records currently in `queue` (reported by `FIONREAD`).
    bytes: usize,
    /// Monotonically increasing counter for allocating watch descriptors (`wd >= 1`).
    next_wd: i32,
}

/// Kernel object backing an open `FileDescriptor::Inotify` handle.
///
/// # Concurrency & Thread Safety
/// Shared via `Arc<Inotify>`. Internal maps and the event queue are guarded by `inner`,
/// while `nonblock` is updated atomically via `fcntl(F_SETFL)`.
///
/// # Lifetime & Cleanup
/// Registered as a [`Weak`] reference in [`INSTANCES`]. When dropped, decrements [`WATCHES`]
/// by the number of remaining active watches.
pub struct Inotify {
    /// Spinlock-protected watch tables and serialized event queue.
    inner: Mutex<Inner>,
    /// Non-blocking I/O flag (`O_NONBLOCK`).
    nonblock: AtomicBool,
    /// Wait queue waking blocked readers and `poll`/`epoll` instances when events arrive.
    pub wq: Arc<WaitQueue>,
}

/// Global registry of weak references to all live [`Inotify`] instances.
static INSTANCES: Mutex<Vec<Weak<Inotify>>> = Mutex::new(Vec::new());
/// Total number of active watches across all [`Inotify`] instances (allows VFS fast-path skip when 0).
static WATCHES: AtomicUsize = AtomicUsize::new(0);
/// Monotonic counter generating unique cookies to pair `IN_MOVED_FROM` and `IN_MOVED_TO` events.
static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

/// Returns `true` if at least one `inotify` watch is currently active anywhere in the system.
pub fn active() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// Generates a fresh, non-zero rename cookie pairing an [`IN_MOVED_FROM`] event with [`IN_MOVED_TO`].
pub fn cookie() -> u32 {
    NEXT_COOKIE.fetch_add(1, Ordering::Relaxed)
}

/// Returns `true` if any live [`Inotify`] instance currently watches ZFS inode `ino`.
///
/// # Arguments
/// * `ino` - ZFS inode number to check.
pub fn watched(ino: u64) -> bool {
    active() && INSTANCES.lock().iter().filter_map(|w| w.upgrade()).any(|i| i.inner.lock().by_ino.contains_key(&ino))
}

/// Serializes a single `struct inotify_event` record (16-byte header plus 16-byte-padded `NUL`-terminated name).
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
    /// Appends a serialized event record to the queue, coalescing identical consecutive events
    /// and emitting [`IN_Q_OVERFLOW`] if [`MAX_QUEUED`] is reached.
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

    /// Removes watch descriptor `wd`, decrements [`WATCHES`], and queues an [`IN_IGNORED`] event.
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

/// Reports a filesystem event `mask` on ZFS inode `ino` (with optional child `name` and rename `cookie`)
/// to all [`Inotify`] instances watching `ino`.
///
/// If `mask` includes [`IN_DELETE_SELF`] or the watch was registered with `IN_ONESHOT`, the
/// watch is automatically removed and an `IN_IGNORED` event is appended.
///
/// # Arguments
/// * `ino` - Target ZFS inode number (either the modified file or the parent directory).
/// * `mask` - Bitmask of `IN_*` event flags describing the operation.
/// * `cookie` - Rename correlation cookie from [`cookie()`] (0 for non-move events).
/// * `name` - Entry filename within directory `ino` (empty slice when reporting on a file itself).
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
    /// Returns `POLLIN` (`0x0001`) if at least one event record is queued for reading.
    pub fn poll_events(&self) -> u32 {
        if self.inner.lock().queue.is_empty() {
            0
        } else {
            0x0001
        }
    }

    /// Returns the total byte size of all queued event records (for `ioctl(FIONREAD)`).
    pub fn pending_bytes(&self) -> usize {
        self.inner.lock().bytes
    }

    /// Updates the `O_NONBLOCK` status flag on this `inotify` instance.
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Returns `true` if `O_NONBLOCK` is enabled on this `inotify` instance.
    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Reads as many whole `struct inotify_event` records as fit into `buf`, blocking if
    /// the queue is empty (unless `O_NONBLOCK` is set).
    ///
    /// # Arguments
    /// * `buf` - User output buffer.
    ///
    /// # Returns
    /// * Total bytes copied into `buf` (`> 0`) on success.
    /// * `-EINVAL` if `buf` is too small to hold the first queued event record.
    /// * `-EAGAIN` if no events are queued and `O_NONBLOCK` is set.
    /// * `ERESTARTSYS` if interrupted by a signal while sleeping.
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

/// Resolves file descriptor `fd` to an [`Arc<Inotify>`] if it refers to an `inotify` instance.
fn inotify_of(fd: u64) -> Option<Arc<Inotify>> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Inotify(i)) => Some(i.clone()),
        _ => None,
    })
}

/// System call handler for `inotify_init1(flags)` and `inotify_init()` (`flags = 0`).
///
/// # Arguments
/// * `flags` - Bitmask of `IN_NONBLOCK` (`0o4000`) and `IN_CLOEXEC` (`0o2000000`).
///
/// # Returns
/// Non-negative file descriptor on success, or `-EINVAL` / `-EMFILE` on error.
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

/// System call handler for `inotify_add_watch(fd, pathname, mask)`.
///
/// Adds a new watch or modifies an existing watch for the inode resolved from `path_ptr`.
///
/// # Arguments
/// * `fd` - File descriptor referring to an [`Inotify`] instance.
/// * `path_ptr` - User virtual address of the `NUL`-terminated path string.
/// * `mask` - Bitmask of `IN_*` events and watch flags (`IN_ONLYDIR`, `IN_DONT_FOLLOW`, `IN_MASK_ADD`, `IN_MASK_CREATE`, `IN_ONESHOT`).
///
/// # Returns
/// Non-negative watch descriptor (`wd`) on success, or a negative errno (`-EINVAL`, `-ENOENT`, `-ENOTDIR`, `-EEXIST`, `-EFAULT`) on failure.
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

/// System call handler for `inotify_rm_watch(fd, wd)`.
///
/// Removes watch descriptor `wd` from `inotify` instance `fd` and queues an `IN_IGNORED` event.
///
/// # Arguments
/// * `fd` - File descriptor referring to an [`Inotify`] instance.
/// * `wd` - Watch descriptor previously returned by [`sys_add_watch()`].
///
/// # Returns
/// `0` on success, or `-EINVAL` if `fd` is not an `inotify` descriptor or `wd` is not registered.
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
