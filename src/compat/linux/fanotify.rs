//! fanotify: `fanotify_init`, `fanotify_mark`, and reading events from the group.
//!
//! - **Marks** sit on inodes (with `FAN_EVENT_ON_CHILD` on a directory, its files too), on
//!   a mount or on the file system; Hydra has one file system, so mount and file system
//!   marks see every file. Ignore masks subtract events.
//! - **File events** (`FAN_OPEN`, `FAN_OPEN_EXEC`, `FAN_ACCESS`, `FAN_MODIFY`,
//!   `FAN_CLOSE_WRITE`, `FAN_CLOSE_NOWRITE`) come from the file layer in the acting process;
//!   **directory and attribute events** (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`/`TO`,
//!   `FAN_ATTRIB`, `FAN_DELETE_SELF`, `FAN_MOVE_SELF`) from the file server's reports, for
//!   groups that report file handles (`FAN_REPORT_FID`, `_DIR_FID`, `_NAME`), as on Linux.
//! - **Reading** gives `struct fanotify_event_metadata` records: with a descriptor opened on
//!   the object in the reader (which makes no events itself), or with file handle records
//!   (the 8-byte inode number, type 1; `name_to_handle_at` gives the same handles).
//!   Repeated events from one process on one file merge; a full queue reports
//!   `FAN_Q_OVERFLOW`.
//! - **Permission events** (`FAN_OPEN_PERM`, `FAN_OPEN_EXEC_PERM`) hold the open or exec
//!   until the listener writes `FAN_ALLOW` or `FAN_DENY` (`EPERM`); a closed group allows.
//!   `FAN_ACCESS_PERM` is accepted but never raised (reads happen under locks a waiting
//!   reader would hold).
//! - **Unprivileged** groups (no `CAP_SYS_ADMIN`) must report file handles, take inode marks
//!   only, and see other processes' events with pid 0, as on Linux.
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

// fanotify_init flags
const FAN_CLOEXEC: u64 = 1;
const FAN_NONBLOCK: u64 = 2;
const FAN_CLASS_MASK: u64 = 0xc;
const FAN_CLASS_NOTIF: u64 = 0;
const FAN_UNLIMITED_QUEUE: u64 = 0x10;
const FAN_UNLIMITED_MARKS: u64 = 0x20;
const FAN_ENABLE_AUDIT: u64 = 0x40;
const FAN_REPORT_TID: u64 = 0x100;
const FAN_REPORT_FID: u64 = 0x200;
const FAN_REPORT_DIR_FID: u64 = 0x400;
const FAN_REPORT_NAME: u64 = 0x800;
const FID_BITS: u64 = FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
const INIT_OK: u64 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_MASK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_TID | FID_BITS;
const ADMIN_ONLY: u64 = FAN_CLASS_MASK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_TID;

// fanotify_mark flags
const FAN_MARK_ADD: u64 = 1;
const FAN_MARK_REMOVE: u64 = 2;
const FAN_MARK_DONT_FOLLOW: u64 = 4;
const FAN_MARK_ONLYDIR: u64 = 8;
const FAN_MARK_MOUNT: u64 = 0x10;
const FAN_MARK_IGNORED_MASK: u64 = 0x20;
const FAN_MARK_IGNORED_SURV_MODIFY: u64 = 0x40;
const FAN_MARK_FLUSH: u64 = 0x80;
const FAN_MARK_FILESYSTEM: u64 = 0x100;
const FAN_MARK_EVICTABLE: u64 = 0x200;
const FAN_MARK_IGNORE: u64 = 0x400;
const MARK_OK: u64 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM | FAN_MARK_EVICTABLE | FAN_MARK_IGNORE;

// Events
/// `FAN_ACCESS`: A file was read.
pub const FAN_ACCESS: u64 = 0x1;
/// `FAN_MODIFY`: A file was written.
pub const FAN_MODIFY: u64 = 0x2;
/// `FAN_ATTRIB`: Attributes changed.
pub const FAN_ATTRIB: u64 = 0x4;
/// `FAN_CLOSE_WRITE`: A file open for writing was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x8;
/// `FAN_CLOSE_NOWRITE`: A file not open for writing was closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
/// `FAN_OPEN`: A file was opened.
pub const FAN_OPEN: u64 = 0x20;
const FAN_MOVED_FROM: u64 = 0x40;
const FAN_MOVED_TO: u64 = 0x80;
const FAN_CREATE: u64 = 0x100;
const FAN_DELETE: u64 = 0x200;
const FAN_DELETE_SELF: u64 = 0x400;
const FAN_MOVE_SELF: u64 = 0x800;
/// `FAN_OPEN_EXEC`: A file was opened to be run.
pub const FAN_OPEN_EXEC: u64 = 0x1000;
const FAN_Q_OVERFLOW: u64 = 0x4000;
const FAN_OPEN_PERM: u64 = 0x1_0000;
const FAN_ACCESS_PERM: u64 = 0x2_0000;
const FAN_OPEN_EXEC_PERM: u64 = 0x4_0000;
const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
const FAN_RENAME: u64 = 0x1000_0000;
const FAN_ONDIR: u64 = 0x4000_0000;
const PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;
const FD_EVENTS: u64 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN | FAN_OPEN_EXEC;
const DIRENT_EVENTS: u64 = FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_DELETE | FAN_RENAME;
const FID_EVENTS: u64 = DIRENT_EVENTS | FAN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF;
const EVENTS_OK: u64 = FD_EVENTS | FID_EVENTS | PERM_EVENTS | FAN_EVENT_ON_CHILD | FAN_ONDIR;

const FAN_ALLOW: u32 = 1;
const FAN_DENY: u32 = 2;
const FAN_NOFD: i32 = -1;
const QUEUE_MAX: usize = 16384;

/// The file system ID Hydra's pool reports (`statfs` `f_fsid`, fanotify handle records).
pub const POOL_FSID: [i32; 2] = [0x4859_4452, 0x5a46_5301];

/// A mark: the events it wants and those it ignores.
#[derive(Clone, Copy, Default)]
struct Mark {
    mask: u64,
    ignore: u64,
}

/// A queued event.
struct Event {
    mask: u64,
    /// The object (0 for an overflow).
    ino: u64,
    /// Its directory and its name there, when known (file handle records).
    dir: u64,
    name: Vec<u8>,
    /// Path to reopen it by (descriptor records).
    path: String,
    pid: u64,
    tid: u64,
    /// A permission event's ID.
    perm: Option<u64>,
}

struct GroupState {
    inodes: BTreeMap<u64, Mark>,
    mount: Option<Mark>,
    filesystem: Option<Mark>,
    queue: VecDeque<Event>,
    /// Permission events: ID -> the listener's answer.
    answers: BTreeMap<u64, Option<u32>>,
    /// Descriptors the reader got for permission events -> their IDs.
    fd_ids: BTreeMap<i32, u64>,
    next_id: u64,
    closed: bool,
}

/// An fanotify group.
pub struct Group {
    flags: u64,
    f_flags: u64,
    /// Made without CAP_SYS_ADMIN (and its owner).
    unprivileged: bool,
    owner: u64,
    st: Mutex<GroupState>,
    wq: Arc<WaitQueue>,
    answered: Arc<WaitQueue>,
}

/// The group descriptor's object (its drop closes the group).
struct FanDev(Arc<Group>);

impl Drop for FanDev {
    fn drop(&mut self) {
        self.0.st.lock().closed = true;
        self.0.answered.wake_all();
    }
}

static GROUPS: Mutex<Vec<Weak<Group>>> = Mutex::new(Vec::new());
static ANY: AtomicBool = AtomicBool::new(false);

/// Whether any group exists (the hooks' fast path).
#[inline]
pub fn active() -> bool {
    ANY.load(Ordering::Relaxed)
}

fn groups() -> Vec<Arc<Group>> {
    let mut g = GROUPS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.iter().filter_map(|w| w.upgrade()).filter(|g| !g.st.lock().closed).collect()
}

fn capable() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 21) != 0 && !t.caps.in_userns).unwrap_or(false)
}

impl Group {
    fn fid_mode(&self) -> bool {
        self.flags & FID_BITS != 0
    }

    /// Events this group takes for object `ino` (in directory `dir`), out of `mask`.
    fn interest(st: &GroupState, ino: u64, dir: u64, mask: u64, is_dir: bool) -> u64 {
        let mut want = 0;
        let mut ignore = 0;
        let mut take = |m: &Mark, child: bool| {
            if child && m.mask & FAN_EVENT_ON_CHILD == 0 {
                return;
            }
            if is_dir && m.mask & FAN_ONDIR == 0 {
                ignore |= m.ignore;
                return;
            }
            want |= m.mask & mask;
            ignore |= m.ignore;
        };
        if let Some(m) = st.inodes.get(&ino) {
            take(m, false);
        }
        if dir != 0 && dir != ino {
            if let Some(m) = st.inodes.get(&dir) {
                take(m, true);
            }
        }
        if let Some(m) = &st.mount {
            take(m, false);
        }
        if let Some(m) = &st.filesystem {
            take(m, false);
        }
        want & !ignore & !(FAN_EVENT_ON_CHILD | FAN_ONDIR)
    }

    /// Queues an event (merging it into the last one when that is the same).
    fn push(&self, st: &mut GroupState, ev: Event) {
        if ev.perm.is_none() {
            if let Some(last) = st.queue.back_mut() {
                if last.perm.is_none() && last.ino == ev.ino && last.pid == ev.pid && last.dir == ev.dir && last.name == ev.name && last.mask & FAN_Q_OVERFLOW == 0 {
                    last.mask |= ev.mask;
                    return;
                }
            }
        }
        if st.queue.len() >= QUEUE_MAX && self.flags & FAN_UNLIMITED_QUEUE == 0 {
            if st.queue.back().map_or(true, |e| e.mask != FAN_Q_OVERFLOW) {
                st.queue.push_back(Event { mask: FAN_Q_OVERFLOW, ino: 0, dir: 0, name: Vec::new(), path: String::new(), pid: 0, tid: 0, perm: None });
            }
            return;
        }
        st.queue.push_back(ev);
    }
}

// ----------------------------------------------------------------------
// Hooks
// ----------------------------------------------------------------------

/// The directory a path is in, when fanotify needs it (`FAN_EVENT_ON_CHILD`, file handle
/// records); 0 otherwise.
pub fn parent_of_path(path: &str) -> u64 {
    if !active() {
        return 0;
    }
    let dir = match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => return 0,
    };
    super::vfs::resolve(0, dir.as_bytes(), true).unwrap_or(0)
}

fn last_name(path: &str) -> Vec<u8> {
    path.rsplit('/').next().unwrap_or("").as_bytes().to_vec()
}

/// A file event (`FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_*`, `FAN_OPEN*`) on `ino` (in
/// directory `dir`, reached by `path`) by the calling process.
pub fn file_event(ino: u64, dir: u64, path: &str, mask: u64, is_dir: bool) {
    if !active() {
        return;
    }
    let (tid, pid) = super::proc::current_ids();
    for g in groups() {
        let mut st = g.st.lock();
        let m = Group::interest(&st, ino, dir, mask, is_dir);
        if m == 0 {
            continue;
        }
        let ev = Event { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino, dir, name: last_name(path), path: String::from(path), pid, tid, perm: None };
        g.push(&mut st, ev);
        drop(st);
        g.wq.wake_all();
    }
}

/// An open (or an exec's open, `exec`) of `ino`: permission events first (`EPERM` if a
/// listener denies), then the notification.
pub fn on_open(ino: u64, dir: u64, path: &str, is_dir: bool, exec: bool) -> Result<(), i64> {
    if !active() {
        return Ok(());
    }
    let perm_mask = if exec { FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM } else { FAN_OPEN_PERM };
    let (tid, pid) = super::proc::current_ids();
    for g in groups() {
        let id = {
            let mut st = g.st.lock();
            let m = Group::interest(&st, ino, dir, perm_mask, is_dir);
            if m == 0 {
                continue;
            }
            let id = st.next_id;
            st.next_id += 1;
            st.answers.insert(id, None);
            let ev = Event { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino, dir, name: last_name(path), path: String::from(path), pid, tid, perm: Some(id) };
            g.push(&mut st, ev);
            id
        };
        g.wq.wake_all();
        // Wait for the listener's answer (a closed group, or SIGKILL, lets it through)
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(g.answered.clone()));
        let answer = loop {
            waits.register();
            {
                let mut st = g.st.lock();
                if st.closed {
                    break FAN_ALLOW;
                }
                if let Some(Some(a)) = st.answers.get(&id) {
                    let a = *a;
                    st.answers.remove(&id);
                    break a;
                }
            }
            if super::proc::sigkill_pending() {
                break FAN_ALLOW;
            }
            waits.wait(None);
        };
        if answer & 3 == FAN_DENY {
            return Err(EPERM);
        }
    }
    file_event(ino, dir, path, if exec { FAN_OPEN_EXEC | FAN_OPEN } else { FAN_OPEN }, is_dir);
    Ok(())
}

/// An event the file server reported (inotify bits, which match fanotify's): directory
/// entry events on directory `ino` with `name`, or events on `ino` itself.
pub fn fs_event(ino: u64, mask: u32, name: &[u8]) {
    if !active() {
        return;
    }
    let is_dir = mask & 0x4000_0000 != 0;
    let mask = mask as u64 & 0xfff;
    let wanted = if name.is_empty() { mask & (FAN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF) } else { mask & DIRENT_EVENTS };
    if wanted == 0 {
        return;
    }
    let (tid, pid) = super::proc::current_ids();
    for g in groups() {
        if !g.fid_mode() {
            continue;
        }
        let mut st = g.st.lock();
        // Entry events belong to the directory (as if on its child, without ON_CHILD)
        let m = if name.is_empty() {
            Group::interest(&st, ino, 0, wanted, is_dir)
        } else {
            let mut m = Group::interest(&st, ino, 0, wanted, false);
            if is_dir && st.inodes.get(&ino).map_or(true, |k| k.mask & FAN_ONDIR == 0) && st.mount.is_none() && st.filesystem.is_none() {
                m = 0; // a subdirectory's entry: only with FAN_ONDIR
            }
            m
        };
        if m == 0 {
            continue;
        }
        let (obj, dir) = if name.is_empty() { (ino, 0) } else { (ino, ino) };
        let ev = Event { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino: obj, dir, name: name.to_vec(), path: String::new(), pid, tid, perm: None };
        g.push(&mut st, ev);
        drop(st);
        g.wq.wake_all();
    }
}

// ----------------------------------------------------------------------
// Reading
// ----------------------------------------------------------------------

/// A file handle record (`struct fanotify_event_info_fid`) of type `kind` for `ino`, with
/// `name` for `FAN_EVENT_INFO_TYPE_DFID_NAME`.
fn fid_record(kind: u8, ino: u64, name: Option<&[u8]>) -> Vec<u8> {
    let mut r = alloc::vec![kind, 0, 0, 0];
    r.extend_from_slice(&POOL_FSID[0].to_le_bytes());
    r.extend_from_slice(&POOL_FSID[1].to_le_bytes());
    r.extend_from_slice(&8u32.to_le_bytes()); // handle_bytes
    r.extend_from_slice(&1i32.to_le_bytes()); // handle_type
    r.extend_from_slice(&ino.to_le_bytes());
    if let Some(n) = name {
        r.extend_from_slice(n);
        r.push(0);
    }
    while r.len() % 4 != 0 {
        r.push(0);
    }
    let len = r.len() as u16;
    r[2..4].copy_from_slice(&len.to_le_bytes());
    r
}

impl Group {
    /// The information records of `ev` (file handle groups).
    fn info(&self, ev: &Event) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.fid_mode() || ev.ino == 0 {
            return out;
        }
        let dirent = ev.mask & DIRENT_EVENTS != 0;
        let is_dir = ev.mask & FAN_ONDIR != 0;
        // The directory: an entry event's own; else the object's (a directory's self)
        let dir = if dirent { ev.ino } else if ev.dir != 0 { ev.dir } else if is_dir { ev.ino } else { 0 };
        if self.flags & FAN_REPORT_DIR_FID != 0 && dir != 0 {
            let named = self.flags & FAN_REPORT_NAME != 0 && !ev.name.is_empty() && !(is_dir && !dirent && ev.dir == 0);
            if named {
                out.extend(fid_record(2, dir, Some(&ev.name))); // DFID_NAME
            } else {
                out.extend(fid_record(3, dir, None)); // DFID
            }
        }
        if self.flags & FAN_REPORT_FID != 0 {
            // Entry events without DIR_FID report the directory, like Linux
            let obj = if dirent && self.flags & FAN_REPORT_DIR_FID == 0 { ev.ino } else if dirent { 0 } else { ev.ino };
            if obj != 0 {
                out.extend(fid_record(1, obj, None)); // FID
            }
        }
        out
    }
}

/// Opens the object of an event in the reader (a descriptor that makes no events).
fn event_fd(g: &Group, ev: &Event) -> Result<i32, i64> {
    let acc = g.f_flags as u32 & (3 | 0o2000 | 0o4000);
    let file = crate::fs::fd::OpenFile::new(ev.ino, acc, ev.path.clone());
    file.lock().nonotify = true;
    let cloexec = g.f_flags & 0o2000000 != 0;
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Vnode(file)) {
        Ok(fd) => {
            fds.set_cloexec(fd, cloexec);
            Ok(fd as i32)
        }
        Err(_) => Err(EMFILE),
    })
}

impl CharDevice for FanDev {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL // reads go through read_unlocked
    }
    fn read_unlocked(&self, buf: &mut [u8]) -> Option<i64> {
        let g = &self.0;
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(g.wq.clone()));
        loop {
            waits.register();
            if !g.st.lock().queue.is_empty() {
                break;
            }
            if g.flags & FAN_NONBLOCK != 0 {
                return Some(EAGAIN);
            }
            if super::proc::signal_pending() {
                return Some(EINTR);
            }
            waits.wait(None);
        }
        let me = super::proc::current_ids().1;
        let mut done = 0usize;
        loop {
            let ev = {
                let mut st = g.st.lock();
                let Some(ev) = st.queue.front() else { break };
                let need = 24 + g.info(ev).len();
                if done + need > buf.len() {
                    if done == 0 {
                        return Some(EINVAL);
                    }
                    break;
                }
                st.queue.pop_front().unwrap()
            };
            let info = g.info(&ev);
            let fd = if g.fid_mode() || ev.ino == 0 {
                FAN_NOFD
            } else {
                match event_fd(g, &ev) {
                    Ok(fd) => fd,
                    Err(e) => {
                        if done == 0 {
                            return Some(e);
                        }
                        break;
                    }
                }
            };
            if let Some(id) = ev.perm {
                g.st.lock().fd_ids.insert(fd, id);
            }
            let raw_pid = if g.flags & FAN_REPORT_TID != 0 { ev.tid } else { ev.pid };
            let pid = if ev.pid == 0 || (g.unprivileged && ev.pid != me) { 0 } else { super::ns::pid_to_caller(raw_pid) };
            let len = 24 + info.len();
            let mut rec = Vec::with_capacity(len);
            rec.extend_from_slice(&(len as u32).to_le_bytes());
            rec.push(3); // FANOTIFY_METADATA_VERSION
            rec.push(0);
            rec.extend_from_slice(&24u16.to_le_bytes());
            rec.extend_from_slice(&ev.mask.to_le_bytes());
            rec.extend_from_slice(&fd.to_le_bytes());
            rec.extend_from_slice(&(pid as i32).to_le_bytes());
            rec.extend_from_slice(&info);
            buf[done..done + len].copy_from_slice(&rec);
            done += len;
        }
        Some(done as i64)
    }
    fn write(&self, data: &[u8]) -> i64 {
        // struct fanotify_response { s32 fd; u32 response; }
        if data.len() < 8 {
            return EINVAL;
        }
        let fd = i32::from_le_bytes(data[0..4].try_into().unwrap());
        let response = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if !matches!(response & 3, FAN_ALLOW | FAN_DENY) || response & !(3 | 0x10 | 0x20) != 0 {
            return EINVAL;
        }
        let g = &self.0;
        let mut st = g.st.lock();
        let Some(id) = st.fd_ids.remove(&fd) else { return ENOENT };
        if let Some(a) = st.answers.get_mut(&id) {
            *a = Some(response);
        }
        drop(st);
        g.answered.wake_all();
        8
    }
    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        // FIONREAD: bytes queued
        if cmd != 0x541B {
            return -25;
        }
        let g = &self.0;
        let n: usize = g.st.lock().queue.iter().map(|e| 24 + g.info(e).len()).sum();
        copy_out(arg, &(n as i32).to_le_bytes()).map_or(EFAULT, |_| 0)
    }
    fn poll_events(&self) -> u32 {
        if self.0.st.lock().queue.is_empty() { 0 } else { 0x41 }
    }
    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.0.wq.clone()));
    }
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::from("anon_inode:[fanotify]")
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        self.0.flags & FAN_NONBLOCK != 0
    }
    fn as_fanotify(&self) -> Option<Arc<Group>> {
        Some(self.0.clone())
    }
}

// ----------------------------------------------------------------------
// System calls
// ----------------------------------------------------------------------

/// `fanotify_init(flags, event_f_flags)`.
fn init(flags: u64, f_flags: u64) -> i64 {
    if flags & !INIT_OK != 0 || flags & FAN_CLASS_MASK == FAN_CLASS_MASK {
        return EINVAL;
    }
    // O_ACCMODE, O_APPEND, O_NONBLOCK, O_DSYNC, O_NOATIME, O_CLOEXEC, O_SYNC, O_LARGEFILE
    if f_flags & !(3 | 0o2000 | 0o4000 | 0o10000 | 0o1000000 | 0o2000000 | 0o4010000 | 0o100000) != 0 || f_flags & 3 == 3 {
        return EINVAL;
    }
    if flags & FAN_REPORT_NAME != 0 && flags & FAN_REPORT_DIR_FID == 0 {
        return EINVAL;
    }
    if flags & FID_BITS != 0 && flags & FAN_CLASS_MASK != FAN_CLASS_NOTIF {
        return EINVAL;
    }
    let privileged = capable();
    if !privileged && (flags & ADMIN_ONLY != 0 || flags & FID_BITS == 0) {
        return EPERM;
    }
    let g = Arc::new(Group {
        flags,
        f_flags,
        unprivileged: !privileged,
        owner: super::proc::current_ids().1,
        st: Mutex::new(GroupState {
            inodes: BTreeMap::new(),
            mount: None,
            filesystem: None,
            queue: VecDeque::new(),
            answers: BTreeMap::new(),
            fd_ids: BTreeMap::new(),
            next_id: 1,
            closed: false,
        }),
        wq: WaitQueue::new_shared(),
        answered: WaitQueue::new_shared(),
    });
    GROUPS.lock().push(Arc::downgrade(&g));
    ANY.store(true, Ordering::Relaxed);
    let dev: Arc<dyn CharDevice> = Arc::new(FanDev(g));
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & FAN_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

fn group_of(fd: u64) -> Result<Arc<Group>, i64> {
    let d = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    match d {
        Some(crate::fs::FileDescriptor::Device(d)) => d.as_fanotify().ok_or(EINVAL),
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    }
}

/// `fanotify_mark(fd, flags, mask, dirfd, pathname)`.
fn mark(fd: u64, flags: u64, mask: u64, dirfd: u64, path: u64) -> i64 {
    let g = match group_of(fd) {
        Ok(g) => g,
        Err(e) => return e,
    };
    if flags & !MARK_OK != 0 {
        return EINVAL;
    }
    let op = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
    if !matches!(op, FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH) {
        return EINVAL;
    }
    let kind = flags & (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM);
    if kind == FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM {
        return EINVAL;
    }
    if kind != 0 && g.unprivileged {
        return EPERM;
    }
    if op == FAN_MARK_FLUSH {
        let mut st = g.st.lock();
        match kind {
            FAN_MARK_MOUNT => st.mount = None,
            FAN_MARK_FILESYSTEM => st.filesystem = None,
            _ => st.inodes.clear(),
        }
        return 0;
    }
    if mask & !EVENTS_OK != 0 || mask == 0 && op == FAN_MARK_ADD {
        return EINVAL;
    }
    if mask & PERM_EVENTS != 0 && g.flags & FAN_CLASS_MASK == FAN_CLASS_NOTIF {
        return EINVAL;
    }
    if mask & FID_EVENTS != 0 && !g.fid_mode() {
        return EINVAL;
    }
    if mask & DIRENT_EVENTS != 0 && kind == FAN_MARK_MOUNT {
        return EINVAL;
    }
    // The object
    let p = if path == 0 { Vec::new() } else {
        match super::vfs::user_cstr(path) {
            Ok(p) => p,
            Err(e) => return e,
        }
    };
    let (ino, is_dir) = {
        let (base, _) = match super::vfs::base_dir(dirfd as i32 as i64, if p.is_empty() { b"x" } else { &p }) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let ino = if p.is_empty() {
            base
        } else {
            match super::vfs::resolve(base, &p, flags & FAN_MARK_DONT_FOLLOW == 0) {
                Ok(i) => i,
                Err(e) => return e,
            }
        };
        let attr = match crate::fs::ZfsClient::getattr(ino) {
            Ok(a) => a,
            Err(e) => return e,
        };
        if g.unprivileged && !super::vfs::may_access(&attr, super::vfs::creds().euid, super::vfs::creds().egid, 4) {
            return -13; // EACCES
        }
        (ino, attr.is_dir())
    };
    if flags & FAN_MARK_ONLYDIR != 0 && !is_dir {
        return ENOTDIR;
    }
    let ignoring = flags & (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE) != 0;
    let mut st = g.st.lock();
    let slot: &mut Option<Mark> = match kind {
        FAN_MARK_MOUNT => &mut st.mount,
        FAN_MARK_FILESYSTEM => &mut st.filesystem,
        _ => {
            let entry = st.inodes.get(&ino).copied();
            let mut m = entry;
            let r = apply(&mut m, op, mask, ignoring);
            match m {
                Some(m) => {
                    st.inodes.insert(ino, m);
                }
                None => {
                    st.inodes.remove(&ino);
                }
            }
            return r;
        }
    };
    apply(slot, op, mask, ignoring)
}

/// Adds `mask` to or removes it from a mark (to its ignore mask with `ignoring`); a mark
/// left with nothing goes.
fn apply(m: &mut Option<Mark>, op: u64, mask: u64, ignoring: bool) -> i64 {
    if op == FAN_MARK_REMOVE {
        let Some(k) = m.as_mut() else { return ENOENT };
        if ignoring {
            k.ignore &= !mask;
        } else {
            k.mask &= !mask;
        }
        if k.mask & !(FAN_EVENT_ON_CHILD | FAN_ONDIR) == 0 && k.ignore == 0 {
            *m = None;
        }
        return 0;
    }
    let k = m.get_or_insert_with(Mark::default);
    if ignoring {
        k.ignore |= mask & !(FAN_EVENT_ON_CHILD | FAN_ONDIR);
        k.mask |= mask & FAN_ONDIR;
    } else {
        k.mask |= mask;
    }
    0
}

/// System calls 300 (`fanotify_init`) and 301 (`fanotify_mark`).
pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
    let _ = (FAN_MARK_EVICTABLE, FAN_MARK_IGNORED_SURV_MODIFY);
    match num {
        300 => init(a[0], a[1]),
        _ => mark(a[0], a[1], a[2], a[3], a[4]),
    }
}

// ----------------------------------------------------------------------
// name_to_handle_at / open_by_handle_at (the handles fanotify reports)
// ----------------------------------------------------------------------

/// `name_to_handle_at(dirfd, path, handle, mount_id, flags)`: the 8-byte inode handle.
pub fn name_to_handle_at(dirfd: u64, path: u64, handle: u64, mount_id: u64, flags: u64) -> i64 {
    const AT_SYMLINK_FOLLOW: u64 = 0x400;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_HANDLE_FID: u64 = 0x200;
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID) != 0 {
        return EINVAL;
    }
    let p = match super::vfs::user_cstr(path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if p.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return ENOENT;
    }
    let (base, _) = match super::vfs::base_dir(dirfd as i32 as i64, if p.is_empty() { b"x" } else { &p }) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let ino = if p.is_empty() {
        base
    } else {
        match super::vfs::resolve(base, &p, flags & AT_SYMLINK_FOLLOW != 0) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    let Ok(hdr) = copy_in(handle, 8) else { return EFAULT };
    let room = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if room > 128 {
        return EINVAL; // MAX_HANDLE_SZ
    }
    if room < 8 {
        let _ = copy_out(handle, &8u32.to_le_bytes());
        return -75; // EOVERFLOW
    }
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&8u32.to_le_bytes());
    out.extend_from_slice(&1i32.to_le_bytes());
    out.extend_from_slice(&ino.to_le_bytes());
    if copy_out(handle, &out).is_err() {
        return EFAULT;
    }
    // The mount ID /proc/self/fdinfo reports
    if copy_out(mount_id, &2069i32.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

/// `open_by_handle_at(mount_fd, handle, flags)` (`CAP_DAC_READ_SEARCH`).
pub fn open_by_handle_at(_mount_fd: u64, handle: u64, flags: u64) -> i64 {
    if !crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 2) != 0 && !t.caps.in_userns).unwrap_or(false) {
        return EPERM;
    }
    let Ok(raw) = copy_in(handle, 16) else { return EFAULT };
    let bytes = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    let kind = i32::from_le_bytes(raw[4..8].try_into().unwrap());
    if bytes != 8 || kind != 1 {
        return -116; // ESTALE
    }
    let ino = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if crate::fs::ZfsClient::getattr(ino).is_err() {
        return -116;
    }
    let file = crate::fs::fd::OpenFile::new(ino, flags as u32 & (3 | 0o2000 | 0o4000 | 0o200000 | 0o10000000), String::new());
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Vnode(file)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags & 0o2000000 != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

#[allow(dead_code)]
fn owner_of(g: &Group) -> u64 {
    g.owner
}
