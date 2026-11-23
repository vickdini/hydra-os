//! # inotify and fanotify: the rules (wave 9, Group 6b-1)
//!
//! Plain `core`/`alloc` logic, no system calls (`tests/host-w9-n` runs it): an inotify
//! instance ([`Inotify`]: watches by inode, the event queue, `read`'s records), a fanotify
//! group ([`Fanotify`]: marks on inodes, the mount and the file system, which events a group
//! wants, its queue and records, permission ids), the record the kernel posts for its own
//! events ([`Assembler`], the other side of the kernel's `lx/notifyfwd.rs::encode`) and the
//! kept-state records of groups, watches and marks ([`KRec`]). The behaviour is the
//! kernel's `src/compat/linux/inotify.rs` and `fanotify.rs`, which stay as the switch back.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EEXIST: i64 = -17;
pub const ENOTDIR: i64 = -20;
pub const EINVAL: i64 = -22;

// ----------------------------------------------------------------------
// inotify
// ----------------------------------------------------------------------

pub const IN_ACCESS: u32 = 0x1;
pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_Q_OVERFLOW: u32 = 0x4000;
pub const IN_IGNORED: u32 = 0x8000;
pub const IN_ISDIR: u32 = 0x4000_0000;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;
pub const IN_ALL_EVENTS: u32 = 0xFFF;
pub const IN_NONBLOCK: u64 = 0o4000;
pub const IN_CLOEXEC: u64 = 0o2000000;
/// Queued events per instance before `IN_Q_OVERFLOW` (Linux's default
/// `max_queued_events`).
pub const MAX_QUEUED: usize = 16384;

/// One watch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Watch {
    pub ino: u64,
    pub mask: u32,
}

/// An inotify instance.
#[derive(Debug, Default)]
pub struct Inotify {
    pub watches: BTreeMap<i32, Watch>,
    pub by_ino: BTreeMap<u64, i32>,
    pub queue: VecDeque<Vec<u8>>,
    pub bytes: usize,
    pub next_wd: i32,
    /// The user that made it (the per-user limits).
    pub uid: u32,
}

/// One `struct inotify_event` (and its name, padded to 16 bytes with a NUL).
pub fn in_record(wd: i32, mask: u32, cookie: u32, name: &[u8]) -> Vec<u8> {
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

/// `inotify_init1`'s flags check.
pub fn in_init_ok(flags: u64) -> bool {
    flags & !(IN_NONBLOCK | IN_CLOEXEC) == 0
}

/// `inotify_add_watch`'s mask check (before the walk).
pub fn in_mask_ok(mask: u32) -> bool {
    mask & IN_ALL_EVENTS != 0 && !(mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0)
}

impl Inotify {
    /// A new instance (watch descriptors from 1).
    pub fn new() -> Self {
        Self { next_wd: 1, ..Self::default() }
    }

    /// Queues one record (an identical unread last record is coalesced; a full queue ends
    /// with one `IN_Q_OVERFLOW`). Whether it was queued.
    pub fn push(&mut self, rec: Vec<u8>) -> bool {
        if self.queue.back() == Some(&rec) {
            return false;
        }
        if self.queue.len() >= MAX_QUEUED {
            let overflow = in_record(-1, IN_Q_OVERFLOW, 0, b"");
            if self.queue.back() != Some(&overflow) {
                self.bytes += overflow.len();
                self.queue.push_back(overflow);
                return true;
            }
            return false;
        }
        self.bytes += rec.len();
        self.queue.push_back(rec);
        true
    }

    /// The queued events were lost (a restart): one `IN_Q_OVERFLOW`.
    pub fn overflow(&mut self) {
        let overflow = in_record(-1, IN_Q_OVERFLOW, 0, b"");
        if self.queue.back() != Some(&overflow) {
            self.bytes += overflow.len();
            self.queue.push_back(overflow);
        }
    }

    /// `inotify_add_watch` on inode `ino` (a directory or not) with `mask`: the watch
    /// descriptor and whether the watch is new (else its mask changed).
    pub fn add_watch(&mut self, ino: u64, is_dir: bool, mask: u32) -> Result<(i32, bool), i64> {
        if !in_mask_ok(mask) {
            return Err(EINVAL);
        }
        if mask & IN_ONLYDIR != 0 && !is_dir {
            return Err(ENOTDIR);
        }
        let keep = mask & (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK);
        if let Some(&wd) = self.by_ino.get(&ino) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(EEXIST);
            }
            let w = self.watches.get_mut(&wd).ok_or(EINVAL)?;
            w.mask = if mask & IN_MASK_ADD != 0 { w.mask | keep } else { keep };
            return Ok((wd, false));
        }
        let wd = self.next_wd;
        self.next_wd = self.next_wd.checked_add(1).unwrap_or(1);
        self.watches.insert(wd, Watch { ino, mask: keep });
        self.by_ino.insert(ino, wd);
        Ok((wd, true))
    }

    /// A watch taken back from kept state.
    pub fn restore_watch(&mut self, wd: i32, w: Watch) {
        if wd <= 0 || self.watches.contains_key(&wd) || self.by_ino.contains_key(&w.ino) {
            return;
        }
        self.watches.insert(wd, w);
        self.by_ino.insert(w.ino, wd);
        if wd >= self.next_wd {
            self.next_wd = wd.checked_add(1).unwrap_or(1);
        }
    }

    /// Removes watch `wd` and queues `IN_IGNORED` for it.
    pub fn rm_watch(&mut self, wd: i32) -> Option<Watch> {
        let w = self.watches.remove(&wd)?;
        self.by_ino.remove(&w.ino);
        self.push(in_record(wd, IN_IGNORED, 0, b""));
        Some(w)
    }

    /// An event on inode `ino`: queued if a watch wants it; the watch goes with
    /// `IN_DELETE_SELF` or a one-shot event. `(queued, the watch descriptor removed)`.
    pub fn event(&mut self, ino: u64, mask: u32, cookie: u32, name: &[u8]) -> (bool, Option<i32>) {
        let Some(&wd) = self.by_ino.get(&ino) else { return (false, None) };
        let wmask = self.watches.get(&wd).map_or(0, |w| w.mask);
        let wanted = wmask & mask & IN_ALL_EVENTS != 0;
        let mut queued = false;
        if wanted {
            queued = self.push(in_record(wd, mask, cookie, name));
        }
        if mask & IN_DELETE_SELF != 0 || (wanted && wmask & IN_ONESHOT != 0) {
            self.rm_watch(wd);
            return (true, Some(wd));
        }
        (queued, None)
    }

    /// Takes as many whole records as fit in `cap` bytes: `Err(EINVAL)` if the first does
    /// not fit, empty if nothing is queued.
    pub fn read(&mut self, cap: usize) -> Result<Vec<u8>, i64> {
        let Some(first) = self.queue.front() else { return Ok(Vec::new()) };
        if first.len() > cap {
            return Err(EINVAL);
        }
        let mut out = Vec::new();
        while let Some(rec) = self.queue.front() {
            if out.len() + rec.len() > cap {
                break;
            }
            let rec = self.queue.pop_front().unwrap_or_default();
            self.bytes -= rec.len();
            out.extend_from_slice(&rec);
        }
        Ok(out)
    }
}

// ----------------------------------------------------------------------
// fanotify
// ----------------------------------------------------------------------

pub const FAN_CLOEXEC: u64 = 1;
pub const FAN_NONBLOCK: u64 = 2;
pub const FAN_CLASS_MASK: u64 = 0xc;
pub const FAN_CLASS_NOTIF: u64 = 0;
pub const FAN_UNLIMITED_QUEUE: u64 = 0x10;
pub const FAN_UNLIMITED_MARKS: u64 = 0x20;
pub const FAN_ENABLE_AUDIT: u64 = 0x40;
pub const FAN_REPORT_TID: u64 = 0x100;
pub const FAN_REPORT_FID: u64 = 0x200;
pub const FAN_REPORT_DIR_FID: u64 = 0x400;
pub const FAN_REPORT_NAME: u64 = 0x800;
pub const FID_BITS: u64 = FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
pub const INIT_OK: u64 = FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_MASK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_TID | FID_BITS;
pub const ADMIN_ONLY: u64 = FAN_CLASS_MASK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS | FAN_ENABLE_AUDIT | FAN_REPORT_TID;

pub const FAN_MARK_ADD: u64 = 1;
pub const FAN_MARK_REMOVE: u64 = 2;
pub const FAN_MARK_DONT_FOLLOW: u64 = 4;
pub const FAN_MARK_ONLYDIR: u64 = 8;
pub const FAN_MARK_MOUNT: u64 = 0x10;
pub const FAN_MARK_IGNORED_MASK: u64 = 0x20;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u64 = 0x40;
pub const FAN_MARK_FLUSH: u64 = 0x80;
pub const FAN_MARK_FILESYSTEM: u64 = 0x100;
pub const FAN_MARK_EVICTABLE: u64 = 0x200;
pub const FAN_MARK_IGNORE: u64 = 0x400;
pub const MARK_OK: u64 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_DONT_FOLLOW | FAN_MARK_ONLYDIR | FAN_MARK_MOUNT | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY | FAN_MARK_FLUSH | FAN_MARK_FILESYSTEM | FAN_MARK_EVICTABLE | FAN_MARK_IGNORE;

pub const FAN_ACCESS: u64 = 0x1;
pub const FAN_MODIFY: u64 = 0x2;
pub const FAN_ATTRIB: u64 = 0x4;
pub const FAN_CLOSE_WRITE: u64 = 0x8;
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
pub const FAN_OPEN: u64 = 0x20;
pub const FAN_MOVED_FROM: u64 = 0x40;
pub const FAN_MOVED_TO: u64 = 0x80;
pub const FAN_CREATE: u64 = 0x100;
pub const FAN_DELETE: u64 = 0x200;
pub const FAN_DELETE_SELF: u64 = 0x400;
pub const FAN_MOVE_SELF: u64 = 0x800;
pub const FAN_OPEN_EXEC: u64 = 0x1000;
pub const FAN_Q_OVERFLOW: u64 = 0x4000;
pub const FAN_OPEN_PERM: u64 = 0x1_0000;
pub const FAN_ACCESS_PERM: u64 = 0x2_0000;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x4_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;
pub const FAN_RENAME: u64 = 0x1000_0000;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const PERM_EVENTS: u64 = FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM;
pub const FD_EVENTS: u64 = FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_OPEN | FAN_OPEN_EXEC;
pub const DIRENT_EVENTS: u64 = FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CREATE | FAN_DELETE | FAN_RENAME;
pub const FID_EVENTS: u64 = DIRENT_EVENTS | FAN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF;
pub const EVENTS_OK: u64 = FD_EVENTS | FID_EVENTS | PERM_EVENTS | FAN_EVENT_ON_CHILD | FAN_ONDIR;

pub const FAN_ALLOW: u32 = 1;
pub const FAN_DENY: u32 = 2;
pub const FAN_NOFD: i32 = -1;
/// Queued events per group without `FAN_UNLIMITED_QUEUE`.
pub const QUEUE_MAX: usize = 16384;
/// The pool's `f_fsid` (the kernel's `fanotify::POOL_FSID`, `statfs`).
pub const POOL_FSID: [i32; 2] = [0x4859_4452, 0x5a46_5301];

/// What a mark wants and ignores.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Mark {
    pub mask: u64,
    pub ignore: u64,
}

/// One queued fanotify event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FanEvent {
    pub mask: u64,
    pub ino: u64,
    pub dir: u64,
    pub name: Vec<u8>,
    /// The file's path (a descriptor event's descriptor shows it).
    pub path: Vec<u8>,
    pub pid: u32,
    pub tid: u32,
    /// A permission event's id (the question it answers).
    pub perm: Option<u64>,
}

/// Which marks a mark call names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkKind {
    Inode,
    Mount,
    Filesystem,
}

/// A checked `fanotify_mark` call: what to do and to which kind of mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkOp {
    /// `FAN_MARK_ADD`, `FAN_MARK_REMOVE` or `FAN_MARK_FLUSH`.
    pub op: u64,
    pub kind: MarkKind,
    pub ignoring: bool,
}

/// A fanotify group.
#[derive(Debug, Default)]
pub struct Fanotify {
    pub flags: u64,
    pub f_flags: u64,
    pub unprivileged: bool,
    pub owner: u32,
    /// The user that made it (the per-user limits).
    pub uid: u32,
    pub inodes: BTreeMap<u64, Mark>,
    pub mount: Option<Mark>,
    pub filesystem: Option<Mark>,
    pub queue: VecDeque<FanEvent>,
    /// Reported permission events: descriptor (in the reader) -> question ids (oldest first:
    /// a descriptor number closed unanswered and reused keeps its older question).
    pub fd_ids: BTreeMap<i32, Vec<u64>>,
}

/// `fanotify_init(flags, event_f_flags)`'s checks (`privileged`: CAP_SYS_ADMIN in the
/// initial user namespace).
pub fn fan_init_ok(flags: u64, f_flags: u64, privileged: bool) -> Result<(), i64> {
    if flags & !INIT_OK != 0 || flags & FAN_CLASS_MASK == FAN_CLASS_MASK {
        return Err(EINVAL);
    }
    // O_ACCMODE, O_APPEND, O_NONBLOCK, O_DSYNC, O_NOATIME, O_CLOEXEC, O_SYNC, O_LARGEFILE
    if f_flags & !(3 | 0o2000 | 0o4000 | 0o10000 | 0o1000000 | 0o2000000 | 0o4010000 | 0o100000) != 0 || f_flags & 3 == 3 {
        return Err(EINVAL);
    }
    if flags & FAN_REPORT_NAME != 0 && flags & FAN_REPORT_DIR_FID == 0 {
        return Err(EINVAL);
    }
    if flags & FID_BITS != 0 && flags & FAN_CLASS_MASK != FAN_CLASS_NOTIF {
        return Err(EINVAL);
    }
    if !privileged && (flags & ADMIN_ONLY != 0 || flags & FID_BITS == 0) {
        return Err(EPERM);
    }
    Ok(())
}

/// A mark set by `op`: adds or removes `mask` (or its ignore part). `ENOENT`: removing
/// from no mark.
pub fn apply(m: &mut Option<Mark>, op: u64, mask: u64, ignoring: bool) -> Result<(), i64> {
    if op == FAN_MARK_REMOVE {
        let Some(k) = m.as_mut() else { return Err(ENOENT) };
        if ignoring {
            k.ignore &= !mask;
        } else {
            k.mask &= !mask;
        }
        if k.mask & !(FAN_EVENT_ON_CHILD | FAN_ONDIR) == 0 && k.ignore == 0 {
            *m = None;
        }
        return Ok(());
    }
    let k = m.get_or_insert_with(Mark::default);
    if ignoring {
        k.ignore |= mask & !(FAN_EVENT_ON_CHILD | FAN_ONDIR);
        k.mask |= mask & FAN_ONDIR;
    } else {
        k.mask |= mask;
    }
    Ok(())
}

/// One FID information record (`struct fanotify_event_info_fid` with an 8-byte handle:
/// the inode).
pub fn fid_record(kind: u8, ino: u64, name: Option<&[u8]>) -> Vec<u8> {
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

impl Fanotify {
    /// A group made by `fanotify_init` (checked).
    pub fn new(flags: u64, f_flags: u64, unprivileged: bool, owner: u32, uid: u32) -> Self {
        Self { flags, f_flags, unprivileged, owner, uid, ..Self::default() }
    }

    /// The group reports file handles (no descriptors).
    pub fn fid_mode(&self) -> bool {
        self.flags & FID_BITS != 0
    }

    /// The group may get permission events (its marks may hold them).
    pub fn has_perm(&self) -> bool {
        let p = |m: &Mark| m.mask & PERM_EVENTS != 0;
        self.inodes.values().any(p) || self.mount.as_ref().is_some_and(p) || self.filesystem.as_ref().is_some_and(p)
    }

    /// A mount or file-system mark: every inode may be of interest.
    pub fn wants_all(&self) -> bool {
        self.mount.is_some() || self.filesystem.is_some()
    }

    /// The bits of `mask` this group wants for an event on `ino` in directory `dir`.
    pub fn interest(&self, ino: u64, dir: u64, mask: u64, is_dir: bool) -> u64 {
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
        if let Some(m) = self.inodes.get(&ino) {
            take(m, false);
        }
        if dir != 0 && dir != ino {
            if let Some(m) = self.inodes.get(&dir) {
                take(m, true);
            }
        }
        if let Some(m) = &self.mount {
            take(m, false);
        }
        if let Some(m) = &self.filesystem {
            take(m, false);
        }
        want & !ignore & !(FAN_EVENT_ON_CHILD | FAN_ONDIR)
    }

    /// Queues `ev` (merged into an equal last event; a full queue ends with one
    /// `FAN_Q_OVERFLOW`). Whether something was added.
    pub fn push(&mut self, ev: FanEvent) -> bool {
        if ev.perm.is_none() {
            if let Some(last) = self.queue.back_mut() {
                if last.perm.is_none() && last.ino == ev.ino && last.pid == ev.pid && last.dir == ev.dir && last.name == ev.name && last.mask & FAN_Q_OVERFLOW == 0 {
                    let before = last.mask;
                    last.mask |= ev.mask;
                    return last.mask != before;
                }
            }
        }
        if self.queue.len() >= QUEUE_MAX && self.flags & FAN_UNLIMITED_QUEUE == 0 {
            if self.queue.back().map_or(true, |e| e.mask != FAN_Q_OVERFLOW) {
                self.queue.push_back(FanEvent { mask: FAN_Q_OVERFLOW, ino: 0, dir: 0, name: Vec::new(), path: Vec::new(), pid: 0, tid: 0, perm: None });
                return true;
            }
            return false;
        }
        self.queue.push_back(ev);
        true
    }

    /// The queued events were lost (a restart): one `FAN_Q_OVERFLOW`.
    pub fn overflow(&mut self) {
        if self.queue.back().map_or(true, |e| e.mask != FAN_Q_OVERFLOW) {
            self.queue.push_back(FanEvent { mask: FAN_Q_OVERFLOW, ino: 0, dir: 0, name: Vec::new(), path: Vec::new(), pid: 0, tid: 0, perm: None });
        }
    }

    /// An event on an open file (`FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_*`, `FAN_OPEN`;
    /// `FAN_ONDIR` in `mask` for a directory). Whether it was queued.
    pub fn file_event(&mut self, ino: u64, dir: u64, path: &[u8], mask: u64, pid: u32, tid: u32) -> bool {
        let is_dir = mask & FAN_ONDIR != 0;
        let m = self.interest(ino, dir, mask & !FAN_ONDIR, is_dir);
        if m == 0 {
            return false;
        }
        let name = path.rsplit(|&b| b == b'/').next().unwrap_or(b"").to_vec();
        self.push(FanEvent { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino, dir, name, path: path.to_vec(), pid, tid, perm: None })
    }

    /// A permission event (question `id`); whether the group asks (it then waits for the
    /// listener's answer).
    pub fn perm_event(&mut self, ino: u64, dir: u64, path: &[u8], mask: u64, pid: u32, tid: u32, id: u64) -> bool {
        let is_dir = mask & FAN_ONDIR != 0;
        let m = self.interest(ino, dir, mask & PERM_EVENTS, is_dir);
        if m == 0 {
            return false;
        }
        // A full queue: the overflow event instead, and the group does not ask (Linux:
        // an event that is not queued is not waited for, so the open is allowed)
        if self.queue.len() >= QUEUE_MAX && self.flags & FAN_UNLIMITED_QUEUE == 0 {
            self.overflow();
            return false;
        }
        let name = path.rsplit(|&b| b == b'/').next().unwrap_or(b"").to_vec();
        self.push(FanEvent { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino, dir, name, path: path.to_vec(), pid, tid, perm: Some(id) })
    }

    /// A zfs event (inotify bits: `name` = an entry of directory `ino`, else the object's
    /// own event; bit 30 = a directory). Only groups that report file handles get these.
    pub fn fs_event(&mut self, ino: u64, mask: u32, name: &[u8], pid: u32, tid: u32) -> bool {
        if !self.fid_mode() {
            return false;
        }
        let is_dir = mask & IN_ISDIR != 0;
        let mask = mask as u64 & 0xfff;
        let wanted = if name.is_empty() { mask & (FAN_ATTRIB | FAN_DELETE_SELF | FAN_MOVE_SELF) } else { mask & DIRENT_EVENTS };
        if wanted == 0 {
            return false;
        }
        // Entry events belong to the directory (as if on its child, without ON_CHILD)
        let m = if name.is_empty() {
            self.interest(ino, 0, wanted, is_dir)
        } else {
            let mut m = self.interest(ino, 0, wanted, false);
            if is_dir && self.inodes.get(&ino).map_or(true, |k| k.mask & FAN_ONDIR == 0) && self.mount.is_none() && self.filesystem.is_none() {
                m = 0; // a subdirectory's entry: only with FAN_ONDIR
            }
            m
        };
        if m == 0 {
            return false;
        }
        let dir = if name.is_empty() { 0 } else { ino };
        self.push(FanEvent { mask: m | if is_dir { FAN_ONDIR } else { 0 }, ino, dir, name: name.to_vec(), path: Vec::new(), pid, tid, perm: None })
    }

    /// The information records of `ev` (file-handle groups).
    pub fn info(&self, ev: &FanEvent) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.fid_mode() || ev.ino == 0 {
            return out;
        }
        let dirent = ev.mask & DIRENT_EVENTS != 0;
        let is_dir = ev.mask & FAN_ONDIR != 0;
        // The directory: an entry event's own; else the object's (a directory's self)
        let dir = if dirent {
            ev.ino
        } else if ev.dir != 0 {
            ev.dir
        } else if is_dir {
            ev.ino
        } else {
            0
        };
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
            let obj = if dirent && self.flags & FAN_REPORT_DIR_FID == 0 {
                ev.ino
            } else if dirent {
                0
            } else {
                ev.ino
            };
            if obj != 0 {
                out.extend(fid_record(1, obj, None)); // FID
            }
        }
        out
    }

    /// Bytes of `ev`'s record.
    pub fn record_len(&self, ev: &FanEvent) -> usize {
        24 + self.info(ev).len()
    }

    /// Bytes queued (`FIONREAD`).
    pub fn queued_bytes(&self) -> usize {
        self.queue.iter().map(|e| self.record_len(e)).sum()
    }

    /// The pid a reader `me` (in the initial PID namespace when `plain_ns`) sees for `ev`.
    pub fn shown_pid(&self, ev: &FanEvent, me: u32, plain_ns: bool) -> u32 {
        let raw = if self.flags & FAN_REPORT_TID != 0 { ev.tid } else { ev.pid };
        if ev.pid == 0 || (self.unprivileged && ev.pid != me) || !plain_ns {
            0
        } else {
            raw
        }
    }

    /// The record of `ev` (`struct fanotify_event_metadata` and its information records).
    pub fn record(&self, ev: &FanEvent, fd: i32, pid: u32) -> Vec<u8> {
        let info = self.info(ev);
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
        rec
    }

    /// Takes the events whose records fit in `cap` bytes (`Err(EINVAL)`: not even the
    /// first).
    pub fn take(&mut self, cap: usize) -> Result<Vec<FanEvent>, i64> {
        let mut out = Vec::new();
        let mut done = 0;
        while let Some(ev) = self.queue.front() {
            let need = self.record_len(ev);
            if done + need > cap {
                if out.is_empty() {
                    return Err(EINVAL);
                }
                break;
            }
            done += need;
            if let Some(ev) = self.queue.pop_front() {
                out.push(ev);
            }
        }
        Ok(out)
    }

    /// Checks a `fanotify_mark(flags, mask)` before the walk.
    pub fn mark_check(&self, flags: u64, mask: u64) -> Result<MarkOp, i64> {
        if flags & !MARK_OK != 0 {
            return Err(EINVAL);
        }
        let op = flags & (FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH);
        if !matches!(op, FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH) {
            return Err(EINVAL);
        }
        let kind = match flags & (FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM) {
            0 => MarkKind::Inode,
            FAN_MARK_MOUNT => MarkKind::Mount,
            FAN_MARK_FILESYSTEM => MarkKind::Filesystem,
            _ => return Err(EINVAL),
        };
        if kind != MarkKind::Inode && self.unprivileged {
            return Err(EPERM);
        }
        let ignoring = flags & (FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORE) != 0;
        if op == FAN_MARK_FLUSH {
            return Ok(MarkOp { op, kind, ignoring });
        }
        if mask & !EVENTS_OK != 0 || mask == 0 && op == FAN_MARK_ADD {
            return Err(EINVAL);
        }
        if mask & PERM_EVENTS != 0 && self.flags & FAN_CLASS_MASK == FAN_CLASS_NOTIF {
            return Err(EINVAL);
        }
        if mask & FID_EVENTS != 0 && !self.fid_mode() {
            return Err(EINVAL);
        }
        if mask & DIRENT_EVENTS != 0 && kind == MarkKind::Mount {
            return Err(EINVAL);
        }
        Ok(MarkOp { op, kind, ignoring })
    }

    /// `FAN_MARK_FLUSH` of marks of `kind`.
    pub fn flush(&mut self, kind: MarkKind) {
        match kind {
            MarkKind::Mount => self.mount = None,
            MarkKind::Filesystem => self.filesystem = None,
            MarkKind::Inode => self.inodes.clear(),
        }
    }

    /// Applies a checked mark call on inode `ino` (ignored for mount and file-system
    /// marks); the mark after it (`None`: gone).
    pub fn mark(&mut self, m: MarkOp, ino: u64, mask: u64) -> Result<Option<Mark>, i64> {
        let slot = match m.kind {
            MarkKind::Mount => &mut self.mount,
            MarkKind::Filesystem => &mut self.filesystem,
            MarkKind::Inode => {
                let mut cur = self.inodes.get(&ino).copied();
                apply(&mut cur, m.op, mask, m.ignoring)?;
                match cur {
                    Some(k) => self.inodes.insert(ino, k),
                    None => self.inodes.remove(&ino),
                };
                return Ok(cur);
            }
        };
        apply(slot, m.op, mask, m.ignoring)?;
        Ok(*slot)
    }

    /// A listener's answer (`struct fanotify_response`): the question id it answers and
    /// whether it denies.
    pub fn response(&mut self, data: &[u8]) -> Result<(u64, bool), i64> {
        if data.len() < 8 {
            return Err(EINVAL);
        }
        let fd = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let response = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if !matches!(response & 3, FAN_ALLOW | FAN_DENY) || response & !(3 | 0x10 | 0x20) != 0 {
            return Err(EINVAL);
        }
        let ids = self.fd_ids.get_mut(&fd).ok_or(ENOENT)?;
        let id = ids.remove(0);
        if ids.is_empty() {
            self.fd_ids.remove(&fd);
        }
        Ok((id, response & 3 == FAN_DENY))
    }

    /// The permission questions this group still has to answer (queued or reported).
    pub fn open_questions(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self.queue.iter().filter_map(|e| e.perm).collect();
        v.extend(self.fd_ids.values().flatten().copied());
        v
    }
}

// ----------------------------------------------------------------------
// The kernel's event records (`lx/notifyfwd.rs::encode`)
// ----------------------------------------------------------------------

/// `LX_FSEV_*` (the protocol's): a zfs event, an open file's event, a permission event.
pub const FSEV_ZFS: u64 = 0;
pub const FSEV_FILE: u64 = 1;
pub const FSEV_PERM: u64 = 2;

/// One event the kernel posted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KEvent {
    pub kind: u64,
    pub ino: u64,
    pub mask: u32,
    pub cookie: u32,
    pub dir: u64,
    pub pid: u32,
    pub tid: u32,
    pub id: u64,
    pub tail: Vec<u8>,
}

/// Puts the kernel's records back together from their note entries (a header, then data
/// entries of 24 bytes). A record cut short (a header before the data was complete, data
/// without a header) is dropped and counted.
#[derive(Debug, Default)]
pub struct Assembler {
    cur: Option<(KEvent, usize)>,
    payload: Vec<u8>,
    pub broken: u64,
}

impl Assembler {
    /// A header entry (`LX_NOTE_FSEVENT`).
    pub fn head(&mut self, a: u64, b: u64, c: u64) -> Option<KEvent> {
        if self.cur.take().is_some() {
            self.broken += 1;
        }
        self.payload.clear();
        let need = (c >> 8) as usize;
        if !(24..=24 + 8192).contains(&need) {
            self.broken += 1;
            return None;
        }
        self.cur = Some((KEvent { kind: c & 0xFF, ino: a, mask: b as u32, cookie: (b >> 32) as u32, ..KEvent::default() }, need));
        None
    }

    /// A data entry (`LX_NOTE_FSDATA`): the event once its payload is complete.
    pub fn data(&mut self, a: u64, b: u64, c: u64) -> Option<KEvent> {
        let Some((_, need)) = self.cur.as_ref() else {
            self.broken += 1;
            return None;
        };
        let need = *need;
        for w in [a, b, c] {
            self.payload.extend_from_slice(&w.to_le_bytes());
        }
        if self.payload.len() < need {
            return None;
        }
        let (mut e, _) = self.cur.take()?;
        let p = &self.payload;
        e.dir = u64::from_le_bytes(p[0..8].try_into().ok()?);
        e.pid = u32::from_le_bytes(p[8..12].try_into().ok()?);
        e.tid = u32::from_le_bytes(p[12..16].try_into().ok()?);
        e.id = u64::from_le_bytes(p[16..24].try_into().ok()?);
        e.tail = p[24..need].to_vec();
        self.payload.clear();
        Some(e)
    }
}

// ----------------------------------------------------------------------
// Kept state: one record per group, watch and mark
// ----------------------------------------------------------------------

/// Bytes of one kept record.
pub const KREC_SIZE: usize = 40;

/// One kept record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KRec {
    /// An inotify instance's object slot.
    InGroup { slot: u32, uid: u32 },
    /// A fanotify group: its slot, init flags, event flags, privilege and owner.
    FanGroup { slot: u32, flags: u64, f_flags: u64, unprivileged: bool, owner: u32, uid: u32 },
    /// An inotify watch.
    InWatch { slot: u32, wd: i32, ino: u64, mask: u32 },
    /// A fanotify mark.
    FanMark { slot: u32, kind: MarkKind, ino: u64, mark: Mark },
}

impl KRec {
    /// The object slot it belongs to.
    pub fn slot(&self) -> u32 {
        match *self {
            KRec::InGroup { slot, .. } | KRec::FanGroup { slot, .. } | KRec::InWatch { slot, .. } | KRec::FanMark { slot, .. } => slot,
        }
    }

    /// The record's bytes.
    pub fn encode(&self) -> [u8; KREC_SIZE] {
        let mut b = [0u8; KREC_SIZE];
        let uid = match *self {
            KRec::InGroup { uid, .. } | KRec::FanGroup { uid, .. } => uid,
            _ => 0,
        };
        b[32..36].copy_from_slice(&uid.to_le_bytes());
        let (tag, sub, slot, x, y, z) = match *self {
            KRec::InGroup { slot, .. } => (1u8, 0u8, slot, 0, 0, 0),
            KRec::FanGroup { slot, flags, f_flags, unprivileged, owner, .. } => (2, unprivileged as u8, slot, flags, f_flags, owner as u64),
            KRec::InWatch { slot, wd, ino, mask } => (3, 0, slot, ino, wd as u32 as u64, mask as u64),
            KRec::FanMark { slot, kind, ino, mark } => (
                4,
                match kind {
                    MarkKind::Inode => 0,
                    MarkKind::Mount => 1,
                    MarkKind::Filesystem => 2,
                },
                slot,
                ino,
                mark.mask,
                mark.ignore,
            ),
        };
        b[0] = tag;
        b[1] = sub;
        b[4..8].copy_from_slice(&slot.to_le_bytes());
        b[8..16].copy_from_slice(&x.to_le_bytes());
        b[16..24].copy_from_slice(&y.to_le_bytes());
        b[24..32].copy_from_slice(&z.to_le_bytes());
        b
    }

    /// Reads a record back (`None`: not one).
    pub fn decode(b: &[u8]) -> Option<KRec> {
        if b.len() < 36 {
            return None;
        }
        let uid = u32::from_le_bytes(b[32..36].try_into().ok()?);
        let slot = u32::from_le_bytes(b[4..8].try_into().ok()?);
        let x = u64::from_le_bytes(b[8..16].try_into().ok()?);
        let y = u64::from_le_bytes(b[16..24].try_into().ok()?);
        let z = u64::from_le_bytes(b[24..32].try_into().ok()?);
        Some(match b[0] {
            1 => KRec::InGroup { slot, uid },
            2 => KRec::FanGroup { slot, flags: x, f_flags: y, unprivileged: b[1] != 0, owner: z as u32, uid },
            3 => KRec::InWatch { slot, wd: y as u32 as i32, ino: x, mask: z as u32 },
            4 => KRec::FanMark {
                slot,
                kind: match b[1] {
                    0 => MarkKind::Inode,
                    1 => MarkKind::Mount,
                    2 => MarkKind::Filesystem,
                    _ => return None,
                },
                ino: x,
                mark: Mark { mask: y, ignore: z },
            },
            _ => return None,
        })
    }
}

/// An inode of a watch made on a path the server does not walk itself (a pseudo file
/// system, a FUSE mount): a stand-in no event names, kept apart from pool inodes by its
/// top bit; one per path.
pub fn stand_in_ino(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h | 1 << 63
}
