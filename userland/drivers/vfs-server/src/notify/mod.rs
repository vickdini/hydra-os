//! # inotify and fanotify (wave 9, Group 6b-1)
//!
//! vfs-server owns the inotify instances and fanotify groups while the file service is
//! forwarded (`docs/linux-services-design.md` 9.4, row 6b-1). Each is a server object of
//! its own kind (`LX_OBJ_KIND_INOTIFY`, `LX_OBJ_KIND_FANOTIFY`): `read` takes the queued
//! records (pending while the queue is empty), `poll`/`epoll` read the readiness word,
//! `FIONREAD` counts the queued bytes, `write` on a fanotify group answers a permission
//! event, and the close note ends it. The rules (watches, marks, which events, the
//! records) are in [`logic`]; the kernel's `inotify.rs`/`fanotify.rs` stay as the switch
//! back (`lx.vfs=kernel`, `lx=kernel`, vfs-server given up).
//!
//! ## Where the events come from
//! - **vfs-server's own changes:** their zfs-server replies carry the events
//!   ([`changed`], called where the change calls get their reply).
//! - **The kernel's changes and open files** (writes, the close-write event, creating opens,
//!   calls the kernel kept, `FAN_ACCESS`/`FAN_MODIFY`/`FAN_CLOSE_*`/`FAN_OPEN`): the kernel
//!   posts them as records in the note ring (`lx/notifyfwd.rs`), only for inodes in the map
//!   this module publishes in the window ([`publish`]: a flags word in the ring's header and
//!   a hash map of watched inodes). A call carries the ring position, so a `read` after a
//!   change finds its event.
//! - **Permission events:** the kernel posts the record with an id and asks with
//!   `LX_KCALL_FANPERM`, answered once every group that wanted it answered (pending
//!   meanwhile; a group closed, a restart or an interrupted question allow the open).
//!   vfs-server's own opens (and `getdents`) go to the kernel while a fanotify group exists
//!   ([`fan_any`]), so FAN_OPEN and permission events are always made where the open is.
//!
//! ## Restarts
//! Groups, watches and marks are kept records (a kept memory object of their own, key
//! [`KEPT_KEY`], hydra-rt's `Kept` format): a new instance takes its objects back
//! (`LX_SVC_LIST`, then `LX_SVC_ADOPT`) with their watches; the queued events are lost and
//! reported as `IN_Q_OVERFLOW` / `FAN_Q_OVERFLOW`.

pub mod logic;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::kept::Kept;
use hydra_rt::mem::{MemObj, PROT_RW};
use hydra_rt::svcrt::{objs, Answer, Cx};
use hydra_rt::{println, sys};

use self::logic::*;
use crate::calls::{ctxt, rules, KERNEL};
use crate::ctx::Ctx;
use crate::lock::YLock;
use crate::walk::Backend;
use crate::proto::{
    notify_hash, LxFhDesc, LxSvcObj, LX_FHP_ABS, LX_FH_INSTALL, LX_FH_NONOTIFY, LX_FH_PATH_MAX, LX_KCALL_FANPERM, LX_NOTES_OFF, LX_NOTES_SVCWORD, LX_NOTE_FSDATA, LX_NOTE_FSEVENT, LX_NOTIFY_ALL,
    LX_NOTIFY_FAN, LX_NOTIFY_INO, LX_NOTIFY_PERM, LX_OBJ_KIND_FANOTIFY, LX_OBJ_KIND_INOTIFY, LX_OBJ_NONE, LX_REPLY_PENDING, LX_VFS_NOTIFY_MAP_LEN, LX_VFS_NOTIFY_MAP_OFF,
};

const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const ENOTTY: i64 = -25;
const EINTR: i64 = -4;
const EACCES: i64 = -13;
const ERESTARTSYS: i64 = -512;
const FIONREAD: u64 = 0x541B;
const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u32 = 0o2000000;
const CAP_SYS_ADMIN: u32 = 21;
/// The kept memory object of the groups, watches and marks (7-6's snapshot slots are keys
/// 1 and 2; tmpfs data keys start at 2^32).
pub const KEPT_KEY: u64 = 3;
/// Kept records (each group, watch and mark takes one).
const KEPT_RECORDS: usize = 16384;
/// The layout version of the kept records.
const KEPT_LAYOUT: u32 = 0x6b01_0001;
/// The readiness bits of a group with queued events (`POLLIN | POLLRDNORM`).
const READABLE: u32 = 0x41;

/// A blocked `read`.
struct Reader {
    id: u64,
    slot: u32,
    buf: u64,
    cap: usize,
    /// The reader's process (fanotify's own-pid rule) and whether its PID namespace is the
    /// initial one (pids are shown only then).
    pid: u32,
    plain_ns: bool,
}

/// A permission question: the groups still to answer, a deny so far, the kernel's call.
#[derive(Default)]
struct Perm {
    waiting: Vec<u32>,
    deny: bool,
    call: Option<u64>,
    /// When the event came (ms since boot).
    at: u64,
}

/// Per-user limits, as Linux's defaults: inotify `max_user_instances` 128 and
/// `max_user_watches` (65536 here: Linux computes 8192..1048576 from memory), fanotify
/// `max_user_groups` 128 and `max_user_marks` 8192.
const MAX_USER_INSTANCES: usize = 128;
const MAX_USER_WATCHES: usize = 65536;
const MAX_USER_GROUPS: usize = 128;
const MAX_USER_MARKS: usize = 8192;
const EMFILE: i64 = -24;
const ENOSPC: i64 = -28;

/// Where a group, watch or mark is kept: `(slot, what, key)` (what: 0 group, 1 watch by
/// wd, 2..4 mark by kind and inode).
type KKey = (u32, u8, u64);

#[derive(Default)]
struct State {
    inos: BTreeMap<u32, Inotify>,
    fans: BTreeMap<u32, Fanotify>,
    readers: Vec<Reader>,
    perms: BTreeMap<u64, Perm>,
    kept: Option<Kept>,
    recs: BTreeMap<KKey, usize>,
    free: Vec<usize>,
    kept_full: bool,
    /// Events from the kernel's records that were cut short.
    asm: Assembler,
}

static ST: YLock<Option<State>> = YLock::new(None);
/// Any group exists (a quick test for [`changed`]).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// A fanotify group exists ([`fan_any`]).
static FAN_ANY: AtomicBool = AtomicBool::new(false);
/// The window (the word and the map are written there).
static WIN: AtomicU64 = AtomicU64::new(0);
/// Events queued, questions asked, kept-state writes (since start).
pub static EVENTS: AtomicU64 = AtomicU64::new(0);
/// See [`EVENTS`].
pub static QUESTIONS: AtomicU64 = AtomicU64::new(0);
/// Instances and groups made (since start).
pub static MADE: AtomicU64 = AtomicU64::new(0);

/// Says how many instances and groups were made, at 1, 16, 32, 64, ...
fn made_one() {
    let n = MADE.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 || (n >= 16 && n.is_power_of_two()) {
        let (i, w, g, m, e, q) = counts();
        println!("[vfs-server] notify: {} made; now {} inotify instances ({} watches), {} fanotify groups ({} marks); {} events, {} questions", n, i, w, g, m, e, q);
    }
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut g = ST.lock();
    f(g.get_or_insert_with(State::default))
}

// ----------------------------------------------------------------------
// Kept records
// ----------------------------------------------------------------------

impl State {
    fn keep(&mut self, key: KKey, r: KRec) {
        let Some(k) = self.kept.as_mut() else { return };
        let i = match self.recs.get(&key) {
            Some(&i) => i,
            None => match self.free.pop() {
                Some(i) => i,
                None => {
                    if !core::mem::replace(&mut self.kept_full, true) {
                        println!("[vfs-server] notify: {} kept records in use: new watches are not kept across a restart", KEPT_RECORDS);
                    }
                    return;
                }
            },
        };
        if k.put(i, &r.encode()) {
            self.recs.insert(key, i);
        }
    }

    fn unkeep(&mut self, key: KKey) {
        if let Some(i) = self.recs.remove(&key) {
            if let Some(k) = self.kept.as_mut() {
                k.clear(i);
            }
            self.free.push(i);
        }
    }

    /// Lets every record of `slot` go.
    fn unkeep_slot(&mut self, slot: u32) {
        let keys: Vec<KKey> = self.recs.range((slot, 0, 0)..=(slot, u8::MAX, u64::MAX)).map(|(k, _)| *k).collect();
        for k in keys {
            self.unkeep(k);
        }
    }
}

fn mark_key(kind: MarkKind, ino: u64) -> (u8, u64) {
    match kind {
        MarkKind::Inode => (2, ino),
        MarkKind::Mount => (3, 0),
        MarkKind::Filesystem => (4, 0),
    }
}

// ----------------------------------------------------------------------
// What the kernel sees: the word and the map
// ----------------------------------------------------------------------

/// Writes the flags word and the watched-inode map for the kernel (`lx/notifyfwd.rs`).
fn publish(st: &State) {
    let win = WIN.load(Ordering::Acquire);
    let mut word = 0u64;
    let mut map = alloc::vec![0u8; LX_VFS_NOTIFY_MAP_LEN];
    let mut set = |ino: u64| {
        let b = notify_hash(ino);
        map[b / 8] |= 1 << (b % 8);
    };
    for i in st.inos.values() {
        if !i.watches.is_empty() {
            word |= LX_NOTIFY_INO;
        }
        for w in i.watches.values() {
            set(w.ino);
        }
    }
    for g in st.fans.values() {
        // (descriptor and permission events come from open files and opens: the kernel's
        // handles; entry and attribute events come with the zfs events)
        let marks = g.inodes.values().chain(g.mount.iter()).chain(g.filesystem.iter());
        for m in marks {
            if m.mask & (FD_EVENTS | PERM_EVENTS) != 0 {
                word |= LX_NOTIFY_FAN;
            }
            if m.mask & FID_EVENTS != 0 {
                word |= LX_NOTIFY_INO;
            }
        }
        if g.wants_all() {
            word |= LX_NOTIFY_ALL;
        }
        if g.has_perm() {
            word |= LX_NOTIFY_PERM;
        }
        for ino in g.inodes.keys() {
            set(*ino);
        }
    }
    ACTIVE.store(!st.inos.is_empty() || !st.fans.is_empty(), Ordering::Release);
    FAN_ANY.store(word & LX_NOTIFY_FAN != 0, Ordering::Release);
    if win == 0 {
        return;
    }
    // (the map first, byte by byte: a byte goes from its old bits to its new ones at once,
    // so an inode watched before and after is never missing; then the word)
    for (i, b) in map.iter().enumerate() {
        // SAFETY: the map lies in the mapped window
        unsafe { core::ptr::write_volatile((win as *mut u8).add(LX_VFS_NOTIFY_MAP_OFF + i), *b) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    // SAFETY: the ring header's spare word in the mapped window (only this service writes it)
    unsafe { core::ptr::write_volatile((win as *mut u64).add(LX_NOTES_OFF / 8 + LX_NOTES_SVCWORD), word) };
}

/// Whether a fanotify mark wants descriptor or permission events: vfs-server's opens and
/// `getdents` go to the kernel then (the kernel makes their events, with its own paths).
pub fn fan_any() -> bool {
    FAN_ANY.load(Ordering::Acquire)
}

/// The readiness of `slot` (bits, queued bytes).
fn readiness(st: &State, slot: u32) -> (u32, u64) {
    if let Some(i) = st.inos.get(&slot) {
        return (if i.queue.is_empty() { 0 } else { READABLE }, i.bytes as u64);
    }
    if let Some(g) = st.fans.get(&slot) {
        return (if g.queue.is_empty() { 0 } else { READABLE }, g.queue.len() as u64);
    }
    (0, 0)
}

/// Sets the readiness words of `slots` (`bump`: new events, so an edge-triggered watch
/// sees an edge even when the group was readable already).
fn refresh(st: &State, slots: &[u32], bump: bool) {
    for &s in slots {
        let (r, n) = readiness(st, s);
        if bump && r != 0 {
            objs::set(s, 0, n);
        }
        objs::set(s, r, n);
    }
}

// ----------------------------------------------------------------------
// Start and restart
// ----------------------------------------------------------------------

/// wave11 GR: the owner of an inotify instance taken back without its records (unknown).
const REBORN_UID: u32 = u32::MAX;

/// Before going online: the window, the kept records and the previous instance's objects.
pub fn start(win: *mut u8) {
    WIN.store(win as u64, Ordering::Release);
    let mut st = State::default();
    let size = Kept::size_for(KEPT_RECORDS, KREC_SIZE);
    let mut indexed: Vec<(usize, KRec)> = Vec::new();
    match MemObj::kept(KEPT_KEY, size as u64).and_then(|(o, _)| o.map(0, size as u64, PROT_RW)) {
        Ok(p) => {
            // SAFETY: `size` bytes of this program's own mapping, used only through `st`
            let (k, a) = unsafe { Kept::open(p, size, KEPT_LAYOUT, KREC_SIZE) };
            for i in 0..k.count() {
                match k.get(i).filter(|d| !d.is_empty()).and_then(KRec::decode) {
                    Some(r) => indexed.push((i, r)),
                    None => st.free.push(i),
                }
            }
            if a.bad_records > 0 {
                println!("[vfs-server] notify: {} kept records failed their checks", a.bad_records);
            }
            st.kept = Some(k);
        }
        Err(e) => println!("[vfs-server] notify: no kept records ({}): watches will not survive a restart", e),
    }
    // (the lowest free index first)
    st.free.reverse();
    // The previous instance's objects
    let mut found: Vec<LxSvcObj> = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut from = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, from) {
        if n == 0 {
            break;
        }
        found.extend_from_slice(&buf[..n]);
        from = buf[n - 1].slot + 1;
    }
    let groups: BTreeMap<u32, KRec> = indexed.iter().filter(|(_, r)| matches!(r, KRec::InGroup { .. } | KRec::FanGroup { .. })).map(|(_, r)| (r.slot(), *r)).collect();
    let mut live: Vec<u32> = Vec::new();
    let mut reborn: Vec<u32> = Vec::new(); // wave11 GR
    for o in &found {
        let ours = o.kind == LX_OBJ_KIND_INOTIFY || o.kind == LX_OBJ_KIND_FANOTIFY;
        let kept_kind = match groups.get(&o.slot) {
            Some(KRec::InGroup { .. }) => LX_OBJ_KIND_INOTIFY,
            Some(KRec::FanGroup { .. }) => LX_OBJ_KIND_FANOTIFY,
            _ => 0,
        };
        if ours && kept_kind == o.kind {
            live.push(o.slot);
        } else if o.kind == LX_OBJ_KIND_INOTIFY {
            // wave11 GR: an inotify instance whose records were lost (the restart ladder
            // reset the kept state after a second crash within 30 s) comes back empty, with
            // an overflow event: its watches are gone (as if removed), but the program's
            // descriptor keeps working and new watches work; failing it instead made
            // programs that read it (GLib, KDirWatch, Firefox) crash
            live.push(o.slot);
            reborn.push(o.slot);
        } else if ours {
            // (an instance or group whose records were lost: its descriptor fails from now
            // on; objects of other kinds are their modules': FUSE's `restart_init`)
            let _ = sys::lx_svc_dead(o.slot);
        }
    }
    let adopted = !live.is_empty() && sys::lx_svc_adopt().is_ok();
    if !adopted {
        live.clear();
    }
    for &s in &live {
        if !objs::reserve(s) {
            continue;
        }
        match groups.get(&s) {
            Some(&KRec::InGroup { uid, .. }) => {
                let mut i = Inotify::new();
                i.uid = uid;
                i.overflow();
                st.inos.insert(s, i);
            }
            Some(&KRec::FanGroup { flags, f_flags, unprivileged, owner, uid, .. }) => {
                let mut g = Fanotify::new(flags, f_flags, unprivileged, owner, uid);
                g.overflow();
                st.fans.insert(s, g);
            }
            // wave11 GR: taken back without its records (owner unknown: counted for no
            // user's limits); its record is written again for the next restart
            _ if reborn.contains(&s) => {
                let mut i = Inotify::new();
                i.uid = REBORN_UID;
                i.overflow();
                st.inos.insert(s, i);
                st.keep((s, 0, 0), KRec::InGroup { slot: s, uid: REBORN_UID });
            }
            _ => {}
        }
    }
    if !reborn.is_empty() && adopted {
        println!("[vfs-server] notify: {} inotify instances taken back without their records (kept state reset): empty, with an overflow event", reborn.len());
    }
    // Watches and marks of the groups taken back; every other record goes
    let (mut watches, mut marks) = (0, 0);
    for (i, r) in indexed {
        let slot = r.slot();
        let key: Option<KKey> = match r {
            KRec::InGroup { .. } | KRec::FanGroup { .. } if st.inos.contains_key(&slot) || st.fans.contains_key(&slot) => Some((slot, 0, 0)),
            KRec::InWatch { wd, ino, mask, .. } => st.inos.get_mut(&slot).map(|g| {
                g.restore_watch(wd, Watch { ino, mask });
                watches += 1;
                (slot, 1, wd as u32 as u64)
            }),
            KRec::FanMark { kind, ino, mark, .. } => st.fans.get_mut(&slot).map(|g| {
                match kind {
                    MarkKind::Inode => {
                        g.inodes.insert(ino, mark);
                    }
                    MarkKind::Mount => g.mount = Some(mark),
                    MarkKind::Filesystem => g.filesystem = Some(mark),
                }
                marks += 1;
                let (w, k) = mark_key(kind, ino);
                (slot, w, k)
            }),
            _ => None,
        };
        match key {
            Some(k) if !st.recs.contains_key(&k) => {
                st.recs.insert(k, i);
            }
            _ => {
                if let Some(kp) = st.kept.as_mut() {
                    kp.clear(i);
                }
                st.free.push(i);
            }
        }
    }
    if !st.inos.is_empty() || !st.fans.is_empty() {
        println!("[vfs-server] notify: took back {} inotify instances ({} watches) and {} fanotify groups ({} marks); their queued events are lost (overflow event)", st.inos.len(), watches, st.fans.len(), marks);
    }
    publish(&st);
    let slots: Vec<u32> = st.inos.keys().chain(st.fans.keys()).copied().collect();
    refresh(&st, &slots, true);
    *ST.lock() = Some(st);
    objs::flush();
}

// ----------------------------------------------------------------------
// The calls
// ----------------------------------------------------------------------

/// Serves an inotify/fanotify call, a call on one of the objects, or the kernel's
/// permission question (`None`: not one of these).
pub fn serve(cx: &Cx) -> Option<Answer> {
    let r = match cx.nr {
        253 | 294 => in_init(cx),
        300 => fan_init(cx),
        254 => add_watch(cx),
        255 => rm_watch(cx),
        301 => fan_mark(cx),
        LX_KCALL_FANPERM => return Some(perm_call(cx)),
        0 | 1 | 16 | 19 | 20 if cx.c.obj != LX_OBJ_NONE && owns(cx.c.obj as u32) => return Some(obj_io(cx)),
        _ => return None,
    };
    // (a walk vfs-server does not make itself: never for these calls, see `add_watch`)
    Some(match r {
        // (a path vfs-server does not walk itself: no instance of the kernel's to send it to)
        Err(e) if not_walked(e) => (EINVAL, 0),
        Ok(v) | Err(v) => (v, 0),
    })
}

/// Whether `slot` is one of this module's objects.
fn owns(slot: u32) -> bool {
    ST.lock().as_ref().is_some_and(|s| s.inos.contains_key(&slot) || s.fans.contains_key(&slot))
}

/// `inotify_init`, `inotify_init1(flags)`.
fn in_init(cx: &Cx) -> Result<i64, i64> {
    let flags = if cx.nr == 294 { cx.args[0] } else { 0 };
    if !in_init_ok(flags) {
        return Err(EINVAL);
    }
    let uid = cx.c.uid;
    if with(|st| st.inos.values().filter(|i| i.uid == uid).count()) >= MAX_USER_INSTANCES {
        return Err(EMFILE);
    }
    let slot = objs::alloc()?;
    with(|st| {
        let mut i = Inotify::new();
        i.uid = uid;
        st.inos.insert(slot, i);
        st.keep((slot, 0, 0), KRec::InGroup { slot, uid });
        publish(st);
    });
    objs::set(slot, 0, 0);
    match objs::install_keyed(cx, slot, LX_OBJ_KIND_INOTIFY, flags as u32 & (O_NONBLOCK | O_CLOEXEC), 0o600, b"anon_inode:inotify", 0, slot as u64) {
        Ok(fd) => {
            made_one();
            Ok(fd)
        }
        Err(e) => {
            drop_group(slot);
            Err(e)
        }
    }
}

/// `fanotify_init(flags, event_f_flags)`.
fn fan_init(cx: &Cx) -> Result<i64, i64> {
    let (flags, f_flags) = (cx.args[0], cx.args[1]);
    let privileged = cx.has_cap(CAP_SYS_ADMIN) && cx.c.user_ns == 0;
    fan_init_ok(flags, f_flags, privileged)?;
    let uid = cx.c.uid;
    if with(|st| st.fans.values().filter(|g| g.uid == uid).count()) >= MAX_USER_GROUPS {
        return Err(EMFILE);
    }
    let slot = objs::alloc()?;
    let owner = cx.c.tgid as u32;
    with(|st| {
        st.fans.insert(slot, Fanotify::new(flags, f_flags, !privileged, owner, uid));
        st.keep((slot, 0, 0), KRec::FanGroup { slot, flags, f_flags, unprivileged: !privileged, owner, uid });
        publish(st);
    });
    objs::set(slot, 0, 0);
    let fl = if flags & FAN_CLOEXEC != 0 { O_CLOEXEC } else { 0 } | if flags & FAN_NONBLOCK != 0 { O_NONBLOCK } else { 0 };
    match objs::install_keyed(cx, slot, LX_OBJ_KIND_FANOTIFY, fl, 0o600, b"anon_inode:[fanotify]", 0, slot as u64) {
        Ok(fd) => {
            made_one();
            Ok(fd)
        }
        Err(e) => {
            drop_group(slot);
            Err(e)
        }
    }
}

/// Whether `e` is an answer for a walk vfs-server leaves to another server (`/proc`,
/// `/sys`, FUSE, a root outside the pool): the watch then names a stand-in inode.
fn not_walked(e: i64) -> bool {
    e == KERNEL || e < -4095
}

/// The inode a watch or mark names for node `(mnt, ino)` of caller `who`: the pool object,
/// or a stand-in for a tmpfs file (tmpfs makes no events, and its numbers are its own).
fn watch_ino(who: &Ctx, n: crate::ctx::Node) -> u64 {
    if n.mnt != 0 && crate::mount::tmpfs_of(who.ns, n.mnt).is_some() {
        (1 << 62) | (n.mnt as u64) << 40 | (n.ino & 0xFF_FFFF_FFFF)
    } else {
        n.ino
    }
}

/// `inotify_add_watch(fd, path, mask)`.
fn add_watch(cx: &Cx) -> Result<i64, i64> {
    let slot = cx.c.obj as u32;
    if !ST.lock().as_ref().is_some_and(|s| s.inos.contains_key(&slot)) {
        return Err(EINVAL);
    }
    let mask = cx.args[2] as u32;
    if !in_mask_ok(mask) {
        return Err(EINVAL);
    }
    let path = ctxt::path(cx, cx.args[1], false)?;
    // (Linux asks for read permission on the watched object)
    let found = ctxt::caller(&cx.c).and_then(|who| {
        let (n, a) = ctxt::find(&cx.c, &who, &path, mask & IN_DONT_FOLLOW == 0)?;
        let acl = ctxt::acl_of(n, &a)?;
        if !ctxt::may_access(&who, &a, acl.as_deref(), cx.c.euid, cx.c.egid, rules::MAY_READ) {
            return Err(EACCES);
        }
        Ok((watch_ino(&who, n), a.is_dir()))
    });
    let (ino, is_dir) = match found {
        Ok(v) => v,
        Err(e) if not_walked(e) => (stand_in_ino(&path), true),
        Err(e) => return Err(e),
    };
    with(|st| {
        // (a new watch counts against its user's limit)
        let uid = st.inos.get(&slot).map_or(0, |i| i.uid);
        let known = st.inos.get(&slot).is_some_and(|i| i.by_ino.contains_key(&ino));
        if !known && st.inos.values().filter(|i| i.uid == uid).map(|i| i.watches.len()).sum::<usize>() >= MAX_USER_WATCHES {
            return Err(ENOSPC);
        }
        let g = st.inos.get_mut(&slot).ok_or(EINVAL)?;
        let (wd, new) = g.add_watch(ino, is_dir, mask)?;
        let m = g.watches.get(&wd).map_or(0, |w| w.mask);
        st.keep((slot, 1, wd as u32 as u64), KRec::InWatch { slot, wd, ino, mask: m });
        if new {
            publish(st);
        }
        Ok(wd as i64)
    })
}

/// `inotify_rm_watch(fd, wd)`.
fn rm_watch(cx: &Cx) -> Result<i64, i64> {
    let slot = cx.c.obj as u32;
    let wd = cx.args[1] as i32;
    let r = with(|st| {
        let g = st.inos.get_mut(&slot).ok_or(EINVAL)?;
        g.rm_watch(wd).ok_or(EINVAL)?;
        st.unkeep((slot, 1, wd as u32 as u64));
        publish(st);
        refresh(st, &[slot], true);
        Ok(0)
    });
    if r.is_ok() {
        wake(&[slot]);
    }
    r
}

/// `fanotify_mark(fd, flags, mask, dirfd, path)`.
fn fan_mark(cx: &Cx) -> Result<i64, i64> {
    let slot = cx.c.obj as u32;
    let [_, flags, mask, _, path_ptr, _] = cx.args;
    let m = {
        let g = ST.lock();
        let Some(f) = g.as_ref().and_then(|s| s.fans.get(&slot)) else { return Err(EINVAL) };
        f.mark_check(flags, mask)?
    };
    if m.op == FAN_MARK_FLUSH {
        return with(|st| {
            let Some(g) = st.fans.get_mut(&slot) else { return Err(EINVAL) };
            let gone: Vec<u64> = match m.kind {
                MarkKind::Inode => g.inodes.keys().copied().collect(),
                _ => alloc::vec![0],
            };
            g.flush(m.kind);
            for ino in gone {
                let (w, k) = mark_key(m.kind, ino);
                st.unkeep((slot, w, k));
            }
            publish(st);
            Ok(0)
        });
    }
    // The object: the path from the directory descriptor, or the descriptor itself
    let c = &cx.c;
    let who = ctxt::caller(c)?;
    let path = if path_ptr == 0 { Vec::new() } else { cx.user_cstr(path_ptr)? };
    let follow = flags & FAN_MARK_DONT_FOLLOW == 0;
    let (n, attr) = if path.is_empty() {
        if c.at_kind == crate::proto::LX_AT_CWD {
            ctxt::find(c, &who, b".", true)?
        } else {
            let n = ctxt::handle(c)?;
            (n, ctxt::BE.getattr(n)?)
        }
    } else {
        ctxt::find(c, &who, &path, follow)?
    };
    let unprivileged = ST.lock().as_ref().and_then(|s| s.fans.get(&slot)).is_some_and(|g| g.unprivileged);
    if unprivileged {
        let acl = ctxt::acl_of(n, &attr)?;
        if !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, rules::MAY_READ) {
            return Err(EACCES);
        }
    }
    if flags & FAN_MARK_ONLYDIR != 0 && !attr.is_dir() {
        return Err(ENOTDIR);
    }
    let ino = watch_ino(&who, n);
    with(|st| {
        let uid = st.fans.get(&slot).map_or(0, |g| g.uid);
        let new_mark = m.op == FAN_MARK_ADD && m.kind == MarkKind::Inode && !st.fans.get(&slot).is_some_and(|g| g.inodes.contains_key(&ino));
        if new_mark && st.fans.values().filter(|g| g.uid == uid).map(|g| g.inodes.len()).sum::<usize>() >= MAX_USER_MARKS {
            return Err(ENOSPC);
        }
        let Some(g) = st.fans.get_mut(&slot) else { return Err(EINVAL) };
        let after = g.mark(m, ino, mask)?;
        let (w, k) = mark_key(m.kind, ino);
        match after {
            Some(mark) => st.keep((slot, w, k), KRec::FanMark { slot, kind: m.kind, ino, mark }),
            None => st.unkeep((slot, w, k)),
        }
        publish(st);
        Ok(0)
    })
}

/// A call on an instance or group: `read`, `write` (a fanotify answer), `ioctl`.
fn obj_io(cx: &Cx) -> Answer {
    let slot = cx.c.obj as u32;
    match cx.nr {
        0 => read(cx, slot),
        1 => (fan_write(cx, slot), 0),
        16 if cx.args[1] == FIONREAD => {
            let n = with(|st| {
                if let Some(i) = st.inos.get(&slot) {
                    i.bytes
                } else {
                    st.fans.get(&slot).map_or(0, |g| g.queued_bytes())
                }
            });
            (cx.copy_out(cx.args[2], &(n as i32).to_le_bytes()).map_or_else(|e| e, |()| 0), 0)
        }
        16 => (ENOTTY, 0),
        _ => (EINVAL, 0),
    }
}

/// `read(fd, buf, count)`: the queued records, or pending until there are some.
fn read(cx: &Cx, slot: u32) -> Answer {
    let (buf, cap) = (cx.args[1], cx.args[2] as usize);
    let me = cx.c.tgid as u32;
    let plain = cx.c.pid_ns == 0;
    match take(cx.id, slot, cap, me, plain) {
        Ok(Some((bytes, asked))) => {
            refresh_one(slot);
            let r = cx.copy_out(buf, &bytes).map_or_else(|e| e, |()| bytes.len() as i64);
            // (the listener never saw these questions: they are denied, as Linux does when
            // an event cannot be copied to the reader)
            if r < 0 {
                deny_reported(slot, &asked);
            }
            (r, 0)
        }
        Ok(None) if cx.nonblock() || buf >= crate::proto::LX_KBUF_ADDR => (EAGAIN, 0),
        Ok(None) => {
            with(|st| st.readers.push(Reader { id: cx.id, slot, buf, cap, pid: me, plain_ns: plain }));
            // (an event may have come between the look and the wait)
            wake(&[slot]);
            (0, LX_REPLY_PENDING)
        }
        Err(e) => (e, 0),
    }
}

fn refresh_one(slot: u32) {
    with(|st| refresh(st, &[slot], false));
}

/// Takes what `cap` bytes hold from `slot`'s queue for request `id` (`None`: nothing
/// queued): fanotify descriptor events get a descriptor in the reader's table.
/// Also the permission questions reported, by descriptor (to deny if the bytes cannot
/// reach the reader).
fn take(id: u64, slot: u32, cap: usize, me: u32, plain: bool) -> Result<Option<(Vec<u8>, Vec<(i32, u64)>)>, i64> {
    enum Got {
        In(Vec<u8>),
        Fan(Vec<FanEvent>, Fanotify),
    }
    let got = with(|st| -> Result<Option<Got>, i64> {
        if let Some(i) = st.inos.get_mut(&slot) {
            let b = i.read(cap)?;
            return Ok(if b.is_empty() { None } else { Some(Got::In(b)) });
        }
        let g = st.fans.get_mut(&slot).ok_or(EBADF)?;
        let evs = g.take(cap)?;
        if evs.is_empty() {
            return Ok(None);
        }
        // (a copy of the group's settings for the records, made without the lock)
        let shape = Fanotify::new(g.flags, g.f_flags, g.unprivileged, g.owner, g.uid);
        Ok(Some(Got::Fan(evs, shape)))
    })?;
    match got {
        None => Ok(None),
        Some(Got::In(b)) => Ok(Some((b, Vec::new()))),
        Some(Got::Fan(evs, shape)) => {
            let mut out = Vec::new();
            let mut asked = Vec::new();
            let mut first_err = None;
            for ev in evs {
                let fd = if shape.fid_mode() || ev.ino == 0 {
                    FAN_NOFD
                } else {
                    match event_fd(id, &shape, &ev) {
                        Ok(fd) => fd,
                        Err(e) => {
                            // (the event is lost, as the kernel's read loses it; a
                            // permission question with it is denied, as Linux does)
                            if let Some(q) = ev.perm {
                                let done = with(|st| answer(st, q, slot, true));
                                finish(done);
                            }
                            if out.is_empty() && first_err.is_none() {
                                first_err = Some(e);
                            }
                            continue;
                        }
                    }
                };
                if let Some(q) = ev.perm {
                    with(|st| {
                        if let Some(g) = st.fans.get_mut(&slot) {
                            g.fd_ids.entry(fd).or_default().push(q);
                        }
                    });
                    asked.push((fd, q));
                }
                let pid = shape.shown_pid(&ev, me, plain);
                out.extend(shape.record(&ev, fd, pid));
            }
            match (out.is_empty(), first_err) {
                (true, Some(e)) => Err(e),
                _ => Ok(Some((out, asked))),
            }
        }
    }
}

/// A descriptor for the file of descriptor event `ev` in request `id`'s caller (it makes
/// no events itself).
fn event_fd(id: u64, g: &Fanotify, ev: &FanEvent) -> Result<i32, i64> {
    let mut d = LxFhDesc::EMPTY;
    d.ino = ev.ino;
    d.is_dir = (ev.mask & FAN_ONDIR != 0) as u32;
    d.flags = (g.f_flags as u32 & (3 | 0o2000 | O_NONBLOCK | O_CLOEXEC)) | LX_FH_NONOTIFY;
    d.path_kind = LX_FHP_ABS;
    let n = ev.path.len().min(LX_FH_PATH_MAX);
    d.path[..n].copy_from_slice(&ev.path[..n]);
    d.path_len = n as u32;
    sys::lx_obj(LX_FH_INSTALL, id, &d as *const LxFhDesc as u64, 0).map(|fd| fd as i32)
}

/// `write(fd, buf, count)` on a fanotify group: a `struct fanotify_response`.
fn fan_write(cx: &Cx, slot: u32) -> i64 {
    if cx.args[2] < 8 {
        return EINVAL;
    }
    let data = match cx.copy_in(cx.args[1], 8) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let r = with(|st| {
        let g = st.fans.get_mut(&slot).ok_or(EINVAL)?;
        let (q, deny) = g.response(&data)?;
        Ok(answer(st, q, slot, deny))
    });
    match r {
        Ok(done) => {
            finish(done);
            8
        }
        Err(e) => e,
    }
}

/// Group `slot` answered question `q` (`deny`): the kernel's call to complete, if that was
/// the last answer.
fn answer(st: &mut State, q: u64, slot: u32, deny: bool) -> Vec<(u64, i64)> {
    let mut done = Vec::new();
    let finished = match st.perms.get_mut(&q) {
        Some(p) => {
            p.waiting.retain(|&s| s != slot);
            p.deny |= deny;
            p.waiting.is_empty() && p.call.is_some()
        }
        None => false,
    };
    if finished {
        if let Some(p) = st.perms.remove(&q) {
            if let Some(id) = p.call {
                done.push((id, if p.deny { EPERM } else { 0 }));
            }
        }
    }
    done
}

fn finish(done: Vec<(u64, i64)>) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
}

/// Denies the questions `asked` that group `slot` reported in a read whose bytes did not
/// reach the reader (it cannot answer them).
fn deny_reported(slot: u32, asked: &[(i32, u64)]) {
    let done = with(|st| {
        let mut done = Vec::new();
        for &(fd, q) in asked {
            if let Some(g) = st.fans.get_mut(&slot) {
                if let Some(v) = g.fd_ids.get_mut(&fd) {
                    v.retain(|&x| x != q);
                    if v.is_empty() {
                        g.fd_ids.remove(&fd);
                    }
                }
            }
            done.extend(answer(st, q, slot, true));
        }
        done
    });
    finish(done);
}

/// `LX_KCALL_FANPERM(id)`: the kernel waits for the answer to question `id`. A question
/// whose record is not here (lost to a full ring or a restart) answers `EAGAIN` while a
/// group may ask (the kernel posts it again), else 0 (no group wants it).
fn perm_call(cx: &Cx) -> Answer {
    let q = cx.args[0];
    with(|st| {
        let Some(p) = st.perms.get_mut(&q) else {
            return (if st.fans.values().any(|g| g.has_perm()) { EAGAIN } else { 0 }, 0);
        };
        if p.waiting.is_empty() {
            let deny = p.deny;
            st.perms.remove(&q);
            return (if deny { EPERM } else { 0 }, 0);
        }
        p.call = Some(cx.id);
        (0, LX_REPLY_PENDING)
    })
}

/// Completes the blocked reads of `slots` that can be served now.
fn wake(slots: &[u32]) {
    for &slot in slots {
        loop {
            let r = with(|st| {
                let i = st.readers.iter().position(|r| r.slot == slot)?;
                let (has, _) = readiness(st, slot);
                if has == 0 {
                    return None;
                }
                Some(st.readers.remove(i))
            });
            let Some(w) = r else { break };
            let res = match take(w.id, slot, w.cap, w.pid, w.plain_ns) {
                Ok(Some((bytes, asked))) => match sys::lx_write(w.id, w.buf, &bytes) {
                    Ok(()) => bytes.len() as i64,
                    Err(_) => {
                        deny_reported(slot, &asked);
                        EFAULT
                    }
                },
                Ok(None) => {
                    with(|st| st.readers.insert(0, w));
                    break;
                }
                Err(e) => e,
            };
            let _ = sys::lx_complete(w.id, res);
            refresh_one(slot);
        }
    }
}

// ----------------------------------------------------------------------
// Events
// ----------------------------------------------------------------------

/// One event for the groups.
enum Src<'a> {
    Zfs { ino: u64, mask: u32, cookie: u32, name: &'a [u8] },
    File { ino: u64, dir: u64, path: &'a [u8], mask: u64 },
    Perm { ino: u64, dir: u64, path: &'a [u8], mask: u64, id: u64 },
}

/// Hands event `e` (caused by `pid`/`tid`) to every group; wakes their readers.
fn dispatch(e: Src, pid: u32, tid: u32) {
    let touched = with(|st| {
        let mut touched: Vec<u32> = Vec::new();
        let mut gone: Vec<(u32, i32)> = Vec::new();
        if let Src::Zfs { ino, mask, cookie, name } = e {
            for (&slot, i) in st.inos.iter_mut() {
                let (queued, removed) = i.event(ino, mask, cookie, name);
                if queued {
                    touched.push(slot);
                }
                if let Some(wd) = removed {
                    gone.push((slot, wd));
                }
            }
        }
        let mut asked: Vec<u32> = Vec::new();
        for (&slot, g) in st.fans.iter_mut() {
            let q = match e {
                Src::Zfs { ino, mask, name, .. } => g.fs_event(ino, mask, name, pid, tid),
                Src::File { ino, dir, path, mask } => g.file_event(ino, dir, path, mask, pid, tid),
                Src::Perm { ino, dir, path, mask, id } => {
                    let q = g.perm_event(ino, dir, path, mask, pid, tid, id);
                    if q {
                        asked.push(slot);
                    }
                    q
                }
            };
            if q {
                touched.push(slot);
            }
        }
        if let Src::Perm { id, .. } = e {
            // (always recorded, also when no group asks: the kernel's question then finds
            // its answer; an unknown question means a lost record, see `perm_call`)
            if !asked.is_empty() {
                QUESTIONS.fetch_add(1, Ordering::Relaxed);
            }
            let now = hydra_rt::svcrt::now_ms();
            // (questions whose call never came: the opener went away)
            st.perms.retain(|_, p| p.call.is_some() || now.saturating_sub(p.at) < 120_000);
            st.perms.insert(id, Perm { waiting: asked, deny: false, call: None, at: now });
        }
        if !gone.is_empty() {
            for (slot, wd) in gone {
                st.unkeep((slot, 1, wd as u32 as u64));
            }
            publish(st);
        }
        if !touched.is_empty() {
            EVENTS.fetch_add(touched.len() as u64, Ordering::Relaxed);
            refresh(st, &touched, true);
        }
        touched
    });
    if !touched.is_empty() {
        wake(&touched);
    }
}

/// The events of a change vfs-server made (its zfs-server reply), caused by `who`.
pub fn changed(r: &Result<crate::zfs::Reply, i64>, who: &Ctx) {
    let Ok(r) = r else { return };
    if r.events.is_empty() || !ACTIVE.load(Ordering::Acquire) {
        return;
    }
    for e in &r.events {
        dispatch(Src::Zfs { ino: e.ino, mask: e.mask, cookie: e.cookie, name: &e.name }, who.pid, who.tid);
    }
}

/// A note from the kernel (`LX_NOTE_FSEVENT`, `LX_NOTE_FSDATA`): `true` if it was one.
pub fn on_note(kind: u64, a: u64, b: u64, c: u64) -> bool {
    let ev = match kind {
        LX_NOTE_FSEVENT => with(|st| st.asm.head(a, b, c)),
        LX_NOTE_FSDATA => with(|st| st.asm.data(a, b, c)),
        _ => return false,
    };
    if let Some(k) = ev {
        let src = match k.kind {
            FSEV_ZFS => Src::Zfs { ino: k.ino, mask: k.mask, cookie: k.cookie, name: &k.tail },
            FSEV_FILE => Src::File { ino: k.ino, dir: k.dir, path: &k.tail, mask: k.mask as u64 },
            FSEV_PERM => Src::Perm { ino: k.ino, dir: k.dir, path: &k.tail, mask: k.mask as u64, id: k.id },
            _ => return true,
        };
        dispatch(src, k.pid, k.tid);
    }
    true
}

/// The kernel's records were lost to a full ring: every group gets an overflow event.
pub fn lost_events() {
    let slots = with(|st| {
        for i in st.inos.values_mut() {
            i.overflow();
        }
        for g in st.fans.values_mut() {
            g.overflow();
        }
        let s: Vec<u32> = st.inos.keys().chain(st.fans.keys()).copied().collect();
        refresh(st, &s, true);
        s
    });
    wake(&slots);
}

// ----------------------------------------------------------------------
// Close and interrupt
// ----------------------------------------------------------------------

/// Ends group `slot`: its watches, its records, its open questions (allowed).
fn drop_group(slot: u32) {
    let done = with(|st| {
        st.inos.remove(&slot);
        let qs = st.fans.remove(&slot).map(|g| g.open_questions()).unwrap_or_default();
        let mut done = Vec::new();
        for q in qs {
            done.extend(answer(st, q, slot, false));
        }
        // (questions that still wait for it but were not queued here any more)
        let waiting: Vec<u64> = st.perms.iter().filter(|(_, p)| p.waiting.contains(&slot)).map(|(q, _)| *q).collect();
        for q in waiting {
            done.extend(answer(st, q, slot, false));
        }
        st.readers.retain(|r| r.slot != slot);
        st.unkeep_slot(slot);
        publish(st);
        done
    });
    finish(done);
    objs::set(slot, 0, 0);
    objs::free(slot);
}

/// The close note of object `slot` of `kind`: `true` if it was one of this module's.
pub fn closed(slot: u32, kind: u32) -> bool {
    if kind != LX_OBJ_KIND_INOTIFY && kind != LX_OBJ_KIND_FANOTIFY {
        return false;
    }
    if !owns(slot) {
        return true;
    }
    drop_group(slot);
    true
}

/// Request `id` was interrupted: a blocked read answers `ERESTARTSYS` (inotify) or
/// `EINTR` (fanotify); a permission question `EINTR` (the open fails, never allowed). `true` if it was one of these.
pub fn interrupted(id: u64) -> bool {
    let r = with(|st| {
        if let Some(i) = st.readers.iter().position(|r| r.id == id) {
            let w = st.readers.remove(i);
            return Some(if st.inos.contains_key(&w.slot) { ERESTARTSYS } else { EINTR });
        }
        // (a signal while the opener waits: the open fails with EINTR, never allowed)
        let q = st.perms.iter().find(|(_, p)| p.call == Some(id)).map(|(q, _)| *q)?;
        st.perms.remove(&q);
        Some(EINTR)
    });
    match r {
        Some(v) => {
            let _ = sys::lx_complete(id, v);
            true
        }
        None => false,
    }
}

/// Claims the inotify/fanotify calls (`notify=0` among the arguments: they stay the
/// kernel's); how many.
pub fn claim(args: &[&str]) -> usize {
    if args.iter().any(|a| *a == "notify=0") {
        return 0;
    }
    [253u64, 294, 300, 254, 255, 301].iter().filter(|&&nr| sys::lx_obj(crate::proto::LX_FH_CLAIM, nr, 1, 0).is_ok()).count()
}

/// Counters for the admin shell and the tests: `(instances, watches, groups, marks,
/// events, questions)`.
pub fn counts() -> (usize, usize, usize, usize, u64, u64) {
    let (a, b, c, d) = ST.lock().as_ref().map_or((0, 0, 0, 0), |s| {
        (s.inos.len(), s.inos.values().map(|i| i.watches.len()).sum(), s.fans.len(), s.fans.values().map(|g| g.inodes.len() + g.mount.is_some() as usize + g.filesystem.is_some() as usize).sum())
    });
    (a, b, c, d, EVENTS.load(Ordering::Relaxed), QUESTIONS.load(Ordering::Relaxed))
}
