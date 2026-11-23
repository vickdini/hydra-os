//! # File events for vfs-server's inotify and fanotify (wave 9, Group 6b-1)
//!
//! vfs-server owns the inotify instances and fanotify groups while it is forwarded
//! (`userland/drivers/vfs-server/src/notify`). The changes it makes itself come with their
//! events in its zfs-server replies; this module hands it the events of what the kernel
//! does: the zfs events of the kernel's own requests (writes, the close-write event,
//! creating opens, calls the kernel kept), the events of open files (`FAN_ACCESS`,
//! `FAN_MODIFY`, `FAN_CLOSE_*`, `FAN_OPEN`) and the permission events of the kernel's opens.
//!
//! - **What vfs-server wants** is in its window: a flags word in the note ring's header
//!   ([`LX_NOTES_SVCWORD`]: `LX_NOTIFY_*`) and a map of the inodes it watches (a hash,
//!   [`LX_VFS_NOTIFY_MAP_OFF`]). Nothing is posted when the word is 0 (no watches), and an
//!   event only when its inode (or the directory of an open file) is in the map, so a
//!   desktop that watches a few directories does not pay for every write.
//! - **How:** one record per event in the note ring ([`LX_NOTE_FSEVENT`] and
//!   [`LX_NOTE_FSDATA`] entries, posted together or not at all; [`encode`] is the format).
//!   A later call carries the ring position, so vfs-server has the event before it answers
//!   a `read` made after the change; the main thread is woken for `poll` and blocked reads.
//!   A full ring drops the record (vfs-server counts the ring's drops and reports an
//!   overflow event).
//! - **Permission events** ([`on_open`]): the record carries an id, then the kernel asks
//!   with [`LX_KCALL_FANPERM`] and waits for the answer (pending in vfs-server until every
//!   group that wanted it answered).
//!
//! With `lx=kernel`, `lx.vfs=kernel` or vfs-server offline the word is not read: the
//! kernel's own `inotify.rs`/`fanotify.rs` serve as before.

use core::sync::atomic::AtomicU64;

use crate::ipc::protocol::{LX_NOTE_FSDATA, LX_NOTE_FSEVENT};
#[cfg(target_os = "uefi")]
use crate::ipc::protocol::{
    notify_hash, LXS_VFS, LX_FSEV_FILE, LX_FSEV_PERM, LX_FSEV_ZFS, LX_KCALL_FANPERM, LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF, LX_NOTES_SVCWORD, LX_NOTIFY_ALL, LX_NOTIFY_FAN, LX_NOTIFY_INO, LX_NOTIFY_PERM,
    LX_VFS_NOTIFY_MAP_OFF, NOTIFY_LX_NOTES,
};
#[cfg(target_os = "uefi")]
use super::svc::{self, Host};

const EPERM: i64 = -1;
const FAN_OPEN: u64 = 0x20;
const FAN_OPEN_EXEC: u64 = 0x1000;
const FAN_OPEN_PERM: u64 = 0x1_0000;
const FAN_OPEN_EXEC_PERM: u64 = 0x4_0000;
const FAN_ONDIR: u64 = 0x4000_0000;
/// The longest name or path a record carries (longer ones are cut).
pub const TAIL_MAX: usize = 4096;
/// Ring entries a record takes at most.
pub const MAX_ENTRIES: usize = 1 + (24 + TAIL_MAX).div_ceil(24);

/// Records posted, and records dropped because the ring was full (since boot).
pub static POSTED: AtomicU64 = AtomicU64::new(0);
/// See [`POSTED`].
pub static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Permission questions asked, and denied.
pub static PERM_ASKED: AtomicU64 = AtomicU64::new(0);
/// See [`PERM_ASKED`].
pub static PERM_DENIED: AtomicU64 = AtomicU64::new(0);
/// Permission questions posted again (ring full, record lost, vfs-server restarted).
pub static PERM_RETRIED: AtomicU64 = AtomicU64::new(0);
/// How often a permission question is posted before the open is refused.
pub const TRIES: usize = 400;
/// The id of the next permission event.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// One event to post.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ev<'a> {
    /// `LX_FSEV_*`.
    pub kind: u64,
    /// The inode (a zfs event's: the directory of an entry event).
    pub ino: u64,
    /// The event bits (inotify's for zfs events, fanotify's for file and permission events).
    pub mask: u32,
    /// A rename's cookie.
    pub cookie: u32,
    /// The directory of an open file (0: not known).
    pub dir: u64,
    /// The process and thread that caused it.
    pub pid: u32,
    /// See [`Ev::pid`].
    pub tid: u32,
    /// A permission event's id.
    pub id: u64,
    /// The entry name (zfs events) or the path (file events).
    pub tail: &'a [u8],
}

/// The ring entries of `e` (`[kind, a, b, c]` each), into `out`; returns how many (at most
/// [`MAX_ENTRIES`]; 0 if `out` is too short). The tail is cut at [`TAIL_MAX`] bytes.
pub fn encode(e: &Ev, out: &mut [[u64; 4]]) -> usize {
    let tail = &e.tail[..e.tail.len().min(TAIL_MAX)];
    let len = 24 + tail.len();
    let n = 1 + len.div_ceil(24);
    if out.len() < n {
        return 0;
    }
    out[0] = [LX_NOTE_FSEVENT, e.ino, e.mask as u64 | (e.cookie as u64) << 32, e.kind | (len as u64) << 8];
    let mut head = [0u8; 24];
    head[..8].copy_from_slice(&e.dir.to_le_bytes());
    head[8..12].copy_from_slice(&e.pid.to_le_bytes());
    head[12..16].copy_from_slice(&e.tid.to_le_bytes());
    head[16..24].copy_from_slice(&e.id.to_le_bytes());
    let byte = |i: usize| -> u8 {
        if i < 24 {
            head[i]
        } else {
            tail.get(i - 24).copied().unwrap_or(0)
        }
    };
    for (k, ent) in out[1..n].iter_mut().enumerate() {
        let mut w = [0u64; 3];
        for (j, word) in w.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            for (x, v) in b.iter_mut().enumerate() {
                *v = byte(k * 24 + j * 8 + x);
            }
            *word = u64::from_le_bytes(b);
        }
        *ent = [LX_NOTE_FSDATA, w[0], w[1], w[2]];
    }
    n
}

/// The permission event's bits of an open (`exec`: also `FAN_OPEN_EXEC_PERM`).
pub fn perm_mask(is_dir: bool, exec: bool) -> u32 {
    (if exec { FAN_OPEN_EXEC_PERM | FAN_OPEN_PERM } else { FAN_OPEN_PERM } | if is_dir { FAN_ONDIR } else { 0 }) as u32
}

/// The bits of an open file's event `mask` (`FAN_ONDIR` added for a directory).
pub fn file_mask(mask: u64, is_dir: bool) -> u32 {
    (mask | if is_dir { FAN_ONDIR } else { 0 }) as u32
}

/// The `FAN_OPEN` event bits of an open.
pub fn open_mask(exec: bool) -> u64 {
    if exec {
        FAN_OPEN_EXEC | FAN_OPEN
    } else {
        FAN_OPEN
    }
}

/// The directory part of absolute path `path` (`None`: not absolute).
pub fn dir_of(path: &str) -> Option<&str> {
    match path.rfind('/') {
        Some(0) => Some("/"),
        Some(i) => Some(&path[..i]),
        None => None,
    }
}

#[cfg(target_os = "uefi")]
mod live {
    use super::*;
    use core::sync::atomic::Ordering;

    /// vfs-server's host and its notify word, when it serves inotify/fanotify and wants
    /// events.
    #[inline]
    pub(super) fn host_word() -> Option<(&'static Host, u64)> {
        // (wave9 G9-C: the file service is always forwarded, also with `lx=kernel`)
        let x = svc::host(svc::host_of(LXS_VFS))?;
        let base = x.notes.load(Ordering::Acquire);
        if base == 0 {
            return None;
        }
        // SAFETY: the ring's header lies in the host's mapped window; vfs-server writes the word
        let w = unsafe { core::ptr::read_volatile((base as *const u64).add(LX_NOTES_SVCWORD)) };
        if w == 0 {
            None
        } else {
            Some((x, w))
        }
    }

    /// Whether inode `ino` is in host `x`'s watched-inode map.
    fn in_map(x: &Host, ino: u64) -> bool {
        let base = x.notes.load(Ordering::Acquire);
        if base == 0 || ino == 0 {
            return false;
        }
        let bit = notify_hash(ino);
        let map = base - LX_NOTES_OFF as u64 + LX_VFS_NOTIFY_MAP_OFF as u64;
        // SAFETY: the map lies in the host's mapped window (`notify_hash` < its bits)
        let byte = unsafe { core::ptr::read_volatile((map + (bit / 8) as u64) as *const u8) };
        byte & (1 << (bit % 8)) != 0
    }

    /// Whether an event on `ino` (in directory `dir`) may be wanted with word `w`.
    pub(super) fn wanted(x: &Host, w: u64, ino: u64, dir: u64) -> bool {
        w & LX_NOTIFY_ALL != 0 || in_map(x, ino) || (dir != 0 && in_map(x, dir))
    }

    /// Posts `e` to host `x`'s ring (all its entries or none) and wakes its main thread.
    pub(super) fn post(x: &Host, e: &Ev) -> bool {
        let mut ents = [[0u64; 4]; MAX_ENTRIES];
        let n = encode(e, &mut ents);
        let base = x.notes.load(Ordering::Acquire);
        if base == 0 || n == 0 {
            return false;
        }
        let ok = x86_64::instructions::interrupts::without_interrupts(|| {
            let _g = x.notes_lock.lock();
            let w = base as *mut u64;
            // SAFETY: the ring (header and entries) lies in the host's 256 KiB window
            unsafe {
                let head = core::ptr::read_volatile(w);
                let tail = core::ptr::read_volatile(w.add(1));
                if head.wrapping_sub(tail) + n as u64 > LX_NOTES {
                    let d = core::ptr::read_volatile(w.add(2));
                    core::ptr::write_volatile(w.add(2), d + 1);
                    return false;
                }
                for (k, ent) in ents[..n].iter().enumerate() {
                    let p = (base + (LX_NOTES_ENTRY_OFF - LX_NOTES_OFF) as u64 + ((head + k as u64) % LX_NOTES) * 32) as *mut u64;
                    for (j, v) in ent.iter().enumerate() {
                        core::ptr::write_volatile(p.add(j), *v);
                    }
                }
                core::sync::atomic::fence(Ordering::Release);
                core::ptr::write_volatile(w, head + n as u64);
                x.notes_head.store(head + n as u64, Ordering::Release);
            }
            true
        });
        if ok {
            POSTED.fetch_add(1, Ordering::Relaxed);
            crate::ipc::service::notify(x.endpoint.load(Ordering::Relaxed), NOTIFY_LX_NOTES);
        } else {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// `(tid, pid)` of the current task, as u32.
    pub(super) fn ids() -> (u32, u32) {
        let (tid, pid) = crate::compat::linux::proc::current_ids();
        (tid as u32, pid as u32)
    }

    /// See the public [`super::zfs_event`].
    pub(super) fn zfs_event(ino: u64, mask: u32, cookie: u32, name: &[u8]) {
        let Some((x, w)) = host_word() else { return };
        if !wanted(x, w, ino, 0) {
            return;
        }
        let (tid, pid) = ids();
        post(x, &Ev { kind: LX_FSEV_ZFS, ino, mask, cookie, dir: 0, pid, tid, id: 0, tail: name });
    }

    /// See the public [`super::file_event`].
    pub(super) fn file_event(ino: u64, dir: u64, path: &str, mask: u64, is_dir: bool) {
        let Some((x, w)) = host_word() else { return };
        if w & LX_NOTIFY_FAN == 0 || !wanted(x, w, ino, dir) {
            return;
        }
        let (tid, pid) = ids();
        post(x, &Ev { kind: LX_FSEV_FILE, ino, mask: file_mask(mask, is_dir), cookie: 0, dir, pid, tid, id: 0, tail: path.as_bytes() });
    }

    /// See the public [`super::on_open`].
    pub(super) fn on_open(ino: u64, dir: u64, path: &str, is_dir: bool, exec: bool) -> Result<(), i64> {
        let Some((x, w)) = host_word() else { return Ok(()) };
        if w & LX_NOTIFY_FAN == 0 || !wanted(x, w, ino, dir) {
            return Ok(());
        }
        if w & LX_NOTIFY_PERM != 0 {
            ask(ino, dir, path, is_dir, exec)?;
        }
        file_event(ino, dir, path, open_mask(exec), is_dir);
        Ok(())
    }

    /// The permission question of an open: `Ok` only for an explicit allow (or when no
    /// group with a permission mark is left: Linux allows when the group is gone),
    /// `Err(EPERM)` denied, `Err(EINTR)` a signal while waiting. A record lost to a full
    /// ring or a vfs-server restart is posted again; a restarting vfs-server is waited for.
    fn ask(ino: u64, dir: u64, path: &str, is_dir: bool, exec: bool) -> Result<(), i64> {
        const EINTR: i64 = -4;
        const EAGAIN: i64 = -11;
        const ERESTARTSYS: i64 = -512;
        let vfs_online = || svc::host(svc::host_of(LXS_VFS)).is_some_and(|x| x.is_online());
        for _ in 0..TRIES {
            if !vfs_online() && crate::lx::restart::restarting(LXS_VFS) {
                let _ = crate::lx::restart::wait_online(LXS_VFS, &vfs_online);
            }
            // (no group with a permission mark wants this open any more: allowed)
            let Some((x, w)) = host_word() else { return Ok(()) };
            if w & LX_NOTIFY_PERM == 0 || !wanted(x, w, ino, dir) {
                return Ok(());
            }
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let (tid, pid) = ids();
            if !post(x, &Ev { kind: LX_FSEV_PERM, ino, mask: perm_mask(is_dir, exec), cookie: 0, dir, pid, tid, id, tail: path.as_bytes() }) {
                // (the ring is full: room comes as vfs-server takes its notes)
                PERM_RETRIED.fetch_add(1, Ordering::Relaxed);
                crate::task::sleep_ms(5);
                continue;
            }
            PERM_ASKED.fetch_add(1, Ordering::Relaxed);
            match crate::lx::call_plain(LX_KCALL_FANPERM, [id, 0, 0, 0, 0, 0]) {
                0 => return Ok(()),
                EPERM => {
                    PERM_DENIED.fetch_add(1, Ordering::Relaxed);
                    return Err(EPERM);
                }
                EINTR | ERESTARTSYS => return Err(EINTR),
                // (the record was lost: asked again)
                EAGAIN => PERM_RETRIED.fetch_add(1, Ordering::Relaxed),
                // (vfs-server went away meanwhile: its new instance is asked)
                _ => {
                    PERM_RETRIED.fetch_add(1, Ordering::Relaxed);
                    crate::task::sleep_ms(10);
                    0
                }
            };
        }
        // (never answered: refused rather than let through)
        PERM_DENIED.fetch_add(1, Ordering::Relaxed);
        Err(EPERM)
    }

    /// The `LX_NOTIFY_*` bits.
    pub(super) fn bits() -> u64 {
        host_word().map_or(0, |(_, w)| w)
    }

    /// See [`super::want_zfs`].
    pub(super) const ZFS: u64 = LX_NOTIFY_INO | LX_NOTIFY_FAN;
    /// See [`super::want_close_write`].
    pub(super) const INO: u64 = LX_NOTIFY_INO;
    /// See [`super::want_fan`].
    pub(super) const FAN: u64 = LX_NOTIFY_FAN;
}

/// The `LX_NOTIFY_*` bits vfs-server wants now (0: none, or vfs-server not serving them).
#[inline]
pub fn bits() -> u64 {
    #[cfg(target_os = "uefi")]
    return live::bits();
    #[cfg(not(target_os = "uefi"))]
    0
}

/// Whether zfs events are wanted at all (the kernel decodes its replies' events then).
#[inline]
pub fn want_zfs() -> bool {
    #[cfg(target_os = "uefi")]
    return bits() & live::ZFS != 0;
    #[cfg(not(target_os = "uefi"))]
    false
}

/// Whether the close-write event is to be asked of zfs-server (inotify watches exist).
#[inline]
pub fn want_close_write() -> bool {
    #[cfg(target_os = "uefi")]
    return bits() & live::INO != 0;
    #[cfg(not(target_os = "uefi"))]
    false
}

/// Whether fanotify groups exist (open files' events are wanted; opens compute the
/// directory of the file).
#[inline]
pub fn want_fan() -> bool {
    #[cfg(target_os = "uefi")]
    return bits() & live::FAN != 0;
    #[cfg(not(target_os = "uefi"))]
    false
}

/// A zfs event of a request the kernel made (`fs/zfs/mod.rs`): handed to vfs-server if its
/// inode is watched.
pub fn zfs_event(ino: u64, mask: u32, cookie: u32, name: &[u8]) {
    #[cfg(target_os = "uefi")]
    live::zfs_event(ino, mask, cookie, name);
    #[cfg(not(target_os = "uefi"))]
    let _ = (ino, mask, cookie, name);
}

/// An event on an open file (`fs/fd.rs`): `FAN_ACCESS`, `FAN_MODIFY`, `FAN_CLOSE_*`.
pub fn file_event(ino: u64, dir: u64, path: &str, mask: u64, is_dir: bool) {
    #[cfg(target_os = "uefi")]
    live::file_event(ino, dir, path, mask, is_dir);
    #[cfg(not(target_os = "uefi"))]
    let _ = (ino, dir, path, mask, is_dir);
}

/// The kernel opens `ino` (in directory `dir`, as `path`): the permission events vfs-server's
/// groups want are answered first (`Err(EPERM)`: denied), then `FAN_OPEN` (and
/// `FAN_OPEN_EXEC`) is posted.
pub fn on_open(ino: u64, dir: u64, path: &str, is_dir: bool, exec: bool) -> Result<(), i64> {
    #[cfg(target_os = "uefi")]
    return live::on_open(ino, dir, path, is_dir, exec);
    #[cfg(not(target_os = "uefi"))]
    {
        let _ = (ino, dir, path, is_dir, exec, EPERM, &NEXT_ID);
        Ok(())
    }
}

/// The directory of absolute path `path` (0 if it cannot be found), for an open's file
/// events when fanotify groups exist.
pub fn parent_of(path: &str) -> u64 {
    let Some(dir) = dir_of(path) else { return 0 };
    #[cfg(target_os = "uefi")]
    return crate::compat::linux::vfs::resolve(0, dir.as_bytes(), true).unwrap_or(0);
    #[cfg(not(target_os = "uefi"))]
    {
        let _ = dir;
        0
    }
}
