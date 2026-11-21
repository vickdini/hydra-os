//! # Path calls and the kernel's file handles (wave 7, Group 7-2)
//!
//! The file service (`vfs-server`, `LXS_VFS`) answers the path calls (`open`, the `stat`
//! family, `access`, `readlink`, creates, removes, `rename`, links, attribute changes,
//! xattrs) and the metadata calls on open files and directories (`getdents64`, `ftruncate`,
//! `fchmod`, `fsync`, ...). The kernel keeps the descriptor table as a table of handles
//! (`docs/vfs-design.md`, section 7):
//!
//! - **A handle is the kernel's `FileDescriptor::Vnode`** ([`crate::fs::OpenFile`]): the pool
//!   object (= the page-cache object), the offset or `getdents64` cookie, the open flags, the
//!   mount and the path `/proc/self/fd` shows. vfs-server keeps no per-open state: it makes
//!   a handle with [`LX_FH_INSTALL`] and forgets it, and each call on a handle carries the
//!   handle's data ([`LxCall::at_ino`], [`LxCall::fh_off`], [`LxCall::fh_flags`]). Reads,
//!   `lseek`, `mmap`, `fstat`, writes, `close`, `dup`, `fcntl` and `poll` stay in the kernel;
//!   they work while vfs-server is down. The kernel's own opens make the same kind.
//! - **The caller's context** comes with each call: root and current directory (inode and
//!   mount, from the descriptor table), the umask, the directory descriptors of `*at` calls
//!   ([`LxCall::at_kind`]), namespaces ([`super::T_FSCTX`]) and the state the service cannot
//!   see ([`LxCall::fs_flags`]: Landlock, fanotify, inotify, ABAC, foreign roots, mounts).
//! - **Claims:** a call goes to vfs-server only once vfs-server claimed its number
//!   ([`LX_FH_CLAIM`]), so calls move one by one; the rest stay in the kernel.
//! - **Redirect to the kernel:** vfs-server answers a call it does not serve (yet) with
//!   [`LX_REPLY_REDIRECT`] to service 0, and the kernel's own code answers it in the same
//!   trap. That is safe because both work on the same pool and keep each other's caches
//!   current:
//!   - vfs-server tells the kernel what it changed ([`LX_FH_CHANGED`]: names, attributes,
//!     truncations for the page cache);
//!   - the kernel tells vfs-server what it changed ([`kernel_changed`] posts
//!     [`LX_NOTE_FSCHANGE`] to vfs-server's ring, which a worker takes before its next call).
//! - **vfs-server not online** (not started, crashed, `lx.vfs=kernel`, `lx=kernel`): the
//!   kernel answers every call itself.
//!
//! [`LX_REPLY_REDIRECT`]: crate::ipc::protocol::LX_REPLY_REDIRECT

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::svc::{self, Host};
use super::{SyscallFrame, T_FSCTX, T_SERVER, T_SVC_SHIFT, T_UMASK};
use crate::fs::fd::OpenFile;
use crate::fs::{FdTable, FileDescriptor};
use crate::ipc::protocol::{
    LxCall, LxFhDesc, LxFhInfo, SvcId, LXS_VFS, LX_AT_CWD, LX_AT_DIR, LX_AT_FILE, LX_AT_OTHER, LX_FHC_ALL_ATTRS, LX_FHC_ATTR, LX_FHC_GONE, LX_FHC_NAMES, LX_FHC_TRUNC, LX_FHP_ABS, LX_FHP_AT,
    LX_FHP_CWD, LX_FH_CHANGED, LX_FH_CHDIR, LX_FH_CHROOT, LX_FH_CLAIM, LX_FH_REROOT, LX_FH_INFO, LX_FH_INSTALL, LX_FH_PATH_MAX, LX_FH_SEEK, LX_FS_ABAC, LX_FS_FANOTIFY, LX_FS_FOREIGN, LX_FS_INOTIFY, LX_FS_LANDLOCK,
    LX_FS_MOUNTS, LX_NOTE_FSCHANGE,
};
use crate::task::TaskId;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

const AT_FDCWD: i32 = -100;
const O_CLOEXEC: u32 = 0o2000000;
/// The open flags a handle keeps (as the kernel's `open` does).
const KEEP: u32 = 0o3 | 0o2000 | 0o4000 | 0o200000 | 0o10000000;

/// Entry bit: a file-service call ([`shape`] says where its descriptors are). Bit 31 (bits
/// 16..30 are `T_BYARG`'s, reserved).
pub const T_VFS: u32 = 1 << 31;

/// A result only the forwarding code sees: the service redirected the call to the kernel.
pub(super) const LX_TO_KERNEL: i64 = -4102;

/// Where a call's descriptor and path arguments are.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Shape {
    /// Paths only (relative ones start at the current directory).
    Path,
    /// `args[0]` is a directory descriptor (`AT_FDCWD`: the current directory).
    At0,
    /// `args[0]` and `args[2]` are directory descriptors (`renameat`, `linkat`).
    At0At2,
    /// `args[1]` is the directory descriptor (`symlinkat`).
    At1,
    /// `args[0]` is a descriptor the call acts on: only a handle goes to the service.
    Handle,
}

/// The file-service calls and their shapes (x86-64 Linux numbers).
pub fn shape(nr: u64) -> Option<Shape> {
    Some(match nr {
        // open, creat, stat, lstat, access, readlink, mkdir, mknod, unlink, rmdir, rename,
        // link, symlink, chmod, chown, lchown, utime, utimes, truncate, the xattrs by path,
        // statfs, chdir; chroot (161, wave7 G7-3)
        2 | 85 | 4 | 6 | 21 | 89 | 83 | 133 | 87 | 84 | 82 | 86 | 88 | 90 | 92 | 94 | 132 | 235 | 76 | 188 | 189 | 191 | 192 | 194 | 195 | 197 | 198 | 137 | 80 | 161 => Shape::Path,
        // openat, openat2, newfstatat, statx, faccessat, faccessat2, readlinkat, mkdirat,
        // mknodat, unlinkat, fchmodat, fchmodat2, fchownat, futimesat, utimensat
        257 | 437 | 262 | 332 | 269 | 439 | 267 | 258 | 259 | 263 | 268 | 452 | 260 | 261 | 280 => Shape::At0,
        // renameat, renameat2, linkat
        264 | 316 | 265 => Shape::At0At2,
        // symlinkat
        266 => Shape::At1,
        // getdents64, getdents, ftruncate, fchmod, fchown, fsync, fdatasync, fallocate,
        // fsetxattr, fgetxattr, flistxattr, fremovexattr, fstatfs, fchdir, sync_file_range
        217 | 78 | 77 | 91 | 93 | 74 | 75 | 285 | 190 | 193 | 196 | 199 | 138 | 81 | 277 => Shape::Handle,
        _ => return None,
    })
}

// ----------------------------------------------------------------------
// Claims and the routing entries
// ----------------------------------------------------------------------

/// The numbers vfs-server claimed (bit `nr`), below the table's 512.
static CLAIMED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// Whether moved calls are routed at all (`lx=kernel` turns it off): set by `set_forwarding`.
static ROUTING: AtomicBool = AtomicBool::new(false);

/// Whether vfs-server claimed call `nr`.
pub fn claimed(nr: u64) -> bool {
    nr < 512 && CLAIMED[nr as usize / 64].load(Ordering::Acquire) & (1 << (nr % 64)) != 0
}

/// The routing entry of file-service call `nr` (0: the kernel answers it).
pub fn entry_for(nr: u64, routing: bool, forward_mode: bool) -> u32 {
    if routing && forward_mode && shape(nr).is_some() && claimed(nr) {
        T_SERVER | T_VFS | T_FSCTX | T_UMASK | (LXS_VFS as u32) << T_SVC_SHIFT
    } else {
        0
    }
}

/// Serializes [`apply`] and [`claim`] (the routing switch and the claims change together).
static APPLY: Mutex<()> = Mutex::new(());

/// Writes the routing entries of every file-service number (`set_forwarding` and a claim).
pub fn apply(on: bool) {
    let _g = APPLY.lock();
    apply_locked(on);
}

fn apply_locked(on: bool) {
    ROUTING.store(on, Ordering::Release);
    let fwd = svc::mode(LXS_VFS) == svc::SvcMode::Forward;
    for nr in 0..512u64 {
        if shape(nr).is_some() {
            super::TABLE[nr as usize].store(entry_for(nr, on, fwd), Ordering::Release);
        }
    }
}

/// [`LX_FH_CLAIM`]: `(nr, on)`.
fn claim(nr: u64, on: bool) -> i64 {
    if shape(nr).is_none() {
        return EINVAL;
    }
    let bit = 1u64 << (nr % 64);
    let _g = APPLY.lock();
    if on {
        CLAIMED[nr as usize / 64].fetch_or(bit, Ordering::AcqRel);
    } else {
        CLAIMED[nr as usize / 64].fetch_and(!bit, Ordering::AcqRel);
    }
    apply_locked(ROUTING.load(Ordering::Acquire));
    0
}

// ----------------------------------------------------------------------
// The call's context
// ----------------------------------------------------------------------

/// What one descriptor argument is: kind (`LX_AT_*`), inode, mount, offset, open flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AtInfo {
    /// `LX_AT_*`.
    pub kind: u32,
    /// The pool object.
    pub ino: u64,
    /// Its mount.
    pub mnt: u32,
    /// The handle's offset.
    pub off: u64,
    /// The handle's open flags.
    pub flags: u32,
}

/// Whether inode `ino` is a plain pool object the service can walk from (not a FUSE file,
/// not the kernel's markers for an empty root or a `/proc` directory).
pub fn plain_ino(ino: u64) -> bool {
    ino >> 62 == 0 && ino < u64::MAX - 1
}

/// Whether `path` (as the kernel shows it) lies where the kernel serves files by name
/// (`/proc`, `/sys`, `/dev`): lookups relative to it are the kernel's until those trees
/// are served by their services (group 7-4).
pub fn pseudo_path(path: &str) -> bool {
    ["/proc", "/sys", "/dev"].iter().any(|d| path.strip_prefix(d).is_some_and(|r| r.is_empty() || r.starts_with('/')))
}

/// The handle data of an open file: `None` when it is not a plain pool object (opened
/// through another process's root, a FUSE file).
pub fn info_of_open(f: &OpenFile) -> Option<AtInfo> {
    // (the `/proc` directory of the pool is served by name: the kernel lists it)
    if f.foreign.is_some() || !plain_ino(f.ino) || f.path.ends_with("/proc") || pseudo_path(&f.path) {
        return None;
    }
    Some(AtInfo { kind: if f.is_dir { LX_AT_DIR } else { LX_AT_FILE }, ino: f.ino, mnt: f.mnt as u32, off: f.offset, flags: f.flags })
}

/// What descriptor `fd` of table `t` is for a file-service call, and the open file to hold
/// while the call is in flight. `wait`: lock the open file (under the kernel lock); else
/// only try (the lock-free path: a reader may hold it across a zfs-server request):
/// `Err(())` then.
fn at_of(t: &FdTable, fd: u64, wait: bool) -> Result<(AtInfo, Option<Arc<Mutex<OpenFile>>>), ()> {
    if fd as i32 == AT_FDCWD {
        return Ok((AtInfo { kind: LX_AT_CWD, ..AtInfo::default() }, None));
    }
    let other = AtInfo { kind: LX_AT_OTHER, ..AtInfo::default() };
    if (fd as i32) < 0 {
        return Ok((other, None));
    }
    match t.get(fd as i32 as usize) {
        Some(FileDescriptor::Vnode(f)) => {
            let g = if wait { Some(f.lock()) } else { f.try_lock() };
            let Some(g) = g else { return Err(()) };
            match info_of_open(&g) {
                Some(i) => {
                    drop(g);
                    Ok((i, Some(f.clone())))
                }
                None => Ok((other, None)),
            }
        }
        _ => Ok((other, None)),
    }
}

/// The open files a call holds while it is in flight (a `close` on another thread cannot
/// release the object under it).
pub(super) type Held = [Option<Arc<Mutex<OpenFile>>>; 2];

/// The state of the caller the service cannot see (`LX_FS_*`), apart from the table.
/// (`pub(super)`: wave7 G7-5's `xexec` fills the same context.)
pub(super) fn fs_flags_global(c: &LxCall) -> u32 {
    use crate::compat::linux as l;
    let mut f = 0;
    if l::landlock::active() {
        f |= LX_FS_LANDLOCK;
    }
    if l::fanotify::active() {
        f |= LX_FS_FANOTIFY;
    }
    if l::inotify::active() {
        f |= LX_FS_INOTIFY;
    }
    if l::abac::active() {
        f |= LX_FS_ABAC;
    }
    if c.mnt_ns != 0 || l::fuse::ns0_any() {
        f |= LX_FS_MOUNTS;
    }
    f
}

/// Fills call `c` (number `nr` of shape `sh`) with the caller's file context from its
/// descriptor table `t`. `Ok(None)`: the kernel answers (a call on a descriptor that is not a
/// handle); `Err(())`: a lock was busy (only when `!wait`).
pub(super) fn fill(c: &mut LxCall, t: &FdTable, sh: Shape, wait: bool) -> Result<Option<Held>, ()> {
    c.root = t.root_ino;
    c.root_mnt = t.root_mnt as u32;
    c.cwd = t.cwd_ino;
    c.cwd_mnt = t.cwd_mnt as u32;
    c.umask = t.umask as u64;
    if !plain_ino(t.root_ino) || !plain_ino(t.cwd_ino) || pseudo_path(&t.cwd_path) || t.cwd_path.ends_with("/proc") {
        c.fs_flags |= LX_FS_FOREIGN;
    }
    let mut held: Held = [None, None];
    let (first, second) = match sh {
        Shape::Path => (None, None),
        Shape::At0 | Shape::Handle => (Some(c.args[0]), None),
        Shape::At0At2 => (Some(c.args[0]), Some(c.args[2])),
        Shape::At1 => (Some(c.args[1]), None),
    };
    if let Some(fd) = first {
        let (i, h) = at_of(t, fd, wait)?;
        // (a call on an O_PATH descriptor is the kernel's: it decides what such a one may do)
        if sh == Shape::Handle && (!matches!(i.kind, LX_AT_FILE | LX_AT_DIR) || i.flags & 0o10000000 != 0) {
            return Ok(None);
        }
        c.at_kind = i.kind;
        c.at_ino = i.ino;
        c.at_mnt = i.mnt;
        c.fh_off = i.off;
        c.fh_flags = i.flags;
        held[0] = h;
    }
    if let Some(fd) = second {
        let (i, h) = at_of(t, fd, wait)?;
        c.at2_kind = i.kind;
        c.at2_ino = i.ino;
        c.at2_mnt = i.mnt;
        held[1] = h;
    }
    Ok(Some(held))
}

// ----------------------------------------------------------------------
// Calls vfs-server would send straight back
// ----------------------------------------------------------------------

/// The `LX_FS_*` bits with which vfs-server sends call `nr` back to the kernel whatever
/// its arguments (`calls/ctxt.rs` `check` and the calls' own masks): the kernel then answers
/// at once, without the round trip. vfs-server checks them again.
pub fn kernel_mask(nr: u64) -> u32 {
    let always = LX_FS_FOREIGN | LX_FS_MOUNTS;
    always
        | match nr {
            // access, faccessat, faccessat2: ABAC may take away what the modes allow
            21 | 269 | 439 => LX_FS_ABAC,
            // getdents64, getdents
            217 | 78 => LX_FS_FANOTIFY,
            // open, openat (and creat, openat2 if claimed)
            2 | 257 | 85 | 437 => LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC,
            // the changes: their events and checks are the kernel's
            90 | 268 | 452 | 91 | 92 | 94 | 260 | 93 | 76 | 77 | 280 | 132 | 235 | 261 | 83 | 258 | 133 | 259 | 88 | 266 | 87 | 84 | 263 | 82 | 264 | 316 | 86 | 265 | 188
            | 189 | 190 | 197 | 198 | 199 => LX_FS_INOTIFY | LX_FS_FANOTIFY | LX_FS_LANDLOCK | LX_FS_ABAC,
            _ => 0,
        }
}

/// Calls the kernel kept because of each `LX_FS_*` bit (bit `i`: `KEPT_BY[i]`).
pub static KEPT_BY: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

/// Whether call `c` is the kernel's at once (counted by reason).
fn kernel_only(c: &LxCall) -> bool {
    let hit = c.fs_flags & kernel_mask(c.nr);
    let mounts = c.root_mnt != 0 || c.cwd_mnt != 0;
    if hit == 0 && !mounts {
        return false;
    }
    for (i, k) in KEPT_BY.iter().enumerate() {
        if hit & (1 << i) != 0 {
            k.fetch_add(1, Ordering::Relaxed);
        }
    }
    KEPT.fetch_add(1, Ordering::Relaxed);
    true
}

// ----------------------------------------------------------------------
// Forwarding (both paths)
// ----------------------------------------------------------------------

/// Per CPU: `(thread, number)` of a call the lock-free path found redirected to the kernel:
/// the ordinary path then does not forward it again.
static TO_KERNEL: [(AtomicU64, AtomicU64); crate::arch::smp::MAX_CPUS] = [const { (AtomicU64::new(0), AtomicU64::new(0)) }; crate::arch::smp::MAX_CPUS];

/// Calls vfs-server answered, redirected to the kernel, and calls on non-handles or with
/// the service offline that the kernel kept (since boot).
pub static SERVED: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL_CALLS: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static KEPT: AtomicU64 = AtomicU64::new(0);

/// The host serving the file service now, if it is online.
fn vfs_host() -> Option<&'static Host> {
    svc::host(svc::host_of(LXS_VFS)).filter(|x| x.is_online())
}

/// Takes this CPU's mark for (`tid`, `nr`), if it is there.
fn take_mark(tid: u64, nr: u64) -> bool {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    let m = &TO_KERNEL[cpu];
    if tid != 0 && m.0.load(Ordering::Relaxed) == tid {
        m.0.store(0, Ordering::Relaxed);
        return m.1.load(Ordering::Relaxed) == nr;
    }
    false
}

fn set_mark(tid: u64, nr: u64) {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    TO_KERNEL[cpu].1.store(nr, Ordering::Relaxed);
    TO_KERNEL[cpu].0.store(tid, Ordering::Relaxed);
}

/// What a forwarded call's result means for the dispatcher: `None` the kernel answers it.
fn outcome(r: i64) -> Option<i64> {
    if r == LX_TO_KERNEL {
        TO_KERNEL_CALLS.fetch_add(1, Ordering::Relaxed);
        None
    } else {
        SERVED.fetch_add(1, Ordering::Relaxed);
        Some(r)
    }
}

/// The ordinary path (under the kernel lock) for a call whose entry has [`T_VFS`]:
/// `None` the kernel's dispatcher answers it.
pub(super) fn forward(frame: &SyscallFrame) -> Option<i64> {
    let nr = frame.rax;
    let tid = crate::task::CURRENT_TID.load(Ordering::Relaxed);
    if take_mark(tid, nr) {
        return None;
    }
    let sh = shape(nr)?;
    let Some(x) = vfs_host() else {
        KEPT.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.svc = LXS_VFS as u32;
    c.tgid = crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(0);
    super::fill_ctx(&mut c, true);
    let held = crate::task::with_current_fds_mut(|t| fill(&mut c, t, sh, true));
    let held = match held {
        Ok(Some(h)) => h,
        _ => {
            KEPT.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };
    c.fs_flags |= fs_flags_global(&c);
    if kernel_only(&c) {
        return None;
    }
    let r = super::call_ident_raw(x, c, true);
    drop(held);
    outcome(r)
}

/// The lock-free path (interrupts off, no kernel lock) for a call whose entry has
/// [`T_VFS`]: `None` the ordinary path takes it (a busy lock, the service offline, the
/// kernel answers).
pub(super) fn fast(id: &super::Ident, frame: &SyscallFrame) -> Option<i64> {
    let nr = frame.rax;
    let sh = shape(nr)?;
    let x = vfs_host()?;
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.tid = id.tid;
    c.tgid = id.tgid;
    [c.uid, c.euid, c.suid, c.gid, c.egid, c.sgid] = id.ids;
    c.caps = id.caps;
    c.svc = LXS_VFS as u32;
    c.ngroups = id.ngroups;
    c.groups = id.groups;
    if !super::fill_ctx(&mut c, false) {
        return None;
    }
    let (fds, _) = super::cached_fds(id)?;
    let r = match fds.try_lock() {
        Some(t) => fill(&mut c, &t, sh, false),
        None => Err(()),
    };
    super::drop_last(fds);
    let held = match r {
        Ok(Some(h)) => h,
        // A call on a descriptor that is not a handle: the kernel, without asking again
        Ok(None) => {
            KEPT.fetch_add(1, Ordering::Relaxed);
            set_mark(id.tid, nr);
            return None;
        }
        Err(()) => return None,
    };
    c.fs_flags |= fs_flags_global(&c);
    if kernel_only(&c) {
        for h in held.into_iter().flatten() {
            super::drop_last(h);
        }
        set_mark(id.tid, nr);
        return None;
    }
    let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
    super::FAST_CALLS.fetch_add(1, Ordering::Relaxed);
    let r = super::call_with(x, id.tid, idx, c, true);
    for h in held.into_iter().flatten() {
        super::drop_last(h);
    }
    match outcome(r) {
        Some(r) => Some(r),
        None => {
            set_mark(id.tid, nr);
            None
        }
    }
}

// ----------------------------------------------------------------------
// The kernel's changes, for vfs-server's caches
// ----------------------------------------------------------------------

/// Notes posted to vfs-server since boot.
pub static NOTES: AtomicU64 = AtomicU64::new(0);

/// The kernel changed pool object `ino` (0: names, or everything): vfs-server forgets what
/// it cached of it before its next call. Not for changes vfs-server made itself (they come
/// back through [`LX_FH_CHANGED`] from its own threads).
pub fn kernel_changed(ino: u64) {
    let Some(x) = vfs_host() else { return };
    let tid = crate::task::CURRENT_TID.load(Ordering::Relaxed);
    if svc::worker_host(tid) == Some(x.id) || super::server_caller().is_ok_and(|(_, _, h)| h == x.id) {
        return;
    }
    if super::note_quiet_to(x, LX_NOTE_FSCHANGE, ino, 0, 0) {
        NOTES.fetch_add(1, Ordering::Relaxed);
    }
}

// ----------------------------------------------------------------------
// The service's operations (`SYS_LX_OBJ`, ops 32..)
// ----------------------------------------------------------------------

/// Joins `base` (an absolute path) and `path` and removes `.`, `..` and repeated slashes
/// (lexically, as the shown path of a descriptor). An absolute `path` ignores `base`.
pub fn join_path(base: &str, path: &[u8]) -> String {
    let mut parts: Vec<&[u8]> = Vec::new();
    let abs = path.first() == Some(&b'/');
    let start: &[u8] = if abs { b"" } else { base.as_bytes() };
    for p in start.split(|&b| b == b'/').chain(path.split(|&b| b == b'/')) {
        match p {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = String::with_capacity(path.len() + base.len() + 1);
    for p in &parts {
        out.push('/');
        out.push_str(&String::from_utf8_lossy(p));
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// The shown path of descriptor `d` for the caller with table `t`.
fn shown_path(t: &FdTable, d: &LxFhDesc) -> Result<String, i64> {
    let n = (d.path_len as usize).min(LX_FH_PATH_MAX);
    let p = &d.path[..n];
    match d.path_kind {
        LX_FHP_ABS => Ok(join_path("/", p)),
        LX_FHP_CWD => Ok(join_path(&t.cwd_path, p)),
        LX_FHP_AT => match t.get(d.at_fd as usize) {
            _ if d.at_fd < 0 => Err(EBADF),
            Some(FileDescriptor::Vnode(f)) => {
                let base = f.lock().path.clone();
                Ok(join_path(&base, p))
            }
            Some(FileDescriptor::File { path, .. }) => Ok(join_path(path, p)),
            Some(_) => Ok(join_path("/", p)),
            None => Err(EBADF),
        },
        _ => Err(EINVAL),
    }
}

/// The descriptor table of request `id`'s caller.
fn client_fds(id: u64) -> Result<crate::fs::SharedFdTable, i64> {
    let client = super::client_of(id).ok_or(ESRCH)?;
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()).ok_or(ESRCH)
}

/// Reads an `LxFhDesc` from the service's memory at `ptr`.
fn read_desc(ptr: u64) -> Result<LxFhDesc, i64> {
    let raw = crate::compat::linux::vfs::copy_in(ptr, core::mem::size_of::<LxFhDesc>()).map_err(|_| EFAULT)?;
    // SAFETY: `raw` holds exactly one `LxFhDesc` (plain integers and bytes)
    Ok(unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const LxFhDesc) })
}

/// Makes the handle `d` names in table `t`: returns the descriptor.
pub fn install_in(t: &mut FdTable, d: &LxFhDesc) -> Result<usize, i64> {
    if !plain_ino(d.ino) {
        return Err(EINVAL);
    }
    let path = shown_path(t, d)?;
    let file = OpenFile::new(d.ino, d.flags & KEEP, path);
    {
        let mut f = file.lock();
        f.mnt = d.mnt as usize;
        f.is_dir = d.is_dir != 0;
    }
    let fd = t.alloc_fd(FileDescriptor::Vnode(file)).map_err(|_| EMFILE)?;
    t.set_cloexec(fd, d.flags & O_CLOEXEC != 0);
    Ok(fd)
}

/// Makes the directory `d` names the current directory of table `t`.
pub fn chdir_in(t: &mut FdTable, d: &LxFhDesc) -> Result<(), i64> {
    if !plain_ino(d.ino) || d.is_dir == 0 {
        return Err(EINVAL);
    }
    let path = shown_path(t, d)?;
    t.cwd_ino = d.ino;
    t.cwd_mnt = d.mnt as usize;
    t.cwd_path = path;
    Ok(())
}

/// Makes the directory `d` names the root of table `t` (`chroot`; group 7-3 checks the
/// permission and the walk).
pub fn chroot_in(t: &mut FdTable, d: &LxFhDesc) -> Result<(), i64> {
    if !plain_ino(d.ino) || d.is_dir == 0 {
        return Err(EINVAL);
    }
    t.root_ino = d.ino;
    t.root_mnt = d.mnt as usize;
    Ok(())
}

/// `pivot_root` for one table: a root or current directory at `old` (inode, mount; inode 0:
/// the pool root) moves to `new`. Whether anything changed.
pub fn reroot_table(t: &mut FdTable, old: (u64, usize), new: (u64, usize)) -> bool {
    let mut changed = false;
    if t.root_ino == old.0 || t.root_ino == 0 {
        t.root_ino = new.0;
        t.root_mnt = new.1;
        changed = true;
    }
    if t.cwd_ino == old.0 || t.cwd_ino == 0 {
        t.cwd_ino = new.0;
        t.cwd_mnt = new.1;
        t.cwd_path = String::from("/");
        changed = true;
    }
    changed
}

/// [`LX_FH_REROOT`]: every process of mount namespace `ns`.
fn reroot(ns: u64, ptr: u64) -> i64 {
    let raw = match crate::compat::linux::vfs::copy_in(ptr, 32) {
        Ok(r) => r,
        Err(_) => return EFAULT,
    };
    let w = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
    let (old, new) = ((w(0), w(1) as usize), (w(2), w(3) as usize));
    if !plain_ino(new.0) {
        return EINVAL;
    }
    let pids: Vec<u64> = crate::compat::linux::proc::PROCS.lock().values().filter(|p| p.ns.mnt == ns && !p.zombie).map(|p| p.pid).collect();
    let mut n = 0;
    for pid in pids {
        let Some(fds) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()) else { continue };
        if reroot_table(&mut fds.lock(), old, new) {
            n += 1;
        }
    }
    n
}

/// Sets the offset of the handle at `fd` of table `t`.
pub fn seek_in(t: &FdTable, fd: u64, pos: u64) -> Result<(), i64> {
    match t.get(fd as i32 as usize) {
        _ if (fd as i32) < 0 => Err(EBADF),
        Some(FileDescriptor::Vnode(f)) => {
            f.lock().offset = pos;
            Ok(())
        }
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    }
}

/// The handle at `fd` of table `t`.
pub fn info_in(t: &FdTable, fd: u64) -> Result<LxFhInfo, i64> {
    match t.get(fd as i32 as usize) {
        _ if (fd as i32) < 0 => Err(EBADF),
        Some(FileDescriptor::Vnode(f)) => {
            let g = f.lock();
            Ok(match info_of_open(&g) {
                Some(i) => LxFhInfo { ino: i.ino, off: i.off, mnt: i.mnt, kind: i.kind, flags: i.flags, pad: 0 },
                None => LxFhInfo { kind: LX_AT_OTHER, ..LxFhInfo::default() },
            })
        }
        Some(_) => Ok(LxFhInfo { kind: LX_AT_OTHER, ..LxFhInfo::default() }),
        None => Err(EBADF),
    }
}

/// [`LX_FH_CHANGED`]: the kernel's caches follow a change vfs-server made.
fn changed(ino: u64, what: u64, arg: u64) -> i64 {
    if what & LX_FHC_TRUNC != 0 {
        let raw = match crate::compat::linux::vfs::copy_in(arg, 8) {
            Ok(r) => r,
            Err(_) => return EFAULT,
        };
        let size = u64::from_le_bytes(raw[..8].try_into().unwrap_or([0; 8]));
        crate::compat::linux::mm::cache_truncated(ino, size);
    }
    if what & LX_FHC_GONE != 0 {
        crate::compat::linux::mm::cache_forget(ino);
    }
    if what & LX_FHC_NAMES != 0 {
        crate::fs::zfs::forget_names();
    }
    if what & LX_FHC_ALL_ATTRS != 0 {
        crate::fs::zfs::forget_all_attrs();
    } else if what & (LX_FHC_ATTR | LX_FHC_TRUNC | LX_FHC_GONE) != 0 {
        crate::fs::zfs::forget_attr_of(ino);
    }
    0
}

/// `SYS_LX_OBJ` operations 32.. of service host `h` (called by `obj::obj_ctl`).
pub fn ctl(h: SvcId, op: u64, a: u64, b: u64, c: u64) -> i64 {
    // Only the file service's host
    if svc::host_of(LXS_VFS) != h {
        return EPERM;
    }
    let own = |id: u64| crate::ipc::protocol::lx_req_svc(id) == h || super::dcall::may_use(id);
    match op {
        LX_FH_CLAIM => claim(a, b != 0),
        LX_FH_CHANGED => changed(a, b, c),
        LX_FH_REROOT => reroot(a, b),
        LX_FH_INSTALL | LX_FH_CHDIR | LX_FH_CHROOT => {
            if !own(a) {
                return ESRCH;
            }
            let d = match read_desc(b) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let fds = match client_fds(a) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let mut t = fds.lock();
            let r = match op {
                LX_FH_INSTALL => install_in(&mut t, &d).map(|fd| fd as i64),
                LX_FH_CHDIR => chdir_in(&mut t, &d).map(|()| 0),
                _ => chroot_in(&mut t, &d).map(|()| 0),
            };
            drop(t);
            // wave7 G7-3: a chroot moves the processes sharing the caller's root (CLONE_FS)
            if op == LX_FH_CHROOT && r.is_ok() {
                if let Some(pid) = super::client_of(a).and_then(crate::compat::linux::proc::tgid_of) {
                    crate::compat::linux::vfs::chroot_peers(pid, d.ino, d.mnt as usize);
                }
            }
            r.unwrap_or_else(|e| e)
        }
        LX_FH_SEEK | LX_FH_INFO => {
            if !own(a) {
                return ESRCH;
            }
            let fds = match client_fds(a) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let t = fds.lock();
            if op == LX_FH_SEEK {
                return seek_in(&t, b, c).map_or_else(|e| e, |()| 0);
            }
            let info = match info_in(&t, b) {
                Ok(i) => i,
                Err(e) => return e,
            };
            drop(t);
            // SAFETY: plain integers
            let bytes = unsafe { core::slice::from_raw_parts(&info as *const LxFhInfo as *const u8, core::mem::size_of::<LxFhInfo>()) };
            crate::compat::linux::vfs::copy_out(c, bytes).map_or_else(|e| e, |()| 0)
        }
        _ => EINVAL,
    }
}

/// `[prof] vfs:` line of `linux prof show`.
pub fn summary() -> String {
    alloc::format!(
        "vfs: served {} to kernel {} kept {} (landlock {} fanotify {} foreign {} mounts {} abac {} inotify {}) notes {}",
        SERVED.load(Ordering::Relaxed),
        TO_KERNEL_CALLS.load(Ordering::Relaxed),
        KEPT.load(Ordering::Relaxed),
        KEPT_BY[0].load(Ordering::Relaxed),
        KEPT_BY[1].load(Ordering::Relaxed),
        KEPT_BY[2].load(Ordering::Relaxed),
        KEPT_BY[3].load(Ordering::Relaxed),
        KEPT_BY[4].load(Ordering::Relaxed),
        KEPT_BY[5].load(Ordering::Relaxed),
        NOTES.load(Ordering::Relaxed)
    )
}

#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_fileh.rs"]
pub(crate) mod tests;
