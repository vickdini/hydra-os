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
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
const EIO: i64 = -5;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOENT: i64 = -2; // wave9 G6b-3
const E2BIG: i64 = -7; // wave9 G6b-3
const EACCES: i64 = -13; // wave9 G6b-3

const AT_FDCWD: i32 = -100;
const O_CLOEXEC: u32 = 0o2000000;
/// The open flags a handle keeps (as the kernel's `open` does).
const KEEP: u32 = 0o3 | 0o2000 | 0o4000 | 0o200000 | 0o10000000;

/// Entry bit: a file-service call ([`shape`] says where its descriptors are). Bit 31 (bits
/// 16..30 are `T_BYARG`'s, reserved).
pub const T_VFS: u32 = 1 << 31;

/// A result only the forwarding code sees: the service redirected the call to the kernel.
pub(super) const LX_TO_KERNEL: i64 = -4102;

// wave10 GV2: which tree (`/sys`, `/dev`, ...) a handle's or working directory's path is in
#[path = "fstree.rs"]
pub mod fstree;

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
    // wave9 G6b-1 begin: inotify and fanotify (vfs-server's objects)
    /// No descriptor to describe; `args[0]` of `inotify_add_watch`/`inotify_rm_watch` is
    /// the instance (only one of vfs-server's goes there: [`LxCall::obj`]).
    Notify,
    /// `fanotify_mark`: `args[0]` is the group (as [`Shape::Notify`]), `args[3]` the
    /// directory descriptor.
    NotifyAt3,
    // wave9 G6b-1 end
}

/// The file-service calls and their shapes (x86-64 Linux numbers).
pub const fn shape(nr: u64) -> Option<Shape> {
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
        // wave8 GF: pivot_root, mount, umount2 (paths only)
        155 | 165 | 166 => Shape::Path,
        // wave9 G6b-1: inotify_init, inotify_init1, fanotify_init, inotify_add_watch,
        // inotify_rm_watch; fanotify_mark
        253 | 294 | 300 | 254 | 255 => Shape::Notify,
        301 => Shape::NotifyAt3,
        _ => return None,
    })
}

// ----------------------------------------------------------------------
// Claims and the routing entries
// ----------------------------------------------------------------------

/// The numbers vfs-server claimed (bit `nr`), below the table's 512.
static CLAIMED: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

/// Whether vfs-server claimed call `nr`.
pub fn claimed(nr: u64) -> bool {
    nr < 512 && CLAIMED[nr as usize / 64].load(Ordering::Acquire) & (1 << (nr % 64)) != 0
}

/// The routing entry of file-service call `nr` (0: the kernel answers it). wave9 G9-C: the
/// file service is always forwarded (`lx.vfs=kernel` is gone; `lx=kernel` moves the other
/// services back, not this one: the kernel no longer has every file call's code).
pub fn entry_for(nr: u64) -> u32 {
    if shape(nr).is_some() && claimed(nr) {
        T_SERVER | T_VFS | T_FSCTX | T_UMASK | (LXS_VFS as u32) << T_SVC_SHIFT
    } else {
        0
    }
}

/// Serializes [`apply`] and [`claim`] (the routing switch and the claims change together).
static APPLY: Mutex<()> = Mutex::new(());

/// Writes the routing entries of every file-service number (`set_forwarding` and a claim).
pub fn apply() {
    let _g = APPLY.lock();
    apply_locked();
}

fn apply_locked() {
    for nr in 0..512u64 {
        if shape(nr).is_some() {
            super::TABLE[nr as usize].store(entry_for(nr), Ordering::Release);
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
    apply_locked();
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

// wave11 GF begin
/// Whether `ino` is an object vfs-server serves for handles and working directories: a pool
/// object, or a file of one of its FUSE connections (it walks into those mounts and decides
/// their changes since wave 11).
pub fn served_ino(ino: u64) -> bool {
    plain_ino(ino) || crate::compat::linux::fuse_svc::is_remote(ino)
}
// wave11 GF end

/// Whether `path` (as the kernel shows it) lies where the kernel serves files by name
/// (`/proc`): lookups relative to it are the kernel's until those trees are served by their
/// services (group 7-4). (wave10 GV2: `/sys` and `/dev` are pool trees vfs-server walks,
/// redirecting the names other services serve at lookup: their handles are pool handles.)
pub fn pseudo_path(path: &str) -> bool {
    path.strip_prefix("/proc").is_some_and(|r| r.is_empty() || r.starts_with('/'))
}

/// The handle data of an open file: `None` when it is not a plain pool object (opened
/// through another process's root, a FUSE file).
pub fn info_of_open(f: &OpenFile) -> Option<AtInfo> {
    // (the `/proc` directory of the pool is served by name: the kernel lists it)
    // (wave11 GF: a file of vfs-server's FUSE connections too)
    if f.foreign.is_some() || !served_ino(f.ino) || f.path.ends_with("/proc") || pseudo_path(&f.path) {
        return None;
    }
    // wave9 G6b-3: and whether Landlock refused truncating it at the open
    let notrunc = if f.no_truncate { crate::ipc::protocol::LX_FH_NOTRUNC } else { 0 };
    // wave10 GV2: and the tree its path is in (`statfs` shows sysfs, cgroup2, ...)
    let tree = fstree::at_bits(&f.path);
    Some(AtInfo { kind: if f.is_dir { LX_AT_DIR } else { LX_AT_FILE }, ino: f.ino, mnt: f.mnt as u32, off: f.offset, flags: f.flags | notrunc | tree })
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
/// (`pub(super)`: wave7 G7-5's `xexec` fills the same context.) wave7 G7-7: also sets
/// [`LxCall::mnt_gen`], the generation of the caller's mount table the service walks with.
pub(super) fn fs_flags_global(c: &mut LxCall) -> u32 {
    use crate::compat::linux as l;
    let mut f = 0;
    // wave9 G6b-3 begin: the domain's id, by which the service keeps a copy of it
    c.ll_dom = l::landlock::domain_id();
    if c.ll_dom != 0 {
        f |= LX_FS_LANDLOCK;
    }
    // wave9 G6b-3 end
    // (wave9 G9-C: `LX_FS_FANOTIFY`/`LX_FS_INOTIFY` are never set: the kernel has no
    // instances of its own since its copy of the notify code is gone)
    // wave9 G6b-3: only callers the policies apply to (a subject; the service asks the
    // kernel for them, `LX_FH_ABAC`)
    if (l::abac::active() || l::abac::apps_active()) && l::abac::applies_to_current() {
        f |= LX_FS_ABAC;
    }
    // wave7 G7-7: the service walks with its copy of the caller's mount table (taken by
    // generation, `LX_FH_MNTTAB`); only a table it cannot walk keeps the call here
    // (wave9 G9-C: `lx.vfsmnt=kernel` is gone)
    match l::mount::vfs_gen(c.mnt_ns as u64) {
        Some(g) => c.mnt_gen = g,
        None => f |= LX_FS_MOUNTS,
    }
    // wave10 GV1: device nodes made under device programs are the kernel's
    if matches!(c.nr, 133 | 259) && l::bpf::any_device_programs() {
        f |= crate::ipc::protocol::LX_FS_DEVCG;
    }
    f
}

// wave7 G7-7 begin

/// [`LX_FH_MNTTAB`](crate::ipc::protocol::LX_FH_MNTTAB): namespace `ns`'s table to `buf` (a
/// head and at most `cap` records); the number of slots.
fn mnttab(ns: u64, buf: u64, cap: u64) -> i64 {
    use crate::ipc::protocol::{LxMntHead, LxMntRec};
    let (gen, root, mounts) = match crate::compat::linux::mount::vfs_table(ns) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let n = mounts.len().min(usize::try_from(cap).unwrap_or(usize::MAX));
    let head = LxMntHead { gen, root, n: mounts.len() as u32 };
    let mut bytes = Vec::with_capacity(core::mem::size_of::<LxMntHead>() + n * core::mem::size_of::<LxMntRec>());
    // SAFETY: plain integers (repr C, no padding holes left uninitialized: all fields set)
    bytes.extend_from_slice(unsafe { core::slice::from_raw_parts(&head as *const LxMntHead as *const u8, core::mem::size_of::<LxMntHead>()) });
    for m in &mounts[..n] {
        let r = LxMntRec { kind: m.kind, flags: m.flags, parent: m.parent, pad: 0, mountpoint: m.mountpoint, root: m.root };
        // SAFETY: as above
        bytes.extend_from_slice(unsafe { core::slice::from_raw_parts(&r as *const LxMntRec as *const u8, core::mem::size_of::<LxMntRec>()) });
    }
    if crate::compat::linux::vfs::copy_out(buf, &bytes).is_err() {
        return EFAULT;
    }
    mounts.len() as i64
}
// wave7 G7-7 end

/// Fills call `c` (number `nr` of shape `sh`) with the caller's file context from its
/// descriptor table `t`. `Ok(None)`: the kernel answers (a call on a descriptor that is not a
/// handle); `Err(())`: a lock was busy (only when `!wait`).
pub(super) fn fill(c: &mut LxCall, t: &FdTable, sh: Shape, wait: bool) -> Result<Option<Held>, ()> {
    c.root = t.root_ino;
    c.root_mnt = t.root_mnt as u32;
    c.cwd = t.cwd_ino;
    c.cwd_mnt = t.cwd_mnt as u32;
    c.umask = t.umask as u64;
    // (wave11 GF: a working directory in one of vfs-server's FUSE mounts too)
    if !plain_ino(t.root_ino) || !served_ino(t.cwd_ino) || pseudo_path(&t.cwd_path) || t.cwd_path.ends_with("/proc") {
        c.fs_flags |= LX_FS_FOREIGN;
    }
    c.fs_flags |= fstree::cwd_bits(&t.cwd_path); // wave10 GV2
    let mut held: Held = [None, None];
    // wave9 G6b-1 begin: the instance or group the call acts on: vfs-server's object, or
    // the kernel answers (an instance the kernel made while vfs-server was away)
    if takes_notify_obj(c.nr) {
        match super::obj::object_in(t, c.args[0]) {
            Some((_dev, slot, flags, h)) if h == svc::host_of(LXS_VFS) => {
                c.obj = slot;
                c.obj_flags = flags;
            }
            _ => return Ok(None),
        }
    }
    // wave9 G6b-1 end
    let (first, second) = match sh {
        Shape::Path | Shape::Notify => (None, None),
        Shape::NotifyAt3 => (Some(c.args[3]), None), // wave9 G6b-1
        Shape::At0 | Shape::Handle => (Some(c.args[0]), None),
        Shape::At0At2 => (Some(c.args[0]), Some(c.args[2])),
        Shape::At1 => (Some(c.args[1]), None),
    };
    if let Some(fd) = first {
        let (i, h) = at_of(t, fd, wait)?;
        // (a call on an O_PATH descriptor is the kernel's: it decides what such a one may do)
        // (wave10 GV1: but fstatfs is allowed on one, as on Linux)
        if sh == Shape::Handle && (!matches!(i.kind, LX_AT_FILE | LX_AT_DIR) || (i.flags & 0o10000000 != 0 && c.nr != 138)) {
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
    // wave9 G6b-1: vfs-server's inotify/fanotify calls are its own whatever the caller's
    // state (it walks what it can; the kernel's instances are the kernel's anyway)
    if is_notify_call(nr) {
        return 0;
    }
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
            // wave8 GF: the mount changes (Landlock forbids them; the kernel's rule)
            155 | 165 | 166 => LX_FS_LANDLOCK,
            _ => 0,
        }
        & policy_mask(nr) // wave9 G6b-3
}

// wave9 G6b-3 begin: Landlock and ABAC checked by vfs-server (wave9 G9-C: `lx.policy=kernel`
// is gone)

/// The bits [`kernel_mask`] keeps for call `nr`: vfs-server checks Landlock and ABAC for
/// the calls it serves (open, access, the attribute changes, mkdir, symlink, unlink, rmdir,
/// rename, the mount calls); the others it does not serve (mknod, link, the xattr calls,
/// utime(s)) stay with the kernel.
pub fn policy_mask(nr: u64) -> u32 {
    let served = matches!(nr, 2 | 257 | 21 | 269 | 439 | 90 | 268 | 91 | 92 | 94 | 260 | 93 | 76 | 77 | 280 | 83 | 258 | 88 | 266 | 87 | 84 | 263 | 82 | 264 | 316 | 155 | 165 | 166)
        // wave10 GV1: creat, mknod(at), link(at), the xattr calls, utime(s), futimesat,
        // fchmodat2 are served too
        || matches!(nr, 85 | 133 | 259 | 86 | 265 | 188..=199 | 132 | 235 | 261 | 452);
    if served {
        !(LX_FS_LANDLOCK | LX_FS_ABAC)
    } else {
        u32::MAX
    }
}

/// A creating open (`O_CREAT`) of a caller under Landlock or ABAC stayed here (vfs-server
/// sent it back): wave10 GV1: vfs-server makes files now, so nothing stays.
fn policy_create(_c: &LxCall) -> u32 {
    0
}

/// [`crate::ipc::protocol::LX_FH_LANDLOCK`]: the domain of request `req`'s caller to `buf`.
fn landlock_of(req: u64, buf: u64, cap: u64) -> i64 {
    let Some(tid) = super::client_of(req) else { return ESRCH };
    let Some(v) = crate::compat::linux::landlock::serialized_of(tid) else { return ENOENT };
    if v.len() as u64 > cap {
        return E2BIG;
    }
    crate::compat::linux::vfs::copy_out(buf, &v).map_or_else(|e| e, |()| v.len() as i64)
}

/// [`crate::ipc::protocol::LX_FH_ABAC`]: may request `req`'s caller access the object
/// `desc` describes?
fn abac_for(req: u64, desc: u64) -> i64 {
    use crate::ipc::protocol::{LxAbacDesc, LX_ABAC_DELETE};
    let Some(tid) = super::client_of(req) else { return ESRCH };
    let Ok(raw) = crate::compat::linux::vfs::copy_in(desc, core::mem::size_of::<LxAbacDesc>()) else { return EFAULT };
    // SAFETY: `raw` holds exactly one `LxAbacDesc` (plain integers)
    let d: LxAbacDesc = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const LxAbacDesc) };
    let path = if d.path != 0 && d.path_len > 0 && d.path_len <= 4096 { crate::compat::linux::vfs::copy_in(d.path, d.path_len as usize).ok() } else { None };
    let path = path.as_deref().and_then(|p| core::str::from_utf8(p).ok());
    let delete = d.want & LX_ABAC_DELETE != 0;
    if crate::compat::linux::abac::check_for(tid, d.ino, d.gen, d.mode, d.want & 7, delete, path) {
        0
    } else {
        EACCES
    }
}
// wave9 G6b-3 end

/// Calls the kernel kept because of each `LX_FS_*` bit (bit `i`: `KEPT_BY[i]`).
pub static KEPT_BY: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];

/// Whether call `c` is the kernel's at once (counted by reason).
fn kernel_only(c: &LxCall) -> bool {
    let hit = c.fs_flags & (kernel_mask(c.nr) | policy_create(c)); // wave9 G6b-3: policy_create
    // (wave7 G7-7: mounts of a namespace's table are the service's too now; in the initial
    // namespace a root or working directory on a mount is a FUSE one)
    // (wave8 GF: the initial namespace's mounts are fixed apart from FUSE, which is the
    // kernel's: its mount calls stay here; wave10 GV2: vfs-server decides them, FUSE too)
    // (wave11 GF: a working directory in one of vfs-server's FUSE mounts is the service's)
    let fuse_cwd = crate::compat::linux::fuse_svc::is_remote(c.cwd);
    let mounts = c.mnt_ns == 0 && (c.root_mnt != 0 || (c.cwd_mnt != 0 && !fuse_cwd)) && !is_notify_call(c.nr); // (wave9 G6b-1)
    if hit == 0 && !mounts {
        return false;
    }
    for (i, k) in KEPT_BY.iter().enumerate() {
        if hit & (1 << i) != 0 {
            k.fetch_add(1, Ordering::Relaxed);
        }
    }
    KEPT.fetch_add(1, Ordering::Relaxed);
    count_kernel(c.nr, false);
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

// wave9 G9-C begin: which calls the kernel's file code still answers, by number
/// Per call number below 512: (sent back by vfs-server, kept without asking, wave10 GV1:
/// unclaimed) since boot.
static KERNEL_BY_NR: [[AtomicU32; 3]; 512] = [const { [const { AtomicU32::new(0) }; 3] }; 512];

// wave10 GV1 begin: file calls vfs-server did not claim (the kernel answers them without
// asking: before vfs-server is up, or a number it does not serve)
/// The file-service numbers ([`shape`]) whose answer is the kernel's path and name code: not
/// the data calls on a handle (`fsync`, `fdatasync`, `sync_file_range`, `fallocate`) nor
/// `getdents64`/`getdents` (left to the kernel's handle code on purpose: 7-2's numbers).
const fn path_bits() -> [u64; 8] {
    let mut b = [0u64; 8];
    let mut nr = 0;
    while nr < 512 {
        if shape(nr as u64).is_some() && !matches!(nr, 74 | 75 | 277 | 285 | 217 | 78) {
            b[nr / 64] |= 1 << (nr % 64);
        }
        nr += 1;
    }
    b
}
static PATH_BITS: [u64; 8] = path_bits();

/// Whether call `nr` is a path or name call of the file service ([`path_bits`]).
pub fn is_path_call(nr: u64) -> bool {
    nr < 512 && PATH_BITS[nr as usize / 64] >> (nr % 64) & 1 != 0
}

/// Counts call `nr` if it is a file-service path call the kernel answers unclaimed.
#[inline]
pub fn count_unclaimed(nr: u64) {
    if is_path_call(nr) {
        KERNEL_BY_NR[nr as usize][2].fetch_add(1, Ordering::Relaxed);
    }
}
// wave10 GV1 end

/// Counts call `nr` answered by the kernel's own file code (`sent`: vfs-server sent it back).
fn count_kernel(nr: u64, sent: bool) {
    if let Some(c) = KERNEL_BY_NR.get(nr as usize) {
        c[if sent { 0 } else { 1 }].fetch_add(1, Ordering::Relaxed);
    }
}

/// The calls the kernel's file code answered, most first: `nr:sent/kept` (at most `n`).
pub fn kernel_by_nr(n: usize) -> String {
    // (wave10 GV1: and the unclaimed calls)
    let mut v: Vec<(u32, u32, u32, usize)> = (0..512)
        .map(|i| (KERNEL_BY_NR[i][0].load(Ordering::Relaxed), KERNEL_BY_NR[i][1].load(Ordering::Relaxed), KERNEL_BY_NR[i][2].load(Ordering::Relaxed), i))
        .filter(|&(a, b, c, _)| a + b + c != 0)
        .collect();
    v.sort_unstable_by(|x, y| (y.0 + y.1 + y.2).cmp(&(x.0 + x.1 + x.2)));
    let mut s = String::from("vfs to kernel by call (nr:sent/kept/unclaimed):");
    for (a, b, c, i) in v.into_iter().take(n) {
        s += &alloc::format!(" {}:{}/{}/{}", i, a, b, c);
    }
    s
}
// wave9 G9-C end

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
fn outcome(nr: u64, r: i64) -> Option<i64> {
    if r == LX_TO_KERNEL {
        TO_KERNEL_CALLS.fetch_add(1, Ordering::Relaxed);
        count_kernel(nr, true);
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
    // wave9 GP2: a handle the lock-free path got for this very call
    let args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    if let Some(code) = take_code(tid, nr, &args) {
        // wave10 GV2: or a device node it found (`LX_REDIR_DEV`)
        if let Some(dv) = dev_decode(code) {
            return Some(dev_open(nr, &args, dv));
        }
        let d = fh_desc(nr, &args, fh_decode(code)?).ok()?;
        let fd = crate::task::with_current_fds_mut(|t| install_in(t, &d));
        SERVED.fetch_add(1, Ordering::Relaxed);
        return Some(fd.map_or_else(|e| e, |fd| fd as i64));
    }
    // wave11 GP: relative to a `/proc` directory lx-proc listed: lx-proc's
    if let Some(r) = proc_dirfd_call(nr, &args) {
        return r;
    }
    if take_mark(tid, nr) {
        return None;
    }
    let sh = shape(nr)?;
    // wave8 GF: a mount change waits for a restarting vfs-server (below)
    let host = vfs_host();
    // wave9 G9-C (was G6b-1's, for the notify calls): every file call waits for a
    // restarting vfs-server (the ladder's 30 s) instead of the kernel answering meanwhile;
    // the kernel answers only before vfs-server first comes up (boot) or once the ladder
    // gave it up (its code is needed anyway for the calls vfs-server sends back)
    // (review M1: a failed wait — a signal, the 30 s passed — is the caller's answer; only
    // "not up yet" / "given up" leaves the call to the kernel)
    let host = match host {
        Some(h) => Some(h),
        None => match offline_wait() {
            Ok(h) => h,
            Err(e) => return Some(e),
        },
    };
    if host.is_none() && !is_mount_call(nr) {
        KEPT.fetch_add(1, Ordering::Relaxed);
        count_kernel(nr, false);
        return None;
    }
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.svc = LXS_VFS as u32;
    c.tgid = crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(0);
    super::fill_ctx(&mut c, true);
    // wave8 GF begin: the mount calls
    if is_mount_call(nr) && crate::task::with_current_task_mut(|t| t.caps.effective & CAP_SYS_ADMIN != 0).unwrap_or(false) {
        c.fs_flags |= crate::ipc::protocol::LX_FS_MNTADMIN;
    }
    let x = match host {
        Some(x) => x,
        // (only a mount change gets here: in a namespace of its own it waits for the restart
        // — vfs-server decides the namespace's mounts — and if vfs-server does not come back
        // within the ladder's 30 s, the kernel answers; vfs-server takes the table from the
        // kernel's copy when it is back)
        None => match mount_wait(c.mnt_ns) {
            Some(x) => x,
            None => {
                KEPT.fetch_add(1, Ordering::Relaxed);
                count_kernel(nr, false);
                return None;
            }
        },
    };
    // wave8 GF end
    let held = crate::task::with_current_fds_mut(|t| fill(&mut c, t, sh, true));
    let held = match held {
        Ok(Some(h)) => h,
        _ => {
            KEPT.fetch_add(1, Ordering::Relaxed);
            // wave10 GV1: a call on a descriptor that is no pool file (a memfd, a socket, a
            // device) is not the file code's: not counted by number
            if sh != Shape::Handle || crate::task::with_current_fds_mut(|t| matches!(t.get(c.args[0] as i32 as usize), Some(FileDescriptor::Vnode(_)))) {
                count_kernel(nr, false);
            }
            return None;
        }
    };
    let f = fs_flags_global(&mut c);
    c.fs_flags |= f;
    // wave8 GF: a mount call whose generation was not at hand (the lock was busy) takes it
    // waiting, so it is not left to the kernel's copy of the rules by chance
    if is_mount_call(nr) && c.fs_flags & LX_FS_MOUNTS != 0 {
        if let Some(g) = crate::compat::linux::mount::vfs_gen_wait(c.mnt_ns as u64) {
            c.mnt_gen = g;
            c.fs_flags &= !LX_FS_MOUNTS;
        }
    }
    if kernel_only(&c) {
        return None;
    }
    if nr == 2 || nr == 257 {
        c.flags |= crate::ipc::protocol::LX_CALL_FHANSWER; // wave9 GP2
    }
    let args = c.args;
    let r = super::call_ident_raw(x, c, true);
    drop(held);
    // wave9 GP2: the handle in the answer (an unreadable path: the kernel opens)
    if let Some(h) = fh_decode(r) {
        let d = fh_desc(nr, &args, h).ok()?;
        let fd = crate::task::with_current_fds_mut(|t| install_in(t, &d));
        SERVED.fetch_add(1, Ordering::Relaxed);
        return Some(fd.map_or_else(|e| e, |fd| fd as i64));
    }
    // wave10 GV2: a device node vfs-server found and checked: the device opens here
    if let Some(dv) = dev_decode(r) {
        return Some(dev_open(nr, &args, dv));
    }
    outcome(nr, r)
}

// wave9 GP2 begin: open's handle made from the answer (`LX_REDIR_FH`)
/// Inodes below this travel in an [`fh_answer`].
const FH_INO_LIMIT: u64 = 1 << 45;

/// The answer of call `c` redirected to `LX_REDIR_FH` with `redir` = (target | tail << 32,
/// inode): the handle, coded below every real result ([`fh_decode`]); a call that did not
/// allow it, or an inode too large: the kernel answers (nothing happened in vfs-server).
pub(super) fn fh_answer(c: &LxCall, redir: (u64, u64)) -> i64 {
    let (tail, ino) = (redir.0 >> 32, redir.1);
    if c.flags & crate::ipc::protocol::LX_CALL_FHANSWER == 0 || !(c.nr == 2 || c.nr == 257) || ino >= FH_INO_LIMIT || ino == 0 {
        return LX_TO_KERNEL;
    }
    let dir = (tail >> 16) & 1;
    let mnt = tail & 0xFFFF;
    (1u64 << 63 | dir << 61 | mnt << 45 | ino) as i64
}

/// Per CPU: a handle the lock-free path got, for the ordinary path to make: (thread,
/// call number, coded handle, path pointer, flags, tick).
static FH_STASH: [[AtomicU64; 6]; crate::arch::smp::MAX_CPUS] = [const { [const { AtomicU64::new(0) }; 6] }; crate::arch::smp::MAX_CPUS];

/// The words of call (`nr`, `args`) a stash is matched by: the path pointer, and the flags
/// with the directory descriptor.
fn fh_key(nr: u64, args: &[u64; 6]) -> (u64, u64) {
    if nr == 2 {
        (args[0], args[1])
    } else {
        (args[1], args[2] | args[0] << 32)
    }
}

/// Keeps handle `h` of call (`tid`, `nr`, `args`) for [`fh_take`] on this CPU.
fn fh_stash(tid: u64, nr: u64, args: &[u64; 6], (ino, mnt, dir): (u64, u32, bool)) {
    stash_code(tid, nr, args, (1u64 << 63 | (dir as u64) << 61 | (mnt as u64) << 45 | ino) as i64);
}

/// Keeps answer `code` of call (`tid`, `nr`, `args`) (an [`fh_answer`] or, wave10 GV2, a
/// [`dev_answer`]) for [`take_code`] on this CPU.
fn stash_code(tid: u64, nr: u64, args: &[u64; 6], code: i64) {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    let s = &FH_STASH[cpu];
    let (p, f) = fh_key(nr, args);
    s[1].store(nr, Ordering::Relaxed);
    s[2].store(code as u64, Ordering::Relaxed);
    s[3].store(p, Ordering::Relaxed);
    s[4].store(f, Ordering::Relaxed);
    s[5].store(crate::arch::pit::ticks(), Ordering::Relaxed);
    s[0].store(tid, Ordering::Release);
}

/// The handle [`fh_stash`] kept on this CPU for exactly this call (same thread, number,
/// path pointer, flags and directory descriptor, within a tick); taken in any case.
fn fh_take(tid: u64, nr: u64, args: &[u64; 6]) -> Option<(u64, u32, bool)> {
    fh_decode(take_code(tid, nr, args)?)
}

/// The answer [`stash_code`] kept on this CPU for exactly this call (as [`fh_take`]).
fn take_code(tid: u64, nr: u64, args: &[u64; 6]) -> Option<i64> {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    let s = &FH_STASH[cpu];
    if tid == 0 || s[0].load(Ordering::Acquire) != tid {
        return None;
    }
    s[0].store(0, Ordering::Relaxed);
    let (p, f) = fh_key(nr, args);
    let fresh = crate::arch::pit::ticks().saturating_sub(s[5].load(Ordering::Relaxed)) <= 1;
    if s[1].load(Ordering::Relaxed) != nr || s[3].load(Ordering::Relaxed) != p || s[4].load(Ordering::Relaxed) != f || !fresh {
        return None;
    }
    Some(s[2].load(Ordering::Relaxed) as i64)
}

/// `(inode, mount, directory)` of an [`fh_answer`] result.
pub fn fh_decode(r: i64) -> Option<(u64, u32, bool)> {
    if r >= -(1i64 << 62) {
        return None;
    }
    let v = r as u64;
    Some((v & (FH_INO_LIMIT - 1), ((v >> 45) & 0xFFFF) as u32, (v >> 61) & 1 != 0))
}

/// The descriptor of handle `(ino, mnt, dir)` of `open`/`openat` (`nr`, `args`): the flags
/// and shown path `LX_FH_INSTALL` would get from vfs-server (`handle_desc`). Reads the
/// caller's memory: never with a descriptor table locked.
pub fn fh_desc(nr: u64, args: &[u64; 6], (ino, mnt, dir): (u64, u32, bool)) -> Result<LxFhDesc, i64> {
    let (dirfd, path_ptr, flags) = if nr == 2 { (-100i32, args[0], args[1] as u32) } else { (args[0] as i32, args[1], args[2] as u32) };
    let mut d = LxFhDesc::EMPTY;
    let n = match super::copy::read_user_str(path_ptr, &mut d.path) {
        Ok(Some(n)) if n > 0 => n,
        _ => return Err(EINVAL),
    };
    d.ino = ino;
    d.mnt = mnt;
    d.is_dir = dir as u32;
    d.flags = flags & (KEEP | O_CLOEXEC);
    d.path_len = n as u32;
    d.path_kind = if d.path[0] == b'/' {
        LX_FHP_ABS
    } else if dirfd == -100 {
        LX_FHP_CWD
    } else {
        d.at_fd = dirfd;
        LX_FHP_AT
    };
    Ok(d)
}
// wave9 GP2 end

// wave10 GV2 begin: a device node vfs-server found and checked (`LX_REDIR_DEV`)
/// Device answers are coded as `-(DEV_CODE + payload)`: below every errno and the
/// kernel's own markers, above every [`fh_answer`] code.
const DEV_CODE: i64 = 1 << 60;
/// The payload of a device answer: the device number (below 2^40) and the block bit.
const DEV_PAYLOAD: u64 = (1 << 41) - 1;

/// The answer of call `c` redirected to `LX_REDIR_DEV` with `redir.1` = the device number
/// `| LX_REDIR_DEV_BLOCK`: coded for [`dev_open`]; only an open may get one (anything else:
/// the kernel answers, nothing happened in vfs-server).
pub(super) fn dev_answer(c: &LxCall, redir: (u64, u64)) -> i64 {
    if !matches!(c.nr, 2 | 257 | 85) || redir.1 & !DEV_PAYLOAD != 0 {
        return LX_TO_KERNEL;
    }
    -(DEV_CODE + redir.1 as i64)
}

/// `(device number, block)` of a [`dev_answer`] code.
pub fn dev_decode(r: i64) -> Option<(u64, bool)> {
    let p = r.checked_neg()?.checked_sub(DEV_CODE)?;
    if !(0..=DEV_PAYLOAD as i64).contains(&p) {
        return None;
    }
    let p = p as u64;
    Some((p & (crate::ipc::protocol::LX_REDIR_DEV_BLOCK - 1), p & crate::ipc::protocol::LX_REDIR_DEV_BLOCK != 0))
}

/// The open flags of `open`/`openat`/`creat` (`nr`, `args`).
fn open_flags(nr: u64, args: &[u64; 6]) -> u32 {
    match nr {
        2 => args[1] as u32,
        85 => 0o100 | 0o1 | 0o1000, // O_CREAT | O_WRONLY | O_TRUNC
        _ => args[2] as u32,
    }
}

/// Opens the device of a [`dev_answer`] for open call (`nr`, `args`): its result. Reads the
/// caller's memory (the path, shown for the console): never with a table locked.
fn dev_open(nr: u64, args: &[u64; 6], (rdev, block): (u64, bool)) -> i64 {
    let flags = open_flags(nr, args);
    // (the shown path is made as for a handle; `creat` takes the path as its first argument)
    let a = if nr == 85 { [args[0], 0, 0, 0, 0, 0] } else { *args };
    let shown = match fh_desc(if nr == 85 { 2 } else { nr }, &a, (0, 0, false)) {
        Ok(d) => crate::task::with_current_fds_mut(|t| shown_path(t, &d)).unwrap_or_default(),
        Err(_) => String::new(),
    };
    SERVED.fetch_add(1, Ordering::Relaxed);
    DEV_OPENS.fetch_add(1, Ordering::Relaxed);
    match crate::compat::linux::vfs::open_device(rdev, block, flags, &shown) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

/// Devices opened from vfs-server's answer since boot.
pub static DEV_OPENS: AtomicU64 = AtomicU64::new(0);
// wave10 GV2 end

/// The lock-free path (interrupts off, no kernel lock) for a call whose entry has
/// [`T_VFS`]: `None` the ordinary path takes it (a busy lock, the service offline, the
/// kernel answers).
pub(super) fn fast(id: &super::Ident, frame: &SyscallFrame) -> Option<i64> {
    let nr = frame.rax;
    // wave9 GP2: a stash of this thread not taken by its ordinary path goes
    let _ = fh_take(id.tid, u64::MAX, &[0; 6]);
    // wave8 GF: the mount calls take the ordinary path (the capability rule needs the task,
    // a down service is waited for)
    if is_mount_call(nr) {
        return None;
    }
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
    // (wave10 GV2: and whether a call on a descriptor is on a file of the file code at all,
    // counted by number as on the ordinary path)
    let mut vnode = sh != Shape::Handle;
    let r = match fds.try_lock() {
        // wave11 GP: a call relative to a `/proc` directory snapshot takes the ordinary path
        // (`proc_dirfd_call`)
        Some(t) if at_proc_dir(nr, &t, c.args[0]) => Err(()),
        Some(t) => {
            vnode |= matches!(t.get(c.args[0] as i32 as usize), Some(FileDescriptor::Vnode(_)));
            fill(&mut c, &t, sh, false)
        }
        None => Err(()),
    };
    super::drop_last(fds);
    let held = match r {
        Ok(Some(h)) => h,
        // A call on a descriptor that is not a handle: the kernel, without asking again
        Ok(None) => {
            KEPT.fetch_add(1, Ordering::Relaxed);
            if vnode {
                count_kernel(nr, false);
            }
            set_mark(id.tid, nr);
            return None;
        }
        Err(()) => return None,
    };
    let f = fs_flags_global(&mut c);
    c.fs_flags |= f;
    if kernel_only(&c) {
        for h in held.into_iter().flatten() {
            super::drop_last(h);
        }
        set_mark(id.tid, nr);
        return None;
    }
    let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
    super::FAST_CALLS.fetch_add(1, Ordering::Relaxed);
    if nr == 2 || nr == 257 {
        c.flags |= crate::ipc::protocol::LX_CALL_FHANSWER; // wave9 GP2
    }
    let r = super::call_with(x, id.tid, idx, c, true);
    for h in held.into_iter().flatten() {
        super::drop_last(h);
    }
    // wave9 GP2 begin: the handle in the answer is made on the ordinary path, as
    // `LX_FH_INSTALL` made it (under the kernel lock, interrupts on: the first open
    // reference of a file may ask zfs-server), from this CPU's stash: the call is not sent
    // again
    if let Some(h) = fh_decode(r) {
        fh_stash(id.tid, nr, &c.args, h);
        return None;
    }
    // wave9 GP2 end
    // wave10 GV2: a device opens on the ordinary path too (its owner may be asked)
    if dev_decode(r).is_some() {
        stash_code(id.tid, nr, &c.args, r);
        return None;
    }
    match outcome(nr, r) {
        Some(r) => Some(r),
        None => {
            set_mark(id.tid, nr);
            None
        }
    }
}

// wave11 GP begin: calls relative to a `/proc` directory descriptor (with Group F)
/// The calls lx-proc serves under `/proc` that take a directory descriptor first.
fn proc_dirfd_nr(nr: u64) -> bool {
    matches!(nr, 257 | 262 | 332 | 269 | 439 | 267)
}

/// Whether call `nr`'s directory descriptor `fd` (in table `t`) is a `/proc` directory
/// lx-proc listed (a kernel-held directory snapshot).
#[cfg(target_os = "uefi")]
fn at_proc_dir(nr: u64, t: &crate::fs::FdTable, fd: u64) -> bool {
    proc_dirfd_nr(nr)
        && (fd as i32) >= 0
        && matches!(t.get(fd as i32 as usize), Some(FileDescriptor::Device(d)) if d.proc_ident().is_some_and(|(_, mode, _)| mode & 0o170000 == 0o040000))
}

/// A path call relative to a `/proc` directory lx-proc listed goes straight to lx-proc, as
/// if the file service had redirected it there (`redirs` 1, the walk's base named by
/// [`LX_PROC_AT_DIRFD`](crate::ipc::protocol::LX_PROC_AT_DIRFD): lx-proc reads the
/// descriptor's path). `None`: not such a call (an absolute or empty path, another
/// descriptor); `Some(None)`: the kernel answers.
#[cfg(not(target_os = "uefi"))]
fn at_proc_dir(_nr: u64, _t: &crate::fs::FdTable, _fd: u64) -> bool {
    false
}

#[cfg(not(target_os = "uefi"))]
fn proc_dirfd_call(_nr: u64, _args: &[u64; 6]) -> Option<Option<i64>> {
    None
}

#[cfg(target_os = "uefi")]
fn proc_dirfd_call(nr: u64, args: &[u64; 6]) -> Option<Option<i64>> {
    use crate::ipc::protocol::{LXS_PROC, LX_PROC_AT_DIRFD, LX_VFS_PSEUDO_PROC};
    if !proc_dirfd_nr(nr) || !crate::task::with_current_fds_mut(|t| at_proc_dir(nr, t, args[0])) {
        return None;
    }
    let path = crate::compat::linux::vfs::user_cstr(args[1]).ok()?;
    if path.is_empty() || path[0] == b'/' {
        return None;
    }
    // (review 11-P 1: a caller under Landlock or ABAC takes the ordinary route: vfs-server
    // sends the call back and the kernel's walk from the `/proc` descriptor applies the same
    // checks as for an absolute `/proc` path)
    {
        use crate::compat::linux as l;
        if l::landlock::domain_id() != 0 || ((l::abac::active() || l::abac::apps_active()) && l::abac::applies_to_current()) {
            return None;
        }
    }
    let x = svc::host(svc::host_of(LXS_PROC))?;
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = *args;
    c.svc = LXS_PROC as u32;
    c.tgid = crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(0);
    super::fill_ctx(&mut c, true);
    c.redirs = 1;
    c.redir_obj = LX_VFS_PSEUDO_PROC | LX_PROC_AT_DIRFD;
    c.redir_tail = 0;
    let r = super::call_ident_raw(x, c, true);
    Some(outcome(nr, r))
}
// wave11 GP end

// wave8 GF begin: the mount calls (`mount`, `umount2`, `pivot_root`)
/// `CAP_SYS_ADMIN`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// Whether `nr` is one of the mount changes vfs-server decides (`pivot_root`, `mount`,
/// `umount2`).
pub fn is_mount_call(nr: u64) -> bool {
    matches!(nr, 155 | 165 | 166)
}

/// Mount changes that waited for a restarting vfs-server, and those the kernel answered
/// because it did not come back.
pub static MOUNT_WAITS: AtomicU64 = AtomicU64::new(0);
/// See [`MOUNT_WAITS`].
pub static MOUNT_WAIT_FAILED: AtomicU64 = AtomicU64::new(0);

/// A mount change of a caller in mount namespace `ns` found vfs-server offline: in a
/// namespace of its own it waits for the restart (the ladder's 30 s); the host then, or
/// `None` (the initial namespace, vfs-server not restarting or not back): the kernel answers.
fn mount_wait(ns: u32) -> Option<&'static Host> {
    if ns == 0 {
        return None;
    }
    MOUNT_WAITS.fetch_add(1, Ordering::Relaxed);
    match super::restart::wait_online(LXS_VFS, &|| vfs_host().is_some()) {
        Ok(()) => vfs_host(),
        Err(_) => {
            MOUNT_WAIT_FAILED.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

// wave9 G6b-1 begin: inotify and fanotify
/// Whether `nr` is one of the inotify/fanotify calls vfs-server serves.
pub fn is_notify_call(nr: u64) -> bool {
    matches!(nr, 253 | 294 | 300 | 254 | 255 | 301)
}

/// Whether call `nr` acts on an instance or group at `args[0]`.
pub fn takes_notify_obj(nr: u64) -> bool {
    matches!(nr, 254 | 255 | 301)
}

/// File calls that waited for a restarting vfs-server (wave9 G6b-1: the notify calls;
/// wave9 G9-C: every file call).
pub static OFFLINE_WAITS: AtomicU64 = AtomicU64::new(0);

/// vfs-server is offline: if it is being restarted, wait for it (the ladder's 30 s).
/// `Ok(None)`: not restarting (not up yet, or given up): the kernel answers; `Err(e)`: the
/// wait failed (`ERESTARTSYS` on a signal, `EIO` after 30 s or if it went again): the
/// caller's answer.
fn offline_wait() -> Result<Option<&'static Host>, i64> {
    if !super::restart::waitable(LXS_VFS) { // wave11 GK: or in its first start
        return Ok(None);
    }
    OFFLINE_WAITS.fetch_add(1, Ordering::Relaxed);
    super::restart::wait_online(LXS_VFS, &|| vfs_host().is_some())?;
    vfs_host().map(Some).ok_or(EIO)
}

// wave11 GK: `notify_init_wait` (inotify/fanotify inits before vfs-server's first start) is
// gone: vfs-server claims them before it goes online, and callers wait for its first start.
// wave9 G6b-1 end

/// [`LX_FH_MNTGET`](crate::ipc::protocol::LX_FH_MNTGET): namespace `ns`'s whole table to
/// `buf` if it fits in `cap` bytes; its length.
fn mntget(ns: u64, buf: u64, cap: u64) -> i64 {
    let t = match crate::compat::linux::mount::full_table(ns) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let bytes = crate::compat::linux::mntrec::encode(&t);
    if bytes.len() as u64 <= cap && crate::compat::linux::vfs::copy_out(buf, &bytes).is_err() {
        return EFAULT;
    }
    bytes.len() as i64
}

/// [`LX_FH_MNTPUT`](crate::ipc::protocol::LX_FH_MNTPUT): namespace `ns`'s table becomes the
/// one in `buf` (`len` bytes); how many tmpfs trees went with it.
fn mntput(ns: u64, buf: u64, len: u64) -> i64 {
    if len > 16 << 20 {
        return EINVAL;
    }
    let raw = match crate::compat::linux::vfs::copy_in(buf, len as usize) {
        Ok(r) => r,
        Err(_) => return EFAULT,
    };
    let t = match crate::compat::linux::mntrec::decode(&raw) {
        Ok(t) => t,
        Err(e) => return e,
    };
    crate::compat::linux::mount::put_table(ns, &t).map_or_else(|e| e, |n| n as i64)
}

/// [`LX_FH_TMPFSID`](crate::ipc::protocol::LX_FH_TMPFSID): `[id, dir]` to `out`.
fn tmpfsid(out: u64) -> i64 {
    let (id, dir) = match crate::compat::linux::mount::tmpfs_new() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&(id as u64).to_le_bytes());
    b[8..].copy_from_slice(&dir.to_le_bytes());
    crate::compat::linux::vfs::copy_out(out, &b).map_or_else(|e| e, |()| 0)
}
// wave8 GF end

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
    // wave9 G6b-2: or a file of a FUSE connection of vfs-server's (it counted the open)
    if !plain_ino(d.ino) && !crate::compat::linux::fuse_svc::is_remote(d.ino) {
        return Err(EINVAL);
    }
    let path = shown_path(t, d)?;
    let file = OpenFile::new(d.ino, d.flags & KEEP, path);
    {
        let mut f = file.lock();
        f.mnt = d.mnt as usize;
        f.is_dir = d.is_dir != 0;
        // wave9 G6b-1: a fanotify event's descriptor makes no events
        f.nonotify = d.flags & crate::ipc::protocol::LX_FH_NONOTIFY != 0;
        f.no_truncate = d.flags & crate::ipc::protocol::LX_FH_NOTRUNC != 0; // wave9 G6b-3
    }
    let fd = t.alloc_fd(FileDescriptor::Vnode(file)).map_err(|_| EMFILE)?;
    t.set_cloexec(fd, d.flags & O_CLOEXEC != 0);
    Ok(fd)
}

/// Makes the directory `d` names the current directory of table `t`.
pub fn chdir_in(t: &mut FdTable, d: &LxFhDesc) -> Result<(), i64> {
    // (wave11 GF: or a directory of vfs-server's FUSE connections)
    if !served_ino(d.ino) || d.is_dir == 0 {
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

// wave7 G7-6 begin
/// [`LX_FH_NSLIST`](crate::ipc::protocol::LX_FH_NSLIST): the live mount namespaces, at most
/// `cap` of them to `buf`; how many there are.
fn nslist(buf: u64, cap: u64) -> i64 {
    let ids = crate::compat::linux::ns::live_mntns();
    // (at most as many as there are: the copy never exceeds the list)
    let n = ids.len().min(usize::try_from(cap).unwrap_or(usize::MAX));
    let mut bytes = Vec::with_capacity(n * 8);
    for id in &ids[..n] {
        bytes.extend_from_slice(&id.to_le_bytes());
    }
    if n > 0 && crate::compat::linux::vfs::copy_out(buf, &bytes).is_err() {
        return EFAULT;
    }
    ids.len() as i64
}
// wave7 G7-6 end

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
    // wave10 GV1: an access-control label attribute changed
    if what & crate::ipc::protocol::LX_FHC_LABELS != 0 {
        crate::compat::linux::abac::labels_changed();
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

// wave9 GM begin
/// [`LX_FH_TMEM`](crate::ipc::protocol::LX_FH_TMEM): sub-op `sub` of the in-memory tmpfs
/// files (`fs::tmem::ctl`); answers go to the caller's buffer `b`.
fn tmem(sub: u64, a: u64, b: u64) -> i64 {
    // wave10 GV1 begin: the changes vfs-server makes to in-memory files
    use crate::ipc::protocol::{LX_TMEM_CREATED, LX_TMEM_MAY_MOVE, LX_TMEM_MNT, LX_TMEM_TIMES, LX_TMEM_TRUNC, LX_TMEM_UNLINKED};
    use crate::fs::tmem as t;
    const ENOENT: i64 = -2;
    let on = t::ENABLED.load(Ordering::Relaxed);
    match sub {
        LX_TMEM_MNT => {
            let Some(id) = crate::compat::linux::mount::tmpfs_of(a >> 32, (a & 0xFFFF_FFFF) as usize).filter(|_| on) else { return ENOENT };
            return crate::compat::linux::vfs::copy_out(b, &(id as u64).to_le_bytes()).map_or_else(|e| e, |()| 0);
        }
        LX_TMEM_CREATED => {
            let raw = match crate::compat::linux::vfs::copy_in(b, 16) {
                Ok(r) => r,
                Err(_) => return EFAULT,
            };
            let w = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap_or([0; 8]));
            let (dir, nm) = (w(0), w(8));
            t::created(dir, a, crate::compat::linux::mount::tmpfs_of(nm >> 32, (nm & 0xFFFF_FFFF) as usize));
            crate::fs::zfs::forget_attr_of(a);
            return 0;
        }
        LX_TMEM_TRUNC => {
            let Some(f) = t::get(a) else { return ENOENT };
            let r = f.truncate(b).map_or_else(|e| e, |()| 0);
            crate::compat::linux::mm::cache_truncated(a, b);
            return r;
        }
        LX_TMEM_TIMES => {
            if let Some(f) = t::get(a) {
                f.times_set();
            }
            return 0;
        }
        LX_TMEM_UNLINKED => {
            crate::fs::zfs::tmem_unlinked(a);
            0
        }
        crate::ipc::protocol::LX_TMEM_TEXT_BUSY => crate::compat::linux::mm::text_busy(a) as i64,
        LX_TMEM_MAY_MOVE => {
            if t::may_move(a, b) {
                0
            } else {
                -18 // EXDEV
            }
        }
        // wave10 GV1 end
        _ => crate::fs::tmem::ctl(sub, a, b, &|v: &[u8]| match crate::compat::linux::vfs::copy_out(b, v) {
            Ok(()) => 0,
            Err(e) => e,
        }),
    }
}
// wave9 GM end

// wave10 GV2 begin: the initial namespace's FUSE mounts, decided by vfs-server
/// [`crate::ipc::protocol::LX_FH_NS0FUSE`] sub-op `sub` with argument `a`; `own`: whether a
/// request is the calling service's.
fn ns0fuse(sub: u64, a: u64, own: &dyn Fn(u64) -> bool) -> i64 {
    use crate::ipc::protocol::{LxNs0Fuse, LX_NS0FUSE_ADD, LX_NS0FUSE_NAME_MAX, LX_NS0FUSE_REMOVE};
    match sub {
        LX_NS0FUSE_ADD => {
            let Ok(raw) = crate::compat::linux::vfs::copy_in(a, core::mem::size_of::<LxNs0Fuse>()) else { return EFAULT };
            // SAFETY: `raw` holds exactly one `LxNs0Fuse` (plain integers and bytes)
            let m: LxNs0Fuse = unsafe { core::ptr::read_unaligned(raw.as_ptr() as *const LxNs0Fuse) };
            if !own(m.req) {
                return ESRCH;
            }
            let text = |b: &[u8], n: u32, max: usize| String::from_utf8_lossy(&b[..(n as usize).min(max)]).into_owned();
            let p = &m.path[..(m.path_len as usize).min(LX_FH_PATH_MAX)];
            let path = match m.path_kind {
                LX_FHP_ABS => join_path("/", p),
                LX_FHP_CWD => match client_fds(m.req) {
                    Ok(fds) => join_path(&fds.lock().cwd_path, p),
                    Err(e) => return e,
                },
                _ => return EINVAL,
            };
            crate::compat::linux::fuse::ns0_record(
                m.mountpoint,
                m.root,
                path,
                text(&m.fstype, m.fstype_len, LX_NS0FUSE_NAME_MAX),
                text(&m.source, m.source_len, LX_NS0FUSE_NAME_MAX),
                m.flags,
                (m.uid, m.gid, m.other != 0),
            );
            0
        }
        LX_NS0FUSE_REMOVE => {
            if crate::compat::linux::fuse::ns0_forget(a) {
                0
            } else {
                ENOENT
            }
        }
        _ => EINVAL,
    }
}
// wave10 GV2 end

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
        // wave7 G7-6 begin
        crate::ipc::protocol::LX_FH_NSLIST => nslist(a, b),
        // wave7 G7-6 end
        crate::ipc::protocol::LX_FH_MNTTAB => mnttab(a, b, c), // wave7 G7-7
        // wave9 G6b-3 begin
        crate::ipc::protocol::LX_FH_LANDLOCK if own(a) => landlock_of(a, b, c),
        crate::ipc::protocol::LX_FH_ABAC if own(a) => abac_for(a, b),
        crate::ipc::protocol::LX_FH_LANDLOCK | crate::ipc::protocol::LX_FH_ABAC => ESRCH,
        // wave9 G6b-3 end
        // wave8 GF begin
        crate::ipc::protocol::LX_FH_MNTGET => mntget(a, b, c),
        crate::ipc::protocol::LX_FH_MNTPUT => mntput(a, b, c),
        crate::ipc::protocol::LX_FH_TMPFSID => tmpfsid(a),
        // wave8 GF end
        crate::ipc::protocol::LX_FH_TMEM => tmem(a, b, c), // wave9 GM
        crate::ipc::protocol::LX_FH_NS0FUSE => ns0fuse(a, b, &own), // wave10 GV2
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
        "vfs: served {} to kernel {} kept {} (landlock {} fanotify {} foreign {} mounts {} abac {} inotify {}) notes {} mount-waits {}/{} notify: posted {} dropped {} perm {}/{}; offline waits {}",
        SERVED.load(Ordering::Relaxed),
        TO_KERNEL_CALLS.load(Ordering::Relaxed),
        KEPT.load(Ordering::Relaxed),
        KEPT_BY[0].load(Ordering::Relaxed),
        KEPT_BY[1].load(Ordering::Relaxed),
        KEPT_BY[2].load(Ordering::Relaxed),
        KEPT_BY[3].load(Ordering::Relaxed),
        KEPT_BY[4].load(Ordering::Relaxed),
        KEPT_BY[5].load(Ordering::Relaxed),
        NOTES.load(Ordering::Relaxed),
        MOUNT_WAITS.load(Ordering::Relaxed), // wave8 GF
        MOUNT_WAIT_FAILED.load(Ordering::Relaxed),
        // wave9 G6b-1: events handed to vfs-server, permission questions (asked/denied)
        super::notifyfwd::POSTED.load(Ordering::Relaxed),
        super::notifyfwd::DROPPED.load(Ordering::Relaxed),
        super::notifyfwd::PERM_ASKED.load(Ordering::Relaxed),
        super::notifyfwd::PERM_DENIED.load(Ordering::Relaxed),
        OFFLINE_WAITS.load(Ordering::Relaxed)
    )
}

#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_fileh.rs"]
pub(crate) mod tests;
