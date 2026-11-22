//! # The mount calls vfs-server serves (wave 7, Group 7-3)
//!
//! **`chroot`** (161): the walk, the checks of the kernel's `sys_chroot` (`CAP_SYS_CHROOT`
//! first, a directory, search permission on it), then `LX_FH_CHROOT`: the kernel sets the
//! caller's root handle (and those of the processes sharing it, `CLONE_FS`). What the calls
//! of Group 7-2 hand to the kernel goes there too: a caller in a mount namespace of its
//! own, a root or working directory outside the pool, a walk into `/proc`, `/sys` or `/dev`
//! (the kernel's empty root for `/proc/<pid>/fd` and the like).
//!
//! wave7 G7-7: claimed again. nstest's Chromium-style `chroot("/proc/self/fdinfo/")` runs in
//! a user namespace of its own, where the call carries no capabilities (`LxCall::caps` 0):
//! such a caller's chroot is the kernel's (its rule counts the namespace's capabilities).
//! nstest and tests/linux/chroot_w7.c pass with the call claimed.
//!
//! wave8 GF: **`mount` (165), `umount2` (166), `pivot_root` (155)** of a caller in a mount
//! namespace of its own: vfs-server decides them ([`crate::ktab`], the kernel's rules) on
//! the namespace's whole table read from the kernel (`LX_FH_MNTGET`) and writes the table
//! back before answering (`LX_FH_MNTPUT`, compare and set: a table the kernel changed in
//! between is read again and the call redone). The kernel's table is the write-through
//! copy its own code walks and the switch back. What stays the kernel's (the redirect):
//! FUSE (the kernel is the FUSE client), the initial namespace (fixed layout), sysfs and
//! devtmpfs, paths that walk into what the kernel serves (`/proc`, `/dev`, FUSE), relative
//! paths when the working directory is not the root (no path text for it here), a caller
//! whose root is not its namespace's root. The kernel's own changes are taken with the
//! table before the next change (one table, one order of changes).

use hydra_rt::svcrt::{Answer, Cx};
use hydra_rt::sys;

use crate::calls::{self, ctxt};
use crate::mtab::CAP_SYS_CHROOT;
use crate::perm::MAY_EXEC;
use crate::proto::{LxFhDesc, LX_FH_CHROOT, LX_FH_CLAIM};
// wave8 GF begin
use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ctx::Ctx;
use crate::fs::fsproto::{FS_MKDIR, FS_RMDIR};
use crate::ktab::{self, Loc};
use crate::lock::YLock;
use crate::mntrec::{self, MntTable};
use crate::proto::{LX_FHC_NAMES, LX_FH_CHANGED, LX_FH_MNTGET, LX_FH_MNTPUT, LX_FH_REROOT, LX_FH_TMPFSID, LX_FS_MNTADMIN};
use crate::zfs;

const EAGAIN: i64 = -11;
const ENOENT: i64 = -2;
// wave8 GF end

const EPERM: i64 = -1;
const ENOTDIR: i64 = -20;
const EACCES: i64 = -13;

/// The calls served here: chroot (wave7 G7-7: claimed again; see the module notes on
/// nstest's `chroot("/proc/self/fdinfo/")`).
/// wave8 GF: and `pivot_root` (155), `mount` (165), `umount2` (166).
pub const CLAIMED: &[u64] = &[161, 155, 165, 166];

/// Claims [`CLAIMED`] (`mcalls=0` among the program's arguments leaves them to the kernel;
/// wave8 GF: `mounts=0` leaves only the three mount changes to it).
pub fn claim_all(args: &[&str]) -> usize {
    if args.iter().any(|a| *a == "mcalls=0") {
        return 0;
    }
    let no_mounts = args.iter().any(|a| *a == "mounts=0");
    CLAIMED.iter().filter(|&&nr| !(no_mounts && nr != 161)).filter(|&&nr| sys::lx_obj(LX_FH_CLAIM, nr, 1, 0).is_ok()).count()
}

/// Serves `cx` if it is one of these calls.
pub fn serve(cx: &Cx) -> Option<Answer> {
    let r = match cx.nr {
        161 => chroot(cx),
        // wave8 GF begin
        155 | 165 | 166 => changes(cx),
        // wave8 GF end
        _ => return None,
    };
    Some(calls::answer(cx, r))
}

// wave8 GF begin: mount, umount2, pivot_root

/// Mount changes served, sent back to the kernel, and redone after the kernel's table
/// changed under one (compare and set failed), since start.
pub static SERVED: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static REDONE: AtomicU64 = AtomicU64::new(0);

/// One mount change at a time here (the kernel's own changes are caught by the compare and
/// set).
static TURN: YLock<()> = YLock::new(());

/// A real errno, or "the kernel answers" for anything else (a redirect the walk found).
fn errno_or_kernel(e: i64) -> i64 {
    if (-4095..0).contains(&e) { e } else { calls::KERNEL }
}

/// `mount`, `umount2`, `pivot_root`: decided on the namespace's table, which is then
/// written back (redone when the kernel changed it meanwhile; after that many tries the
/// kernel answers).
fn changes(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    // (the initial namespace: fixed layout and FUSE, the kernel's — it keeps those calls)
    if c.mnt_ns == 0 {
        return Err(calls::KERNEL);
    }
    let _turn = TURN.lock();
    for attempt in 0..6 {
        let r = change_once(cx);
        match r {
            Err(EAGAIN_PUT) => {
                REDONE.fetch_add(1, Ordering::Relaxed);
                if attempt == 0 {
                    continue;
                }
                sys::sleep_ms(1);
            }
            Err(calls::KERNEL) => {
                TO_KERNEL.fetch_add(1, Ordering::Relaxed);
                return Err(calls::KERNEL);
            }
            r => {
                let n = SERVED.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_power_of_two() && n >= 64 {
                    hydra_rt::println!("[vfs-server] {} mount changes decided here (to the kernel {}, redone {})", n, TO_KERNEL.load(Ordering::Relaxed), REDONE.load(Ordering::Relaxed));
                }
                return r;
            }
        }
    }
    TO_KERNEL.fetch_add(1, Ordering::Relaxed);
    Err(calls::KERNEL)
}

/// What a lost compare and set answers inside [`changes`] (never to the caller).
const EAGAIN_PUT: i64 = i64::MIN + 1;

/// The calls' system side: a new tmpfs tree (kept across a redo of the same call).
struct SysEnv {
    made: Option<(u32, u64, u64)>,
}

impl ktab::Env for SysEnv {
    fn make_tmpfs(&mut self, mode: u32, uid: u32, gid: u32) -> Result<(u32, u64), i64> {
        if let Some((n, root, _)) = self.made {
            return Ok((n, root));
        }
        let mut out = [0u64; 2];
        sys::lx_obj(LX_FH_TMPFSID, out.as_mut_ptr() as u64, 0, 0).map_err(|_| calls::KERNEL)?;
        let (n, dir) = (out[0] as u32, out[1]);
        let name = alloc::format!("{}", n);
        let r = zfs::request(FS_MKDIR, |w| {
            w.u64(dir);
            w.bytes(name.as_bytes());
            w.u64(mode as u64);
            w.u64(uid as u64);
            w.u64(gid as u64);
        })?;
        let _ = sys::lx_obj(LX_FH_CHANGED, dir, LX_FHC_NAMES, 0);
        self.made = Some((n, r.value, dir));
        Ok((n, r.value))
    }
}

impl SysEnv {
    /// The call failed: the tree made for it goes (it is empty).
    fn undo(&mut self) {
        if let Some((n, _, dir)) = self.made.take() {
            let name = alloc::format!("{}", n);
            let _ = zfs::request(FS_RMDIR, |w| {
                w.u64(dir);
                w.bytes(name.as_bytes());
            });
            let _ = sys::lx_obj(LX_FH_CHANGED, dir, LX_FHC_NAMES, 0);
        }
    }
}

/// Namespace `ns`'s whole table from the kernel.
fn pull(ns: u32) -> Result<MntTable, i64> {
    let mut cap = 16 * 1024;
    for _ in 0..4 {
        let mut buf = alloc::vec![0u8; cap];
        let n = sys::lx_obj(LX_FH_MNTGET, ns as u64, buf.as_mut_ptr() as u64, cap as u64).map_err(|_| calls::KERNEL)? as usize;
        if n > cap {
            cap = n + 4096;
            continue;
        }
        return mntrec::decode(&buf[..n]).map_err(|_| calls::KERNEL);
    }
    Err(calls::KERNEL)
}

/// Writes table `t` back as namespace `ns`'s ([`EAGAIN_PUT`]: the kernel's changed since
/// it was read).
fn push(ns: u32, t: &MntTable) -> Result<(), i64> {
    let b = mntrec::encode(t);
    match sys::lx_obj(LX_FH_MNTPUT, ns as u64, b.as_ptr() as u64, b.len() as u64) {
        Ok(removed) => {
            // (the kernel removed tmpfs trees on this thread: no change notes come for their
            // objects, whose numbers zfs-server may give out again)
            if removed > 0 {
                crate::cache::forget_all();
            }
            Ok(())
        }
        Err(EAGAIN) => Err(EAGAIN_PUT),
        // (a table the kernel refuses, a namespace that went: the kernel answers)
        Err(_) => Err(calls::KERNEL),
    }
}

/// Locates path argument `ptr` of call `cx` in table `t`: its absolute path in the
/// namespace and the object the walk finds. `lenient`: a path that does not resolve is
/// `(path, 0, 0)`.
fn locate(cx: &Cx, t: &MntTable, who: &Ctx, ptr: u64, follow: bool, lenient: bool) -> Result<Loc, i64> {
    let c = &cx.c;
    let path = ctxt::path(cx, ptr, false)?;
    let text = core::str::from_utf8(&path).map_err(|_| calls::KERNEL)?;
    let abs = if path.first() == Some(&b'/') {
        ktab::normalize(text)
    } else {
        // (relative: only from a working directory at the root, whose path is "/")
        let root_ino = t.get(t.root).map_or(0, |m| m.root);
        let at_root = c.cwd == 0 || (c.cwd == root_ino && (c.cwd_mnt == 0 || c.cwd_mnt == t.root));
        if !at_root {
            return Err(calls::KERNEL);
        }
        ktab::normalize(&alloc::format!("/{}", text))
    };
    let found = ctxt::find(c, who, &path, follow);
    // (the first failures of this instance in the log, to tell vfs-server's answer from the
    // kernel's when a program is surprised)
    if let Err(e) = found {
        if e != ENOENT || !lenient {
            let n = LOCATE_ERRS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                hydra_rt::println!("[vfs-server] mount call {}: {} did not resolve here ({})", cx.nr, abs, if (-4095..0).contains(&e) { e } else { 0 });
            }
        }
    }
    match found {
        Ok((node, attr)) => Ok(Loc { path: abs, ino: node.ino, mnt: node.mnt as u32, is_dir: attr.is_dir() }),
        Err(e) if lenient && (e == ENOENT || e == ENOTDIR) => Ok(Loc { path: abs, ino: 0, mnt: 0, is_dir: false }),
        // (inside a user namespace of its own the walk has no capabilities here: the kernel
        // decides what it may see)
        Err(e) if c.user_ns != 0 && (-4095..0).contains(&e) => Err(calls::KERNEL),
        Err(e) => Err(errno_or_kernel(e)),
    }
}

/// Paths of mount calls that did not resolve here (the first are logged).
static LOCATE_ERRS: AtomicU64 = AtomicU64::new(0);

/// An optional string argument as the kernel reads it (unreadable: none).
fn opt_str(cx: &Cx, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }
    cx.user_cstr(ptr).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// One try of a mount change: read the table, decide, write it back.
fn change_once(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    let a = cx.args;
    let admin = c.fs_flags & LX_FS_MNTADMIN != 0;
    // (FUSE: the kernel is its client — before the capability, as the kernel's order)
    let fs = if cx.nr == 165 && a[2] != 0 { opt_str(cx, a[2]) } else { None };
    if cx.nr == 165 && fs.as_deref().is_some_and(ktab::is_fuse_type) && a[3] & (ktab::MS_REMOUNT | ktab::MS_BIND | ktab::MS_MOVE) == 0 {
        return Err(calls::KERNEL);
    }
    if !admin {
        return Err(EPERM);
    }
    if cx.nr == 166 && a[1] & !(ktab::MNT_FORCE | ktab::MNT_DETACH | ktab::MNT_EXPIRE | ktab::UMOUNT_NOFOLLOW) != 0 {
        return Err(ktab::EINVAL);
    }
    let mut t = pull(c.mnt_ns)?;
    // (a root other than the namespace's: the kernel's paths; vfs-server's walk would agree,
    // but the shown paths start at the namespace's root)
    let root_ino = t.get(t.root).map_or(0, |m| m.root);
    if c.root != 0 && !(c.root == root_ino && (c.root_mnt == 0 || c.root_mnt == t.root)) {
        return Err(calls::KERNEL);
    }
    let who = ctxt::caller(c)?;
    let mut env = SysEnv { made: None };
    let r = match cx.nr {
        165 => {
            let flags = a[3];
            let target = locate(cx, &t, &who, a[1], true, ktab::lenient(flags))?;
            let source_name = opt_str(cx, a[0]);
            let data = opt_str(cx, a[4]);
            let src = if flags & (ktab::MS_BIND | ktab::MS_MOVE) != 0 {
                if a[0] == 0 { Err(ktab::EFAULT) } else { Ok(locate(cx, &t, &who, a[0], true, false)?) }
            } else {
                Err(ktab::EFAULT)
            };
            ktab::mount(&mut t, src.as_ref().map_err(|e| *e), &target, fs.as_deref(), source_name.as_deref(), flags, data.as_deref(), (c.euid, c.egid), &mut env)
        }
        166 => {
            let target = locate(cx, &t, &who, a[0], a[1] & ktab::UMOUNT_NOFOLLOW == 0, true)?;
            ktab::umount(&mut t, &target, a[1])
        }
        _ => {
            let new_root = locate(cx, &t, &who, a[0], true, false)?;
            let put_old = locate(cx, &t, &who, a[1], true, false)?;
            ktab::pivot_root(&mut t, &new_root, &put_old)
        }
    };
    let done = match r {
        Ok(d) => d,
        Err(e) => {
            env.undo();
            return Err(e);
        }
    };
    if let Err(e) = push(c.mnt_ns, &t) {
        // (a redo makes its own tree again; a tree is never left behind)
        env.undo();
        return Err(e);
    }
    if let Some((old, new, mnt)) = done.pivot {
        let w: [u64; 4] = [old, 0, new, mnt as u64];
        let _ = sys::lx_obj(LX_FH_REROOT, c.mnt_ns as u64, w.as_ptr() as u64, 0);
    }
    Ok(0)
}
// wave8 GF end

/// `chroot(path)`.
fn chroot(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    // As the kernel: the capability before anything about the path
    // (wave7 G7-7: in a user namespace of its own the call carries no capabilities —
    // `LxCall::caps` is 0 there — but the kernel's rule counts the namespace's: the kernel
    // decides; nstest's Chromium-style `chroot("/proc/self/fdinfo/")` runs so)
    if c.caps & CAP_SYS_CHROOT == 0 {
        return Err(if c.user_ns != 0 { calls::KERNEL } else { EPERM });
    }
    let who = ctxt::caller(c)?;
    let path = ctxt::path(cx, cx.args[0], false)?;
    let (node, attr) = ctxt::find(c, &who, &path, true)?;
    // (a directory inside another mount: the kernel's, until handles carry mounts)
    if node.mnt != 0 {
        return Err(calls::KERNEL);
    }
    if !attr.is_dir() {
        return Err(ENOTDIR);
    }
    let acl = ctxt::acl_of(node, &attr)?;
    if !ctxt::may_access(&who, &attr, acl.as_deref(), who.uid, who.gid, MAY_EXEC) {
        return Err(EACCES);
    }
    let d = LxFhDesc { ino: node.ino, mnt: 0, is_dir: 1, ..LxFhDesc::EMPTY };
    sys::lx_obj(LX_FH_CHROOT, c.id, &d as *const LxFhDesc as u64, 0)?;
    // The first one of this instance in the log (shows vfs-server answers them)
    if !FIRST.swap(true, core::sync::atomic::Ordering::Relaxed) {
        hydra_rt::println!("[vfs-server] first chroot served (object {})", node.ino);
    }
    Ok(0)
}

/// Whether a chroot was served yet.
static FIRST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
