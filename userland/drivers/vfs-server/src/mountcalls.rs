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
use crate::walk::Backend; // wave10 GV2
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
const EINVAL: i64 = -22; // wave10 GV2
const EBADF: i64 = -9; // wave10 GV2
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
    // (wave11 GF: a walk's question to a FUSE daemon: the call waits and runs again)
    if (-4095..0).contains(&e) || crate::fuse::is_miss(e) { e } else { calls::KERNEL }
}

/// `mount`, `umount2`, `pivot_root`: decided on the namespace's table, which is then
/// written back (redone when the kernel changed it meanwhile; after that many tries the
/// kernel answers).
fn changes(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    // (a Landlock domain forbids mount changes: the kernel's rule; wave9 G6b-3: answered here)
    ctxt::check(c, 0)?;
    if c.ll_dom != 0 {
        return Err(EPERM);
    }
    // (the initial namespace: fixed layout; wave10 GV2: its FUSE mounts are decided here)
    if c.mnt_ns == 0 {
        return ns0(cx);
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

// wave10 GV2 begin: the initial namespace (fusermount3's FUSE mounts)
/// `MS_REMOUNT`, `MS_BIND`, `MS_MOVE`.
const MS_REMOUNT_BIND_MOVE: u64 = 32 | 4096 | 8192;
/// `UMOUNT_NOFOLLOW`.
const UMOUNT_NOFOLLOW: u64 = 8;

/// `mount`, `umount2`, `pivot_root` in the initial namespace: its layout is fixed (`EPERM`,
/// the kernel's rule) but for FUSE mounts, which fusermount3 makes and removes there
/// (vfs-server is the FUSE client: it mounts the connection; the kernel's list is the
/// write-through copy, `LX_FH_NS0FUSE`).
fn ns0(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    let admin = c.fs_flags & LX_FS_MNTADMIN != 0;
    match cx.nr {
        165 => ns0_mount(cx, admin),
        166 => ns0_umount(cx, admin),
        _ => Err(EPERM),
    }
}

/// The `fd=`, `user_id=`, `group_id=`, `allow_other` of FUSE mount data (`rootmode=` must be
/// there too), as the kernel's `fuse::options`.
pub fn fuse_options(data: &str) -> Result<(i32, u32, u32, bool), i64> {
    let (mut fd, mut rootmode, mut uid, mut gid, mut other) = (None, None, None, None, false);
    for o in data.split(',') {
        let (k, v) = o.split_once('=').unwrap_or((o, ""));
        match k {
            "fd" => fd = v.parse::<i32>().ok(),
            "rootmode" => rootmode = u32::from_str_radix(v, 8).ok(),
            "user_id" => uid = v.parse::<u32>().ok(),
            "group_id" => gid = v.parse::<u32>().ok(),
            "allow_other" => other = true,
            _ => {}
        }
    }
    match (fd, rootmode, uid, gid) {
        (Some(f), Some(_), Some(u), Some(g)) => Ok((f, u, g, other)),
        _ => Err(EINVAL),
    }
}

/// `mount(source, target, fstype, flags, data)` in the initial namespace.
fn ns0_mount(cx: &Cx, admin: bool) -> Result<i64, i64> {
    use crate::proto::{LxNs0Fuse, LX_FHP_ABS, LX_FHP_CWD, LX_FH_NS0FUSE, LX_FH_PATH_MAX, LX_NS0FUSE_ADD, LX_NS0FUSE_NAME_MAX, LX_OBJ_FD, LX_OBJ_KIND_FUSE};
    let c = &cx.c;
    let a = cx.args;
    let fstype = if a[2] != 0 { cx.user_cstr(a[2])? } else { alloc::vec::Vec::new() };
    let fuse = fstype == b"fuse" || fstype.starts_with(b"fuse.");
    if !fuse || a[3] & MS_REMOUNT_BIND_MOVE != 0 || !admin {
        return Err(EPERM);
    }
    let path = calls::ctxt::path(cx, a[1], false)?;
    let k = ctxt::call(c)?;
    let start = k.start(c, &path)?;
    let (n, attr, track) = match crate::walk::walk_track(&k.w, &k.who, start, &path, 0)? {
        (crate::walk::Walked::Found { node, attr }, t) => (node, attr, t),
        (crate::walk::Walked::Redirect(_), _) => return Err(calls::KERNEL),
    };
    if !attr.is_dir() {
        return Err(ENOTDIR);
    }
    // (on a FUSE directory or another mount: the kernel's)
    if n.mnt != 0 {
        return Err(calls::KERNEL);
    }
    if a[4] == 0 {
        return Err(EINVAL);
    }
    let data = cx.user_cstr(a[4])?;
    let (fd, uid, gid, other) = fuse_options(core::str::from_utf8(&data).map_err(|_| EINVAL)?)?;
    let source = if a[0] != 0 { cx.user_cstr(a[0]).unwrap_or_else(|_| fstype.clone()) } else { fstype.clone() };
    // The caller's /dev/fuse: one of this service's objects
    let v = sys::lx_obj(LX_OBJ_FD, c.id, fd as i64 as u64, 0).map_err(|_| EBADF)?;
    if (v >> 32) as u32 & 0x3FFF_FFFF != LX_OBJ_KIND_FUSE {
        return Err(EINVAL);
    }
    // (review 6: the record holds the whole path, type and source, or the mount is refused
    // before anything is mounted)
    let text = track.text();
    if text.len() > LX_FH_PATH_MAX {
        return Err(-36); // ENAMETOOLONG
    }
    if fstype.len() > LX_NS0FUSE_NAME_MAX || source.len() > LX_NS0FUSE_NAME_MAX {
        return Err(EINVAL);
    }
    let who = crate::fuse::wire::Who { uid: c.euid, gid: c.egid, pid: c.tgid as u32 };
    let conn = crate::fuse::mount_conn(v as u32, (uid, gid, other), who)?;
    let root = crate::fuse::wire::ino(conn, 1);
    let mut m = LxNs0Fuse {
        req: c.id,
        mountpoint: n.ino,
        root,
        flags: a[3],
        uid,
        gid,
        other: other as u32,
        path_kind: if track.abs { LX_FHP_ABS } else { LX_FHP_CWD },
        path_len: text.len().min(LX_FH_PATH_MAX) as u32,
        fstype_len: fstype.len().min(LX_NS0FUSE_NAME_MAX) as u32,
        source_len: source.len().min(LX_NS0FUSE_NAME_MAX) as u32,
        pad: 0,
        path: [0; LX_FH_PATH_MAX],
        fstype: [0; LX_NS0FUSE_NAME_MAX],
        source: [0; LX_NS0FUSE_NAME_MAX],
    };
    m.path[..m.path_len as usize].copy_from_slice(&text[..m.path_len as usize]);
    m.fstype[..m.fstype_len as usize].copy_from_slice(&fstype[..m.fstype_len as usize]);
    m.source[..m.source_len as usize].copy_from_slice(&source[..m.source_len as usize]);
    if let Err(e) = sys::lx_obj(LX_FH_NS0FUSE, LX_NS0FUSE_ADD, &m as *const LxNs0Fuse as u64, 0) {
        crate::fuse::abort_conn(conn);
        return Err(e);
    }
    hydra_rt::println!("[vfs-server] FUSE connection {} mounted on {} (initial namespace)", conn, core::str::from_utf8(&text).unwrap_or("?"));
    Ok(0)
}

/// `umount2(target, flags)` in the initial namespace: only a FUSE mount (fusermount3 -u).
fn ns0_umount(cx: &Cx, admin: bool) -> Result<i64, i64> {
    use crate::proto::{LX_FH_NS0FUSE, LX_MNT_FUSE, LX_NS0FUSE_REMOVE};
    let c = &cx.c;
    let a = cx.args;
    if !admin {
        return Err(EPERM);
    }
    if a[1] & !(1 | 2 | 4 | UMOUNT_NOFOLLOW) != 0 {
        return Err(EINVAL);
    }
    let path = calls::ctxt::path(cx, a[0], false)?;
    let k = ctxt::call(c)?;
    let start = k.start(c, &path)?;
    // The mount point as the pool has it (not crossed into the mount)
    let p = match crate::walk::walk_parent(&k.w, &k.who, start, &path)? {
        crate::walk::ParentWalked::Found(p) => p,
        crate::walk::ParentWalked::Redirect(_) => return Err(calls::KERNEL),
    };
    let Some(child) = p.child else { return Err(ENOENT) };
    let rec = k.w.view.recs.iter().rev().find(|r| r.kind == LX_MNT_FUSE && r.mountpoint == child.ino && r.parent == child.mnt as u32);
    // (a symbolic link to follow, or not a FUSE mount point: the kernel's rule for a fixed
    // layout is EPERM)
    let Some(rec) = rec else {
        return Err(if a[1] & UMOUNT_NOFOLLOW == 0 && k.w.getattr(child).is_ok_and(|at| at.mode & 0o170000 == 0o120000) { calls::KERNEL } else { EPERM });
    };
    let root = rec.root;
    let Some((conn, _)) = crate::fuse::wire::split(root) else { return Err(calls::KERNEL) };
    sys::lx_obj(LX_FH_NS0FUSE, LX_NS0FUSE_REMOVE, root, 0)?;
    crate::fuse::abort_conn(conn);
    hydra_rt::println!("[vfs-server] FUSE connection {} unmounted (initial namespace)", conn);
    Ok(0)
}
// wave10 GV2 end

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
    // wave9 GM begin
    fn tmpfs_data(&mut self, n: u32, data: Option<&str>) {
        crate::tmem::set_limit(n, data);
    }
    // wave9 GM end
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
        if e != ENOENT || !lenient || cx.nr == 166 {
            let n = LOCATE_ERRS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                hydra_rt::println!("[vfs-server] mount call {}: {} did not resolve here ({:#x})", cx.nr, abs, e);
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
    // (wave11 GF: a new FUSE mount is this service's too, below: vfs-server is the client)
    let fs = if cx.nr == 165 && a[2] != 0 { opt_str(cx, a[2]) } else { None };
    let new_fuse = cx.nr == 165 && fs.as_deref().is_some_and(ktab::is_fuse_type) && a[3] & (ktab::MS_REMOUNT | ktab::MS_BIND | ktab::MS_MOVE) == 0;
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
    // wave11 GF: a FUSE mount in this namespace
    if new_fuse {
        return ns_fuse_mount(cx, &mut t, &who, fs.as_deref().unwrap_or("fuse"));
    }
    let mut env = SysEnv { made: None };
    let r = match cx.nr {
        165 => {
            let flags = a[3];
            let target = locate(cx, &t, &who, a[1], true, ktab::lenient(flags))?;
            let source_name = opt_str(cx, a[0]);
            let data = opt_str(cx, a[4]);
            // (wave11 GF: a remount names no source: bubblewrap's "none")
            let src = if flags & (ktab::MS_BIND | ktab::MS_MOVE) != 0 && flags & ktab::MS_REMOUNT == 0 {
                if a[0] == 0 { Err(ktab::EFAULT) } else { Ok(locate(cx, &t, &who, a[0], true, false)?) }
            } else {
                Err(ktab::EFAULT)
            };
            ktab::mount(&mut t, src.as_ref().map_err(|e| *e), &target, fs.as_deref(), source_name.as_deref(), flags, data.as_deref(), (c.euid, c.egid), &mut env)
        }
        166 => {
            let target = locate(cx, &t, &who, a[0], a[1] & ktab::UMOUNT_NOFOLLOW == 0, true)?;
            let r = ktab::umount(&mut t, &target, a[1]);
            if r == Err(ktab::EINVAL) && LOCATE_ERRS.fetch_add(1, Ordering::Relaxed) < 8 {
                hydra_rt::println!("[vfs-server] umount2 {}: object {} in mount {} is no mount here (gen {}, {} slots, view gen {})", target.path, target.ino, target.mnt, t.gen, t.slots.len(), c.mnt_gen);
            }
            r
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

// wave11 GF begin: FUSE mounts in a namespace of the caller's own
/// `mount(source, target, "fuse[.name]", flags, "fd=N,...")` in namespace table `t`: the
/// caller's `/dev/fuse` connection (one of this service's objects) mounted at the target as
/// a tree whose root is the connection's root (the kernel's table shows it as a FUSE mount;
/// the walk goes into it, `LX_MNT_FUSE`). The connection ends with its daemon's close.
fn ns_fuse_mount(cx: &Cx, t: &mut MntTable, who: &Ctx, fstype: &str) -> Result<i64, i64> {
    use crate::proto::{LX_OBJ_FD, LX_OBJ_KIND_FUSE};
    let c = &cx.c;
    let a = cx.args;
    let target = locate(cx, t, who, a[1], true, false)?;
    if !target.is_dir {
        return Err(ENOTDIR);
    }
    let data = opt_str(cx, a[4]).ok_or(EINVAL)?;
    let (fd, uid, gid, other) = fuse_options(&data)?;
    let v = sys::lx_obj(LX_OBJ_FD, c.id, fd as i64 as u64, 0).map_err(|_| EBADF)?;
    if (v >> 32) as u32 & 0x3FFF_FFFF != LX_OBJ_KIND_FUSE {
        return Err(EINVAL);
    }
    let source = opt_str(cx, a[0]).unwrap_or_else(|| String::from(fstype));
    let fw = crate::fuse::wire::Who { uid: c.euid, gid: c.egid, pid: c.tgid as u32 };
    let conn = crate::fuse::mount_conn(v as u32, (uid, gid, other), fw)?;
    t.push(mntrec::MntRec {
        id: 0,
        parent: target.mnt,
        kind: mntrec::MK_TREE,
        tmpfs: 0,
        mountpoint: target.ino,
        root: crate::fuse::wire::ino(conn, 1),
        flags: a[3] & ktab::PER_MOUNT,
        propagation: 0,
        fstype: String::from(fstype),
        source,
        path: target.path.clone(),
        serves: None,
    });
    // (the table changed meanwhile: the connection is ended, the caller sees EBUSY; rare)
    if let Err(e) = push(c.mnt_ns, t) {
        crate::fuse::abort_conn(conn);
        return Err(if e == EAGAIN_PUT { -16 } else { e });
    }
    hydra_rt::println!("[vfs-server] FUSE connection {} mounted on {} (namespace {})", conn, target.path, c.mnt_ns);
    Ok(0)
}
// wave11 GF end

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
    if !ctxt::allowed(&who, &attr, acl.as_deref(), who.uid, who.gid, MAY_EXEC, &path)? { // wave9 G6b-3: and ABAC
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
