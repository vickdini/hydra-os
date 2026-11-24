//! The calls that change files and names (the kernel's `vfs::setattr_at`, `with_parent`,
//! `rename_at` and the `mkdir`, `symlink`, `unlink`/`rmdir` arms): the walk and the checks
//! here, the change through zfs-server, then the caches: vfs-server's own (`cache`) and the
//! kernel's (`LX_FH_CHANGED`: names, attributes, the page cache).
//!
//! Sent to the kernel before anything changes: callers with inotify or fanotify watches
//! (their events come from the kernel's client); a new object in a
//! directory with extended attributes (a default ACL would be inherited); `utimensat` with
//! "now" (the kernel's clock).

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt::{self, KERNEL};
use super::rules;
use crate::cache;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::{suid_killed, Attr, SetAttr, FS_MKDIR, FS_RENAME, FS_RMDIR, FS_SETATTR, FS_SYMLINK, FS_UNLINK};
use crate::policy::{self, ll};
use crate::proto::{LxCall, LX_FHC_ALL_ATTRS, LX_FHC_ATTR, LX_FHC_GONE, LX_FHC_NAMES, LX_FHC_TRUNC, LX_FH_CHANGED, LX_FH_NOTRUNC, LX_FS_FANOTIFY, LX_FS_INOTIFY};
use crate::walk::{self, Backend, ParentWalked};
use crate::zfs;

const EPERM: i64 = -1;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EXDEV: i64 = -18; // wave10 GV1
const EACCES: i64 = -13;

/// What only the kernel has for a change (wave9 G6b-3: Landlock and ABAC are checked here).
const NEED: u32 = LX_FS_INOTIFY | LX_FS_FANOTIFY;
/// `CAP_FSETID`.
const CAP_FSETID: u32 = 4;
const AT_REMOVEDIR: u64 = 0x200;
const RENAME_NOREPLACE: u64 = 1;

/// Tells the kernel's caches about change `what` (`LX_FHC_*`) to `ino`.
pub fn tell_kernel(ino: u64, what: u64, size: u64) {
    let _ = sys::lx_obj(LX_FH_CHANGED, ino, what, &size as *const u64 as u64);
}

// ----------------------------------------------------------------------
// Attribute changes
// ----------------------------------------------------------------------

/// The object of a change on `path` (`ptr` 0 or an empty path: the descriptor, if
/// `empty_ok`).
fn target(cx: &Cx, who: &Ctx, ptr: u64, follow: bool, empty_ok: bool) -> Result<(Node, Attr), i64> {
    let c = &cx.c;
    let path = if ptr == 0 { alloc::vec::Vec::new() } else { cx.user_cstr(ptr)? };
    if path.is_empty() {
        if !empty_ok {
            return Err(rules::ENOENT);
        }
        let n = ctxt::handle(c)?;
        return Ok((n, ctxt::attr_of(c, n)?)); // wave11 GF: (a FUSE file's too)
    }
    ctxt::find(c, who, &path, follow)
}

// wave11 GF begin: changes of FUSE files (the daemon's operations; the reply answers)
/// [`setattr`], or for a FUSE file the daemon's SETATTR (the call waits for the reply).
fn set_on(c: &LxCall, who: &Ctx, n: Node, a: &Attr, set: SetAttr) -> Result<i64, i64> {
    if !ctxt::is_fuse(n) {
        return setattr(who, n, a, set);
    }
    let what = LX_FHC_ATTR | if set.size.is_some() { LX_FHC_TRUNC } else { 0 };
    let size = set.size.unwrap_or(0);
    crate::fuse::start(c, n.ino, crate::fuse::Req::Setattr(set), then_tell(crate::fuse::How::Zero, n.ino, what, size))
}

/// A [`crate::fuse::Then`] telling the kernel's caches `what` about `ino` after a success.
pub(super) fn then_tell(how: crate::fuse::How, ino: u64, what: u64, size: u64) -> crate::fuse::Then {
    crate::fuse::Then { how, tell: Some((ino, what, size)) }
}

/// The FUSE operation of a name change in directory `dir`: 0 from the daemon's reply (the
/// kernel's name caches are told, as [`names_changed`]).
pub(super) fn fuse_names(c: &LxCall, dir: Node, req: crate::fuse::Req) -> Result<i64, i64> {
    // ("." and ".." always exist: Linux's VFS answers before the file system)
    if let crate::fuse::Req::Mkdir { name, .. } | crate::fuse::Req::Mknod { name, .. } | crate::fuse::Req::Symlink { name, .. } | crate::fuse::Req::Link { name, .. } = &req {
        if name == b"." || name == b".." {
            return Err(EEXIST);
        }
    }
    crate::fuse::start(c, dir.ino, req, then_tell(crate::fuse::How::Zero, 0, LX_FHC_NAMES | LX_FHC_ALL_ATTRS, 0))
}
// wave11 GF end

/// Applies `set` to `n` (attributes `a` before) through zfs-server (the caller checked that
/// `n`'s mount is writable: [`attrs`]).
pub(super) fn setattr(who: &Ctx, n: Node, a: &Attr, mut set: SetAttr) -> Result<i64, i64> {
    // wave9 GM: an in-memory tmpfs file's size and data times are the kernel's (wave10 GV1:
    // changed there by `tmem`'s calls, the rest here)
    let mem = (set.size.is_some() || set.mtime.is_some()) && crate::tmem::candidate(a) && crate::tmem::is_tmem(n.ino);
    // A truncation by a caller without CAP_FSETID drops the set-ID bits, as a write does
    if let (Some(_), None) = (set.size, set.mode) {
        if !who.cap(CAP_FSETID) && a.mode & 0o170000 != 0o040000 {
            let mut groups = alloc::vec![who.gid];
            groups.extend_from_slice(&who.groups[..who.ngroups]);
            let m = suid_killed(a.mode & 0o7777, a.gid, &groups);
            if m != a.mode & 0o7777 {
                set.mode = Some(m);
            }
        }
    }
    // wave10 GV1 begin
    let cut = if mem { set.size.take() } else { None };
    // (the in-memory data first: a truncation the tmpfs refuses (EFBIG, its size=) changes
    // nothing else — review 9)
    if let Some(size) = cut {
        if let Err(e) = crate::tmem::truncate(n.ino, size) {
            return Err(e);
        }
    }
    if mem && set.mtime.is_some() {
        crate::tmem::times_set(n.ino);
    }
    let nothing = set.mode.is_none() && set.uid.is_none() && set.gid.is_none() && set.size.is_none() && set.atime.is_none() && set.mtime.is_none() && !set.kill_suid;
    let zr = if mem && nothing {
        None
    } else {
        Some(zfs::request(FS_SETATTR, |w| {
            w.u64(n.ino);
            w.setattr(&set);
        }))
    };
    // wave9 G6b-1: the events of the change for inotify/fanotify
    if let Some(z) = &zr {
        crate::notify::changed(z, who);
    }
    let r: Result<(), i64> = match zr {
        Some(Err(e)) => Err(e),
        _ => Ok(()),
    };
    // wave10 GV1 end
    // wave10 GV1: a mode change of an object with extended attributes also rewrites its
    // access ACL's owner, mask and other entries (the kernel's `acl::on_chmod`)
    if let (Ok(_), Some(mode), true) = (&r, set.mode, a.has_xattr) {
        acl_follows_mode(n, mode);
    }
    cache::forget_attr(n);
    // (the page cache is cut only when the file was)
    let size = set.size.unwrap_or(0);
    tell_kernel(n.ino, LX_FHC_ATTR | if set.size.is_some() && r.is_ok() { LX_FHC_TRUNC } else { 0 }, size);
    r.map(|_| 0)
}

// wave10 GV1 begin
/// The truncation of a truncating `open` of regular file `n` (attributes `a`), as the
/// kernel's: to size 0, the set-ID bits as for any truncation.
pub(super) fn truncate_for_open(who: &Ctx, n: Node, a: &Attr) -> Result<(), i64> {
    setattr(who, n, a, SetAttr { size: Some(0), ..SetAttr::default() }).map(|_| ())
}

/// After a chmod of `n` to `mode`: its access ACL, if it has one, takes the new owner, mask
/// (or owning group) and other bits.
fn acl_follows_mode(n: Node, mode: u32) {
    if let Ok(old) = zfs::getxattr(n.ino, super::acl::ACCESS) {
        if let Some(new) = super::acl::on_chmod(&old, mode) {
            let _ = zfs::request(crate::fs::fsproto::FS_SETXATTR, |w| {
                w.u64(n.ino);
                w.bytes(super::acl::ACCESS);
                w.bytes(&new);
                w.u64(0);
            });
        }
    }
}
// wave10 GV1 end

/// `chown`'s rule ([`rules::chown_ok`]).
fn chown_ok(who: &Ctx, a: &Attr, uid: u32, gid: u32) -> bool {
    rules::chown_ok(who.uid, a.uid, a.gid, uid, gid, |g| who.in_group(g))
}

/// `chmod`, `fchmodat`, `fchmod`, `chown`, `lchown`, `fchownat`, `fchown`, `truncate`,
/// `ftruncate`, `utimensat`.
pub fn attrs(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let who = ctxt::caller(c)?;
    let owner = |who: &Ctx, at: &Attr| who.uid == 0 || who.uid == at.uid;
    match cx.nr {
        // chmod(path, mode), fchmodat(dirfd, path, mode), fchmod(fd, mode), (wave10 GV1)
        // fchmodat2(dirfd, path, mode, flags)
        90 | 268 | 91 | 452 => {
            let (ptr, mode, follow, empty) = match cx.nr {
                90 => (a[0], a[1], true, false),
                268 => (a[1], a[2], true, false),
                452 => {
                    if a[3] & !(ctxt::AT_SYMLINK_NOFOLLOW | ctxt::AT_EMPTY_PATH) != 0 {
                        return Err(EINVAL);
                    }
                    (a[1], a[2], a[3] & ctxt::AT_SYMLINK_NOFOLLOW == 0, a[3] & ctxt::AT_EMPTY_PATH != 0)
                }
                _ => (0, a[1], true, true),
            };
            let (n, at) = target(cx, &who, ptr, follow, empty)?;
            // (wave10 GV1: fchmodat2 with AT_SYMLINK_NOFOLLOW on a link: Linux's EOPNOTSUPP)
            if !follow && at.mode & 0o170000 == 0o120000 {
                return Err(-95);
            }
            // (wave10 GV1: an access ACL takes the new bits in `setattr`)
            ctxt::writable(c, n)?; // wave7 G7-7
            if !owner(&who, &at) {
                return Err(EPERM);
            }
            set_on(c, &who, n, &at, SetAttr { mode: Some(mode as u32), ..SetAttr::default() })
        }
        // chown(path, uid, gid), lchown, fchownat(dirfd, path, uid, gid, flags), fchown
        92 | 94 | 260 | 93 => {
            let (ptr, uid, gid, follow, empty) = match cx.nr {
                92 => (a[0], a[1], a[2], true, false),
                94 => (a[0], a[1], a[2], false, false),
                260 => (a[1], a[2], a[3], a[4] & ctxt::AT_SYMLINK_NOFOLLOW == 0, a[4] & ctxt::AT_EMPTY_PATH != 0),
                _ => (0, a[1], a[2], true, true),
            };
            let (uid, gid) = (uid as u32, gid as u32);
            let (n, at) = target(cx, &who, ptr, follow, empty)?;
            ctxt::writable(c, n)?; // wave7 G7-7
            if !chown_ok(&who, &at, uid, gid) {
                return Err(EPERM);
            }
            let set = SetAttr {
                uid: (uid != u32::MAX).then_some(uid),
                gid: (gid != u32::MAX).then_some(gid),
                // Linux clears the set-ID bits of a non-directory on any chown
                kill_suid: true,
                ..SetAttr::default()
            };
            set_on(c, &who, n, &at, set)
        }
        // truncate(path, size)
        76 => {
            if (a[1] as i64) < 0 {
                return Err(EINVAL);
            }
            let (n, at) = target(cx, &who, a[0], true, false)?;
            // wave9 G6b-3: Landlock's TRUNCATE first, as the kernel
            if let Some(d) = policy::domain(c)? {
                if policy::refused_on(&d, c.id, n, at.is_dir(), ll::TRUNCATE)? != 0 {
                    return Err(EACCES);
                }
            }
            ctxt::writable(c, n)?; // wave7 G7-7
            let acl = ctxt::acl_of(n, &at)?;
            // (wave11 GF: EACCES, as Linux's `do_sys_truncate`; the kernel's copy said EPERM)
            if !ctxt::allowed(&who, &at, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE, b"")? {
                return Err(EACCES);
            }
            // wave10 GV1 (review 3): a running program's file is not truncated
            if crate::tmem::text_busy_attr(&at) {
                return Err(-26); // ETXTBSY
            }
            set_on(c, &who, n, &at, SetAttr { size: Some(a[1]), ..SetAttr::default() })
        }
        // ftruncate(fd, size): a handle open for writing
        77 => {
            if (a[1] as i64) < 0 {
                return Err(EINVAL);
            }
            if c.fh_flags & rules::O_ACCMODE == rules::O_RDONLY {
                return Err(EINVAL);
            }
            // wave9 G6b-3: Landlock refused TRUNCATE when the handle was opened
            if c.fh_flags & LX_FH_NOTRUNC != 0 {
                return Err(EACCES);
            }
            let n = ctxt::handle(c)?;
            ctxt::writable(c, n)?; // wave7 G7-7
            let at = ctxt::attr_of(c, n)?; // wave11 GF: (a FUSE file's too)
            set_on(c, &who, n, &at, SetAttr { size: Some(a[1]), ..SetAttr::default() })
        }
        // wave10 GV1 begin: utimensat(dirfd, path, times, flags), utime(path, times),
        // utimes(path, times), futimesat(dirfd, path, times); "now" from the wall clock
        _ => {
            let (ptr, times, follow, empty) = match cx.nr {
                280 => {
                    if a[3] & !(ctxt::AT_SYMLINK_NOFOLLOW | ctxt::AT_EMPTY_PATH) != 0 {
                        return Err(EINVAL);
                    }
                    (a[1], a[2], a[3] & ctxt::AT_SYMLINK_NOFOLLOW == 0, true)
                }
                261 => (a[1], a[2], true, false),
                _ => (a[0], a[1], true, false),
            };
            let raw = match (cx.nr, times) {
                (_, 0) => None,
                (132, p) => Some(cx.copy_in(p, 16)?),
                (_, p) => Some(cx.copy_in(p, 32)?),
            };
            let now = {
                let (s, ns) = sys::clock();
                (s as i64, ns)
            };
            let (atime, mtime) = rules::utimes(cx.nr, raw.as_deref(), now)?;
            let explicit = rules::times_explicit(cx.nr, raw.as_deref());
            let (n, at) = target(cx, &who, ptr, follow, empty)?;
            // (both omitted: nothing changes; Linux answers 0 after the walk)
            if atime.is_none() && mtime.is_none() {
                return Ok(0);
            }
            ctxt::writable(c, n)?; // wave7 G7-7
            if !owner(&who, &at) {
                // "now" needs write access, explicit times the owner (Linux's rule)
                if explicit {
                    return Err(EPERM);
                }
                let acl = ctxt::acl_of(n, &at)?;
                if !ctxt::allowed(&who, &at, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE, b"")? {
                    return Err(EACCES);
                }
            }
            set_on(c, &who, n, &at, SetAttr { atime, mtime, ..SetAttr::default() })
            // wave10 GV1 end
        }
    }
}

// ----------------------------------------------------------------------
// Names
// ----------------------------------------------------------------------

/// The directory and last name of `path` for a change, with the kernel's checks
/// (`with_parent`): `EEXIST`/`ENOENT` for the name first, then write and search permission
/// on the directory. `create`: the call makes the name.
pub(super) fn parent(c: &LxCall, who: &Ctx, path: &[u8], create: bool) -> Result<walk::Parent, i64> {
    let start = ctxt::start(c, path)?;
    let p = match walk::walk_parent(&ctxt::walker(c)?, who, start, path)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    parent_checks(c, who, p, path, create)
}

/// [`parent`]'s checks on an already walked parent `p` (wave10 GV1: a creating open walks
/// it itself).
pub(super) fn parent_checks(c: &LxCall, who: &Ctx, p: walk::Parent, path: &[u8], create: bool) -> Result<walk::Parent, i64> {
    // (wave11 GF: a FUSE directory's changes are this service's too: `crate::fuse::start`)
    if !p.dir_attr.is_dir() {
        return Err(ENOTDIR);
    }
    // wave7 G7-7: a read-only mount, or a mount point to remove: the kernel's
    ctxt::writable(c, p.dir)?;
    if let Some(ch) = p.child {
        ctxt::not_mountpoint(c, ch)?;
    }
    if p.name != b"." && p.name != b".." {
        match p.child {
            Some(_) if create => return Err(EEXIST),
            None if !create => return Err(rules::ENOENT),
            _ => {}
        }
    }
    // (wave10 GV1: a new object in a labelled folder inherits its labels here, `xattr::new_mode`)
    let acl = ctxt::acl_of(p.dir, &p.dir_attr)?;
    if !ctxt::allowed(who, &p.dir_attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC, path)? {
        return Err(EACCES);
    }
    Ok(p)
}

/// The kernel's sticky-directory rule ([`rules::sticky_denied`]).
pub(super) fn sticky_denied(c: &LxCall, dir: &Attr, entry: Node) -> Result<bool, i64> {
    let euid = c.euid;
    if euid == 0 || dir.mode & 0o1000 == 0 || dir.uid == euid {
        return Ok(false);
    }
    // (wave11 GF: a FUSE entry's owner from the daemon)
    Ok(rules::sticky_denied(dir.mode, dir.uid, ctxt::attr_of(c, entry)?.uid, euid))
}

/// After a change of names in `dirs`: vfs-server's caches and the kernel's.
pub(super) fn names_changed(dirs: &[Node], gone: Option<u64>) {
    for d in dirs {
        cache::forget_dir(*d);
        cache::forget_attr(*d);
    }
    if let Some(ino) = gone {
        cache::CACHE.forget_object(ino);
    }
    tell_kernel(gone.unwrap_or(0), LX_FHC_NAMES | LX_FHC_ALL_ATTRS | if gone.is_some() { LX_FHC_GONE } else { 0 }, 0);
}

/// `mkdir(path, mode)`, `mkdirat(dirfd, path, mode)`.
pub fn mkdir(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let (ptr, mode) = if cx.nr == 83 { (a[0], a[1]) } else { (a[1], a[2]) };
    let path = ctxt::path(cx, ptr, false)?;
    let who = ctxt::caller(c)?;
    let p = parent(c, &who, &path, true)?;
    // wave9 G6b-3: Landlock
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, p.dir, ll::MAKE_DIR)?;
    }
    // wave11 GF: in a FUSE mount: the daemon's MKDIR (the umask applied here)
    if ctxt::is_fuse(p.dir) {
        let perm = mode as u32 & 0o7777 & !(c.umask as u32);
        return fuse_names(c, p.dir, crate::fuse::Req::Mkdir { name: p.name, perm });
    }
    // wave10 GV1: a default ACL and the labels are inherited here
    let (perm, plan) = super::xattr::new_mode(p.dir, &p.dir_attr, mode as u32 & 0o7777, c.umask as u32, true)?;
    let r = zfs::request(FS_MKDIR, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.u64(perm as u64);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
    // wave9 G6b-1: the events of the change for inotify/fanotify
    crate::notify::changed(&r, &who);
    if let Ok(made) = &r {
        if !plan.is_empty() {
            super::xattr::inherit(made.value, &plan); // wave10 GV1
        }
    }
    names_changed(&[p.dir], None);
    r.map(|_| 0)
}

/// `symlink(target, path)`, `symlinkat(target, dirfd, path)`.
pub fn symlink(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let target = ctxt::path(cx, a[0], false)?;
    let ptr = if cx.nr == 88 { a[1] } else { a[2] };
    let path = ctxt::path(cx, ptr, false)?;
    let who = ctxt::caller(c)?;
    let p = parent(c, &who, &path, true)?;
    // wave9 G6b-3: Landlock
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, p.dir, ll::MAKE_SYM)?;
    }
    // wave11 GF: in a FUSE mount: the daemon's SYMLINK
    if ctxt::is_fuse(p.dir) {
        return fuse_names(c, p.dir, crate::fuse::Req::Symlink { name: p.name, to: target });
    }
    let r = zfs::request(FS_SYMLINK, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.bytes(&target);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
    // wave9 G6b-1: the events of the change for inotify/fanotify
    crate::notify::changed(&r, &who);
    names_changed(&[p.dir], None);
    r.map(|_| 0)
}

/// `unlink(path)`, `rmdir(path)`, `unlinkat(dirfd, path, flags)`.
pub fn unlink(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let (ptr, rmdir) = match cx.nr {
        87 => (a[0], false),
        84 => (a[0], true),
        _ => (a[1], a[2] & AT_REMOVEDIR != 0),
    };
    let path = ctxt::path(cx, ptr, false)?;
    let who = ctxt::caller(c)?;
    let p = parent(c, &who, &path, false)?;
    // wave11 GF: an efivars file: linux-server deletes the variable (the pool's file follows)
    if !rmdir && super::served::is_efivars_dir(&ctxt::walker(c)?, &who, p.dir) {
        if let Some(tail) = super::served::efivars_tail(&path) {
            let r = crate::walk::Redirect { svc: crate::proto::LXS_LINUX, obj: crate::proto::LX_VFS_PSEUDO_SYS, tail: Some(tail), text: alloc::vec::Vec::new() };
            return Err(super::pseudo_redirect(&r));
        }
        return Err(KERNEL);
    }
    // wave9 G6b-3: Landlock (by the call: rmdir needs REMOVE_DIR, unlink REMOVE_FILE)
    if let Some(d) = policy::domain(c)? {
        policy::check_dir(&d, p.dir, if rmdir { ll::REMOVE_DIR } else { ll::REMOVE_FILE })?;
    }
    let victim = p.child;
    // wave9 GM: an in-memory tmpfs file's last name: the kernel frees its data (wave10 GV1:
    // told after the unlink here)
    let mem = !rmdir && victim.is_some_and(crate::tmem::node_is_tmem);
    if let Some(v) = victim {
        if sticky_denied(c, &p.dir_attr, v)? {
            return Err(EPERM);
        }
        // wave9 G6b-3: the access policies: deleting needs the delete right on the file
        if who.abac && c.euid != 0 && !policy::abac(&who, &ctxt::attr_of(c, v)?, 0, true, &path)? {
            return Err(EACCES);
        }
    }
    // wave11 GF: in a FUSE mount: the daemon's UNLINK or RMDIR (the types checked here, as
    // Linux's VFS does before asking any file system)
    if ctxt::is_fuse(p.dir) {
        match (&p.name[..], rmdir) {
            (b".", true) => return Err(EINVAL),
            (b"..", true) => return Err(-39), // ENOTEMPTY
            (b"." | b"..", false) => return Err(-21), // EISDIR
            _ => {}
        }
        let v = victim.ok_or(rules::ENOENT)?;
        let dir = ctxt::attr_of(c, v)?.is_dir();
        if rmdir && !dir {
            return Err(ENOTDIR);
        }
        if !rmdir && dir {
            return Err(-21); // EISDIR
        }
        let req = if rmdir { crate::fuse::Req::Rmdir { name: p.name } } else { crate::fuse::Req::Unlink { name: p.name } };
        return fuse_names(c, p.dir, req);
    }
    let r = zfs::request(if rmdir { FS_RMDIR } else { FS_UNLINK }, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
    });
    // wave9 G6b-1: the events of the change for inotify/fanotify
    crate::notify::changed(&r, &who);
    if r.is_ok() && rmdir {
        if let Some(v) = victim {
            policy::names_changed(v.ino); // wave9 G6b-3
            cache::CACHE.forget_object(v.ino);
        }
    }
    names_changed(&[p.dir], if r.is_ok() && !rmdir { victim.map(|v| v.ino) } else { None });
    if let (Ok(_), true, Some(v)) = (&r, mem, victim) {
        crate::tmem::unlinked(v.ino); // wave10 GV1
    }
    r.map(|_| 0)
}

/// `rename(old, new)`, `renameat(olddir, old, newdir, new)`, `renameat2(.., flags)`.
pub fn rename(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, NEED)?;
    let a = cx.args;
    let (op, np, flags) = match cx.nr {
        82 => (a[0], a[1], 0),
        264 => (a[1], a[3], 0),
        _ => (a[1], a[3], a[4]),
    };
    if flags & !RENAME_NOREPLACE != 0 {
        return Err(EINVAL);
    }
    let op = ctxt::path(cx, op, false)?;
    let np = ctxt::path(cx, np, false)?;
    let who = ctxt::caller(c)?;
    // The second path starts at the second directory descriptor
    let mut c2 = *c;
    c2.at_kind = c.at2_kind;
    c2.at_ino = c.at2_ino;
    c2.at_mnt = c.at2_mnt;
    let src = match walk::walk_parent(&ctxt::walker(c)?, &who, ctxt::start(c, &op)?, &op)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    let dst = match walk::walk_parent(&ctxt::walker(c)?, &who, ctxt::start(&c2, &np)?, &np)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    // wave7 G7-7: a mount point: the kernel's (wave10 GV1: across mounts EXDEV, a read-only
    // one EROFS, here)
    if src.dir.mnt != dst.dir.mnt {
        return Err(EXDEV);
    }
    ctxt::writable(c, src.dir)?;
    // wave9 GM: moving or replacing an in-memory tmpfs file (wave10 GV1: the kernel says
    // whether its data may follow the name, and frees a replaced one's)
    let moved_mem = src.child.filter(|s| crate::tmem::node_is_tmem(*s));
    let replaced_mem = dst.child.filter(|d| crate::tmem::node_is_tmem(*d));
    if let Some(m) = moved_mem {
        crate::tmem::may_move(m.ino, dst.dir.ino)?;
    }
    for ch in [src.child, dst.child].into_iter().flatten() {
        ctxt::not_mountpoint(c, ch)?;
    }

    for d in [&src, &dst] {
        if !d.dir_attr.is_dir() {
            return Err(ENOTDIR);
        }
        let acl = ctxt::acl_of(d.dir, &d.dir_attr)?;
        // (wave9 G6b-3: and the access policies, as the kernel's `may_access` — review)
        let named = if d.dir == src.dir { &op } else { &np };
        if !ctxt::allowed(&who, &d.dir_attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC, named)? {
            return Err(EACCES);
        }
    }
    if let Some(s) = src.child {
        if sticky_denied(c, &src.dir_attr, s)? {
            return Err(EPERM);
        }
        // wave9 G6b-3: the access policies: moving a file away from its folder needs the
        // delete right
        if who.abac && c.euid != 0 && src.dir.ino != dst.dir.ino && !policy::abac(&who, &ctxt::attr_of(c, s)?, 0, true, &op)? {
            return Err(EACCES);
        }
    }
    // wave9 G6b-3: and a file replaced
    if let Some(d) = dst.child {
        if who.abac && c.euid != 0 && !policy::abac(&who, &ctxt::attr_of(c, d)?, 0, true, &np)? {
            return Err(EACCES);
        }
    }
    if let Some(d) = dst.child {
        if sticky_denied(c, &dst.dir_attr, d)? {
            return Err(EPERM);
        }
        if flags & RENAME_NOREPLACE != 0 {
            return Err(EEXIST);
        }
    }
    // wave9 G6b-3 begin: Landlock (the kernel's check_move: remove, make, REFER)
    if let Some(dom) = policy::domain(c)? {
        let s = src.child.ok_or(rules::ENOENT)?;
        let ftype = ctxt::BE.getattr(s)?.mode & rules::S_IFMT;
        let remove_dst = match dst.child {
            Some(d) => ll::remove_right(ctxt::BE.getattr(d)?.mode & rules::S_IFMT),
            None => 0,
        };
        policy::check_move(&dom, src.dir, dst.dir, ftype, remove_dst)?;
    }
    // wave9 G6b-3 end
    // wave11 GF: in a FUSE mount (both directories: one mount): the daemon's RENAME
    if ctxt::is_fuse(src.dir) {
        let s = src.child.ok_or(rules::ENOENT)?;
        if [&src.name[..], &dst.name[..]].iter().any(|n| *n == b"." || *n == b"..") {
            return Err(-16); // EBUSY
        }
        let sdir = ctxt::attr_of(c, s)?.is_dir();
        if let Some(d) = dst.child {
            if d == s {
                return Ok(0);
            }
            let ddir = ctxt::attr_of(c, d)?.is_dir();
            if sdir && !ddir {
                return Err(ENOTDIR);
            }
            if !sdir && ddir {
                return Err(-21); // EISDIR
            }
        }
        // (a directory into itself or below it)
        if sdir && crate::fuse::descends(dst.dir.ino, s.ino) {
            return Err(EINVAL);
        }
        return fuse_names(c, src.dir, crate::fuse::Req::Rename { sname: src.name, ddir: dst.dir.ino, dname: dst.name });
    }
    let r = zfs::request(FS_RENAME, |w| {
        w.u64(src.dir.ino);
        w.bytes(&src.name);
        w.u64(dst.dir.ino);
        w.bytes(&dst.name);
    });
    // wave9 G6b-1: the events of the change for inotify/fanotify
    crate::notify::changed(&r, &who);
    let replaced = if r.is_ok() { dst.child.map(|d| d.ino).filter(|&d| Some(d) != src.child.map(|s| s.ino)) } else { None };
    if let Some(s) = src.child {
        cache::CACHE.forget_object(s.ino);
    }
    // wave9 G6b-3: (a directory may have moved, or been replaced)
    policy::names_changed(src.child.map_or(0, |s| s.ino));
    if let Some(d) = dst.child {
        policy::names_changed(d.ino);
    }
    names_changed(&[src.dir, dst.dir], replaced);
    // wave10 GV1: a replaced in-memory file lost its name
    if let (Some(rep), Some(d)) = (replaced, replaced_mem) {
        if rep == d.ino {
            crate::tmem::unlinked(d.ino);
        }
    }
    r.map(|_| 0)
}
