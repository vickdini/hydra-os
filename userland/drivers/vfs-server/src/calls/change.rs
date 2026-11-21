//! The calls that change files and names (the kernel's `vfs::setattr_at`, `with_parent`,
//! `rename_at` and the `mkdir`, `symlink`, `unlink`/`rmdir` arms): the walk and the checks
//! here, the change through zfs-server, then the caches: vfs-server's own (`cache`) and the
//! kernel's (`LX_FH_CHANGED`: names, attributes, the page cache).
//!
//! Sent to the kernel before anything changes: callers with inotify or fanotify watches
//! (their events come from the kernel's client), Landlock or ABAC rules; a new object in a
//! directory with extended attributes (a default ACL would be inherited); `utimensat` with
//! "now" (the kernel's clock).

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt::{self, KERNEL};
use super::rules;
use crate::cache;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::{suid_killed, Attr, SetAttr, FS_MKDIR, FS_RENAME, FS_RMDIR, FS_SETATTR, FS_SYMLINK, FS_UNLINK};
use crate::proto::{LxCall, LX_FHC_ALL_ATTRS, LX_FHC_ATTR, LX_FHC_GONE, LX_FHC_NAMES, LX_FHC_TRUNC, LX_FH_CHANGED, LX_FS_ABAC, LX_FS_FANOTIFY, LX_FS_INOTIFY, LX_FS_LANDLOCK};
use crate::walk::{self, Backend, ParentWalked};
use crate::zfs;

const EPERM: i64 = -1;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;
const EACCES: i64 = -13;

/// What only the kernel has for a change.
const NEED: u32 = LX_FS_INOTIFY | LX_FS_FANOTIFY | LX_FS_LANDLOCK | LX_FS_ABAC;
/// `CAP_FSETID`.
const CAP_FSETID: u32 = 4;
const AT_REMOVEDIR: u64 = 0x200;
const RENAME_NOREPLACE: u64 = 1;
const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

/// Tells the kernel's caches about change `what` (`LX_FHC_*`) to `ino`.
fn tell_kernel(ino: u64, what: u64, size: u64) {
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
        return Ok((n, ctxt::BE.getattr(n)?));
    }
    ctxt::find(c, who, &path, follow)
}

/// Applies `set` to `n` (attributes `a` before) through zfs-server.
fn setattr(who: &Ctx, n: Node, a: &Attr, mut set: SetAttr) -> Result<i64, i64> {
    // A truncation by a caller without CAP_FSETID drops the set-ID bits, as a write does
    if let (Some(_), None) = (set.size, set.mode) {
        if !who.has_cap(CAP_FSETID) && a.mode & 0o170000 != 0o040000 {
            let mut groups = alloc::vec![who.gid];
            groups.extend_from_slice(&who.groups[..who.ngroups]);
            let m = suid_killed(a.mode & 0o7777, a.gid, &groups);
            if m != a.mode & 0o7777 {
                set.mode = Some(m);
            }
        }
    }
    let r = zfs::request(FS_SETATTR, |w| {
        w.u64(n.ino);
        w.setattr(&set);
    });
    cache::forget_attr(n);
    // (the page cache is cut only when the file was)
    let size = set.size.unwrap_or(0);
    tell_kernel(n.ino, LX_FHC_ATTR | if set.size.is_some() && r.is_ok() { LX_FHC_TRUNC } else { 0 }, size);
    r.map(|_| 0)
}

/// `chown`'s rule (the kernel's `chown_ok`).
fn chown_ok(who: &Ctx, a: &Attr, uid: u32, gid: u32) -> bool {
    if who.uid == 0 {
        return true;
    }
    let uid_ok = uid == u32::MAX || uid == a.uid;
    let gid_ok = gid == u32::MAX || gid == a.gid || who.in_group(gid);
    who.uid == a.uid && uid_ok && gid_ok
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
        // chmod(path, mode), fchmodat(dirfd, path, mode), fchmod(fd, mode)
        90 | 268 | 91 => {
            let (ptr, mode, empty) = match cx.nr {
                90 => (a[0], a[1], false),
                268 => (a[1], a[2], false),
                _ => (0, a[1], true),
            };
            let (n, at) = target(cx, &who, ptr, true, empty)?;
            if !owner(&who, &at) {
                return Err(EPERM);
            }
            setattr(&who, n, &at, SetAttr { mode: Some(mode as u32), ..SetAttr::default() })
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
            setattr(&who, n, &at, set)
        }
        // truncate(path, size)
        76 => {
            if (a[1] as i64) < 0 {
                return Err(EINVAL);
            }
            let (n, at) = target(cx, &who, a[0], true, false)?;
            let acl = ctxt::acl_of(n, &at)?;
            if !ctxt::may_access(&who, &at, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE) {
                return Err(EPERM);
            }
            setattr(&who, n, &at, SetAttr { size: Some(a[1]), ..SetAttr::default() })
        }
        // ftruncate(fd, size): a handle open for writing
        77 => {
            if (a[1] as i64) < 0 {
                return Err(EINVAL);
            }
            if c.fh_flags & rules::O_ACCMODE == rules::O_RDONLY {
                return Err(EINVAL);
            }
            let n = ctxt::handle(c)?;
            let at = ctxt::BE.getattr(n)?;
            setattr(&who, n, &at, SetAttr { size: Some(a[1]), ..SetAttr::default() })
        }
        // utimensat(dirfd, path, times, flags): explicit times only (else the kernel's clock)
        _ => {
            if a[2] == 0 {
                return Err(KERNEL);
            }
            let raw = cx.copy_in(a[2], 32)?;
            let ts = |off: usize| -> Result<Option<(i64, u32)>, i64> {
                let s = i64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
                let ns = i64::from_le_bytes(raw[off + 8..off + 16].try_into().unwrap());
                match ns {
                    UTIME_NOW => Err(KERNEL),
                    UTIME_OMIT => Ok(None),
                    _ => Ok(Some((s, ns as u32))),
                }
            };
            let (atime, mtime) = (ts(0)?, ts(16)?);
            let (n, at) = target(cx, &who, a[1], a[3] & ctxt::AT_SYMLINK_NOFOLLOW == 0, true)?;
            if !owner(&who, &at) {
                return Err(EPERM);
            }
            setattr(&who, n, &at, SetAttr { atime, mtime, ..SetAttr::default() })
        }
    }
}

// ----------------------------------------------------------------------
// Names
// ----------------------------------------------------------------------

/// The directory and last name of `path` for a change, with the kernel's checks
/// (`with_parent`): `EEXIST`/`ENOENT` for the name first, then write and search permission
/// on the directory. `create`: the call makes the name.
fn parent(c: &LxCall, who: &Ctx, path: &[u8], create: bool) -> Result<walk::Parent, i64> {
    let start = ctxt::start(c, path)?;
    let p = match walk::walk_parent(&ctxt::BE, who, start, path)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    if !p.dir_attr.is_dir() {
        return Err(ENOTDIR);
    }
    if p.name != b"." && p.name != b".." {
        match p.child {
            Some(_) if create => return Err(EEXIST),
            None if !create => return Err(rules::ENOENT),
            _ => {}
        }
    }
    let acl = ctxt::acl_of(p.dir, &p.dir_attr)?;
    if !ctxt::may_access(who, &p.dir_attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC) {
        return Err(EACCES);
    }
    Ok(p)
}

/// The kernel's sticky-directory rule: may `euid` not remove `entry` from `dir`?
fn sticky_denied(dir: &Attr, entry: Node, euid: u32) -> Result<bool, i64> {
    if euid == 0 || dir.mode & 0o1000 == 0 || dir.uid == euid {
        return Ok(false);
    }
    Ok(ctxt::BE.getattr(entry)?.uid != euid)
}

/// After a change of names in `dirs`: vfs-server's caches and the kernel's.
fn names_changed(dirs: &[Node], gone: Option<u64>) {
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
    // A default ACL (or ABAC labels) would be inherited: the kernel's
    if p.dir_attr.has_xattr {
        return Err(KERNEL);
    }
    let perm = mode as u32 & 0o7777 & !(c.umask as u32);
    let r = zfs::request(FS_MKDIR, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.u64(perm as u64);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
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
    let r = zfs::request(FS_SYMLINK, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
        w.bytes(&target);
        w.u64(c.euid as u64);
        w.u64(c.egid as u64);
    });
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
    let victim = p.child;
    if let Some(v) = victim {
        if sticky_denied(&p.dir_attr, v, c.euid)? {
            return Err(EPERM);
        }
    }
    let r = zfs::request(if rmdir { FS_RMDIR } else { FS_UNLINK }, |w| {
        w.u64(p.dir.ino);
        w.bytes(&p.name);
    });
    if r.is_ok() && rmdir {
        if let Some(v) = victim {
            cache::CACHE.forget_object(v.ino);
        }
    }
    names_changed(&[p.dir], if r.is_ok() && !rmdir { victim.map(|v| v.ino) } else { None });
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
    let src = match walk::walk_parent(&ctxt::BE, &who, ctxt::start(c, &op)?, &op)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    let dst = match walk::walk_parent(&ctxt::BE, &who, ctxt::start(&c2, &np)?, &np)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    for d in [&src, &dst] {
        if !d.dir_attr.is_dir() {
            return Err(ENOTDIR);
        }
        let acl = ctxt::acl_of(d.dir, &d.dir_attr)?;
        if !ctxt::may_access(&who, &d.dir_attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC) {
            return Err(EACCES);
        }
    }
    if let Some(s) = src.child {
        if sticky_denied(&src.dir_attr, s, c.euid)? {
            return Err(EPERM);
        }
    }
    if let Some(d) = dst.child {
        if sticky_denied(&dst.dir_attr, d, c.euid)? {
            return Err(EPERM);
        }
        if flags & RENAME_NOREPLACE != 0 {
            return Err(EEXIST);
        }
    }
    let r = zfs::request(FS_RENAME, |w| {
        w.u64(src.dir.ino);
        w.bytes(&src.name);
        w.u64(dst.dir.ino);
        w.bytes(&dst.name);
    });
    let replaced = if r.is_ok() { dst.child.map(|d| d.ino).filter(|&d| Some(d) != src.child.map(|s| s.ino)) } else { None };
    if let Some(s) = src.child {
        cache::CACHE.forget_object(s.ino);
    }
    names_changed(&[src.dir, dst.dir], replaced);
    r.map(|_| 0)
}
