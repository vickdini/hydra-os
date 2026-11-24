//! # The extended attribute calls (wave 10, Group V1)
//!
//! `setxattr`, `lsetxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`,
//! `llistxattr`, `flistxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, as the kernel's
//! `vfs::xattr_op`: the namespace rules ([`rules::xattr_ns`]), POSIX ACLs through
//! `system.posix_acl_*` ([`super::acl`]: validated, an access ACL sets the mode), the values
//! through zfs-server, then the caches (an ACL or a mode changed: vfs-server's and the
//! kernel's; an access-control label: the kernel's ABAC caches, `LX_FHC_LABELS`).

use alloc::vec::Vec;

use hydra_rt::svcrt::Cx;

use super::acl;
use super::change::{setattr, tell_kernel};
use super::ctxt;
use super::rules::{self, XattrNs};
use crate::cache;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::{Attr, SetAttr, FS_REMOVEXATTR, FS_SETXATTR};
use crate::proto::{LX_FHC_ATTR, LX_FHC_LABELS, LX_FS_FANOTIFY, LX_FS_INOTIFY};
use crate::walk::Backend;
use crate::zfs;

const EPERM: i64 = -1;
const EACCES: i64 = -13;
const E2BIG: i64 = -7;
const ENODATA: i64 = -61;
const EINVAL: i64 = -22;

/// `CAP_FOWNER`, `CAP_FSETID`, `CAP_SYS_ADMIN`, `CAP_SETFCAP`.
const CAP_FOWNER: u32 = 3;
const CAP_FSETID: u32 = 4;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_SETFCAP: u32 = 31;
/// The largest value (Linux's `XATTR_SIZE_MAX`).
const SIZE_MAX: u64 = 65536;

/// The xattr call numbers.
pub const CALLS: core::ops::RangeInclusive<u64> = 188..=199;

/// Serves xattr call `cx` (188..=199).
pub fn serve(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, LX_FS_INOTIFY | LX_FS_FANOTIFY)?;
    let a = cx.args;
    // (kind: 0 set, 1 get, 2 list, 3 remove; by path followed, path not followed, handle)
    let (kind, how) = ((cx.nr - 188) / 3, (cx.nr - 188) % 3);
    // (one copy of the caller's mount table for the whole call)
    let k = ctxt::call(c)?;
    let who = k.who.clone();
    let (n, attr) = if how == 2 {
        let n = ctxt::handle(c)?;
        (n, ctxt::attr_of(c, n)?) // wave11 GF: (a FUSE file's too)
    } else {
        let path = ctxt::path(cx, a[0], false)?;
        k.find(c, &path, how == 0)?
    };
    let out = |data: &[u8], ptr: u64, size: u64| -> Result<i64, i64> {
        let n = rules::xattr_fits(data.len(), size)?;
        if size != 0 && n > 0 {
            cx.copy_out(ptr, data)?;
        }
        Ok(n as i64)
    };
    // wave11 GF: a FUSE file: the daemon's LISTXATTR, its reply to the caller's buffer
    let fuse = ctxt::is_fuse(n);
    if kind == 2 && fuse {
        let then = crate::fuse::Then { how: crate::fuse::How::Bytes { ptr: a[1], size: a[2], list: Some(who.cap(CAP_SYS_ADMIN)) }, tell: None };
        return crate::fuse::start(c, n.ino, crate::fuse::Req::Listxattr, then);
    }
    if kind == 2 {
        let names = zfs::listxattr(n.ino)?;
        return out(&rules::xattr_list_shown(&names, who.cap(CAP_SYS_ADMIN)), a[1], a[2]);
    }
    let name = cx.user_cstr(a[1])?;
    let ns = rules::xattr_ns(&name)?;
    let write = kind != 1;
    if ns == XattrNs::System {
        return Err(if kind == 0 { rules::EOPNOTSUPP } else { ENODATA });
    }
    if write {
        k.writable(n)?;
    }
    // (wave11 GF: in a FUSE mount the ACL names are the daemon's xattrs, as Linux's client
    // without `posix_acl` passes them: below)
    if let (XattrNs::Acl(default), 3, false) = (ns, kind, fuse) {
        return acl_remove(&who, n, &attr, default);
    }
    match ns {
        XattrNs::Trusted if !who.cap(CAP_SYS_ADMIN) => return Err(if write { EPERM } else { ENODATA }),
        XattrNs::User => {
            let t = attr.mode & 0o170000;
            if t != 0o100000 && t != 0o040000 {
                return Err(if write { EPERM } else { ENODATA });
            }
            let acl = ctxt::acl_of(n, &attr)?;
            if !ctxt::allowed(&who, &attr, acl.as_deref(), c.euid, c.egid, if write { rules::MAY_WRITE } else { rules::MAY_READ }, b"")? {
                return Err(EACCES);
            }
        }
        XattrNs::Security if write => {
            let needed = if &name[..] == b"security.capability" { CAP_SETFCAP } else { CAP_SYS_ADMIN };
            if !who.cap(needed) {
                return Err(EPERM);
            }
        }
        _ => {}
    }
    // wave11 GF begin: a FUSE file: the daemon's GETXATTR, SETXATTR, REMOVEXATTR
    if fuse {
        let zero = crate::fuse::Then { how: crate::fuse::How::Zero, tell: None };
        return match kind {
            1 => crate::fuse::start(c, n.ino, crate::fuse::Req::Getxattr { name }, crate::fuse::Then { how: crate::fuse::How::Bytes { ptr: a[2], size: a[3], list: None }, tell: None }),
            3 => crate::fuse::start(c, n.ino, crate::fuse::Req::Removexattr { name }, zero),
            _ => {
                let (value, size, flags) = (a[2], a[3], a[4]);
                if flags & !3 != 0 || flags == 3 {
                    return Err(EINVAL);
                }
                if size > SIZE_MAX {
                    return Err(E2BIG);
                }
                let data = cx.copy_in_any(value, size as usize)?;
                if &name[..] == b"security.capability" && !rules::fcaps_valid(&data) {
                    return Err(EINVAL);
                }
                crate::fuse::start(c, n.ino, crate::fuse::Req::Setxattr { name, value: data, flags: flags as u32 }, zero)
            }
        };
    }
    // wave11 GF end
    match kind {
        1 => {
            let v = zfs::getxattr(n.ino, &name)?;
            out(&v[..v.len().min(SIZE_MAX as usize)], a[2], a[3])
        }
        3 => {
            let r = zfs::request(FS_REMOVEXATTR, |w| {
                w.u64(n.ino);
                w.bytes(&name);
            });
            changed(&who, n, &name, &r);
            r.map(|_| 0)
        }
        _ => {
            let (value, size, flags) = (a[2], a[3], a[4]);
            // (both XATTR_CREATE and XATTR_REPLACE: EINVAL, as Linux)
            if flags & !3 != 0 || flags == 3 {
                return Err(EINVAL);
            }
            if size > SIZE_MAX {
                return Err(E2BIG);
            }
            let data = cx.copy_in_any(value, size as usize)?;
            if &name[..] == b"security.capability" && !rules::fcaps_valid(&data) {
                return Err(EINVAL);
            }
            if let XattrNs::Acl(default) = ns {
                // (Linux ignores XATTR_CREATE/XATTR_REPLACE for ACLs)
                return acl_set(&who, c.egid, n, &attr, default, &data, 0);
            }
            set(&who, n, &name, &data, flags as u32)
        }
    }
}

/// Sets xattr `name` of `n` to `data`.
fn set(who: &Ctx, n: Node, name: &[u8], data: &[u8], flags: u32) -> Result<i64, i64> {
    let r = zfs::request(FS_SETXATTR, |w| {
        w.u64(n.ino);
        w.bytes(name);
        w.bytes(data);
        w.u64(flags as u64);
    });
    changed(who, n, name, &r);
    r.map(|_| 0)
}

/// After an xattr change of `n`: events, the caches (its attributes and ACL here, its
/// attributes in the kernel; a label: the kernel's ABAC caches).
fn changed(who: &Ctx, n: Node, name: &[u8], r: &Result<zfs::Reply, i64>) {
    crate::notify::changed(r, who);
    // (an ACL changed: its cached copy goes too)
    if name == acl::ACCESS || name == acl::DEFAULT {
        cache::forget_attr(n);
    } else {
        cache::CACHE.forget_attr_keep_acl(n);
    }
    let labels = if name == acl::LABELS { LX_FHC_LABELS } else { 0 };
    tell_kernel(n.ino, LX_FHC_ATTR | labels, 0);
}

/// Whether the caller may change `attr`'s ACLs (its owner, or `CAP_FOWNER`).
fn may_change(who: &Ctx, attr: &Attr) -> bool {
    who.uid == attr.uid || who.cap(CAP_FOWNER)
}

/// Removes `n`'s access or default ACL (the mode stays).
fn acl_remove(who: &Ctx, n: Node, attr: &Attr, default: bool) -> Result<i64, i64> {
    if !may_change(who, attr) {
        return Err(EPERM);
    }
    let name = if default { acl::DEFAULT } else { acl::ACCESS };
    let r = zfs::request(FS_REMOVEXATTR, |w| {
        w.u64(n.ino);
        w.bytes(name);
    });
    changed(who, n, name, &r);
    r.map(|_| 0)
}

/// Sets `n`'s access or default ACL from `value` (empty: removes it), as the kernel's
/// `acl::set`: an access ACL sets the mode's permission bits, one equivalent to the mode is
/// not kept, set-group-ID goes for a non-member without `CAP_FSETID`.
fn acl_set(who: &Ctx, egid: u32, n: Node, attr: &Attr, default: bool, value: &[u8], flags: u32) -> Result<i64, i64> {
    if !may_change(who, attr) {
        return Err(EPERM);
    }
    if default && !attr.is_dir() {
        return Err(EACCES);
    }
    if value.is_empty() {
        return match acl_remove(who, n, attr, default) {
            Err(ENODATA) => Ok(0),
            r => r,
        };
    }
    let e = acl::parse(value)?;
    if default {
        return set(who, n, acl::DEFAULT, &acl::encode(&e), flags);
    }
    let in_group = egid == attr.gid || who.in_group(attr.gid) || who.cap(CAP_FSETID);
    let (keep, mode) = acl::set_access(value, attr.mode, in_group)?;
    match keep {
        Some(b) => {
            set(who, n, acl::ACCESS, &b, flags)?;
        }
        // Equivalent to the mode: only the mode is kept
        None => match acl_remove_raw(who, n) {
            Ok(()) | Err(ENODATA) => {}
            Err(e) => return Err(e),
        },
    }
    // (the ACL now matches the mode: `setattr`'s ACL rewrite changes nothing)
    let fresh = ctxt::BE.getattr(n).unwrap_or(*attr);
    setattr(who, n, &fresh, SetAttr { mode: Some(mode), ..SetAttr::default() })
}

/// Removes `n`'s access ACL without the owner check (the caller made it).
fn acl_remove_raw(who: &Ctx, n: Node) -> Result<(), i64> {
    let r = zfs::request(FS_REMOVEXATTR, |w| {
        w.u64(n.ino);
        w.bytes(acl::ACCESS);
    });
    changed(who, n, acl::ACCESS, &r);
    r.map(|_| ())
}

/// The inherited xattrs of a new object `ino` (its directory's default ACL and labels).
pub fn inherit(ino: u64, plan: &acl::Inherit) {
    let put = |name: &[u8], v: &[u8]| {
        let _ = zfs::request(FS_SETXATTR, |w| {
            w.u64(ino);
            w.bytes(name);
            w.bytes(v);
            w.u64(0);
        });
    };
    if let Some(a) = &plan.access {
        put(acl::ACCESS, a);
    }
    if let Some(d) = &plan.default {
        put(acl::DEFAULT, d);
    }
    if let Some(l) = &plan.labels {
        put(acl::LABELS, l);
    }
}

/// What a new object in directory `dir` (attributes `dattr`) asked for with `perm` gets:
/// its permission bits (umask, or the default ACL) and what it inherits (that ACL, the
/// directory's labels).
pub fn new_mode(dir: Node, dattr: &Attr, perm: u32, umask: u32, is_dir: bool) -> Result<(u32, acl::Inherit), i64> {
    if !dattr.has_xattr {
        return Ok((perm & !umask, acl::Inherit::default()));
    }
    let read = |name: &[u8]| -> Result<Option<Vec<u8>>, i64> {
        match zfs::getxattr(dir.ino, name) {
            Ok(v) => Ok(Some(v)),
            Err(ENODATA) => Ok(None),
            Err(e) => Err(e),
        }
    };
    let def = read(acl::DEFAULT)?;
    let (mode, mut plan) = acl::create_mode(def.as_deref(), perm, umask, is_dir);
    plan.labels = read(acl::LABELS)?;
    Ok((mode, plan))
}
