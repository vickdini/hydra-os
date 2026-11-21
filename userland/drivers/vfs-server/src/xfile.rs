//! # Files for the other Linux services (wave 7, Group 7-5)
//!
//! Direct calls (`LX_DCALL_NR`) from linux-server, made in the context of the program it
//! serves (the program's `LxCall` comes as the first part of the input, so the checks are
//! 7-2's `calls::ctxt` ones):
//!
//! - [`LX_VFS_OP_EXEC`]: `execve`'s program, a `#!` interpreter or the ELF interpreter:
//!   the walk, exec permission, the file's first bytes and the path `/proc/self/exe` shows
//!   ([`crate::xpath::real_path`]);
//! - [`LX_VFS_OP_READ`]: more bytes of such a file (a `PT_INTERP` past the head);
//! - [`LX_VFS_OP_SOCK`]: the socket node of a Unix socket path name (`bind` makes it,
//!   `connect` checks it), Group 13's temporary `vfs_resolve` in the kernel before.
//!
//! What vfs-server does not serve yet (a walk into `/proc`, `/sys`, `/dev`, a mount, a
//! caller with Landlock, fanotify or ABAC rules, a default ACL to inherit) answers
//! [`LX_VFS_KERNEL`] before anything changed: linux-server then lets the kernel do it.

use alloc::vec::Vec;

use hydra_rt::svccall::DcallArgs;
use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use crate::cache;
use crate::calls::ctxt;
use crate::calls::rules::{self, KERNEL};
use crate::ctx::Ctx;
use crate::fs::fsproto::{FS_MKNOD, FS_READ, FS_UNLINK};
use crate::fs::types::{S_IFMT, S_IFREG, S_IFSOCK};
use crate::proto::*;
use crate::walk::{self, ParentWalked, Start, Walked};
use crate::{xpath, zfs};

const EINVAL: i64 = -22;
const EACCES: i64 = -13;
const EEXIST: i64 = -17;
const ENOTDIR: i64 = -20;
const ECONNREFUSED: i64 = -111;

/// Direct calls of this module served, and handed back to the kernel, since start.
pub static SERVED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Serves direct call `a` if it is one of this module's (`None`: not one).
pub fn dcall(cx: &Cx, a: &DcallArgs) -> Option<i64> {
    let r = match a.op {
        LX_VFS_OP_EXEC => exec(cx, a),
        LX_VFS_OP_READ => read(cx, a),
        LX_VFS_OP_SOCK => sock(cx, a),
        _ => return None,
    };
    Some(match r {
        Err(KERNEL) => {
            TO_KERNEL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            LX_VFS_KERNEL
        }
        Ok(v) | Err(v) => {
            SERVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            v
        }
    })
}

/// The program's call at the head of input `b` (a plain repr(C) struct).
fn call_of(b: &[u8]) -> Result<LxCall, i64> {
    if b.len() < core::mem::size_of::<LxCall>() {
        return Err(EINVAL);
    }
    // SAFETY: at least that many bytes; LxCall is plain data
    Ok(unsafe { core::ptr::read_unaligned(b.as_ptr() as *const LxCall) })
}

/// The bytes of `n` as a byte slice (plain repr(C) structs only).
fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: a plain repr(C) struct of integers
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// Up to `n` bytes of pool object `ino` from `off`.
fn read_obj(ino: u64, off: u64, n: usize) -> Result<Vec<u8>, i64> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let r = zfs::request(FS_READ, |w| {
        w.u64(ino);
        w.u64(off);
        w.u64(n as u64);
    })?;
    let k = (r.value as usize).min(r.data.len()).min(n);
    Ok(r.data[..k].to_vec())
}

/// [`LX_VFS_OP_EXEC`].
fn exec(cx: &Cx, a: &DcallArgs) -> Result<i64, i64> {
    let cs = core::mem::size_of::<LxCall>();
    let es = core::mem::size_of::<LxVfsExecIn>();
    if a.input_len < cs + es {
        return Err(EINVAL);
    }
    let b = cx.copy_in(a.input, a.input_len)?;
    let c = call_of(&b)?;
    // SAFETY: at least `cs + es` bytes, a plain repr(C) struct
    let e: LxVfsExecIn = unsafe { core::ptr::read_unaligned(b.as_ptr().add(cs) as *const LxVfsExecIn) };
    let (pl, al) = (e.path_len as usize, e.abs_len as usize);
    if cs + es + pl + al > b.len() {
        return Err(EINVAL);
    }
    let path = &b[cs + es..cs + es + pl];
    let abs = &b[cs + es + pl..cs + es + pl + al];
    ctxt::check(&c, LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC)?;
    rules::check_path(path, false)?;
    let who = ctxt::caller(&c)?;
    let start = if e.flags & LX_VFS_EXEC_FROM_ROOT != 0 { Start::Root } else { ctxt::start(&c, path)? };
    let flags = if e.flags & LX_VFS_EXEC_NOFOLLOW != 0 { walk::NOFOLLOW } else { 0 };
    let (node, attr) = match walk::walk(&ctxt::BE, &who, start, path, flags)? {
        Walked::Found { node, attr } => (node, attr),
        Walked::Redirect(_) => return Err(KERNEL),
    };
    // (the kernel loads pool objects only)
    if node.mnt != 0 {
        return Err(KERNEL);
    }
    if e.flags & LX_VFS_EXEC_NOCHECK == 0 {
        let acl = ctxt::acl_of(node, &attr)?;
        if attr.mode & S_IFMT != S_IFREG || !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, rules::MAY_EXEC) || attr.mode & 0o111 == 0 {
            return Err(EACCES);
        }
    }
    let os = core::mem::size_of::<LxVfsExecOut>();
    if a.output_cap < os {
        return Err(EINVAL);
    }
    let room = a.output_cap - os;
    let head = if attr.mode & S_IFMT == S_IFREG { read_obj(attr.ino, 0, (e.head_max as usize).min(room).min(attr.size as usize))? } else { Vec::new() };
    let real = if e.flags & LX_VFS_EXEC_REAL != 0 { xpath::real_path(&ctxt::BE, who.root, abs, attr.ino) } else { None };
    let real = real.filter(|r| head.len() + r.len() <= room).unwrap_or_default();
    let o = LxVfsExecOut { ino: attr.ino, mnt: 0, mode: attr.mode, uid: attr.uid, gid: attr.gid, head_len: head.len() as u32, size: attr.size, real_len: real.len() as u32, pad: 0 };
    let mut out = Vec::with_capacity(os + head.len() + real.len());
    out.extend_from_slice(bytes_of(&o));
    out.extend_from_slice(&head);
    out.extend_from_slice(&real);
    cx.copy_out_any(a.output, &out)?;
    Ok(0)
}

/// [`LX_VFS_OP_READ`].
fn read(cx: &Cx, a: &DcallArgs) -> Result<i64, i64> {
    if a.input_len < 24 {
        return Err(EINVAL);
    }
    let b = cx.copy_in(a.input, 24)?;
    let (ino, off, len) = (Cx::u64_at(&b, 0), Cx::u64_at(&b, 8), Cx::u64_at(&b, 16) as usize);
    let d = read_obj(ino, off, len.min(a.output_cap))?;
    cx.copy_out_any(a.output, &d)?;
    Ok(d.len() as i64)
}

/// Tells the kernel's caches that names changed (and that object `gone` went).
fn names_changed(dir: crate::ctx::Node, gone: Option<u64>) {
    cache::forget_dir(dir);
    cache::forget_attr(dir);
    if let Some(ino) = gone {
        cache::CACHE.forget_object(ino);
    }
    let size = 0u64;
    let what = LX_FHC_NAMES | LX_FHC_ALL_ATTRS | if gone.is_some() { LX_FHC_GONE } else { 0 };
    let _ = sys::lx_obj(LX_FH_CHANGED, gone.unwrap_or(0), what, &size as *const u64 as u64);
}

/// The directory and last name of a socket path (`Err(KERNEL)` outside the pool's tree).
fn sock_parent(c: &LxCall, who: &Ctx, path: &[u8]) -> Result<walk::Parent, i64> {
    let p = match walk::walk_parent(&ctxt::BE, who, ctxt::start(c, path)?, path)? {
        ParentWalked::Found(p) => p,
        ParentWalked::Redirect(_) => return Err(KERNEL),
    };
    if p.dir.mnt != 0 {
        return Err(KERNEL);
    }
    if !p.dir_attr.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(p)
}

/// [`LX_VFS_OP_SOCK`].
fn sock(cx: &Cx, a: &DcallArgs) -> Result<i64, i64> {
    let cs = core::mem::size_of::<LxCall>();
    if a.input_len < cs + 8 {
        return Err(EINVAL);
    }
    let b = cx.copy_in(a.input, a.input_len)?;
    let c = call_of(&b)?;
    let op = Cx::u64_at(&b, cs);
    let path = &b[cs + 8..];
    let path = &path[..path.iter().position(|&x| x == 0).unwrap_or(path.len())];
    // (making a node is a change: inotify watches and Landlock's MAKE_SOCK are the kernel's)
    let need = if op == LX_VFS_SOCK_CHECK { 0 } else { LX_FS_INOTIFY | LX_FS_FANOTIFY | LX_FS_LANDLOCK | LX_FS_ABAC };
    ctxt::check(&c, need)?;
    rules::check_path(path, false)?;
    let who = ctxt::caller(&c)?;
    match op {
        LX_VFS_SOCK_MAKE => {
            let p = sock_parent(&c, &who, path)?;
            if p.child.is_some() || p.name == b"." || p.name == b".." {
                return Err(EEXIST);
            }
            let acl = ctxt::acl_of(p.dir, &p.dir_attr)?;
            if !ctxt::may_access(&who, &p.dir_attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE | rules::MAY_EXEC) {
                return Err(EACCES);
            }
            // A default ACL (or ABAC labels) would be inherited: the kernel's
            if p.dir_attr.has_xattr {
                return Err(KERNEL);
            }
            let perm = 0o777 & !(c.umask as u32);
            let r = zfs::request(FS_MKNOD, |w| {
                w.u64(p.dir.ino);
                w.bytes(&p.name);
                w.u64((S_IFSOCK | perm) as u64);
                w.u64(0);
                w.u64(c.euid as u64);
                w.u64(c.egid as u64);
            });
            names_changed(p.dir, None);
            r.map(|r| r.value as i64)
        }
        LX_VFS_SOCK_CHECK => {
            let (n, attr) = ctxt::find(&c, &who, path, true)?;
            if n.mnt != 0 {
                return Err(KERNEL);
            }
            if attr.mode & S_IFMT != S_IFSOCK {
                return Err(ECONNREFUSED);
            }
            let acl = ctxt::acl_of(n, &attr)?;
            if !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, rules::MAY_WRITE) {
                return Err(EACCES);
            }
            Ok(attr.ino as i64)
        }
        LX_VFS_SOCK_REMOVE => {
            let p = sock_parent(&c, &who, path)?;
            let victim = p.child;
            let r = zfs::request(FS_UNLINK, |w| {
                w.u64(p.dir.ino);
                w.bytes(&p.name);
            });
            names_changed(p.dir, if r.is_ok() { victim.map(|v| v.ino) } else { None });
            r.map(|_| 0)
        }
        _ => Err(EINVAL),
    }
}
