//! The `stat` family, `access`, `readlink` and `statfs`: read-only path calls (the kernel's
//! `vfs::stat_at`, `access_at`, `readlink_at`, `statfs_out`).

use hydra_rt::svcrt::Cx;

use super::ctxt::{self, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
use super::enc;
use crate::walk::Backend;
use crate::fstree; // wave10 GV2

const EINVAL: i64 = -22;
const EACCES: i64 = -13;
/// `faccessat2`'s `AT_EACCESS`: check with the effective ids.
const AT_EACCESS: u64 = 0x200;

/// `stat(path, buf)`, `lstat`, `newfstatat(dirfd, path, buf, flags)`, `statx(dirfd, path,
/// flags, mask, buf)`.
pub fn stat(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let a = cx.args;
    let (path_ptr, flags, out, x) = super::rules::stat_args(cx.nr, &a);
    let path = cx.user_cstr(path_ptr)?;
    let mut attr = if path.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            return Err(ctxt::ENOENT);
        }
        // The descriptor itself (a handle; anything else is the kernel's)
        let n = ctxt::handle(c)?;
        ctxt::BE.getattr(n)?
    } else {
        super::rules::check_path(&path, false)?;
        ctxt::call(c)?.find(c, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?.1 // wave9 GP2
    };
    crate::tmem::overlay(&mut attr); // wave9 GM: an in-memory tmpfs file's size and times
    if x {
        let mut b = enc::statx(&attr);
        crate::fuse::fix_stat(&attr, &mut b, true); // wave9 G6b-2
        enc::fix_console_stat(&attr, &mut b, true); // wave10 GV2
        cx.copy_out(out, &b)?;
    } else {
        let mut b = enc::stat(&attr);
        crate::fuse::fix_stat(&attr, &mut b, false); // wave9 G6b-2
        enc::fix_console_stat(&attr, &mut b, false); // wave10 GV2
        cx.copy_out(out, &b)?;
    }
    Ok(0)
}

/// `access(path, mode)`, `faccessat(dirfd, path, mode)`, `faccessat2(dirfd, path, mode,
/// flags)`.
pub fn access(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    // (wave9 G6b-3: ABAC rules may take away what the modes allow: asked below)
    ctxt::check(c, 0)?;
    let a = cx.args;
    let (path_ptr, mode, flags) = super::rules::access_args(cx.nr, &a);
    let path = ctxt::path(cx, path_ptr, false)?;
    let k = ctxt::call(c)?; // wave9 GP2
    let who = &k.who;
    let (n, attr) = k.find(c, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    if mode & 7 == 0 {
        return Ok(0);
    }
    // wave7 G7-7: write on a read-only mount, run on a noexec one (wave10 GV1: answered
    // here, as Linux: EROFS for a file, directory or link; EACCES for a regular file)
    let mf = k.mount_flags(n)?;
    let kind = attr.mode & 0o170000;
    if mode & 2 != 0 && mf & crate::kmounts::MS_RDONLY != 0 && matches!(kind, 0o100000 | 0o040000 | 0o120000) {
        return Err(ctxt::EROFS);
    }
    if mode & 1 != 0 && mf & crate::kmounts::MS_NOEXEC != 0 && kind == 0o100000 {
        return Err(EACCES);
    }
    let (uid, gid) = if flags & AT_EACCESS != 0 { (c.euid, c.egid) } else { (c.uid, c.gid) };
    let acl = ctxt::acl_of(n, &attr)?;
    if ctxt::allowed(who, &attr, acl.as_deref(), uid, gid, mode & 7, &path)? {
        Ok(0)
    } else {
        Err(EACCES)
    }
}

/// `readlink(path, buf, size)`, `readlinkat(dirfd, path, buf, size)`.
pub fn readlink(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let a = cx.args;
    let (path_ptr, buf, size) = if cx.nr == 89 { (a[0], a[1], a[2] as usize) } else { (a[1], a[2], a[3] as usize) };
    if size == 0 {
        return Err(EINVAL);
    }
    let path = ctxt::path(cx, path_ptr, false)?;
    let k = ctxt::call(c)?; // wave9 GP2
    let (n, attr) = k.find(c, &path, false)?;
    if attr.mode & 0o170000 != 0o120000 {
        return Err(EINVAL);
    }
    let target = k.w.readlink(n)?; // wave9 G6b-2: (a FUSE link too)
    let k = target.len().min(size);
    cx.copy_out(buf, &target[..k])?;
    Ok(k as i64)
}

/// `statfs(path, buf)`.
pub fn statfs(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let path = ctxt::path(cx, cx.args[0], false)?;
    // wave10 GV2: the tree the walk ended in (sysfs, cgroup2, efivarfs, devpts by type)
    let k = ctxt::call(c)?;
    let start = k.start(c, &path)?;
    let (n, track) = match crate::walk::walk_track(&k.w, &k.who, start, &path, 0)? {
        (crate::walk::Walked::Found { node, .. }, t) => (node, t),
        (crate::walk::Walked::Redirect(r), _) => return Err(super::pseudo_redirect(&r)),
    };
    let names: alloc::vec::Vec<&[u8]> = track.names.iter().map(|n| &n[..]).collect();
    let tree = if track.abs {
        fstree::class_of_names(&names)
    } else {
        // (relative: from the working directory's or the descriptor's tree, which the kernel
        // sends; going up out of it is not followed: rare)
        let from = if c.at_kind == crate::proto::LX_AT_CWD { fstree::cwd_of(c.fs_flags) } else { fstree::at_of(c.fh_flags) };
        if track.ups == 0 { fstree::class_below(from, &names) } else { from }
    };
    if let Some(r) = statfs_tree(cx, tree, cx.args[1]) {
        return r;
    }
    statfs_of(cx, n, cx.args[1])
}

/// `statfs` of tree `tree` when it is one shown by its type (`None`: the pool's).
fn statfs_tree(cx: &Cx, tree: u32, out: u64) -> Option<Result<i64, i64>> {
    let magic = fstree::magic_of(tree);
    if magic == 0 {
        return None;
    }
    Some(cx.copy_out(out, &enc::statfs_named(magic)).map(|_| 0))
}

// wave10 GV1 begin
/// `fstatfs(fd, buf)` of a handle.
pub fn fstatfs(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let n = ctxt::handle(c)?;
    // wave10 GV2: a handle in `/sys` (its tree comes from the kernel, which knows its path)
    if let Some(r) = statfs_tree(cx, fstree::at_of(c.fh_flags), cx.args[1]) {
        return r;
    }
    statfs_of(cx, n, cx.args[1])
}

/// `struct statfs` of the file system `n` is in, to `out`: a tmpfs mount's own numbers (its
/// `size=` and use, the kernel's), else the pool's. (The kernel's `f_flags` are 0 for every
/// mount: a mount with flags answers as the others.)
fn statfs_of(cx: &Cx, n: crate::ctx::Node, out: u64) -> Result<i64, i64> {
    let c = &cx.c;
    // (a FUSE file system: the daemon's figures; wave10 GV2: asked here, the call waits for
    // the daemon and runs again, `fuse::be_statfs`)
    if crate::fuse::wire::split(n.ino).is_some() {
        let r = crate::fuse::be_statfs(n, c.euid)?;
        cx.copy_out(out, &crate::fuse::statfs_bytes(n.ino, &r))?;
        return Ok(0);
    }
    if n.mnt != 0 && ctxt::walker(c)?.view.is_tmpfs(n.mnt) {
        let usage = crate::tmem::mount_id(c.mnt_ns, n.mnt).and_then(crate::tmem::usage);
        cx.copy_out(out, &enc::statfs_tmpfs(usage))?;
        return Ok(0);
    }
    let (total, free, objs) = crate::zfs::statfs()?;
    cx.copy_out(out, &enc::statfs(total, free, objs, POOL_FSID))?;
    Ok(0)
}
// wave10 GV1 end

/// The pool's `f_fsid` (the kernel's `fanotify::POOL_FSID`).
const POOL_FSID: [u32; 2] = [0x4859_4452, 0x5a46_5301];
