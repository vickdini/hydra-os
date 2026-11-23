//! The `stat` family, `access`, `readlink` and `statfs`: read-only path calls (the kernel's
//! `vfs::stat_at`, `access_at`, `readlink_at`, `statfs_out`).

use hydra_rt::svcrt::Cx;

use super::ctxt::{self, AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
use super::enc;
use crate::walk::Backend;

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
        let who = ctxt::caller(c)?;
        ctxt::find(c, &who, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?.1
    };
    crate::tmem::overlay(&mut attr); // wave9 GM: an in-memory tmpfs file's size and times
    if x {
        let mut b = enc::statx(&attr);
        crate::fuse::fix_stat(&attr, &mut b, true); // wave9 G6b-2
        cx.copy_out(out, &b)?;
    } else {
        let mut b = enc::stat(&attr);
        crate::fuse::fix_stat(&attr, &mut b, false); // wave9 G6b-2
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
    let who = ctxt::caller(c)?;
    let (n, attr) = ctxt::find(c, &who, &path, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    if mode & 7 == 0 {
        return Ok(0);
    }
    // wave7 G7-7: write on a read-only mount, run on a noexec one: the kernel decides
    let mf = ctxt::mount_flags(c, n)?;
    if (mode & 2 != 0 && mf & crate::kmounts::MS_RDONLY != 0) || (mode & 1 != 0 && mf & crate::kmounts::MS_NOEXEC != 0) {
        return Err(ctxt::KERNEL);
    }
    let (uid, gid) = if flags & AT_EACCESS != 0 { (c.euid, c.egid) } else { (c.uid, c.gid) };
    let acl = ctxt::acl_of(n, &attr)?;
    if ctxt::allowed(&who, &attr, acl.as_deref(), uid, gid, mode & 7, &path)? {
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
    let who = ctxt::caller(c)?;
    let (n, attr) = ctxt::find(c, &who, &path, false)?;
    if attr.mode & 0o170000 != 0o120000 {
        return Err(EINVAL);
    }
    let target = ctxt::walker(c)?.readlink(n)?; // wave9 G6b-2: (a FUSE link too)
    let k = target.len().min(size);
    cx.copy_out(buf, &target[..k])?;
    Ok(k as i64)
}

/// `statfs(path, buf)`.
pub fn statfs(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let path = ctxt::path(cx, cx.args[0], false)?;
    let who = ctxt::caller(c)?;
    let (n, _) = ctxt::find(c, &who, &path, true)?;
    // wave7 G7-7: a tmpfs mount reports its own numbers (the kernel's)
    // (and a mount with flags: the kernel reports them in `f_flags`)
    if ctxt::walker(c)?.view.is_tmpfs(n.mnt) || ctxt::mount_flags(c, n)? != 0 {
        return Err(ctxt::KERNEL);
    }
    let (total, free, objs) = crate::zfs::statfs()?;

    cx.copy_out(cx.args[1], &enc::statfs(total, free, objs, POOL_FSID))?;
    Ok(0)
}

/// The pool's `f_fsid` (the kernel's `fanotify::POOL_FSID`).
const POOL_FSID: [u32; 2] = [0x4859_4452, 0x5a46_5301];
