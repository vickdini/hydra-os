//! `open` and `openat` of existing regular files and directories (the kernel's
//! `vfs::open_path`, its pool part): the walk, the type and permission checks
//! ([`super::rules`]), and a handle made in the kernel (`LX_FH_INSTALL`). Everything else
//! goes to the kernel before anything has changed: creating and truncating opens, `O_PATH`,
//! `O_TMPFILE`, devices, FIFOs, sockets, and callers with Landlock, fanotify or ABAC rules.

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt;
use super::rules::{self, KERNEL, O_CREAT, O_EXCL, O_NOFOLLOW};
use crate::proto::{LxFhDesc, LX_FH_INSTALL, LX_FS_ABAC, LX_FS_FANOTIFY, LX_FS_LANDLOCK};

const EEXIST: i64 = -17;
const EACCES: i64 = -13;

/// `open(path, flags, mode)`, `openat(dirfd, path, flags, mode)`.
pub fn open(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC)?;
    let a = cx.args;
    let (dirfd, path_ptr, flags) = if cx.nr == 2 { (-100i32, a[0], a[1] as u32) } else { (a[0] as i32, a[1], a[2] as u32) };
    if !rules::servable(flags) {
        return Err(KERNEL);
    }
    let path = ctxt::path(cx, path_ptr, false)?;
    let who = ctxt::caller(c)?;
    let follow = flags & O_NOFOLLOW == 0;
    let (n, attr) = if flags & O_CREAT != 0 {
        // O_EXCL never follows the last component: a symlink there (even dangling) exists
        match ctxt::find(c, &who, &path, follow && flags & O_EXCL == 0) {
            Ok(_) if flags & O_EXCL != 0 => return Err(EEXIST),
            Ok(f) => f,
            // A new file: the kernel makes it (until the change calls move)
            Err(rules::ENOENT) => return Err(KERNEL),
            Err(e) => return Err(e),
        }
    } else {
        ctxt::find(c, &who, &path, follow)?
    };
    let want = rules::decide(attr.mode, flags)?;
    let acl = ctxt::acl_of(n, &attr);
    if !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, want) {
        return Err(EACCES);
    }
    let d = rules::handle_desc(c, n.ino, n.mnt, attr.is_dir(), flags, &path, dirfd)?;
    let fd = sys::lx_obj(LX_FH_INSTALL, cx.id, &d as *const LxFhDesc as u64, 0)?;
    Ok(fd as i64)
}
