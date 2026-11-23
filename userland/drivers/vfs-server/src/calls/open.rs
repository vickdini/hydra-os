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

// wave7 G7-5 begin: a FIFO opens as a pipe end of the IPC service (linux-server)
/// [`open`]'s answer for a FIFO node: redirected to `LXS_IPC` with the node's object number
/// (linux-server's `pipe.rs` makes or finds the pipe, as for the kernel's `LX_KCALL_FIFO`).
pub fn serve(cx: &Cx) -> hydra_rt::svcrt::Answer {
    let mut fifo = 0u64;
    let r = open_or_fifo(cx, &mut fifo);
    if r == Err(FIFO) {
        super::SERVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return hydra_rt::svcrt::redirect(cx.page(), crate::proto::LXS_IPC, fifo, 0);
    }
    super::answer(cx, r)
}

/// [`open_or_fifo`]'s error for a FIFO node it checked (never a Linux errno).
const FIFO: i64 = i64::MIN + 1;

/// `open(path, flags, mode)`, `openat(dirfd, path, flags, mode)`.
pub fn open(cx: &Cx) -> Result<i64, i64> {
    let mut fifo = 0;
    match open_or_fifo(cx, &mut fifo) {
        Err(FIFO) => Err(KERNEL),
        r => r,
    }
}

/// [`open`], or `Err(FIFO)` with `*fifo` = the object of a FIFO node the caller may open.
fn open_or_fifo(cx: &Cx, fifo: &mut u64) -> Result<i64, i64> {
// wave7 G7-5 end
    let c = &cx.c;
    ctxt::check(c, LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC)?;
    // wave9 G6b-1: with vfs-server's fanotify groups the kernel opens (FAN_OPEN and the
    // permission events are made there, with the kernel's path)
    if crate::notify::fan_any() {
        return Err(KERNEL);
    }
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
    // wave7 G7-5 begin
    if attr.mode & rules::S_IFMT == 0o010000 && n.mnt == 0 && flags & rules::O_DIRECTORY == 0 {
        let want = match flags & rules::O_ACCMODE {
            rules::O_RDONLY => rules::MAY_READ,
            rules::O_WRONLY => rules::MAY_WRITE,
            _ => rules::MAY_READ | rules::MAY_WRITE,
        };
        let acl = ctxt::acl_of(n, &attr)?;
        if !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, want) {
            return Err(EACCES);
        }
        *fifo = n.ino;
        return Err(FIFO);
    }
    // wave7 G7-5 end
    // wave7 G7-7: writing into a read-only mount: the kernel answers (EROFS)
    if flags & rules::O_ACCMODE != rules::O_RDONLY {
        ctxt::writable(c, n)?;
    }
    let want = rules::decide(attr.mode, flags)?;

    let acl = ctxt::acl_of(n, &attr)?;
    if !ctxt::may_access(&who, &attr, acl.as_deref(), c.euid, c.egid, want) {
        return Err(EACCES);
    }
    let d = rules::handle_desc(c, n.ino, n.mnt, attr.is_dir(), flags, &path, dirfd)?;
    // wave9 G6b-2: a FUSE file: the open counts here (the daemon's handles live while it is open)
    let fuse = crate::fuse::local_open_ref(n.ino);
    let fd = match sys::lx_obj(LX_FH_INSTALL, cx.id, &d as *const LxFhDesc as u64, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if fuse {
                crate::fuse::local_release(n.ino);
            }
            return Err(e);
        }
    };
    Ok(fd as i64)
}
