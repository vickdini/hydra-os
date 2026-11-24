//! `open`, `openat` and (wave10 GV1) `creat` (the kernel's `vfs::open_path`, its pool part):
//! the walk, the type and permission checks ([`super::rules`]), and a handle made in the
//! kernel (`LX_FH_INSTALL`, or the answer itself). wave10 GV1: creating opens
//! (`super::make::create`), truncating opens, `O_PATH` and `O_TMPFILE`
//! (`super::make::tmpfile`) are served here too. Still the kernel's, before anything has
//! changed: devices, sockets, `O_CREAT` through a dangling symbolic link or with
//! `O_DIRECTORY`, and callers with fanotify marks. (wave9 G6b-3: Landlock and ABAC are
//! checked here, `crate::policy`.)

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt;
use super::rules::{self, KERNEL, O_CREAT, O_EXCL, O_NOFOLLOW};
use crate::policy::{self, ll};
use crate::proto::{LxFhDesc, LX_FH_INSTALL, LX_FH_NOTRUNC, LX_FS_FANOTIFY};

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
    // wave9 GP2: the kernel makes the handle from the answer (`fifo` holds it)
    if r == Err(FHANSWER) {
        super::SERVED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return hydra_rt::svcrt::redirect(cx.page(), crate::proto::LX_REDIR_FH, fifo & ((1 << 45) - 1), (fifo >> 45) as u32);
    }
    super::answer(cx, r)
}

/// [`open_or_fifo`]'s error for a FIFO node it checked (never a Linux errno).
const FIFO: i64 = i64::MIN + 1;
/// wave9 GP2: answered with the handle for the kernel to make (`LX_REDIR_FH`).
const FHANSWER: i64 = i64::MIN + 2;

/// `open(path, flags, mode)`, `openat(dirfd, path, flags, mode)`.
pub fn open(cx: &Cx) -> Result<i64, i64> {
    let mut fifo = 0;
    match open_or_fifo(cx, &mut fifo) {
        Err(FIFO) | Err(FHANSWER) => Err(KERNEL),
        r => r,
    }
}

/// [`open`], or `Err(FIFO)` with `*fifo` = the object of a FIFO node the caller may open.
fn open_or_fifo(cx: &Cx, fifo: &mut u64) -> Result<i64, i64> {
// wave7 G7-5 end
    let c = &cx.c;
    // (wave9 G6b-3: Landlock and ABAC are checked here)
    ctxt::check(c, LX_FS_FANOTIFY)?;
    // wave9 G6b-1: with vfs-server's fanotify groups the kernel opens (FAN_OPEN and the
    // permission events are made there, with the kernel's path)
    if crate::notify::fan_any() {
        return Err(KERNEL);
    }
    let dom = policy::domain(c)?;
    let a = cx.args;
    // (wave10 GV1: the mode of a new file; creat(path, mode) = open(path, O_CREAT | O_WRONLY |
    // O_TRUNC, mode))
    let (dirfd, path_ptr, flags, mode) = match cx.nr {
        2 => (-100i32, a[0], a[1] as u32, a[2] as u32),
        85 => (-100i32, a[0], O_CREAT | rules::O_WRONLY | rules::O_TRUNC, a[1] as u32),
        _ => (a[0] as i32, a[1], a[2] as u32, a[3] as u32),
    };
    if !rules::servable(flags) {
        return Err(KERNEL);
    }
    let path = ctxt::path(cx, path_ptr, false)?;
    // (wave10 GV1: a path too long for a handle is the kernel's: decided before anything is
    // made or truncated here)
    if path.len() > crate::proto::LX_FH_PATH_MAX {
        return Err(KERNEL);
    }
    let k = ctxt::call(c)?; // wave9 GP2
    let who = &k.who;
    let follow = flags & O_NOFOLLOW == 0;
    // wave10 GV1 begin: O_TMPFILE, O_PATH
    if flags & rules::O_TMPFILE_MASK != 0 {
        return super::make::tmpfile(cx, &k, &path, flags, mode, dirfd).map_err(plain);
    }
    if flags & rules::O_PATH != 0 {
        let (n, attr) = k.find(c, &path, follow).map_err(plain)?;
        return opath(cx, c, n, &attr, flags, &path, dirfd, fifo);
    }
    // A file this call makes opens with the access asked for, whatever its new mode says
    // (creat(path, 0444) returns a writable descriptor); it is not truncated
    let mut created = false;
    let mut made: Option<(crate::ctx::Node, alloc::vec::Vec<u8>)> = None;
    // wave10 GV1 end
    let (n, attr) = if flags & O_CREAT != 0 {
        // O_EXCL never follows the last component: a symlink there (even dangling) exists
        match k.find(c, &path, follow && flags & O_EXCL == 0) {
            Ok(_) if flags & O_EXCL != 0 => return Err(EEXIST),
            Ok(f) => f,
            // wave10 GV1: a new file, made here
            Err(rules::ENOENT) => match super::make::create(cx, &k, &path, flags, mode)? {
                super::make::Made::New(n, a, dir, name) => {
                    created = true;
                    made = Some((dir, name));
                    (n, a)
                }
                super::make::Made::Exists => k.find(c, &path, follow)?,
            },
            Err(e) => return Err(e),
        }
    } else {
        k.find(c, &path, follow)?
    };
    // wave7 G7-5 begin
    if attr.mode & rules::S_IFMT == 0o010000 && n.mnt == 0 && flags & rules::O_DIRECTORY == 0 {
        let want = match flags & rules::O_ACCMODE {
            rules::O_RDONLY => rules::MAY_READ,
            rules::O_WRONLY => rules::MAY_WRITE,
            _ => rules::MAY_READ | rules::MAY_WRITE,
        };
        let acl = ctxt::acl_of(n, &attr)?;
        if !ctxt::allowed(who, &attr, acl.as_deref(), c.euid, c.egid, want, &path)? {
            return Err(EACCES);
        }
        // wave9 G6b-3: Landlock
        if let Some(d) = &dom {
            if policy::refused_on(d, c.id, n, false, ll::open_rights(flags, false))? != 0 {
                return Err(EACCES);
            }
        }
        *fifo = n.ino;
        return Err(FIFO);
    }
    // wave7 G7-5 end
    let want = rules::decide(attr.mode, flags)?;
    // wave7 G7-7: writing into a read-only mount (wave10 GV1: EROFS here, after the type
    // checks, as the kernel's)
    if flags & rules::O_ACCMODE != rules::O_RDONLY || flags & rules::O_TRUNC != 0 {
        k.writable(n)?;
    }
    if !created {
        let acl = ctxt::acl_of(n, &attr)?;
        if !ctxt::allowed(who, &attr, acl.as_deref(), c.euid, c.egid, want, &path)? {
            return Err(EACCES);
        }
        // wave10 GV1 (review 3): a running program's file is not opened for writing
        if (flags & rules::O_ACCMODE != rules::O_RDONLY || flags & rules::O_TRUNC != 0) && crate::tmem::text_busy_attr(&attr) {
            return Err(-26); // ETXTBSY
        }
    }
    // wave9 G6b-3 begin: Landlock, as the kernel's open: the open's rights, and TRUNCATE
    // for every file (a later ftruncate on the handle depends on it)
    let mut notrunc = false;
    if let Some(d) = &dom {
        // (a FUSE file: the kernel's, with its lexical chain)
        if crate::fuse::wire::split(n.ino).is_some() {
            return Err(KERNEL);
        }
        let is_dir = attr.is_dir();
        // (wave10 GV1: a file this call made is not truncated)
        let want = ll::open_rights(if created { flags & !rules::O_TRUNC } else { flags }, is_dir);
        let extra = if is_dir { 0 } else { ll::TRUNCATE };
        let refused = policy::refused_on(d, c.id, n, is_dir, want | extra)?;
        if refused & want != 0 {
            return Err(EACCES);
        }
        notrunc = refused & ll::TRUNCATE != 0;
    }
    // wave9 G6b-3 end
    // wave10 GV1: a truncating open of a regular file for writing (an in-memory tmpfs file's
    // pool size is 0 whatever its data: asked)
    let trunc = flags & rules::O_TRUNC != 0 && attr.mode & rules::S_IFMT == rules::S_IFREG && flags & rules::O_ACCMODE != rules::O_RDONLY && !created;
    // (review 2: the handle is installed first, then the file is truncated, so an open that
    // fails to install — EMFILE — leaves the data; a file this open made goes again)
    let trunc = trunc && (attr.size != 0 || (crate::tmem::candidate(&attr) && crate::tmem::is_tmem(n.ino)));
    let mut d = rules::handle_desc(c, n.ino, n.mnt, attr.is_dir(), flags, &path, dirfd)?;
    if notrunc {
        d.flags |= LX_FH_NOTRUNC; // wave9 G6b-3
    }
    // wave9 GP2: the kernel takes the handle with the answer (no LX_FH_INSTALL round): not
    // for FUSE files (counted here), flags beyond the plain ones (6b-3's NOTRUNC), or a call
    // run again
    if !trunc && !created && c.flags & crate::proto::LX_CALL_FHANSWER != 0 && !cx.page().is_null() && n.ino != 0 && n.ino < 1 << 45 && crate::fuse::wire::split(n.ino).is_none() && d.flags & !rules::FH_PLAIN == 0 {
        *fifo = n.ino | (n.mnt as u64) << 45 | (attr.is_dir() as u64) << 61;
        return Err(FHANSWER);
    }
    // wave9 G6b-2: a FUSE file: the open counts here (the daemon's handles live while it is open)
    let fuse = crate::fuse::local_open_ref(n.ino);
    let fd = match sys::lx_obj(LX_FH_INSTALL, cx.id, &d as *const LxFhDesc as u64, 0) {
        Ok(fd) => fd,
        Err(e) => {
            if fuse {
                crate::fuse::local_release(n.ino);
            }
            if let Some((dir, name)) = &made {
                super::make::undo_create(*dir, name, n.ino);
            }
            return Err(e);
        }
    };
    // (a truncation that fails after the install answers its error; the descriptor stays
    // open: there is no way to close it from here, and it is rare — EIO)
    if trunc {
        super::change::truncate_for_open(who, n, &attr)?;
    }
    Ok(fd as i64)
}

// wave10 GV1 begin
/// A walk's error as a plain answer: a redirect to another service or a FUSE wait is the
/// kernel's for the opens that do not go there (`O_PATH`, `O_TMPFILE`).
fn plain(e: i64) -> i64 {
    if e < -4095 {
        KERNEL
    } else {
        e
    }
}

/// `open(path, O_PATH ...)` of `n` (the kernel's rules: no permission check, no Landlock,
/// a symbolic link itself with `O_NOFOLLOW`, any file type; `O_DIRECTORY` and a directory
/// opened for writing as for other opens).
#[allow(clippy::too_many_arguments)]
fn opath(cx: &Cx, c: &crate::proto::LxCall, n: crate::ctx::Node, attr: &crate::fs::fsproto::Attr, flags: u32, path: &[u8], dirfd: i32, fh: &mut u64) -> Result<i64, i64> {
    let kind = attr.mode & rules::S_IFMT;
    if flags & rules::O_DIRECTORY != 0 && kind != rules::S_IFDIR {
        return Err(rules::ENOTDIR);
    }
    if kind == rules::S_IFDIR && flags & rules::O_ACCMODE != rules::O_RDONLY {
        return Err(rules::EISDIR);
    }
    // (a FUSE object: the daemon's handles live while it is open; the kernel's)
    if crate::fuse::wire::split(n.ino).is_some() {
        return Err(KERNEL);
    }
    let d = rules::handle_desc(c, n.ino, n.mnt, attr.is_dir(), flags, path, dirfd)?;
    if c.flags & crate::proto::LX_CALL_FHANSWER != 0 && !cx.page().is_null() && n.ino != 0 && n.ino < 1 << 45 && d.flags & !rules::FH_PLAIN == 0 {
        *fh = n.ino | (n.mnt as u64) << 45 | (attr.is_dir() as u64) << 61;
        return Err(FHANSWER);
    }
    let fd = sys::lx_obj(LX_FH_INSTALL, cx.id, &d as *const LxFhDesc as u64, 0)?;
    Ok(fd as i64)
}
// wave10 GV1 end
