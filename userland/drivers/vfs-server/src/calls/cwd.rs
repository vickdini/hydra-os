//! `chdir` and `fchdir` (wave 10, Group V2; the kernel's `NR_CHDIR`/`NR_FCHDIR`): the walk
//! or the handle, the checks (a directory, search permission, the access policies), then
//! `LX_FH_CHDIR`: the kernel sets the caller's working directory handle and its path (shown
//! by `getcwd`) from the path the walk took ([`crate::walk::Track`]: symbolic links
//! resolved, as the kernel's `dir_path` had it).

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt;
use super::rules::{self, KERNEL};
use crate::perm::MAY_EXEC;
use crate::proto::{LxFhDesc, LX_FH_CHDIR};
use crate::walk::{self, Backend, Walked};

const EACCES: i64 = -13;
const AT_FDCWD: i32 = -100;

/// `chdir(path)`.
pub fn chdir(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let path = ctxt::path(cx, cx.args[0], false)?;
    let k = ctxt::call(c)?;
    let start = k.start(c, &path)?;
    let (n, attr, track) = match walk::walk_track(&k.w, &k.who, start, &path, 0)? {
        (Walked::Found { node, attr }, t) => (node, attr, t),
        // (a directory another service serves, `/proc`: the kernel's)
        (Walked::Redirect(_), _) => return Err(KERNEL),
    };
    enter(cx, &k.who, n, &attr, &path, &track.text(), AT_FDCWD)
}

/// `fchdir(fd)`.
pub fn fchdir(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    let k = ctxt::call(c)?;
    let n = ctxt::handle(c)?;
    let attr = k.w.getattr(n)?;
    // (the shown path is the handle's own: `LX_FHP_AT` with nothing after it)
    enter(cx, &k.who, n, &attr, b"", b"", cx.args[0] as i32)
}

/// Makes directory `n` (attributes `attr`, named `named` by the caller) the caller's working
/// directory, shown as `shown` (relative to the working directory, or to descriptor `fd`
/// when that is not `AT_FDCWD`).
fn enter(cx: &Cx, who: &crate::ctx::Ctx, n: crate::ctx::Node, attr: &crate::fs::fsproto::Attr, named: &[u8], shown: &[u8], fd: i32) -> Result<i64, i64> {
    let c = &cx.c;
    if !attr.is_dir() {
        return Err(rules::ENOTDIR);
    }
    // (a FUSE directory: a working directory in a FUSE mount is the kernel's)
    if crate::fuse::wire::split(n.ino).is_some() {
        return Err(KERNEL);
    }
    let acl = ctxt::acl_of(n, attr)?;
    if !ctxt::allowed(who, attr, acl.as_deref(), c.euid, c.egid, MAY_EXEC, named)? {
        return Err(EACCES);
    }
    let d: LxFhDesc = rules::handle_desc(c, n.ino, n.mnt, true, 0, shown, fd)?;
    sys::lx_obj(LX_FH_CHDIR, cx.id, &d as *const LxFhDesc as u64, 0)?;
    Ok(0)
}
