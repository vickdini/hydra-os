//! `getdents64` and `getdents` on a directory handle (the kernel's `vfs::getdents64` and
//! `misc::getdents`): the entries from zfs-server at the handle's cookie, packed for the
//! caller, and the handle's new cookie set in the kernel (`LX_FH_SEEK`).

use hydra_rt::svcrt::Cx;
use hydra_rt::sys;

use super::ctxt;
use super::enc;
use crate::proto::{LX_AT_DIR, LX_AT_FILE, LX_FH_SEEK, LX_FS_FANOTIFY};
use crate::walk::Backend;

const ENOTDIR: i64 = -20;
const EINVAL: i64 = -22;

/// `getdents64(fd, buf, count)`, `getdents(fd, buf, count)`.
pub fn getdents(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, LX_FS_FANOTIFY)?;
    let [fd, buf, count, ..] = cx.args;
    let count = count as u32 as usize;
    let n = ctxt::handle(c)?;
    if c.at_kind == LX_AT_FILE {
        return Err(ENOTDIR);
    }
    debug_assert_eq!(c.at_kind, LX_AT_DIR);
    if !ctxt::BE.getattr(n)?.is_dir() {
        return Err(ENOTDIR);
    }
    let cookie = c.fh_off;
    let entries = crate::zfs::readdir(n.ino, cookie, (count / 24).max(1))?;
    let (out, next) = if cx.nr == 217 { enc::dirents(&entries, count, cookie) } else { enc::dirents_old(&entries, count, cookie) };
    if out.is_empty() {
        if next != cookie {
            return Err(EINVAL);
        }
        // The end of the directory, or a buffer too small for the next entry
        if entries.is_empty() {
            return Ok(0);
        }
        return Err(EINVAL);
    }
    cx.copy_out(buf, &out)?;
    sys::lx_obj(LX_FH_SEEK, cx.id, fd, next)?;
    Ok(out.len() as i64)
}
