//! # The mount calls vfs-server serves (wave 7, Group 7-3)
//!
//! **`chroot`** (161): the walk, the checks of the kernel's `sys_chroot` (`CAP_SYS_CHROOT`
//! first, a directory, search permission on it), then `LX_FH_CHROOT`: the kernel sets the
//! caller's root handle (and those of the processes sharing it, `CLONE_FS`). What the calls
//! of Group 7-2 hand to the kernel goes there too: a caller in a mount namespace of its
//! own, a root or working directory outside the pool, a walk into `/proc`, `/sys` or `/dev`
//! (the kernel's empty root for `/proc/<pid>/fd` and the like).
//!
//! **Not yet moved:** `mount`, `umount2`, `pivot_root` and the new mount API (`fsopen`,
//! `fsconfig`, `fsmount`, `open_tree`, `move_mount`, `fspick`, `mount_setattr`, `statmount`,
//! `listmount`). Their tables are ready ([`crate::mtab`]), but while the kernel still answers
//! the path calls of a process in a mount namespace of its own (7-2 hands them back), the
//! mounts must stay in the kernel's table, or those calls would not see them; and a tmpfs
//! file needs a kernel handle on its memory object (7-2's next step). They move together
//! with the path calls of such processes.

use hydra_rt::svcrt::{Answer, Cx};
use hydra_rt::sys;

use crate::calls::{self, ctxt};
use crate::mtab::CAP_SYS_CHROOT;
use crate::perm::MAY_EXEC;
use crate::proto::{LxFhDesc, LX_FH_CHROOT, LX_FH_CLAIM};

const EPERM: i64 = -1;
const ENOTDIR: i64 = -20;
const EACCES: i64 = -13;

/// The calls served here. **Empty for now:** with chroot (161) claimed, nstest's
/// `chroot("/proc/self/fdinfo/")` from a `CLONE_FS` child (a walk into /proc: vfs-server
/// answers "redirect to the kernel") leaves the parent able to `open("/etc/hostname")`
/// although its root is the kernel's empty root; unclaimed, or with `lx.vfs=kernel`, nstest
/// passes. Until the redirect path for this call is understood (7-2's `LX_TO_KERNEL` after
/// `fill`), chroot stays the kernel's; the code below is tested (tests/linux/chroot_w7.c
/// PASS when claimed) and is switched on by putting 161 back here.
pub const CLAIMED: &[u64] = &[];

/// Claims [`CLAIMED`] (`mcalls=0` among the program's arguments leaves them to the kernel).
pub fn claim_all(args: &[&str]) -> usize {
    if args.iter().any(|a| *a == "mcalls=0") {
        return 0;
    }
    CLAIMED.iter().filter(|&&nr| sys::lx_obj(LX_FH_CLAIM, nr, 1, 0).is_ok()).count()
}

/// Serves `cx` if it is one of these calls.
pub fn serve(cx: &Cx) -> Option<Answer> {
    let r = match cx.nr {
        161 => chroot(cx),
        _ => return None,
    };
    Some(calls::answer(cx, r))
}

/// `chroot(path)`.
fn chroot(cx: &Cx) -> Result<i64, i64> {
    let c = &cx.c;
    ctxt::check(c, 0)?;
    // As the kernel: the capability before anything about the path
    if c.caps & CAP_SYS_CHROOT == 0 {
        return Err(EPERM);
    }
    let who = ctxt::caller(c)?;
    let path = ctxt::path(cx, cx.args[0], false)?;
    let (node, attr) = ctxt::find(c, &who, &path, true)?;
    if !attr.is_dir() {
        return Err(ENOTDIR);
    }
    let acl = ctxt::acl_of(node, &attr)?;
    if !ctxt::may_access(&who, &attr, acl.as_deref(), who.uid, who.gid, MAY_EXEC) {
        return Err(EACCES);
    }
    let d = LxFhDesc { ino: node.ino, mnt: 0, is_dir: 1, ..LxFhDesc::EMPTY };
    sys::lx_obj(LX_FH_CHROOT, c.id, &d as *const LxFhDesc as u64, 0)?;
    // The first one of this instance in the log (shows vfs-server answers them)
    if !FIRST.swap(true, core::sync::atomic::Ordering::Relaxed) {
        hydra_rt::println!("[vfs-server] first chroot served (object {})", node.ino);
    }
    Ok(0)
}

/// Whether a chroot was served yet.
static FIRST: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
