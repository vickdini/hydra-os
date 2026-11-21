//! # The file calls (wave 7, Group 7-2)
//!
//! The path calls and the calls on handles that vfs-server answers, on top of the core's
//! walk, caches and zfs-server client (Group 7-1). The kernel sends a call here only once
//! vfs-server claimed its number ([`claim_all`], `LX_FH_CLAIM`); it carries the caller's
//! context (`LxCall::root`/`cwd` and mounts, the directory descriptor of an `*at` call as
//! `at_kind`/`at_ino`, a handle's offset and flags, `fs_flags`). Handles are the kernel's: an
//! `open` makes one with `LX_FH_INSTALL` and vfs-server keeps nothing of it.
//!
//! **What goes back to the kernel** (the answer "redirect to service 0", [`KERNEL`]): what
//! vfs-server does not serve yet, decided before anything is changed:
//! - a walk that ends in `/proc`, `/sys` or `/dev` (the kernel serves them by name until
//!   group 7-4), a descriptor that is not a pool handle, a root or working directory outside
//!   the pool, a mount namespace of its own or FUSE mounts (until group 7-3);
//! - callers whose calls make events or checks only the kernel has: Landlock, fanotify,
//!   ABAC (and inotify for the changes);
//! - `open` of anything but an existing regular file or directory, `O_PATH`, `O_TMPFILE`,
//!   creating and truncating opens.
//!
//! The modules: [`enc`] (result layouts), `ctxt` (the caller's context), `stat` (the `stat`
//! family, `access`, `readlink`, `statfs`), `dir` (`getdents64`, `getdents`), `open`.

pub mod enc;
mod ctxt;
mod dir;
mod open;
pub mod rules;
mod stat;

use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::svcrt::{self, Answer, Cx};
use hydra_rt::sys;

use crate::proto::{LX_FH_CLAIM};

pub use ctxt::KERNEL;

/// The calls this module serves (x86-64 numbers): stat, lstat, newfstatat, statx, access,
/// faccessat, faccessat2, readlink, readlinkat, statfs, getdents64, getdents, open, openat.
pub const CLAIMED: &[u64] = &[4, 6, 262, 332, 21, 269, 439, 89, 267, 137, 217, 78, 2, 257];

/// Calls answered here, and sent back to the kernel, since start.
pub static SERVED: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL: AtomicU64 = AtomicU64::new(0);

/// Claims every call of [`CLAIMED`] (once online; `calls=0` among the program's arguments
/// leaves them all to the kernel). Returns how many the kernel took.
pub fn claim_all(args: &[&str]) -> usize {
    if args.iter().any(|a| *a == "calls=0") {
        return 0;
    }
    // `calls=4,6,...`: only these
    let only: Option<alloc::vec::Vec<u64>> = args.iter().find_map(|a| a.strip_prefix("calls=")).map(|l| l.split(',').filter_map(|n| n.parse().ok()).collect());
    CLAIMED.iter().filter(|nr| only.as_ref().is_none_or(|o| o.contains(nr))).filter(|&&nr| sys::lx_obj(LX_FH_CLAIM, nr, 1, 0).is_ok()).count()
}

/// Serves forwarded call `cx` if it is one of this module's (`None`: not one).
pub fn serve(cx: &Cx) -> Option<Answer> {
    let r = match cx.nr {
        4 | 6 | 262 | 332 => stat::stat(cx),
        21 | 269 | 439 => stat::access(cx),
        89 | 267 => stat::readlink(cx),
        137 => stat::statfs(cx),
        217 | 78 => dir::getdents(cx),
        2 | 257 => open::open(cx),
        _ => return None,
    };
    Some(answer(cx, r))
}

/// The answer for result `r` (`Err(KERNEL)`: the kernel's code answers the call).
pub fn answer(cx: &Cx, r: Result<i64, i64>) -> Answer {
    match r {
        Err(KERNEL) => {
            TO_KERNEL.fetch_add(1, Ordering::Relaxed);
            svcrt::redirect(cx.page(), 0, 0, 0)
        }
        Ok(v) | Err(v) => {
            SERVED.fetch_add(1, Ordering::Relaxed);
            (v, 0)
        }
    }
}
