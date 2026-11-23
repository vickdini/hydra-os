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
//! family, `access`, `readlink`, `statfs`), `dir` (`getdents64`, `getdents`), `open`,
//! `change` (attributes and names), `rules` (decisions, host-tested).

pub mod enc;
mod change;
// (crate-visible: 7-3's mount calls use the same caller context)
pub(crate) mod ctxt;
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
/// faccessat, faccessat2, readlink, readlinkat, statfs, open, openat;
/// chmod, fchmodat, fchmod, chown, lchown, fchownat, fchown, truncate, ftruncate,
/// utimensat; mkdir, mkdirat, symlink, symlinkat, unlink, rmdir, unlinkat, rename,
/// renameat, renameat2.
pub const CLAIMED: &[u64] = &[
    // read-only. getdents64/getdents (217, 78) are served by `dir.rs` but not claimed: with
    // them a warm `find /usr` took 0.87-0.93 s against the kernel's 0.46-0.52 s; without,
    // 0.44-0.48 s (budget runs bA5/bA6/bG1, 2026-11-21). `calls=...` can claim them for tests.
    4, 6, 262, 332, 21, 269, 439, 89, 267, 137, 2, 257,
    90, 268, 91, 92, 94, 260, 93, 76, 77, 280, // attributes
    83, 258, 88, 266, 87, 84, 263, 82, 264, 316, // names
];

/// Calls served here but claimed only on request (`calls=...`): getdents64, getdents.
pub const EXTRA: &[u64] = &[217, 78];

// wave7 G7-4 begin: redirects to the Linux services' pseudo file systems
/// Calls redirected to linux-server (`/proc`, `/sys`) since start.
pub static TO_PSEUDO: AtomicU64 = AtomicU64::new(0);
/// `pseudo=0` among the program's arguments: `/proc` and `/sys` stay the kernel's.
static PSEUDO_OFF: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
/// The tag of a [`pseudo_redirect`] error (bits 60..64 = 0b1001; `KERNEL` is `i64::MIN`).
const PSEUDO_TAG: u64 = 0x9 << 60;

/// The error a walk that ended in a served mount answers: a redirect to linux-server for
/// `/proc` and `/sys` (when the rest of the path is the argument's suffix), else [`KERNEL`].
/// [`answer`] makes the redirect, for the calls linux-server serves.
pub fn pseudo_redirect(r: &crate::walk::Redirect) -> i64 {
    use crate::proto::{LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};
    let obj = r.obj & 0xFFFF_FFFF;
    match r.tail {
        Some(t) if !PSEUDO_OFF.load(Ordering::Relaxed) && (r.svc == LXS_PROC || r.svc == LXS_LINUX) && (obj == LX_VFS_PSEUDO_PROC || obj == LX_VFS_PSEUDO_SYS) && t < 1 << 20 => {
            (PSEUDO_TAG | (r.svc as u64) << 48 | obj << 36 | t as u64) as i64
        }
        _ => KERNEL,
    }
}

/// The redirect a [`pseudo_redirect`] error names: `(service, object, tail)`.
fn pseudo_of(e: i64) -> Option<(u8, u64, u32)> {
    let v = e as u64;
    (e != KERNEL && v >> 60 == PSEUDO_TAG >> 60).then(|| (((v >> 48) & 0xFF) as u8, (v >> 36) & 0xFFF, (v & 0xF_FFFF) as u32))
}

/// Calls linux-server serves under `/proc` and `/sys` (stat family, access, readlink,
/// open); the others go to the kernel straight away.
fn pseudo_served(nr: u64) -> bool {
    matches!(nr, 4 | 6 | 262 | 332 | 21 | 269 | 439 | 89 | 267 | 2 | 257)
}
// wave7 G7-4 end

/// Calls answered here, and sent back to the kernel, since start.
pub static SERVED: AtomicU64 = AtomicU64::new(0);
/// See [`SERVED`].
pub static TO_KERNEL: AtomicU64 = AtomicU64::new(0);

/// Claims every call of [`CLAIMED`] (once online; `calls=0` among the program's arguments
/// leaves them all to the kernel). `calls=4,6,...`: only these (also [`EXTRA`]). Returns how many the kernel took.
pub fn claim_all(args: &[&str]) -> usize {
    if args.iter().any(|a| *a == "pseudo=0") {
        PSEUDO_OFF.store(true, Ordering::Relaxed); // wave7 G7-4
    }
    if args.iter().any(|a| *a == "calls=0") {
        return 0;
    }
    // `calls=4,6,...`: only these
    let only: Option<alloc::vec::Vec<u64>> = args.iter().find_map(|a| a.strip_prefix("calls=")).map(|l| l.split(',').filter_map(|n| n.parse().ok()).collect());
    let list: alloc::vec::Vec<u64> = match only {
        // (also the calls served here but not claimed by default)
        Some(o) => o.into_iter().filter(|nr| CLAIMED.contains(nr) || EXTRA.contains(nr)).collect(),
        None => CLAIMED.to_vec(),
    };
    list.iter().filter(|&&nr| sys::lx_obj(LX_FH_CLAIM, nr, 1, 0).is_ok()).count()
}

/// Serves forwarded call `cx` if it is one of this module's (`None`: not one).
pub fn serve(cx: &Cx) -> Option<Answer> {
    let r = match cx.nr {
        4 | 6 | 262 | 332 => stat::stat(cx),
        21 | 269 | 439 => stat::access(cx),
        89 | 267 => stat::readlink(cx),
        137 => stat::statfs(cx),
        217 | 78 => dir::getdents(cx),
        2 | 257 => return Some(open::serve(cx)), // (wave7 G7-5: FIFOs redirect to LXS_IPC)
        90 | 268 | 91 | 92 | 94 | 260 | 93 | 76 | 77 | 280 => change::attrs(cx),
        83 | 258 => change::mkdir(cx),
        88 | 266 => change::symlink(cx),
        87 | 84 | 263 => change::unlink(cx),
        82 | 264 | 316 => change::rename(cx),
        _ => return None,
    };
    Some(answer(cx, r))
}

/// The answer for result `r` (`Err(KERNEL)`: the kernel's code answers the call).
pub fn answer(cx: &Cx, r: Result<i64, i64>) -> Answer {
    // wave9 G6b-2 begin: the walk has to ask a FUSE daemon: the call waits and runs again
    // from the reply (`crate::fuse`); a call that cannot is the kernel's
    let r = match r {
        Err(e) if crate::fuse::is_miss(e) => {
            if crate::fuse::wait_miss(e, &cx.c) {
                return (0, crate::proto::LX_REPLY_PENDING);
            }
            Err(KERNEL)
        }
        r => r,
    };
    // A call run again after a FUSE reply has no page: "the kernel answers" is told with
    // the result (`crate::rerun`)
    if cx.page().is_null() {
        if let Err(e) = r {
            if e == KERNEL || pseudo_of(e).is_some() {
                TO_KERNEL.fetch_add(1, Ordering::Relaxed);
                return (0, crate::proto::LX_REPLY_REDIRECT);
            }
        }
    }
    // wave9 G6b-2 end
    // wave7 G7-4: a walk into `/proc` or `/sys`: linux-server serves the call
    if let Err(e) = r {
        if let Some((svc, obj, tail)) = pseudo_of(e) {
            if pseudo_served(cx.nr) {
                let n = TO_PSEUDO.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || (n >= 1024 && n.is_power_of_two()) {
                    hydra_rt::println!("[vfs-server] {} calls redirected to linux-server (/proc, /sys)", n);
                }
                return svcrt::redirect(cx.page(), svc, obj, tail);
            }
            TO_KERNEL.fetch_add(1, Ordering::Relaxed);
            return svcrt::redirect(cx.page(), 0, 0, 0);
        }
    }
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
