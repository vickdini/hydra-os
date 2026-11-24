//! # The names other services serve in `/sys` and `/dev` (wave 10, Group V2)
//!
//! `/sys` and `/dev` are pool trees (written at boot by the kernel's `devices.rs`) that
//! vfs-server walks like any other directory. A few names in them are served by another
//! service, as Linux mounts other file systems there (decision 19: reached with one
//! redirect at lookup, `walk::Backend::served`):
//!
//! - `/sys/devices/system/cpu/{online,possible,present}` and efivars *opens*
//!   (`/sys/firmware/efi/efivars/<name>`): linux-server, with the tail below `/sys` exactly as
//!   when it got the whole of `/sys` (its `pseudo/path.rs` rules; the efivars files are in
//!   the pool too, so their `stat` and `access` are answered here);
//! - `/sys/fs/cgroup/.../cgroup.procs`: the kernel's control groups (service 0);
//! - `/dev/pts`: the terminals' service (devpts: the pseudo-terminal slaves are its nodes).
//!
//! Plain functions of their inputs (host-tested in `tests/host-w10-v2`).

use crate::ctx::{Ctx, Node};
use crate::proto::{SvcId, LXS_LINUX, LXS_TTY, LX_VFS_PSEUDO_DEVPTS, LX_VFS_PSEUDO_SYS};
use crate::walk::Backend;

/// The tree a served name may start in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tree {
    /// The caller's root's `sys`.
    Sys,
    /// The caller's root's `dev`.
    Dev,
}

/// Whether a served name may start at component `name` (the first component below the
/// tree's top: the walk asks only then; review 3: and the names a walk that starts inside
/// `/dev/pts` or a control group directory meets: a slave's number, `ptmx`, `cgroup.procs`).
pub fn may_serve(name: &[u8]) -> bool {
    matches!(name, b"devices" | b"firmware" | b"fs" | b"pts" | b"ptmx" | b"cgroup.procs") || is_number(name)
}

/// Whether `name` is a decimal number (a pseudo-terminal slave's name).
fn is_number(name: &[u8]) -> bool {
    !name.is_empty() && name.len() <= 7 && name.iter().all(|b| b.is_ascii_digit())
}

/// [`LX_VFS_PSEUDO_DEVPTS`] with this bit: the redirect's rest starts below `pts` (a walk that
/// started in the `/dev/pts` directory) instead of at `pts`.
pub const PTS_BELOW: u64 = 0x100;
/// wave11 GF (review 4): with [`LX_VFS_PSEUDO_DEVPTS`]: the mount is a devpts of its own (a
/// sandbox's newinstance mount), not the system's.
pub const PTS_NEWINST: u64 = 0x200;

/// The tree a served name starting at `name` is in (`name` passed [`may_serve`]).
pub fn tree_of(name: &[u8]) -> Tree {
    if name == b"pts" { Tree::Dev } else { Tree::Sys }
}

/// The walk's question (`walk::Backend::served`) for back end `be`: the service serving
/// `name` (with `rest` after it) in directory `dir`, when `dir` is the caller's root's `sys`
/// or `dev` (looked up when such a name is met, from the caches). `open`: the call is an open.
pub fn check(be: &dyn Backend, cx: &Ctx, dir: Node, name: &[u8], rest: &[&[u8]], open: bool) -> Option<(SvcId, u64)> {
    // review 3: walks that start inside /dev/pts or a control group directory (a descriptor
    // or the working directory there)
    if name == b"cgroup.procs" {
        return in_cgroup(be, cx, dir).then_some((0, 0));
    }
    if name == b"ptmx" || is_number(name) {
        let pts = be.lookup(be.lookup(cx.root, b"dev").ok()?, b"pts").ok()?;
        return (dir == pts).then_some((LXS_TTY, LX_VFS_PSEUDO_DEVPTS | PTS_BELOW));
    }
    let tree = tree_of(name);
    let top: &[u8] = if tree == Tree::Dev { b"dev" } else { b"sys" };
    if be.lookup(cx.root, top).ok()? != dir {
        return None;
    }
    served(tree, name, rest, open)
}

/// Whether directory `dir` is the caller's root's `sys/fs/cgroup` or below it (climbing `..`
/// from the caches, 32 levels at most).
fn in_cgroup(be: &dyn Backend, cx: &Ctx, dir: Node) -> bool {
    let cg = (|| be.lookup(be.lookup(be.lookup(cx.root, b"sys").ok()?, b"fs").ok()?, b"cgroup").ok())();
    let Some(cg) = cg else { return false };
    let mut d = dir;
    for _ in 0..32 {
        if d == cg {
            return true;
        }
        if d == cx.root {
            return false;
        }
        match be.lookup(d, b"..") {
            Ok(p) if p != d => d = p,
            _ => return false,
        }
    }
    false
}

/// The service serving `name` with `rest` after it, directly below the top of `tree`:
/// `(service, object)` for the redirect (service 0: the kernel). `open`: the call is an
/// open (efivars files are redirected only then).
pub fn served(tree: Tree, name: &[u8], rest: &[&[u8]], open: bool) -> Option<(SvcId, u64)> {
    match (tree, name, rest) {
        (Tree::Sys, b"devices", [b"system", b"cpu", b"online" | b"possible" | b"present"]) => Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)),
        (Tree::Sys, b"firmware", [b"efi", b"efivars", n]) if open && !n.is_empty() => Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)),
        (Tree::Sys, b"fs", [b"cgroup", .., last]) if *last == b"cgroup.procs" => Some((0, 0)),
        // (wave11 GF: an open of the directory itself is the pool's `/dev/pts`: a handle that
        // `*at` calls start from and that the kernel lists through tty-server)
        (Tree::Dev, b"pts", []) if open => None,
        (Tree::Dev, b"pts", _) => Some((LXS_TTY, LX_VFS_PSEUDO_DEVPTS)),
        _ => None,
    }
}

// wave11 GF begin: efivars unlinks (linux-server deletes the variable)
/// Whether directory `dir` is the caller's root's `sys/firmware/efi/efivars` (from the
/// caches).
pub fn is_efivars_dir(be: &dyn Backend, cx: &Ctx, dir: Node) -> bool {
    let mut n = cx.root;
    for name in [&b"sys"[..], b"firmware", b"efi", b"efivars"] {
        match be.lookup(n, name) {
            Ok(x) => n = x,
            Err(_) => return false,
        }
    }
    n == dir
}

/// Where the part below `/sys` starts in `path` (an absolute or relative path naming an
/// efivars file: `.../firmware/efi/efivars/<name>`), as linux-server's rules take it.
pub fn efivars_tail(path: &[u8]) -> Option<u32> {
    let key: &[u8] = b"firmware/efi/efivars/";
    let i = path.windows(key.len()).rposition(|w| w == key)?;
    (i == 0 || path[i - 1] == b'/').then_some(i as u32)
}
// wave11 GF end
