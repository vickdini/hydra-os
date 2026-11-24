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
/// tree's top: the walk asks only then).
pub fn may_serve(name: &[u8]) -> bool {
    matches!(name, b"devices" | b"firmware" | b"fs" | b"pts")
}

/// The tree a served name starting at `name` is in (`name` passed [`may_serve`]).
pub fn tree_of(name: &[u8]) -> Tree {
    if name == b"pts" { Tree::Dev } else { Tree::Sys }
}

/// The walk's question (`walk::Backend::served`) for back end `be`: the service serving
/// `name` (with `rest` after it) in directory `dir`, when `dir` is the caller's root's `sys`
/// or `dev` (looked up when such a name is met, from the caches). `open`: the call is an open.
pub fn check(be: &dyn Backend, cx: &Ctx, dir: Node, name: &[u8], rest: &[&[u8]], open: bool) -> Option<(SvcId, u64)> {
    let tree = tree_of(name);
    let top: &[u8] = if tree == Tree::Dev { b"dev" } else { b"sys" };
    if be.lookup(cx.root, top).ok()? != dir {
        return None;
    }
    served(tree, name, rest, open)
}

/// The service serving `name` with `rest` after it, directly below the top of `tree`:
/// `(service, object)` for the redirect (service 0: the kernel). `open`: the call is an
/// open (efivars files are redirected only then).
pub fn served(tree: Tree, name: &[u8], rest: &[&[u8]], open: bool) -> Option<(SvcId, u64)> {
    match (tree, name, rest) {
        (Tree::Sys, b"devices", [b"system", b"cpu", b"online" | b"possible" | b"present"]) => Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)),
        (Tree::Sys, b"firmware", [b"efi", b"efivars", n]) if open && !n.is_empty() => Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)),
        (Tree::Sys, b"fs", [b"cgroup", .., last]) if *last == b"cgroup.procs" => Some((0, 0)),
        (Tree::Dev, b"pts", _) => Some((LXS_TTY, LX_VFS_PSEUDO_DEVPTS)),
        _ => None,
    }
}
