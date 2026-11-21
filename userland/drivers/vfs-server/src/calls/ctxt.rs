//! The caller's context of a file call: where its paths start, who it is, and when the
//! kernel must answer instead (`fs_flags`, roots and descriptors outside the pool).

use alloc::vec::Vec;

use hydra_rt::svcrt::Cx;

use crate::be::ZfsBackend;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::Attr;
use crate::perm;
use crate::proto::{LxCall, LX_AT_CWD, LX_AT_DIR, LX_AT_FILE, LX_FS_FOREIGN, LX_FS_MOUNTS};
use crate::walk::{self, Start, Walked};
use crate::zfs;

pub use super::rules::{ENOENT, KERNEL};
/// `AT_SYMLINK_NOFOLLOW`.
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// `AT_EMPTY_PATH`.
pub const AT_EMPTY_PATH: u64 = 0x1000;

/// The back end every call walks through (the caches in front of zfs-server).
pub static BE: ZfsBackend = ZfsBackend { nocache: false };

/// The node of a kernel context word: inode `ino` (0: the pool root) in mount `mnt`.
pub fn node(ino: u64, mnt: u32) -> Result<Node, i64> {
    // (mounts are the kernel's until group 7-3 moves the tables)
    if mnt != 0 || mnt > u16::MAX as u32 {
        return Err(KERNEL);
    }
    Ok(Node::new(0, if ino == 0 { zfs::root()? } else { ino }))
}

/// Fails with [`KERNEL`] when the caller's state needs the kernel: `need` is the call's own
/// `LX_FS_*` bits on top of a root or working directory outside the pool and mounts the
/// service does not know.
pub fn check(c: &LxCall, need: u32) -> Result<(), i64> {
    if c.fs_flags & (LX_FS_FOREIGN | LX_FS_MOUNTS | need) != 0 || c.root_mnt != 0 || c.cwd_mnt != 0 {
        return Err(KERNEL);
    }
    Ok(())
}

/// The caller (its effective ids, groups, capabilities, namespace and root).
pub fn caller(c: &LxCall) -> Result<Ctx, i64> {
    Ok(Ctx::from_call(c, node(c.root, c.root_mnt)?))
}

/// Where a relative `path` of call `c` starts: its directory descriptor (`at_*`) or the
/// working directory. A descriptor that is not a pool handle is the kernel's.
pub fn start(c: &LxCall, path: &[u8]) -> Result<Start, i64> {
    if path.first() == Some(&b'/') {
        return Ok(Start::Root);
    }
    match c.at_kind {
        LX_AT_CWD => Ok(Start::At(node(c.cwd, c.cwd_mnt)?)),
        // (a file as the directory: the walk says ENOTDIR, as Linux does)
        LX_AT_FILE | LX_AT_DIR => Ok(Start::At(node(c.at_ino, c.at_mnt)?)),
        _ => Err(KERNEL),
    }
}

/// The handle of a call on a descriptor (`at_*` with kind file or directory).
pub fn handle(c: &LxCall) -> Result<Node, i64> {
    match c.at_kind {
        LX_AT_FILE | LX_AT_DIR => node(c.at_ino, c.at_mnt),
        _ => Err(KERNEL),
    }
}

/// The path at `ptr` as the kernel reads one for a path call ([`super::rules::check_path`]).
pub fn path(cx: &Cx, ptr: u64, empty_ok: bool) -> Result<Vec<u8>, i64> {
    let p = cx.user_cstr(ptr)?;
    super::rules::check_path(&p, empty_ok)?;
    Ok(p)
}

/// Walks `path` of call `c` for `who`: the object and its attributes; a walk into a tree
/// another service (today: the kernel) serves is [`KERNEL`].
pub fn find(c: &LxCall, who: &Ctx, path: &[u8], follow: bool) -> Result<(Node, Attr), i64> {
    let start = start(c, path)?;
    match walk::walk(&BE, who, start, path, if follow { 0 } else { walk::NOFOLLOW })? {
        Walked::Found { node, attr } => Ok((node, attr)),
        Walked::Redirect(_) => Err(KERNEL),
    }
}

/// The kernel's permission rule ([`super::rules::may_access`]) for `uid`/`gid` with the
/// caller's supplementary groups; `acl`: the object's access ACL, if it has one.
pub fn may_access(who: &Ctx, attr: &Attr, acl: Option<&[u8]>, uid: u32, gid: u32, want: u32) -> bool {
    let mut as_ids = who.clone();
    as_ids.uid = uid;
    as_ids.gid = gid;
    let by_acl = if uid == 0 { None } else { acl.and_then(|a| perm::acl_check(&as_ids, attr, a, want)) };
    super::rules::may_access(attr.mode, attr.uid, attr.gid, uid, want, by_acl, |g| as_ids.in_group(g))
}

/// The access ACL of `n` when its attributes say it may have one.
pub fn acl_of(n: Node, attr: &Attr) -> Option<Vec<u8>> {
    use crate::walk::Backend;
    if attr.has_xattr {
        BE.acl(n)
    } else {
        None
    }
}
