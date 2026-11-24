//! The caller's context of a file call: where its paths start, who it is, and when the
//! kernel must answer instead (`fs_flags`, roots and descriptors outside the pool).

use alloc::sync::Arc;
use alloc::vec::Vec;

use hydra_rt::svcrt::Cx;

use crate::be::ZfsBackend;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::Attr;
use crate::kmounts::{self, View};
use crate::perm;
use crate::proto::{LxCall, LX_AT_CWD, LX_AT_DIR, LX_AT_FILE, LX_FS_FOREIGN, LX_FS_MOUNTS};
use crate::walk::{self, Backend, Mounts, Start, Walked};
use crate::zfs;

pub use super::rules::{ENOENT, KERNEL};
/// `AT_SYMLINK_NOFOLLOW`.
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// `AT_EMPTY_PATH`.
pub const AT_EMPTY_PATH: u64 = 0x1000;
/// `EROFS` (wave10 GV1).
pub const EROFS: i64 = -30;

/// The back end of the objects themselves (the caches in front of zfs-server): pool
/// objects only (`POOL_ONLY`: no node reaches vfs-server's own tmpfs through the calls;
/// the kernel's tmpfs mounts are pool trees). The walks use [`walker`]: this back end with
/// the caller's mount table.
pub static BE: ZfsBackend = ZfsBackend { nocache: false, ns: crate::mount::POOL_ONLY };

// wave7 G7-7 begin: the caller's mount table (`kmounts`)
/// The walk's back end for one call: [`BE`] with the copy of the caller's mount table.
pub struct Walker {
    /// The copy of the caller's table.
    pub view: Arc<View>,
    // wave9 G6b-2 begin
    /// The call may wait for a FUSE daemon (and run again from its reply).
    pub fuse: bool,
    /// The caller's effective user (FUSE mounts without `allow_other` are their owner's).
    pub euid: u32,
    // wave9 G6b-2 end
    /// wave9 G6b-3: the caller is landlocked (its walks leave parent hints).
    pub ll: bool,
    /// wave9 G6b-3: the call (its walk's last step is remembered for it).
    pub req: u64,
    /// wave10 GV2: the call's number (efivars: only an open is redirected).
    pub nr: u64,
}

impl Walker {
    /// wave9 G6b-2: a FUSE node, for a call that may wait (else the kernel answers it).
    fn fuse_node(&self, n: Node) -> Result<bool, i64> {
        match crate::fuse::wire::split(n.ino) {
            Some(_) if self.fuse => Ok(true),
            Some(_) => Err(KERNEL),
            None => Ok(false),
        }
    }
}

impl Backend for Walker {
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64> {
        if self.fuse_node(dir)? {
            return crate::fuse::be_lookup(dir, name, self.euid);
        }
        BE.lookup(dir, name)
    }
    fn getattr(&self, n: Node) -> Result<Attr, i64> {
        if self.fuse_node(n)? {
            return crate::fuse::be_getattr(n, self.euid);
        }
        BE.getattr(n)
    }
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64> {
        if self.fuse_node(n)? {
            return crate::fuse::be_readlink(n, self.euid);
        }
        BE.readlink(n)
    }
    fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64> {
        // (FUSE: no ACLs here; the daemon decides beyond the mode bits)
        if self.fuse_node(n)? {
            return Ok(None);
        }
        BE.acl(n)
    }
    fn mounts(&self) -> &dyn Mounts {
        &*self.view
    }
    // wave9 G6b-3 begin
    fn found(&self, dir: Node, name: &[u8], child: Node) {
        if self.ll {
            crate::policy::hint(self.req, dir, name, child);
        }
    }
    fn may_search_policy(&self, cx: &Ctx, dir: &Attr) -> Result<bool, i64> {
        // (root is not restricted: the kernel's `may_search` returns before for euid 0)
        if cx.uid == 0 {
            return Ok(true);
        }
        crate::policy::abac(cx, dir, perm::MAY_EXEC, false, b"")
    }
    // wave9 G6b-3 end
    // wave10 GV2 begin
    fn may_serve(&self, name: &[u8]) -> bool {
        super::served::may_serve(name)
    }
    fn served(&self, cx: &Ctx, dir: Node, name: &[u8], rest: &[&[u8]]) -> Option<(crate::proto::SvcId, u64)> {
        super::served::check(self, cx, dir, name, rest, matches!(self.nr, 2 | 257 | 85))
    }
    // wave10 GV2 end
}

/// The walker of call `c`: the copy of its caller's mount table at least as new as the
/// call (`LxCall::mnt_gen`).
pub fn walker(c: &LxCall) -> Result<Walker, i64> {
    Ok(Walker { view: kmounts::view(c.mnt_ns, c.mnt_gen)?, fuse: crate::fuse::rerunnable(c.nr) && !(c.ll_dom != 0 && matches!(c.nr, 2 | 257)), euid: c.euid, ll: c.ll_dom != 0, req: c.id, nr: c.nr })
}

/// The caller's root in table `v`: inode `c.root` (0: the pool's root, or in another
/// namespace its root mount's root) in mount `c.root_mnt` (0 there: the root mount).
fn root_in(v: &View, c: &LxCall) -> Result<Node, i64> {
    if v.ns == 0 {
        if c.root_mnt != 0 {
            return Err(KERNEL);
        }
        return Ok(Node::new(0, if c.root == 0 { zfs::root()? } else { c.root }));
    }
    let mnt = if c.root_mnt == 0 { v.root } else { c.root_mnt };
    let ino = if c.root == 0 { v.root_ino().ok_or(KERNEL)? } else { c.root };
    let n = Node::new(u16::try_from(mnt).map_err(|_| KERNEL)?, ino);
    if !v.walkable(n) {
        return Err(KERNEL);
    }
    Ok(n)
}

/// The node of a kernel context word in table `v`: inode `ino` in mount `mnt` (the initial
/// namespace: 0 is the pool root; another: 0 is the caller's `root`, and a mount 0 is only
/// right for the root itself, as the kernel's walk takes it).
fn node_in(v: &View, root: Node, ino: u64, mnt: u32) -> Result<Node, i64> {
    if v.ns == 0 {
        if mnt != 0 {
            return Err(KERNEL);
        }
        return Ok(Node::new(0, if ino == 0 { zfs::root()? } else { ino }));
    }
    if ino == 0 || (mnt == 0 && ino == root.ino) {
        return Ok(root);
    }
    let n = Node::new(u16::try_from(mnt).map_err(|_| KERNEL)?, ino);
    if mnt == 0 || !v.walkable(n) {
        return Err(KERNEL);
    }
    Ok(n)
}

/// The `MS_*` flags of the mount `n` is in, for call `c`.
pub fn mount_flags(c: &LxCall, n: Node) -> Result<u32, i64> {
    let w = walker(c)?;
    // (a newer copy taken during the call may no longer have the mount: the kernel decides)
    if !w.view.walkable(n) {
        return Err(KERNEL);
    }
    Ok(w.view.flags(n.mnt))
}

/// `EROFS` when `n` lies in a read-only mount (wave10 GV1: answered here; was the kernel's).
pub fn writable(c: &LxCall, n: Node) -> Result<(), i64> {
    if mount_flags(c, n)? & kmounts::MS_RDONLY != 0 {
        return Err(EROFS);
    }
    Ok(())
}

/// [`KERNEL`] when `n` is a mount point (removing or renaming it is the kernel's).
pub fn not_mountpoint(c: &LxCall, n: Node) -> Result<(), i64> {
    let w = walker(c)?;
    // (a newer copy without `n`'s mount: the kernel decides — 7-7 review)
    if !w.view.walkable(n) || w.view.is_mountpoint(n) {
        return Err(KERNEL);
    }
    Ok(())
}
// wave7 G7-7 end

/// Fails with [`KERNEL`] when the caller's state needs the kernel: `need` is the call's own
/// `LX_FS_*` bits on top of a root or working directory outside the pool and mounts the
/// service cannot be given (wave7 G7-7: the others come as a copy of the table, `walker`).
pub fn check(c: &LxCall, need: u32) -> Result<(), i64> {
    if c.fs_flags & (LX_FS_FOREIGN | LX_FS_MOUNTS | need) != 0 || (c.mnt_ns == 0 && (c.root_mnt != 0 || c.cwd_mnt != 0)) {
        return Err(KERNEL);
    }
    Ok(())
}

/// The caller (its effective ids, groups, capabilities, namespace and root).
pub fn caller(c: &LxCall) -> Result<Ctx, i64> {
    let w = walker(c)?;
    Ok(Ctx::from_call(c, root_in(&w.view, c)?))
}

/// Where a relative `path` of call `c` starts: its directory descriptor (`at_*`) or the
/// working directory. A descriptor that is not a pool handle is the kernel's.
pub fn start(c: &LxCall, path: &[u8]) -> Result<Start, i64> {
    if path.first() == Some(&b'/') {
        return Ok(Start::Root);
    }
    let w = walker(c)?;
    let root = root_in(&w.view, c)?;
    match c.at_kind {
        LX_AT_CWD => Ok(Start::At(node_in(&w.view, root, c.cwd, c.cwd_mnt)?)),
        // (a file as the directory: the walk says ENOTDIR, as Linux does)
        LX_AT_FILE | LX_AT_DIR => Ok(Start::At(node_in(&w.view, root, c.at_ino, c.at_mnt)?)),
        _ => Err(KERNEL),
    }
}

/// The handle of a call on a descriptor (`at_*` with kind file or directory).
pub fn handle(c: &LxCall) -> Result<Node, i64> {
    match c.at_kind {
        LX_AT_FILE | LX_AT_DIR => {
            let w = walker(c)?;
            let root = root_in(&w.view, c)?;
            node_in(&w.view, root, c.at_ino, c.at_mnt)
        }
        _ => Err(KERNEL),
    }
}

/// The path at `ptr` as the kernel reads one for a path call ([`super::rules::check_path`]).
pub fn path(cx: &Cx, ptr: u64, empty_ok: bool) -> Result<Vec<u8>, i64> {
    let p = cx.user_cstr(ptr)?;
    super::rules::check_path(&p, empty_ok)?;
    Ok(p)
}

// wave9 GP2 begin: one copy of the caller's mount table for the whole call
/// A call's walker and caller, made once (`caller`, `start`, `find` and `mount_flags` each
/// take the table's copy again).
pub struct Call {
    /// The walker (the copy of the caller's table).
    pub w: Walker,
    /// The caller.
    pub who: Ctx,
}

/// The [`Call`] of `c`.
pub fn call(c: &LxCall) -> Result<Call, i64> {
    let w = walker(c)?;
    let who = Ctx::from_call(c, root_in(&w.view, c)?);
    Ok(Call { w, who })
}

impl Call {
    /// As [`start`], in this call's table.
    pub fn start(&self, c: &LxCall, path: &[u8]) -> Result<Start, i64> {
        if path.first() == Some(&b'/') {
            return Ok(Start::Root);
        }
        let v = &self.w.view;
        match c.at_kind {
            LX_AT_CWD => Ok(Start::At(node_in(v, self.who.root, c.cwd, c.cwd_mnt)?)),
            LX_AT_FILE | LX_AT_DIR => Ok(Start::At(node_in(v, self.who.root, c.at_ino, c.at_mnt)?)),
            _ => Err(KERNEL),
        }
    }

    /// As [`find`], in this call's table.
    pub fn find(&self, c: &LxCall, path: &[u8], follow: bool) -> Result<(Node, Attr), i64> {
        let start = self.start(c, path)?;
        match walk::walk(&self.w, &self.who, start, path, if follow { 0 } else { walk::NOFOLLOW })? {
            Walked::Found { node, attr } => Ok((node, attr)),
            Walked::Redirect(r) => Err(super::pseudo_redirect(&r)),
        }
    }

    /// As [`mount_flags`], in this call's table.
    pub fn mount_flags(&self, n: Node) -> Result<u32, i64> {
        if !self.w.view.walkable(n) {
            return Err(KERNEL);
        }
        Ok(self.w.view.flags(n.mnt))
    }

    /// As [`writable`], in this call's table.
    pub fn writable(&self, n: Node) -> Result<(), i64> {
        if self.mount_flags(n)? & kmounts::MS_RDONLY != 0 {
            return Err(EROFS);
        }
        Ok(())
    }
}
// wave9 GP2 end

/// Walks `path` of call `c` for `who`: the object and its attributes; a walk into a tree
/// another service (today: the kernel) serves is [`KERNEL`].
pub fn find(c: &LxCall, who: &Ctx, path: &[u8], follow: bool) -> Result<(Node, Attr), i64> {
    let start = start(c, path)?;
    match walk::walk(&walker(c)?, who, start, path, if follow { 0 } else { walk::NOFOLLOW })? {
        Walked::Found { node, attr } => Ok((node, attr)),
        // wave7 G7-4: `/proc` and `/sys` go to linux-server (the answer makes the redirect)
        Walked::Redirect(r) => Err(super::pseudo_redirect(&r)),
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

// wave9 G6b-3 begin
/// [`may_access`], then the access policies, which may only take rights away (the kernel's
/// `vfs::may_access`; not for user 0); `path`: the path the caller named (audit).
pub fn allowed(who: &Ctx, attr: &Attr, acl: Option<&[u8]>, uid: u32, gid: u32, want: u32, path: &[u8]) -> Result<bool, i64> {
    if !may_access(who, attr, acl, uid, gid, want) {
        return Ok(false);
    }
    if uid == 0 {
        return Ok(true);
    }
    crate::policy::abac(who, attr, want, false, path)
}
// wave9 G6b-3 end

/// The access ACL of `n` when its attributes say it may have one (an ACL that cannot be
/// read fails the call: the mode bits alone could allow what it denies — 7-1's a78655f).
pub fn acl_of(n: Node, attr: &Attr) -> Result<Option<Vec<u8>>, i64> {
    if attr.has_xattr {

        BE.acl(n)
    } else {
        Ok(None)
    }
}
