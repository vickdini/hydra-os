//! # The path walk
//!
//! Turns a path into an object, the way Linux and the kernel's ZFS client do (the kernel's
//! rules: `zfs-server`'s `resolve_mnt`, `vfs::may_search`), one component at a time over a
//! [`Backend`] (zfs-server through vfs-server's caches; a fake one in the unit tests):
//!
//! - an absolute path starts at the caller's root, a relative one at its working directory or
//!   at the directory of an `*at` call;
//! - `..` never leaves the caller's root, and climbs out of a mounted root to the directory
//!   it covers before going up;
//! - symbolic links are followed in every component but the last, and in the last unless
//!   the call says not to (a trailing `/` always follows); 40 at most (`ELOOP`);
//! - every directory looked up in needs search (`x`) permission ([`crate::perm`]);
//! - entering a directory some mount covers continues in the mount's root; a mount another
//!   service serves (`/proc`, `/sys`, `/dev`, FUSE) ends the walk with a [`Redirect`]: the
//!   service, its object, and the rest of the path (where it starts in the path argument, or
//!   its text when symbolic links led there).

use alloc::vec::Vec;

use crate::ctx::{Ctx, Node, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH};
use crate::fs::fsproto::{Attr, EEXIST, EIO, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR};

/// Permission denied.
pub const EACCES: i64 = -13;
/// Stale handle: a node in a mount the caller's namespace does not have.
pub const ESTALE: i64 = -116;
use crate::fs::types::DnodeType;
use crate::perm::{self, MAY_EXEC};
use crate::proto::{SvcId, LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_DEV, LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};

/// Symbolic links followed in one walk at most (Linux `MAXSYMLINKS`).
pub const SYMLOOP_MAX: u32 = 40;
/// Longest path (with its NUL: `PATH_MAX`).
pub const PATH_MAX: usize = 4096;
/// Longest component (`NAME_MAX`).
pub const NAME_MAX: usize = 255;
/// Walk flag: do not follow a symbolic link in the last component.
pub const NOFOLLOW: u32 = 1;

// ----------------------------------------------------------------------
// Mounts as the walk sees them (7-3's `mount.rs` tables implement [`Mounts`])
// ----------------------------------------------------------------------

/// What a mount holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MountKind {
    /// A ZFS tree (a bind mount of the pool, a dataset).
    Zfs,
    /// A `tmpfs` (7-3), by its id.
    Tmpfs(u32),
    /// A file system another service serves (`/proc`, `/sys`, `/dev`, FUSE): the walk stops
    /// and answers "redirect to `svc`, object `obj`".
    Redirect {
        /// The serving service.
        svc: SvcId,
        /// Its object for the mount's root.
        obj: u64,
    },
    /// wave9 G6b-2: a FUSE connection of vfs-server's (its files: `crate::fuse`).
    Fuse,
}

/// One mount.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MountInfo {
    /// The mount it is mounted on (0: the root's own tree).
    pub parent: u16,
    /// The directory it covers (in `parent`).
    pub mountpoint: Node,
    /// Its root directory (`mnt` = this mount's index).
    pub root: Node,
    /// What it holds.
    pub kind: MountKind,
}

/// The mount tables, by mount namespace.
pub trait Mounts {
    /// The topmost mount covering directory `at` in namespace `ns`, if any.
    fn covering(&self, ns: u32, at: Node) -> Option<u16>;
    /// Mount `m` of namespace `ns`.
    fn mount(&self, ns: u32, m: u16) -> Option<MountInfo>;
    /// A file system another service serves under the name `name` directly below the
    /// caller's root: `(service, object)`.
    fn pseudo_at_root(&self, ns: u32, name: &[u8]) -> Option<(SvcId, u64)>;
}

/// The boot table (until 7-3's tables): no mounts; the pseudo file systems the Linux
/// services serve as names directly under the caller's root: `proc` (the process service),
/// `sys` and `dev` (linux-server) -- the kernel's rule today: `/proc` is the caller's root's
/// `proc`, whatever directory that is.
pub struct BootMounts {
    /// Whether the pseudo file systems are redirected.
    pub pseudo: bool,
}

impl Mounts for BootMounts {
    fn covering(&self, _ns: u32, _at: Node) -> Option<u16> {
        None
    }

    fn mount(&self, _ns: u32, _m: u16) -> Option<MountInfo> {
        None
    }

    fn pseudo_at_root(&self, _ns: u32, name: &[u8]) -> Option<(SvcId, u64)> {
        if !self.pseudo {
            return None;
        }
        match name {
            b"proc" => Some((LXS_PROC, LX_VFS_PSEUDO_PROC)),
            b"sys" => Some((LXS_LINUX, LX_VFS_PSEUDO_SYS)),
            b"dev" => Some((LXS_LINUX, LX_VFS_PSEUDO_DEV)),
            _ => None,
        }
    }
}

// ----------------------------------------------------------------------
// The back end
// ----------------------------------------------------------------------

/// What the walk asks of the file systems below it.
pub trait Backend {
    /// Object `name` in directory `dir` (in `dir`'s mount; `..` is its parent there).
    fn lookup(&self, dir: Node, name: &[u8]) -> Result<Node, i64>;
    /// The attributes of `n`.
    fn getattr(&self, n: Node) -> Result<Attr, i64>;
    /// The target of symbolic link `n`.
    fn readlink(&self, n: Node) -> Result<Vec<u8>, i64>;
    /// The access ACL of `n` (`system.posix_acl_access`), if it has one (an error when it
    /// cannot be read: the walk fails rather than decide by the mode bits, which an ACL may
    /// restrict).
    fn acl(&self, n: Node) -> Result<Option<Vec<u8>>, i64>;
    /// The mount tables.
    fn mounts(&self) -> &dyn Mounts;
}

/// Where a relative path starts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Start {
    /// At the caller's root.
    Root,
    /// At this directory (the working directory, or the directory of an `*at` call).
    At(Node),
}

/// A walk that ended in a mount another service serves.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Redirect {
    /// The serving service.
    pub svc: SvcId,
    /// Its object for the mount's root.
    pub obj: u64,
    /// Where the rest of the path starts in the path argument; `None`: symbolic links led
    /// here and the rest is [`Redirect::text`].
    pub tail: Option<u32>,
    /// The rest of the path when it is not a suffix of the argument (components joined by
    /// `/`; empty otherwise).
    pub text: Vec<u8>,
}

/// What a walk found.
#[derive(Clone, Debug)]
pub enum Walked {
    /// An object of the file service, and its attributes.
    Found {
        /// The object.
        node: Node,
        /// Its attributes.
        attr: Attr,
    },
    /// The path belongs to another service.
    Redirect(Redirect),
}

/// The directory a path's last component is in.
#[derive(Clone, Debug)]
pub struct Parent {
    /// The directory.
    pub dir: Node,
    /// Its attributes.
    pub dir_attr: Attr,
    /// The last component (may be `.` or `..`: the call decides what that means).
    pub name: Vec<u8>,
    /// The object of that name, if it exists (not followed, not crossed into a mount).
    pub child: Option<Node>,
}

/// What a parent walk found.
#[derive(Clone, Debug)]
pub enum ParentWalked {
    /// The directory and the last name.
    Found(Parent),
    /// The path belongs to another service.
    Redirect(Redirect),
}

/// A component still to walk, and where it starts in the path argument (`None`: it came
/// from a symbolic link).
type Seg = (Vec<u8>, Option<usize>);

/// The components of `path` (no empty ones), last first (a stack); `origin`: whether
/// `path` is the argument (offsets kept) or a link's target.
fn components(path: &[u8], origin: bool) -> Vec<Seg> {
    let mut v = Vec::new();
    let mut start = 0;
    for i in 0..=path.len() {
        if i == path.len() || path[i] == b'/' {
            let c = &path[start..i];
            if !c.is_empty() {
                v.push((c.to_vec(), origin.then_some(start)));
            }
            start = i + 1;
        }
    }
    v.reverse();
    v
}

/// The redirect to `(svc, obj)` with `pending` still to walk (a stack) in a path argument of
/// `len` bytes.
fn redirect(svc: SvcId, obj: u64, pending: &[Seg], len: usize, trailing: bool) -> Redirect {
    if pending.is_empty() {
        return Redirect { svc, obj, tail: Some(len as u32), text: Vec::new() };
    }
    if pending.iter().all(|s| s.1.is_some()) {
        // Untouched by links: the argument's own suffix
        return Redirect { svc, obj, tail: pending.last().and_then(|s| s.1).map(|o| o as u32), text: Vec::new() };
    }
    let mut text = Vec::new();
    for (i, s) in pending.iter().rev().enumerate() {
        if i > 0 {
            text.push(b'/');
        }
        text.extend_from_slice(&s.0);
    }
    // (a trailing `/` that came from a link's target: the other service must see it too)
    if trailing {
        text.push(b'/');
    }
    Redirect { svc, obj, tail: None, text }
}

/// Checks that `dir` is a directory the caller may search.
fn search(be: &dyn Backend, cx: &Ctx, dir: Node) -> Result<Attr, i64> {
    let a = be.getattr(dir)?;
    if !a.is_dir() {
        return Err(ENOTDIR);
    }
    if cx.has_cap(CAP_DAC_READ_SEARCH) || cx.has_cap(CAP_DAC_OVERRIDE) {
        return Ok(a);
    }
    let acl = if perm::needs_acl(cx, &a, MAY_EXEC) { be.acl(dir)? } else { None };
    if perm::may(cx, &a, acl.as_deref(), MAY_EXEC) {
        Ok(a)
    } else {
        Err(EACCES)
    }
}

/// `..` from `cur`.
fn up(be: &dyn Backend, cx: &Ctx, mut cur: Node) -> Result<Node, i64> {
    let m = be.mounts();
    for _ in 0..=u16::MAX as usize {
        if cur == cx.root {
            return Ok(cur);
        }
        // (mount 0 is asked too: after a pivot_root a table may put it under another —
        // wave7 G7-7)
        match m.mount(cx.ns, cur.mnt) {
            // The root of a mount with nothing below it (a namespace's root): `..` stays, as
            // at the top of Linux's tree
            Some(info) if info.root == cur && info.mountpoint == cur => return Ok(cur),
            Some(info) if info.root == cur => cur = info.mountpoint,
            Some(_) => return be.lookup(cur, b".."),
            // The own tree of mount 0
            None if cur.mnt == 0 => return be.lookup(cur, b".."),
            // A mount this namespace does not have (gone, or another namespace's): never
            // climb the tree below it (a bind mount's `..` would leave its root)
            None => return Err(ESTALE),
        }
    }
    Err(ELOOP)
}

/// Enters `n`: the root of the topmost mount covering it, if any (`Err((svc, obj))`: a
/// mount another service serves).
fn enter(be: &dyn Backend, cx: &Ctx, mut n: Node) -> Result<Result<Node, (SvcId, u64)>, i64> {
    let m = be.mounts();
    for _ in 0..64 {
        let Some(k) = m.covering(cx.ns, n) else { return Ok(Ok(n)) };
        let info = m.mount(cx.ns, k).ok_or(EIO)?;
        match info.kind {
            MountKind::Redirect { svc, obj } => return Ok(Err((svc, obj))),
            _ => n = info.root,
        }
    }
    Err(ELOOP)
}

/// Walks `path` for caller `cx` from `start` (for a relative path); `flags`: [`NOFOLLOW`].
///
/// # Errors
/// `ENOENT` (empty path, a missing component), `ENOTDIR`, `EACCES`, `ELOOP`,
/// `ENAMETOOLONG`, or the back end's error.
pub fn walk(be: &dyn Backend, cx: &Ctx, start: Start, path: &[u8], flags: u32) -> Result<Walked, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() >= PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    // A trailing `/`: the result must be a directory (a trailing `.` or `..` is a lookup in
    // it, which checks that already)
    let mut trailing = path.ends_with(b"/");
    let follow_last = flags & NOFOLLOW == 0 || trailing;
    let root = cx.root;
    let mut cur = match start {
        _ if path[0] == b'/' => root,
        Start::Root => root,
        Start::At(n) => n,
    };
    let mut pending = components(path, true);
    let mut links = 0u32;
    // The attributes of `cur`, when the last step looked them up
    let mut known: Option<(Node, Attr)> = None;
    while let Some((comp, _)) = pending.pop() {
        if comp.len() > NAME_MAX {
            return Err(ENAMETOOLONG);
        }
        // Every component, `.` and `..` too, needs search permission on the directory it is
        // looked up in (Linux's `may_lookup`)
        search(be, cx, cur)?;
        if comp == b"." {
            continue;
        }
        if comp == b".." {
            // `..` at the caller's root stays there, as `/` does (it does not enter a mount on
            // top of the root, as the kernel's walk — wave7 G7-7)
            if cur == root {
                continue;
            }
            let parent = up(be, cx, cur)?;
            // (`sub/..` back at the root is the root itself, as `/..` is: no entering a mount
            // on top of it — 7-7 review)
            if parent == root {
                cur = root;
                continue;
            }
            // (the parent may be covered by a mount made after the walk's start went below it)
            cur = match enter(be, cx, parent)? {
                Ok(n) => n,
                Err((svc, obj)) => return Ok(Walked::Redirect(redirect(svc, obj, &pending, path.len(), trailing))),
            };
            continue;
        }
        if cur == root {
            if let Some((svc, obj)) = be.mounts().pseudo_at_root(cx.ns, &comp) {
                // `/proc/..`: back out of the mount here, not in the other service
                if pending.last().is_some_and(|s| s.0 == b"..") {
                    pending.pop();
                    continue;
                }
                return Ok(Walked::Redirect(redirect(svc, obj, &pending, path.len(), trailing)));
            }
        }
        let next = be.lookup(cur, &comp)?;
        let is_last = pending.is_empty();
        let attr = be.getattr(next)?;
        if attr.kind() == DnodeType::Symlink && (!is_last || follow_last) {
            links += 1;
            if links > SYMLOOP_MAX {
                return Err(ELOOP);
            }
            let target = be.readlink(next)?;
            if target.is_empty() {
                return Err(ENOENT);
            }
            if target[0] == b'/' {
                cur = root;
            }
            // `link -> file/` as the last component: the result must be a directory
            if is_last && target.ends_with(b"/") {
                trailing = true;
            }
            pending.extend(components(&target, false));
            continue;
        }
        if !is_last && !attr.is_dir() {
            return Err(ENOTDIR);
        }
        match enter(be, cx, next)? {
            Ok(n) => {
                if n == next {
                    known = Some((n, attr));
                }
                cur = n;
            }
            Err((svc, obj)) => {
                // `mnt/..`: back out of the mount here (to the directory it is in)
                if pending.last().is_some_and(|s| s.0 == b"..") {
                    pending.pop();
                    continue;
                }
                return Ok(Walked::Redirect(redirect(svc, obj, &pending, path.len(), trailing)));
            }
        }
    }
    let attr = match known {
        Some((n, a)) if n == cur => a,
        _ => be.getattr(cur)?,
    };
    if trailing && !attr.is_dir() {
        return Err(ENOTDIR);
    }
    Ok(Walked::Found { node: cur, attr })
}

/// Walks to the directory `path`'s last component is in (for the calls that make, remove or
/// rename a name), and looks that name up.
///
/// # Errors
/// As [`walk`]; `EEXIST` for `/` (no last component).
pub fn walk_parent(be: &dyn Backend, cx: &Ctx, start: Start, path: &[u8]) -> Result<ParentWalked, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() >= PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    let trimmed = &path[..end];
    if trimmed == b"/" {
        return Err(EEXIST);
    }
    let (dir_walk, name_at) = match trimmed.iter().rposition(|&c| c == b'/') {
        Some(0) => (Some(&b"/"[..]), 1),
        Some(i) => (Some(&trimmed[..i]), i + 1),
        None => (None, 0),
    };
    let name = &trimmed[name_at..];
    if name.len() > NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    let (dir, dir_attr) = match dir_walk {
        Some(d) => match walk(be, cx, start, d, 0)? {
            Walked::Found { node, attr } => (node, attr),
            Walked::Redirect(mut r) => {
                // The rest of the path goes on with the last name
                match r.tail {
                    Some(t) if t as usize >= d.len() => r.tail = Some(name_at as u32),
                    Some(_) => {}
                    None => {
                        if !r.text.is_empty() && !r.text.ends_with(b"/") {
                            r.text.push(b'/');
                        }
                        r.text.extend_from_slice(name);
                        // (the argument's trailing `/` goes with the name: the other service
                        // checks that it is a directory — wave7 G7-7)
                        if end < path.len() {
                            r.text.push(b'/');
                        }
                    }
                }
                return Ok(ParentWalked::Redirect(r));
            }
        },
        None => {
            let n = match start {
                Start::Root => cx.root,
                Start::At(n) => n,
            };
            (n, be.getattr(n)?)
        }
    };
    if !dir_attr.is_dir() {
        return Err(ENOTDIR);
    }
    search(be, cx, dir)?;
    if dir == cx.root {
        if let Some((svc, obj)) = be.mounts().pseudo_at_root(cx.ns, name) {
            return Ok(ParentWalked::Redirect(Redirect { svc, obj, tail: Some(path.len() as u32), text: Vec::new() }));
        }
    }
    let child = if name == b"." || name == b".." {
        None
    } else {
        match be.lookup(dir, name) {
            Ok(n) => Some(n),
            Err(ENOENT) => None,
            Err(e) => return Err(e),
        }
    };
    Ok(ParentWalked::Found(Parent { dir, dir_attr, name: name.to_vec(), child }))
}
