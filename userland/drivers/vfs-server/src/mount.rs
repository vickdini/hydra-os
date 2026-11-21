//! Mounts as the walk sees them. **7-3 owns this file after the merge** (mount tables,
//! namespaces, the mount API, `tmpfs`); the walk uses only the [`Mounts`] trait.
//!
//! The boot table ([`BootMounts`]) has no mounts of its own and the pseudo file systems the
//! Linux services serve as names directly under the caller's root: `proc` (the process
//! service), `sys` and `dev` (linux-server; the device service later). That is the kernel's
//! rule today: `/proc` means the caller's root's `proc`, whatever directory that is.

use crate::ctx::Node;
use crate::proto::{SvcId, LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_DEV, LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};

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

/// The boot table: no mounts; `proc`, `sys`, `dev` under every root when `pseudo`.
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
