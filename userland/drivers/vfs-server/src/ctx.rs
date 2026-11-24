//! Who is calling, and from where: the caller's identity as the permission checks need it,
//! its mount namespace and its root (`docs/vfs-design.md` section 6: every forwarded call
//! carries this, so vfs-server keeps no per-process state).

use crate::proto::{LxCall, LX_FS_ABAC, LX_GROUPS};

/// `CAP_DAC_OVERRIDE`: read, write and search anything; execute what has an `x` bit.
pub const CAP_DAC_OVERRIDE: u32 = 1;
/// `CAP_DAC_READ_SEARCH`: read files and search directories regardless of their modes.
pub const CAP_DAC_READ_SEARCH: u32 = 2;

/// An object of the file service: an object number within a mount (0: the root's own tree).
/// The pool root is named by its real object number, never by 0.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Node {
    /// The mount it lies in.
    pub mnt: u16,
    /// Its object number in the mount's back end.
    pub ino: u64,
}

impl Node {
    /// Object `ino` of mount `mnt`.
    pub const fn new(mnt: u16, ino: u64) -> Self {
        Self { mnt, ino }
    }
}

/// The caller of one call.
#[derive(Clone, Debug)]
pub struct Ctx {
    /// Effective (= file system) user id.
    pub uid: u32,
    /// Effective group id.
    pub gid: u32,
    /// Supplementary groups.
    pub groups: [u32; LX_GROUPS],
    /// How many of `groups` are used.
    pub ngroups: usize,
    /// Effective capabilities.
    pub caps: u64,
    /// Mount namespace (0: the initial one).
    pub ns: u32,
    /// The caller's root directory.
    pub root: Node,
    /// wave9 G6b-1: the calling process and thread (the events of its changes say who).
    pub pid: u32,
    /// See [`Ctx::pid`].
    pub tid: u32,
    // wave9 G6b-3 begin
    /// The forwarded call (its request id: the kernel's ABAC decisions are made for it).
    pub req: u64,
    /// The access policies apply to the caller (`LX_FS_ABAC`): objects with extended
    /// attributes are asked about (`crate::policy::abac`).
    pub abac: bool,
    // wave9 G6b-3 end
}

impl Ctx {
    /// A caller with these ids and no supplementary groups.
    pub fn new(uid: u32, gid: u32, caps: u64, root: Node) -> Self {
        Self { uid, gid, groups: [0; LX_GROUPS], ngroups: 0, caps, ns: 0, root, pid: 0, tid: 0, req: 0, abac: false }
    }

    /// The caller of forwarded call `c`, whose root is `root`.
    pub fn from_call(c: &LxCall, root: Node) -> Self {
        let n = (c.ngroups as usize).min(LX_GROUPS);
        let mut x = Self::new(c.euid, c.egid, c.caps, root);
        x.groups[..n].copy_from_slice(&c.groups[..n]);
        x.ngroups = n;
        x.ns = c.mnt_ns;
        x.pid = c.tgid as u32;
        x.tid = c.tid as u32;
        x.req = c.id; // wave9 G6b-3
        x.abac = c.fs_flags & LX_FS_ABAC != 0; // wave9 G6b-3
        x
    }

    /// Adds supplementary group `g`.
    pub fn with_group(mut self, g: u32) -> Self {
        if self.ngroups < LX_GROUPS {
            self.groups[self.ngroups] = g;
            self.ngroups += 1;
        }
        self
    }

    /// Whether `gid` is the caller's group or one of its supplementary groups.
    pub fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups[..self.ngroups].contains(&gid)
    }

    /// Whether the caller holds capability `cap` (a bit number), or is root (the kernel's
    /// rule: euid 0 passes the discretionary checks).
    pub fn has_cap(&self, cap: u32) -> bool {
        self.uid == 0 || (cap < 64 && self.caps & (1 << cap) != 0)
    }

    /// wave10 GV1: whether the caller's effective capability set holds `cap` (a bit
    /// number), whatever its user (the kernel's `caps.has`: a root that dropped it has not).
    pub fn cap(&self, cap: u32) -> bool {
        cap < 64 && self.caps & (1 << cap) != 0
    }
}
