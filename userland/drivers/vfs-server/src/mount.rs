//! # Mount tables and mount namespaces (vfs-server; wave 7, Group 7-3)
//!
//! The ring-3 file service's mount state: one [`MountNs`] table per mount namespace, held
//! together in [`MountTables`]. This is the logic of the kernel's `compat/linux/mount.rs`,
//! moved out of the kernel and cut loose from it: everything here is plain data and pure
//! functions on *located* arguments. Path walking, permission checks, descriptors and the
//! calls to zfs-server stay with the caller (the walk of Group 7-1, the calls of Group 7-2):
//!
//! - the caller resolves each path argument to a [`Loc`] (the path in the namespace, the
//!   object it names, the mount it is in) and calls the operation here;
//! - each operation answers with what changed and what the caller must do outside the
//!   tables ([`Effects`]: pool objects to hold or let go at mount roots, `tmpfs` instances
//!   no namespace mounts any more; [`Pivot`]: the process roots to move).
//!
//! ## Mounts, back ends and the walk
//!
//! A mount shows a tree of one back end ([`Backend`]): the ZFS pool (through zfs-server), a
//! `tmpfs` instance of this server ([`super::tmpfs`]), or a file system **served by another
//! service** (`/proc`, `/sys`, `/dev`, `devpts`, `cgroup2`, `mqueue`: linux-server, decision
//! 19). Mounts of a served file system are where the walk answers with a redirect
//! ([`MountNs::redirect`]): the serving endpoint and the path inside its tree.
//!
//! The walk (Group 7-1) uses three questions:
//! - [`MountNs::child_at`]: is object `ino` of mount `m` a mount point? Ask again on the
//!   mount's root (mounts stack);
//! - [`MountNs::up`]: `..` at a mount's root leaves to the parent mount's mount point (then
//!   takes `..` there), unless it is the caller's root;
//! - [`MountNs::by_name`]: Hydra's initial namespace serves `/proc`, `/sys`, `/dev` and
//!   `/dev/pts` *by name*, at those paths from the caller's root (as the kernel does today,
//!   so `chroot /ubuntu` sees them too). Such mounts have `by_name` set and no mount point
//!   object; a namespace made from it turns them into ordinary mounts at the objects there.
//!
//! Mounts are named by their **index** in their namespace's table (1-based; slots are never
//! reused, so an index stays valid while the mount lives), as the kernel's descriptor table
//! names them today (`root_mnt`, `cwd_mnt`). A copied namespace keeps the indices, so a
//! process's root and working directory need no renaming when it unshares.
//!
//! ## Kept state
//!
//! Group 7-6 keeps the tables across a vfs-server restart (decision 21):
//! [`MountTables::encode`] writes everything into a byte string with a version and a
//! checksum, [`MountTables::decode`] checks and reads it back. No pointers, no handles of
//! this instance: indices, object numbers, endpoints and strings only.
//!
//! Not here (yet): propagation between namespaces (flags are kept and listed, nothing
//! propagates, as in the kernel copy), id-mapped mounts, overlayfs.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const E2BIG: i64 = -7;
pub const EBADF: i64 = -9;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EINVAL: i64 = -22;
pub const EROFS: i64 = -30;
pub const EOVERFLOW: i64 = -75;
pub const EOPNOTSUPP: i64 = -95;

pub const MS_RDONLY: u64 = 1;
pub const MS_NOSUID: u64 = 2;
pub const MS_NODEV: u64 = 4;
pub const MS_NOEXEC: u64 = 8;
pub const MS_REMOUNT: u64 = 32;
pub const MS_NOSYMFOLLOW: u64 = 256;
pub const MS_NOATIME: u64 = 1024;
pub const MS_NODIRATIME: u64 = 2048;
pub const MS_BIND: u64 = 4096;
pub const MS_MOVE: u64 = 8192;
pub const MS_REC: u64 = 16384;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
pub const MS_RELATIME: u64 = 1 << 21;
/// The flags kept per mount.
pub const PER_MOUNT: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW | MS_NOATIME | MS_NODIRATIME | MS_RELATIME;
pub const PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

pub const MNT_FORCE: u64 = 1;
pub const MNT_DETACH: u64 = 2;
pub const MNT_EXPIRE: u64 = 4;
pub const UMOUNT_NOFOLLOW: u64 = 8;

/// `CAP_SYS_CHROOT`.
pub const CAP_SYS_CHROOT: u64 = 1 << 18;
/// `CAP_SYS_ADMIN`, needed in the caller's user namespace to change mounts.
pub const CAP_SYS_ADMIN: u64 = 1 << 21;

/// A mount namespace id (the kernel's `Ns::mnt`; 0 is the initial namespace).
pub type NsId = u64;
/// A mount's index in its namespace's table, 1-based (0: none).
pub type MntIdx = usize;

/// The back end whose tree a mount shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backend {
    /// The ZFS pool (zfs-server's object numbers).
    Pool,
    /// A `tmpfs` instance of this server ([`super::tmpfs::Tmpfs`]).
    Tmpfs(u32),
    /// A file system served by another service: lookups below the mount are redirected to
    /// `endpoint`, with the mount's `fs_root` joined to the rest of the path.
    Remote { endpoint: u32 },
}

/// One mount.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mount {
    /// Mount ID (`mountinfo`; the unique ID of `statmount` is this plus 2^32).
    pub id: u32,
    /// Index of the parent mount (0: none, the namespace root).
    pub parent: MntIdx,
    /// The object mounted on, in the parent mount's back end (0 for the root and for
    /// mounts served by name).
    pub mountpoint: u64,
    /// Served by name at `path` from the caller's root (Hydra's initial namespace).
    pub by_name: bool,
    pub backend: Backend,
    /// The root object in the back end (0 for a served file system).
    pub root: u64,
    /// The mount's root inside its file system (`mountinfo`'s fourth field: `/`, or a bind
    /// mount's source directory). For a served file system it is also the path the
    /// redirect starts at.
    pub fs_root: String,
    /// The superblock number (`mountinfo`'s `0:N`); bind mounts share their source's.
    pub dev: u32,
    /// Per-mount `MS_*` flags ([`PER_MOUNT`]).
    pub flags: u64,
    /// Propagation flags ([`PROPAGATION`]): kept and listed, never acted on.
    pub propagation: u64,
    pub fstype: String,
    pub source: String,
    /// The file system's own options (`mountinfo`'s last field, after `rw`/`ro`).
    pub sb_opts: String,
    /// The mount point path in the namespace (from its root).
    pub path: String,
}

/// A resolved path argument: the path in the namespace's view (normalized, absolute), the
/// object it names and the mount it is in. For a mount point that does not resolve (a
/// mount served by name), `ino` and `mnt` are 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loc {
    pub path: String,
    pub ino: u64,
    pub mnt: MntIdx,
    pub is_dir: bool,
}

impl Loc {
    pub fn new(path: &str, ino: u64, mnt: MntIdx, is_dir: bool) -> Loc {
        Loc { path: normalize(path), ino, mnt, is_dir }
    }
}

/// What the caller must do outside the tables after a change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// Pool objects now at the root of a mount: hold them (`open_ref`), so a mounted file
    /// lives while mounted even when deleted (bubblewrap binds such files).
    pub hold: Vec<u64>,
    /// Pool objects no longer at the root of a mount: let them go (`release`).
    pub release: Vec<u64>,
    /// `tmpfs` instances no namespace mounts any more: drop them once no file of theirs is
    /// open.
    pub tmpfs_gone: Vec<u32>,
}

impl Effects {
    fn merge(&mut self, o: Effects) {
        self.hold.extend(o.hold);
        self.release.extend(o.release);
        self.tmpfs_gone.extend(o.tmpfs_gone);
    }
}

/// `pivot_root`'s answer: every process of the namespace whose root (or working directory)
/// is `old_root` moves to `new_root`; both are `(mount, object)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pivot {
    pub old_root: (MntIdx, u64),
    pub new_root: (MntIdx, u64),
}

/// Where a lookup goes after reaching a mount of a served file system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub endpoint: u32,
    /// The mount (for the `..` that leaves it again).
    pub mnt: MntIdx,
    /// The path inside the serving service's tree (absolute).
    pub path: String,
}

/// Makes new file systems for [`MountTables::mount_new`]: the caller's part of a mount
/// (the `tmpfs` instances live in the server, the served types are another service's).
pub trait FsFactory {
    /// A new `tmpfs` instance from the mount data (`size=`, `mode=`, ...), owned by the
    /// caller `(euid, egid)` unless the data says otherwise: `(instance, root object)`.
    fn new_tmpfs(&mut self, data: &str, euid: u32, egid: u32) -> Result<(u32, u64), i64>;
    /// The service serving file system type `fstype`, and the path in its tree a new mount
    /// of it shows (`None`: no service serves it).
    fn served(&self, fstype: &str) -> Option<(u32, String)>;
}

/// Who asks: the caller's mount namespace and effective capabilities and ids.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    pub ns: NsId,
    pub caps: u64,
    pub euid: u32,
    pub egid: u32,
}

/// File system types `mount` and `fsopen` know.
pub fn known_fs(fs: &str) -> bool {
    matches!(
        fs,
        "tmpfs" | "ramfs" | "sysfs" | "devtmpfs" | "proc" | "devpts" | "cgroup2" | "cgroup" | "mqueue" | "binfmt_misc" | "debugfs" | "tracefs" | "securityfs" | "pstore" | "bpf" | "fusectl" | "configfs"
    )
}

/// The superblock magic of a file system type (`statfs`'s `f_type`, `statmount`).
pub fn fs_magic(fstype: &str) -> u64 {
    match fstype {
        "zfs" => 0x2fc1_2fc1,
        "proc" => 0x9fa0,
        "sysfs" => 0x6265_6572,
        "tmpfs" | "devtmpfs" | "ramfs" => 0x0102_1994,
        "devpts" => 0x1cd1,
        "cgroup2" => 0x6367_7270,
        "mqueue" => 0x1980_2202,
        _ => 0,
    }
}

/// Normalizes an absolute path lexically (`.`, `..`, repeated `/`).
pub fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() { String::from("/") } else { format!("/{}", parts.join("/")) }
}

/// `path` below `prefix` (or `prefix` itself) rewritten under `to`; `None` if it is not
/// below `prefix`.
pub fn rebase(path: &str, prefix: &str, to: &str) -> Option<String> {
    let rest = if prefix == "/" {
        path.trim_start_matches('/')
    } else if path == prefix {
        ""
    } else {
        path.strip_prefix(prefix)?.strip_prefix('/')?
    };
    Some(normalize(&format!("{}/{}", to, rest)))
}

/// Whether the caller may change mounts: `CAP_SYS_ADMIN`, and not in the initial namespace
/// while its layout is fixed.
pub fn may_admin(c: &Caller, ns0_fixed: bool) -> Result<(), i64> {
    if c.caps & CAP_SYS_ADMIN == 0 {
        return Err(EPERM);
    }
    if c.ns == 0 && ns0_fixed {
        return Err(EPERM);
    }
    Ok(())
}

/// `chroot(2)`'s checks on the resolved directory (the kernel then sets the process root
/// handle): `CAP_SYS_CHROOT`, and a directory.
pub fn chroot_check(caps: u64, target: &Loc) -> Result<(), i64> {
    if caps & CAP_SYS_CHROOT == 0 {
        return Err(EPERM);
    }
    if !target.is_dir {
        return Err(ENOTDIR);
    }
    Ok(())
}

/// A mount namespace's table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountNs {
    /// Index = mount index - 1; `None` for an unmounted slot (never reused).
    pub mounts: Vec<Option<Mount>>,
    /// The root mount.
    pub root: MntIdx,
}

impl MountNs {
    /// Mount `i`.
    pub fn get(&self, i: MntIdx) -> Option<&Mount> {
        self.mounts.get(i.wrapping_sub(1)).and_then(|m| m.as_ref())
    }

    fn get_mut(&mut self, i: MntIdx) -> Option<&mut Mount> {
        self.mounts.get_mut(i.wrapping_sub(1)).and_then(|m| m.as_mut())
    }

    fn push(&mut self, m: Mount) -> MntIdx {
        self.mounts.push(Some(m));
        self.mounts.len()
    }

    /// The live mounts with their indices, in table order.
    pub fn live(&self) -> impl Iterator<Item = (MntIdx, &Mount)> {
        self.mounts.iter().enumerate().filter_map(|(i, m)| m.as_ref().map(|m| (i + 1, m)))
    }

    /// Number of live mounts.
    pub fn len(&self) -> usize {
        self.live().count()
    }

    /// Indices of `i` and every mount below it (`i` first).
    pub fn subtree(&self, i: MntIdx) -> Vec<MntIdx> {
        let mut out = vec![i];
        let mut k = 0;
        while k < out.len() {
            let p = out[k];
            for (j, m) in self.live() {
                if m.parent == p && j != p && !out.contains(&j) {
                    out.push(j);
                }
            }
            k += 1;
        }
        out
    }

    /// The mount on object `ino` of mount `parent`, if `ino` is a mount point there (the
    /// latest one when several were mounted on it). The walk asks again on the found
    /// mount's root, since mounts stack.
    pub fn child_at(&self, parent: MntIdx, ino: u64) -> Option<MntIdx> {
        self.live().filter(|(_, m)| !m.by_name && m.parent == parent && m.mountpoint == ino && parent != 0).map(|(i, _)| i).last()
    }

    /// `..` at the root of mount `i`: the parent mount and the object mounted on (`None` at
    /// the namespace root or for a mount served by name).
    pub fn up(&self, i: MntIdx) -> Option<(MntIdx, u64)> {
        let m = self.get(i)?;
        if i == self.root || m.parent == 0 || m.by_name {
            return None;
        }
        Some((m.parent, m.mountpoint))
    }

    /// The deepest mount served by name at or above `abs` (a path from the caller's root),
    /// and the rest of the path below it. Mounts on objects are found by the walk instead.
    pub fn by_name(&self, abs: &str) -> Option<(MntIdx, String)> {
        let abs = normalize(abs);
        self.live()
            .filter(|(_, m)| m.by_name)
            .filter_map(|(i, m)| rebase(&abs, &m.path, "/").map(|rest| (i, m.path.len(), rest)))
            .max_by_key(|(i, len, _)| (*len, *i))
            .map(|(i, _, rest)| (i, rest))
    }

    /// Where a lookup of `rest` (relative to the root of mount `i`) goes, when `i` is a
    /// mount of a file system served by another service.
    pub fn redirect(&self, i: MntIdx, rest: &str) -> Option<Redirect> {
        let m = self.get(i)?;
        let Backend::Remote { endpoint } = m.backend else { return None };
        Some(Redirect { endpoint, mnt: i, path: normalize(&format!("{}/{}", m.fs_root, rest)) })
    }

    /// The per-mount flags of mount `i` (0 if none).
    pub fn flags_of(&self, i: MntIdx) -> u64 {
        self.get(i).map_or(0, |m| m.flags)
    }

    /// `0`, or `EROFS` when mount `i` is read-only (checked by every change after the walk).
    pub fn check_write(&self, i: MntIdx) -> i64 {
        if self.flags_of(i) & MS_RDONLY != 0 { EROFS } else { 0 }
    }

    /// `(noexec, nosuid)` of mount `i` (for `execve`).
    pub fn exec_flags(&self, i: MntIdx) -> (bool, bool) {
        let f = self.flags_of(i);
        (f & MS_NOEXEC != 0, f & MS_NOSUID != 0)
    }

    /// Whether mount `i` shows a `tmpfs` (for `statfs`).
    pub fn is_tmpfs(&self, i: MntIdx) -> bool {
        matches!(self.get(i).map(|m| m.backend), Some(Backend::Tmpfs(_)))
    }

    /// The mount whose mount point `loc` is: a mount on an object by its root, one served
    /// by name by its path.
    pub fn mount_at(&self, loc: &Loc) -> Option<MntIdx> {
        if let Some(m) = self.get(loc.mnt) {
            let remote = matches!(m.backend, Backend::Remote { .. });
            if (!remote && m.root == loc.ino && loc.ino != 0) || (remote && m.path == loc.path) {
                return Some(loc.mnt);
            }
        }
        // Mounts the walk does not enter by object: served by name or by another service
        self.live().filter(|(_, m)| (m.by_name || matches!(m.backend, Backend::Remote { .. })) && m.path == loc.path).map(|(i, _)| i).last()
    }

    /// The `tmpfs` instances this table mounts.
    fn tmpfs_ids(&self) -> Vec<u32> {
        self.live().filter_map(|(_, m)| if let Backend::Tmpfs(t) = m.backend { Some(t) } else { None }).collect()
    }

    /// The pool objects at the roots of this table's mounts.
    fn pool_roots(&self) -> Vec<u64> {
        self.live().filter(|(_, m)| m.backend == Backend::Pool && m.root != 0).map(|(_, m)| m.root).collect()
    }

    /// The deepest live mount whose path is at or above `path` (for parents of new mounts).
    fn deepest_at(&self, path: &str) -> MntIdx {
        self.live().filter(|(_, m)| rebase(path, &m.path, "/").is_some()).max_by_key(|(i, m)| (m.path.len(), *i)).map_or(0, |(i, _)| i)
    }
}

/// A mount of an initial table ([`MountTables::install`]).
#[derive(Clone, Debug)]
pub struct InitialMount {
    pub path: String,
    /// The object at `path` in the pool (0: serve it by name).
    pub mountpoint: u64,
    pub backend: Backend,
    pub root: u64,
    pub fs_root: String,
    pub fstype: String,
    pub source: String,
    pub flags: u64,
}

/// Hydra's standard layout: `/proc`, `/sys`, `/sys/fs/cgroup`, `/dev` and `/dev/pts` served
/// by `linux_ep` (linux-server; Group 7-4 serves them), and `/run` listed as a `tmpfs`
/// that shows the pool's directory (as the kernel lists it today). `lookup` gives the
/// pool object at a path (0 if none); with `by_name` the served ones are mounted by name
/// (the initial namespace), else on those objects.
pub fn standard_layout(linux_ep: u32, by_name: bool, lookup: &dyn Fn(&str) -> u64) -> Vec<InitialMount> {
    let mut out = Vec::new();
    for (path, fstype, source, fs_root) in [
        ("/proc", "proc", "proc", "/"),
        ("/sys", "sysfs", "sysfs", "/"),
        ("/sys/fs/cgroup", "cgroup2", "cgroup2", "/fs/cgroup"),
        ("/dev", "devtmpfs", "udev", "/"),
        ("/dev/pts", "devpts", "devpts", "/pts"),
    ] {
        out.push(InitialMount {
            path: String::from(path),
            mountpoint: if by_name { 0 } else { lookup(path) },
            backend: Backend::Remote { endpoint: linux_ep },
            root: 0,
            fs_root: String::from(fs_root),
            fstype: String::from(fstype),
            source: String::from(source),
            flags: MS_NOSUID | MS_NOEXEC | MS_RELATIME,
        });
    }
    let run = lookup("/run");
    if run != 0 {
        out.push(InitialMount {
            path: String::from("/run"),
            mountpoint: run,
            backend: Backend::Pool,
            root: run,
            fs_root: String::from("/run"),
            fstype: String::from("tmpfs"),
            source: String::from("tmpfs"),
            flags: MS_NOSUID | MS_NODEV | MS_RELATIME,
        });
    }
    out
}

/// Every mount namespace's table, and the counters that number mounts and superblocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountTables {
    pub spaces: BTreeMap<NsId, MountNs>,
    next_id: u32,
    next_dev: u32,
    /// The initial namespace's layout cannot be changed (the kernel's rule until now).
    pub ns0_fixed: bool,
}

impl Default for MountTables {
    fn default() -> Self {
        Self::new()
    }
}

/// The mount object of a served file system type: `(backend, root, fs_root, dev)`.
type Made = (Backend, u64, String, u32);

impl MountTables {
    pub fn new() -> MountTables {
        MountTables { spaces: BTreeMap::new(), next_id: 100, next_dev: 1, ns0_fixed: true }
    }

    fn new_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn new_dev(&mut self) -> u32 {
        let d = self.next_dev;
        self.next_dev += 1;
        d
    }

    /// Namespace `ns`'s table.
    pub fn ns(&self, ns: NsId) -> Option<&MountNs> {
        self.spaces.get(&ns)
    }

    fn ns_mut(&mut self, ns: NsId) -> Result<&mut MountNs, i64> {
        self.spaces.get_mut(&ns).ok_or(EINVAL)
    }

    /// Makes namespace `ns`'s table: the pool's `root` at `/`, then `extra` (parents found
    /// by path). Replaces a table that was there.
    pub fn install(&mut self, ns: NsId, root: u64, extra: &[InitialMount]) -> Effects {
        let mut t = MountNs { mounts: Vec::new(), root: 1 };
        let pool_dev = self.new_dev();
        let id = self.new_id();
        t.push(Mount {
            id,
            parent: 0,
            mountpoint: 0,
            by_name: false,
            backend: Backend::Pool,
            root,
            fs_root: String::from("/"),
            dev: pool_dev,
            flags: MS_RELATIME,
            propagation: MS_SHARED,
            fstype: String::from("zfs"),
            source: String::from("hydrapool/root"),
            sb_opts: String::new(),
            path: String::from("/"),
        });
        for m in extra {
            let path = normalize(&m.path);
            let parent = t.deepest_at(&path);
            let dev = if m.backend == Backend::Pool && m.fstype == "zfs" { pool_dev } else { self.new_dev() };
            let id = self.new_id();
            t.push(Mount {
                id,
                parent,
                mountpoint: m.mountpoint,
                by_name: m.mountpoint == 0,
                backend: m.backend,
                root: m.root,
                fs_root: normalize(&m.fs_root),
                dev,
                flags: m.flags & PER_MOUNT,
                propagation: MS_SHARED,
                fstype: m.fstype.clone(),
                source: m.source.clone(),
                sb_opts: String::new(),
                path,
            });
        }
        let mut fx = Effects { hold: t.pool_roots(), ..Effects::default() };
        if let Some(old) = self.spaces.insert(ns, t) {
            fx.merge(self.forget(old));
        }
        fx
    }

    /// The effects of a table going away (its roots let go, `tmpfs` instances no other
    /// table mounts).
    fn forget(&self, t: MountNs) -> Effects {
        let mut fx = Effects { release: t.pool_roots(), ..Effects::default() };
        let mut ids = t.tmpfs_ids();
        ids.sort_unstable();
        ids.dedup();
        fx.tmpfs_gone = ids.into_iter().filter(|n| !self.tmpfs_in_use(*n)).collect();
        fx
    }

    /// Whether any namespace mounts `tmpfs` instance `n`.
    pub fn tmpfs_in_use(&self, n: u32) -> bool {
        self.spaces.values().any(|t| t.live().any(|(_, m)| m.backend == Backend::Tmpfs(n)))
    }

    /// Gives new namespace `new` (`unshare`/`clone` with `CLONE_NEWNS`) a copy of `from`'s
    /// table, with new mount IDs and the same indices. Mounts served by name (the initial
    /// namespace's) become mounts on the objects `lookup` finds at their paths in the copy
    /// (kept by name where it finds none).
    pub fn copy_ns(&mut self, from: NsId, new: NsId, lookup: &dyn Fn(&str) -> u64) -> Result<Effects, i64> {
        if self.spaces.contains_key(&new) {
            return Err(EBUSY);
        }
        let mut copy = self.spaces.get(&from).ok_or(EINVAL)?.clone();
        for m in copy.mounts.iter_mut().flatten() {
            m.id = self.next_id;
            self.next_id += 1;
            if m.by_name {
                let ino = lookup(&m.path);
                if ino != 0 {
                    m.by_name = false;
                    m.mountpoint = ino;
                }
            }
        }
        let fx = Effects { hold: copy.pool_roots(), ..Effects::default() };
        self.spaces.insert(new, copy);
        Ok(fx)
    }

    /// Drops the tables of namespaces not in `live` (no live process uses them; the initial
    /// one always stays).
    pub fn collect(&mut self, live: &[NsId]) -> Effects {
        let dead: Vec<NsId> = self.spaces.keys().copied().filter(|id| *id != 0 && !live.contains(id)).collect();
        let mut fx = Effects::default();
        let tables: Vec<MountNs> = dead.into_iter().filter_map(|id| self.spaces.remove(&id)).collect();
        for t in tables {
            fx.merge(self.forget(t));
        }
        fx
    }

    /// `mount(2)` on located arguments, by its flags: a propagation change, `MS_REMOUNT`,
    /// `MS_MOVE`, `MS_BIND` (with `MS_REC`), or a new file system of type `fs`. `src` is the
    /// located source of a bind or move (`None`: not given or not found).
    #[allow(clippy::too_many_arguments)]
    pub fn mount(&mut self, c: &Caller, src: Option<&Loc>, target: &Loc, fs: Option<&str>, source_name: Option<&str>, flags: u64, data: Option<&str>, f: &mut dyn FsFactory) -> Result<Effects, i64> {
        may_admin(c, self.ns0_fixed)?;
        if flags & PROPAGATION != 0 && flags & (MS_BIND | MS_MOVE | MS_REMOUNT) == 0 {
            self.set_propagation(c.ns, target, flags & PROPAGATION, flags & MS_REC != 0)?;
            return Ok(Effects::default());
        }
        if flags & MS_REMOUNT != 0 {
            let t = self.ns_mut(c.ns)?;
            let idx = t.mount_at(target).ok_or(EINVAL)?;
            if flags & MS_BIND != 0 {
                // Only the per-mount flags change
                t.get_mut(idx).ok_or(EINVAL)?.flags = flags & PER_MOUNT;
            } else {
                let m = t.get_mut(idx).ok_or(EINVAL)?;
                m.flags = flags & PER_MOUNT;
                if let Some(d) = data.filter(|d| !d.is_empty()) {
                    m.sb_opts = String::from(d);
                }
            }
            return Ok(Effects::default());
        }
        if flags & MS_MOVE != 0 {
            self.move_mount(c.ns, src.ok_or(EFAULT)?, target)?;
            return Ok(Effects::default());
        }
        if flags & MS_BIND != 0 {
            return self.bind(c.ns, src.ok_or(EFAULT)?, target, flags);
        }
        let fs = fs.ok_or(EFAULT)?;
        self.mount_new(c, target, fs, source_name.unwrap_or(fs), flags, data.unwrap_or(""), f).map(|(_, fx)| fx)
    }

    /// Sets propagation `prop` on the mount at `target` (and below it with `recursive`).
    pub fn set_propagation(&mut self, ns: NsId, target: &Loc, prop: u64, recursive: bool) -> Result<(), i64> {
        let t = self.ns_mut(ns)?;
        let at = t.mount_at(target).unwrap_or(target.mnt);
        let all = if recursive { t.subtree(at) } else { vec![at] };
        for i in all {
            if let Some(m) = t.get_mut(i) {
                m.propagation = prop;
            }
        }
        Ok(())
    }

    /// A new file system of type `fs` at `target` (a directory): `(new mount, effects)`.
    #[allow(clippy::too_many_arguments)]
    pub fn mount_new(&mut self, c: &Caller, target: &Loc, fs: &str, source: &str, flags: u64, data: &str, f: &mut dyn FsFactory) -> Result<(MntIdx, Effects), i64> {
        if !self.spaces.contains_key(&c.ns) {
            return Err(EINVAL);
        }
        if target.mnt != 0 && !target.is_dir {
            return Err(ENOTDIR);
        }
        let made: Made = match fs {
            "tmpfs" | "ramfs" => {
                let (n, root) = f.new_tmpfs(data, c.euid, c.egid)?;
                (Backend::Tmpfs(n), root, String::from("/"), self.new_dev())
            }
            _ if known_fs(fs) => match f.served(fs) {
                Some((endpoint, fs_root)) => (Backend::Remote { endpoint }, 0, fs_root, self.new_dev()),
                None => return Err(ENODEV),
            },
            _ => return Err(ENODEV),
        };
        let (backend, root, fs_root, dev) = made;
        let id = self.new_id();
        let t = self.ns_mut(c.ns)?;
        let parent = if target.mnt != 0 { target.mnt } else { t.deepest_at(&target.path) };
        let idx = t.push(Mount {
            id,
            parent,
            mountpoint: target.ino,
            by_name: target.ino == 0,
            backend,
            root,
            fs_root,
            dev,
            flags: flags & PER_MOUNT,
            propagation: 0,
            fstype: String::from(fs),
            source: String::from(source),
            sb_opts: String::from(data),
            path: target.path.clone(),
        });
        Ok((idx, Effects::default()))
    }

    /// `MS_BIND`: the tree at `src` also shows at `target` (with `MS_REC`, the mounts below
    /// `src` too, at the same places).
    pub fn bind(&mut self, ns: NsId, src: &Loc, target: &Loc, flags: u64) -> Result<Effects, i64> {
        if src.is_dir != target.is_dir {
            return Err(ENOTDIR);
        }
        let mut next_id = self.next_id;
        let t = self.ns_mut(ns)?;
        let s = t.get(src.mnt).cloned().ok_or(EINVAL)?;
        if s.propagation & MS_UNBINDABLE != 0 {
            return Err(EINVAL);
        }
        let rel = rebase(&src.path, &s.path, "/").unwrap_or_else(|| String::from("/"));
        let fs_root = normalize(&format!("{}/{}", s.fs_root, rel));
        // Binding a remote file system's file: the redirect starts at its path there
        let root = if matches!(s.backend, Backend::Remote { .. }) { 0 } else { src.ino };
        let parent = if target.mnt != 0 { target.mnt } else { t.deepest_at(&target.path) };
        let id = next_id;
        next_id += 1;
        let new = t.push(Mount {
            id,
            parent,
            mountpoint: target.ino,
            by_name: target.ino == 0,
            root,
            fs_root,
            propagation: 0,
            flags: flags & PER_MOUNT,
            path: target.path.clone(),
            ..s
        });
        let mut hold = Vec::new();
        if t.get(new).is_some_and(|m| m.backend == Backend::Pool && m.root != 0) {
            hold.push(root);
        }
        if flags & MS_REC != 0 {
            let below: Vec<MntIdx> = t.subtree(src.mnt).into_iter().filter(|i| *i != src.mnt && *i < new).collect();
            let mut map: BTreeMap<MntIdx, MntIdx> = BTreeMap::new();
            map.insert(src.mnt, new);
            for i in below {
                let Some(m) = t.get(i).cloned() else { continue };
                if m.propagation & MS_UNBINDABLE != 0 {
                    continue;
                }
                let (Some(&parent), Some(path)) = (map.get(&m.parent), rebase(&m.path, &src.path, &target.path)) else { continue };
                if m.backend == Backend::Pool && m.root != 0 {
                    hold.push(m.root);
                }
                let id = next_id;
                next_id += 1;
                let copy = t.push(Mount { id, parent, path, propagation: 0, ..m });
                map.insert(i, copy);
            }
        }
        self.next_id = next_id;
        Ok(Effects { hold, ..Effects::default() })
    }

    /// `MS_MOVE`: the mount at `src` (and what is below it) moves to `target`.
    pub fn move_mount(&mut self, ns: NsId, src: &Loc, target: &Loc) -> Result<(), i64> {
        let t = self.ns_mut(ns)?;
        let smnt = t.mount_at(src).ok_or(EINVAL)?;
        if smnt == t.root {
            return Err(EINVAL);
        }
        let moved = t.subtree(smnt);
        if moved.contains(&target.mnt) {
            return Err(EINVAL); // into itself
        }
        let spath = t.get(smnt).map(|m| m.path.clone()).ok_or(EINVAL)?;
        for i in moved {
            if let Some(m) = t.get_mut(i) {
                if let Some(p) = rebase(&m.path, &spath, &target.path) {
                    m.path = p;
                }
            }
        }
        let parent = if target.mnt != 0 { target.mnt } else { t.deepest_at(&target.path) };
        let m = t.get_mut(smnt).ok_or(EINVAL)?;
        m.mountpoint = target.ino;
        m.by_name = target.ino == 0;
        m.parent = parent;
        Ok(())
    }

    /// `umount2(2)` of the mount at `target`: with submounts only with `MNT_DETACH`.
    pub fn umount(&mut self, c: &Caller, target: &Loc, flags: u64) -> Result<Effects, i64> {
        may_admin(c, self.ns0_fixed)?;
        if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
            return Err(EINVAL);
        }
        let t = self.ns_mut(c.ns)?;
        let idx = t.mount_at(target).filter(|i| *i != t.root).ok_or(EINVAL)?;
        let gone = t.subtree(idx);
        if gone.len() > 1 && flags & MNT_DETACH == 0 {
            return Err(EBUSY);
        }
        let mut fx = Effects::default();
        let mut tmpfs = Vec::new();
        for i in gone {
            if let Some(m) = t.mounts[i - 1].take() {
                match m.backend {
                    Backend::Pool if m.root != 0 => fx.release.push(m.root),
                    Backend::Tmpfs(n) => tmpfs.push(n),
                    _ => {}
                }
            }
        }
        tmpfs.sort_unstable();
        tmpfs.dedup();
        fx.tmpfs_gone = tmpfs.into_iter().filter(|n| !self.tmpfs_in_use(*n)).collect();
        Ok(fx)
    }

    /// `pivot_root(2)`: the mount at `new_root` becomes the namespace's root and the old
    /// root moves to `put_old` (at or under `new_root`).
    pub fn pivot_root(&mut self, c: &Caller, new_root: &Loc, put_old: &Loc) -> Result<Pivot, i64> {
        may_admin(c, self.ns0_fixed)?;
        if !new_root.is_dir || !put_old.is_dir {
            return Err(ENOTDIR);
        }
        let t = self.ns_mut(c.ns)?;
        let old = t.root;
        let old_root = t.get(old).map(|m| m.root).ok_or(EINVAL)?;
        let nmnt = new_root.mnt;
        if t.get(nmnt).map_or(true, |m| m.root != new_root.ino) || nmnt == old {
            return Err(EINVAL); // new_root must be a mount, not the current root
        }
        let put_rel = rebase(&put_old.path, &new_root.path, "/").ok_or(EINVAL)?;
        // put_old must be reachable from new_root through the mounts below it
        let below = t.subtree(nmnt);
        if !below.contains(&put_old.mnt) {
            return Err(EINVAL);
        }
        let new_path = new_root.path.clone();
        for (i, slot) in t.mounts.iter_mut().enumerate() {
            let Some(m) = slot else { continue };
            if i + 1 == old {
                continue;
            }
            m.path = match rebase(&m.path, &new_path, "/") {
                Some(p) if below.contains(&(i + 1)) => p,
                _ => normalize(&format!("{}/{}", put_rel, m.path)),
            };
        }
        let m = t.get_mut(old).ok_or(EINVAL)?;
        m.mountpoint = put_old.ino;
        m.parent = put_old.mnt;
        m.path = put_rel;
        let n = t.get_mut(nmnt).ok_or(EINVAL)?;
        n.mountpoint = 0;
        n.parent = 0;
        n.path = String::from("/");
        t.root = nmnt;
        Ok(Pivot { old_root: (old, old_root), new_root: (nmnt, new_root.ino) })
    }

    /// Sets `set` and clears `clear` (per-mount `MS_*` flags), and sets propagation `prop`
    /// (if not 0), on the mount at `target` (and below it with `recursive`).
    pub fn set_attrs(&mut self, ns: NsId, target: &Loc, set: u64, clear: u64, recursive: bool, prop: u64) -> Result<(), i64> {
        let t = self.ns_mut(ns)?;
        let idx = t.mount_at(target).ok_or(EINVAL)?;
        let all = if recursive { t.subtree(idx) } else { vec![idx] };
        for i in all {
            if let Some(m) = t.get_mut(i) {
                m.flags = (m.flags & !clear) | set;
                if prop != 0 {
                    m.propagation = prop;
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Listings: /proc/<pid>/mountinfo, /proc/<pid>/mounts, listmount, statmount
    // ------------------------------------------------------------------

    /// `/proc/<pid>/mountinfo` of namespace `ns`.
    pub fn mountinfo(&self, ns: NsId) -> Option<String> {
        let t = self.ns(ns)?;
        let mut out = String::new();
        for (_, m) in t.live() {
            let parent = t.get(m.parent).map_or(m.id, |p| p.id);
            let prop = if m.propagation & MS_SHARED != 0 { format!(" shared:{}", m.dev) } else { String::new() };
            out.push_str(&format!("{} {} 0:{} {} {} {}{} - {} {} {}\n", m.id, parent, m.dev, m.fs_root, m.path, mount_opts(m.flags), prop, m.fstype, m.source, super_opts(m)));
        }
        Some(out)
    }

    /// `/proc/<pid>/mounts` (fstab format) of namespace `ns`.
    pub fn mounts(&self, ns: NsId) -> Option<String> {
        let t = self.ns(ns)?;
        let mut out = String::new();
        for (_, m) in t.live() {
            out.push_str(&format!("{} {} {} {} 0 0\n", m.source, m.path, m.fstype, super_opts(m)));
        }
        Some(out)
    }

    /// `listmount(2)`: the unique IDs of the mounts below unique ID `mnt_id` ([`LSMT_ROOT`]:
    /// every mount), after `last` (before it with `reverse`), at most `nr`.
    pub fn listmount(&self, ns: NsId, mnt_id: u64, last: u64, reverse: bool, nr: usize) -> Result<Vec<u64>, i64> {
        let t = self.ns(ns).ok_or(EINVAL)?;
        let mut found: Vec<u64> = if mnt_id == LSMT_ROOT {
            t.live().map(|(_, m)| UNIQUE_BASE + m.id as u64).collect()
        } else {
            let (pi, _) = t.live().find(|(_, m)| UNIQUE_BASE + m.id as u64 == mnt_id).ok_or(ENOENT)?;
            t.live().filter(|(i, m)| m.parent == pi && *i != pi).map(|(_, m)| UNIQUE_BASE + m.id as u64).collect()
        };
        found.sort_unstable();
        if reverse {
            found.reverse();
            if last != 0 {
                found.retain(|&i| i < last);
            }
        } else {
            found.retain(|&i| i > last);
        }
        found.truncate(nr.min(1_000_000));
        Ok(found)
    }

    /// `statmount(2)`: the answer buffer for unique ID `mnt_id` and request mask `mask`
    /// (`struct statmount` with its strings after it), or `EOVERFLOW` if longer than
    /// `bufsize`.
    pub fn statmount(&self, ns: NsId, mnt_id: u64, mask: u64, bufsize: usize) -> Result<Vec<u8>, i64> {
        let t = self.ns(ns).ok_or(EINVAL)?;
        let (_, m) = t.live().find(|(_, m)| UNIQUE_BASE + m.id as u64 == mnt_id).ok_or(ENOENT)?;
        let parent = t.get(m.parent).map_or(m.id, |p| p.id);
        let out = statmount_buf(m, parent, ns, mask);
        if bufsize < out.len() {
            return Err(EOVERFLOW);
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Kept state (Group 7-6)
    // ------------------------------------------------------------------

    /// Everything, as a sealed byte string (version and checksum) for the kept-state object.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        e.u32(self.next_id);
        e.u32(self.next_dev);
        e.u8(self.ns0_fixed as u8);
        e.u32(self.spaces.len() as u32);
        for (id, t) in &self.spaces {
            e.u64(*id);
            e.u64(t.root as u64);
            e.u32(t.mounts.len() as u32);
            for slot in &t.mounts {
                match slot {
                    None => e.u8(0),
                    Some(m) => {
                        e.u8(1);
                        encode_mount(&mut e, m);
                    }
                }
            }
        }
        seal(MOUNT_MAGIC, MOUNT_VERSION, &e.buf)
    }

    /// Reads back what [`Self::encode`] wrote: `EINVAL` if damaged or of another version
    /// (the caller then starts from the boot table).
    pub fn decode(b: &[u8]) -> Result<MountTables, i64> {
        let body = unseal(MOUNT_MAGIC, MOUNT_VERSION, b)?;
        let mut d = Dec::new(body);
        let next_id = d.u32()?;
        let next_dev = d.u32()?;
        let ns0_fixed = d.u8()? != 0;
        let n = d.u32()?;
        let mut spaces = BTreeMap::new();
        for _ in 0..n {
            let id = d.u64()?;
            let root = d.u64()? as usize;
            let count = d.u32()? as usize;
            if count > d.remaining() {
                return Err(EINVAL);
            }
            let mut mounts = Vec::with_capacity(count);
            for _ in 0..count {
                mounts.push(match d.u8()? {
                    0 => None,
                    1 => Some(decode_mount(&mut d)?),
                    _ => return Err(EINVAL),
                });
            }
            let t = MountNs { mounts, root };
            if t.get(root).is_none() {
                return Err(EINVAL);
            }
            spaces.insert(id, t);
        }
        if !d.done() {
            return Err(EINVAL);
        }
        Ok(MountTables { spaces, next_id, next_dev, ns0_fixed })
    }
}

/// `rw`/`ro` and the per-mount options, as `mountinfo` shows them.
pub fn mount_opts(flags: u64) -> String {
    let mut opts = String::from(if flags & MS_RDONLY != 0 { "ro" } else { "rw" });
    for (bit, name) in [(MS_NOSUID, "nosuid"), (MS_NODEV, "nodev"), (MS_NOEXEC, "noexec"), (MS_NOATIME, "noatime"), (MS_NODIRATIME, "nodiratime"), (MS_RELATIME, "relatime"), (MS_NOSYMFOLLOW, "nosymfollow")] {
        if flags & bit != 0 {
            opts.push(',');
            opts.push_str(name);
        }
    }
    opts
}

/// The superblock options (`rw`/`ro` and the file system's own).
fn super_opts(m: &Mount) -> String {
    let mut s = String::from(if m.flags & MS_RDONLY != 0 { "ro" } else { "rw" });
    if !m.sb_opts.is_empty() {
        s.push(',');
        s.push_str(&m.sb_opts);
    }
    s
}

/// `listmount`'s request for every mount.
pub const LSMT_ROOT: u64 = u64::MAX;
/// Unique (64-bit) mount IDs: the `mountinfo` ID above 2^32, as Linux numbers them apart.
pub const UNIQUE_BASE: u64 = 1 << 32;

pub const STATMOUNT_SB_BASIC: u64 = 1;
pub const STATMOUNT_MNT_BASIC: u64 = 2;
pub const STATMOUNT_PROPAGATE_FROM: u64 = 4;
pub const STATMOUNT_MNT_ROOT: u64 = 8;
pub const STATMOUNT_MNT_POINT: u64 = 0x10;
pub const STATMOUNT_FS_TYPE: u64 = 0x20;
pub const STATMOUNT_MNT_NS_ID: u64 = 0x40;
pub const STATMOUNT_MNT_OPTS: u64 = 0x80;
pub const STATMOUNT_SB_SOURCE: u64 = 0x200;

/// `struct statmount` for mount `m` (parent ID `parent`) and its strings.
fn statmount_buf(m: &Mount, parent: u32, ns: NsId, mask: u64) -> Vec<u8> {
    const HDR: usize = 512;
    let mut out = vec![0u8; HDR];
    let mut strings: Vec<u8> = Vec::new();
    let mut done = 0u64;
    let put_str = |strings: &mut Vec<u8>, s: &str| -> u32 {
        let at = strings.len() as u32;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        at
    };
    let p64 = |out: &mut [u8], o: usize, v: u64| out[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let p32 = |out: &mut [u8], o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_le_bytes());
    if mask & STATMOUNT_SB_BASIC != 0 {
        p32(&mut out, 16, 0);
        p32(&mut out, 20, m.dev);
        p64(&mut out, 24, fs_magic(&m.fstype));
        p32(&mut out, 32, if m.flags & MS_RDONLY != 0 { 1 } else { 0 }); // SB_RDONLY
        done |= STATMOUNT_SB_BASIC;
    }
    if mask & STATMOUNT_MNT_BASIC != 0 {
        p64(&mut out, 40, UNIQUE_BASE + m.id as u64);
        p64(&mut out, 48, UNIQUE_BASE + parent as u64);
        p32(&mut out, 56, m.id);
        p32(&mut out, 60, parent);
        p64(&mut out, 64, ms_to_attr(m.flags));
        let shared = m.propagation & MS_SHARED != 0;
        p64(&mut out, 72, if shared { MS_SHARED } else { MS_PRIVATE });
        p64(&mut out, 80, if shared { m.dev as u64 } else { 0 });
        done |= STATMOUNT_MNT_BASIC;
    }
    if mask & STATMOUNT_PROPAGATE_FROM != 0 {
        p64(&mut out, 96, 0);
        done |= STATMOUNT_PROPAGATE_FROM;
    }
    if mask & STATMOUNT_MNT_ROOT != 0 {
        let at = put_str(&mut strings, &m.fs_root);
        p32(&mut out, 104, at);
        done |= STATMOUNT_MNT_ROOT;
    }
    if mask & STATMOUNT_MNT_POINT != 0 {
        let at = put_str(&mut strings, &m.path);
        p32(&mut out, 108, at);
        done |= STATMOUNT_MNT_POINT;
    }
    if mask & STATMOUNT_FS_TYPE != 0 {
        let at = put_str(&mut strings, &m.fstype);
        p32(&mut out, 36, at);
        done |= STATMOUNT_FS_TYPE;
    }
    if mask & STATMOUNT_MNT_NS_ID != 0 {
        p64(&mut out, 112, ns);
        done |= STATMOUNT_MNT_NS_ID;
    }
    if mask & STATMOUNT_MNT_OPTS != 0 {
        let at = put_str(&mut strings, &m.sb_opts);
        p32(&mut out, 4, at);
        done |= STATMOUNT_MNT_OPTS;
    }
    if mask & STATMOUNT_SB_SOURCE != 0 {
        let at = put_str(&mut strings, &m.source);
        p32(&mut out, 124, at);
        done |= STATMOUNT_SB_SOURCE;
    }
    let total = HDR + strings.len();
    p32(&mut out, 0, total as u32);
    p64(&mut out, 8, done);
    out.extend_from_slice(&strings);
    out
}

// ----------------------------------------------------------------------
// The new mount API: fsopen, fsconfig, fsmount, open_tree, move_mount, fspick,
// mount_setattr (the objects behind their descriptors, and the argument rules)
// ----------------------------------------------------------------------

pub const FSOPEN_CLOEXEC: u64 = 1;
pub const FSCONFIG_SET_FLAG: u64 = 0;
pub const FSCONFIG_SET_STRING: u64 = 1;
pub const FSCONFIG_SET_BINARY: u64 = 2;
pub const FSCONFIG_SET_PATH: u64 = 3;
pub const FSCONFIG_SET_PATH_EMPTY: u64 = 4;
pub const FSCONFIG_SET_FD: u64 = 5;
pub const FSCONFIG_CMD_CREATE: u64 = 6;
pub const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
pub const FSCONFIG_CMD_CREATE_EXCL: u64 = 8;

pub const MOUNT_ATTR_RDONLY: u64 = 1;
pub const MOUNT_ATTR_NOSUID: u64 = 2;
pub const MOUNT_ATTR_NODEV: u64 = 4;
pub const MOUNT_ATTR_NOEXEC: u64 = 8;
pub const MOUNT_ATTR_ATIME: u64 = 0x70;
pub const MOUNT_ATTR_RELATIME: u64 = 0;
pub const MOUNT_ATTR_NOATIME: u64 = 0x10;
pub const MOUNT_ATTR_STRICTATIME: u64 = 0x20;
pub const MOUNT_ATTR_NODIRATIME: u64 = 0x80;
pub const MOUNT_ATTR_IDMAP: u64 = 0x10_0000;
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x20_0000;
pub const MOUNT_ATTR_ALL: u64 = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_IDMAP | MOUNT_ATTR_NOSYMFOLLOW;

/// `MOUNT_ATTR_*` as per-mount `MS_*` flags.
pub fn attr_to_ms(attr: u64) -> u64 {
    let mut f = 0;
    for (a, m) in [(MOUNT_ATTR_RDONLY, MS_RDONLY), (MOUNT_ATTR_NOSUID, MS_NOSUID), (MOUNT_ATTR_NODEV, MS_NODEV), (MOUNT_ATTR_NOEXEC, MS_NOEXEC), (MOUNT_ATTR_NODIRATIME, MS_NODIRATIME), (MOUNT_ATTR_NOSYMFOLLOW, MS_NOSYMFOLLOW)] {
        if attr & a != 0 {
            f |= m;
        }
    }
    match attr & MOUNT_ATTR_ATIME {
        MOUNT_ATTR_NOATIME => f |= MS_NOATIME,
        MOUNT_ATTR_STRICTATIME => {}
        _ => f |= MS_RELATIME,
    }
    f
}

/// Per-mount `MS_*` flags as `MOUNT_ATTR_*` (`statmount`'s `mnt_attr`).
pub fn ms_to_attr(ms: u64) -> u64 {
    let mut a = 0;
    for (m, at) in [(MS_RDONLY, MOUNT_ATTR_RDONLY), (MS_NOSUID, MOUNT_ATTR_NOSUID), (MS_NODEV, MOUNT_ATTR_NODEV), (MS_NOEXEC, MOUNT_ATTR_NOEXEC), (MS_NODIRATIME, MOUNT_ATTR_NODIRATIME), (MS_NOSYMFOLLOW, MOUNT_ATTR_NOSYMFOLLOW), (MS_NOATIME, MOUNT_ATTR_NOATIME)] {
        if ms & m != 0 {
            a |= at;
        }
    }
    if ms & (MS_NOATIME | MS_RELATIME) == 0 {
        a |= MOUNT_ATTR_STRICTATIME;
    }
    a
}

/// A file system context (`fsopen`, `fspick`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsCtx {
    pub fs: String,
    pub source: Option<String>,
    pub options: Vec<String>,
    /// `MS_RDONLY` from the "ro" flag.
    pub ro: bool,
    pub created: bool,
    pub mounted: bool,
    /// `fspick`: the mount being reconfigured (its path).
    pub reconfigure: Option<String>,
}

/// What a detached mount (`fsmount`, `open_tree` with `OPEN_TREE_CLONE`) will be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spec {
    New { fs: String, source: Option<String>, data: String },
    Clone { source: String, recursive: bool },
}

/// A mount object not (yet) attached anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detached {
    pub spec: Spec,
    /// Per-mount `MS_*` flags and propagation, applied when it is attached.
    pub flags: u64,
    pub propagation: u64,
    /// Where it was attached (then `move_mount` moves it).
    pub attached: Option<String>,
}

/// The objects behind the new API's descriptors (server objects of vfs-server).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountObj {
    Ctx(FsCtx),
    Mnt(Detached),
}

impl MountObj {
    /// The path `/proc/self/fd` shows.
    pub fn path(&self) -> String {
        match self {
            MountObj::Ctx(_) => String::from("anon_inode:[fscontext]"),
            MountObj::Mnt(m) => m.attached.clone().unwrap_or_else(|| String::from("/")),
        }
    }
}

/// `fsopen(fsname, flags)`: a new context (the caller checks [`may_admin`] first).
pub fn fsopen(fs: &str, flags: u64) -> Result<FsCtx, i64> {
    if flags & !FSOPEN_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    if !known_fs(fs) {
        return Err(ENODEV);
    }
    Ok(FsCtx { fs: String::from(fs), source: None, options: Vec::new(), ro: false, created: false, mounted: false, reconfigure: None })
}

/// `fspick`: a context for reconfiguring the mount at `target`.
pub fn fspick(t: &MountNs, target: &Loc) -> Result<FsCtx, i64> {
    let idx = t.mount_at(target).ok_or(EINVAL)?;
    let m = t.get(idx).ok_or(EINVAL)?;
    Ok(FsCtx { fs: m.fstype.clone(), source: Some(m.source.clone()), options: Vec::new(), ro: m.flags & MS_RDONLY != 0, created: true, mounted: false, reconfigure: Some(target.path.clone()) })
}

/// What an `fsconfig` asks the caller to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigOut {
    Done,
    /// `FSCONFIG_CMD_RECONFIGURE`: set or clear `MS_RDONLY` on the mount at `path`
    /// ([`MountTables::set_attrs`]).
    Reconfigure { path: String, ro: bool },
}

/// `fsconfig(fd, cmd, key, value, aux)` on a context; `key` and `value` are the strings
/// (already copied in; `None` for a null pointer).
pub fn fsconfig(c: &mut FsCtx, cmd: u64, key: Option<&str>, value: Option<&str>, aux: u64) -> Result<ConfigOut, i64> {
    match cmd {
        FSCONFIG_SET_FLAG => {
            let k = key.ok_or(EINVAL)?;
            if value.is_some() || aux != 0 {
                return Err(EINVAL);
            }
            match k {
                "ro" => c.ro = true,
                "rw" => c.ro = false,
                _ => c.options.push(String::from(k)),
            }
            Ok(ConfigOut::Done)
        }
        FSCONFIG_SET_STRING | FSCONFIG_SET_PATH | FSCONFIG_SET_PATH_EMPTY => {
            let k = key.ok_or(EINVAL)?;
            let v = value.ok_or(EINVAL)?;
            if cmd == FSCONFIG_SET_STRING && aux != 0 {
                return Err(EINVAL);
            }
            if k == "source" {
                if c.source.is_some() {
                    return Err(EINVAL);
                }
                c.source = Some(String::from(v));
            } else {
                c.options.push(format!("{}={}", k, v));
            }
            Ok(ConfigOut::Done)
        }
        FSCONFIG_SET_BINARY | FSCONFIG_SET_FD => Err(EINVAL),
        FSCONFIG_CMD_CREATE | FSCONFIG_CMD_CREATE_EXCL => {
            if key.is_some() || value.is_some() || aux != 0 {
                return Err(EINVAL);
            }
            if c.created || c.reconfigure.is_some() {
                return Err(EBUSY);
            }
            c.created = true;
            Ok(ConfigOut::Done)
        }
        FSCONFIG_CMD_RECONFIGURE => {
            let path = c.reconfigure.clone().ok_or(EINVAL)?;
            Ok(ConfigOut::Reconfigure { path, ro: c.ro })
        }
        _ => Err(EOPNOTSUPP),
    }
}

/// `fsmount(fs_fd, flags, attr_flags)`: the detached mount of a created context.
pub fn fsmount(c: &mut FsCtx, flags: u64, attr: u64) -> Result<Detached, i64> {
    if flags & !FSOPEN_CLOEXEC != 0 || attr & !MOUNT_ATTR_ALL != 0 || attr & MOUNT_ATTR_IDMAP != 0 {
        return Err(EINVAL);
    }
    if !c.created || c.reconfigure.is_some() {
        return Err(EINVAL);
    }
    if c.mounted {
        return Err(EBUSY);
    }
    c.mounted = true;
    let mut ms = attr_to_ms(attr);
    if c.ro {
        ms |= MS_RDONLY;
    }
    Ok(Detached { spec: Spec::New { fs: c.fs.clone(), source: c.source.clone(), data: c.options.join(",") }, flags: ms, propagation: 0, attached: None })
}

pub const OPEN_TREE_CLONE: u64 = 1;
pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
pub const AT_NO_AUTOMOUNT: u64 = 0x800;
pub const AT_EMPTY_PATH: u64 = 0x1000;
pub const AT_RECURSIVE: u64 = 0x8000;
pub const O_CLOEXEC: u64 = 0o2000000;

/// `open_tree`'s flag check: `Ok(true)` for a clone (a [`Detached`] of the located path,
/// [`open_tree_clone`]), `Ok(false)` for a plain `O_PATH` descriptor.
pub fn open_tree_flags(flags: u64) -> Result<bool, i64> {
    if flags & !(OPEN_TREE_CLONE | O_CLOEXEC | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW) != 0 {
        return Err(EINVAL);
    }
    if flags & AT_RECURSIVE != 0 && flags & OPEN_TREE_CLONE == 0 {
        return Err(EINVAL);
    }
    Ok(flags & OPEN_TREE_CLONE != 0)
}

/// `open_tree` with `OPEN_TREE_CLONE` of the located `source`.
pub fn open_tree_clone(source: &Loc, flags: u64) -> Detached {
    Detached { spec: Spec::Clone { source: source.path.clone(), recursive: flags & AT_RECURSIVE != 0 }, flags: 0, propagation: 0, attached: None }
}

pub const MOVE_MOUNT_F_SYMLINKS: u64 = 1;
pub const MOVE_MOUNT_F_AUTOMOUNTS: u64 = 2;
pub const MOVE_MOUNT_F_EMPTY_PATH: u64 = 4;
pub const MOVE_MOUNT_T_SYMLINKS: u64 = 0x10;
pub const MOVE_MOUNT_T_AUTOMOUNTS: u64 = 0x20;
pub const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;

/// `move_mount`'s flag check (`MOVE_MOUNT_SET_GROUP` and `_BENEATH` are not supported).
pub fn move_mount_flags(flags: u64) -> Result<(), i64> {
    let ok = MOVE_MOUNT_F_SYMLINKS | MOVE_MOUNT_F_AUTOMOUNTS | MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_SYMLINKS | MOVE_MOUNT_T_AUTOMOUNTS | MOVE_MOUNT_T_EMPTY_PATH;
    if flags & !ok != 0 { Err(EINVAL) } else { Ok(()) }
}

/// What attaching a detached mount at a target does, for the caller to carry out (it
/// resolves the source paths): a move of where it is attached, a new file system, or a
/// bind of the clone's source. Then [`MountTables::set_attrs`] with `flags` (for a clone)
/// and `propagation`, and [`Detached::attached`] = the target path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attach {
    Move { from: String },
    New { fs: String, source: Option<String>, data: String, flags: u64 },
    Bind { source: String, recursive: bool, flags: u64 },
}

impl Detached {
    /// What `move_mount` of this object does.
    pub fn attach(&self) -> Attach {
        match (&self.attached, &self.spec) {
            (Some(at), _) => Attach::Move { from: at.clone() },
            (None, Spec::New { fs, source, data }) => Attach::New { fs: fs.clone(), source: source.clone(), data: data.clone(), flags: self.flags },
            (None, Spec::Clone { source, recursive }) => Attach::Bind { source: source.clone(), recursive: *recursive, flags: self.flags },
        }
    }
}

/// `mount_setattr`'s `struct mount_attr` (`size` bytes, already copied in): the per-mount
/// flags to set and clear, and the propagation (0: unchanged).
pub fn parse_mount_attr(raw: &[u8], flags: u64) -> Result<(u64, u64, u64), i64> {
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return Err(EINVAL);
    }
    if raw.len() < 32 {
        return Err(EINVAL);
    }
    if raw.len() > 4096 {
        return Err(E2BIG);
    }
    if raw[32..].iter().any(|&b| b != 0) {
        return Err(E2BIG);
    }
    let field = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (attr_set, attr_clr, prop) = (field(0), field(1), field(2));
    if (attr_set | attr_clr) & !MOUNT_ATTR_ALL != 0 || (attr_set | attr_clr) & MOUNT_ATTR_IDMAP != 0 {
        return Err(EINVAL);
    }
    if prop != 0 && !matches!(prop, MS_PRIVATE | MS_SHARED | MS_SLAVE | MS_UNBINDABLE) {
        return Err(EINVAL);
    }
    // Setting an atime mode replaces the current one
    let mut set = attr_to_ms(attr_set & !MOUNT_ATTR_ATIME) & !MS_RELATIME;
    let mut clear = attr_to_ms(attr_clr & !MOUNT_ATTR_ATIME) & !MS_RELATIME;
    if (attr_set | attr_clr) & MOUNT_ATTR_ATIME != 0 {
        clear |= MS_NOATIME | MS_RELATIME;
        set |= attr_to_ms(attr_set & MOUNT_ATTR_ATIME) & (MS_NOATIME | MS_RELATIME);
    }
    Ok((set, clear, prop))
}

/// [`Detached`]: `mount_setattr` on a mount not yet attached (kept until it is).
pub fn setattr_detached(d: &mut Detached, set: u64, clear: u64, prop: u64) {
    d.flags = (d.flags & !clear) | set;
    if prop != 0 {
        d.propagation = prop;
    }
}

// ----------------------------------------------------------------------
// Byte strings for the kept state (shared with tmpfs.rs)
// ----------------------------------------------------------------------

const MOUNT_MAGIC: u32 = 0x4d4e_5433; // "MNT3"
const MOUNT_VERSION: u32 = 1;

fn encode_mount(e: &mut Enc, m: &Mount) {
    e.u32(m.id);
    e.u64(m.parent as u64);
    e.u64(m.mountpoint);
    e.u8(m.by_name as u8);
    match m.backend {
        Backend::Pool => e.u8(0),
        Backend::Tmpfs(n) => {
            e.u8(1);
            e.u32(n);
        }
        Backend::Remote { endpoint } => {
            e.u8(2);
            e.u32(endpoint);
        }
    }
    e.u64(m.root);
    e.str(&m.fs_root);
    e.u32(m.dev);
    e.u64(m.flags);
    e.u64(m.propagation);
    e.str(&m.fstype);
    e.str(&m.source);
    e.str(&m.sb_opts);
    e.str(&m.path);
}

fn decode_mount(d: &mut Dec) -> Result<Mount, i64> {
    let id = d.u32()?;
    let parent = d.u64()? as usize;
    let mountpoint = d.u64()?;
    let by_name = d.u8()? != 0;
    let backend = match d.u8()? {
        0 => Backend::Pool,
        1 => Backend::Tmpfs(d.u32()?),
        2 => Backend::Remote { endpoint: d.u32()? },
        _ => return Err(EINVAL),
    };
    Ok(Mount {
        id,
        parent,
        mountpoint,
        by_name,
        backend,
        root: d.u64()?,
        fs_root: d.str()?,
        dev: d.u32()?,
        flags: d.u64()?,
        propagation: d.u64()?,
        fstype: d.str()?,
        source: d.str()?,
        sb_opts: d.str()?,
        path: d.str()?,
    })
}

/// A little-endian byte writer.
#[derive(Default)]
pub struct Enc {
    pub buf: Vec<u8>,
}

impl Enc {
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }
    pub fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }
    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
}

/// The reader of [`Enc`]'s strings: every read checks the length (`EINVAL` when short).
pub struct Dec<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    pub fn new(b: &'a [u8]) -> Dec<'a> {
        Dec { b, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], i64> {
        let end = self.at.checked_add(n).ok_or(EINVAL)?;
        let s = self.b.get(self.at..end).ok_or(EINVAL)?;
        self.at = end;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, i64> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32, i64> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, i64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64, i64> {
        self.u64().map(|v| v as i64)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, i64> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn str(&mut self) -> Result<String, i64> {
        String::from_utf8(self.bytes()?).map_err(|_| EINVAL)
    }
    /// Bytes left (an upper bound for counts read from the input).
    pub fn remaining(&self) -> usize {
        self.b.len() - self.at
    }
    pub fn done(&self) -> bool {
        self.at == self.b.len()
    }
}

/// FNV-1a, 64 bits: the kept state's checksum.
pub fn checksum(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// `body` behind a header: magic, version, length, checksum.
pub fn seal(magic: u32, version: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 24);
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&checksum(body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The body of a [`seal`]ed string, if magic, version, length and checksum agree (trailing
/// bytes after the body are ignored: a kept object is page-sized).
pub fn unseal(magic: u32, version: u32, b: &[u8]) -> Result<&[u8], i64> {
    if b.len() < 24 {
        return Err(EINVAL);
    }
    let m = u32::from_le_bytes(b[0..4].try_into().unwrap());
    let v = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let len = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let sum = u64::from_le_bytes(b[16..24].try_into().unwrap());
    if m != magic || v != version || len > (b.len() - 24) as u64 {
        return Err(EINVAL);
    }
    let body = &b[24..24 + len as usize];
    if checksum(body) != sum {
        return Err(EINVAL);
    }
    Ok(body)
}
