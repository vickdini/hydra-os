//! # The walk's view of the mount tables (vfs-server; wave 7, Group 7-3)
//!
//! [`TableMounts`] answers Group 7-1's [`Mounts`] questions from [`crate::mtab`]'s tables,
//! and the `tmpfs_*` functions are the walk's back end for nodes in tmpfs mounts
//! ([`crate::be`] routes them here by the node's mount).
//!
//! - The walk's mount 0 (the "own tree": the pool at `/`) is table index 1, the mount every
//!   table starts with (copies keep indices). It is fixed: a `pivot_root` that moves the
//!   namespace's root elsewhere does not renumber handles that name mount 0.
//!   [`to_idx`]/[`to_walk`] translate; indices above 16 bits are never handed to the walk
//!   (tables stop at [`crate::mtab::MAX_MOUNTS`]).
//! - A namespace the server has not heard of uses the initial namespace's table.
//! - While only the boot table exists ([`SIMPLE`]), the answers come without the lock and
//!   are those of 7-1's [`BootMounts`]: `proc`, `sys` and `dev` by name under every root.

use crate::ctx::Node;
use crate::proto::{SvcId, LXS_LINUX, LXS_PROC, LX_VFS_PSEUDO_DEV, LX_VFS_PSEUDO_PROC, LX_VFS_PSEUDO_SYS};
use crate::walk::{BootMounts, MountInfo, MountKind, Mounts};

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::fsproto::{Attr, ENOENT};
use crate::lock::YLock;
use crate::mtab::{self, InitialMount, MntIdx, MountNs, MountTables, MS_NOEXEC, MS_NOSUID, MS_RELATIME};
use crate::tmpfs::{self, TmpfsSet};

/// Every mount namespace's table (`None` until [`install_boot`]).
pub static MTAB: YLock<Option<MountTables>> = YLock::new(None);
/// The `tmpfs` instances (`None` until [`install_boot`]).
pub static TMPFS: YLock<Option<TmpfsSet>> = YLock::new(None);
/// Only the boot table exists, and it has no mounts on objects: the walk's questions are
/// answered without the lock (the same answers as [`BootMounts`]). Cleared by the first
/// change ([`changed`]).
static SIMPLE: AtomicBool = AtomicBool::new(true);

/// The boot table's mounts: `/proc`, `/sys` and `/dev` served by name from every root, with
/// the objects Group 7-1's redirect names (`LX_VFS_PSEUDO_*`).
pub fn boot_layout() -> Vec<InitialMount> {
    let served = |path: &str, fstype: &str, source: &str, svc: SvcId, obj: u64| InitialMount {
        path: String::from(path),
        mountpoint: 0,
        backend: mtab::Backend::Remote { svc, obj },
        root: 0,
        fs_root: String::from("/"),
        fstype: String::from(fstype),
        source: String::from(source),
        flags: MS_NOSUID | MS_NOEXEC | MS_RELATIME,
    };
    alloc::vec![
        served("/proc", "proc", "proc", LXS_PROC, LX_VFS_PSEUDO_PROC),
        served("/sys", "sysfs", "sysfs", LXS_LINUX, LX_VFS_PSEUDO_SYS),
        served("/dev", "devtmpfs", "udev", LXS_LINUX, LX_VFS_PSEUDO_DEV),
    ]
}

/// Makes the initial namespace's table (the pool's root object `pool_root` at `/`) and the
/// empty tmpfs set; once, at start-up.
pub fn install_boot(pool_root: u64) {
    let mut t = MountTables::new();
    t.install(0, pool_root, &boot_layout());
    *MTAB.lock() = Some(t);
    *TMPFS.lock() = Some(TmpfsSet::new());
}

/// Sets the pool's root object in every table whose `/` still has none (`install_boot`
/// ran before zfs-server answered; called again until it does). Whether it is known now.
pub fn set_pool_root(root: u64) -> bool {
    let mut g = MTAB.lock();
    let Some(t) = g.as_mut() else { return false };
    if root == 0 {
        return false;
    }
    for ns in t.spaces.values_mut() {
        ns.set_first_root(root);
    }
    true
}

/// The kernel's note ring lost entries (`dropped` moved): namespace notes may be among
/// them, so the tables of every namespace but the initial one are dropped (calls of an
/// unknown namespace use the initial table, as before its note) and their tmpfs instances
/// go once nothing holds them.
pub fn forget_namespaces(store: &mut dyn tmpfs::DataStore) {
    let gone = {
        let mut g = MTAB.lock();
        let Some(t) = g.as_mut() else { return };
        t.collect(&[]).tmpfs_gone
    };
    if !gone.is_empty() {
        let m = MTAB.lock();
        let mounted = |n: u32| m.as_ref().is_some_and(|t| t.tmpfs_in_use(n));
        if let Some(s) = TMPFS.lock().as_mut() {
            s.reap(&mounted, store);
        }
    }
}

/// A table changed: the walk asks the tables from now on.
pub fn changed() {
    SIMPLE.store(false, Ordering::Release);
}

/// Namespace `ns`'s table, or the initial one for a namespace the server has not heard of.
fn table(t: &MountTables, ns: u32) -> Option<&MountNs> {
    t.ns(ns as u64).or_else(|| t.ns(0))
}

/// The walk's mount number `m` as a table index (the walk's 0 is the namespace's root).
fn to_idx(_t: &MountNs, m: u16) -> MntIdx {
    if m == 0 { 1 } else { m as MntIdx }
}

/// A table index as the walk's mount number.
fn to_walk(_t: &MountNs, i: MntIdx) -> Option<u16> {
    match i {
        1 => Some(0),
        // (index 0 is "no mount"; nothing above 16 bits reaches the walk)
        0 => None,
        i => u16::try_from(i).ok(),
    }
}

/// The mount tables as the walk asks them.
pub struct TableMounts;

/// The tables, for the walk.
pub static TABLES: TableMounts = TableMounts;

/// The boot answers, while [`SIMPLE`].
const BOOT: BootMounts = BootMounts { pseudo: true };

impl Mounts for TableMounts {
    fn covering(&self, ns: u32, at: Node) -> Option<u16> {
        if SIMPLE.load(Ordering::Acquire) {
            return None;
        }
        let g = MTAB.lock();
        let t = table(g.as_ref()?, ns)?;
        let i = t.covering(to_idx(t, at.mnt), at.ino)?;
        to_walk(t, i).filter(|w| *w != 0)
    }

    fn mount(&self, ns: u32, m: u16) -> Option<MountInfo> {
        // (mount 0 is the own tree: never a mount the walk climbs out of, as in BootMounts)
        if m == 0 || SIMPLE.load(Ordering::Acquire) {
            return None;
        }
        let g = MTAB.lock();
        let t = table(g.as_ref()?, ns)?;
        let i = to_idx(t, m);
        let mt = t.get(i)?;
        let parent = if mt.parent == 0 { 0 } else { to_walk(t, mt.parent)? };
        let kind = match mt.backend {
            mtab::Backend::Pool => MountKind::Zfs,
            mtab::Backend::Tmpfs(n) => MountKind::Tmpfs(n),
            mtab::Backend::Remote { svc, obj } => MountKind::Redirect { svc, obj },
        };
        Some(MountInfo { parent, mountpoint: Node::new(parent, mt.mountpoint), root: Node::new(to_walk(t, i)?, mt.root), kind })
    }

    fn pseudo_at_root(&self, ns: u32, name: &[u8]) -> Option<(SvcId, u64)> {
        if SIMPLE.load(Ordering::Acquire) {
            return BOOT.pseudo_at_root(ns, name);
        }
        let g = MTAB.lock();
        table(g.as_ref()?, ns)?.pseudo_at_root(name)
    }
}

/// The tmpfs instance mount `mnt` (the walk's number) of namespace `ns` shows, if it is a
/// tmpfs mount.
pub fn tmpfs_of(ns: u32, mnt: u16) -> Option<u32> {
    if mnt == 0 || SIMPLE.load(Ordering::Acquire) {
        return None;
    }
    let g = MTAB.lock();
    let t = table(g.as_ref()?, ns)?;
    match t.get(to_idx(t, mnt))?.backend {
        mtab::Backend::Tmpfs(n) => Some(n),
        _ => None,
    }
}

/// Runs `f` on tmpfs instance `n`.
fn with_tmpfs<R>(n: u32, f: impl FnOnce(&tmpfs::Tmpfs) -> Result<R, i64>) -> Result<R, i64> {
    let g = TMPFS.lock();
    f(g.as_ref().and_then(|s| s.get(n)).ok_or(ENOENT)?)
}

/// The walk's back end for a node in a tmpfs mount: `lookup`.
pub fn tmpfs_lookup(n: u32, dir: Node, name: &[u8]) -> Result<Node, i64> {
    with_tmpfs(n, |t| t.lookup(dir.ino, name)).map(|i| Node::new(dir.mnt, i))
}

/// `getattr`, as the pool's attributes.
pub fn tmpfs_getattr(n: u32, node: Node) -> Result<Attr, i64> {
    let a = with_tmpfs(n, |t| t.getattr(node.ino))?;
    Ok(Attr { ino: a.ino, mode: a.mode, nlink: a.nlink, uid: a.uid, gid: a.gid, rdev: a.rdev, size: a.size, blocks: a.blocks, atime: a.atime, mtime: a.mtime, ctime: a.ctime, ..Attr::default() })
}

/// `readlink`.
pub fn tmpfs_readlink(n: u32, node: Node) -> Result<Vec<u8>, i64> {
    with_tmpfs(n, |t| t.readlink(node.ino))
}

/// The POSIX access ACL (tmpfs keeps it as an xattr like any other): `Ok(None)` when
/// there is none (an empty one counts as none, as zfs-server's).
pub fn tmpfs_acl(n: u32, node: Node) -> Result<Option<Vec<u8>>, i64> {
    match with_tmpfs(n, |t| t.getxattr(node.ino, crate::perm::ACL_ACCESS)) {
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(tmpfs::ENODATA) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `LX_NOTE_MNTNS`: namespace `new` was made as a copy of `from` (its served mounts stay
/// by name, so a chrooted process keeps its `/proc`, as in the kernel), or (`from` =
/// `LX_MNTNS_GONE`) `new` has no live process left: its table goes, and the tmpfs instances
/// no namespace mounts and no handle holds go with it (their data from `store`).
pub fn on_mntns(new: u64, from: u64, store: &mut dyn tmpfs::DataStore) {
    let mut g = MTAB.lock();
    let Some(t) = g.as_mut() else { return };
    // The first few, in the log (shows the notes arrive)
    if NOTED.fetch_add(1, Ordering::Relaxed) < 8 {
        log_mntns(new, from, t.spaces.len());
    }
    if from == crate::proto::LX_MNTNS_GONE {
        let fx = t.drop_ns(new);
        let gone = fx.tmpfs_gone;
        drop(g);
        if !gone.is_empty() {
            let m = MTAB.lock();
            let mounted = |n: u32| m.as_ref().is_some_and(|t| t.tmpfs_in_use(n));
            if let Some(s) = TMPFS.lock().as_mut() {
                s.reap(&mounted, store);
            }
        }
        // (pool roots of binds: held and let go once the mount calls hold them)
        return;
    }
    // A namespace made from one the server never heard of copies the initial one
    let src = if t.ns(from).is_some() { from } else { 0 };
    // A table already there under this id is stale (its "gone" note was lost): replaced
    if t.ns(new).is_some() && new != 0 {
        let fx = t.drop_ns(new);
        drop(fx); // (its tmpfs instances: reaped with the next one that goes)
    }
    if t.copy_ns(src, new, &|_| 0).is_ok() {
        changed();
    }
}

/// Namespace notes seen.
static NOTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

#[cfg(not(test))]
fn log_mntns(new: u64, from: u64, tables: usize) {
    if from == crate::proto::LX_MNTNS_GONE {
        hydra_rt::println!("[vfs-server] mount namespace {} gone ({} tables)", new, tables);
    } else {
        hydra_rt::println!("[vfs-server] mount namespace {} made from {} ({} tables)", new, from, tables);
    }
}

#[cfg(test)]
fn log_mntns(_new: u64, _from: u64, _tables: usize) {}
