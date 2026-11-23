//! # The kernel's mount tables, as vfs-server walks them (wave 7, Group 7-7)
//!
//! The kernel's table (`compat/linux/mount.rs`) stays the one owner of every namespace's
//! mounts this wave: `mount`, `umount2`, `pivot_root` and the new mount API are the kernel's,
//! and so is every call vfs-server sends back. vfs-server keeps a **copy** of each table it
//! needs ([`View`]), taken with `LX_FH_MNTTAB` and named by its generation: each call carries
//! the generation of its caller's table (`LxCall::mnt_gen`), and a copy older than that is
//! taken again before the walk. So a call made after a `mount` returned always walks with a
//! table that has it.
//!
//! - Mount numbers are the kernel's (1-based slots; `FdTable::root_mnt`, `OpenFile::mnt`):
//!   the initial namespace's pool tree is mount 0, its FUSE mounts are 1..; another
//!   namespace's objects are all in mounts >= 1 (its root mount is [`View::root`]).
//! - A pool tree (bind mount, tmpfs, the root) is walked here; a mount the kernel serves
//!   (FUSE, a named mount the kernel serves by another path) ends the walk with "redirect to
//!   the kernel" ([`MountKind::Redirect`] to service 0), as `/proc`, `/sys` and `/dev` by name
//!   under the caller's root do (the boot rule, [`BootMounts`]).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ctx::Node;
use crate::lock::YLock;
use crate::proto::{LxMntHead, LxMntRec, SvcId, LX_MNT_FUSE, LX_MNT_HOLE, LX_MNT_KERNEL, LX_MNT_TMPFS, LX_MNT_TREE};
use crate::walk::{BootMounts, MountInfo, MountKind, Mounts};

/// `MS_RDONLY`.
pub const MS_RDONLY: u32 = 1;
/// `MS_NOSUID`.
pub const MS_NOSUID: u32 = 2;
/// `MS_NOEXEC`.
pub const MS_NOEXEC: u32 = 8;

/// The copy of one namespace's table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    /// The namespace.
    pub ns: u32,
    /// The table's generation (at least: the kernel reads it before the table).
    pub gen: u64,
    /// The root mount (0 in the initial namespace).
    pub root: u32,
    /// The slots (slot `i` is mount `i + 1`).
    pub recs: Vec<LxMntRec>,
}

impl View {
    /// The initial namespace without mounts (generation 0).
    pub const fn empty() -> Self {
        Self { ns: 0, gen: 0, root: 0, recs: Vec::new() }
    }

    /// Slot `m` (1-based), if it holds a mount the walk sees.
    pub fn rec(&self, m: u32) -> Option<&LxMntRec> {
        let r = self.recs.get((m as usize).checked_sub(1)?)?;
        (r.kind != LX_MNT_HOLE).then_some(r)
    }

    /// The `MS_*` flags of mount `m` (0 for the initial namespace's own tree).
    pub fn flags(&self, m: u16) -> u32 {
        self.rec(m as u32).map_or(0, |r| r.flags)
    }

    /// Whether mount `m` is a tmpfs.
    pub fn is_tmpfs(&self, m: u16) -> bool {
        self.rec(m as u32).is_some_and(|r| r.kind == LX_MNT_TMPFS)
    }

    /// Whether `n` is a pool object vfs-server may walk from: in the initial namespace one of
    /// its own tree; in another, one of a pool tree of the table.
    pub fn walkable(&self, n: Node) -> bool {
        if self.ns == 0 {
            return n.mnt == 0;
        }
        // (and every mount below it a pool tree too: `..` out of a mount on something the
        // kernel serves would leave the pool — 7-7 review)
        let mut m = n.mnt as u32;
        for _ in 0..64 {
            match self.rec(m) {
                Some(r) if r.kind == LX_MNT_TREE || r.kind == LX_MNT_TMPFS => {
                    if r.parent == 0 {
                        return true;
                    }
                    m = r.parent;
                }
                _ => return false,
            }
        }
        false
    }

    /// Whether directory `n` is the mount point of any mount (listed or not): it cannot be
    /// removed or renamed (Linux: `EBUSY`; the kernel decides).
    pub fn is_mountpoint(&self, n: Node) -> bool {
        // (by object only: a directory mounted on is busy through every bind of its tree,
        // as Linux's `is_local_mountpoint` — 7-7 review)
        self.recs.iter().any(|r| r.mountpoint != 0 && r.mountpoint == n.ino)
    }

    /// The root object of the namespace's root mount (another namespace).
    pub fn root_ino(&self) -> Option<u64> {
        self.rec(self.root).map(|r| r.root)
    }
}

/// The boot rule for the names under the caller's root (`/proc`, `/sys`, `/dev`).
const BOOT: BootMounts = BootMounts { pseudo: true };

impl Mounts for View {
    fn covering(&self, _ns: u32, at: Node) -> Option<u16> {
        // The topmost: the latest slot on that directory (the kernel's `enter`)
        let i = self.recs.iter().rposition(|r| r.kind != LX_MNT_HOLE && r.mountpoint == at.ino && r.parent == at.mnt as u32)?;
        u16::try_from(i + 1).ok()
    }

    fn mount(&self, _ns: u32, m: u16) -> Option<MountInfo> {
        let r = self.rec(m as u32)?;
        let root = Node::new(m, r.root);
        let kind = match r.kind {
            LX_MNT_KERNEL => MountKind::Redirect { svc: 0, obj: 0 },
            LX_MNT_FUSE => MountKind::Fuse, // wave9 G6b-2
            _ => MountKind::Zfs,
        };
        // A mount with nothing below it (a namespace's root): its mount point is itself,
        // so `..` stays there
        let mountpoint = if r.parent == 0 && self.ns != 0 { root } else { Node::new(r.parent as u16, r.mountpoint) };
        Some(MountInfo { parent: r.parent as u16, mountpoint, root, kind })
    }

    fn pseudo_at_root(&self, ns: u32, name: &[u8]) -> Option<(SvcId, u64)> {
        BOOT.pseudo_at_root(ns, name)
    }
}

/// Builds a view from an `LX_FH_MNTTAB` answer (head + records); `None` if it does not fit
/// the walk (more than 65,535 slots, a parent outside the table).
pub fn parse(ns: u32, head: &LxMntHead, recs: &[LxMntRec]) -> Option<View> {
    if recs.len() != head.n as usize || recs.len() > u16::MAX as usize || head.root as usize > recs.len() {
        return None;
    }
    if ns != 0 && (head.root == 0 || recs[head.root as usize - 1].kind == LX_MNT_HOLE) {
        return None;
    }
    if recs.iter().any(|r| r.kind > LX_MNT_FUSE || (r.kind != LX_MNT_HOLE && r.parent as usize > recs.len())) {
        return None;
    }
    Some(View { ns, gen: head.gen, root: head.root, recs: recs.to_vec() })
}

/// The copies, by namespace.
static VIEWS: YLock<BTreeMap<u32, Arc<View>>> = YLock::new(BTreeMap::new());
/// Copies taken from the kernel since start, and calls that found theirs current.
pub static PULLS: AtomicU64 = AtomicU64::new(0);
/// See [`PULLS`].
pub static HITS: AtomicU64 = AtomicU64::new(0);
/// At most this many copies are kept (beyond it they are all dropped and taken again).
const KEEP: usize = 256;

/// Takes namespace `ns`'s table from the kernel.
#[cfg(not(test))]
fn pull(ns: u32) -> Result<View, i64> {
    use crate::proto::LX_FH_MNTTAB;
    let head_len = core::mem::size_of::<LxMntHead>();
    let rec_len = core::mem::size_of::<LxMntRec>();
    let mut cap = 64usize;
    for _ in 0..4 {
        let mut buf = alloc::vec![0u8; head_len + cap * rec_len];
        // (any error: the kernel answers the call — never the primitive's errno to the caller)
        let n = hydra_rt::sys::lx_obj(LX_FH_MNTTAB, ns as u64, buf.as_mut_ptr() as u64, cap as u64).map_err(|_| crate::calls::KERNEL)? as usize;
        if n > u16::MAX as usize {
            return Err(crate::calls::KERNEL);
        }
        if n > cap {
            cap = n + 8;
            continue;
        }
        // SAFETY: the kernel wrote a head and `n` records (plain integers)
        let head: LxMntHead = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const LxMntHead) };
        let recs: Vec<LxMntRec> = (0..n).map(|i| unsafe { core::ptr::read_unaligned(buf.as_ptr().add(head_len + i * rec_len) as *const LxMntRec) }).collect();
        let p = PULLS.fetch_add(1, Ordering::Relaxed) + 1;
        // The first copies and then every 1,024th in the log (shows the calls of callers
        // with mounts reach vfs-server)
        if p <= 2 || p % 1024 == 0 {
            hydra_rt::println!("[vfs-server] mount table of namespace {} taken (generation {}, {} slots; {} copies so far)", ns, head.gen, n, p);
        }
        return parse(ns, &head, &recs).ok_or(crate::calls::KERNEL);
    }
    Err(crate::calls::KERNEL)
}

#[cfg(test)]
fn pull(_ns: u32) -> Result<View, i64> {
    Err(crate::calls::KERNEL)
}

/// The copy of namespace `ns`'s table at least as new as generation `gen`, taken from the
/// kernel if the one kept is older. `Err(KERNEL)`: a table vfs-server cannot walk (the
/// kernel answers the call).
pub fn view(ns: u32, gen: u64) -> Result<Arc<View>, i64> {
    if ns == 0 && gen == 0 {
        static EMPTY: YLock<Option<Arc<View>>> = YLock::new(None);
        let mut e = EMPTY.lock();
        return Ok(e.get_or_insert_with(|| Arc::new(View::empty())).clone());
    }
    if let Some(v) = VIEWS.lock().get(&ns) {
        if v.gen >= gen {
            HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(v.clone());
        }
    }
    let v = pull(ns)?;
    if v.gen < gen {
        // (cannot happen: the kernel's generation only grows)
        return Err(crate::calls::KERNEL);
    }
    let v = Arc::new(v);
    let mut g = VIEWS.lock();
    if g.len() >= KEEP && !g.contains_key(&ns) {
        g.clear();
    }
    match g.get(&ns) {
        Some(old) if old.gen >= v.gen => Ok(old.clone()),
        _ => {
            g.insert(ns, v.clone());
            Ok(v)
        }
    }
}

/// Namespace `ns` is gone (its last process ended): its copy goes.
pub fn forget(ns: u32) {
    VIEWS.lock().remove(&ns);
}

/// Every copy goes (a ring overflow: notes may have been lost; the generations still keep
/// each call right, this only frees memory).
pub fn forget_all() {
    VIEWS.lock().clear();
}

/// `(copies kept, pulls, hits)`.
pub fn stats() -> (usize, u64, u64) {
    (VIEWS.lock().len(), PULLS.load(Ordering::Relaxed), HITS.load(Ordering::Relaxed))
}
