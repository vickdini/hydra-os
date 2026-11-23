//! # Landlock and the access policies for forwarded callers (wave 9, Group 6b-3)
//!
//! - **Landlock:** the kernel keeps the rulesets and the domains; every forwarded call names
//!   its caller's domain by id (`LxCall::ll_dom`, never reused) and vfs-server keeps a copy
//!   per id, fetched once (`LX_FH_LANDLOCK`). The checks ([`ll`]) need the chain of
//!   directories above an object as the kernel's `dir_chain` takes it (the pool's `..`):
//!   the walks of landlocked callers leave parent hints ([`hint`]), each checked against
//!   the name cache before use, else zfs-server is asked for `..`. A copy lost with a restart
//!   is fetched again: the kernel's domain is the truth.
//! - **ABAC:** the kernel's evaluator decides (`LX_FH_ABAC`, its caches and audit ring, as
//!   the caller): asked only for objects with extended attributes (labels live in one),
//!   callers that are not root and that the policies apply to (`LX_FS_ABAC`).
//!
//! Anything a copy cannot answer (too big, a parent not known) is the kernel's ([`KERNEL`]).

pub mod ll;
pub mod steps;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::sys;

use crate::cache::CACHE;
use crate::calls::rules::KERNEL;
use crate::ctx::{Ctx, Node};
use crate::fs::fsproto::Attr;
use crate::lock::YLock;
use crate::proto::{LxAbacDesc, LxCall, LX_ABAC_DELETE, LX_FH_ABAC, LX_FH_LANDLOCK};

pub use ll::Domain;

/// Copies of domains by id.
static DOMAINS: YLock<BTreeMap<u64, Arc<Domain>>> = YLock::new(BTreeMap::new());
/// Most copies kept (all go when full: they are fetched again on use).
const MAX_DOMAINS: usize = 256;
/// The largest domain copied (a bigger one: the kernel answers its calls).
const MAX_BYTES: usize = 256 * 1024;

/// Parent hints: object → (directory, name, object) a landlocked caller's walk found it by.
static HINTS: YLock<BTreeMap<u64, (Node, Vec<u8>, Node)>> = YLock::new(BTreeMap::new());
/// Most hints kept (all go when full).
const MAX_HINTS: usize = 16384;
/// Directories' parents zfs-server named (`..`), for those no walk passed through (above a
/// chroot such as `/ubuntu`): emptied by any change the kernel or vfs-server makes to names
/// of directories (see [`names_changed`]), so a moved directory is asked about again.
static PARENTS: YLock<BTreeMap<u64, u64>> = YLock::new(BTreeMap::new());
/// Most parents kept.
const MAX_PARENTS: usize = 4096;
/// The deepest chain followed (the kernel's 256).
const MAX_DEPTH: usize = 256;

/// Domains fetched, Landlock checks made, ABAC questions asked (since start).
pub static FETCHES: AtomicU64 = AtomicU64::new(0);
/// See [`FETCHES`].
pub static LL_CHECKS: AtomicU64 = AtomicU64::new(0);
/// See [`FETCHES`].
pub static ABAC_ASKS: AtomicU64 = AtomicU64::new(0);

// ----------------------------------------------------------------------
// Landlock
// ----------------------------------------------------------------------

/// The copy of call `c`'s caller's domain (`None`: not landlocked; [`KERNEL`]: no copy).
pub fn domain(c: &LxCall) -> Result<Option<Arc<Domain>>, i64> {
    if c.ll_dom == 0 {
        return Ok(None);
    }
    if let Some(d) = DOMAINS.lock().get(&c.ll_dom) {
        return Ok(Some(d.clone()));
    }
    let mut buf = vec![0u8; MAX_BYTES];
    let n = sys::lx_obj(LX_FH_LANDLOCK, c.id, buf.as_mut_ptr() as u64, buf.len() as u64).map_err(|_| KERNEL)? as usize;
    let d = ll::parse(buf.get(..n).ok_or(KERNEL)?).filter(|d| d.id == c.ll_dom).ok_or(KERNEL)?;
    FETCHES.fetch_add(1, Ordering::Relaxed);
    let d = Arc::new(d);
    let mut g = DOMAINS.lock();
    if g.len() >= MAX_DOMAINS {
        g.clear();
    }
    g.insert(c.ll_dom, d.clone());
    Ok(Some(d))
}

/// Forgets every copy and hint (a restart starts empty anyway; for tests and resyncs).
pub fn forget_all() {
    DOMAINS.lock().clear();
    HINTS.lock().clear();
    PARENTS.lock().clear();
    CALL_LAST.lock().clear();
}

/// The last object each call's walk found, and the directory it found it in (a file's
/// parent comes from the call's own walk: with hard links, another call's hint could name an
/// allowed directory for a denied path — review of 6b-3).
/// (Most calls remembered: 1024; all go when full, and a call that lost its entry is the
/// kernel's.)
static CALL_LAST: YLock<steps::LastSteps> = YLock::new(steps::LastSteps::new(1024));
/// Moves on with every [`names_changed`]: a `..` answer taken across one is not kept.
static PARENTS_EPOCH: AtomicU64 = AtomicU64::new(0);

/// A landlocked caller's walk (call `req`) found `child` by `name` in `dir`.
pub fn hint(req: u64, dir: Node, name: &[u8], child: Node) {
    if name == b"." || name == b".." || dir.ino == child.ino {
        return;
    }
    CALL_LAST.lock().record(req, child.ino, dir.ino);
    let mut g = HINTS.lock();
    if g.len() >= MAX_HINTS {
        g.clear();
    }
    g.insert(child.ino, (dir, name.to_vec(), child));
}

/// The directory call `req`'s walk found file `ino` in (its last step), if that is what it
/// found last.
fn call_parent(req: u64, ino: u64) -> Option<u64> {
    CALL_LAST.lock().take(req, ino)
}

/// The directory above directory `ino` in the pool (a directory has one parent): a hint
/// the name cache still confirms, else zfs-server's `..`.
fn parent_of(ino: u64) -> Option<u64> {
    // (the pool root is its own parent: no question to zfs-server)
    if crate::zfs::root().ok() == Some(ino) {
        return Some(ino);
    }
    let h = HINTS.lock().get(&ino).cloned();
    if let Some((d, name, ch)) = h {
        if CACHE.name(d, &name) == Some(Some(ch)) {
            return Some(d.ino);
        }
    }
    if let Some(&p) = PARENTS.lock().get(&ino) {
        return Some(p);
    }
    let epoch = PARENTS_EPOCH.load(Ordering::Acquire);
    let p = crate::zfs::lookup(ino, b"..").ok()?;
    let mut g = PARENTS.lock();
    // (a change meanwhile: the answer may be stale, not kept)
    if PARENTS_EPOCH.load(Ordering::Acquire) != epoch {
        return Some(p);
    }
    if g.len() >= MAX_PARENTS {
        g.clear();
    }
    g.insert(ino, p);
    Some(p)
}

/// Object `ino` changed (a kernel note names the object it moved or removed; 0: anything
/// may have): the parent zfs-server named for it may be stale.
pub fn names_changed(ino: u64) {
    let mut g = PARENTS.lock();
    PARENTS_EPOCH.fetch_add(1, Ordering::AcqRel);
    if g.is_empty() {
        return;
    }
    if ino == 0 {
        g.clear();
    } else {
        g.remove(&ino);
    }
}

/// Directory `dir` and every directory above it in the pool (the kernel's `dir_chain`).
pub fn dir_chain(dir: u64) -> Vec<u64> {
    let mut v = vec![dir];
    let mut cur = dir;
    for _ in 0..MAX_DEPTH {
        match parent_of(cur) {
            Some(p) if p != cur => {
                v.push(p);
                cur = p;
            }
            _ => break,
        }
    }
    v
}

/// [`KERNEL`] for a FUSE object: the kernel's chain goes through the daemon's tree.
fn pool_only(ino: u64) -> Result<(), i64> {
    if crate::fuse::wire::split(ino).is_some() {
        return Err(KERNEL);
    }
    Ok(())
}

/// The chain of object `n` that call `req` walked to (a directory's own chain; a file, the
/// chain of the directory the call's own walk found it in): [`KERNEL`] when not known (a
/// file reached otherwise, e.g. a file bind-mounted over a name).
fn chain_of(req: u64, n: Node, is_dir: bool) -> Result<Vec<u64>, i64> {
    pool_only(n.ino)?;
    if is_dir {
        CALL_LAST.lock().forget(req);
        return Ok(dir_chain(n.ino));
    }
    let p = call_parent(req, n.ino).ok_or(KERNEL)?;
    let mut v = vec![n.ino];
    v.extend(dir_chain(p));
    Ok(v)
}

/// Which of `want` the domain refuses on object `n`, which call `req` walked to.
pub fn refused_on(d: &Domain, req: u64, n: Node, is_dir: bool, want: u64) -> Result<u64, i64> {
    LL_CHECKS.fetch_add(1, Ordering::Relaxed);
    Ok(ll::refused(d, &chain_of(req, n, is_dir)?, want))
}

/// Checks making or removing an entry (`want`) in directory `dir`: `EACCES` when refused.
pub fn check_dir(d: &Domain, dir: Node, want: u64) -> Result<(), i64> {
    LL_CHECKS.fetch_add(1, Ordering::Relaxed);
    pool_only(dir.ino)?;
    if ll::refused(d, &dir_chain(dir.ino), want) != 0 {
        Err(ll::EACCES)
    } else {
        Ok(())
    }
}

/// Checks a rename of an entry of type `ftype` from `sdir` to `ddir`, replacing an entry
/// whose removal needs `remove_dst` (the kernel's `check_move`).
pub fn check_move(d: &Domain, sdir: Node, ddir: Node, ftype: u32, remove_dst: u64) -> Result<(), i64> {
    LL_CHECKS.fetch_add(1, Ordering::Relaxed);
    pool_only(sdir.ino)?;
    pool_only(ddir.ino)?;
    let schain = dir_chain(sdir.ino);
    let same = sdir.ino == ddir.ino;
    let dchain = if same { schain.clone() } else { dir_chain(ddir.ino) };
    ll::check_move(d, &schain, &dchain, same, ftype, true, remove_dst)
}

// ----------------------------------------------------------------------
// ABAC
// ----------------------------------------------------------------------

/// Whether the access policies let caller `who` (not root: the caller checks) access
/// `attr` for `want` (`r` 4, `w` 2, `x` 1), or delete it (`delete`); `path`: the path it
/// named (audit). Asked of the kernel only for callers the policies apply to and objects
/// with extended attributes.
pub fn abac(who: &Ctx, attr: &Attr, want: u32, delete: bool, path: &[u8]) -> Result<bool, i64> {
    if !who.abac || !attr.has_xattr {
        return Ok(true);
    }
    ABAC_ASKS.fetch_add(1, Ordering::Relaxed);
    let d = LxAbacDesc {
        ino: attr.ino,
        gen: attr.generation,
        mode: attr.mode,
        want: if delete { LX_ABAC_DELETE } else { want & 7 },
        path: if path.is_empty() { 0 } else { path.as_ptr() as u64 },
        path_len: path.len() as u64,
    };
    match sys::lx_obj(LX_FH_ABAC, who.req, &d as *const LxAbacDesc as u64, 0) {
        Ok(_) => Ok(true),
        Err(ll::EACCES) => Ok(false),
        Err(_) => Err(KERNEL),
    }
}

/// `[vfs-server] policy:` counters.
pub fn summary() -> alloc::string::String {
    alloc::format!(
        "policy: domains {} fetched {} landlock checks {} abac asks {} hints {}",
        DOMAINS.lock().len(),
        FETCHES.load(Ordering::Relaxed),
        LL_CHECKS.load(Ordering::Relaxed),
        ABAC_ASKS.load(Ordering::Relaxed),
        HINTS.lock().len()
    )
}
