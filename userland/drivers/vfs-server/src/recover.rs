//! # vfs-server's restart: saving and taking back the kept state (wave 7, Group 7-6)
//!
//! `docs/vfs-design.md` section 8.1; the format is [`crate::kept`]'s.
//!
//! - **[`open`]**, at start, before the service goes online: maps the two slots (kept memory
//!   objects, `SNAP_MAX` bytes each, made zeroed by the kernel the first time), and if one
//!   holds a valid snapshot, takes back the mount tables and the `tmpfs` trees (each checked
//!   by its decoder), re-opens every `tmpfs` file's data object by its key, and frees the
//!   data objects a crash left behind. A snapshot that fails a check: the other slot, then
//!   the boot table (and the log says so). The restart ladder's reset (a second crash within
//!   30 s) drops every kept object in the kernel: the next instance starts fresh.
//! - **[`save`]** after every change of the tables or the trees (the caller holds none of
//!   their locks), before the answer leaves the worker.
//! - **[`resync`]**, right after going online: the namespace notes posted while the server
//!   was down are lost, so the kernel's list of live mount namespaces (`LX_FH_NSLIST`) is
//!   compared with the tables: tables of namespaces that are gone go, live namespaces
//!   without a table get a copy of the initial one (as a note from an unknown namespace).
//!   The same runs when the note ring overflowed. Namespace notes and a resync exclude each
//!   other ([`NS_SYNC`]).
//! - **Known limits:** a namespace made while no instance was online is copied from the
//!   initial table (its parent is not known); a tmpfs data object freed for a change whose
//!   snapshot a crash never wrote reads as zeros after the restart (the change itself fails
//!   with `EIO` or is sent again).
//! - **[`ktest`]**: the test hook `LX_VFS_KTEST` (a tmpfs file of a test instance, written
//!   before a kill and read after it).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::mem::{MemObj, PROT_RW};
use hydra_rt::svcrt::Cx;
use hydra_rt::{println, sys};

use crate::kept::{self, Counters, Snapshot, SLOT_HEADER, SLOT_KEYS, SNAP_MAX};
use crate::lock::YLock;
use crate::locks::LockTable;
use crate::mount::{self, MTAB, TMPFS};
use crate::mtab::MountTables;
use crate::proto::{LX_FH_NSLIST, LX_MNTNS_GONE};
use crate::tmpfs::{DataStore, TmpfsSet, S_IFREG};
use crate::tmpfs_mem::{DATA_NEXT, STORE};

const EINVAL: i64 = -22;
const ENOENT: i64 = -2;

/// The two slots, mapped for the life of the instance.
struct Slots {
    base: [*mut u8; 2],
    /// The generation written last (0: none yet).
    gen: u64,
    /// Snapshots that did not fit (logged once).
    too_big: bool,
}

// SAFETY: the slot pointers are this program's own mappings, used under the lock
unsafe impl Send for Slots {}

static SLOTS: YLock<Option<Slots>> = YLock::new(None);

/// The file locks (kept; the lock calls are still the kernel's: `locks.rs`).
pub static LOCKS: YLock<LockTable> = YLock::new(LockTable::new());

/// Held by [`resync`] and by every namespace note while it is applied: a note is applied
/// wholly before or after a resync (its list and its changes), never in between, so a
/// resync cannot drop a namespace a note just made nor bring back one a note just dropped.
/// Taken before `STORE`, `MTAB`, `TMPFS` and the slots.
pub static NS_SYNC: YLock<()> = YLock::new(());

/// Instances that took over a kept state, and the test hook's instance/file.
static RESTARTS: AtomicU64 = AtomicU64::new(0);
static KTEST: YLock<(u32, u64)> = YLock::new((0, 0));
/// Snapshots written since start (for the log and the tests).
pub static SAVES: AtomicU64 = AtomicU64::new(0);

/// What [`open`] found.
pub enum Found {
    /// No kept state (the first instance, or the ladder reset it).
    Fresh,
    /// A kept state was taken back.
    Restored { gen: u64, spaces: usize, tmpfs: usize, files: usize, missing: usize, freed: usize },
    /// Both slots failed their checks: the boot table.
    Damaged,
    /// The kept objects could not be had (the error): nothing survives this instance.
    NoKept(i64),
}

/// Maps the slots and takes back what they hold (see the module comment).
pub fn open() -> Found {
    let mut base = [core::ptr::null_mut(); 2];
    let mut any = false;
    for (i, key) in SLOT_KEYS.iter().enumerate() {
        let (o, existed) = match MemObj::kept(*key, SNAP_MAX) {
            Ok(x) => x,
            Err(e) => return Found::NoKept(e),
        };
        base[i] = match o.map(0, SNAP_MAX, PROT_RW) {
            Ok(p) => p,
            Err(e) => return Found::NoKept(e),
        };
        // (the mapping keeps the object; the handle is not needed)
        drop(o);
        any |= existed;
    }
    // SAFETY: each slot is SNAP_MAX mapped bytes of this program's, nothing else writes them
    let views = base.map(|p| unsafe { core::slice::from_raw_parts(p as *const u8, SNAP_MAX as usize) });
    let mut found = if any { Found::Damaged } else { Found::Fresh };
    let mut gen = 0;
    for (_, g, body) in kept::by_age(views) {
        // (the newest valid slot's generation, unless an older one is the one restored: the
        // next save then goes to the slot that failed, never over the one taken back)
        gen = gen.max(g);
        match restore(body) {
            Ok(f) => {
                gen = g;
                found = match f {
                    Found::Restored { spaces, tmpfs, files, missing, freed, .. } => Found::Restored { gen: g, spaces, tmpfs, files, missing, freed },
                    f => f,
                };
                break;
            }
            Err(e) => println!("[vfs-server] kept state of generation {} fails its checks ({}): trying the other slot", g, e),
        }
    }
    *SLOTS.lock() = Some(Slots { base, gen, too_big: false });
    found
}

/// Takes back one snapshot's body: `Err` (nothing changed) if a part fails its check.
fn restore(body: &[u8]) -> Result<Found, i64> {
    let s = Snapshot::decode(body)?;
    let tables = match &s.mounts {
        Some(m) => Some(MountTables::decode(m)?),
        None => None,
    };
    let set = match &s.tmpfs {
        Some(t) => Some(TmpfsSet::decode(t)?),
        None => None,
    };
    let locks = match &s.locks {
        Some(l) => LockTable::decode(l)?,
        None => LockTable::new(),
    };
    let c = s.counters;
    // Every check passed: install
    let named = set.as_ref().map_or_else(Vec::new, |t| t.data_keys());
    let (mut missing, mut freed) = (0, 0);
    {
        let mut store = STORE.lock();
        for (i, &k) in named.iter().enumerate() {
            match store.adopt(k) {
                Ok(true) => {}
                Ok(false) => missing += 1,
                Err(e) => {
                    // Give back the handles taken so far (the kept objects stay for a later try)
                    for &j in &named[..i] {
                        store.forget(j);
                    }
                    return Err(e);
                }
            }
        }
        // Data objects made for changes whose snapshot was never written
        for k in kept::sweep_keys(&named, c.data_next) {
            if let Ok((o, existed)) = MemObj::kept(k, 4096) {
                let _ = MemObj::unkeep(k);
                drop(o);
                freed += existed as usize;
            }
        }
    }
    // Past the swept window and past every key a tree names (a key taken while the last
    // snapshot was being made may be named although `data_next` was read before it)
    let next = named.iter().map(|k| k + 1).max().unwrap_or(0).max(c.data_next.saturating_add(kept::SWEEP));
    DATA_NEXT.store(next, Ordering::Relaxed);
    RESTARTS.store(c.restarts + 1, Ordering::Relaxed);
    *KTEST.lock() = (c.ktest_inst, c.ktest_ino);
    let spaces = tables.as_ref().map_or(1, |t| t.spaces.len());
    let ntmpfs = set.as_ref().map_or(0, |t| t.all.len());
    if let Some(t) = tables {
        *MTAB.lock() = Some(t);
    }
    if let Some(t) = set {
        *TMPFS.lock() = Some(t);
    }
    *LOCKS.lock() = locks;
    if spaces > 1 || ntmpfs > 0 {
        mount::changed();
    }
    Ok(Found::Restored { gen: 0, spaces, tmpfs: ntmpfs, files: named.len(), missing, freed })
}

/// The snapshot of now.
fn snapshot() -> Snapshot {
    // (the lock order of the rest of the server: the tables, then the trees, then the test
    // hook's words)
    let m = MTAB.lock();
    let t = TMPFS.lock();
    let l = LOCKS.lock();
    // Read under the trees' lock: a worker making a data object holds it from taking the key
    // to naming it in its tree, so every key below `data_next` that a file uses is in the
    // tree encoded here (and a new instance starts past every named key anyway)
    let (ktest_inst, ktest_ino) = *KTEST.lock();
    let counters = Counters { restarts: RESTARTS.load(Ordering::Relaxed), data_next: DATA_NEXT.load(Ordering::Relaxed), ktest_inst, ktest_ino };
    Snapshot { counters, mounts: m.as_ref().map(|m| m.encode()), tmpfs: t.as_ref().map(|t| t.encode()), locks: Some(l.encode()) }
}

/// Writes the state of now to the older slot (see the module comment). The caller holds
/// none of the tables' and trees' locks.
pub fn save() {
    let mut g = SLOTS.lock();
    let Some(s) = g.as_mut() else { return };
    let gen = s.gen + 1;
    let bytes = kept::encode_slot(gen, &snapshot().encode());
    if bytes.len() as u64 > SNAP_MAX {
        if !core::mem::replace(&mut s.too_big, true) {
            println!("[vfs-server] kept state of {} bytes does not fit its {} byte slot: not saved", bytes.len(), SNAP_MAX);
        }
        return;
    }
    let dst = s.base[kept::slot_for(gen)];
    // SAFETY: the slot is SNAP_MAX mapped bytes of this program's; the header goes last
    // (a torn copy fails its checksum anyway; this keeps the old magic invalid meanwhile)
    unsafe {
        for i in 0..SLOT_HEADER / 8 {
            core::ptr::write_volatile((dst as *mut u64).add(i), 0);
        }
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        core::ptr::copy_nonoverlapping(bytes.as_ptr().add(SLOT_HEADER), dst.add(SLOT_HEADER), bytes.len() - SLOT_HEADER);
        core::sync::atomic::compiler_fence(Ordering::SeqCst);
        for i in 0..SLOT_HEADER / 8 {
            core::ptr::write_volatile((dst as *mut u64).add(i), u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
        }
    }
    s.gen = gen;
    SAVES.fetch_add(1, Ordering::Relaxed);
}

/// Compares the tables with the kernel's live mount namespaces (see the module comment):
/// `(dropped, added)`.
pub fn resync() -> (usize, usize) {
    let _sync = NS_SYNC.lock();
    let mut ids: Vec<u64> = alloc::vec![0; 64];
    loop {
        match sys::lx_obj(LX_FH_NSLIST, ids.as_mut_ptr() as u64, ids.len() as u64, 0) {
            Ok(n) if (n as usize) <= ids.len() => {
                ids.truncate(n as usize);
                break;
            }
            Ok(n) => ids.resize(n as usize + 16, 0),
            Err(e) => {
                println!("[vfs-server] cannot list the mount namespaces ({}): tables not checked", e);
                return (0, 0);
            }
        }
    }
    let known: Vec<u64> = MTAB.lock().as_ref().map_or_else(Vec::new, |t| t.spaces.keys().copied().collect());
    let gone: Vec<u64> = known.iter().copied().filter(|k| *k != 0 && !ids.contains(k)).collect();
    let new: Vec<u64> = ids.iter().copied().filter(|k| *k != 0 && !known.contains(k)).collect();
    for &k in &gone {
        mount::on_mntns(k, LX_MNTNS_GONE, &mut *STORE.lock());
    }
    for &k in &new {
        // (made from a namespace the server does not know: a copy of the initial one)
        mount::on_mntns(k, u64::MAX - 1, &mut *STORE.lock());
    }
    if !gone.is_empty() || !new.is_empty() {
        save();
    }
    (gone.len(), new.len())
}

/// Instances that took over a kept state.
pub fn restarts() -> u64 {
    RESTARTS.load(Ordering::Relaxed)
}

/// The test hook (`LX_VFS_KTEST`): `op` 1 writes the 64 bytes at `buf` into the test file
/// (its instance and file made the first time, held open so they are never reaped), 2 reads
/// them back to `buf`. Returns [`restarts`].
pub fn ktest(cx: &Cx, op: u64, buf: u64) -> i64 {
    // (the caller's memory is read and written outside the server's locks)
    let data = if op == 1 {
        match cx.copy_in(buf, 64) {
            Ok(d) => d,
            Err(e) => return e,
        }
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    let r = (|| -> Result<i64, i64> {
        let mut store = STORE.lock();
        let mut tg = TMPFS.lock();
        let set = tg.as_mut().ok_or(EINVAL)?;
        let mut kt = KTEST.lock();
        match op {
            1 => {
                if kt.0 == 0 || set.get(kt.0).is_none() {
                    let (n, root) = set.create("", 0, 0, 1 << 30, (0, 0))?;
                    let t = set.get_mut(n).ok_or(EINVAL)?;
                    let ino = t.mknod(root, b"ktest", S_IFREG | 0o600, 0, 0, 0, (0, 0))?;
                    t.open(ino)?;
                    *kt = (n, ino);
                }
                let t = set.get_mut(kt.0).ok_or(EINVAL)?;
                t.write(kt.1, 0, &data, &mut *store as &mut dyn DataStore, (0, 0))?;
            }
            2 => {
                let t = set.get(kt.0).ok_or(ENOENT)?;
                out = t.read(kt.1, 0, 64, &mut *store as &mut dyn DataStore)?;
            }
            _ => return Err(EINVAL),
        }
        Ok(RESTARTS.load(Ordering::Relaxed) as i64)
    })();
    if op == 1 {
        // (also after a failed step: what was made is kept consistently)
        save();
    }
    if op == 2 && r.is_ok() {
        if let Err(e) = cx.copy_out(buf, &out) {
            return e;
        }
    }
    r.unwrap_or_else(|e| e)
}
