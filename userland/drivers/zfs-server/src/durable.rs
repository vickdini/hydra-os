//! # Durability across a kill (wave 8, Group Z)
//!
//! The server's side of the intent log ([`crate::zil`]): what happens around each request
//! ([`before`], [`after`]), the commits the log forces, and the replay at start
//! ([`recover`]), before the endpoint is registered (clients wait for the restart meanwhile).
//!
//! Rules that keep a replay exact:
//! - every request that changed something (the DMU's change counter moved, or it changed
//!   the open handle counts) is logged after it ran and before its answer leaves;
//! - the clock is frozen for each request (live and in replay), so timestamps are equal;
//! - no commit happens in the middle of a request: the dirty-data commit
//!   (`ZfsServer::maybe_sync`, formerly inside the requests) is made here, after the log
//!   write; a request that commits by itself (`FS_SYNC`, `FS_SYNC_IF_DIRTY`, `FS_SNAPSHOT`,
//!   the checks) is not logged but followed by a commit of anything it left, then the log
//!   starts a new generation;
//! - after every commit the log starts over with the state the next requests depend on
//!   (open handle counts, unlinked-but-open objects).

use alloc::vec::Vec;
use spin::Mutex;

use crate::zfs::fsproto::*;
use crate::zfs::server::{with_server, ZfsServer};
use crate::zil::{self, Log};

/// The log's kept object: its key and size (a header page and two record areas of 20 MiB:
/// one for the current generation, the other keeps the previous one until the new header).
pub const LOG_KEY: u64 = 1;
/// See [`LOG_KEY`].
pub const LOG_BYTES: usize = zil::HDR_SIZE + 2 * 20 * 1024 * 1024;
/// A commit is made once a generation's records take this much. It is above the 16 MiB of
/// dirty data that commits anyway (as before the log), so plain writing never commits
/// earlier than without the log: a commit the log forced at 11 MiB wrote short-lived files
/// that the txgd's commit would never have seen (zfsbench append_64k: 54 -> 484 us per
/// write). Only rewriting the same blocks over and over fills the log first.
pub const COMMIT_AT: usize = 18 * 1024 * 1024;

static LOG: Mutex<Option<Log<'static>>> = Mutex::new(None);
static FROZEN: Mutex<Option<(u64, u32)>> = Mutex::new(None);

/// What the counters were when a request started.
#[derive(Clone, Copy, Debug)]
pub struct Before {
    txg: u64,
    changes: u64,
    time: (u64, u32),
    /// wave8 GB: the object allocator's state (free list head, next object number)
    alloc: (u64, u64),
}

/// The time every clock read of the current request returns (`None`: not in a request).
pub fn frozen() -> Option<(u64, u32)> {
    *FROZEN.lock()
}

fn freeze(t: (u64, u32)) {
    *FROZEN.lock() = Some(t);
}

fn thaw() {
    *FROZEN.lock() = None;
}

/// Whether there is a usable log (a kept object was given and its generation is set).
pub fn active() -> bool {
    LOG.lock().as_ref().is_some_and(|l| l.gen() != 0)
}

/// The log's size in use (0: no log).
pub fn used() -> usize {
    LOG.lock().as_ref().map_or(0, |l| l.used())
}

/// Requests that commit by themselves or are checks: never logged, followed by a commit.
fn commits_itself(op: u32) -> bool {
    matches!(op, FS_SYNC | FS_SYNC_IF_DIRTY | FS_SNAPSHOT | FS_SELFTEST | FS_VERIFY | FS_FSCK)
}

fn guid(s: &ZfsServer) -> u64 {
    s.dmu.spa.label.pool_guid
}

/// Starts a new generation at the committed txg.
fn reset(s: &ZfsServer, log: &mut Option<Log<'static>>) {
    KEEP_WRITES.lock().clear(); // wave8 GB
    if let Some(l) = log.as_mut() {
        if !l.reset(guid(s), s.dmu.ub.txg, &s.durable_state()) {
            crate::println!("[zfs-server] intent log: the server state does not fit; changes are committed one by one until the next commit");
        }
    }
}

/// Commits the open transaction group and starts a new generation of the log; `false` when
/// the commit failed (a disk error). Then a log that no longer describes the changes since
/// the pool's last commit (a request committed by itself, or a change could not be logged)
/// is disabled: a kill loses what a power loss would, never replays a log with a gap.
fn commit(s: &mut ZfsServer, log: &mut Option<Log<'static>>) -> bool {
    if s.sync().is_ok() && !s.dmu.has_pending_changes() {
        reset(s, log);
        return true;
    }
    if let Some(l) = log.as_mut() {
        if l.gen() != 0 && l.gen() != s.dmu.ub.txg {
            crate::println!("[zfs-server] intent log: commit failed after TXG #{}; log off until the next commit", s.dmu.ub.txg);
            l.disable(guid(s));
        }
    }
    false
}

/// Called before serving a request at time `now`: freezes the clock and notes the counters.
pub fn before(now: (u64, u32)) -> Before {
    let (txg, changes, alloc) = with_server(|s| Ok((s.dmu.ub.txg, s.dmu.changes, (s.dmu.ub.free_obj_head, s.dmu.ub.next_obj)))).unwrap_or((0, 0, (0, 0)));
    freeze(now);
    Before { txg, changes, time: now, alloc }
}

/// Called after serving request `op` (`req` its bytes) that answered `(status, value)`,
/// before the answer leaves: logs it if it changed something, and commits when the log or
/// the dirty data is full.
pub fn after(b: Before, op: u32, req: &[u8], status: i64, value: u64) {
    thaw();
    let mut log = LOG.lock();
    let _ = with_server(|s| {
        if s.dmu.ub.txg != b.txg || commits_itself(op) {
            commit(s, &mut log);
            return Ok(());
        }
        let changed = s.dmu.changes != b.changes || matches!(op, FS_OPEN_REF | FS_RELEASE);
        // wave8 GB: a request of the droppable kind that allocated or freed an object (a
        // write dropping a file capability frees its xattr object) must stay in the log:
        // without it, later object numbers would differ in a replay
        if object_only(op) && (s.dmu.ub.free_obj_head, s.dmu.ub.next_obj) != b.alloc && req.len() >= 8 {
            KEEP_WRITES.lock().insert(u64::from_le_bytes(req[..8].try_into().unwrap()));
        }
        // (a log switched off after a failed commit is not retried per request: the next
        // threshold or txgd commit starts it again; meanwhile a kill loses what a power
        // loss would, as before the log - review 8z)
        if changed && log.as_ref().is_some_and(|l| l.gen() != 0) {
            if let Some(l) = log.as_mut() {
                // (wave8 GB: first room made by dropping the data of files deleted since the
                // commit, then the append again)
                if !l.append(op, b.time, status, value, req) && !(reclaim(s, l) && l.append(op, b.time, status, value, req)) {
                    // No room (or no usable log): the change is made durable by a commit;
                    // if that fails too, the log (now missing this change) goes off
                    if !commit(s, &mut log) {
                        if let Some(l) = log.as_mut() {
                            if l.gen() != 0 {
                                crate::println!("[zfs-server] intent log: a change could neither be logged nor committed; log off until the next commit");
                                l.disable(guid(s));
                            }
                        }
                    }
                    return Ok(());
                }
            }
        }
        let full = log.as_ref().is_some_and(|l| l.used() > COMMIT_AT);
        let dirty = s.dmu.dirty_blocks() >= crate::zfs::dmu::DIRTY_SYNC_THRESHOLD;
        // wave8 GB: a log full of deleted files' data is compacted instead of committed
        if dirty || (full && !log.as_mut().is_some_and(|l| reclaim(s, l))) {
            commit(s, &mut log);
        }
        Ok(())
    });
}

// wave8 GB begin: the data of files deleted within a generation
/// Requests whose only effect is on the contents of the object named by their first
/// parameter (writes): once that object is freed (deleted, no handle left), replaying them
/// changes nothing a later request can see. (Not setattr/setxattr: those may create or
/// free an xattr object, which moves later object numbers.)
fn object_only(op: u32) -> bool {
    op == FS_WRITE
}

/// Objects some of whose [`object_only`] requests in the current generation allocated or
/// freed an object: their requests are never dropped (cleared at each new generation).
static KEEP_WRITES: Mutex<alloc::collections::BTreeSet<u64>> = Mutex::new(alloc::collections::BTreeSet::new());

/// Whether object `ino` was freed in the open transaction group (its dnode is the empty one
/// a free leaves, and dirty). Anything else, including an object number reused since, is
/// "not freed": its requests are kept.
fn freed(s: &mut ZfsServer, ino: u64) -> bool {
    ino != 0 && ino < s.dmu.ub.next_obj && s.dmu.is_dirty_dnode(ino) && s.dmu.get_dnode(ino).is_ok_and(|d| d.mode == 0 && d.obj_type == 0)
}

/// Drops from the current generation the requests of [`object_only`] kind whose object has
/// been freed since (appending to a file and deleting it at once filled the log with data
/// no replay needs, and the log then forced commits the dirty-data threshold never would:
/// zfsbench append_64k 51 -> 267 us per write, Group Z). Replay stays exact: the creates,
/// links and deletes stay, so object numbers come out the same; the dropped requests
/// touched only the freed object. Done only when it at least halves the log (else the
/// caller commits, as before). `true`: the log was compacted.
fn reclaim(s: &mut ZfsServer, l: &mut Log<'static>) -> bool {
    let recs = l.records();
    let keep_writes = KEEP_WRITES.lock().clone();
    let mut dead: alloc::collections::BTreeMap<u64, bool> = alloc::collections::BTreeMap::new();
    // An object number created again later in the generation (the free list reuses the
    // last freed number first) had died before: its requests up to that point are its
    // earlier life's, droppable whatever the number holds now
    let mut last_birth: alloc::collections::BTreeMap<u64, usize> = alloc::collections::BTreeMap::new();
    for (i, &(kind, op, value, _, _)) in recs.iter().enumerate() {
        if kind == zil::KIND_OP && matches!(op, FS_CREATE | FS_MKDIR | FS_MKNOD | FS_SYMLINK) && value != 0 {
            last_birth.insert(value, i);
        }
    }
    let mut keep = Vec::with_capacity(recs.len());
    let mut kept = 0usize;
    for (i, &(kind, op, _, at, len)) in recs.iter().enumerate() {
        let drop = kind == zil::KIND_OP && object_only(op) && len >= 8 && {
            let ino = u64::from_le_bytes(l.payload((at, 8)).try_into().unwrap());
            !keep_writes.contains(&ino)
                && (last_birth.get(&ino).is_some_and(|&b| b > i) || *dead.entry(ino).or_insert_with(|| freed(s, ino)))
        };
        if !drop {
            kept += zil::REC_HEAD + ((len + 7) & !7);
        }
        keep.push(!drop);
    }
    if kept > l.used() / 2 {
        return false;
    }
    let before = l.used();
    let ok = l.compact(guid(s), &keep);
    if ok {
        COMPACTIONS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        if COMPACTIONS.load(core::sync::atomic::Ordering::Relaxed) == 1 {
            crate::println!("[zfs-server] intent log: dropped deleted files' data ({} -> {} KiB) instead of a commit", before / 1024, l.used() / 1024);
        }
    }
    ok
}

/// Compactions made by [`reclaim`] (the first one is reported on the console).
pub static COMPACTIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
// wave8 GB end

/// What [`recover`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    /// The log's generation was this pool's imported txg.
    pub matched: bool,
    /// The log was given up after too many attempts.
    pub given_up: bool,
    pub replayed: zil::Replayed,
    /// The replay ended at a torn record.
    pub torn: bool,
    /// The log was of the generation before the imported txg (a kill between a commit and
    /// the log's next generation): nothing replayed, the open handle counts taken from it.
    pub handles_from_older: bool,
    /// The log's state record could not be read: nothing replayed.
    pub bad_state: bool,
    /// Changes in a log that was given up or could not be read (lost: on the console).
    pub dropped: usize,
    /// The replay differed and the commit after it failed: the log was switched off (its
    /// skipped records must never be replayed after newer ones).
    pub log_off: bool,
    /// The txg after the replay's commit.
    pub txg: u64,
}

/// At start, after the import and before the endpoint is registered: replays the log in
/// `buf` (the kept object; `existed`: it is an old instance's) if it belongs to this pool's
/// imported txg, commits the result, and keeps the log for the requests to come.
pub fn recover(buf: &'static mut [u8], existed: bool) -> Recovered {
    let mut log = Log::attach(buf);
    let mut rec = Recovered::default();
    let (pool, txg) = with_server(|s| Ok((guid(s), s.dmu.ub.txg))).unwrap_or((0, 0));
    let header = if existed { log.header() } else { None };
    let header = header.filter(|h| h.guid == pool && h.gen != 0);
    if let Some(h) = header.filter(|h| h.gen < txg) {
        // Its changes are on disk; the open handles are not: the state record and the
        // handle requests after it give them, and the unlinked ones are those with no link
        let scan = log.scan(&h);
        rec.handles_from_older = handles_only(&log, &scan);
    }
    if let Some(h) = header.filter(|h| h.gen == txg) {
        rec.matched = true;
        let scan = log.scan(&h);
        let state = scan.state.and_then(|p| zil::decode_state(log.payload(p)));
        if log.begin_replay() >= zil::MAX_ATTEMPTS {
            // Its changes are lost (on the console with their count); the open handles are
            // still taken from it (review 8z), and its area stays as it is until the
            // second commit from now
            rec.given_up = true;
            rec.dropped = scan.ops.len();
            handles_only(&log, &scan);
        } else if state.is_none() {
            rec.bad_state = true;
            rec.dropped = scan.ops.len();
        } else {
            rec.torn = scan.torn;
            if let Some(st) = state {
                let _ = with_server(|s| {
                    s.restore_durable_state(st.0, st.1);
                    Ok(())
                });
            }
            let mut out: Vec<u8> = alloc::vec![0u8; EVENT_OFFSET];
            rec.replayed = zil::replay(&log, &scan, |op, req, t| {
                freeze(t);
                let (status, value, _) = crate::serve::serve(op, req, &mut out);
                thaw();
                crate::compat::linux::inotify::take();
                (status, value)
            });
            log.resume(&h, &scan);
            let mut g = LOG.lock();
            *g = Some(log);
            let differed = rec.replayed.mismatches > 0;
            let _ = with_server(|s| {
                if !commit(s, &mut g) && differed {
                    // The skipped records are still in the log: new ones after them would
                    // never be replayed (review 8z): off until the next commit
                    if let Some(l) = g.as_mut() {
                        l.disable(guid(s));
                    }
                    rec.log_off = true;
                }
                rec.txg = s.dmu.ub.txg;
                Ok(())
            });
            return rec;
        }
    }
    let mut g = LOG.lock();
    *g = Some(log);
    let _ = with_server(|s| {
        reset(s, &mut g);
        rec.txg = s.dmu.ub.txg;
        Ok(())
    });
    rec
}

/// The open handle counts after the generation in `scan` without replaying its changes
/// (they are on disk already, or given up): its state record plus its handle requests; an
/// unlinked one is one with no link left. `false`: no readable state record.
fn handles_only(log: &Log, scan: &zil::Scan) -> bool {
    let Some((open, _)) = scan.state.and_then(|p| zil::decode_state(log.payload(p))) else { return false };
    let ops: Vec<(u32, u64)> = scan
        .ops
        .iter()
        .filter(|r| r.op == FS_OPEN_REF || r.op == FS_RELEASE)
        .map(|r| (r.op, Reader::new(log.payload(r.payload)).u64()))
        .collect();
    let open = zil::counts_after(open, &ops, FS_OPEN_REF, FS_RELEASE);
    let _ = with_server(|s| {
        let mut kept = alloc::collections::BTreeMap::new();
        let mut orphans = alloc::collections::BTreeSet::new();
        for (ino, n) in open {
            if let Ok(a) = s.getattr(ino) {
                if a.nlink == 0 {
                    orphans.insert(ino);
                }
                kept.insert(ino, n);
            }
        }
        s.restore_durable_state(kept, orphans);
        Ok(())
    });
    true
}

/// Switches the log off as a failed commit does (tests).
pub fn switch_off() {
    let mut g = LOG.lock();
    let _ = with_server(|s| {
        if let Some(l) = g.as_mut() {
            l.disable(guid(s));
        }
        Ok(())
    });
}

/// Drops the log (tests: a "killed" server's statics go with it).
pub fn detach() {
    *LOG.lock() = None;
    thaw();
}
