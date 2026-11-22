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
    let (txg, changes) = with_server(|s| Ok((s.dmu.ub.txg, s.dmu.changes))).unwrap_or((0, 0));
    freeze(now);
    Before { txg, changes, time: now }
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
        if changed {
            if let Some(l) = log.as_mut() {
                if !l.append(op, b.time, status, value, req) {
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
        if full || s.dmu.dirty_blocks() >= crate::zfs::dmu::DIRTY_SYNC_THRESHOLD {
            commit(s, &mut log);
        }
        Ok(())
    });
}

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
        if let Some((open, _)) = scan.state.and_then(|p| zil::decode_state(log.payload(p))) {
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
                    match s.getattr(ino) {
                        Ok(a) => {
                            if a.nlink == 0 {
                                orphans.insert(ino);
                            }
                            kept.insert(ino, n);
                        }
                        Err(_) => {}
                    }
                }
                s.restore_durable_state(kept, orphans);
                Ok(())
            });
            rec.handles_from_older = true;
        }
    }
    if let Some(h) = header.filter(|h| h.gen == txg) {
        rec.matched = true;
        let scan = log.scan(&h);
        let state = scan.state.and_then(|p| zil::decode_state(log.payload(p)));
        if log.begin_replay() >= zil::MAX_ATTEMPTS {
            rec.given_up = true;
        } else if state.is_none() {
            rec.bad_state = true;
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
            let _ = with_server(|s| {
                commit(s, &mut g);
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

/// Drops the log (tests: a "killed" server's statics go with it).
pub fn detach() {
    *LOG.lock() = None;
    thaw();
}
