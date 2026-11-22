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

/// The log's kept object: its key and size (a header page and 16 MiB of records).
pub const LOG_KEY: u64 = 1;
/// See [`LOG_KEY`].
pub const LOG_BYTES: usize = zil::HDR_SIZE + 16 * 1024 * 1024;
/// A commit is made once the log holds this much (it is also made at 16 MiB of dirty data).
pub const COMMIT_AT: usize = 12 * 1024 * 1024;

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

/// Commits the open transaction group; the log starts over when the pool is now at a
/// newer txg than the log's records (or nothing is left uncommitted).
fn commit(s: &mut ZfsServer, log: &mut Option<Log<'static>>) {
    let _ = s.sync();
    let stale = log.as_ref().is_some_and(|l| l.gen() != s.dmu.ub.txg);
    if stale || !s.dmu.has_pending_changes() {
        reset(s, log);
    }
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
                    // No room (or no usable log): the change is made durable by a commit
                    commit(s, &mut log);
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
    if let Some(h) = header.filter(|h| h.guid == pool && h.gen == txg && h.gen != 0) {
        rec.matched = true;
        if log.begin_replay() >= zil::MAX_ATTEMPTS {
            rec.given_up = true;
        } else {
            let scan = log.scan(h.gen);
            rec.torn = scan.torn;
            if let Some(st) = scan.state.and_then(|p| zil::decode_state(log.payload(p))) {
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
            log.resume(h.gen, &scan);
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
