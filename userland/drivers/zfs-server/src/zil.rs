//! # The intent log (wave 8, Group Z)
//!
//! zfs-server answers a change once it is in the open transaction group; the disk sees it at
//! the next commit (the kernel's txgd every 5 s, 16 MiB of dirty data, `sync`/`fsync`). A
//! kill re-imports the last committed uberblock, so without this log the changes answered
//! since that commit would be gone while programs keep running.
//!
//! The log lives in a **kept memory object** (it survives this process, not a power loss:
//! there, only what was synced survives, as before). After a request changed something
//! and before its answer leaves, the request is appended: its raw bytes as received, the
//! time the request used (the clock is frozen for each request, live and in replay), and
//! its status and value. A restarted server imports the pool, and if the log belongs to
//! that pool and to the imported transaction group, it replays the records through the same
//! request code, in order, before it registers its endpoint. Object numbers are allocated
//! from the committed free list and the next object number, so the same requests on the
//! same committed state give the same numbers (each replayed result is compared with the
//! logged one).
//!
//! ## Layout (all little-endian)
//! - **Header** (one page): magic, version, pool GUID, generation (the committed txg the
//!   records apply to), a checksum of those; then, outside the checksum, the replay attempts
//!   for this generation (one aligned 8-byte store changes it).
//! - **Records** from [`HDR_SIZE`] on, 8-byte aligned: a 64-byte head (magic, kind, payload
//!   length, sequence number, generation, time, request code, status, value, checksum of
//!   head and payload) and the payload. The first record of a generation is a
//!   [`KIND_STATE`] record (the server state the requests need besides the pool: open
//!   handle counts and unlinked-but-open objects); the others are [`KIND_OP`] requests.
//!
//! A record is valid when its magic, generation, sequence number and checksum match: the
//! first invalid one ends the log (a record torn by a kill in the middle of writing it, or
//! an older generation's record past the end).
//!
//! This module is plain logic over a byte buffer (the host tests in `tests/host-w8-z` run it
//! and the real ZFS code on a RAM pool).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// The header's size: the records start here.
pub const HDR_SIZE: usize = 4096;
/// The head of each record.
pub const REC_HEAD: usize = 64;
/// "HYDRAZIL".
pub const HDR_MAGIC: u64 = u64::from_le_bytes(*b"HYDRAZIL");
/// The format version.
pub const VERSION: u64 = 1;
/// A record's magic ("ZILR").
pub const REC_MAGIC: u32 = u32::from_le_bytes(*b"ZILR");
/// The server state at the generation's start (first record).
pub const KIND_STATE: u32 = 1;
/// A request.
pub const KIND_OP: u32 = 2;
/// Replays started for one generation after which the log is given up (it made the server
/// fail that often: a record that crashes it must not keep it from starting).
pub const MAX_ATTEMPTS: u64 = 3;

// Header offsets
const H_MAGIC: usize = 0;
const H_VERSION: usize = 8;
const H_GUID: usize = 16;
const H_GEN: usize = 24;
const H_SUM: usize = 32;
const H_ATTEMPTS: usize = 40;

/// A 64-bit checksum (two running sums over 8-byte words, Fletcher style; the tail is
/// zero-padded).
pub fn checksum(parts: &[&[u8]]) -> u64 {
    let (mut a, mut b) = (0x9E37_79B9_7F4A_7C15u64, 0u64);
    for p in parts {
        let mut chunks = p.chunks_exact(8);
        for c in &mut chunks {
            a = a.wrapping_add(u64::from_le_bytes(c.try_into().unwrap()));
            b = b.wrapping_add(a);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut w = [0u8; 8];
            w[..rest.len()].copy_from_slice(rest);
            a = a.wrapping_add(u64::from_le_bytes(w) ^ (rest.len() as u64) << 56);
            b = b.wrapping_add(a);
        }
        // (the part boundary counts: ["ab", "c"] differs from ["a", "bc"])
        a = a.wrapping_add(p.len() as u64);
        b = b.wrapping_add(a);
    }
    a ^ b.rotate_left(32)
}

fn get64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// A valid header's contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub guid: u64,
    pub gen: u64,
    pub attempts: u64,
}

/// A record found by [`Log::scan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rec {
    pub kind: u32,
    pub seq: u32,
    pub time: (u64, u32),
    pub op: u32,
    pub status: i64,
    pub value: u64,
    /// Where its payload is in the buffer.
    pub payload: (usize, usize),
}

/// What [`Log::scan`] found for one generation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scan {
    /// The state record's payload (`None`: the generation has no valid first record).
    pub state: Option<(usize, usize)>,
    /// The requests, in order.
    pub ops: Vec<Rec>,
    /// Where the valid records end (the next append goes there).
    pub end: usize,
    /// The next sequence number.
    pub next_seq: u32,
    /// Something that is not a valid record of this generation followed the last one (a
    /// torn record, or an older generation's): `true` only when it had this record's magic.
    pub torn: bool,
}

/// The log over its buffer (the mapped kept object).
pub struct Log<'a> {
    buf: &'a mut [u8],
    /// Where the next record goes.
    end: usize,
    /// Its sequence number.
    seq: u32,
    /// The current generation (0: no usable log; appends are refused).
    gen: u64,
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

impl<'a> Log<'a> {
    /// The log over `buf` (at least [`HDR_SIZE`] + one record), as yet without a generation:
    /// [`Log::reset`] or [`Log::resume`] makes it usable.
    pub fn attach(buf: &'a mut [u8]) -> Self {
        Self { buf, end: HDR_SIZE, seq: 0, gen: 0 }
    }

    /// The buffer's size.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Bytes in use (header and records).
    pub fn used(&self) -> usize {
        self.end
    }

    /// The current generation (0: none, appends are refused).
    pub fn gen(&self) -> u64 {
        self.gen
    }

    /// The header, if it is valid.
    pub fn header(&self) -> Option<Header> {
        let b = &self.buf[..HDR_SIZE];
        if get64(b, H_MAGIC) != HDR_MAGIC || get64(b, H_VERSION) != VERSION {
            return None;
        }
        if get64(b, H_SUM) != checksum(&[&b[..H_SUM]]) {
            return None;
        }
        Some(Header { guid: get64(b, H_GUID), gen: get64(b, H_GEN), attempts: get64(b, H_ATTEMPTS) })
    }

    fn write_header(&mut self, guid: u64, gen: u64) {
        let b = &mut self.buf[..HDR_SIZE];
        // (a kill in the middle leaves a header that fails its checksum: no log, which is
        // right whenever the header is written: after a commit, or with nothing logged yet)
        put64(b, H_SUM, 0);
        put64(b, H_MAGIC, HDR_MAGIC);
        put64(b, H_VERSION, VERSION);
        put64(b, H_GUID, guid);
        put64(b, H_GEN, gen);
        put64(b, H_ATTEMPTS, 0);
        let sum = checksum(&[&b[..H_SUM]]);
        put64(b, H_SUM, sum);
    }

    /// Writes one record at the end; `false` when it does not fit.
    #[allow(clippy::too_many_arguments)]
    fn put(&mut self, kind: u32, time: (u64, u32), op: u32, status: i64, value: u64, payload: &[u8]) -> bool {
        let total = REC_HEAD + align8(payload.len());
        if self.gen == 0 || payload.len() > u32::MAX as usize || self.end + total > self.buf.len() {
            return false;
        }
        let at = self.end;
        let mut head = [0u8; REC_HEAD];
        put32(&mut head, 4, kind);
        put32(&mut head, 8, payload.len() as u32);
        put32(&mut head, 12, self.seq);
        put64(&mut head, 16, self.gen);
        put64(&mut head, 24, time.0);
        put32(&mut head, 32, time.1);
        put32(&mut head, 36, op);
        put64(&mut head, 40, status as u64);
        put64(&mut head, 48, value);
        // The magic is part of the checksum but written last: a record a kill interrupted
        // has an old magic or fails its checksum
        put32(&mut head, 0, REC_MAGIC);
        let sum = checksum(&[&head[..56], payload]);
        put64(&mut head, 56, sum);
        self.buf[at + REC_HEAD..at + REC_HEAD + payload.len()].copy_from_slice(payload);
        self.buf[at + 4..at + REC_HEAD].copy_from_slice(&head[4..]);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.buf[at..at + 4].copy_from_slice(&head[..4]);
        self.end = at + total;
        self.seq = self.seq.wrapping_add(1);
        true
    }

    /// Starts generation `gen` (the transaction group just committed) of pool `guid`, with
    /// the server state `state` as its first record. The record is written before the
    /// header names the generation, so a kill in between leaves the older generation (which
    /// no import matches any more: the log is ignored, which is right after a commit).
    /// `false`: the state does not fit (the log stays unusable until the next reset).
    pub fn reset(&mut self, guid: u64, gen: u64, state: &[u8]) -> bool {
        self.end = HDR_SIZE;
        self.seq = 0;
        self.gen = gen;
        if gen == 0 || !self.put(KIND_STATE, (0, 0), 0, 0, 0, state) {
            self.gen = 0;
            self.end = HDR_SIZE;
            // (no usable log: a header no import matches)
            self.write_header(guid, 0);
            return false;
        }
        self.write_header(guid, gen);
        true
    }

    /// Appends request `op` (its raw bytes `req`) that ran at `time` and answered
    /// `(status, value)`. `false`: it does not fit, or there is no usable log (the caller
    /// commits instead).
    pub fn append(&mut self, op: u32, time: (u64, u32), status: i64, value: u64, req: &[u8]) -> bool {
        self.put(KIND_OP, time, op, status, value, req)
    }

    /// The valid records of generation `gen` (the header is not checked: see
    /// [`Log::header`]).
    pub fn scan(&self, gen: u64) -> Scan {
        let mut s = Scan { end: HDR_SIZE, ..Scan::default() };
        let mut at = HDR_SIZE;
        let mut seq = 0u32;
        while at + REC_HEAD <= self.buf.len() {
            let h = &self.buf[at..at + REC_HEAD];
            if get32(h, 0) != REC_MAGIC {
                break;
            }
            let len = get32(h, 8) as usize;
            let total = REC_HEAD + align8(len);
            let ok = at + total <= self.buf.len()
                && get32(h, 12) == seq
                && get64(h, 16) == gen
                && get64(h, 56) == checksum(&[&h[..56], &self.buf[at + REC_HEAD..at + REC_HEAD + len]]);
            if !ok {
                s.torn = true;
                break;
            }
            let kind = get32(h, 4);
            let rec = Rec {
                kind,
                seq,
                time: (get64(h, 24), get32(h, 32)),
                op: get32(h, 36),
                status: get64(h, 40) as i64,
                value: get64(h, 48),
                payload: (at + REC_HEAD, len),
            };
            match (seq, kind) {
                (0, KIND_STATE) => s.state = Some(rec.payload),
                (n, KIND_OP) if n > 0 => s.ops.push(rec),
                // (a state record anywhere else, an op first, an unknown kind: not this log)
                _ => {
                    s.torn = true;
                    break;
                }
            }
            at += total;
            seq = seq.wrapping_add(1);
        }
        if s.state.is_none() {
            s.ops.clear();
            at = HDR_SIZE;
            seq = 0;
        }
        s.end = at;
        s.next_seq = seq;
        s
    }

    /// A record's payload.
    pub fn payload(&self, r: (usize, usize)) -> &[u8] {
        &self.buf[r.0..r.0 + r.1]
    }

    /// Counts one more replay attempt for the current header (one 8-byte store); returns
    /// the attempts before this one.
    pub fn begin_replay(&mut self) -> u64 {
        let n = get64(self.buf, H_ATTEMPTS);
        put64(self.buf, H_ATTEMPTS, n + 1);
        n
    }

    /// Continues generation `gen` after a replay: appends go after the records
    /// [`Log::scan`] found (the attempts count stays until the next [`Log::reset`], which
    /// the commit after a replay makes).
    pub fn resume(&mut self, gen: u64, scan: &Scan) {
        self.gen = gen;
        self.end = scan.end;
        self.seq = scan.next_seq;
    }
}

/// The server state a generation starts from: open handle counts and the unlinked objects
/// kept for their open handles (replayed `FS_RELEASE`/`FS_UNLINK` depend on them).
pub fn encode_state(open: &BTreeMap<u64, u32>, orphans: &BTreeSet<u64>) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + open.len() * 12 + orphans.len() * 8);
    v.extend_from_slice(&(open.len() as u64).to_le_bytes());
    for (ino, n) in open {
        v.extend_from_slice(&ino.to_le_bytes());
        v.extend_from_slice(&n.to_le_bytes());
    }
    v.extend_from_slice(&(orphans.len() as u64).to_le_bytes());
    for ino in orphans {
        v.extend_from_slice(&ino.to_le_bytes());
    }
    v
}

/// [`encode_state`]'s inverse (`None`: not a state record).
pub fn decode_state(b: &[u8]) -> Option<(BTreeMap<u64, u32>, BTreeSet<u64>)> {
    let n = get64(b.get(..8)?, 0) as usize;
    let mut at = 8;
    let mut open = BTreeMap::new();
    for _ in 0..n {
        let r = b.get(at..at + 12)?;
        open.insert(get64(r, 0), get32(r, 8));
        at += 12;
    }
    let m = get64(b.get(at..at + 8)?, 0) as usize;
    at += 8;
    let mut orphans = BTreeSet::new();
    for _ in 0..m {
        orphans.insert(get64(b.get(at..at + 8)?, 0));
        at += 8;
    }
    (at == b.len()).then_some((open, orphans))
}

/// What a replay did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Replayed {
    /// Requests applied.
    pub applied: usize,
    /// Requests whose result differed from the logged one.
    pub mismatches: usize,
    /// The first such request's sequence number (0: none).
    pub first_mismatch: u32,
}

/// Replays `scan`'s requests in order through `apply(op, request bytes, time) -> (status,
/// value)` and compares each result with the logged one.
pub fn replay(log: &Log, scan: &Scan, mut apply: impl FnMut(u32, &[u8], (u64, u32)) -> (i64, u64)) -> Replayed {
    let mut r = Replayed::default();
    for rec in &scan.ops {
        let got = apply(rec.op, log.payload(rec.payload), rec.time);
        r.applied += 1;
        if got != (rec.status, rec.value) {
            if r.mismatches == 0 {
                r.first_mismatch = rec.seq;
            }
            r.mismatches += 1;
        }
    }
    r
}
