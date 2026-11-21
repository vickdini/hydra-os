//! # vfs-server's kept state: the format (wave 7, Group 7-6)
//!
//! What a new instance of vfs-server finds of the old one's state (`docs/vfs-design.md`,
//! section 8.1): the mount tables of every namespace and the `tmpfs` trees (Group 7-3's
//! `MountTables::encode` and `TmpfsSet::encode`), the next `tmpfs` data key, and a few
//! counters. The file data of `tmpfs` lives in kept memory objects of its own (one per file,
//! keyed by a data key: `tmpfs_mem.rs`); only their keys are in the snapshot.
//!
//! - **Two slots.** The snapshot is written whole after every change, before the answer
//!   leaves the worker, into the older of two kept memory objects (`recover.rs`), behind a
//!   header: magic, a generation number, the length and a checksum of both. A crash in the
//!   middle of a write leaves a slot that fails its checksum; the other slot still holds the
//!   generation before, so a change is either all there or not at all.
//! - **Sections.** The body is a list of `(tag, length, bytes)`; each part is sealed and
//!   checked by its own decoder (7-3's), so a damaged part is found before it is used.
//!   Unknown tags are skipped (a newer layout adds parts without breaking older ones).
//!
//! Plain `core`/`alloc` (no system calls): the host tests (`tests/host-w7-42`) run it.

use alloc::vec::Vec;

use crate::mtab::{checksum, Dec, Enc};

const EINVAL: i64 = -22;

/// A slot's magic number ("HYVFSK01").
pub const SLOT_MAGIC: u64 = u64::from_le_bytes(*b"HYVFSK01");
/// Bytes of a slot's header: magic, generation, length, checksum.
pub const SLOT_HEADER: usize = 32;
/// The largest snapshot (the size of each slot's kept memory object; sparse: only the pages
/// written cost memory).
pub const SNAP_MAX: u64 = 64 << 20;
/// The kept-object keys of the two slots (key 0 is restart support's `LX_SVC_KEPT` object).
pub const SLOT_KEYS: [u64; 2] = [1, 2];
/// The first key of `tmpfs` data objects (keys below are the server's own).
pub const DATA_KEY_BASE: u64 = 1 << 32;

/// Section tags.
pub const TAG_MOUNTS: u32 = 1;
pub const TAG_TMPFS: u32 = 2;
pub const TAG_LOCKS: u32 = 3;
pub const TAG_COUNTERS: u32 = 4;

/// One slot's bytes: the header and `body`.
pub fn encode_slot(gen: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SLOT_HEADER + body.len());
    out.extend_from_slice(&SLOT_MAGIC.to_le_bytes());
    out.extend_from_slice(&gen.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&slot_sum(gen, body).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The checksum of a slot: the generation and the body (a torn write of either fails it).
fn slot_sum(gen: u64, body: &[u8]) -> u64 {
    checksum(&gen.to_le_bytes()) ^ checksum(body).rotate_left(1)
}

/// The generation and body of a slot, if its header and checksum agree (`b` may be longer
/// than the slot: the kept object is larger).
pub fn read_slot(b: &[u8]) -> Option<(u64, &[u8])> {
    if b.len() < SLOT_HEADER {
        return None;
    }
    let w = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    let (magic, gen, len, sum) = (w(0), w(1), w(2), w(3));
    if magic != SLOT_MAGIC || gen == 0 || len > (b.len() - SLOT_HEADER) as u64 {
        return None;
    }
    let body = &b[SLOT_HEADER..SLOT_HEADER + len as usize];
    (slot_sum(gen, body) == sum).then_some((gen, body))
}

/// The slots in the order to try them: the valid ones, newest generation first, as
/// `(slot index, generation, body)`.
pub fn by_age<'a>(slots: [&'a [u8]; 2]) -> Vec<(usize, u64, &'a [u8])> {
    let mut v: Vec<(usize, u64, &[u8])> = slots.iter().enumerate().filter_map(|(i, s)| read_slot(s).map(|(g, b)| (i, g, b))).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v
}

/// The slot the next generation `gen` is written to (the older one: generations alternate).
pub fn slot_for(gen: u64) -> usize {
    (gen % 2) as usize
}

/// What the snapshot holds besides the sealed parts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Instances that took over a kept state (the first instance: 0).
    pub restarts: u64,
    /// The next `tmpfs` data key ([`DATA_KEY_BASE`] or more).
    pub data_next: u64,
    /// The test hook's tmpfs instance and file (`LX_VFS_KTEST`; 0: none).
    pub ktest_inst: u32,
    pub ktest_ino: u64,
}

/// A snapshot: the counters and the sealed parts (each `None` if absent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub counters: Counters,
    pub mounts: Option<Vec<u8>>,
    pub tmpfs: Option<Vec<u8>>,
    pub locks: Option<Vec<u8>>,
}

impl Snapshot {
    /// The body of a slot.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        let c = &self.counters;
        let mut ce = Enc::default();
        ce.u64(c.restarts);
        ce.u64(c.data_next);
        ce.u32(c.ktest_inst);
        ce.u64(c.ktest_ino);
        section(&mut e, TAG_COUNTERS, &ce.buf);
        for (tag, part) in [(TAG_MOUNTS, &self.mounts), (TAG_TMPFS, &self.tmpfs), (TAG_LOCKS, &self.locks)] {
            if let Some(p) = part {
                section(&mut e, tag, p);
            }
        }
        e.buf
    }

    /// Reads a body back: `EINVAL` for a broken list of sections or counters (the parts
    /// themselves are checked by their own decoders), or a part given twice.
    pub fn decode(b: &[u8]) -> Result<Snapshot, i64> {
        let mut d = Dec::new(b);
        let mut s = Snapshot::default();
        let mut seen_counters = false;
        while !d.done() {
            let tag = d.u32()?;
            let part = d.bytes()?;
            let slot = match tag {
                TAG_COUNTERS => {
                    if seen_counters {
                        return Err(EINVAL);
                    }
                    seen_counters = true;
                    let mut cd = Dec::new(&part);
                    s.counters = Counters { restarts: cd.u64()?, data_next: cd.u64()?, ktest_inst: cd.u32()?, ktest_ino: cd.u64()? };
                    if s.counters.data_next < DATA_KEY_BASE {
                        return Err(EINVAL);
                    }
                    continue;
                }
                TAG_MOUNTS => &mut s.mounts,
                TAG_TMPFS => &mut s.tmpfs,
                TAG_LOCKS => &mut s.locks,
                // (a part of a newer layout)
                _ => continue,
            };
            if slot.replace(part).is_some() {
                return Err(EINVAL);
            }
        }
        if !seen_counters {
            return Err(EINVAL);
        }
        Ok(s)
    }
}

fn section(e: &mut Enc, tag: u32, part: &[u8]) {
    e.u32(tag);
    e.bytes(part);
}

/// The data objects a new instance frees: every kept object the kernel lists for the
/// service (`kept`, from `LX_MEM_KEPTKEYS`) that is a data key ([`DATA_KEY_BASE`] or above)
/// and that no restored file names (`named`). Covers objects made for changes whose snapshot
/// was never written and objects let go by a change saved just before a crash, wherever
/// their keys lie.
pub fn orphans(named: &[u64], kept: &[u64]) -> Vec<u64> {
    let named: alloc::collections::BTreeSet<u64> = named.iter().copied().collect();
    kept.iter().copied().filter(|k| *k >= DATA_KEY_BASE && !named.contains(k)).collect()
}

/// The first data key a new instance hands out: past the snapshot's `data_next` and past
/// every named key (a key taken while the last snapshot was being made may be named above
/// `data_next`), never below [`DATA_KEY_BASE`].
pub fn next_key(named: &[u64], data_next: u64) -> u64 {
    named.iter().map(|k| k.saturating_add(1)).max().unwrap_or(0).max(data_next).max(DATA_KEY_BASE)
}

/// The data keys to let go of after a restore that is given up part way: the ones the
/// kernel made new for it (`(key, existed)` as `adopt` answered); objects that existed stay
/// for the next try (another slot, or a later instance).
pub fn rollback(adopted: &[(u64, bool)]) -> Vec<u64> {
    adopted.iter().filter(|(_, existed)| !existed).map(|(k, _)| *k).collect()
}

/// Data objects let go of by changes, held until a snapshot that no longer names them is
/// written (**save before unkeep**): a crash before that snapshot leaves the files' data in
/// place for the old snapshot, and the new instance frees what no file names ([`orphans`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frees {
    pending: Vec<u64>,
}

impl Frees {
    pub const fn new() -> Frees {
        Frees { pending: Vec::new() }
    }

    /// A change let go of data key `key` (its file is gone from the tree).
    pub fn free(&mut self, key: u64) {
        self.pending.push(key);
    }

    /// Taken while the snapshot is made (under the trees' lock): the keys the snapshot does
    /// not name. Hand them to [`Frees::committed`] once it is written, or back with
    /// [`Frees::failed`].
    pub fn take(&mut self) -> Vec<u64> {
        core::mem::take(&mut self.pending)
    }

    /// The snapshot was written: these keys may be unkept now (returned for the caller).
    pub fn committed(&mut self, batch: Vec<u64>) -> Vec<u64> {
        batch
    }

    /// The snapshot was not written: the keys wait for the next one.
    pub fn failed(&mut self, batch: Vec<u64>) {
        self.pending.extend(batch);
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }
}
