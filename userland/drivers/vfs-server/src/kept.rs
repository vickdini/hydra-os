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
/// Data keys a crash may have used past the snapshot's `data_next` (an object made for a
/// change whose snapshot was never written): a new instance looks at this many and frees
/// the ones no file names. Each change makes at most one data object and is saved before it
/// is answered, so a few workers' worth is enough.
pub const SWEEP: u64 = 256;

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

/// What a new instance does with the data keys it finds: the keys the restored trees name
/// (`named`, sorted or not) and the sweep window after `data_next` give the keys to adopt
/// (named) and the ones to look at and free if they exist (the window, minus named ones).
pub fn sweep_keys(named: &[u64], data_next: u64) -> Vec<u64> {
    (data_next..data_next.saturating_add(SWEEP)).filter(|k| !named.contains(k)).collect()
}
