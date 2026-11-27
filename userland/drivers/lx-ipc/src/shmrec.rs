//! # A System V shared memory segment's kept record (wave 12, Group V)
//!
//! Each segment has a kept record of its own (`kstore`, kind [`K_SHMSEG`]): `shmget` writes
//! one small record and `IPC_RMID` clears it, instead of writing all of System V's tables
//! again (semaphores, message queues with their messages, undo lists) as one record and an
//! arena chain after every call (wave 10: about 4 us per `shmget`/`IPC_RMID`). The tables'
//! record (`K_SYSV`) keeps the semaphores, message queues and undo lists, and no segments.
//!
//! The layout (little-endian): kind, the next sequence number, id, IPC namespace, the
//! permission words (key, uid, gid, cuid, cgid, mode, seq), size, ctime, cpid.

use alloc::vec::Vec;

/// Record kind of a segment (after `kstore::K_TOKENS`).
pub const K_SHMSEG: u8 = 11;

/// What a segment's record holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegRec {
    /// The tables' next sequence number when it was written (ids made after a restart
    /// must not repeat one in use).
    pub next_seq: u16,
    pub id: i32,
    /// IPC namespace.
    pub ns: u64,
    /// key, uid, gid, cuid, cgid, mode, seq.
    pub perm: [u32; 7],
    pub size: u64,
    pub ctime: i64,
    pub cpid: u32,
}

/// Bytes of a record.
pub const LEN: usize = 1 + 4 + 4 + 8 + 7 * 4 + 8 + 8 + 4;

/// The record's bytes.
pub fn encode(r: &SegRec) -> Vec<u8> {
    let mut b = Vec::with_capacity(LEN);
    b.push(K_SHMSEG);
    b.extend_from_slice(&(r.next_seq as u32).to_le_bytes());
    b.extend_from_slice(&(r.id as u32).to_le_bytes());
    b.extend_from_slice(&r.ns.to_le_bytes());
    for p in r.perm {
        b.extend_from_slice(&p.to_le_bytes());
    }
    b.extend_from_slice(&r.size.to_le_bytes());
    b.extend_from_slice(&(r.ctime as u64).to_le_bytes());
    b.extend_from_slice(&r.cpid.to_le_bytes());
    b
}

/// A record read back: `None` unless it is a segment's record of the right length.
pub fn decode(b: &[u8]) -> Option<SegRec> {
    if b.len() != LEN || b[0] != K_SHMSEG {
        return None;
    }
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let mut perm = [0u32; 7];
    for (i, p) in perm.iter_mut().enumerate() {
        *p = u32_at(17 + i * 4);
    }
    Some(SegRec { next_seq: u32_at(1) as u16, id: u32_at(5) as i32, ns: u64_at(9), perm, size: u64_at(45), ctime: u64_at(53) as i64, cpid: u32_at(61) })
}

/// The next sequence number after a restart: the largest one the tables' record and the
/// segments' records carry (`a` and `b`; a sequence number wraps past 0xFFFF, so the one
/// ahead in that order wins).
pub fn later_seq(a: u16, b: u16) -> u16 {
    if b.wrapping_sub(a) < 0x8000 {
        b
    } else {
        a
    }
}
