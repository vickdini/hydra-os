//! # The data arena: lx-ipc's bytes in flight, kept across its restarts (wave 9, Group X3)
//!
//! Pipe bytes and the messages of Unix sockets live in one big memory object that lx-ipc
//! keeps across its own restarts (kept memory object [`crate::kstore::KEY_ARENA`]; pages
//! are made on first touch, and allocation is first-fit from the start, so only as many
//! pages are touched as are in use at the peak). A restarted lx-ipc finds the same bytes at
//! the same offsets (`docs/linux-services-design.md` 5.1: no pointers, offsets only).
//!
//! - **Units** of [`UNIT`] bytes; an allocation is a run of units. Which units are taken is
//!   known only in memory; a restarted instance rebuilds it from the chains its records name
//!   ([`Chain::restore`]): whatever no chain reaches is free.
//! - **A segment** is one allocation: a 16-byte header (`next`, data length, metadata
//!   length, units, check word), the metadata (a Unix message's descriptors and
//!   credentials), then the data.
//! - **A chain** is a queue of segments linked by `next`. Its *image* (head, offset into the
//!   head, tail, the tail's length, bytes, segments: [`Chain::image`]) goes into the owner's
//!   kept record, and that record write is the commit point: a new segment is written and
//!   linked first, then the record says it is there; a crash in between leaves the previous
//!   queue. Segments freed by a change are given back only after the owner wrote its record
//!   ([`Chain::release`]), so the record on disk never names a unit already reused.
//! - Data bytes are not checksummed (they are the programs' bytes); every header field is
//!   checked before it is trusted.
//!
//! In linux-server (which builds these files for `lx.ipc=linux`) the arena is an ordinary
//! anonymous object made on first use: the same code, nothing is kept.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::lock::YLock;

/// Bytes of an allocation unit.
pub const UNIT: usize = 256;
/// Bytes of a segment header.
pub const HDR: usize = 16;
/// Bytes of the arena (virtual: pages are made on first touch).
pub const SIZE: usize = 128 << 20;
/// Most units in one segment (the header's `units` field).
pub const MAX_SEG_UNITS: usize = 0xFFFF;
/// Most segments a restored chain may have (a damaged chain must not loop forever).
const MAX_SEGS: usize = 1 << 20;
/// Bytes of a chain's image ([`Chain::image`]).
pub const IMG: usize = 24;

const CHECK: u32 = 0x5EC7_0000;

/// The arena: its memory and which units are taken.
pub struct Arena {
    base: *mut u8,
    units: usize,
    map: YLock<Map>,
}

struct Map {
    bits: Vec<u64>,
    /// No free unit lies below this one.
    low: usize,
    used: usize,
}

// SAFETY: the memory is this process's own; the map is locked, segments belong to the
// chain that holds them (its owner's lock)
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Arena {
    /// The arena over `size` bytes at `base`, every unit free.
    ///
    /// # Safety
    ///
    /// `base` must point to `size` writable bytes owned by this process for its life.
    pub unsafe fn new(base: *mut u8, size: usize) -> Self {
        let units = size / UNIT;
        Self { base, units, map: YLock::new(Map { bits: alloc::vec![0u64; units.div_ceil(64)], low: 0, used: 0 }) }
    }

    /// Units in the arena.
    pub fn units(&self) -> usize {
        self.units
    }

    /// Units taken.
    pub fn used(&self) -> usize {
        self.map.lock().used
    }

    /// `n` free units in a row (first fit): the first one's number.
    pub fn alloc(&self, n: usize) -> Option<u32> {
        if n == 0 || n > MAX_SEG_UNITS {
            return None;
        }
        let mut m = self.map.lock();
        let mut i = m.low;
        let mut run = 0usize;
        let mut start = i;
        let mut first_free = None;
        while i < self.units {
            let w = m.bits[i / 64];
            if w == u64::MAX && i % 64 == 0 {
                run = 0;
                i += 64;
                start = i;
                continue;
            }
            if w & (1 << (i % 64)) != 0 {
                run = 0;
                i += 1;
                start = i;
                continue;
            }
            if first_free.is_none() {
                first_free = Some(i);
            }
            run += 1;
            i += 1;
            if run == n {
                for u in start..start + n {
                    m.bits[u / 64] |= 1 << (u % 64);
                }
                m.used += n;
                if first_free == Some(start) {
                    m.low = start + n;
                } else if let Some(f) = first_free {
                    m.low = f;
                }
                return Some(start as u32);
            }
        }
        if let Some(f) = first_free {
            m.low = f;
        }
        None
    }

    /// Gives back `n` units from `first`.
    pub fn free(&self, first: u32, n: usize) {
        let mut m = self.map.lock();
        let first = first as usize;
        for u in first..(first + n).min(self.units) {
            if m.bits[u / 64] & (1 << (u % 64)) != 0 {
                m.bits[u / 64] &= !(1 << (u % 64));
                m.used -= 1;
            }
        }
        if first < m.low {
            m.low = first;
        }
    }

    /// Takes `n` units from `first` for a restored segment: `false` if any is outside the
    /// arena or taken already (a damaged or shared chain).
    pub fn mark(&self, first: u32, n: usize) -> bool {
        let first = first as usize;
        if n == 0 || first.checked_add(n).is_none_or(|e| e > self.units) {
            return false;
        }
        let mut m = self.map.lock();
        if (first..first + n).any(|u| m.bits[u / 64] & (1 << (u % 64)) != 0) {
            return false;
        }
        for u in first..first + n {
            m.bits[u / 64] |= 1 << (u % 64);
        }
        m.used += n;
        if m.low >= first && m.low < first + n {
            m.low = first + n;
        }
        true
    }

    fn ptr(&self, unit: u32) -> *mut u8 {
        // SAFETY: callers pass units of their own segments (inside the arena)
        unsafe { self.base.add(unit as usize * UNIT) }
    }

    fn rd32(&self, unit: u32, off: usize) -> u32 {
        // SAFETY: within the segment's first unit
        unsafe { core::ptr::read_volatile(self.ptr(unit).add(off) as *const u32) }
    }

    fn wr32(&self, unit: u32, off: usize, v: u32) {
        // SAFETY: within the segment's first unit
        unsafe { core::ptr::write_volatile(self.ptr(unit).add(off) as *mut u32, v) }
    }

    fn check_word(unit: u32, meta: u16, units: u16) -> u32 {
        CHECK ^ unit ^ ((units as u32) << 16 | meta as u32).rotate_left(5)
    }
}

/// One segment of a chain (the in-memory copy of its header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seg {
    pub unit: u32,
    pub units: u16,
    /// Bytes of metadata before the data.
    pub meta: u16,
    /// Bytes of data.
    pub len: u32,
}

impl Seg {
    /// Bytes of data that still fit in the segment.
    fn spare(&self) -> usize {
        (self.units as usize * UNIT).saturating_sub(HDR + self.meta as usize + self.len as usize)
    }
}

/// A queue of segments (see the module comment).
#[derive(Default)]
pub struct Chain {
    pub segs: VecDeque<Seg>,
    /// Bytes of the head segment already taken.
    pub head_pos: u32,
    /// Data bytes in the chain (not counting the head's taken ones).
    pub bytes: usize,
    /// Segments taken out, given back by [`Chain::release`].
    freed: Vec<(u32, u16)>,
}

impl Chain {
    /// An empty chain.
    pub const fn new() -> Self {
        Self { segs: VecDeque::new(), head_pos: 0, bytes: 0, freed: Vec::new() }
    }

    /// Segment `i`'s data (all of it, including what the head gave already).
    pub fn data<'a>(&self, a: &'a Arena, i: usize) -> &'a [u8] {
        let s = self.segs[i];
        // SAFETY: the segment's data lies within its units
        unsafe { core::slice::from_raw_parts(a.ptr(s.unit).add(HDR + s.meta as usize), s.len as usize) }
    }

    /// Segment `i`'s metadata.
    pub fn meta<'a>(&self, a: &'a Arena, i: usize) -> &'a [u8] {
        let s = self.segs[i];
        // SAFETY: the metadata lies within the segment's units
        unsafe { core::slice::from_raw_parts(a.ptr(s.unit).add(HDR), s.meta as usize) }
    }

    /// Adds a segment with `meta` and `data`, with room for `spare` more data bytes
    /// ([`Chain::append`]): `false` if the arena is full.
    pub fn push(&mut self, a: &Arena, meta: &[u8], data: &[u8], spare: usize) -> bool {
        let need = HDR + meta.len() + data.len();
        let units = (need + spare).div_ceil(UNIT).max(need.div_ceil(UNIT)).min(MAX_SEG_UNITS);
        if meta.len() > u16::MAX as usize || need > units * UNIT || data.len() > u32::MAX as usize {
            return false;
        }
        let Some(u) = a.alloc(units) else { return false };
        let p = a.ptr(u);
        // SAFETY: the new segment's units are ours
        unsafe {
            core::ptr::copy_nonoverlapping(meta.as_ptr(), p.add(HDR), meta.len());
            core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(HDR + meta.len()), data.len());
        }
        a.wr32(u, 0, 0);
        a.wr32(u, 4, data.len() as u32);
        a.wr32(u, 8, meta.len() as u32 | (units as u32) << 16);
        a.wr32(u, 12, Arena::check_word(u, meta.len() as u16, units as u16));
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.segs.back() {
            // The old tail's length is final now (it may have grown by `append`), then the
            // link; the owner's record still names the old tail until it is written
            a.wr32(t.unit, 4, t.len);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            a.wr32(t.unit, 0, u + 1);
        }
        self.segs.push_back(Seg { unit: u, units: units as u16, meta: meta.len() as u16, len: data.len() as u32 });
        self.bytes += data.len();
        true
    }

    /// Adds up to `data.len()` bytes into the tail segment's spare room (a segment without
    /// metadata only): how many went in.
    pub fn append(&mut self, a: &Arena, data: &[u8]) -> usize {
        let Some(t) = self.segs.back_mut() else { return 0 };
        if t.meta != 0 {
            return 0;
        }
        let n = t.spare().min(data.len());
        if n == 0 {
            return 0;
        }
        // SAFETY: within the tail segment's units (its spare room)
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), a.ptr(t.unit).add(HDR + t.len as usize), n) };
        t.len += n as u32;
        self.bytes += n;
        n
    }

    /// Copies `n` data bytes from `off` bytes past the head's position into `out`.
    pub fn copy(&self, a: &Arena, off: usize, n: usize, out: &mut Vec<u8>) {
        let mut skip = off + self.head_pos as usize;
        let mut left = n;
        for i in 0..self.segs.len() {
            if left == 0 {
                break;
            }
            let d = self.data(a, i);
            if skip >= d.len() {
                skip -= d.len();
                continue;
            }
            let take = (d.len() - skip).min(left);
            out.extend_from_slice(&d[skip..skip + take]);
            left -= take;
            skip = 0;
        }
    }

    /// Takes `n` data bytes from the front (segments emptied go, their metadata with them).
    pub fn consume(&mut self, n: usize) {
        let mut left = n.min(self.bytes);
        while left > 0 {
            let Some(h) = self.segs.front() else { break };
            let avail = (h.len - self.head_pos) as usize;
            if left < avail {
                self.head_pos += left as u32;
                self.bytes -= left;
                return;
            }
            left -= avail;
            self.pop_front();
        }
    }

    /// Takes the head segment out (whatever of its data was not taken goes too).
    pub fn pop_front(&mut self) -> Option<Seg> {
        let h = self.segs.pop_front()?;
        self.bytes -= (h.len as usize).saturating_sub(self.head_pos as usize);
        self.head_pos = 0;
        self.freed.push((h.unit, h.units));
        Some(h)
    }

    /// Empties the chain.
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
        self.bytes = 0;
    }

    /// Gives the segments taken out back to the arena: call after the owner's record is
    /// written (or when nothing is kept).
    pub fn release(&mut self, a: &Arena) {
        for (u, n) in self.freed.drain(..) {
            a.free(u, n as usize);
        }
    }

    /// The chain's image for its owner's record ([`IMG`] bytes).
    pub fn image(&self) -> [u8; IMG] {
        let mut b = [0u8; IMG];
        let (head, tail, tail_len) = match (self.segs.front(), self.segs.back()) {
            (Some(h), Some(t)) => (h.unit + 1, t.unit + 1, t.len),
            _ => (0, 0, 0),
        };
        b[0..4].copy_from_slice(&head.to_le_bytes());
        b[4..8].copy_from_slice(&self.head_pos.to_le_bytes());
        b[8..12].copy_from_slice(&tail.to_le_bytes());
        b[12..16].copy_from_slice(&tail_len.to_le_bytes());
        b[16..20].copy_from_slice(&(self.bytes as u32).to_le_bytes());
        b[20..24].copy_from_slice(&(self.segs.len() as u32).to_le_bytes());
        b
    }

    /// The chain an image names, its units taken in `a`; `None` (nothing taken) if the
    /// image or any segment fails its checks.
    pub fn restore(a: &Arena, img: &[u8]) -> Option<Chain> {
        let g = |o: usize| -> Option<u32> { Some(u32::from_le_bytes(img.get(o..o + 4)?.try_into().ok()?)) };
        let (head, head_pos, tail, tail_len) = (g(0)?, g(4)?, g(8)?, g(12)?);
        let (bytes, nsegs) = (g(16)? as usize, g(20)? as usize);
        let mut c = Chain::new();
        if head == 0 {
            return (tail == 0 && bytes == 0 && nsegs == 0 && head_pos == 0).then_some(c);
        }
        if tail == 0 || nsegs == 0 || nsegs > MAX_SEGS {
            return None;
        }
        let mut u = head - 1;
        let ok = loop {
            if u as usize >= a.units() || c.segs.len() >= nsegs {
                break false;
            }
            let mw = a.rd32(u, 8);
            let (meta, units) = ((mw & 0xFFFF) as u16, (mw >> 16) as u16);
            if units == 0 || a.rd32(u, 12) != Arena::check_word(u, meta, units) || HDR + meta as usize > units as usize * UNIT {
                break false;
            }
            let last = u + 1 == tail;
            let len = if last { tail_len } else { a.rd32(u, 4) };
            if HDR + meta as usize + len as usize > units as usize * UNIT {
                break false;
            }
            if !a.mark(u, units as usize) {
                break false;
            }
            c.segs.push_back(Seg { unit: u, units, meta, len });
            if last {
                break true;
            }
            let next = a.rd32(u, 0);
            if next == 0 {
                break false;
            }
            u = next - 1;
        };
        let total: usize = c.segs.iter().map(|s| s.len as usize).sum();
        let head_ok = c.segs.front().is_some_and(|h| head_pos <= h.len);
        if !ok || c.segs.len() != nsegs || !head_ok || total - head_pos as usize != bytes {
            for s in &c.segs {
                a.free(s.unit, s.units as usize);
            }
            return None;
        }
        c.head_pos = head_pos;
        c.bytes = bytes;
        Some(c)
    }
}

// ----------------------------------------------------------------------
// The arena of this process
// ----------------------------------------------------------------------

static ARENA: spin::Once<Arena> = spin::Once::new();

/// Sets the arena (lx-ipc: its kept object, before anything is served).
///
/// # Safety
///
/// As [`Arena::new`].
pub unsafe fn init(base: *mut u8, size: usize) {
    // SAFETY: the caller's promise
    ARENA.call_once(|| unsafe { Arena::new(base, size) });
}

/// The arena: made from an anonymous object on first use when nobody set one
/// (linux-server; lx-ipc without a kept object).
pub fn get() -> &'static Arena {
    ARENA.call_once(|| {
        let p = hydra_rt::mem::MemObj::anon(SIZE as u64).and_then(|m| {
            let p = m.map(0, SIZE as u64, hydra_rt::mem::PROT_RW);
            let _ = m.into_raw();
            p
        });
        match p {
            // SAFETY: the mapping is ours for the process's life
            Ok(p) => unsafe { Arena::new(p, SIZE) },
            // SAFETY: an empty arena never touches its base
            Err(_) => unsafe { Arena::new(core::ptr::null_mut(), 0) },
        }
    })
}
