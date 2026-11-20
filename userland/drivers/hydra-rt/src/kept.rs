//! # Kept state: memory a Linux service keeps across its own restarts (wave 6, Group 21)
//!
//! The kernel gives each Linux service one *kept-state object* (`LX_SVC_KEPT`, see
//! [`crate::sys::lx_svc_kept`]): the first instance gets it zeroed, every later instance
//! gets the same memory back. A crash can happen in the middle of any write, and the bug
//! that crashed the service may have written garbage, so a new instance must never trust
//! it blindly (`docs/linux-services-design.md`, sections 5.1 and 10). This module is the
//! format every service uses:
//!
//! - **A header** with a magic number, the service's *layout version*, the record size and
//!   count, and a checksum of its own. A different layout (a new program version with
//!   another format) or a bad header: the whole area is reset ("fresh").
//! - **Fixed-size records, each stored twice** (copy A and B) with a sequence number, a
//!   length and a CRC-32C. A write goes to the copy that is *not* the current one and
//!   writes the checksum last, so a crash in the middle of it leaves the other copy valid:
//!   a record changes all at once or not at all (this is the "journal for changes of more
//!   than one word" of the design, per record). A record whose copies both fail their
//!   checksum is dropped and counted.
//!
//! A change that spans several records is the service's to make safe (for example: write
//! the new records first, then the one that points at them).
//!
//! **No pointers** belong in kept state: the next instance may map it at another address.
//! Store indexes and keys (a slot number, a net-server handle, a key serial).
//!
//! The code is plain `core` (no system calls), so the kernel's host tests run it.

/// The header's magic number ("HYKEPT01").
pub const MAGIC: u64 = u64::from_le_bytes(*b"HYKEPT01");

/// Bytes of the header.
pub const HEADER: usize = 64;
/// Bytes of a record copy's own fields (sequence, length, checksum, padding).
const COPY_HDR: usize = 16;

/// CRC-32C (Castagnoli), bit by bit: kept records are small and written rarely.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
        }
    }
    !crc
}

/// What [`Kept::open`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Adopted {
    /// The area was reset: new (zeroed), another layout, or a bad header. Every record is
    /// empty.
    pub fresh: bool,
    /// Records whose copies both failed their checksums (dropped: now empty).
    pub bad_records: usize,
    /// Records with data.
    pub records: usize,
}

/// A service's kept-state area, laid out as fixed-size records (see the module comment).
pub struct Kept {
    base: *mut u8,
    size: usize,
    rec_size: usize,
    count: usize,
}

// SAFETY: the area is the service's own memory; callers serialize writes themselves
unsafe impl Send for Kept {}
unsafe impl Sync for Kept {}

impl Kept {
    /// How many records of `rec_size` bytes fit in `size` bytes.
    pub const fn capacity(size: usize, rec_size: usize) -> usize {
        if size <= HEADER {
            return 0;
        }
        (size - HEADER) / (2 * (COPY_HDR + rec_size))
    }

    /// Bytes needed for `count` records of `rec_size` bytes (to ask the kernel for).
    pub const fn size_for(count: usize, rec_size: usize) -> usize {
        HEADER + count * 2 * (COPY_HDR + rec_size)
    }

    /// Takes the area of `size` bytes at `base` (the address `lx_svc_kept` returned) for
    /// records of `rec_size` bytes in layout `layout`: checks the header and every record,
    /// resets what fails.
    ///
    /// # Safety
    ///
    /// `base` must point to `size` bytes of writable memory that nothing else uses while
    /// the `Kept` lives (8-byte aligned; a page is).
    pub unsafe fn open(base: *mut u8, size: usize, layout: u32, rec_size: usize) -> (Self, Adopted) {
        let rec_size = rec_size.max(1);
        let count = Self::capacity(size, rec_size);
        let k = Self { base, size, rec_size, count };
        let mut a = Adopted::default();
        if !k.header_ok(layout) {
            k.reset(layout);
            a.fresh = true;
            return (k, a);
        }
        for i in 0..count {
            match k.current(i) {
                Some((_, len)) if len > 0 => a.records += 1,
                Some(_) => {}
                None => {
                    // Both copies are bad: the record is lost (counted), and emptied
                    a.bad_records += 1;
                    k.clear_both(i);
                }
            }
        }
        (k, a)
    }

    /// Number of records.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Record `i`'s data, if it has any.
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        if i >= self.count {
            return None;
        }
        let (c, len) = self.current(i)?;
        if len == 0 {
            return None;
        }
        // SAFETY: the copy lies within the area (checked by `capacity`)
        Some(unsafe { core::slice::from_raw_parts(self.copy_ptr(i, c).add(COPY_HDR), len) })
    }

    /// Sets record `i` to `data` (at most the record size; empty: the record is cleared),
    /// all at once: a crash in the middle leaves the previous value.
    ///
    /// # Returns
    ///
    /// `false` if `i` or `data` do not fit.
    pub fn put(&mut self, i: usize, data: &[u8]) -> bool {
        if i >= self.count || data.len() > self.rec_size {
            return false;
        }
        let (cur, seq) = match self.current(i) {
            Some((c, _)) => (c, self.seq(i, c)),
            None => (1, 0),
        };
        let other = 1 - cur;
        let p = self.copy_ptr(i, other);
        // SAFETY: the copy lies within the area; fields are written with volatile stores,
        // the checksum last (after a fence), so a torn write fails its check
        unsafe {
            core::ptr::write_volatile(p.add(12) as *mut u32, 0);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::ptr::write_volatile(p as *mut u32, seq.wrapping_add(1));
            core::ptr::write_volatile(p.add(4) as *mut u32, data.len() as u32);
            core::ptr::copy_nonoverlapping(data.as_ptr(), p.add(COPY_HDR), data.len());
            core::ptr::write_bytes(p.add(COPY_HDR + data.len()), 0, self.rec_size - data.len());
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            let crc = self.copy_crc(i, other);
            core::ptr::write_volatile(p.add(8) as *mut u32, crc);
            core::ptr::write_volatile(p.add(12) as *mut u32, 1);
        }
        true
    }

    /// Clears record `i`.
    pub fn clear(&mut self, i: usize) -> bool {
        self.put(i, &[])
    }

    /// The first record with no data, if any.
    pub fn free_record(&self) -> Option<usize> {
        (0..self.count).find(|&i| self.get(i).is_none())
    }

    // ---- internals ----

    fn hdr(&self, off: usize) -> *mut u8 {
        // SAFETY: header offsets are below HEADER <= size (callers check size first)
        unsafe { self.base.add(off) }
    }

    fn header_crc(&self) -> u32 {
        // SAFETY: the first 32 header bytes lie within the area
        crc32c(unsafe { core::slice::from_raw_parts(self.base, 32) })
    }

    fn header_ok(&self, layout: u32) -> bool {
        if self.size < HEADER || self.count == 0 {
            return false;
        }
        // SAFETY: within the header
        unsafe {
            core::ptr::read_volatile(self.hdr(0) as *const u64) == MAGIC
                && core::ptr::read_volatile(self.hdr(8) as *const u32) == layout
                && core::ptr::read_volatile(self.hdr(12) as *const u32) as usize == self.rec_size
                && core::ptr::read_volatile(self.hdr(16) as *const u32) as usize == self.count
                && core::ptr::read_volatile(self.hdr(32) as *const u32) == self.header_crc()
        }
    }

    fn reset(&self, layout: u32) {
        // SAFETY: the area is `size` bytes (the caller's promise)
        unsafe {
            core::ptr::write_bytes(self.base, 0, self.size);
            if self.size < HEADER || self.count == 0 {
                return;
            }
            core::ptr::write_volatile(self.hdr(0) as *mut u64, MAGIC);
            core::ptr::write_volatile(self.hdr(8) as *mut u32, layout);
            core::ptr::write_volatile(self.hdr(12) as *mut u32, self.rec_size as u32);
            core::ptr::write_volatile(self.hdr(16) as *mut u32, self.count as u32);
            let crc = self.header_crc();
            core::ptr::write_volatile(self.hdr(32) as *mut u32, crc);
        }
    }

    fn copy_ptr(&self, i: usize, c: usize) -> *mut u8 {
        // SAFETY: i < count and c < 2 keep the copy within the area
        unsafe { self.base.add(HEADER + (2 * i + c) * (COPY_HDR + self.rec_size)) }
    }

    fn seq(&self, i: usize, c: usize) -> u32 {
        // SAFETY: within the copy
        unsafe { core::ptr::read_volatile(self.copy_ptr(i, c) as *const u32) }
    }

    /// The checksum of copy `c` of record `i`: over its index, sequence, length and data.
    fn copy_crc(&self, i: usize, c: usize) -> u32 {
        let p = self.copy_ptr(i, c);
        // SAFETY: within the copy
        let (seq, len) = unsafe { (core::ptr::read_volatile(p as *const u32), core::ptr::read_volatile(p.add(4) as *const u32)) };
        let len = (len as usize).min(self.rec_size);
        let mut head = [0u8; 12];
        head[..4].copy_from_slice(&(i as u32).to_le_bytes());
        head[4..8].copy_from_slice(&seq.to_le_bytes());
        head[8..].copy_from_slice(&(len as u32).to_le_bytes());
        // SAFETY: within the copy
        let data = unsafe { core::slice::from_raw_parts(p.add(COPY_HDR), len) };
        crc32c(&head) ^ crc32c(data).rotate_left(7)
    }

    /// Whether copy `c` of record `i` is valid: `Some(length)`.
    fn valid(&self, i: usize, c: usize) -> Option<usize> {
        let p = self.copy_ptr(i, c);
        // SAFETY: within the copy
        let (len, crc, done) =
            unsafe { (core::ptr::read_volatile(p.add(4) as *const u32) as usize, core::ptr::read_volatile(p.add(8) as *const u32), core::ptr::read_volatile(p.add(12) as *const u32)) };
        if done == 0 {
            // Never written (both zero: an empty record), or a write that did not finish
            let seq = self.seq(i, c);
            return (seq == 0 && len == 0 && crc == 0).then_some(0);
        }
        (done == 1 && len <= self.rec_size && crc == self.copy_crc(i, c)).then_some(len)
    }

    /// The current copy of record `i` and its length: the valid copy with the higher
    /// sequence number (`None`: both copies are bad).
    fn current(&self, i: usize) -> Option<(usize, usize)> {
        match (self.valid(i, 0), self.valid(i, 1)) {
            (Some(a), Some(b)) => {
                let (sa, sb) = (self.seq(i, 0), self.seq(i, 1));
                // (sequence numbers wrap: the newer is the one just "after" the other)
                if sb.wrapping_sub(sa) as i32 > 0 {
                    Some((1, b))
                } else {
                    Some((0, a))
                }
            }
            (Some(a), None) => Some((0, a)),
            (None, Some(b)) => Some((1, b)),
            (None, None) => None,
        }
    }

    fn clear_both(&self, i: usize) {
        for c in 0..2 {
            // SAFETY: within the area
            unsafe { core::ptr::write_bytes(self.copy_ptr(i, c), 0, COPY_HDR + self.rec_size) };
        }
    }
}
