//! # The raw input ring's layout and its two ends (wave 8, Group I)
//!
//! One file for the kernel (the producer, `ipc/input.rs`, and its own consumer, the
//! switch-back `compat/linux/evdev.rs`), the input service (the consumer,
//! `userland/drivers/input-server`) and the host tests: a view of the ring's memory
//! ([`INPUT_RING_BYTES`]: a header page with `head`, `tail`, `drops` and a magic word, then
//! [`INPUT_RING_RECS`] records of [`INPUT_REC_SIZE`] bytes).
//!
//! `head` counts records ever appended (only the producer writes it), `tail` records ever
//! taken (only the consumer writes it); `head - tail` records wait. Producers must be
//! serialized by the caller; there is one consumer at a time.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::protocol::{InputRec, INPUT_REC_SIZE, INPUT_RING_DROPS, INPUT_RING_HEAD, INPUT_RING_MAGIC, INPUT_RING_MAGIC_OFF, INPUT_RING_RECS, INPUT_RING_REC_OFF, INPUT_RING_TAIL};

/// A view of a ring's memory.
#[derive(Clone, Copy)]
pub struct RingView {
    base: *mut u8,
}

// SAFETY: every access goes through atomics or volatile copies of whole records ordered by
// the header words
unsafe impl Send for RingView {}
unsafe impl Sync for RingView {}

/// Whether a ring with `head` appended and `tail` taken has room for one more record.
#[inline]
pub fn has_room(head: u64, tail: u64) -> bool {
    head.wrapping_sub(tail) < INPUT_RING_RECS as u64
}

/// The byte offset in the ring of record number `n`.
#[inline]
pub fn rec_off(n: u64) -> usize {
    INPUT_RING_REC_OFF + (n % INPUT_RING_RECS as u64) as usize * INPUT_REC_SIZE
}

impl RingView {
    /// A view of the ring at `base`.
    ///
    /// # Safety
    /// `base` points to [`INPUT_RING_BYTES`](super::protocol::INPUT_RING_BYTES) bytes,
    /// 8-byte aligned, that stay mapped while the view is used.
    pub const unsafe fn new(base: *mut u8) -> Self {
        Self { base }
    }

    fn word(&self, off: usize) -> &AtomicU64 {
        // SAFETY: within the header page, aligned (see `new`)
        unsafe { &*(self.base.add(off) as *const AtomicU64) }
    }

    /// Marks fresh (zeroed) ring memory as set up.
    pub fn format(&self) {
        // SAFETY: as `word`
        unsafe { (*(self.base.add(INPUT_RING_MAGIC_OFF) as *const AtomicU32)).store(INPUT_RING_MAGIC, Ordering::Release) };
    }

    /// Whether the memory was set up by [`RingView::format`].
    pub fn valid(&self) -> bool {
        // SAFETY: as `word`
        unsafe { (*(self.base.add(INPUT_RING_MAGIC_OFF) as *const AtomicU32)).load(Ordering::Acquire) == INPUT_RING_MAGIC }
    }

    /// Appends `r`; false (and one more drop counted) if the ring is full. Producers are
    /// serialized by the caller.
    pub fn push(&self, r: InputRec) -> bool {
        let head = self.word(INPUT_RING_HEAD).load(Ordering::Relaxed);
        let tail = self.word(INPUT_RING_TAIL).load(Ordering::Acquire);
        if !has_room(head, tail) {
            self.word(INPUT_RING_DROPS).fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // SAFETY: inside the records page; the slot is free (head - tail < RECS)
        unsafe { core::ptr::write_volatile(self.base.add(rec_off(head)) as *mut InputRec, r) };
        self.word(INPUT_RING_HEAD).store(head.wrapping_add(1), Ordering::Release);
        true
    }

    /// Whether records wait.
    pub fn pending(&self) -> bool {
        self.word(INPUT_RING_HEAD).load(Ordering::Acquire) != self.word(INPUT_RING_TAIL).load(Ordering::Acquire)
    }

    /// Takes every waiting record, oldest first, handing each to `f`; returns how many.
    /// The consumer's side (one at a time).
    pub fn take(&self, mut f: impl FnMut(InputRec)) -> usize {
        let head = self.word(INPUT_RING_HEAD).load(Ordering::Acquire);
        let mut tail = self.word(INPUT_RING_TAIL).load(Ordering::Acquire);
        // A torn or foreign tail (more than a ring behind or ahead): start again at the head
        if head.wrapping_sub(tail) > INPUT_RING_RECS as u64 {
            tail = head;
            self.word(INPUT_RING_TAIL).store(tail, Ordering::Release);
        }
        let mut n = 0;
        while tail != head {
            // SAFETY: inside the records page; records before `head` are complete
            let r = unsafe { core::ptr::read_volatile(self.base.add(rec_off(tail)) as *const InputRec) };
            tail = tail.wrapping_add(1);
            self.word(INPUT_RING_TAIL).store(tail, Ordering::Release);
            f(r);
            n += 1;
        }
        n
    }

    /// `(appended, taken, dropped)` so far.
    pub fn counters(&self) -> (u64, u64, u64) {
        (self.word(INPUT_RING_HEAD).load(Ordering::Acquire), self.word(INPUT_RING_TAIL).load(Ordering::Acquire), self.word(INPUT_RING_DROPS).load(Ordering::Acquire))
    }
}
