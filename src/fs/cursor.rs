//! # The offset of a by-path file description (wave 7, Group 7-7)
//!
//! A by-path descriptor ([`super::FileDescriptor::File`]: the pseudo-files served by name,
//! `/dev/null`, `/proc/version`, ...) is held by value in the descriptor table, so its
//! offset lives in a [`FileCursor`]: one shared offset per open file description. A `dup`
//! (and `fork`, which copies the table) clones the descriptor and with it the handle to the
//! same offset, so the copies share it, as Linux's file descriptions do; a new `open` makes a
//! new one.
//!
//! Reads, writes and seeks through the description are serialized ([`FileCursor::io`],
//! Linux's `f_pos_lock` for regular files), so two readers sharing it never read the same
//! bytes and a seek is never undone by a read that was in flight. The offset itself is
//! read without that lock ([`FileCursor::get`]: `/proc/self/fdinfo` of the very descriptor
//! being read must not wait for it). Offsets stay within `0..=i64::MAX` (`off_t`).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

/// `EINVAL`: a seek before the start.
const EINVAL: i64 = -22;
/// `EOVERFLOW`: a seek past `i64::MAX`.
const EOVERFLOW: i64 = -75;
/// The largest offset (`off_t`).
const MAX: usize = i64::MAX as usize;

struct Shared {
    pos: AtomicUsize,
    io: spin::Mutex<()>,
}

/// The shared offset of one open file description.
#[derive(Clone)]
pub struct FileCursor(Arc<Shared>);

impl core::fmt::Debug for FileCursor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileCursor({})", self.get())
    }
}

impl Default for FileCursor {
    fn default() -> Self {
        Self::new(0)
    }
}

impl FileCursor {
    /// A new description's offset, at `pos`.
    pub fn new(pos: usize) -> Self {
        Self(Arc::new(Shared { pos: AtomicUsize::new(pos.min(MAX)), io: spin::Mutex::new(()) }))
    }

    /// The offset (without waiting for an I/O in progress).
    pub fn get(&self) -> usize {
        self.0.pos.load(Ordering::Acquire)
    }

    /// Sets the offset (at most `i64::MAX`).
    pub fn set(&self, pos: usize) {
        let _io = self.0.io.lock();
        self.0.pos.store(pos.min(MAX), Ordering::Release);
    }

    /// Moves the offset on by `n` (at most to `i64::MAX`); the new offset.
    pub fn advance(&self, n: usize) -> usize {
        let _io = self.0.io.lock();
        self.advance_locked(n)
    }

    fn advance_locked(&self, n: usize) -> usize {
        let new = self.get().saturating_add(n).min(MAX);
        self.0.pos.store(new, Ordering::Release);
        new
    }

    /// Runs one read or write `f(offset)` with the description's I/O lock held; `f`
    /// returns the bytes done and, when it decides the new offset itself (an append), that
    /// offset. Otherwise the offset moves on by the bytes done.
    pub fn io<E>(&self, f: impl FnOnce(usize) -> Result<(usize, Option<usize>), E>) -> Result<usize, E> {
        let _io = self.0.io.lock();
        let (n, end) = f(self.get())?;
        match end {
            Some(e) => self.0.pos.store(e.min(MAX), Ordering::Release),
            None => {
                self.advance_locked(n);
            }
        }
        Ok(n)
    }

    /// Moves the offset by `delta` (`SEEK_CUR`) in one step: the new offset, `EINVAL`
    /// before the start, `EOVERFLOW` past `i64::MAX` (the offset is kept then).
    pub fn seek_by(&self, delta: i64) -> Result<usize, i64> {
        let _io = self.0.io.lock();
        let new = (self.get() as i64).checked_add(delta).ok_or(EOVERFLOW)?;
        if new < 0 {
            return Err(EINVAL);
        }
        self.0.pos.store(new as usize, Ordering::Release);
        Ok(new as usize)
    }

    /// The description's identity (equal for a descriptor and its `dup`s).
    pub fn id(&self) -> usize {
        Arc::as_ptr(&self.0) as *const u8 as usize
    }
}

impl PartialEq for FileCursor {
    /// Two handles to the same description.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
