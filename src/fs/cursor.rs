//! # The offset of a by-path file description (wave 7, Group 7-7)
//!
//! A by-path descriptor ([`super::FileDescriptor::File`]: the pseudo-files served by name,
//! `/dev/null`, `/proc/version`, ...) is held by value in the descriptor table, so its
//! offset lives in a [`FileCursor`]: one shared counter per open file description. A `dup`
//! (and `fork`, which copies the table) clones the descriptor and with it the handle to the
//! same counter, so the copies share the offset, as Linux's file descriptions do; a new
//! `open` makes a new one.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The shared offset of one open file description.
#[derive(Clone, Debug, Default)]
pub struct FileCursor(Arc<AtomicUsize>);

impl FileCursor {
    /// A new description's offset, at `pos`.
    pub fn new(pos: usize) -> Self {
        Self(Arc::new(AtomicUsize::new(pos)))
    }

    /// The offset.
    pub fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    /// Sets the offset.
    pub fn set(&self, pos: usize) {
        self.0.store(pos, Ordering::Release);
    }

    /// Moves the offset on by `n`; the new offset.
    pub fn advance(&self, n: usize) -> usize {
        self.0.fetch_add(n, Ordering::AcqRel).wrapping_add(n)
    }

    /// The description's identity (equal for a descriptor and its `dup`s).
    pub fn id(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
}

impl PartialEq for FileCursor {
    /// Two handles to the same description.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
