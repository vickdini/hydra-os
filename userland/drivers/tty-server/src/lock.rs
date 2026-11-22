//! A spin lock for the server's threads that yields the CPU while it waits: the holder may
//! have been preempted in user mode, and spinning would only burn the waiter's timeslice.

use core::ops::{Deref, DerefMut};

/// A lock around a `T`.
pub struct YLock<T> {
    inner: spin::Mutex<T>,
}

/// Holds a [`YLock`] until dropped.
pub struct YGuard<'a, T> {
    g: spin::MutexGuard<'a, T>,
}

impl<T> YLock<T> {
    /// A lock holding `v`.
    pub const fn new(v: T) -> Self {
        Self { inner: spin::Mutex::new(v) }
    }

    /// Takes the lock: spins a little, then yields between attempts.
    pub fn lock(&self) -> YGuard<'_, T> {
        let mut spins = 0u32;
        loop {
            if let Some(g) = self.inner.try_lock() {
                return YGuard { g };
            }
            spins += 1;
            if spins < 64 {
                core::hint::spin_loop();
            } else {
                spins = 0;
                hydra_rt::sys::yield_now();
            }
        }
    }
}

impl<T> Deref for YGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.g
    }
}

impl<T> DerefMut for YGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.g
    }
}
