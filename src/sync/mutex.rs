//! # Synchronization Subsystem: Sleep Mutex
//!
//! Implements [`Mutex<T>`], a blocking mutual exclusion primitive that suspends contended tasks
//! via a [`WaitQueue`] rather than spinning on the CPU.
//!
//! ## Architectural Role & Design Rationale
//!
//! Spinlocks are appropriate for short, non-blocking critical sections, but holding a spinlock
//! across lengthy operations wastes CPU time. [`Mutex<T>`] attempts an uncontended atomic
//! `compare_exchange` fast path and falls back to enqueuing the caller's `TaskId` in a
//! [`WaitQueue`] and invoking [`crate::task::block_current`]. When the `MutexGuard` drops,
//! it releases the lock and wakes the oldest waiting task in FIFO order.
//!
//! ## Key Types & Interfaces
//!
//! - [`Mutex<T>`]: Blocking mutual exclusion primitive with owner tracking and wait-queue integration.
//! - [`MutexGuard<'a, T>`]: RAII guard providing `Deref`/`DerefMut` access and automatic unlock on `Drop`.
//!
//! ## Hardware & Dependency Context
//!
//! - **Atomics**: Uses `AtomicBool` (`Acquire`/`Release`) for lock state and `AtomicU64` for owner PID diagnostics.
//! - **Scheduler**: Relies on [`crate::task::SCHEDULER`] and [`crate::task::block_current`].

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex as SpinLock;

use super::wait_queue::WaitQueue;
use crate::task::{self, TaskId};

/// Microkernel sleep-mutex with wait-queue task blocking.
///
/// Unlike spinlocks which burn CPU cycles while waiting, `Mutex<T>` transitions
/// contended threads into `TaskState::Blocked`, yielding execution until awakened.
pub struct Mutex<T> {
    /// Atomic flag indicating whether the mutex is currently held (`true` = locked).
    locked: AtomicBool,
    /// Task ID of the thread currently holding the mutex (`0` when unlocked).
    owner: AtomicU64,
    /// Spinlock-protected FIFO queue of tasks blocked waiting to acquire this mutex.
    waiters: SpinLock<WaitQueue>,
    /// Interior-mutable storage for the protected value `T`.
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates a new mutex protecting `data`.
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            owner: AtomicU64::new(0),
            waiters: SpinLock::new(WaitQueue::new()),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquires the mutex, blocking the calling task if contended.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let current_id = task::SCHEDULER.lock().current_task_id().0;

        loop {
            // Fast-path: Uncontended atomic acquisition
            if self
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                self.owner.store(current_id, Ordering::Relaxed);
                return MutexGuard { mutex: self };
            }

            // Slow-path: Enqueue into wait-queue and transition task to Blocked
            {
                let mut wq = self.waiters.lock();
                // Double check after acquiring internal spinlock
                if self
                    .locked
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    self.owner.store(current_id, Ordering::Relaxed);
                    return MutexGuard { mutex: self };
                }
                wq.enqueue(TaskId(current_id));
            }

            // Deschedule calling thread
            task::block_current();
        }
    }

    /// Attempts to acquire the mutex without blocking.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let current_id = task::SCHEDULER.lock().current_task_id().0;
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.owner.store(current_id, Ordering::Relaxed);
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Releases the mutex and awakens the next waiting task if any.
    fn unlock(&self) {
        self.owner.store(0, Ordering::Relaxed);
        self.locked.store(false, Ordering::Release);

        let mut wq = self.waiters.lock();
        wq.wake_one();
    }

    /// Returns the PID of the current owner, or 0 if unlocked.
    pub fn owner_pid(&self) -> u64 {
        self.owner.load(Ordering::Relaxed)
    }

    /// Returns true if the mutex is currently locked.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Returns the count of tasks currently waiting on this mutex.
    pub fn waiting_count(&self) -> usize {
        self.waiters.lock().len()
    }
}

/// RAII lock guard for `Mutex<T>`. Unlocks the mutex on drop.
pub struct MutexGuard<'a, T> {
    /// Reference to the underlying [`Mutex`] unlocked when this guard is dropped.
    pub(crate) mutex: &'a Mutex<T>,
}

impl<'a, T> Deref for MutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.data.get() }
    }
}

impl<'a, T> DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}
