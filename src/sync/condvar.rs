//! # Synchronization Subsystem: Condition Variable
//!
//! Provides [`CondVar`], a condition variable primitive that allows threads to atomically release
//! a `MutexGuard` and suspend execution until notified by another thread.
//!
//! ## Architectural Role & Design Rationale
//!
//! Condition variables allow threads to wait for arbitrary predicates protected by a [`Mutex`]
//! without polling. [`CondVar::wait`] registers the calling task in its internal [`WaitQueue`]
//! *before* dropping the `MutexGuard`, preventing lost wakeups if [`CondVar::notify_one`] or
//! [`CondVar::notify_all`] is called immediately after the mutex is unlocked.
//!
//! ## Key Types & Interfaces
//!
//! - [`CondVar`]: Condition variable supporting [`CondVar::wait`], [`CondVar::notify_one`], and [`CondVar::notify_all`].
//!
//! ## Hardware & Dependency Context
//!
//! - **Synchronization**: Pairs with `super::mutex::Mutex` and `super::wait_queue::WaitQueue`.
//! - **Scheduler**: Blocks the calling thread via [`crate::task::block_current`].

use spin::Mutex as SpinLock;

use super::mutex::{Mutex, MutexGuard};
use super::wait_queue::WaitQueue;
use crate::task::{self, TaskId};

/// Microkernel Condition Variable.
///
/// Enables threads to suspend execution until a particular condition is met,
/// atomically releasing an associated `MutexGuard` before sleeping.
pub struct CondVar {
    /// Spinlock-protected FIFO queue of tasks waiting for notification.
    waiters: SpinLock<WaitQueue>,
}

impl CondVar {
    /// Creates a new Condition Variable.
    pub const fn new() -> Self {
        Self {
            waiters: SpinLock::new(WaitQueue::new()),
        }
    }

    /// Atomically releases `guard`, blocks the calling thread on this condition variable,
    /// and re-acquires the mutex before returning.
    pub fn wait<'a, T>(&self, guard: MutexGuard<'a, T>) -> MutexGuard<'a, T> {
        let current_id = task::SCHEDULER.lock().current_task_id().0;

        // 1. Enqueue current task in condition variable wait-queue
        {
            let mut wq = self.waiters.lock();
            wq.enqueue(TaskId(current_id));
        }

        // 2. Extract mutex reference and drop guard to release lock
        let mutex_ref: &'a Mutex<T> = guard.mutex;
        drop(guard);

        // 3. Block current task until notified
        task::block_current();

        // 4. Re-acquire the mutex upon waking
        mutex_ref.lock()
    }

    /// Wakes a single waiting thread.
    pub fn notify_one(&self) {
        let mut wq = self.waiters.lock();
        wq.wake_one();
    }

    /// Wakes all waiting threads.
    pub fn notify_all(&self) -> usize {
        let mut wq = self.waiters.lock();
        wq.wake_all()
    }

    /// Returns the number of threads currently waiting on this condition variable.
    pub fn waiting_count(&self) -> usize {
        self.waiters.lock().len()
    }
}
