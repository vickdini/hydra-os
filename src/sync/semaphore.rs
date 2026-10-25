use core::sync::atomic::{AtomicIsize, Ordering};
use spin::Mutex as SpinLock;

use super::wait_queue::WaitQueue;
use crate::task::{self, TaskId};

/// Counting Semaphore with task blocking.
pub struct Semaphore {
    permits: AtomicIsize,
    waiters: SpinLock<WaitQueue>,
}

impl Semaphore {
    /// Creates a new semaphore with `initial_permits`.
    pub const fn new(initial_permits: isize) -> Self {
        Self {
            permits: AtomicIsize::new(initial_permits),
            waiters: SpinLock::new(WaitQueue::new()),
        }
    }

    /// Acquires a permit, blocking if none are available.
    pub fn acquire(&self) {
        let current_id = task::SCHEDULER.lock().current_task_id().0;

        loop {
            let mut current = self.permits.load(Ordering::Acquire);
            while current > 0 {
                match self.permits.compare_exchange_weak(
                    current,
                    current - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return,
                    Err(actual) => current = actual,
                }
            }

            // No permits available: register in wait-queue and block
            {
                let mut wq = self.waiters.lock();
                // Double check permits after lock
                if self.permits.load(Ordering::Acquire) > 0 {
                    continue;
                }
                wq.enqueue(TaskId(current_id));
            }

            task::block_current();
        }
    }

    /// Attempts to acquire a permit without blocking.
    pub fn try_acquire(&self) -> bool {
        let mut current = self.permits.load(Ordering::Acquire);
        while current > 0 {
            match self.permits.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    /// Releases a permit and unblocks a waiting task if any.
    pub fn release(&self) {
        self.permits.fetch_add(1, Ordering::Release);
        let mut wq = self.waiters.lock();
        wq.wake_one();
    }

    /// Returns the currently available permits.
    pub fn available_permits(&self) -> isize {
        self.permits.load(Ordering::Relaxed)
    }

    /// Returns the number of tasks waiting for a permit.
    pub fn waiting_count(&self) -> usize {
        self.waiters.lock().len()
    }
}
