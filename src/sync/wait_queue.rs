use alloc::collections::VecDeque;
use crate::task::{self, TaskId};

/// Thread-safe FIFO wait-queue for tracking blocked tasks.
#[derive(Debug, Clone, Default)]
pub struct WaitQueue {
    waiters: VecDeque<TaskId>,
}

impl WaitQueue {
    /// Creates a new empty wait-queue.
    pub const fn new() -> Self {
        Self {
            waiters: VecDeque::new(),
        }
    }

    /// Enqueues a specific task ID into the wait-queue.
    pub fn enqueue(&mut self, id: TaskId) {
        if !self.waiters.contains(&id) {
            self.waiters.push_back(id);
        }
    }

    /// Enqueues the currently executing task and transitions it to `TaskState::Blocked`.
    ///
    /// The caller yields the CPU immediately and will not be scheduled until awakened
    /// by `wake_one()` or `wake_all()`.
    pub fn wait(&mut self) -> TaskId {
        let current_id = task::SCHEDULER.lock().current_task_id();
        self.enqueue(current_id);
        task::block_current()
    }

    /// Wakes the oldest task in the wait-queue (FIFO order).
    ///
    /// Returns the `TaskId` of the awakened task, or `None` if the queue was empty.
    pub fn wake_one(&mut self) -> Option<TaskId> {
        while let Some(id) = self.waiters.pop_front() {
            if task::unblock_task(id) {
                return Some(id);
            }
        }
        None
    }

    /// Wakes all waiting tasks in the queue.
    ///
    /// Returns the count of successfully unblocked tasks.
    pub fn wake_all(&mut self) -> usize {
        let mut count = 0;
        while let Some(id) = self.waiters.pop_front() {
            if task::unblock_task(id) {
                count += 1;
            }
        }
        count
    }

    /// Returns true if there are no waiting tasks.
    pub fn is_empty(&self) -> bool {
        self.waiters.is_empty()
    }

    /// Returns the number of tasks currently waiting.
    pub fn len(&self) -> usize {
        self.waiters.len()
    }
}
