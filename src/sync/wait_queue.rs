//! # Synchronization Subsystem: FIFO Task Wait-Queue
//!
//! Provides [`WaitQueue`], the foundational FIFO queue of blocked `TaskId`s used by higher-level
//! synchronization primitives (`super::Mutex`, `super::CondVar`, `super::Semaphore`, `super::Channel`).
//!
//! ## Architectural Role & Design Rationale
//!
//! Whenever a kernel thread blocks on a contended lock, condition variable, semaphore, or channel,
//! its `TaskId` is appended to a [`WaitQueue`] (avoiding duplicate entries). When the resource
//! becomes available, [`WaitQueue::wake_one`] or [`WaitQueue::wake_all`] pops waiting task IDs in
//! FIFO order and transitions them back to `TaskState::Ready` via [`crate::task::unblock_task`].
//!
//! ## Key Types & Interfaces
//!
//! - [`WaitQueue`]: FIFO wait-queue supporting [`WaitQueue::enqueue`], [`WaitQueue::wait`],
//!   [`WaitQueue::wake_one`], and [`WaitQueue::wake_all`].
//!
//! ## Hardware & Dependency Context
//!
//! - **Allocation**: Backed by `alloc::collections::VecDeque<TaskId>`.
//! - **Scheduler**: Interacts directly with [`crate::task::SCHEDULER`], [`crate::task::block_current`],
//!   and [`crate::task::unblock_task`].

use alloc::collections::VecDeque;
use crate::task::{self, TaskId};

/// Thread-safe FIFO wait-queue for tracking blocked tasks.
#[derive(Debug, Clone, Default)]
pub struct WaitQueue {
    /// Double-ended FIFO queue of task IDs currently waiting on this queue.
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
