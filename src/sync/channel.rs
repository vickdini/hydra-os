//! # Synchronization Subsystem: Bounded Blocking Channel
//!
//! Implements a bounded, thread-safe multi-producer multi-consumer (MPMC) FIFO message channel
//! with both blocking ([`Channel::send`], [`Channel::recv`]) and non-blocking
//! ([`Channel::try_send`], [`Channel::try_recv`]) operations.
//!
//! ## Architectural Role & Design Rationale
//!
//! Kernel threads and service tasks communicate structured messages through bounded channels
//! to apply backpressure when a consumer falls behind. When the internal ring buffer (`VecDeque`)
//! reaches capacity, senders enqueue themselves on `send_waiters` and block; when the buffer is
//! empty, receivers enqueue themselves on `recv_waiters` and block.
//!
//! ## Key Types & Interfaces
//!
//! - [`Channel<T>`]: Bounded generic message queue supporting blocking and try-based operations.
//!
//! ## Hardware & Dependency Context
//!
//! - **Allocation**: Uses `alloc::collections::VecDeque` pre-sized to the requested capacity.
//! - **Scheduling**: Wakes blocked peers via [`WaitQueue::wake_one`] and yields via [`crate::task::block_current`].

use alloc::collections::VecDeque;
use spin::Mutex as SpinLock;

use super::wait_queue::WaitQueue;
use crate::task::{self, TaskId};

/// Bounded synchronized channel with blocking send and receive operations.
pub struct Channel<T> {
    /// Spinlock-protected ring buffer holding queued items.
    buffer: SpinLock<VecDeque<T>>,
    /// Maximum number of items the buffer can hold before senders block.
    capacity: usize,
    /// Wait-queue of sender tasks blocked waiting for free buffer space.
    send_waiters: SpinLock<WaitQueue>,
    /// Wait-queue of receiver tasks blocked waiting for items to arrive.
    recv_waiters: SpinLock<WaitQueue>,
}

impl<T> Channel<T> {
    /// Creates a bounded channel with the given buffer `capacity`.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of items the channel can buffer before blocking.
    ///
    /// # Returns
    ///
    /// An initialized [`Channel`] instance.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: SpinLock::new(VecDeque::with_capacity(capacity.max(1))),
            capacity: capacity.max(1),
            send_waiters: SpinLock::new(WaitQueue::new()),
            recv_waiters: SpinLock::new(WaitQueue::new()),
        }
    }

    /// Sends an item into the channel, blocking if the channel is full.
    ///
    /// # Arguments
    ///
    /// * `item` - The value of type `T` to push into the channel.
    pub fn send(&self, item: T) {
        let current_id = task::SCHEDULER.lock().current_task_id().0;

        loop {
            {
                let mut buf = self.buffer.lock();
                if buf.len() < self.capacity {
                    buf.push_back(item);
                    // Wake any receiver waiting for data
                    self.recv_waiters.lock().wake_one();
                    return;
                }
                // Buffer is full: enqueue sender
                self.send_waiters.lock().enqueue(TaskId(current_id));
            }

            // Block sender until space is available
            task::block_current();
        }
    }

    /// Attempts to send an item without blocking. Returns Err(item) if full.
    ///
    /// # Arguments
    ///
    /// * `item` - The value to send.
    ///
    /// # Returns
    ///
    /// `Ok(())` if stored in buffer, or `Err(item)` returning the unconsumed item if full.
    pub fn try_send(&self, item: T) -> Result<(), T> {
        let mut buf = self.buffer.lock();
        if buf.len() < self.capacity {
            buf.push_back(item);
            self.recv_waiters.lock().wake_one();
            Ok(())
        } else {
            Err(item)
        }
    }

    /// Receives an item from the channel, blocking if the channel is empty.
    ///
    /// # Returns
    ///
    /// The next available item of type `T`.
    pub fn recv(&self) -> T {
        let current_id = task::SCHEDULER.lock().current_task_id().0;

        loop {
            {
                let mut buf = self.buffer.lock();
                if let Some(item) = buf.pop_front() {
                    // Wake any sender waiting for buffer space
                    self.send_waiters.lock().wake_one();
                    return item;
                }
                // Buffer is empty: enqueue receiver
                self.recv_waiters.lock().enqueue(TaskId(current_id));
            }

            // Block receiver until data arrives
            task::block_current();
        }
    }

    /// Attempts to receive an item without blocking.
    ///
    /// # Returns
    ///
    /// `Some(T)` if available, or `None` if the buffer is currently empty.
    pub fn try_recv(&self) -> Option<T> {
        let mut buf = self.buffer.lock();
        if let Some(item) = buf.pop_front() {
            self.send_waiters.lock().wake_one();
            Some(item)
        } else {
            None
        }
    }

    /// Returns the number of items currently buffered in the channel.
    ///
    /// # Returns
    ///
    /// Item count as `usize`.
    pub fn len(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Returns true if the channel contains no items.
    ///
    /// # Returns
    ///
    /// `true` if empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.buffer.lock().is_empty()
    }

    /// Returns the capacity of the channel.
    ///
    /// # Returns
    ///
    /// Maximum capacity as `usize`.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the count of waiting receivers.
    ///
    /// # Returns
    ///
    /// Number of blocked receiver tasks.
    pub fn waiting_receivers(&self) -> usize {
        self.recv_waiters.lock().len()
    }

    /// Returns the count of waiting senders.
    ///
    /// # Returns
    ///
    /// Number of blocked sender tasks.
    pub fn waiting_senders(&self) -> usize {
        self.send_waiters.lock().len()
    }
}
