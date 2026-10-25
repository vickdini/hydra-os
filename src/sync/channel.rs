use alloc::collections::VecDeque;
use spin::Mutex as SpinLock;

use super::wait_queue::WaitQueue;
use crate::task::{self, TaskId};

/// Bounded synchronized channel with blocking send and receive operations.
pub struct Channel<T> {
    buffer: SpinLock<VecDeque<T>>,
    capacity: usize,
    send_waiters: SpinLock<WaitQueue>,
    recv_waiters: SpinLock<WaitQueue>,
}

impl<T> Channel<T> {
    /// Creates a bounded channel with the given buffer `capacity`.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: SpinLock::new(VecDeque::with_capacity(capacity.max(1))),
            capacity: capacity.max(1),
            send_waiters: SpinLock::new(WaitQueue::new()),
            recv_waiters: SpinLock::new(WaitQueue::new()),
        }
    }

    /// Sends an item into the channel, blocking if the channel is full.
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
    pub fn len(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Returns true if the channel contains no items.
    pub fn is_empty(&self) -> bool {
        self.buffer.lock().is_empty()
    }

    /// Returns the capacity of the channel.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the count of waiting receivers.
    pub fn waiting_receivers(&self) -> usize {
        self.recv_waiters.lock().len()
    }

    /// Returns the count of waiting senders.
    pub fn waiting_senders(&self) -> usize {
        self.send_waiters.lock().len()
    }
}
