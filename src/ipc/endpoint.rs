//! # IPC Subsystem: Rendezvous Channels & Shared Endpoints
//!
//! Provides bounded circular FIFO message queues, blocking wait queues, and thread-safe
//! shared endpoints for inter-task communication.
//!
//! ## Architectural Role & Design Rationale
//!
//! An [`Endpoint`] acts as a bidirectional communication mailbox between tasks. Each endpoint
//! manages a bounded ring buffer of 16 messages and two wait queues (`WaitQueue`): one for
//! senders waiting for buffer space when the queue is full, and one for receivers waiting for incoming
//! messages when the queue is empty.
//!
//! To support concurrent access from multiple threads and interrupt handlers, [`SharedEndpoint`] wraps
//! an [`Endpoint`] in a spinlock (`Mutex`) and provides both non-blocking (`send`, `receive`)
//! and blocking (`send_blocking`, `receive_blocking`) semantics.
//!
//! ## Key Types & Interfaces
//!
//! - `QUEUE_CAPACITY`: Maximum buffered messages per endpoint (16 messages).
//! - `EndpointState`: Lifecycle state of an endpoint channel (`Idle`, `Active`).
//! - [`Endpoint`]: Core ring-buffer communication channel.
//! - [`SharedEndpoint`]: Thread-safe wrapper around [`Endpoint`].
//! - `SYSTEM_ENDPOINTS`: Global static array of system-wide rendezvous endpoints (0..15).
//! - `get_system_endpoint`: Retrieves a reference to a system endpoint by ID.

use super::Message;
use spin::Mutex;
use crate::sync::WaitQueue;

/// Maximum number of messages that can be queued concurrently in an endpoint buffer.
pub const QUEUE_CAPACITY: usize = 16;

/// Operational lifecycle state of an IPC endpoint channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// Endpoint is idle with no active senders or receivers.
    Idle,
    /// Endpoint has active communicating tasks attached.
    Active,
}

/// Bounded circular FIFO message queue with separate sender and receiver wait queues.
pub struct Endpoint {
    id: u32,
    buffer: [Option<Message>; QUEUE_CAPACITY],
    head: usize,
    tail: usize,
    count: usize,
    send_waiters: WaitQueue,
    recv_waiters: WaitQueue,
}

impl Endpoint {
    /// Constructs a new empty endpoint with the given numeric identifier.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            buffer: [None; QUEUE_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
            send_waiters: WaitQueue::new(),
            recv_waiters: WaitQueue::new(),
        }
    }

    /// Returns the unique numeric identifier of this endpoint.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sends a message into the endpoint queue non-blockingly.
    ///
    /// # Arguments
    ///
    /// * `msg` - The message to enqueue.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Message successfully queued; wakes any sleeping receiver.
    /// * `Err("Endpoint message queue is full")` - If all 16 slots are full.
    pub fn send(&mut self, msg: Message) -> Result<(), &'static str> {
        if self.count >= QUEUE_CAPACITY {
            return Err("Endpoint message queue is full");
        }
        self.buffer[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % QUEUE_CAPACITY;
        self.count += 1;
        // Wake up a waiting receiver if any
        self.recv_waiters.wake_one();
        Ok(())
    }

    /// Receives a message from the endpoint queue non-blockingly.
    ///
    /// # Returns
    ///
    /// * `Some(Message)` - The oldest queued message; wakes any sleeping sender.
    /// * `None` - If the endpoint queue is currently empty.
    pub fn receive(&mut self) -> Option<Message> {
        if self.count == 0 {
            return None;
        }
        let msg = self.buffer[self.head].take();
        self.head = (self.head + 1) % QUEUE_CAPACITY;
        self.count -= 1;
        // Wake up a waiting sender if any
        self.send_waiters.wake_one();
        msg
    }

    /// Returns the count of pending unconsumed messages currently in the queue.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Returns the number of threads currently blocked waiting to receive from this endpoint.
    pub fn waiting_receivers(&self) -> usize {
        self.recv_waiters.len()
    }

    /// Returns the number of threads currently blocked waiting to send into this endpoint.
    pub fn waiting_senders(&self) -> usize {
        self.send_waiters.len()
    }
}

/// Thread-safe wrapper around [`Endpoint`] protected by a [`spin::Mutex`].
pub struct SharedEndpoint(Mutex<Endpoint>);

impl SharedEndpoint {
    /// Constructs a new thread-safe shared endpoint with the given identifier.
    pub const fn new(id: u32) -> Self {
        Self(Mutex::new(Endpoint::new(id)))
    }

    /// Non-blocking send: returns an error immediately if the endpoint is full.
    pub fn send(&self, msg: Message) -> Result<(), &'static str> {
        self.0.lock().send(msg)
    }

    /// Non-blocking receive: returns `None` immediately if no messages are pending.
    pub fn receive(&self) -> Option<Message> {
        self.0.lock().receive()
    }

    /// Blocking send: suspends the current task if the endpoint queue is full until space frees up.
    pub fn send_blocking(&self, msg: Message) {
        let current_id = crate::task::SCHEDULER.lock().current_task_id();
        loop {
            {
                let mut ep = self.0.lock();
                if ep.count < QUEUE_CAPACITY {
                    let _ = ep.send(msg);
                    return;
                }
                ep.send_waiters.enqueue(current_id);
            }
            // Yield CPU while waiting for buffer space
            crate::task::block_current();
        }
    }

    /// Blocking receive: suspends the current task until an incoming message is deposited.
    pub fn receive_blocking(&self) -> Message {
        let current_id = crate::task::SCHEDULER.lock().current_task_id();
        loop {
            {
                let mut ep = self.0.lock();
                if let Some(msg) = ep.receive() {
                    return msg;
                }
                ep.recv_waiters.enqueue(current_id);
            }
            // Yield CPU while waiting for an incoming message
            crate::task::block_current();
        }
    }

    /// Returns the numeric identifier of the encapsulated endpoint.
    pub fn id(&self) -> u32 {
        self.0.lock().id()
    }

    /// Returns the number of messages currently waiting in the queue.
    pub fn pending_count(&self) -> usize {
        self.0.lock().pending_count()
    }

    /// Returns the count of receivers currently blocked on this endpoint.
    pub fn waiting_receivers(&self) -> usize {
        self.0.lock().waiting_receivers()
    }

    /// Returns the count of senders currently blocked on this endpoint.
    pub fn waiting_senders(&self) -> usize {
        self.0.lock().waiting_senders()
    }
}

/// System-wide shared IPC endpoints (IDs 0..15) accessible across all tasks.
pub static SYSTEM_ENDPOINTS: [SharedEndpoint; 16] = [
    SharedEndpoint::new(0),
    SharedEndpoint::new(1),
    SharedEndpoint::new(2),
    SharedEndpoint::new(3),
    SharedEndpoint::new(4),
    SharedEndpoint::new(5),
    SharedEndpoint::new(6),
    SharedEndpoint::new(7),
    SharedEndpoint::new(8),
    SharedEndpoint::new(9),
    SharedEndpoint::new(10),
    SharedEndpoint::new(11),
    SharedEndpoint::new(12),
    SharedEndpoint::new(13),
    SharedEndpoint::new(14),
    SharedEndpoint::new(15),
];

/// Retrieves a reference to a system endpoint by its numeric ID.
pub fn get_system_endpoint(id: u32) -> Option<&'static SharedEndpoint> {
    if (id as usize) < SYSTEM_ENDPOINTS.len() {
        Some(&SYSTEM_ENDPOINTS[id as usize])
    } else {
        None
    }
}
