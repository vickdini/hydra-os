use super::Message;
use spin::Mutex;
use crate::sync::WaitQueue;

const QUEUE_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    Idle,
    Active,
}

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

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Sends a message into the endpoint queue (non-blocking).
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

    /// Receives a message from the endpoint queue (non-blocking).
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

    pub fn pending_count(&self) -> usize {
        self.count
    }

    pub fn waiting_receivers(&self) -> usize {
        self.recv_waiters.len()
    }

    pub fn waiting_senders(&self) -> usize {
        self.send_waiters.len()
    }
}

pub struct SharedEndpoint(Mutex<Endpoint>);

impl SharedEndpoint {
    pub const fn new(id: u32) -> Self {
        Self(Mutex::new(Endpoint::new(id)))
    }

    /// Non-blocking send.
    pub fn send(&self, msg: Message) -> Result<(), &'static str> {
        self.0.lock().send(msg)
    }

    /// Non-blocking receive.
    pub fn receive(&self) -> Option<Message> {
        self.0.lock().receive()
    }

    /// Blocking send: suspends the current task if the endpoint queue is full.
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

    /// Blocking receive: suspends the current task until a message is sent.
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

    pub fn id(&self) -> u32 {
        self.0.lock().id()
    }

    pub fn pending_count(&self) -> usize {
        self.0.lock().pending_count()
    }

    pub fn waiting_receivers(&self) -> usize {
        self.0.lock().waiting_receivers()
    }

    pub fn waiting_senders(&self) -> usize {
        self.0.lock().waiting_senders()
    }
}

/// System-wide shared IPC endpoints (IDs 0..15).
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

/// Retrieves a reference to a system endpoint by ID.
pub fn get_system_endpoint(id: u32) -> Option<&'static SharedEndpoint> {
    if (id as usize) < SYSTEM_ENDPOINTS.len() {
        Some(&SYSTEM_ENDPOINTS[id as usize])
    } else {
        None
    }
}
