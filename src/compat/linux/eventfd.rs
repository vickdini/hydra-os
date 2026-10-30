//! # Linux Eventfd Subsystem
//!
//! Provides `eventfd` counter-based wait/notify mechanism used extensively by
//! modern asynchronous Linux runtimes, Wayland clients, and Qt6 (QEventLoop).

use alloc::sync::Arc;
use spin::Mutex;

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK: u32 = 0x800;
pub const EFD_CLOEXEC: u32 = 0x80000;

/// Represents an in-kernel Linux eventfd counter synchronization object.
pub struct EventFd {
    pub counter: u64,
    pub semaphore: bool,
    pub nonblocking: bool,
}

impl EventFd {
    /// Creates a new EventFd object wrapped in an Arc<Mutex>.
    pub fn new(initval: u32, flags: u32) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            counter: initval as u64,
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            nonblocking: (flags & EFD_NONBLOCK) != 0,
        }))
    }

    /// Reads from the eventfd counter. Expects an 8-byte buffer.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.len() < 8 {
            return Err("EINVAL: buffer smaller than 8 bytes");
        }
        if self.counter == 0 {
            if self.nonblocking {
                return Err("Resource temporarily unavailable (EAGAIN)");
            }
            return Err("EAGAIN");
        }

        let val = if self.semaphore {
            self.counter -= 1;
            1u64
        } else {
            let v = self.counter;
            self.counter = 0;
            v
        };

        buf[..8].copy_from_slice(&val.to_ne_bytes());
        Ok(8)
    }

    /// Writes an 8-byte integer to the eventfd counter, incrementing it.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if data.len() < 8 {
            return Err("EINVAL: buffer smaller than 8 bytes");
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        let val = u64::from_ne_bytes(bytes);

        if val == u64::MAX {
            return Err("Invalid argument (EINVAL)");
        }

        if u64::MAX - 1 - self.counter < val {
            if self.nonblocking {
                return Err("Resource temporarily unavailable (EAGAIN)");
            }
            return Err("EAGAIN");
        }

        self.counter += val;
        Ok(8)
    }

    /// Evaluates eventfd readiness for poll/epoll.
    pub fn poll_events(&self) -> u32 {
        let mut ev = 0;
        if self.counter > 0 {
            ev |= 0x0001; // EPOLLIN
        }
        if self.counter < u64::MAX - 1 {
            ev |= 0x0004; // EPOLLOUT
        }
        ev
    }
}
