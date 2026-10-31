//! # Linux Eventfd Subsystem
//!
//! Provides `eventfd` counter-based wait/notify mechanism used extensively by
//! modern asynchronous Linux runtimes, Wayland clients, and Qt6 (QEventLoop).
//!
//! A read takes the counter (or one unit in semaphore mode) and waits while it is zero;
//! a write adds to it and waits while the sum would overflow. Both wake the object's wait
//! queue, so `poll`/`epoll` sleep until the counter changes.

use alloc::sync::Arc;
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK: u32 = 0x800;
pub const EFD_CLOEXEC: u32 = 0x80000;

const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

/// Represents an in-kernel Linux eventfd counter synchronization object.
pub struct EventFd {
    pub counter: u64,
    pub semaphore: bool,
    pub nonblocking: bool,
    /// Readers and writers waiting for the counter to change.
    pub wq: Arc<WaitQueue>,
}

impl EventFd {
    /// Creates a new EventFd object wrapped in an Arc<Mutex>.
    pub fn new(initval: u32, flags: u32) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            counter: initval as u64,
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            nonblocking: (flags & EFD_NONBLOCK) != 0,
            wq: WaitQueue::new_shared(),
        }))
    }

    /// Takes the value a read returns, if the counter is non-zero.
    fn take(&mut self) -> Option<u64> {
        if self.counter == 0 {
            return None;
        }
        Some(if self.semaphore {
            self.counter -= 1;
            1
        } else {
            core::mem::take(&mut self.counter)
        })
    }

    /// Reads from the eventfd counter without waiting (Hydra-native descriptor reads).
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.len() < 8 {
            return Err("EINVAL: buffer smaller than 8 bytes");
        }
        let val = self.take().ok_or("Resource temporarily unavailable (EAGAIN)")?;
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        self.wq.wake_all();
        Ok(8)
    }

    /// Adds to the counter without waiting (Hydra-native descriptor writes).
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if data.len() < 8 {
            return Err("EINVAL: buffer smaller than 8 bytes");
        }
        let val = u64::from_ne_bytes(data[..8].try_into().unwrap());
        if val == u64::MAX {
            return Err("Invalid argument (EINVAL)");
        }
        if u64::MAX - 1 - self.counter < val {
            return Err("Resource temporarily unavailable (EAGAIN)");
        }
        self.counter += val;
        self.wq.wake_all();
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

/// `read(2)`: waits while the counter is zero (unless non-blocking).
pub fn read(efd: &Arc<Mutex<EventFd>>, buf: &mut [u8]) -> i64 {
    if buf.len() < 8 {
        return EINVAL;
    }
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Shared(efd.lock().wq.clone()));
    loop {
        waits.register();
        {
            let mut e = efd.lock();
            if let Some(val) = e.take() {
                buf[..8].copy_from_slice(&val.to_ne_bytes());
                e.wq.wake_all(); // writers waiting for room
                return 8;
            }
            if e.nonblocking {
                return EAGAIN;
            }
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        waits.wait(None);
    }
}

/// `write(2)`: adds to the counter, waiting while it would overflow.
pub fn write(efd: &Arc<Mutex<EventFd>>, data: &[u8]) -> i64 {
    if data.len() < 8 {
        return EINVAL;
    }
    let val = u64::from_ne_bytes(data[..8].try_into().unwrap());
    if val == u64::MAX {
        return EINVAL;
    }
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Shared(efd.lock().wq.clone()));
    loop {
        waits.register();
        {
            let mut e = efd.lock();
            if u64::MAX - 1 - e.counter >= val {
                e.counter += val;
                e.wq.wake_all();
                return 8;
            }
            if e.nonblocking {
                return EAGAIN;
            }
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        waits.wait(None);
    }
}

/// `eventfd(initval)` and `eventfd2(initval, flags)`.
pub fn sys_eventfd2(initval: u64, flags: u64) -> i64 {
    if flags as u32 & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
        return EINVAL;
    }
    let efd = EventFd::new(initval as u32, flags as u32);
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::EventFd(efd)) {
        Ok(fd) => {
            fds.set_cloexec(fd, flags as u32 & EFD_CLOEXEC != 0);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}
