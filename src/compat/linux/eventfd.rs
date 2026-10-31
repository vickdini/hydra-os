//! # Linux Compatibility: Eventfd Counter Synchronization Subsystem
//!
//! Provides the `eventfd` counter-based wait/notify mechanism used extensively by
//! modern asynchronous Linux runtimes, GLib/GTK, Wayland clients, and Qt6 (`QEventLoop`).
//!
//! ## Architectural Role & Design Rationale
//! Unlike pipes which allocate a 4 KiB ring buffer to transfer arbitrary byte streams,
//! an `eventfd` maintains a single 64-bit unsigned counter in kernel space. A `read(2)`
//! consumes the counter (or decrements it by 1 in semaphore mode) and sleeps while it is
//! zero; a `write(2)` adds an 8-byte integer to the counter and sleeps if the sum would
//! exceed `u64::MAX - 1`. Both operations wake the object's [`WaitQueue`], enabling
//! ultra-lightweight cross-thread and `poll`/`epoll` event signaling.
//!
//! ## Key Types & Interfaces
//! - [`EventFd`]: In-kernel counter object with wait queue and mode flags.
//! - [`sys_eventfd2()`]: System call handler for `eventfd(2)` and `eventfd2(2)`.
//! - [`read()`] / [`write()`]: Blocking/non-blocking Linux VFS read and write entry points.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (purely logical synchronization primitive)
//! - Concurrency: Protected by [`spin::Mutex`] and synchronized via [`WaitQueue`]

use alloc::sync::Arc;
use spin::Mutex;

use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

/// Flag for `eventfd2`: provide semaphore-like semantics where each read decrements the counter by 1.
pub const EFD_SEMAPHORE: u32 = 1;
/// Flag for `eventfd2`: set non-blocking mode (`O_NONBLOCK`) on the new file description.
pub const EFD_NONBLOCK: u32 = 0x800;
/// Flag for `eventfd2`: atomically set close-on-exec (`FD_CLOEXEC`) on the new file descriptor.
pub const EFD_CLOEXEC: u32 = 0x80000;

/// Negative errno for resource temporarily unavailable / operation would block.
const EAGAIN: i64 = -11;
/// Negative errno for invalid argument or buffer smaller than 8 bytes.
const EINVAL: i64 = -22;
/// Negative errno for per-process open file descriptor table full.
const EMFILE: i64 = -24;

/// Represents an in-kernel Linux `eventfd` counter synchronization object.
///
/// # Concurrency & Thread Safety
/// Shared across threads and processes via `Arc<Mutex<EventFd>>`. Tasks blocking on
/// counter transitions sleep on `wq` outside the spinlock.
///
/// # Lifetime & Cleanup
/// Dropped automatically when all `FileDescriptor::EventFd` handles referencing it are closed.
pub struct EventFd {
    /// Current 64-bit unsigned event counter value (valid range `0..=u64::MAX - 1`).
    pub counter: u64,
    /// When `true` (`EFD_SEMAPHORE`), reads decrement `counter` by 1 instead of resetting it to 0.
    pub semaphore: bool,
    /// When `true` (`EFD_NONBLOCK`), reads on 0 and writes that would overflow return `-EAGAIN`.
    pub nonblocking: bool,
    /// Wait queue of readers and writers waiting for the counter value to change.
    pub wq: Arc<WaitQueue>,
}

impl EventFd {
    /// Creates a new [`EventFd`] object wrapped in an `Arc<Mutex<Self>>`.
    ///
    /// # Arguments
    /// * `initval` - Initial 32-bit counter value assigned to the eventfd.
    /// * `flags` - Bitmask of [`EFD_SEMAPHORE`] and [`EFD_NONBLOCK`] flags.
    ///
    /// # Returns
    /// A shared, spinlock-protected [`EventFd`] instance.
    pub fn new(initval: u32, flags: u32) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            counter: initval as u64,
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            nonblocking: (flags & EFD_NONBLOCK) != 0,
            wq: WaitQueue::new_shared(),
        }))
    }

    /// Consumes the counter according to the configured mode if the counter is non-zero.
    ///
    /// # Returns
    /// * `Some(1)` and decrements `self.counter` by 1 if `self.semaphore` is true and `counter > 0`.
    /// * `Some(counter)` and resets `self.counter` to 0 if `self.semaphore` is false and `counter > 0`.
    /// * `None` if `self.counter == 0`.
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

    /// Reads from the `eventfd` counter without blocking (Hydra-native descriptor read path).
    ///
    /// # Arguments
    /// * `buf` - Destination buffer; must be at least 8 bytes long to receive the native-endian `u64`.
    ///
    /// # Returns
    /// * `Ok(8)` on success after writing the 8-byte counter value and waking `self.wq`.
    /// * `Err(...)` if the buffer is too small or the counter is currently zero.
    ///
    /// # Errors
    /// * `"EINVAL: buffer smaller than 8 bytes"` - `buf.len() < 8`.
    /// * `"Resource temporarily unavailable (EAGAIN)"` - `self.counter == 0`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.len() < 8 {
            return Err("EINVAL: buffer smaller than 8 bytes");
        }
        let val = self.take().ok_or("Resource temporarily unavailable (EAGAIN)")?;
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        self.wq.wake_all();
        Ok(8)
    }

    /// Adds an 8-byte integer to the `eventfd` counter without blocking (Hydra-native descriptor write path).
    ///
    /// # Arguments
    /// * `data` - Source buffer containing at least 8 bytes of a native-endian `u64` increment.
    ///
    /// # Returns
    /// * `Ok(8)` on success after incrementing `self.counter` and waking `self.wq`.
    /// * `Err(...)` if the buffer is too small, the value is `u64::MAX`, or the addition would overflow.
    ///
    /// # Errors
    /// * `"EINVAL: buffer smaller than 8 bytes"` - `data.len() < 8`.
    /// * `"Invalid argument (EINVAL)"` - The written value equals `0xffff_ffff_ffff_ffff`.
    /// * `"Resource temporarily unavailable (EAGAIN)"` - Adding the value would exceed `u64::MAX - 1`.
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

    /// Evaluates `eventfd` readiness flags for `poll(2)`, `select(2)`, and `epoll(7)`.
    ///
    /// # Returns
    /// Bitmask combining `EPOLLIN` (`0x0001`) if `counter > 0` and `EPOLLOUT` (`0x0004`)
    /// if `counter < u64::MAX - 1`.
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

/// Performs a Linux VFS `read(2)` on an [`EventFd`], sleeping while the counter is zero
/// unless non-blocking mode is enabled.
///
/// # Arguments
/// * `efd` - Shared reference to the target [`EventFd`].
/// * `buf` - User buffer to populate with the 8-byte counter value.
///
/// # Returns
/// * `8` on success.
/// * `-EINVAL` if `buf.len() < 8`.
/// * `-EAGAIN` if the counter is zero and `nonblocking` is set.
/// * `ERESTARTSYS` if interrupted by a pending signal while sleeping.
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

/// Performs a Linux VFS `write(2)` on an [`EventFd`], adding the 8-byte value in `data`
/// to the counter and sleeping if the addition would overflow `u64::MAX - 1`.
///
/// # Arguments
/// * `efd` - Shared reference to the target [`EventFd`].
/// * `data` - Slice containing the 8-byte native-endian `u64` increment.
///
/// # Returns
/// * `8` on success.
/// * `-EINVAL` if `data.len() < 8` or the encoded value is `u64::MAX`.
/// * `-EAGAIN` if the counter would overflow and `nonblocking` is set.
/// * `ERESTARTSYS` if interrupted by a pending signal while sleeping.
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

/// System call handler for `eventfd(initval)` and `eventfd2(initval, flags)`.
///
/// Allocates a new [`EventFd`] instance and installs it in the calling task's file
/// descriptor table.
///
/// # Arguments
/// * `initval` - Initial counter value (`u32`).
/// * `flags` - Bitwise OR of [`EFD_SEMAPHORE`], [`EFD_NONBLOCK`], and [`EFD_CLOEXEC`].
///
/// # Returns
/// Non-negative file descriptor index on success, or `-EINVAL` / `-EMFILE` on error.
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

