//! # Linux Compatibility: Epoll & Event Multiplexing Subsystem
//!
//! Provides the scalable I/O event notification facility (`epoll_create1`,
//! `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `poll`, `ppoll`) driving Qt6
//! (`QEventLoop`) and Wayland clients in userspace.
//!
//! ## Architectural Role & Design Rationale
//! Event-driven GUI toolkits and asynchronous runtimes monitor dozens of file descriptors
//! simultaneously (sockets, pipes, `eventfd`, `timerfd`, `signalfd`, `inotify`). This module
//! implements an `O(N)` interest list backed by a [`BTreeMap`] and integrates with Hydra's
//! [`WaitSet`](crate::task::wait::WaitSet) infrastructure so blocked threads sleep with zero CPU
//! overhead until any monitored descriptor signals readiness.
//!
//! ## Key Types & Interfaces
//! - [`EpollInstance`]: Kernel state of an open `epoll` file descriptor holding registered watches.
//! - [`LinuxEpollEvent`]: Packed 12-byte `x86_64` ABI event structure exchanged with userland.
//! - [`LinuxPollFd`]: Standard 8-byte `struct pollfd` used by `poll(2)` and `ppoll(2)`.
//! - [`epoll_wait_set()`]: Gathers wait queues across all watched file descriptors.
//! - [`epoll_collect_ready()`]: Evaluates readiness masks and handles `EPOLLONESHOT` state transitions.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (purely logical synchronization over VFS and IPC primitives)
//! - Concurrency: Protected by [`spin::Mutex`] wrapped in [`Arc`] for shared file table access

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::compat::linux::types::*;

/// Associated file descriptor is available for `read(2)` operations without blocking.
pub const EPOLLIN: u32 = 0x0001;
/// Exceptional condition or urgent out-of-band data available on the descriptor.
pub const EPOLLPRI: u32 = 0x0002;
/// Associated file descriptor is available for `write(2)` operations without blocking.
pub const EPOLLOUT: u32 = 0x0004;
/// Error condition occurred on the associated file descriptor (always monitored).
pub const EPOLLERR: u32 = 0x0008;
/// Hang up (peer closed connection or pipe write end) occurred on the descriptor (always monitored).
pub const EPOLLHUP: u32 = 0x0010;
/// Specified file descriptor is invalid or not open (`POLLNVAL` in `poll(2)`).
pub const EPOLLNVAL: u32 = 0x0020;
/// Stream socket peer closed connection, or shut down writing half of connection.
pub const EPOLLRDHUP: u32 = 0x2000;
/// Sets an exclusive wakeup mode for the `epoll` file descriptor to avoid thundering herds.
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
/// Prevents system suspend while the event is pending or being processed.
pub const EPOLLWAKEUP: u32 = 1 << 29;
/// Disables the watch after a single event is reported until re-armed via [`EPOLL_CTL_MOD`].
pub const EPOLLONESHOT: u32 = 1 << 30;
/// Requests edge-triggered notification semantics instead of the default level-triggered mode.
pub const EPOLLET: u32 = 1 << 31;

/// `epoll_ctl` operation: register a new target file descriptor on the `epoll` instance.
pub const EPOLL_CTL_ADD: i32 = 1;
/// `epoll_ctl` operation: deregister a target file descriptor from the `epoll` instance.
pub const EPOLL_CTL_DEL: i32 = 2;
/// `epoll_ctl` operation: update the event mask or user data for an existing watched descriptor.
pub const EPOLL_CTL_MOD: i32 = 3;

/// Flag for `epoll_create1`: atomically set close-on-exec (`FD_CLOEXEC`) on the new descriptor.
pub const EPOLL_CLOEXEC: u32 = 0x80000;

/// Linux `epoll_event` representation on `x86_64`.
///
/// # ABI Layout & Packing
/// Linux `x86_64` uniquely defines `struct epoll_event` with `#[repr(C, packed)]` (4-byte alignment,
/// total 12 bytes: `uint32_t events` followed immediately by `uint64_t data`) to match the 32-bit
/// compatibility layout without padding.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxEpollEvent {
    /// Bitmask of monitored or triggered event flags (e.g., [`EPOLLIN`], [`EPOLLOUT`]).
    pub events: u32,
    /// Opaque 64-bit user data (`epoll_data_t` union) returned unmodified when the event fires.
    pub data: u64,
}

/// Linux `struct pollfd` representation for `poll(2)` and `ppoll(2)` system calls.
///
/// # Concurrency & Thread Safety
/// Plain old data copied in and out of userland memory during a single `poll` invocation.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxPollFd {
    /// File descriptor index to monitor (negative values are ignored and set `revents` to 0).
    pub fd: i32,
    /// Bitmask of requested interest events (input parameter).
    pub events: i16,
    /// Bitmask of events that actually occurred on `fd` (output parameter filled by kernel).
    pub revents: i16,
}

/// Internal kernel entry representing a single file descriptor registered in an [`EpollInstance`].
///
/// # Lifecycle
/// Created by [`EPOLL_CTL_ADD`], updated by [`EPOLL_CTL_MOD`], and removed by [`EPOLL_CTL_DEL`]
/// or when the parent [`EpollInstance`] is dropped.
#[derive(Clone, Copy, Debug)]
pub struct EpollWatch {
    /// Monitored file descriptor number within the process file table.
    pub fd: i32,
    /// Bitmask of subscribed `EPOLL*` event flags.
    pub events: u32,
    /// Opaque 64-bit user token associated with this registration.
    pub data: u64,
}

/// Represents an active in-kernel `epoll` instance backing `FileDescriptor::Epoll`.
///
/// # Concurrency & Thread Safety
/// Wrapped in an `Arc<Mutex<EpollInstance>>` so multiple threads or duplicated descriptors
/// can concurrently modify the interest list via `epoll_ctl` and wait via `epoll_wait`.
///
/// # Lifetime & Cleanup
/// Automatically deallocated when the last `FileDescriptor::Epoll` reference is closed.
pub struct EpollInstance {
    /// Map from target file descriptor number to its active [`EpollWatch`] configuration.
    pub watches: BTreeMap<i32, EpollWatch>,
}

impl EpollInstance {
    /// Allocates and initializes an empty [`EpollInstance`] wrapped in an `Arc<Mutex<Self>>`.
    ///
    /// # Returns
    /// A shared, spinlock-protected reference to the newly created `epoll` instance.
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            watches: BTreeMap::new(),
        }))
    }

    /// Modifies the interest list of this `epoll` instance (`epoll_ctl(2)`).
    ///
    /// # Arguments
    /// * `op` - Control operation: [`EPOLL_CTL_ADD`], [`EPOLL_CTL_DEL`], or [`EPOLL_CTL_MOD`].
    /// * `fd` - Target file descriptor number to add, remove, or modify.
    /// * `event` - Optional [`LinuxEpollEvent`] specifying the event mask and user data token
    ///   (required for `ADD` and `MOD`; ignored for `DEL`).
    ///
    /// # Returns
    /// * `Ok(())` on successful registration, modification, or removal.
    /// * `Err(errno)` containing a negative Linux errno code on failure.
    ///
    /// # Errors
    /// * `-EEXIST` - `op` is [`EPOLL_CTL_ADD`] and `fd` is already registered in this instance.
    /// * `-ENOENT` - `op` is [`EPOLL_CTL_MOD`] or [`EPOLL_CTL_DEL`] and `fd` is not registered.
    /// * `-EINVAL` - `op` is unrecognized, or `event` is `None` for `ADD`/`MOD`.
    pub fn ctl(&mut self, op: i32, fd: i32, event: Option<LinuxEpollEvent>) -> Result<(), i64> {
        match op {
            EPOLL_CTL_ADD => {
                if self.watches.contains_key(&fd) {
                    return Err(-EEXIST);
                }
                let ev = event.ok_or(-EINVAL)?;
                self.watches.insert(fd, EpollWatch {
                    fd,
                    events: ev.events,
                    data: ev.data,
                });
                Ok(())
            }
            EPOLL_CTL_DEL => {
                if self.watches.remove(&fd).is_some() {
                    Ok(())
                } else {
                    Err(-ENOENT)
                }
            }
            EPOLL_CTL_MOD => {
                let entry = self.watches.get_mut(&fd).ok_or(-ENOENT)?;
                let ev = event.ok_or(-EINVAL)?;
                entry.events = ev.events;
                entry.data = ev.data;
                Ok(())
            }
            _ => Err(-EINVAL),
        }
    }
}

/// Builds a [`WaitSet`](crate::task::wait::WaitSet) containing the wait queues of every file
/// descriptor currently watched by `epoll` in the calling process's file table.
///
/// # Arguments
/// * `epoll` - Shared reference to the [`EpollInstance`] being waited on.
///
/// # Returns
/// A populated [`WaitSet`](crate::task::wait::WaitSet) ready for registration before sleeping.
pub fn epoll_wait_set(epoll: &Arc<Mutex<EpollInstance>>) -> crate::task::wait::WaitSet {
    let fds_watched: Vec<i32> = epoll.lock().watches.values().map(|w| w.fd).collect();
    let mut waits = crate::task::wait::WaitSet::new();
    crate::task::with_current_fds_mut(|fds| {
        for fd in fds_watched {
            if let Some(desc) = fds.get(fd as usize) {
                desc.add_wait_queues(&mut waits);
            }
        }
    });
    waits
}

/// Polls all active watches in `epoll` against the calling task's file descriptor table and
/// collects up to `maxevents` ready events.
///
/// If a watched descriptor has [`EPOLLONESHOT`] set and fires, its event mask is disarmed
/// to `EPOLLONESHOT` until explicitly re-enabled via [`EPOLL_CTL_MOD`]. If a watched
/// descriptor has been closed, `EPOLLHUP | EPOLLERR` is synthesized.
///
/// # Arguments
/// * `epoll` - Shared reference to the [`EpollInstance`] to inspect.
/// * `maxevents` - Maximum number of ready [`LinuxEpollEvent`] items to collect.
///
/// # Returns
/// A vector of triggered [`LinuxEpollEvent`] records ready to copy to userland.
pub fn epoll_collect_ready(
    epoll: &Arc<Mutex<EpollInstance>>,
    maxevents: usize,
) -> Vec<LinuxEpollEvent> {
    let mut ready = Vec::new();
    let watches: Vec<EpollWatch> = {
        let ep = epoll.lock();
        ep.watches.values().copied().collect()
    };

    let mut fired_oneshot = Vec::new();
    crate::task::with_current_fds_mut(|fds| {
        for watch in watches {
            if ready.len() >= maxevents {
                break;
            }
            if watch.events == EPOLLONESHOT {
                continue; // a one-shot watch that already fired: disabled until EPOLL_CTL_MOD
            }
            if let Some(desc) = fds.get(watch.fd as usize) {
                let current_ev = desc.poll_events();
                let matched = current_ev & (watch.events | EPOLLERR | EPOLLHUP);
                if matched != 0 {
                    ready.push(LinuxEpollEvent {
                        events: matched,
                        data: watch.data,
                    });
                    if watch.events & EPOLLONESHOT != 0 {
                        fired_oneshot.push(watch.fd);
                    }
                }
            } else {
                // FD closed while being monitored -> report EPOLLHUP | EPOLLERR
                ready.push(LinuxEpollEvent {
                    events: EPOLLHUP | EPOLLERR,
                    data: watch.data,
                });
            }
        }
    });
    if !fired_oneshot.is_empty() {
        let mut ep = epoll.lock();
        for fd in fired_oneshot {
            if let Some(w) = ep.watches.get_mut(&fd) {
                w.events = EPOLLONESHOT;
            }
        }
    }

    ready
}
