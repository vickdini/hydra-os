//! # Linux Epoll & Event Multiplexing Subsystem
//!
//! Provides the scalable I/O event notification facility (`epoll_create1`,
//! `epoll_ctl`, `epoll_wait`, `epoll_pwait`, `poll`, `ppoll`) driving Qt6
//! (QEventLoop) and Wayland clients in userspace.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use crate::compat::linux::types::*;

pub const EPOLLIN: u32 = 0x0001;
pub const EPOLLPRI: u32 = 0x0002;
pub const EPOLLOUT: u32 = 0x0004;
pub const EPOLLERR: u32 = 0x0008;
pub const EPOLLHUP: u32 = 0x0010;
pub const EPOLLNVAL: u32 = 0x0020;
pub const EPOLLRDHUP: u32 = 0x2000;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

pub const EPOLL_CLOEXEC: u32 = 0x80000;

/// Linux epoll event representation on x86_64.
///
/// NOTE: Linux x86_64 defines `struct epoll_event` as packed (4-byte alignment,
/// total 12 bytes: `uint32_t events` followed immediately by `uint64_t data`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxEpollEvent {
    pub events: u32,
    pub data: u64,
}

/// Linux `struct pollfd` for `poll` and `ppoll`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct LinuxPollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[derive(Clone, Copy, Debug)]
pub struct EpollWatch {
    pub fd: i32,
    pub events: u32,
    pub data: u64,
}

/// Represents an active epoll instance.
pub struct EpollInstance {
    pub watches: BTreeMap<i32, EpollWatch>,
}

impl EpollInstance {
    /// Creates a new EpollInstance wrapped in an Arc<Mutex>.
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            watches: BTreeMap::new(),
        }))
    }

    /// Modifies the interest list of this epoll instance.
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

/// Collects ready events for this epoll instance using the current process FdTable.
/// Wait set of every descriptor an epoll instance watches.
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
