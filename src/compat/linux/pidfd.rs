//! # Process Descriptors (`pidfd_open`, `CLONE_PIDFD`)
//!
//! A descriptor naming a process: readable in `poll`/`epoll` once the process has exited,
//! usable with `pidfd_send_signal` and `waitid(P_PIDFD)`. Unlike a pid it cannot come to
//! name another process later. Process exits wake [`EXIT_WQ`].

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::task::wait::WaitQueue;

const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

const PIDFD_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC_FLAG: bool = true;

/// Woken whenever a process exits, stops or continues (pidfd readiness, `wait4`).
pub static EXIT_WQ: WaitQueue = WaitQueue::new();

/// Represents a Linux process file descriptor (`pidfd`).
pub struct PidFd {
    /// Monitored process identifier.
    pub pid: u64,
    nonblock: AtomicBool,
}

impl PidFd {
    /// Polls readiness events on this process descriptor (reports `POLLIN` when target has exited).
    pub fn poll_events(&self) -> u32 {
        if super::proc::has_exited(self.pid) {
            0x0001 // POLLIN: the process exited
        } else {
            0
        }
    }

    /// Sets or clears non-blocking behavior on this descriptor.
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Queries whether non-blocking mode is currently enabled on this descriptor.
    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}

/// Installs a pidfd for `pid` (close-on-exec, as Linux always makes them).
pub fn install(pid: u64, nonblock: bool) -> i64 {
    let fd = Arc::new(PidFd { pid, nonblock: AtomicBool::new(nonblock) });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::PidFd(fd)) {
        Ok(n) => {
            fds.set_cloexec(n, O_CLOEXEC_FLAG);
            n as i64
        }
        Err(_) => EMFILE,
    })
}

/// The process named by pidfd `fd`.
pub fn pid_of(fd: u64) -> Result<u64, i64> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::PidFd(p)) => Ok(p.pid),
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    })
}

/// `pidfd_open(pid, flags)`.
pub fn sys_pidfd_open(pid: u64, flags: u64) -> i64 {
    if flags & !PIDFD_NONBLOCK != 0 || pid as i64 <= 0 {
        return EINVAL;
    }
    if !super::proc::process_exists(pid) {
        return ESRCH;
    }
    install(pid, flags & PIDFD_NONBLOCK != 0)
}

/// `pidfd_send_signal(pidfd, sig, info, flags)` (`info` is not supported and ignored).
pub fn sys_pidfd_send_signal(fd: u64, sig: u64, _info: u64, flags: u64) -> i64 {
    if flags != 0 || sig > 64 {
        return EINVAL;
    }
    let pid = match pid_of(fd) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if super::proc::has_exited(pid) {
        return ESRCH;
    }
    if sig == 0 {
        return 0;
    }
    if super::proc::post_process(pid, sig as u32) {
        0
    } else {
        ESRCH
    }
}
