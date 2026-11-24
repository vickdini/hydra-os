//! # Process Descriptors (`pidfd_open`, `CLONE_PIDFD`)
//!
//! A descriptor naming a process: readable in `poll`/`epoll` once the process has exited,
//! usable with `pidfd_send_signal` and `waitid(P_PIDFD)`. Unlike a pid it cannot come to
//! name another process later. Process exits wake [`EXIT_WQ`].


use crate::task::wait::WaitQueue;

const ESRCH: i64 = -3;
const EPERM: i64 = -1;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;

/// Woken whenever a process exits, stops or continues (pidfd readiness, `wait4`).
pub static EXIT_WQ: WaitQueue = WaitQueue::new();

/// Retrieves the process ID tracked by a pidfd.
///
/// # Arguments
///
/// * `fd` - File descriptor index of the pidfd.
///
/// # Returns
///
/// * `Ok(pid)` containing the monitored process ID.
/// * `Err(EBADF)` if descriptor does not exist.
/// * `Err(EINVAL)` if descriptor is not a pidfd.
pub fn pid_of(fd: u64) -> Result<u64, i64> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        // Group 13: a pidfd of linux-server names its process in the descriptor
        Some(crate::fs::FileDescriptor::Device(d)) if d.as_server().is_some_and(|o| o.kind() == crate::ipc::protocol::LX_OBJ_KIND_PIDFD) => Ok(d.as_server().unwrap().tag()),
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    })
}

// wave10 G7b-1 begin
/// The process pidfd `fd` of descriptor table `fds` names (`None`: not a pidfd), for
/// another thread's table (lx-proc's `LXP_NS_FD`).
pub fn pid_in(fds: &crate::fs::FdTable, fd: u64) -> Option<u64> {
    match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::Device(d)) if d.as_server().is_some_and(|o| o.kind() == crate::ipc::protocol::LX_OBJ_KIND_PIDFD) => d.as_server().map(|o| o.tag()),
        _ => None,
    }
}
// wave10 G7b-1 end

/// Linux `pidfd_send_signal(2)` system call implementation.
///
/// # Arguments
///
/// * `fd` - Pidfd descriptor targeting the recipient process.
/// * `sig` - Signal number to deliver (`0` for existence check).
/// * `_info` - Pointer to `siginfo_t` struct (currently unsupported).
/// * `flags` - Operation flags (must be `0`).
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
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
    // Linux: the same permission check as kill(2)
    if !super::proc::may_signal(pid, sig as u32) {
        return EPERM;
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
