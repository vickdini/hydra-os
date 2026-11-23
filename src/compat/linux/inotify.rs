//! # Linux Compatibility: `inotify` (what the kernel keeps)
//!
//! Since wave 9 (Group 6b-1) inotify instances are vfs-server's objects: `inotify_init1`,
//! `inotify_add_watch` and `inotify_rm_watch` go there (`lx::fileh`, waiting for a
//! restarting vfs-server), and the kernel hands vfs-server the events of its own changes
//! (`lx::notifyfwd`). Wave 9's closing (Group 9-C) deleted the kernel's own instances (the
//! switch back `lx.vfs=kernel`); what is left are the event bits other kernel code names
//! and the answers for the calls that still reach the kernel:
//! - `inotify_init`/`inotify_init1` with vfs-server not running (before it first comes up,
//!   or given up by its restart ladder): `ENOSYS` (programs fall back to polling);
//! - `inotify_add_watch`/`inotify_rm_watch` on a descriptor that is not vfs-server's
//!   instance: `EBADF` (not open) or `EINVAL`, as Linux.

/// Event mask bit: file opened for writing was closed.
pub const IN_CLOSE_WRITE: u32 = 0x8;

const ENOSYS: i64 = -38;
const EBADF: i64 = -9;
const EINVAL: i64 = -22;

/// `EBADF` for a descriptor that is not open, else `EINVAL` (not an inotify instance).
fn not_an_instance(fd: u64) -> i64 {
    if crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).is_some()) {
        EINVAL
    } else {
        EBADF
    }
}

/// `inotify_init1(flags)` / `inotify_init()` reaching the kernel: vfs-server is not there.
pub fn sys_init1(_flags: u64) -> i64 {
    ENOSYS
}

/// `inotify_add_watch(fd, ..)` reaching the kernel: `fd` is no instance.
pub fn sys_add_watch(fd: u64, _path_ptr: u64, _mask: u64) -> i64 {
    not_an_instance(fd)
}

/// `inotify_rm_watch(fd, ..)` reaching the kernel: `fd` is no instance.
pub fn sys_rm_watch(fd: u64, _wd: u64) -> i64 {
    not_an_instance(fd)
}
