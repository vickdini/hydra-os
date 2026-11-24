//! # System V IPC: the kernel's mapping half
//!
//! Since wave 10 every System V object is lx-ipc's: semaphore sets, message queues and the
//! naming half of shared memory (`shmget`, `shmctl`; `shmat`'s permission check). What stays
//! here is mechanism: `shmat` after lx-ipc's answer maps the segment's kept memory object,
//! `shmdt` unmaps it, and fork, exec and exit keep the attachment table (`lx::shm`) right.
//! (Wave 10 10-C deleted the in-kernel copy of the objects, `lx=kernel`/`lx.ipc=kernel`'s.)

/// A forked child inherits its parent's shared memory attachments (its address space is a
/// copy, mappings included).
///
/// # Arguments
/// * `parent` - Parent process ID.
/// * `child` - Child process ID.
pub fn on_fork(parent: u64, child: u64) {
    crate::lx::shm::on_fork(parent, child);
}

/// Drops a process's attachments (its address space is gone or replaced).
///
/// # Arguments
/// * `pid` - Process ID.
/// * `_exiting` - The process is exiting (not just replacing its image).
pub fn forget_process(pid: u64, _exiting: bool) {
    crate::lx::shm::forget(pid);
}

/// The System V calls the kernel answers: `shmat` (30) once lx-ipc named the segment
/// (`lx::shm::forward_kept`), and `shmdt` (67). Every other System V call is lx-ipc's.
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for these calls, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    match num {
        30 => Some(crate::lx::shm::shmat(a[0] as i32, a[1], a[2])),
        67 => Some(crate::lx::shm::shmdt(a[0])),
        _ => None,
    }
}
