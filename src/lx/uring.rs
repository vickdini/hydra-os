//! wave9 G6b-4: io_uring requests and aio operations routed to each descriptor's owner.
//!
//! The rings stay the kernel's this wave (`compat/linux/io_uring.rs`, `aio.rs`: the ring
//! pages, SQE decoding, links, timeouts, the `iou-wrk` worker, the completions). What each
//! request does is the program's own system call made on its behalf
//! (`compat::linux::nested_routed`); this file sends that call where the program's own call
//! would go ([`super::forward`]): a path call to vfs-server, a call on a server object
//! (an lx-ipc pipe or eventfd, an lx-net socket, a device service's descriptor) to the
//! object's service with the object held for the call, a socket family to its service. A
//! call nobody claims (a kernel file handle, a kernel descriptor) stays the kernel's.
//!
//! - **The worker** (`iou-wrk`: same thread group, descriptor table, address space and
//!   credentials as the program) forwards as a thread of the process.
//! - **A service crash** with requests in flight: a request being served is an ordinary
//!   forwarded call, so it gets that service's restart rule (re-sent when not committed,
//!   otherwise `-EIO`); a request waiting for readiness wakes on the dead object's
//!   `POLLERR | POLLHUP` and completes with the call's error. The ring is the kernel's and
//!   survives.
//! - **No switch back** (wave 10 10-C, decision 34: the rings stay in the kernel as
//!   mechanism; `lx.uring=kernel` is ignored with a boot-log line).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::syscall::SyscallFrame;

/// Requests answered by a service (counted for `[lx] uring` and the tests).
static FORWARDED: AtomicU64 = AtomicU64::new(0);
/// Requests the kernel answered.
static IN_KERNEL: AtomicU64 = AtomicU64::new(0);


/// Routes the request call in `frame` (call number and arguments in place) like the
/// program's own call: `Some(result)` when its owner answered it, `None` when the kernel's
/// code runs it.
pub fn route(frame: &SyscallFrame) -> Option<i64> {
    let r = super::forward(frame);
    if r.is_some() { &FORWARDED } else { &IN_KERNEL }.fetch_add(1, Ordering::Relaxed);
    r
}

/// (forwarded, answered by the kernel) requests since boot.
pub fn counts() -> (u64, u64) {
    (FORWARDED.load(Ordering::Relaxed), IN_KERNEL.load(Ordering::Relaxed))
}

#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_uring.rs"]
mod tests;
