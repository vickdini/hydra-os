//! MEASUREMENT ONLY (microkernel wave 2, group 6, step 0). Not part of a normal build:
//! compiled only with `cargo build --features g6-probe`, so the default kernel is unchanged.
//!
//! A Linux system call (number [`NR`]) that measures what forwarding a system call to a
//! Ring 3 server would cost today. Each forwarded call is a supervisor ping
//! (`MSG_SUPERVISOR_PING`) to an existing server: `hydra-rt` answers pings in its receive
//! loop without running any handler, so the time is the IPC round trip alone.
//!
//! `syscall(NR, op, endpoint, count)`:
//! - `op 0`: nothing (the cost of the normal, locked system call path itself);
//! - `op 1`: `count` pings in [`CallMode::Handoff`] (the CPU goes straight to the server);
//! - `op 2`: `count` pings in [`CallMode::Queued`] (the caller sleeps on a wait queue).
//!
//! Returns the nanoseconds the `count` calls took inside the kernel, or a negative errno.
//! The user program also times the whole system call (trap included).

use crate::ipc::service::{call_once_mode, CallMode};
use crate::ipc::Message;

/// The probe's system call number (far above Linux's own).
pub const NR: u64 = 0x6706;

/// Runs one probe request (see the module comment).
pub fn run(op: u64, endpoint: u64, count: u64) -> i64 {
    let mode = match op {
        0 => return 0,
        1 => CallMode::Handoff,
        2 => CallMode::Queued,
        _ => return -22,
    };
    let t0 = crate::arch::pit::now_ns();
    for seq in 0..count.max(1) {
        let msg = Message::with_args(crate::ipc::protocol::MSG_SUPERVISOR_PING, [seq, 0, 0, 0]);
        if let Err(e) = call_once_mode(endpoint as u32, msg, 100, mode) {
            return e;
        }
    }
    (crate::arch::pit::now_ns() - t0) as i64
}
