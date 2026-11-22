//! Netlink sockets are lx-net's (wave 8): lx-ipc's message queues reach one for glibc's
//! `mq_notify(SIGEV_THREAD)` through the kernel (`LX_OBJ_PIN` / `LX_OBJ_NOTIFY`, which
//! forwards the notification to the socket's service). These are the names `mqueue.rs`
//! uses when netlink sockets live in the same program (linux-server with everything
//! co-located); here no socket is ever ours.

use crate::client::Cx;

/// Tokens of [`pin`] carry this bit (the kernel's `LX_OBJ_PIN` tokens never do).
pub const PIN_BIT: u64 = 1 << 62;

/// Never ours: the kernel keeps the socket instead.
pub fn pin(_cx: &Cx, _fd: u64) -> Option<u64> {
    None
}

/// (No token of ours exists.)
pub fn deliver(_token: u64, _data: &[u8]) {}

/// (No token of ours exists.)
pub fn unpin(_token: u64) {}
