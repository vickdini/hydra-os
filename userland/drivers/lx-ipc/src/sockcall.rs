//! # Socket calls on descriptors that are no sockets (wave 12, Group V)
//!
//! The kernel sends a socket call (`sendto`, `recvmsg`, `getsockopt`, ...) to the service that
//! owns the descriptor. On one of lx-ipc's objects that is no socket (a pipe, FIFO, eventfd,
//! timerfd, signalfd, pidfd, message queue) Linux answers `ENOTSOCK`. lx-ipc answered
//! `ENOSYS`, which broke PulseAudio: its `pa_write()` tries `send()` first and falls back to
//! `write()` only on `ENOTSOCK`, so the wake-ups of its main loop (a pipe) failed and
//! Firefox's audio output, and with it every video, stalled at "loading".

/// The calls on a socket descriptor, by number: connect, accept, sendto, recvfrom, sendmsg,
/// recvmsg, shutdown, bind, listen, getsockname, getpeername, setsockopt, getsockopt,
/// accept4, recvmmsg, sendmmsg (the kernel's `BYFD_NUMBERS`).
pub const SOCKET_FD_CALLS: [u64; 16] = [42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 288, 299, 307];

/// Whether call `nr` is a call on a socket descriptor.
pub fn is_socket_fd_call(nr: u64) -> bool {
    SOCKET_FD_CALLS.contains(&nr)
}

/// Whether call `nr` on an object of ours that is no socket gets `ENOTSOCK` (`on_object`: the
/// call names one of our objects; `is_socket`: that object is a Unix socket).
pub fn not_a_socket(nr: u64, on_object: bool, is_socket: bool) -> bool {
    on_object && !is_socket && is_socket_fd_call(nr)
}
