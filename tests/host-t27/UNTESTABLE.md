# Group 27: what the host tests do not reach

None of Group 27's files touches hardware: no port I/O, MSRs, control registers or `asm!`.
Everything they call (the scheduler, the descriptor table, the process table, net-server's
client, the frame allocator, linux-server) is replaced by a fake in `src/fake.rs`, so every
file is fully testable on the host, and nothing is listed as hardware-only.

The few lines no test reaches (measured with `tools/host_coverage.py`, tests/host and
tests/host-t27 merged; 5017 of 5037 lines, 99.6 %) are these:

| File | Line(s) | What | Why not reached |
|---|---|---|---|
| `epoll.rs` | 339 | closing brace of the readiness loop | a coverage artefact (the loop exits by `break`) |
| `inet.rs` | 1282 | `}` after IPv6's early privileged-port check | coverage artefact of the `if let` |
| `inet.rs` | 1540 | `Err(e) => e` after `getsockopt` | dead: `v` is always `Ok` there |
| `inet.rs` | 1543 | `_ => ENOTSOCK` | dead: every number let through is handled above |
| `io_uring.rs` | 1046-1049 | worker: a request ready at the check that must wait again when run | needs the descriptor's readiness to change between the check and the run (another CPU) |
| `io_uring.rs` | 1215 | `io_uring_setup`: parameters readable but not writable | the fake's user memory faults on reads and writes alike |
| `io_uring.rs` | 1462 | `IORING_REGISTER_RING_FDS`: results readable but not writable | same |
| `itimer.rs` | 143 | `itimerd`: a process removed between listing and locking (2 regions) | a race with another CPU |
| `rtnetlink.rs` | 105-106 | padding a message to 4 bytes | every body built is already a multiple of 4 |
| `rtnetlink.rs` | 166 | `}` of the link-local address branch | coverage artefact |
| `socket.rs` | 305 | `accept` taking a connection that arrived during a yield | needs another task to connect while the listener's lock is held across the yield |
| `unix.rs` | 888 | `read_addr`: empty path after a non-NUL first byte | dead: the first byte is part of the path |
| `unix.rs` | 1029 | `}` in `build_control` | coverage artefact |
| `unix.rs` | 1323, 1659 | `accept`'s peer that is not connected, `dispatch`'s `_ => EINVAL` | dead: a queued connection is always connected; every number let through is handled |
