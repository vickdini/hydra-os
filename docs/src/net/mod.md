# Networking: net-server and the kernel's socket client

Since microkernel wave 2 (Group 2, branch `mk-net`) the network protocols run in Ring 3.
The kernel keeps only the Linux socket semantics and a thin client.

```text
 Linux programs (curl, apt, Firefox, sshd...)        kernel shell (ifconfig, ping, dns, wget)
        | socket system calls                                 |
        v                                                     v
 compat/linux/inet.rs  (blocking, poll/epoll, SO_* options, MSG_PEEK, SIGPIPE, sockaddrs)
        |                                                     |
 src/net/client.rs  (requests, readiness from the status area, per-socket wait queues)
        |  hand-off calls to endpoint 0x28            ^ doorbell (syscall 35) wakes waiters
        v                                             |
 net-server (Ring 3, userland/drivers/net-server)
   Ethernet, ARP, IPv4, ICMP, UDP, TCP, loopback (127/8, ::1), DHCP client, DNS resolver
        |  calls to endpoint 0x22 through the driver's window   ^ its interrupt, forwarded
        v                                                     |   as a notification
 e1000-driver (Ring 3)  ->  Intel 8254x / 82574 / I217-I218 adapter (DMA in its IOMMU domain)
```

## Who does what

| Piece | Where | Job |
|---|---|---|
| `e1000-driver` | `userland/drivers/e1000-driver` | Rings, DMA buffers, interrupt; frames in batches through its window |
| net-server | `userland/drivers/net-server` | All protocols and socket state; DHCP; DNS lookups |
| kernel client | `src/net/client.rs` | The socket functions `inet.rs` calls; status-area reads; wait queues |
| kernel helpers | `src/net/mod.rs` | Boot report, `dhcp_renew`, `resolve`, `ping`, `http_get` (for the shell) |
| Linux sockets | `src/compat/linux/inet.rs`, `rtnetlink.rs` | Linux semantics; unchanged in shape |

The supervisor starts `net_driver` and then `net_server` (always, so loopback works without
a card; `nic=1` when the driver runs), and restarts either when it dies.

## The protocol

Labels, arguments and the window layout are documented in `src/ipc/protocol.rs`
(`ENDPOINT_NET_SERVER = 0x28`, `MSG_NETS_*`, `NETS_*`). hydra-rt includes the same file, so
server and kernel cannot disagree. In short:

- **Requests** carry a socket handle and arguments; payloads sit in the server's window at an
  offset the request names (the data area is the first 192 KiB). Socket requests never wait
  for the network: they answer at once (`-EAGAIN` when there is nothing yet), so callers can
  use hand-off calls while holding socket locks. Only `MSG_NETS_DHCP` and `MSG_NETS_RESOLVE`
  answer later, and must be queued calls.
- **Readiness** lives in the window's status area: one 64-bit word per socket slot (handle,
  in/out/hup/err/accept bits, TCP state, pending error). `poll`, `select`, `epoll`, and the
  quick checks before `recv` read it without a call.
- **Waking**: when words change, the server appends the handles to an event ring in the
  status area and calls `SYS_SVC_SIGNAL` (35). The kernel runs the hook the client registered
  (`client::on_signal`), which wakes the wait queue of each listed socket.
- **Interface state** (MAC, address, mask, gateway, DNS, link, counters) is in the status
  page too: `rtnetlink`, `/proc/net/*`, `ifconfig` read it directly.

## Kernel IPC primitives added for it (`src/ipc/service.rs`)

- `SYS_SVC_RECV` with `RECV_NOTIFY | timeout` in `arg2`: the server also gets notifications
  (request ID 0, `MSG_SVC_NOTIFY`, bits in `args[0]`) and a timeout for its timers.
- `service::forward_irq(from, to)`: the e1000 interrupt becomes a notification for net-server.
- `service::set_signal_hook(endpoint, fn)` and syscall 35 `SYS_SVC_SIGNAL`: a server's
  doorbell to its kernel client; the hook is also called with `SIGNAL_GONE` when the server
  goes away.
- Scheduler (`wait_out_handoff`): a server that a hand-off participant waits on through a
  queued request may enter the kernel during the hand-off (the e1000 driver while net-server,
  serving a kernel caller's hand-off, waits for it).

## When net-server dies

The supervisor restarts it (DHCP runs again; QEMU gives the same address). The hook wakes
every waiting socket; sockets of the old server are dead from then on: TCP calls fail with
`ECONNRESET`, UDP/ICMP receives with `ENETDOWN`, `poll` reports `POLLERR|POLLHUP`. The kernel
names sockets by handles of its own, so a socket of the old server can never reach a socket
of the new one even if the new server hands out the same numbers. New sockets work at once.

## Performance notes

- One hand-off call per socket operation (the old in-kernel stack had none); readiness
  checks need no call.
- Frames: received in batches per interrupt; sent in batches (`MSG_NET_TRANSMIT_BATCH`)
  flushed before each reply and after each round of received frames.
- Before/after numbers: see the Group 2 report (branch `mk-net`).

## Two clients: the kernel and linux-server (wave 5, step 3)

Since wave 5 (Group 12, branch `mk-lxnet`) the Linux programs' `AF_INET`/`AF_INET6`
sockets live in the ring-3 `linux-server`, which is net-server's client directly
(`userland/drivers/linux-server/src/netc.rs`); the kernel's `inet.rs` above is used only with
`lx=kernel` and by the kernel's own helpers (`net::http_get`, `ping`, `resolve`).

- **The window is shared:** the kernel uses `[0, NETS_KERNEL_DATA_LEN)` (64 KiB) of the data
  area and the DNS name page at `0x2F000`; linux-server uses `NETS_LX_DATA_LEN` bytes at
  `NETS_LX_DATA_OFF` (0x10000), as two regions its threads take for one request each.
  `allow_client(0x28, 0x29)` lets it map the window.
- **Client tags:** requests that make a handle carry the client's tag in `args[3]`
  (`NETS_CLIENT_KERNEL` 0, `NETS_CLIENT_LX` 1); listeners and accepted connections take their
  parent's. `MSG_NETS_CLIENT_RESET(tag)` closes all of a tag's handles: a restarted
  linux-server sends it at start, so its predecessor's connections do not linger.
- **The doorbell reaches both:** the kernel's hook (`client::on_signal`) wakes the kernel's
  own sockets and raises `NOTIFY_LX_NET` for linux-server's main thread (`NOTIFY_LX_NET_GONE`
  when net-server went away). Each client reads the event ring with a tail of its own.
- **Receive capacity:** `MSG_NETS_UDP_RECV` and `MSG_NETS_ICMP_RECV` take a capacity in
  `args[3]` (0: up to the data area's end, the kernel's old behaviour) and return the whole
  length and the bytes copied, so a client's part of the window is never overrun.

