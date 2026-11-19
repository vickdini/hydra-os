//! # IPC Subsystem: Microkernel Service Protocols
//!
//! ## Subsystem Role & Architecture
//! Defines standard operation codes (labels), argument conventions, and response
//! envelopes for user-space driver daemons and decoupled microkernel services.
//!
//! ## Key Protocols
//! - **Block Device Protocol** (`0x2000..0x200F`): Read, write, flush, and capacity queries for Ring 3 disk drivers.
//! - **Filesystem Protocol** (`0x3000..0x300F`): Open, read, write, close, and stat for user-space storage servers.
//! - **Network Interface Protocol** (`0x4000..0x400F`): Transmit, receive, MAC query, and link status for unprivileged NIC drivers.
//! - **Display & Compositor Protocol** (`0x5000..0x500F`): Framebuffer geometry, damage flushes, and input event routing for user-space window servers.
//! - **Supervisor & Reincarnation Protocol** (`0x6000..0x600F`): Heartbeat ping/pong, vitality queries, and driver restart coordination for MINIX 3-style fault tolerance.
//!
//! ## Concurrency & Performance
//! All operations fit within the 4-argument `Message` structure, ensuring zero heap allocation
//! across client-server IPC boundaries.

/// Well-known endpoint of the OpenZFS file server (0x20 = 32).
pub const ENDPOINT_ZFS_SERVER: u32 = 0x20;
/// Well-known endpoint of the block device (ATA) driver (0x21 = 33).
pub const ENDPOINT_BLOCK_DEV: u32 = 0x21;
/// Well-known endpoint of the network interface (e1000) driver (0x22 = 34).
pub const ENDPOINT_NET_DEV: u32 = 0x22;
/// Well-known endpoint of the display server (0x23 = 35).
pub const ENDPOINT_DISPLAY_DEV: u32 = 0x23;
/// Well-known endpoint of the process supervisor (0x24 = 36).
pub const ENDPOINT_SUPERVISOR: u32 = 0x24;

/// Protocol label for a block device read operation.
///
/// Inline arguments:
/// - `args[0]`: Logical block address (LBA).
/// - `args[1]`: Number of 4 KiB blocks to read.
/// - `args[2]`: Virtual address of the target buffer in the caller's address space.
/// - `args[3]`: Reserved (must be 0).
pub const MSG_BLOCK_READ: u32 = 0x2001;

/// Protocol label for a block device write operation.
///
/// Inline arguments:
/// - `args[0]`: Logical block address (LBA).
/// - `args[1]`: Number of 4 KiB blocks to write.
/// - `args[2]`: Virtual address of the source buffer in the caller's address space.
/// - `args[3]`: Reserved (must be 0).
pub const MSG_BLOCK_WRITE: u32 = 0x2002;

/// Protocol label for a block device cache flush operation.
///
/// Inline arguments:
/// - `args[0..3]`: Reserved (must be 0).
pub const MSG_BLOCK_FLUSH: u32 = 0x2003;

/// Protocol label to query total addressable blocks on the block device.
///
/// Inline arguments:
/// - `args[0..3]`: Reserved (must be 0).
pub const MSG_BLOCK_GET_SIZE: u32 = 0x2004;

/// Protocol label for a vectored block device read: several runs of blocks in one
/// request, which the driver may have in flight at once (AHCI native command queueing).
///
/// Inline arguments:
/// - `args[0]`: Number of runs `n` (1..=[`BLOCK_READV_MAX`]).
/// - `args[1..3]`: Reserved (must be 0).
///
/// The run table is in the service window at [`BLOCK_READV_TABLE`]: `n` entries of three
/// little-endian `u64`s, `[first block, block count, window byte offset]` (offsets are
/// multiples of 4096; runs end at or before the table). The reply is
/// [`MSG_BLOCK_REPLY`] `[status, blocks read]`, all runs or none; a driver without it
/// answers `-ENOSYS` (-38).
pub const MSG_BLOCK_READV: u32 = 0x2005;

/// Most runs in one [`MSG_BLOCK_READV`] request (the AHCI command slots).
pub const BLOCK_READV_MAX: usize = 32;

/// Window offset of a [`MSG_BLOCK_READV`] run table: the window's last 4 KiB page (the
/// data before it).
pub const BLOCK_READV_TABLE: usize = 63 * 4096;

/// Protocol label for a block device operation reply.
///
/// Inline arguments:
/// - `args[0]`: Status code (0 for success, negative for standard POSIX errno).
/// - `args[1]`: Total blocks successfully transferred or total capacity in blocks.
/// - `args[2..3]`: Reserved.
pub const MSG_BLOCK_REPLY: u32 = 0x200F;

/// Protocol label for filesystem file open.
///
/// Inline arguments:
/// - `args[0]`: Pointer to UTF-8 path string.
/// - `args[1]`: Length of path string.
/// - `args[2]`: Open flags (e.g. `O_RDONLY`, `O_WRONLY`, `O_RDWR`).
/// - `args[3]`: Reserved.
pub const MSG_FS_OPEN: u32 = 0x3001;

/// Protocol label for filesystem file read.
///
/// Inline arguments:
/// - `args[0]`: File descriptor or object identifier.
/// - `args[1]`: Virtual address of destination buffer.
/// - `args[2]`: Buffer capacity in bytes.
/// - `args[3]`: Reserved.
pub const MSG_FS_READ: u32 = 0x3002;

/// Protocol label for filesystem file write.
///
/// Inline arguments:
/// - `args[0]`: File descriptor or object identifier.
/// - `args[1]`: Virtual address of source buffer.
/// - `args[2]`: Buffer length in bytes.
/// - `args[3]`: Reserved.
pub const MSG_FS_WRITE: u32 = 0x3003;

/// Protocol label for filesystem file close.
///
/// Inline arguments:
/// - `args[0]`: File descriptor or object identifier.
/// - `args[1..3]`: Reserved.
pub const MSG_FS_CLOSE: u32 = 0x3004;

/// Protocol label for querying file metadata (stat).
///
/// Inline arguments:
/// - `args[0]`: Pointer to UTF-8 path string.
/// - `args[1]`: Length of path string.
/// - `args[2]`: Destination pointer for serialized `FileStat` structure.
/// - `args[3]`: Reserved.
pub const MSG_FS_STAT: u32 = 0x3005;

/// Protocol label for committing transaction groups (sync).
///
/// Inline arguments:
/// - `args[0..3]`: Reserved.
pub const MSG_FS_SYNC: u32 = 0x3006;

/// Protocol label for filesystem operation reply.
///
/// Inline arguments:
/// - `args[0]`: Return code (non-negative on success, negative errno on failure).
/// - `args[1]`: Operation-specific secondary result (e.g. bytes read or written).
/// - `args[2..3]`: Reserved.
pub const MSG_FS_REPLY: u32 = 0x300F;

/// Protocol label to transmit an Ethernet frame via the network driver.
///
/// Inline arguments:
/// - `args[0]`: Virtual pointer to raw Ethernet frame bytes.
/// - `args[1]`: Length of Ethernet frame in bytes.
/// - `args[2..3]`: Reserved.
pub const MSG_NET_TRANSMIT: u32 = 0x4001;

/// Protocol label to receive an Ethernet frame from the network driver.
///
/// Inline arguments:
/// - `args[0]`: Virtual pointer to destination buffer in caller's space.
/// - `args[1]`: Maximum buffer capacity in bytes.
/// - `args[2..3]`: Reserved.
pub const MSG_NET_RECEIVE: u32 = 0x4002;

/// Protocol label to query the network adapter's 48-bit hardware MAC address.
///
/// Inline arguments:
/// - `args[0..3]`: Reserved.
pub const MSG_NET_GET_MAC: u32 = 0x4003;

/// Protocol label to query link carrier status and link speed.
///
/// Inline arguments:
/// - `args[0..3]`: Reserved.
pub const MSG_NET_GET_STATUS: u32 = 0x4004;

/// Test only (IOMMU, Group 1): makes the adapter read physical address `args[0]` by DMA, as
/// a rogue driver would (one transmit descriptor pointing there). The driver accepts it
/// only when started with `dma_test=1` (QEMU `opt/hydra/iommu=test`). Reply `[0]` once
/// the descriptor completed, or a negative errno.
pub const MSG_NET_DMA_TEST: u32 = 0x4005;

/// Protocol label for network driver operation reply.
///
/// Inline arguments:
/// - `args[0]`: Return status code (0 for success, negative for standard POSIX errno).
/// - `args[1]`: Primary return value (e.g. bytes transferred, or low 32 bits of MAC).
/// - `args[2]`: Secondary return value (e.g. high 16 bits of MAC).
/// - `args[3]`: Link state bitmask (bit 0 = Link Up, bit 1 = Full Duplex, bit 2 = 1 Gbps).
pub const MSG_NET_REPLY: u32 = 0x400F;

/// Transmit several frames in one request (net-server's batches): the window holds
/// `args[0]` frames, each a 16-bit little-endian length and the frame (as
/// [`MSG_NET_RECEIVE`] returns them). Reply `[0, frames sent]`, or a negative errno with
/// `args[1]` the frames sent before the failure.
pub const MSG_NET_TRANSMIT_BATCH: u32 = 0x4006;

// ----------------------------------------------------------------------------------------
// Server notifications (any server)
// ----------------------------------------------------------------------------------------

/// What `SYS_SVC_RECV` returns (request ID 0) to a server that asked for notifications
/// ([`RECV_NOTIFY`] in `arg2`) when it has no request to take: `args[0]` holds the
/// notification bits that were raised ([`NOTIFY_IRQ`], ...), 0 if its timeout (the low
/// bits of `arg2`, in ticks) ran out first. A notification needs no reply.
pub const MSG_SVC_NOTIFY: u32 = 0x6010;

/// Notification bit: the interrupt of a device another driver owns arrived (the kernel
/// forwards it, `ipc::service::forward_irq`): net-server learns that the network driver
/// has frames for it.
pub const NOTIFY_IRQ: u64 = 1;

/// `SYS_SVC_RECV` `arg2` flag: also return notifications (the low bits: a timeout in
/// ticks, 0 for none).
pub const RECV_NOTIFY: u64 = 1 << 63;

// ----------------------------------------------------------------------------------------
// Network server (net-server): sockets over Ethernet, IPv4, ICMP, UDP and TCP
// ----------------------------------------------------------------------------------------
//
// net-server (`userland/drivers/net-server`) owns the protocols; its clients (the kernel's
// Linux socket layer today, a ring-3 Linux server later) hold socket handles (u32) and
// make every blocking wait themselves: no request waits for the network, each answers at
// once (except [`MSG_NETS_DHCP`] and [`MSG_NETS_RESOLVE`], which answer later and must be
// queued calls).
//
// Addresses: an IPv4 address `[a, b, c, d]` travels as `u32::from_le_bytes([a, b, c,
// d])`; with a port, `addr << 16 | port`. IPv6 `::1` and the card's `fe80::` address are
// carried as `0.0.0.1` and `0.0.0.2` (see net-server's `stack.rs`).
//
// Payloads are in the server's window: requests name an offset in its data area
// ([`NETS_DATA_LEN`] bytes from 0) where the client put or wants the bytes.
//
// The window's last 64 KiB is the status area, written only by the server: the status
// page ([`NETS_STATUS_OFF`], words below), the event ring ([`NETS_EVENTS_OFF`]) and the
// readiness table ([`NETS_SOCKS_OFF`]). A client reads readiness from the table instead of
// asking; when words change the server appends the handles to the ring and rings the
// doorbell (`SYS_SVC_SIGNAL`), whose kernel hook wakes the waiters of those sockets.
//
// Every reply is [`MSG_NETS_REPLY`] with `args[0]` the result (>= 0) or a negative errno.

/// Well-known endpoint of the network server (0x28 = 40).
pub const ENDPOINT_NET_SERVER: u32 = 0x28;

/// Bytes of the window's data area (offset 0): payloads of requests and replies.
pub const NETS_DATA_LEN: usize = 0x30000;
/// The kernel's part of the data area: `[0, NETS_KERNEL_DATA_LEN)`, and its DNS name page
/// at `NETS_DATA_LEN - 4096` (wave 5: two clients share the window).
pub const NETS_KERNEL_DATA_LEN: usize = 0x10000;
/// linux-server's part of the data area (wave 5, step 3): `NETS_LX_DATA_LEN` bytes at
/// `NETS_LX_DATA_OFF`, which it divides among its threads.
pub const NETS_LX_DATA_OFF: usize = 0x10000;
/// See [`NETS_LX_DATA_OFF`].
pub const NETS_LX_DATA_LEN: usize = 0x1E000;
/// Client tags (wave 5): the requests that make a handle (`TCP_CONNECT`, `TCP_BIND`,
/// `UDP_OPEN`, `ICMP_OPEN`) carry the client's tag in `args[3]`; listeners and accepted
/// connections take their parent's. [`MSG_NETS_CLIENT_RESET`] closes all of one tag's
/// handles (a restarted linux-server's predecessor's). The kernel's tag is 0.
pub const NETS_CLIENT_KERNEL: u64 = 0;
/// The tag of linux-server (see [`NETS_CLIENT_KERNEL`]).
pub const NETS_CLIENT_LX: u64 = 1;
/// Offset of the status page: little-endian u64 words `NETS_ST_*`.
pub const NETS_STATUS_OFF: usize = 0x30000;
/// Offset of the event ring: [`NETS_EVENTS`] u32 handles; entry `n % NETS_EVENTS` is the
/// `n`-th event, and the status word [`NETS_ST_EVENT_HEAD`] counts the events written.
pub const NETS_EVENTS_OFF: usize = 0x31000;
/// Entries of the event ring.
pub const NETS_EVENTS: usize = 4096;
/// Offset of the readiness table: [`NETS_SLOTS`] u64 words, one per socket slot (a
/// handle's low 12 bits): bits 0..32 the handle (0: free slot), 32..40 readiness
/// (`NETS_R_*`), 40..48 the TCP state (`NETS_TCP_*`, 0 for others), 48..64 a pending
/// socket error (a positive errno).
pub const NETS_SOCKS_OFF: usize = 0x38000;
/// Socket slots (a handle is `generation << 12 | slot`).
pub const NETS_SLOTS: usize = 4096;

/// Status word: [`NETS_MAGIC`] once the server has set the area up.
pub const NETS_ST_MAGIC: usize = 0;
/// The value of [`NETS_ST_MAGIC`] ("NETSRV01").
pub const NETS_MAGIC: u64 = u64::from_le_bytes(*b"NETSRV01");
/// Status word: flags `NETS_F_*`.
pub const NETS_ST_FLAGS: usize = 1;
/// Status word: the card's MAC address (bytes 0..6).
pub const NETS_ST_MAC: usize = 2;
/// Status word: the IPv4 address (as above; 0 while unconfigured).
pub const NETS_ST_IP: usize = 3;
/// Status word: the subnet mask.
pub const NETS_ST_MASK: usize = 4;
/// Status word: the default gateway.
pub const NETS_ST_GATEWAY: usize = 5;
/// Status word: the DNS server.
pub const NETS_ST_DNS: usize = 6;
/// Status word: the DHCP server that gave the lease.
pub const NETS_ST_DHCP_SERVER: usize = 7;
/// Status word: events written to the ring so far.
pub const NETS_ST_EVENT_HEAD: usize = 8;
/// Status words: card traffic: packets received, bytes received, packets sent, bytes sent.
pub const NETS_ST_ETH_COUNTERS: usize = 9;
/// Status words: loopback traffic: bytes, packets.
pub const NETS_ST_LO_COUNTERS: usize = 13;
/// Status words: receive requests made to the network driver and frames they returned.
pub const NETS_ST_RX_CALLS: usize = 15;
/// Status word: bumped whenever the interface changes (a lease).
pub const NETS_ST_IFACE_SEQ: usize = 17;

/// Flag: a network card (and its driver) is present.
pub const NETS_F_NIC: u64 = 1;
/// Flag: the card has a carrier link.
pub const NETS_F_LINK: u64 = 2;
/// Flag: DHCP gave an address (the interface is configured).
pub const NETS_F_CONFIGURED: u64 = 4;
/// Flag: a DHCP exchange is in progress.
pub const NETS_F_DHCP_BUSY: u64 = 8;

/// Readiness: data (or end of stream, or an error) to read.
pub const NETS_R_IN: u64 = 1;
/// Readiness: room to write.
pub const NETS_R_OUT: u64 = 2;
/// Readiness: hung up.
pub const NETS_R_HUP: u64 = 4;
/// Readiness: an error is pending.
pub const NETS_R_ERR: u64 = 8;
/// Readiness (listeners): a connection waits to be accepted.
pub const NETS_R_ACCEPT: u64 = 16;

/// TCP state `SynSent` (readiness words, [`MSG_NETS_TCP_INFO`]).
pub const NETS_TCP_SYN_SENT: u64 = 1;
/// TCP state `SynReceived`.
pub const NETS_TCP_SYN_RECEIVED: u64 = 2;
/// TCP state `Established`.
pub const NETS_TCP_ESTABLISHED: u64 = 3;
/// TCP state `FinWait1`.
pub const NETS_TCP_FIN_WAIT1: u64 = 4;
/// TCP state `FinWait2`.
pub const NETS_TCP_FIN_WAIT2: u64 = 5;
/// TCP state `CloseWait`.
pub const NETS_TCP_CLOSE_WAIT: u64 = 6;
/// TCP state `LastAck`.
pub const NETS_TCP_LAST_ACK: u64 = 7;
/// TCP state `Closing`.
pub const NETS_TCP_CLOSING: u64 = 8;
/// TCP state `TimeWait`.
pub const NETS_TCP_TIME_WAIT: u64 = 9;
/// TCP state `Closed`.
pub const NETS_TCP_CLOSED: u64 = 10;

/// TCP: connect `[addr, port, local port (0: any)]` -> `[handle]` (in `SynSent`; the
/// state in the readiness word tells when it is established or failed).
pub const MSG_NETS_TCP_CONNECT: u32 = 0x9001;
/// TCP: send `[handle, offset, length]` -> `[bytes taken]` (0: no room yet).
pub const MSG_NETS_TCP_SEND: u32 = 0x9002;
/// TCP: receive `[handle, offset, capacity, peek]` -> `[bytes, end of stream]`.
pub const MSG_NETS_TCP_RECV: u32 = 0x9003;
/// TCP: shut down writing (`FIN` after the buffered data) `[handle]`.
pub const MSG_NETS_TCP_SHUTDOWN: u32 = 0x9004;
/// TCP: close `[handle]` (the connection finishes in the background).
pub const MSG_NETS_TCP_CLOSE: u32 = 0x9005;
/// TCP: take the pending error `[handle]` -> `[positive errno, or 0]`.
pub const MSG_NETS_TCP_TAKE_ERROR: u32 = 0x9006;
/// TCP: endpoints `[handle]` -> `[0, local addr << 16 | port, remote addr << 16 | port,
/// state]`.
pub const MSG_NETS_TCP_INFO: u32 = 0x9007;
/// TCP: reserve a port `[addr, port (0: any), flags]` (flags bit 0 `SO_REUSEADDR`, 1
/// `SO_REUSEPORT`, 2 IPv4, 3 IPv6) -> `[handle, port]`.
pub const MSG_NETS_TCP_BIND: u32 = 0x9008;
/// TCP: release a reservation `[handle]`.
pub const MSG_NETS_TCP_UNBIND: u32 = 0x9009;
/// TCP: listen on a reservation `[bind handle, backlog]` -> `[listener handle]`.
pub const MSG_NETS_TCP_LISTEN: u32 = 0x900A;
/// TCP: change a listener's backlog `[handle, backlog]`.
pub const MSG_NETS_TCP_BACKLOG: u32 = 0x900B;
/// TCP: accept `[listener]` -> `[connection handle]` or `-EAGAIN`.
pub const MSG_NETS_TCP_ACCEPT: u32 = 0x900C;
/// TCP: stop listening `[listener]` (waiting connections are reset).
pub const MSG_NETS_TCP_UNLISTEN: u32 = 0x900D;
/// UDP: open `[port (0: any)]` -> `[handle]`.
pub const MSG_NETS_UDP_OPEN: u32 = 0x9010;
/// UDP: move to a port `[handle, port]`.
pub const MSG_NETS_UDP_REBIND: u32 = 0x9011;
/// UDP: its port `[handle]` -> `[port]`.
pub const MSG_NETS_UDP_PORT: u32 = 0x9012;
/// UDP: send `[handle, addr << 16 | port, offset, length]` -> `[length]`.
pub const MSG_NETS_UDP_SEND: u32 = 0x9013;
/// UDP: receive `[handle, offset, peek, capacity (0: the data area's end)]` -> `[length,
/// addr << 16 | port, arrival time (ns since 1970), bytes copied]` with the datagram (at
/// most `capacity` bytes of it) at the offset, or `-EAGAIN`.
pub const MSG_NETS_UDP_RECV: u32 = 0x9014;
/// UDP: close `[handle]`.
pub const MSG_NETS_UDP_CLOSE: u32 = 0x9015;
/// ICMP: open `[raw, IPv6]` -> `[handle]` (a ping socket unless raw).
pub const MSG_NETS_ICMP_OPEN: u32 = 0x9020;
/// ICMP: echo identifier `[handle]` -> `[identifier]`.
pub const MSG_NETS_ICMP_IDENT: u32 = 0x9021;
/// ICMP: set the echo identifier (`bind`) `[handle, identifier]`.
pub const MSG_NETS_ICMP_SET_IDENT: u32 = 0x9022;
/// ICMP: send `[handle, addr, offset, length]` -> `[length]`.
pub const MSG_NETS_ICMP_SEND: u32 = 0x9023;
/// ICMP: receive `[handle, offset, peek, capacity (0: the data area's end)]` -> `[length,
/// addr, arrival time, bytes copied]`, or `-EAGAIN`.
pub const MSG_NETS_ICMP_RECV: u32 = 0x9024;
/// ICMP: close `[handle]`.
pub const MSG_NETS_ICMP_CLOSE: u32 = 0x9025;
/// Tables `[kind, offset, capacity]` -> `[records]`, each [`NETS_LIST_RECORD`] bytes of
/// little-endian u64 words: kind 0 TCP connections `[handle, local addr << 16 | port,
/// remote addr << 16 | port, state, bytes queued to send, bytes unread]`; 1 listeners
/// `[handle, addr << 16 | port, waiting, backlog]`; 2 UDP sockets `[handle, port, bytes
/// queued]`; 3 the ARP cache `[addr, MAC]`.
pub const MSG_NETS_LIST: u32 = 0x9030;
/// Bytes per record of [`MSG_NETS_LIST`].
pub const NETS_LIST_RECORD: usize = 64;
/// Run DHCP again (deferred reply, a queued call): `[0, lease address]` once it is bound,
/// or an error.
pub const MSG_NETS_DHCP: u32 = 0x9031;
/// Look a name up (DNS A record) `[offset, length]` (the name in the data area) (deferred
/// reply, a queued call) -> `[0, address]`.
pub const MSG_NETS_RESOLVE: u32 = 0x9032;
/// Close every handle made by the client with tag `[tag]` (wave 5: a restarted linux-server
/// clears what its predecessor left).
pub const MSG_NETS_CLIENT_RESET: u32 = 0x9033;
/// The network server's reply.
pub const MSG_NETS_REPLY: u32 = 0x90FF;

/// Protocol label to query linear framebuffer hardware properties and dimensions.
///
/// Inline arguments:
/// - `args[0..3]`: Reserved (must be 0).
///
/// Reply ([`MSG_FB_REPLY`]):
/// - `args[0]`: Physical base address of the GOP linear framebuffer.
/// - `args[1]`: Packed `(width as u64) | ((height as u64) << 32)`.
/// - `args[2]`: Packed `(stride as u64) | ((if is_bgr { 1 } else { 0 }) << 32)`.
/// - `args[3]`: Total size of the framebuffer in bytes.
pub const MSG_FB_GET_INFO: u32 = 0x5001;

/// Protocol label to flush/flip an off-screen canvas to the hardware display.
///
/// Inline arguments:
/// - `args[0]`: Virtual address of the source pixel buffer (or 0 for current compositor canvas).
/// - `args[1]`: Packed `(dirty_x as u64) | ((dirty_y as u64) << 32)` damage rectangle origin.
/// - `args[2]`: Packed `(dirty_w as u64) | ((dirty_h as u64) << 32)` damage rectangle dimensions.
/// - `args[3]`: Flush flags (bit 0 = full frame sync, bit 1 = wait vsync).
pub const MSG_FB_FLUSH: u32 = 0x5002;

/// Protocol label to route reflected hardware input events (mouse / keyboard) to the display server.
///
/// Inline arguments:
/// - `args[0]`: Input event type:
///   - `1`: Mouse motion (`args[1]` = packed `(x as u64) | ((y as u64) << 32)`).
///   - `2`: Mouse button transition (`args[1]` = packed `(x as u64) | ((y as u64) << 32)`,
///     `args[2]` = bitmask with bit 0 = left pressed, bit 1 = left held, bit 2 = right pressed).
///   - `3`: Key character input (`args[1]` = Unicode code point, `args[2]` = modifier mask).
/// - `args[1..3]`: Event-specific payloads as defined above.
pub const MSG_FB_INPUT_EVENT: u32 = 0x5003;

/// Protocol label for display server operation reply.
///
/// Inline arguments:
/// - `args[0]`: Return status code (0 for success, negative for standard POSIX errno).
/// - `args[1..3]`: Operation-specific return payloads.
pub const MSG_FB_REPLY: u32 = 0x500F;

/// Protocol label for a supervisor heartbeat ping sent to a driver daemon.
///
/// Inline arguments:
/// - `args[0]`: Monotonically increasing sequence number.
/// - `args[1]`: Timestamp or PIT timer ticks at dispatch.
/// - `args[2..3]`: Reserved (must be 0).
pub const MSG_SUPERVISOR_PING: u32 = 0x6001;

/// Protocol label for a driver heartbeat pong response sent back to the supervisor.
///
/// Inline arguments:
/// - `args[0]`: Echoed sequence number from the matching [`MSG_SUPERVISOR_PING`].
/// - `args[1]`: Driver health bitmask (bit 0 = Healthy, bit 1 = Busy, bit 2 = Degraded).
/// - `args[2..3]`: Driver-specific operational telemetry.
pub const MSG_SUPERVISOR_PONG: u32 = 0x6002;

/// Protocol label to query driver status and telemetry from the supervisor.
///
/// Inline arguments:
/// - `args[0]`: Service index or identifier (or 0 for summary).
/// - `args[1..3]`: Reserved.
pub const MSG_SUPERVISOR_STATUS: u32 = 0x6003;

/// Protocol label to explicitly request reincarnation/restart of a service.
///
/// Inline arguments:
/// - `args[0]`: Service endpoint ID or numeric identifier.
/// - `args[1]`: Flags (bit 0 = force kill, bit 1 = preserve state).
/// - `args[2..3]`: Reserved.
pub const MSG_SUPERVISOR_RESTART: u32 = 0x6004;

/// Protocol label for supervisor operation reply.
///
/// Inline arguments:
/// - `args[0]`: Status code (0 for success, negative for standard POSIX errno).
/// - `args[1]`: New process ID (if restarted) or service count.
/// - `args[2..3]`: Reserved.
pub const MSG_SUPERVISOR_REPLY: u32 = 0x600F;




/// Well-known endpoint of the USB input driver (xHCI host controller, HID keyboards and
/// pointers) (0x25 = 37).
pub const ENDPOINT_INPUT_DEV: u32 = 0x25;

/// Protocol label to collect input from the USB driver: it services its controller's
/// events, then fills the service window with 8-byte records:
/// - `[1, scancode, 0...]`: one set-1 keyboard scancode byte (0xE0 prefixes are records too);
/// - `[2, buttons, dx lo, dx hi, dy lo, dy hi, wheel, 0]`: relative pointer motion (dy down,
///   wheel positive away from the user, buttons bit 0 left, 1 right, 2 middle);
/// - `[3, buttons, x lo, x hi, y lo, y hi, wheel, 0]`: absolute pointer, x and y 0..=0xFFFF.
///
/// Reply ([`MSG_INPUT_REPLY`]): `args[0]` status, `args[1]` record count, `args[2]` devices.
pub const MSG_INPUT_READ: u32 = 0x7001;

/// Protocol label for the USB input driver's reply.
pub const MSG_INPUT_REPLY: u32 = 0x700F;

/// Well-known endpoint of the USB disks (USB mass storage: sticks, card readers, USB
/// hard disks) (0x27 = 39). Served by the USB driver (the process owning the xHCI
/// controller), which also serves [`ENDPOINT_INPUT_DEV`]: the two endpoints share one
/// call slot, so a call to either may find the driver busy with the other (`-EBUSY`; the
/// kernel's `ipc::service::call` waits and retries for this endpoint).
///
/// The block protocol of the disk drivers (`MSG_BLOCK_READ`, `_WRITE`, `_READV`, `_FLUSH`,
/// `_GET_SIZE`, 4 KiB blocks, data in this endpoint's own window), with `args[3]` the USB
/// disk number (0, 1, ... as [`MSG_BLOCK_LIST`] reports them; `-ENODEV` for none).
/// More replies: `-ENOMEDIUM` (-123: a card reader without a card), `-EROFS` (-30: a
/// write-protected medium).
pub const ENDPOINT_USB_DISK: u32 = 0x27;

/// Protocol label to describe the disks a multi-disk driver serves (the USB driver).
///
/// Reply ([`MSG_BLOCK_REPLY`]): `args[0]` status, `args[1]` the number of disks `n`,
/// `args[2]` a generation counter that changes whenever a disk is plugged in or out.
/// The window holds `n` records of [`BLOCK_LIST_RECORD`] bytes (little-endian):
/// - `0..4` disk number (`args[3]` of the other requests), `4..8` its generation (a new
///   disk under a reused number has a new one);
/// - `8..16` size in 4 KiB blocks (0: no medium), `16..20` sector size in bytes;
/// - `20` root port of the xHCI controller (1-based), `21` hubs between it and the root
///   port (its tier), `22` speed (xHCI protocol speed ID: 1 full, 2 low, 3 high, 4 Super-
///   Speed, 5 SuperSpeedPlus), `23` flags (bit 0 removable medium, bit 1 write-protected,
///   bit 2 medium present);
/// - `24..28` route string (hub port at each tier below the root port, 4 bits each,
///   tier 1 in bits 0..3; ports above 15 read 15);
/// - `28..30` USB vendor ID, `30..32` product ID;
/// - `32..72` model: SCSI INQUIRY vendor (8), space, product (16), space, revision (4),
///   space padded; `72..104` USB serial number string (ASCII, space padded);
/// - `104` USB interface number, `105` LUN; the rest is 0.
///
/// A UEFI device path of the disk reads `PciRoot(..)/Pci(<xHCI>)/USB(<root port - 1>, i)`
/// for a disk on a root port, `.../USB(<root port - 1>, 0)/USB(<tier 1 hub port - 1>,
/// i)` behind one hub, and so on: one USB node per tier, the root port and then each
/// route nibble minus one (UEFI numbers ports from 0), the last node carrying the
/// interface number `i`.
pub const MSG_BLOCK_LIST: u32 = 0x2006;

/// Bytes per disk record of [`MSG_BLOCK_LIST`].
pub const BLOCK_LIST_RECORD: usize = 128;

/// Well-known endpoint of the sound driver (Intel High Definition Audio) (0x26 = 38).
pub const ENDPOINT_SOUND_DEV: u32 = 0x26;

/// Sound: describe the card. Reply ([`MSG_SND_REPLY`]): `args[0]` status, `args[1]` codec
/// vendor and device ID, `args[2]` directions (bit 0 playback, bit 1 capture), `args[3]`
/// amplifiers: bits 0..32 the playback volume's, 32..64 the capture volume's, each
/// `steps | offset << 8 | step size << 16 | present << 24 | can mute << 25` (the HDA
/// amplifier capabilities: gain `offset` is 0 dB, each step is `(step size + 1) / 4` dB).
/// The window holds a NUL-terminated description of the codec.
pub const MSG_SND_INFO: u32 = 0x8001;

/// Sound: program a stream. The window holds six little-endian u64: direction (0
/// playback, 1 capture), the ring buffer's physical address, its length in bytes, the
/// period length in bytes (the buffer holds a whole number of them, at most 256), the HDA
/// stream format word, and the physical address of the 4 KiB position buffer the
/// controller writes each stream's position into. Reply: `args[0]` status, `args[1]` the
/// stream's slot in the position buffer (its u64 at `8 * slot`, low 32 bits = byte
/// position in the ring).
pub const MSG_SND_SETUP: u32 = 0x8002;

/// Sound: start (`args[1]` = 1) or stop (0) the stream of direction `args[0]`; the
/// position is kept across a stop (pause). Reply: `args[0]` status, `args[1]` position.
pub const MSG_SND_TRIGGER: u32 = 0x8003;

/// Sound: the stream of direction `args[0]`'s byte position in its ring. Reply: `args[0]`
/// status, `args[1]` position.
pub const MSG_SND_POSITION: u32 = 0x8004;

/// Sound: set the volume of direction `args[0]`: `args[1]` left and `args[2]` right gain
/// (amplifier steps), `args[3]` bit 0 mutes left, bit 1 right.
pub const MSG_SND_VOLUME: u32 = 0x8005;

/// Protocol label for the sound driver's reply.
pub const MSG_SND_REPLY: u32 = 0x800F;

// ----------------------------------------------------------------------------------------
// Linux server (linux-server): Linux system calls forwarded out of the kernel (wave 3, step 1)
// ----------------------------------------------------------------------------------------
//
// The kernel's system-call trap forwards the calls its forwarding table gives to the server
// (`src/lx`) to the ring-3 `linux-server` (`userland/drivers/linux-server`). Each worker
// thread of the server has a syscall page ([`LxCall`] at offset 0), mapped in both the
// kernel and the server: the kernel writes a call into it and the worker answers with
// `SYS_LX_REPLY_RECV`, which also waits for the next call. The design is in
// `docs/linux-server-design.md` (sections 5.2 and 6.3) and `docs/src/linux-server.md`.
//
// The server's main thread serves [`ENDPOINT_LINUX_SERVER`] as an ordinary service:
// supervisor heartbeats, kernel requests made while the kernel may hold locks
// ([`MSG_LX_PROC_KEYS`]), and the notification ring in its window ([`LX_NOTES_OFF`]).

/// Well-known endpoint of the Linux server (0x29 = 41).
pub const ENDPOINT_LINUX_SERVER: u32 = 0x29;

/// Hydra's test call (a Linux system call number of its own): forwarded to the server when
/// the forwarding is on, answered in the kernel otherwise. `arg0` = [`LX_NULL_RETURN`] (0)
/// answers 0 at once; [`LX_NULL_PENDING`] answers 42 later, from the main thread, after
/// `arg1` ms (`lx_complete`); [`LX_NULL_COPY`] reads `arg2` bytes at `arg1` of the caller,
/// adds 1 to each and writes them back (client memory primitives), returning the length.
pub const LX_NULL_NR: u64 = 0x6710;
/// [`LX_NULL_NR`] operation: return 0.
pub const LX_NULL_RETURN: u64 = 0;
/// [`LX_NULL_NR`] operation: answer later (pending), then 42.
pub const LX_NULL_PENDING: u64 = 1;
/// [`LX_NULL_NR`] operation: read, change and write back the caller's buffer.
pub const LX_NULL_COPY: u64 = 2;
/// [`LX_NULL_NR`] operation (Group 9): a new test server object; `arg1` = `O_CLOEXEC` /
/// `O_NONBLOCK`; returns its descriptor. Writing `r` / `w` to it makes it readable /
/// writable, `c` clears both; reading it gives `slot N\n`.
pub const LX_NULL_OBJ: u64 = 3;
/// [`LX_NULL_NR`] operation (Group 9): how many test objects the server has seen closed
/// (their last descriptor went) since it started.
pub const LX_NULL_OBJ_CLOSES: u64 = 4;

/// Size of a worker's syscall page.
pub const LX_PAGE_SIZE: usize = 4096;
/// Most supplementary groups passed with a call (more are cut off).
pub const LX_GROUPS: usize = 32;

/// A forwarded call, at offset 0 of the worker's syscall page. The kernel fills it before
/// the worker returns from `SYS_LX_REPLY_RECV`; only `flags` changes while the worker
/// serves it (the kernel sets [`LX_CALL_INTERRUPTED`]).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LxCall {
    /// The request's ID (for `SYS_LX_COMPLETE` and the client memory primitives).
    pub id: u64,
    /// The calling thread.
    pub tid: u64,
    /// The calling thread's process.
    pub tgid: u64,
    /// Linux system call number.
    pub nr: u64,
    /// The system call's arguments.
    pub args: [u64; 6],
    /// Real user ID.
    pub uid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Saved user ID.
    pub suid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved group ID.
    pub sgid: u32,
    /// Effective capabilities (0 when they hold only inside a user namespace of its own).
    pub caps: u64,
    /// Notifications posted before this call: the server takes the ring up to here before
    /// serving it ([`LX_NOTES_OFF`]).
    pub note_seq: u64,
    /// [`LX_CALL_INTERRUPTED`].
    pub flags: u64,
    /// How many of `groups` are used.
    pub ngroups: u64,
    /// Supplementary groups.
    pub groups: [u32; LX_GROUPS],
    // Group 9 (wave 4, step 2): server-object descriptors. Appended; filled only for calls
    // whose forwarding-table entry asks for them.
    /// The slot of the server object at descriptor `args[0]` ([`LX_OBJ_NONE`]: not one of
    /// this server's objects, or the call does not take a descriptor first).
    pub obj: u64,
    /// That descriptor's status flags (`O_NONBLOCK`).
    pub obj_flags: u64,
    /// The caller's IPC namespace (System V IPC, POSIX message queues).
    pub ipc_ns: u64,
    /// The caller's umask.
    pub umask: u64,
    // Group 13 (wave 5, step 4). Appended.
    /// **Temporary** (until the VFS moves, step 6a): for `bind`/`connect` on a Unix socket
    /// path name, the socket node's inode the kernel resolved (or created, for `bind`) in
    /// the caller's context at trap time; a negative errno if that failed; 0 otherwise.
    pub ino: u64,
    // wave6 G19 begin: routing to several services (docs/linux-services-design.md 3.8). Appended.
    /// The caller's personality (Group 14's; 0 = Linux).
    pub pers: u32,
    /// The logical service the call was routed to ([`LXS_LINUX`], [`LXS_SEC`], ...): a process
    /// hosting several services (co-located) may dispatch by it.
    pub svc: u32,
    /// A second result (Group 14's, for BSD/macOS `fork`/`pipe`; unused yet).
    pub result2: u64,
    /// The caller's root and current directory as kernel directory-handle keys (0 until the
    /// kernel has directory handles, wave 7).
    pub root: u64,
    /// See [`LxCall::root`].
    pub cwd: u64,
    /// The caller's process group and session (entries with `T_FSCTX`).
    pub pgid: u32,
    /// See [`LxCall::pgid`].
    pub sid: u32,
    /// The caller's mount, network, PID and user namespace ids (entries with `T_FSCTX`).
    pub mnt_ns: u32,
    /// See [`LxCall::mnt_ns`].
    pub net_ns: u32,
    /// See [`LxCall::mnt_ns`].
    pub pid_ns: u32,
    /// See [`LxCall::mnt_ns`].
    pub user_ns: u32,
    /// The device number of a forwarded device `open` ([`LX_KCALL_DEVOPEN`]).
    pub dev: u64,
    /// The object a redirect named ([`LX_REPLY_REDIRECT`]); 0 if the call was not redirected.
    pub redir_obj: u64,
    /// Where the redirected service's part of a path starts (the redirect's `tail`).
    pub redir_tail: u32,
    /// How many times this call was redirected.
    pub redirs: u32,
    /// Group 20: the request a call between services is made for (delegation).
    pub on_behalf: u64,
    /// Group 20: the calling service of a call between services.
    pub from_svc: u32,
    /// Group 20: the operation of a call between services.
    pub dcall_op: u32,
    // wave6 G19 end
}

impl LxCall {
    /// A call with every field zero.
    pub const EMPTY: Self = Self {
        id: 0,
        tid: 0,
        tgid: 0,
        nr: 0,
        args: [0; 6],
        uid: 0,
        euid: 0,
        suid: 0,
        gid: 0,
        egid: 0,
        sgid: 0,
        caps: 0,
        note_seq: 0,
        flags: 0,
        ngroups: 0,
        groups: [0; LX_GROUPS],
        obj: LX_OBJ_NONE,
        obj_flags: 0,
        ipc_ns: 0,
        umask: 0,
        ino: 0,
        pers: 0,
        svc: 0,
        result2: 0,
        root: 0,
        cwd: 0,
        pgid: 0,
        sid: 0,
        mnt_ns: 0,
        net_ns: 0,
        pid_ns: 0,
        user_ns: 0,
        dev: 0,
        redir_obj: 0,
        redir_tail: 0,
        redirs: 0,
        on_behalf: 0,
        from_svc: 0,
        dcall_op: 0,
    };
}

/// [`LxCall::flags`]: a signal arrived for the caller while the call was being served (the
/// server may answer `-EINTR`).
pub const LX_CALL_INTERRUPTED: u64 = 1;
/// [`LxCall::flags`] bit (Group 12): the call is made again after its net wait ended
/// (`LX_OBJ_NETWAIT`): a `connect` then waits for its handshake instead of starting one.
pub const LX_CALL_RETRIED: u64 = 2;

// The copy-in/copy-out table (wave 4, Group 10). For the calls the kernel's table
// (`src/lx/copy.rs`) describes, the kernel copies pointer arguments (paths, small structures,
// buffers) into the syscall page at trap time, and copies results the server leaves in the
// page back to the caller after the answer: most calls then need no client memory call.

/// Offset of the [`LxCopy`] header in the syscall page.
pub const LX_COPY_OFF: usize = 0x200;
/// Offset of the copy area in the syscall page: the copied-in bytes and the space for output.
pub const LX_DATA_OFF: usize = 0x400;
/// Size of the copy area.
pub const LX_DATA_SIZE: usize = LX_PAGE_SIZE - LX_DATA_OFF;

/// Where the kernel put each pointer argument's bytes, at [`LX_COPY_OFF`] of the syscall page.
/// Offsets count from the start of the page; 0 means none. Valid until the worker answers.
///
/// - `in_off[i]`/`in_len[i]`: the bytes `args[i]` points to (a string: its length, without
///   the NUL that follows it). 0: not copied (a NULL pointer, too long, or no table entry):
///   the server uses `SYS_LX_READ` / `SYS_LX_READ_STR`.
/// - `out_off[i]`/`out_cap[i]`: space for output to `args[i]`'s pointer (0: none: the server
///   uses `SYS_LX_WRITE`). For in/out arguments it is the same place as the input.
/// - `out_len[i]`: written by the server before an immediate answer: bytes the kernel copies
///   from `out_off[i]` to `args[i]` after the answer (not after `LX_REPLY_PENDING`). A copy
///   that faults makes the call's result `-EFAULT`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LxCopy {
    /// See the type.
    pub in_off: [u16; 6],
    /// See the type.
    pub in_len: [u16; 6],
    /// See the type.
    pub out_off: [u16; 6],
    /// See the type.
    pub out_cap: [u16; 6],
    /// See the type.
    pub out_len: [u16; 6],
    /// Reserved (0).
    pub reserved: [u16; 2],
}

impl LxCopy {
    /// No copies.
    pub const EMPTY: Self = Self { in_off: [0; 6], in_len: [0; 6], out_off: [0; 6], out_cap: [0; 6], out_len: [0; 6], reserved: [0; 2] };
}

const _: () = assert!(core::mem::size_of::<LxCall>() <= LX_COPY_OFF);
const _: () = assert!(LX_COPY_OFF + core::mem::size_of::<LxCopy>() <= LX_DATA_OFF);

/// `SYS_LX_REPLY_RECV` flag: the call blocks; the caller keeps sleeping until some thread
/// answers it with `SYS_LX_COMPLETE`.
pub const LX_REPLY_PENDING: u64 = 1;
/// `SYS_LX_REPLY_RECV` flag: no answer (the worker's first call).
pub const LX_REPLY_NONE: u64 = 2;
/// `SYS_LX_REPLY_RECV` flag (wave 6, Group 19): a redirect: `result` = target service id
/// `| tail << 32`, the object in the page's [`LxCall::redir_obj`]. The kernel forwards the same
/// call to that service in the same trap.
pub const LX_REPLY_REDIRECT: u64 = 4;

/// `SYS_LX_CTL` operation: register the calling thread as a worker; returns the address of
/// its syscall page.
pub const LX_CTL_ATTACH: u64 = 0;
/// `SYS_LX_CTL` operation: every worker is attached and the endpoint registered: the kernel
/// starts forwarding.
pub const LX_CTL_ONLINE: u64 = 1;
/// `SYS_LX_CTL` operation: wake the server's main thread ([`NOTIFY_LX_NOTES`]), which then
/// looks at its timed work (a worker queued some).
pub const LX_CTL_WAKE: u64 = 2;
/// `SYS_LX_CTL` operation (wave 6, Group 19): maps the calling service's object area
/// (readiness slots and bitmaps, [`LX_OBJ_OFF`]) into it and returns its address.
pub const LX_CTL_OBJAREA: u64 = 3;

/// Notification ring in the server's window: u64 words at this offset: `[0]` head (the
/// kernel's next sequence number), `[1]` tail (the server's: everything before it is
/// taken), `[2]` notifications dropped because the ring was full. Entries follow at
/// [`LX_NOTES_ENTRY_OFF`]: entry `seq % LX_NOTES` is four u64 `[kind, a, b, c]`.
pub const LX_NOTES_OFF: usize = 0;
/// Offset of the first ring entry.
pub const LX_NOTES_ENTRY_OFF: usize = 64;
/// Ring entries.
pub const LX_NOTES: u64 = 4096;
/// Notification: process `a` forked process `b` (a new process, not a thread).
pub const LX_NOTE_FORK: u64 = 1;
/// Notification: thread `a` of process `b` called `execve`.
pub const LX_NOTE_EXEC: u64 = 2;
/// Notification: the last thread of process `a` ended.
pub const LX_NOTE_EXIT: u64 = 3;
/// Notification: a signal arrived for the caller of pending request `a` (answered later
/// with `SYS_LX_COMPLETE`); the server may answer it `-EINTR`.
pub const LX_NOTE_INTERRUPT: u64 = 4;
/// Notification: the last descriptor of server object `a` (a slot) went away (closed,
/// its process ended, or close-on-exec); `b` is the object's kind ([`LX_OBJ_KIND_MQ`], ...).
pub const LX_NOTE_CLOSE: u64 = 5;
/// Notification bit ([`MSG_SVC_NOTIFY`]): notifications were posted to the ring.
pub const NOTIFY_LX_NOTES: u64 = 2;

/// Kernel to linux-server's main thread: the text of `/proc/keys` for the caller. `args`:
/// `[0]` tid, `[1]` tgid, `[2]` `euid | egid << 32`, `[3]` effective capabilities. The
/// window holds the caller's supplementary groups at [`LX_PROC_KEYS_GROUPS_OFF`] (u32
/// count, then the IDs); the text goes to [`LX_PROC_KEYS_TEXT_OFF`]. Reply
/// [`MSG_LX_REPLY`] with `args[0]` the text's length or a negative errno.
pub const MSG_LX_PROC_KEYS: u32 = 0xA001;
/// Reply label of the Linux server's endpoint requests.
pub const MSG_LX_REPLY: u32 = 0xA00F;
/// Window offset of the groups of [`MSG_LX_PROC_KEYS`].
pub const LX_PROC_KEYS_GROUPS_OFF: usize = 0x30000;
/// Window offset of the text of [`MSG_LX_PROC_KEYS`] (up to [`LX_PROC_KEYS_TEXT_MAX`] bytes).
pub const LX_PROC_KEYS_TEXT_OFF: usize = 0x31000;
/// Most bytes of `/proc/keys` text.
pub const LX_PROC_KEYS_TEXT_MAX: usize = 0xF000;

// Server-object descriptors (Group 9, wave 4, step 2)
// ----------------------------------------------------------------------------------------
//
// A descriptor whose object lives in linux-server (a POSIX message queue, a bpf map, ...).
// The kernel keeps the descriptor table: the descriptor is a kernel object naming the
// server's *slot*; `dup`, `fork`, close-on-exec and exit share and drop it as any other
// descriptor, and when the last reference goes the server gets [`LX_NOTE_CLOSE`]. The
// server keeps each object's readiness in its window ([`LX_OBJ_OFF`]): `poll`, `select` and
// `epoll` read it without a call; when words change the server marks the slots in
// [`LX_OBJ_CHANGED_OFF`] and rings `SYS_SVC_SIGNAL(ENDPOINT_LINUX_SERVER, LX_SIGNAL_OBJS)`,
// and the kernel wakes the waiters.

/// [`LxCall::obj_flags`] bit: `obj` is the object of the descriptor `args[1]` points to (its
/// number in bits 32..62), not of `args[0]`.
pub const LX_OBJ_FLAGS_AT1: u64 = 1 << 63;

/// Number of server-object slots of one service (wave 6, Group 19: was 2048; Wine used half).
pub const LX_OBJ_SLOTS: usize = 8192;
/// [`LxCall::obj`]: no server object.
pub const LX_OBJ_NONE: u64 = u64::MAX;
/// Offset of the readiness slots **in the service's object area** (wave 6, Group 19: no longer
/// in the window; `LX_CTL_OBJAREA` maps the area): slot `s` is 16 bytes at `LX_OBJ_OFF + 16 * s`:
/// `[u32 poll bits (POLLIN, POLLOUT, POLLERR, POLLHUP, ...), u32 edge count (+1 whenever
/// bits are added: edge-triggered epoll), u64 size (st_size)]`.
pub const LX_OBJ_OFF: usize = 0;
/// Object-area offset of the changed-slot bitmap (`LX_OBJ_SLOTS` bits, u64 words): the server
/// sets bit `s` (atomic or) after changing slot `s`; the kernel takes the words (atomic swap
/// with 0) and wakes the objects' waiters.
pub const LX_OBJ_CHANGED_OFF: usize = 16 * LX_OBJ_SLOTS;
/// Object-area offset of the watched-slot bitmap (`LX_OBJ_SLOTS` bits): the kernel sets bit `s`
/// (atomic or) the first time a task waits for slot `s` (`poll`, `select`, `epoll`) and never
/// clears it; the server clears it when it hands the slot out again. The server rings the
/// doorbell only for watched slots (an object nobody ever waited on costs no doorbell).
/// Ordering: the kernel sets the bit before it reads the word; the server writes the word,
/// then (after a full fence) reads the bit.
pub const LX_OBJ_WATCHED_OFF: usize = LX_OBJ_CHANGED_OFF + LX_OBJ_SLOTS / 8;
/// Pages of a service's object area (the readiness slots and both bitmaps).
pub const LX_OBJ_AREA_PAGES: u64 = ((LX_OBJ_WATCHED_OFF + LX_OBJ_SLOTS / 8 + 4095) / 4096) as u64;
/// `SYS_SVC_SIGNAL` bits from the server: readiness words changed.
pub const LX_SIGNAL_OBJS: u64 = 1;

/// Kind of a server object (told to the kernel at install, given back in [`LX_NOTE_CLOSE`]).
pub const LX_OBJ_KIND_TEST: u32 = 1;
/// A POSIX message queue descriptor.
pub const LX_OBJ_KIND_MQ: u32 = 2;
/// A bpf map.
pub const LX_OBJ_KIND_BPF_MAP: u32 = 3;
/// A bpf program.
pub const LX_OBJ_KIND_BPF_PROG: u32 = 4;
/// A bpf link.
pub const LX_OBJ_KIND_BPF_LINK: u32 = 5;
/// A bpf BTF object.
pub const LX_OBJ_KIND_BPF_BTF: u32 = 6;

/// `SYS_LX_OBJ` operation: `(request id, *LxObjDesc) -> fd`: installs a new descriptor for
/// the server object the description names in the table of request `id`'s caller.
pub const LX_OBJ_INSTALL: u64 = 0;
/// `SYS_LX_OBJ` operation: `(request id, fd) -> slot | kind << 32 | nonblock << 62`: the
/// server object behind descriptor `fd` of the caller (`-EBADF`: none of this server's).
pub const LX_OBJ_FD: u64 = 1;
/// `SYS_LX_OBJ` operation: `(slot, flags)`: sets the object's `O_NONBLOCK` (`mq_setattr`).
pub const LX_OBJ_SETFL: u64 = 2;
/// `SYS_LX_OBJ` operation: `(request id, fd) -> token`: keeps the caller's (kernel)
/// descriptor `fd` for the server (glibc's `SIGEV_THREAD` netlink socket).
pub const LX_OBJ_PIN: u64 = 3;
/// `SYS_LX_OBJ` operation: `(token)`: lets a kept descriptor go.
pub const LX_OBJ_UNPIN: u64 = 4;
/// `SYS_LX_OBJ` operation: `(token, buf, len)`: queues `len` bytes as a notification
/// message on a kept descriptor (a netlink socket).
pub const LX_OBJ_NOTIFY: u64 = 5;
/// `SYS_LX_OBJ` operation: `(request id, buf, len)`: the caller's `comm` (bpf's
/// `get_current_comm`), NUL-padded to `len` (at most 16) bytes.
pub const LX_OBJ_COMM: u64 = 6;
/// `SYS_LX_OBJ` operation, **temporary** (until the VFS moves, step 6): `(request id, fd,
/// buf) -> length`: the path of the caller's file descriptor `fd` (at most 4096 bytes; a bpf
/// cgroup attachment names its cgroup by a directory descriptor).
pub const LX_OBJ_FDPATH: u64 = 7;
/// `SYS_LX_OBJ` operation: `(buf, len)`: the complete list of bpf device programs attached
/// to cgroups, which the kernel runs itself on device opens and `mknod`s: entries of
/// `[u32 cgroup length, cgroup path below /sys/fs/cgroup, u32 instruction count, the
/// instructions (8 bytes each)]`. `-EINVAL` if one is refused (it uses maps, or fails the
/// kernel's checks); the kernel then keeps its previous list.
pub const LX_OBJ_BPF_DEVICE: u64 = 8;

/// Most bytes of an object's name in [`LxObjDesc`].
pub const LX_OBJ_NAME_MAX: usize = 104;

/// The description of a new server object for [`LX_OBJ_INSTALL`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LxObjDesc {
    /// Its slot (`0..LX_OBJ_SLOTS`; the server initializes the readiness slot first).
    pub slot: u32,
    /// `LX_OBJ_KIND_*`.
    pub kind: u32,
    /// Linux `O_CLOEXEC` and `O_NONBLOCK` bits.
    pub flags: u32,
    /// `st_mode` (file type and permissions).
    pub mode: u32,
    /// `st_uid`.
    pub uid: u32,
    /// `st_gid`.
    pub gid: u32,
    /// Bytes of `name` used.
    pub name_len: u32,
    /// Unused (0).
    pub pad: u32,
    /// What `/proc/<pid>/fd/N` shows (`/name` for a message queue, `anon_inode:bpf-map`).
    pub name: [u8; LX_OBJ_NAME_MAX],
    /// Group 13: a value the kernel may read back from the descriptor (a pidfd's process;
    /// a Unix socket's or pipe's inode number for `fstat`; 0: none).
    pub tag: u64,
}

// Group 13 (wave 5, step 4): Unix sockets, pipes, eventfd, timerfd, signalfd, pidfd
// ----------------------------------------------------------------------------------------

/// The read end of a pipe (or a FIFO opened for reading).
pub const LX_OBJ_KIND_PIPE_R: u32 = 16;
/// The write end of a pipe (or a FIFO opened for writing).
pub const LX_OBJ_KIND_PIPE_W: u32 = 17;
/// A Unix socket.
pub const LX_OBJ_KIND_UNIX: u32 = 18;
/// An eventfd.
pub const LX_OBJ_KIND_EVENTFD: u32 = 19;
/// A timerfd.
pub const LX_OBJ_KIND_TIMERFD: u32 = 20;
/// A signalfd.
pub const LX_OBJ_KIND_SIGNALFD: u32 = 21;
/// A pidfd.
pub const LX_OBJ_KIND_PIDFD: u32 = 22;
/// A FIFO opened `O_RDWR` (a read and a write end in one).
pub const LX_OBJ_KIND_PIPE_RW: u32 = 23;

/// [`LxCall::obj_flags`] bit: a transfer the kernel makes with its own buffer (`splice`,
/// `sendfile`, io_uring, aio's eventfd): `args[1]` is [`LX_KBUF_ADDR`], whose bytes are all in
/// the copy area (in for a write, out for a read). The server must answer at once (never
/// `LX_REPLY_PENDING`: `-EAGAIN` instead; the kernel waits on the readiness word) and posts
/// no `SIGPIPE` (the kernel does).
pub const LX_OBJ_FLAGS_KBUF: u64 = 1 << 60;
/// `args[1]` of a kernel-buffer call: not a user address (a fallback to the client memory
/// primitives fails with `-EFAULT`).
pub const LX_KBUF_ADDR: u64 = 0xFFFF_FF80_0000_0000;

/// `SYS_LX_OBJ` operation (descriptor passing, `SCM_RIGHTS`): `(request id, buf, n)`: keeps
/// `n` descriptors of the caller for the server. `buf` (server memory) holds `n` entries of
/// three u64: in `[0]` the descriptor; out `[1]` a token, `[2]` what it is:
/// `slot | kind << 32 | 1 << 63` for one of this server's objects, 0 for a kernel
/// descriptor. All or nothing (`-EBADF` names no entry).
pub const LX_OBJ_TAKE: u64 = 9;
/// `SYS_LX_OBJ` operation: `(request id, buf, n | flags << 32)`: installs kept descriptors
/// in the caller's table (`flags`: `O_CLOEXEC`). Entries of two u64: in `[0]` a token, out
/// `[1]` the new descriptor. Installed tokens are used up; on an error (`-EMFILE`) the
/// entries not installed keep their tokens and their `[1]` is `u64::MAX`.
pub const LX_OBJ_GIVE: u64 = 10;
/// `SYS_LX_OBJ` operation: `(buf, n)`: lets `n` kept descriptors go (u64 tokens).
pub const LX_OBJ_DROP: u64 = 11;
/// `SYS_LX_OBJ` operation: `(slot)`: how many kernel references hold the server object in
/// `slot` (descriptors, kept descriptors, calls in flight); 0 if none.
pub const LX_OBJ_REFS: u64 = 12;
/// `SYS_LX_OBJ` operation: `(pid)`: 1 if Linux process `pid` runs, 2 if it has exited (a
/// zombie), `-ESRCH` if there is none (pidfd).
pub const LX_OBJ_PROC: u64 = 13;
/// `SYS_LX_OBJ` operation: `(slot, mask)`: the signals signalfd `slot` takes (the kernel
/// answers `poll` on it from the process's pending signals).
pub const LX_OBJ_SIGMASK: u64 = 14;

/// Native system call `SYS_LX_TIMER` (62) operation: `(cookie, ns)`: notify
/// [`LX_NOTE_TIMER`] once the kernel's monotonic clock reaches `ns` (re-arming a cookie
/// replaces its deadline). Checked at every timer tick (10 ms).
pub const LX_TIMER_ARM: u64 = 0;
/// `SYS_LX_TIMER` operation: `(cookie)`: forget the timer.
pub const LX_TIMER_CANCEL: u64 = 1;
/// `SYS_LX_TIMER` operation: returns the kernel's monotonic clock (ns since boot).
pub const LX_TIMER_NOW: u64 = 2;
/// Notification: timer `a` (a cookie) armed for `b` expired.
pub const LX_NOTE_TIMER: u64 = 6;
/// Notification (signalfd): a signal in mask `b` became pending for thread `a` (0: for
/// the process `c`).
pub const LX_NOTE_SIGNAL: u64 = 7;

/// Kernel to linux-server's main thread: the text of `/proc/net/unix`; the text goes to
/// [`LX_PROC_KEYS_TEXT_OFF`] (reply `args[0]`: its length).
pub const MSG_LX_PROC_NET_UNIX: u32 = 0xA003;

/// Hydra-private call numbers the kernel forwards on behalf of the current Linux thread
/// (not reachable from user mode: the table only routes numbers below 512 and
/// [`LX_NULL_NR`]). `LX_KCALL_REOPEN(fd, access)`: opening `/proc/self/fd/N` of a pipe: a
/// new descriptor for the same pipe (`args[1]`: `O_RDONLY` or `O_WRONLY`, plus
/// `O_CLOEXEC`/`O_NONBLOCK`), object in [`LxCall::obj`].
pub const LX_KCALL_REOPEN: u64 = 0x6780;
/// `LX_KCALL_PIDFD(pid, flags)`: a new pidfd for process `pid` in the caller's table
/// (`clone(CLONE_PIDFD)`, `SO_PEERPIDFD` of a kernel socket).
pub const LX_KCALL_PIDFD: u64 = 0x6781;
/// `LX_KCALL_FCNTL(fd, cmd, arg)`: `fcntl` commands of server objects
/// (`F_GETPIPE_SZ`, `F_SETPIPE_SZ`).
pub const LX_KCALL_FCNTL: u64 = 0x6782;
/// `LX_KCALL_FIFO(ino, flags)`: `open` of FIFO node `ino` (permissions checked by the
/// kernel): a pipe end in the caller's table, waiting for the other side as Linux does.
pub const LX_KCALL_FIFO: u64 = 0x6783;
// Network sockets in linux-server (Group 12, wave 5, step 3)
// ----------------------------------------------------------------------------------------
//
// AF_INET, AF_INET6 and AF_NETLINK sockets are server objects; linux-server is
// net-server's second client (its part of the window: [`NETS_LX_DATA_OFF`], its tag
// [`NETS_CLIENT_LX`]). net-server's doorbell reaches it as a notification
// ([`NOTIFY_LX_NET`]), and it relays the readiness of its sockets to their objects'
// readiness words (`docs/linux-server-design.md`, step 3 as built).

/// Notification bit ([`MSG_SVC_NOTIFY`]): net-server rang its doorbell (socket readiness
/// changed: new entries in its event ring).
pub const NOTIFY_LX_NET: u64 = 4;
/// Notification bit: net-server went away (its sockets are dead; a new one may come).
pub const NOTIFY_LX_NET_GONE: u64 = 8;
/// Kind of a server object: an `AF_INET` or `AF_INET6` socket.
pub const LX_OBJ_KIND_INET: u32 = 7;
/// Kind of a server object: an `AF_NETLINK` socket (routing or uevent).
pub const LX_OBJ_KIND_NETLINK: u32 = 8;
/// [`LxCall::obj_flags`] bit of a socket call (routed by family or descriptor): the caller
/// is in a network namespace of its own (it sees only loopback). Never set together with
/// [`LX_OBJ_FLAGS_AT1`].
pub const LX_OBJ_FLAGS_NETNS: u64 = 1 << 61;
/// `SYS_LX_OBJ` operation: `(request id, port, access)`: Landlock's check of a TCP `bind`
/// (access 1) or `connect` (2) to `port` for the request's caller: 0 or `-EACCES`.
pub const LX_OBJ_NETCHECK: u64 = 16;
/// `SYS_LX_OBJ` operation: `(request id, signal)`: posts `signal` to the request's calling
/// thread (`SIGPIPE` of a send on a broken connection).
pub const LX_OBJ_SIGTHREAD: u64 = 17;
/// Kernel to linux-server's main thread: the text of `/proc/net/<file>` (`args[0]`: 0 `tcp`,
/// 1 `tcp6`, 2 `udp`, 3 `udp6`; `args[1]`: 1 if the reader is in a network namespace of
/// its own) to [`LX_PROC_KEYS_TEXT_OFF`]. Reply [`MSG_LX_REPLY`], `args[0]` its length.
pub const MSG_LX_PROC_NET: u32 = 0xA002;
/// `SYS_SVC_CALL` timeout bit: a hand-off call (only linux-server calling net-server: its
/// socket requests answer at once, like the kernel's own hand-off socket calls).
pub const SVC_CALL_HANDOFF: u64 = 1 << 62;
/// `SYS_LX_OBJ` operation: `(request id, net-server handle, readiness word seen)`: the
/// request waits on the handle (a socket call that must block). 1: the handle's readiness
/// word is no longer the one seen (try the call again now); 0: registered: the kernel's
/// net-server doorbell completes the request with [`LX_RETRY`] when the handle has an event,
/// and the caller makes the call again (the server answers it "pending" as usual).
pub const LX_OBJ_NETWAIT: u64 = 18;
/// `SYS_LX_OBJ` operation: `(request id)`: withdraws its net wait; 1 if it was still
/// registered (the server then answers the request itself), 0 if not.
pub const LX_OBJ_NETCANCEL: u64 = 19;
/// `SYS_LX_OBJ` operation: `(on)`: linux-server keeps socket calls that need net-server's
/// events relayed to its main thread (on), or none any more (the kernel then relays only
/// while an Internet socket is watched by `poll`/`select`/`epoll`).
pub const LX_OBJ_RELAY: u64 = 20;
/// The answer to a forwarded call that means "make the same call again" (a net wait ended):
/// handled by the kernel's forwarding, never seen by a Linux program (not an errno).
pub const LX_RETRY: i64 = -4097;

// wave6 G23 begin: memory objects (`SYS_LX_MEM`, native syscall 64; kernel side `crate::lx::mem`)
/// `SYS_LX_MEM` operation: `(size, flags, key) -> handle`: a new anonymous memory object of
/// `size` bytes (rounded up to pages), zero-filled, pages allocated on first touch. With
/// [`LX_MEM_KEPT`] it is a *kept* object: owned by the service registry, found again by
/// `(service, key)` after a restart (`key` 0 is reserved); the result then has
/// [`LX_MEM_EXISTED`] set when the object already existed (its contents survived).
pub const LX_MEM_ANON: u64 = 1;
/// `SYS_LX_MEM` operation: `(size, *dev_addr) -> handle`: physically contiguous, pinned,
/// zeroed memory the caller's device may reach (as `SYS_DMA_ALLOC`, at most 16 MiB); its
/// device address is stored at `dev_addr` (if not 0).
pub const LX_MEM_DMA: u64 = 2;
/// `SYS_LX_MEM` operation: `(handle, offset, len, prot) -> addr`: maps `len` bytes of the
/// object from byte `offset` (page-aligned) into the caller, shared.
pub const LX_MEM_MAP: u64 = 3;
/// `SYS_LX_MEM` operation: `(addr, len)`: unmaps a range of the caller.
pub const LX_MEM_UNMAP: u64 = 4;
/// `SYS_LX_MEM` operation: `(handle)`: drops the caller's handle (mappings stay).
pub const LX_MEM_CLOSE: u64 = 5;
/// `SYS_LX_MEM` operation: `(handle, peer endpoint) -> the peer's handle`: the design's
/// `LX_SVC_SHARE`: the same object in another service's table (the caller tells the peer
/// the number itself).
pub const LX_MEM_SHARE: u64 = 6;
/// `SYS_LX_MEM` operation: `(handle) -> pages | flags << 48` (bit 48: kept, bit 49: DMA).
pub const LX_MEM_INFO: u64 = 7;
/// `SYS_LX_MEM` operation: `(key)`: the caller's service drops its kept object `key`.
pub const LX_MEM_UNKEEP: u64 = 8;
/// [`LX_MEM_ANON`] flag: a kept object.
pub const LX_MEM_KEPT: u64 = 1;
/// [`LX_MEM_ANON`] result bit: the kept object existed already.
pub const LX_MEM_EXISTED: i64 = 1 << 32;
/// Largest anonymous memory object (1 GiB).
pub const LX_MEM_MAX: u64 = 1 << 30;
/// Most handles one service holds at once.
pub const LX_MEM_HANDLES: usize = 4096;

/// A service's answer to a forwarded `mmap` (nr 9) of one of its objects: map the memory
/// object `handle` (in the answering service's table), starting at object page `pgoff`;
/// `read_only` refuses a writable shared mapping (`EACCES`). Negative answers are errnos.
pub const fn lx_mmap_answer(handle: u32, pgoff: u64, read_only: bool) -> i64 {
    ((handle as u64 & 0x7FFF) | (read_only as u64) << 15 | (pgoff & 0x7FFF_FFFF_FFFF) << 16) as i64
}

/// The parts of an [`lx_mmap_answer`]: `(handle, pgoff, read_only)`.
pub const fn lx_mmap_parts(answer: i64) -> (u32, u64, bool) {
    let a = answer as u64;
    ((a & 0x7FFF) as u32, a >> 16 & 0x7FFF_FFFF_FFFF, a >> 15 & 1 == 1)
}
// wave6 G23 end
// ----------------------------------------------------------------------------------------
// wave6 G19 begin: services (wave 6, Group 19, docs/linux-services-design.md section 3)
// ----------------------------------------------------------------------------------------
//
// The kernel routes each forwarded call to the service that owns it. A service id names a
// Linux-facing service; several ids may be served by one process (co-located: their
// registry entries name the same endpoint). Request ids carry the id of the process's
// table (`id = host << 56 | sequence`).

/// A service id (0: the kernel).
pub type SvcId = u8;
/// The kernel (not forwarded).
pub const LXS_KERNEL: SvcId = 0;
/// linux-server: everything not split out yet.
pub const LXS_LINUX: SvcId = 1;
/// vfs-server (wave 7).
pub const LXS_VFS: SvcId = 2;
/// Internet and netlink sockets.
pub const LXS_NET: SvcId = 3;
/// Unix sockets, pipes, FIFOs, eventfd, timerfd, signalfd, pidfd, POSIX and System V IPC.
pub const LXS_IPC: SvcId = 4;
/// Process and signal policy, `/proc`.
pub const LXS_PROC: SvcId = 5;
/// Display (DRM).
pub const LXS_DISPLAY: SvcId = 6;
/// Input (evdev).
pub const LXS_INPUT: SvcId = 7;
/// Sound (ALSA).
pub const LXS_SOUND: SvcId = 8;
/// Terminals.
pub const LXS_TTY: SvcId = 9;
/// Keys and bpf (lx-sec).
pub const LXS_SEC: SvcId = 10;
/// The test service (`userland/drivers/svc-test`).
pub const LXS_TEST: SvcId = 11;
/// Size of the registry.
pub const LXS_MAX: usize = 16;
/// The services' names (boot words `lx.<name>=kernel|linux`, logs).
pub const LXS_NAMES: [&str; LXS_MAX] = ["kernel", "linux", "vfs", "net", "ipc", "proc", "display", "input", "sound", "tty", "sec", "test", "s12", "s13", "s14", "s15"];

/// Endpoint of vfs-server (wave 7).
pub const ENDPOINT_VFS_SERVER: u32 = 0x2D;
/// Endpoint of lx-net, once split out.
pub const ENDPOINT_LX_NET: u32 = 0x2E;
/// Endpoint of lx-ipc, once split out.
pub const ENDPOINT_LX_IPC: u32 = 0x2F;
/// Endpoint of lx-proc, once split out.
pub const ENDPOINT_LX_PROC: u32 = 0x30;
/// Endpoint of lx-sec (keys, bpf), once split out.
pub const ENDPOINT_LX_SEC: u32 = 0x31;
/// Endpoint of the test service.
pub const ENDPOINT_SVC_TEST: u32 = 0x32;

/// Request ids: bits 56..63 hold the id of the table (the serving process's host id).
pub const LX_REQ_SVC_SHIFT: u32 = 56;

/// The host id of request `id`.
pub const fn lx_req_svc(id: u64) -> SvcId {
    (id >> LX_REQ_SVC_SHIFT) as SvcId
}

/// Most redirects of one call (then `-ELOOP`).
pub const LX_REDIR_MAX: u32 = 4;
/// Internal result of a redirected call (never seen by a program).
pub const LX_REDIRECTED: i64 = -4100;

/// `LX_KCALL_DEVOPEN(rdev, flags)`: `open` of a character device whose major a service
/// claimed ([`LX_SVC_CLAIM_MAJOR`]), with [`LxCall::dev`] = `rdev`: the service installs a
/// descriptor ([`LX_OBJ_INSTALL`]) and answers its number.
pub const LX_KCALL_DEVOPEN: u64 = 0x6784;

/// The test service's call (a Hydra-private number, routed to [`LXS_TEST`]). `arg0` is the
/// operation: [`LX_TEST_NULL`], [`LX_TEST_OBJ`], ...
pub const LX_TEST_NR: u64 = 0x6711;
/// [`LX_TEST_NR`]: return 0 at once.
pub const LX_TEST_NULL: u64 = 0;
/// [`LX_TEST_NR`]: a new test object (`arg1`: `O_CLOEXEC`/`O_NONBLOCK`); returns its descriptor.
/// Writing `r`/`w`/`c` makes it readable / writable / clears both; reading gives `svc-test N`.
pub const LX_TEST_OBJ: u64 = 1;
/// [`LX_TEST_NR`]: answer later (pending): `arg1` ms, then [`LX_TEST_PENDING_RESULT`].
pub const LX_TEST_PENDING: u64 = 2;
/// The answer of [`LX_TEST_PENDING`].
pub const LX_TEST_PENDING_RESULT: i64 = 4242;
/// [`LX_TEST_NR`]: redirect to linux-server (`arg1` = object, `arg2` = tail): linux-server's
/// answer to a redirected [`LX_TEST_NR`] is `0x5000 + redir_obj + 0x100 * redirs + redir_tail`.
pub const LX_TEST_REDIRECT: u64 = 3;
/// [`LX_TEST_NR`]: which process serves it (the test service's process id).
pub const LX_TEST_WHO: u64 = 4;
/// [`LX_TEST_NR`]: add 1 to each of `arg2` bytes at `arg1` of the caller (client memory).
pub const LX_TEST_COPY: u64 = 5;
/// [`LX_TEST_NR`]: redirect to itself `arg1` times more (a loop: `-ELOOP` beyond the limit).
pub const LX_TEST_REDIR_LOOP: u64 = 6;
/// Kind of the test service's objects.
pub const LX_OBJ_KIND_SVCTEST: u32 = 30;
/// The character major the test service claims (Linux's "local/experimental" range).
pub const SVC_TEST_MAJOR: u64 = 240;

/// Native system call 72 `SYS_LX_SVC(op, a, b, c)`: a service's registry operations.
/// `(mask)`: the process events (bit k = notification kind k: FORK 1, EXEC 2, EXIT 3) the
/// calling service wants in its ring.
pub const LX_SVC_SUBSCRIBE: u64 = 0;
/// `SYS_LX_SVC`: `(major, svc)`: `open` of a character device of `major` goes to service
/// `svc` (one hosted by the caller; 0: the caller's own).
pub const LX_SVC_CLAIM_MAJOR: u64 = 1;
/// `SYS_LX_SVC`: the calling process's host id.
pub const LX_SVC_WHOAMI: u64 = 2;
// (ops 3-7: Group 20; 16-23: Group 21)
// wave6 G19 end
