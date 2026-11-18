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
/// UDP: receive `[handle, offset, peek]` -> `[length, addr << 16 | port, arrival time
/// (ns since 1970)]` with the whole datagram at the offset, or `-EAGAIN`.
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
/// ICMP: receive `[handle, offset, peek]` -> `[length, addr, arrival time]`, or `-EAGAIN`.
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
    };
}

/// [`LxCall::flags`]: a signal arrived for the caller while the call was being served (the
/// server may answer `-EINTR`).
pub const LX_CALL_INTERRUPTED: u64 = 1;

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

/// `SYS_LX_CTL` operation: register the calling thread as a worker; returns the address of
/// its syscall page.
pub const LX_CTL_ATTACH: u64 = 0;
/// `SYS_LX_CTL` operation: every worker is attached and the endpoint registered: the kernel
/// starts forwarding.
pub const LX_CTL_ONLINE: u64 = 1;
/// `SYS_LX_CTL` operation: wake the server's main thread ([`NOTIFY_LX_NOTES`]), which then
/// looks at its timed work (a worker queued some).
pub const LX_CTL_WAKE: u64 = 2;

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
