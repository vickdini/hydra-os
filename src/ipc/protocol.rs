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
//! All operations fit within the 4-argument [`super::Message`] structure, ensuring zero heap allocation
//! across client-server IPC boundaries.

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

/// Protocol label for network driver operation reply.
///
/// Inline arguments:
/// - `args[0]`: Return status code (0 for success, negative for standard POSIX errno).
/// - `args[1]`: Primary return value (e.g. bytes transferred, or low 32 bits of MAC).
/// - `args[2]`: Secondary return value (e.g. high 16 bits of MAC).
/// - `args[3]`: Link state bitmask (bit 0 = Link Up, bit 1 = Full Duplex, bit 2 = 1 Gbps).
pub const MSG_NET_REPLY: u32 = 0x400F;

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



