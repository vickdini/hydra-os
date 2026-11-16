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
