//! # Admin interface: the wire format (shared with ring-3 programs)
//!
//! The kernel's admin interface is the small, explicit set of kernel calls a ring-3 shell
//! needs (see `docs/shell-admin-interface.md`). This file is the whole ABI: operation
//! numbers, the call block and the records the kernel writes back. It has no dependencies,
//! so ring-3 programs include it as source (`#[path]`), as the drivers do with
//! `ipc/protocol.rs`.
//!
//! ## The call
//! A program fills an [`AdminCall`] and makes the native system call [`SYS_ADMIN`] with its
//! address in `rdi`. The result in `rax`:
//! - `>= 0`: success; the size in bytes of the whole answer. The kernel wrote
//!   `min(answer, out_cap)` bytes to `out_ptr`; when the answer is larger the caller retries
//!   with a bigger buffer (like `snprintf`).
//! - `< 0`: `-errno` ([`EPERM`]: the caller is not an authorized admin console). If the
//!   failing operation has a message for the user, the kernel wrote it (UTF-8) to `out_ptr`
//!   and its length to [`AdminCall::err_len`].
//!
//! Records are `#[repr(C)]` and are written back to back; readers use unaligned reads.

/// The native system call number of the admin interface.
pub const SYS_ADMIN: u64 = 40;

/// Version of this interface (`ADMIN_VERSION` answers it): bumped on incompatible changes.
pub const ADMIN_ABI_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Operations. Groups by the high nibble: 0x0_ meta, 0x1_ console, 0x2_ tasks, 0x3_ memory,
// 0x4_ services, 0x5_ storage, 0x7_ power. Part 2 adds more (network, Linux root, ...).
// ---------------------------------------------------------------------------

/// Answers a `u32`: [`ADMIN_ABI_VERSION`].
pub const ADMIN_VERSION: u32 = 0x01;
/// Sets the console colours: `args[0]` foreground, `args[1]` background (the UEFI text
/// colour numbers 0-15, as `uefi::proto::console::text::Color`). No answer.
pub const ADMIN_CONSOLE_COLOR: u32 = 0x10;
/// Answers a [`TaskListHeader`] and then `count` [`TaskRecord`]s.
pub const ADMIN_TASK_LIST: u32 = 0x20;
/// Answers a [`MemInfo`].
pub const ADMIN_MEM_INFO: u32 = 0x30;
/// Answers [`ServiceRecord`]s (one per supervised service).
pub const ADMIN_SERVICE_LIST: u32 = 0x40;
/// Answers [`IrqRecord`]s (one per interrupt line routed to a driver).
pub const ADMIN_IRQ_LIST: u32 = 0x41;
/// Answers a [`PoolStatus`].
pub const ADMIN_POOL_STATUS: u32 = 0x50;
/// Input: a path. Answers a [`DirHeader`] and then `count` [`DirRecord`]s.
pub const ADMIN_DIR_LIST: u32 = 0x51;
/// Input: a path. Answers a [`LookupRecord`].
pub const ADMIN_LOOKUP: u32 = 0x52;
/// `args[0]`: [`POWER_OFF`] or [`POWER_REBOOT`]. Does not return on success.
pub const ADMIN_POWER: u32 = 0x70;

/// `ADMIN_POWER`: power off (ACPI S5).
pub const POWER_OFF: u64 = 0;
/// `ADMIN_POWER`: restart.
pub const POWER_REBOOT: u64 = 1;

// errno values the interface returns (negated)
/// Not an authorized admin console.
pub const EPERM: i64 = 1;
/// No such file or object.
pub const ENOENT: i64 = 2;
/// The operation failed; see the message.
pub const EIO: i64 = 5;
/// A bad pointer.
pub const EFAULT: i64 = 14;
/// A bad argument.
pub const EINVAL: i64 = 22;
/// Unknown operation.
pub const ENOSYS: i64 = 38;

/// The call block (`rdi` points to it). The kernel reads it and writes back `err_len`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct AdminCall {
    /// Operation (`ADMIN_*`).
    pub op: u32,
    /// Reserved, 0.
    pub flags: u32,
    /// Numeric arguments.
    pub args: [u64; 4],
    /// Input bytes (a path or a name), or 0.
    pub in_ptr: u64,
    /// Length of the input.
    pub in_len: u64,
    /// The answer buffer, or 0 (then the call only returns the answer's size).
    pub out_ptr: u64,
    /// Size of the answer buffer.
    pub out_cap: u64,
    /// Out: length of the error message written to `out_ptr` (0: none).
    pub err_len: u64,
}

/// Fixed-size, NUL-padded name field of the records.
pub const NAME_LEN: usize = 32;

/// `ADMIN_TASK_LIST` header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TaskListHeader {
    /// Number of [`TaskRecord`]s that follow.
    pub count: u32,
    /// Scheduler time slice in milliseconds.
    pub timeslice_ms: u32,
    /// The demo worker counter (`spawn worker`).
    pub worker_counter: u64,
}

/// Task modes ([`TaskRecord::mode`]).
pub const MODE_KERNEL: u8 = 0;
/// Ring 3.
pub const MODE_USER: u8 = 1;

/// Task states ([`TaskRecord::state`]).
pub const STATE_READY: u8 = 0;
/// Running on a CPU.
pub const STATE_RUNNING: u8 = 1;
/// Blocked on a wait queue.
pub const STATE_BLOCKED: u8 = 2;
/// Sleeping until a deadline.
pub const STATE_SLEEPING: u8 = 3;
/// Exited, not yet reaped.
pub const STATE_DEAD: u8 = 4;

/// Priorities ([`TaskRecord::priority`]): 0 Idle, 1 Low, 2 Normal, 3 High, 4 Realtime.
pub const PRIORITY_NAMES: [&str; 5] = ["Idle", "Low", "Normal", "High", "Realtime"];

/// One task (`ADMIN_TASK_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TaskRecord {
    /// Task id.
    pub pid: u64,
    /// Real user id.
    pub uid: u32,
    /// [`MODE_KERNEL`] or [`MODE_USER`].
    pub mode: u8,
    /// `STATE_*`.
    pub state: u8,
    /// Index into [`PRIORITY_NAMES`].
    pub priority: u8,
    /// Reserved.
    pub _pad: u8,
    /// Timer ticks run.
    pub ticks: u64,
    /// Last saved stack pointer.
    pub rsp: u64,
    /// Name, NUL-padded.
    pub name: [u8; NAME_LEN],
}

/// `ADMIN_MEM_INFO`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MemInfo {
    /// Usable physical memory in bytes.
    pub total: u64,
    /// Allocated physical memory in bytes.
    pub allocated: u64,
    /// Free physical memory in bytes.
    pub free: u64,
    /// Page size in bytes.
    pub page_size: u64,
    /// 1 if the kernel heap is initialized.
    pub heap_initialized: u64,
    /// Kernel heap start address.
    pub heap_start: u64,
    /// Kernel heap size in bytes.
    pub heap_total: u64,
    /// Kernel heap bytes in use.
    pub heap_used: u64,
    /// Kernel heap bytes free.
    pub heap_free: u64,
}

/// Service states ([`ServiceRecord::state`]).
pub const SVC_RUNNING: u8 = 0;
/// Being restarted.
pub const SVC_RESTARTING: u8 = 1;
/// Crashed, restarts exhausted.
pub const SVC_FAULTED: u8 = 2;
/// Stopped.
pub const SVC_STOPPED: u8 = 3;

/// One supervised service (`ADMIN_SERVICE_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ServiceRecord {
    /// Process id, or `u64::MAX` when not running.
    pub pid: u64,
    /// IPC endpoint.
    pub endpoint: u32,
    /// `SVC_*`.
    pub state: u8,
    /// Reserved.
    pub _pad: [u8; 3],
    /// Restarts so far.
    pub restarts: u32,
    /// Heartbeats not answered.
    pub unanswered_pings: u32,
    /// Name, NUL-padded.
    pub name: [u8; NAME_LEN],
}

/// One interrupt line routed to a driver (`ADMIN_IRQ_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct IrqRecord {
    /// Interrupt line.
    pub irq: u64,
    /// Owning process.
    pub owner: u64,
    /// Interrupts counted.
    pub count: u64,
    /// Client wakeups.
    pub notified: u64,
    /// Pending interrupts.
    pub pending: u64,
    /// 1 if masked.
    pub masked: u64,
}

/// `ADMIN_POOL_STATUS`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct PoolStatus {
    /// 1 if the pool is on a disk (a disk driver answers), 0 on the RAM fallback.
    pub on_disk: u64,
    /// 1 if the metrics below are valid (the file server answered).
    pub metrics_valid: u64,
    /// Capacity in MiB.
    pub total_mib: u64,
    /// Allocated KiB.
    pub alloc_kib: u64,
    /// Free KiB.
    pub free_kib: u64,
    /// Active transaction group.
    pub txg: u64,
}

/// Object kinds ([`DirRecord::kind`], [`LookupRecord::kind`]).
pub const KIND_OTHER: u8 = 0;
/// A regular file.
pub const KIND_FILE: u8 = 1;
/// A directory.
pub const KIND_DIR: u8 = 2;
/// A directory slot without a valid entry (`ls` skips it, but counts it).
pub const KIND_INVALID: u8 = 3;

/// `ADMIN_DIR_LIST` header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DirHeader {
    /// Number of [`DirRecord`]s that follow.
    pub count: u64,
    /// The dataset's name, NUL-padded.
    pub dataset: [u8; NAME_LEN],
}

/// Length of [`DirRecord::name`] (ZFS names are at most 255 bytes).
pub const DIR_NAME_LEN: usize = 256;

/// One directory entry (`ADMIN_DIR_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DirRecord {
    /// Object number.
    pub obj: u64,
    /// `KIND_*`.
    pub kind: u8,
    /// Reserved.
    pub _pad: [u8; 7],
    /// Name, NUL-padded.
    pub name: [u8; DIR_NAME_LEN],
}

impl Default for DirRecord {
    fn default() -> Self {
        Self { obj: 0, kind: 0, _pad: [0; 7], name: [0; DIR_NAME_LEN] }
    }
}

/// `ADMIN_LOOKUP`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LookupRecord {
    /// Object number.
    pub obj: u64,
    /// `KIND_*`.
    pub kind: u64,
    /// Size in bytes.
    pub size: u64,
}

/// The text of a NUL-padded name field.
///
/// # Arguments
/// * `name` - The field.
///
/// # Returns
/// The bytes before the first NUL, as UTF-8 (`"?"` if invalid).
pub fn name_str(name: &[u8]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    core::str::from_utf8(&name[..end]).unwrap_or("?")
}

/// Fills a NUL-padded name field from `s` (truncated to fit, keeping one NUL).
///
/// # Arguments
/// * `s` - The name.
///
/// # Returns
/// The field.
pub fn name_field<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let n = s.len().min(N - 1);
    out[..n].copy_from_slice(&s.as_bytes()[..n]);
    out
}

/// The bytes of a record, to append to an answer.
///
/// # Arguments
/// * `r` - The record (a `#[repr(C)]` type of this file, with no padding holes that matter).
///
/// # Returns
/// Its bytes.
pub fn as_bytes<T: Copy>(r: &T) -> &[u8] {
    unsafe { core::slice::from_raw_parts(r as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// Reads record `T` at byte `offset` of an answer.
///
/// # Arguments
/// * `buf` - The answer.
/// * `offset` - Where the record starts.
///
/// # Returns
/// The record, or `None` if the answer is too short.
pub fn read_record<T: Copy + Default>(buf: &[u8], offset: usize) -> Option<T> {
    let size = core::mem::size_of::<T>();
    if offset.checked_add(size)? > buf.len() {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(buf[offset..].as_ptr() as *const T) })
}
