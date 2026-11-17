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
pub const ADMIN_ABI_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Operations. Groups by the high nibble: 0x0_ meta, 0x1_ console and session, 0x2_ tasks,
// 0x3_ memory and the CPU, 0x4_ services, 0x5_ storage, 0x6_ network (temporary, until
// net-server), 0x7_ power and fault tests, 0x8_ the Linux root (kept apart: it becomes the
// Linux server's protocol when the Linux layer leaves the kernel).
//
// "Report" operations (marked so) have the kernel print a diagnostic dump on the caller's
// standard output (fd 1) instead of answering records: they show deep kernel internals
// whose layout changes often (profiles, lock tables, file server checks). A pipe on fd 1
// captures them like any other output.
// ---------------------------------------------------------------------------

/// Answers a `u32`: [`ADMIN_ABI_VERSION`].
pub const ADMIN_VERSION: u32 = 0x01;

/// Sets the console colours: `args[0]` foreground, `args[1]` background (the UEFI text
/// colour numbers 0-15, as `uefi::proto::console::text::Color`). No answer.
pub const ADMIN_CONSOLE_COLOR: u32 = 0x10;
/// Waits for a key: `args[0]` longest wait in milliseconds (0: do not wait, `u64::MAX`:
/// no limit), `args[1]` the console output generation the caller has seen (`u64::MAX`:
/// do not watch the output). Answers a [`KeyEvent`]: a key, a timeout, or "other output
/// appeared on the console" (so a line editor can draw its prompt again).
pub const ADMIN_CONSOLE_READ: u32 = 0x11;
/// Console control: `args[0]` is a `CTL_*` code, `args[1..]` its arguments. Answers two
/// `u64`s (see each code).
pub const ADMIN_CONSOLE_CTL: u32 = 0x12;
/// Answers a [`SessionInfo`]: who is logged in on the console.
pub const ADMIN_SESSION_INFO: u32 = 0x18;
/// Login, `su`, `sudo`: `args[0]` a `LOGIN_*` mode, input `name\0password`. Answers a
/// [`LoginResult`]. The kernel checks the password (PAM's `unix_chkpwd` in the installed
/// system) and the admin group itself and records the console's user: the shell never
/// tells the kernel who it is.
pub const ADMIN_SESSION_LOGIN: u32 = 0x19;

/// Answers a [`TaskListHeader`] and then `count` [`TaskRecord`]s.
pub const ADMIN_TASK_LIST: u32 = 0x20;
/// Ends task `args[0]`. No answer.
pub const ADMIN_TASK_KILL: u32 = 0x21;
/// Starts an ELF program of the pool: input `path\0arg1\0...` (a native Hydra or a static
/// Linux program), `args[0]`: [`EXEC_BACKGROUND`] or 0 (wait for it). Answers an
/// [`ExecResult`].
pub const ADMIN_TASK_EXEC: u32 = 0x22;
/// Answers a [`SyscallStats`].
pub const ADMIN_SYSCALL_STATS: u32 = 0x23;
/// Answers [`EndpointRecord`]s (the system IPC endpoints 0-7).
pub const ADMIN_ENDPOINT_LIST: u32 = 0x24;
/// Answers a [`RequestHeader`] and then `count` [`RequestRecord`]s (service requests in
/// flight).
pub const ADMIN_REQUEST_LIST: u32 = 0x25;

/// Answers a [`MemInfo`].
pub const ADMIN_MEM_INFO: u32 = 0x30;
/// Answers a [`CpuState`].
pub const ADMIN_CPU_STATE: u32 = 0x31;
/// Answers an [`RtcTime`].
pub const ADMIN_RTC_TIME: u32 = 0x32;
/// Report: the page table walk of virtual address `args[0]` in the caller's address space.
pub const ADMIN_TRANSLATE: u32 = 0x33;
/// Runs the kernel heap's self-test. No answer (`EIO` with a message on failure).
pub const ADMIN_HEAP_TEST: u32 = 0x34;

/// Answers [`ServiceRecord`]s (one per supervised service).
pub const ADMIN_SERVICE_LIST: u32 = 0x40;
/// Answers [`IrqRecord`]s (one per interrupt line routed to a driver).
pub const ADMIN_IRQ_LIST: u32 = 0x41;
/// Service control: `args[0]` a `SVCCTL_*` code, input the service name. Answers the new
/// (or ended) process id as a `u64`.
pub const ADMIN_SERVICE_CTL: u32 = 0x42;
/// Report: the IOMMU (`args[0]`: 0 status, 1 faults, 2 the rogue-DMA test).
pub const ADMIN_IOMMU: u32 = 0x43;

/// Answers a [`PoolStatus`].
pub const ADMIN_POOL_STATUS: u32 = 0x50;
/// Input: a path. Answers a [`DirHeader`] and then `count` [`DirRecord`]s.
pub const ADMIN_DIR_LIST: u32 = 0x51;
/// Input: a path. Answers a [`LookupRecord`].
pub const ADMIN_LOOKUP: u32 = 0x52;
/// A change in the pool: `args[0]` an `FS_*` code, input `path` or `path\0second` (the
/// target of a copy or move, or the data of a write). Answers the transaction group as a
/// `u64`.
pub const ADMIN_FS_OP: u32 = 0x53;
/// Input: a path. Answers a [`StatRecord`].
pub const ADMIN_FILE_STAT: u32 = 0x54;
/// Answers a [`DatasetHeader`] and then `count` [`DatasetRecord`]s.
pub const ADMIN_DATASET_LIST: u32 = 0x55;
/// Report: a file server check, `args[0]` an `ZFSDIAG_*` code, `args[1]` 1 to repair
/// (fsck), input the directory (fsck).
pub const ADMIN_ZFS_DIAG: u32 = 0x56;
/// Answers a [`DiskInfo`] (the pool's disk).
pub const ADMIN_DISK_INFO: u32 = 0x57;
/// Report: USB disks, `args[0]` a `USBDISK_*` code, `args[1..]` its numbers.
pub const ADMIN_USBDISK: u32 = 0x58;

/// Report: network commands until the ring-3 net-server answers them (`args[0]` a `NET_*`
/// code, input the arguments separated by NUL).
pub const ADMIN_NET: u32 = 0x60;

/// `args[0]`: [`POWER_OFF`], [`POWER_REBOOT`] or [`POWER_HALT`]. Does not return on success.
pub const ADMIN_POWER: u32 = 0x70;
/// Fault tests: `args[0]` [`FAULT_PANIC`] (now, or after `args[1]` seconds from a kernel
/// task), [`FAULT_TRAP`] (a breakpoint exception in the kernel, which resumes).
pub const ADMIN_FAULT_TEST: u32 = 0x71;

/// Answers a [`LinuxStats`].
pub const ADMIN_LINUX_STATUS: u32 = 0x80;
/// Starts a Linux program as the console's user: `args[0]` [`RUN_CHROOT`] (input
/// `root\0program\0arg1...`) or [`RUN_FILE`] (input `path\0arg1...`, a static program of
/// the pool), plus [`RUN_FOREGROUND`] (it gets the console as its terminal; wait for it
/// with [`ADMIN_LINUX_WAIT`]). Answers a [`RunResult`].
pub const ADMIN_LINUX_RUN: u32 = 0x81;
/// Waits until Linux process `args[0]` (started in the foreground) exits, then gives the
/// console back. Answers a [`WaitResult`].
pub const ADMIN_LINUX_WAIT: u32 = 0x82;
/// Report: the Linux layer's self-test.
pub const ADMIN_LINUX_TEST: u32 = 0x83;
/// System call tracing: `args[0]` 1 on, 0 off, input a program name filter. No answer.
pub const ADMIN_LINUX_TRACE: u32 = 0x84;
/// Report: the Linux profiler, `args[0]` a `PROF_*` code, `args[1]`/`args[2]` numbers,
/// input a task name (sample).
pub const ADMIN_LINUX_PROF: u32 = 0x85;
/// Report: starts the KDE desktop from root `input` (default `/ubuntu`), `args[0]` 1 for
/// `nologin` (the session without the login screen). Returns when the desktop runs as a
/// service, or when the session ends.
pub const ADMIN_LINUX_PLASMA: u32 = 0x86;

/// `ADMIN_POWER`: power off (ACPI S5).
pub const POWER_OFF: u64 = 0;
/// `ADMIN_POWER`: restart.
pub const POWER_REBOOT: u64 = 1;
/// `ADMIN_POWER`: stop the CPU (interrupts off, `hlt`).
pub const POWER_HALT: u64 = 2;

/// `ADMIN_FAULT_TEST`: a kernel panic.
pub const FAULT_PANIC: u64 = 0;
/// `ADMIN_FAULT_TEST`: a breakpoint exception in the kernel.
pub const FAULT_TRAP: u64 = 1;

/// `ADMIN_TASK_EXEC`: do not wait for the program.
pub const EXEC_BACKGROUND: u64 = 1;

/// `ADMIN_LINUX_RUN`: start `program` inside the root directory given first.
pub const RUN_CHROOT: u64 = 0;
/// `ADMIN_LINUX_RUN`: start a static Linux program read from the pool.
pub const RUN_FILE: u64 = 1;
/// `ADMIN_LINUX_RUN` flag: the program gets the console (keyboard, Ctrl+C).
pub const RUN_FOREGROUND: u64 = 0x100;

// ADMIN_CONSOLE_CTL codes (answers: two u64s, 0 unless said)
/// Answers `[column, row]` of the cursor.
pub const CTL_CURSOR_GET: u64 = 0;
/// Moves the cursor to `args[1]` column, `args[2]` row.
pub const CTL_CURSOR_SET: u64 = 1;
/// Answers `[columns, rows]` of the screen.
pub const CTL_SIZE: u64 = 2;
/// Clears the screen.
pub const CTL_CLEAR: u64 = 3;
/// Clears the scrollback.
pub const CTL_CLEAR_SCROLLBACK: u64 = 4;
/// Cursor: `args[1]` 0 off, 1 on (blinking text cursor of the console).
pub const CTL_CURSOR_ENABLE: u64 = 5;
/// Cursor shape: `args[1]` 0 underline, 1 block, 2 bar.
pub const CTL_CURSOR_SHAPE: u64 = 6;
/// Answers `[enabled, shape]` of the cursor.
pub const CTL_CURSOR_INFO: u64 = 7;
/// Scroll lock: `args[1]` 0 off, 1 on, 2 toggle, 3 only ask. Answers `[active, 0]`.
pub const CTL_SCROLL_LOCK: u64 = 8;
/// Answers `[lines that can be scrolled back, 0]`.
pub const CTL_MAX_SCROLL: u64 = 9;
/// Draws the scrollback viewport `args[1]` lines up with the input line at the bottom:
/// `args[2]` cursor position in the line, `args[3]` prompt colour; input `prompt\0text`.
pub const CTL_VIEWPORT: u64 = 10;
/// Answers `[console output generation, 0]` (it changes on every console output).
pub const CTL_GENERATION: u64 = 11;
/// Shows (`args[1]` 1) or hides (0) the cursor now.
pub const CTL_CURSOR_SHOW: u64 = 12;

// ADMIN_SESSION_LOGIN modes
/// Log in (`name\0password`): only root and members of `sudo`/`admin`.
pub const LOGIN_LOGIN: u64 = 0;
/// `su name`: the target's password, none when the console is root.
pub const LOGIN_SU: u64 = 1;
/// `sudo`: become root with the console user's own password (remembered 5 minutes); an
/// empty password only asks whether one is needed ([`LOGIN_NEED_PASSWORD`]).
pub const LOGIN_SUDO: u64 = 2;
/// Back to account `name` (after `sudo command`): only while the console is root.
pub const LOGIN_RESTORE: u64 = 3;
/// Log out: the next commands need a login again.
pub const LOGIN_LOGOUT: u64 = 4;

// LoginResult::status
/// Done: the console's user changed.
pub const LOGIN_OK: u32 = 0;
/// Wrong name or password.
pub const LOGIN_INCORRECT: u32 = 1;
/// The account exists but may not administer the system.
pub const LOGIN_NOT_ADMIN: u32 = 2;
/// No such account.
pub const LOGIN_NO_USER: u32 = 3;
/// `sudo`: a password is needed.
pub const LOGIN_NEED_PASSWORD: u32 = 4;
/// The installed system cannot check passwords (no accounts): nothing is protected.
pub const LOGIN_UNPROTECTED: u32 = 5;

// ADMIN_SERVICE_CTL codes
/// Restart a service.
pub const SVCCTL_RESTART: u64 = 0;
/// End a service's process (a simulated crash) and run a supervisor sweep.
pub const SVCCTL_KILL: u64 = 1;
/// Start a stopped service.
pub const SVCCTL_START: u64 = 2;
/// Run a supervisor sweep (input empty).
pub const SVCCTL_TICK: u64 = 3;

// ADMIN_FS_OP codes
/// Create a directory.
pub const FS_MKDIR: u64 = 0;
/// Create a directory and its missing parents.
pub const FS_MKDIR_ALL: u64 = 1;
/// Remove an empty directory.
pub const FS_RMDIR: u64 = 2;
/// Remove a file.
pub const FS_UNLINK: u64 = 3;
/// Copy `path` to `second`.
pub const FS_COPY: u64 = 4;
/// Move `path` to `second`.
pub const FS_RENAME: u64 = 5;
/// Create the file if missing (timestamps).
pub const FS_TOUCH: u64 = 6;
/// Replace the file's contents with `second` (the data).
pub const FS_WRITE: u64 = 7;
/// Append `second` (the data) to the file.
pub const FS_APPEND: u64 = 8;
/// Commit the pool (input empty).
pub const FS_SYNC: u64 = 9;
/// Take a snapshot (input empty).
pub const FS_SNAPSHOT: u64 = 10;

// ADMIN_ZFS_DIAG codes
/// The file server's self-test.
pub const ZFSDIAG_SELFTEST: u64 = 0;
/// Verify every block's checksum.
pub const ZFSDIAG_VERIFY: u64 = 1;
/// Check (and with `args[1]` = 1 repair) a directory tree.
pub const ZFSDIAG_FSCK: u64 = 2;

// ADMIN_USBDISK codes
/// List USB disks.
pub const USBDISK_LIST: u64 = 0;
/// Write test of disk `args[1]`, `args[2]` blocks.
pub const USBDISK_TEST: u64 = 1;
/// Speed test of disk `args[1]` (`u64::MAX`: the AHCI disk), `args[2]` MiB, `args[3]` 1 to write.
pub const USBDISK_SPEED: u64 = 2;

// ADMIN_NET codes (temporary, until net-server)
/// Interface configuration.
pub const NET_IFCONFIG: u64 = 0;
/// Ask DHCP for a lease.
pub const NET_DHCP: u64 = 1;
/// Resolve a name (input: the name).
pub const NET_DNS: u64 = 2;
/// Ping (input: address or name).
pub const NET_PING: u64 = 3;
/// HTTP download (input: `server\0port\0path\0destination`).
pub const NET_WGET: u64 = 4;

// ADMIN_LINUX_PROF codes
/// Reset and start.
pub const PROF_ON: u64 = 0;
/// Stop.
pub const PROF_OFF: u64 = 1;
/// Reset.
pub const PROF_RESET: u64 = 2;
/// Show the top `args[1]` entries.
pub const PROF_SHOW: u64 = 3;
/// Tune: `args[1]` 0 kick deferral (`args[2]` 1 on, 0 off), 1 idle poll (`args[2]` us),
/// 2 only show.
pub const PROF_TUNE: u64 = 4;
/// Log calls of at least `args[1]` ms (0 off).
pub const PROF_WAITS: u64 = 5;
/// Show the slow calls logged.
pub const PROF_WAITS_SHOW: u64 = 6;
/// Sample the task named by the input (`*`: all), `args[1]` 1 for kernel PCs too.
pub const PROF_SAMPLE: u64 = 7;
/// Stop sampling.
pub const PROF_SAMPLE_STOP: u64 = 8;
/// Show the top `args[1]` samples.
pub const PROF_SAMPLE_SHOW: u64 = 9;

// errno values the interface returns (negated)
/// Not an authorized admin console.
pub const EPERM: i64 = 1;
/// No such file or object.
pub const ENOENT: i64 = 2;
/// The operation failed; see the message.
pub const EIO: i64 = 5;
/// A bad pointer.
pub const EFAULT: i64 = 14;
/// Permission denied (the console's user may not do this).
pub const EACCES: i64 = 13;
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

/// Key event kinds ([`KeyEvent::kind`]).
pub const KEY_NONE: u32 = 0;
/// A character (`code`: its Unicode value; control keys are 1-31, Backspace 8, Enter 13).
pub const KEY_CHAR: u32 = 1;
/// A special key (`code`: one of the `SC_*` scan codes, as UEFI's).
pub const KEY_SPECIAL: u32 = 2;
/// Other output appeared on the console since the generation the caller gave.
pub const KEY_REFRESH: u32 = 3;

/// Special keys (UEFI scan codes).
pub const SC_UP: u32 = 0x01;
/// Down arrow.
pub const SC_DOWN: u32 = 0x02;
/// Right arrow.
pub const SC_RIGHT: u32 = 0x03;
/// Left arrow.
pub const SC_LEFT: u32 = 0x04;
/// Home.
pub const SC_HOME: u32 = 0x05;
/// End.
pub const SC_END: u32 = 0x06;
/// Delete.
pub const SC_DELETE: u32 = 0x08;
/// Page Up.
pub const SC_PAGE_UP: u32 = 0x09;
/// Page Down.
pub const SC_PAGE_DOWN: u32 = 0x0A;
/// F12.
pub const SC_F12: u32 = 0x16;
/// Escape.
pub const SC_ESCAPE: u32 = 0x17;

/// `ADMIN_CONSOLE_READ`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct KeyEvent {
    /// `KEY_*`.
    pub kind: u32,
    /// The character or scan code.
    pub code: u32,
    /// The console output generation now.
    pub generation: u64,
}

/// `ADMIN_SESSION_INFO`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SessionInfo {
    /// The console's user id.
    pub uid: u32,
    /// Its group id.
    pub gid: u32,
    /// 1 when somebody is logged in (or nothing needs a login).
    pub logged_in: u32,
    /// 1 when the installed system can check passwords (its accounts protect the console).
    pub protected: u32,
    /// 1 in the live session (Hydra from its USB stick: root without a password).
    pub live: u32,
    /// 1 when a `sudo` password was given in the last 5 minutes.
    pub sudo_fresh: u32,
    /// The user's name, NUL-padded.
    pub name: [u8; NAME_LEN],
}

/// `ADMIN_SESSION_LOGIN`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LoginResult {
    /// `LOGIN_*` status.
    pub status: u32,
    /// The console's user id now.
    pub uid: u32,
    /// Its group id.
    pub gid: u32,
    /// Reserved.
    pub _pad: u32,
    /// Its name, NUL-padded.
    pub name: [u8; NAME_LEN],
}

/// `ADMIN_TASK_EXEC`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ExecResult {
    /// The new process.
    pub pid: u64,
    /// Bytes of the program file.
    pub size: u64,
    /// 1 for a Linux program, 0 for a native one.
    pub linux: u32,
    /// 1 when it has already ended (started without [`EXEC_BACKGROUND`]).
    pub finished: u32,
}

/// `ADMIN_SYSCALL_STATS`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct SyscallStats {
    /// IA32_EFER.
    pub efer: u64,
    /// IA32_STAR.
    pub star: u64,
    /// IA32_LSTAR.
    pub lstar: u64,
    /// IA32_FMASK.
    pub fmask: u64,
    /// Native call counts: yield, sleep, write, exit, getpid, uptime, ipc, total.
    pub counts: [u64; 8],
}

/// One system IPC endpoint (`ADMIN_ENDPOINT_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct EndpointRecord {
    /// Endpoint number.
    pub id: u64,
    /// Messages queued.
    pub pending: u64,
    /// Receivers waiting.
    pub receivers: u64,
    /// Senders waiting.
    pub senders: u64,
}

/// `ADMIN_REQUEST_LIST` header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RequestHeader {
    /// Number of [`RequestRecord`]s that follow.
    pub count: u64,
    /// Page grants made since boot.
    pub grants_made: u64,
}

/// One service request in flight (`ADMIN_REQUEST_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RequestRecord {
    /// Request id.
    pub id: u64,
    /// Service endpoint.
    pub endpoint: u64,
    /// Calling task.
    pub caller: u64,
    /// Its state, NUL-padded text.
    pub state: [u8; NAME_LEN],
    /// The call mode, NUL-padded text.
    pub mode: [u8; NAME_LEN],
}

/// `ADMIN_CPU_STATE` (the CPU that answers).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct CpuState {
    /// CR0.
    pub cr0: u64,
    /// CR2 (last page fault address).
    pub cr2: u64,
    /// CR3 (the caller's page table root).
    pub cr3: u64,
    /// CR4.
    pub cr4: u64,
}

/// `ADMIN_RTC_TIME` (UTC).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct RtcTime {
    /// 1 if the clock answered.
    pub valid: u32,
    /// Year.
    pub year: u16,
    /// Month 1-12.
    pub month: u8,
    /// Day 1-31.
    pub day: u8,
    /// Hour.
    pub hour: u8,
    /// Minute.
    pub minute: u8,
    /// Second.
    pub second: u8,
    /// Reserved.
    pub _pad: u8,
    /// Timer ticks since boot (100 Hz).
    pub ticks: u64,
}

/// `ADMIN_FILE_STAT`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct StatRecord {
    /// Object number.
    pub obj: u64,
    /// `KIND_*`.
    pub kind: u64,
    /// Size in bytes.
    pub size: u64,
    /// Transaction group it was born in.
    pub birth_txg: u64,
    /// Its Fletcher-4 checksum.
    pub checksum: [u64; 4],
}

/// `ADMIN_DATASET_LIST` header.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DatasetHeader {
    /// Number of [`DatasetRecord`]s that follow.
    pub count: u64,
    /// Pool bytes allocated.
    pub allocated: u64,
    /// Pool bytes free.
    pub free: u64,
}

/// Length of the dataset name fields.
pub const DATASET_NAME_LEN: usize = 64;

/// One dataset or snapshot (`ADMIN_DATASET_LIST`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DatasetRecord {
    /// Transaction group it was created in.
    pub txg: u64,
    /// 1 for a snapshot.
    pub snapshot: u64,
    /// Name, NUL-padded.
    pub name: [u8; DATASET_NAME_LEN],
    /// Mount point, NUL-padded.
    pub mount: [u8; DATASET_NAME_LEN],
}

impl Default for DatasetRecord {
    fn default() -> Self {
        Self { txg: 0, snapshot: 0, name: [0; DATASET_NAME_LEN], mount: [0; DATASET_NAME_LEN] }
    }
}

/// `ADMIN_DISK_INFO`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct DiskInfo {
    /// 1 if the pool is on a disk.
    pub present: u64,
    /// 512-byte sectors.
    pub sectors: u64,
    /// 1 with 48-bit addressing.
    pub lba48: u64,
    /// 1 with bus-master DMA.
    pub dma: u64,
    /// Model, NUL-padded.
    pub model: [u8; NAME_LEN],
}

/// `ADMIN_LINUX_STATUS`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct LinuxStats {
    /// System calls: total, file and terminal, memory, processes and signals,
    /// arch_prctl, time, unknown.
    pub calls: [u64; 7],
}

/// `ADMIN_LINUX_RUN`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RunResult {
    /// The new process.
    pub pid: u64,
    /// Bytes of the program file ([`RUN_FILE`]).
    pub size: u64,
    /// User id it runs as.
    pub uid: u32,
    /// Group id.
    pub gid: u32,
    /// The program file found ([`RUN_FILE`]), NUL-padded.
    pub path: [u8; DIR_NAME_LEN],
}

impl Default for RunResult {
    fn default() -> Self {
        Self { pid: 0, size: 0, uid: 0, gid: 0, path: [0; DIR_NAME_LEN] }
    }
}

/// `ADMIN_LINUX_WAIT`.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct WaitResult {
    /// 1 if the wait status is known.
    pub known: u64,
    /// Its wait status (`status & 0x7f`: the signal, `(status >> 8) & 0xff`: the exit code).
    pub status: u64,
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
