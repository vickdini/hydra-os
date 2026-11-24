//! # Admin interface: the kernel calls the console shell needs
//!
//! The console shell is the ring-3 program `hydra-shell` (microkernel plan, group 4). This
//! module is what it asks the kernel for: a small, explicit set of operations behind one
//! native system call, [`proto::SYS_ADMIN`]. The design is in
//! `docs/shell-admin-interface.md`; the wire format in [`proto`] (shared with ring-3
//! programs as source).
//!
//! ## Authorization
//! Only the admin console may call it: the process the kernel itself started as the console
//! shell ([`launch_shell`]), recorded here by task id. Linux processes never reach it (their
//! system calls go to the Linux table, where 40 is `sendfile`), and drivers are not the
//! console. Everything else gets `-EPERM`. Until somebody logs in on the console
//! ([`session`]), only the console's own operations and the login are answered.
//!
//! ## Parts
//! - [`console`]: keys, cursor, scrollback (the line editor's needs).
//! - [`session`]: who is logged in; the login, `su` and `sudo` rules.
//! - [`system`]: tasks, memory, the CPU, services, power, fault tests.
//! - [`storage`]: the pool (through the file server) and the disks.
//! - [`net`]: the network commands, until the ring-3 net-server answers them.
//! - [`linux`]: the Linux root (its own op group: it becomes the Linux server's protocol).
//! - [`boot`]: the console's start after boot: the desktop, then `hydra-shell`, watched,
//!   with the emergency prompt (`crate::shell`) when it cannot run.
//!
//! ## Context
//! - Ring 0, in the system call of the calling process (interrupts enabled, as for Linux
//!   system calls: operations may call the file server or wait).

pub mod boot;
pub mod console;
pub mod linux;
pub mod net;
pub mod proto;
pub mod session;
pub mod storage;
pub mod system;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::proto::console::text::Color;

use proto::*;

/// The `hydra-shell` program (built in `userland/drivers`, embedded like the drivers).
static HYDRA_SHELL_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/hydra-shell"));

/// Task id of the authorized admin console plus one (0: none).
static CONSOLE_TASK: AtomicU64 = AtomicU64::new(0);

/// Starts `hydra-shell` as the admin console and authorizes it.
///
/// # Arguments
/// * `args` - Its arguments (`args[0]` is the program name).
/// * `uid` - User id it starts with (the session sets it at login).
/// * `gid` - Group id.
///
/// # Returns
/// The task id of the shell.
///
/// # Errors
/// If the image cannot be loaded or the process not created.
pub fn launch_shell(args: &[&str], uid: u32, gid: u32) -> Result<crate::task::TaskId, &'static str> {
    spawn_native("hydra-shell", HYDRA_SHELL_ELF, args, uid, gid, true)
}

/// Starts a native Hydra program (a static ELF on `hydra-rt`) in an address space of its
/// own, as the supervisor starts drivers; `console`: authorize it as the admin console.
///
/// # Errors
/// If the image cannot be loaded or the process not created.
pub fn spawn_native(name: &'static str, image: &[u8], args: &[&str], uid: u32, gid: u32, console: bool) -> Result<crate::task::TaskId, &'static str> {
    use crate::task::{exec, scheduler, TaskPersonality, TaskPriority, SCHEDULER};
    if !exec::is_vm_loadable(image) {
        return Err("not a loadable static ELF executable");
    }
    let source = exec::ElfSource::from_bytes(image.to_vec().into_boxed_slice());
    let path = args.first().copied().unwrap_or(name);
    let loaded = scheduler::load_linux_image(source, path, args, uid, gid, None)?;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        let id = sched.spawn_linux_process(name, loaded, path, args, TaskPriority::Normal, uid, gid, None)?;
        // A native Hydra program (native system calls), not a driver (no service)
        sched.with_task_mut(id, |t| t.personality = TaskPersonality::Hydra);
        if console {
            CONSOLE_TASK.store(id.0 + 1, Ordering::Release);
        }
        Ok(id)
    })
}

/// Withdraws the admin console's authorization (when it has exited).
///
/// # Arguments
/// * `id` - The console's task id.
pub fn revoke_console(id: crate::task::TaskId) {
    let _ = CONSOLE_TASK.compare_exchange(id.0 + 1, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// The authorized console task, if one runs.
pub fn console_task() -> Option<crate::task::TaskId> {
    match CONSOLE_TASK.load(Ordering::Acquire) {
        0 => None,
        n => Some(crate::task::TaskId(n - 1)),
    }
}

/// Whether the calling task is the authorized admin console.
fn caller_authorized() -> bool {
    let console = CONSOLE_TASK.load(Ordering::Acquire);
    if console == 0 {
        return false;
    }
    let me = crate::task::SCHEDULER.lock().current_task_id().0;
    me + 1 == console && crate::task::current_personality() == crate::task::TaskPersonality::Hydra
}

/// Highest user-space address + 1.
const USER_END: u64 = 0x0000_8000_0000_0000;

/// Copies `data` to user memory at `ptr`.
fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
    if data.is_empty() {
        return Ok(());
    }
    let end = ptr.checked_add(data.len() as u64).ok_or(-EFAULT)?;
    if ptr == 0 || end > USER_END || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
        return Err(-EFAULT);
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    Ok(())
}

/// Copies `len` bytes of user memory at `ptr`.
fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let end = ptr.checked_add(len as u64).ok_or(-EFAULT)?;
    if ptr == 0 || end > USER_END || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
        return Err(-EFAULT);
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Ok(v)
}

/// Largest input an operation takes (a path, or the data of a file write).
const MAX_INPUT: usize = 4 * 1024 * 1024;

/// How an operation failed.
pub enum Failure {
    /// An errno.
    Errno(i64),
    /// An errno and a message for the user.
    Message(i64, &'static str),
    /// An errno and a message made for this failure.
    Text(i64, alloc::string::String),
}

/// The native system call `SYS_ADMIN`: runs the operation in the [`AdminCall`] at `call_ptr`.
///
/// # Arguments
/// * `call_ptr` - User address of the call block.
///
/// # Returns
/// The answer's size, or `-errno` (see [`proto`]).
pub fn syscall(call_ptr: u64) -> i64 {
    if !caller_authorized() {
        return -EPERM;
    }
    // As for Linux system calls: interrupts on (operations may wait for the file server)
    x86_64::instructions::interrupts::enable();
    let raw = match copy_in(call_ptr, core::mem::size_of::<AdminCall>()) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut call: AdminCall = match read_record(&raw, 0) {
        Some(c) => c,
        None => return -EFAULT,
    };
    if call.in_len as usize > MAX_INPUT {
        return -EINVAL;
    }
    let input = match copy_in(call.in_ptr, call.in_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let result = if needs_login(call.op) && !session::logged_in() { Err(Failure::Message(EACCES, "not logged in")) } else { run(&call, &input) };
    match result {
        Ok(answer) => {
            let n = answer.len().min(call.out_cap as usize);
            if n > 0 {
                if let Err(e) = copy_out(call.out_ptr, &answer[..n]) {
                    return e;
                }
            }
            answer.len() as i64
        }
        Err(Failure::Errno(e)) => -e,
        Err(Failure::Text(e, msg)) => fail_with(call_ptr, &mut call, e, &msg),
        Err(Failure::Message(e, msg)) => fail_with(call_ptr, &mut call, e, msg),
    }
}

/// Writes failure message `msg` to the caller's answer buffer and answers `-e`.
fn fail_with(call_ptr: u64, call: &mut AdminCall, e: i64, msg: &str) -> i64 {
    let n = msg.len().min(call.out_cap as usize);
    if n > 0 && copy_out(call.out_ptr, &msg.as_bytes()[..n]).is_ok() {
        call.err_len = n as u64;
        let off = core::mem::offset_of!(AdminCall, err_len) as u64;
        let _ = copy_out(call_ptr + off, &call.err_len.to_le_bytes());
    }
    -e
}

/// Whether operation `op` needs somebody logged in on the console (all but the console's
/// own, the session's and the version).
fn needs_login(op: u32) -> bool {
    !matches!(op, ADMIN_VERSION | ADMIN_CONSOLE_COLOR | ADMIN_CONSOLE_READ | ADMIN_CONSOLE_CTL | ADMIN_SESSION_INFO | ADMIN_SESSION_LOGIN)
}

/// The input as text.
fn input_str(input: &[u8]) -> Result<&str, Failure> {
    core::str::from_utf8(input).map_err(|_| Failure::Errno(EINVAL))
}

/// UEFI text colours by number.
pub(crate) const COLORS: [Color; 16] = [
    Color::Black, Color::Blue, Color::Green, Color::Cyan, Color::Red, Color::Magenta, Color::Brown, Color::LightGray,
    Color::DarkGray, Color::LightBlue, Color::LightGreen, Color::LightCyan, Color::LightRed, Color::LightMagenta,
    Color::Yellow, Color::White,
];

/// Appends record `r` to an answer.
fn push<T: Copy>(out: &mut Vec<u8>, r: &T) {
    out.extend_from_slice(as_bytes(r));
}

/// Runs one operation.
///
/// # Returns
/// The answer's bytes.
fn run(call: &AdminCall, input: &[u8]) -> Result<Vec<u8>, Failure> {
    use Failure::*;
    let a = &call.args;
    let mut out = Vec::new();
    match call.op {
        ADMIN_VERSION => out.extend_from_slice(&ADMIN_ABI_VERSION.to_le_bytes()),
        // Console and session
        ADMIN_CONSOLE_COLOR => {
            let fg = *COLORS.get(a[0] as usize).ok_or(Errno(EINVAL))?;
            let bg = *COLORS.get(a[1] as usize).ok_or(Errno(EINVAL))?;
            crate::console::set_color(fg, bg);
        }
        ADMIN_CONSOLE_READ => push(&mut out, &console::read(a[0], a[1])),
        ADMIN_CONSOLE_CTL => {
            let r = console::ctl(a, input).ok_or(Errno(EINVAL))?;
            out.extend_from_slice(&r[0].to_le_bytes());
            out.extend_from_slice(&r[1].to_le_bytes());
        }
        ADMIN_SESSION_INFO => push(&mut out, &session::info()),
        ADMIN_SESSION_LOGIN => {
            let text = input_str(input)?;
            let (name, password) = text.split_once('\0').unwrap_or((text, ""));
            push(&mut out, &session::login_op(a[0], name, password));
        }
        // Tasks
        ADMIN_TASK_LIST => system::task_list(&mut out)?,
        ADMIN_TASK_KILL => system::kill(a[0])?,
        ADMIN_TASK_EXEC => {
            let (uid, gid, _) = session::user();
            push(&mut out, &system::exec(a[0], input, uid, gid)?);
        }
        ADMIN_SYSCALL_STATS => push(&mut out, &system::syscall_stats()),
        ADMIN_ENDPOINT_LIST => system::endpoints(&mut out),
        ADMIN_REQUEST_LIST => system::requests(&mut out),
        // Memory and the CPU
        ADMIN_MEM_INFO => push(&mut out, &system::mem_info()),
        ADMIN_CPU_STATE => push(&mut out, &system::cpu_state()),
        ADMIN_RTC_TIME => push(&mut out, &system::rtc_time()),
        ADMIN_TRANSLATE => system::translate(a[0])?,
        ADMIN_HEAP_TEST => crate::memory::heap::self_test().map_err(|e| Message(EIO, e))?,
        // Services
        ADMIN_SERVICE_LIST => system::services(&mut out),
        ADMIN_IRQ_LIST => system::irqs(&mut out),
        ADMIN_SERVICE_CTL => {
            let pid = system::service_ctl(a[0], input_str(input)?, a[1])?; // wave11 GR: a[1] = delay (s)
            out.extend_from_slice(&pid.to_le_bytes());
        }
        ADMIN_IOMMU => system::iommu(a[0])?,
        // Storage
        ADMIN_POOL_STATUS => push(&mut out, &storage::pool_status()),
        ADMIN_DIR_LIST => storage::dir_list(input_str(input)?, &mut out)?,
        ADMIN_LOOKUP => push(&mut out, &storage::lookup(input_str(input)?)?),
        ADMIN_FS_OP => {
            let txg = storage::fs_op(a[0], input)?;
            out.extend_from_slice(&txg.to_le_bytes());
        }
        ADMIN_FILE_STAT => push(&mut out, &storage::stat(input_str(input)?)?),
        ADMIN_DATASET_LIST => storage::datasets(&mut out)?,
        ADMIN_ZFS_DIAG => storage::zfs_diag(a[0], a[1] != 0, input_str(input)?)?,
        ADMIN_DISK_INFO => push(&mut out, &storage::disk_info()),
        ADMIN_USBDISK => storage::usbdisk(a)?,
        // Network (until net-server)
        ADMIN_NET => {
            let words: Vec<&str> = if input.is_empty() { Vec::new() } else { linux::words(input) };
            net::run(a[0], &words)?
        }
        // Power and fault tests
        ADMIN_POWER => system::power(a[0])?,
        ADMIN_FAULT_TEST => system::fault_test(a[0], a[1])?,
        // The Linux root
        ADMIN_LINUX_STATUS => push(&mut out, &linux::status()),
        ADMIN_LINUX_RUN => {
            let (uid, gid, _) = session::user();
            push(&mut out, &linux::run(a[0], input, uid, gid).map_err(|e| Text(EIO, e))?);
        }
        ADMIN_LINUX_WAIT => push(&mut out, &linux::wait(a[0]).ok_or(Message(EINVAL, "not the console's foreground process"))?),
        ADMIN_LINUX_TEST => linux::self_test(),
        ADMIN_LINUX_TRACE => linux::trace(a[0] != 0, input_str(input)?),
        ADMIN_LINUX_PROF => {
            if !linux::prof(a, input_str(input)?) {
                return Err(Errno(EINVAL));
            }
        }
        ADMIN_LINUX_PLASMA => {
            let root = input_str(input)?;
            linux::plasma(if root.is_empty() { "/ubuntu" } else { root }, a[0] != 0);
        }
        _ => return Err(Errno(ENOSYS)),
    }
    Ok(out)
}
