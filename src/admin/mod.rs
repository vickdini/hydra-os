//! # Admin interface: the kernel calls a ring-3 shell needs
//!
//! The kernel shell (`src/shell`) is moving out of the kernel into the ring-3 program
//! `hydra-shell` (microkernel plan, group 4). This module is what that program asks the
//! kernel for: a small, explicit set of operations behind one native system call,
//! [`proto::SYS_ADMIN`]. The design is in `docs/shell-admin-interface.md`; the wire format
//! in [`proto`] (shared with ring-3 programs as source).
//!
//! ## Authorization
//! Only the admin console may call it: the process the kernel itself started as the console
//! shell ([`launch_shell`]), recorded here by task id. Linux processes never reach it (their
//! system calls go to the Linux table, where 40 is `sendfile`), and drivers are not the
//! console. Everything else gets `-EPERM`.
//!
//! ## Part 1 (this wave)
//! The kernel shell stays the console; `ushell` starts `hydra-shell` from it for testing and
//! waits until it exits. The operations cover a first subset: tasks, memory, services,
//! the pool's status, directory listings and lookups, console colours and power.
//!
//! ## Context
//! - Ring 0, in the system call of the calling process (interrupts enabled, as for Linux
//!   system calls: operations may call the file server).

pub mod proto;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::proto::console::text::Color;

use proto::*;

/// The `hydra-shell` program (built in `userland/drivers`, embedded like the drivers).
static HYDRA_SHELL_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/hydra-shell"));

/// Task id of the authorized admin console plus one (0: none).
static CONSOLE_TASK: AtomicU64 = AtomicU64::new(0);

/// Counter the kernel shell's demo worker tasks (`spawn worker`) bump; `ps` shows it.
pub static DEMO_WORKER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Starts `hydra-shell` as the admin console and authorizes it.
///
/// # Arguments
/// * `args` - Its arguments (`args[0]` is the program name).
/// * `uid` - User id of the console session.
/// * `gid` - Group id of the console session.
///
/// # Returns
/// The task id of the shell.
///
/// # Errors
/// If the image cannot be loaded or the process not created.
pub fn launch_shell(args: &[&str], uid: u32, gid: u32) -> Result<crate::task::TaskId, &'static str> {
    use crate::task::{exec, scheduler, TaskPersonality, TaskPriority, SCHEDULER};
    if !exec::is_vm_loadable(HYDRA_SHELL_ELF) {
        return Err("hydra-shell is not a loadable static ELF executable");
    }
    let source = exec::ElfSource::from_bytes(HYDRA_SHELL_ELF.to_vec().into_boxed_slice());
    let path = args.first().copied().unwrap_or("hydra-shell");
    let loaded = scheduler::load_linux_image(source, path, args, uid, gid, None)?;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        let id = sched.spawn_linux_process("hydra-shell", loaded, path, args, TaskPriority::Normal, uid, gid, None)?;
        // A native Hydra program (native system calls), not a driver (no service)
        sched.with_task_mut(id, |t| t.personality = TaskPersonality::Hydra);
        CONSOLE_TASK.store(id.0 + 1, Ordering::Release);
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

/// Largest input (a path) an operation takes.
const MAX_INPUT: usize = 4096;

/// How an operation failed.
enum Failure {
    /// An errno.
    Errno(i64),
    /// An errno and a message for the user.
    Message(i64, &'static str),
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
    match run(&call, &input) {
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
        Err(Failure::Message(e, msg)) => {
            let n = msg.len().min(call.out_cap as usize);
            if n > 0 && copy_out(call.out_ptr, &msg.as_bytes()[..n]).is_ok() {
                call.err_len = n as u64;
                let off = core::mem::offset_of!(AdminCall, err_len) as u64;
                let _ = copy_out(call_ptr + off, &call.err_len.to_le_bytes());
            }
            -e
        }
    }
}

/// The input as a path.
fn input_str(input: &[u8]) -> Result<&str, Failure> {
    core::str::from_utf8(input).map_err(|_| Failure::Errno(EINVAL))
}

/// UEFI text colours by number.
const COLORS: [Color; 16] = [
    Color::Black, Color::Blue, Color::Green, Color::Cyan, Color::Red, Color::Magenta, Color::Brown, Color::LightGray,
    Color::DarkGray, Color::LightBlue, Color::LightGreen, Color::LightCyan, Color::LightRed, Color::LightMagenta,
    Color::Yellow, Color::White,
];

/// Runs one operation.
///
/// # Returns
/// The answer's bytes.
fn run(call: &AdminCall, input: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    match call.op {
        ADMIN_VERSION => out.extend_from_slice(&ADMIN_ABI_VERSION.to_le_bytes()),
        ADMIN_CONSOLE_COLOR => {
            let fg = *COLORS.get(call.args[0] as usize).ok_or(Failure::Errno(EINVAL))?;
            let bg = *COLORS.get(call.args[1] as usize).ok_or(Failure::Errno(EINVAL))?;
            crate::console::set_color(fg, bg);
        }
        ADMIN_TASK_LIST => {
            use crate::task::{PrivilegeMode, TaskPriority, TaskState};
            if !crate::task::is_active() {
                return Err(Failure::Message(EIO, "Multitasking scheduler is not yet active."));
            }
            let snaps = crate::task::get_task_snapshots();
            let header = TaskListHeader {
                count: snaps.len() as u32,
                timeslice_ms: crate::task::scheduler::DEFAULT_TIMESLICE_TICKS * 10,
                worker_counter: DEMO_WORKER_COUNTER.load(Ordering::Relaxed),
            };
            out.extend_from_slice(as_bytes(&header));
            for s in &snaps {
                let rec = TaskRecord {
                    pid: s.id.0,
                    uid: s.uid,
                    mode: match s.mode {
                        PrivilegeMode::Kernel => MODE_KERNEL,
                        PrivilegeMode::User => MODE_USER,
                    },
                    state: match s.state {
                        TaskState::Ready => STATE_READY,
                        TaskState::Running => STATE_RUNNING,
                        TaskState::Blocked => STATE_BLOCKED,
                        TaskState::Sleeping { .. } => STATE_SLEEPING,
                        TaskState::Dead => STATE_DEAD,
                    },
                    priority: match s.priority {
                        TaskPriority::Idle => 0,
                        TaskPriority::Low => 1,
                        TaskPriority::Normal => 2,
                        TaskPriority::High => 3,
                        TaskPriority::Realtime => 4,
                    },
                    _pad: 0,
                    ticks: s.ticks_run,
                    rsp: s.rsp,
                    name: name_field(s.name),
                };
                out.extend_from_slice(as_bytes(&rec));
            }
        }
        ADMIN_MEM_INFO => {
            let (total, allocated, free) = {
                let a = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
                (a.total_usable_memory(), a.allocated_memory(), a.free_memory())
            };
            let h = crate::memory::heap::stats();
            let info = MemInfo {
                total,
                allocated,
                free,
                page_size: crate::memory::frame_allocator::PAGE_SIZE,
                heap_initialized: h.is_initialized as u64,
                heap_start: h.start_address,
                heap_total: h.total_bytes as u64,
                heap_used: h.used_bytes as u64,
                heap_free: h.free_bytes as u64,
            };
            out.extend_from_slice(as_bytes(&info));
        }
        ADMIN_SERVICE_LIST => {
            use crate::task::supervisor::ServiceState;
            for s in crate::task::supervisor::get_service_snapshots() {
                let rec = ServiceRecord {
                    pid: s.task_id.unwrap_or(u64::MAX),
                    endpoint: s.endpoint_id,
                    state: match s.state {
                        ServiceState::Running => SVC_RUNNING,
                        ServiceState::Restarting => SVC_RESTARTING,
                        ServiceState::Faulted => SVC_FAULTED,
                        ServiceState::Stopped => SVC_STOPPED,
                    },
                    _pad: [0; 3],
                    restarts: s.restart_count,
                    unanswered_pings: s.unanswered_pings,
                    name: name_field(s.name),
                };
                out.extend_from_slice(as_bytes(&rec));
            }
        }
        ADMIN_IRQ_LIST => {
            for (irq, owner, count, notified, pending, masked) in crate::ipc::service::irq_stats() {
                let rec = IrqRecord { irq: irq as u64, owner, count, notified, pending: pending as u64, masked: masked as u64 };
                out.extend_from_slice(as_bytes(&rec));
            }
        }
        ADMIN_POOL_STATUS => {
            let mut st = PoolStatus { on_disk: crate::fs::zfs::disk_info().is_some() as u64, ..Default::default() };
            if let Ok((total_mib, alloc_kib, free_kib, txg)) = crate::fs::ZfsClient::pool_status() {
                st.metrics_valid = 1;
                st.total_mib = total_mib;
                st.alloc_kib = alloc_kib;
                st.free_kib = free_kib;
                st.txg = txg;
            }
            out.extend_from_slice(as_bytes(&st));
        }
        ADMIN_DIR_LIST => {
            use crate::fs::zfs::types::DnodeType;
            let path = input_str(input)?;
            let (entries, count, dataset) = crate::fs::ZfsClient::list_dir(path).map_err(|e| Failure::Message(ENOENT, e))?;
            let header = DirHeader { count: count as u64, dataset: name_field(dataset) };
            out.extend_from_slice(as_bytes(&header));
            for e in entries.iter() {
                let rec = DirRecord {
                    obj: e.object_id,
                    kind: if !e.is_valid {
                        KIND_INVALID
                    } else if e.obj_type == DnodeType::Directory {
                        KIND_DIR
                    } else if e.obj_type == DnodeType::PlainFile {
                        KIND_FILE
                    } else {
                        KIND_OTHER
                    },
                    _pad: [0; 7],
                    name: name_field(&e.name),
                };
                out.extend_from_slice(as_bytes(&rec));
            }
        }
        ADMIN_LOOKUP => {
            use crate::fs::zfs::types::DnodeType;
            let path = input_str(input)?;
            let st = crate::fs::ZfsClient::file_stat(path).map_err(|e| Failure::Message(ENOENT, e))?;
            let rec = LookupRecord {
                obj: st.obj_id,
                kind: match st.obj_type {
                    DnodeType::Directory => KIND_DIR as u64,
                    DnodeType::PlainFile => KIND_FILE as u64,
                    _ => KIND_OTHER as u64,
                },
                size: st.size,
            };
            out.extend_from_slice(as_bytes(&rec));
        }
        ADMIN_POWER => match call.args[0] {
            POWER_OFF => crate::arch::power::power_off(),
            POWER_REBOOT => crate::arch::power::reboot(),
            _ => return Err(Failure::Errno(EINVAL)),
        },
        _ => return Err(Failure::Errno(ENOSYS)),
    }
    Ok(out)
}
