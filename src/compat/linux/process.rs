//! # Linux Process-Attribute System Calls
//!
//! Resource limits, robust futex lists, `rseq`, and process-group/session identifiers.
//! Hydra has no process tree yet (milestone 2), so every process is its own process
//! group and session leader with PID 1 as its parent.

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const ENOSYS: i64 = -38;

const NR_GETRLIMIT: u64 = 97;
const NR_REBOOT: u64 = 169;
const NR_GETPPID: u64 = 110;
const NR_GETPGRP: u64 = 111;
const NR_SETSID: u64 = 112;
const NR_SETPGID: u64 = 109;
const NR_GETPGID: u64 = 121;
const NR_GETSID: u64 = 124;
const NR_SETRLIMIT: u64 = 160;
const NR_SET_ROBUST_LIST: u64 = 273;
const NR_GET_ROBUST_LIST: u64 = 274;
const NR_PRLIMIT64: u64 = 302;
const NR_RSEQ: u64 = 334;
const NR_NANOSLEEP: u64 = 35;
const NR_CLOCK_NANOSLEEP: u64 = 230;
const NR_KILL: u64 = 62;
const NR_PRCTL: u64 = 157;
const NR_TKILL: u64 = 200;
const NR_SCHED_SETAFFINITY: u64 = 203;
const NR_SCHED_GETAFFINITY: u64 = 204;
const NR_TGKILL: u64 = 234;

const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_DUMPABLE: u64 = 4;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const PR_CAPBSET_READ: u64 = 23;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;
const PR_GET_AUXV: u64 = 0x4155_5856;

/// Writes a 16-byte `(rlim_cur, rlim_max)` pair into user virtual memory.
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to `struct rlimit` (or `0` to ignore).
/// * `limit` - `(soft, hard)` limit values to write.
///
/// # Returns
///
/// `0` on success, or `-EFAULT` if user memory cannot be prefaulted.
fn write_rlimit(ptr: u64, limit: (u64, u64)) -> i64 {
    if ptr == 0 {
        return 0;
    }
    if !crate::memory::vm::prefault_current(ptr, 16, true) {
        return EFAULT;
    }
    unsafe {
        *(ptr as *mut u64) = limit.0;
        *((ptr + 8) as *mut u64) = limit.1;
    }
    0
}

/// The calling process's auxiliary vector.
///
/// # Returns
///
/// Raw ELF auxiliary vector bytes stored in the current process's memory manager.
pub fn current_auxv() -> alloc::vec::Vec<u8> {
    super::mm::current_mm().map(|mm| mm.lock().auxv.clone()).unwrap_or_default()
}

/// Copies byte data to user virtual address space after prefaulting.
///
/// # Arguments
///
/// * `ptr` - User destination address.
/// * `data` - Source bytes to copy.
///
/// # Returns
///
/// `0` on success, or `-EFAULT` if destination pages cannot be mapped.
fn copy_out(ptr: u64, data: &[u8]) -> i64 {
    if !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
        return EFAULT;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    0
}

/// Sleeps until `deadline_ns` on the boot clock, waking early (with `EINTR`) for signals.
/// Deadlines of interrupted sleeps, by thread, so a transparent restart (after a stop
/// signal or an ignored signal) sleeps only for the remaining time.
static SLEEP_DEADLINES: spin::Mutex<alloc::collections::BTreeMap<u64, u64>> = spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Sleeps until `deadline_ns` (boot clock). If a signal interrupts the sleep, the remaining
/// time is written to `rem` (when given) and the call reports `ERESTART_RESTARTBLOCK`.
///
/// # Arguments
///
/// * `deadline_ns` - Absolute monotonic deadline in nanoseconds.
/// * `rem` - Optional user pointer to write remaining duration if interrupted (`0` if null).
///
/// # Returns
///
/// `0` if full duration elapsed, or `-ERESTART_RESTARTBLOCK` if interrupted by a signal.
fn sleep_until(deadline_ns: u64, rem: u64) -> i64 {
    loop {
        let now = crate::arch::pit::ticks() * 10_000_000;
        if now >= deadline_ns {
            return 0;
        }
        if super::proc::signal_pending() {
            let (tid, _) = super::proc::current_ids();
            SLEEP_DEADLINES.lock().insert(tid, deadline_ns);
            if rem != 0 && crate::memory::vm::prefault_current(rem, 16, true) {
                let left = deadline_ns - now;
                unsafe {
                    *(rem as *mut i64) = (left / 1_000_000_000) as i64;
                    *((rem + 8) as *mut i64) = (left % 1_000_000_000) as i64;
                }
            }
            return super::proc::ERESTART_RESTARTBLOCK;
        }
        crate::task::sleep_ticks(1);
    }
}

/// Reads a 16-byte `struct timespec` from user space and converts it to nanoseconds.
///
/// # Arguments
///
/// * `ptr` - User virtual pointer to `struct timespec`.
///
/// # Returns
///
/// `Some(nanoseconds)` if valid, or `None` if invalid or memory cannot be accessed.
fn read_timespec_ns(ptr: u64) -> Option<u64> {
    if !crate::memory::vm::prefault_current(ptr, 16, false) {
        return None;
    }
    let (s, ns) = unsafe { (*(ptr as *const i64), *((ptr + 8) as *const i64)) };
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return None;
    }
    Some(s as u64 * 1_000_000_000 + ns as u64)
}

/// Handles process-attribute system calls; `None` if `num` is not one of them.
///
/// # Arguments
///
/// * `num` - System call number.
/// * `a` - System call argument register array `[arg0..arg5]`.
///
/// # Returns
///
/// * `Some(result)` if the system call is handled by this dispatcher.
/// * `None` if `num` does not belong to process-attribute system calls.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    Some(match num {
        NR_SET_ROBUST_LIST => {
            // The list is only consulted when a thread dies holding a robust mutex
            if a[1] != 24 {
                EINVAL
            } else {
                0
            }
        }
        NR_GET_ROBUST_LIST => {
            if a[1] != 0 {
                let _ = write_rlimit(a[1], (0, 0));
            }
            if a[2] != 0 && crate::memory::vm::prefault_current(a[2], 8, true) {
                unsafe { *(a[2] as *mut u64) = 24 };
            }
            0
        }
        NR_RSEQ => ENOSYS,
        115 => super::proc::sys_getgroups(a[0], a[1]),
        116 => super::proc::sys_setgroups(a[0], a[1]),
        73 => super::locks::flock(a[0], a[1]),
        // sync_file_range: writeback hint; data reaches the pool with the next transaction group
        277 => 0,
        // fadvise64: access-pattern hints (no read-ahead policy to tune)
        221 => 0,
        // alarm / getitimer / setitimer
        37 => super::itimer::sys_alarm(a[0]),
        36 => super::itimer::sys_getitimer(a[0], a[1]),
        38 => super::itimer::sys_setitimer(a[0], a[1], a[2]),
        // pidfd_open / pidfd_send_signal
        434 => super::pidfd::sys_pidfd_open(a[0], a[1]),
        424 => super::pidfd::sys_pidfd_send_signal(a[0], a[1], a[2], a[3]),
        // eventfd / eventfd2
        284 => super::eventfd::sys_eventfd2(a[0], 0),
        290 => super::eventfd::sys_eventfd2(a[0], a[1]),
        // timerfd_create / settime / gettime
        283 => super::timerfd::sys_create(a[0], a[1]),
        286 => super::timerfd::sys_settime(a[0], a[1], a[2], a[3]),
        287 => super::timerfd::sys_gettime(a[0], a[1]),
        // inotify_init / inotify_init1 / add_watch / rm_watch
        253 => super::inotify::sys_init1(0),
        294 => super::inotify::sys_init1(a[0]),
        254 => super::inotify::sys_add_watch(a[0], a[1], a[2]),
        255 => super::inotify::sys_rm_watch(a[0], a[1]),
        282 => super::signalfd::sys_signalfd4(a[0] as i32 as i64, a[1], a[2], 0),
        289 => super::signalfd::sys_signalfd4(a[0] as i32 as i64, a[1], a[2], a[3]),
        // pause: sleep until a signal is delivered (a posted signal wakes the event wait)
        34 => loop {
            if super::proc::signal_pending() {
                break -4; // EINTR (never restarted)
            }
            crate::task::wait::wait(None);
        },
        // getrusage(who, struct rusage *): CPU time from the scheduler's tick accounting
        // (user and system time are not told apart); other fields stay zero
        98 => {
            let who = a[0] as i32;
            if !(-1..=1).contains(&who) {
                EINVAL
            } else {
                let ticks = if who == -1 { 0 } else { crate::task::with_current_task_mut(|t| t.ticks_run).unwrap_or(0) };
                let us = ticks * 1_000_000 / crate::arch::pit::frequency_hz().max(1);
                let mut ru = [0u8; 144];
                ru[0..8].copy_from_slice(&(us / 1_000_000).to_le_bytes());
                ru[8..16].copy_from_slice(&(us % 1_000_000).to_le_bytes());
                copy_out(a[1], &ru)
            }
        }
        229 => {
            // clock_getres: 10 ms timer resolution
            if a[1] != 0 {
                if !crate::memory::vm::prefault_current(a[1], 16, true) {
                    return Some(EFAULT);
                }
                unsafe {
                    *(a[1] as *mut i64) = 0;
                    *((a[1] + 8) as *mut i64) = 10_000_000;
                }
            }
            0
        }
        23 => super::select::sys_select(a),
        270 => super::select::sys_pselect6(a),
        201 => {
            // time(tloc)
            let now = crate::arch::rtc::now().0 as i64;
            if a[0] != 0 {
                if !crate::memory::vm::prefault_current(a[0], 8, true) {
                    return Some(EFAULT);
                }
                unsafe { *(a[0] as *mut i64) = now };
            }
            now
        }
        // setfsuid/setfsgid: file-system ids follow the effective ids; report the current one
        122 => crate::task::with_current_task_mut(|t| t.euid as i64).unwrap_or(0),
        123 => crate::task::with_current_task_mut(|t| t.egid as i64).unwrap_or(0),
        NR_NANOSLEEP | NR_CLOCK_NANOSLEEP => {
            let (req, abs, rem) = if num == NR_NANOSLEEP { (a[0], false, a[1]) } else { (a[2], a[1] & 1 != 0, a[3]) };
            // A transparently restarted sleep continues toward its original deadline
            let (tid, _) = super::proc::current_ids();
            let saved = SLEEP_DEADLINES.lock().remove(&tid);
            if super::proc::take_restart_flag() {
                if let Some(deadline) = saved {
                    return Some(sleep_until(deadline, if abs { 0 } else { rem }));
                }
            }
            let ns = match read_timespec_ns(req) {
                Some(ns) => ns,
                None => return Some(EINVAL),
            };
            let now = crate::arch::pit::ticks() * 10_000_000;
            let deadline = if abs {
                // CLOCK_REALTIME deadlines are converted to the boot clock
                if num == NR_CLOCK_NANOSLEEP && a[0] == 0 {
                    let (s, n) = crate::arch::rtc::now();
                    let wall = s * 1_000_000_000 + n as u64;
                    now + ns.saturating_sub(wall)
                } else {
                    ns
                }
            } else {
                now + ns
            };
            sleep_until(deadline, if abs { 0 } else { rem })
        }
        NR_GETRLIMIT | NR_SETRLIMIT | NR_PRLIMIT64 => super::limits::rlimit(num, a),
        NR_REBOOT => sys_reboot(a[0] as u32, a[1] as u32, a[2] as u32),
        NR_GETPPID => super::proc::getppid(),
        NR_GETPGRP => super::proc::getpgid(0),
        NR_GETPGID => super::proc::getpgid(a[0] as u32 as u64),
        NR_GETSID => super::proc::getsid(a[0] as u32 as u64),
        NR_SETPGID => super::proc::setpgid(a[0] as u32 as u64, a[1] as u32 as u64),
        NR_SETSID => super::proc::setsid(),
        // pid_t arguments are 32-bit: sign-extend from the low half of the register
        // PID namespace: 1 is the namespace's init
        NR_KILL => {
            let pid = a[0] as i32 as i64;
            super::proc::sys_kill(if pid > 0 { super::ns::pid_from_caller(pid as u64) as i64 } else { pid }, a[1])
        }
        NR_TKILL => super::proc::sys_tkill(super::ns::pid_from_caller(a[0] as u32 as u64), a[1]),
        NR_TGKILL => super::proc::sys_tgkill(super::ns::pid_from_caller(a[0] as u32 as u64), super::ns::pid_from_caller(a[1] as u32 as u64), a[2]),
        NR_SCHED_GETAFFINITY => {
            // One CPU: report a mask with only CPU 0 set, sized as the kernel's cpumask (8 bytes)
            if (a[1] as usize) < 8 {
                EINVAL
            } else {
                let mut mask = alloc::vec![0u8; 8];
                mask[0] = 1;
                match copy_out(a[2], &mask) {
                    0 => 8,
                    e => e,
                }
            }
        }
        NR_SCHED_SETAFFINITY => super::limits::sched_setaffinity(a[0], a[1], a[2]),
        99 => {
            // sysinfo
            let fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
            let (total, free) = (fa.total_usable_memory(), fa.free_memory());
            drop(fa);
            let mut b = [0u8; 112];
            b[0..8].copy_from_slice(&(crate::arch::pit::ticks() / 100).to_le_bytes());
            b[32..40].copy_from_slice(&total.to_le_bytes());
            b[40..48].copy_from_slice(&free.to_le_bytes());
            let procs = super::proc::process_count() as u16;
            b[80..82].copy_from_slice(&procs.to_le_bytes());
            b[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
            copy_out(a[0], &b)
        }
        // mlock, munlock, mlockall, munlockall, mlock2
        149 | 150 | 151 | 152 | 325 => super::limits::mlock(num, a),
        // ioprio_set / ioprio_get
        251 | 252 => super::limits::ioprio(num, a[0], a[1], a[2]),
        239 => {
            // get_mempolicy: one NUMA node, so always MPOL_DEFAULT
            if a[0] != 0 {
                match copy_out(a[0], &0i32.to_le_bytes()) {
                    0 => {}
                    e => return Some(e),
                }
            }
            0
        }
        140 => super::limits::getpriority(a[0], a[1]),
        141 => super::limits::setpriority(a[0], a[1], a[2]),
        142 => super::limits::sched_set(a[0], None, a[1]),
        143 => super::limits::sched_getparam(a[0], a[1]),
        144 => super::limits::sched_set(a[0], Some(a[1]), a[2]),
        145 => super::limits::sched_getscheduler(a[0]),
        146 => match a[0] {
            1 | 2 => 99,
            0 | 3 | 5 => 0,
            _ => EINVAL,
        },
        147 => match a[0] {
            1 | 2 => 1,
            0 | 3 | 5 => 0,
            _ => EINVAL,
        },
        303 => super::fanotify::name_to_handle_at(a[0], a[1], a[2], a[3], a[4]),
        125 => {
            // capget: root holds every capability, other users none
            let version = match super::vfs::copy_in(a[0], 4) {
                Ok(v) => u32::from_le_bytes(v[..4].try_into().unwrap()),
                Err(e) => return Some(e),
            };
            let words = match version {
                0x1998_0330 => 1,
                0x2007_1026 | 0x2008_0522 => 2,
                _ => {
                    // Unknown version: report the preferred one
                    let _ = copy_out(a[0], &0x2008_0522u32.to_le_bytes());
                    return Some(if a[1] == 0 { 0 } else { EINVAL });
                }
            };
            if a[1] == 0 {
                return Some(0);
            }
            let caps = crate::task::with_current_task_mut(|t| t.caps).unwrap_or(crate::task::tcb::Caps::for_euid(0));
            let mut data = alloc::vec![0u8; 12 * words];
            for w in 0..words {
                // effective, permitted (inheritable stays empty)
                let (e, p) = ((caps.effective >> (32 * w)) as u32, (caps.permitted >> (32 * w)) as u32);
                data[w * 12..w * 12 + 4].copy_from_slice(&e.to_le_bytes());
                data[w * 12 + 4..w * 12 + 8].copy_from_slice(&p.to_le_bytes());
            }
            copy_out(a[1], &data)
        }
        126 => {
            // capset (own process): permitted may only shrink, effective must stay within it
            let head = match super::vfs::copy_in(a[0], 8) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let words = match u32::from_le_bytes(head[..4].try_into().unwrap()) {
                0x1998_0330 => 1,
                0x2007_1026 | 0x2008_0522 => 2,
                _ => return Some(EINVAL),
            };
            let pid = i32::from_le_bytes(head[4..8].try_into().unwrap());
            if pid != 0 && pid as u64 != super::proc::current_ids().1 {
                return Some(EPERM);
            }
            let data = match super::vfs::copy_in(a[1], 12 * words) {
                Ok(v) => v,
                Err(e) => return Some(e),
            };
            let (mut eff, mut perm) = (0u64, 0u64);
            for w in 0..words {
                eff |= (u32::from_le_bytes(data[w * 12..w * 12 + 4].try_into().unwrap()) as u64) << (32 * w);
                perm |= (u32::from_le_bytes(data[w * 12 + 4..w * 12 + 8].try_into().unwrap()) as u64) << (32 * w);
            }
            crate::task::with_current_task_mut(|t| {
                if words == 1 {
                    // A v1 caller cannot see the upper capabilities: keep them as they are
                    eff |= t.caps.effective & !0xFFFF_FFFF;
                    perm |= t.caps.permitted & !0xFFFF_FFFF;
                }
                if perm & !t.caps.permitted != 0 || eff & !perm != 0 {
                    return EPERM;
                }
                t.caps.permitted = perm;
                t.caps.effective = eff;
                0
            })
            .unwrap_or(EPERM)
        }
        NR_PRCTL => match a[0] {
            PR_GET_AUXV => {
                let auxv = current_auxv();
                let n = auxv.len().min(a[2] as usize);
                if n > 0 {
                    let r = copy_out(a[1], &auxv[..n]);
                    if r != 0 {
                        return Some(r);
                    }
                }
                auxv.len() as i64
            }
            PR_SET_NAME | PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_CHILD_SUBREAPER => 0,
            // PR_GET_SECCOMP, PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS, PR_GET_NO_NEW_PRIVS
            21 | 22 | PR_SET_NO_NEW_PRIVS | PR_GET_NO_NEW_PRIVS => super::seccomp::prctl(a[0], a[1], a[2]).unwrap_or(EINVAL),
            8 => {
                // PR_SET_KEEPCAPS
                if a[1] > 1 {
                    return Some(EINVAL);
                }
                crate::task::with_current_task_mut(|t| t.caps.keep = a[1] == 1);
                0
            }
            7 => crate::task::with_current_task_mut(|t| t.caps.keep as i64).unwrap_or(0), // PR_GET_KEEPCAPS
            47 => 0, // PR_CAP_AMBIENT
            24 => 0,     // PR_CAPBSET_DROP
            PR_GET_NAME => {
                let mut name = [0u8; 16];
                name[..9].copy_from_slice(b"linux_app");
                copy_out(a[1], &name)
            }
            PR_GET_DUMPABLE | PR_CAPBSET_READ => 1,
            _ => EINVAL,
        },
        _ => return None,
    })
}

/// `reboot(2)`: powers the machine off, halts or restarts it (after committing the pool),
/// as systemd and login managers do at the end of a shutdown. Needs `CAP_SYS_BOOT` and
/// the magic numbers that guard against stray calls.
///
/// # Arguments
/// * `magic` - `LINUX_REBOOT_MAGIC1`.
/// * `magic2` - One of the `LINUX_REBOOT_MAGIC2*` values.
/// * `cmd` - What to do (`LINUX_REBOOT_CMD_*`).
///
/// # Returns
/// `0` for the commands that return (Ctrl+Alt+Del handling), or a negative error.
fn sys_reboot(magic: u32, magic2: u32, cmd: u32) -> i64 {
    const MAGIC1: u32 = 0xfee1_dead;
    const MAGIC2: [u32; 4] = [672274793, 85072278, 369367448, 537993216];
    const CMD_RESTART: u32 = 0x0123_4567;
    const CMD_HALT: u32 = 0xcdef_0123;
    const CMD_POWER_OFF: u32 = 0x4321_fedc;
    const CMD_CAD_ON: u32 = 0x89ab_cdef;
    const CMD_CAD_OFF: u32 = 0;
    if magic != MAGIC1 || !MAGIC2.contains(&magic2) {
        return -22; // EINVAL
    }
    if !crate::task::with_current_task_mut(|t| t.caps.has(crate::task::tcb::Caps::SYS_BOOT)).unwrap_or(false) {
        return -1; // EPERM
    }
    match cmd {
        CMD_POWER_OFF | CMD_HALT => crate::arch::power::power_off(),
        CMD_RESTART => crate::arch::power::reboot(),
        CMD_CAD_ON | CMD_CAD_OFF => 0,
        _ => -22,
    }
}
