//! # Linux Process-Attribute System Calls
//!
//! Resource limits, robust futex lists, `rseq`, and process-group/session identifiers.
//! Hydra has no process tree yet (milestone 2), so every process is its own process
//! group and session leader with PID 1 as its parent.

const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

const NR_GETRLIMIT: u64 = 97;
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

const RLIM_INFINITY: u64 = u64::MAX;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_NLIMITS: u64 = 16;

/// Default (soft, hard) limit for a resource, matching a stock Linux login session.
fn default_limit(resource: u64) -> (u64, u64) {
    match resource {
        RLIMIT_STACK => (8 * 1024 * 1024, RLIM_INFINITY),
        RLIMIT_NOFILE => (crate::fs::MAX_FDS as u64, crate::fs::MAX_FDS as u64),
        _ => (RLIM_INFINITY, RLIM_INFINITY),
    }
}

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
pub fn current_auxv() -> alloc::vec::Vec<u8> {
    super::mm::current_mm().map(|mm| mm.lock().auxv.clone()).unwrap_or_default()
}

fn copy_out(ptr: u64, data: &[u8]) -> i64 {
    if !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
        return EFAULT;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    0
}

fn current_tgid() -> u64 {
    crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(1)
}

/// Sleeps until `deadline_ns` on the boot clock, waking early (with `EINTR`) for signals.
/// Deadlines of interrupted sleeps, by thread, so a transparent restart (after a stop
/// signal or an ignored signal) sleeps only for the remaining time.
static SLEEP_DEADLINES: spin::Mutex<alloc::collections::BTreeMap<u64, u64>> = spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Sleeps until `deadline_ns` (boot clock). If a signal interrupts the sleep, the remaining
/// time is written to `rem` (when given) and the call reports `ERESTART_RESTARTBLOCK`.
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
        NR_GETRLIMIT => {
            if a[0] >= RLIMIT_NLIMITS {
                EINVAL
            } else {
                write_rlimit(a[1], default_limit(a[0]))
            }
        }
        NR_SETRLIMIT => 0,
        NR_PRLIMIT64 => {
            if a[0] != 0 && a[0] != current_tgid() {
                ESRCH
            } else if a[1] >= RLIMIT_NLIMITS {
                EINVAL
            } else {
                write_rlimit(a[3], default_limit(a[1]))
            }
        }
        NR_GETPPID => super::proc::getppid(),
        NR_GETPGRP => super::proc::getpgid(0),
        NR_GETPGID => super::proc::getpgid(a[0] as u32 as u64),
        NR_GETSID => super::proc::getsid(a[0] as u32 as u64),
        NR_SETPGID => super::proc::setpgid(a[0] as u32 as u64, a[1] as u32 as u64),
        NR_SETSID => super::proc::setsid(),
        // pid_t arguments are 32-bit: sign-extend from the low half of the register
        NR_KILL => super::proc::sys_kill(a[0] as i32 as i64, a[1]),
        NR_TKILL => super::proc::sys_tkill(a[0] as u32 as u64, a[1]),
        NR_TGKILL => super::proc::sys_tgkill(a[0] as u32 as u64, a[1] as u32 as u64, a[2]),
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
        NR_SCHED_SETAFFINITY => 0,
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
            PR_SET_NAME | PR_SET_PDEATHSIG | PR_SET_DUMPABLE | PR_SET_CHILD_SUBREAPER | PR_SET_NO_NEW_PRIVS => 0,
            PR_GET_NAME => {
                let mut name = [0u8; 16];
                name[..9].copy_from_slice(b"linux_app");
                copy_out(a[1], &name)
            }
            PR_GET_DUMPABLE | PR_CAPBSET_READ => 1,
            PR_GET_NO_NEW_PRIVS => 0,
            _ => EINVAL,
        },
        _ => return None,
    })
}
