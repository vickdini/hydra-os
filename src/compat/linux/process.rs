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

/// Default action for a signal sent by a process to itself: Hydra has no signal handlers
/// yet (milestone 2), so terminating signals end the whole process and the rest are ignored.
fn self_signal(sig: u64) -> i64 {
    match sig {
        0 => 0,
        17 | 18 | 23 | 28 => 0, // SIGCHLD, SIGCONT, SIGURG, SIGWINCH: ignored by default
        _ => {
            let pid = current_tgid();
            crate::println!("[linux] pid {} terminated by signal {}", pid, sig);
            crate::task::exit_group();
        }
    }
}

fn current_tgid() -> u64 {
    crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(1)
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
        NR_GETPPID => 1,
        NR_GETPGRP => current_tgid() as i64,
        NR_GETPGID | NR_GETSID => {
            if a[0] == 0 || a[0] == current_tgid() {
                current_tgid() as i64
            } else {
                ESRCH
            }
        }
        NR_SETPGID => 0,
        NR_SETSID => current_tgid() as i64,
        NR_KILL => {
            if a[0] as i64 == current_tgid() as i64 || a[0] == 0 {
                self_signal(a[1])
            } else {
                ESRCH
            }
        }
        NR_TKILL => self_signal(a[1]),
        NR_TGKILL => {
            if a[0] == current_tgid() {
                self_signal(a[2])
            } else {
                ESRCH
            }
        }
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
