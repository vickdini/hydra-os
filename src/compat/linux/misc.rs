//! # Smaller system calls
//!
//! `times`, `getcpu`, `membarrier`, `personality`, `sched_rr_get_interval`,
//! `restart_syscall`, the original `getdents`, and the older timestamp calls `utime`,
//! `utimes` and `futimesat`.
//!
//! Hydra runs on one CPU: `getcpu` reports CPU 0 on node 0, and `membarrier` holds without
//! interrupting anyone (no other thread runs while the caller does, and switching to one
//! is a full barrier).

use alloc::collections::BTreeMap;
use spin::Mutex;

use super::vfs::{copy_in, copy_out};

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const EINTR: i64 = -4;
const ESRCH: i64 = -3;
const AT_FDCWD: i64 = -100;

/// Clock ticks per second of `times` (`USER_HZ`, what `sysconf(_SC_CLK_TCK)` reports).
const USER_HZ: u64 = 100;

/// `membarrier` commands offered: GLOBAL, GLOBAL_EXPEDITED and its registration,
/// PRIVATE_EXPEDITED and its registration, PRIVATE_EXPEDITED_RSEQ and its registration.
/// (SYNC_CORE is not offered: returning to user mode is not always serializing here.)
const MEMBARRIER_SUPPORTED: u64 = 1 | 2 | 4 | 8 | 16 | 128 | 256;

/// `membarrier` registrations per process: the REGISTER_* command bits.
static MEMBARRIER_REGISTERED: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

/// Converts timer ticks to `USER_HZ` clock ticks.
fn to_clock_ticks(ticks: u64) -> u64 {
    ticks * USER_HZ / crate::arch::pit::frequency_hz().max(1)
}

/// `times(2)`: the process's CPU time and the clock ticks since boot. Hydra does not tell
/// user from system time (all of it is reported as user time) and does not add up the
/// times of waited-for children (reported as 0).
fn times(buf: u64) -> i64 {
    if buf != 0 {
        // tms_utime, tms_stime, tms_cutime, tms_cstime
        let (_, pid) = super::proc::current_ids();
        let c = super::proc::cpu_times(pid);
        let mut tms = [0u8; 32];
        for (i, v) in [c.0, c.1, c.2, c.3].into_iter().enumerate() {
            tms[i * 8..i * 8 + 8].copy_from_slice(&to_clock_ticks(v).to_le_bytes());
        }
        if copy_out(buf, &tms).is_err() {
            return EFAULT;
        }
    }
    to_clock_ticks(crate::arch::pit::ticks()) as i64
}

/// `membarrier(2)`.
fn membarrier(cmd: u64, flags: u64) -> i64 {
    let (_, pid) = super::proc::current_ids();
    if cmd == 0 {
        // MEMBARRIER_CMD_QUERY
        return if flags == 0 { MEMBARRIER_SUPPORTED as i64 } else { EINVAL };
    }
    // MEMBARRIER_CMD_FLAG_CPU is only for the RSEQ command
    if (flags != 0 && cmd != 128) || flags & !1 != 0 || cmd.count_ones() != 1 || cmd & MEMBARRIER_SUPPORTED == 0 {
        return EINVAL;
    }
    let mut reg = MEMBARRIER_REGISTERED.lock();
    let mine = reg.entry(pid).or_insert(0);
    match cmd {
        // Registrations: REGISTER_GLOBAL_EXPEDITED, REGISTER_PRIVATE_EXPEDITED, REGISTER_..._RSEQ
        4 | 16 | 256 => {
            *mine |= cmd;
            0
        }
        // PRIVATE_EXPEDITED and PRIVATE_EXPEDITED_RSEQ need their registration
        8 | 128 if *mine & (cmd << 1) == 0 => EPERM,
        _ => {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            0
        }
    }
}

/// Forgets a process's `membarrier` registrations (it exited or replaced its image).
///
/// # Arguments
/// * `pid` - Process ID.
pub fn forget_process(pid: u64) {
    MEMBARRIER_REGISTERED.lock().remove(&pid);
}

/// `personality(2)`: reads (`0xffffffff`) or sets the execution domain. Hydra keeps the
/// value (programs and `setarch` read it back) but it changes nothing: Linux binaries run
/// as `PER_LINUX`, and address space randomization is not used anyway.
fn personality(persona: u64) -> i64 {
    let (_, pid) = super::proc::current_ids();
    let mut procs = super::proc::PROCS.lock();
    let Some(p) = procs.get_mut(&pid) else { return 0 };
    let old = p.personality;
    if persona as u32 != 0xffff_ffff {
        p.personality = persona as u32;
    }
    old as i64
}

/// `sched_rr_get_interval(2)`: the scheduler's time slice.
fn sched_rr_get_interval(pid: u64, ts: u64) -> i64 {
    let pid = super::ns::pid_from_caller(pid);
    if pid != 0 && !super::proc::process_exists(pid) {
        return ESRCH;
    }
    let ns = crate::task::scheduler::DEFAULT_TIMESLICE_TICKS as u64 * 1_000_000_000 / crate::arch::pit::frequency_hz().max(1);
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_le_bytes());
    b[8..16].copy_from_slice(&((ns % 1_000_000_000) as i64).to_le_bytes());
    if copy_out(ts, &b).is_err() {
        return EFAULT;
    }
    0
}

/// The original `getdents(2)`: `getdents64` records converted in place. Both formats
/// have the same record length; `struct linux_dirent` keeps the type in the last byte.
fn getdents(fd: u64, dirp: u64, count: u64) -> i64 {
    let n = match super::vfs::dispatch(217, [fd, dirp, count, 0, 0, 0]) {
        Some(n) if n > 0 => n,
        Some(n) => return n,
        None => return -9,
    };
    let mut buf = match copy_in(dirp, n as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut off = 0;
    while off + 19 < buf.len() {
        let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
        if reclen < 20 || off + reclen > buf.len() {
            break;
        }
        let rec = &mut buf[off..off + reclen];
        let kind = rec[18];
        // The name (with its NUL) moves one byte down, over the type
        let name_len = rec[19..].iter().position(|&b| b == 0).unwrap_or(reclen - 20);
        rec.copy_within(19..19 + name_len, 18);
        for b in rec[18 + name_len..reclen - 1].iter_mut() {
            *b = 0;
        }
        rec[reclen - 1] = kind;
        off += reclen;
    }
    if copy_out(dirp, &buf).is_err() {
        return EFAULT;
    }
    n
}

/// Reads two `struct timeval`s (`utimes`, `futimesat`) as `(seconds, nanoseconds)`.
fn timevals(ptr: u64) -> Result<Option<[(i64, u32); 2]>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let raw = copy_in(ptr, 32)?;
    let tv = |o: usize| -> Result<(i64, u32), i64> {
        let s = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
        let us = i64::from_le_bytes(raw[o + 8..o + 16].try_into().unwrap());
        if !(0..1_000_000).contains(&us) {
            return Err(EINVAL);
        }
        Ok((s, us as u32 * 1000))
    };
    Ok(Some([tv(0)?, tv(16)?]))
}

/// Handles the calls of this module.
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for a call handled here, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    Some(match num {
        78 => getdents(a[0], a[1], a[2]),
        100 => times(a[0]),
        // utime(path, struct utimbuf*): whole seconds
        132 => {
            let times = if a[1] == 0 {
                None
            } else {
                match copy_in(a[1], 16) {
                    Ok(r) => {
                        let t = |o: usize| (i64::from_le_bytes(r[o..o + 8].try_into().unwrap()), 0u32);
                        Some([t(0), t(8)])
                    }
                    Err(e) => return Some(e),
                }
            };
            super::vfs::set_times(AT_FDCWD, a[0], times)
        }
        135 => personality(a[0]),
        148 => sched_rr_get_interval(a[0], a[1]),
        // restart_syscall: Hydra restarts interrupted calls itself; called directly, there
        // is nothing to restart
        219 => EINTR,
        235 => match timevals(a[1]) {
            Ok(t) => super::vfs::set_times(AT_FDCWD, a[0], t),
            Err(e) => e,
        },
        261 => match timevals(a[2]) {
            Ok(t) => super::vfs::set_times(a[0] as i32 as i64, a[1], t),
            Err(e) => e,
        },
        // getcpu(cpu*, node*, cache): one CPU, one node
        309 => {
            // getcpu(cpu, node): the CPU running the caller (one NUMA node)
            let cpu = crate::arch::percpu::cpu() as u32;
            for (p, v) in [(a[0], cpu), (a[1], 0u32)] {
                if p != 0 && copy_out(p, &v.to_le_bytes()).is_err() {
                    return Some(EFAULT);
                }
            }
            0
        }
        324 => membarrier(a[0], a[1]),
        _ => return None,
    })
}
