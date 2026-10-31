//! Fast Userspace Mutex (futex) implementation for Linux ABI.
//!
//! The kernel side of glibc's and Qt's mutexes, condition variables, semaphores and
//! thread joins: `FUTEX_WAIT` / `FUTEX_WAIT_BITSET` (with relative or absolute timeouts,
//! interrupted by signals), `FUTEX_WAKE` / `FUTEX_WAKE_BITSET`, `FUTEX_WAKE_OP`,
//! `FUTEX_REQUEUE` and `FUTEX_CMP_REQUEUE`. Priority-inheritance operations fail with
//! `ENOSYS`, which makes glibc use its plain locks.
//!
//! A private futex (`FUTEX_PRIVATE_FLAG`, or any futex in private memory) is identified
//! by its address within an address space, so processes using the same virtual address do
//! not wake each other. A shared futex in a shared mapping (`MAP_SHARED` file, memfd or
//! anonymous memory inherited across `fork`) is identified by the physical address of its
//! word, which every process mapping it sees: process-shared mutexes, semaphores and
//! condition variables work between processes.
//!
//! Waiters sleep in event waits ([`crate::task::wait::wait`]): a wake removes the waiter
//! from the queue and makes it ready; a signal or the timeout ends the wait with the
//! waiter still queued, and it removes itself.

use alloc::vec::Vec;
use spin::Mutex;
use crate::task::TaskId;

pub const FUTEX_WAIT: i32 = 0;
pub const FUTEX_WAKE: i32 = 1;
pub const FUTEX_FD: i32 = 2;
pub const FUTEX_REQUEUE: i32 = 3;
pub const FUTEX_CMP_REQUEUE: i32 = 4;
pub const FUTEX_WAKE_OP: i32 = 5;
pub const FUTEX_LOCK_PI: i32 = 6;
pub const FUTEX_UNLOCK_PI: i32 = 7;
pub const FUTEX_TRYLOCK_PI: i32 = 8;
pub const FUTEX_WAIT_BITSET: i32 = 9;
pub const FUTEX_WAKE_BITSET: i32 = 10;
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
pub const FUTEX_CLOCK_REALTIME: i32 = 256;
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ETIMEDOUT: i64 = -110;

/// A futex: (address space, user address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexKey {
    pub space: u64,
    pub uaddr: u64,
}

/// Represents a thread waiting on a futex word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    pub key: FutexKey,
    pub task_id: TaskId,
    pub bitset: u32,
}

/// Global futex queue managing blocked threads.
pub struct FutexQueue {
    waiters: Vec<FutexWaiter>,
}

impl FutexQueue {
    pub const fn new() -> Self {
        Self { waiters: Vec::new() }
    }

    /// Removes up to `max_wake` waiters on `key` matching `bitset`, returning their ids.
    pub fn wake_task_ids(&mut self, key: FutexKey, max_wake: usize, bitset: u32) -> Vec<TaskId> {
        let mut ids = Vec::new();
        let mut i = 0;
        while i < self.waiters.len() && ids.len() < max_wake {
            if self.waiters[i].key == key && (self.waiters[i].bitset & bitset) != 0 {
                ids.push(self.waiters.remove(i).task_id);
            } else {
                i += 1;
            }
        }
        ids
    }

    /// Moves up to `max` waiters from `from` to `to`. Returns how many moved.
    fn requeue(&mut self, from: FutexKey, to: FutexKey, max: usize) -> usize {
        let mut n = 0;
        for w in self.waiters.iter_mut() {
            if n >= max {
                break;
            }
            if w.key == from {
                w.key = to;
                n += 1;
            }
        }
        n
    }

    fn is_waiting(&self, task: TaskId) -> bool {
        self.waiters.iter().any(|w| w.task_id == task)
    }

    fn remove(&mut self, task: TaskId) {
        self.waiters.retain(|w| w.task_id != task);
    }
}

pub static GLOBAL_FUTEX: Mutex<FutexQueue> = Mutex::new(FutexQueue::new());

/// Identity of the current address space (threads of a process, and a `vfork` child,
/// share it).
fn current_space() -> u64 {
    crate::task::with_current_task_mut(|t| t.mm.as_ref().map_or(t.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64)).unwrap_or(0)
}

/// `FutexKey::space` of futexes keyed by physical address (shared mappings).
const PHYSICAL: u64 = u64::MAX;

/// Key of `uaddr` in the current address space.
pub fn key_of(uaddr: u64) -> FutexKey {
    FutexKey { space: current_space(), uaddr }
}

/// Key of a futex operation: shared futexes in shared mappings are keyed by the physical
/// address of the word (the page is faulted in first), all others by address space.
fn key_for(uaddr: u64, private: bool) -> FutexKey {
    if !private && crate::memory::vm::prefault_current(uaddr & !3, 4, false) {
        if let Some(phys) = crate::memory::vm::shared_phys_current(uaddr) {
            return FutexKey { space: PHYSICAL, uaddr: phys };
        }
    }
    key_of(uaddr)
}

/// Key of `uaddr` in the address space of task `task` (for wakes from the scheduler).
pub fn key_for_task(task: &crate::task::Task, uaddr: u64) -> FutexKey {
    FutexKey { space: task.mm.as_ref().map_or(task.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64), uaddr }
}

fn read_word(uaddr: u64) -> Result<u32, i64> {
    if uaddr & 3 != 0 || !crate::memory::vm::prefault_current(uaddr, 4, false) {
        return Err(if uaddr & 3 != 0 { EINVAL } else { EFAULT });
    }
    Ok(unsafe { core::ptr::read_volatile(uaddr as *const u32) })
}

/// Wakes the listed tasks (they are in event waits).
fn wake_ids(ids: &[TaskId]) {
    if ids.is_empty() {
        return;
    }
    let mut sched = crate::task::SCHEDULER.lock();
    for id in ids {
        sched.wake_task(id.0);
    }
}

/// Timeout tick for a wait: `relative` timespecs count from now; absolute ones are on
/// CLOCK_MONOTONIC or (with `realtime`) the wall clock.
fn deadline_tick(ts_ptr: u64, relative: bool, realtime: bool) -> Result<Option<u64>, i64> {
    if ts_ptr == 0 {
        return Ok(None);
    }
    if !crate::memory::vm::prefault_current(ts_ptr, 16, false) {
        return Err(EFAULT);
    }
    let s = unsafe { core::ptr::read_unaligned(ts_ptr as *const i64) };
    let ns = unsafe { core::ptr::read_unaligned((ts_ptr + 8) as *const i64) };
    if s < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(EINVAL);
    }
    let total_ns = s as i128 * 1_000_000_000 + ns as i128;
    let now_ticks = crate::arch::pit::ticks() as i128;
    let tick_ns = 10_000_000i128;
    let target_ns = if relative {
        now_ticks * tick_ns + total_ns
    } else if realtime {
        let (rs, rns) = crate::arch::rtc::now();
        let offset = rs as i128 * 1_000_000_000 + rns as i128 - now_ticks * tick_ns;
        total_ns - offset
    } else {
        total_ns
    };
    Ok(Some(((target_ns.max(0) + tick_ns - 1) / tick_ns) as u64))
}

/// `FUTEX_WAIT*`: sleeps while `*uaddr == val` until woken, a signal, or the deadline.
fn wait(uaddr: u64, val: u32, bitset: u32, deadline: Option<u64>, private: bool) -> i64 {
    if bitset == 0 {
        return EINVAL;
    }
    if uaddr & 3 != 0 {
        return EINVAL;
    }
    let key = key_for(uaddr, private);
    let me = crate::task::SCHEDULER.lock().current_task_id();
    {
        let mut fq = GLOBAL_FUTEX.lock();
        // Checking the value and queueing happen under the queue lock, so a waker that
        // changes the value first and then wakes cannot be missed
        match read_word(uaddr) {
            Ok(v) if v == val => {}
            Ok(_) => return EAGAIN,
            Err(e) => return e,
        }
        fq.waiters.push(FutexWaiter { key, task_id: me, bitset });
    }
    loop {
        crate::task::wait::wait(deadline);
        let mut fq = GLOBAL_FUTEX.lock();
        if !fq.is_waiting(me) {
            return 0; // woken
        }
        if deadline.map_or(false, |d| crate::arch::pit::ticks() >= d) {
            fq.remove(me);
            return ETIMEDOUT;
        }
        if super::proc::signal_pending() {
            fq.remove(me);
            return if deadline.is_some() { EINTR } else { super::proc::ERESTARTSYS };
        }
        // Spurious wakeup: keep waiting
    }
}

/// Applies a `FUTEX_WAKE_OP` operation to `*uaddr2`; returns whether its comparison of the
/// old value holds.
fn wake_op_apply(uaddr2: u64, encoded: u32) -> Result<bool, i64> {
    if uaddr2 & 3 != 0 || !crate::memory::vm::prefault_current(uaddr2, 4, true) {
        return Err(EFAULT);
    }
    let op = (encoded >> 28) & 0xf;
    let cmp = (encoded >> 24) & 0xf;
    let mut oparg = (encoded >> 12) & 0xfff;
    let cmparg = encoded & 0xfff;
    if op & 8 != 0 {
        oparg = 1u32.checked_shl(oparg).unwrap_or(0); // FUTEX_OP_OPARG_SHIFT
    }
    let p = uaddr2 as *mut u32;
    let old = unsafe { core::ptr::read_volatile(p) };
    let new = match op & 7 {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        4 => old ^ oparg,
        _ => return Err(ENOSYS),
    };
    unsafe { core::ptr::write_volatile(p, new) };
    let (o, c) = (old as i32, cmparg as i32);
    Ok(match cmp {
        0 => o == c,
        1 => o != c,
        2 => o < c,
        3 => o <= c,
        4 => o > c,
        5 => o >= c,
        _ => return Err(ENOSYS),
    })
}

/// Top-level system call dispatcher for `sys_futex`.
pub fn dispatch_futex(uaddr: u64, op: i32, val: u32, timeout: u64, uaddr2: u64, val3: u32) -> i64 {
    let cmd = op & FUTEX_CMD_MASK;
    let realtime = op & FUTEX_CLOCK_REALTIME != 0;
    let private = op & FUTEX_PRIVATE_FLAG != 0;
    let key_of = |addr: u64| key_for(addr, private);
    match cmd {
        FUTEX_WAIT => match deadline_tick(timeout, true, false) {
            Ok(d) => wait(uaddr, val, FUTEX_BITSET_MATCH_ANY, d, private),
            Err(e) => e,
        },
        FUTEX_WAIT_BITSET => match deadline_tick(timeout, false, realtime) {
            Ok(d) => wait(uaddr, val, val3, d, private),
            Err(e) => e,
        },
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            let bitset = if cmd == FUTEX_WAKE { FUTEX_BITSET_MATCH_ANY } else { val3 };
            if bitset == 0 {
                return EINVAL;
            }
            let ids = GLOBAL_FUTEX.lock().wake_task_ids(key_of(uaddr), val as usize, bitset);
            wake_ids(&ids);
            ids.len() as i64
        }
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            // `timeout` carries the maximum number of waiters to requeue
            let (from, to) = (key_of(uaddr), key_of(uaddr2));
            let mut fq = GLOBAL_FUTEX.lock();
            if cmd == FUTEX_CMP_REQUEUE {
                match read_word(uaddr) {
                    Ok(v) if v == val3 => {}
                    Ok(_) => return EAGAIN,
                    Err(e) => return e,
                }
            }
            let ids = fq.wake_task_ids(from, val as usize, FUTEX_BITSET_MATCH_ANY);
            let moved = fq.requeue(from, to, timeout as u32 as usize);
            drop(fq);
            wake_ids(&ids);
            (ids.len() + if cmd == FUTEX_CMP_REQUEUE { moved } else { 0 }) as i64
        }
        FUTEX_WAKE_OP => {
            let mut fq = GLOBAL_FUTEX.lock();
            let fire = match wake_op_apply(uaddr2, val3) {
                Ok(f) => f,
                Err(e) => return e,
            };
            let mut ids = fq.wake_task_ids(key_of(uaddr), val as usize, FUTEX_BITSET_MATCH_ANY);
            if fire {
                // `timeout` carries the number of waiters to wake on uaddr2
                ids.extend(fq.wake_task_ids(key_of(uaddr2), timeout as u32 as usize, FUTEX_BITSET_MATCH_ANY));
            }
            drop(fq);
            wake_ids(&ids);
            ids.len() as i64
        }
        // Priority inheritance and futex descriptors: glibc falls back to plain futexes
        _ => ENOSYS,
    }
}
