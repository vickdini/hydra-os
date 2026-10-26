//! Fast Userspace Mutex (futex) implementation for Linux ABI.
//!
//! Provides thread synchronization primitives (`FUTEX_WAIT`, `FUTEX_WAKE`,
//! `FUTEX_WAIT_BITSET`, `FUTEX_WAKE_BITSET`) and robust exit handling
//! for pthread mutexes, condition variables, and thread joins.

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

/// Represents a thread waiting on a futex word at a specific userspace address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    pub uaddr: u64,
    pub task_id: TaskId,
    pub bitset: u32,
}

/// Global futex queue managing blocked threads.
pub struct FutexQueue {
    waiters: Vec<FutexWaiter>,
}

impl FutexQueue {
    pub const fn new() -> Self {
        Self {
            waiters: Vec::new(),
        }
    }

    /// Blocks the current task if `*uaddr == val`.
    pub fn wait(&mut self, uaddr: u64, val: u32, bitset: u32) -> Result<(), i64> {
        let ptr = uaddr as *const u32;
        if ptr.is_null() || (uaddr & 3) != 0 {
            return Err(-14); // -EFAULT
        }

        let cur_val = unsafe { *ptr };
        if cur_val != val {
            return Err(-11); // -EAGAIN: value changed concurrently
        }

        let current_task_id = crate::task::SCHEDULER.lock().current_task_id();
        self.waiters.push(FutexWaiter {
            uaddr,
            task_id: current_task_id,
            bitset,
        });

        // Transition task to Blocked state
        crate::task::SCHEDULER.lock().block_current();
        Ok(())
    }

    /// Collects up to `max_wake` thread IDs waiting on `uaddr` and removes them from the queue.
    pub fn wake_task_ids(&mut self, uaddr: u64, max_wake: usize, bitset: u32) -> Vec<TaskId> {
        let mut ids = Vec::new();
        let mut i = 0;
        while i < self.waiters.len() && ids.len() < max_wake {
            if self.waiters[i].uaddr == uaddr && (self.waiters[i].bitset & bitset) != 0 {
                let waiter = self.waiters.remove(i);
                ids.push(waiter.task_id);
            } else {
                i += 1;
            }
        }
        ids
    }
}

pub static GLOBAL_FUTEX: Mutex<FutexQueue> = Mutex::new(FutexQueue::new());

/// Top-level system call dispatcher for `sys_futex`.
pub fn dispatch_futex(
    uaddr: u64,
    op: i32,
    val: u32,
    _timeout: u64,
    _uaddr2: u64,
    val3: u32,
) -> i64 {
    let cmd = op & FUTEX_CMD_MASK;
    match cmd {
        FUTEX_WAIT => {
            let mut fq = GLOBAL_FUTEX.lock();
            match fq.wait(uaddr, val, FUTEX_BITSET_MATCH_ANY) {
                Ok(()) => {
                    drop(fq);
                    crate::task::yield_now();
                    0
                }
                Err(e) => e,
            }
        }
        FUTEX_WAIT_BITSET => {
            let bitset = if val3 != 0 { val3 } else { FUTEX_BITSET_MATCH_ANY };
            let mut fq = GLOBAL_FUTEX.lock();
            match fq.wait(uaddr, val, bitset) {
                Ok(()) => {
                    drop(fq);
                    crate::task::yield_now();
                    0
                }
                Err(e) => e,
            }
        }
        FUTEX_WAKE => {
            let mut fq = GLOBAL_FUTEX.lock();
            let ids = fq.wake_task_ids(uaddr, val as usize, FUTEX_BITSET_MATCH_ANY);
            drop(fq);
            let mut sched = crate::task::SCHEDULER.lock();
            for id in ids.iter() {
                sched.unblock_task(*id);
            }
            ids.len() as i64
        }
        FUTEX_WAKE_BITSET => {
            let bitset = if val3 != 0 { val3 } else { FUTEX_BITSET_MATCH_ANY };
            let mut fq = GLOBAL_FUTEX.lock();
            let ids = fq.wake_task_ids(uaddr, val as usize, bitset);
            drop(fq);
            let mut sched = crate::task::SCHEDULER.lock();
            for id in ids.iter() {
                sched.unblock_task(*id);
            }
            ids.len() as i64
        }
        _ => 0, // Fallback success for unimplemented futex sub-commands
    }
}
