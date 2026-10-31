//! # Linux Compatibility: Fast Userspace Mutex (`futex`) Subsystem
//!
//! Provides the kernel-assisted sleeping and waking mechanism (`sys_futex`) backing
//! `glibc`, `musl`, and Qt6 mutexes, condition variables, semaphores, and thread joins.
//!
//! ## Architectural Role & Design Rationale
//! In uncontended cases, userspace locks acquire and release atomically without entering the
//! kernel. When contention occurs, threads invoke `sys_futex` to atomically verify that the
//! 32-bit lock word at `uaddr` still holds the expected value `val` before enqueuing on
//! [`GLOBAL_FUTEX`] and sleeping via [`crate::task::wait::wait`].
//!
//! A private futex (`FUTEX_PRIVATE_FLAG`, or any futex in private memory) is keyed by its
//! virtual address within an address space, so unrelated processes using the same virtual
//! address do not wake each other. A shared futex in a shared mapping (`MAP_SHARED` file,
//! `memfd`, or anonymous memory inherited across `fork`) is keyed by the underlying physical
//! address of its 32-bit word, enabling cross-process synchronization.
//!
//! ## Key Types & Interfaces
//! - [`FutexKey`]: Composite `(space, uaddr)` identifier distinguishing private and shared futexes.
//! - [`FutexWaiter`]: Wait queue entry associating a sleeping `TaskId` with a [`FutexKey`] and bitset.
//! - [`FutexQueue`] / [`GLOBAL_FUTEX`]: Global spinlock-protected wait list for blocked threads.
//! - [`dispatch_futex()`]: Top-level `sys_futex` system call multiplexer.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reads PIT tick counter and CMOS RTC for relative/absolute timeouts;
//!   queries page tables via [`crate::memory::vm`] to resolve shared physical addresses.
//! - Concurrency: Atomicity between the 32-bit word check and sleep enqueueing is guaranteed by
//!   holding [`GLOBAL_FUTEX`].

use alloc::vec::Vec;
use spin::Mutex;
use crate::task::TaskId;

/// `futex` operation: verify `*uaddr == val` and sleep until woken or timed out (relative timeout).
pub const FUTEX_WAIT: i32 = 0;
/// `futex` operation: wake up to `val` waiters blocked on `uaddr`.
pub const FUTEX_WAKE: i32 = 1;
/// Legacy `futex` operation: create a file descriptor associated with a futex (unsupported; returns `-ENOSYS`).
pub const FUTEX_FD: i32 = 2;
/// `futex` operation: wake up to `val` waiters on `uaddr` and move up to `timeout` waiters to `uaddr2`.
pub const FUTEX_REQUEUE: i32 = 3;
/// `futex` operation: like [`FUTEX_REQUEUE`], but first verifies `*uaddr == val3`.
pub const FUTEX_CMP_REQUEUE: i32 = 4;
/// `futex` operation: atomically modify `*uaddr2`, wake waiters on `uaddr`, and conditionally wake `uaddr2`.
pub const FUTEX_WAKE_OP: i32 = 5;
/// Priority-inheritance futex lock (returns `-ENOSYS` so `glibc` falls back to normal futexes).
pub const FUTEX_LOCK_PI: i32 = 6;
/// Priority-inheritance futex unlock (returns `-ENOSYS`).
pub const FUTEX_UNLOCK_PI: i32 = 7;
/// Priority-inheritance futex trylock (returns `-ENOSYS`).
pub const FUTEX_TRYLOCK_PI: i32 = 8;
/// `futex` operation: like [`FUTEX_WAIT`], but matches a 32-bit `val3` bitmask and uses an absolute timeout.
pub const FUTEX_WAIT_BITSET: i32 = 9;
/// `futex` operation: wake up to `val` waiters on `uaddr` whose bitset intersects `val3`.
pub const FUTEX_WAKE_BITSET: i32 = 10;
/// Flag bit in `op`: futex is process-private and never shared across address spaces.
pub const FUTEX_PRIVATE_FLAG: i32 = 128;
/// Flag bit in `op`: evaluate absolute timeouts against `CLOCK_REALTIME` instead of `CLOCK_MONOTONIC`.
pub const FUTEX_CLOCK_REALTIME: i32 = 256;
/// Mask extracting the base `FUTEX_*` command from `op` by stripping modifier flags.
pub const FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
/// Wildcard bitset (`0xffff_ffff`) matching any waiter bitmask in `FUTEX_WAIT` / `FUTEX_WAKE`.
pub const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

/// Negative errno for wait interrupted by a pending signal.
const EINTR: i64 = -4;
/// Negative errno for `*uaddr != val` mismatch during wait or compare-requeue.
const EAGAIN: i64 = -11;
/// Negative errno for invalid or unmapped userland pointer.
const EFAULT: i64 = -14;
/// Negative errno for unaligned `uaddr`, zero bitset, or invalid timespec.
const EINVAL: i64 = -22;
/// Negative errno for unimplemented futex operation (e.g., PI futexes).
const ENOSYS: i64 = -38;
/// Negative errno for wait timeout expiration.
const ETIMEDOUT: i64 = -110;

/// Unique kernel identifier for a futex word: `(address_space_id, address)`.
///
/// # Concurrency & Thread Safety
/// Value type compared under [`GLOBAL_FUTEX`] to match wakers with sleeping threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexKey {
    /// Address-space token (pointer to `Mm`, thread-group ID, or [`PHYSICAL`] for shared pages).
    pub space: u64,
    /// Virtual address (for private futexes) or physical byte address (for shared futexes).
    pub uaddr: u64,
}

/// Represents a single thread blocked in the kernel waiting on a futex word.
///
/// # Lifecycle
/// Pushed onto [`FutexQueue`] before sleeping in [`wait`], and removed either by a waker
/// (`wake_task_ids`) or by the waiter itself upon timeout or signal interruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FutexWaiter {
    /// Target futex key being waited upon.
    pub key: FutexKey,
    /// Scheduler identifier of the sleeping thread.
    pub task_id: TaskId,
    /// 32-bit bitmask used by `FUTEX_WAIT_BITSET` / `FUTEX_WAKE_BITSET`.
    pub bitset: u32,
}

/// Global futex wait queue managing all threads currently blocked on `sys_futex`.
///
/// # Concurrency & Thread Safety
/// Guarded by the [`GLOBAL_FUTEX`] spinlock. To prevent lost wakeups, [`wait`] reads the
/// userland futex word while holding this lock before inserting the [`FutexWaiter`].
pub struct FutexQueue {
    /// Ordered list of active futex waiters (FIFO wake order).
    waiters: Vec<FutexWaiter>,
}

impl FutexQueue {
    /// Creates an empty [`FutexQueue`] at compile time.
    pub const fn new() -> Self {
        Self { waiters: Vec::new() }
    }

    /// Removes up to `max_wake` waiters blocked on `key` whose bitset intersects `bitset`,
    /// returning their `TaskId`s so the caller can wake them in the scheduler.
    ///
    /// # Arguments
    /// * `key` - Target [`FutexKey`] to match.
    /// * `max_wake` - Maximum number of waiting tasks to dequeue.
    /// * `bitset` - Bitmask filter (`(waiter.bitset & bitset) != 0`).
    ///
    /// # Returns
    /// Vector of dequeued `TaskId`s to wake.
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

    /// Moves up to `max` waiters from `from` to `to` without waking them (`FUTEX_REQUEUE`).
    ///
    /// # Returns
    /// Number of waiters whose key was updated to `to`.
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

    /// Returns `true` if `task` is still present in the wait queue (not yet woken).
    fn is_waiting(&self, task: TaskId) -> bool {
        self.waiters.iter().any(|w| w.task_id == task)
    }

    /// Removes all waiter entries belonging to `task` (used on timeout or signal interruption).
    fn remove(&mut self, task: TaskId) {
        self.waiters.retain(|w| w.task_id != task);
    }
}

/// Global spinlock-protected futex queue shared across all Linux processes and threads.
pub static GLOBAL_FUTEX: Mutex<FutexQueue> = Mutex::new(FutexQueue::new());

/// Returns the identity of the calling task's address space (shared by threads of a process
/// and by a `vfork` child).
fn current_space() -> u64 {
    crate::task::with_current_task_mut(|t| t.mm.as_ref().map_or(t.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64)).unwrap_or(0)
}

/// Sentinel `FutexKey::space` value for futexes keyed by physical address in shared mappings.
const PHYSICAL: u64 = u64::MAX;

/// Constructs a private [`FutexKey`] for virtual address `uaddr` in the calling task's address space.
///
/// # Arguments
/// * `uaddr` - User virtual address of the 32-bit futex word.
///
/// # Returns
/// A [`FutexKey`] scoped to the current address space.
pub fn key_of(uaddr: u64) -> FutexKey {
    FutexKey { space: current_space(), uaddr }
}

/// Computes the [`FutexKey`] for a futex operation: shared futexes in shared mappings are
/// keyed by the physical address of the word (faulting the page in first), while private
/// futexes are keyed by virtual address and address space.
fn key_for(uaddr: u64, private: bool) -> FutexKey {
    if !private && crate::memory::vm::prefault_current(uaddr & !3, 4, false) {
        if let Some(phys) = crate::memory::vm::shared_phys_current(uaddr) {
            return FutexKey { space: PHYSICAL, uaddr: phys };
        }
    }
    key_of(uaddr)
}

/// Constructs the [`FutexKey`] of `uaddr` in the address space of `task` (used when the
/// scheduler wakes `clear_child_tid` on thread exit while holding the scheduler lock).
///
/// # Arguments
/// * `task` - Reference to the exiting [`Task`](crate::task::Task).
/// * `uaddr` - User virtual address of the `clear_child_tid` futex word.
///
/// # Returns
/// The [`FutexKey`] corresponding to `uaddr` in `task`'s address space.
pub fn key_for_task(task: &crate::task::Task, uaddr: u64) -> FutexKey {
    FutexKey { space: task.mm.as_ref().map_or(task.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64), uaddr }
}

/// Reads a 4-byte aligned `u32` word from user memory at `uaddr`, prefaulting the page if necessary.
fn read_word(uaddr: u64) -> Result<u32, i64> {
    if uaddr & 3 != 0 || !crate::memory::vm::prefault_current(uaddr, 4, false) {
        return Err(if uaddr & 3 != 0 { EINVAL } else { EFAULT });
    }
    Ok(unsafe { core::ptr::read_volatile(uaddr as *const u32) })
}

/// Wakes each task in `ids` via the global task scheduler.
fn wake_ids(ids: &[TaskId]) {
    if ids.is_empty() {
        return;
    }
    let mut sched = crate::task::SCHEDULER.lock();
    for id in ids {
        sched.wake_task(id.0);
    }
}

/// Computes the PIT deadline tick for a futex wait from a user `struct timespec` pointer.
///
/// Relative timespecs count from the current tick; absolute timespecs are evaluated against
/// `CLOCK_MONOTONIC` or (when `realtime` is `true`) the CMOS wall clock (`CLOCK_REALTIME`).
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

/// Implements `FUTEX_WAIT` and `FUTEX_WAIT_BITSET`: verifies `*uaddr == val` under the queue
/// lock and sleeps until woken by a waker, interrupted by a signal, or `deadline` expires.
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

/// Applies an encoded `FUTEX_WAKE_OP` read-modify-write operation to `*uaddr2` and evaluates
/// whether its comparison against the old value holds.
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

/// Top-level system call dispatcher for `sys_futex` (`SYSCALL 202`).
///
/// # Arguments
/// * `uaddr` - User virtual address of the primary 32-bit futex word (must be 4-byte aligned).
/// * `op` - Futex command (`FUTEX_WAIT`, `FUTEX_WAKE`, etc.) combined with [`FUTEX_PRIVATE_FLAG`]
///   and [`FUTEX_CLOCK_REALTIME`].
/// * `val` - Expected value for `WAIT` or maximum number of waiters to wake for `WAKE`/`REQUEUE`.
/// * `timeout` - Pointer to `struct timespec` for `WAIT*`, or `val2` (requeue/wake limit) for
///   `REQUEUE`/`WAKE_OP`.
/// * `uaddr2` - Secondary futex word address for `REQUEUE` and `WAKE_OP`.
/// * `val3` - Bitmask for `*_BITSET`, expected value for `CMP_REQUEUE`, or encoded op for `WAKE_OP`.
///
/// # Returns
/// * `0` on a successful `FUTEX_WAIT*` wakeup.
/// * Number of woken (and for `CMP_REQUEUE`, requeued) waiters for `WAKE`/`REQUEUE`/`WAKE_OP`.
/// * Negative errno (`-EAGAIN`, `-EINTR`, `-ETIMEDOUT`, `-EINVAL`, `-EFAULT`, `-ENOSYS`) on error.
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
