//! # FreeBSD `_umtx_op` (wave 12, Group FK)
//!
//! libthr's mutexes, condition variables, semaphores, rwlocks and plain waits, done the way
//! FreeBSD's `kern_umtx.c` does them, over a wait queue of the kernel's own (design 4.3: the
//! mutex, condition-variable and rwlock protocols are libthr-defined state words, so the
//! kernel side is waits and wakes plus the compare-and-swaps FreeBSD's kernel makes).
//!
//! - **Keys:** `(address space, address, kind)`, as FreeBSD's `umtx_key` (one queue per
//!   object kind on an address). Process-shared objects (`USYNC_PROCESS_SHARED`, the
//!   non-private waits) in shared memory are keyed by the word's physical address, as the
//!   Linux futex code does.
//! - **The "busy" monitor of FreeBSD's queues is the kernel lock:** every FreeBSD system call
//!   runs under it (`personality::syscall`), and a sleeping thread lets go of it, which is
//!   exactly when FreeBSD unbusies a key.
//! - **Sleeping:** a thread is queued, checks the user word, and sleeps until a waker takes
//!   it off the queue (then 0), its deadline passes (`ETIMEDOUT`) or a signal arrives
//!   (`EINTR`; libthr loops on it).
//! - **Not built:** priority inheritance and protection (`UMUTEX_PRIO_INHERIT`,
//!   `UMUTEX_PRIO_PROTECT` mutexes are handled as normal ones: libthr sends them to the kernel
//!   for every lock and unlock, so the word stays consistent), the robust list walk at a
//!   thread's death (`ROBUST_LISTS` is accepted), `UMTX_OP_SHM` (process-shared pthread
//!   objects: `ENOSYS`), the deprecated `SEM_WAIT`/`SEM_WAKE` and the FreeBSD 10 `LOCK`/`UNLOCK`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::fbsd_xlat::umtx::*;
use crate::task::TaskId;

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EAGAIN: i64 = -11;
const EBUSY: i64 = -16;
const EPERM: i64 = -1;
const ENOSYS: i64 = -38;
const EINTR: i64 = -4;
const ETIMEDOUT: i64 = -110;
const EOWNERDEAD: i64 = -130;
const ENOTRECOVERABLE: i64 = -131;

/// Object kinds: one queue each on the same address (FreeBSD's `TYPE_*`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// `UMTX_OP_WAIT*`/`WAKE*`, and `thr_exit`'s wake.
    Simple,
    /// Mutexes (`TYPE_NORMAL_UMUTEX`; PI and PP ones too, see the module page).
    Mutex,
    /// Condition variables.
    Cv,
    /// Rwlock readers (`UMTX_SHARED_QUEUE`).
    RwRead,
    /// Rwlock writers (`UMTX_EXCLUSIVE_QUEUE`).
    RwWrite,
    /// Semaphores.
    Sem,
    /// `thr_suspend`'s sleep (the address is the thread id).
    Suspend,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Key {
    space: u64,
    addr: u64,
    kind: Kind,
}

#[derive(Clone, Copy)]
struct Waiter {
    key: Key,
    task: TaskId,
}

/// The waiters of every key (FIFO per key).
static QUEUE: Mutex<Vec<Waiter>> = Mutex::new(Vec::new());
/// `thr_wake` calls that came before the thread's `thr_suspend` (thread ids).
static WAKE_PENDING: Mutex<Vec<u64>> = Mutex::new(Vec::new());

/// The address space of the calling thread (shared by its process's threads).
fn current_space() -> u64 {
    crate::task::with_current_task_mut(|t| t.mm.as_ref().map_or(t.tgid, |m| alloc::sync::Arc::as_ptr(m) as u64)).unwrap_or(0)
}

/// The key of word `addr` of kind `kind`: by physical address for a shared object in a
/// shared mapping (`shared`), else private to this address space.
fn key(addr: u64, kind: Kind, shared: bool) -> Key {
    if shared && crate::memory::vm::prefault_current(addr & !3, 4, false) {
        if let Some(phys) = crate::memory::vm::shared_phys_current(addr) {
            return Key { space: u64::MAX, addr: phys, kind };
        }
    }
    Key { space: current_space(), addr, kind }
}

fn me() -> TaskId {
    crate::task::SCHEDULER.lock().current_task_id()
}

fn insert(k: Key) {
    let task = me();
    QUEUE.lock().push(Waiter { key: k, task });
}

/// Takes the caller off `k`'s queue; `true` if it was still there (nobody woke it).
fn remove(k: Key) -> bool {
    let task = me();
    let mut q = QUEUE.lock();
    match q.iter().position(|w| w.key == k && w.task == task) {
        Some(i) => {
            q.remove(i);
            true
        }
        None => false,
    }
}

fn count(k: Key) -> usize {
    QUEUE.lock().iter().filter(|w| w.key == k).count()
}

/// Wakes up to `n` waiters of `k` (oldest first); answers how many.
fn signal(k: Key, n: usize) -> usize {
    let mut ids = Vec::new();
    {
        let mut q = QUEUE.lock();
        let mut i = 0;
        while i < q.len() && ids.len() < n {
            if q[i].key == k {
                ids.push(q.remove(i).task);
            } else {
                i += 1;
            }
        }
    }
    if !ids.is_empty() {
        let mut s = crate::task::SCHEDULER.lock();
        for id in &ids {
            s.wake_task(id.0);
        }
    }
    ids.len()
}

/// Sleeps while queued on `k`: 0 when a waker took the caller off the queue, `ETIMEDOUT`
/// past `deadline` (boot-clock nanoseconds), `EINTR` for a signal. The caller is off the
/// queue in every case.
fn sleep(k: Key, deadline: Option<u64>) -> i64 {
    let task = me();
    loop {
        if !QUEUE.lock().iter().any(|w| w.key == k && w.task == task) {
            return 0;
        }
        let end = if deadline.is_some_and(|d| crate::arch::pit::now_ns() >= d) {
            Some(ETIMEDOUT)
        } else if crate::compat::linux::proc::signal_pending() {
            Some(EINTR)
        } else {
            None
        };
        if let Some(e) = end {
            return if remove(k) { e } else { 0 };
        }
        crate::task::wait::wait_ns(deadline);
    }
}

// --- user words ----------------------------------------------------------

fn load32(addr: u64) -> Result<u32, i64> {
    if addr & 3 != 0 {
        return Err(EINVAL);
    }
    if !crate::memory::vm::prefault_current(addr, 4, false) {
        return Err(EFAULT);
    }
    // SAFETY: a user word of the current address space, faulted in
    Ok(unsafe { (*(addr as *const AtomicU32)).load(Ordering::SeqCst) })
}

fn load64(addr: u64) -> Result<u64, i64> {
    if addr & 7 != 0 {
        return Err(EINVAL);
    }
    if !crate::memory::vm::prefault_current(addr, 8, false) {
        return Err(EFAULT);
    }
    // SAFETY: as in `load32`
    Ok(unsafe { (*(addr as *const AtomicU64)).load(Ordering::SeqCst) })
}

fn store32(addr: u64, v: u32) -> Result<(), i64> {
    if addr & 3 != 0 {
        return Err(EINVAL);
    }
    if !crate::memory::vm::prefault_current(addr, 4, true) {
        return Err(EFAULT);
    }
    // SAFETY: as in `load32`, writable
    unsafe { (*(addr as *const AtomicU32)).store(v, Ordering::SeqCst) };
    Ok(())
}

/// Compare-and-swap on a user word: `Ok(Ok(()))` swapped, `Ok(Err(found))` not.
fn cas32(addr: u64, old: u32, new: u32) -> Result<Result<(), u32>, i64> {
    if addr & 3 != 0 {
        return Err(EINVAL);
    }
    if !crate::memory::vm::prefault_current(addr, 4, true) {
        return Err(EFAULT);
    }
    // SAFETY: as in `store32`
    let w = unsafe { &*(addr as *const AtomicU32) };
    Ok(w.compare_exchange(old, new, Ordering::SeqCst, Ordering::SeqCst).map(|_| ()))
}

// --- timeouts ------------------------------------------------------------

/// The deadline (boot-clock nanoseconds) of the timeout at `ptr` with size argument
/// `size` (`umtx_copyin_umtx_time`), `None` without one.
fn deadline(ptr: u64, size: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let b = crate::compat::linux::vfs::copy_in(ptr, timeout_len(size)).map_err(|_| EFAULT)?;
    let t = parse_timeout(&b).map_err(|_| EINVAL)?;
    Ok(Some(abs_ns(t.sec, t.nsec, t.abs, clock_is_realtime(t.clock))))
}

/// A FreeBSD time as a boot-clock deadline: relative, or absolute on the wall clock or on
/// the monotonic clocks (which count from boot here).
pub fn abs_ns(sec: i64, nsec: i64, abs: bool, realtime: bool) -> u64 {
    let total = sec as i128 * 1_000_000_000 + nsec as i128;
    let now = crate::arch::pit::now_ns() as i128;
    let t = if !abs {
        now + total
    } else if realtime {
        let (rs, rns) = crate::arch::rtc::now();
        total - (rs as i128 * 1_000_000_000 + rns as i128 - now)
    } else {
        total
    };
    t.clamp(0, u64::MAX as i128) as u64
}

// --- the operations ------------------------------------------------------

/// `_umtx_op(obj, op, val, uaddr1, uaddr2)`, in the internal (Linux) errno convention.
pub fn op(obj: u64, op: u64, val: u64, uaddr1: u64, uaddr2: u64) -> i64 {
    let r = match op {
        OP_WAIT => wait(obj, val, uaddr1, uaddr2, false, false),
        OP_WAIT_UINT => wait(obj, val, uaddr1, uaddr2, true, false),
        OP_WAIT_UINT_PRIVATE => wait(obj, val, uaddr1, uaddr2, true, true),
        OP_WAKE => Ok(wake(obj, val, false)),
        OP_WAKE_PRIVATE => Ok(wake(obj, val, true)),
        OP_NWAKE_PRIVATE => nwake(obj, val),
        OP_MUTEX_TRYLOCK => mutex_lock(obj, None, Mode::Try),
        OP_MUTEX_LOCK => deadline(uaddr2, uaddr1).and_then(|d| mutex_lock(obj, d, Mode::Lock)),
        OP_MUTEX_WAIT => deadline(uaddr2, uaddr1).and_then(|d| mutex_lock(obj, d, Mode::Wait)),
        OP_MUTEX_UNLOCK => mutex_unlock(obj),
        OP_MUTEX_WAKE => mutex_wake(obj),
        OP_MUTEX_WAKE2 => mutex_wake2(obj, val as u32),
        OP_CV_WAIT => cv_wait(obj, uaddr1, uaddr2, val),
        OP_CV_SIGNAL => cv_signal(obj),
        OP_CV_BROADCAST => cv_broadcast(obj),
        OP_RW_RDLOCK => deadline(uaddr2, uaddr1).and_then(|d| rw_rdlock(obj, val, d)),
        OP_RW_WRLOCK => deadline(uaddr2, uaddr1).and_then(|d| rw_wrlock(obj, d)),
        OP_RW_UNLOCK => rw_unlock(obj),
        OP_SEM2_WAIT => deadline(uaddr2, uaddr1).and_then(|d| sem2_wait(obj, d)),
        OP_SEM2_WAKE => sem2_wake(obj),
        OP_ROBUST_LISTS => Ok(0),
        OP_SET_MIN_TIMEOUT => Ok(0),
        OP_GET_MIN_TIMEOUT => crate::compat::linux::vfs::copy_out(uaddr1, &0i32.to_le_bytes()).map(|_| 0),
        OP_SET_CEILING => Err(EINVAL),
        _ => Err(ENOSYS),
    };
    match r {
        Ok(v) => v,
        Err(e) => e,
    }
}

/// `UMTX_OP_WAIT(_UINT)(_PRIVATE)`: sleeps while the word (8 bytes, or 4 with `uint`)
/// holds `val`.
fn wait(obj: u64, val: u64, size: u64, tm: u64, uint: bool, private: bool) -> Result<i64, i64> {
    let d = deadline(tm, size)?;
    let k = key(obj, Kind::Simple, !private);
    insert(k);
    let cur = if uint { load32(obj).map(|v| v as u64) } else { load64(obj) };
    match cur {
        Ok(v) if v == if uint { val & 0xffff_ffff } else { val } => Ok(sleep(k, d)),
        Ok(_) => {
            remove(k);
            Ok(0)
        }
        Err(e) => {
            remove(k);
            Err(e)
        }
    }
}

/// `UMTX_OP_WAKE(_PRIVATE)`: wakes up to `n` waiters of the word (also `thr_exit`).
pub fn wake(obj: u64, n: u64, private: bool) -> i64 {
    signal(key(obj, Kind::Simple, !private), n.min(i32::MAX as u64) as usize);
    0
}

/// `UMTX_OP_NWAKE_PRIVATE`: wakes every waiter of each of the `n` words in the array at
/// `obj` (libthr's deferred wakes).
fn nwake(obj: u64, n: u64) -> Result<i64, i64> {
    let n = n.min(4096) as usize;
    let b = crate::compat::linux::vfs::copy_in(obj, n * 8).map_err(|_| EFAULT)?;
    for i in 0..n {
        let a = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        signal(key(a, Kind::Simple, false), usize::MAX);
    }
    Ok(0)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lock,
    Try,
    Wait,
}

/// The caller's FreeBSD thread id (the owner value libthr writes into its mutexes: the
/// Linux layer's thread id, which `thr_self`/`thr_new` hand out).
fn my_tid() -> u32 {
    crate::compat::linux::proc::current_ids().0 as u32
}

fn shared(flags: u32) -> bool {
    flags & USYNC_PROCESS_SHARED != 0
}

/// `do_lock_normal`: `MUTEX_LOCK`, `MUTEX_TRYLOCK`, `MUTEX_WAIT` (the last only waits for
/// the lock to be free, libthr takes it itself).
fn mutex_lock(m: u64, d: Option<u64>, mode: Mode) -> Result<i64, i64> {
    let id = my_tid();
    let flags = load32(m + M_FLAGS)?;
    let mut error = 0;
    loop {
        let owner = load32(m + M_OWNER)?;
        if mode == Mode::Wait {
            if mutex_wait_done(owner) {
                return Ok(0);
            }
        } else {
            if owner == UMUTEX_RB_OWNERDEAD {
                match cas32(m + M_OWNER, UMUTEX_RB_OWNERDEAD, id | UMUTEX_CONTESTED)? {
                    Ok(()) => return Err(EOWNERDEAD),
                    Err(_) => continue,
                }
            }
            if owner == UMUTEX_RB_NOTRECOV {
                return Err(ENOTRECOVERABLE);
            }
            match cas32(m + M_OWNER, UMUTEX_UNOWNED, id)? {
                Ok(()) => return Ok(0),
                Err(found) => {
                    if found == UMUTEX_CONTESTED {
                        match cas32(m + M_OWNER, UMUTEX_CONTESTED, id | UMUTEX_CONTESTED)? {
                            Ok(()) => return Ok(0),
                            Err(_) => continue,
                        }
                    }
                }
            }
            if (owner & !UMUTEX_CONTESTED) == id {
                // (FreeBSD would sleep forever on its own lock; libthr checks first)
                return Err(-35); // EDEADLK
            }
        }
        if mode == Mode::Try {
            return Err(EBUSY);
        }
        // A signal or timeout seen in the last sleep: out after this retry
        if error != 0 {
            return Err(error);
        }
        let k = key(m, Kind::Mutex, shared(flags));
        insert(k);
        // The contested bit, so the owner's unlock comes to the kernel; if the word moved,
        // try again
        let owner = match load32(m + M_OWNER) {
            Ok(o) => o,
            Err(e) => {
                remove(k);
                return Err(e);
            }
        };
        if mode == Mode::Wait && mutex_wait_done(owner) {
            remove(k);
            return Ok(0);
        }
        if mode != Mode::Wait && (owner & !UMUTEX_CONTESTED) == 0 {
            remove(k);
            continue;
        }
        match cas32(m + M_OWNER, owner, owner | UMUTEX_CONTESTED) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                remove(k);
                continue;
            }
            Err(e) => {
                remove(k);
                return Err(e);
            }
        }
        error = sleep(k, d);
        if error == 0 && mode == Mode::Wait {
            return Ok(0);
        }
    }
}

/// `do_unlock_normal`: releases the caller's mutex and wakes one waiter.
fn mutex_unlock(m: u64) -> Result<i64, i64> {
    let id = my_tid();
    loop {
        let owner = load32(m + M_OWNER)?;
        let flags = load32(m + M_FLAGS)?;
        if (owner & !UMUTEX_CONTESTED) != id {
            return Err(EPERM);
        }
        if owner & UMUTEX_CONTESTED == 0 {
            match cas32(m + M_OWNER, owner, unlock_value(flags, 0))? {
                Ok(()) => return Ok(0),
                Err(_) => continue,
            }
        }
        let k = key(m, Kind::Mutex, shared(flags));
        let n = count(k);
        let r = cas32(m + M_OWNER, owner, unlock_value(flags, n))?;
        signal(k, 1);
        match r {
            Ok(()) => return Ok(0),
            Err(old) if old != owner => return Err(EINVAL),
            Err(_) => continue,
        }
    }
}

/// `do_wake_umutex` (deprecated `MUTEX_WAKE`): if the mutex is free, clears the contested
/// bit when at most one waits, and wakes one.
fn mutex_wake(m: u64) -> Result<i64, i64> {
    loop {
        let owner = load32(m + M_OWNER)?;
        if (owner & !UMUTEX_CONTESTED) != 0 && owner != UMUTEX_RB_OWNERDEAD && owner != UMUTEX_RB_NOTRECOV {
            return Ok(0);
        }
        let flags = load32(m + M_FLAGS)?;
        let k = key(m, Kind::Mutex, shared(flags));
        let n = count(k);
        if n <= 1 && owner != UMUTEX_RB_OWNERDEAD && owner != UMUTEX_RB_NOTRECOV {
            if cas32(m + M_OWNER, UMUTEX_CONTESTED, UMUTEX_UNOWNED)?.is_err() {
                continue;
            }
        }
        if n != 0 {
            signal(k, 1);
        }
        return Ok(0);
    }
}

/// `do_wake2_umutex` (`MUTEX_WAKE2`, libthr's unlock of a contested mutex): sets the
/// contested bit again when others still wait, and wakes one if the mutex is free.
fn mutex_wake2(m: u64, flags: u32) -> Result<i64, i64> {
    let k = key(m, Kind::Mutex, shared(flags));
    let n = count(k);
    let mut owner = match load32(m + M_OWNER) {
        Ok(o) => o,
        Err(e) => {
            signal(k, usize::MAX);
            return Err(e);
        }
    };
    while owner & UMUTEX_CONTESTED == 0 && (n > 1 || (n == 1 && (owner & !UMUTEX_CONTESTED) != 0)) {
        match cas32(m + M_OWNER, owner, owner | UMUTEX_CONTESTED) {
            Ok(Ok(())) => break,
            Ok(Err(old)) => owner = old,
            Err(e) => {
                signal(k, usize::MAX);
                return Err(e);
            }
        }
    }
    if n != 0 && ((owner & !UMUTEX_CONTESTED) == 0 || owner == UMUTEX_RB_OWNERDEAD || owner == UMUTEX_RB_NOTRECOV) {
        signal(k, 1);
    }
    Ok(0)
}

/// `do_cv_wait`: queues on the condition variable, marks it as having waiters, unlocks the
/// mutex and sleeps (the timeout is a `struct timespec`, absolute with `CVWAIT_ABSTIME`,
/// on the variable's clock with `CVWAIT_CLOCKID`).
fn cv_wait(cv: u64, m: u64, tm: u64, wflags: u64) -> Result<i64, i64> {
    let flags = load32(cv + C_FLAGS)?;
    let clock = if wflags & CVWAIT_CLOCKID != 0 { load32(cv + C_CLOCKID)? } else { 0 };
    let k = key(cv, Kind::Cv, shared(flags));
    insert(k);
    let hw = load32(cv + C_HAS_WAITERS);
    let set = match hw {
        Ok(0) => store32(cv + C_HAS_WAITERS, 1),
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    };
    if set.is_err() {
        remove(k);
        return Err(EFAULT);
    }
    let d = if tm != 0 {
        match crate::compat::linux::vfs::copy_in(tm, 16) {
            Ok(b) => match parse_timeout(&b) {
                Ok(t) => Some(abs_ns(t.sec, t.nsec, wflags & CVWAIT_ABSTIME != 0, clock_is_realtime(clock))),
                Err(()) => {
                    remove(k);
                    return Err(EINVAL);
                }
            },
            Err(_) => {
                remove(k);
                return Err(EFAULT);
            }
        }
    } else {
        None
    };
    if let Err(e) = mutex_unlock(m) {
        // (FreeBSD reports the unlock's error after taking the waiter off the queue)
        if remove(k) && count(k) == 0 {
            let _ = store32(cv + C_HAS_WAITERS, 0);
        }
        return Err(e);
    }
    let r = sleep(k, d);
    if r != 0 && count(k) == 0 {
        // Timed out or interrupted as the last waiter: no waiters any more
        let _ = store32(cv + C_HAS_WAITERS, 0);
    }
    if r != 0 {
        Err(r)
    } else {
        Ok(0)
    }
}

/// `do_cv_signal`.
fn cv_signal(cv: u64) -> Result<i64, i64> {
    let flags = load32(cv + C_FLAGS)?;
    let k = key(cv, Kind::Cv, shared(flags));
    let n = count(k);
    let woke = signal(k, 1);
    if n <= woke {
        store32(cv + C_HAS_WAITERS, 0)?;
    }
    Ok(0)
}

/// `do_cv_broadcast`.
fn cv_broadcast(cv: u64) -> Result<i64, i64> {
    let flags = load32(cv + C_FLAGS)?;
    signal(key(cv, Kind::Cv, shared(flags)), usize::MAX);
    store32(cv + C_HAS_WAITERS, 0)?;
    Ok(0)
}

/// Adds `d` to a rwlock's blocked-readers or blocked-writers count (`off`); answers the old
/// count.
fn bump(rw: u64, off: u64, d: i32) -> Result<u32, i64> {
    let v = load32(rw + off)?;
    store32(rw + off, (v as i32 + d) as u32)?;
    Ok(v)
}

/// Clears `bit` in the rwlock state.
fn clear_state_bit(rw: u64, bit: u32) -> Result<(), i64> {
    let mut s = load32(rw + RW_STATE)?;
    loop {
        match cas32(rw + RW_STATE, s, s & !bit)? {
            Ok(()) => return Ok(()),
            Err(o) => s = o,
        }
    }
}

/// `do_rw_rdlock`.
fn rw_rdlock(rw: u64, fflag: u64, d: Option<u64>) -> Result<i64, i64> {
    let flags = load32(rw + RW_FLAGS)?;
    let wrflags = rd_block_mask(fflag, flags);
    let k = key(rw, Kind::RwRead, shared(flags));
    loop {
        let mut state = load32(rw + RW_STATE)?;
        while state & wrflags == 0 {
            if readers(state) == URWLOCK_MAX_READERS {
                return Err(EAGAIN);
            }
            match cas32(rw + RW_STATE, state, state + 1)? {
                Ok(()) => return Ok(0),
                Err(o) => state = o,
            }
        }
        // The read-contention bit, then sleep while a writer keeps us out
        state = load32(rw + RW_STATE)?;
        let mut go_sleep = false;
        while state & wrflags != 0 {
            if state & URWLOCK_READ_WAITERS != 0 {
                go_sleep = true;
                break;
            }
            match cas32(rw + RW_STATE, state, state | URWLOCK_READ_WAITERS)? {
                Ok(()) => {
                    go_sleep = true;
                    break;
                }
                Err(o) => state = o,
            }
        }
        if !go_sleep {
            continue;
        }
        bump(rw, RW_BLOCKED_READERS, 1)?;
        let mut error = 0;
        while state & wrflags != 0 {
            insert(k);
            error = sleep(k, d);
            if error != 0 {
                break;
            }
            state = load32(rw + RW_STATE)?;
        }
        let was = bump(rw, RW_BLOCKED_READERS, -1)?;
        if was == 1 {
            clear_state_bit(rw, URWLOCK_READ_WAITERS)?;
        }
        if error != 0 {
            return Err(error);
        }
    }
}

/// `do_rw_wrlock`.
fn rw_wrlock(rw: u64, d: Option<u64>) -> Result<i64, i64> {
    let flags = load32(rw + RW_FLAGS)?;
    let kw = key(rw, Kind::RwWrite, shared(flags));
    let kr = key(rw, Kind::RwRead, shared(flags));
    let mut blocked_readers;
    loop {
        let mut state = load32(rw + RW_STATE)?;
        while state & URWLOCK_WRITE_OWNER == 0 && readers(state) == 0 {
            match cas32(rw + RW_STATE, state, state | URWLOCK_WRITE_OWNER)? {
                Ok(()) => return Ok(0),
                Err(o) => state = o,
            }
        }
        state = load32(rw + RW_STATE)?;
        let held = |s: u32| s & URWLOCK_WRITE_OWNER != 0 || readers(s) != 0;
        let mut go_sleep = false;
        while held(state) {
            if state & URWLOCK_WRITE_WAITERS != 0 {
                go_sleep = true;
                break;
            }
            match cas32(rw + RW_STATE, state, state | URWLOCK_WRITE_WAITERS)? {
                Ok(()) => {
                    go_sleep = true;
                    break;
                }
                Err(o) => state = o,
            }
        }
        if !go_sleep {
            continue;
        }
        bump(rw, RW_BLOCKED_WRITERS, 1)?;
        let mut error = 0;
        while held(state) {
            insert(kw);
            error = sleep(kw, d);
            if error != 0 {
                break;
            }
            state = load32(rw + RW_STATE)?;
        }
        let was = bump(rw, RW_BLOCKED_WRITERS, -1)?;
        if was == 1 {
            clear_state_bit(rw, URWLOCK_WRITE_WAITERS)?;
            blocked_readers = load32(rw + RW_BLOCKED_READERS)?;
        } else {
            blocked_readers = 0;
        }
        if error != 0 {
            // The last writer gave up: readers blocked behind it may go
            let s = load32(rw + RW_STATE).unwrap_or(0);
            if s & (URWLOCK_WRITE_OWNER | URWLOCK_WRITE_WAITERS) == 0 && blocked_readers != 0 {
                signal(kr, usize::MAX);
            }
            return Err(error);
        }
    }
}

/// `do_rw_unlock`.
fn rw_unlock(rw: u64) -> Result<i64, i64> {
    let flags = load32(rw + RW_FLAGS)?;
    let mut state = load32(rw + RW_STATE)?;
    loop {
        let new = rw_unlocked(state).map_err(|_| EPERM)?;
        match cas32(rw + RW_STATE, state, new)? {
            Ok(()) => break,
            Err(o) => state = o,
        }
    }
    if let Some((writers, n)) = rw_unlock_wakes(state, flags) {
        let kind = if writers { Kind::RwWrite } else { Kind::RwRead };
        signal(key(rw, kind, shared(flags)), n);
    }
    Ok(0)
}

/// `do_sem2_wait`.
fn sem2_wait(sem: u64, d: Option<u64>) -> Result<i64, i64> {
    let flags = load32(sem + SEM_FLAGS)?;
    let k = key(sem, Kind::Sem, shared(flags));
    loop {
        insert(k);
        let count = match load32(sem + SEM_COUNT) {
            Ok(c) => c,
            Err(e) => {
                remove(k);
                return Err(e);
            }
        };
        if count & USEM_MAX_COUNT != 0 {
            remove(k);
            return Ok(0);
        }
        if count != USEM_HAS_WAITERS {
            match cas32(sem + SEM_COUNT, 0, USEM_HAS_WAITERS) {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    remove(k);
                    continue;
                }
                Err(e) => {
                    remove(k);
                    return Err(e);
                }
            }
        }
        let r = sleep(k, d);
        return if r != 0 { Err(r) } else { Ok(0) };
    }
}

/// `do_sem2_wake`.
fn sem2_wake(sem: u64) -> Result<i64, i64> {
    let flags = load32(sem + SEM_FLAGS)?;
    let k = key(sem, Kind::Sem, shared(flags));
    let n = count(k);
    if n > 0 {
        if n == 1 {
            // The last sleeper: the waiters bit goes
            let mut c = load32(sem + SEM_COUNT)?;
            while c & USEM_HAS_WAITERS != 0 {
                match cas32(sem + SEM_COUNT, c, c & !USEM_HAS_WAITERS)? {
                    Ok(()) => break,
                    Err(o) => c = o,
                }
            }
        }
        signal(k, 1);
    }
    Ok(0)
}

// --- thr_suspend / thr_wake ----------------------------------------------

/// `thr_suspend(timeout)`: sleeps until `thr_wake` names the caller (at once if it did
/// already), the relative timeout passes (`ETIMEDOUT`) or a signal arrives (`EINTR`).
pub fn thr_suspend(tm: u64) -> i64 {
    let tid = crate::compat::linux::proc::current_ids().0;
    let d = if tm != 0 {
        match crate::compat::linux::vfs::copy_in(tm, 16).map_err(|_| EFAULT).and_then(|b| parse_timeout(&b).map_err(|_| EINVAL)) {
            Ok(t) => Some(abs_ns(t.sec, t.nsec, false, false)),
            Err(e) => return e,
        }
    } else {
        None
    };
    let k = Key { space: current_space(), addr: tid, kind: Kind::Suspend };
    {
        let mut p = WAKE_PENDING.lock();
        if let Some(i) = p.iter().position(|&t| t == tid) {
            p.remove(i);
            return 0;
        }
        insert(k);
    }
    sleep(k, d)
}

/// `thr_wake(id)`: wakes thread `id` of the caller's process from `thr_suspend`, or makes
/// its next one return at once.
pub fn thr_wake(id: u64) -> i64 {
    let (_, pid) = crate::compat::linux::proc::current_ids();
    if crate::compat::linux::proc::tgid_of(id) != Some(pid) {
        return -3; // ESRCH
    }
    let k = Key { space: current_space(), addr: id, kind: Kind::Suspend };
    let mut p = WAKE_PENDING.lock();
    if signal(k, 1) == 0 && !p.contains(&id) {
        p.push(id);
    }
    0
}

/// A thread is gone: its pending `thr_wake` too.
pub fn thread_gone(tid: u64) {
    WAKE_PENDING.lock().retain(|&t| t != tid);
}
