//! Host stand-ins for the kernel services Group 27's files call.
//!
//! Each fake keeps its state in thread-locals. The test harness runs every `#[test]` on its
//! own thread, so tests configure the fakes freely and still run in parallel. Call [`reset`]
//! at the start of a test that relies on a clean slate. (A few kernel tables are global
//! statics in the code under test, such as the interval timers by process: tests give each
//! process its own ID with [`IDS`].)
//!
//! Blocking: code under test that would sleep calls [`wait::WaitSet::wait`] (or the free
//! `wait`/`wait_ns`). On the host a sleep with a deadline moves the fake clock to it; a test
//! can install [`WAIT_HOOK`] to change the world while "asleep" (data arrives, a signal is
//! posted); a sleep with neither panics with [`wait::WOULD_BLOCK`], which tests catch.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

thread_local! {
    /// The boot clock, in nanoseconds.
    pub static NOW_NS: Cell<u64> = const { Cell::new(10_000_000_000) };
    /// Effective capability bits of the current task (`None`: no task).
    pub static CAPS: Cell<Option<u64>> = const { Cell::new(Some(0)) };
    /// Effective user ID of the current task.
    pub static EUID: Cell<u32> = const { Cell::new(0) };
    /// (euid, egid) as `vfs::creds` reports them.
    pub static CREDS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
    /// (tid, tgid) of the current task.
    pub static IDS: Cell<(u64, u64)> = const { Cell::new((1, 1)) };
    /// What `signal_pending()` reports.
    pub static SIGNAL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// User memory that faults: `[start, end)` ranges.
    pub static BAD_PTRS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    /// Number of `WaitQueue::wake_all` calls (all queues).
    pub static WAKES: Cell<usize> = const { Cell::new(0) };
    /// Sleeps taken by the code under test.
    pub static WAITS: Cell<usize> = const { Cell::new(0) };
    /// The deadline (ns) of the last sleep (`None`: none).
    pub static LAST_DEADLINE: Cell<Option<u64>> = const { Cell::new(None) };
    /// Called at each sleep, with the sleep's number (1, 2, ...): changes the world while the
    /// code under test "sleeps". Without one, a sleep with no deadline panics.
    pub static WAIT_HOOK: RefCell<Option<Box<dyn FnMut(usize)>>> = RefCell::new(None);
    /// Most sleeps one test allows (a guard against loops that never end).
    pub static WAIT_LIMIT: Cell<usize> = const { Cell::new(10_000) };
    /// Whether the caller sits in a network namespace of its own.
    pub static NET_ISOLATED: Cell<bool> = const { Cell::new(false) };
    /// Landlock port rules that refuse: (port, access).
    pub static LANDLOCK_DENY: RefCell<Vec<(u16, u64)>> = const { RefCell::new(Vec::new()) };
    /// `tty::pump` calls.
    pub static TTY_PUMPS: Cell<usize> = const { Cell::new(0) };
    /// Calls forwarded to linux-server: (nr, args, inode).
    pub static LX_CALLS: RefCell<Vec<(u64, [u64; 6], Option<u64>)>> = const { RefCell::new(Vec::new()) };
    /// What forwarded calls return.
    pub static LX_RESULT: Cell<i64> = const { Cell::new(0) };
    /// Deferred eventfd writes to linux-server objects.
    pub static LX_WRITES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    /// Nested system calls (io_uring): the handler, and the calls made.
    pub static NESTED: RefCell<Option<Box<dyn FnMut(u64, [u64; 6]) -> i64>>> = RefCell::new(None);
    pub static NESTED_CALLS: RefCell<Vec<(u64, [u64; 6])>> = const { RefCell::new(Vec::new()) };
    /// Frames still allowed to be allocated (`None`: no limit).
    pub static FRAME_BUDGET: Cell<Option<usize>> = const { Cell::new(None) };
    /// Frames allocated and not yet freed, by this thread.
    pub static FRAMES_LIVE: Cell<i64> = const { Cell::new(0) };
}

/// Restores every fake to its initial state.
pub fn reset() {
    NOW_NS.set(10_000_000_000);
    CAPS.set(Some(0));
    EUID.set(0);
    CREDS.set((0, 0));
    IDS.set((1, 1));
    SIGNAL_PENDING.set(false);
    BAD_PTRS.with_borrow_mut(|v| v.clear());
    WAKES.set(0);
    WAITS.set(0);
    LAST_DEADLINE.set(None);
    WAIT_HOOK.with_borrow_mut(|h| *h = None);
    WAIT_LIMIT.set(10_000);
    NET_ISOLATED.set(false);
    LANDLOCK_DENY.with_borrow_mut(|v| v.clear());
    TTY_PUMPS.set(0);
    LX_CALLS.with_borrow_mut(|v| v.clear());
    LX_RESULT.set(0);
    LX_WRITES.with_borrow_mut(|v| v.clear());
    NESTED.with_borrow_mut(|h| *h = None);
    NESTED_CALLS.with_borrow_mut(|v| v.clear());
    FRAME_BUDGET.set(None);
    fd::FDS.with_borrow_mut(|f| *f = fd::Fds::default());
    net::NET.with_borrow_mut(|n| *n = net::NetState::default());
    proc::reset();
    task::reset();
}

/// Installs a sleep hook (see [`WAIT_HOOK`]).
pub fn on_wait(f: impl FnMut(usize) + 'static) {
    WAIT_HOOK.with_borrow_mut(|h| *h = Some(Box::new(f)));
}

/// Makes `[ptr, ptr + len)` fault.
pub fn bad_ptr(ptr: u64, len: u64) {
    BAD_PTRS.with_borrow_mut(|v| v.push((ptr, ptr + len)));
}

// ------------------------------------------------------------------ clock

pub const TICK_NS: u64 = 10_000_000;

pub fn frequency_hz() -> u64 {
    100
}
pub fn tick_ns() -> u64 {
    TICK_NS
}
pub fn now_ns() -> u64 {
    NOW_NS.get()
}
pub fn ticks() -> u64 {
    NOW_NS.get() / TICK_NS
}
/// Moves the clock forward by `ns`.
pub fn advance_ns(ns: u64) {
    NOW_NS.set(NOW_NS.get() + ns);
}
/// Moves the clock forward by `t` ticks.
pub fn advance_ticks(t: u64) {
    advance_ns(t * TICK_NS);
}
/// Wall-clock seconds at boot (2026-01-01T00:00:00Z).
pub const WALL_BASE_S: u64 = 1_767_225_600;
/// The wall clock: the boot instant plus the boot clock.
pub fn rtc_now() -> (u64, u32) {
    let ns = NOW_NS.get();
    (WALL_BASE_S + ns / 1_000_000_000, (ns % 1_000_000_000) as u32)
}

// ------------------------------------------------------------------ memory

/// `vm::prefault_current`: user pointers are host pointers; null and [`BAD_PTRS`] fault.
pub fn prefault_current(ptr: u64, len: u64, _write: bool) -> bool {
    if ptr == 0 {
        return false;
    }
    let end = ptr.saturating_add(len.max(1));
    !BAD_PTRS.with_borrow(|v| v.iter().any(|&(s, e)| ptr < e && s < end))
}

const FRAME_LAYOUT: std::alloc::Layout = match std::alloc::Layout::from_size_align(4096, 4096) {
    Ok(l) => l,
    Err(_) => panic!(),
};

/// A zeroed host page as a "physical" frame.
pub fn alloc_user_frame() -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>> {
    if let Some(b) = FRAME_BUDGET.get() {
        if b == 0 {
            return None;
        }
        FRAME_BUDGET.set(Some(b - 1));
    }
    let p = unsafe { std::alloc::alloc_zeroed(FRAME_LAYOUT) };
    assert!(!p.is_null());
    let _ = FRAMES_LIVE.try_with(|c| c.set(c.get() + 1));
    Some(x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(p as u64)))
}

/// Frees the host page behind `f` (frames here have one reference).
pub fn frame_ref_dec(f: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>) {
    let _ = FRAMES_LIVE.try_with(|c| c.set(c.get() - 1));
    unsafe { std::alloc::dealloc(f.start_address().as_u64() as *mut u8, FRAME_LAYOUT) };
}

/// Frames are host pages: identity.
pub fn phys_to_virt(addr: u64) -> *mut u8 {
    addr as *mut u8
}

// ------------------------------------------------------------------ nested calls

/// A nested system call (io_uring): recorded, then answered by [`NESTED`] (`-ENOSYS` without
/// a handler).
pub fn nested(num: u64, args: [u64; 6]) -> i64 {
    NESTED_CALLS.with_borrow_mut(|v| v.push((num, args)));
    let h = NESTED.with_borrow_mut(|h| h.take());
    match h {
        Some(mut f) => {
            let r = f(num, args);
            NESTED.with_borrow_mut(|slot| {
                if slot.is_none() {
                    *slot = Some(f)
                }
            });
            r
        }
        None => -38,
    }
}

/// Sets the nested-call handler.
pub fn on_nested(f: impl FnMut(u64, [u64; 6]) -> i64 + 'static) {
    NESTED.with_borrow_mut(|h| *h = Some(Box::new(f)));
}

// ------------------------------------------------------------------ processes and signals

pub mod proc {
    use super::*;

    pub const SIGPIPE: u32 = 13;
    pub const SIGALRM: u32 = 14;
    pub const SIGCHLD: u32 = 17;
    pub const SIGVTALRM: u32 = 26;
    pub const SIGPROF: u32 = 27;
    pub const ERESTARTSYS: i64 = -512;

    /// *mirror* of the kernel's dequeued signal.
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    pub struct TakenSignal {
        pub signo: u32,
        pub code: i32,
        pub pid: u32,
        pub uid: u32,
        pub value: u64,
    }

    /// A process as `worker_main` reads it.
    #[derive(Default)]
    pub struct Process {
        pub zombie: bool,
    }

    /// The process table (shared by all test threads, like the kernel's).
    pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

    thread_local! {
        /// Signals posted: (pid, tid or 0, sig).
        pub static POSTED: RefCell<Vec<(u64, u64, u32)>> = const { RefCell::new(Vec::new()) };
        /// POSIX timer signals posted: (pid, tid, sig, timer, overrun, value).
        pub static TIMER_SIGNALS: RefCell<Vec<(u64, Option<u64>, u32, i32, u32, u64)>> = const { RefCell::new(Vec::new()) };
        /// Overruns set on queued timer signals: (pid, tid, sig, overrun).
        pub static OVERRUNS: RefCell<Vec<(u64, Option<u64>, u32, u32)>> = const { RefCell::new(Vec::new()) };
        /// Processes that are gone (posting to them fails).
        pub static GONE: RefCell<BTreeSet<u64>> = const { RefCell::new(BTreeSet::new()) };
        /// Processes that exited (zombies or reaped).
        pub static EXITED: RefCell<BTreeSet<u64>> = const { RefCell::new(BTreeSet::new()) };
        /// Processes that exist.
        pub static LIVE: RefCell<BTreeSet<u64>> = const { RefCell::new(BTreeSet::new()) };
        /// Whether `may_signal` refuses.
        pub static DENY_SIGNAL: Cell<bool> = const { Cell::new(false) };
        /// The caller's pending signals (signalfd reads them).
        pub static PENDING: RefCell<VecDeque<TakenSignal>> = const { RefCell::new(VecDeque::new()) };
        /// What `sigchld_details` reports.
        pub static SIGCHLD_DETAILS: Cell<(i32, u64, i32)> = const { Cell::new((0, 0, 0)) };
        /// Signals still queued: (pid, sig).
        pub static QUEUED: RefCell<BTreeSet<(u64, u32)>> = const { RefCell::new(BTreeSet::new()) };
        /// Threads by process.
        pub static THREADS: RefCell<BTreeMap<u64, Vec<u64>>> = const { RefCell::new(BTreeMap::new()) };
        /// Temporary signal masks: the masks set, and the old masks restored.
        pub static TEMP_MASKS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
        pub static RESTORED_MASKS: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset() {
        POSTED.with_borrow_mut(|v| v.clear());
        TIMER_SIGNALS.with_borrow_mut(|v| v.clear());
        OVERRUNS.with_borrow_mut(|v| v.clear());
        GONE.with_borrow_mut(|v| v.clear());
        EXITED.with_borrow_mut(|v| v.clear());
        LIVE.with_borrow_mut(|v| v.clear());
        DENY_SIGNAL.set(false);
        PENDING.with_borrow_mut(|v| v.clear());
        SIGCHLD_DETAILS.set((0, 0, 0));
        QUEUED.with_borrow_mut(|v| v.clear());
        THREADS.with_borrow_mut(|v| v.clear());
        TEMP_MASKS.with_borrow_mut(|v| v.clear());
        RESTORED_MASKS.with_borrow_mut(|v| v.clear());
    }

    pub fn current_ids() -> (u64, u64) {
        IDS.get()
    }
    pub fn signal_pending() -> bool {
        SIGNAL_PENDING.get()
    }
    pub fn post_thread(pid: u64, tid: u64, sig: u32) -> bool {
        POSTED.with_borrow_mut(|v| v.push((pid, tid, sig)));
        !GONE.with_borrow(|g| g.contains(&pid))
    }
    pub fn post_process(pid: u64, sig: u32) -> bool {
        POSTED.with_borrow_mut(|v| v.push((pid, 0, sig)));
        !GONE.with_borrow(|g| g.contains(&pid))
    }
    pub fn has_exited(pid: u64) -> bool {
        EXITED.with_borrow(|e| e.contains(&pid))
    }
    pub fn process_exists(pid: u64) -> bool {
        LIVE.with_borrow(|l| l.contains(&pid))
    }
    pub fn may_signal(_pid: u64, _sig: u32) -> bool {
        !DENY_SIGNAL.get()
    }
    fn bit(sig: u32) -> u64 {
        1u64 << (sig - 1)
    }
    pub fn take_signal_info(mask: u64) -> Option<TakenSignal> {
        PENDING.with_borrow_mut(|q| {
            let i = q.iter().position(|s| mask & bit(s.signo) != 0)?;
            q.remove(i)
        })
    }
    pub fn pending_for(_pid: u64, mask: u64) -> bool {
        PENDING.with_borrow(|q| q.iter().any(|s| mask & bit(s.signo) != 0))
    }
    pub fn sigchld_details(_parent: u64) -> (i32, u64, i32) {
        SIGCHLD_DETAILS.get()
    }
    pub fn signal_queued(pid: u64, _tid: Option<u64>, sig: u32) -> bool {
        QUEUED.with_borrow(|q| q.contains(&(pid, sig)))
    }
    pub fn set_timer_overrun(pid: u64, tid: Option<u64>, sig: u32, overrun: u32) {
        OVERRUNS.with_borrow_mut(|v| v.push((pid, tid, sig, overrun)));
    }
    pub fn post_timer_signal(pid: u64, tid: Option<u64>, sig: u32, timer: i32, overrun: u32, value: u64) -> bool {
        TIMER_SIGNALS.with_borrow_mut(|v| v.push((pid, tid, sig, timer, overrun, value)));
        !GONE.with_borrow(|g| g.contains(&pid))
    }
    pub fn thread_ids_of(pid: u64) -> Vec<u64> {
        THREADS.with_borrow(|t| t.get(&pid).cloned().unwrap_or_default())
    }
    /// The old mask (0) when a mask was installed.
    pub fn temp_mask(mask: u64) -> Option<u64> {
        TEMP_MASKS.with_borrow_mut(|v| v.push(mask));
        Some(0x5a5a)
    }
    pub fn end_temp_mask(old: u64) {
        RESTORED_MASKS.with_borrow_mut(|v| v.push(old));
    }
}

// ------------------------------------------------------------------ tasks

pub mod task {
    use super::*;

    /// Thread id, as in the kernel's `task::TaskId`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct TaskId(pub u64);

    /// *mirror* of the kernel's priorities.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum TaskPriority {
        Idle,
        Low,
        Normal,
        High,
    }

    /// Capability set of a task, as far as the code under test looks at it.
    pub struct Caps {
        pub effective: u64,
    }

    /// The parts of the kernel's `Task` the code under test reads.
    pub struct Task {
        pub caps: Caps,
        pub euid: u32,
    }

    thread_local! {
        /// Kernel tasks spawned: (name, entry).
        pub static SPAWNED: RefCell<Vec<(&'static str, fn())>> = const { RefCell::new(Vec::new()) };
        /// What `spawn_process_worker` returns (`None`: no worker can start).
        pub static WORKER_ID: Cell<Option<u64>> = const { Cell::new(None) };
        /// Process workers spawned: (name, entry).
        pub static WORKERS: RefCell<Vec<(&'static str, fn())>> = const { RefCell::new(Vec::new()) };
        /// CPU ticks by process.
        pub static CPU_TICKS: RefCell<BTreeMap<u64, u64>> = const { RefCell::new(BTreeMap::new()) };
        /// Processes `with_process` finds.
        pub static PROCESSES: RefCell<BTreeSet<u64>> = const { RefCell::new(BTreeSet::new()) };
        /// `yield_now` calls, and a hook run at each.
        pub static YIELDS: Cell<usize> = const { Cell::new(0) };
        pub static YIELD_HOOK: RefCell<Option<Box<dyn FnMut(usize)>>> = RefCell::new(None);
    }

    pub fn reset() {
        SPAWNED.with_borrow_mut(|v| v.clear());
        WORKER_ID.set(None);
        WORKERS.with_borrow_mut(|v| v.clear());
        CPU_TICKS.with_borrow_mut(|v| v.clear());
        PROCESSES.with_borrow_mut(|v| v.clear());
        YIELDS.set(0);
        YIELD_HOOK.with_borrow_mut(|h| *h = None);
    }

    pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        let effective = CAPS.get()?;
        let mut t = Task { caps: Caps { effective }, euid: EUID.get() };
        let r = f(&mut t);
        CAPS.set(Some(t.caps.effective));
        Some(r)
    }

    pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut super::fd::Fds) -> R) -> R {
        super::fd::FDS.with_borrow_mut(f)
    }

    /// Every kernel task spawned by any test (a daemon starts once per test binary).
    pub static SPAWNED_ALL: spin::Mutex<Vec<(&'static str, fn())>> = spin::Mutex::new(Vec::new());

    /// Records the kernel task (tests can run its entry function).
    pub fn spawn(name: &'static str, entry_fn: fn(), _priority: TaskPriority) -> TaskId {
        SPAWNED.with_borrow_mut(|v| v.push((name, entry_fn)));
        SPAWNED_ALL.lock().push((name, entry_fn));
        TaskId(1000)
    }

    /// The entry function of kernel task `name`, if one was spawned.
    pub fn spawned(name: &str) -> Option<fn()> {
        SPAWNED_ALL.lock().iter().find(|(n, _)| *n == name).map(|&(_, f)| f)
    }

    /// Runs a daemon's loop for `rounds` sleeps (each moves the clock to its deadline), then
    /// stops it (a panic it cannot catch, raised from its next sleep).
    pub fn run_daemon(entry: fn(), rounds: usize) {
        super::on_wait(move |n| {
            if n > rounds {
                panic!("{}", DAEMON_STOP);
            }
        });
        let start = super::WAITS.get();
        super::WAITS.set(0);
        let r = std::panic::catch_unwind(entry);
        super::WAITS.set(start);
        super::WAIT_HOOK.with_borrow_mut(|h| *h = None);
        match r {
            Ok(()) => {}
            Err(e) => {
                let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
                assert_eq!(msg, DAEMON_STOP, "the daemon panicked");
            }
        }
    }

    /// The panic that stops a daemon loop.
    pub const DAEMON_STOP: &str = "fake: daemon stopped";

    pub fn yield_now() {
        let n = YIELDS.get() + 1;
        YIELDS.set(n);
        let h = YIELD_HOOK.with_borrow_mut(|h| h.take());
        if let Some(mut f) = h {
            f(n);
            YIELD_HOOK.with_borrow_mut(|slot| {
                if slot.is_none() {
                    *slot = Some(f)
                }
            });
        }
    }

    /// Stand-in for `task::SCHEDULER`.
    pub struct Scheduler;
    pub static SCHEDULER: Scheduler = Scheduler;
    pub struct SchedulerGuard;

    impl Scheduler {
        pub fn lock(&self) -> SchedulerGuard {
            SchedulerGuard
        }
    }

    impl SchedulerGuard {
        pub fn process_ticks(&self, tgid: u64) -> u64 {
            CPU_TICKS.with_borrow(|m| m.get(&tgid).copied().unwrap_or(0))
        }
        pub fn spawn_process_worker(&mut self, name: &'static str, entry_fn: fn()) -> Option<TaskId> {
            let id = WORKER_ID.get()?;
            WORKERS.with_borrow_mut(|v| v.push((name, entry_fn)));
            Some(TaskId(id))
        }
        pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
            if PROCESSES.with_borrow(|p| p.contains(&tgid)) {
                Some(f(&Task { caps: Caps { effective: 0 }, euid: 0 }))
            } else {
                None
            }
        }
        pub fn current_task_id(&self) -> TaskId {
            TaskId(IDS.get().0)
        }
    }
}

// ------------------------------------------------------------------ wait queues

pub mod wait {
    use super::*;

    /// Message of the panic raised when code under test would sleep with nothing to end it.
    pub const WOULD_BLOCK: &str = "fake wait: the operation would block";

    /// Records wake-ups; never actually sleeps.
    #[derive(Default)]
    pub struct WaitQueue {
        wakes: core::sync::atomic::AtomicU64,
    }

    impl WaitQueue {
        pub const fn new() -> Self {
            WaitQueue { wakes: core::sync::atomic::AtomicU64::new(0) }
        }
        pub fn new_shared() -> Arc<Self> {
            Arc::new(WaitQueue::new())
        }
        pub fn register(&self) {}
        pub fn unregister(&self) {}
        /// This queue's own wakeups.
        pub fn wakes(&self) -> u64 {
            self.wakes.load(core::sync::atomic::Ordering::Relaxed)
        }
        pub fn wake_all(&self) {
            self.wakes.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let _ = WAKES.try_with(|w| w.set(w.get() + 1));
        }
    }

    pub enum QueueRef {
        Static(&'static WaitQueue),
        Shared(Arc<WaitQueue>),
    }

    /// *mirror* of the kernel's trait.
    pub trait Deadline: Send + Sync {
        fn next_tick(&self) -> Option<u64>;
        fn next_ns(&self) -> Option<u64> {
            None
        }
    }

    thread_local! {
        /// Queues the last registered wait set held (how many).
        pub static LAST_QUEUES: Cell<usize> = const { Cell::new(0) };
        /// Whether the last wait set was `polled`.
        pub static LAST_POLLED: Cell<bool> = const { Cell::new(false) };
    }

    /// The queues one blocking call waits on (same fields and rules as the kernel's).
    pub struct WaitSet {
        queues: Vec<QueueRef>,
        pub polled: bool,
        deadlines: Vec<Arc<dyn Deadline>>,
    }

    impl WaitSet {
        pub fn new() -> Self {
            Self { queues: Vec::new(), polled: false, deadlines: Vec::new() }
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn add_deadline(&mut self, d: Arc<dyn Deadline>) {
            self.deadlines.push(d);
        }
        /// The number of queues in the set (tests).
        pub fn queue_count(&self) -> usize {
            self.queues.len()
        }
        pub fn register(&self) {
            LAST_QUEUES.set(self.queues.len());
            LAST_POLLED.set(self.polled);
        }
        /// *mirror* of the kernel's deadline rules, then a fake sleep.
        pub fn wait(&self, deadline: Option<u64>) {
            if self.deadlines.iter().any(|d| d.next_ns().is_some()) {
                return self.wait_ns(deadline.map(|t| t * TICK_NS));
            }
            let deadline = self.deadlines.iter().filter_map(|d| d.next_tick()).fold(deadline, |acc, t| Some(acc.map_or(t, |a| a.min(t))));
            let deadline = if self.polled {
                let next = ticks() + 1;
                Some(deadline.map_or(next, |d| d.min(next)))
            } else {
                deadline
            };
            wait(deadline);
        }
        pub fn wait_ns(&self, deadline_ns: Option<u64>) {
            let mut deadline = deadline_ns;
            for d in &self.deadlines {
                if let Some(t) = d.next_ns().or_else(|| d.next_tick().map(|t| t * TICK_NS)) {
                    deadline = Some(deadline.map_or(t, |a| a.min(t)));
                }
            }
            if self.polled {
                let next = (ticks() + 1) * TICK_NS;
                deadline = Some(deadline.map_or(next, |d| d.min(next)));
            }
            wait_ns(deadline);
        }
    }

    /// A fake sleep until boot-clock `deadline_ns`: runs [`WAIT_HOOK`], moves the clock to
    /// the deadline; with neither, the operation would block for ever (panic).
    pub fn wait_ns(deadline_ns: Option<u64>) {
        let n = WAITS.get() + 1;
        WAITS.set(n);
        LAST_DEADLINE.set(deadline_ns);
        if n > WAIT_LIMIT.get() {
            panic!("fake wait: more than {} sleeps", WAIT_LIMIT.get());
        }
        let hook = WAIT_HOOK.with_borrow_mut(|h| h.take());
        let had_hook = hook.is_some();
        if let Some(mut f) = hook {
            f(n);
            WAIT_HOOK.with_borrow_mut(|slot| {
                if slot.is_none() {
                    *slot = Some(f)
                }
            });
        }
        match deadline_ns {
            Some(d) => NOW_NS.set(NOW_NS.get().max(d)),
            None if had_hook => {}
            None => panic!("{}", WOULD_BLOCK),
        }
    }

    /// As [`wait_ns`], with a deadline in ticks.
    pub fn wait(deadline: Option<u64>) {
        wait_ns(deadline.map(|t| t * TICK_NS))
    }
}

// ------------------------------------------------------------------ descriptors

pub mod fd {
    use super::*;
    use crate::compat::linux as lx;

    /// An open ZFS file (only its existence matters here).
    pub struct Vnode;
    /// A memfd (only its existence matters here).
    pub struct MemFdStub;

    /// *stub* The kernel's descriptor enum, with the variants the code under test matches.
    #[derive(Clone)]
    pub enum FileDescriptor {
        PipeRead(Arc<spin::Mutex<crate::fs::pipe::PipeBuffer>>),
        PipeWrite(Arc<spin::Mutex<crate::fs::pipe::PipeBuffer>>),
        Socket(Arc<spin::Mutex<lx::socket::UnixSocket>>),
        Epoll(Arc<spin::Mutex<lx::epoll::EpollInstance>>),
        EventFd(Arc<spin::Mutex<lx::eventfd::EventFd>>),
        MemFd { memfd: Arc<spin::Mutex<MemFdStub>>, flags: u32 },
        Vnode(Arc<spin::Mutex<Vnode>>),
        Inet(Arc<spin::Mutex<lx::inet::InetSocket>>),
        SignalFd(Arc<lx::signalfd::SignalFd>),
        Unix(Arc<lx::unix::UnixSocket>),
        TimerFd(Arc<lx::timerfd::TimerFd>),
        PidFd(Arc<lx::pidfd::PidFd>),
        Device(Arc<dyn lx::chardev::CharDevice>),
        File { path: String, readable: bool, writable: bool },
    }

    impl FileDescriptor {
        /// *mirror* of the kernel's `object_id` for these variants.
        pub fn object_id(&self) -> usize {
            fn of<T: ?Sized>(a: &Arc<T>) -> usize {
                Arc::as_ptr(a) as *const u8 as usize
            }
            use FileDescriptor::*;
            match self {
                PipeRead(a) | PipeWrite(a) => of(a),
                Socket(a) => of(a),
                Epoll(a) => of(a),
                EventFd(a) => of(a),
                MemFd { memfd, .. } => of(memfd),
                Vnode(a) => of(a),
                Inet(a) => of(a),
                SignalFd(a) => of(a),
                Unix(a) => of(a),
                TimerFd(a) => of(a),
                PidFd(a) => of(a),
                Device(a) => of(a),
                File { path, .. } => path.as_ptr() as usize,
            }
        }
    }

    thread_local! {
        pub static FDS: RefCell<Fds> = RefCell::new(Fds::default());
    }

    /// Minimal descriptor table: lowest free number from 3, up to `limit`.
    pub struct Fds {
        pub limit: usize,
        pub open: BTreeMap<usize, (FileDescriptor, bool)>,
    }

    impl Default for Fds {
        fn default() -> Self {
            Self { limit: 1024, open: BTreeMap::new() }
        }
    }

    impl Fds {
        pub fn alloc_fd(&mut self, d: FileDescriptor) -> Result<usize, &'static str> {
            let fd = (3..self.limit).find(|n| !self.open.contains_key(n)).ok_or("Too many open files")?;
            self.open.insert(fd, (d, false));
            Ok(fd)
        }
        pub fn set_cloexec(&mut self, fd: usize, on: bool) {
            if let Some(e) = self.open.get_mut(&fd) {
                e.1 = on;
            }
        }
        pub fn cloexec(&self, fd: usize) -> bool {
            self.open.get(&fd).is_some_and(|e| e.1)
        }
        pub fn get(&self, fd: usize) -> Option<&FileDescriptor> {
            self.open.get(&fd).map(|e| &e.0)
        }
        /// *mirror* of the kernel's readiness rules for these variants.
        pub fn readiness(&self, desc: &FileDescriptor) -> u32 {
            use FileDescriptor::*;
            match desc {
                EventFd(e) => e.lock().poll_events(),
                Device(d) => d.poll_events(),
                File { .. } | Vnode(_) | MemFd { .. } => 0x1 | 0x4,
                Unix(s) => s.poll_events(),
                Inet(s) => s.lock().poll_events(),
                TimerFd(t) => t.poll_events(),
                SignalFd(s) => s.poll_events(),
                PidFd(p) => p.poll_events(),
                Socket(s) => s.lock().poll_events(),
                PipeRead(p) => {
                    let p = p.lock();
                    (if p.available_read() > 0 { 0x1 } else { 0 }) | (if p.writers_count() == 0 { 0x10 } else { 0 })
                }
                PipeWrite(p) => {
                    let p = p.lock();
                    (if p.available_write() > 0 { 0x4 } else { 0 }) | (if p.readers_count() == 0 { 0x8 } else { 0 })
                }
                Epoll(_) => 0,
            }
        }
        pub fn add_wait_queues_for(&self, desc: &FileDescriptor, waits: &mut wait::WaitSet) {
            use FileDescriptor::*;
            match desc {
                EventFd(e) => waits.add(wait::QueueRef::Shared(e.lock().wq.clone())),
                Device(d) => d.add_wait_queues(waits),
                Unix(s) => s.add_wait_queues(waits),
                TimerFd(t) => waits.add(wait::QueueRef::Shared(t.wq.clone())),
                Inet(s) => match s.lock().wait_queue() {
                    Some(q) => waits.add(wait::QueueRef::Shared(q)),
                    None => waits.polled = true,
                },
                PidFd(_) => waits.add(wait::QueueRef::Static(&lx::pidfd::EXIT_WQ)),
                _ => {}
            }
        }
        /// Closes a descriptor (drops it from the table).
        pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
            self.open.remove(&fd).map(|_| ()).ok_or("Bad file descriptor")
        }
        /// Test helper: install `d` at a specific number.
        pub fn install(&mut self, fd: usize, d: FileDescriptor) {
            self.open.insert(fd, (d, false));
        }
    }

    /// Test helper: the descriptor at `fd`, cloned.
    pub fn get(fd: i64) -> Option<FileDescriptor> {
        FDS.with_borrow(|f| f.get(fd as usize).cloned())
    }

    /// Test helper: installs `d` at `fd`.
    pub fn install(fd: usize, d: FileDescriptor) {
        FDS.with_borrow_mut(|f| f.install(fd, d));
    }
}

// ------------------------------------------------------------------ user memory, socket names

pub mod vfs {
    use super::*;
    const EFAULT: i64 = -14;

    thread_local! {
        /// Socket nodes in the "file system": path -> inode.
        pub static SOCKET_NODES: RefCell<BTreeMap<Vec<u8>, u64>> = const { RefCell::new(BTreeMap::new()) };
        /// Paths that exist (any kind of file).
        pub static PATHS: RefCell<BTreeSet<Vec<u8>>> = const { RefCell::new(BTreeSet::new()) };
        /// Next inode `make_socket_node` hands out.
        pub static NEXT_NODE: Cell<u64> = const { Cell::new(7000) };
        /// Socket nodes unlinked.
        pub static UNLINKED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    /// *mirror* of the kernel's credential snapshot.
    pub(crate) struct Creds {
        pub uid: u32,
        pub gid: u32,
        pub euid: u32,
        pub egid: u32,
    }
    pub(crate) fn creds() -> Creds {
        let (euid, egid) = CREDS.get();
        Creds { uid: euid, gid: egid, euid, egid }
    }
    /// The lookup key of a socket path: its node's inode key (`ENOENT` without one).
    pub(crate) fn socket_key(path: &[u8]) -> Result<Vec<u8>, i64> {
        SOCKET_NODES.with_borrow(|m| m.get(path).map(|&ino| socket_ino_key(ino))).ok_or(-2)
    }
    /// Verbatim from the kernel.
    pub(crate) fn socket_ino_key(ino: u64) -> Vec<u8> {
        format!("ino:{}", ino).into_bytes()
    }
    /// Creates a socket node (`EADDRINUSE` if the path exists).
    pub(crate) fn make_socket_node(path: &[u8]) -> Result<u64, i64> {
        if PATHS.with_borrow(|p| p.contains(path)) || SOCKET_NODES.with_borrow(|m| m.contains_key(path)) {
            return Err(-98);
        }
        let ino = NEXT_NODE.get();
        NEXT_NODE.set(ino + 1);
        SOCKET_NODES.with_borrow_mut(|m| m.insert(path.to_vec(), ino));
        Ok(ino)
    }
    pub(crate) fn path_exists(path: &[u8]) -> bool {
        PATHS.with_borrow(|p| p.contains(path)) || SOCKET_NODES.with_borrow(|m| m.contains_key(path))
    }
    pub(crate) fn socket_node_for_connect(path: &[u8]) -> Result<u64, i64> {
        if let Some(ino) = SOCKET_NODES.with_borrow(|m| m.get(path).copied()) {
            return Ok(ino);
        }
        Err(if PATHS.with_borrow(|p| p.contains(path)) { -111 } else { -2 })
    }
    pub(crate) fn unlink_socket_node(path: &[u8]) {
        SOCKET_NODES.with_borrow_mut(|m| m.remove(path));
        UNLINKED.with_borrow_mut(|v| v.push(path.to_vec()));
    }
    pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
        if !prefault_current(ptr, data.len() as u64, true) {
            return Err(EFAULT);
        }
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
        Ok(())
    }
    pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if !prefault_current(ptr, len as u64, false) {
            return Err(EFAULT);
        }
        let mut v = vec![0u8; len];
        unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
        Ok(v)
    }
}

// ------------------------------------------------------------------ net-server's client

pub mod net {
    //! A scripted net-server: connections, listeners, UDP and ICMP endpoints whose state the
    //! test sets, and a log of what the kernel asked for.
    use super::*;

    pub const ECONNREFUSED: i64 = -111;
    pub const ECONNRESET: i64 = -104;
    pub const ETIMEDOUT: i64 = -110;
    pub const ENOTCONN: i64 = -107;
    pub const EPIPE: i64 = -32;
    pub const ENETUNREACH: i64 = -101;
    pub const ENETDOWN: i64 = -100;

    /// *mirror* of the kernel's TCP states.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TcpState {
        SynSent,
        SynReceived,
        Established,
        FinWait1,
        FinWait2,
        CloseWait,
        LastAck,
        Closing,
        TimeWait,
        Closed,
    }

    pub const V6_LOOPBACK: [u8; 4] = [0, 0, 0, 1];
    pub const V6_LINKLOCAL: [u8; 4] = [0, 0, 0, 2];

    /// Verbatim from the kernel.
    pub fn is_v6(ip: [u8; 4]) -> bool {
        ip == V6_LOOPBACK || ip == V6_LINKLOCAL
    }

    /// *mirror* of the kernel's interface record.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct IfaceInfo {
        pub running: bool,
        pub present: bool,
        pub link: bool,
        pub dhcp_busy: bool,
        pub mac: [u8; 6],
        pub ip: [u8; 4],
        pub mask: [u8; 4],
        pub gateway: [u8; 4],
        pub dns: [u8; 4],
        pub dhcp_server: [u8; 4],
        pub eth: [u64; 4],
        pub lo: [u64; 2],
        pub rx_calls: [u64; 2],
    }

    /// *mirror* of the kernel's connection list entry.
    pub struct TcpEntry {
        pub id: u32,
        pub local: ([u8; 4], u16),
        pub remote: ([u8; 4], u16),
        pub state: TcpState,
        pub tx: usize,
        pub rx: usize,
    }

    /// A TCP connection in the fake server.
    pub struct Tcp {
        pub state: TcpState,
        /// Pending error (`SO_ERROR`).
        pub error: Option<i64>,
        /// Bytes to receive; `eof` once the peer finished.
        pub rx: VecDeque<u8>,
        pub eof: bool,
        /// Error a receive reports.
        pub recv_err: Option<i64>,
        /// Bytes taken by sends.
        pub sent: Vec<u8>,
        /// Most bytes one send takes (`None`: all).
        pub send_cap: Option<usize>,
        /// Error a send reports.
        pub send_err: Option<i64>,
        /// (local port, remote ip, remote port).
        pub endpoints: Option<(u16, [u8; 4], u16)>,
        pub local_ip: Option<[u8; 4]>,
        /// Readiness override (otherwise from rx and state).
        pub poll: Option<(bool, bool, bool, bool)>,
        pub shut_wr: bool,
    }

    impl Default for Tcp {
        fn default() -> Self {
            Tcp {
                state: TcpState::Established,
                error: None,
                rx: VecDeque::new(),
                eof: false,
                recv_err: None,
                sent: Vec::new(),
                send_cap: None,
                send_err: None,
                endpoints: Some((40000, [10, 0, 2, 2], 80)),
                local_ip: Some([10, 0, 2, 15]),
                poll: None,
                shut_wr: false,
            }
        }
    }

    /// A UDP endpoint.
    #[derive(Default)]
    pub struct Udp {
        pub port: u16,
        pub rx: VecDeque<([u8; 4], u16, Vec<u8>, u64)>,
        pub sent: Vec<([u8; 4], u16, Vec<u8>)>,
        pub send_err: Option<i64>,
    }

    /// An ICMP endpoint.
    #[derive(Default)]
    pub struct Icmp {
        pub raw: bool,
        pub v6: bool,
        pub ident: u16,
        pub rx: VecDeque<([u8; 4], Vec<u8>, u64)>,
        pub sent: Vec<([u8; 4], Vec<u8>)>,
    }

    /// A listener.
    #[derive(Default)]
    pub struct Listener {
        pub bind: u32,
        pub backlog: usize,
        pub queue: VecDeque<u32>,
    }

    /// The fake server's state.
    pub struct NetState {
        pub iface: IfaceInfo,
        pub running: bool,
        pub next_id: u32,
        pub tcp: BTreeMap<u32, Tcp>,
        pub udp: BTreeMap<u32, Udp>,
        pub icmp: BTreeMap<u32, Icmp>,
        pub listeners: BTreeMap<u32, Listener>,
        /// Port reservations: id -> (ip, port, reuse_addr, reuse_port, v4, v6).
        pub binds: BTreeMap<u32, ([u8; 4], u16, bool, bool, bool, bool)>,
        /// Handles without a wait queue.
        pub no_queue: BTreeSet<u32>,
        pub queues: BTreeMap<u32, Arc<wait::WaitQueue>>,
        /// Handles that died with the server.
        pub dead: BTreeSet<u32>,
        /// Errors for the next calls of these kinds.
        pub connect_err: Option<i64>,
        pub bind_err: Option<i64>,
        pub listen_err: Option<i64>,
        pub udp_open_err: Option<i64>,
        pub rebind_err: Option<i64>,
        pub ident_err: Option<i64>,
        pub icmp_send_err: Option<i64>,
        /// The state a new connection starts in.
        pub connect_state: TcpState,
        /// Calls made: a log of names and arguments.
        pub log: Vec<String>,
        pub counters: [((u64, u64), (u64, u64)); 2],
        pub arp: Vec<([u8; 4], [u8; 6])>,
    }

    impl Default for NetState {
        fn default() -> Self {
            NetState {
                iface: IfaceInfo::default(),
                running: true,
                next_id: 100,
                tcp: BTreeMap::new(),
                udp: BTreeMap::new(),
                icmp: BTreeMap::new(),
                listeners: BTreeMap::new(),
                binds: BTreeMap::new(),
                no_queue: BTreeSet::new(),
                queues: BTreeMap::new(),
                dead: BTreeSet::new(),
                connect_err: None,
                bind_err: None,
                listen_err: None,
                udp_open_err: None,
                rebind_err: None,
                ident_err: None,
                icmp_send_err: None,
                connect_state: TcpState::SynSent,
                log: Vec::new(),
                counters: [((0, 0), (0, 0)); 2],
                arp: Vec::new(),
            }
        }
    }

    thread_local! {
        pub static NET: RefCell<NetState> = RefCell::new(NetState::default());
    }

    /// Runs `f` on the fake server's state.
    pub fn with<R>(f: impl FnOnce(&mut NetState) -> R) -> R {
        NET.with_borrow_mut(f)
    }

    fn log(s: String) {
        with(|n| n.log.push(s));
    }

    fn new_id(n: &mut NetState) -> u32 {
        let id = n.next_id;
        n.next_id += 1;
        n.queues.insert(id, wait::WaitQueue::new_shared());
        id
    }

    /// A configured Ethernet interface (10.0.2.15/24 via 10.0.2.2).
    pub fn eth_up() {
        with(|n| {
            n.iface = IfaceInfo {
                running: true,
                present: true,
                link: true,
                mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
                ip: [10, 0, 2, 15],
                mask: [255, 255, 255, 0],
                gateway: [10, 0, 2, 2],
                dns: [10, 0, 2, 3],
                ..Default::default()
            }
        });
    }

    pub fn iface() -> IfaceInfo {
        with(|n| n.iface)
    }
    pub fn service_running() -> bool {
        with(|n| n.running)
    }
    pub fn wait_queue(id: u32) -> Option<Arc<wait::WaitQueue>> {
        with(|n| if n.no_queue.contains(&id) { None } else { n.queues.get(&id).cloned() })
    }
    pub fn on_signal(_arg: u64) {}
    pub fn dead(id: u32) -> bool {
        with(|n| n.dead.contains(&id))
    }
    /// *mirror* of the kernel's: from the interface's MAC.
    pub fn link_local6() -> Option<[u8; 16]> {
        let i = iface();
        if !i.present {
            return None;
        }
        let m = i.mac;
        Some([0xfe, 0x80, 0, 0, 0, 0, 0, 0, m[0] ^ 2, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]])
    }
    /// *mirror* of the kernel's.
    pub fn is_local(ip: [u8; 4]) -> bool {
        if ip[0] == 127 || ip == V6_LOOPBACK {
            return true;
        }
        let i = iface();
        (ip == V6_LINKLOCAL && i.present) || (ip != [0, 0, 0, 0] && ip == i.ip)
    }
    pub fn counters() -> [((u64, u64), (u64, u64)); 2] {
        with(|n| n.counters)
    }
    pub fn arp_entries() -> Vec<([u8; 4], [u8; 6])> {
        with(|n| n.arp.clone())
    }

    // TCP

    pub fn tcp_connect(ip: [u8; 4], port: u16, local_port: Option<u16>) -> Result<u32, i64> {
        log(format!("tcp_connect {:?} {} {:?}", ip, port, local_port));
        with(|n| {
            if let Some(e) = n.connect_err.take() {
                return Err(e);
            }
            let id = new_id(n);
            let state = n.connect_state;
            n.tcp.insert(id, Tcp { state, endpoints: Some((local_port.unwrap_or(40000), ip, port)), ..Default::default() });
            Ok(id)
        })
    }
    pub fn tcp_state(id: u32) -> TcpState {
        with(|n| n.tcp.get(&id).map_or(TcpState::Closed, |t| t.state))
    }
    pub fn tcp_take_error(id: u32) -> Option<i64> {
        with(|n| n.tcp.get_mut(&id).and_then(|t| t.error.take()))
    }
    pub fn tcp_send(id: u32, data: &[u8]) -> Result<usize, i64> {
        with(|n| {
            let t = n.tcp.get_mut(&id).ok_or(ECONNRESET)?;
            if let Some(e) = t.send_err {
                return Err(e);
            }
            let k = t.send_cap.map_or(data.len(), |c| c.min(data.len()));
            t.sent.extend_from_slice(&data[..k]);
            Ok(k)
        })
    }
    pub fn tcp_recv(id: u32, buf: &mut [u8], peek: bool) -> Result<(usize, bool), i64> {
        with(|n| {
            let t = n.tcp.get_mut(&id).ok_or(ECONNRESET)?;
            if t.rx.is_empty() {
                if let Some(e) = t.recv_err {
                    return Err(e);
                }
            }
            let k = buf.len().min(t.rx.len());
            for (i, b) in t.rx.iter().take(k).enumerate() {
                buf[i] = *b;
            }
            if !peek {
                t.rx.drain(..k);
            }
            Ok((k, t.eof && t.rx.is_empty()))
        })
    }
    pub fn tcp_poll(id: u32) -> (bool, bool, bool, bool) {
        with(|n| match n.tcp.get(&id) {
            Some(t) => t.poll.unwrap_or((!t.rx.is_empty() || t.eof, t.state == TcpState::Established, t.state == TcpState::Closed, t.error.is_some())),
            None => (true, false, true, true),
        })
    }
    pub fn tcp_shutdown_write(id: u32) {
        log(format!("tcp_shutdown_write {}", id));
        with(|n| {
            if let Some(t) = n.tcp.get_mut(&id) {
                t.shut_wr = true;
            }
        });
    }
    pub fn tcp_close(id: u32) {
        log(format!("tcp_close {}", id));
    }
    pub fn tcp_endpoints(id: u32) -> Option<(u16, [u8; 4], u16)> {
        with(|n| n.tcp.get(&id).and_then(|t| t.endpoints))
    }
    pub fn tcp_local_ip(id: u32) -> Option<[u8; 4]> {
        with(|n| n.tcp.get(&id).and_then(|t| t.local_ip))
    }
    pub fn tcp_bind(ip: [u8; 4], port: u16, reuse_addr: bool, reuse_port: bool, v4: bool, v6: bool) -> Result<(u32, u16), i64> {
        log(format!("tcp_bind {:?} {} {} {} {} {}", ip, port, reuse_addr, reuse_port, v4, v6));
        with(|n| {
            if let Some(e) = n.bind_err.take() {
                return Err(e);
            }
            let id = new_id(n);
            let port = if port == 0 { 32768 + id as u16 } else { port };
            n.binds.insert(id, (ip, port, reuse_addr, reuse_port, v4, v6));
            Ok((id, port))
        })
    }
    pub fn tcp_unbind(id: u32) {
        log(format!("tcp_unbind {}", id));
    }
    pub fn tcp_listen(bind: u32, backlog: usize) -> Result<u32, i64> {
        log(format!("tcp_listen {} {}", bind, backlog));
        with(|n| {
            if let Some(e) = n.listen_err.take() {
                return Err(e);
            }
            let id = new_id(n);
            n.listeners.insert(id, Listener { bind, backlog, queue: VecDeque::new() });
            Ok(id)
        })
    }
    pub fn tcp_set_backlog(id: u32, backlog: usize) {
        log(format!("tcp_set_backlog {} {}", id, backlog));
        with(|n| {
            if let Some(l) = n.listeners.get_mut(&id) {
                l.backlog = backlog;
            }
        });
    }
    pub fn tcp_accept(id: u32) -> Option<u32> {
        with(|n| n.listeners.get_mut(&id).and_then(|l| l.queue.pop_front()))
    }
    pub fn tcp_acceptable(id: u32) -> bool {
        with(|n| n.listeners.get(&id).is_some_and(|l| !l.queue.is_empty()))
    }
    pub fn tcp_unlisten(id: u32) {
        log(format!("tcp_unlisten {}", id));
    }
    /// Test helper: an incoming connection queued on listener `lid`; its id.
    pub fn incoming(lid: u32, conn: Tcp) -> u32 {
        with(|n| {
            let id = new_id(n);
            n.tcp.insert(id, conn);
            n.listeners.get_mut(&lid).expect("listener").queue.push_back(id);
            id
        })
    }
    pub fn tcp_list() -> Vec<TcpEntry> {
        with(|n| {
            n.tcp
                .iter()
                .map(|(&id, t)| {
                    let (lp, rip, rp) = t.endpoints.unwrap_or((0, [0; 4], 0));
                    TcpEntry { id, local: (t.local_ip.unwrap_or([0; 4]), lp), remote: (rip, rp), state: t.state, tx: t.sent.len(), rx: t.rx.len() }
                })
                .collect()
        })
    }
    pub fn listener_list() -> Vec<(u32, [u8; 4], u16, usize, usize)> {
        with(|n| {
            n.listeners
                .iter()
                .map(|(&id, l)| {
                    let (ip, port, ..) = n.binds.get(&l.bind).copied().unwrap_or(([0; 4], 0, false, false, true, false));
                    (id, ip, port, l.queue.len(), l.backlog)
                })
                .collect()
        })
    }

    // UDP

    pub fn udp_list() -> Vec<(u32, u16, usize)> {
        with(|n| n.udp.iter().map(|(&id, u)| (id, u.port, u.rx.iter().map(|d| d.2.len()).sum())).collect())
    }
    pub fn udp_open(port: u16) -> Result<u32, i64> {
        log(format!("udp_open {}", port));
        with(|n| {
            if let Some(e) = n.udp_open_err.take() {
                return Err(e);
            }
            let id = new_id(n);
            let port = if port == 0 { 50000 + id as u16 } else { port };
            n.udp.insert(id, Udp { port, ..Default::default() });
            Ok(id)
        })
    }
    pub fn udp_rebind(id: u32, port: u16) -> Result<(), i64> {
        log(format!("udp_rebind {} {}", id, port));
        with(|n| {
            if let Some(e) = n.rebind_err.take() {
                return Err(e);
            }
            if let Some(u) = n.udp.get_mut(&id) {
                u.port = port;
            }
            Ok(())
        })
    }
    pub fn udp_port(id: u32) -> u16 {
        with(|n| n.udp.get(&id).map_or(0, |u| u.port))
    }
    pub fn udp_send(id: u32, ip: [u8; 4], port: u16, data: &[u8]) -> Result<usize, i64> {
        with(|n| {
            let u = n.udp.get_mut(&id).ok_or(ENETDOWN)?;
            if let Some(e) = u.send_err {
                return Err(e);
            }
            u.sent.push((ip, port, data.to_vec()));
            Ok(data.len())
        })
    }
    pub fn udp_recv(id: u32, peek: bool) -> Option<([u8; 4], u16, Vec<u8>, u64)> {
        with(|n| {
            let u = n.udp.get_mut(&id)?;
            if peek {
                u.rx.front().cloned()
            } else {
                u.rx.pop_front()
            }
        })
    }
    pub fn udp_readable(id: u32) -> bool {
        with(|n| n.udp.get(&id).is_some_and(|u| !u.rx.is_empty()))
    }
    pub fn udp_close(id: u32) {
        log(format!("udp_close {}", id));
    }

    // ICMP

    pub fn icmp_open(raw: bool, v6: bool) -> u32 {
        log(format!("icmp_open {} {}", raw, v6));
        with(|n| {
            let id = new_id(n);
            n.icmp.insert(id, Icmp { raw, v6, ident: 1234, ..Default::default() });
            id
        })
    }
    pub fn icmp_ident(id: u32) -> u16 {
        with(|n| n.icmp.get(&id).map_or(0, |i| i.ident))
    }
    pub fn icmp_set_ident(id: u32, ident: u16) -> Result<(), i64> {
        with(|n| {
            if let Some(e) = n.ident_err.take() {
                return Err(e);
            }
            if let Some(i) = n.icmp.get_mut(&id) {
                i.ident = ident;
            }
            Ok(())
        })
    }
    pub fn icmp_send(id: u32, dst: [u8; 4], msg: &[u8]) -> Result<usize, i64> {
        with(|n| {
            if let Some(e) = n.icmp_send_err.take() {
                return Err(e);
            }
            n.icmp.get_mut(&id).ok_or(ENETDOWN)?.sent.push((dst, msg.to_vec()));
            Ok(msg.len())
        })
    }
    pub fn icmp_recv(id: u32, peek: bool) -> Option<([u8; 4], Vec<u8>, u64)> {
        with(|n| {
            let i = n.icmp.get_mut(&id)?;
            if peek {
                i.rx.front().cloned()
            } else {
                i.rx.pop_front()
            }
        })
    }
    pub fn icmp_readable(id: u32) -> bool {
        with(|n| n.icmp.get(&id).is_some_and(|i| !i.rx.is_empty()))
    }
    pub fn icmp_close(id: u32) {
        log(format!("icmp_close {}", id));
    }
}
