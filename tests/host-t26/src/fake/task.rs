//! *stub* `crate::task`: the current task, other processes, the scheduler's lookups and
//! wait queues that never sleep.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::cell::{Cell, RefCell};

use crate::fake::fd::{FdTable, SharedFdTable};
use crate::memory::vm::Mm;

/// Capability set of a task.
#[derive(Clone, Copy)]
pub struct Caps {
    pub effective: u64,
    /// Capabilities held only inside a user namespace.
    pub in_userns: bool,
}

impl Caps {
    pub fn has(&self, mask: u64) -> bool {
        self.effective & mask == mask
    }
}

/// Thread id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId(pub u64);

/// The parts of the kernel's `Task` the file layer reads.
pub struct Task {
    pub id: TaskId,
    pub tgid: u64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub caps: Caps,
    pub fds: SharedFdTable,
    pub mm: Option<Arc<spin::Mutex<Mm>>>,
    pub exe: String,
    pub cmdline: Option<Vec<u8>>,
    /// The driver service a system process serves.
    pub service: Option<u32>,
    pub runnable: bool,
}

impl Task {
    pub fn exe_path(&self) -> &str {
        &self.exe
    }

    /// A task of process `pid` (thread `pid`) owned by `uid`, with an empty table.
    pub fn new(pid: u64, uid: u32) -> Task {
        Task {
            id: TaskId(pid),
            tgid: pid,
            uid,
            gid: uid,
            euid: uid,
            egid: uid,
            suid: uid,
            sgid: uid,
            caps: Caps { effective: if uid == 0 { ALL_CAPS } else { 0 }, in_userns: false },
            fds: Arc::new(spin::Mutex::new(FdTable::new())),
            mm: None,
            exe: String::from("/usr/bin/test-program"),
            cmdline: None,
            service: None,
            runnable: true,
        }
    }
}

/// Every capability (bits 0..40).
pub const ALL_CAPS: u64 = (1 << 41) - 1;

/// The current test task's process id.
pub const SELF_PID: u64 = 100;

thread_local! {
    static CURRENT: RefCell<Option<Task>> = const { RefCell::new(None) };
    static OTHERS: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
}

pub fn reset() {
    clear_tasks();
    CURRENT.with_borrow_mut(|c| *c = Some(Task::new(SELF_PID, 0)));
    crate::fake::linux::proc::add(SELF_PID, 1);
    wait::reset();
    SLEEPS.set(0);
}

/// Drops every task (their descriptors close).
pub fn clear_tasks() {
    let c = CURRENT.with_borrow_mut(|c| c.take());
    let o = OTHERS.with_borrow_mut(|o| core::mem::take(o));
    drop(c);
    drop(o);
}

/// Runs `f` on the current task (test helper; panics if there is none).
pub fn current<R>(f: impl FnOnce(&mut Task) -> R) -> R {
    with_current_task_mut(f).expect("no current task")
}

/// Sets the current task's real, effective and saved ids, and drops its capabilities
/// unless `uid` is 0.
pub fn set_ids(uid: u32, gid: u32) {
    current(|t| {
        (t.uid, t.euid, t.suid) = (uid, uid, uid);
        (t.gid, t.egid, t.sgid) = (gid, gid, gid);
        t.caps.effective = if uid == 0 { ALL_CAPS } else { 0 };
    });
}

/// Sets the current task's effective capabilities.
pub fn set_caps(caps: u64) {
    current(|t| t.caps.effective = caps);
}

/// Adds another process `pid` owned by `uid` (a task and a process-table entry); returns
/// its descriptor table.
pub fn add_process(pid: u64, uid: u32) -> SharedFdTable {
    let t = Task::new(pid, uid);
    let fds = t.fds.clone();
    OTHERS.with_borrow_mut(|o| o.push(t));
    crate::fake::linux::proc::add(pid, SELF_PID);
    fds
}

/// Runs `f` on another process's task.
pub fn with_other<R>(pid: u64, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    OTHERS.with_borrow_mut(|o| o.iter_mut().find(|t| t.tgid == pid).map(f))
}

pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    CURRENT.with_borrow_mut(|c| c.as_mut().map(f))
}

pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut FdTable) -> R) -> R {
    let fds = CURRENT.with_borrow(|c| c.as_ref().map(|t| t.fds.clone())).expect("no current task");
    let mut g = fds.lock();
    f(&mut g)
}

thread_local! {
    static SLEEPS: Cell<u64> = const { Cell::new(0) };
}

/// *stub* Sleeping moves the fake clock (and runs the wait hook: another thread's turn).
pub fn sleep_ticks(ticks: u64) {
    crate::fake::arch::TICKS.set(crate::fake::arch::TICKS.get() + ticks);
    SLEEPS.set(SLEEPS.get() + 1);
    if SLEEPS.get() > 100_000 {
        panic!("sleep loop: the code under test never stops sleeping");
    }
    wait::run_hook();
}

pub mod scheduler {
    use core::sync::atomic::AtomicU64;
    pub const CPU_USER: usize = 0;
    pub const CPU_SYSTEM: usize = 1;
    pub const CPU_IDLE: usize = 2;
    pub static CPU_TIMES: [[AtomicU64; 3]; crate::arch::smp::MAX_CPUS] = [const { [const { AtomicU64::new(0) }; 3] }; 16];
    pub static LOAD_AVG: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
}

/// *stub* The scheduler: lookups among the current task and [`add_process`]'s.
pub struct Scheduler;
pub static SCHEDULER: Scheduler = Scheduler;
pub struct SchedulerGuard;

impl Scheduler {
    pub fn lock(&self) -> SchedulerGuard {
        SchedulerGuard
    }
}

impl SchedulerGuard {
    pub fn with_process<R>(&mut self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        let mine = CURRENT.with_borrow(|c| c.as_ref().is_some_and(|t| t.tgid == tgid));
        if mine {
            return CURRENT.with_borrow(|c| c.as_ref().map(f));
        }
        OTHERS.with_borrow(|o| o.iter().find(|t| t.tgid == tgid).map(f))
    }
    pub fn process_runnable(&self, tgid: u64) -> bool {
        let mine = CURRENT.with_borrow(|c| c.as_ref().filter(|t| t.tgid == tgid).map(|t| t.runnable));
        mine.or_else(|| OTHERS.with_borrow(|o| o.iter().find(|t| t.tgid == tgid).map(|t| t.runnable))).unwrap_or(false)
    }
    /// (running, total)
    pub fn task_counts(&self) -> (usize, usize) {
        let n = 1 + OTHERS.with_borrow(|o| o.len());
        let running = CURRENT.with_borrow(|c| c.as_ref().map_or(0, |t| t.runnable as usize)) + OTHERS.with_borrow(|o| o.iter().filter(|t| t.runnable).count());
        (running, n)
    }
    pub fn exe_of(&self, tgid: u64) -> Option<String> {
        let mut s = SchedulerGuard;
        s.with_process(tgid, |t| t.exe.clone())
    }
}

pub mod wait {
    //! Wait queues count wake-ups; a wait runs the test's hook (another thread's turn) or,
    //! without one, fails the test with [`WOULD_BLOCK`].
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::cell::{Cell, RefCell};

    pub const WOULD_BLOCK: &str = "fake wait: the operation would block";

    thread_local! {
        static HOOK: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
        static WAITS: Cell<u64> = const { Cell::new(0) };
    }

    pub fn reset() {
        HOOK.with_borrow_mut(|h| *h = None);
        WAITS.set(0);
    }

    /// Runs `f` whenever the code under test would sleep (in place of the other threads).
    pub fn on_wait(f: impl FnMut() + 'static) {
        HOOK.with_borrow_mut(|h| *h = Some(Box::new(f)));
    }

    /// Removes the wait hook.
    pub fn clear_on_wait() {
        HOOK.with_borrow_mut(|h| *h = None);
    }

    /// How many waits the code under test made.
    pub fn waits() -> u64 {
        WAITS.get()
    }

    /// Runs the hook if there is one; `false` if there is none.
    pub(crate) fn run_hook() -> bool {
        let taken = HOOK.with_borrow_mut(|h| h.take());
        match taken {
            Some(mut f) => {
                f();
                HOOK.with_borrow_mut(|h| {
                    if h.is_none() {
                        *h = Some(f);
                    }
                });
                true
            }
            None => false,
        }
    }

    fn block(deadline: Option<u64>) {
        WAITS.set(WAITS.get() + 1);
        if WAITS.get() > 100_000 {
            panic!("wait loop: the code under test never stops waiting");
        }
        if run_hook() {
            return;
        }
        match deadline {
            Some(d) => crate::fake::arch::TICKS.set(crate::fake::arch::TICKS.get().max(d)),
            None => panic!("{}", WOULD_BLOCK),
        }
    }

    #[derive(Default)]
    pub struct WaitQueue {
        wakes: AtomicU64,
    }

    impl WaitQueue {
        pub const fn new() -> Self {
            WaitQueue { wakes: AtomicU64::new(0) }
        }
        pub fn new_shared() -> Arc<Self> {
            Arc::new(WaitQueue::new())
        }
        pub fn register(&self) {}
        pub fn unregister(&self) {}
        pub fn wake_all(&self) {
            self.wakes.fetch_add(1, Ordering::Relaxed);
            crate::fake::count("wake");
        }
        /// Wake-ups of this queue.
        pub fn wakes(&self) -> u64 {
            self.wakes.load(Ordering::Relaxed)
        }
    }

    pub enum QueueRef {
        Static(&'static WaitQueue),
        Shared(Arc<WaitQueue>),
    }

    #[derive(Default)]
    pub struct WaitSet {
        queues: Vec<QueueRef>,
    }

    impl WaitSet {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn len(&self) -> usize {
            self.queues.len()
        }
        pub fn register(&self) {}
        pub fn wait(&self, deadline: Option<u64>) {
            block(deadline);
        }
    }

    /// Sleeps until tick `deadline` or a wake of a registered queue.
    pub fn wait(deadline: Option<u64>) {
        block(deadline);
    }
}
