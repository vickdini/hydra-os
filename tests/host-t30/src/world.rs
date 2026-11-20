//! A one-CPU simulation of the scheduler for the forwarding core's host tests.
//!
//! Every fake task runs on an OS thread of its own, but only one runs at a time: the
//! *baton* (the world's current task) says which. A task gives the CPU up exactly where the
//! kernel's would: the yield vector (`int 0x81`), the direct-switch vector (`int 0x82`),
//! `task::yield_now`, `wait::wait`. The scheduler then picks the next ready task (round
//! robin, deterministic), advancing the fake clock to the earliest deadline when only
//! sleepers are left. So a test drives a request table race step by step, as on one CPU,
//! with the kernel's own code on both sides.
//!
//! Lost wake-ups are caught: when the running task blocks and no task can ever run again
//! (no ready task, no deadline), the world reports a **deadlock** naming the blocked
//! tasks, and the test fails.
//!
//! Every block, wake, direct switch and hand-off is recorded in [`World::log`], for the
//! tests to check how a call went (a direct switch or a wake, who ran when).

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crate::fs::SharedFdTable;
use crate::memory::vm::Mm;
use crate::task::{TaskId, TaskPersonality, TaskState};

/// Preemptions to make in `task::block_current` before it blocks (a timer tick that lets
/// the other tasks run between a waiter's enqueue and its block).
pub static PREEMPT_BEFORE_BLOCK: AtomicU64 = AtomicU64::new(0);

/// The fake clock, in nanoseconds since boot (a tick is 10 ms).
pub static NOW_NS: AtomicU64 = AtomicU64::new(0);
pub const TICK_NS: u64 = 10_000_000;

/// Capabilities as the forwarding code reads them.
#[derive(Clone, Copy, Default, Debug)]
pub struct Caps {
    pub in_userns: bool,
    pub effective: u64,
}

/// `seccomp` state as the forwarding code reads it.
#[derive(Clone, Copy, Default, Debug)]
pub struct Seccomp {
    pub mode: u32,
}

/// A fake task: the fields the kernel code under test reads.
pub struct Task {
    pub id: TaskId,
    pub name: String,
    pub state: TaskState,
    pub event_wait: bool,
    pub wake_pending: bool,
    /// Blocked on the lock-free path (`BLOCK_NOBKL` was set when it gave the CPU up).
    pub nobkl_wait: bool,
    pub tgid: u64,
    pub uid: u32,
    pub euid: u32,
    pub suid: u32,
    pub gid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub caps: Caps,
    pub seccomp: Seccomp,
    pub personality: TaskPersonality,
    pub service: Option<u32>,
    pub mm: Option<Arc<spin::Mutex<Mm>>>,
    pub fds: SharedFdTable,
}

impl Task {
    /// A Linux thread `id` of process `tgid` (uid 1000), with an empty descriptor table.
    pub fn linux(id: u64, tgid: u64) -> Task {
        Task {
            id: TaskId(id),
            name: format!("t{id}"),
            state: TaskState::Ready,
            event_wait: false,
            wake_pending: false,
            nobkl_wait: false,
            tgid,
            uid: 1000,
            euid: 1000,
            suid: 1000,
            gid: 1000,
            egid: 1000,
            sgid: 1000,
            caps: Caps::default(),
            seccomp: Seccomp::default(),
            personality: TaskPersonality::Linux,
            service: None,
            mm: None,
            fds: Arc::new(spin::Mutex::new(crate::fs::FdTable::new())),
        }
    }

    /// A service thread `id` of process `tgid` serving endpoint `ep` (a ring-3 server).
    pub fn server(id: u64, tgid: u64, ep: u32) -> Task {
        let mut t = Task::linux(id, tgid);
        t.personality = TaskPersonality::Hydra;
        t.service = Some(ep);
        t.uid = 0;
        t.euid = 0;
        t.suid = 0;
        t.gid = 0;
        t.egid = 0;
        t.sgid = 0;
        t
    }
}

/// One entry of the world's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ev {
    /// Task blocked itself (`block_current`).
    Block(u64),
    /// `unblock_task` made task ready (it was blocked).
    Unblock(u64),
    /// A wait queue's wake made task ready.
    Wake(u64),
    /// The CPU went from the first task to the second (any switch).
    Switch(u64, u64),
    /// A direct switch (`int 0x82`) from the first task to the second.
    Direct(u64, u64),
    /// A direct switch refused, with the reason.
    DirectFail(u64, &'static str),
    /// A hand-off began: caller, server.
    Handoff(u64, u64),
    /// A hand-off ended: its caller resumes.
    HandoffEnd(u64),
    /// A deadline passed: the clock moved to this tick.
    Clock(u64),
    /// The task ended.
    Exit(u64),
    /// `kill_group` of a process.
    Kill(u64),
}

#[derive(Clone, Copy)]
struct Handoff {
    server: u64,
    caller: u64,
    deadline: u64,
}

/// The simulated machine.
pub struct World {
    pub tasks: Vec<Task>,
    /// Index of the running task.
    pub cur: usize,
    handoffs: Vec<Handoff>,
    pub log: Vec<Ev>,
    killed: bool,
    deadlock: Option<String>,
    panics: Vec<String>,
    /// `task::is_active()` (the scheduler runs).
    pub active: bool,
    /// Tasks spawned by kernel code (`task::spawn`): `(name, entry)`, not run.
    pub spawned: Vec<&'static str>,
    pub killed_groups: Vec<u64>,
}

static WORLD: Mutex<World> = Mutex::new(World::empty());
static CV: Condvar = Condvar::new();
/// Wakes recorded by `WaitQueue::wake_all` (any context), applied under the world's lock.
static DEFERRED: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// Threads of the tasks spawned in this world (joined at the end).
static THREADS: Mutex<Vec<std::thread::JoinHandle<()>>> = Mutex::new(Vec::new());
/// Serializes the tests that use the world (and every other kernel global).
static TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static MY_TID: Cell<u64> = const { Cell::new(u64::MAX) };
    static BKL: Cell<bool> = const { Cell::new(false) };
}

/// The payload a task thread unwinds with when the world ends.
struct Killed;

impl World {
    const fn empty() -> World {
        World { tasks: Vec::new(), cur: usize::MAX, handoffs: Vec::new(), log: Vec::new(), killed: false, deadlock: None, panics: Vec::new(), active: false, spawned: Vec::new(), killed_groups: Vec::new() }
    }

    fn idx(&self, id: u64) -> Option<usize> {
        self.tasks.iter().position(|t| t.id.0 == id)
    }

    // ------------------------------------------------------------------
    // The scheduler methods the kernel code calls (`SCHEDULER.lock().x()`)
    // ------------------------------------------------------------------

    pub fn current_task_id(&self) -> TaskId {
        self.tasks.get(self.cur).map_or(TaskId(0), |t| t.id)
    }

    pub fn current_index(&self) -> usize {
        self.cur
    }

    pub fn current_task_mut<R>(&mut self, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        let c = self.cur;
        self.tasks.get_mut(c).map(f)
    }

    pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        let i = self.idx(id.0)?;
        if self.tasks[i].state == TaskState::Dead {
            return None;
        }
        Some(f(&mut self.tasks[i]))
    }

    pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        self.tasks.iter().find(|t| t.tgid == tgid && t.state != TaskState::Dead).map(f)
    }

    pub fn current_fds(&self) -> Option<SharedFdTable> {
        self.tasks.get(self.cur).map(|t| t.fds.clone())
    }

    pub fn block_current(&mut self) -> TaskId {
        let c = self.cur;
        match self.tasks.get_mut(c) {
            Some(t) => {
                t.state = TaskState::Blocked;
                let id = t.id;
                self.log.push(Ev::Block(id.0));
                id
            }
            None => TaskId(0),
        }
    }

    pub fn unblock_task(&mut self, id: TaskId) -> bool {
        match self.idx(id.0) {
            Some(i) if self.tasks[i].state == TaskState::Blocked => {
                self.tasks[i].state = TaskState::Ready;
                self.log.push(Ev::Unblock(id.0));
                true
            }
            _ => false,
        }
    }

    pub fn is_task_alive(&self, id: TaskId) -> bool {
        self.idx(id.0).is_some_and(|i| self.tasks[i].state != TaskState::Dead)
    }

    /// The real one's wake: an event-waiting task becomes ready, any other keeps it.
    pub fn wake_task(&mut self, id: u64) {
        let Some(i) = self.idx(id) else { return };
        let t = &mut self.tasks[i];
        match t.state {
            TaskState::Dead => {}
            TaskState::Blocked | TaskState::Sleeping { .. } if t.event_wait => {
                t.state = TaskState::Ready;
                t.event_wait = false;
                self.log.push(Ev::Wake(id));
            }
            _ => t.wake_pending = true,
        }
    }

    pub fn apply_wakes(&mut self) {
        let ids: Vec<u64> = std::mem::take(&mut *DEFERRED.lock().unwrap());
        for id in ids {
            self.wake_task(id);
        }
    }

    pub fn event_wait_current(&mut self, deadline: Option<u64>) -> bool {
        self.apply_wakes();
        let c = self.cur;
        let Some(t) = self.tasks.get_mut(c) else { return false };
        if t.wake_pending {
            t.wake_pending = false;
            return false;
        }
        t.event_wait = true;
        t.state = match deadline {
            Some(wake_tick) => TaskState::Sleeping { wake_tick },
            None => TaskState::Blocked,
        };
        true
    }

    pub fn begin_handoff(&mut self, server: u64, deadline: u64) -> bool {
        if self.handoffs.len() >= 8 {
            return false;
        }
        let caller = self.current_task_id().0;
        self.handoffs.push(Handoff { server, caller, deadline });
        crate::task::scheduler::HANDOFF_ACTIVE.store(true, Ordering::Release);
        self.log.push(Ev::Handoff(caller, server));
        self.block_current();
        true
    }

    fn remove_handoff(&mut self, i: usize) {
        let h = self.handoffs.remove(i);
        crate::task::scheduler::HANDOFF_ACTIVE.store(!self.handoffs.is_empty(), Ordering::Release);
        self.log.push(Ev::HandoffEnd(h.caller));
        if let Some(c) = self.idx(h.caller) {
            if self.tasks[c].state == TaskState::Blocked {
                self.tasks[c].state = TaskState::Ready;
            }
        }
    }

    pub fn end_handoff(&mut self, server: u64) {
        if let Some(i) = self.handoffs.iter().rposition(|h| h.server == server) {
            self.remove_handoff(i);
        }
    }

    pub fn end_handoff_of(&mut self, caller: u64) {
        if let Some(i) = self.handoffs.iter().rposition(|h| h.caller == caller) {
            self.remove_handoff(i);
        }
    }

    pub fn end_handoffs_to(&mut self, server: u64) {
        while let Some(i) = self.handoffs.iter().rposition(|h| h.server == server) {
            self.remove_handoff(i);
        }
    }

    pub fn in_handoff(&self, id: u64) -> bool {
        self.handoffs.iter().any(|h| h.server == id || h.caller == id)
    }

    /// Ends every thread of process `tgid` (not the running one: the real one retires it).
    pub fn kill_group(&mut self, tgid: u64) -> usize {
        self.killed_groups.push(tgid);
        self.log.push(Ev::Kill(tgid));
        let cur = self.cur;
        let mut n = 0;
        for (i, t) in self.tasks.iter_mut().enumerate() {
            if t.tgid == tgid && t.state != TaskState::Dead {
                n += 1;
                if i != cur {
                    t.state = TaskState::Dead;
                }
            }
        }
        n
    }

    pub fn kill_linux_tasks(&mut self) -> usize {
        0
    }

    pub fn set_task_credentials(&mut self, _id: TaskId, _uid: u32, _gid: u32) {}

    // ------------------------------------------------------------------
    // Switching
    // ------------------------------------------------------------------

    /// The next task to run after the current one (`None`: nothing can ever run).
    fn pick(&mut self) -> Option<usize> {
        loop {
            self.apply_wakes();
            let n = self.tasks.len();
            let start = if self.cur < n { self.cur + 1 } else { 0 };
            for k in 0..n {
                let i = (start + k) % n;
                if self.tasks[i].state == TaskState::Ready {
                    return Some(i);
                }
            }
            // Only sleepers: the clock moves to the earliest deadline
            let sleep = self.tasks.iter().filter_map(|t| if let TaskState::Sleeping { wake_tick } = t.state { Some(wake_tick) } else { None }).min();
            let hand = self.handoffs.iter().map(|h| h.deadline).min();
            let next = match (sleep, hand) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) | (None, Some(a)) => a,
                (None, None) => return None,
            };
            let now = NOW_NS.load(Ordering::Acquire) / TICK_NS;
            if next > now {
                NOW_NS.store(next * TICK_NS, Ordering::Release);
            }
            self.log.push(Ev::Clock(next.max(now)));
            let now = next.max(now);
            for t in self.tasks.iter_mut() {
                if let TaskState::Sleeping { wake_tick } = t.state {
                    if wake_tick <= now {
                        t.state = TaskState::Ready;
                        t.event_wait = false;
                    }
                }
            }
            while let Some(i) = self.handoffs.iter().position(|h| h.deadline <= now) {
                self.remove_handoff(i);
            }
        }
    }

    fn describe(&self) -> String {
        self.tasks.iter().filter(|t| t.state != TaskState::Dead).map(|t| format!("{}({}):{:?}", t.id.0, t.name, t.state)).collect::<Vec<_>>().join(", ")
    }
}

/// Hands the baton to task index `next` and waits until the calling task has it again.
fn switch_to(mut w: MutexGuard<'static, World>, next: usize) {
    let me = MY_TID.with(|t| t.get());
    let from = w.tasks.get(w.cur).map_or(0, |t| t.id.0);
    w.cur = next;
    w.tasks[next].state = TaskState::Running;
    let to = w.tasks[next].id.0;
    if from != to {
        w.log.push(Ev::Switch(from, to));
    }
    crate::task::CURRENT_TID.store(to, Ordering::Release);
    crate::task::scheduler::CURRENT_IDX.store(next as u64, Ordering::Release);
    CV.notify_all();
    wait_baton(w, me);
}

/// Waits until task `me` runs (or the world ends: the thread unwinds).
fn wait_baton(mut w: MutexGuard<'static, World>, me: u64) {
    loop {
        if w.killed {
            drop(w);
            std::panic::resume_unwind(Box::new(Killed));
        }
        if let Some(d) = w.deadlock.clone() {
            let main = w.tasks.first().is_some_and(|t| t.id.0 == me);
            drop(w);
            if main {
                panic!("{d}");
            }
            std::panic::resume_unwind(Box::new(Killed));
        }
        if w.tasks.get(w.cur).is_some_and(|t| t.id.0 == me) {
            crate::task::CURRENT_TID.store(me, Ordering::Release);
            return;
        }
        w = CV.wait(w).unwrap();
    }
}

/// Gives the CPU up (the yield vector): the current task blocked itself before, or it only
/// yields (then it stays ready and runs again after the others).
pub fn yield_cpu() {
    let mut w = WORLD.lock().unwrap();
    w.apply_wakes();
    let c = w.cur;
    let nobkl = crate::task::scheduler::BLOCK_NOBKL.load(Ordering::Relaxed) == 1;
    if w.tasks[c].state == TaskState::Running {
        w.tasks[c].state = TaskState::Ready;
    } else {
        w.tasks[c].nobkl_wait = nobkl;
    }
    // The yield vector's direct switch (`ipc::service::hand_back`): to that task if ready
    let to = crate::task::scheduler::DIRECT_TO.swap(0, Ordering::Relaxed);
    let next = to.checked_sub(1).and_then(|t| w.idx(t)).filter(|&i| w.tasks[i].state == TaskState::Ready).or_else(|| w.pick());
    match next {
        Some(i) if i == c => {
            w.tasks[c].state = TaskState::Running;
        }
        Some(i) => switch_to(w, i),
        None => deadlock(w),
    }
}

/// Nothing can run any more: report it (the main thread's test fails with the message).
fn deadlock(mut w: MutexGuard<'static, World>) -> ! {
    let msg = format!("deadlock: task {} blocked and no task can run: [{}]", w.tasks[w.cur].id.0, w.describe());
    w.deadlock = Some(msg.clone());
    let main = w.cur == 0;
    CV.notify_all();
    drop(w);
    if main {
        panic!("{msg}");
    }
    std::panic::resume_unwind(Box::new(Killed));
}

/// The direct-switch vector (`int 0x82`): mirrors `Scheduler::direct_call`'s conditions.
/// Returns 0 once the caller runs again after the switch, 1 at once if it was refused.
pub fn direct_vector() -> u64 {
    use crate::task::scheduler::{BLOCK_NOBKL, DIRECT_EVENT, DIRECT_GUARD, DIRECT_HINT, DIRECT_TO};
    let to = DIRECT_TO.swap(0, Ordering::Relaxed);
    let hint = DIRECT_HINT.load(Ordering::Relaxed) as usize;
    let guard = DIRECT_GUARD.load(Ordering::Relaxed) as *const std::sync::atomic::AtomicBool;
    let mut w = WORLD.lock().unwrap();
    w.apply_wakes();
    let c = w.cur;
    let me = w.tasks[c].id.0;
    let fail = |w: &mut World, why: &'static str| {
        w.log.push(Ev::DirectFail(me, why));
        1
    };
    if !w.handoffs.is_empty() {
        return fail(&mut w, "hand-off");
    }
    let event = hint & DIRECT_EVENT != 0;
    let Some(next) = to.checked_sub(1).and_then(|t| w.idx(t)) else { return fail(&mut w, "no such task") };
    let t = &w.tasks[next];
    let parked = t.state == TaskState::Blocked || (event && t.event_wait && matches!(t.state, TaskState::Sleeping { .. }));
    if next == c || !parked {
        return fail(&mut w, "not parked");
    }
    if !t.nobkl_wait && !bkl_held() {
        return fail(&mut w, "blocked under the kernel lock");
    }
    // SAFETY: the guard is a static flag of the kernel code under test
    if !guard.is_null() && unsafe { (*guard).load(Ordering::SeqCst) } {
        return fail(&mut w, "guard set");
    }
    let keep = w.tasks[c].event_wait && matches!(w.tasks[c].state, TaskState::Blocked | TaskState::Sleeping { .. });
    if w.tasks[c].state == TaskState::Ready {
        return fail(&mut w, "current ready");
    }
    if event {
        w.tasks[next].event_wait = false;
    }
    if !keep {
        w.tasks[c].state = TaskState::Blocked;
    }
    w.tasks[c].nobkl_wait = BLOCK_NOBKL.load(Ordering::Relaxed) == 1;
    let to = w.tasks[next].id.0;
    w.log.push(Ev::Direct(me, to));
    switch_to(w, next);
    0
}

// ----------------------------------------------------------------------
// The kernel lock, per task (one CPU: bookkeeping only)
// ----------------------------------------------------------------------

pub fn bkl_held() -> bool {
    BKL.with(|b| b.get())
}
pub fn bkl_enter() {
    BKL.with(|b| b.set(true));
}
pub fn bkl_exit() {
    BKL.with(|b| b.set(false));
}

// ----------------------------------------------------------------------
// Wake-ups from any context
// ----------------------------------------------------------------------

/// Records wakes of `ids` and applies them now if the world's lock is free (as the real
/// `wait::flush`).
pub fn defer_wakes(ids: impl IntoIterator<Item = u64>) {
    DEFERRED.lock().unwrap().extend(ids);
    if let Ok(mut w) = WORLD.try_lock() {
        w.apply_wakes();
    }
}

// ----------------------------------------------------------------------
// The scheduler lock
// ----------------------------------------------------------------------

/// `task::SCHEDULER`.
pub struct Scheduler;

impl Scheduler {
    pub fn lock(&self) -> MutexGuard<'static, World> {
        WORLD.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn try_lock(&self) -> Option<MutexGuard<'static, World>> {
        WORLD.try_lock().ok()
    }
}

// ----------------------------------------------------------------------
// Running a test in the world
// ----------------------------------------------------------------------

/// A test's world: the test's own thread is task `tasks[0]` (running). Ends (joining every
/// task thread) when dropped; a task that panicked fails the test then.
pub struct Sim {
    _serial: MutexGuard<'static, ()>,
}

/// Takes the global test lock without a world (tests of plain functions that touch globals).
pub fn serial() -> MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

impl Sim {
    /// A new world whose running task is `main` (on the calling thread).
    pub fn new(mut main: Task) -> Sim {
        let serial = serial();
        let mut w = WORLD.lock().unwrap_or_else(|e| e.into_inner());
        *w = World::empty();
        w.active = true;
        ACTIVE.store(true, Ordering::Release);
        main.state = TaskState::Running;
        let id = main.id.0;
        w.tasks.push(main);
        w.cur = 0;
        drop(w);
        DEFERRED.lock().unwrap().clear();
        MY_TID.with(|t| t.set(id));
        BKL.with(|b| b.set(false));
        NOW_NS.store(0, Ordering::Release);
        crate::task::CURRENT_TID.store(id, Ordering::Release);
        crate::task::scheduler::CURRENT_IDX.store(0, Ordering::Release);
        crate::task::scheduler::HANDOFF_ACTIVE.store(false, Ordering::Release);
        crate::task::scheduler::DIRECT_TO.store(0, Ordering::Release);
        crate::task::scheduler::BLOCK_NOBKL.store(0, Ordering::Release);
        PREEMPT_BEFORE_BLOCK.store(0, Ordering::Release);
        crate::fake::reset();
        Sim { _serial: serial }
    }

    /// Adds task `t` (ready) running `f` on a thread of its own; it runs when the
    /// scheduler picks it.
    pub fn spawn(&self, t: Task, f: impl FnOnce() + Send + 'static) -> u64 {
        let id = t.id.0;
        WORLD.lock().unwrap().tasks.push(t);
        let h = std::thread::Builder::new()
            .name(format!("task-{id}"))
            .spawn(move || {
                MY_TID.with(|t| t.set(id));
                let w = WORLD.lock().unwrap();
                let start = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wait_baton(w, id)));
                if start.is_err() {
                    return;
                }
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
                let mut w = WORLD.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(e) = r {
                    if e.downcast_ref::<Killed>().is_some() {
                        return;
                    }
                    let msg = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                    w.panics.push(format!("task {id}: {msg}"));
                }
                if w.killed || w.deadlock.is_some() {
                    return;
                }
                let c = w.cur;
                w.tasks[c].state = TaskState::Dead;
                w.log.push(Ev::Exit(id));
                match w.pick() {
                    Some(i) => {
                        let from = id;
                        w.cur = i;
                        w.tasks[i].state = TaskState::Running;
                        let to = w.tasks[i].id.0;
                        w.log.push(Ev::Switch(from, to));
                        crate::task::CURRENT_TID.store(to, Ordering::Release);
                        crate::task::scheduler::CURRENT_IDX.store(i as u64, Ordering::Release);
                        CV.notify_all();
                    }
                    None => {
                        w.deadlock = Some(format!("deadlock: task {id} ended and no task can run: [{}]", w.describe()));
                        CV.notify_all();
                    }
                }
            })
            .unwrap();
        THREADS.lock().unwrap().push(h);
        id
    }

    /// The log so far.
    pub fn log(&self) -> Vec<Ev> {
        WORLD.lock().unwrap().log.clone()
    }

    /// Clears the log.
    pub fn clear_log(&self) {
        WORLD.lock().unwrap().log.clear();
    }

    /// Task `id`'s state.
    pub fn state(&self, id: u64) -> TaskState {
        let w = WORLD.lock().unwrap();
        w.idx(id).map_or(TaskState::Dead, |i| w.tasks[i].state)
    }

    /// Runs `f` on task `id`'s entry.
    pub fn with_task<R>(&self, id: u64, f: impl FnOnce(&mut Task) -> R) -> R {
        let mut w = WORLD.lock().unwrap();
        let i = w.idx(id).expect("task");
        f(&mut w.tasks[i])
    }

    /// Lets every other ready task run until it blocks (the calling task yields).
    pub fn run_others(&self) {
        yield_cpu();
    }

    /// Moves the fake clock forward by `ticks`.
    pub fn advance(&self, ticks: u64) {
        NOW_NS.fetch_add(ticks * TICK_NS, Ordering::AcqRel);
    }

    /// Tasks kernel code spawned (`task::spawn`), by name.
    pub fn spawned(&self) -> Vec<&'static str> {
        WORLD.lock().unwrap().spawned.clone()
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        {
            let mut w = WORLD.lock().unwrap_or_else(|e| e.into_inner());
            w.killed = true;
            CV.notify_all();
        }
        let threads: Vec<_> = std::mem::take(&mut *THREADS.lock().unwrap_or_else(|e| e.into_inner()));
        for t in threads {
            let _ = t.join();
        }
        let panics = {
            let mut w = WORLD.lock().unwrap_or_else(|e| e.into_inner());
            let p = std::mem::take(&mut w.panics);
            *w = World::empty();
            p
        };
        crate::task::CURRENT_TID.store(0, Ordering::Release);
        ACTIVE.store(false, Ordering::Release);
        if !panics.is_empty() && !std::thread::panicking() {
            panic!("a task failed: {}", panics.join("; "));
        }
    }
}

/// Whether the world runs (`task::is_active`).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// `task::is_active()` (set while a world runs).
pub static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Kernel code spawned a task (not run on the host).
pub fn note_spawn(name: &'static str) {
    WORLD.lock().unwrap().spawned.push(name);
}

