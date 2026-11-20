//! Host stand-ins for the kernel services the Linux process files call (Group 29).
//!
//! Unlike `tests/host`'s fakes, the scheduler here holds real task records: a per-thread
//! list of [`Task`]s and the id of the current one. `SCHEDULER.lock()` marks the
//! scheduler locked for as long as the guard lives, so kernel code that would take the
//! (non-reentrant) scheduler lock twice panics with [`DEADLOCK`] instead of hanging.
//!
//! Most kernel files compiled here keep global tables (`static Mutex<BTreeMap<..>>`), so
//! every test starts with [`setup`], which serialises the tests of this binary and resets
//! the fakes.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

// ------------------------------------------------------------------ set-up

/// Serialises the tests of one binary (they share the kernel's global tables) and resets
/// every fake. Hold the guard for the whole test.
pub fn setup() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    g
}

thread_local! {
    /// What `signal_pending()` reports (when the real proc.rs is not asked).
    pub static SIGNAL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// Number of wait-queue wakes.
    pub static WAKES: Cell<usize> = const { Cell::new(0) };
    /// Calls recorded by stubs: "module::function(args)".
    pub static CALLS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Return values for stubs, by name (default: 0).
    pub static RETS: RefCell<BTreeMap<String, i64>> = const { RefCell::new(BTreeMap::new()) };
    /// Timer ticks reported by `pit::ticks()` (1 kHz).
    pub static TICKS: Cell<u64> = const { Cell::new(1_000) };
    /// RTC seconds set through `rtc::set_now`.
    pub static RTC_SET: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    /// Whether the fake EFER reports NX as enabled.
    pub static NX_ENABLED: Cell<bool> = const { Cell::new(true) };
    /// Ranges passed to `make_user_accessible`.
    pub static USER_RANGES: RefCell<Vec<(u64, usize)>> = const { RefCell::new(Vec::new()) };
    /// Files visible through `ZfsClient` by path (contents).
    pub static ZFS_FILES: RefCell<BTreeMap<String, Vec<u8>>> = const { RefCell::new(BTreeMap::new()) };
    /// Inode mode and contents for the inode-level `ZfsClient` calls.
    pub static INODES: RefCell<BTreeMap<u64, (u32, Vec<u8>)>> = const { RefCell::new(BTreeMap::new()) };
    /// Owner (uid, gid) of an inode (`ZfsClient::getattr`; root when absent).
    pub static INODE_OWNERS: RefCell<BTreeMap<u64, (u32, u32)>> = const { RefCell::new(BTreeMap::new()) };
    /// Path -> inode, for `vfs::resolve`.
    pub static INODE_PATHS: RefCell<BTreeMap<String, u64>> = const { RefCell::new(BTreeMap::new()) };
    /// Tasks woken through the scheduler.
    pub static WOKEN: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    /// Processes whose stopped threads were let run again (`unblock_group`).
    pub static UNBLOCKED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    /// Whether `wait::wait_ns(None)` returns at once instead of reporting that it would
    /// block (for loops that re-check a condition another fake changes).
    pub static SPIN_WAITS: Cell<bool> = const { Cell::new(false) };
    /// A hook run by every wait (lets a test change state "while asleep").
    pub static ON_WAIT: RefCell<Option<Box<dyn FnMut()>>> = RefCell::new(None);
    /// How many waits ran.
    pub static WAITS: Cell<usize> = const { Cell::new(0) };
    /// CPUs online (`smp::online`).
    pub static ONLINE_CPUS: Cell<usize> = const { Cell::new(1) };
    /// The CPU's FS and GS bases (`segments::set_fs_base` / `current_bases`).
    pub static FS_GS: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
    /// System calls the fake Linux server answers (`lx::forward`): number -> result.
    pub static LX_FORWARD: RefCell<BTreeMap<u64, i64>> = const { RefCell::new(BTreeMap::new()) };
    /// `/proc/...` symlink targets (`fs::proc_link`).
    pub static PROC_LINKS: RefCell<BTreeMap<String, String>> = const { RefCell::new(BTreeMap::new()) };
    /// `mount::exec_flags()`: (noexec, nosuid) of the executable's mount.
    pub static MOUNT_EXEC_FLAGS: Cell<(bool, bool)> = const { Cell::new((false, false)) };
    /// File capabilities by inode (`vfs::file_caps`).
    pub static FILE_CAPS: RefCell<BTreeMap<u64, (u64, bool)>> = const { RefCell::new(BTreeMap::new()) };
    /// Pseudo-file paths (`compat::linux::fs::match_pseudo_path`).
    pub static PSEUDO: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Next thread id `spawn_clone` hands out.
    pub static NEXT_TID: Cell<u64> = const { Cell::new(1000) };
    /// Make `spawn_clone` fail.
    pub static CLONE_FAILS: Cell<bool> = const { Cell::new(false) };
    /// Readiness overrides by descriptor object id (`FdTable::readiness`).
    pub static READY: RefCell<BTreeMap<usize, u32>> = const { RefCell::new(BTreeMap::new()) };
    /// What was written to the console descriptors.
    pub static CONSOLE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// The error a failing inode write reports.
    pub static WRITE_ERROR: Cell<&'static str> = const { Cell::new("I/O error") };
    /// The working directory (`vfs::base_dir` with `AT_FDCWD`).
    pub static CWD: RefCell<String> = RefCell::new(String::from("/"));
}

/// Records a stub call.
pub fn rec(s: impl Into<String>) {
    let _ = CALLS.try_with(|v| v.borrow_mut().push(s.into()));
}

/// The calls recorded so far (and forgets them).
pub fn take_calls() -> Vec<String> {
    CALLS.with_borrow_mut(std::mem::take)
}

/// Whether a call starting with `prefix` was recorded.
pub fn called(prefix: &str) -> bool {
    CALLS.with_borrow(|v| v.iter().any(|c| c.starts_with(prefix)))
}

/// The value stub `name` returns (set with [`set_ret`]; 0 by default).
pub fn ret(name: &str) -> i64 {
    RETS.with_borrow(|m| m.get(name).copied().unwrap_or(0))
}

pub fn set_ret(name: &str, v: i64) {
    RETS.with_borrow_mut(|m| m.insert(name.to_string(), v));
}

/// An `Option` dispatcher stub: records "name(num)" and answers `Some(v)` when a test set
/// "name" (all numbers) or "name:num" (that number) with [`set_ret`]; `None` otherwise.
pub fn opt(name: &str, num: u64) -> Option<i64> {
    rec(format!("{name}({num})"));
    RETS.with_borrow(|m| m.get(&format!("{name}:{num}")).or_else(|| m.get(name)).copied())
}

/// Restore every fake to its initial state.
pub fn reset() {
    SIGNAL_PENDING.set(false);
    WAKES.set(0);
    CALLS.with_borrow_mut(|v| v.clear());
    RETS.with_borrow_mut(|m| m.clear());
    TICKS.set(1_000);
    RTC_SET.with_borrow_mut(|v| v.clear());
    NX_ENABLED.set(true);
    USER_RANGES.with_borrow_mut(|v| v.clear());
    ZFS_FILES.with_borrow_mut(|m| m.clear());
    INODES.with_borrow_mut(|m| m.clear());
    INODE_PATHS.with_borrow_mut(|m| m.clear());
    INODE_OWNERS.with_borrow_mut(|m| m.clear());
    WOKEN.with_borrow_mut(|v| v.clear());
    UNBLOCKED.with_borrow_mut(|v| v.clear());
    SPIN_WAITS.set(false);
    ON_WAIT.with_borrow_mut(|h| *h = None);
    WAITS.set(0);
    ONLINE_CPUS.set(1);
    FS_GS.set((0, 0));
    LX_FORWARD.with_borrow_mut(|m| m.clear());
    PROC_LINKS.with_borrow_mut(|m| m.clear());
    MOUNT_EXEC_FLAGS.set((false, false));
    FILE_CAPS.with_borrow_mut(|m| m.clear());
    CWD.with_borrow_mut(|c| *c = String::from("/"));
    CONSOLE.with_borrow_mut(|c| c.clear());
    WRITE_ERROR.set("I/O error");
    READY.with_borrow_mut(|m| m.clear());
    PSEUDO.with_borrow_mut(|v| v.clear());
    NEXT_TID.set(1000);
    CLONE_FAILS.set(false);
    TASKS.with_borrow_mut(|v| v.clear());
    CURRENT.set(0);
    LOCKED.set(false);
    FDS.with_borrow_mut(|f| *f = FdTable::default());
}

// ------------------------------------------------------------------- tasks

/// The kernel's capability sets (mirror of `task::tcb::Caps`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Caps {
    pub effective: u64,
    pub permitted: u64,
    pub keep: bool,
    pub in_userns: bool,
}

impl Caps {
    pub const FULL: u64 = (1 << 41) - 1;
    pub const SETGID: u64 = 1 << 6;
    pub const SETUID: u64 = 1 << 7;
    pub const SYS_BOOT: u64 = 1 << 22;
    pub const fn for_euid(euid: u32) -> Self {
        let all = if euid == 0 { Self::FULL } else { 0 };
        Self { effective: all, permitted: all, keep: false, in_userns: false }
    }
    pub fn has(&self, cap: u64) -> bool {
        !self.in_userns && self.effective & cap != 0
    }
    pub fn on_exec(&mut self, uid: u32, euid: u32) {
        self.permitted = if uid == 0 || euid == 0 { Self::FULL } else { 0 };
        self.effective = if euid == 0 { self.permitted } else { 0 };
        self.keep = false;
    }
    /// Verbatim from the kernel (`Caps::on_uid_change`).
    pub fn on_uid_change(&mut self, old: (u32, u32, u32), new: (u32, u32, u32)) {
        let had_root = old.0 == 0 || old.1 == 0 || old.2 == 0;
        let has_root = new.0 == 0 || new.1 == 0 || new.2 == 0;
        if had_root && !has_root && !self.keep {
            self.permitted = 0;
            self.effective = 0;
        }
        if old.1 == 0 && new.1 != 0 {
            self.effective = 0;
        } else if old.1 != 0 && new.1 == 0 {
            self.effective = self.permitted;
        }
    }
    pub fn enter_userns(&mut self) {
        self.effective = Self::FULL;
        self.permitted = Self::FULL;
        self.in_userns = true;
    }
}

/// Thread id, as in the kernel's `task::TaskId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TaskId(pub u64);

/// Mirror of the kernel's task states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TaskState {
    #[default]
    Ready,
    Running,
    Blocked,
    Sleeping {
        wake_tick: u64,
    },
    Dead,
}

/// Mirror of the kernel's scheduling classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TaskPriority {
    Idle = 0,
    Low = 1,
    #[default]
    Normal = 2,
    High = 3,
    Realtime = 4,
}

/// The saved registers of a task (only the address space root is read here).
#[derive(Clone, Copy, Debug, Default)]
pub struct TaskRegisters {
    pub cr3: u64,
}

/// The parts of the kernel's `Task` the code under test reads and writes.
pub struct Task {
    pub regs: TaskRegisters,
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub priority: TaskPriority,
    pub personality: crate::task::TaskPersonality,
    pub fs_base: u64,
    pub segs: crate::arch::segments::UserSegs,
    pub ldt: Option<crate::arch::segments::SharedLdt>,
    pub debugregs: [u64; 8],
    pub brk: u64,
    pub clear_child_tid: u64,
    pub robust_list: u64,
    pub tgid: u64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub caps: Caps,
    pub seccomp: crate::compat::linux::seccomp::State,
    pub ticks_run: u64,
    pub ticks_sys: u64,
    pub fds: crate::fs::SharedFdTable,
    pub mm: Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>,
    pub exe: Option<Arc<str>>,
    pub cmdline: Option<Arc<[u8]>>,
    pub service: Option<u32>,
    pub syscall_nr: u64,
    pub fpu: Box<crate::arch::idt::FpuState>,
}

impl Task {
    /// A Linux thread `tid` of process `tgid`, root, no address space.
    pub fn new(tid: u64, tgid: u64) -> Task {
        Task {
            regs: TaskRegisters::default(),
            id: TaskId(tid),
            name: "test",
            state: TaskState::Ready,
            priority: TaskPriority::Normal,
            personality: crate::task::TaskPersonality::Linux,
            fs_base: 0,
            segs: Default::default(),
            ldt: None,
            debugregs: [0; 8],
            brk: 0,
            clear_child_tid: 0,
            robust_list: 0,
            tgid,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            fsuid: 0,
            fsgid: 0,
            caps: Caps::for_euid(0),
            seccomp: Default::default(),
            ticks_run: 0,
            ticks_sys: 0,
            fds: Arc::new(spin::Mutex::new(FdTable::default())),
            mm: None,
            exe: None,
            cmdline: None,
            service: None,
            syscall_nr: 0,
            fpu: Box::new(crate::arch::idt::FpuState::new()),
        }
    }

    /// Same ids for real, effective, saved and file system.
    pub fn with_ids(mut self, uid: u32, gid: u32) -> Task {
        self.uid = uid;
        self.euid = uid;
        self.suid = uid;
        self.fsuid = uid;
        self.gid = gid;
        self.egid = gid;
        self.sgid = gid;
        self.fsgid = gid;
        self.caps = Caps::for_euid(uid);
        self
    }

    pub fn join_cmdline<'a>(args: impl IntoIterator<Item = &'a [u8]>) -> Arc<[u8]> {
        let mut out = Vec::new();
        for a in args {
            out.extend_from_slice(a);
            out.push(0);
        }
        Arc::from(out)
    }

    pub fn exe_path(&self) -> &str {
        self.exe.as_deref().unwrap_or(self.name)
    }
}

thread_local! {
    /// Every task the fake scheduler knows (this test thread's).
    pub static TASKS: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
    /// The current task's id (0: none).
    pub static CURRENT: Cell<u64> = const { Cell::new(0) };
    /// Whether a scheduler guard is alive.
    pub static LOCKED: Cell<bool> = const { Cell::new(false) };
}

/// Message of the panic raised when kernel code takes the scheduler lock twice.
pub const DEADLOCK: &str = "fake scheduler: lock taken twice (a deadlock in the kernel)";

/// Adds a task to the fake scheduler.
pub fn add_task(t: Task) {
    TASKS.with_borrow_mut(|v| v.push(t));
}

/// Adds a task and makes it the current one.
pub fn run_as(t: Task) {
    CURRENT.set(t.id.0);
    add_task(t);
}

/// Makes task `tid` current.
pub fn switch_to(tid: u64) {
    CURRENT.set(tid);
}

/// Runs `f` on task `tid` directly (test helper; no lock).
pub fn task<R>(tid: u64, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    TASKS.with_borrow_mut(|v| v.iter_mut().find(|t| t.id.0 == tid).map(f))
}

/// Removes task `tid` (it exited and was reaped).
pub fn remove_task(tid: u64) {
    TASKS.with_borrow_mut(|v| v.retain(|t| t.id.0 != tid));
}

pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let mut g = SCHEDULER.lock();
    g.current_task_mut(f)
}

/// Stand-in for `task::SCHEDULER`.
pub struct Scheduler;

pub static SCHEDULER: Scheduler = Scheduler;

pub struct SchedulerGuard(());

impl Scheduler {
    pub fn lock(&self) -> SchedulerGuard {
        if LOCKED.get() {
            panic!("{}", DEADLOCK);
        }
        LOCKED.set(true);
        SchedulerGuard(())
    }
    pub fn try_lock(&self) -> Option<SchedulerGuard> {
        if LOCKED.get() {
            return None;
        }
        Some(self.lock())
    }
}

impl Drop for SchedulerGuard {
    fn drop(&mut self) {
        let _ = LOCKED.try_with(|l| l.set(false));
    }
}

impl SchedulerGuard {
    pub fn current_task_mut<R>(&mut self, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        let cur = CURRENT.get();
        TASKS.with_borrow_mut(|v| v.iter_mut().find(|t| t.id.0 == cur).map(f))
    }
    pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        TASKS.with_borrow_mut(|v| v.iter_mut().find(|t| t.id == id).map(f))
    }
    pub fn with_task<R>(&self, id: TaskId, f: impl FnOnce(&Task) -> R) -> Option<R> {
        TASKS.with_borrow(|v| v.iter().find(|t| t.id == id).map(f))
    }
    /// Every live task (as the kernel's: dead ones are skipped).
    pub fn for_each_task_mut(&mut self, mut f: impl FnMut(&mut Task)) {
        TASKS.with_borrow_mut(|v| v.iter_mut().filter(|t| t.state != TaskState::Dead).for_each(|t| f(t)));
    }
    pub fn for_each_task(&self, mut f: impl FnMut(&Task)) {
        TASKS.with_borrow(|v| v.iter().for_each(|t| f(t)));
    }
    /// CPU time (user, system ticks) of process `tgid`'s live threads.
    pub fn process_cpu(&self, tgid: u64) -> (u64, u64) {
        TASKS.with_borrow(|v| {
            v.iter().filter(|t| t.tgid == tgid).fold((0, 0), |a, t| (a.0 + t.ticks_run, a.1 + t.ticks_sys))
        })
    }
    pub fn unblock_group(&mut self, tgid: u64) {
        UNBLOCKED.with_borrow_mut(|v| v.push(tgid));
    }
    pub fn exe_of(&self, pid: u64) -> Option<String> {
        TASKS.with_borrow(|v| v.iter().find(|t| t.tgid == pid).and_then(|t| t.exe.as_deref().map(String::from)))
    }
    /// *mirror* of the kernel's `spawn_clone`, cut down: a new task (thread or process)
    /// copying the current one; `CLONE_VM` shares the address space, `CLONE_FILES` the
    /// descriptor table, `CLONE_THREAD` the thread group. Recorded with its arguments.
    pub fn spawn_clone(&mut self, frame: &crate::arch::syscall::SyscallFrame, args: [u64; 5]) -> Result<TaskId, &'static str> {
        rec(format!("spawn_clone({:#x},{:#x})", args[0], args[1]));
        if CLONE_FAILS.get() {
            return Err("Out of memory");
        }
        let [flags, _stack, _ptid, _ctid, _tls] = args;
        let tid = NEXT_TID.get();
        NEXT_TID.set(tid + 1);
        let cur = CURRENT.get();
        let child = TASKS.with_borrow(|v| {
            let p = v.iter().find(|t| t.id.0 == cur)?;
            let mut c = Task::new(tid, if flags & 0x10000 != 0 { p.tgid } else { tid });
            c.uid = p.uid;
            c.gid = p.gid;
            c.euid = p.euid;
            c.egid = p.egid;
            c.suid = p.suid;
            c.sgid = p.sgid;
            c.fsuid = p.fsuid;
            c.fsgid = p.fsgid;
            c.caps = p.caps;
            c.personality = p.personality;
            c.seccomp = p.seccomp.clone();
            c.fds = if flags & 0x400 != 0 { p.fds.clone() } else { p.fds.lock().fork_copy().into_shared() };
            c.mm = if flags & 0x100 != 0 { p.mm.clone() } else { None };
            c.exe = p.exe.clone();
            Some(c)
        });
        let c = child.ok_or("Scheduler not initialized")?;
        TASKS.with_borrow_mut(|v| v.push(c));
        let _ = frame;
        Ok(TaskId(tid))
    }
    /// Kills the current task's sibling threads (execve's de-thread): recorded and done.
    pub fn terminate_current_group(&mut self) {
        let cur = CURRENT.get();
        TASKS.with_borrow_mut(|v| {
            let tgid = v.iter().find(|t| t.id.0 == cur).map(|t| t.tgid);
            for t in v.iter_mut() {
                if Some(t.tgid) == tgid && t.id.0 != cur {
                    t.state = TaskState::Dead;
                }
            }
        });
        rec("terminate_current_group()");
    }
    pub fn note_loaded_cr3(&mut self, cr3: u64) {
        rec(format!("note_loaded_cr3({cr3:#x})"));
    }
    pub fn current_task_id(&self) -> TaskId {
        TaskId(CURRENT.get())
    }
    pub fn wake_task(&mut self, id: u64) {
        WOKEN.with_borrow_mut(|v| v.push(id));
    }
    pub fn unblock(&mut self, id: TaskId) -> bool {
        WOKEN.with_borrow_mut(|v| v.push(id.0));
        true
    }
    /// The first live task of process `tgid` (as the kernel's).
    pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        TASKS.with_borrow(|v| v.iter().find(|t| t.tgid == tgid && t.state != TaskState::Dead).map(f))
    }
}

/// `task::is_task_alive`.
pub fn is_task_alive(id: TaskId) -> bool {
    TASKS.with_borrow(|v| v.iter().any(|t| t.id == id && t.state != TaskState::Dead))
}

// --------------------------------------------------------------- fd table

/// A minimal descriptor table (the kernel's `fs::FdTable`, cut down).
#[derive(Clone)]
pub struct FdTable {
    pub open: BTreeMap<usize, (crate::fs::FileDescriptor, bool)>,
    pub umask: u32,
    pub root_ino: u64,
    pub root_mnt: u64,
    pub cwd_ino: u64,
    pub cwd_mnt: u64,
    pub cwd_path: String,
}

impl Default for FdTable {
    fn default() -> Self {
        Self { open: BTreeMap::new(), umask: 0o022, root_ino: 0, root_mnt: 0, cwd_ino: 0, cwd_mnt: 0, cwd_path: String::from("/") }
    }
}

impl FdTable {
    /// A copy for a new process (`fork`, `unshare(CLONE_FILES)`, `execve`).
    pub fn fork_copy(&self) -> FdTable {
        self.clone()
    }
    pub fn into_shared(self) -> crate::fs::SharedFdTable {
        Arc::new(spin::Mutex::new(self))
    }
    pub fn alloc_fd(&mut self, d: crate::fs::FileDescriptor) -> Result<usize, &'static str> {
        let fd = (0..crate::fs::MAX_FDS).find(|n| !self.open.contains_key(n)).ok_or("Too many open files")?;
        self.open.insert(fd, (d, false));
        Ok(fd)
    }
    pub fn set_cloexec(&mut self, fd: usize, on: bool) {
        if let Some(e) = self.open.get_mut(&fd) {
            e.1 = on;
        }
    }
    pub fn cloexec(&self, fd: usize) -> bool {
        self.open.get(&fd).map_or(false, |e| e.1)
    }
    pub fn get(&self, fd: usize) -> Option<&crate::fs::FileDescriptor> {
        self.open.get(&fd).map(|e| &e.0)
    }
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut crate::fs::FileDescriptor> {
        self.open.get_mut(&fd).map(|e| &mut e.0)
    }
    pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
        self.open.remove(&fd).map(|_| ()).ok_or("Bad file descriptor")
    }
    /// Closes every close-on-exec descriptor (execve).
    pub fn close_on_exec(&mut self) {
        self.open.retain(|_, e| !e.1);
    }
    pub fn install(&mut self, fd: usize, d: crate::fs::FileDescriptor) {
        self.open.insert(fd, (d, false));
    }
    /// `dup2`: `newfd` becomes a copy of `oldfd` (close-on-exec clear).
    pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
        let d = self.get(oldfd).cloned().ok_or("Bad file descriptor")?;
        if newfd >= crate::fs::MAX_FDS {
            return Err("Bad file descriptor");
        }
        self.open.insert(newfd, (d, false));
        Ok(newfd)
    }
    /// Readiness (EPOLL* bits): files are always ready; pipes and sockets ask the real
    /// objects; a test may override any descriptor through [`READY`] (by object id).
    pub fn readiness(&self, desc: &crate::fs::FileDescriptor) -> u32 {
        use crate::fs::FileDescriptor::*;
        if let Some(r) = READY.with_borrow(|m| m.get(&desc.object_id()).copied()) {
            return r;
        }
        match desc {
            File { .. } | Vnode(_) | MemFd { .. } | ConsoleOut | ConsoleErr => 0x1 | 0x4,
            PipeRead(p) => {
                let p = p.lock();
                if !p.is_empty() {
                    0x1
                } else if p.writers_count() == 0 {
                    0x10
                } else {
                    0
                }
            }
            PipeWrite(p) => {
                let p = p.lock();
                if p.readers_count() == 0 {
                    0x8
                } else if !p.is_full() {
                    0x4
                } else {
                    0
                }
            }
            Socket(s) => s.lock().poll_events(),
            _ => 0,
        }
    }
    pub fn add_wait_queues_for(&self, _desc: &crate::fs::FileDescriptor, _waits: &mut wait::WaitSet) {}
}

thread_local! {
    /// The descriptor table used when there is no current task.
    pub static FDS: RefCell<FdTable> = RefCell::new(FdTable::default());
}

pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut FdTable) -> R) -> R {
    let shared = {
        let mut g = SCHEDULER.lock();
        g.current_task_mut(|t| t.fds.clone())
    };
    match shared {
        Some(fds) => f(&mut fds.lock()),
        None => FDS.with_borrow_mut(f),
    }
}

// ------------------------------------------------------------- wait queues

pub mod wait {
    use super::*;

    /// Records wake-ups; never actually sleeps.
    #[derive(Default, Debug)]
    pub struct WaitQueue;

    impl WaitQueue {
        pub const fn new() -> Self {
            WaitQueue
        }
        pub fn new_shared() -> Arc<Self> {
            Arc::new(WaitQueue)
        }
        pub fn register(&self) {}
        pub fn unregister(&self) {}
        pub fn wakes(&self) -> u64 {
            WAKES.get() as u64
        }
        pub fn wake_all(&self) {
            WAKES.set(WAKES.get() + 1);
        }
        pub fn wake_one(&self) {
            WAKES.set(WAKES.get() + 1);
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

    /// Message of the panic raised when code under test would go to sleep.
    pub const WOULD_BLOCK: &str = "fake wait: the operation would block";

    fn waited(deadline: Option<u64>) {
        WAITS.set(WAITS.get() + 1);
        let hook = ON_WAIT.with_borrow_mut(|h| h.take());
        if let Some(mut h) = hook {
            h();
            ON_WAIT.with_borrow_mut(|slot| {
                if slot.is_none() {
                    *slot = Some(h)
                }
            });
            return;
        }
        match deadline {
            Some(d) => TICKS.set(TICKS.get().max(d.div_ceil(1_000_000))),
            None if SPIN_WAITS.get() => {}
            None => panic!("{}", WOULD_BLOCK),
        }
    }

    impl WaitSet {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn register(&self) {}
        pub fn wait(&self, deadline: Option<u64>) {
            waited(deadline)
        }
        pub fn wait_ns(&self, deadline: Option<u64>) {
            waited(deadline)
        }
    }

    /// Sleeps until the boot-clock deadline (ns) or a wake: the fake clock jumps to the
    /// deadline; without one, [`ON_WAIT`] runs, or the wait returns at once with
    /// [`SPIN_WAITS`], or it reports that it would block (a panic).
    pub fn wait_ns(deadline: Option<u64>) {
        waited(deadline)
    }

    /// Wakes process `tgid` once the scheduler lock is released (counted on the host).
    pub fn wake_process_deferred(tgid: u64) {
        WAKES.set(WAKES.get() + 1);
        rec(format!("wake_process_deferred({tgid})"));
    }

    pub fn wait(deadline: Option<u64>) {
        waited(deadline)
    }
}

// ---------------------------------------------------------------- ZFS client

pub struct FileStat {
    pub size: u64,
    pub obj_id: u64,
    pub obj_type: crate::fs::zfs::DnodeType,
}

pub struct ZfsClient;

impl ZfsClient {
    pub fn file_stat(path: &str) -> Result<FileStat, &'static str> {
        ZFS_FILES.with_borrow(|m| {
            m.get(path)
                .map(|d| FileStat { size: d.len() as u64, obj_id: 7, obj_type: crate::fs::zfs::DnodeType::PlainFile })
                .ok_or("ENOENT")
        })
    }
    pub fn read_file_by_path(path: &str, out: &mut [u8]) -> Result<usize, &'static str> {
        ZFS_FILES.with_borrow(|m| {
            let d = m.get(path).ok_or("ENOENT")?;
            let n = d.len().min(out.len());
            out[..n].copy_from_slice(&d[..n]);
            Ok(n)
        })
    }
    pub fn touch_file(path: &str) -> Result<(), &'static str> {
        ZFS_FILES.with_borrow_mut(|m| {
            m.entry(path.to_string()).or_default();
        });
        Ok(())
    }
    pub fn getattr(ino: u64) -> Result<crate::fs::zfs::fsproto::Attr, i64> {
        INODES.with_borrow(|m| {
            let (mode, d) = m.get(&ino).ok_or(-2i64)?;
            let (uid, gid) = INODE_OWNERS.with_borrow(|o| o.get(&ino).copied().unwrap_or((0, 0)));
            Ok(crate::fs::zfs::fsproto::Attr { ino, size: d.len() as u64, mode: *mode, uid, gid, ..Default::default() })
        })
    }
    pub fn read_at(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        INODES.with_borrow(|m| {
            let (_, d) = m.get(&ino).ok_or(-2i64)?;
            let start = (offset as usize).min(d.len());
            let n = buf.len().min(d.len() - start);
            buf[..n].copy_from_slice(&d[start..start + n]);
            Ok(n)
        })
    }
    pub fn read_uncached(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
        Self::read_at(ino, offset, buf)
    }
    pub fn write_at(ino: u64, offset: u64, data: &[u8]) -> Result<usize, i64> {
        INODES.with_borrow_mut(|m| {
            let (_, d) = m.get_mut(&ino).ok_or(-2i64)?;
            let end = offset as usize + data.len();
            if d.len() < end {
                d.resize(end, 0);
            }
            d[offset as usize..end].copy_from_slice(data);
            Ok(data.len())
        })
    }
    /// Path lookup in [`INODE_PATHS`] (the path as given).
    pub fn resolve(_base: u64, path: &[u8], _follow: bool) -> Result<u64, i64> {
        let p = String::from_utf8_lossy(path).into_owned();
        INODE_PATHS.with_borrow(|m| m.get(&p).copied().ok_or(-2))
    }
    pub fn resolve_in(_root: u64, base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
        Self::resolve(base, path, follow)
    }
    pub fn open_ref(_ino: u64) {}
    pub fn release(_ino: u64) {}
    pub fn readlink(ino: u64) -> Result<Vec<u8>, i64> {
        INODES.with_borrow(|m| m.get(&ino).map(|(_, d)| d.clone()).ok_or(-2))
    }
}

// ------------------------------------------------------------------- paging

pub fn make_user_accessible(start: x86_64::VirtAddr, size: usize) -> Result<(), &'static str> {
    USER_RANGES.with_borrow_mut(|v| v.push((start.as_u64(), size)));
    Ok(())
}

/// `rdmsr` stand-in: only IA32_EFER (0xC000_0080) is meaningful.
///
/// # Safety
/// Always safe on the host; `unsafe` only to match the kernel signature.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    match msr {
        0xC000_0080 if NX_ENABLED.get() => 1 << 11,
        _ => 0,
    }
}

/// `wrmsr` stand-in: recorded.
///
/// # Safety
/// Always safe on the host.
pub unsafe fn wrmsr(msr: u32, value: u64) {
    rec(format!("wrmsr({msr:#x},{value:#x})"));
}

/// Stand-in for `paging::AddressSpace` (as in `tests/host`).
pub struct AddressSpace {
    pml4: x86_64::PhysAddr,
}

impl AddressSpace {
    pub fn create_user_space(
        alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager,
    ) -> Result<Self, &'static str> {
        use x86_64::structures::paging::PageTableFlags as F;
        let pml4 = alloc.allocate_zeroed_frame().ok_or("Out of memory: PML4")?;
        let pdpt = alloc.allocate_zeroed_frame().ok_or("Out of memory: low PDPT")?;
        let table = unsafe { &mut *(pml4.start_address().as_u64() as *mut x86_64::structures::paging::PageTable) };
        table[0].set_addr(pdpt.start_address(), F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE);
        Ok(Self { pml4: pml4.start_address() })
    }
    pub fn pml4_physical_address(&self) -> x86_64::PhysAddr {
        self.pml4
    }
    pub const fn from_pml4(pml4: x86_64::PhysAddr) -> Self {
        Self { pml4 }
    }
    /// # Safety
    /// Not reachable.
    pub unsafe fn leaf_entry(&self, _va: u64) -> Option<&'static mut x86_64::structures::paging::page_table::PageTableEntry> {
        None
    }
    /// # Safety
    /// Not reachable.
    pub unsafe fn map_page(
        &mut self,
        _page: x86_64::structures::paging::Page,
        _frame: x86_64::structures::paging::PhysFrame,
        _flags: x86_64::structures::paging::PageTableFlags,
        _alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager,
    ) -> Result<(), &'static str> {
        Err("no kernel address space on the host")
    }
}

// ------------------------------------------------------------------- clocks

pub fn ticks() -> u64 {
    TICKS.get()
}
pub fn frequency_hz() -> u64 {
    1000
}
pub fn tick_ns() -> u64 {
    1_000_000
}
pub fn now_ns() -> u64 {
    TICKS.get() * 1_000_000
}
pub fn uptime_ms() -> u64 {
    TICKS.get()
}
pub fn sleep_ms(ms: u64) {
    TICKS.set(TICKS.get() + ms);
}
pub fn clock_state() -> (u64, u64, u64, u64) {
    (TICKS.get() * 1_000_000, 0, 0, 0)
}
pub fn wall_base_ns() -> i64 {
    1_767_225_600 * 1_000_000_000
}
/// RTC time: a fixed instant (2026-01-01T00:00:00Z) unless set.
pub fn rtc_now() -> (u64, u32) {
    (RTC_SET.with_borrow(|v| v.last().copied()).unwrap_or(1_767_225_600), 0)
}
pub fn rtc_set_now(secs: u64, _ns: u32) {
    RTC_SET.with_borrow_mut(|v| v.push(secs));
}

/// Deterministic "random" bytes (a counter), so tests are repeatable.
pub fn random_fill(buf: &mut [u8]) {
    static NEXT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);
    for b in buf {
        *b = NEXT.fetch_add(37, core::sync::atomic::Ordering::Relaxed);
    }
}

// ------------------------------------------------------------------- per-CPU

/// Single-CPU stand-in for `arch::percpu::PerCpuPtr` (same methods).
pub struct PerCpuPtr<T>(core::sync::atomic::AtomicPtr<T>);

impl<T> PerCpuPtr<T> {
    pub const fn new() -> Self {
        Self(core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()))
    }
    pub fn load(&self, o: core::sync::atomic::Ordering) -> *mut T {
        self.0.load(o)
    }
    pub fn store(&self, v: *mut T, o: core::sync::atomic::Ordering) {
        self.0.store(v, o)
    }
    pub fn swap(&self, v: *mut T, o: core::sync::atomic::Ordering) -> *mut T {
        self.0.swap(v, o)
    }
}
