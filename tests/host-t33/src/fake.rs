//! Host stand-ins for the kernel services that Group 33's files call.
//!
//! State lives in thread-locals (each `#[test]` runs on its own thread) unless the kernel
//! keeps it in a global the code under test reads (the process table). Call [`reset`] at
//! the start of a test that relies on a clean slate.
//!
//! `lib.rs` re-exports these items at the module paths the kernel uses.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

thread_local! {
    /// Effective capability bits of the "current task". `None` = no task.
    pub static CAPS: Cell<Option<u64>> = const { Cell::new(Some(0)) };
    /// What `signal_pending()` reports.
    pub static SIGNAL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// Number of `WaitQueue::wake_all` calls.
    pub static WAKES: Cell<usize> = const { Cell::new(0) };
    /// Ranges passed to `make_user_accessible`.
    pub static USER_RANGES: RefCell<Vec<(u64, usize)>> = RefCell::new(Vec::new());
    /// Make `make_user_accessible` fail with this message.
    pub static PAGING_ERROR: Cell<Option<&'static str>> = const { Cell::new(None) };
    /// The current task's descriptor table (the kernel's real `FdTable`).
    pub static FDS: RefCell<crate::fs::FdTable> = RefCell::new(crate::fs::FdTable::new_default());
    /// Milliseconds slept (`pit::sleep_ms`, `task::sleep_ms`).
    pub static SLEPT_MS: Cell<u64> = const { Cell::new(0) };
    /// Kernel console output captured (`println!`).
    pub static CONSOLE: RefCell<String> = const { RefCell::new(String::new()) };
    /// Kernel log captured (`kprintln!`).
    pub static KLOG: RefCell<String> = const { RefCell::new(String::new()) };
    /// Keys `console::read_key` returns.
    pub static KEYS: RefCell<VecDeque<uefi::proto::console::text::Key>> = RefCell::new(VecDeque::new());
    /// What `console::is_hardware_mode` reports (boot services gone: true on the host).
    pub static HARDWARE_MODE: Cell<bool> = const { Cell::new(true) };
    /// fw_cfg files.
    pub static FWCFG: RefCell<BTreeMap<String, Vec<u8>>> = RefCell::new(BTreeMap::new());
    /// `boottime::mark` calls.
    pub static MARKS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Kernel tasks started (`task::spawn`).
    pub static SPAWNED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Kernel-lock depth (`smp::bkl_enter`/`bkl_exit`).
    pub static BKL: Cell<i64> = const { Cell::new(0) };
    /// What `net::client::service_running` reports.
    pub static NET_RUNNING: Cell<bool> = const { Cell::new(false) };
}

/// Appends kernel console output.
pub fn console_push(s: &str) {
    let _ = CONSOLE.try_with(|c| {
        let mut c = c.borrow_mut();
        c.push_str(s);
        c.push('\n');
    });
}

/// Takes the console output so far.
pub fn console_take() -> String {
    CONSOLE.with_borrow_mut(std::mem::take)
}

/// Appends kernel log output.
pub fn klog_push(s: &str) {
    let _ = KLOG.try_with(|c| {
        let mut c = c.borrow_mut();
        c.push_str(s);
        c.push('\n');
    });
}

/// Takes the kernel log so far.
pub fn klog_take() -> String {
    KLOG.with_borrow_mut(std::mem::take)
}

/// Restores every fake to its initial state.
pub fn reset() {
    CAPS.set(Some(0));
    SIGNAL_PENDING.set(false);
    WAKES.set(0);
    USER_RANGES.with_borrow_mut(|v| v.clear());
    PAGING_ERROR.set(None);
    FDS.with_borrow_mut(|f| *f = crate::fs::FdTable::new_default());
    SLEPT_MS.set(0);
    console_take();
    klog_take();
    KEYS.with_borrow_mut(|v| v.clear());
    HARDWARE_MODE.set(true);
    FWCFG.with_borrow_mut(|m| m.clear());
    MARKS.with_borrow_mut(|v| v.clear());
    SPAWNED.with_borrow_mut(|v| v.clear());
    NET_RUNNING.set(false);
    NX_ENABLED.set(true);
    IN_USERNS.set(false);
    SIGKILL_PENDING.set(false);
    TASK_MM.with_borrow_mut(|m| *m = None);
    CREDS.set((0, 0));
    UID.set(0);
    POSTED.with_borrow_mut(|v| v.clear());
    IDS.set((1, 1));
    TICKS.set(1_000);
    SECCOMP.set(Default::default());
    SIBLINGS.with_borrow_mut(|v| v.clear());
    SIGSYS.with_borrow_mut(|v| v.clear());
    TRACER.with_borrow_mut(|t| *t = None);
    EXE.with_borrow_mut(|e| *e = None);
    FS_BASE.set(0);
    PERS_CALL.set(None);
    linux_stubs::reset();
}

// ------------------------------------------------------------------- tasks

/// Capability set of a task, as far as the code under test looks at it.
pub struct Caps {
    pub effective: u64,
    /// Capabilities held only inside a user namespace (not over the host).
    pub in_userns: bool,
}

impl Caps {
    pub const SETGID: u64 = 1 << 6;
    pub fn has(&self, mask: u64) -> bool {
        self.effective & mask == mask
    }
}

/// The parts of the kernel's `Task` the code under test reads.
pub struct Task {
    pub caps: Caps,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub mm: Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>,
    pub seccomp: crate::compat::linux::seccomp::State,
    pub id: TaskId,
    pub tgid: u64,
    pub robust_list: u64,
    pub service: Option<u32>,
    pub debugregs: [u64; 8],
    /// The executable's path (`/proc/self/exe`).
    pub exe: Option<String>,
    /// `FS` base (TLS).
    pub fs_base: u64,
    /// A personality's system call in progress (`personality::syscall`).
    pub pers_call: Option<[u64; 8]>,
}

/// Thread id, as in the kernel's `task::TaskId`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId(pub u64);

impl Task {
    /// Another thread of the current process, for [`SIBLINGS`].
    pub fn sibling(tid: u64) -> Task {
        Task {
            caps: Caps { effective: 0, in_userns: false },
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            mm: None,
            seccomp: Default::default(),
            id: TaskId(tid),
            tgid: IDS.get().1,
            robust_list: 0,
            service: None,
            debugregs: [0; 8],
            exe: None,
            fs_base: 0,
            pers_call: None,
        }
    }
}

thread_local! {
    pub static IN_USERNS: Cell<bool> = const { Cell::new(false) };
    pub static SIGKILL_PENDING: Cell<bool> = const { Cell::new(false) };
    /// Real uid of the current task.
    pub static UID: Cell<u32> = const { Cell::new(0) };
    /// Signals posted: (pid, sig, code, sender pid, sender uid, value).
    pub static POSTED: RefCell<Vec<(u64, u32, i32, u32, u32, u64)>> = const { RefCell::new(Vec::new()) };
    /// (euid, egid) of the current task.
    pub static CREDS: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
    /// (tid, tgid) of the current task.
    pub static IDS: Cell<(u64, u64)> = const { Cell::new((1, 1)) };
    /// IPC namespace of the current task.
    pub static IPC_NS: Cell<u64> = const { Cell::new(0) };
    /// Timer ticks reported by `pit::ticks()`.
    pub static TICKS: Cell<u64> = const { Cell::new(1_000) };
    /// The current task's address space.
    pub static TASK_MM: RefCell<Option<Arc<spin::Mutex<crate::memory::vm::Mm>>>> = const { RefCell::new(None) };
    pub static EXE: RefCell<Option<String>> = const { RefCell::new(None) };
    pub static FS_BASE: Cell<u64> = const { Cell::new(0) };
    pub static PERS_CALL: Cell<Option<[u64; 8]>> = const { Cell::new(None) };
}

pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
    let effective = CAPS.get()?;
    let mm = TASK_MM.with_borrow(|m| m.clone());
    let (euid, egid) = CREDS.get();
    let (tid, tgid) = IDS.get();
    let seccomp = SECCOMP.take();
    let mut t = Task {
        caps: Caps { effective, in_userns: IN_USERNS.get() },
        uid: UID.get(),
        gid: egid,
        euid,
        egid,
        suid: euid,
        sgid: egid,
        mm,
        seccomp,
        id: TaskId(tid),
        tgid,
        robust_list: 0,
        service: None,
        debugregs: [0; 8],
        exe: EXE.with_borrow(|e| e.clone()),
        fs_base: FS_BASE.get(),
        pers_call: PERS_CALL.get(),
    };
    let r = f(&mut t);
    CAPS.set(Some(t.caps.effective));
    SECCOMP.set(t.seccomp);
    PERS_CALL.set(t.pers_call);
    Some(r)
}

thread_local! {
    pub static SECCOMP: RefCell<crate::compat::linux::seccomp::State> = RefCell::new(Default::default());
    pub static SIBLINGS: RefCell<Vec<Task>> = const { RefCell::new(Vec::new()) };
    pub static SIGSYS: RefCell<Vec<(i32, u64, i32)>> = const { RefCell::new(Vec::new()) };
    pub static TRACER: RefCell<Option<Box<dyn FnMut(&mut crate::arch::syscall::SyscallFrame, u16) -> Result<(), i64>>>> = RefCell::new(None);
}

/// Stand-in for `task::SCHEDULER`: its tasks are the current one plus [`SIBLINGS`].
pub struct Scheduler;

pub static SCHEDULER: Scheduler = Scheduler;

pub struct SchedulerGuard;

impl Scheduler {
    pub fn lock(&self) -> SchedulerGuard {
        SchedulerGuard
    }
    pub fn try_lock(&self) -> Option<SchedulerGuard> {
        Some(SchedulerGuard)
    }
}

impl SchedulerGuard {
    pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        let mut f = Some(f);
        let mut out = None;
        self.for_each_task_mut(|t| {
            if t.id == id {
                if let Some(g) = f.take() {
                    out = Some(g(t));
                }
            }
        });
        out
    }
    pub fn for_each_task_mut(&mut self, mut f: impl FnMut(&mut Task)) {
        with_current_task_mut(|t| f(t));
        SIBLINGS.with_borrow_mut(|v| v.iter_mut().for_each(|t| f(t)));
    }
    pub fn process_cpu(&self, _tgid: u64) -> (u64, u64) {
        (0, 0)
    }
    pub fn current_task_id(&self) -> TaskId {
        TaskId(IDS.get().0)
    }
    pub fn wake_task(&mut self, id: u64) {
        WOKEN.with_borrow_mut(|v| v.push(id));
    }
    pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        if tgid == IDS.get().1 {
            with_current_task_mut(|t| f(t))
        } else {
            SIBLINGS.with_borrow(|v| v.iter().find(|t| t.tgid == tgid).map(f))
        }
    }
}

thread_local! {
    pub static WOKEN: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    pub static SPIN_WAITS: Cell<bool> = const { Cell::new(false) };
}

pub fn is_task_alive(id: TaskId) -> bool {
    id.0 == IDS.get().0 || SIBLINGS.with_borrow(|v| v.iter().any(|t| t.id == id))
}

pub fn die_by_signal(sig: u32) -> ! {
    panic!("killed by signal {sig}")
}

pub fn force_seccomp_sigsys(nr: i32, ip: u64, errno: i32) {
    SIGSYS.with_borrow_mut(|v| v.push((nr, ip, errno)));
}

pub fn seccomp_stop(frame: &mut crate::arch::syscall::SyscallFrame, data: u16) -> Option<Result<(), i64>> {
    TRACER.with_borrow_mut(|t| t.as_mut().map(|f| f(frame, data)))
}

pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut crate::fs::FdTable) -> R) -> R {
    FDS.with_borrow_mut(f)
}

// ------------------------------------------------------------- wait queues

pub mod wait {
    use super::*;

    /// Records wake-ups; never actually sleeps.
    #[derive(Default)]
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
            let _ = WAKES.try_with(|w| w.set(w.get() + 1));
        }
    }

    pub enum QueueRef {
        Static(&'static WaitQueue),
        Shared(Arc<WaitQueue>),
    }

    #[derive(Default)]
    pub struct WaitSet {
        pub queues: Vec<QueueRef>,
        /// Readiness that is polled, not announced by a queue.
        pub polled: bool,
        /// Timer deadlines added (`add_deadline`).
        pub deadlines: usize,
    }

    pub const WOULD_BLOCK: &str = "fake WaitSet::wait: the operation would block";

    impl WaitSet {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn add(&mut self, q: QueueRef) {
            self.queues.push(q);
        }
        pub fn add_deadline<T>(&mut self, _t: T) {
            self.deadlines += 1;
        }
        pub fn register(&self) {}
        pub fn wait(&self, _deadline: Option<u64>) {
            panic!("{}", WOULD_BLOCK);
        }
    }

    pub fn wait_ns(deadline: Option<u64>) {
        match deadline {
            Some(d) => TICKS.set(TICKS.get().max(d.div_ceil(1_000_000))),
            None if SPIN_WAITS.get() => std::thread::yield_now(),
            None => panic!("{}", WOULD_BLOCK),
        }
    }

    pub fn wake_process_deferred(_tgid: u64) {
        WAKES.set(WAKES.get() + 1);
    }

    pub fn wait(_deadline: Option<u64>) {
        panic!("{}", WOULD_BLOCK);
    }
}

// ------------------------------------------------------------------- paging

pub fn make_user_accessible(start: x86_64::VirtAddr, size: usize) -> Result<(), &'static str> {
    if let Some(e) = PAGING_ERROR.get() {
        return Err(e);
    }
    USER_RANGES.with_borrow_mut(|v| v.push((start.as_u64(), size)));
    Ok(())
}

pub fn sleep_ms(ms: u64) {
    SLEPT_MS.set(SLEPT_MS.get() + ms);
}

thread_local! {
    pub static NX_ENABLED: Cell<bool> = const { Cell::new(true) };
}

/// `rdmsr` stand-in: only IA32_EFER (0xC000_0080) is meaningful.
///
/// # Safety
/// Always safe on the host.
pub unsafe fn rdmsr(msr: u32) -> u64 {
    match msr {
        0xC000_0080 if NX_ENABLED.get() => 1 << 11,
        _ => 0,
    }
}

/// Stand-in for `paging::AddressSpace` (user address spaces only).
pub struct AddressSpace {
    pml4: x86_64::PhysAddr,
}

impl AddressSpace {
    pub fn create_user_space(alloc: &mut crate::memory::frame_allocator::PhysicalMemoryManager) -> Result<Self, &'static str> {
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

// ------------------------------------------------------- processes, clocks

pub fn current_ids() -> (u64, u64) {
    IDS.get()
}

/// The parts of the kernel's `Process` the code under test reads.
#[derive(Default)]
pub struct Process {
    pub ppid: u64,
    pub groups: Vec<u32>,
    pub cgroup: Option<Arc<str>>,
    /// ABAC subject id.
    pub abac: u32,
    /// (session id, process group id).
    pub session: (u64, u64),
}

/// Process table (shared by all test threads, like the kernel's). Key by tgid.
pub static PROCS: spin::Mutex<BTreeMap<u64, Process>> = spin::Mutex::new(BTreeMap::new());

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

pub fn random_fill(buf: &mut [u8]) {
    static NEXT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);
    for b in buf {
        *b = NEXT.fetch_add(37, core::sync::atomic::Ordering::Relaxed);
    }
}

pub fn uptime_ms() -> u64 {
    TICKS.get()
}

pub fn clock_state() -> (u64, u64, u64, u64) {
    (TICKS.get() * 1_000_000, 0, 0, 0)
}

pub fn wall_base_ns() -> i64 {
    1_767_225_600 * 1_000_000_000
}

thread_local! {
    /// RTC seconds (default: 2026-01-01T00:00:00Z).
    pub static RTC: Cell<u64> = const { Cell::new(1_767_225_600) };
}

pub fn rtc_now() -> (u64, u32) {
    (RTC.get(), 0)
}

/// Single-CPU stand-in for `arch::percpu::PerCpuPtr`.
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

// ------------------------------------------------- the Linux layer's other modules

/// *stub* Modules of the Linux layer outside Group 33, re-exported under
/// `crate::compat::linux`.
pub mod linux_stubs {
    use super::*;

    thread_local! {
        /// Linux calls run through `dispatch_linux_syscall`: (nr, args).
        pub static LINUX_CALLS: RefCell<Vec<(u64, [u64; 6])>> = const { RefCell::new(Vec::new()) };
        /// Results `dispatch_linux_syscall` gives, per number (default 0).
        pub static LINUX_RESULTS: RefCell<BTreeMap<u64, i64>> = RefCell::new(BTreeMap::new());
        /// `deliver_on_syscall_return` calls: (orig nr, rip after).
        pub static DELIVERED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
        /// What `deliver_on_syscall_return` does to the frame (a handler that restarts).
        pub static DELIVER_HOOK: RefCell<Option<Box<dyn FnMut(&mut crate::arch::syscall::SyscallFrame)>>> = RefCell::new(None);
        /// Signal actions (`proc::set_action`).
        pub static ACTIONS: RefCell<BTreeMap<u32, proc::SigAction>> = RefCell::new(BTreeMap::new());
        /// The signal mask (`proc::set_current_mask`).
        pub static MASK: Cell<u64> = const { Cell::new(0) };
        /// The alternate signal stack: (sp, size, enabled).
        pub static ALT: Cell<(u64, u64, bool)> = const { Cell::new((0, 0, false)) };
        /// `ident_changed` calls.
        pub static IDENT_CHANGES: Cell<u32> = const { Cell::new(0) };
        /// Whether `fanotify::active` / `inotify::active` report watchers.
        pub static FANOTIFY_ON: Cell<bool> = const { Cell::new(false) };
        pub static INOTIFY_ON: Cell<bool> = const { Cell::new(false) };
        /// Events reported: (source, ino, mask, name).
        pub static NOTIFIED: RefCell<Vec<(&'static str, u64, u64, String)>> = const { RefCell::new(Vec::new()) };
        /// Locks released: ("release_file", key) / ("closed", ino).
        pub static LOCKS: RefCell<Vec<(&'static str, u64)>> = const { RefCell::new(Vec::new()) };
        /// `RLIMIT_NOFILE` / `RLIMIT_FSIZE`.
        pub static NOFILE: Cell<usize> = const { Cell::new(1024) };
        pub static FSIZE: Cell<u64> = const { Cell::new(u64::MAX) };
        /// Page cache calls: (what, ino, a, b).
        pub static CACHE: RefCell<Vec<(&'static str, u64, u64, u64)>> = const { RefCell::new(Vec::new()) };
        /// `acl::on_chmod` calls: (ino, mode).
        pub static CHMODS: RefCell<Vec<(u64, u32)>> = const { RefCell::new(Vec::new()) };
        /// Paths `vfs::lookup_path` knows: path -> (ino, is_dir).
        pub static LOOKUPS: RefCell<BTreeMap<String, (u64, bool)>> = RefCell::new(BTreeMap::new());
        /// tid -> tgid for `proc::tgid_of`.
        pub static TGIDS: RefCell<BTreeMap<u64, u64>> = RefCell::new(BTreeMap::new());
        /// `extra::may_access` answer.
        pub static MAY_ACCESS: Cell<i64> = const { Cell::new(0) };
        /// `pty::hangup` answer: (leader, foreground group).
        pub static HANGUP: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
        /// Signals posted to processes / groups: (target, sig, group?).
        pub static SIGNALS: RefCell<Vec<(u64, u32, bool)>> = const { RefCell::new(Vec::new()) };
        /// FUSE calls routed to the stub daemon.
        pub static FUSE_CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
        /// FUSE mounts in the initial namespace (`fuse::ns0_any`).
        pub static FUSE_NS0: Cell<bool> = const { Cell::new(false) };
        /// What `fuse::walk` answers.
        pub static FUSE_WALK: RefCell<Option<Result<fuse::Walk, i64>>> = const { RefCell::new(None) };
    }

    pub fn reset() {
        LINUX_CALLS.with_borrow_mut(|v| v.clear());
        LINUX_RESULTS.with_borrow_mut(|v| v.clear());
        DELIVERED.with_borrow_mut(|v| v.clear());
        DELIVER_HOOK.with_borrow_mut(|v| *v = None);
        ACTIONS.with_borrow_mut(|v| v.clear());
        MASK.set(0);
        ALT.set((0, 0, false));
        IDENT_CHANGES.set(0);
        FANOTIFY_ON.set(false);
        INOTIFY_ON.set(false);
        NOTIFIED.with_borrow_mut(|v| v.clear());
        LOCKS.with_borrow_mut(|v| v.clear());
        NOFILE.set(1024);
        FSIZE.set(u64::MAX);
        CACHE.with_borrow_mut(|v| v.clear());
        CHMODS.with_borrow_mut(|v| v.clear());
        LOOKUPS.with_borrow_mut(|v| v.clear());
        TGIDS.with_borrow_mut(|v| v.clear());
        MAY_ACCESS.set(0);
        HANGUP.set(None);
        SIGNALS.with_borrow_mut(|v| v.clear());
        FUSE_CALLS.with_borrow_mut(|v| v.clear());
        FUSE_NS0.set(false);
        FUSE_WALK.with_borrow_mut(|v| *v = None);
    }

    /// *stub* System call tracing switch.
    pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    pub fn ident_changed() {
        IDENT_CHANGES.set(IDENT_CHANGES.get() + 1);
    }

    /// *mirror* of the kernel's list of calls that change identity.
    pub fn changes_identity(nr: u64) -> bool {
        matches!(nr, 59 | 322 | 101 | 105 | 106 | 113 | 114 | 116 | 117 | 119 | 122 | 123 | 126 | 157 | 272 | 308 | 317)
    }

    /// *stub* The Linux dispatcher: records the call, answers from [`LINUX_RESULTS`].
    pub fn dispatch_linux_syscall(f: &mut crate::arch::syscall::SyscallFrame) -> i64 {
        let nr = f.rax;
        LINUX_CALLS.with_borrow_mut(|v| v.push((nr, [f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9])));
        LINUX_RESULTS.with_borrow(|m| m.get(&nr).copied().unwrap_or(0))
    }

    /// *stub* The kernel's `CharDevice` trait (the methods the code under test calls or
    /// implements; defaults as the kernel's).
    pub mod chardev {
        use alloc::string::String;
        use alloc::sync::Arc;

        use crate::memory::vm::MappedObject;
        use crate::task::wait::WaitSet;

        pub trait CharDevice: Send + Sync {
            fn read(&self, buf: &mut [u8]) -> i64;
            fn write(&self, _data: &[u8]) -> i64 {
                -22
            }
            fn ioctl(&self, _cmd: u64, _arg: u64) -> i64 {
                -25
            }
            fn poll_events(&self) -> u32;
            fn add_wait_queues(&self, waits: &mut WaitSet);
            fn rdev(&self) -> u64;
            fn path(&self) -> String;
            fn edges(&self) -> Option<u64> {
                None
            }
            fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
                Err(-19)
            }
            fn mmap_object_at(&self, _pgoff: u64) -> Result<Arc<dyn MappedObject>, i64> {
                self.mmap_object()
            }
            fn set_nonblock(&self, on: bool);
            fn nonblock(&self) -> bool;
            fn stat(&self) -> crate::compat::linux::types::LinuxStat {
                crate::compat::linux::types::LinuxStat::default()
            }
            fn deliver_notification(&self, _data: &[u8]) -> bool {
                false
            }
            fn seek(&self, _offset: i64, _whence: u32) -> Option<i64> {
                None
            }
            fn as_mqueue(&self) -> Option<&crate::compat::linux::mqueue::MqHandle> {
                None
            }
            fn as_server(&self) -> Option<&crate::lx::obj::ServerObject> {
                None
            }
            fn as_landlock(&self) -> Option<&crate::compat::linux::landlock::Ruleset> {
                None
            }
            fn as_bpf(&self) -> Option<crate::compat::linux::bpf::Obj> {
                None
            }
            fn as_perf(&self) -> Option<Arc<crate::compat::linux::perf::Event>> {
                None
            }
        }
    }

    /// *stub* The process table and signals.
    pub mod proc {
        use super::*;
        pub use crate::fake::{current_ids, die_by_signal, force_seccomp_sigsys, Process, PROCS};

        pub const ERESTARTSYS: i64 = -512;
        pub const SIGPIPE: u32 = 13;

        /// *mirror* of the kernel's saved user registers (signal frames).
        #[derive(Clone, Copy, Default, Debug, PartialEq)]
        pub struct UserRegs {
            pub r8: u64,
            pub r9: u64,
            pub r10: u64,
            pub r11: u64,
            pub r12: u64,
            pub r13: u64,
            pub r14: u64,
            pub r15: u64,
            pub rdi: u64,
            pub rsi: u64,
            pub rbp: u64,
            pub rbx: u64,
            pub rdx: u64,
            pub rax: u64,
            pub rcx: u64,
            pub rsp: u64,
            pub rip: u64,
            pub rflags: u64,
        }

        /// *mirror* of the kernel's `struct sigaction`.
        #[derive(Clone, Copy, Default, Debug, PartialEq)]
        pub struct SigAction {
            pub handler: u64,
            pub flags: u64,
            pub restorer: u64,
            pub mask: u64,
        }

        pub fn sigkill_pending() -> bool {
            crate::fake::SIGKILL_PENDING.get()
        }
        pub fn in_supplementary_groups(gid: u32) -> bool {
            let (_, pid) = current_ids();
            PROCS.lock().get(&pid).map_or(false, |p| p.groups.contains(&gid))
        }
        pub fn supplementary_groups() -> alloc::vec::Vec<u32> {
            let (_, pid) = current_ids();
            PROCS.lock().get(&pid).map_or(alloc::vec::Vec::new(), |p| p.groups.clone())
        }
        pub fn process_exists(pid: u64) -> bool {
            PROCS.lock().contains_key(&pid)
        }
        pub fn post_with_info(pid: u64, sig: u32, code: i32, spid: u32, suid: u32, value: u64) -> bool {
            crate::fake::POSTED.with_borrow_mut(|v| v.push((pid, sig, code, spid, suid, value)));
            process_exists(pid)
        }
        pub fn signal_pending() -> bool {
            crate::fake::SIGNAL_PENDING.get()
        }
        pub fn post_thread(pid: u64, _tid: u64, sig: u32) -> bool {
            crate::fake::POSTED.with_borrow_mut(|v| v.push((pid, sig, 0, 0, 0, 0)));
            process_exists(pid)
        }
        pub fn post_process(pid: u64, sig: u32) -> bool {
            SIGNALS.with_borrow_mut(|v| v.push((pid, sig, false)));
            true
        }
        pub fn post_group(pgid: u64, sig: u32) -> usize {
            SIGNALS.with_borrow_mut(|v| v.push((pgid, sig, true)));
            1
        }
        pub fn abac_subject(pid: u64) -> u32 {
            PROCS.lock().get(&pid).map_or(0, |p| p.abac)
        }
        pub fn set_abac_subject(pid: u64, subject: u32) -> bool {
            match PROCS.lock().get_mut(&pid) {
                Some(p) => {
                    p.abac = subject;
                    true
                }
                None => false,
            }
        }
        pub fn session_of(pid: u64) -> Option<(u64, u64)> {
            PROCS.lock().get(&pid).map(|p| p.session).filter(|s| s.0 != 0)
        }
        pub fn tgid_of(tid: u64) -> Option<u64> {
            TGIDS.with_borrow(|m| m.get(&tid).copied())
        }
        pub fn set_action(sig: u32, new: Option<SigAction>) -> Result<SigAction, i64> {
            if sig == 0 || sig > 64 {
                return Err(-22);
            }
            ACTIONS.with_borrow_mut(|m| {
                let old = m.get(&sig).copied().unwrap_or_default();
                if let Some(n) = new {
                    m.insert(sig, n);
                }
                Ok(old)
            })
        }
        pub fn alt_stack() -> (u64, u64, bool) {
            ALT.get()
        }
        pub fn set_current_mask(mask: u64) {
            MASK.set(mask);
        }
        /// Records the delivery point; [`DELIVER_HOOK`] may change the frame (a handler).
        pub fn deliver_on_syscall_return(frame: &mut crate::arch::syscall::SyscallFrame, _fpu: *mut crate::arch::idt::FpuState, orig_nr: u64) {
            DELIVERED.with_borrow_mut(|v| v.push(orig_nr));
            DELIVER_HOOK.with_borrow_mut(|h| {
                if let Some(h) = h.as_mut() {
                    h(frame)
                }
            });
        }
        /// What `return_to_user` would load: raised as a panic payload tests catch.
        #[derive(Debug, Clone)]
        pub struct Returned {
            pub regs: UserRegs,
            pub mxcsr: u32,
            pub fpu_written: bool,
            pub cs: u16,
        }
        /// # Safety
        /// Never returns: panics with [`Returned`].
        pub unsafe fn return_to_user(regs: &UserRegs, fpu: &crate::arch::idt::FpuState, cs: u16) -> ! {
            let mxcsr = u32::from_le_bytes(fpu.0[24..28].try_into().unwrap());
            std::panic::panic_any(Returned { regs: *regs, mxcsr, fpu_written: fpu.0[512] & 3 == 3, cs })
        }
    }

    /// *stub*
    pub mod ptrace {
        pub use crate::fake::seccomp_stop;
    }

    /// *stub* Namespaces.
    pub mod ns {
        pub fn pid_from_caller(id: u64) -> u64 {
            id
        }
        pub fn pid_to_caller(id: u64) -> u64 {
            id
        }
        pub fn ipc_ns() -> u64 {
            crate::fake::IPC_NS.get()
        }
    }

    /// *stub* User memory and path helpers (user pointers are host pointers).
    pub mod vfs {
        use super::*;
        const EFAULT: i64 = -14;

        pub(crate) struct Creds {
            pub uid: u32,
            pub gid: u32,
            pub euid: u32,
            pub egid: u32,
        }
        pub(crate) fn creds() -> Creds {
            crate::task::with_current_task_mut(|t| Creds { uid: t.uid, gid: t.gid, euid: t.euid, egid: t.egid }).unwrap_or(Creds { uid: 0, gid: 0, euid: 0, egid: 0 })
        }
        pub(crate) fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
            if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
                return Err(EFAULT);
            }
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
            Ok(())
        }
        pub(crate) fn copy_in(ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, i64> {
            if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
                return Err(EFAULT);
            }
            let mut v = alloc::vec![0u8; len];
            unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
            Ok(v)
        }
        pub(crate) fn user_cstr(ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
            if ptr == 0 {
                return Err(EFAULT);
            }
            let mut out = alloc::vec::Vec::new();
            let mut addr = ptr;
            loop {
                let b = unsafe { *(addr as *const u8) };
                if b == 0 {
                    return Ok(out);
                }
                out.push(b);
                if out.len() >= 4096 {
                    return Err(-36);
                }
                addr += 1;
            }
        }
        pub(crate) fn user_path(ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
            let p = user_cstr(ptr)?;
            if p.is_empty() {
                return Err(-2);
            }
            Ok(p)
        }
        /// Path lookup through the real ZFS client (the real one also handles mount
        /// namespaces and /proc/<pid>/root).
        pub(crate) fn resolve(base: u64, path: &[u8], follow: bool) -> Result<u64, i64> {
            crate::fs::ZfsClient::resolve(base, path, follow)
        }
        pub(crate) fn join_path(base: &str, path: &[u8]) -> alloc::string::String {
            let p = alloc::string::String::from_utf8_lossy(path);
            if p.starts_with('/') {
                p.into_owned()
            } else {
                alloc::format!("{}/{}", base.trim_end_matches('/'), p)
            }
        }
        /// A user path to `(inode, is directory)`: from [`LOOKUPS`], else the pool.
        pub(crate) fn lookup_path(ptr: u64, follow: bool) -> Result<(u64, bool), i64> {
            let p = user_path(ptr)?;
            let s = alloc::string::String::from_utf8_lossy(&p).into_owned();
            if let Some(v) = LOOKUPS.with_borrow(|m| m.get(&s).copied()) {
                return Ok(v);
            }
            let ino = crate::fs::ZfsClient::resolve(0, &p, follow)?;
            let a = crate::fs::ZfsClient::getattr(ino)?;
            Ok((ino, a.is_dir()))
        }
    }

    /// *stub* epoll: the instance as far as the descriptor table reads it.
    pub mod epoll {
        pub const EPOLLIN: u32 = 0x001;
        pub const EPOLLOUT: u32 = 0x004;
        pub const EPOLLERR: u32 = 0x008;
        pub const EPOLLHUP: u32 = 0x010;
        pub const EPOLLONESHOT: u32 = 1 << 30;
        pub struct Watch {
            pub fd: i32,
            pub events: u32,
            pub reported: bool,
        }
        #[derive(Default)]
        pub struct EpollInstance {
            pub watches: alloc::collections::BTreeMap<u64, Watch>,
        }
        impl EpollInstance {
            pub fn watch(&mut self, fd: i32, events: u32) {
                let k = self.watches.len() as u64;
                self.watches.insert(k, Watch { fd, events, reported: false });
            }
        }
    }

    /// *stub* The page cache: reads go to the file server, other calls are recorded.
    pub mod mm {
        use super::*;
        pub fn current_mm() -> Option<Arc<spin::Mutex<crate::memory::vm::Mm>>> {
            crate::fake::TASK_MM.with_borrow(|m| m.clone())
        }
        pub fn cached_read(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
            CACHE.with_borrow_mut(|v| v.push(("read", ino, offset, buf.len() as u64)));
            crate::fs::ZfsClient::read_uncached(ino, offset, buf)
        }
        pub fn cache_written(ino: u64, offset: u64, data: &[u8]) {
            let _ = CACHE.try_with(|v| v.borrow_mut().push(("written", ino, offset, data.len() as u64)));
        }
        pub fn cache_truncated(ino: u64, size: u64) {
            CACHE.with_borrow_mut(|v| v.push(("truncated", ino, size, 0)));
        }
        pub fn cache_forget(ino: u64) {
            CACHE.with_borrow_mut(|v| v.push(("forget", ino, 0, 0)));
        }
        pub fn cache_flush() {
            CACHE.with_borrow_mut(|v| v.push(("flush", 0, 0, 0)));
        }
        pub fn cache_shrink(_want: usize) {}
    }

    /// *stub* No userfaultfd on the host.
    pub mod userfaultfd {
        pub enum Waited {
            Again,
            Proceed,
            Refuse,
        }
        pub fn active() -> bool {
            false
        }
        pub fn wait_fault(_id: u64, _page: u64, _write: bool, _kernel: bool) -> Waited {
            Waited::Proceed
        }
    }

    /// *stub* The legacy Unix socket (descriptor variant `Socket`).
    pub mod socket {
        use super::*;
        pub const SHUT_RDWR: u32 = 2;
        pub struct Chan {
            pub wq: Arc<crate::task::wait::WaitQueue>,
        }
        pub enum UnixSocketRole {
            Unbound,
            Connected { rx: Arc<spin::Mutex<Chan>>, tx: Arc<spin::Mutex<Chan>> },
        }
        pub struct UnixSocket {
            pub role: UnixSocketRole,
            pub data: Vec<u8>,
            pub shut: Option<u32>,
        }
        impl UnixSocket {
            pub fn connected() -> Self {
                let c = || Arc::new(spin::Mutex::new(Chan { wq: crate::task::wait::WaitQueue::new_shared() }));
                Self { role: UnixSocketRole::Connected { rx: c(), tx: c() }, data: Vec::new(), shut: None }
            }
            pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
                let n = buf.len().min(self.data.len());
                buf[..n].copy_from_slice(&self.data[..n]);
                self.data.drain(..n);
                Ok(n)
            }
            pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
                if self.shut.is_some() {
                    return Err("Broken pipe");
                }
                self.data.extend_from_slice(data);
                Ok(data.len())
            }
            pub fn poll_events(&self) -> u32 {
                if self.data.is_empty() { 0x4 } else { 0x5 }
            }
            pub fn shutdown(&mut self, how: u32) -> Result<(), &'static str> {
                self.shut = Some(how);
                Ok(())
            }
        }
    }

    /// *stub* Internet sockets.
    pub mod inet {
        use super::*;
        pub struct InetSocket {
            pub wq: Option<Arc<crate::task::wait::WaitQueue>>,
            pub events: u32,
        }
        impl InetSocket {
            pub fn wait_queue(&mut self) -> Option<Arc<crate::task::wait::WaitQueue>> {
                self.wq.clone()
            }
            pub fn poll_events(&self) -> u32 {
                self.events
            }
        }
    }

    /// *stub* Pseudo-terminals.
    pub mod pty {
        use super::*;
        pub struct Pty {
            pub wq: Arc<crate::task::wait::WaitQueue>,
        }
        pub struct PtyFile {
            pub pty: Pty,
            pub written: spin::Mutex<Vec<u8>>,
        }
        impl PtyFile {
            pub fn new() -> Self {
                Self { pty: Pty { wq: crate::task::wait::WaitQueue::new_shared() }, written: spin::Mutex::new(Vec::new()) }
            }
            pub fn write_nowait(&self, data: &[u8]) -> usize {
                self.written.lock().extend_from_slice(data);
                data.len()
            }
            pub fn poll_events(&self) -> u32 {
                0x4
            }
        }
        pub fn hangup(_sid: u64) -> Option<(u64, u64)> {
            HANGUP.get()
        }
    }

    /// *stub*
    pub mod signalfd {
        pub struct SignalFd;
        impl SignalFd {
            pub fn poll_events(&self) -> u32 {
                0x1
            }
        }
    }

    /// *stub* Linux `AF_UNIX` sockets.
    pub mod unix {
        pub struct UnixSocket;
        impl UnixSocket {
            pub fn poll_events(&self) -> u32 {
                0x4
            }
            pub fn add_wait_queues(&self, waits: &mut crate::task::wait::WaitSet) {
                waits.add(crate::task::wait::QueueRef::Shared(crate::task::wait::WaitQueue::new_shared()));
            }
        }
    }

    /// *stub*
    pub mod timerfd {
        use super::*;
        pub struct TimerFd {
            pub wq: Arc<crate::task::wait::WaitQueue>,
        }
        impl TimerFd {
            pub fn poll_events(&self) -> u32 {
                0
            }
        }
    }

    /// *stub* inotify: the switch and the events the file layer reports.
    pub mod inotify {
        use super::*;
        pub const IN_CLOSE_WRITE: u32 = 0x8;
        pub struct Inotify {
            pub wq: Arc<crate::task::wait::WaitQueue>,
        }
        impl Inotify {
            pub fn poll_events(&self) -> u32 {
                0
            }
        }
        pub fn active() -> bool {
            INOTIFY_ON.get()
        }
        pub fn event(ino: u64, mask: u32, _cookie: u32, name: &[u8]) {
            NOTIFIED.with_borrow_mut(|v| v.push(("inotify", ino, mask as u64, String::from_utf8_lossy(name).into_owned())));
        }
    }

    /// *stub* fanotify.
    pub mod fanotify {
        use super::*;
        pub const FAN_ACCESS: u64 = 0x1;
        pub const FAN_MODIFY: u64 = 0x2;
        pub const FAN_CLOSE_WRITE: u64 = 0x8;
        pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
        pub fn active() -> bool {
            FANOTIFY_ON.get()
        }
        pub fn file_event(ino: u64, _dir: u64, path: &str, mask: u64, _is_dir: bool) {
            let _ = NOTIFIED.try_with(|v| v.borrow_mut().push(("fanotify", ino, mask, path.into())));
        }
        pub fn fs_event(ino: u64, mask: u32, name: &[u8]) {
            NOTIFIED.with_borrow_mut(|v| v.push(("fan-fs", ino, mask as u64, String::from_utf8_lossy(name).into_owned())));
        }
    }

    /// *stub*
    pub mod pidfd {
        pub static EXIT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
        pub struct PidFd;
        impl PidFd {
            pub fn poll_events(&self) -> u32 {
                0x1
            }
        }
    }

    /// *stub* The console terminal.
    pub mod tty {
        pub static INPUT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
        thread_local! {
            pub static ATTACHED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
            pub static HAS_INPUT: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
        }
        pub fn attached() -> bool {
            ATTACHED.get()
        }
        pub fn has_input() -> bool {
            HAS_INPUT.get()
        }
    }

    /// *stub* File locks.
    pub mod locks {
        use super::*;
        pub fn release_file(key: usize) {
            let _ = LOCKS.try_with(|v| v.borrow_mut().push(("release_file", key as u64)));
        }
        pub fn closed(ino: u64) {
            LOCKS.with_borrow_mut(|v| v.push(("closed", ino)));
        }
        pub fn process_exited(_pid: u64) {}
    }

    /// *stub* Resource limits.
    pub mod limits {
        use super::*;
        pub fn nofile() -> usize {
            NOFILE.try_with(|n| n.get()).unwrap_or(1024)
        }
        pub fn fsize() -> u64 {
            FSIZE.get()
        }
    }

    /// *stub*
    pub mod extra {
        use super::*;
        pub fn may_access(_tgid: u64) -> Result<(), i64> {
            match MAY_ACCESS.get() {
                0 => Ok(()),
                e => Err(e),
            }
        }
    }

    /// *stub* POSIX ACLs.
    pub mod acl {
        use super::*;
        pub fn on_chmod(attr: &crate::fs::zfs::fsproto::Attr, mode: u32) {
            CHMODS.with_borrow_mut(|v| v.push((attr.ino, mode)));
        }
    }

    /// *stub* FUSE: an object number with bit 62 set is a FUSE file; every call is
    /// recorded and answers a fixed value.
    pub mod fuse {
        use super::*;
        use crate::fs::zfs::fsproto::{Attr, ReaddirEntry, SetAttr};

        pub enum Walk {
            Done(u64, usize),
            Out(u64, usize, alloc::vec::Vec<u8>),
        }

        fn note(what: &'static str) {
            FUSE_CALLS.with_borrow_mut(|v| v.push(what));
        }
        pub fn is_fuse(ino: u64) -> bool {
            ino & (1 << 62) != 0
        }
        pub fn ns0_any() -> bool {
            FUSE_NS0.get()
        }
        pub fn ns0_list() -> alloc::vec::Vec<(u64, u64, usize)> {
            alloc::vec::Vec::new()
        }
        pub fn ns0_mnt_of(_ino: u64) -> usize {
            0
        }
        #[allow(clippy::too_many_arguments)]
        pub fn walk(_cur: u64, _mnt: usize, _rest: &[u8], _follow: bool, _mounts: &[(u64, u64, usize)], _root: u64, _root_mnt: usize, _links: &mut u32) -> Result<Walk, i64> {
            note("walk");
            FUSE_WALK.with_borrow_mut(|w| w.take()).unwrap_or(Err(-2))
        }
        pub fn lookup(dir: u64, _name: &[u8]) -> Result<u64, i64> {
            note("lookup");
            Ok(dir + 1)
        }
        pub fn getattr(ino: u64) -> Result<Attr, i64> {
            note("getattr");
            Ok(Attr { ino, mode: 0o100644, ..Default::default() })
        }
        pub fn setattr(ino: u64, _s: SetAttr) -> Result<Attr, i64> {
            note("setattr");
            Ok(Attr { ino, mode: 0o100600, ..Default::default() })
        }
        pub fn read(_ino: u64, _off: u64, buf: &mut [u8]) -> Result<usize, i64> {
            note("read");
            buf.fill(b'f');
            Ok(buf.len())
        }
        pub fn write(_ino: u64, _off: u64, data: &[u8]) -> Result<usize, i64> {
            note("write");
            Ok(data.len())
        }
        pub fn create(dir: u64, _name: &[u8], _perm: u32) -> Result<u64, i64> {
            note("create");
            Ok(dir + 2)
        }
        pub fn mknod(dir: u64, _name: &[u8], _mode: u32, _rdev: u64) -> Result<u64, i64> {
            note("mknod");
            Ok(dir + 3)
        }
        pub fn mkdir(dir: u64, _name: &[u8], _perm: u32) -> Result<u64, i64> {
            note("mkdir");
            Ok(dir + 4)
        }
        pub fn symlink(dir: u64, _name: &[u8], _target: &[u8]) -> Result<u64, i64> {
            note("symlink");
            Ok(dir + 5)
        }
        pub fn getxattr(_ino: u64, _name: &[u8]) -> Result<alloc::vec::Vec<u8>, i64> {
            note("getxattr");
            Ok(b"fx".to_vec())
        }
        pub fn setxattr(_ino: u64, _name: &[u8], _value: &[u8], _flags: u32) -> Result<(), i64> {
            note("setxattr");
            Ok(())
        }
        pub fn listxattr(_ino: u64) -> Result<alloc::vec::Vec<u8>, i64> {
            note("listxattr");
            Ok(b"user.f\0".to_vec())
        }
        pub fn removexattr(_ino: u64, _name: &[u8]) -> Result<(), i64> {
            note("removexattr");
            Ok(())
        }
        pub fn readlink(_ino: u64) -> Result<alloc::vec::Vec<u8>, i64> {
            note("readlink");
            Ok(b"/fuse/target".to_vec())
        }
        pub fn link(_ino: u64, _dir: u64, _name: &[u8]) -> Result<(), i64> {
            note("link");
            Ok(())
        }
        pub fn unlink(_dir: u64, _name: &[u8]) -> Result<(), i64> {
            note("unlink");
            Ok(())
        }
        pub fn rmdir(_dir: u64, _name: &[u8]) -> Result<(), i64> {
            note("rmdir");
            Ok(())
        }
        pub fn rename(_sdir: u64, _sname: &[u8], _ddir: u64, _dname: &[u8]) -> Result<(), i64> {
            note("rename");
            Ok(())
        }
        pub fn readdir(dir: u64, _cookie: u64, _max: usize) -> Result<alloc::vec::Vec<ReaddirEntry>, i64> {
            note("readdir");
            Ok(alloc::vec![ReaddirEntry { name: b"f".to_vec(), ino: dir + 9, dtype: 8, next_cookie: 3 }])
        }
        pub fn open_ref(_ino: u64) {
            note("open_ref");
        }
        pub fn release(_ino: u64) {
            note("release");
        }
    }
}
