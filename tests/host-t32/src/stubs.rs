//! *stub* Stand-ins for the kernel outside `src/arch` and `src/memory`, re-exported by
//! `lib.rs` at the kernel's module paths. Each is cut down to what the files under test
//! call. Calls with an effect are recorded in [`CALLS`] (per thread: each `#[test]` has
//! its own), and answers can be set per thread, so tests check what the arch code decided.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

thread_local! {
    /// `kprintln!`/`println!` output of this thread.
    pub static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Calls into the stubs with an effect, in order ("module::function args").
    pub static CALLS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    /// Integer answers of stubs, by name (absent: the stub's default).
    pub static ANSWERS: RefCell<BTreeMap<&'static str, i64>> = const { RefCell::new(BTreeMap::new()) };
    /// The UEFI load options (`iommu::load_options_say` stand-in) of this thread's boot.
    pub static LOAD_OPTIONS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub fn log(s: String) {
    LOG.with_borrow_mut(|l| l.push(s));
}

/// This thread's log lines, emptied.
pub fn take_log() -> Vec<String> {
    LOG.with_borrow_mut(std::mem::take)
}

/// Records a call.
pub fn call(s: String) {
    CALLS.with_borrow_mut(|c| c.push(s));
}

/// This thread's recorded calls, emptied.
pub fn take_calls() -> Vec<String> {
    CALLS.with_borrow_mut(std::mem::take)
}

/// What stub `name` answers (`default` unless set with [`answer`]).
pub fn ans(name: &'static str, default: i64) -> i64 {
    ANSWERS.with_borrow(|a| a.get(name).copied().unwrap_or(default))
}

/// Sets what stub `name` answers on this thread.
pub fn answer(name: &'static str, v: i64) {
    ANSWERS.with_borrow_mut(|a| a.insert(name, v));
}

/// Clears this thread's stub state.
pub fn reset() {
    LOG.with_borrow_mut(|l| l.clear());
    CALLS.with_borrow_mut(|l| l.clear());
    ANSWERS.with_borrow_mut(|l| l.clear());
    LOAD_OPTIONS.with_borrow_mut(|l| l.clear());
    console::SERIAL.with_borrow_mut(|s| s.clear());
    fs::bootfs::FILES.with_borrow_mut(|f| f.clear());
    task::reset();
}

macro_rules! rec {
    ($($arg:tt)*) => { $crate::stubs::call(format!($($arg)*)) };
}

pub mod linux {
    /// *stub* wave8 GB: not a live session (`compat::linux::live`).
    pub mod live {
        pub fn is_live() -> bool {
            false
        }
    }
    use crate::arch::idt::{ExceptionContext, FpuState};
    use crate::arch::syscall::SyscallFrame;
    use crate::stubs::ans;

    /// *stub* System call tracing switch (`linux trace`).
    pub static TRACE_SYSCALLS: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    pub fn trace_matches_current() -> bool {
        ans("linux::trace_matches_current", 1) != 0
    }
    /// Answers with `linux::fast_syscall` when set.
    pub fn fast_syscall(frame: &SyscallFrame) -> Option<i64> {
        let r = ans("linux::fast_syscall", i64::MIN);
        if r == i64::MIN {
            return None;
        }
        rec!("linux::fast_syscall {}", frame.rax);
        Some(r)
    }
    pub fn dispatch_linux_syscall(frame: &mut SyscallFrame) -> i64 {
        rec!("linux::dispatch {} {:#x} {:#x}", frame.rax, frame.rdi, frame.rsi);
        ans("linux::dispatch", 0)
    }
    pub fn changes_identity(nr: u64) -> bool {
        nr == 105 // setuid
    }
    // wave10 G8-1: *stub* (the request does not matter here)
    pub fn changes_identity_of(nr: u64, _arg0: u64) -> bool {
        changes_identity(nr)
    }
    pub fn ident_changed() {
        rec!("linux::ident_changed");
    }

    /// *stub* The profiler: nothing is measured on the host.
    pub mod prof {
        pub const FAULT_PRESENT: usize = 0;
        pub const FAULT_ANON: usize = 1;
        pub const FAULT_OBJECT: usize = 2;
        pub const FAULT_FAILED: usize = 3;
        pub fn start() -> u64 {
            0
        }
        pub fn fault(_kind: usize, _t0: u64) {}
        pub fn slow(_nr: u64, _r: i64, _a0: u64, _a1: u64, _a2: u64, _t0: u64) {}
        pub fn ipi_sent(kick: bool, _t0: u64) {
            rec!("prof::ipi_sent {}", kick);
        }
        pub fn kick_latency(_ns: u64) {}
    }
    /// *stub* No userfaultfd registrations on the host.
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
    /// *stub* The page cache: nothing to shrink on the host.
    pub mod mm {
        pub fn cache_shrink(_want: usize) {}
    }
    /// *stub* The process table's signal entry points.
    pub mod proc {
        use super::*;
        pub fn current_ids() -> (u64, u64) {
            (crate::stubs::ans("proc::tid", 7) as u64, crate::stubs::ans("proc::pid", 7) as u64)
        }
        pub fn force_fault_signal(ctx: &mut ExceptionContext, _fpu: *mut FpuState, sig: u32) {
            rec!("proc::force_fault_signal {} rip={:#x}", sig, ctx.rip);
        }
        pub fn set_exit_status(pid: u64, status: i32) {
            rec!("proc::set_exit_status {} {}", pid, status);
        }
        pub fn deliver_on_trap_return(ctx: &mut ExceptionContext, _fpu: *mut FpuState) {
            rec!("proc::deliver_on_trap_return {}", ctx.vector);
        }
        pub fn deliver_on_syscall_return(frame: &mut SyscallFrame, _fpu: *mut FpuState, nr: u64) {
            rec!("proc::deliver_on_syscall_return {} rax={}", nr, frame.rax as i64);
        }
    }
    /// *stub* ptrace: tracing set per thread.
    pub mod ptrace {
        use super::*;
        pub fn active() -> bool {
            ans("ptrace::active", 0) != 0
        }
        pub fn is_traced(_tid: u64) -> bool {
            ans("ptrace::traced", 0) != 0
        }
        pub fn syscall_entry(_frame: &mut SyscallFrame, _fpu: *mut FpuState, num: u64) -> Result<u64, i64> {
            rec!("ptrace::syscall_entry {}", num);
            match ans("ptrace::entry", i64::MIN) {
                i64::MIN => Ok(num),
                r if r < 0 => Err(r),
                n => Ok(n as u64),
            }
        }
        pub fn syscall_exit(_frame: &mut SyscallFrame, _fpu: *mut FpuState, num: u64, res: i64) -> i64 {
            rec!("ptrace::syscall_exit {} {}", num, res);
            res
        }
    }
    /// *stub*
    pub mod admin {
        pub fn flush() {
            rec!("linux::admin::flush");
        }
    }
    /// *stub* User memory copies: with no address space, user pointers are host pointers.
    pub mod vfs {
        pub fn copy_in(ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
            if ptr == 0 {
                return Err(-14);
            }
            Ok(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
        }
        pub fn copy_out(ptr: u64, data: &[u8]) -> Result<(), i64> {
            if ptr == 0 {
                return Err(-14);
            }
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
            Ok(())
        }
    }
    /// *stub*
    pub mod ldt {
        pub fn int80(eax: u64, ebx: u64) -> i64 {
            rec!("ldt::int80 {} {}", eax, ebx);
            crate::stubs::ans("ldt::int80", -38)
        }
    }
    /// *stub*
    pub mod perf {
        pub fn active() -> bool {
            crate::stubs::ans("perf::active", 0) != 0
        }
        pub fn fault(tgid: u64) {
            rec!("perf::fault {}", tgid);
        }
    }
    /// *stub*
    pub mod tty {
        pub static INPUT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
        pub fn pump() {
            rec!("tty::pump");
        }
    }
    /// *stub* evdev: input events recorded.
    pub mod evdev {
        pub fn routing() -> bool {
            crate::stubs::ans("evdev::routing", 0) != 0
        }
        pub fn push_scancode(code: u8) {
            rec!("evdev::scancode {:#x}", code);
        }
        pub fn push_mouse(dx: i32, dy: i32, wheel: i32, buttons: u8) {
            rec!("evdev::mouse {} {} {} {}", dx, dy, wheel, buttons);
        }
        pub fn push_abs(x: u16, y: u16, wheel: i8, buttons: u8) {
            rec!("evdev::abs {} {} {} {}", x, y, wheel, buttons);
        }
    }
    /// *stub*
    pub mod drm {
        pub fn session_hidden() -> bool {
            crate::stubs::ans("drm::session_hidden", 0) != 0
        }
        pub fn request_vt_switch(to_session: bool) {
            rec!("drm::request_vt_switch {}", to_session);
        }
    }
}

/// *stub* The scheduler and tasks.
pub mod task {
    use super::{ans, Cell, RefCell};
    use crate::arch::idt::ExceptionContext;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    /// The running thread (none on the host).
    pub static CURRENT_TID: AtomicU64 = AtomicU64::new(0);
    /// Preemption points held (the scheduler's counter).
    pub static PREEMPT_POINTS: AtomicU64 = AtomicU64::new(0);
    pub static TICK_DEFERRED: AtomicU64 = AtomicU64::new(0);
    pub static TICK_YIELD: AtomicU64 = AtomicU64::new(0);
    pub static CURRENT_SYSCALL: AtomicU64 = AtomicU64::new(u64::MAX);
    pub static CURRENT_SYSCALL_ARGS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

    thread_local! {
        /// Whether the scheduler runs (`task::is_active`).
        pub static ACTIVE: Cell<bool> = const { Cell::new(false) };
        pub static PERSONALITY: Cell<TaskPersonality> = const { Cell::new(TaskPersonality::Linux) };
        pub static RETIRED: Cell<u32> = const { Cell::new(0) };
        pub static SERVICE: Cell<Option<u32>> = const { Cell::new(None) };
        pub static ON_OWN_STACK: Cell<bool> = const { Cell::new(true) };
        pub static CURRENT: RefCell<Task> = RefCell::new(Task::default());
        pub static FDS: RefCell<Fds> = RefCell::new(Fds::default());
    }

    pub fn reset() {
        ACTIVE.set(false);
        PERSONALITY.set(TaskPersonality::Linux);
        RETIRED.set(0);
        SERVICE.set(None);
        ON_OWN_STACK.set(true);
        CURRENT.with_borrow_mut(|t| *t = Task::default());
        FDS.with_borrow_mut(|f| *f = Fds::default());
    }

    pub fn is_active() -> bool {
        ACTIVE.get()
    }
    pub fn is_active_hint() -> bool {
        ACTIVE.get()
    }
    pub fn current_personality() -> TaskPersonality {
        PERSONALITY.get()
    }
    /// Retired while running: true for the next `RETIRED` checks.
    pub fn current_retired() -> bool {
        let n = RETIRED.get();
        if n > 0 {
            RETIRED.set(n - 1);
        }
        n > 0
    }
    pub fn leave_retired() {
        rec!("task::leave_retired");
    }
    pub fn close_retired() {
        rec!("task::close_retired");
    }
    pub fn current_service() -> Option<u32> {
        SERVICE.get()
    }
    pub fn on_current_kernel_stack(_addr: u64) -> bool {
        ON_OWN_STACK.get()
    }
    pub fn tick_on_return() {
        rec!("task::tick_on_return");
    }
    pub fn yield_now() {
        rec!("task::yield_now");
    }
    pub fn sleep_ms(ms: u64) {
        rec!("task::sleep_ms {}", ms);
    }
    pub fn exit() -> ! {
        rec!("task::exit");
        panic!("task::exit")
    }
    pub fn exit_group() -> ! {
        rec!("task::exit_group");
        panic!("task::exit_group")
    }
    thread_local! {
        /// Entry points of the tasks spawned on this thread (tests may run them).
        pub static SPAWNED: RefCell<Vec<fn()>> = const { RefCell::new(Vec::new()) };
    }
    pub fn spawn(name: &'static str, entry: fn(), _prio: TaskPriority) -> TaskId {
        rec!("task::spawn {}", name);
        SPAWNED.with_borrow_mut(|s| s.push(entry));
        TaskId(99)
    }
    pub fn update_cr3(cr3: u64) {
        rec!("task::update_cr3 {:#x}", cr3);
    }
    pub fn with_current_task_mut<R>(f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        if ans("task::no_current", 0) != 0 {
            return None;
        }
        Some(CURRENT.with_borrow_mut(f))
    }
    pub fn with_current_fds_mut<R>(f: impl FnOnce(&mut Fds) -> R) -> R {
        FDS.with_borrow_mut(f)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TaskPersonality {
        Hydra,
        Linux,
        FreeBsd,
        MacOs,
    }
    impl TaskPersonality {
        pub fn is_posix(self) -> bool {
            self != TaskPersonality::Hydra
        }
    }
    pub enum TaskPriority {
        Idle,
        Low,
        Normal,
        High,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TaskId(pub u64);

    /// The fields of a task the arch code reads.
    #[derive(Default)]
    pub struct Task {
        pub debugregs: [u64; 8],
        pub cmdline: Option<Vec<u8>>,
        pub exe: String,
        pub mm: Option<alloc::sync::Arc<spin::Mutex<crate::memory::vm::Mm>>>,
    }
    impl Task {
        pub fn exe_path(&self) -> &str {
            &self.exe
        }
    }

    /// *stub* A descriptor table: a few slots of [`crate::fs::FileDescriptor`].
    #[derive(Default)]
    pub struct Fds {
        pub slots: Vec<Option<crate::fs::FileDescriptor>>,
        /// Most slots (`alloc_fd` fails beyond).
        pub limit: Option<usize>,
    }
    impl Fds {
        pub fn get_mut(&mut self, fd: usize) -> Option<&mut crate::fs::FileDescriptor> {
            self.slots.get_mut(fd).and_then(|s| s.as_mut())
        }
        pub fn alloc_fd(&mut self, d: crate::fs::FileDescriptor) -> Result<usize, &'static str> {
            let i = self.slots.iter().position(|s| s.is_none()).unwrap_or(self.slots.len());
            if self.limit.is_some_and(|l| i >= l) {
                return Err("EMFILE");
            }
            if i == self.slots.len() {
                self.slots.push(None);
            }
            self.slots[i] = Some(d);
            Ok(i)
        }
        pub fn close(&mut self, fd: usize) -> Result<(), &'static str> {
            self.slots.get_mut(fd).and_then(|s| s.take()).map(|_| ()).ok_or("EBADF")
        }
        pub fn dup2(&mut self, old: usize, new: usize) -> Result<usize, &'static str> {
            let d = self.slots.get(old).and_then(|s| s.clone()).ok_or("EBADF")?;
            while self.slots.len() <= new {
                self.slots.push(None);
            }
            self.slots[new] = Some(d);
            Ok(new)
        }
        pub fn trace_describe(&self, fd: usize) -> String {
            format!("fd{}", fd)
        }
    }

    pub mod wait {
        use core::sync::atomic::{AtomicU64, Ordering};
        /// *stub* A wait queue: counts wakeups.
        pub struct WaitQueue(AtomicU64);
        impl WaitQueue {
            pub const fn new() -> Self {
                Self(AtomicU64::new(0))
            }
            pub fn wake_all(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            pub fn wakes(&self) -> u64 {
                self.0.load(Ordering::SeqCst)
            }
            pub fn register(&self) {
                rec!("wq::register");
            }
            pub fn unregister(&self) {
                rec!("wq::unregister");
            }
        }
        pub fn wakes_pending() -> bool {
            crate::stubs::ans("wait::wakes_pending", 0) != 0
        }
        /// Waits: recorded; panics ("wait limit") after `wait::limit` waits to end loops.
        pub fn wait(deadline: Option<u64>) {
            rec!("wait::wait {:?}", deadline.is_some());
            let n = crate::stubs::ans("wait::count", 0) + 1;
            crate::stubs::answer("wait::count", n);
            if n >= crate::stubs::ans("wait::limit", i64::MAX) {
                panic!("wait limit");
            }
        }
    }

    pub mod scheduler {
        use core::sync::atomic::AtomicU64;
        pub static DIRECT_TO: AtomicU64 = AtomicU64::new(0);
        pub static DIRECT_HINT: AtomicU64 = AtomicU64::new(0);
        pub static DIRECT_GUARD: AtomicU64 = AtomicU64::new(0);
        pub fn handoff_active() -> bool {
            crate::stubs::ans("sched::handoff_active", 0) != 0
        }
        pub fn wait_out_handoff() {
            rec!("sched::wait_out_handoff");
        }
        pub fn reap_dead_tasks() {
            rec!("sched::reap_dead_tasks");
        }
        pub fn idle_task_entry() {
            rec!("sched::idle_task_entry");
        }
    }

    pub mod supervisor {
        pub fn start_all() {
            rec!("supervisor::start_all");
        }
    }

    /// *stub* The scheduler lock: a global flag (taking it twice on one thread panics,
    /// as the kernel would deadlock).
    pub struct Scheduler(core::sync::atomic::AtomicBool);
    pub static SCHEDULER: Scheduler = Scheduler(core::sync::atomic::AtomicBool::new(false));
    thread_local! {
        static HELD: Cell<bool> = const { Cell::new(false) };
        /// `try_lock` fails while this is set (another CPU holds it).
        pub static BUSY: Cell<u32> = const { Cell::new(0) };
    }
    pub struct SchedulerGuard;
    impl Scheduler {
        pub fn lock(&self) -> SchedulerGuard {
            assert!(!HELD.get(), "scheduler lock taken twice on one CPU");
            HELD.set(true);
            SchedulerGuard
        }
        pub fn try_lock(&self) -> Option<SchedulerGuard> {
            if BUSY.get() > 0 {
                BUSY.set(BUSY.get() - 1);
                return None;
            }
            if HELD.get() {
                return None;
            }
            HELD.set(true);
            Some(SchedulerGuard)
        }
        pub fn is_locked(&self) -> bool {
            HELD.get()
        }
    }
    impl Drop for SchedulerGuard {
        fn drop(&mut self) {
            HELD.set(false);
        }
    }
    impl SchedulerGuard {
        pub fn current_task_id(&self) -> TaskId {
            TaskId(ans("sched::current", 42) as u64)
        }
        pub fn current_index(&self) -> usize {
            3
        }
        pub fn account_tick(&mut self, ctx: &ExceptionContext) {
            rec!("sched::account_tick {}", ctx.vector);
        }
        pub fn schedule(&mut self, ctx: &mut ExceptionContext) {
            rec!("sched::schedule {}", ctx.vector);
        }
        pub fn schedule_now(&mut self, ctx: &mut ExceptionContext) {
            rec!("sched::schedule_now {}", ctx.vector);
        }
        pub fn apply_wakes(&mut self) {
            rec!("sched::apply_wakes");
        }
        pub fn handoff_server_ready(&self) -> bool {
            ans("sched::handoff_server_ready", 0) != 0
        }
        pub fn bury_current(&mut self) {
            rec!("sched::bury_current");
        }
        pub fn terminate_current(&mut self) {
            rec!("sched::terminate_current");
        }
        pub fn terminate_current_group(&mut self) {
            rec!("sched::terminate_current_group");
        }
        pub fn dump_tasks(&self) {
            rec!("sched::dump_tasks");
        }
        pub fn direct_switch(&mut self, _ctx: &mut ExceptionContext, to: u64) {
            rec!("sched::direct_switch {}", to);
        }
        pub fn direct_call(&mut self, _ctx: &mut ExceptionContext, to: u64, hint: usize, _g: *const core::sync::atomic::AtomicBool) -> bool {
            rec!("sched::direct_call {} {}", to, hint);
            ans("sched::direct_call", 1) != 0
        }
        pub fn add_cpu(&mut self, cpu: usize) {
            rec!("sched::add_cpu {}", cpu);
        }
        pub fn with_process<R>(&self, _pid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
            CURRENT.with_borrow(|t| Some(f(t)))
        }
        pub fn current_task_mut<R>(&mut self, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
            CURRENT.with_borrow_mut(|t| Some(f(t)))
        }
        pub fn spawn_native_thread(&mut self, _frame: &crate::arch::syscall::SyscallFrame, entry: u64, stack: u64, arg: u64) -> Result<TaskId, &'static str> {
            rec!("sched::spawn_native_thread {:#x} {:#x} {}", entry, stack, arg);
            if ans("sched::spawn_fails", 0) != 0 {
                Err("no memory")
            } else {
                Ok(TaskId(77))
            }
        }
    }
    /// Unused: keeps `AtomicUsize`/`Ordering` imported for edits.
    static _UNUSED: AtomicUsize = AtomicUsize::new(0);
    fn _unused() -> usize {
        _UNUSED.load(Ordering::Relaxed)
    }
}

/// *stub* The console: serial output is kept per thread.
pub mod console {
    use std::cell::RefCell;
    thread_local! {
        /// What went to the serial port on this thread.
        pub static SERIAL: RefCell<String> = const { RefCell::new(String::new()) };
    }
    pub fn serial_write(s: &str) {
        SERIAL.with_borrow_mut(|o| o.push_str(s));
    }
    /// This thread's serial output, emptied.
    pub fn take_serial() -> String {
        SERIAL.with_borrow_mut(std::mem::take)
    }
    pub fn set_color(fg: uefi::proto::console::text::Color, _bg: uefi::proto::console::text::Color) {
        rec!("console::set_color {:?}", fg);
    }
    pub fn clear_scrollback() {
        rec!("console::clear_scrollback");
    }
    pub fn clear_screen() {
        rec!("console::clear_screen");
    }
    pub fn enable_standalone_video(on: bool) {
        rec!("console::enable_standalone_video {}", on);
    }
    pub fn set_hardware_mode(on: bool) {
        rec!("console::set_hardware_mode {}", on);
    }
    /// Verbatim from the kernel: a fixed buffer for formatting without allocating.
    pub struct FixedBuf {
        buf: [u8; 160],
        len: usize,
    }
    impl FixedBuf {
        pub const fn new() -> Self {
            Self { buf: [0; 160], len: 0 }
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
        }
    }
    impl core::fmt::Write for FixedBuf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
            self.len += n;
            Ok(())
        }
    }
    /// `core::fmt::Write` to the serial port only.
    pub struct SerialOnly;
    impl core::fmt::Write for SerialOnly {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            serial_write(s);
            Ok(())
        }
    }
}

/// *stub* File systems and descriptors.
pub mod fs {
    use alloc::sync::Arc;

    /// wave7 G7-7: the real shared offset of by-path descriptors.
    #[path = "../../../../../src/fs/cursor.rs"]
    pub mod cursor;
    pub use cursor::FileCursor;

    /// *stub* The FAT boot volume: files set per thread.
    pub mod bootfs {
        use std::cell::RefCell;
        use std::collections::BTreeMap;
        thread_local! {
            pub static FILES: RefCell<BTreeMap<String, Vec<u8>>> = const { RefCell::new(BTreeMap::new()) };
        }
        pub fn file_exists(path: &str) -> bool {
            FILES.with_borrow(|f| f.contains_key(path))
        }
        pub fn read_boot_file(path: &str) -> Result<Vec<u8>, &'static str> {
            FILES.with_borrow(|f| f.get(path).cloned()).ok_or("not found")
        }
    }
    /// *stub*
    pub mod client {
        pub fn start_txg_sync() {
            rec!("fs::start_txg_sync");
        }
    }
    /// *stub*
    pub struct ZfsClient;
    impl ZfsClient {
        pub fn touch_file(path: &str) -> Result<(), &'static str> {
            rec!("zfs::touch {}", path);
            Ok(())
        }
        pub fn sync() -> Result<(), &'static str> {
            rec!("zfs::sync");
            if crate::stubs::ans("zfs::sync_fails", 0) != 0 {
                Err("pool gone")
            } else {
                Ok(())
            }
        }
    }
    /// *stub* A pipe: the bytes written.
    #[derive(Default)]
    pub struct PipeBuffer(pub spin::Mutex<Vec<u8>>);
    impl PipeBuffer {
        pub fn new() -> Arc<PipeBuffer> {
            Arc::new(PipeBuffer::default())
        }
    }
    /// *stub* The descriptor variants the native system calls make.
    #[derive(Clone)]
    pub enum FileDescriptor {
        File { path: String, cursor: FileCursor, readable: bool, writable: bool, append: bool, shown: Option<u64> },
        PipeRead(Arc<PipeBuffer>),
        PipeWrite(Arc<PipeBuffer>),
        /// A test descriptor: writes collect here, reads give these bytes; `fail` makes both fail.
        Buf { data: Arc<spin::Mutex<Vec<u8>>>, fail: bool },
    }
    impl FileDescriptor {
        pub fn write(&mut self, d: &[u8]) -> Result<usize, &'static str> {
            match self {
                FileDescriptor::Buf { data, fail: false } => {
                    data.lock().extend_from_slice(d);
                    Ok(d.len())
                }
                FileDescriptor::PipeWrite(p) => {
                    p.0.lock().extend_from_slice(d);
                    Ok(d.len())
                }
                _ => Err("EIO"),
            }
        }
        pub fn read(&mut self, out: &mut [u8]) -> Result<usize, &'static str> {
            match self {
                FileDescriptor::Buf { data, fail: false } => {
                    let d = data.lock();
                    let n = d.len().min(out.len());
                    out[..n].copy_from_slice(&d[..n]);
                    Ok(n)
                }
                _ => Err("EIO"),
            }
        }
    }
}

/// *stub* The ring-3 service layer and endpoints.
pub mod ipc {
    pub mod service {
        use crate::ipc::message::Message;
        use crate::stubs::ans;
        pub const CALL_TIMEOUT_TICKS: u64 = 500;
        pub const GRANT_RANGES: usize = 4;
        pub const MSI_FIRST_LINE: u8 = 16;
        /// Verbatim from the kernel.
        #[repr(C)]
        #[derive(Clone, Copy, Default)]
        pub struct WireMessage {
            pub label: u64,
            pub args: [u64; 4],
        }
        impl From<Message> for WireMessage {
            fn from(m: Message) -> Self {
                Self { label: m.label as u64, args: m.args }
            }
        }
        impl From<WireMessage> for Message {
            fn from(w: WireMessage) -> Self {
                Message::with_args(w.label as u32, w.args)
            }
        }
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum CallMode {
            Handoff,
            Queued,
        }
        pub struct GrantSpec {
            pub ranges: [(u64, u64); GRANT_RANGES],
            pub n: usize,
            pub server_writes: bool,
        }
        fn res(name: &'static str) -> Result<i64, i64> {
            let r = ans(name, 0);
            if r < 0 {
                Err(r)
            } else {
                Ok(r)
            }
        }
        pub fn iopl_allowed() -> Result<(), i64> {
            res("svc::iopl").map(|_| ())
        }
        pub fn physmap(a: u64, l: u64) -> Result<u64, i64> {
            rec!("svc::physmap {:#x} {}", a, l);
            res("svc::physmap").map(|v| v as u64)
        }
        pub fn dma_alloc(l: u64) -> Result<(u64, u64), i64> {
            rec!("svc::dma_alloc {}", l);
            res("svc::dma_alloc").map(|v| (v as u64, 0x1234_5000))
        }
        pub fn irq_register(l: u64) -> Result<(), i64> {
            rec!("svc::irq_register {}", l);
            res("svc::irq_register").map(|_| ())
        }
        pub fn irq_wait(l: u64, t: u64) -> Result<u64, i64> {
            rec!("svc::irq_wait {} {}", l, t);
            res("svc::irq_wait").map(|v| v as u64)
        }
        pub fn irq_ack(l: u64) -> Result<u64, i64> {
            rec!("svc::irq_ack {}", l);
            res("svc::irq_ack").map(|v| v as u64)
        }
        pub fn attach(ep: u32) -> Result<u64, i64> {
            rec!("svc::attach {}", ep);
            res("svc::attach").map(|v| v as u64)
        }
        pub fn register(ep: u32) -> Result<u64, i64> {
            rec!("svc::register {}", ep);
            res("svc::register").map(|v| v as u64)
        }
        pub fn recv_with(ep: u32, flags: u64) -> Result<(u64, Message), i64> {
            rec!("svc::recv_with {} {:#x}", ep, flags);
            res("svc::recv").map(|id| (id as u64, Message::with_args(5, [1, 2, 3, 4])))
        }
        pub fn reply_recv(ep: u32, id: u64, m: Message, flags: u64) -> Result<(u64, Message), i64> {
            rec!("svc::reply_recv {} {} {} {:#x}", ep, id, m.label, flags);
            res("svc::recv").map(|id| (id as u64, Message::with_args(6, [4, 3, 2, 1])))
        }
        pub fn reply(ep: u32, id: u64, m: Message) -> Result<(), i64> {
            rec!("svc::reply {} {} {}", ep, id, m.label);
            res("svc::reply").map(|_| ())
        }
        pub fn driver_call_mode() -> CallMode {
            CallMode::Queued
        }
        pub fn call_mode(ep: u32, m: Message, timeout: u64, mode: CallMode) -> Result<Message, i64> {
            rec!("svc::call_mode {} {} {} {:?}", ep, m.label, timeout, mode);
            res("svc::call").map(|_| Message::with_args(m.label + 1, m.args))
        }
        pub fn call_with(ep: u32, m: Message, timeout: u64, mode: CallMode, spec: Option<&GrantSpec>) -> Result<Message, i64> {
            let s = spec.map(|s| format!("{} {:?} {}", s.n, &s.ranges[..s.n], s.server_writes)).unwrap_or_default();
            rec!("svc::call_with {} {} {} {:?} {}", ep, m.label, timeout, mode, s);
            res("svc::call").map(|_| Message::with_args(m.label + 1, m.args))
        }
        pub fn signal(ep: u32, bits: u64) -> Result<(), i64> {
            rec!("svc::signal {} {:#x}", ep, bits);
            res("svc::signal").map(|_| ())
        }
        pub fn grant_segments(ep: u32, id: u64) -> Result<(Vec<(u64, u64)>, u64), i64> {
            rec!("svc::grant_segments {} {}", ep, id);
            res("svc::grant").map(|_| (vec![(0x1000, 0x200), (0x5000, 0x10)], 0))
        }
        pub fn irq_raised(irq: u8) -> bool {
            rec!("svc::irq_raised {}", irq);
            ans("svc::irq_raised", 0) != 0
        }
        pub fn msix_line(dev: &crate::arch::pci::PciDevice) -> Option<(u8, u64, u32, u32)> {
            rec!("svc::msix_line {:02x}:{:02x}.{}", dev.bus, dev.device, dev.function);
            (ans("svc::msix_line", 1) != 0).then_some((20, 0xFEE0_0000, 0x54, 4))
        }
        pub fn is_online(ep: u32) -> bool {
            ans("svc::online", 0) != 0 && ep != 0
        }
        pub fn notify_on_irq(ep: u32, _wq: &'static crate::task::wait::WaitQueue) {
            rec!("svc::notify_on_irq {}", ep);
        }
        pub struct WindowGuard;
        pub fn hold_window_queued(_ep: u32) -> WindowGuard {
            WindowGuard
        }
        std::thread_local! {
            /// Replies of `call_queued` (front first) and the window's bytes.
            pub static QUEUED: std::cell::RefCell<std::collections::VecDeque<Result<Message, i64>>> = const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
            pub static WINDOW: std::cell::RefCell<Option<&'static mut [u8]>> = const { std::cell::RefCell::new(None) };
        }
        pub fn call_queued(ep: u32, m: Message, _timeout: u64) -> Result<Message, i64> {
            rec!("svc::call_queued {} {}", ep, m.label);
            QUEUED.with_borrow_mut(|q| q.pop_front()).unwrap_or(Err(-110))
        }
        pub fn window(_ep: u32) -> Option<&'static mut [u8]> {
            WINDOW.with_borrow_mut(|w| w.as_mut().map(|s| unsafe { core::slice::from_raw_parts_mut(s.as_mut_ptr(), s.len()) }))
        }
    }
    pub mod endpoint {
        use crate::ipc::message::Message;
        /// *stub* System endpoint 1 exists; messages go through a per-thread queue.
        pub struct Ep;
        std::thread_local! {
            pub static QUEUE: std::cell::RefCell<std::collections::VecDeque<Message>> = const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        }
        impl Ep {
            pub fn send_blocking(&self, m: Message) {
                rec!("ep::send_blocking {}", m.label);
                QUEUE.with_borrow_mut(|q| q.push_back(m));
            }
            pub fn send(&self, m: Message) -> Result<(), ()> {
                if QUEUE.with_borrow(|q| q.len()) >= 2 {
                    return Err(());
                }
                QUEUE.with_borrow_mut(|q| q.push_back(m));
                Ok(())
            }
            pub fn receive_blocking(&self) -> Message {
                QUEUE.with_borrow_mut(|q| q.pop_front()).unwrap_or(Message::with_args(9, [0; 4]))
            }
            pub fn receive(&self) -> Option<Message> {
                QUEUE.with_borrow_mut(|q| q.pop_front())
            }
        }
        pub fn get_system_endpoint(id: u32) -> Option<&'static Ep> {
            static EP: Ep = Ep;
            (id == 1).then_some(&EP)
        }
    }
}

/// *stub* The forwarding to the ring-3 Linux server.
pub mod lx {
    /// *stub* wave8 GT: the terminals are never tty-server's here (`tty::pump` runs).
    pub mod console {
        pub fn forwarded() -> bool {
            false
        }
        /// Not forwarded: the in-kernel copy's pump, as the kernel's `trap_pump` does.
        pub fn trap_pump() {
            crate::compat::linux::tty::pump();
        }
    }
    use crate::arch::syscall::SyscallFrame;
    use crate::stubs::ans;
    pub enum Fast {
        Call(i64),
        Reply(i64),
    }
    #[derive(Debug)]
    pub enum MemOp {
        Read,
        Write,
        ReadStr,
    }
    /// Answers `lx::fast` (0: none, 1: a call with `lx::fast_r`, 2: a reply).
    pub fn fast_entry(frame: &SyscallFrame) -> Option<Fast> {
        let r = ans("lx::fast_r", 0);
        match ans("lx::fast", 0) {
            1 => {
                rec!("lx::fast_entry call {}", frame.rax);
                Some(Fast::Call(r))
            }
            2 => {
                rec!("lx::fast_entry reply {}", frame.rax);
                Some(Fast::Reply(r))
            }
            _ => None,
        }
    }
    pub fn delivery_maybe() -> bool {
        ans("lx::delivery_maybe", 0) != 0
    }
    pub fn ctl(op: u64) -> i64 {
        rec!("lx::ctl {}", op);
        11
    }
    pub fn reply_recv(r: i64, f: u64) -> i64 {
        rec!("lx::reply_recv {} {}", r, f);
        12
    }
    pub fn complete(id: u64, r: i64) -> i64 {
        rec!("lx::complete {} {}", id, r);
        13
    }
    pub fn client_mem(op: MemOp, id: u64, a: u64, l: u64, b: u64) -> i64 {
        rec!("lx::client_mem {:?} {} {} {} {}", op, id, a, l, b);
        14
    }
    pub fn proc_info(t: u64, o: u64) -> i64 {
        rec!("lx::proc_info {} {}", t, o);
        15
    }
    pub mod obj {
        pub fn obj_ctl(op: u64, a: u64, b: u64, c: u64) -> i64 {
            rec!("lx::obj_ctl {} {} {} {}", op, a, b, c);
            16
        }
        pub fn sig_post(t: u64, s: u64, c: u64, i: u64, v: u64) -> i64 {
            rec!("lx::sig_post {} {} {} {} {}", t, s, c, i, v);
            17
        }
        pub fn sig_take(id: u64, m: u64, b: u64, u: u64) -> i64 {
            rec!("lx::sig_take {} {} {} {}", id, m, b, u);
            18
        }
    }
    pub mod timer {
        pub fn sys_timer(op: u64, c: u64, ns: u64) -> i64 {
            rec!("lx::sys_timer {} {} {}", op, c, ns);
            19
        }
        pub fn on_tick() {
            rec!("lx::timer::on_tick");
        }
    }
    pub mod dcall {
        pub fn dcall(me: u64, idx: usize, a: [u64; 6], nobkl: bool) -> i64 {
            rec!("lx::dcall {} {} {:?} {}", me, idx, a, nobkl);
            20
        }
        pub fn post(a: [u64; 6]) -> i64 {
            rec!("lx::post {:?}", a);
            21
        }
    }
    pub mod mem {
        pub fn sys_mem(op: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
            rec!("lx::sys_mem {} {} {} {} {}", op, a, b, c, d);
            22
        }
    }
    pub mod svc {
        pub fn svc_ctl(op: u64, a: u64, b: u64, c: u64) -> i64 {
            rec!("lx::svc_ctl {} {} {} {}", op, a, b, c);
            23
        }
    }
}

/// *stub* The personality hook: a table pointer per CPU.
pub mod personality {
    pub struct Table(pub u32);
    pub static CURRENT_TABLE: crate::arch::percpu::PerCpuPtr<Table> = crate::arch::percpu::PerCpuPtr::new();
    pub fn syscall(frame: &mut crate::arch::syscall::SyscallFrame, _fpu: *mut crate::arch::idt::FpuState, t: &'static Table) {
        rec!("personality::syscall {} table {}", frame.rax, t.0);
    }
}

/// *stub* The shell's admin interface.
pub mod admin {
    pub mod proto {
        pub const SYS_ADMIN: u64 = 40;
    }
    pub fn syscall(arg: u64) -> i64 {
        rec!("admin::syscall {:#x}", arg);
        24
    }
}

/// *stub*
pub mod video {
    pub struct VideoModeInfo {
        pub base_ptr: *mut u8,
    }
    thread_local! {
        pub static FB: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    pub fn get_video_info() -> Option<VideoModeInfo> {
        let fb = FB.get();
        (fb != 0).then_some(VideoModeInfo { base_ptr: fb as *mut u8 })
    }
    pub mod splash {
        pub fn tick() {
            rec!("splash::tick");
        }
    }
}

// *stub* The fix-up labels of `crate::lx::copy`'s user-memory copies: each "instruction"
// range is 4 bytes, its fix-up right after it.
core::arch::global_asm!(
    ".text",
    ".globl hydra_uaccess_copy_insn",
    ".globl hydra_uaccess_copy_insn_end",
    ".globl hydra_uaccess_copy_fix",
    ".globl hydra_uaccess_str_insn",
    ".globl hydra_uaccess_str_insn_end",
    ".globl hydra_uaccess_str_fix",
    "hydra_uaccess_copy_insn:",
    "nop", "nop", "nop", "nop",
    "hydra_uaccess_copy_insn_end:",
    "nop",
    "hydra_uaccess_copy_fix:",
    "ret",
    "hydra_uaccess_str_insn:",
    "nop", "nop", "nop", "nop",
    "hydra_uaccess_str_insn_end:",
    "nop",
    "hydra_uaccess_str_fix:",
    "ret",
);
