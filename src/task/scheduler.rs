//! # Task Subsystem: Preemptive Round-Robin Scheduler
//!
//! Implements the kernel's priority-aware preemptive round-robin task scheduler, context
//! switcher, thread/process cloner (`clone`/`fork`), and task lifecycle manager.
//!
//! ## Architectural Role & Design Rationale
//!
//! Driven by the 100 Hz Programmable Interval Timer (IRQ 0) and cooperative yield interrupts
//! (`int 0x81`), `Scheduler` multiplexes CPU execution across kernel threads and Ring 3 user
//! processes. High-priority service tasks (`TaskPriority::High` and above) are scheduled ahead
//! of normal round-robin tasks, while `TaskPriority::Idle` runs only when no other task is ready.
//! On each context switch, the scheduler saves and restores general-purpose registers, `FS_BASE`,
//! x87/SSE FPU state, TSS `RSP0`, and the `CR3` page table root.
//!
//! ## Key Types & Interfaces
//!
//! - `Scheduler`: Core scheduler state machine managing the task table and active context switches.
//! - [`SCHEDULER`]: Global spinlock-protected `Scheduler` singleton.
//! - `TaskSnapshot`: Diagnostic summary of a task's state, priority, registers, and CPU ticks.
//!
//! ## Hardware & Dependency Context
//!
//! - **Interrupt Frame**: Saves/restores `ExceptionContext` pushed by hardware interrupt stubs.
//! - **CPU Registers & MSRs**: Updates `CR3`, `IA32_FS_BASE` (`0xC000_0100`), TSS `RSP0`, and `SYSCALL` kernel RSP.

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::registers::control::Cr3;

use crate::arch::idt::ExceptionContext;
use crate::capability::table::CapabilityTable;
use super::tcb::{PrivilegeMode, Task, TaskId, TaskPriority, TaskRegisters, TaskState};

/// Default timeslice granted to a scheduled task in PIT timer ticks (50 ms at 100 Hz).
pub const DEFAULT_TIMESLICE_TICKS: u32 = 5; // 50ms at 100 Hz PIT timer
/// Scheduling decisions a ready task may lose before it goes first (about 100 ms when
/// woken tasks take every tick).
const STARVATION_LIMIT: u32 = 10;
/// Default kernel stack size allocated per thread in bytes (64 KiB).
pub const DEFAULT_STACK_SIZE: usize = 65536;

/// Dead tasks moved out of the table by the scheduler, waiting to be freed outside the
/// timer interrupt (see [`reap_dead_tasks`]).
static PARKED_TASKS: spin::Mutex<[Option<Task>; 64]> = spin::Mutex::new([const { None }; 64]);

/// Frees the kernel stacks and other memory of dead tasks parked by the scheduler. Call
/// only where no heap, scheduler or file-system locks are held (system call entry).
pub fn reap_dead_tasks() {
    loop {
        // One at a time: a task is too large to move many of them onto this stack
        let task = match PARKED_TASKS.try_lock() {
            Some(mut p) => match p.iter_mut().find(|s| s.is_some()) {
                Some(slot) => slot.take(),
                None => None,
            },
            None => None,
        };
        match task {
            Some(t) => drop(t),
            None => break,
        }
    }
}  // 64 KiB per kernel thread stack

/// Diagnostic snapshot of a task for shell inspection (e.g. `ps` / `tasks` command).
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    /// Unique task identifier (PID/TID).
    pub id: TaskId,
    /// Human-readable task name.
    pub name: &'static str,
    /// Current scheduling state of the task.
    pub state: TaskState,
    /// Scheduling priority class.
    pub priority: TaskPriority,
    /// CPU privilege mode (`Kernel` Ring 0 or `User` Ring 3).
    pub mode: PrivilegeMode,
    /// Real user ID (`uid`) owning the task.
    pub uid: u32,
    /// Total PIT timer ticks accumulated by this task.
    pub ticks_run: u64,
    /// Last saved stack pointer (`RSP`).
    pub rsp: u64,
    /// Last saved instruction pointer (`RIP`).
    pub rip: u64,
}

/// Loads a Linux program into a new address space, for [`Scheduler::spawn_linux_process`].
///
/// Reads files (its dynamic linker), so it must run without the scheduler lock: disk reads
/// are calls to the disk driver process, which need the scheduler.
///
/// # Arguments
///
/// * `exe` - ELF image source descriptor.
/// * `exec_path` - Path string for `/proc/<pid>/exe`.
/// * `args` - Command-line arguments.
/// * `uid` - Process user ID.
/// * `gid` - Process group ID.
/// * `root` - Optional chroot root directory inode.
///
/// # Returns
///
/// `Ok(LinuxExecImage)` containing the loaded memory space, entry point, and stack layout.
///
/// # Errors
///
/// Returns static error string if binary parsing or dynamic linker loading fails.
pub fn load_linux_image(
    exe: super::exec::ElfSource,
    exec_path: &str,
    args: &[&str],
    uid: u32,
    gid: u32,
    root: Option<u64>,
) -> Result<super::exec::LinuxExecImage, &'static str> {
    let read_in_root = |path: &str| -> Option<super::exec::ElfSource> {
        let root = root?;
        let ino = crate::fs::ZfsClient::resolve_in(root, root, path.as_bytes(), true).ok()?;
        crate::compat::linux::mm::inode_source(ino).ok()
    };
    let read_legacy = |path: &str| -> Option<super::exec::ElfSource> {
        read_interpreter(path).map(|b| super::exec::ElfSource::from_bytes(b.into_boxed_slice()))
    };
    let interp_reader: &dyn Fn(&str) -> Option<super::exec::ElfSource> = if root.is_some() { &read_in_root } else { &read_legacy };
    let env = linux_env(uid);
    let env: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    super::exec::load_linux_exec(exe, exec_path, args, &env, super::exec::ExecCreds { uid, gid, euid: uid, egid: gid }, interp_reader)
        .map_err(|e| e.as_str())
}

/// Global preemptive round-robin scheduler instance.
pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

/// Preemptive Round-Robin Multitasking Scheduler.
pub struct Scheduler {
    /// Table of all registered tasks (active, sleeping, blocked, and dead).
    tasks: Vec<Task>,
    /// Index into `tasks` of the currently executing task.
    current_index: usize,
    /// Monotonically increasing counter for assigning new `TaskId`s.
    next_id: u64,
    /// Default timeslice in timer ticks assigned when a task is scheduled.
    default_timeslice: u32,
    /// True once [`Scheduler::init`] has registered the boot/main task and idle thread.
    initialized: bool,
    /// The kernel's own page table root, which kernel tasks always run on (never a Linux
    /// process's tables: those are freed when the process exits).
    kernel_cr3: u64,
    /// Driver calls in progress, innermost last (a server may call another service).
    handoffs: [Option<Handoff>; MAX_HANDOFFS],
    /// The caller of a driver call that just ended: it runs next, before any other task,
    /// since it may hold kernel locks (as when an in-kernel driver returned to it).
    resume_first: Option<u64>,
    /// Descriptor tables of exited tasks, to close without the scheduler lock (closing a
    /// socket or a file talks to a driver process, which needs the scheduler).
    pending_close: Vec<crate::fs::FdTable>,
}

/// Nesting limit of driver calls (kernel -> file server -> disk driver needs 2).
const MAX_HANDOFFS: usize = 8;

/// Whether a driver call is in progress (mirrors [`Scheduler::handoffs`] for lock-free
/// checks): its caller may hold kernel locks.
static HANDOFF_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether a driver is serving a call, whose caller may hold kernel locks (the file
/// system's): work that takes such locks must wait until it is over.
///
/// # Returns
///
/// `true` if any service handoff is actively executing.
pub fn handoff_active() -> bool {
    HANDOFF_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
}

/// A driver call in progress ([`crate::ipc::service::call`]): `caller` waits while only
/// `server` runs, as an in-kernel driver would have run in the caller's place. Callers may
/// hold kernel locks; no other task runs until the reply, so none can contend for them.
#[derive(Clone, Copy)]
struct Handoff {
    /// Task serving the call.
    server: u64,
    /// Task waiting for the reply.
    caller: u64,
    /// Tick after which the caller resumes without a reply.
    deadline: u64,
}

impl Scheduler {
    /// Creates an uninitialized `Scheduler` with an empty task list.
    pub const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_index: 0,
            next_id: 1,
            default_timeslice: DEFAULT_TIMESLICE_TICKS,
            initialized: false,
            kernel_cr3: 0,
            handoffs: [None; MAX_HANDOFFS],
            resume_first: None,
            pending_close: Vec::new(),
        }
    }

    /// Takes the descriptor tables of exited tasks, for [`crate::task::close_retired`].
    ///
    /// # Returns
    ///
    /// Vector of orphaned [`crate::fs::FdTable`] instances to close.
    pub fn take_pending_close(&mut self) -> Vec<crate::fs::FdTable> {
        core::mem::take(&mut self.pending_close)
    }

    /// Takes the current task's descriptor table if no other thread shares it (it is
    /// about to exit and closes it itself, before it is retired).
    ///
    /// # Returns
    ///
    /// `Some(FdTable)` if this was the last thread referencing the table, `None` otherwise.
    pub fn take_current_fds_if_last(&mut self) -> Option<crate::fs::FdTable> {
        if !self.initialized || self.current_index >= self.tasks.len() {
            return None;
        }
        let task = &mut self.tasks[self.current_index];
        if alloc::sync::Arc::strong_count(&task.fds) != 1 {
            return None;
        }
        let fds = core::mem::replace(&mut task.fds, crate::fs::FdTable::empty().into_shared());
        alloc::sync::Arc::try_unwrap(fds).ok().map(|m| m.into_inner())
    }

    /// Innermost driver call in progress.
    ///
    /// # Returns
    ///
    /// `Some(Handoff)` of the active handoff level, or `None` if normal scheduling applies.
    fn handoff_top(&self) -> Option<Handoff> {
        self.handoffs.iter().rev().find_map(|h| *h)
    }

    /// Publishes whether a driver call is in progress (after the stack changed).
    fn note_handoffs(&self) {
        HANDOFF_ACTIVE.store(self.handoffs.iter().any(|h| h.is_some()), core::sync::atomic::Ordering::Release);
    }

    /// Blocks the current task in a call to the driver task `server` and lets only that
    /// task run (the caller then yields) until [`Self::end_handoff`] or tick `deadline`.
    /// Returns `false` if calls are nested too deeply.
    ///
    /// # Arguments
    ///
    /// * `server` - Task ID of the service provider driver.
    /// * `deadline` - Maximum PIT timer tick before caller timeout.
    ///
    /// # Returns
    ///
    /// `true` if handoff was established, `false` if handoff stack exceeded `MAX_HANDOFFS`.
    pub fn begin_handoff(&mut self, server: u64, deadline: u64) -> bool {
        let Some(slot) = self.handoffs.iter().position(|h| h.is_none()) else { return false };
        let caller = self.current_task_id().0;
        self.handoffs[slot] = Some(Handoff { server, caller, deadline });
        self.note_handoffs();
        self.block_current();
        true
    }

    /// Ends the innermost driver call, served by `server`, and makes its caller runnable.
    ///
    /// # Arguments
    ///
    /// * `server` - Server Task ID matching the active handoff.
    pub fn end_handoff(&mut self, server: u64) {
        if let Some(i) = self.handoffs.iter().rposition(|h| h.is_some()) {
            if let Some(h) = self.handoffs[i] {
                if h.server == server {
                    self.handoffs[i] = None;
                    self.note_handoffs();
                    self.resume_caller(h.caller);
                }
            }
        }
    }

    /// Makes a task blocked in a driver call runnable again, and the next to run.
    ///
    /// # Arguments
    ///
    /// * `caller` - Task ID of the waiting caller to resume.
    fn resume_caller(&mut self, caller: u64) {
        if let Some(t) = self.tasks.iter_mut().find(|t| t.id.0 == caller) {
            if t.state == TaskState::Blocked {
                t.state = TaskState::Ready;
                t.woken = true;
                self.resume_first = Some(caller);
            }
        }
    }

    /// Initializes multitasking by wrapping the current execution thread as Task 0 ("shell").
    ///
    /// # Arguments
    ///
    /// * `current_cr3` - Physical CR3 page directory address active at boot.
    pub fn init(&mut self, current_cr3: u64) {
        if self.initialized {
            return;
        }

        self.kernel_cr3 = current_cr3;
        // Register the active main thread as Task 0
        let main_task = Task::new_main(TaskId(0), "shell", current_cr3);
        self.tasks.push(main_task);
        self.current_index = 0;
        self.initialized = true;

        // Spawn background Idle task (Task 1) with lowest priority
        self.spawn_internal("idle", idle_task_entry, TaskPriority::Idle, current_cr3);
    }

    /// Updates the CR3 root paging address for the primary main task and background kernel tasks.
    ///
    /// # Arguments
    ///
    /// * `cr3` - Physical CR3 base register address.
    pub fn update_main_cr3(&mut self, cr3: u64) {
        self.kernel_cr3 = cr3;
        for task in &mut self.tasks {
            task.regs.cr3 = cr3;
        }
    }

    /// Returns true if the scheduler has been initialized via [`Self::init`].
    ///
    /// # Returns
    ///
    /// `true` if initialized, `false` otherwise.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Spawns a new kernel thread with the given entry point and priority.
    ///
    /// # Arguments
    ///
    /// * `name` - Static string identifier for the kernel thread.
    /// * `entry_fn` - Function pointer to the thread entry.
    /// * `priority` - Initial scheduling priority level.
    ///
    /// # Returns
    ///
    /// The unique [`TaskId`] assigned to the new thread.
    pub fn spawn(
        &mut self,
        name: &'static str,
        entry_fn: fn(),
        priority: TaskPriority,
    ) -> TaskId {
        // Kernel tasks may be started from a Linux system call (itimerd from alarm()):
        // they still get the kernel's tables, not the caller's
        let cr3 = if self.kernel_cr3 != 0 { self.kernel_cr3 } else { Cr3::read().0.start_address().as_u64() };
        self.spawn_internal(name, entry_fn, priority, cr3)
    }

    /// Allocates a kernel stack and appends a new Ring 0 task using page table root `cr3`.
    ///
    /// # Arguments
    ///
    /// * `name` - Static string name of the thread.
    /// * `entry_fn` - Entry function pointer.
    /// * `priority` - Task priority.
    /// * `cr3` - CR3 physical address to assign to task registers.
    ///
    /// # Returns
    ///
    /// The allocated [`TaskId`].
    fn spawn_internal(
        &mut self,
        name: &'static str,
        entry_fn: fn(),
        priority: TaskPriority,
        cr3: u64,
    ) -> TaskId {
        let id = TaskId(self.next_id);
        self.next_id += 1;

        // Allocate a dedicated 16 KiB kernel stack on the heap
        let stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();
        let stack_bottom = stack.as_ptr() as u64;
        let stack_top = (stack_bottom + stack.len() as u64) & !0xF;
        let initial_rsp = stack_top.saturating_sub(48);

        let mut regs = TaskRegisters::empty();
        regs.rip = task_trampoline as *const () as usize as u64;
        let fn_ptr = entry_fn as *const () as usize as u64;
        regs.rcx = fn_ptr; // 1st arg in Win64 / UEFI ABI
        regs.rdi = fn_ptr; // 1st arg in SysV AMD64 ABI
        regs.rsp = initial_rsp;
        regs.cr3 = cr3;
        regs.cs = 0x08;      // Kernel code
        regs.ss = 0x10;      // Kernel data
        regs.rflags = 0x202; // IF=1: Interrupts enabled

        let task = Task {
            id,
            name,
            state: TaskState::Ready,
            priority,
            mode: PrivilegeMode::Kernel,
            personality: super::tcb::TaskPersonality::Hydra,
            fs_base: 0,
            brk: 0,
            clear_child_tid: 0,
            tgid: id.0 as u64,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            caps: crate::task::tcb::Caps::for_euid(0),
            seccomp: Default::default(),
            regs,
            stack: Some(stack),
            user_stack: None,
            user_image: None,
            interp_image: None,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default().into_shared(),
            mm: None,
            exe: None,
            cmdline: None,
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        };

        self.tasks.push(task);
        id
    }

    /// Spawns an unprivileged Ring 3 User Mode task.
    ///
    /// Allocates both a kernel stack (for TSS RSP0 and hardware SYSCALL)
    /// and a user stack (for userland RSP). Configures user code (0x23) and
    /// user data (0x1B) segment selectors with RPL=3.
    ///
    /// # Arguments
    ///
    /// * `name` - Static string identifier for the user task.
    /// * `entry_fn` - Function pointer representing user code entry.
    /// * `priority` - Initial scheduling priority.
    ///
    /// # Returns
    ///
    /// The unique [`TaskId`] assigned to the new user process.
    pub fn spawn_user(
        &mut self,
        name: &'static str,
        entry_fn: fn(),
        priority: TaskPriority,
    ) -> TaskId {
        let current_cr3 = Cr3::read().0.start_address().as_u64();
        let id = TaskId(self.next_id);
        self.next_id += 1;

        // 1. Allocate dedicated 16 KiB Kernel Stack
        let kernel_stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();

        // 2. Allocate dedicated 16 KiB User Stack
        let user_stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();
        let user_stack_bottom = user_stack.as_ptr() as u64;
        let user_stack_top = (user_stack_bottom + user_stack.len() as u64) & !0xF;
        let initial_user_rsp = user_stack_top.saturating_sub(48);

        // 3. Mark user stack memory as USER_ACCESSIBLE
        let _ = crate::memory::paging::make_user_accessible(
            x86_64::VirtAddr::new(user_stack_bottom),
            user_stack.len(),
        );

        // 4. Mark user entry code page as USER_ACCESSIBLE
        let fn_ptr = entry_fn as *const () as usize as u64;
        let _ = crate::memory::paging::make_user_accessible(
            x86_64::VirtAddr::new(fn_ptr),
            4096,
        );

        let mut regs = TaskRegisters::empty();
        regs.rip = fn_ptr;
        regs.rsp = initial_user_rsp;
        regs.cs = 0x20 | 3;  // User Code Segment (0x23, RPL 3)
        regs.ss = 0x18 | 3;  // User Data Segment (0x1B, RPL 3)
        regs.rflags = 0x202; // IF=1: Interrupts enabled
        regs.cr3 = current_cr3;

        let task = Task {
            id,
            name,
            state: TaskState::Ready,
            priority,
            mode: PrivilegeMode::User,
            personality: super::tcb::TaskPersonality::Hydra,
            fs_base: 0,
            brk: 0,
            clear_child_tid: 0,
            tgid: id.0 as u64,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            caps: crate::task::tcb::Caps::for_euid(0),
            seccomp: Default::default(),
            regs,
            stack: Some(kernel_stack),
            user_stack: Some(user_stack),
            user_image: None,
            interp_image: None,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default().into_shared(),
            mm: None,
            exe: None,
            cmdline: None,
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        };

        self.tasks.push(task);
        id
    }

    /// Spawns an unprivileged Ring 3 task from an in-memory ELF64 binary image.
    ///
    /// Parses the ELF64 headers and segments, allocates and maps loadable segments
    /// with `USER_ACCESSIBLE` page table flags, initializes user stack, sets up
    /// Ring 3 execution selectors (`CS = 0x23`, `SS = 0x1B`, `RFLAGS = 0x202`),
    /// and enqueues the task in the scheduler's ready queue.
    ///
    /// # Arguments
    ///
    /// * `name` - Descriptive name identifying the process in task diagnostics.
    /// * `elf_data` - Raw bytes of the ELF64 executable file.
    /// * `priority` - Task scheduling priority.
    ///
    /// # Returns
    ///
    /// Returns the assigned `TaskId` on success, or a static error description
    /// if the binary is malformed or memory allocation failed.
    ///
    /// # Errors
    ///
    /// - Returns an error message if ELF parsing fails or segments cannot be mapped.
    pub fn spawn_elf(
        &mut self,
        name: &'static str,
        elf_data: &[u8],
        priority: TaskPriority,
    ) -> Result<TaskId, &'static str> {
        let current_cr3 = Cr3::read().0.start_address().as_u64();
        let image = super::elf::load_elf(elf_data).map_err(|e| e.as_str())?;

        let id = TaskId(self.next_id);
        self.next_id += 1;

        let mut regs = TaskRegisters::empty();
        regs.rip = image.entry_point;
        regs.rsp = image.initial_user_rsp;
        regs.cs = 0x20 | 3;  // User Code Segment (0x23, RPL 3)
        regs.ss = 0x18 | 3;  // User Data Segment (0x1B, RPL 3)
        regs.rflags = 0x202; // IF=1: Interrupts enabled
        regs.cr3 = current_cr3;

        let task = Task {
            id,
            name,
            state: TaskState::Ready,
            priority,
            mode: PrivilegeMode::User,
            personality: super::tcb::TaskPersonality::Hydra,
            fs_base: 0,
            brk: 0,
            clear_child_tid: 0,
            tgid: id.0 as u64,
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            caps: crate::task::tcb::Caps::for_euid(0),
            seccomp: Default::default(),
            regs,
            stack: Some(image.kernel_stack),
            user_stack: Some(image.user_stack),
            user_image: image.allocated_image,
            interp_image: image.interp_image,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default().into_shared(),
            mm: None,
            exe: None,
            cmdline: None,
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        };

        self.tasks.push(task);
        Ok(id)
    }

    /// Spawns an unprivileged Ring 3 task running a Linux ELF64 binary with the Linux ABI.
    ///
    /// # Arguments
    ///
    /// * `name` - Static string identifier for the Linux task.
    /// * `elf_data` - Raw bytes of the Linux ELF binary.
    /// * `args` - Command line argument strings.
    /// * `priority` - Task scheduling priority.
    /// * `uid` - User ID.
    /// * `gid` - Group ID.
    ///
    /// # Returns
    ///
    /// `Ok(TaskId)` of the spawned task.
    ///
    /// # Errors
    ///
    /// Returns static string error if ELF loading fails.
    pub fn spawn_linux_elf(
        &mut self,
        name: &'static str,
        elf_data: &[u8],
        args: &[&str],
        priority: TaskPriority,
        uid: u32,
        gid: u32,
    ) -> Result<TaskId, &'static str> {
        // Programs for a private address space go through `task::spawn_linux_elf`, which
        // loads them before taking the scheduler lock

        let current_cr3 = Cr3::read().0.start_address().as_u64();
        let image = super::elf::load_linux_elf(elf_data, args).map_err(|e| e.as_str())?;

        let id = TaskId(self.next_id);
        self.next_id += 1;

        let mut regs = TaskRegisters::empty();
        regs.rip = image.entry_point;
        regs.rsp = image.initial_user_rsp;
        regs.cs = 0x20 | 3;  // User Code Segment (0x23, RPL 3)
        regs.ss = 0x18 | 3;  // User Data Segment (0x1B, RPL 3)
        regs.rflags = 0x202; // IF=1: Interrupts enabled
        regs.cr3 = current_cr3;

        let task = Task {
            id,
            name,
            state: TaskState::Ready,
            priority,
            mode: PrivilegeMode::User,
            personality: super::tcb::TaskPersonality::Linux,
            fs_base: 0,
            brk: image.initial_brk,
            clear_child_tid: 0,
            tgid: id.0 as u64,
            uid,
            gid,
            euid: uid,
            egid: gid,
            suid: uid,
            sgid: gid,
            caps: crate::task::tcb::Caps::for_euid(uid),
            seccomp: Default::default(),
            regs,
            stack: Some(image.kernel_stack),
            user_stack: Some(image.user_stack),
            user_image: image.allocated_image,
            interp_image: image.interp_image,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default().into_shared(),
            mm: None,
            exe: None,
            cmdline: None,
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        };

        self.tasks.push(task);
        crate::compat::linux::proc::register_process(id.0, 0, id.0, None);
        Ok(id)
    }

    /// Spawns a Linux process in its own private address space (PIE and high-linked binaries).
    ///
    /// With `root` set, the process runs `chroot`ed into that directory inode: the dynamic
    /// linker is looked up inside it and it becomes the process's root and working directory.
    ///
    /// `image` comes from [`load_linux_image`], which must run before the scheduler lock is
    /// taken.
    ///
    /// # Arguments
    ///
    /// * `name` - Static string identifier for the Linux process.
    /// * `image` - Loaded Linux execution image containing address space.
    /// * `exec_path` - Path string for `/proc/<pid>/exe`.
    /// * `args` - Command-line argument strings.
    /// * `priority` - Task priority.
    /// * `uid` - User ID.
    /// * `gid` - Group ID.
    /// * `root` - Optional chroot directory inode number.
    ///
    /// # Returns
    ///
    /// `Ok(TaskId)` of the spawned process.
    ///
    /// # Errors
    ///
    /// Returns static string error if process setup fails.
    pub fn spawn_linux_process(
        &mut self,
        name: &'static str,
        image: super::exec::LinuxExecImage,
        exec_path: &str,
        args: &[&str],
        priority: TaskPriority,
        uid: u32,
        gid: u32,
        root: Option<u64>,
    ) -> Result<TaskId, &'static str> {
        let id = TaskId(self.next_id);
        self.next_id += 1;

        let mm = alloc::sync::Arc::new(Mutex::new(image.mm));
        let mut regs = TaskRegisters::empty();
        regs.rip = image.entry;
        regs.rsp = image.rsp;
        regs.cs = 0x20 | 3;
        regs.ss = 0x18 | 3;
        regs.rflags = 0x202;
        regs.cr3 = mm.lock().cr3();

        self.tasks.push(Task {
            id,
            name,
            state: TaskState::Ready,
            priority,
            mode: PrivilegeMode::User,
            personality: super::tcb::TaskPersonality::Linux,
            fs_base: 0,
            brk: 0,
            clear_child_tid: 0,
            tgid: id.0 as u64,
            uid,
            gid,
            euid: uid,
            egid: gid,
            suid: uid,
            sgid: gid,
            caps: crate::task::tcb::Caps::for_euid(uid),
            seccomp: Default::default(),
            regs,
            stack: Some(alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice()),
            user_stack: None,
            user_image: None,
            interp_image: None,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: {
                let mut fds = crate::fs::FdTable::new_default();
                if let Some(r) = root {
                    fds.root_ino = r;
                    fds.cwd_ino = r;
                }
                fds.into_shared()
            },
            mm: Some(mm),
            exe: Some(alloc::sync::Arc::from(exec_path)),
            cmdline: Some(Task::join_cmdline(args.iter().map(|a| a.as_bytes()))),
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        });
        crate::compat::linux::proc::register_process(id.0, 0, id.0, None);
        Ok(id)
    }

    /// Clones the calling task into a new thread or child process for the Linux ABI
    /// (`clone`, `fork`, `vfork`). Without `CLONE_VM` the child gets a copy-on-write copy of
    /// the address space; without `CLONE_THREAD` it becomes a new process.
    ///
    /// `args` are the `clone` arguments (flags, stack, parent_tid, child_tid, tls); the rest
    /// of the child's registers come from `frame`.
    pub fn spawn_clone(
        &mut self,
        frame: &crate::arch::syscall::SyscallFrame,
        args: [u64; 5],
    ) -> Result<TaskId, &'static str> {
        use crate::compat::linux::types::{CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_THREAD};
        const CLONE_VM: u64 = 0x100;
        let [flags, child_stack, ptid, ctid, newtls] = args;

        if !self.initialized || self.current_index >= self.tasks.len() {
            return Err("Scheduler not initialized");
        }

        let curr_idx = self.current_index;
        let parent = &self.tasks[curr_idx];
        let parent_cr3 = parent.regs.cr3;
        let parent_fs_base = parent.fs_base;
        let parent_tgid = parent.tgid;
        let parent_brk = parent.brk;
        let parent_name = parent.name;
        let parent_priority = parent.priority;
        // Threads share the descriptor table; a new process gets a copy
        let parent_fds = if flags & CLONE_FILES != 0 {
            parent.fds.clone()
        } else {
            parent.fds.lock().fork_copy().into_shared()
        };
        let parent_tid = parent.id.0;
        let parent_uid = parent.uid;
        let parent_gid = parent.gid;
        let parent_euid = parent.euid;
        let parent_egid = parent.egid;
        let parent_suid = parent.suid;
        let parent_sgid = parent.sgid;
        let parent_caps = parent.caps;
        let parent_seccomp = parent.seccomp.clone();
        let parent_exe = parent.exe.clone();
        let parent_cmdline = parent.cmdline.clone();
        let parent_mm = if flags & CLONE_VM != 0 {
            parent.mm.clone()
        } else {
            match parent.mm.as_ref() {
                Some(mm) => Some(alloc::sync::Arc::new(Mutex::new(mm.lock().fork()?))),
                None => parent.mm.clone(),
            }
        };
        let parent_cr3 = parent_mm.as_ref().map_or(parent_cr3, |m| m.lock().cr3());

        let child_id = TaskId(self.next_id);
        self.next_id += 1;

        let mut regs = TaskRegisters::empty();
        regs.rip = frame.rip;
        regs.rsp = if child_stack != 0 { child_stack } else { frame.rsp };
        regs.rflags = frame.rflags;
        regs.rax = 0; // Return value in child thread is 0
        regs.rdi = frame.rdi;
        regs.rsi = frame.rsi;
        regs.rdx = frame.rdx;
        regs.rcx = frame.rip;
        regs.r8 = frame.r8;
        regs.r9 = frame.r9;
        regs.r10 = frame.r10;
        regs.r11 = frame.rflags;
        regs.rbx = frame.rbx;
        regs.rbp = frame.rbp;
        regs.r12 = frame.r12;
        regs.r13 = frame.r13;
        regs.r14 = frame.r14;
        regs.r15 = frame.r15;
        regs.cs = 0x20 | 3;
        regs.ss = 0x18 | 3;
        regs.cr3 = parent_cr3;

        // The parent's live FS base is in the MSR, not yet saved in its task
        let _ = parent_fs_base;
        let child_fs_base = if flags & CLONE_SETTLS != 0 {
            newtls
        } else {
            unsafe { crate::arch::syscall::rdmsr(0xC000_0100) }
        };

        let child_tgid = if flags & CLONE_THREAD != 0 { parent_tgid } else { child_id.0 as u64 };

        let clear_child_tid = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };

        let tid_bytes = (child_id.0 as i32).to_le_bytes();
        if flags & CLONE_PARENT_SETTID != 0 && ptid != 0 && crate::memory::vm::prefault_current(ptid, 4, true) {
            unsafe { *(ptid as *mut i32) = child_id.0 as i32 };
        }
        if flags & CLONE_CHILD_SETTID != 0 && ctid != 0 {
            if flags & CLONE_VM != 0 {
                if crate::memory::vm::prefault_current(ctid, 4, true) {
                    unsafe { *(ctid as *mut i32) = child_id.0 as i32 };
                }
            } else if let Some(mm) = parent_mm.as_ref() {
                let _ = mm.lock().write_bytes(ctid, &tid_bytes);
            }
        }

        let kernel_stack = alloc::vec![0u8; DEFAULT_STACK_SIZE].into_boxed_slice();

        // The child resumes with the parent's user FPU state as saved at syscall entry
        let syscall_fpu = crate::arch::syscall::SYSCALL_FPU.load(core::sync::atomic::Ordering::Acquire);
        let child_fpu = if syscall_fpu.is_null() {
            crate::arch::idt::FpuState::new()
        } else {
            unsafe { (*syscall_fpu).clone() }
        };

        let task = Task {
            id: child_id,
            name: parent_name,
            state: TaskState::Ready,
            priority: parent_priority,
            mode: PrivilegeMode::User,
            personality: super::tcb::TaskPersonality::Linux,
            fs_base: child_fs_base,
            brk: parent_brk,
            clear_child_tid,
            tgid: child_tgid,
            uid: parent_uid,
            gid: parent_gid,
            euid: parent_euid,
            egid: parent_egid,
            suid: parent_suid,
            sgid: parent_sgid,
            caps: parent_caps,
            seccomp: parent_seccomp,
            regs,
            stack: Some(kernel_stack),
            user_stack: None,
            user_image: None,
            interp_image: None,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: parent_fds,
            mm: parent_mm,
            exe: parent_exe,
            cmdline: parent_cmdline,
            service: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            syscall_args: [0; 2],
            event_wait: false,
            woken: false,
            preempted: false,
            passed_over: 0,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(child_fpu),
        };

        self.tasks.push(task);
        if child_tgid == parent_tgid {
            crate::compat::linux::proc::register_thread(child_tgid, child_id.0, parent_tid);
        } else {
            crate::compat::linux::proc::register_process(child_tgid, parent_tgid, child_id.0, Some(parent_tgid));
        }
        Ok(child_id)
    }

    /// Gives up the rest of the current timeslice and switches to the next ready task
    /// (voluntary yield, `sched_yield`, blocking and sleeping).
    ///
    /// # Arguments
    ///
    /// * `ctx` - CPU interrupt frame registers.
    pub fn schedule_now(&mut self, ctx: &mut ExceptionContext) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
        self.schedule(ctx);
    }

    /// Invoked on every IRQ 0 timer interrupt (100 Hz) to perform timeslice accounting and context switching.
    ///
    /// # Arguments
    ///
    /// * `ctx` - CPU interrupt frame registers.
    pub fn schedule(&mut self, ctx: &mut ExceptionContext) {
        if !self.initialized || self.tasks.is_empty() {
            return;
        }

        let current_ticks = crate::arch::pit::ticks();

        // 1. Apply wait-queue wakeups, and wake sleeping tasks whose timer target has expired
        self.apply_wakes();
        for task in self.tasks.iter_mut() {
            if let TaskState::Sleeping { wake_tick } = task.state {
                if current_ticks >= wake_tick {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                }
            }
        }

        // 1b. A driver call whose server died or missed its deadline ends: the caller
        // resumes and finds no reply
        while let Some(h) = self.handoff_top() {
            let server_alive = self.tasks.iter().any(|t| t.id.0 == h.server && t.state != TaskState::Dead);
            if server_alive && current_ticks < h.deadline {
                break;
            }
            if let Some(i) = self.handoffs.iter().rposition(|x| x.is_some()) {
                self.handoffs[i] = None;
            }
            self.note_handoffs();
            self.resume_caller(h.caller);
        }
        let handoff_server = self.handoff_top().map(|h| h.server);

        let mut curr_idx = self.current_index;
        let curr_task = &mut self.tasks[curr_idx];
        curr_task.ticks_run += 1;

        // 2. Check if current task still has timeslice and is eligible to continue. A task
        // woken by an event (input, a socket, a futex; not a timed sleep, which polling
        // loops use) preempts it: interactive work waits at most one tick instead of a
        // full timeslice per busy task ahead of it.
        let may_continue = handoff_server.map_or(true, |s| s == curr_task.id.0) && self.resume_first.is_none();
        if curr_task.state == TaskState::Running && curr_task.timeslice_remaining > 1 && may_continue {
            curr_task.timeslice_remaining -= 1;
            if handoff_server.is_some() {
                return; // the server of a driver call runs undisturbed until it replies
            }
            // Also preempted: the idle task by any ready work, and any task by ready work of
            // higher priority (a timed sleep that ended, such as the timer daemons'); equal
            // priority tasks woken from timed sleeps still wait for the slice to end
            let current_priority = self.tasks[curr_idx].priority;
            let woken_waiting = self.tasks.iter().any(|t| {
                t.state == TaskState::Ready && t.priority > TaskPriority::Idle && (t.woken || t.priority > current_priority)
            });
            if !woken_waiting {
                return;
            }
            // Preempted mid-slice: it resumes right after the woken work
            self.tasks[curr_idx].preempted = true;
        }
        let curr_task = &mut self.tasks[curr_idx];

        // 3. Current task's timeslice expired or it is not Running (e.g. Blocked, Sleeping, Dead)
        let current_cr3 = Cr3::read().0.start_address().as_u64();
        // A task without an address space of its own keeps the kernel's tables
        let saved_cr3 = if curr_task.mm.is_none() && self.kernel_cr3 != 0 { self.kernel_cr3 } else { current_cr3 };
        curr_task.regs.save_from_context(ctx, saved_cr3);
        curr_task.fs_base = unsafe { crate::arch::syscall::rdmsr(0xC000_0100) };
        if curr_task.state == TaskState::Running {
            curr_task.state = TaskState::Ready;
        }

        // 3b. Release address spaces of tasks that died earlier (never the current task,
        // whose page tables are still loaded), then move the dead tasks themselves out of
        // the table (their kernel stacks are freed by `reap_dead_tasks`). Parking never
        // allocates or frees: this runs in the timer interrupt.
        let mut idx = self.tasks.len();
        while idx > 0 {
            idx -= 1;
            if idx == curr_idx || self.tasks[idx].state != TaskState::Dead {
                continue;
            }
            if let Some(mm) = self.tasks[idx].mm.take() {
                if let Err(mm) = crate::memory::vm::retire_mm(mm) {
                    self.tasks[idx].mm = Some(mm);
                    continue;
                }
            }
            let mut parked = match PARKED_TASKS.try_lock() {
                Some(p) => p,
                None => break,
            };
            let slot = match parked.iter_mut().find(|s| s.is_none()) {
                Some(s) => s,
                None => break,
            };
            let last = self.tasks.len() - 1;
            *slot = Some(self.tasks.swap_remove(idx));
            if curr_idx == last {
                curr_idx = idx; // the current task moved into the freed position
            }
        }
        self.current_index = curr_idx;

        // 4. Select the next Ready task in round-robin fashion
        let num_tasks = self.tasks.len();
        let mut next_idx = None;

        // The caller of a driver call that just ended runs first
        if let Some(caller) = self.resume_first.take() {
            next_idx = self.tasks.iter().position(|t| t.id.0 == caller && t.state == TaskState::Ready);
        }
        // During a driver call only its server runs, or the idle task while the server
        // waits for its device
        if let (Some(server), None) = (handoff_server, next_idx) {
            let server_idx = self.tasks.iter().position(|t| t.id.0 == server && t.state == TaskState::Ready);
            let idle_idx = self.tasks.iter().position(|t| t.priority == TaskPriority::Idle && t.state == TaskState::Ready);
            next_idx = server_idx.or(idle_idx);
        }

        // First pass: high-priority service tasks (the network task) run as soon as they
        // are ready; then non-idle Ready tasks in round-robin order
        for offset in 1..=num_tasks {
            if next_idx.is_some() {
                break;
            }
            let idx = (curr_idx + offset) % num_tasks;
            if self.tasks[idx].state == TaskState::Ready && self.tasks[idx].priority >= TaskPriority::High {
                next_idx = Some(idx);
                break;
            }
        }
        // A ready task passed over too often runs now (the longest-waiting one), so the
        // tiers below cannot starve it
        if next_idx.is_none() && handoff_server.is_none() {
            next_idx = (0..num_tasks)
                .filter(|&i| {
                    let t = &self.tasks[i];
                    t.state == TaskState::Ready && t.priority > TaskPriority::Idle && t.passed_over >= STARVATION_LIMIT
                })
                .max_by_key(|&i| self.tasks[i].passed_over);
        }
        // (event-woken tasks first, then tasks they preempted, then the rest)
        for tier in 0..3 {
            for offset in 1..=num_tasks {
                if next_idx.is_some() {
                    break;
                }
                let idx = (curr_idx + offset) % num_tasks;
                let t = &self.tasks[idx];
                let eligible = match tier {
                    0 => t.woken,
                    1 => t.preempted,
                    _ => true,
                };
                if t.state == TaskState::Ready && t.priority > TaskPriority::Idle && eligible {
                    next_idx = Some(idx);
                }
            }
        }

        // Second pass: If no standard task is ready, allow Idle task (priority 0)
        if next_idx.is_none() && handoff_server.is_none() {
            for offset in 1..=num_tasks {
                let idx = (curr_idx + offset) % num_tasks;
                if self.tasks[idx].state == TaskState::Ready {
                    next_idx = Some(idx);
                    break;
                }
            }
        }

        let next_idx = next_idx.unwrap_or(curr_idx);
        for (i, t) in self.tasks.iter_mut().enumerate() {
            if i != next_idx && t.state == TaskState::Ready && t.priority > TaskPriority::Idle {
                t.passed_over = t.passed_over.saturating_add(1);
            }
        }
        self.tasks[next_idx].woken = false;
        self.tasks[next_idx].preempted = false;
        self.tasks[next_idx].passed_over = 0;
        if next_idx == curr_idx {
            self.tasks[curr_idx].state = TaskState::Running;
            self.tasks[curr_idx].timeslice_remaining = self.default_timeslice;
            return;
        }
        self.current_index = next_idx;

        // 4a. The preemption-point marker belongs to the task, not the CPU
        self.tasks[curr_idx].preempt_depth =
            super::PREEMPT_POINTS.swap(self.tasks[next_idx].preempt_depth, core::sync::atomic::Ordering::SeqCst);
        self.tasks[curr_idx].syscall_nr =
            super::CURRENT_SYSCALL.swap(self.tasks[next_idx].syscall_nr, core::sync::atomic::Ordering::Relaxed);
        for k in 0..2 {
            self.tasks[curr_idx].syscall_args[k] =
                super::CURRENT_SYSCALL_ARGS[k].swap(self.tasks[next_idx].syscall_args[k], core::sync::atomic::Ordering::Relaxed);
        }

        // 4b'. Swap x87/SSE state through the trap frame's save area
        let trap_fpu = crate::arch::idt::CURRENT_TRAP_FPU.load(core::sync::atomic::Ordering::Acquire);
        if !trap_fpu.is_null() {
            unsafe {
                self.tasks[curr_idx].fpu.0 = (*trap_fpu).0;
                (*trap_fpu).0 = self.tasks[next_idx].fpu.0;
            }
        }

        let next_task = &mut self.tasks[next_idx];
        next_task.state = TaskState::Running;
        next_task.timeslice_remaining = self.default_timeslice;
        crate::memory::vm::set_current_mm(next_task.mm.as_ref());

        // 4b. Update hardware TSS RSP0 and SYSCALL kernel RSP for the incoming task
        let kernel_top = next_task.kernel_stack_top();
        crate::arch::gdt::set_privilege_stack(x86_64::VirtAddr::new(kernel_top));
        let kernel_bottom = next_task.stack.as_ref().map_or(0, |s| s.as_ptr() as u64);
        super::CURRENT_KSTACK[0].store(kernel_bottom, core::sync::atomic::Ordering::Release);
        super::CURRENT_KSTACK[1].store(kernel_top, core::sync::atomic::Ordering::Release);
        crate::arch::syscall::set_kernel_rsp(kernel_top);

        // 4c. Switch FS_BASE MSR for incoming task
        unsafe {
            crate::arch::syscall::wrmsr(0xC000_0100, next_task.fs_base);
        }

        // 5. Restore registers into the ExceptionContext frame for iretq execution
        next_task.regs.restore_to_context(ctx);

        // 6. Switch address space if the target task has a custom CR3 root
        if next_task.regs.cr3 != 0 && next_task.regs.cr3 != current_cr3 {
            unsafe {
                Cr3::write(
                    x86_64::structures::paging::PhysFrame::containing_address(
                        x86_64::PhysAddr::new(next_task.regs.cr3),
                    ),
                    x86_64::registers::control::Cr3Flags::empty(),
                );
            }
        }
    }

    /// Marks the currently running task as sleeping until `wake_tick`.
    ///
    /// # Arguments
    ///
    /// * `wake_tick` - Target PIT timer tick when the task becomes runnable.
    pub fn sleep_current(&mut self, wake_tick: u64) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].state = TaskState::Sleeping { wake_tick };
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
    }

    /// Executable path of process `tgid` (`/proc/<pid>/exe`), if it has a live thread.
    ///
    /// # Arguments
    ///
    /// * `tgid` - Thread Group ID (process ID).
    ///
    /// # Returns
    ///
    /// `Some(String)` path of the binary image, or `None` if process has no live threads.
    pub fn exe_of(&self, tgid: u64) -> Option<alloc::string::String> {
        self.tasks.iter().find(|t| t.tgid == tgid && t.state != TaskState::Dead).map(|t| alloc::string::String::from(t.exe_path()))
    }

    /// Runs `f` on task `id`, or returns `None` if there is no such task.
    ///
    /// # Arguments
    ///
    /// * `id` - Task ID to look up.
    /// * `f` - Closure taking mutable reference to target [`Task`].
    ///
    /// # Returns
    ///
    /// `Some(R)` produced by `f`, or `None` if task ID not found.
    pub fn with_task_mut<R>(&mut self, id: TaskId, f: impl FnOnce(&mut Task) -> R) -> Option<R> {
        self.tasks.iter_mut().find(|t| t.id == id).map(f)
    }

    /// Runs `f` on every live task.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure applied to each task.
    pub fn for_each_task_mut(&mut self, mut f: impl FnMut(&mut Task)) {
        for t in self.tasks.iter_mut().filter(|t| t.state != TaskState::Dead) {
            f(t);
        }
    }

    /// Runs `f` on a live thread of process `tgid`, or returns `None` if there is none.
    ///
    /// # Arguments
    ///
    /// * `tgid` - Process Thread Group ID.
    /// * `f` - Closure operating on the first live [`Task`].
    ///
    /// # Returns
    ///
    /// `Some(R)` produced by `f`, or `None` if process has no live threads.
    pub fn with_process<R>(&self, tgid: u64, f: impl FnOnce(&Task) -> R) -> Option<R> {
        self.tasks.iter().find(|t| t.tgid == tgid && t.state != TaskState::Dead).map(f)
    }

    /// CPU time of process `tgid` (all its live threads) in timer ticks.
    ///
    /// # Arguments
    ///
    /// * `tgid` - Process Thread Group ID.
    ///
    /// # Returns
    ///
    /// Cumulative ticks run across all threads belonging to `tgid`.
    pub fn process_ticks(&self, tgid: u64) -> u64 {
        self.tasks.iter().filter(|t| t.tgid == tgid && t.state != TaskState::Dead).map(|t| t.ticks_run).sum()
    }

    /// Wakes task `id` from an event wait; a task that is not waiting yet, or is blocked for
    /// another reason (a futex, a driver call), keeps the wakeup for its next wait.
    ///
    /// # Arguments
    ///
    /// * `id` - 64-bit Task ID to wake.
    pub fn wake_task(&mut self, id: u64) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id.0 == id) {
            match task.state {
                TaskState::Dead => {}
                TaskState::Blocked | TaskState::Sleeping { .. } if task.event_wait => {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                    task.woken = true;
                }
                // Blocked for another reason (a futex, a driver call it is making): not
                // disturbed, but the wakeup is kept for its next wait, as for a running task
                // (an interrupt can wake a task while it waits for its driver's reply)
                _ => task.wake_pending = true,
            }
        }
    }

    /// Applies wakeups recorded by [`super::wait::WaitQueue::wake_all`].
    pub fn apply_wakes(&mut self) {
        let mut woken = [(0u64, false); 64];
        let mut n = 0;
        let overflow = super::wait::drain(|id, process| {
            woken[n] = (id, process);
            n += 1;
        });
        for &(id, process) in &woken[..n] {
            if process {
                self.unblock_group(id);
            } else {
                self.wake_task(id);
            }
        }
        if overflow {
            for task in self.tasks.iter_mut() {
                if task.event_wait && matches!(task.state, TaskState::Blocked | TaskState::Sleeping { .. }) {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                }
            }
        }
    }

    /// Puts the current task in an event wait (until `deadline`, if any). Returns false
    /// without sleeping when a wakeup already arrived; the caller then re-checks.
    ///
    /// # Arguments
    ///
    /// * `deadline` - Optional maximum timer tick.
    ///
    /// # Returns
    ///
    /// `true` if task entered sleep state, `false` if wake arrived previously.
    pub fn event_wait_current(&mut self, deadline: Option<u64>) -> bool {
        self.apply_wakes();
        if !self.initialized || self.current_index >= self.tasks.len() {
            return false;
        }
        let task = &mut self.tasks[self.current_index];
        if task.wake_pending {
            task.wake_pending = false;
            return false;
        }
        task.event_wait = true;
        task.state = match deadline {
            Some(wake_tick) => TaskState::Sleeping { wake_tick },
            None => TaskState::Blocked,
        };
        task.timeslice_remaining = 0;
        true
    }

    /// Marks the currently running task as Blocked and zeroes its remaining timeslice.
    ///
    /// # Returns
    ///
    /// The [`TaskId`] of the blocked task.
    pub fn block_current(&mut self) -> TaskId {
        if self.initialized && self.current_index < self.tasks.len() {
            let task = &mut self.tasks[self.current_index];
            task.state = TaskState::Blocked;
            task.timeslice_remaining = 0;
            task.id
        } else {
            TaskId(0)
        }
    }

    /// Wakes a blocked task by its ID, transitioning its state back to Ready.
    ///
    /// # Arguments
    ///
    /// * `id` - Task ID to unblock.
    ///
    /// # Returns
    ///
    /// `true` if task found and unblocked, `false` otherwise.
    pub fn unblock_task(&mut self, id: TaskId) -> bool {
        for task in self.tasks.iter_mut() {
            if task.id == id && task.state == TaskState::Blocked {
                task.state = TaskState::Ready;
                task.woken = true;
                return true;
            }
        }
        false
    }

    /// Marks task `idx` as Dead and releases what it holds: wakes `CLONE_CHILD_CLEARTID`
    /// waiters, closes its descriptors (so pipe readers see end-of-file), and tells the
    /// Linux process table, which turns the process into a zombie after its last thread.
    ///
    /// # Arguments
    ///
    /// * `idx` - Internal index in `tasks` array.
    fn retire_task(&mut self, idx: usize) {
        if self.tasks[idx].state == TaskState::Dead {
            return;
        }
        self.tasks[idx].state = TaskState::Dead;
        self.tasks[idx].timeslice_remaining = 0;

        // The clear-tid word lives in the task's own address space: only write it when
        // that address space is the one currently loaded
        let clear_child_tid = self.tasks[idx].clear_child_tid;
        let active_cr3 = Cr3::read().0.start_address().as_u64();
        if clear_child_tid != 0 && self.tasks[idx].regs.cr3 == active_cr3 {
            if crate::memory::vm::prefault_current(clear_child_tid, 4, true) {
                unsafe { *(clear_child_tid as *mut i32) = 0 };
            }
            let key = crate::compat::linux::futex::key_for_task(&self.tasks[idx], clear_child_tid);
            let mut fq = crate::compat::linux::futex::GLOBAL_FUTEX.lock();
            let ids = fq.wake_task_ids(key, 1, crate::compat::linux::futex::FUTEX_BITSET_MATCH_ANY);
            drop(fq);
            for id in ids {
                self.wake_task(id.0);
            }
        }

        // The last thread using the descriptor table has its descriptors closed, after the
        // scheduler lock is released (see `task::close_retired`)
        let fds = core::mem::replace(&mut self.tasks[idx].fds, crate::fs::FdTable::empty().into_shared());
        if let Ok(fds) = alloc::sync::Arc::try_unwrap(fds) {
            self.pending_close.push(fds.into_inner());
        }
        if self.tasks[idx].personality == super::tcb::TaskPersonality::Linux {
            crate::compat::linux::proc::thread_exited(self.tasks[idx].tgid, self.tasks[idx].id.0);
        }
    }

    /// Marks the currently running task as Dead and zeroes its timeslice.
    pub fn terminate_current(&mut self) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.retire_task(self.current_index);
        }
    }

    /// Marks every other thread sharing the current task's thread group as Dead.
    pub fn terminate_current_group(&mut self) {
        if !self.initialized || self.current_index >= self.tasks.len() {
            return;
        }
        let tgid = self.tasks[self.current_index].tgid;
        let me = self.tasks[self.current_index].id;
        for idx in 0..self.tasks.len() {
            if self.tasks[idx].tgid == tgid && self.tasks[idx].id != me {
                self.retire_task(idx);
            }
        }
    }

    /// Wakes every blocked thread of process `tgid` (a signal arrived), including threads
    /// in event waits; a thread about to wait finds the wakeup pending.
    ///
    /// # Arguments
    ///
    /// * `tgid` - Thread Group ID whose threads will be unblocked.
    pub fn unblock_group(&mut self, tgid: u64) {
        for task in self.tasks.iter_mut() {
            if task.tgid != tgid {
                continue;
            }
            match task.state {
                TaskState::Blocked => {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                }
                TaskState::Sleeping { .. } if task.event_wait => {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                }
                TaskState::Running | TaskState::Ready => task.wake_pending = true,
                _ => {}
            }
        }
    }

    /// Terminates a task by its ID. Returns true if successfully located and terminated.
    /// System tasks (PID 0 'shell' and PID 1 'idle') are immune to termination.
    ///
    /// # Arguments
    ///
    /// * `id` - Task ID to terminate.
    ///
    /// # Returns
    ///
    /// `true` if target task was found and transitioned to Dead, `false` otherwise.
    pub fn kill_task(&mut self, id: TaskId) -> bool {
        if id.0 <= 1 {
            return false;
        }
        for i in 0..self.tasks.len() {
            if self.tasks[i].id == id && self.tasks[i].state != TaskState::Dead {
                self.retire_task(i);
                return true;
            }
        }
        false
    }

    /// Returns the TaskId of the currently running task.
    ///
    /// # Returns
    ///
    /// Active [`TaskId`].
    pub fn current_task_id(&self) -> TaskId {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].id
        } else {
            TaskId(0)
        }
    }

    /// Returns the target OS personality of the currently active task.
    ///
    /// # Returns
    ///
    /// Current [`super::tcb::TaskPersonality`].
    pub fn current_personality(&self) -> super::tcb::TaskPersonality {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].personality
        } else {
            super::tcb::TaskPersonality::Hydra
        }
    }

    /// Executes a closure with a mutable reference to the currently executing task.
    ///
    /// # Arguments
    ///
    /// * `f` - Callable closure accepting `&mut Task`.
    ///
    /// # Returns
    ///
    /// `Some(R)` produced by `f`, or `None` if scheduler uninitialized.
    pub fn current_task_mut<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut Task) -> R,
    {
        if self.initialized && self.current_index < self.tasks.len() {
            Some(f(&mut self.tasks[self.current_index]))
        } else {
            None
        }
    }

    /// The current task's descriptor table (shared, with a lock of its own).
    ///
    /// # Returns
    ///
    /// `Some(SharedFdTable)` cloned from current task, or `None` if uninitialized.
    pub fn current_fds(&self) -> Option<crate::fs::SharedFdTable> {
        (self.initialized && self.current_index < self.tasks.len()).then(|| self.tasks[self.current_index].fds.clone())
    }

    /// Returns true if a task with the given ID exists and is active (not Dead).
    ///
    /// # Arguments
    ///
    /// * `id` - Task ID to check.
    ///
    /// # Returns
    ///
    /// `true` if active, `false` if dead or non-existent.
    pub fn is_task_alive(&self, id: TaskId) -> bool {
        for task in &self.tasks {
            if task.id == id && task.state != TaskState::Dead {
                return true;
            }
        }
        false
    }

    /// Returns the total count of registered tasks (active and dead).
    ///
    /// # Returns
    ///
    /// Total number of task control blocks as `usize`.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Writes every live task's state and pending system call to the serial port without
    /// allocating (used from interrupt context to diagnose hangs).
    pub fn dump_tasks(&self) {
        if let Some(h) = crate::memory::heap::try_stats() {
            crate::console::serial_write(&alloc::format!(
                "[heap] {} KiB used, {} KiB free of {} KiB\n",
                h.used_bytes / 1024,
                h.free_bytes / 1024,
                h.total_bytes / 1024
            ));
        }
        for h in self.handoffs.iter().flatten() {
            let mut b = crate::console::FixedBuf::new();
            let _ = core::fmt::Write::write_fmt(
                &mut b,
                format_args!("[handoff] server {} caller {} deadline {} (now {})\n", h.server, h.caller, h.deadline, crate::arch::pit::ticks()),
            );
            crate::console::serial_write(b.as_str());
        }
        if let Some(r) = self.resume_first {
            let mut b = crate::console::FixedBuf::new();
            let _ = core::fmt::Write::write_fmt(&mut b, format_args!("[handoff] resume first {}\n", r));
            crate::console::serial_write(b.as_str());
        }
        crate::console::serial_write("[tasks] id state tgid syscall rip ticks exe\n");
        for (i, task) in self.tasks.iter().enumerate() {
            if task.state == TaskState::Dead {
                continue;
            }
            let (nr, args) = if i == self.current_index {
                (
                    super::CURRENT_SYSCALL.load(core::sync::atomic::Ordering::Relaxed),
                    [0, 1].map(|k| super::CURRENT_SYSCALL_ARGS[k].load(core::sync::atomic::Ordering::Relaxed)),
                )
            } else {
                (task.syscall_nr, task.syscall_args)
            };
            let mut b = crate::console::FixedBuf::new();
            let _ = core::fmt::Write::write_fmt(
                &mut b,
                format_args!(
                    "[tasks] {} {} {} {}({:#x},{:#x}) {:#x} {} {}\n",
                    task.id.0, task.state.as_str(), task.tgid, nr as i64, args[0], args[1], task.regs.rip, task.ticks_run,
                    if task.exe.is_some() { task.exe_path() } else { task.name }
                ),
            );
            crate::console::serial_write(b.as_str());
        }
    }

    /// Captures a diagnostic snapshot of all registered tasks.
    ///
    /// # Returns
    ///
    /// Vector of [`TaskSnapshot`] objects for each task.
    pub fn snapshots(&self) -> Vec<TaskSnapshot> {
        let mut list = Vec::with_capacity(self.tasks.len());
        for task in &self.tasks {
            list.push(TaskSnapshot {
                id: task.id,
                name: task.name,
                state: task.state,
                priority: task.priority,
                mode: task.mode,
                uid: task.uid,
                ticks_run: task.ticks_run,
                rsp: task.regs.rsp,
                rip: task.regs.rip,
            });
        }
        list
    }

    /// Sets POSIX credentials (UID, GID, EUID, EGID, SUID, SGID) for a target task.
    ///
    /// # Arguments
    ///
    /// * `id` - Target task ID.
    /// * `uid` - New real/effective user ID.
    /// * `gid` - New real/effective group ID.
    pub fn set_task_credentials(&mut self, id: TaskId, uid: u32, gid: u32) {
        for task in &mut self.tasks {
            if task.id == id {
                task.uid = uid;
                task.gid = gid;
                task.euid = uid;
                task.egid = gid;
                task.suid = uid;
                task.sgid = gid;
                task.caps = crate::task::tcb::Caps::for_euid(uid);
                break;
            }
        }
    }
}

/// Environment given to Linux processes started from the Hydra shell as `uid`: the
/// user's identity and home, and the runtime directory a login would provide (see
/// `linux chroot`, which creates `/run/user/<uid>`).
///
/// # Arguments
///
/// * `uid` - User ID for which environment is created.
///
/// # Returns
///
/// Vector of `"KEY=VALUE"` environment variable strings.
fn linux_env(uid: u32) -> Vec<alloc::string::String> {
    use alloc::format;
    let (user, home) = if uid == 0 { ("root", alloc::string::String::from("/root")) } else { ("hydra", format!("/home/hydra")) };
    alloc::vec![
        format!("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
        format!("HOME={}", home),
        format!("USER={}", user),
        format!("LOGNAME={}", user),
        format!("SHELL=/bin/bash"),
        format!("TERM=linux"),
        format!("LANG=C.UTF-8"),
        format!("XDG_RUNTIME_DIR=/run/user/{}", uid),
        format!("WAYLAND_DISPLAY=wayland-0"),
    ]
}

/// Reads a dynamic linker named by `PT_INTERP` from the filesystem (or boot media).
///
/// # Arguments
///
/// * `path` - Virtual filesystem path to dynamic interpreter.
///
/// # Returns
///
/// `Some(Vec<u8>)` containing file bytes, or `None` if read failed.
fn read_interpreter(path: &str) -> Option<Vec<u8>> {
    if let Ok(stat) = crate::fs::client::ZfsClient::file_stat(path) {
        let mut buf = alloc::vec![0u8; stat.size as usize];
        if let Ok(n) = crate::fs::client::ZfsClient::read_file_by_path(path, &mut buf) {
            buf.truncate(n);
            return Some(buf);
        }
    }
    if !crate::arch::boot_services::is_hardware_takeover_complete() {
        let fat_path = path.replace('/', "\\");
        if let Ok(data) = crate::shell::fs::read_boot_file(&fat_path) {
            return Some(data);
        }
    }
    None
}

/// Trampoline wrapper function called when a spawned kernel thread starts execution.
///
/// # Arguments
///
/// * `entry_fn_addr` - Memory address of the entry function pointer.
///
/// # Returns
///
/// This function never returns (!).
extern "C" fn task_trampoline(entry_fn_addr: usize) -> ! {
    let func: fn() = unsafe { core::mem::transmute(entry_fn_addr) };
    func();

    // Mark task Dead upon normal function exit and yield CPU
    crate::task::exit();
}

/// Background idle loop executing CPU halts to conserve energy when all tasks are idle.
fn idle_task_entry() {
    loop {
        if x86_64::instructions::interrupts::are_enabled() {
            // Halt until the next interrupt, unless one already woke a task: checking with
            // interrupts disabled and re-enabling them atomically with `hlt` closes the gap
            // in which a wakeup could be missed until the next timer tick
            x86_64::instructions::interrupts::disable();
            if crate::task::wait::wakes_pending() {
                x86_64::instructions::interrupts::enable();
                crate::task::yield_now();
            } else {
                crate::task::preemptible(x86_64::instructions::interrupts::enable_and_hlt);
            }
        } else {
            core::hint::spin_loop();
        }
    }
}
