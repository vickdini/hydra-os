use alloc::boxed::Box;
use crate::arch::idt::ExceptionContext;
use crate::capability::table::CapabilityTable;

/// Unique 64-bit identifier for a kernel task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// Lifecycle state of a thread/task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Sleeping { wake_tick: u64 },
    Dead,
}

impl TaskState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskState::Ready => "Ready",
            TaskState::Running => "Running",
            TaskState::Blocked => "Blocked",
            TaskState::Sleeping { .. } => "Sleeping",
            TaskState::Dead => "Dead",
        }
    }
}

/// Scheduling priority level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Realtime = 4,
}

impl TaskPriority {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskPriority::Idle => "Idle",
            TaskPriority::Low => "Low",
            TaskPriority::Normal => "Normal",
            TaskPriority::High => "High",
            TaskPriority::Realtime => "Realtime",
        }
    }
}

/// Architectural CPU registers and execution context for x86_64 long mode.
#[derive(Debug, Clone, Copy)]
pub struct TaskRegisters {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub cr3: u64,
}

impl TaskRegisters {
    /// Creates an empty register state with standard 64-bit kernel segment selectors.
    pub const fn empty() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            rip: 0,
            cs: 0x08,      // Hydra Kernel Code Segment
            rflags: 0x202, // IF (Interrupt Flag) enabled
            rsp: 0,
            ss: 0x10,      // Hydra Kernel Data Segment
            cr3: 0,
        }
    }

    /// Captures register state from the hardware interrupt context frame.
    pub fn save_from_context(&mut self, ctx: &ExceptionContext, cr3: u64) {
        self.r15 = ctx.r15;
        self.r14 = ctx.r14;
        self.r13 = ctx.r13;
        self.r12 = ctx.r12;
        self.rbp = ctx.rbp;
        self.rbx = ctx.rbx;
        self.r11 = ctx.r11;
        self.r10 = ctx.r10;
        self.r9 = ctx.r9;
        self.r8 = ctx.r8;
        self.rdi = ctx.rdi;
        self.rsi = ctx.rsi;
        self.rdx = ctx.rdx;
        self.rcx = ctx.rcx;
        self.rax = ctx.rax;
        self.rip = ctx.rip;
        self.cs = ctx.cs;
        self.rflags = ctx.rflags;
        self.rsp = ctx.rsp;
        self.ss = ctx.ss;
        self.cr3 = cr3;
    }

    /// Restores saved register state into the hardware interrupt context frame before iretq.
    pub fn restore_to_context(&self, ctx: &mut ExceptionContext) {
        ctx.r15 = self.r15;
        ctx.r14 = self.r14;
        ctx.r13 = self.r13;
        ctx.r12 = self.r12;
        ctx.rbp = self.rbp;
        ctx.rbx = self.rbx;
        ctx.r11 = self.r11;
        ctx.r10 = self.r10;
        ctx.r9 = self.r9;
        ctx.r8 = self.r8;
        ctx.rdi = self.rdi;
        ctx.rsi = self.rsi;
        ctx.rdx = self.rdx;
        ctx.rcx = self.rcx;
        ctx.rax = self.rax;
        ctx.rip = self.rip;
        ctx.cs = self.cs;
        ctx.rflags = self.rflags;
        ctx.rsp = self.rsp;
        ctx.ss = self.ss;
    }
}

/// Execution privilege level of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeMode {
    Kernel, // Ring 0
    User,   // Ring 3
}

impl PrivilegeMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivilegeMode::Kernel => "Kernel",
            PrivilegeMode::User => "User",
        }
    }
}

/// Target OS ABI personality for system call routing and runtime semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPersonality {
    Hydra,
    Linux,
}

impl TaskPersonality {
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskPersonality::Hydra => "Hydra",
            TaskPersonality::Linux => "Linux",
        }
    }
}

/// Task Control Block (TCB) representing a thread of execution in Hydra Microkernel.
pub struct Task {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub priority: TaskPriority,
    pub mode: PrivilegeMode,
    pub personality: TaskPersonality,
    pub fs_base: u64,
    pub brk: u64,
    pub clear_child_tid: u64,
    pub tgid: u64,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub regs: TaskRegisters,
    pub stack: Option<Box<[u8]>>,       // Kernel stack (used for Ring 0 execution and TSS RSP0)
    pub user_stack: Option<Box<[u8]>>,  // User stack (used for Ring 3 unprivileged execution)
    pub user_image: Option<Box<[u8]>>,  // Backing segment buffer for ELF process image
    pub interp_image: Option<Box<[u8]>>, // Backing segment buffer for dynamic linker (PT_INTERP)
    pub ticks_run: u64,
    pub timeslice_remaining: u32,
    pub cspace: Box<CapabilityTable>,
    pub fds: crate::fs::FdTable,
    /// Private address space (Linux processes loaded through the VM subsystem). Threads of
    /// one process share it. `None` for kernel tasks and legacy tasks in the kernel space.
    pub mm: Option<alloc::sync::Arc<spin::Mutex<crate::memory::vm::Mm>>>,
    /// Path of the executable image (`/proc/self/exe`), for Linux processes.
    pub exe: Option<alloc::sync::Arc<str>>,
    /// Nesting depth of `task::preemptible` wait points this task is inside; saved and
    /// restored with the task so the timer only preempts the task that is actually waiting.
    pub preempt_depth: u32,
    /// Linux system call in progress (`u64::MAX` when none); saved with the task.
    pub syscall_nr: u64,
    /// Sleeping in [`crate::task::wait::wait`]: a wait-queue wakeup or signal makes it ready.
    pub event_wait: bool,
    /// A wakeup arrived while the task was not (yet) waiting: its next wait returns at once.
    pub wake_pending: bool,
    /// Saved x87/SSE register state while the task is not running.
    pub fpu: Box<crate::arch::idt::FpuState>,
}

impl Task {
    /// Creates a placeholder task descriptor for the already-executing main thread.
    pub fn new_main(id: TaskId, name: &'static str, cr3: u64) -> Self {
        let mut regs = TaskRegisters::empty();
        regs.cr3 = cr3;

        Self {
            id,
            name,
            state: TaskState::Running,
            priority: TaskPriority::Normal,
            mode: PrivilegeMode::Kernel,
            personality: TaskPersonality::Hydra,
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
            regs,
            stack: None,      // Uses existing firmware/boot stack
            user_stack: None,
            user_image: None,
            interp_image: None,
            ticks_run: 0,
            timeslice_remaining: 5,
            cspace: Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default(),
            mm: None,
            exe: None,
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        }
    }

    /// Path of the running executable, or the task name for kernel tasks.
    pub fn exe_path(&self) -> &str {
        self.exe.as_deref().unwrap_or(self.name)
    }

    /// Returns the top address of the task's kernel stack (used for TSS RSP0 and hardware SYSCALL).
    pub fn kernel_stack_top(&self) -> u64 {
        if let Some(ref stack) = self.stack {
            let bottom = stack.as_ptr() as u64;
            (bottom + stack.len() as u64) & !0xF
        } else {
            // Main thread uses existing firmware stack pointer
            self.regs.rsp
        }
    }
}
