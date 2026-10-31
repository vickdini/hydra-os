//! # Task Subsystem: Task Control Block (TCB) and Execution Context
//!
//! Defines the [`Task`] control block, saved x86_64 CPU register context ([`TaskRegisters`]),
//! scheduling state (`TaskState`), priority levels (`TaskPriority`), privilege rings
//! ([`PrivilegeMode`]), and OS ABI personalities ([`TaskPersonality`]).
//!
//! ## Architectural Role & Design Rationale
//!
//! Every thread of execution in Hydra OS—whether a Ring 0 kernel thread, a native Hydra
//! Ring 3 process, or a Linux ABI thread—is represented by a [`Task`] instance stored in
//! `super::scheduler::Scheduler`. Separating the TCB data structures from scheduling policy
//! keeps context-switch state, POSIX credentials, file descriptor tables, capability spaces,
//! and virtual memory handles self-contained in one canonical record.
//!
//! ## Key Types & Interfaces
//!
//! - `TaskId`: Unique 64-bit identifier (`PID` / `TID`) for a kernel or user task.
//! - [`Task`]: Complete Task Control Block holding registers, stacks, credentials, `FdTable`, and `Mm`.
//! - [`TaskRegisters`]: Saved general-purpose, instruction/stack pointer, segment, and `CR3` registers.
//! - `TaskState`, `TaskPriority`, [`PrivilegeMode`], [`TaskPersonality`]: Task classification enums.
//!
//! ## Hardware & Dependency Context
//!
//! - **x86_64 Context Switch**: [`TaskRegisters`] mirrors the register frame captured and restored
//!   across [`crate::arch::idt::ExceptionContext`] during `iretq` transitions.
//! - **FPU/SIMD**: Each [`Task`] owns a heap-allocated [`crate::arch::idt::FpuState`] save area.

use alloc::boxed::Box;
use crate::arch::idt::ExceptionContext;
use crate::capability::table::CapabilityTable;

/// Unique 64-bit identifier for a kernel task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// Lifecycle state of a thread/task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Runnable and waiting in the scheduler queue for a CPU timeslice.
    Ready,
    /// Currently executing on the CPU.
    Running,
    /// Suspended waiting on a synchronization primitive, futex, or I/O event.
    Blocked,
    /// Suspended until the system PIT timer reaches `wake_tick`.
    Sleeping {
        /// Target PIT tick count at which the task transitions back to [`TaskState::Ready`].
        wake_tick: u64,
    },
    /// Terminated and awaiting resource reaping.
    Dead,
}

impl TaskState {
    /// Returns a static string name for this task state.
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
    /// Lowest priority; scheduled only when no other task is ready (used by the CPU halt loop).
    Idle = 0,
    /// Background priority for low-urgency work.
    Low = 1,
    /// Default priority for interactive shells and standard user processes.
    Normal = 2,
    /// Elevated priority for latency-sensitive kernel services (e.g. network stack).
    High = 3,
    /// Highest scheduling priority.
    Realtime = 4,
}

impl TaskPriority {
    /// Returns a static string name for this priority level.
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
    /// General-purpose register `R15` (callee-saved).
    pub r15: u64,
    /// General-purpose register `R14` (callee-saved).
    pub r14: u64,
    /// General-purpose register `R13` (callee-saved).
    pub r13: u64,
    /// General-purpose register `R12` (callee-saved).
    pub r12: u64,
    /// Frame base pointer register `RBP` (callee-saved).
    pub rbp: u64,
    /// General-purpose register `RBX` (callee-saved).
    pub rbx: u64,
    /// General-purpose register `R11` (caller-saved; holds `RFLAGS` across `SYSCALL`).
    pub r11: u64,
    /// General-purpose register `R10` (caller-saved; 4th syscall argument in Linux ABI).
    pub r10: u64,
    /// General-purpose register `R9` (caller-saved; 6th function/syscall argument).
    pub r9: u64,
    /// General-purpose register `R8` (caller-saved; 5th function/syscall argument).
    pub r8: u64,
    /// Destination index register `RDI` (1st argument in System V AMD64 ABI).
    pub rdi: u64,
    /// Source index register `RSI` (2nd argument in System V AMD64 ABI).
    pub rsi: u64,
    /// Data register `RDX` (3rd argument in System V AMD64 ABI).
    pub rdx: u64,
    /// Counter register `RCX` (1st argument in UEFI/Win64 ABI; holds return `RIP` across `SYSCALL`).
    pub rcx: u64,
    /// Accumulator register `RAX` (syscall number and return value).
    pub rax: u64,
    /// Instruction pointer `RIP`.
    pub rip: u64,
    /// Code segment selector `CS` (`0x08` for Ring 0, `0x23` for Ring 3).
    pub cs: u64,
    /// Processor status and control flags `RFLAGS`.
    pub rflags: u64,
    /// Stack pointer `RSP`.
    pub rsp: u64,
    /// Stack segment selector `SS` (`0x10` for Ring 0, `0x1B` for Ring 3).
    pub ss: u64,
    /// Control Register 3 (`CR3`) physical address of the task's root `PML4` page table.
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
    /// Privileged supervisor execution in CPU Ring 0.
    Kernel, // Ring 0
    /// Unprivileged application execution in CPU Ring 3.
    User,   // Ring 3
}

impl PrivilegeMode {
    /// Returns a static string name for this privilege mode.
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
    /// Native Hydra microkernel ABI.
    Hydra,
    /// Linux x86_64 ABI compatibility layer.
    Linux,
}

impl TaskPersonality {
    /// Returns a static string name for this OS personality.
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskPersonality::Hydra => "Hydra",
            TaskPersonality::Linux => "Linux",
        }
    }
}

/// Task Control Block (TCB) representing a thread of execution in Hydra Microkernel.
pub struct Task {
    /// Unique identifier (`TID`) of this task.
    pub id: TaskId,
    /// Static human-readable label for the task.
    pub name: &'static str,
    /// Current scheduling lifecycle state.
    pub state: TaskState,
    /// Scheduling priority level.
    pub priority: TaskPriority,
    /// Hardware CPU privilege ring (`Kernel` or `User`).
    pub mode: PrivilegeMode,
    /// System call ABI personality (`Hydra` or `Linux`).
    pub personality: TaskPersonality,
    /// Thread-local storage base address loaded into `IA32_FS_BASE` (`0xC000_0100`).
    pub fs_base: u64,
    /// Legacy program break address (for tasks without a private [`crate::memory::vm::Mm`]).
    pub brk: u64,
    /// User-space address cleared and futex-woken upon thread exit (`CLONE_CHILD_CLEARTID`).
    pub clear_child_tid: u64,
    /// Thread group ID (`PID` in POSIX terms; shared by threads created with `CLONE_THREAD`).
    pub tgid: u64,
    /// Real user ID.
    pub uid: u32,
    /// Real group ID.
    pub gid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Saved set-user-ID.
    pub suid: u32,
    /// Saved set-group-ID.
    pub sgid: u32,
    /// Saved CPU general-purpose and control register state.
    pub regs: TaskRegisters,
    /// Dedicated kernel stack buffer (used for Ring 0 execution and TSS `RSP0`).
    pub stack: Option<Box<[u8]>>,       // Kernel stack (used for Ring 0 execution and TSS RSP0)
    /// Dedicated user stack buffer (for legacy Ring 3 tasks without a demand-paged [`crate::memory::vm::Mm`]).
    pub user_stack: Option<Box<[u8]>>,  // User stack (used for Ring 3 unprivileged execution)
    /// Backing segment buffer for legacy PIE ELF process images.
    pub user_image: Option<Box<[u8]>>,  // Backing segment buffer for ELF process image
    /// Backing segment buffer for legacy dynamic linker (`PT_INTERP`) images.
    pub interp_image: Option<Box<[u8]>>, // Backing segment buffer for dynamic linker (PT_INTERP)
    /// Cumulative number of PIT timer ticks this task has executed.
    pub ticks_run: u64,
    /// Remaining PIT timer ticks in the current scheduling quantum.
    pub timeslice_remaining: u32,
    /// Per-task capability table governing object access rights.
    pub cspace: Box<CapabilityTable>,
    /// Descriptor table, shared with the other threads of the process (`CLONE_FILES`).
    pub fds: crate::fs::SharedFdTable,
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
            fds: crate::fs::FdTable::new_default().into_shared(),
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
