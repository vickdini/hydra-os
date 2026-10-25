use alloc::vec::Vec;
use spin::Mutex;
use x86_64::registers::control::Cr3;

use crate::arch::idt::ExceptionContext;
use crate::capability::table::CapabilityTable;
use super::tcb::{PrivilegeMode, Task, TaskId, TaskPriority, TaskRegisters, TaskState};

pub const DEFAULT_TIMESLICE_TICKS: u32 = 5; // 50ms at 100 Hz PIT timer
pub const DEFAULT_STACK_SIZE: usize = 16384;  // 16 KiB per kernel thread stack

/// Diagnostic snapshot of a task for shell inspection (e.g. `ps` / `tasks` command).
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub priority: TaskPriority,
    pub mode: PrivilegeMode,
    pub ticks_run: u64,
    pub rsp: u64,
    pub rip: u64,
}

/// Global preemptive round-robin scheduler instance.
pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

/// Preemptive Round-Robin Multitasking Scheduler.
pub struct Scheduler {
    tasks: Vec<Task>,
    current_index: usize,
    next_id: u64,
    default_timeslice: u32,
    initialized: bool,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_index: 0,
            next_id: 1,
            default_timeslice: DEFAULT_TIMESLICE_TICKS,
            initialized: false,
        }
    }

    /// Initializes multitasking by wrapping the current execution thread as Task 0 ("shell").
    pub fn init(&mut self, current_cr3: u64) {
        if self.initialized {
            return;
        }

        // Register the active main thread as Task 0
        let main_task = Task::new_main(TaskId(0), "shell", current_cr3);
        self.tasks.push(main_task);
        self.current_index = 0;
        self.initialized = true;

        // Spawn background Idle task (Task 1) with lowest priority
        self.spawn_internal("idle", idle_task_entry, TaskPriority::Idle, current_cr3);
    }

    /// Updates the CR3 root paging address for the primary main task.
    pub fn update_main_cr3(&mut self, cr3: u64) {
        if !self.tasks.is_empty() {
            self.tasks[0].regs.cr3 = cr3;
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Spawns a new kernel thread with the given entry point and priority.
    pub fn spawn(
        &mut self,
        name: &'static str,
        entry_fn: fn(),
        priority: TaskPriority,
    ) -> TaskId {
        let current_cr3 = Cr3::read().0.start_address().as_u64();
        self.spawn_internal(name, entry_fn, priority, current_cr3)
    }

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
            regs,
            stack: Some(stack),
            user_stack: None,
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default(),
        };

        self.tasks.push(task);
        id
    }

    /// Spawns an unprivileged Ring 3 User Mode task.
    ///
    /// Allocates both a kernel stack (for TSS RSP0 and hardware SYSCALL)
    /// and a user stack (for userland RSP). Configures user code (0x23) and
    /// user data (0x1B) segment selectors with RPL=3.
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
            regs,
            stack: Some(kernel_stack),
            user_stack: Some(user_stack),
            ticks_run: 0,
            timeslice_remaining: self.default_timeslice,
            cspace: alloc::boxed::Box::new(CapabilityTable::new()),
            fds: crate::fs::FdTable::new_default(),
        };

        self.tasks.push(task);
        id
    }

    /// Invoked on every IRQ 0 timer interrupt (100 Hz) to perform timeslice accounting and context switching.
    pub fn schedule(&mut self, ctx: &mut ExceptionContext) {
        if !self.initialized || self.tasks.is_empty() {
            return;
        }

        let current_ticks = crate::arch::pit::ticks();

        // 1. Wake up any sleeping tasks whose timer target has expired
        for task in self.tasks.iter_mut() {
            if let TaskState::Sleeping { wake_tick } = task.state {
                if current_ticks >= wake_tick {
                    task.state = TaskState::Ready;
                }
            }
        }

        let curr_idx = self.current_index;
        let curr_task = &mut self.tasks[curr_idx];
        curr_task.ticks_run += 1;

        // 2. Check if current task still has timeslice and is eligible to continue
        if curr_task.state == TaskState::Running && curr_task.timeslice_remaining > 1 {
            curr_task.timeslice_remaining -= 1;
            return;
        }

        // 3. Current task's timeslice expired or it is not Running (e.g. Blocked, Sleeping, Dead)
        let current_cr3 = Cr3::read().0.start_address().as_u64();
        curr_task.regs.save_from_context(ctx, current_cr3);
        if curr_task.state == TaskState::Running {
            curr_task.state = TaskState::Ready;
        }

        // 4. Select the next Ready task in round-robin fashion
        let num_tasks = self.tasks.len();
        let mut next_idx = None;

        // First pass: Check non-idle Ready tasks
        for offset in 1..=num_tasks {
            let idx = (curr_idx + offset) % num_tasks;
            if self.tasks[idx].state == TaskState::Ready && self.tasks[idx].priority > TaskPriority::Idle {
                next_idx = Some(idx);
                break;
            }
        }

        // Second pass: If no standard task is ready, allow Idle task (priority 0)
        if next_idx.is_none() {
            for offset in 1..=num_tasks {
                let idx = (curr_idx + offset) % num_tasks;
                if self.tasks[idx].state == TaskState::Ready {
                    next_idx = Some(idx);
                    break;
                }
            }
        }

        let next_idx = next_idx.unwrap_or(curr_idx);
        self.current_index = next_idx;

        let next_task = &mut self.tasks[next_idx];
        next_task.state = TaskState::Running;
        next_task.timeslice_remaining = self.default_timeslice;

        // 4b. Update hardware TSS RSP0 and SYSCALL kernel RSP for the incoming task
        let kernel_top = next_task.kernel_stack_top();
        crate::arch::gdt::set_privilege_stack(x86_64::VirtAddr::new(kernel_top));
        crate::arch::syscall::set_kernel_rsp(kernel_top);

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
    pub fn sleep_current(&mut self, wake_tick: u64) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].state = TaskState::Sleeping { wake_tick };
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
    }

    /// Marks the currently running task as Blocked and zeroes its remaining timeslice.
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
    pub fn unblock_task(&mut self, id: TaskId) -> bool {
        for task in self.tasks.iter_mut() {
            if task.id == id && task.state == TaskState::Blocked {
                task.state = TaskState::Ready;
                return true;
            }
        }
        false
    }

    /// Marks the currently running task as Dead and zeroes its timeslice.
    pub fn terminate_current(&mut self) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].state = TaskState::Dead;
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
    }

    /// Terminates a task by its ID. Returns true if successfully located and terminated.
    /// System tasks (PID 0 'shell' and PID 1 'idle') are immune to termination.
    pub fn kill_task(&mut self, id: TaskId) -> bool {
        if id.0 <= 1 {
            return false;
        }
        for task in self.tasks.iter_mut() {
            if task.id == id && task.state != TaskState::Dead {
                task.state = TaskState::Dead;
                task.timeslice_remaining = 0;
                return true;
            }
        }
        false
    }

    /// Returns the TaskId of the currently running task.
    pub fn current_task_id(&self) -> TaskId {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].id
        } else {
            TaskId(0)
        }
    }

    /// Executes a closure with a mutable reference to the currently executing task's FD table.
    pub fn current_task_fds_mut<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut crate::fs::FdTable) -> R,
    {
        if self.initialized && self.current_index < self.tasks.len() {
            Some(f(&mut self.tasks[self.current_index].fds))
        } else {
            None
        }
    }

    /// Returns true if a task with the given ID exists and is active (not Dead).
    pub fn is_task_alive(&self, id: TaskId) -> bool {
        for task in &self.tasks {
            if task.id == id && task.state != TaskState::Dead {
                return true;
            }
        }
        false
    }

    /// Returns the total count of registered tasks (active and dead).
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }

    /// Captures a diagnostic snapshot of all registered tasks.
    pub fn snapshots(&self) -> Vec<TaskSnapshot> {
        let mut list = Vec::with_capacity(self.tasks.len());
        for task in &self.tasks {
            list.push(TaskSnapshot {
                id: task.id,
                name: task.name,
                state: task.state,
                priority: task.priority,
                mode: task.mode,
                ticks_run: task.ticks_run,
                rsp: task.regs.rsp,
                rip: task.regs.rip,
            });
        }
        list
    }
}

/// Trampoline wrapper function called when a spawned kernel thread starts execution.
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
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
}
