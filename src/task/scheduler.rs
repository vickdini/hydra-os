use alloc::vec::Vec;
use spin::Mutex;
use x86_64::registers::control::Cr3;

use crate::arch::idt::ExceptionContext;
use crate::capability::table::CapabilityTable;
use super::tcb::{PrivilegeMode, Task, TaskId, TaskPriority, TaskRegisters, TaskState};

pub const DEFAULT_TIMESLICE_TICKS: u32 = 5; // 50ms at 100 Hz PIT timer
pub const DEFAULT_STACK_SIZE: usize = 65536;  // 64 KiB per kernel thread stack

/// Diagnostic snapshot of a task for shell inspection (e.g. `ps` / `tasks` command).
#[derive(Debug, Clone)]
pub struct TaskSnapshot {
    pub id: TaskId,
    pub name: &'static str,
    pub state: TaskState,
    pub priority: TaskPriority,
    pub mode: PrivilegeMode,
    pub uid: u32,
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

    /// Updates the CR3 root paging address for the primary main task and background kernel tasks.
    pub fn update_main_cr3(&mut self, cr3: u64) {
        for task in &mut self.tasks {
            task.regs.cr3 = cr3;
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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
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
    /// Returns the assigned [`TaskId`] on success, or a static error description
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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
            wake_pending: false,
            fpu: alloc::boxed::Box::new(crate::arch::idt::FpuState::new()),
        };

        self.tasks.push(task);
        Ok(id)
    }

    /// Spawns an unprivileged Ring 3 task running a Linux ELF64 binary with the Linux ABI.
    pub fn spawn_linux_elf(
        &mut self,
        name: &'static str,
        elf_data: &[u8],
        args: &[&str],
        priority: TaskPriority,
        uid: u32,
        gid: u32,
    ) -> Result<TaskId, &'static str> {
        if super::exec::is_vm_loadable(elf_data) {
            // /proc/self/exe must be absolute; `linux run` resolves bare names in /bin
            let arg0 = args.first().copied().unwrap_or(name);
            let exec_path = if arg0.starts_with('/') { alloc::string::String::from(arg0) } else { alloc::format!("/bin/{}", arg0) };
            let source = super::exec::ElfSource::from_bytes(elf_data.to_vec().into_boxed_slice());
            return self.spawn_linux_process(name, source, &exec_path, args, priority, uid, gid, None);
        }

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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
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
    pub fn spawn_linux_process(
        &mut self,
        name: &'static str,
        exe: super::exec::ElfSource,
        exec_path: &str,
        args: &[&str],
        priority: TaskPriority,
        uid: u32,
        gid: u32,
        root: Option<u64>,
    ) -> Result<TaskId, &'static str> {
        let read_in_root = |path: &str| -> Option<super::exec::ElfSource> {
            let root = root?;
            let ino = crate::fs::ZfsClient::resolve_in(root, root, path.as_bytes(), true).ok()?;
            crate::compat::linux::mm::inode_source(ino).ok()
        };
        let read_legacy = |path: &str| -> Option<super::exec::ElfSource> {
            read_interpreter(path).map(|b| super::exec::ElfSource::from_bytes(b.into_boxed_slice()))
        };
        let interp_reader: &dyn Fn(&str) -> Option<super::exec::ElfSource> = if root.is_some() { &read_in_root } else { &read_legacy };
        let image = super::exec::load_linux_exec(
            exe,
            exec_path,
            args,
            DEFAULT_LINUX_ENV,
            super::exec::ExecCreds { uid, gid },
            interp_reader,
        )
        .map_err(|e| e.as_str())?;

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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
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
        let parent_exe = parent.exe.clone();
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
            preempt_depth: 0,
            syscall_nr: u64::MAX,
            event_wait: false,
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
    pub fn schedule_now(&mut self, ctx: &mut ExceptionContext) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
        self.schedule(ctx);
    }

    /// Invoked on every IRQ 0 timer interrupt (100 Hz) to perform timeslice accounting and context switching.
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
        curr_task.fs_base = unsafe { crate::arch::syscall::rdmsr(0xC000_0100) };
        if curr_task.state == TaskState::Running {
            curr_task.state = TaskState::Ready;
        }

        // 3b. Release address spaces of tasks that died earlier (never the current task,
        // whose page tables are still loaded). Parking never allocates.
        for (idx, task) in self.tasks.iter_mut().enumerate() {
            if idx != curr_idx && task.state == TaskState::Dead {
                if let Some(mm) = task.mm.take() {
                    if let Err(mm) = crate::memory::vm::retire_mm(mm) {
                        task.mm = Some(mm);
                    }
                }
            }
        }

        // 4. Select the next Ready task in round-robin fashion
        let num_tasks = self.tasks.len();
        let mut next_idx = None;

        // First pass: high-priority service tasks (the network task) run as soon as they
        // are ready; then non-idle Ready tasks in round-robin order
        for offset in 1..=num_tasks {
            let idx = (curr_idx + offset) % num_tasks;
            if self.tasks[idx].state == TaskState::Ready && self.tasks[idx].priority >= TaskPriority::High {
                next_idx = Some(idx);
                break;
            }
        }
        for offset in 1..=num_tasks {
            if next_idx.is_some() {
                break;
            }
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
    pub fn sleep_current(&mut self, wake_tick: u64) {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].state = TaskState::Sleeping { wake_tick };
            self.tasks[self.current_index].timeslice_remaining = 0;
        }
    }

    /// Wakes task `id` from an event wait; a task that is not waiting yet keeps the wakeup
    /// for its next wait. Tasks blocked for other reasons (futexes, IPC) are not disturbed.
    pub fn wake_task(&mut self, id: u64) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id.0 == id) {
            match task.state {
                TaskState::Dead => {}
                TaskState::Blocked | TaskState::Sleeping { .. } if task.event_wait => {
                    task.state = TaskState::Ready;
                    task.event_wait = false;
                }
                TaskState::Blocked | TaskState::Sleeping { .. } => {}
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

    /// Marks task `idx` as Dead and releases what it holds: wakes `CLONE_CHILD_CLEARTID`
    /// waiters, closes its descriptors (so pipe readers see end-of-file), and tells the
    /// Linux process table, which turns the process into a zombie after its last thread.
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
            let mut fq = crate::compat::linux::futex::GLOBAL_FUTEX.lock();
            let ids = fq.wake_task_ids(clear_child_tid, 1, crate::compat::linux::futex::FUTEX_BITSET_MATCH_ANY);
            drop(fq);
            for id in ids {
                self.unblock_task(id);
            }
        }

        // The last thread using the descriptor table closes its descriptors
        let fds = core::mem::replace(&mut self.tasks[idx].fds, crate::fs::FdTable::empty().into_shared());
        if let Ok(fds) = alloc::sync::Arc::try_unwrap(fds) {
            fds.into_inner().close_all();
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
    pub fn current_task_id(&self) -> TaskId {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].id
        } else {
            TaskId(0)
        }
    }

    /// Returns the target OS personality of the currently active task.
    pub fn current_personality(&self) -> super::tcb::TaskPersonality {
        if self.initialized && self.current_index < self.tasks.len() {
            self.tasks[self.current_index].personality
        } else {
            super::tcb::TaskPersonality::Hydra
        }
    }

    /// Executes a closure with a mutable reference to the currently executing task.
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

    /// Executes a closure with a mutable reference to the currently executing task's FD table.
    pub fn current_task_fds_mut<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut crate::fs::FdTable) -> R,
    {
        if self.initialized && self.current_index < self.tasks.len() {
            Some(f(&mut self.tasks[self.current_index].fds.lock()))
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

    /// Writes every live task's state and pending system call to the serial port without
    /// allocating (used from interrupt context to diagnose hangs).
    pub fn dump_tasks(&self) {
        crate::console::serial_write("[tasks] id state tgid syscall rip ticks exe\n");
        for (i, task) in self.tasks.iter().enumerate() {
            if task.state == TaskState::Dead {
                continue;
            }
            let nr = if i == self.current_index {
                super::CURRENT_SYSCALL.load(core::sync::atomic::Ordering::Relaxed)
            } else {
                task.syscall_nr
            };
            let mut b = crate::console::FixedBuf::new();
            let _ = core::fmt::Write::write_fmt(
                &mut b,
                format_args!(
                    "[tasks] {} {} {} {} {:#x} {} {}\n",
                    task.id.0, task.state.as_str(), task.tgid, nr as i64, task.regs.rip, task.ticks_run,
                    if task.exe.is_some() { task.exe_path() } else { task.name }
                ),
            );
            crate::console::serial_write(b.as_str());
        }
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
                uid: task.uid,
                ticks_run: task.ticks_run,
                rsp: task.regs.rsp,
                rip: task.regs.rip,
            });
        }
        list
    }

    /// Sets POSIX credentials (UID, GID, EUID, EGID, SUID, SGID) for a target task.
    pub fn set_task_credentials(&mut self, id: TaskId, uid: u32, gid: u32) {
        for task in &mut self.tasks {
            if task.id == id {
                task.uid = uid;
                task.gid = gid;
                task.euid = uid;
                task.egid = gid;
                task.suid = uid;
                task.sgid = gid;
                break;
            }
        }
    }
}

/// Environment given to Linux processes started from the Hydra shell.
const DEFAULT_LINUX_ENV: &[&str] = &[
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "USER=root",
    "LOGNAME=root",
    "SHELL=/bin/bash",
    "TERM=linux",
    "LANG=C.UTF-8",
    "XDG_RUNTIME_DIR=/run/user/1000",
    "WAYLAND_DISPLAY=wayland-0",
];

/// Reads a dynamic linker named by `PT_INTERP` from the filesystem (or boot media).
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
