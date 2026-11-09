//! # Task Subsystem: Preemptive Multitasking and Process Management
//!
//! Coordinates kernel threads, unprivileged Ring 3 user processes, ELF64 binary loading,
//! Linux `execve` process image construction, and scheduler-integrated event wait queues.
//!
//! ## Architectural Role & Design Rationale
//!
//! The `task` module exposes the top-level API for spawning, scheduling, blocking, sleeping,
//! and terminating execution threads in Hydra OS. It supports both native Hydra tasks and
//! Linux ABI processes (`TaskPersonality::Linux`), providing preemption points for idle/wait
//! loops (`preemptible`) while keeping kernel critical sections non-preemptible.
//!
//! ## Key Types & Interfaces
//!
//! - `Task`, `TaskId`, `TaskState`, `TaskPriority`: Core Task Control Block (TCB) types.
//! - `SCHEDULER` & `TaskSnapshot`: Global preemptive round-robin scheduler and diagnostic state.
//! - `spawn`, `spawn_user`, `spawn_elf`, `spawn_linux_elf`, `spawn_linux_chroot`: Process and thread creation APIs.
//! - `yield_now`, `block_current`, `unblock_task`, `sleep_ms`, `exit`: Lifecycle and scheduling control.
//! - `supervisor`: MINIX 3-style driver reincarnation server, heartbeat monitoring, and self-healing.
//!
//! ## Hardware & Dependency Context
//!
//! - **Interrupts**: Triggered by IRQ 0 PIT timer ticks (100 Hz) and software yield interrupt `int 0x81`.
//! - **CPU Privilege Levels**: Manages Ring 0 (Kernel) and Ring 3 (User) stacks, `CR3` page tables, and `FS_BASE` TLS MSRs.

/// ELF64 binary parser and user-space segment mapper.
pub mod elf;
/// Demand-paged Linux `execve` process image builder.
pub mod exec;
/// Preemptive round-robin task scheduler.
pub mod scheduler;
/// Task Control Block (TCB), register state, and task metadata definitions.
pub mod tcb;
/// Lock-free interrupt-safe event wait queues (`poll`, `select`, pipes, sockets).
pub mod wait;
/// MINIX 3-style process reincarnation server, driver heartbeat watchdog, and fault recovery.
pub mod supervisor;

use alloc::vec::Vec;
pub use elf::{load_elf, load_linux_elf, ElfBinary, ElfError, ElfProcessImage};
pub use scheduler::{TaskSnapshot, SCHEDULER};
pub use supervisor::{
    get_service_snapshots, kill_service_by_name, restart_service_by_name, supervisor_init,
    supervisor_tick, ServiceDescriptor, ServiceSnapshot, ServiceState, Supervisor, SUPERVISOR,
};
pub use tcb::{PrivilegeMode, Task, TaskId, TaskPersonality, TaskPriority, TaskRegisters, TaskState};

/// Number of kernel wait points currently active (see `preemptible`).
pub static PREEMPT_POINTS: crate::arch::percpu::PerCpuU32 = crate::arch::percpu::PerCpuU32::new();

/// Linux system call the running task is executing (`u64::MAX` when none), for
/// [`scheduler::Scheduler::dump_tasks`].
pub static CURRENT_SYSCALL: crate::arch::percpu::PerCpuU64 = crate::arch::percpu::PerCpuU64::new(u64::MAX);
/// First two arguments of [`CURRENT_SYSCALL`] (for the task dump).
pub static CURRENT_SYSCALL_ARGS: [crate::arch::percpu::PerCpuU64; 2] =
    [crate::arch::percpu::PerCpuU64::new(0), crate::arch::percpu::PerCpuU64::new(0)];

/// Kernel stack `[bottom, top)` of the running task (bottom 0: unknown, such as the boot
/// thread's firmware stack).
pub static CURRENT_KSTACK: [crate::arch::percpu::PerCpuU64; 2] =
    [crate::arch::percpu::PerCpuU64::new(0), crate::arch::percpu::PerCpuU64::new(0)];

/// Whether `addr` (a trap frame) lies on the running task's own kernel stack.
///
/// The scheduler switches tasks by rewriting the trap frame being returned through, so
/// after a switch the handler is still running on the previous task's stack. Work that
/// may block (exiting, stopping) must not run there for the new task: once it blocks, the
/// stack's owner resumes and overwrites its frames.
///
/// # Arguments
///
/// * `addr` - Address to check.
///
/// # Returns
///
/// `true` if `addr` is on the current task's kernel stack (or the stack is unknown).
pub fn on_current_kernel_stack(addr: u64) -> bool {
    let bottom = CURRENT_KSTACK[0].load(core::sync::atomic::Ordering::Acquire);
    let top = CURRENT_KSTACK[1].load(core::sync::atomic::Ordering::Acquire);
    bottom == 0 || (addr >= bottom && addr < top)
}

/// Runs `f` (an idle wait such as `hlt` or a timed sleep) as a preemption point.
///
/// Kernel-mode code is otherwise never preempted by the timer: kernel spinlocks are not
/// interrupt-safe, and syscalls run with interrupts disabled, so switching away from a task
/// that holds one would deadlock the CPU. `f` must not be called with any lock held.
///
/// # Arguments
///
/// * `f` - Callable closure executing during the preemptible interval.
///
/// # Returns
///
/// The return value of `f`.
pub fn preemptible<R>(f: impl FnOnce() -> R) -> R {
    PREEMPT_POINTS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let r = f();
    PREEMPT_POINTS.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    r
}

/// Initializes the multitasking subsystem and registers the current main thread.
///
/// # Arguments
///
/// * `current_cr3` - Physical CR3 page directory address active at boot.
pub fn init(current_cr3: u64) {
    let mut sched = SCHEDULER.lock();
    sched.init(current_cr3);
}

/// Updates the CR3 root paging table for the active main thread.
///
/// # Arguments
///
/// * `cr3` - Physical CR3 page table base to update.
pub fn update_cr3(cr3: u64) {
    let mut sched = SCHEDULER.lock();
    if sched.is_initialized() {
        sched.update_main_cr3(cr3);
    } else {
        sched.init(cr3);
    }
}

/// Returns true if multitasking is initialized.
///
/// # Returns
///
/// `true` if multitasking scheduler is active and initialized.
pub fn is_active() -> bool {
    SCHEDULER.lock().is_initialized()
}

/// Spawns a new background kernel task (Ring 0).
///
/// # Arguments
///
/// * `name` - Static string name of the task.
/// * `entry_fn` - Function pointer representing the entry point.
/// * `priority` - Initial scheduling priority level.
///
/// # Returns
///
/// The unique [`TaskId`] assigned to the task.
pub fn spawn(name: &'static str, entry_fn: fn(), priority: TaskPriority) -> TaskId {
    let mut sched = SCHEDULER.lock();
    sched.spawn(name, entry_fn, priority)
}

/// Spawns a new unprivileged user process (Ring 3).
///
/// # Arguments
///
/// * `name` - Static string name of the user task.
/// * `entry_fn` - Function pointer representing userland code entry.
/// * `priority` - Initial scheduling priority level.
///
/// # Returns
///
/// The unique [`TaskId`] assigned to the user process.
pub fn spawn_user(name: &'static str, entry_fn: fn(), priority: TaskPriority) -> TaskId {
    let mut sched = SCHEDULER.lock();
    sched.spawn_user(name, entry_fn, priority)
}

/// Spawns a new unprivileged user process from an in-memory ELF64 binary image.
///
/// # Arguments
///
/// * `name` - Static string name of the ELF task.
/// * `elf_data` - Raw bytes of the ELF binary.
/// * `priority` - Initial scheduling priority level.
///
/// # Returns
///
/// `Ok(TaskId)` on successful spawn, or static error string.
///
/// # Errors
///
/// Returns static string slice if ELF parsing, segment loading, or allocation fails.
pub fn spawn_elf(
    name: &'static str,
    elf_data: &[u8],
    priority: TaskPriority,
) -> Result<TaskId, &'static str> {
    let mut sched = SCHEDULER.lock();
    sched.spawn_elf(name, elf_data, priority)
}

/// Spawns a new unprivileged user process running a Linux ELF64 binary under the Linux ABI.
///
/// # Arguments
///
/// * `name` - Static string identifier for the Linux process.
/// * `elf_data` - Raw bytes of the Linux ELF binary.
/// * `args` - Command-line argument strings.
/// * `priority` - Scheduling priority level.
/// * `uid` - User ID assigned to the process.
/// * `gid` - Group ID assigned to the process.
///
/// # Returns
///
/// `Ok(TaskId)` of the spawned Linux process.
///
/// # Errors
///
/// Returns static error string if image loading or process setup fails.
pub fn spawn_linux_elf(
    name: &'static str,
    elf_data: &[u8],
    args: &[&str],
    priority: TaskPriority,
    uid: u32,
    gid: u32,
) -> Result<TaskId, &'static str> {
    if exec::is_vm_loadable(elf_data) {
        // /proc/self/exe must be absolute; `linux run` resolves bare names in /bin
        let arg0 = args.first().copied().unwrap_or(name);
        let exec_path = if arg0.starts_with('/') { alloc::string::String::from(arg0) } else { alloc::format!("/bin/{}", arg0) };
        let source = exec::ElfSource::from_bytes(elf_data.to_vec().into_boxed_slice());
        let image = scheduler::load_linux_image(source, &exec_path, args, uid, gid, None)?;
        return x86_64::instructions::interrupts::without_interrupts(|| {
            SCHEDULER.lock().spawn_linux_process(name, image, &exec_path, args, priority, uid, gid, None)
        });
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        sched.spawn_linux_elf(name, elf_data, args, priority, uid, gid)
    })
}

/// Spawns a Linux program `exe` (a path inside `root_dir`) `chroot`ed into `root_dir`.
///
/// # Arguments
///
/// * `root_dir` - Directory path representing the chroot root.
/// * `exe` - Path to executable within chroot.
/// * `args` - Command-line arguments.
/// * `uid` - Real user ID.
/// * `gid` - Real group ID.
///
/// # Returns
///
/// `Ok(TaskId)` of the spawned chrooted process.
///
/// # Errors
///
/// Returns descriptive String error if resolving paths, loading ELF, or spawning fails.
pub fn spawn_linux_chroot(
    root_dir: &str,
    exe: &str,
    args: &[&str],
    uid: u32,
    gid: u32,
) -> Result<TaskId, alloc::string::String> {
    use crate::fs::ZfsClient;
    let root = ZfsClient::resolve(0, root_dir.as_bytes(), true)
        .map_err(|e| alloc::format!("cannot open root directory {} (errno {})", root_dir, e))?;
    let ino = ZfsClient::resolve_in(root, root, exe.as_bytes(), true)
        .map_err(|e| alloc::format!("{}: not found in {} (errno {})", exe, root_dir, e))?;
    let source = crate::compat::linux::mm::inode_source(ino).map_err(|e| alloc::format!("read failed (errno {})", e))?;
    if !elf::ElfBinary::parse(&source.head).is_ok() || !exec::is_vm_loadable(&source.head) {
        return Err(alloc::format!("{} is not a position-independent x86_64 ELF executable", exe));
    }
    let image = scheduler::load_linux_image(source, exe, args, uid, gid, Some(root)).map_err(alloc::string::String::from)?;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        sched
            .spawn_linux_process("linux_app", image, exe, args, TaskPriority::Normal, uid, gid, Some(root))
            .map_err(alloc::string::String::from)
    })
}

/// Starts a driver or server program (a static native ELF built into the kernel image as
/// a boot module) in an address space of its own, as the server of `endpoint`.
///
/// `args[0]` is its path for `/proc` and diagnostics; the rest describe its devices.
///
/// # Arguments
///
/// * `name` - Static name of the driver service.
/// * `image` - Raw byte slice of the service ELF binary.
/// * `args` - Command-line arguments describing device parameters.
/// * `endpoint` - IPC endpoint ID to register this service on.
///
/// # Returns
///
/// `Ok(TaskId)` of the spawned service driver process.
///
/// # Errors
///
/// Returns static string error if ELF is not static or VM loadable.
pub fn spawn_service(name: &'static str, image: &[u8], args: &[&str], endpoint: u32) -> Result<TaskId, &'static str> {
    if !exec::is_vm_loadable(image) {
        return Err("not a loadable static ELF executable");
    }
    let source = exec::ElfSource::from_bytes(image.to_vec().into_boxed_slice());
    let path = args.first().copied().unwrap_or(name);
    let loaded = scheduler::load_linux_image(source, path, args, 0, 0, None)?;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        let id = sched.spawn_linux_process(name, loaded, path, args, TaskPriority::High, 0, 0, None)?;
        sched.with_task_mut(id, |t| {
            t.personality = TaskPersonality::Hydra;
            t.service = Some(endpoint);
        });
        Ok(id)
    })
}

/// Endpoint of the driver service the current task serves, if it is a driver process.
///
/// # Returns
///
/// `Some(u32)` endpoint ID if the current task serves a service endpoint, `None` otherwise.
pub fn current_service() -> Option<u32> {
    with_current_task_mut(|t| t.service).flatten()
}

/// Sets credentials for a specific task.
///
/// # Arguments
///
/// * `id` - Task ID whose credentials to update.
/// * `uid` - New User ID.
/// * `gid` - New Group ID.
pub fn set_task_credentials(id: TaskId, uid: u32, gid: u32) {
    SCHEDULER.lock().set_task_credentials(id, uid, gid);
}

/// Returns the personality (Hydra vs Linux) of the currently running task.
///
/// # Returns
///
/// Active [`TaskPersonality`] of the running task.
pub fn current_personality() -> TaskPersonality {
    SCHEDULER.lock().current_personality()
}

/// Executes a closure with mutable access to the active task control block.
///
/// # Arguments
///
/// * `f` - Closure taking mutable reference to current [`Task`].
///
/// # Returns
///
/// `Some(R)` with closure result, or `None` if scheduler not initialized or no active task.
pub fn with_current_task_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Task) -> R,
{
    let mut sched = SCHEDULER.lock();
    sched.current_task_mut(f)
}

/// Cooperatively yields the current task's timeslice to the next ready task.
pub fn yield_now() {
    if !is_active() {
        return;
    }
    unsafe {
        core::arch::asm!("int 0x81");
    }
}

/// Transitions the calling task to `TaskState::Blocked` and yields the CPU immediately.
///
/// # Returns
///
/// The [`TaskId`] of the newly blocked task.
pub fn block_current() -> TaskId {
    if !is_active() {
        return TaskId(0);
    }
    let id = {
        let mut sched = SCHEDULER.lock();
        sched.block_current()
    };
    yield_now();
    id
}

/// Unblocks a previously blocked task, moving it back to `TaskState::Ready`.
///
/// # Arguments
///
/// * `id` - Task ID to unblock.
///
/// # Returns
///
/// `true` if task was found and unblocked, `false` otherwise.
pub fn unblock_task(id: TaskId) -> bool {
    let mut sched = SCHEDULER.lock();
    sched.unblock_task(id)
}

/// Earliest precise wakeup time (ns) of a sleeping task (`u64::MAX`: none); the timer
/// interrupts between ticks wake tasks once it passes.
pub static HR_EARLIEST: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Sleeps the current task until `deadline_ns` (nanoseconds since boot, as
/// [`crate::arch::pit::now_ns`]), to within a fraction of a millisecond.
pub fn sleep_until_ns(deadline_ns: u64) {
    if !is_active() || !crate::arch::pit::is_active() {
        while crate::arch::pit::now_ns() < deadline_ns {
            crate::arch::pit::sleep_ticks(1);
        }
        return;
    }
    if crate::arch::pit::now_ns() >= deadline_ns {
        return;
    }
    {
        let mut sched = SCHEDULER.lock();
        sched.sleep_current_ns(deadline_ns);
    }
    yield_now();
}

/// Puts the current task to sleep for a specified number of PIT timer ticks.
///
/// Works inside system calls (which run with interrupts disabled): the task sleeps in the
/// scheduler and the CPU keeps running other tasks, whose timer interrupts wake it.
///
/// # Arguments
///
/// * `ticks` - Number of timer ticks to sleep.
pub fn sleep_ticks(ticks: u64) {
    if !is_active() || !crate::arch::pit::is_active() {
        crate::arch::pit::sleep_ticks(ticks);
        return;
    }
    let wake_tick = crate::arch::pit::ticks() + ticks;
    {
        let mut sched = SCHEDULER.lock();
        sched.sleep_current(wake_tick);
    }
    yield_now();
}

/// Puts the current task to sleep for a duration in milliseconds.
///
/// # Arguments
///
/// * `ms` - Duration to sleep in milliseconds.
pub fn sleep_ms(ms: u64) {
    if !is_active() || !crate::arch::pit::is_active() {
        crate::arch::pit::sleep_ms(ms);
        return;
    }
    let freq = crate::arch::pit::frequency_hz();
    let ticks = (ms.saturating_mul(freq) + 999) / 1000;
    sleep_ticks(ticks.max(1));
}

/// Terminates the calling task and relinquishes CPU ownership permanently.
///
/// # Returns
///
/// This function never returns (!).
pub fn exit() -> ! {
    // Close the descriptors while still alive: closing may call a driver, whose reply only
    // a live task resumes from
    // (bound first: an `if let` would hold the scheduler lock through its block)
    let own = SCHEDULER.lock().take_current_fds_if_last();
    if let Some(mut fds) = own {
        fds.close_all();
    }
    close_retired();
    {
        let mut sched = SCHEDULER.lock();
        sched.terminate_current();
    }
    yield_now();
    loop {
        if x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
}

/// Terminates every thread of the calling process (Linux `exit_group`).
///
/// # Returns
///
/// This function never returns (!).
pub fn exit_group() -> ! {
    {
        let mut sched = SCHEDULER.lock();
        sched.terminate_current_group();
    }
    exit()
}

/// Terminates a task by its TaskId.
///
/// # Arguments
///
/// * `id` - Task ID to terminate.
///
/// # Returns
///
/// `true` if task was found and terminated, `false` otherwise.
pub fn kill(id: TaskId) -> bool {
    let killed = SCHEDULER.lock().kill_task(id);
    close_retired();
    killed
}

/// Closes the descriptors of exited tasks (which [`scheduler::Scheduler`] retires under its
/// lock, where closing cannot happen). Must be called without the scheduler lock, and not
/// while a driver serves a call (its caller may hold locks closing takes).
pub fn close_retired() {
    // Not in a driver process: closing files calls the file server, which may be the caller
    if scheduler::handoff_active() || current_service().is_some() {
        return;
    }
    let tables = SCHEDULER.lock().take_pending_close();
    for mut fds in tables {
        fds.close_all();
    }
}

/// Returns true if a task with the given ID is still active (not Dead).
///
/// # Arguments
///
/// * `id` - Task ID to check.
///
/// # Returns
///
/// `true` if task exists and is not `TaskState::Dead`.
pub fn is_task_alive(id: TaskId) -> bool {
    let sched = SCHEDULER.lock();
    sched.is_task_alive(id)
}

/// Waits synchronously for a task with the given ID to complete (transition to Dead).
/// Yields execution to the scheduler while waiting. Returns true if completed, false if interrupted.
///
/// # Arguments
///
/// * `id` - Task ID to wait on.
///
/// # Returns
///
/// `true` if task completed, `false` if user aborted with Ctrl+C.
pub fn wait_task(id: TaskId) -> bool {
    while is_task_alive(id) {
        if crate::console::check_interrupt() {
            crate::println!("^C");
            let _ = kill(id);
            return false;
        }
        sleep_ms(10);
    }
    true
}

/// Returns a diagnostic snapshot list of all registered tasks.
///
/// # Returns
///
/// A vector of [`TaskSnapshot`] structs.
pub fn get_task_snapshots() -> Vec<TaskSnapshot> {
    let sched = SCHEDULER.lock();
    sched.snapshots()
}

/// Fallback file descriptor table used before the multitasking scheduler is initialized.
static FALLBACK_FDS: spin::Mutex<crate::fs::FdTable> = spin::Mutex::new(crate::fs::FdTable::empty());

/// Executes a closure with mutable access to the active task's file descriptor table.
/// Falls back to a global default table if multitasking is not yet initialized.
///
/// # Arguments
///
/// * `f` - Closure operating on the task's [`crate::fs::fd::FdTable`].
///
/// # Returns
///
/// Result value produced by the closure `f`.
pub fn with_current_fds_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut crate::fs::FdTable) -> R,
{
    // Only the table is locked while `f` runs, not the scheduler: file I/O in `f` calls the
    // disk driver process, which needs the scheduler to run
    let fds = {
        let sched = SCHEDULER.lock();
        if sched.is_initialized() {
            Some(sched.current_fds().expect("Task FdTable missing"))
        } else {
            None
        }
    };
    match fds {
        Some(fds) => f(&mut fds.lock()),
        None => {
            let mut fallback = FALLBACK_FDS.lock();
            fallback.init_default();
            f(&mut fallback)
        }
    }
}
