pub mod elf;
pub mod exec;
pub mod scheduler;
pub mod tcb;
pub mod wait;

use alloc::vec::Vec;
pub use elf::{load_elf, load_linux_elf, ElfBinary, ElfError, ElfProcessImage};
pub use scheduler::{TaskSnapshot, SCHEDULER};
pub use tcb::{PrivilegeMode, Task, TaskId, TaskPersonality, TaskPriority, TaskRegisters, TaskState};

/// Number of kernel wait points currently active (see [`preemptible`]).
pub static PREEMPT_POINTS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Linux system call the running task is executing (`u64::MAX` when none), for
/// [`scheduler::Scheduler::dump_tasks`].
pub static CURRENT_SYSCALL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// Runs `f` (an idle wait such as `hlt` or a timed sleep) as a preemption point.
///
/// Kernel-mode code is otherwise never preempted by the timer: kernel spinlocks are not
/// interrupt-safe, and syscalls run with interrupts disabled, so switching away from a task
/// that holds one would deadlock the CPU. `f` must not be called with any lock held.
pub fn preemptible<R>(f: impl FnOnce() -> R) -> R {
    PREEMPT_POINTS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    let r = f();
    PREEMPT_POINTS.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    r
}

/// Initializes the multitasking subsystem and registers the current main thread.
pub fn init(current_cr3: u64) {
    let mut sched = SCHEDULER.lock();
    sched.init(current_cr3);
}

/// Updates the CR3 root paging table for the active main thread.
pub fn update_cr3(cr3: u64) {
    let mut sched = SCHEDULER.lock();
    if sched.is_initialized() {
        sched.update_main_cr3(cr3);
    } else {
        sched.init(cr3);
    }
}

/// Returns true if multitasking is initialized.
pub fn is_active() -> bool {
    SCHEDULER.lock().is_initialized()
}

/// Spawns a new background kernel task (Ring 0).
pub fn spawn(name: &'static str, entry_fn: fn(), priority: TaskPriority) -> TaskId {
    let mut sched = SCHEDULER.lock();
    sched.spawn(name, entry_fn, priority)
}

/// Spawns a new unprivileged user process (Ring 3).
pub fn spawn_user(name: &'static str, entry_fn: fn(), priority: TaskPriority) -> TaskId {
    let mut sched = SCHEDULER.lock();
    sched.spawn_user(name, entry_fn, priority)
}

/// Spawns a new unprivileged user process from an in-memory ELF64 binary image.
pub fn spawn_elf(
    name: &'static str,
    elf_data: &[u8],
    priority: TaskPriority,
) -> Result<TaskId, &'static str> {
    let mut sched = SCHEDULER.lock();
    sched.spawn_elf(name, elf_data, priority)
}

/// Spawns a new unprivileged user process running a Linux ELF64 binary under the Linux ABI.
pub fn spawn_linux_elf(
    name: &'static str,
    elf_data: &[u8],
    args: &[&str],
    priority: TaskPriority,
    uid: u32,
    gid: u32,
) -> Result<TaskId, &'static str> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        sched.spawn_linux_elf(name, elf_data, args, priority, uid, gid)
    })
}

/// Spawns a Linux program `exe` (a path inside `root_dir`) `chroot`ed into `root_dir`.
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
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut sched = SCHEDULER.lock();
        sched
            .spawn_linux_process("linux_app", source, exe, args, TaskPriority::Normal, uid, gid, Some(root))
            .map_err(alloc::string::String::from)
    })
}

/// Sets credentials for a specific task.
pub fn set_task_credentials(id: TaskId, uid: u32, gid: u32) {
    SCHEDULER.lock().set_task_credentials(id, uid, gid);
}

/// Returns the personality (Hydra vs Linux) of the currently running task.
pub fn current_personality() -> TaskPersonality {
    SCHEDULER.lock().current_personality()
}

/// Executes a closure with mutable access to the active task control block.
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
/// Returns the TaskId of the blocked task.
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
pub fn unblock_task(id: TaskId) -> bool {
    let mut sched = SCHEDULER.lock();
    sched.unblock_task(id)
}

/// Puts the current task to sleep for a specified number of PIT timer ticks.
///
/// Works inside system calls (which run with interrupts disabled): the task sleeps in the
/// scheduler and the CPU keeps running other tasks, whose timer interrupts wake it.
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
pub fn exit() -> ! {
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
pub fn exit_group() -> ! {
    {
        let mut sched = SCHEDULER.lock();
        sched.terminate_current_group();
    }
    exit()
}

/// Terminates a task by its TaskId.
pub fn kill(id: TaskId) -> bool {
    let mut sched = SCHEDULER.lock();
    sched.kill_task(id)
}

/// Returns true if a task with the given ID is still active (not Dead).
pub fn is_task_alive(id: TaskId) -> bool {
    let sched = SCHEDULER.lock();
    sched.is_task_alive(id)
}

/// Waits synchronously for a task with the given ID to complete (transition to Dead).
/// Yields execution to the scheduler while waiting. Returns true if completed, false if interrupted.
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
pub fn get_task_snapshots() -> Vec<TaskSnapshot> {
    let sched = SCHEDULER.lock();
    sched.snapshots()
}

static FALLBACK_FDS: spin::Mutex<crate::fs::FdTable> = spin::Mutex::new(crate::fs::FdTable::empty());

/// Executes a closure with mutable access to the active task's file descriptor table.
/// Falls back to a global default table if multitasking is not yet initialized.
pub fn with_current_fds_mut<F, R>(f: F) -> R
where
    F: FnOnce(&mut crate::fs::FdTable) -> R,
{
    let mut sched = SCHEDULER.lock();
    if sched.is_initialized() {
        sched.current_task_fds_mut(f).expect("Task FdTable missing")
    } else {
        drop(sched);
        let mut fallback = FALLBACK_FDS.lock();
        fallback.init_default();
        f(&mut fallback)
    }
}
