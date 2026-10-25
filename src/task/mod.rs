pub mod scheduler;
pub mod tcb;

use alloc::vec::Vec;
pub use scheduler::{TaskSnapshot, SCHEDULER};
pub use tcb::{PrivilegeMode, Task, TaskId, TaskPriority, TaskRegisters, TaskState};

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

/// Cooperatively yields the current task's timeslice to the next ready task.
pub fn yield_now() {
    if !is_active() {
        return;
    }
    unsafe {
        core::arch::asm!("int 32");
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
pub fn sleep_ticks(ticks: u64) {
    if !is_active() || !x86_64::instructions::interrupts::are_enabled() {
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
    if !is_active() || !x86_64::instructions::interrupts::are_enabled() {
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
