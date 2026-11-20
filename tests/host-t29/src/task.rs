//! *stub* `crate::task`: the scheduler and task records are fakes (see `fake`); the ELF
//! parser and the Linux image loader are the kernel's own.

pub static CURRENT_TID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[path = "../../../src/task/elf.rs"]
pub mod elf;
#[path = "../../../src/task/exec.rs"]
pub mod exec;

pub mod scheduler {
    pub const DEFAULT_STACK_SIZE: usize = 65536;
    pub static MAX_KSTACK_USE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
}
pub use crate::fake::wait;
pub mod tcb {
    pub use crate::fake::{Caps, Task, TaskId, TaskPriority, TaskState};
}
/// *mirror* of `src/task/tcb.rs`'s personalities.
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
    pub fn as_str(&self) -> &'static str {
        match self {
            TaskPersonality::Hydra => "Hydra",
            TaskPersonality::Linux => "Linux",
            TaskPersonality::FreeBsd => "FreeBSD",
            TaskPersonality::MacOs => "macOS",
        }
    }
}
/// *stub* The fake clock moves instead (nothing sleeps on the host).
/// *stub* The fake clock moves, and the test's wait hook (`fake::ON_WAIT`) runs: kernel loops
/// that poll with a sleep (a stopped process, `rt_sigsuspend`) see what it changes. Without
/// a hook, a sleep loop that would never end fails the test.
pub fn sleep_ticks(ticks: u64) {
    crate::fake::TICKS.set(crate::fake::TICKS.get() + ticks);
    crate::fake::SLEEPS.set(crate::fake::SLEEPS.get() + 1);
    let hook = crate::fake::ON_WAIT.with_borrow_mut(|h| h.take());
    match hook {
        Some(mut h) => {
            h();
            crate::fake::ON_WAIT.with_borrow_mut(|slot| {
                if slot.is_none() {
                    *slot = Some(h)
                }
            });
        }
        None if crate::fake::SLEEPS.get() > 100_000 => panic!("fake sleep: a sleep loop that never ends"),
        None => {}
    }
}
pub fn sleep_ms(ms: u64) {
    crate::fake::TICKS.set(crate::fake::TICKS.get() + ms);
}
pub fn yield_now() {
    crate::fake::rec("yield_now()");
}
/// *stub* The thread's exit ends the test with a panic it can catch.
pub fn exit() -> ! {
    panic!("task::exit")
}
/// *stub* A thread group's exit ends the test with a panic it can catch.
pub fn exit_group() -> ! {
    panic!("task::exit_group")
}
pub use crate::fake::{
    is_task_alive, with_current_fds_mut, with_current_task_mut, Task, TaskId, TaskPriority, TaskState, SCHEDULER,
};
