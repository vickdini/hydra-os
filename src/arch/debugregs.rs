//! x86 debug registers: the hardware breakpoints and watchpoints debuggers set through
//! ptrace.
//!
//! Each task keeps `[dr0, dr1, dr2, dr3, -, -, dr6, dr7]` (the layout of `u_debugreg` in
//! Linux's `struct user`); [`switch_to`] loads them when the task is switched in. Most tasks
//! have none, and then nothing is written unless the previous task had some.
use core::sync::atomic::Ordering;

/// Whether each CPU has a task's breakpoints enabled right now (per CPU: one CPU's switch
/// must not hide another's loaded breakpoints, which would then fire in its next task).
static LOADED: super::percpu::PerCpuU32 = super::percpu::PerCpuU32::new();

unsafe fn write_dr7(v: u64) {
    core::arch::asm!("mov dr7, {}", in(reg) v, options(nostack, preserves_flags));
}

/// Loads the incoming task's debug registers (or disables the previous task's).
pub fn switch_to(dr: &[u64; 8]) {
    if dr[7] & 0xff == 0 {
        if LOADED.swap(0, Ordering::Relaxed) != 0 {
            unsafe { write_dr7(0) };
        }
        return;
    }
    unsafe {
        write_dr7(0);
        core::arch::asm!("mov dr0, {}", in(reg) dr[0], options(nostack, preserves_flags));
        core::arch::asm!("mov dr1, {}", in(reg) dr[1], options(nostack, preserves_flags));
        core::arch::asm!("mov dr2, {}", in(reg) dr[2], options(nostack, preserves_flags));
        core::arch::asm!("mov dr3, {}", in(reg) dr[3], options(nostack, preserves_flags));
        write_dr7(dr[7]);
    }
    LOADED.store(1, Ordering::Relaxed);
}

/// Reads and clears DR6 (which breakpoint fired, or a single step).
pub fn take_dr6() -> u64 {
    let v: u64;
    unsafe {
        core::arch::asm!("mov {}, dr6", out(reg) v, options(nostack, preserves_flags));
        core::arch::asm!("mov dr6, {}", in(reg) 0u64, options(nostack, preserves_flags));
    }
    v
}
