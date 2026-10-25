use core::sync::atomic::{AtomicU64, Ordering};
use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::shell::command::{parse_u64, Command};
use crate::shell::state::ShellState;
use crate::task::{self, TaskId, TaskPriority, TaskState};

static WORKER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Background demo worker task executing concurrently with the interactive shell (Ring 0).
fn demo_background_worker() {
    for _ in 0..500 {
        WORKER_COUNTER.fetch_add(1, Ordering::Relaxed);
        task::sleep_ms(100);
    }
}

/// User-mode process executing in Ring 3, interacting exclusively via hardware SYSCALLs.
fn demo_user_process() {
    crate::syscall::sys_print("\n  [Ring 3 User Mode] Process initialized! Executing in unprivileged Ring 3.\n");
    let _pid = crate::syscall::sys_getpid();
    let _uptime = crate::syscall::sys_uptime();
    
    for i in 1..=4 {
        crate::syscall::sys_print("  [Ring 3 User Mode] Iteration ");
        // Print iteration number as ascii
        let digit = [b'0' + (i as u8), b'\n'];
        if let Ok(s) = core::str::from_utf8(&digit) {
            crate::syscall::sys_print(s);
        }
        crate::syscall::sys_sleep(300);
    }

    crate::syscall::sys_print("  [Ring 3 User Mode] Task completed successfully. Invoking SYS_EXIT.\n");
    crate::syscall::sys_exit();
}

/// Rogue user-mode process that attempts to execute a privileged instruction ('cli') in Ring 3.
///
/// Demonstrates hardware CPU privilege protection: the CPU immediately intercepts this with #GP.
fn demo_rogue_process() {
    crate::syscall::sys_print("\n  [Ring 3 Rogue Task] Running in unprivileged user mode.\n");
    crate::syscall::sys_print("  [Ring 3 Rogue Task] Attempting privileged 'cli' instruction (Ring 0 only)...\n");
    unsafe {
        core::arch::asm!("cli");
    }
    // Should never reach here because hardware raises General Protection Fault (#GP)
    crate::syscall::sys_exit();
}

/// Lists all registered tasks, thread states, privilege levels, and CPU tick statistics.
pub struct PsCommand;

impl Command for PsCommand {
    fn name(&self) -> &'static str {
        "ps"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["tasks", "threads"]
    }

    fn description(&self) -> &'static str {
        "List all active and sleeping kernel/user tasks in the preemptive scheduler"
    }

    fn usage(&self) -> &'static str {
        "ps"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        if !task::is_active() {
            set_color(Color::Yellow, Color::Black);
            println!("[-] Multitasking scheduler is not yet active.");
            return;
        }

        let snapshots = task::get_task_snapshots();

        set_color(Color::LightCyan, Color::Black);
        println!(
            "{:<5} {:<14} {:<8} {:<11} {:<9} {:>8} {:>18}",
            "PID", "NAME", "MODE", "STATE", "PRIORITY", "TICKS", "STACK (RSP)"
        );
        println!("{:-<78}", "");

        for s in &snapshots {
            match s.state {
                TaskState::Running => set_color(Color::LightGreen, Color::Black),
                TaskState::Ready => set_color(Color::White, Color::Black),
                TaskState::Sleeping { .. } => set_color(Color::Yellow, Color::Black),
                TaskState::Blocked => set_color(Color::LightMagenta, Color::Black),
                TaskState::Dead => set_color(Color::DarkGray, Color::Black),
            }

            println!(
                "{:<5} {:<14} {:<8} {:<11} {:<9} {:>8} {:#018x}",
                s.id.0,
                s.name,
                s.mode.as_str(),
                s.state.as_str(),
                s.priority.as_str(),
                s.ticks_run,
                s.rsp
            );
        }

        set_color(Color::LightCyan, Color::Black);
        println!("{:-<78}", "");
        let worker_val = WORKER_COUNTER.load(Ordering::Relaxed);
        println!(
            "Total tasks: {} | Timeslice: {} ms | Worker counter: {}",
            snapshots.len(),
            task::scheduler::DEFAULT_TIMESLICE_TICKS * 10,
            worker_val
        );
    }
}

/// Spawns a new concurrent background kernel or user task.
pub struct SpawnCommand;

impl Command for SpawnCommand {
    fn name(&self) -> &'static str {
        "spawn"
    }

    fn description(&self) -> &'static str {
        "Spawn a new task (e.g. 'spawn worker', 'spawn user', 'spawn rogue')"
    }

    fn usage(&self) -> &'static str {
        "spawn [worker | user | rogue]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if !task::is_active() {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Multitasking scheduler is not active.");
            return;
        }

        let target = args.first().copied().unwrap_or("worker");

        match target {
            "worker" | "counter" | "demo" => {
                let id = task::spawn("bg_worker", demo_background_worker, TaskPriority::Normal);
                set_color(Color::LightGreen, Color::Black);
                println!(
                    "[+] Spawned Ring 0 background worker task #{} ('bg_worker').",
                    id.0
                );
                println!("    Type 'ps' to observe the task executing concurrently.");
            }
            "user" | "ring3" => {
                let id = task::spawn_user("user_demo", demo_user_process, TaskPriority::Normal);
                set_color(Color::LightGreen, Color::Black);
                println!(
                    "[+] Spawned Ring 3 User Mode process #{} ('user_demo').",
                    id.0
                );
                println!("    Privilege: Unprivileged Ring 3 (CS=0x23, SS=0x1B)");
                println!("    Type 'ps' to observe its execution or 'syscalls' for metrics.");
            }
            "rogue" => {
                let id = task::spawn_user("rogue_task", demo_rogue_process, TaskPriority::Normal);
                set_color(Color::Yellow, Color::Black);
                println!(
                    "[+] Spawned Ring 3 Rogue process #{} ('rogue_task').",
                    id.0
                );
                println!("    This task will attempt an illegal 'cli' instruction in user mode.");
                println!("    Observe the CPU General Protection Fault (#GP) handling.");
            }
            unknown => {
                set_color(Color::LightRed, Color::Black);
                println!(
                    "Unknown task template '{}'. Available templates: worker, user, rogue",
                    unknown
                );
            }
        }
    }
}

/// Terminates an active task by its Task ID.
pub struct KillCommand;

impl Command for KillCommand {
    fn name(&self) -> &'static str {
        "kill"
    }

    fn description(&self) -> &'static str {
        "Terminate an active task by its PID (e.g. 'kill 2')"
    }

    fn usage(&self) -> &'static str {
        "kill <pid>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let arg = match args.first() {
            Some(a) => *a,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: kill <pid>");
                return;
            }
        };

        let pid = match parse_u64(arg) {
            Some(p) => p,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Invalid PID '{}'", arg);
                return;
            }
        };

        if pid == 0 {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Cannot kill PID 0 (Main shell thread).");
            return;
        }

        if pid == 1 {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Cannot kill PID 1 (Kernel idle thread).");
            return;
        }

        if task::kill(TaskId(pid)) {
            set_color(Color::LightGreen, Color::Black);
            println!("[+] Task #{} terminated.", pid);
        } else {
            set_color(Color::LightRed, Color::Black);
            println!("[!] Task #{} not found or already dead.", pid);
        }
    }
}

/// Inspects hardware system call registers and usage statistics.
pub struct SyscallsCommand;

impl Command for SyscallsCommand {
    fn name(&self) -> &'static str {
        "syscalls"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["sys", "syscall"]
    }

    fn description(&self) -> &'static str {
        "Display hardware system call configuration (MSRs) and execution statistics"
    }

    fn usage(&self) -> &'static str {
        "syscalls"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::LightGreen, Color::Black);
        println!("\n============================================================");
        println!(" [+] HYDRA MICROKERNEL: HARDWARE SYSTEM CALL SUBSYSTEM      ");
        println!("============================================================");

        unsafe {
            let efer = crate::arch::syscall::rdmsr(crate::arch::syscall::IA32_EFER);
            let star = crate::arch::syscall::rdmsr(crate::arch::syscall::IA32_STAR);
            let lstar = crate::arch::syscall::rdmsr(crate::arch::syscall::IA32_LSTAR);
            let fmask = crate::arch::syscall::rdmsr(crate::arch::syscall::IA32_FMASK);

            println!("  Hardware MSR Registers:");
            println!("    - IA32_EFER.SCE (0xC0000080) : {:#018x} (SCE={})", efer, efer & 1);
            println!("    - IA32_STAR     (0xC0000081) : {:#018x}", star);
            println!("      * Kernel CS:SS Base : {:#06x} / {:#06x}", (star >> 32) & 0xFFFF, ((star >> 32) & 0xFFFF) + 8);
            println!("      * User CS:SS Base   : {:#06x} (CS={:#06x}, SS={:#06x})", (star >> 48) & 0xFFFF, ((star >> 48) & 0xFFFF) + 16 | 3, ((star >> 48) & 0xFFFF) + 8 | 3);
            println!("    - IA32_LSTAR    (0xC0000082) : {:#018x} (asm_syscall_entry)", lstar);
            println!("    - IA32_FMASK    (0xC0000084) : {:#018x} (Flags masked on entry)", fmask);
        }

        let stats = crate::arch::syscall::SYSCALL_STATS.lock();
        println!("\n  Registered System Calls & Invocation Counts:");
        println!("    - [1] SYS_YIELD    : {} calls", stats.yield_calls);
        println!("    - [2] SYS_SLEEP    : {} calls", stats.sleep_calls);
        println!("    - [3] SYS_WRITE    : {} calls", stats.write_calls);
        println!("    - [4] SYS_EXIT     : {} calls", stats.exit_calls);
        println!("    - [5] SYS_GETPID   : {} calls", stats.getpid_calls);
        println!("    - [6] SYS_UPTIME   : {} calls", stats.uptime_calls);
        println!("    - [7] SYS_IPC_SEND : {} calls", stats.ipc_calls);
        println!("    - [8] SYS_IPC_RECV : {} calls", stats.ipc_calls);
        println!("    ---------------------------------------------");
        println!("    * Total Hardware System Calls Handled: {}", stats.total_calls);
        println!("============================================================\n");
    }
}
