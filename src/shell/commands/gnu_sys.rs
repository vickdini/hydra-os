//! # Shell Commands: GNU Coreutils System, Identity & Timing Utilities
//!
//! Implements standard UNIX system inspection, privilege management, and shell scripting
//! utilities (`uname`, `whoami`, `su`, `sudo`, `sleep`, `seq`, `yes`, `true`, `false`, and
//! `uptime`).
//!
//! ## Architectural Role & Design Rationale
//! Interactive administration and shell scripts depend on standard identity switching (`su`,
//! `sudo`, `whoami`), kernel metadata queries (`uname`, `uptime`), and loop/delay primitives
//! (`sleep`, `seq`, `yes`, `true`, `false`). These built-in commands synchronize user/group
//! credential changes with both `ShellState` and the active kernel task control block.
//!
//! ## Key Types & Interfaces
//! - [`UnameCommand`]: Prints kernel name, hostname, release, version, and machine architecture.
//! - [`WhoamiCommand`]: Displays effective UID/GID and capability space (`CSpace`) security profile.
//! - [`SuCommand`] / [`SudoCommand`]: Switches or temporarily elevates the session's active UID/GID.
//! - [`SleepCommand`] / [`UptimeCommand`]: Delays execution with `Ctrl+C` polling and reports 8254 PIT uptime ticks.
//! - [`SeqCommand`] / [`YesCommand`] / [`TrueCommand`] / [`FalseCommand`]: Standard scripting primitives.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Queries [`crate::arch::pit`] and interrupt flags in `uptime`; stalls via [`crate::console::stall`]
//! - Concurrency: Polls [`crate::console::check_interrupt()`] during loops and delays

use core::time::Duration;
use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::shell::command::{parse_u64, Command};
use crate::shell::state::ShellState;

/// Built-in `uname` command that prints operating system and hardware architecture metadata.
pub struct UnameCommand;

impl Command for UnameCommand {
    fn name(&self) -> &'static str {
        "uname"
    }

    fn description(&self) -> &'static str {
        "Print system information (options: -a all, -s kernel, -n node, -r release, -v version, -m arch)"
    }

    fn usage(&self) -> &'static str {
        "uname [-a] [-s] [-n] [-r] [-v] [-m]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let mut opt_s = false;
        let mut opt_n = false;
        let mut opt_r = false;
        let mut opt_v = false;
        let mut opt_m = false;

        for &arg in args {
            if arg.starts_with('-') && arg.len() > 1 {
                for c in arg.chars().skip(1) {
                    match c {
                        'a' => {
                            opt_s = true;
                            opt_n = true;
                            opt_r = true;
                            opt_v = true;
                            opt_m = true;
                        }
                        's' => opt_s = true,
                        'n' => opt_n = true,
                        'r' => opt_r = true,
                        'v' => opt_v = true,
                        'm' => opt_m = true,
                        _ => {}
                    }
                }
            }
        }

        // Default to -s if no options given
        if !opt_s && !opt_n && !opt_r && !opt_v && !opt_m {
            opt_s = true;
        }

        let mut first = true;
        set_color(Color::White, Color::Black);

        if opt_s {
            if !first { print!(" "); }
            print!("Hydra");
            first = false;
        }
        if opt_n {
            if !first { print!(" "); }
            print!("hydra-node-0");
            first = false;
        }
        if opt_r {
            if !first { print!(" "); }
            print!("0.1.0");
            first = false;
        }
        if opt_v {
            if !first { print!(" "); }
            print!("#1 SMP UEFI 64-bit Long Mode");
            first = false;
        }
        if opt_m {
            if !first { print!(" "); }
            print!("x86_64");
        }
        println!();
    }
}

/// Print current user and capability context.
pub struct WhoamiCommand;

impl Command for WhoamiCommand {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["id"]
    }

    fn description(&self) -> &'static str {
        "Print current effective user and capability security identity"
    }

    fn usage(&self) -> &'static str {
        "whoami [-u] [-g]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let is_id = args.contains(&"-u") || args.contains(&"-g") || args.contains(&"-a");

        set_color(Color::White, Color::Black);
        if is_id || args.is_empty() && self.name() == "id" {
            let role_desc = if state.is_root() {
                "cspace=Root slots rights=ALL(0xFFFFFFFF)"
            } else {
                "cspace=User slots rights=REDUCED(0x00000003)"
            };
            println!("uid={}({}) gid={}({}) groups={}({}) {}",
                state.current_uid, state.username_str(),
                state.current_gid, state.username_str(),
                state.current_gid, state.username_str(),
                role_desc);
        } else {
            println!("{}", state.username_str());
        }
    }
}

/// Switch active user identity.
pub struct SuCommand;

impl Command for SuCommand {
    fn name(&self) -> &'static str {
        "su"
    }

    fn description(&self) -> &'static str {
        "Switch shell user and effective credentials (e.g. 'su root' or 'su hydra')"
    }

    fn usage(&self) -> &'static str {
        "su [user]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let target_user = if args.is_empty() { "root" } else { args[0] };

        match target_user {
            "root" | "0" => {
                state.set_user("root", 0, 0);
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Switched to superuser 'root' (UID 0, GID 0)");
            }
            "hydra" | "1000" => {
                state.set_user("hydra", 1000, 1000);
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Switched to standard user 'hydra' (UID 1000, GID 1000)");
            }
            other => {
                if let Some(uid) = parse_u64(other) {
                    state.set_user("user", uid as u32, uid as u32);
                    set_color(Color::LightGreen, Color::Black);
                    println!("[+] Switched to UID {} (GID {})", uid, uid);
                } else {
                    set_color(Color::LightRed, Color::Black);
                    println!("su: user '{}' does not exist in /etc/passwd", other);
                    state.last_status = 1;
                }
            }
        }
    }
}

/// Execute command with superuser privileges.
pub struct SudoCommand;

impl Command for SudoCommand {
    fn name(&self) -> &'static str {
        "sudo"
    }

    fn description(&self) -> &'static str {
        "Execute a shell command with superuser (UID 0 / root) privileges"
    }

    fn usage(&self) -> &'static str {
        "sudo <command> [args...]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let old_uid = state.current_uid;
        let old_gid = state.current_gid;
        let mut old_user = [0u8; 32];
        let old_user_len = state.username_len;
        old_user[..old_user_len].copy_from_slice(&state.username[..old_user_len]);

        // Temporarily escalate to root
        state.set_user("root", 0, 0);

        let cmd_name = args[0];
        let sub_args = &args[1..];

        if let Some(cmd) = crate::shell::commands::find_command(cmd_name) {
            cmd.execute(sub_args, state);
        } else if crate::shell::fs::search_and_execute(cmd_name, sub_args, state) {
            state.last_status = 0;
        } else {
            set_color(Color::LightRed, Color::Black);
            println!("sudo: command not found: '{}'", cmd_name);
            state.last_status = 127;
        }

        // Restore previous identity
        if let Ok(prev_name) = core::str::from_utf8(&old_user[..old_user_len]) {
            state.set_user(prev_name, old_uid, old_gid);
        }
    }
}

/// Delay execution for a specified duration in seconds.
pub struct SleepCommand;

impl Command for SleepCommand {
    fn name(&self) -> &'static str {
        "sleep"
    }

    fn description(&self) -> &'static str {
        "Delay execution for a specified number of seconds"
    }

    fn usage(&self) -> &'static str {
        "sleep <seconds>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let secs = match parse_u64(args[0]) {
            Some(s) if s <= 60 => s,
            Some(_) => {
                set_color(Color::LightRed, Color::Black);
                println!("sleep: interval exceeds 60 seconds limit");
                return;
            }
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("sleep: invalid time interval '{}'", args[0]);
                return;
            }
        };

        // Sleep in 100ms increments to yield cleanly to firmware and check for Ctrl+C
        for _ in 0..(secs * 10) {
            if crate::console::check_interrupt() {
                println!("^C");
                _state.last_status = 130;
                return;
            }
            crate::console::stall(Duration::from_millis(100));
        }
    }
}

/// Print a sequence of numbers.
pub struct SeqCommand;

impl Command for SeqCommand {
    fn name(&self) -> &'static str {
        "seq"
    }

    fn description(&self) -> &'static str {
        "Print a sequence of numbers (e.g. 'seq 5', 'seq 2 5', 'seq 1 2 9')"
    }

    fn usage(&self) -> &'static str {
        "seq [FIRST [INCREMENT]] LAST"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let (first, step, last) = match args.len() {
            1 => {
                let last = parse_u64(args[0]).unwrap_or(0);
                (1u64, 1u64, last)
            }
            2 => {
                let first = parse_u64(args[0]).unwrap_or(1);
                let last = parse_u64(args[1]).unwrap_or(first);
                (first, 1u64, last)
            }
            _ => {
                let first = parse_u64(args[0]).unwrap_or(1);
                let step = parse_u64(args[1]).unwrap_or(1);
                let last = parse_u64(args[2]).unwrap_or(first);
                (first, if step == 0 { 1 } else { step }, last)
            }
        };

        set_color(Color::White, Color::Black);
        let mut curr = first;
        while curr <= last {
            println!("{}", curr);
            if crate::console::check_interrupt() {
                println!("^C");
                _state.last_status = 130;
                break;
            }
            curr = curr.saturating_add(step);
            if curr == 0 { break; } // Overflow guard
        }
    }
}

/// Output a string repeatedly.
pub struct YesCommand;

impl Command for YesCommand {
    fn name(&self) -> &'static str {
        "yes"
    }

    fn description(&self) -> &'static str {
        "Output a string repeatedly until interrupted with Ctrl+C"
    }

    fn usage(&self) -> &'static str {
        "yes [string]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let msg = if args.is_empty() { "y" } else { args[0] };
        set_color(Color::White, Color::Black);

        loop {
            println!("{}", msg);
            if crate::console::check_interrupt() {
                println!("^C");
                _state.last_status = 130;
                break;
            }
            // Yield 10ms to avoid pegging CPU and check for interrupts
            crate::console::stall(Duration::from_millis(10));
        }
    }
}

/// Returns true (exit status 0).
pub struct TrueCommand;

impl Command for TrueCommand {
    fn name(&self) -> &'static str {
        "true"
    }

    fn description(&self) -> &'static str {
        "Do nothing, successfully"
    }

    fn usage(&self) -> &'static str {
        "true"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        // Successful no-op
    }
}

/// Returns false (exit status 1).
pub struct FalseCommand;

impl Command for FalseCommand {
    fn name(&self) -> &'static str {
        "false"
    }

    fn description(&self) -> &'static str {
        "Do nothing, unsuccessfully"
    }

    fn usage(&self) -> &'static str {
        "false"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        // Unsuccessful no-op
    }
}

/// Print system uptime, PIT timer ticks, and interrupt subsystem diagnostics.
pub struct UptimeCommand;

impl Command for UptimeCommand {
    fn name(&self) -> &'static str {
        "uptime"
    }

    fn description(&self) -> &'static str {
        "Display system uptime, PIT timer ticks, and interrupt status"
    }

    fn usage(&self) -> &'static str {
        "uptime"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        if crate::arch::pit::is_active() {
            let total_sec = crate::arch::pit::uptime_seconds();
            let hours = total_sec / 3600;
            let minutes = (total_sec % 3600) / 60;
            let seconds = total_sec % 60;
            let ticks = crate::arch::pit::ticks();
            let freq = crate::arch::pit::frequency_hz();

            set_color(Color::LightGreen, Color::Black);
            println!(
                "[+] Uptime: {:02}:{:02}:{:02} ({} total seconds)",
                hours, minutes, seconds, total_sec
            );
            set_color(Color::LightCyan, Color::Black);
            println!(
                "    - PIT Hardware Ticks : {} ticks @ {} Hz ({} ms interval)",
                ticks, freq, if freq > 0 { 1000 / freq } else { 0 }
            );
            println!(
                "    - CPU Interrupts     : {}",
                if x86_64::instructions::interrupts::are_enabled() {
                    "ENABLED (Hardware IRQ0 Timer & IRQ1 Keyboard active)"
                } else {
                    "DISABLED"
                }
            );
        } else {
            set_color(Color::Yellow, Color::Black);
            println!("[-] PIT hardware timer is inactive (system running under UEFI Boot Services).");
            println!("    Run 'exitboot' to activate the 8254 PIT timer and hardware interrupts.");
        }
    }
}
