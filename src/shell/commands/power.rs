//! # Shell Commands: System Power Management (`shutdown`, `reboot`, `halt`)
//!
//! Provides commands to shut down the machine, perform hardware resets, or enter low-power halt state.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command powering off the hardware system via UEFI runtime services or ACPI.
pub struct ShutdownCommand;

impl Command for ShutdownCommand {
    fn name(&self) -> &'static str {
        "shutdown"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["poweroff", "exit", "logout"]
    }

    fn description(&self) -> &'static str {
        "Power off system using ACPI S5 and UEFI runtime shutdown"
    }

    fn usage(&self) -> &'static str {
        "shutdown"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Powering down system...");
        crate::arch::power::power_off();
    }
}

/// Shell command resetting and rebooting the hardware system.
pub struct RebootCommand;

impl Command for RebootCommand {
    fn name(&self) -> &'static str {
        "reboot"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["restart"]
    }

    fn description(&self) -> &'static str {
        "Reboot system via 8042 keyboard pulse, PCI reset, and UEFI cold reset"
    }

    fn usage(&self) -> &'static str {
        "reboot"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Rebooting system...");
        crate::arch::power::reboot();
    }
}

/// Shell command halting the CPU into an infinite low-power loop (`HLT`).
pub struct HaltCommand;

impl Command for HaltCommand {
    fn name(&self) -> &'static str {
        "halt"
    }

    fn description(&self) -> &'static str {
        "Disable interrupts and halt the CPU"
    }

    fn usage(&self) -> &'static str {
        "halt"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::Yellow, Color::Black);
        println!("[*] Halting CPU. Hardware interrupts disabled.");
        x86_64::instructions::interrupts::disable();
        loop {
            x86_64::instructions::hlt();
        }
    }
}
