//! # Shell Command: System Information & Version (`info`, `about`)
//!
//! Displays kernel version, architecture target, and project metadata.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command displaying operating system version and build details.
pub struct InfoCommand;

impl Command for InfoCommand {
    fn name(&self) -> &'static str {
        "info"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["version", "about"]
    }

    fn description(&self) -> &'static str {
        "Display OS version, architecture, and multi-cloud / edge vision"
    }

    fn usage(&self) -> &'static str {
        "info"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        set_color(Color::LightCyan, Color::Black);
        println!("\n============================================================");
        println!("                HYDRA MICROKERNEL v0.1.0                     ");
        println!("     UNIX-like Distributed Cloud/Fog/Edge Operating System  ");
        println!("============================================================");
        set_color(Color::White, Color::Black);
        println!("Target:        x86_64-unknown-uefi (Native 64-bit Long Mode)");
        println!("Security:      Object-Capability Security Model (seL4-inspired)");
        println!("IPC:           Synchronous Rendezvous & Fast Inline Register Passing");
        println!("Memory:        4-Level PML4 Paging & Physical Frame Allocator");
        println!("Firmware:      UEFI 64-bit (SystemTable, Direct Console I/O)");
        println!("Distributed:   Self-* Autonomous Healing, Edge/Cloud Resource Virtualization\n");
    }
}
