//! # Shell Command: CPU Control Register Inspector (`cpu`)
//!
//! Reads and displays the current x86_64 architectural control registers (`CR0`, `CR2`, `CR3`,
//! and `CR4`) via [`crate::arch::cpu::read_state()`].
//!
//! ## Architectural Role & Design Rationale
//! Verifying paging configuration, write-protection enforcement (`CR0.WP`), active 4-level
//! page table roots (`CR3`), and last page-fault linear addresses (`CR2`) is essential during
//! kernel debugging. [`CpuCommand`] exposes these hardware registers in a human-readable format.
//!
//! ## Key Types & Interfaces
//! - [`CpuCommand`]: Implements the `cpu` built-in command.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (executes privileged `mov crX` instructions via [`crate::arch::cpu`])
//! - Hardware Interaction: Reads `CR0`, `CR2`, `CR3`, and `CR4` registers
//! - Concurrency: Stateless read-only snapshot of the executing processor's control registers

use uefi::proto::console::text::Color;
use crate::arch;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Built-in `cpu` command that displays x86_64 control registers (`CR0`, `CR2`, `CR3`, `CR4`).
pub struct CpuCommand;

impl Command for CpuCommand {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn description(&self) -> &'static str {
        "Display CPU control registers (CR0, CR2, CR3, CR4)"
    }

    fn usage(&self) -> &'static str {
        "cpu"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        let cpu = arch::cpu::read_state();
        set_color(Color::LightCyan, Color::Black);
        println!("\nCPU State & Control Registers:");
        set_color(Color::White, Color::Black);
        println!("  CR0:                {:?} (Paging & Protection flags)", cpu.cr0);
        println!("  CR2:                {:#x} (Last Page Fault linear address)", cpu.cr2);
        println!("  CR3 (PML4 Root):    {:#x} (Base physical address of 4-level page table)", cpu.cr3_frame.as_u64());
        println!("  CR4:                {:?} (Architecture Extensions & PAE)\n", cpu.cr4);
    }
}
