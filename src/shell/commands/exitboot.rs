//! # Shell Command: UEFI Boot Services Termination (`exitboot`)
//!
//! Implements the `exitboot` command (and aliases `takeover`, `baremetal`, `hwmode`) to
//! terminate UEFI Boot Services and transition the kernel into full bare-metal hardware
//! ownership.
//!
//! ## Architectural Role & Design Rationale
//! Hydra OS boots as a UEFI image, initially utilizing UEFI firmware services for console
//! and disk access. Invoking [`ExitBootCommand`] calls `take_hardware_ownership`, which
//! exits UEFI Boot Services, installs the kernel's custom GDT, TSS, IDT, 4-level page tables,
//! 8259 PIC / 8254 PIT timer, PS/2 keyboard driver, and direct GOP framebuffer console.
//!
//! ## Key Types & Interfaces
//! - [`ExitBootCommand`]: Implements the `exitboot` shell command and `exitboot status` query.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reloads `CR3`, `GDTR`, `IDTR`, `TR`, programs 8259 PIC and 8254 PIT via [`crate::arch::boot_services`]
//! - Concurrency: Must be invoked on the bootstrap processor before preemptive scheduling begins

use uefi::proto::console::text::Color;
use crate::arch::boot_services::{is_hardware_takeover_complete, take_hardware_ownership};
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Built-in `exitboot` command that terminates UEFI Boot Services and claims bare-metal hardware control.
pub struct ExitBootCommand;

impl Command for ExitBootCommand {
    fn name(&self) -> &'static str {
        "exitboot"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["takeover", "baremetal", "hwmode"]
    }

    fn description(&self) -> &'static str {
        "Terminate UEFI Boot Services and transition to full bare-metal hardware ownership"
    }

    fn usage(&self) -> &'static str {
        "exitboot [status]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if let Some(&"status") = args.first() {
            let active = is_hardware_takeover_complete();
            if active {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Hardware Mode: ACTIVE (Operating directly on CPU, Framebuffer & PS/2 controller)");
            } else {
                set_color(Color::Yellow, Color::Black);
                println!("[-] Hardware Mode: INACTIVE (Running under UEFI Boot Services)");
                println!("    Type 'exitboot' to terminate boot services and take full hardware control.");
            }
            return;
        }

        if is_hardware_takeover_complete() {
            set_color(Color::Yellow, Color::Black);
            println!("[!] Hardware takeover has already occurred; kernel is in bare-metal ownership.");
            return;
        }

        println!("[*] Initiating ExitBootServices and Bare-Metal Hardware Takeover...");
        match take_hardware_ownership() {
            Ok(stats) => {
                set_color(Color::LightCyan, Color::Black);
                println!("[+] Hardware transition successful!");
                println!("    - Memory Map Descriptors : {}", stats.memory_map_entries);
                println!("    - Active PML4 Root (CR3) : {:#x}", stats.active_cr3_pml4);
                println!("    - Framebuffer Base       : {:#x}", stats.framebuffer_virt);
                println!("    - Segment Selectors      : CS={:#x}, DS={:#x}, TR={:#x}",
                    stats.gdt_code_selector, stats.gdt_data_selector, stats.tss_selector
                );
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Hardware takeover failed: {}", e);
            }
        }
    }
}
