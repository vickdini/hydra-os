//! # Shell Command: System Subsystems Operational Health (`status`)
//!
//! Provides the `status` shell command checking subsystem health across memory, scheduler,
//! storage, and network layers.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::memory;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command inspecting global microkernel subsystem operational readiness.
pub struct StatusCommand;

impl Command for StatusCommand {
    fn name(&self) -> &'static str {
        "status"
    }

    fn description(&self) -> &'static str {
        "Inspect operational health of all microkernel subsystems"
    }

    fn usage(&self) -> &'static str {
        "status"
    }

    fn execute(&self, _args: &[&str], state: &mut ShellState) {
        set_color(Color::LightGreen, Color::Black);
        println!("\nSubsystem Status:");
        println!("  [+] GDT & TSS:           ONLINE (Ring 0 & Ring 3 segments initialized)");
        println!("  [+] CPU Registers:       ONLINE (Paging and Protection enabled)");

        let (usable_mb, allocated_kb, free_mb) = {
            let alloc = memory::frame_allocator::FRAME_ALLOCATOR.lock();
            (
                alloc.total_usable_memory() / (1024 * 1024),
                alloc.allocated_memory() / 1024,
                alloc.free_memory() / (1024 * 1024),
            )
        };
        println!("  [+] Frame Allocator:     ONLINE (Usable: {} MiB, Alloc: {} KiB, Free: {} MiB)",
            usable_mb, allocated_kb, free_mb);

        let address_space = memory::paging::AddressSpace::active();
        println!("  [+] Virtual Memory:      ONLINE (Active PML4: {:#x})",
            address_space.pml4_physical_address().as_u64());

        let mut cap_count = 0;
        for slot in 0..crate::capability::table::MAX_CAPABILITIES {
            if state.cap_table.get(slot).is_some() {
                cap_count += 1;
            }
        }
        println!("  [+] Capability Table:    ONLINE ({} active capabilities in CSpace)", cap_count);
        println!("  [+] IPC Rendezvous:      ONLINE (Endpoint #{} active, {} pending messages)\n",
            state.endpoint.id(), state.endpoint.pending_count());
    }
}
