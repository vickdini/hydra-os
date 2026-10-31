//! # Shell Commands: Capability Space (`CSpace`) Management
//!
//! Provides interactive commands (`caps`, `cap_insert`, `cap_revoke`) for inspecting and
//! manipulating the shell session's object capability table ([`crate::capability::table::CapabilityTable`]).
//!
//! ## Architectural Role & Design Rationale
//! In Hydra's capability-based security model, access to kernel objects (address spaces, IPC
//! endpoints, physical memory frames, threads, and devices) is governed by unforgeable tokens
//! stored in a task's `CSpace`. These commands allow developers and administrators to inspect
//! active capability slots, mint test `Endpoint` capabilities, and verify capability revocation
//! semantics interactively.
//!
//! ## Key Types & Interfaces
//! - [`CapsCommand`]: Lists all occupied capability slots, object types, and bitmask rights (`caps` / `cspace`).
//! - [`CapInsertCommand`]: Mints and inserts an `Endpoint` capability into the session's `CSpace` (`cap_insert`).
//! - [`CapRevokeCommand`]: Revokes and clears a capability slot by index (`cap_revoke`).
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (operates on `ShellState::cap_table`)
//! - Concurrency: Mutates session-local `ShellState`

use uefi::proto::console::text::Color;
use crate::capability::{CapType, Capability, Rights};
use crate::console::set_color;
use crate::shell::command::{parse_u32, parse_usize, Command};
use crate::shell::state::ShellState;

/// Built-in `caps` (`cspace`) command that lists active capability slots, object types, and permissions.
pub struct CapsCommand;

impl Command for CapsCommand {
    fn name(&self) -> &'static str {
        "caps"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["cspace"]
    }

    fn description(&self) -> &'static str {
        "List active task capability slots, object types, and rights"
    }

    fn usage(&self) -> &'static str {
        "caps"
    }

    fn execute(&self, _args: &[&str], state: &mut ShellState) {
        set_color(Color::LightCyan, Color::Black);
        println!("\nActive Task Capability Space (CSpace):");
        println!("+------+------------------------------------+-----------------------------+");
        println!("| Slot | Capability Type                    | Rights                      |");
        println!("+------+------------------------------------+-----------------------------+");

        let mut found = 0;
        for slot in 0..crate::capability::table::MAX_CAPABILITIES {
            if let Some(cap) = state.cap_table.get(slot) {
                found += 1;
                match cap.cap_type {
                    CapType::AddressSpace { root_cr3 } => {
                        print!("| {:4} | AddressSpace (CR3={:#x})", slot, root_cr3);
                    }
                    CapType::Endpoint { endpoint_id } => {
                        print!("| {:4} | Endpoint (ID={})", slot, endpoint_id);
                    }
                    CapType::MemoryFrame { physical_addr } => {
                        print!("| {:4} | MemoryFrame ({:#x})", slot, physical_addr);
                    }
                    CapType::Thread { thread_id } => {
                        print!("| {:4} | Thread (ID={})", slot, thread_id);
                    }
                    CapType::HardwareDevice { device_id } => {
                        print!("| {:4} | HardwareDevice (ID={})", slot, device_id);
                    }
                    CapType::UntypedMemory { size_bytes } => {
                        print!("| {:4} | UntypedMemory ({} bytes)", slot, size_bytes);
                    }
                }

                print!(" | ");
                let mut rights_printed = false;
                if cap.rights.contains(Rights::READ) { print!("READ "); rights_printed = true; }
                if cap.rights.contains(Rights::WRITE) { print!("WRITE "); rights_printed = true; }
                if cap.rights.contains(Rights::EXECUTE) { print!("EXEC "); rights_printed = true; }
                if cap.rights.contains(Rights::GRANT) { print!("GRANT "); rights_printed = true; }
                if cap.rights.contains(Rights::CALL) { print!("CALL "); rights_printed = true; }
                if !rights_printed { print!("NONE"); }
                println!(" |");
            }
        }

        if found == 0 {
            println!("| (empty capability table)                                                |");
        }
        println!("+------+------------------------------------+-----------------------------+\n");
    }
}

/// Built-in `cap_insert` command that inserts a new `Endpoint` capability into the session's `CSpace`.
pub struct CapInsertCommand;

impl Command for CapInsertCommand {
    fn name(&self) -> &'static str {
        "cap_insert"
    }

    fn description(&self) -> &'static str {
        "Insert a new Endpoint capability into the task's CSpace"
    }

    fn usage(&self) -> &'static str {
        "cap_insert <endpoint_id> (e.g. cap_insert 2)"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let ep_id = match args.first().and_then(|s| parse_u32(s)) {
            Some(id) => id,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: {}", self.usage());
                return;
            }
        };

        let cap = Capability::new(
            CapType::Endpoint { endpoint_id: ep_id },
            Rights(Rights::READ.0 | Rights::WRITE.0 | Rights::CALL.0),
        );

        match state.cap_table.insert(cap) {
            Ok(slot) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Inserted Endpoint #{} capability into CSpace slot #{}", ep_id, slot);
            }
            Err(err) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to insert capability: {}", err);
            }
        }
    }
}

/// Built-in `cap_revoke` command that revokes an existing capability from the specified `CSpace` slot.
pub struct CapRevokeCommand;

impl Command for CapRevokeCommand {
    fn name(&self) -> &'static str {
        "cap_revoke"
    }

    fn description(&self) -> &'static str {
        "Revoke an existing capability from the specified CSpace slot"
    }

    fn usage(&self) -> &'static str {
        "cap_revoke <slot_number> (e.g. cap_revoke 1)"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let slot = match args.first().and_then(|s| parse_usize(s)) {
            Some(s) => s,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: {}", self.usage());
                return;
            }
        };

        match state.cap_table.revoke(slot) {
            Some(cap) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Revoked capability at slot #{}: {:?}", slot, cap.cap_type);
            }
            None => {
                set_color(Color::Yellow, Color::Black);
                println!("[*] Slot #{} was already empty or out of bounds.", slot);
            }
        }
    }
}
