//! # Shell Command: Microkernel Process Supervisor & Reincarnation Control (`service`)
//!
//! Provides diagnostic inspection, manual reincarnation, and fault injection testing for
//! decoupled Ring 3 driver daemons managed by the MINIX 3-style Reincarnation Server.
//!
//! ## Architectural Role & Design Rationale
//!
//! In Hydra's microkernel architecture, storage, network, and display drivers run as isolated
//! user-space daemons. The `service` command exposes the operational state of the
//! [`crate::task::supervisor::Supervisor`], allowing operators to:
//! - View active PIDs, bound IPC endpoints, and heartbeat statuses (`service list` / `service status`).
//! - Manually restart or cycle driver daemons without rebooting (`service restart <name>`).
//! - Simulate sudden driver faults or crashes to observe automated self-healing (`service kill <name>`).
//! - Execute manual watchdog health checks (`service tick`).
//!
//! ## Key Types & Interfaces
//!
//! - [`ServiceCommand`]: Command trait implementation registered in the shell dispatcher.

use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;
use crate::task::supervisor::{
    get_service_snapshots, kill_service_by_name, restart_service_by_name, supervisor_tick,
    ServiceState, SUPERVISOR,
};

/// Shell command to inspect and manage supervised microkernel services.
pub struct ServiceCommand;

impl Command for ServiceCommand {
    fn name(&self) -> &'static str {
        "service"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["rs", "daemon", "daemons"]
    }

    fn description(&self) -> &'static str {
        "MINIX 3-style process supervisor: monitor, restart, and inspect microkernel driver daemons"
    }

    fn usage(&self) -> &'static str {
        "service [status|list|restart <name>|kill <name>|start <name>|tick]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let subcmd = args.first().copied().unwrap_or("status");

        match subcmd {
            "status" | "list" => {
                set_color(Color::LightCyan, Color::Black);
                crate::println!("\n=========================================================================================");
                crate::println!(" HYDRA PROCESS SUPERVISOR & REINCARNATION SERVER (MINIX 3 ARCHITECTURE)                  ");
                crate::println!("=========================================================================================");
                set_color(Color::Yellow, Color::Black);
                crate::println!("{:<16} {:<8} {:<10} {:<12} {:<10} {:<12} {:<10}",
                    "NAME", "PID", "ENDPOINT", "STATE", "RESTARTS", "MISSED PING", "HEALTH"
                );
                set_color(Color::DarkGray, Color::Black);
                crate::println!("-----------------------------------------------------------------------------------------");

                let snapshots = get_service_snapshots();
                if snapshots.is_empty() {
                    set_color(Color::LightGray, Color::Black);
                    crate::println!("  No microkernel services currently registered.");
                } else {
                    for s in snapshots {
                        let pid_str = match s.task_id {
                            Some(pid) => alloc::format!("{}", pid),
                            None => alloc::string::String::from("-"),
                        };

                        let (state_str, state_color) = match s.state {
                            ServiceState::Running => ("Running", Color::LightGreen),
                            ServiceState::Restarting => ("Restarting", Color::LightMagenta),
                            ServiceState::Faulted => ("Faulted", Color::LightRed),
                            ServiceState::Stopped => ("Stopped", Color::DarkGray),
                        };

                        let health_str = if s.state == ServiceState::Running {
                            if s.unanswered_pings == 0 {
                                "Healthy"
                            } else {
                                "Degraded"
                            }
                        } else {
                            "-"
                        };

                        set_color(Color::White, Color::Black);
                        crate::print!("{:<16} {:<8} {:<#10x} ", s.name, pid_str, s.endpoint_id);
                        set_color(state_color, Color::Black);
                        crate::print!("{:<12} ", state_str);
                        set_color(Color::White, Color::Black);
                        crate::println!("{:<10} {:<12} {:<10}", s.restart_count, s.unanswered_pings, health_str);
                    }
                }
                for (irq, owner, count, notified, pending, masked) in crate::ipc::service::irq_stats() {
                    set_color(Color::LightGray, Color::Black);
                    crate::println!(
                        "  IRQ {:<3} -> process {:<6} {} interrupts, {} client wakes, {} pending, {}",
                        irq, owner, count, notified, pending, if masked { "masked" } else { "unmasked" }
                    );
                }
                set_color(Color::LightCyan, Color::Black);
                crate::println!("=========================================================================================\n");
                set_color(Color::White, Color::Black);
            }

            "restart" => {
                if let Some(&name) = args.get(1) {
                    set_color(Color::Yellow, Color::Black);
                    crate::println!("[*] Requesting reincarnation of service '{}'...", name);
                    match restart_service_by_name(name) {
                        Ok(new_pid) => {
                            set_color(Color::LightGreen, Color::Black);
                            crate::println!("[+] Service '{}' successfully reincarnated as Task PID {}.", name, new_pid.0);
                        }
                        Err(err) => {
                            set_color(Color::LightRed, Color::Black);
                            crate::println!("[!] Reincarnation failed for '{}': {}", name, err);
                        }
                    }
                    set_color(Color::White, Color::Black);
                } else {
                    set_color(Color::LightRed, Color::Black);
                    crate::println!("Usage: service restart <name>");
                    set_color(Color::White, Color::Black);
                }
            }

            "kill" => {
                if let Some(&name) = args.get(1) {
                    set_color(Color::LightRed, Color::Black);
                    crate::println!("[!] Simulating fatal fault in service '{}'...", name);
                    match kill_service_by_name(name) {
                        Ok(killed_pid) => {
                            crate::println!("[+] Terminated process PID {} for service '{}'.", killed_pid.0, name);
                            set_color(Color::Yellow, Color::Black);
                            crate::println!("[*] Running supervisor watchdog sweep to test automated reincarnation...");
                            supervisor_tick();
                            set_color(Color::LightGreen, Color::Black);
                            crate::println!("[+] Supervisor sweep completed. Check 'service status' for reincarnation metrics.");
                        }
                        Err(err) => {
                            crate::println!("[!] Failed to terminate service '{}': {}", name, err);
                        }
                    }
                    set_color(Color::White, Color::Black);
                } else {
                    set_color(Color::LightRed, Color::Black);
                    crate::println!("Usage: service kill <name>");
                    set_color(Color::White, Color::Black);
                }
            }

            "start" => {
                if let Some(&name) = args.get(1) {
                    set_color(Color::Yellow, Color::Black);
                    crate::println!("[*] Starting service '{}'...", name);
                    let res = SUPERVISOR.lock().start_service(name);
                    match res {
                        Ok(pid) => {
                            set_color(Color::LightGreen, Color::Black);
                            crate::println!("[+] Service '{}' started successfully as PID {}.", name, pid.0);
                        }
                        Err(err) => {
                            set_color(Color::LightRed, Color::Black);
                            crate::println!("[!] Failed to start service '{}': {}", name, err);
                        }
                    }
                    set_color(Color::White, Color::Black);
                } else {
                    set_color(Color::LightRed, Color::Black);
                    crate::println!("Usage: service start <name>");
                    set_color(Color::White, Color::Black);
                }
            }

            "tick" => {
                set_color(Color::LightCyan, Color::Black);
                crate::println!("[*] Dispatching supervisor heartbeat watchdog tick...");
                supervisor_tick();
                set_color(Color::LightGreen, Color::Black);
                crate::println!("[+] Supervisor heartbeat tick completed.");
                set_color(Color::White, Color::Black);
            }

            unknown => {
                set_color(Color::LightRed, Color::Black);
                crate::println!("[!] Unknown service subcommand '{}'. Usage: {}", unknown, self.usage());
                set_color(Color::White, Color::Black);
            }
        }
    }
}

