//! # Shell Command: Microkernel IPC Rendezvous Testing (`ipc`)
//!
//! Provides the `ipc` shell command for testing message transmission and receipt across endpoints.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::ipc::Message;
use crate::shell::command::{parse_hex, parse_u64, Command};
use crate::shell::state::ShellState;

/// Shell command exercising IPC message passing and queue inspection.
pub struct IpcCommand;

impl Command for IpcCommand {
    fn name(&self) -> &'static str {
        "ipc"
    }

    fn description(&self) -> &'static str {
        "Send and receive a fast register message on IPC Endpoint #1"
    }

    fn usage(&self) -> &'static str {
        "ipc <hex_label> [arg0] [arg1] [arg2] (e.g. ipc 0x1001 42 1337)"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let label = match args.first().and_then(|s| parse_hex(s)) {
            Some(l) => l as u32,
            None => {
                set_color(Color::LightRed, Color::Black);
                println!("Usage: {}", self.usage());
                return;
            }
        };

        let arg0 = args.get(1).and_then(|s| parse_u64(s)).unwrap_or(0);
        let arg1 = args.get(2).and_then(|s| parse_u64(s)).unwrap_or(0);
        let arg2 = args.get(3).and_then(|s| parse_u64(s)).unwrap_or(0);
        let arg3 = args.get(4).and_then(|s| parse_u64(s)).unwrap_or(0);

        let msg = Message::with_args(label, [arg0, arg1, arg2, arg3]);

        match state.endpoint.send(msg) {
            Ok(()) => {
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Message queued to Endpoint #{}: label={:#x}, args=[{}, {}, {}, {}]",
                    state.endpoint.id(), msg.label, msg.args[0], msg.args[1], msg.args[2], msg.args[3]);
            }
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Failed to send message: {}", e);
                return;
            }
        }

        // Immediately consume to complete rendezvous demonstration
        if let Some(received) = state.endpoint.receive() {
            set_color(Color::LightCyan, Color::Black);
            println!("[+] Rendezvous complete! Received message from Endpoint #{}:", state.endpoint.id());
            println!("    - Label: {:#x}", received.label);
            println!("    - Args:  {:?}", received.args);
        }
    }
}
