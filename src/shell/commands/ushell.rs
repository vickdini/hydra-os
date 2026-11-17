//! # `ushell`: run the Ring 3 `hydra-shell` on the console (microkernel plan, group 4)
//!
//! Starts `hydra-shell` (embedded in the kernel, see `crate::admin`) with this session's
//! working directory and user, authorizes it as the admin console, and waits until it exits.
//! For testing part 1 only: the kernel shell stays the default console.
//!
//! While it runs, the kernel shell does not read the keyboard (it only checks whether the
//! program is still alive), so every key goes to `hydra-shell`.

use alloc::format;
use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Shell command starting the Ring 3 shell.
pub struct UshellCommand;

impl Command for UshellCommand {
    fn name(&self) -> &'static str {
        "ushell"
    }

    fn description(&self) -> &'static str {
        "Run the Ring 3 hydra-shell on the console until it exits (test of the admin interface)"
    }

    fn usage(&self) -> &'static str {
        "ushell"
    }

    fn execute(&self, _args: &[&str], state: &mut ShellState) {
        if !crate::task::is_active() {
            set_color(Color::LightRed, Color::Black);
            println!("[!] ushell: the scheduler is not active yet (run 'exitboot' first).");
            state.last_status = 1;
            return;
        }
        let cwd = format!("--cwd={}", state.cwd_str());
        let uid = format!("--uid={}", state.current_uid);
        let argv = ["hydra-shell", cwd.as_str(), uid.as_str()];
        let id = match crate::admin::launch_shell(&argv, state.current_uid, state.current_gid) {
            Ok(id) => id,
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] ushell: cannot start hydra-shell: {}", e);
                state.last_status = 1;
                return;
            }
        };
        // Not task::wait_task: it reads keys (for Ctrl+C), which belong to hydra-shell now
        while crate::task::is_task_alive(id) {
            crate::task::sleep_ms(20);
        }
        crate::admin::revoke_console(id);
        set_color(Color::White, Color::Black);
        state.last_status = 0;
    }
}
