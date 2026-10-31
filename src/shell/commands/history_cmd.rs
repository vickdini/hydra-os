//! # Shell Command: Command History Navigation (`history`)
//!
//! Provides the `history` command displaying interactive shell command history entries.

use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// Display command history list with line numbers.
pub struct HistoryCommand;

impl Command for HistoryCommand {
    fn name(&self) -> &'static str {
        "history"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["hist"]
    }

    fn description(&self) -> &'static str {
        "Display command history list with line numbers"
    }

    fn usage(&self) -> &'static str {
        "history"
    }

    fn execute(&self, _args: &[&str], state: &mut ShellState) {
        let total = state.history.total_count();
        let start = state.history.start_session_index();

        if start == 0 {
            set_color(Color::DarkGray, Color::Black);
            println!("  (history is empty)");
            return;
        }

        set_color(Color::Yellow, Color::Black);
        println!("Session Command History:");
        for i in start..=total {
            if let Some(cmd) = state.history.get_by_index(i) {
                set_color(Color::LightCyan, Color::Black);
                print!("  {:4}  ", i);
                set_color(Color::White, Color::Black);
                println!("{}", cmd);
            }
        }
    }
}
