//! # Shell Commands: Miscellaneous Console & Diagnostic Utilities
//!
//! Provides utilities for color configuration, echo output, screen clearing, crash simulation,
//! exception trapping, scroll lock toggling, and cursor styling.

use uefi::proto::console::text::Color;
use crate::console::{clear_screen, set_color};
use crate::shell::command::Command;
use crate::shell::print_welcome_banner;
use crate::shell::state::ShellState;

/// Shell command configuring console foreground text color.
pub struct ColorCommand;

impl Command for ColorCommand {
    fn name(&self) -> &'static str {
        "color"
    }

    fn description(&self) -> &'static str {
        "Change shell prompt and text color (cyan, green, yellow, red, white, magenta, blue)"
    }

    fn usage(&self) -> &'static str {
        "color <cyan|green|yellow|red|white|magenta|blue>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        let name = match args.first() {
            Some(n) => *n,
            None => {
                println!("Usage: {}", self.usage());
                return;
            }
        };

        let color = match name {
            "cyan" => Color::LightCyan,
            "green" => Color::LightGreen,
            "yellow" => Color::Yellow,
            "red" => Color::LightRed,
            "white" => Color::White,
            "magenta" => Color::LightMagenta,
            "blue" => Color::LightBlue,
            _ => {
                println!("Available colors: cyan, green, yellow, red, white, magenta, blue");
                return;
            }
        };

        state.prompt_color = color;
        set_color(color, Color::Black);
        println!("[+] Shell prompt color changed to {}", name);
    }
}

/// Shell command echoing arguments back to console output.
pub struct EchoCommand;

impl Command for EchoCommand {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "Echo arguments back to the screen"
    }

    fn usage(&self) -> &'static str {
        "echo <text...>"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        for (i, word) in args.iter().enumerate() {
            if i > 0 {
                print!(" ");
            }
            print!("{}", word);
        }
        println!();
    }
}

/// Shell command clearing the terminal screen and resetting cursor position.
pub struct ClearCommand;

impl Command for ClearCommand {
    fn name(&self) -> &'static str {
        "clear"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["cls"]
    }

    fn description(&self) -> &'static str {
        "Clear the active screen buffer and scrollback history"
    }

    fn usage(&self) -> &'static str {
        "clear"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        crate::console::clear_scrollback();
        clear_screen();
        print_welcome_banner();
    }
}

/// Shell command triggering a deliberate kernel panic for handler testing.
pub struct PanicCommand;

impl Command for PanicCommand {
    fn name(&self) -> &'static str {
        "panic"
    }

    fn description(&self) -> &'static str {
        "Manually trigger a kernel panic to test diagnostic handler"
    }

    fn usage(&self) -> &'static str {
        "panic"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        panic!("Manual kernel panic triggered by user from shell.");
    }
}

/// Shell command triggering an architectural CPU exception trap (`#BP`, `#DE`, `#UD`).
pub struct TrapCommand;

impl Command for TrapCommand {
    fn name(&self) -> &'static str {
        "trap"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["int3", "breakpoint"]
    }

    fn description(&self) -> &'static str {
        "Trigger an intentional CPU breakpoint exception (#BP) to test IDT routing"
    }

    fn usage(&self) -> &'static str {
        "trap"
    }

    fn execute(&self, _args: &[&str], _state: &mut ShellState) {
        println!("[*] Executing INT3 instruction to test IDT breakpoint trap...");
        unsafe {
            core::arch::asm!("int3");
        }
        set_color(Color::LightGreen, Color::Black);
        println!("[+] Resumed successfully from #BP exception handler!");
    }
}

/// Shell command pausing and inspecting terminal scrollback history.
pub struct ScrollLockCommand;

impl Command for ScrollLockCommand {
    fn name(&self) -> &'static str {
        "scroll"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["scrolllock", "slock"]
    }

    fn description(&self) -> &'static str {
        "Toggle or query Scroll Lock mode for Up/Down arrow terminal scrolling"
    }

    fn usage(&self) -> &'static str {
        "scroll [on|off]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        let new_state = match args.first() {
            Some(&"on") => {
                crate::console::set_scroll_lock(true);
                true
            }
            Some(&"off") => {
                crate::console::set_scroll_lock(false);
                false
            }
            _ => crate::console::toggle_scroll_lock(),
        };

        if new_state {
            set_color(Color::LightCyan, Color::Black);
            println!("[+] Scroll Lock: ON");
            println!("    Use Up / Down arrow keys (or PageUp / PageDown) to scroll the terminal screen.");
            println!("    Type 'scroll off' or toggle Scroll Lock (or Ctrl+S) to resume history navigation.");
        } else {
            set_color(Color::Yellow, Color::Black);
            println!("[-] Scroll Lock: OFF");
            println!("    Up / Down arrow keys now navigate command history as normal.");
        }
    }
}

/// Shell command configuring terminal text cursor shape (`block`, `underline`, `bar`).
pub struct CursorCommand;

impl Command for CursorCommand {
    fn name(&self) -> &'static str {
        "cursor"
    }

    fn description(&self) -> &'static str {
        "Configure shell cursor visibility and style (on, off, underline, block, bar)"
    }

    fn usage(&self) -> &'static str {
        "cursor [on|off|underline|block|bar]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        use crate::console::CursorShape;

        match args.first() {
            Some(&"on") | Some(&"enable") => {
                crate::console::set_cursor_enabled(true);
                set_color(Color::LightGreen, Color::Black);
                println!("[+] Terminal cursor enabled.");
            }
            Some(&"off") | Some(&"disable") => {
                crate::console::set_cursor_enabled(false);
                set_color(Color::Yellow, Color::Black);
                println!("[-] Terminal cursor disabled.");
            }
            Some(&"underline") => {
                crate::console::set_cursor_shape(CursorShape::Underline);
                set_color(Color::LightCyan, Color::Black);
                println!("[+] Terminal cursor shape set to Underline (3-pixel baseline).");
            }
            Some(&"block") => {
                crate::console::set_cursor_shape(CursorShape::Block);
                set_color(Color::LightCyan, Color::Black);
                println!("[+] Terminal cursor shape set to Block (8x16 inverted box).");
            }
            Some(&"bar") => {
                crate::console::set_cursor_shape(CursorShape::Bar);
                set_color(Color::LightCyan, Color::Black);
                println!("[+] Terminal cursor shape set to Bar (2-pixel vertical line).");
            }
            Some(other) => {
                println!("[-] Unknown cursor option: '{}'", other);
                println!("Usage: {}", self.usage());
            }
            None => {
                let enabled = crate::console::is_cursor_enabled();
                let shape = match crate::console::cursor_shape() {
                    CursorShape::Underline => "underline",
                    CursorShape::Block => "block",
                    CursorShape::Bar => "bar",
                };
                let (col, row) = crate::console::cursor_position();

                set_color(Color::LightCyan, Color::Black);
                println!("[*] Terminal Cursor Status:");
                println!("    Enabled:  {}", if enabled { "yes" } else { "no" });
                println!("    Shape:    {}", shape);
                println!("    Position: col {}, row {}", col, row);
                println!("    Blink:    ~1 Hz (500ms interval)");
                println!("Usage: {}", self.usage());
            }
        }
    }
}


