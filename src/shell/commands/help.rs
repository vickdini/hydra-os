//! # Shell Command: System Help & Command Discovery (`help`, `?`)
//!
//! Provides the `help` command listing built-in microkernel commands and usage summaries.

use uefi::proto::console::text::Color;
use crate::console::set_color;
use crate::shell::command::Command;
use crate::shell::commands::all_commands;
use crate::shell::state::ShellState;

/// Shell command displaying the help catalog and command summaries.
pub struct HelpCommand;

impl Command for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["?"]
    }

    fn description(&self) -> &'static str {
        "Show this command manual and usage summary"
    }

    fn usage(&self) -> &'static str {
        "help [command]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        if let Some(target) = args.first() {
            for cmd in all_commands() {
                if cmd.name() == *target || cmd.aliases().contains(target) {
                    set_color(Color::LightCyan, Color::Black);
                    println!("\nCommand: {}", cmd.name());
                    if !cmd.aliases().is_empty() {
                        print!("Aliases: ");
                        for (i, alias) in cmd.aliases().iter().enumerate() {
                            if i > 0 { print!(", "); }
                            print!("{}", alias);
                        }
                        println!();
                    }
                    println!("Description: {}", cmd.description());
                    if !cmd.usage().is_empty() {
                        println!("Usage:       {}", cmd.usage());
                    }
                    println!();
                    return;
                }
            }
            set_color(Color::LightRed, Color::Black);
            println!("No help entry found for '{}'.", target);
            return;
        }

        set_color(Color::Yellow, Color::Black);
        println!("\nHydra Shell Available Commands:");
        for cmd in all_commands() {
            set_color(Color::LightGreen, Color::Black);
            print!("  {:14}", cmd.name());
            set_color(Color::White, Color::Black);
            println!("- {}", cmd.description());
        }
        set_color(Color::LightCyan, Color::Black);
        println!("\nGNU Core Utilities Suite & OpenZFS Subsystems:");
        set_color(Color::White, Color::Black);
        println!("  - Filesystem:  pwd, cd, ls, cat, write, touch, mkdir, rmdir, rm, cp, mv, stat, df, du");
        println!("  - Text stream: head, tail, wc, grep, basename, dirname");
        println!("  - System/misc: uname, whoami/id, sleep, seq, yes, true, false");
        println!("  - OpenZFS:     zpool, zfs (snapshots, datasets, Fletcher-4 checksums)");
        println!("  - Firmware:    efifs, mem, cpu, translate, caps, ipc, time, color, clear, panic");
        println!("\nType 'help <command>' for specific syntax, flags, and options.\n");
    }
}
