//! # Shell Subsystem: Interactive Microkernel Command Interpreter
//!
//! Provides the primary interactive read-eval-print loop (REPL), command line lexical
//! analyzer, pipeline router, and boot-service transition sequence for Hydra OS.
//!
//! ## Architectural Role & Design Rationale
//! The Hydra interactive shell serves as the administrative and user-facing command console
//! during both early UEFI boot services and post-takeover bare-metal execution. Rather than
//! relying on an external userland shell binary to bootstrap the system, this built-in
//! command interpreter allows immediate inspection of kernel subsystems, capability tables,
//! ZFS datasets, and Ring 3 ELF process execution.
//!
//! ## Key Types & Interfaces
//! - `Command`: Trait implemented by all built-in shell commands.
//! - `ShellState`: Persistent session context holding capabilities, working directory, and history.
//! - `run`: Main diverging REPL entry point that drives interactive console input and dispatch.
//! - `execute_command`: High-level dispatcher supporting history expansion (`!!`), pipelines, and redirections.
//! - `execute_single_command`: Direct command and `$PATH` binary resolver.
//! - `split_words`: POSIX-like lexical tokenizer handling single quotes, double quotes, and backslash escapes.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel supervisor context; spawns Ring 3 userland tasks on demand)
//! - Hardware Interaction: Console text output and keyboard polling via [`crate::console`]
//! - Concurrency: Single-threaded interactive REPL loop on the bootstrap processor (BSP)

/// Command trait definition and integer argument parsing helpers.
pub mod command;
/// Built-in shell command implementations and command registry.
pub mod commands;
/// Interactive line editor with history navigation and tab auto-completion.
pub mod editor;
/// Filesystem binary search, UEFI image loading, and Ring 3 ELF process spawning.
pub mod fs;
/// Fixed-capacity circular buffer for session command history.
pub mod history;
/// Interactive terminal text pager for multi-page command output.
pub mod pager;
/// Unidirectional pipe chaining (`|`) and file output redirection (`>`, `>>`).
pub mod pipeline;
/// Session state management including working directory, credentials, and capabilities.
pub mod state;

use core::str;
use uefi::proto::console::text::Color;

use crate::console::set_color;
pub use command::Command;
pub use state::ShellState;

/// Maximum byte capacity of the interactive input line buffer.
const LINE_BUF_LEN: usize = 1024;
/// Maximum number of whitespace-separated arguments parsed per command invocation.
const MAX_ARGS: usize = 16;

/// Prints the formatted ASCII welcome banner for the Hydra Microkernel Interactive Shell.
///
/// Renders a cyan-bordered header box to the active console output device to indicate
/// that the interactive shell initialization is ready.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn print_welcome_banner() {
    set_color(Color::LightCyan, Color::Black);
    println!("\n+--------------------------------------------------------------+");
    println!("|             HYDRA MICROKERNEL INTERACTIVE SHELL              |");
    println!("|  Type 'help' for available commands, or 'info' for details.  |");
    println!("+--------------------------------------------------------------+\n");
}

/// Parses and executes an interactive shell command line, including history expansion and pipelines.
///
/// Trims leading and trailing whitespace, expands the `!!` history substitution shortcut if
/// requested, delegates pipeline (`|`) and redirection (`>`, `>>`) chains to
/// [`pipeline::try_execute_pipeline`], and falls back to `execute_single_command` for
/// simple command invocations.
///
/// # Arguments
///
/// * `cmd_line` - Raw UTF-8 command line string entered by the user or script runner.
/// * `state` - Mutable reference to the active `ShellState` session context.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn execute_command(cmd_line: &str, state: &mut ShellState) {
    let trimmed = cmd_line.trim();
    if trimmed.is_empty() {
        return;
    }

    // Support '!!' to repeat the last command (Bash / Zsh style)
    if trimmed == "!!" {
        let mut target_cmd = None;
        for i in 0..state.history.len() {
            if let Some(cmd) = state.history.get_from_latest(i) {
                if cmd != "!!" {
                    target_cmd = Some(cmd);
                    break;
                }
            }
        }

        if let Some(prev) = target_cmd {
            set_color(Color::LightCyan, Color::Black);
            println!("{}", prev);
            let mut copy_buf = [0u8; 1024];
            let len = prev.len().min(copy_buf.len());
            copy_buf[..len].copy_from_slice(&prev.as_bytes()[..len]);
            if let Ok(prev_str) = core::str::from_utf8(&copy_buf[..len]) {
                execute_command(prev_str, state);
            }
            return;
        } else {
            set_color(Color::LightRed, Color::Black);
            println!("!!: event not found");
            state.last_status = 1;
            return;
        }
    }

    // Check for shell pipeline (|) or file output redirection (> or >>)
    if pipeline::try_execute_pipeline(trimmed, state) {
        return;
    }

    execute_single_command(trimmed, state);
}

/// Executes a single unpiped, unredirected shell command.
///
/// Tokenizes the command line via `split_words`, resolves the primary command name
/// against built-in commands in [`commands::find_command`], searches external binaries
/// via [`fs::search_and_execute`], or invokes the `sh` interpreter for `.sh` scripts.
/// Updates `state.last_status` to `127` if the command cannot be resolved.
///
/// # Arguments
///
/// * `cmd_line` - Single command string without unquoted pipe or redirection operators.
/// * `state` - Mutable reference to the active `ShellState` session context.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn execute_single_command(cmd_line: &str, state: &mut ShellState) {
    let trimmed = cmd_line.trim();
    if trimmed.is_empty() {
        return;
    }

    let words = split_words(trimmed);
    let mut args_buf = [""; MAX_ARGS];
    let mut arg_count = 0;

    for word in words.iter() {
        if arg_count < MAX_ARGS {
            args_buf[arg_count] = word.as_str();
            arg_count += 1;
        }
    }

    if arg_count == 0 {
        return;
    }

    let command_name = args_buf[0];
    let args = &args_buf[1..arg_count];

    if let Some(cmd) = commands::find_command(command_name) {
        cmd.execute(args, state);
    } else if fs::search_and_execute(command_name, args, state) {
        // Successfully found and executed external program via $PATH
        state.last_status = 0;
    } else if command_name.starts_with("./") || command_name.ends_with(".sh") {
        // Direct execution of scripts (e.g. "./demo.sh" or "demo.sh")
        if let Some(sh_cmd) = commands::find_command("sh") {
            sh_cmd.execute(&args_buf[..arg_count], state);
        }
    } else {
        set_color(Color::LightRed, Color::Black);
        println!("Unknown command: '{}'. Type 'help' for built-ins or 'path' for executable search dirs.", command_name);
        state.last_status = 127;
    }
}

/// Splits a command line into words using POSIX-compatible quoting and escaping rules.
///
/// Whitespace separates words outside of quotes. Single quotes (`'...'`) preserve all
/// enclosed characters literally. Double quotes (`"..."`) group characters while allowing
/// backslash escapes for `"`, `\`, `\$`, and `` ` ``. Unquoted backslashes escape the
/// immediately following character.
///
/// # Arguments
///
/// * `line` - Raw input command line slice to tokenize.
///
/// # Returns
///
/// A heap-allocated `Vec<String>` containing the unquoted, unescaped argument tokens.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn split_words(line: &str) -> alloc::vec::Vec<alloc::string::String> {
    const SQ: char = '\'';
    const BS: char = '\\';
    let mut words = alloc::vec::Vec::new();
    let mut cur = alloc::string::String::new();
    let mut in_word = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == SQ {
            in_word = true;
            for q in chars.by_ref() {
                if q == SQ {
                    break;
                }
                cur.push(q);
            }
        } else if c == '"' {
            in_word = true;
            while let Some(q) = chars.next() {
                if q == '"' {
                    break;
                }
                if q == BS {
                    if let Some(n) = chars.next() {
                        if !(n == '"' || n == BS || n == '$' || n == '`') {
                            cur.push(BS);
                        }
                        cur.push(n);
                    }
                } else {
                    cur.push(q);
                }
            }
        } else if c == BS {
            in_word = true;
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c.is_whitespace() {
            if in_word {
                words.push(core::mem::take(&mut cur));
                in_word = false;
            }
        } else {
            in_word = true;
            cur.push(c);
        }
    }
    if in_word {
        words.push(cur);
    }
    words
}

/// Runs an interactive 3-second countdown before automatically invoking `exitboot`.
///
/// Allows the user to press Enter to transition immediately to bare-metal hardware mode,
/// or press any other key to cancel the transition and remain under UEFI Boot Services.
///
/// # Arguments
///
/// * `state` - Mutable reference to the active `ShellState` passed to the `exitboot` command.
fn auto_exitboot_countdown(state: &mut ShellState) {
    if crate::arch::boot_services::is_hardware_takeover_complete() {
        return;
    }

    set_color(Color::LightCyan, Color::Black);
    crate::print!("[*] Transitioning to bare-metal hardware mode in 3 seconds (press any key to cancel): ");

    let mut cancelled = false;
    let mut proceed_early = false;

    for remaining in (1..=3).rev() {
        set_color(Color::Yellow, Color::Black);
        crate::print!("{}... ", remaining);

        for _ in 0..20 {
            if let Some(key) = crate::console::read_key() {
                match key {
                    uefi::proto::console::text::Key::Printable(ch)
                        if u16::from(ch) == 13 || u16::from(ch) == 10 || char::from(ch) == '\r' || char::from(ch) == '\n' =>
                    {
                        proceed_early = true;
                        break;
                    }
                    _ => {
                        cancelled = true;
                        break;
                    }
                }
            }
            crate::console::stall(core::time::Duration::from_millis(50));
        }

        if cancelled || proceed_early {
            break;
        }
    }

    if cancelled {
        set_color(Color::LightRed, Color::Black);
        crate::println!("CANCELLED");
        set_color(Color::White, Color::Black);
        crate::println!("    Operating under UEFI Boot Services. Type 'exitboot' to transition to bare metal.\n");
    } else {
        set_color(Color::LightGreen, Color::Black);
        crate::println!("NOW");
        execute_command("exitboot", state);
        crate::println!();
    }
}

/// After the bare-metal transition, waits 3 seconds for a key press and otherwise starts
/// the KDE desktop (`linux plasma`). Any key cancels and leaves the Hydra shell.
fn auto_plasma_countdown(state: &mut ShellState) {
    if !crate::arch::boot_services::is_hardware_takeover_complete() {
        return; // the user stayed under UEFI Boot Services
    }
    set_color(Color::LightCyan, Color::Black);
    crate::print!("[*] Starting KDE Plasma in 3 seconds (press any key for the Hydra shell): ");
    let mut cancelled = false;
    'countdown: for remaining in (1..=3).rev() {
        set_color(Color::Yellow, Color::Black);
        crate::print!("{}... ", remaining);
        for _ in 0..20 {
            if crate::console::read_key().is_some() {
                cancelled = true;
                break 'countdown;
            }
            crate::console::stall(core::time::Duration::from_millis(50));
        }
    }
    if cancelled {
        set_color(Color::LightRed, Color::Black);
        crate::println!("CANCELLED");
        set_color(Color::White, Color::Black);
        crate::println!("    Type 'linux plasma' to start the desktop later.
");
    } else {
        set_color(Color::LightGreen, Color::Black);
        crate::println!("NOW");
        set_color(Color::White, Color::Black);
        execute_command("linux plasma", state);
    }
}

/// Starts the main diverging interactive shell read-eval-print loop (REPL).
///
/// Initializes a fresh `ShellState`, prints the welcome banner, runs the automatic
/// bare-metal transition countdown, and repeatedly reads and executes user commands
/// until EOF (`Ctrl+D` on an empty line) triggers system shutdown.
///
/// # Returns
///
/// Never returns (`!`). Enters an infinite stall loop if system shutdown returns.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn run() -> ! {
    let mut state = ShellState::new();
    let mut line_buf = [0u8; LINE_BUF_LEN];

    print_welcome_banner();
    auto_exitboot_countdown(&mut state);
    auto_plasma_countdown(&mut state);

    loop {
        set_color(state.prompt_color, Color::Black);
        let mut prompt_buf = [0u8; 96];
        let prompt_str = state.format_prompt(&mut prompt_buf);
        let len = match editor::read_line(prompt_str, &mut line_buf, &mut state) {
            Some(l) => l,
            None => {
                set_color(Color::LightCyan, Color::Black);
                println!("logout");
                if let Some(cmd) = commands::find_command("shutdown") {
                    cmd.execute(&[], &mut state);
                }
                loop {
                    crate::console::stall(core::time::Duration::from_millis(500));
                }
            }
        };
        set_color(Color::White, Color::Black);

        if len == 0 {
            continue;
        }

        let input_str = match str::from_utf8(&line_buf[..len]) {
            Ok(s) => s.trim(),
            Err(_) => {
                set_color(Color::LightRed, Color::Black);
                println!("[!] Invalid input encoding.");
                continue;
            }
        };

        if input_str.is_empty() {
            continue;
        }

        execute_command(input_str, &mut state);
    }
}
