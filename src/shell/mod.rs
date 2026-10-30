pub mod command;
pub mod commands;
pub mod editor;
pub mod fs;
pub mod history;
pub mod pager;
pub mod pipeline;
pub mod state;

use core::str;
use uefi::proto::console::text::Color;

use crate::console::set_color;
pub use command::Command;
pub use state::ShellState;

const LINE_BUF_LEN: usize = 1024;
const MAX_ARGS: usize = 16;

pub fn print_welcome_banner() {
    set_color(Color::LightCyan, Color::Black);
    println!("\n+--------------------------------------------------------------+");
    println!("|             HYDRA MICROKERNEL INTERACTIVE SHELL              |");
    println!("|  Type 'help' for available commands, or 'info' for details.  |");
    println!("+--------------------------------------------------------------+\n");
}

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

/// Splits a command line into words like a POSIX shell: whitespace separates words,
/// single quotes keep text literally, double quotes group text, and a backslash escapes
/// the next character (outside single quotes).
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

pub fn run() -> ! {
    let mut state = ShellState::new();
    let mut line_buf = [0u8; LINE_BUF_LEN];

    print_welcome_banner();
    auto_exitboot_countdown(&mut state);

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
