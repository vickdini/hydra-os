//! # Shell Command: Shell Script Execution (`sh`, `source`)
//!
//! Provides the `sh` command executing shell script files line-by-line from the filesystem.

use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::{normalize_path, ZfsClient};
use crate::shell::command::Command;
use crate::shell::execute_command;
use crate::shell::state::ShellState;

/// Executes a shell script file (.sh) line-by-line.
pub struct ShCommand;

impl Command for ShCommand {
    fn name(&self) -> &'static str {
        "sh"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["source", "."]
    }

    fn description(&self) -> &'static str {
        "Execute shell script file line-by-line (supports # comments and ; chaining)"
    }

    fn usage(&self) -> &'static str {
        "sh <script.sh> [args...]"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        if args.is_empty() {
            set_color(Color::LightRed, Color::Black);
            println!("Usage: {}", self.usage());
            return;
        }

        let script_file = args[0];
        let script_args = &args[1..];

        let mut norm_buf = [0u8; 128];
        let path = normalize_path(state.cwd_str(), script_file, &mut norm_buf);

        let mut file_buf = [0u8; 4096];
        let bytes_read = match ZfsClient::read_file_by_path(path, &mut file_buf) {
            Ok(n) => n,
            Err(e) => {
                set_color(Color::LightRed, Color::Black);
                println!("sh: cannot open script '{}': {}", script_file, e);
                state.last_status = 1;
                return;
            }
        };

        let script_text = match core::str::from_utf8(&file_buf[..bytes_read]) {
            Ok(s) => s,
            Err(_) => {
                set_color(Color::LightRed, Color::Black);
                println!("sh: script '{}' contains invalid UTF-8 encoding", script_file);
                state.last_status = 1;
                return;
            }
        };

        for (_line_num, raw_line) in script_text.lines().enumerate() {
            let mut line = raw_line.trim();

            // Skip empty lines and comment lines (including shebang #!/bin/sh)
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Strip inline comment if preceded by space
            if let Some(comment_pos) = line.find(" #") {
                line = line[..comment_pos].trim();
            }

            if line.is_empty() {
                continue;
            }

            // Support command chaining with ';'
            for sub_cmd in line.split(';') {
                if crate::console::check_interrupt() {
                    println!("^C");
                    state.last_status = 130;
                    return;
                }

                let trimmed_cmd = sub_cmd.trim();
                if trimmed_cmd.is_empty() {
                    continue;
                }

                // Variable substitution for $1, $2, $?, $0 into expanded buffer
                let mut expanded_buf = [0u8; 256];
                let expanded_cmd = substitute_variables(
                    trimmed_cmd,
                    script_file,
                    script_args,
                    state.last_status,
                    &mut expanded_buf,
                );

                execute_command(expanded_cmd, state);
            }
        }

        state.last_status = 0;
    }
}

/// Replaces basic Bash script variables: $0, $1, $2, $?, $@
fn substitute_variables<'a>(
    cmd: &'a str,
    script_name: &str,
    args: &[&str],
    last_status: i32,
    out: &'a mut [u8; 256],
) -> &'a str {
    let mut out_len = 0;
    let bytes = cmd.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            match next {
                b'0' => {
                    let name_b = script_name.as_bytes();
                    let len = name_b.len().min(out.len().saturating_sub(out_len));
                    out[out_len..out_len + len].copy_from_slice(&name_b[..len]);
                    out_len += len;
                    i += 2;
                    continue;
                }
                b'1'..=b'9' => {
                    let arg_idx = (next - b'1') as usize;
                    if arg_idx < args.len() {
                        let arg_b = args[arg_idx].as_bytes();
                        let len = arg_b.len().min(out.len().saturating_sub(out_len));
                        out[out_len..out_len + len].copy_from_slice(&arg_b[..len]);
                        out_len += len;
                    }
                    i += 2;
                    continue;
                }
                b'?' => {
                    // Convert last_status to ASCII digit
                    let status_char = if last_status == 0 { b'0' } else { b'1' };
                    if out_len < out.len() {
                        out[out_len] = status_char;
                        out_len += 1;
                    }
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }

        if out_len < out.len() {
            out[out_len] = bytes[i];
            out_len += 1;
        }
        i += 1;
    }

    core::str::from_utf8(&out[..out_len]).unwrap_or(cmd)
}
