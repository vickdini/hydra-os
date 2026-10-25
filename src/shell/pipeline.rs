use alloc::vec::Vec;
use uefi::proto::console::text::Color;

use crate::console::set_color;
use crate::fs::client::normalize_path;
use crate::fs::{FileDescriptor, PipeBuffer};
use crate::shell::state::ShellState;

/// Executes a pipeline or redirected command line string.
///
/// Returns `true` if handled as a pipeline or redirection, or `false` if it is a simple command.
pub fn try_execute_pipeline(cmd_line: &str, state: &mut ShellState) -> bool {
    let trimmed = cmd_line.trim();

    // Check if the command line contains '|', '>', or '>>'
    let has_pipe = trimmed.contains('|');
    let has_redirect = trimmed.contains('>');

    if !has_pipe && !has_redirect {
        return false;
    }

    if has_pipe {
        execute_pipe_chain(trimmed, state);
    } else {
        execute_single_redirect(trimmed, state);
    }

    true
}

/// Executes a pipeline of commands: `cmd1 | cmd2 | ... | cmdN`.
fn execute_pipe_chain(cmd_line: &str, state: &mut ShellState) {
    let raw_stages: Vec<&str> = cmd_line.split('|').map(|s| s.trim()).collect();
    if raw_stages.is_empty() {
        return;
    }

    let num_stages = raw_stages.len();
    let mut pipe_buffers: Vec<alloc::sync::Arc<spin::Mutex<PipeBuffer>>> = Vec::new();

    for _ in 0..(num_stages - 1) {
        pipe_buffers.push(PipeBuffer::new());
    }

    // Check if the final stage has file redirection (e.g. `cmd1 | cmd2 > file.txt`)
    let last_stage_str = raw_stages[num_stages - 1];
    let (final_cmd, redirect_info) = if last_stage_str.contains('>') {
        let (cmd, path, append) = parse_redirect_target(last_stage_str);
        (cmd, Some((path, append)))
    } else {
        (last_stage_str, None)
    };

    let redirect_pipe = if redirect_info.is_some() {
        Some(PipeBuffer::new())
    } else {
        None
    };

    for i in 0..num_stages {
        // Setup input FD (stdin / fd 0)
        let old_in = if i > 0 {
            let prev_pipe = pipe_buffers[i - 1].clone();
            crate::task::with_current_fds_mut(|fds| {
                fds.set_fd(0, Some(FileDescriptor::PipeRead(prev_pipe)))
            })
        } else {
            None
        };

        // Setup output FD (stdout / fd 1)
        let old_out = if i < num_stages - 1 {
            let next_pipe = pipe_buffers[i].clone();
            crate::task::with_current_fds_mut(|fds| {
                fds.set_fd(1, Some(FileDescriptor::PipeWrite(next_pipe)))
            })
        } else if let Some(ref rpipe) = redirect_pipe {
            crate::task::with_current_fds_mut(|fds| {
                fds.set_fd(1, Some(FileDescriptor::PipeWrite(rpipe.clone())))
            })
        } else {
            None
        };

        let cmd_to_run = if i == num_stages - 1 { final_cmd } else { raw_stages[i] };
        crate::shell::execute_single_command(cmd_to_run, state);

        // Restore stdout and close writer end so reader sees EOF
        if i < num_stages - 1 {
            pipe_buffers[i].lock().drop_writer();
            if let Some(prev) = old_out {
                crate::task::with_current_fds_mut(|fds| {
                    fds.set_fd(1, Some(prev));
                });
            }
        } else if old_out.is_some() {
            crate::task::with_current_fds_mut(|fds| {
                fds.set_fd(1, old_out);
            });
        }

        // Restore stdin
        if i > 0 {
            pipe_buffers[i - 1].lock().drop_reader();
            if let Some(prev) = old_in {
                crate::task::with_current_fds_mut(|fds| {
                    fds.set_fd(0, Some(prev));
                });
            }
        }
    }

    // If final stage had file redirection, commit collected output to ZFS
    if let (Some((file_path, append)), Some(rpipe)) = (redirect_info, redirect_pipe) {
        let mut norm_buf = [0u8; 128];
        let norm_path = normalize_path(state.cwd_str(), file_path, &mut norm_buf);

        let mut collected = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = rpipe.lock().read(&mut chunk);
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&chunk[..n]);
        }

        commit_file_output(norm_path, &collected, append);
    }
}

/// Executes a single command with file output redirection (`>` or `>>`).
fn execute_single_redirect(cmd_line: &str, state: &mut ShellState) {
    let (cmd_part, file_path, append) = parse_redirect_target(cmd_line);
    if file_path.is_empty() {
        set_color(Color::LightRed, Color::Black);
        println!("syntax error: missing redirection target file");
        state.last_status = 2;
        return;
    }

    let mut norm_buf = [0u8; 128];
    let norm_path = normalize_path(state.cwd_str(), file_path, &mut norm_buf);

    let pipe = PipeBuffer::new();
    let old_stdout = crate::task::with_current_fds_mut(|fds| {
        fds.set_fd(1, Some(FileDescriptor::PipeWrite(pipe.clone())))
    });

    crate::shell::execute_single_command(cmd_part, state);

    // Restore stdout
    crate::task::with_current_fds_mut(|fds| {
        fds.set_fd(1, old_stdout);
    });

    // Collect all output written to the buffer
    let mut collected = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = pipe.lock().read(&mut chunk);
        if n == 0 {
            break;
        }
        collected.extend_from_slice(&chunk[..n]);
    }

    commit_file_output(norm_path, &collected, append);
}

/// Writes or appends collected bytes to a file in ZFS.
fn commit_file_output(path: &str, data: &[u8], append: bool) {
    if append {
        let mut existing = alloc::vec![0u8; 65536];
        let existing_len = crate::fs::ZfsClient::read_file_by_path(path, &mut existing).unwrap_or(0);
        let mut combined = Vec::with_capacity(existing_len + data.len());
        combined.extend_from_slice(&existing[..existing_len]);
        combined.extend_from_slice(data);
        if let Err(e) = crate::fs::ZfsClient::write_file_by_path(path, &combined) {
            set_color(Color::LightRed, Color::Black);
            println!("failed to append to '{}': {}", path, e);
        }
    } else {
        if let Err(e) = crate::fs::ZfsClient::write_file_by_path(path, data) {
            set_color(Color::LightRed, Color::Black);
            println!("failed to write to '{}': {}", path, e);
        }
    }
}

/// Helper to parse redirection target: returns `(cmd_part, file_path, append)`.
fn parse_redirect_target(s: &str) -> (&str, &str, bool) {
    if let Some(idx) = s.find(">>") {
        let cmd = s[..idx].trim();
        let target = s[idx + 2..].trim();
        (cmd, target, true)
    } else if let Some(idx) = s.find('>') {
        let cmd = s[..idx].trim();
        let target = s[idx + 1..].trim();
        (cmd, target, false)
    } else {
        (s.trim(), "", false)
    }
}
