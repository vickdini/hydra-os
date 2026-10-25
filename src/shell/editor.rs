use uefi::proto::console::text::{Color, Key, ScanCode};

use crate::console::{get_key_or_refresh, set_color};
use crate::fs::client::{normalize_path, ZfsClient};
use crate::fs::zfs::types::DnodeType;
use crate::shell::commands::all_commands;
use crate::shell::state::ShellState;

/// Moves cursor left by `count` positions on the console.
fn move_cursor_left(count: usize) {
    if count == 0 {
        return;
    }
    let (col, row) = crate::console::cursor_position();
    if col >= count {
        crate::console::set_cursor_position(col - count, row);
    }
}

/// Moves cursor right by `count` positions on the console.
fn move_cursor_right(count: usize) {
    if count == 0 {
        return;
    }
    let (col, row) = crate::console::cursor_position();
    crate::console::set_cursor_position(col + count, row);
}

/// Redraws the line from the start of the input area (prompt_col).
fn redraw_line(old_len: usize, new_text: &str, cursor_pos_before: usize, new_cursor_pos: usize) {
    let (cur_col, cur_row) = crate::console::cursor_position();
    let prompt_col = cur_col.saturating_sub(cursor_pos_before);
    crate::console::set_cursor_position(prompt_col, cur_row);
    crate::print!("{}", new_text);
    if old_len > new_text.len() {
        for _ in 0..(old_len - new_text.len()) {
            crate::print!(" ");
        }
    }
    crate::console::set_cursor_position(prompt_col + new_cursor_pos, cur_row);
}

fn navigate_history_up(
    buf: &mut [u8],
    len: &mut usize,
    cursor_pos: &mut usize,
    history_offset: &mut Option<usize>,
    draft_buf: &mut [u8; 128],
    draft_len: &mut usize,
    state: &ShellState,
) {
    let hist_len = state.history.len();
    if hist_len > 0 {
        let next_offset = match *history_offset {
            None => {
                draft_buf[..*len].copy_from_slice(&buf[..*len]);
                *draft_len = *len;
                Some(0)
            }
            Some(off) if off + 1 < hist_len => Some(off + 1),
            Some(off) => Some(off),
        };

        if let Some(off) = next_offset {
            *history_offset = Some(off);
            if let Some(entry) = state.history.get_from_latest(off) {
                let old_len = *len;
                let entry_bytes = entry.as_bytes();
                let copy_len = entry_bytes.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&entry_bytes[..copy_len]);
                *len = copy_len;
                redraw_line(old_len, entry, *cursor_pos, *len);
                *cursor_pos = *len;
            }
        }
    }
}

fn navigate_history_down(
    buf: &mut [u8],
    len: &mut usize,
    cursor_pos: &mut usize,
    history_offset: &mut Option<usize>,
    draft_buf: &[u8; 128],
    draft_len: usize,
    state: &ShellState,
) {
    if let Some(off) = *history_offset {
        if off > 0 {
            *history_offset = Some(off - 1);
            if let Some(entry) = state.history.get_from_latest(off - 1) {
                let old_len = *len;
                let entry_bytes = entry.as_bytes();
                let copy_len = entry_bytes.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&entry_bytes[..copy_len]);
                *len = copy_len;
                redraw_line(old_len, entry, *cursor_pos, *len);
                *cursor_pos = *len;
            }
        } else {
            // Restore draft line
            *history_offset = None;
            let old_len = *len;
            buf[..draft_len].copy_from_slice(&draft_buf[..draft_len]);
            *len = draft_len;
            let text = core::str::from_utf8(&buf[..*len]).unwrap_or("");
            redraw_line(old_len, text, *cursor_pos, *len);
            *cursor_pos = *len;
        }
    }
}

/// Interactive line editor supporting:
/// - Key combinations:
///   - Ctrl+C: Cancel current line / interrupt
///   - Ctrl+D: EOF (exit shell if line empty; delete char at cursor if non-empty)
///   - Ctrl+L: Clear screen and repaint prompt and buffer
///   - Ctrl+A / Ctrl+E: Jump to start / end of line
///   - Ctrl+U: Kill text from cursor to start of line
///   - Ctrl+K: Kill text from cursor to end of line
///   - Ctrl+W: Kill previous word
///   - Ctrl+P / Ctrl+N: History previous / next command
///   - Ctrl+B / Ctrl+F: Move cursor left / right
///   - Ctrl+H: Backspace
/// - Up / Down arrow history navigation and cycling
/// - Left / Right arrow cursor movement
/// - Home / End line boundary jumps
/// - In-line Backspace and Delete editing
/// - Tab auto-completion for commands and ZFS filesystem paths (Zsh-style)
pub fn read_line(prompt: &str, buf: &mut [u8], state: &mut ShellState) -> Option<usize> {
    crate::print!("{}", prompt);
    let mut last_gen = crate::console::console_output_generation();

    let mut len = 0;
    let mut cursor_pos = 0;
    let mut history_offset: Option<usize> = None;
    let mut scroll_offset: usize = 0;
    let mut draft_buf = [0u8; 128];
    let mut draft_len = 0;

    loop {
        let key = match get_key_or_refresh(last_gen) {
            Ok(k) => k,
            Err(()) => {
                // Background task output occurred; wait briefly for continuous output bursts to settle
                crate::console::stall(core::time::Duration::from_millis(20));

                // If background output did not end with a newline, advance to the next line
                let (col, _) = crate::console::cursor_position();
                if col > 0 {
                    crate::println!();
                }

                // Automatically re-render the prompt on the fresh line
                let mut pbuf = [0u8; 96];
                let cur_prompt = state.format_prompt(&mut pbuf);
                set_color(state.prompt_color, Color::Black);
                crate::print!("{}", cur_prompt);
                set_color(Color::White, Color::Black);

                // Redraw any partial line the user had already typed
                if len > 0 {
                    if let Ok(text) = core::str::from_utf8(&buf[..len]) {
                        crate::print!("{}", text);
                        if cursor_pos < len {
                            move_cursor_left(len - cursor_pos);
                        }
                    }
                }
                last_gen = crate::console::console_output_generation();
                continue;
            }
        };
        match key {
            Key::Printable(ch) => {
                let code = u16::from(ch);
                let c = char::from(ch);

                if code == 1 {
                    // Ctrl+A: Move cursor to beginning of line (Home)
                    if cursor_pos > 0 {
                        move_cursor_left(cursor_pos);
                        cursor_pos = 0;
                    }
                } else if code == 2 {
                    // Ctrl+B: Move cursor left one character
                    if cursor_pos > 0 {
                        cursor_pos -= 1;
                        move_cursor_left(1);
                    }
                } else if code == 3 {
                    // Ctrl+C: Cancel current line, print ^C, reprint prompt
                    if scroll_offset > 0 {
                        scroll_offset = 0;
                    }
                    crate::console::set_scroll_lock(false);
                    set_color(Color::LightGray, Color::Black);
                    crate::println!("^C");
                    len = 0;
                    cursor_pos = 0;
                    history_offset = None;
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    set_color(state.prompt_color, Color::Black);
                    crate::print!("{}", cur_prompt);
                    set_color(Color::White, Color::Black);
                } else if code == 4 {
                    // Ctrl+D: EOF on empty line, or forward delete if non-empty
                    if len == 0 {
                        crate::console::hide_cursor();
                        return None;
                    } else if cursor_pos < len {
                        let old_len = len;
                        for i in (cursor_pos + 1)..len {
                            buf[i - 1] = buf[i];
                        }
                        len -= 1;
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        redraw_line(old_len, text, cursor_pos, cursor_pos);
                    }
                } else if code == 5 {
                    // Ctrl+E: Move cursor to end of line (End)
                    if cursor_pos < len {
                        move_cursor_right(len - cursor_pos);
                        cursor_pos = len;
                    }
                } else if code == 6 {
                    // Ctrl+F: Move cursor right one character
                    if cursor_pos < len {
                        cursor_pos += 1;
                        move_cursor_right(1);
                    }
                } else if code == 8 || c == '\x08' {
                    // Backspace / Ctrl+H
                    if cursor_pos > 0 {
                        let old_len = len;
                        for i in cursor_pos..len {
                            buf[i - 1] = buf[i];
                        }
                        len -= 1;
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        redraw_line(old_len, text, cursor_pos, cursor_pos - 1);
                        cursor_pos -= 1;
                    }
                } else if code == 9 || c == '\t' {
                    // Tab Auto-Completion (Zsh-style)
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    handle_tab_completion(cur_prompt, buf, &mut len, &mut cursor_pos, state);
                } else if code == 10 || code == 13 || c == '\r' || c == '\n' {
                    // Enter / Return / Ctrl+M / Ctrl+J
                    crate::console::hide_cursor();
                    if scroll_offset > 0 {
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                    }
                    crate::println!();
                    if len > 0 {
                        if let Ok(cmd_str) = core::str::from_utf8(&buf[..len]) {
                            let trimmed = cmd_str.trim();
                            if trimmed != "!!" {
                                state.history.add(trimmed);
                            }
                        }
                    }
                    return Some(len);
                } else if code == 11 {
                    // Ctrl+K: Kill from cursor to end of line
                    if cursor_pos < len {
                        let old_len = len;
                        len = cursor_pos;
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        redraw_line(old_len, text, cursor_pos, cursor_pos);
                    }
                } else if code == 12 {
                    // Ctrl+L: Clear screen and reprint prompt + current line
                    crate::console::clear_screen();
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    set_color(state.prompt_color, Color::Black);
                    crate::print!("{}", cur_prompt);
                    set_color(Color::White, Color::Black);
                    let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    crate::print!("{}", text);
                    if cursor_pos < len {
                        move_cursor_left(len - cursor_pos);
                    }
                } else if code == 14 {
                    // Ctrl+N: Next command in history (same as Down Arrow)
                    navigate_history_down(
                        buf,
                        &mut len,
                        &mut cursor_pos,
                        &mut history_offset,
                        &draft_buf,
                        draft_len,
                        state,
                    );
                } else if code == 16 {
                    // Ctrl+P: Previous command in history (same as Up Arrow)
                    navigate_history_up(
                        buf,
                        &mut len,
                        &mut cursor_pos,
                        &mut history_offset,
                        &mut draft_buf,
                        &mut draft_len,
                        state,
                    );
                } else if code == 21 {
                    // Ctrl+U: Kill from cursor to beginning of line
                    if cursor_pos > 0 {
                        let old_len = len;
                        let remaining = len - cursor_pos;
                        for i in 0..remaining {
                            buf[i] = buf[cursor_pos + i];
                        }
                        len = remaining;
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        redraw_line(old_len, text, cursor_pos, 0);
                        cursor_pos = 0;
                    }
                } else if code == 23 {
                    // Ctrl+W: Kill word backward before cursor
                    if cursor_pos > 0 {
                        let old_len = len;
                        let mut new_pos = cursor_pos;
                        while new_pos > 0 && buf[new_pos - 1] == b' ' {
                            new_pos -= 1;
                        }
                        while new_pos > 0 && buf[new_pos - 1] != b' ' {
                            new_pos -= 1;
                        }
                        let del = cursor_pos - new_pos;
                        if del > 0 {
                            for i in cursor_pos..len {
                                buf[i - del] = buf[i];
                            }
                            len -= del;
                            let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                            redraw_line(old_len, text, cursor_pos, new_pos);
                            cursor_pos = new_pos;
                        }
                    }
                } else if code == 19 {
                    // Ctrl+S: Toggle Scroll Lock mode
                    let active = crate::console::toggle_scroll_lock();
                    if !active && scroll_offset > 0 {
                        scroll_offset = 0;
                    }
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    crate::console::draw_scroll_viewport(scroll_offset, cur_prompt, text, cursor_pos, state.prompt_color);
                } else if code == 26 {
                    // Ctrl+Z: Suspend notification
                    set_color(Color::Yellow, Color::Black);
                    crate::print!("^Z");
                    set_color(Color::White, Color::Black);
                } else if code == 27 {
                    // Escape: Exit scroll mode / reset scrollback viewport
                    if scroll_offset > 0 || crate::console::is_scroll_lock_active() {
                        scroll_offset = 0;
                        crate::console::set_scroll_lock(false);
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                    }
                } else if len < buf.len() && (c as u32) >= 32 && (c as u32) <= 126 {
                    if scroll_offset > 0 {
                        scroll_offset = 0;
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                    }
                    let b = c as u8;
                    let old_len = len;

                    // Make room if inserting in the middle
                    for i in (cursor_pos..len).rev() {
                        buf[i + 1] = buf[i];
                    }
                    buf[cursor_pos] = b;
                    len += 1;
                    cursor_pos += 1;

                    if cursor_pos == len {
                        crate::print!("{}", c);
                    } else {
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        redraw_line(old_len, text, cursor_pos - 1, cursor_pos);
                    }
                }
            }
            Key::Special(ScanCode::UP) => {
                if crate::console::is_scroll_lock_active() {
                    let max = crate::console::max_scroll_offset();
                    if max > 0 && scroll_offset < max {
                        scroll_offset += 1;
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(
                            scroll_offset,
                            cur_prompt,
                            text,
                            cursor_pos,
                            state.prompt_color,
                        );
                    }
                } else {
                    if scroll_offset > 0 {
                        scroll_offset = 0;
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                    }
                    navigate_history_up(
                        buf,
                        &mut len,
                        &mut cursor_pos,
                        &mut history_offset,
                        &mut draft_buf,
                        &mut draft_len,
                        state,
                    );
                }
            }
            Key::Special(ScanCode::DOWN) => {
                if crate::console::is_scroll_lock_active() {
                    if scroll_offset > 0 {
                        scroll_offset -= 1;
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(
                            scroll_offset,
                            cur_prompt,
                            text,
                            cursor_pos,
                            state.prompt_color,
                        );
                    }
                } else {
                    if scroll_offset > 0 {
                        scroll_offset = 0;
                        let mut pbuf = [0u8; 96];
                        let cur_prompt = state.format_prompt(&mut pbuf);
                        let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                        crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                    }
                    navigate_history_down(
                        buf,
                        &mut len,
                        &mut cursor_pos,
                        &mut history_offset,
                        &draft_buf,
                        draft_len,
                        state,
                    );
                }
            }
            Key::Special(ScanCode::LEFT) => {
                if cursor_pos > 0 {
                    cursor_pos -= 1;
                    move_cursor_left(1);
                }
            }
            Key::Special(ScanCode::RIGHT) => {
                if cursor_pos < len {
                    cursor_pos += 1;
                    move_cursor_right(1);
                }
            }
            Key::Special(ScanCode::HOME) => {
                if cursor_pos > 0 {
                    move_cursor_left(cursor_pos);
                    cursor_pos = 0;
                }
            }
            Key::Special(ScanCode::END) => {
                if cursor_pos < len {
                    move_cursor_right(len - cursor_pos);
                    cursor_pos = len;
                }
            }
            Key::Special(ScanCode::DELETE) => {
                if cursor_pos < len {
                    let old_len = len;
                    for i in (cursor_pos + 1)..len {
                        buf[i - 1] = buf[i];
                    }
                    len -= 1;
                    let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    redraw_line(old_len, text, cursor_pos, cursor_pos);
                }
            }
            Key::Special(ScanCode::PAGE_UP) => {
                if !crate::console::is_scroll_lock_active() {
                    crate::console::set_scroll_lock(true);
                }
                let max = crate::console::max_scroll_offset();
                let (_cols, rows) = crate::console::screen_size();
                let step = rows.saturating_sub(2).max(1);
                scroll_offset = (scroll_offset + step).min(max);
                let mut pbuf = [0u8; 96];
                let cur_prompt = state.format_prompt(&mut pbuf);
                let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                crate::console::draw_scroll_viewport(
                    scroll_offset,
                    cur_prompt,
                    text,
                    cursor_pos,
                    state.prompt_color,
                );
            }
            Key::Special(ScanCode::PAGE_DOWN) => {
                if crate::console::is_scroll_lock_active() {
                    let (_cols, rows) = crate::console::screen_size();
                    let step = rows.saturating_sub(2).max(1);
                    scroll_offset = scroll_offset.saturating_sub(step);
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    crate::console::draw_scroll_viewport(
                        scroll_offset,
                        cur_prompt,
                        text,
                        cursor_pos,
                        state.prompt_color,
                    );
                }
            }
            Key::Special(ScanCode::FUNCTION_12) => {
                let active = crate::console::toggle_scroll_lock();
                if !active && scroll_offset > 0 {
                    scroll_offset = 0;
                }
                let mut pbuf = [0u8; 96];
                let cur_prompt = state.format_prompt(&mut pbuf);
                let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                crate::console::draw_scroll_viewport(scroll_offset, cur_prompt, text, cursor_pos, state.prompt_color);
            }
            Key::Special(ScanCode::ESCAPE) => {
                if scroll_offset > 0 || crate::console::is_scroll_lock_active() {
                    scroll_offset = 0;
                    crate::console::set_scroll_lock(false);
                    let mut pbuf = [0u8; 96];
                    let cur_prompt = state.format_prompt(&mut pbuf);
                    let text = core::str::from_utf8(&buf[..len]).unwrap_or("");
                    crate::console::draw_scroll_viewport(0, cur_prompt, text, cursor_pos, state.prompt_color);
                }
            }
            _ => {}
        }
        last_gen = crate::console::console_output_generation();
    }
}

/// Handles Zsh-style Tab completion for commands and file paths.
fn handle_tab_completion(
    prompt: &str,
    buf: &mut [u8],
    len: &mut usize,
    cursor_pos: &mut usize,
    state: &ShellState,
) {
    let input_before = match core::str::from_utf8(&buf[..*cursor_pos]) {
        Ok(s) => s,
        Err(_) => return,
    };

    let (is_command, _word_start, token) = match input_before.rfind(' ') {
        Some(idx) => (false, idx + 1, &input_before[idx + 1..]),
        None => (true, 0, input_before),
    };

    let mut match_names = [[0u8; 32]; 32];
    let mut match_lens = [0usize; 32];
    let mut is_dir_match = [false; 32];
    let mut match_count = 0;

    if is_command {
        // Complete built-in command names and aliases
        for &cmd in all_commands() {
            let name = cmd.name();
            if name.starts_with(token) && match_count < 32 {
                let nb = name.as_bytes();
                let clen = nb.len().min(32);
                match_names[match_count][..clen].copy_from_slice(&nb[..clen]);
                match_lens[match_count] = clen;
                is_dir_match[match_count] = false;
                match_count += 1;
            }
            for &alias in cmd.aliases() {
                if alias.starts_with(token) && match_count < 32 {
                    let ab = alias.as_bytes();
                    let clen = ab.len().min(32);
                    match_names[match_count][..clen].copy_from_slice(&ab[..clen]);
                    match_lens[match_count] = clen;
                    is_dir_match[match_count] = false;
                    match_count += 1;
                }
            }
        }
    } else {
        // Complete filesystem paths in current working directory or given prefix
        let (dir_path_raw, file_prefix) = match token.rfind(['/', '\\']) {
            Some(idx) => (&token[..=idx], &token[idx + 1..]),
            None => ("", token),
        };

        let mut norm_dir_buf = [0u8; 128];
        let target_dir = if dir_path_raw.is_empty() {
            state.cwd_str()
        } else {
            normalize_path(state.cwd_str(), dir_path_raw, &mut norm_dir_buf)
        };

        if let Ok((entries, entry_count, _)) = ZfsClient::list_dir(target_dir) {
            for entry in entries.iter().take(entry_count) {
                if entry.is_valid {
                    let name = entry.name_str();
                    if name.starts_with(file_prefix) && match_count < 32 {
                        let nb = name.as_bytes();
                        let clen = nb.len().min(32);
                        match_names[match_count][..clen].copy_from_slice(&nb[..clen]);
                        match_lens[match_count] = clen;
                        is_dir_match[match_count] = entry.obj_type == DnodeType::Directory;
                        match_count += 1;
                    }
                }
            }
        }
    }

    if match_count == 0 {
        return;
    }

    if match_count == 1 {
        // Unique match: auto-complete inline
        let full_match = core::str::from_utf8(&match_names[0][..match_lens[0]]).unwrap_or("");
        let is_dir = is_dir_match[0];
        let token_file_part = match token.rfind(['/', '\\']) {
            Some(idx) => &token[idx + 1..],
            None => token,
        };

        if full_match.len() >= token_file_part.len() {
            let suffix = &full_match[token_file_part.len()..];
            let old_len = *len;

            // Insert remaining suffix into buffer
            for &b in suffix.as_bytes() {
                if *len < buf.len() {
                    for i in (*cursor_pos..*len).rev() {
                        buf[i + 1] = buf[i];
                    }
                    buf[*cursor_pos] = b;
                    *len += 1;
                    *cursor_pos += 1;
                }
            }

            // Add trailing space for files/commands, or slash for directories
            let trailer = if is_dir { b'/' } else { b' ' };
            if *len < buf.len() {
                for i in (*cursor_pos..*len).rev() {
                    buf[i + 1] = buf[i];
                }
                buf[*cursor_pos] = trailer;
                *len += 1;
                *cursor_pos += 1;
            }

            let new_text = core::str::from_utf8(&buf[..*len]).unwrap_or("");
            redraw_line(old_len, new_text, *cursor_pos - suffix.len() - 1, *cursor_pos);
        }
    } else {
        // Multiple matches: show options on next line (Zsh style)
        crate::println!();
        for i in 0..match_count {
            let name = core::str::from_utf8(&match_names[i][..match_lens[i]]).unwrap_or("");
            if is_dir_match[i] {
                set_color(Color::LightCyan, Color::Black);
                crate::print!("{}/  ", name);
            } else if is_command {
                set_color(Color::LightGreen, Color::Black);
                crate::print!("{}  ", name);
            } else {
                set_color(Color::White, Color::Black);
                crate::print!("{}  ", name);
            }
        }
        crate::println!();

        // Reprint prompt and line
        set_color(state.prompt_color, Color::Black);
        crate::print!("{}", prompt);
        set_color(Color::White, Color::Black);
        let current_text = core::str::from_utf8(&buf[..*len]).unwrap_or("");
        crate::print!("{}", current_text);

        // Adjust cursor back to cursor_pos if not at end
        if *cursor_pos < *len {
            move_cursor_left(*len - *cursor_pos);
        }
    }
}
