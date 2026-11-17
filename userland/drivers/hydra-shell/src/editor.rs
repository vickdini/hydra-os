//! The line editor: the kernel shell's, in ring 3. History, cursor keys, Readline's
//! control keys, Tab completion and the scrollback viewport, on the admin interface's
//! console operations (keys, cursor position, viewport).

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::Shell;
use hydra_rt::print;

/// Longest line.
const LINE_MAX: usize = 1024;

/// Moves the cursor `count` columns left on its row.
fn left(count: usize) {
    if count == 0 {
        return;
    }
    let [col, row] = ctl(CTL_CURSOR_GET, 0, 0, 0, &[]);
    if col as usize >= count {
        ctl(CTL_CURSOR_SET, col - count as u64, row, 0, &[]);
    }
}

/// Moves the cursor `count` columns right on its row.
fn right(count: usize) {
    if count == 0 {
        return;
    }
    let [col, row] = ctl(CTL_CURSOR_GET, 0, 0, 0, &[]);
    ctl(CTL_CURSOR_SET, col + count as u64, row, 0, &[]);
}

/// Redraws the line in place from the prompt's end: `old_len` was its length, the cursor
/// was at `before`; it goes to `after`.
fn redraw(old_len: usize, text: &[u8], before: usize, after: usize) {
    let [col, row] = ctl(CTL_CURSOR_GET, 0, 0, 0, &[]);
    let start = col.saturating_sub(before as u64);
    ctl(CTL_CURSOR_SET, start, row, 0, &[]);
    write_out(text);
    if old_len > text.len() {
        write_out(&alloc::vec![b' '; old_len - text.len()]);
    }
    ctl(CTL_CURSOR_SET, start + after as u64, row, 0, &[]);
}

/// Draws the scrollback viewport `offset` lines up, with the input line at the bottom.
fn viewport(sh: &Shell, offset: usize, line: &[u8], cursor: usize) {
    let mut input = sh.prompt().into_bytes();
    input.push(0);
    input.extend_from_slice(line);
    ctl(CTL_VIEWPORT, offset as u64, cursor as u64, sh.prompt_color(), &input);
}

/// Prints the prompt in its colour.
pub fn print_prompt(sh: &Shell) {
    color(sh.prompt_color());
    print!("{}", sh.prompt());
    color(WHITE);
}

/// Replaces the line with `entry` (history).
fn replace(line: &mut Vec<u8>, cursor: &mut usize, entry: &[u8]) {
    let old_len = line.len();
    line.clear();
    line.extend_from_slice(&entry[..entry.len().min(LINE_MAX)]);
    redraw(old_len, line, *cursor, line.len());
    *cursor = line.len();
}

/// Reads a command line with editing. Keys: Ctrl+C cancels, Ctrl+D ends the session on an
/// empty line (else deletes forward), Ctrl+L clears the screen, Ctrl+A/Home, Ctrl+E/End,
/// Ctrl+B/Left, Ctrl+F/Right, Ctrl+U, Ctrl+K, Ctrl+W, Ctrl+P/Up and Ctrl+N/Down (history),
/// Tab (completion), Ctrl+S/F12 (scroll lock), PgUp/PgDn/Esc (the scrollback).
///
/// # Returns
/// The line, or `None` at Ctrl+D on an empty line.
pub fn read_line(sh: &mut Shell) -> Option<String> {
    print_prompt(sh);
    let mut line: Vec<u8> = Vec::new();
    let mut cursor = 0usize;
    let mut hist: Option<usize> = None;
    let mut draft: Vec<u8> = Vec::new();
    let mut scroll = 0usize;
    let mut generation = ctl(CTL_GENERATION, 0, 0, 0, &[])[0];
    loop {
        let k = read_key(u64::MAX, generation);
        match k.kind {
            KEY_REFRESH => {
                // Other output (a background task): let a burst settle, then the prompt and
                // the line again on a fresh line
                hydra_rt::sys::sleep_ms(20);
                if ctl(CTL_CURSOR_GET, 0, 0, 0, &[])[0] > 0 {
                    print!("\n");
                }
                print_prompt(sh);
                write_out(&line);
                left(line.len() - cursor);
                generation = ctl(CTL_GENERATION, 0, 0, 0, &[])[0];
                continue;
            }
            KEY_CHAR => match k.code {
                1 => {
                    left(cursor);
                    cursor = 0;
                }
                2 if cursor > 0 => {
                    cursor -= 1;
                    left(1);
                }
                3 => {
                    scroll = 0;
                    ctl(CTL_SCROLL_LOCK, 0, 0, 0, &[]);
                    color(LIGHT_GRAY);
                    print!("^C\n");
                    line.clear();
                    cursor = 0;
                    hist = None;
                    print_prompt(sh);
                }
                4 if line.is_empty() => return None,
                4 if cursor < line.len() => {
                    let old = line.len();
                    line.remove(cursor);
                    redraw(old, &line, cursor, cursor);
                }
                5 => {
                    right(line.len() - cursor);
                    cursor = line.len();
                }
                6 if cursor < line.len() => {
                    cursor += 1;
                    right(1);
                }
                8 | 0x7f if cursor > 0 => {
                    let old = line.len();
                    line.remove(cursor - 1);
                    redraw(old, &line, cursor, cursor - 1);
                    cursor -= 1;
                }
                9 => complete(sh, &mut line, &mut cursor),
                10 | 13 => {
                    if scroll > 0 {
                        viewport(sh, 0, &line, cursor);
                    }
                    print!("\n");
                    let text = String::from_utf8(line).unwrap_or_default();
                    let trimmed = text.trim();
                    if !trimmed.is_empty() && trimmed != "!!" {
                        sh.remember(trimmed);
                    }
                    return Some(text);
                }
                11 if cursor < line.len() => {
                    let old = line.len();
                    line.truncate(cursor);
                    redraw(old, &line, cursor, cursor);
                }
                12 => {
                    ctl(CTL_CLEAR, 0, 0, 0, &[]);
                    print_prompt(sh);
                    write_out(&line);
                    left(line.len() - cursor);
                }
                14 | 16 => history_step(sh, k.code == 16, &mut line, &mut cursor, &mut hist, &mut draft),
                19 => {
                    let active = ctl(CTL_SCROLL_LOCK, 2, 0, 0, &[])[0] != 0;
                    if !active {
                        scroll = 0;
                    }
                    viewport(sh, scroll, &line, cursor);
                }
                21 if cursor > 0 => {
                    let old = line.len();
                    line.drain(..cursor);
                    redraw(old, &line, cursor, 0);
                    cursor = 0;
                }
                23 if cursor > 0 => {
                    let mut start = cursor;
                    while start > 0 && line[start - 1] == b' ' {
                        start -= 1;
                    }
                    while start > 0 && line[start - 1] != b' ' {
                        start -= 1;
                    }
                    let old = line.len();
                    line.drain(start..cursor);
                    redraw(old, &line, cursor, start);
                    cursor = start;
                }
                26 => {
                    color(YELLOW);
                    print!("^Z");
                    color(WHITE);
                }
                27 => {
                    if scroll > 0 || ctl(CTL_SCROLL_LOCK, 3, 0, 0, &[])[0] != 0 {
                        scroll = 0;
                        ctl(CTL_SCROLL_LOCK, 0, 0, 0, &[]);
                        viewport(sh, 0, &line, cursor);
                    }
                }
                c if (32..127).contains(&c) && line.len() < LINE_MAX => {
                    if scroll > 0 {
                        scroll = 0;
                        viewport(sh, 0, &line, cursor);
                    }
                    let old = line.len();
                    line.insert(cursor, c as u8);
                    cursor += 1;
                    if cursor == line.len() {
                        write_out(&[c as u8]);
                    } else {
                        redraw(old, &line, cursor - 1, cursor);
                    }
                }
                _ => {}
            },
            KEY_SPECIAL => {
                let locked = || ctl(CTL_SCROLL_LOCK, 3, 0, 0, &[])[0] != 0;
                let rows = || ctl(CTL_SIZE, 0, 0, 0, &[])[1] as usize;
                match k.code {
                    SC_UP | SC_DOWN if locked() => {
                        let max = ctl(CTL_MAX_SCROLL, 0, 0, 0, &[])[0] as usize;
                        if k.code == SC_UP && scroll < max {
                            scroll += 1;
                        } else if k.code == SC_DOWN && scroll > 0 {
                            scroll -= 1;
                        }
                        viewport(sh, scroll, &line, cursor);
                    }
                    SC_UP | SC_DOWN => {
                        if scroll > 0 {
                            scroll = 0;
                            viewport(sh, 0, &line, cursor);
                        }
                        history_step(sh, k.code == SC_UP, &mut line, &mut cursor, &mut hist, &mut draft);
                    }
                    SC_LEFT if cursor > 0 => {
                        cursor -= 1;
                        left(1);
                    }
                    SC_RIGHT if cursor < line.len() => {
                        cursor += 1;
                        right(1);
                    }
                    SC_HOME => {
                        left(cursor);
                        cursor = 0;
                    }
                    SC_END => {
                        right(line.len() - cursor);
                        cursor = line.len();
                    }
                    SC_DELETE if cursor < line.len() => {
                        let old = line.len();
                        line.remove(cursor);
                        redraw(old, &line, cursor, cursor);
                    }
                    SC_PAGE_UP => {
                        ctl(CTL_SCROLL_LOCK, 1, 0, 0, &[]);
                        let max = ctl(CTL_MAX_SCROLL, 0, 0, 0, &[])[0] as usize;
                        scroll = (scroll + rows().saturating_sub(2).max(1)).min(max);
                        viewport(sh, scroll, &line, cursor);
                    }
                    SC_PAGE_DOWN if locked() => {
                        scroll = scroll.saturating_sub(rows().saturating_sub(2).max(1));
                        viewport(sh, scroll, &line, cursor);
                    }
                    SC_F12 => {
                        if ctl(CTL_SCROLL_LOCK, 2, 0, 0, &[])[0] == 0 {
                            scroll = 0;
                        }
                        viewport(sh, scroll, &line, cursor);
                    }
                    SC_ESCAPE => {
                        if scroll > 0 || locked() {
                            scroll = 0;
                            ctl(CTL_SCROLL_LOCK, 0, 0, 0, &[]);
                            viewport(sh, 0, &line, cursor);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        generation = ctl(CTL_GENERATION, 0, 0, 0, &[])[0];
    }
}

/// One step through the history: older (`up`) or newer, back to the draft at the end.
fn history_step(sh: &Shell, up: bool, line: &mut Vec<u8>, cursor: &mut usize, hist: &mut Option<usize>, draft: &mut Vec<u8>) {
    let n = sh.history.len();
    if up {
        if n == 0 {
            return;
        }
        let off = match *hist {
            None => {
                *draft = line.clone();
                0
            }
            Some(o) => (o + 1).min(n - 1),
        };
        *hist = Some(off);
        let entry = String::from(sh.history.get_from_latest(off).unwrap_or(""));
        replace(line, cursor, entry.as_bytes());
    } else if let Some(off) = *hist {
        if off > 0 {
            *hist = Some(off - 1);
            let entry = String::from(sh.history.get_from_latest(off - 1).unwrap_or(""));
            replace(line, cursor, entry.as_bytes());
        } else {
            *hist = None;
            let d = draft.clone();
            replace(line, cursor, &d);
        }
    }
}

/// Tab: completes a command name (first word) or a pool path; several matches are listed.
fn complete(sh: &Shell, line: &mut Vec<u8>, cursor: &mut usize) {
    let before = String::from_utf8_lossy(&line[..*cursor]).into_owned();
    let (is_command, token) = match before.rfind(' ') {
        Some(i) => (false, &before[i + 1..]),
        None => (true, before.as_str()),
    };
    let mut matches: Vec<(String, bool)> = Vec::new();
    let prefix;
    if is_command {
        prefix = token;
        for c in crate::COMMANDS {
            for name in core::iter::once(&c.name).chain(c.aliases.iter()) {
                if name.starts_with(token) && matches.len() < 32 {
                    matches.push((String::from(*name), false));
                }
            }
        }
    } else {
        let (dir, file) = match token.rfind('/') {
            Some(i) => (&token[..=i], &token[i + 1..]),
            None => ("", token),
        };
        prefix = file;
        let target = if dir.is_empty() { sh.cwd.clone() } else { crate::normalize_path(&sh.cwd, dir) };
        if let Ok(a) = admin(ADMIN_DIR_LIST, [0; 4], target.as_bytes()) {
            let header: DirHeader = read_record(&a, 0).unwrap_or_default();
            for e in records::<DirRecord>(&a, core::mem::size_of::<DirHeader>(), header.count as usize) {
                let name = name_str(&e.name);
                if e.kind != KIND_INVALID && name.starts_with(file) && matches.len() < 32 {
                    matches.push((String::from(name), e.kind == KIND_DIR));
                }
            }
        }
    }
    match matches.len() {
        0 => {}
        1 => {
            let (name, dir) = &matches[0];
            let mut add: Vec<u8> = name.as_bytes()[prefix.len().min(name.len())..].to_vec();
            add.push(if *dir { b'/' } else { b' ' });
            let old = line.len();
            let at = *cursor;
            for (i, b) in add.iter().enumerate() {
                if line.len() < LINE_MAX {
                    line.insert(at + i, *b);
                }
            }
            *cursor = (at + add.len()).min(line.len());
            redraw(old, line, at, *cursor);
        }
        _ => {
            print!("\n");
            for (name, dir) in &matches {
                if *dir {
                    color(LIGHT_CYAN);
                    print!("{}/  ", name);
                } else {
                    color(if is_command { LIGHT_GREEN } else { WHITE });
                    print!("{}  ", name);
                }
            }
            print!("\n");
            print_prompt(sh);
            write_out(line);
            left(line.len() - *cursor);
        }
    }
}

/// Reads a line for a question (login name, password): echo unless `secret`, Backspace,
/// Ctrl+C clears.
pub fn read_input(prompt: &str, secret: bool) -> String {
    print!("{}", prompt);
    let mut line = String::new();
    loop {
        let k = read_key(u64::MAX, u64::MAX);
        if k.kind != KEY_CHAR {
            continue;
        }
        match k.code {
            13 | 10 => {
                print!("\n");
                return line;
            }
            3 => {
                print!("^C\n{}", prompt);
                line.clear();
            }
            8 | 127 => {
                if line.pop().is_some() && !secret {
                    print!("\x08 \x08");
                }
            }
            c if c >= 32 && line.len() < 128 => {
                if let Some(ch) = char::from_u32(c) {
                    line.push(ch);
                    if !secret {
                        print!("{}", ch);
                    }
                }
            }
            _ => {}
        }
    }
}
