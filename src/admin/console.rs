//! # Admin console operations: keys, cursor, screen
//!
//! What a ring-3 line editor needs from the kernel console beyond writing text on fd 1:
//! keys (arrows and the other special keys included), waiting for them without polling,
//! the cursor position, the scrollback viewport and scroll lock. The console itself (the
//! screen, the scrollback, the keyboard buffer) stays in the kernel.

use uefi::proto::console::text::Key;

use super::proto::*;

/// Wakeups while waiting for a key, at most this many ticks apart (the cursor blinks, and
/// an input source that does not wake the input queue is still seen).
const WAIT_TICKS: u64 = 5;

/// The event for a key read from the console.
fn event(key: Key) -> KeyEvent {
    let generation = crate::console::console_output_generation();
    match key {
        Key::Printable(ch) => KeyEvent { kind: KEY_CHAR, code: u16::from(ch) as u32, generation },
        Key::Special(sc) => KeyEvent { kind: KEY_SPECIAL, code: crate::console::probe_scancode(sc) as u32, generation },
    }
}

/// `ADMIN_CONSOLE_READ`: waits for a key, at most `timeout_ms` (`u64::MAX`: no limit), or
/// until the console output generation differs from `seen` (`u64::MAX`: not watched).
///
/// Sleeps on the console input queue (the keyboard interrupt and USB input wake it), so a
/// waiting shell costs nothing. The cursor blinks meanwhile.
pub fn read(timeout_ms: u64, seen: u64) -> KeyEvent {
    if let Some(k) = crate::console::read_key() {
        return event(k);
    }
    let now = crate::arch::pit::ticks();
    let deadline = if timeout_ms == u64::MAX { u64::MAX } else { now.saturating_add(timeout_ms.div_ceil(10)) };
    let none = |kind| KeyEvent { kind, code: 0, generation: crate::console::console_output_generation() };
    if timeout_ms == 0 {
        return none(KEY_NONE);
    }
    crate::console::show_cursor();
    let mut blink = now + 50;
    let mut waits = crate::task::wait::WaitSet::new();
    waits.add(crate::task::wait::QueueRef::Static(&crate::compat::linux::tty::INPUT_WQ));
    let result = loop {
        waits.register();
        if let Some(k) = crate::console::read_key() {
            break event(k);
        }
        if seen != u64::MAX && crate::console::console_output_generation() != seen {
            break none(KEY_REFRESH);
        }
        let t = crate::arch::pit::ticks();
        if t >= deadline {
            break none(KEY_NONE);
        }
        if t >= blink {
            blink = t + 50;
            crate::console::toggle_cursor();
        }
        waits.wait(Some((t + WAIT_TICKS).min(deadline)));
    };
    crate::console::hide_cursor();
    result
}

/// `ADMIN_CONSOLE_CTL`.
///
/// # Arguments
/// * `args` - The call's arguments (`args[0]` the `CTL_*` code).
/// * `input` - `prompt\0text` for [`CTL_VIEWPORT`].
///
/// # Returns
/// Two numbers (see the codes), or `None` for an unknown code.
pub fn ctl(args: &[u64; 4], input: &[u8]) -> Option<[u64; 2]> {
    use crate::console as c;
    let mut out = [0u64; 2];
    match args[0] {
        CTL_CURSOR_GET => {
            let (col, row) = c::cursor_position();
            out = [col as u64, row as u64];
        }
        CTL_CURSOR_SET => c::set_cursor_position(args[1] as usize, args[2] as usize),
        CTL_SIZE => {
            let (cols, rows) = c::screen_size();
            out = [cols as u64, rows as u64];
        }
        CTL_CLEAR => c::clear_screen(),
        CTL_CLEAR_SCROLLBACK => c::clear_scrollback(),
        CTL_CURSOR_ENABLE => c::set_cursor_enabled(args[1] != 0),
        CTL_CURSOR_SHAPE => c::set_cursor_shape(match args[1] {
            0 => c::CursorShape::Underline,
            1 => c::CursorShape::Block,
            _ => c::CursorShape::Bar,
        }),
        CTL_CURSOR_INFO => {
            let shape = match c::cursor_shape() {
                c::CursorShape::Underline => 0,
                c::CursorShape::Block => 1,
                c::CursorShape::Bar => 2,
            };
            out = [c::is_cursor_enabled() as u64, shape];
        }
        CTL_SCROLL_LOCK => {
            let active = match args[1] {
                0 | 1 => {
                    c::set_scroll_lock(args[1] == 1);
                    args[1] == 1
                }
                2 => c::toggle_scroll_lock(),
                _ => c::is_scroll_lock_active(),
            };
            out = [active as u64, 0];
        }
        CTL_MAX_SCROLL => out = [c::max_scroll_offset() as u64, 0],
        CTL_VIEWPORT => {
            let text = core::str::from_utf8(input).unwrap_or("");
            let (prompt, line) = text.split_once('\0').unwrap_or((text, ""));
            let color = super::COLORS.get(args[3] as usize).copied().unwrap_or(uefi::proto::console::text::Color::LightGreen);
            c::draw_scroll_viewport(args[1] as usize, prompt, line, args[2] as usize, color);
        }
        CTL_GENERATION => out = [c::console_output_generation(), 0],
        CTL_CURSOR_SHOW => {
            if args[1] != 0 {
                c::show_cursor()
            } else {
                c::hide_cursor()
            }
        }
        _ => return None,
    }
    Some(out)
}
