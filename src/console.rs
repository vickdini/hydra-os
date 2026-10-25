use core::fmt::{self, Write};
use core::time::Duration;
use spin::Mutex;
use uefi::proto::console::text::{Color, Key, ScanCode};

const SCROLLBACK_MAX_LINES: usize = 512;
const SCROLLBACK_LINE_LEN: usize = 128;

pub fn color_to_u8(c: Color) -> u8 {
    match c {
        Color::Black => 0,
        Color::Blue => 1,
        Color::Green => 2,
        Color::Cyan => 3,
        Color::Red => 4,
        Color::Magenta => 5,
        Color::Brown => 6,
        Color::LightGray => 7,
        Color::DarkGray => 8,
        Color::LightBlue => 9,
        Color::LightGreen => 10,
        Color::LightCyan => 11,
        Color::LightRed => 12,
        Color::LightMagenta => 13,
        Color::Yellow => 14,
        Color::White => 15,
    }
}

pub fn u8_to_color(val: u8) -> Color {
    match val & 0x0F {
        0 => Color::Black,
        1 => Color::Blue,
        2 => Color::Green,
        3 => Color::Cyan,
        4 => Color::Red,
        5 => Color::Magenta,
        6 => Color::Brown,
        7 => Color::LightGray,
        8 => Color::DarkGray,
        9 => Color::LightBlue,
        10 => Color::LightGreen,
        11 => Color::LightCyan,
        12 => Color::LightRed,
        13 => Color::LightMagenta,
        14 => Color::Yellow,
        _ => Color::White,
    }
}

pub fn u8_to_bg_color(val: u8) -> Color {
    match (val >> 4) & 0x07 {
        0 => Color::Black,
        1 => Color::Blue,
        2 => Color::Green,
        3 => Color::Cyan,
        4 => Color::Red,
        5 => Color::Magenta,
        6 => Color::Brown,
        _ => Color::LightGray,
    }
}

pub struct ScrollbackBuffer {
    lines: [[u8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
    attrs: [[u8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
    lens: [usize; SCROLLBACK_MAX_LINES],
    cur_line: [u8; SCROLLBACK_LINE_LEN],
    cur_attrs: [u8; SCROLLBACK_LINE_LEN],
    head: usize,
    count: usize,
    cur_len: usize,
}

impl ScrollbackBuffer {
    pub const fn new() -> Self {
        Self {
            lines: [[0u8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
            attrs: [[0x0Fu8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
            lens: [0; SCROLLBACK_MAX_LINES],
            cur_line: [0u8; SCROLLBACK_LINE_LEN],
            cur_attrs: [0x0Fu8; SCROLLBACK_LINE_LEN],
            head: 0,
            count: 0,
            cur_len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
        self.cur_len = 0;
        self.lens = [0; SCROLLBACK_MAX_LINES];
    }

    pub fn push_str(&mut self, s: &str, attr: u8) {
        for b in s.bytes() {
            if b == b'\n' {
                self.commit_cur_line();
            } else if b == b'\r' {
                // Ignore carriage return
            } else {
                if self.cur_len == SCROLLBACK_LINE_LEN {
                    self.commit_cur_line();
                }
                let c = self.cur_len;
                self.cur_line[c] = b;
                self.cur_attrs[c] = attr;
                self.cur_len += 1;
            }
        }
    }

    fn commit_cur_line(&mut self) {
        let h = self.head;
        let len = self.cur_len;
        self.lines[h][..len].copy_from_slice(&self.cur_line[..len]);
        self.attrs[h][..len].copy_from_slice(&self.cur_attrs[..len]);
        self.lens[h] = len;
        self.head = (self.head + 1) % SCROLLBACK_MAX_LINES;
        if self.count < SCROLLBACK_MAX_LINES {
            self.count += 1;
        }
        self.cur_len = 0;
    }

    pub fn total_lines(&self) -> usize {
        self.count + if self.cur_len > 0 { 1 } else { 0 }
    }

    pub fn get_line_with_attrs(
        &self,
        idx: usize,
        line_buf: &mut [u8; SCROLLBACK_LINE_LEN],
        attr_buf: &mut [u8; SCROLLBACK_LINE_LEN],
    ) -> Option<usize> {
        let total = self.total_lines();
        if idx >= total {
            return None;
        }

        if idx == self.count && self.cur_len > 0 {
            let len = self.cur_len;
            line_buf[..len].copy_from_slice(&self.cur_line[..len]);
            attr_buf[..len].copy_from_slice(&self.cur_attrs[..len]);
            return Some(len);
        }

        let ring_idx = if self.count < SCROLLBACK_MAX_LINES {
            idx
        } else {
            (self.head + idx) % SCROLLBACK_MAX_LINES
        };

        let len = self.lens[ring_idx];
        line_buf[..len].copy_from_slice(&self.lines[ring_idx][..len]);
        attr_buf[..len].copy_from_slice(&self.attrs[ring_idx][..len]);
        Some(len)
    }
}

pub static CONSOLE: Mutex<Console> = Mutex::new(Console::new());

pub struct Console {
    pub scrollback: ScrollbackBuffer,
    pub current_attr: u8,
}

impl Console {
    pub const fn new() -> Self {
        Self {
            scrollback: ScrollbackBuffer::new(),
            current_attr: 0x0F, // White on Black
        }
    }
}

pub fn color_to_rgb(c: Color) -> (u8, u8, u8) {
    match c {
        Color::Black => (0, 0, 0),
        Color::Blue => (0, 0, 170),
        Color::Green => (0, 170, 0),
        Color::Cyan => (0, 170, 170),
        Color::Red => (170, 0, 0),
        Color::Magenta => (170, 0, 170),
        Color::Brown => (170, 85, 0),
        Color::LightGray => (170, 170, 170),
        Color::DarkGray => (85, 85, 85),
        Color::LightBlue => (85, 85, 255),
        Color::LightGreen => (85, 255, 85),
        Color::LightCyan => (85, 255, 255),
        Color::LightRed => (255, 85, 85),
        Color::LightMagenta => (255, 85, 255),
        Color::Yellow => (255, 255, 85),
        Color::White => (255, 255, 255),
    }
}

static USE_STANDALONE_VIDEO: Mutex<bool> = Mutex::new(false);

pub fn enable_standalone_video(enabled: bool) {
    *USE_STANDALONE_VIDEO.lock() = enabled;
}

pub fn is_standalone_video() -> bool {
    *USE_STANDALONE_VIDEO.lock()
}

static CONSOLE_OUTPUT_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn console_output_generation() -> u64 {
    CONSOLE_OUTPUT_GENERATION.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn inc_console_output_generation() {
    CONSOLE_OUTPUT_GENERATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let attr = self.current_attr;
        self.scrollback.push_str(s, attr);
        if is_standalone_video() {
            crate::video::console::write_str(s);
        } else {
            uefi::system::with_stdout(|stdout| {
                let _ = stdout.write_str(s);
            });
        }
        inc_console_output_generation();
        Ok(())
    }
}

pub fn set_color(foreground: Color, background: Color) {
    {
        let mut console = CONSOLE.lock();
        console.current_attr = color_to_u8(foreground) | (color_to_u8(background) << 4);
    }
    if is_standalone_video() {
        crate::video::console::set_colors(color_to_rgb(foreground), color_to_rgb(background));
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.set_color(foreground, background);
        });
    }
}

pub fn clear_screen() {
    if is_standalone_video() {
        crate::video::console::clear_screen();
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.clear();
        });
    }
}

/// Clears the terminal scrollback history buffer.
pub fn clear_scrollback() {
    let mut console = CONSOLE.lock();
    console.scrollback.clear();
}


pub fn probe_scancode(s: ScanCode) -> u16 {
    s.0
}

pub fn screen_size() -> (usize, usize) {
    if is_standalone_video() {
        crate::video::console::dimensions()
    } else {
        uefi::system::with_stdout(|stdout| {
            if let Ok(Some(mode)) = stdout.current_mode() {
                (mode.columns(), mode.rows())
            } else {
                (80, 25)
            }
        })
    }
}

pub fn cursor_position() -> (usize, usize) {
    if is_standalone_video() {
        crate::video::console::cursor_position()
    } else {
        uefi::system::with_stdout(|stdout| stdout.cursor_position())
    }
}

pub fn set_cursor_position(col: usize, row: usize) {
    if is_standalone_video() {
        crate::video::console::set_cursor_position(col, row);
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.set_cursor_position(col, row);
        });
    }
}

pub use crate::video::console::CursorShape;

/// Displays the cursor at the current screen coordinate.
pub fn show_cursor() {
    if is_standalone_video() {
        crate::video::console::show_cursor();
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.enable_cursor(true);
        });
    }
}

/// Hides the cursor from the screen.
pub fn hide_cursor() {
    if is_standalone_video() {
        crate::video::console::hide_cursor();
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.enable_cursor(false);
        });
    }
}

/// Toggles the cursor state for blinking.
pub fn toggle_cursor() {
    if is_standalone_video() {
        crate::video::console::toggle_cursor();
    }
}

/// Enables or disables the visual cursor.
pub fn set_cursor_enabled(enabled: bool) {
    if is_standalone_video() {
        crate::video::console::set_cursor_enabled(enabled);
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.enable_cursor(enabled);
        });
    }
}

/// Returns whether the visual cursor is enabled.
pub fn is_cursor_enabled() -> bool {
    if is_standalone_video() {
        crate::video::console::is_cursor_enabled()
    } else {
        true
    }
}

/// Sets the visual cursor rendering shape.
pub fn set_cursor_shape(shape: CursorShape) {
    if is_standalone_video() {
        crate::video::console::set_cursor_shape(shape);
    }
}

/// Returns the current cursor rendering shape.
pub fn cursor_shape() -> CursorShape {
    if is_standalone_video() {
        crate::video::console::cursor_shape()
    } else {
        CursorShape::Underline
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Directly writes raw text to the physical console screen / framebuffer without FD indirection.
pub fn print_raw(s: &str) {
    let mut console = CONSOLE.lock();
    let _ = console.write_str(s);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    struct Fd1Writer;
    impl fmt::Write for Fd1Writer {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            crate::task::with_current_fds_mut(|fds| {
                if let Some(desc) = fds.get_mut(1) {
                    let _ = desc.write(s.as_bytes());
                } else {
                    print_raw(s);
                }
            });
            Ok(())
        }
    }
    let mut writer = Fd1Writer;
    let _ = writer.write_fmt(args);
}

static HARDWARE_MODE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn set_hardware_mode(enabled: bool) {
    HARDWARE_MODE.store(enabled, core::sync::atomic::Ordering::SeqCst);
}

pub fn is_hardware_mode() -> bool {
    HARDWARE_MODE.load(core::sync::atomic::Ordering::SeqCst)
}

/// Polls for a key without blocking (from PS/2 keyboard in hardware mode, or UEFI stdin).
pub fn read_key() -> Option<Key> {
    if is_hardware_mode() {
        crate::arch::keyboard::read_key()
    } else {
        uefi::system::with_stdin(|stdin| {
            stdin.read_key().unwrap_or(None)
        })
    }
}

/// Checks non-blockingly whether Ctrl+C (ASCII 3) or Ctrl+\ (ASCII 28) was pressed to interrupt execution.
pub fn check_interrupt() -> bool {
    if let Some(key) = read_key() {
        match key {
            Key::Printable(ch) if u16::from(ch) == 3 || u16::from(ch) == 28 => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Delays execution for the specified duration.
/// In UEFI mode, calls `uefi::boot::stall`.
/// In standalone hardware mode, uses PIT hardware timer ticks (if interrupts active) or RDTSC spin loop.
pub fn stall(duration: Duration) {
    if is_hardware_mode() {
        if crate::arch::pit::is_active() && x86_64::instructions::interrupts::are_enabled() {
            crate::arch::pit::sleep_ms(duration.as_millis() as u64);
        } else {
            let nanos = duration.as_nanos();
            let cycles = (nanos as u64).saturating_mul(2);
            let start = unsafe { core::arch::x86_64::_rdtsc() };
            while unsafe { core::arch::x86_64::_rdtsc() }.wrapping_sub(start) < cycles {
                core::hint::spin_loop();
            }
        }
    } else {
        uefi::boot::stall(duration);
    }
}

/// Waits until a key is pressed (from PS/2 keyboard in hardware mode, or UEFI stdin).
pub fn get_key() -> Key {
    show_cursor();
    let mut blink_counter = 0u32;
    loop {
        if let Some(key) = read_key() {
            hide_cursor();
            return key;
        }
        stall(Duration::from_millis(10));
        blink_counter += 1;
        if blink_counter >= 50 {
            blink_counter = 0;
            toggle_cursor();
        }
    }
}

/// Waits for a key press, or returns Err(()) if new console output was generated while waiting.
pub fn get_key_or_refresh(last_gen: u64) -> Result<Key, ()> {
    show_cursor();
    let mut blink_counter = 0u32;
    loop {
        if let Some(key) = read_key() {
            hide_cursor();
            return Ok(key);
        }
        if console_output_generation() != last_gen {
            hide_cursor();
            return Err(());
        }
        stall(Duration::from_millis(10));
        blink_counter += 1;
        if blink_counter >= 50 {
            blink_counter = 0;
            toggle_cursor();
        }
    }
}

/// Erases the character preceding the cursor on the screen.
pub fn backspace() {
    if is_standalone_video() {
        crate::video::console::write_str("\x08");
    } else {
        uefi::system::with_stdout(|stdout| {
            let (col, row) = stdout.cursor_position();
            if col > 0 {
                let _ = stdout.set_cursor_position(col - 1, row);
                let _ = stdout.write_str(" ");
                let _ = stdout.set_cursor_position(col - 1, row);
            }
        });
    }
}

/// Reads a line of ASCII text interactively from the console into `buf`.
pub fn read_line(prompt: &str, buf: &mut [u8]) -> usize {
    crate::print!("{}", prompt);
    let mut len = 0;
    loop {
        let key = get_key();
        match key {
            Key::Printable(ch) => {
                let code = u16::from(ch);
                let c = char::from(ch);
                if code == 3 {
                    // Ctrl+C
                    crate::println!("^C");
                    crate::print!("{}", prompt);
                    len = 0;
                } else if c == '\r' || c == '\n' {
                    crate::println!();
                    break;
                } else if c == '\x08' || u16::from(ch) == 8 {
                    if len > 0 {
                        len -= 1;
                        backspace();
                    }
                } else if len < buf.len() && (c as u32) <= 127 {
                    let b = c as u8;
                    buf[len] = b;
                    len += 1;
                    crate::print!("{}", c);
                }
            }
            Key::Special(ScanCode::DELETE) => {
                if len > 0 {
                    len -= 1;
                    backspace();
                }
            }
            Key::Special(ScanCode::UP) => {}
            Key::Special(ScanCode::DOWN) => {}
            Key::Special(ScanCode::LEFT) => {}
            Key::Special(ScanCode::RIGHT) => {}
            Key::Special(ScanCode::HOME) => {}
            Key::Special(ScanCode::END) => {}
            _ => {}
        }
    }
    len
}

use core::sync::atomic::{AtomicBool, Ordering};

pub static SCROLL_LOCK: AtomicBool = AtomicBool::new(false);

/// Checks whether Scroll Lock is active (via BDA 0x417 bit 0x10 or software toggle).
pub fn is_scroll_lock_active() -> bool {
    if SCROLL_LOCK.load(Ordering::Relaxed) {
        return true;
    }
    unsafe {
        let ptr = 0x417 as *const u8;
        (*ptr & 0x10) != 0
    }
}

/// Toggles the software Scroll Lock state and returns the new state.
pub fn toggle_scroll_lock() -> bool {
    let current = SCROLL_LOCK.load(Ordering::Relaxed);
    let new_val = !current;
    SCROLL_LOCK.store(new_val, Ordering::Relaxed);
    new_val
}

/// Sets the software Scroll Lock state.
pub fn set_scroll_lock(active: bool) {
    SCROLL_LOCK.store(active, Ordering::Relaxed);
}

/// Returns the maximum scroll offset available in the scrollback buffer.
pub fn max_scroll_offset() -> usize {
    let (_cols, rows) = screen_size();
    let console = CONSOLE.lock();
    let total = console.scrollback.total_lines();
    total.saturating_sub(rows.saturating_sub(1))
}

fn write_viewport_str(s: &str) {
    if is_standalone_video() {
        crate::video::console::write_str(s);
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.write_str(s);
        });
    }
}

fn set_viewport_color(fg: Color, bg: Color) {
    if is_standalone_video() {
        crate::video::console::set_colors(color_to_rgb(fg), color_to_rgb(bg));
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.set_color(fg, bg);
        });
    }
}

fn render_formatted_line(line: &[u8], attrs: &[u8]) {
    let len = line.len();
    if len == 0 {
        return;
    }

    let mut start = 0;
    while start < len {
        let current_attr = attrs[start];
        let mut end = start + 1;
        while end < len && attrs[end] == current_attr {
            end += 1;
        }

        let fg = u8_to_color(current_attr);
        let bg = u8_to_bg_color(current_attr);
        set_viewport_color(fg, bg);
        if let Ok(segment) = core::str::from_utf8(&line[start..end]) {
            write_viewport_str(segment);
        }

        start = end;
    }
    // Restore default text colors
    set_viewport_color(Color::White, Color::Black);
}

fn format_scroll_status<'a>(buf: &'a mut [u8], top: usize, bottom: usize, total: usize, offset: usize) -> &'a str {
    struct BufWriter<'b> {
        buf: &'b mut [u8],
        pos: usize,
    }
    impl<'b> Write for BufWriter<'b> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            let rem = self.buf.len().saturating_sub(self.pos);
            let to_copy = rem.min(bytes.len());
            self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
            Ok(())
        }
    }

    let mut writer = BufWriter { buf, pos: 0 };
    let _ = write!(
        writer,
        "-- SCROLL LOCK (up {} lines, lines {}-{} of {}) [UP/DOWN or PgUp/PgDn, ESC to exit] --",
        offset, top, bottom, total
    );
    let len = writer.pos;
    core::str::from_utf8(&buf[..len]).unwrap_or("-- SCROLL LOCK ACTIVE [UP/DOWN to scroll, ESC to exit] --")
}

/// Draws the terminal screen shifted up by `offset` lines.
/// When `offset == 0`, restores the live view with prompt and active line buffer.
pub fn draw_scroll_viewport(
    offset: usize,
    prompt: &str,
    line_text: &str,
    cursor_pos: usize,
    prompt_color: Color,
) {
    let (_cols, rows) = screen_size();
    let console = CONSOLE.lock();
    let total = console.scrollback.total_lines();
    let visible_rows = rows.saturating_sub(1);

    clear_screen();

    let mut line_buf = [0u8; SCROLLBACK_LINE_LEN];
    let mut attr_buf = [0u8; SCROLLBACK_LINE_LEN];

    if offset == 0 {
        // Live bottom view
        let top = total.saturating_sub(visible_rows);

        for i in top..total {
            if let Some(len) = console.scrollback.get_line_with_attrs(i, &mut line_buf, &mut attr_buf) {
                render_formatted_line(&line_buf[..len], &attr_buf[..len]);
                write_viewport_str("\r\n");
            } else {
                write_viewport_str("\r\n");
            }
        }

        // Draw active prompt on bottom line
        set_viewport_color(prompt_color, Color::Black);
        write_viewport_str(prompt);
        set_viewport_color(Color::White, Color::Black);
        write_viewport_str(line_text);
        let (cur_col, cur_row) = cursor_position();
        let prompt_col = cur_col.saturating_sub(line_text.len());
        set_cursor_position(prompt_col + cursor_pos, cur_row);
    } else {
        // Scrolled up into history
        let bottom = total.saturating_sub(offset);
        let top = bottom.saturating_sub(visible_rows);

        for i in top..bottom {
            if let Some(len) = console.scrollback.get_line_with_attrs(i, &mut line_buf, &mut attr_buf) {
                render_formatted_line(&line_buf[..len], &attr_buf[..len]);
                write_viewport_str("\r\n");
            } else {
                write_viewport_str("\r\n");
            }
        }

        for _ in (bottom - top)..visible_rows {
            write_viewport_str("\r\n");
        }

        // Status line on the bottom row
        let display_top = if bottom == 0 { 0 } else { top + 1 };
        set_viewport_color(Color::Black, Color::Cyan);
        let mut num_buf = [0u8; 96];
        let status = format_scroll_status(&mut num_buf, display_top, bottom, total, offset);
        write_viewport_str(status);
        set_viewport_color(Color::White, Color::Black);
    }
}


