//! # Console Subsystem: Dual-Mode Terminal, Scrollback History & Serial Output
//!
//! Provides unified text output, interactive keyboard line editing, scrollback history,
//! and COM1 serial logging across both early UEFI Boot Services and standalone hardware
//! framebuffer modes.
//!
//! ## Architectural Role & Design Rationale
//!
//! During early boot, Hydra OS relies on the UEFI Simple Text Output Protocol (`stdout`) and
//! Simple Text Input Protocol (`stdin`). Once [`crate::arch::boot_services::take_hardware_ownership`]
//! terminates UEFI Boot Services, the console transparently switches to the autonomous GOP linear
//! framebuffer renderer (`VideoConsole`) and the 8042 PS/2 keyboard driver.
//!
//! In addition, all console writes are recorded in a 512-line circular `ScrollbackBuffer`
//! (preserving per-character VGA foreground/background color attributes) so users can inspect
//! historical output via Scroll Lock, and mirrored to the `COM1` (`0x3F8`) serial port for
//! automated test capture and crash diagnostics.
//!
//! ## Key Types & Interfaces
//!
//! - `Console`: Global terminal state holding the active color attribute and `ScrollbackBuffer`.
//! - `ScrollbackBuffer`: Fixed-size ring buffer storing 512 lines of 128 characters with attributes.
//! - `FixedBuf`: Stack-allocated formatting buffer usable inside interrupt/watchdog handlers without heap locks.
//! - [`print!`] / [`println!`]: Standard formatted output macros routed through the current task's file descriptor 1 (`stdout`).
//! - [`kprintln!`]: Kernel diagnostic macro that writes directly to the physical screen and serial port, bypassing task pipes.
//! - `serial_write`: Direct polled UART `COM1` (`0x3F8`) string transmitter.
//!
//! ## Hardware & Dependency Context
//!
//! - **CPU Privilege Level**: Ring 0 (Kernel).
//! - **Hardware Interaction**: `COM1` UART I/O ports (`0x3F8`..`0x3FD`), BIOS Data Area (`0x417`), PIT/RDTSC delay timers.
//! - **Concurrency**: Protected by [`spin::Mutex`] (`CONSOLE`, `USE_STANDALONE_VIDEO`) and lock-free atomics (`HARDWARE_MODE`, `CONSOLE_OUTPUT_GENERATION`, `SCROLL_LOCK`).

use core::fmt::{self, Write};
use core::time::Duration;
use spin::Mutex;
use uefi::proto::console::text::{Color, Key, ScanCode};

/// Maximum number of historical lines retained in the terminal scrollback ring buffer.
const SCROLLBACK_MAX_LINES: usize = 512;
/// Maximum number of ASCII characters stored per scrollback line before automatic wrapping.
const SCROLLBACK_LINE_LEN: usize = 128;

/// Converts a UEFI [`Color`] variant into its corresponding 4-bit VGA color nibble (`0x0..=0xF`).
///
/// # Arguments
///
/// * `c` - The UEFI [`Color`] enum value to encode.
///
/// # Returns
///
/// The 4-bit integer index (`0` for `Black` through `15` for `White`).
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

/// Decodes the low 4-bit foreground nibble of a VGA attribute byte into a UEFI [`Color`].
///
/// # Arguments
///
/// * `val` - Packed 8-bit attribute byte (`bits 0..=3` represent foreground color).
///
/// # Returns
///
/// The corresponding foreground [`Color`] variant.
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

/// Decodes the background color nibble (`bits 4..=6`) of a VGA attribute byte into a UEFI [`Color`].
///
/// # Arguments
///
/// * `val` - Packed 8-bit attribute byte (`bits 4..=6` represent standard 8-color background).
///
/// # Returns
///
/// The corresponding background [`Color`] variant (`Black` through `LightGray`).
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

/// Circular ring buffer storing historical console text lines and per-character color attributes.
///
/// # Concurrency & Thread Safety
/// Accessed exclusively through the global [`CONSOLE`] [`spin::Mutex`].
///
/// # Lifetime & Cleanup
/// Statically allocated in the kernel `.bss`/`.data` segment; overwrites the oldest committed line
/// once [`SCROLLBACK_MAX_LINES`] (512) lines have been recorded, or resets on [`ScrollbackBuffer::clear`].
pub struct ScrollbackBuffer {
    /// Committed line character payloads indexed by ring slot.
    lines: [[u8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
    /// Committed per-character VGA color attributes (`bg << 4 | fg`) indexed by ring slot.
    attrs: [[u8; SCROLLBACK_LINE_LEN]; SCROLLBACK_MAX_LINES],
    /// Valid character count for each committed line in `lines`.
    lens: [usize; SCROLLBACK_MAX_LINES],
    /// Character staging buffer for the currently active, uncommitted bottom line.
    cur_line: [u8; SCROLLBACK_LINE_LEN],
    /// Color attribute staging buffer for the currently active, uncommitted bottom line.
    cur_attrs: [u8; SCROLLBACK_LINE_LEN],
    /// Ring index where the next committed line will be written.
    head: usize,
    /// Number of committed lines currently stored in the ring (`0..=SCROLLBACK_MAX_LINES`).
    count: usize,
    /// Number of characters currently buffered in `cur_line`.
    cur_len: usize,
}

impl ScrollbackBuffer {
    /// Creates an empty, zero-initialized `ScrollbackBuffer` with default white-on-black (`0x0F`) attributes.
    ///
    /// # Returns
    ///
    /// A new `ScrollbackBuffer` instance suitable for `const` static initialization.
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

    /// Resets the scrollback history, discarding all committed and in-progress lines.
    pub fn clear(&mut self) {
        self.head = 0;
        self.count = 0;
        self.cur_len = 0;
        self.lens = [0; SCROLLBACK_MAX_LINES];
    }

    /// Appends a UTF-8 string slice with the specified color attribute byte to the scrollback buffer.
    ///
    /// Automatically commits the active line upon encountering a newline (`\n`) or reaching
    /// [`SCROLLBACK_LINE_LEN`] (128 characters). Carriage returns (`\r`) are ignored.
    ///
    /// # Arguments
    ///
    /// * `s` - Text string slice to append.
    /// * `attr` - Packed VGA color attribute byte (`(bg << 4) | fg`).
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

    /// Commits the staging line (`cur_line`) into the circular ring at `head` and resets `cur_len`.
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

    /// Returns the total number of viewable lines in the scrollback buffer, including any
    /// partially written active line.
    ///
    /// # Returns
    ///
    /// Total logical line count (`0..=SCROLLBACK_MAX_LINES + 1`).
    pub fn total_lines(&self) -> usize {
        self.count + if self.cur_len > 0 { 1 } else { 0 }
    }

    /// Copies the characters and color attributes of logical line `idx` (oldest = `0`) into caller buffers.
    ///
    /// # Arguments
    ///
    /// * `idx` - Logical line index from `0` (oldest retained line) up to `total_lines() - 1`.
    /// * `line_buf` - Destination 128-byte buffer to receive the line's ASCII bytes.
    /// * `attr_buf` - Destination 128-byte buffer to receive the per-character color attribute bytes.
    ///
    /// # Returns
    ///
    /// * `Some(len)` - Number of valid bytes copied into `line_buf` and `attr_buf`.
    /// * `None` - If `idx >= self.total_lines()`.
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

/// Global mutex-protected system console instance.
pub static CONSOLE: Mutex<Console> = Mutex::new(Console::new());

/// Central console state tracking scrollback history and active text color attributes.
///
/// # Concurrency & Thread Safety
/// Synchronized globally via [`CONSOLE`] (`spin::Mutex<Console>`).
pub struct Console {
    /// Historical line and attribute ring buffer.
    pub scrollback: ScrollbackBuffer,
    /// Currently active VGA color attribute byte (`(bg << 4) | fg`).
    pub current_attr: u8,
}

impl Console {
    /// Creates a new `Console` initialized with an empty scrollback buffer and white-on-black (`0x0F`) colors.
    ///
    /// # Returns
    ///
    /// A const-initialized `Console`.
    pub const fn new() -> Self {
        Self {
            scrollback: ScrollbackBuffer::new(),
            current_attr: 0x0F, // White on Black
        }
    }
}

/// Maps a UEFI [`Color`] variant to its standard 24-bit `(R, G, B)` CGA/EGA palette triplet.
///
/// # Arguments
///
/// * `c` - The UEFI [`Color`] to convert.
///
/// # Returns
///
/// A tuple `(red, green, blue)` with 8-bit channel intensities (`0..=255`).
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

/// Flag indicating whether console output should route to the standalone GOP framebuffer instead of UEFI `stdout`.
static USE_STANDALONE_VIDEO: Mutex<bool> = Mutex::new(false);

/// Enables or disables routing console output to the autonomous GOP linear framebuffer (`VideoConsole`).
///
/// # Arguments
///
/// * `enabled` - `true` to use the standalone framebuffer and `COM1` serial port; `false` to use UEFI Boot Services `stdout`.
pub fn enable_standalone_video(enabled: bool) {
    *USE_STANDALONE_VIDEO.lock() = enabled;
}

/// Returns whether console output is currently routed to the standalone GOP framebuffer.
///
/// # Returns
///
/// `true` if standalone video mode is active, or `false` if UEFI `stdout` is still in use.
pub fn is_standalone_video() -> bool {
    *USE_STANDALONE_VIDEO.lock()
}

/// Monotonically increasing counter incremented on every console write operation.
static CONSOLE_OUTPUT_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Reads the current console output generation counter.
///
/// Used by interactive UI loops (such as [`get_key_or_refresh`]) to detect background task output
/// and trigger a prompt redraw.
///
/// # Returns
///
/// The current 64-bit generation count.
pub fn console_output_generation() -> u64 {
    CONSOLE_OUTPUT_GENERATION.load(core::sync::atomic::Ordering::Relaxed)
}

/// Increments the global console output generation counter by one.
pub fn inc_console_output_generation() {
    CONSOLE_OUTPUT_GENERATION.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let attr = self.current_attr;
        self.scrollback.push_str(s, attr);
        if is_standalone_video() {
            crate::video::console::write_str(s);
            serial_write(s);
        } else {
            uefi::system::with_stdout(|stdout| {
                let _ = stdout.write_str(s);
            });
        }
        inc_console_output_generation();
        Ok(())
    }
}

/// Fixed-capacity stack text buffer for formatting strings without heap allocation or mutex locks.
///
/// # Concurrency & Thread Safety
/// Owned on the caller's stack; safe to instantiate inside interrupt handlers and kernel watchdog traps.
pub struct FixedBuf {
    /// Internal 160-byte ASCII/UTF-8 storage array.
    buf: [u8; 160],
    /// Number of valid bytes written into `buf`.
    len: usize,
}

impl FixedBuf {
    /// Creates an empty 160-byte `FixedBuf`.
    ///
    /// # Returns
    ///
    /// A zeroed `FixedBuf` with `len == 0`.
    pub const fn new() -> Self {
        Self { buf: [0; 160], len: 0 }
    }

    /// Returns the buffered contents as a UTF-8 string slice.
    ///
    /// # Returns
    ///
    /// The formatted `&str`, or `""` if truncation split a multi-byte UTF-8 sequence.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl core::fmt::Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Mirrors console output to the `COM1` (`0x3F8`) serial port so kernel logs survive after
/// UEFI Boot Services exit.
///
/// Automatically translates `\n` line feeds into `\r\n` carriage-return/line-feed pairs.
///
/// # Arguments
///
/// * `s` - The UTF-8 string slice to transmit over `COM1`.
pub fn serial_write(s: &str) {
    use x86_64::instructions::port::Port;
    const COM1: u16 = 0x3F8;
    let mut data: Port<u8> = Port::new(COM1);
    let mut status: Port<u8> = Port::new(COM1 + 5);
    for b in s.bytes() {
        if b == b'\n' {
            serial_put(&mut data, &mut status, b'\r');
        }
        serial_put(&mut data, &mut status, b);
    }
}

/// Polls the UART Line Status Register (`COM1 + 5`) until the Transmit Holding Register Empty
/// (`THRE`, bit 5) flag is set, then writes a single byte `b` to the data port.
fn serial_put(data: &mut x86_64::instructions::port::Port<u8>, status: &mut x86_64::instructions::port::Port<u8>, b: u8) {
    unsafe {
        // Wait (bounded) for the transmit holding register to empty
        for _ in 0..100_000 {
            if status.read() & 0x20 != 0 {
                break;
            }
        }
        data.write(b);
    }
}

/// Sets the active foreground and background colors for subsequent console text output.
///
/// Updates both the scrollback attribute byte in [`CONSOLE`] and the active display backend
/// (either [`crate::video::console`] or UEFI `stdout`).
///
/// # Arguments
///
/// * `foreground` - Text glyph [`Color`].
/// * `background` - Cell background [`Color`].
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

/// Clears the visible terminal screen and resets the cursor to the top-left corner `(0, 0)`.
///
/// Does not clear the scrollback history; use [`clear_scrollback`] to reset saved history.
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


/// Extracts the raw 16-bit UEFI numeric code from a [`ScanCode`].
///
/// # Arguments
///
/// * `s` - The UEFI [`ScanCode`] wrapper.
///
/// # Returns
///
/// The underlying `u16` scan code value.
pub fn probe_scancode(s: ScanCode) -> u16 {
    s.0
}

/// Queries the dimensions of the active text console in character cells.
///
/// # Returns
///
/// A tuple `(columns, rows)` representing the width and height of the text grid (defaults to `(80, 25)` if unavailable).
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

/// Queries the current `(column, row)` coordinates of the text cursor.
///
/// # Returns
///
/// A zero-based `(col, row)` tuple.
pub fn cursor_position() -> (usize, usize) {
    if is_standalone_video() {
        crate::video::console::cursor_position()
    } else {
        uefi::system::with_stdout(|stdout| stdout.cursor_position())
    }
}

/// Moves the text cursor to the specified zero-based `(col, row)` cell coordinate.
///
/// # Arguments
///
/// * `col` - Zero-based horizontal column index.
/// * `row` - Zero-based vertical row index.
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
///
/// # Arguments
///
/// * `enabled` - `true` to show the cursor, `false` to hide it.
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
///
/// # Returns
///
/// `true` if cursor rendering is enabled, `false` otherwise.
pub fn is_cursor_enabled() -> bool {
    if is_standalone_video() {
        crate::video::console::is_cursor_enabled()
    } else {
        true
    }
}

/// Sets the visual cursor rendering shape.
///
/// # Arguments
///
/// * `shape` - Desired [`CursorShape`] (`Underline`, `Block`, or `Beam`).
pub fn set_cursor_shape(shape: CursorShape) {
    if is_standalone_video() {
        crate::video::console::set_cursor_shape(shape);
    }
}

/// Returns the current cursor rendering shape.
///
/// # Returns
///
/// The active [`CursorShape`] (always [`CursorShape::Underline`] in UEFI text mode).
pub fn cursor_shape() -> CursorShape {
    if is_standalone_video() {
        crate::video::console::cursor_shape()
    } else {
        CursorShape::Underline
    }
}

/// Prints formatted text to the current task's standard output (file descriptor 1) without a trailing newline.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(format_args!($($arg)*))
    };
}

/// Prints formatted text with a trailing newline to the current task's standard output (file descriptor 1).
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

/// Prints a kernel diagnostic to the console and serial port, never through the current
/// task's standard output (which may be a pipe another process parses).
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => ($crate::console::_kprint(format_args!("{}\n", format_args!($($arg)*))));
}

/// Internal implementation backing [`kprintln!`], writing directly to [`CONSOLE`].
#[doc(hidden)]
pub fn _kprint(args: fmt::Arguments) {
    let mut console = CONSOLE.lock();
    let _ = console.write_fmt(args);
}

/// Directly writes raw text to the physical console screen / framebuffer without FD indirection.
///
/// # Arguments
///
/// * `s` - Raw UTF-8 string slice to render on the physical console and serial port.
pub fn print_raw(s: &str) {
    let mut console = CONSOLE.lock();
    let _ = console.write_str(s);
}

/// Internal implementation backing [`print!`] and [`println!`], routing output through file descriptor 1
/// of the current task when the kernel heap and task table are active.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    struct Fd1Writer;
    impl fmt::Write for Fd1Writer {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            // The descriptor table allocates; before the heap exists print directly
            if !crate::memory::heap::is_initialized() {
                print_raw(s);
                return Ok(());
            }
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

/// Atomic flag indicating whether UEFI Boot Services have exited and bare-metal hardware I/O is active.
static HARDWARE_MODE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Switches the console subsystem between UEFI firmware I/O (`false`) and bare-metal PS/2 + PIT hardware I/O (`true`).
///
/// # Arguments
///
/// * `enabled` - `true` once hardware ownership is taken; `false` during UEFI Boot Services.
pub fn set_hardware_mode(enabled: bool) {
    HARDWARE_MODE.store(enabled, core::sync::atomic::Ordering::SeqCst);
}

/// Returns whether the console is operating in bare-metal hardware mode.
///
/// # Returns
///
/// `true` if using PS/2 keyboard and PIT/RDTSC timers, `false` if using UEFI Boot Services.
pub fn is_hardware_mode() -> bool {
    HARDWARE_MODE.load(core::sync::atomic::Ordering::SeqCst)
}

/// Polls for a key without blocking (from PS/2 keyboard in hardware mode, or UEFI stdin).
///
/// # Returns
///
/// * `Some(Key)` - If a key press event is immediately available.
/// * `None` - If no key has been pressed.
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
///
/// # Returns
///
/// `true` if an interrupt key combination was read, `false` otherwise.
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
///
/// # Arguments
///
/// * `duration` - Time interval to stall the calling thread.
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
///
/// # Returns
///
/// The [`Key`] pressed by the user.
pub fn get_key() -> Key {
    show_cursor();
    let mut blink_counter = 0u32;
    loop {
        if let Some(key) = read_key() {
            hide_cursor();
            return key;
        }
        crate::task::preemptible(|| stall(Duration::from_millis(10)));
        blink_counter += 1;
        if blink_counter >= 50 {
            blink_counter = 0;
            toggle_cursor();
        }
    }
}

/// Waits for a key press, or returns `Err(())` if new console output was generated while waiting.
///
/// # Arguments
///
/// * `last_gen` - Snapshot of [`console_output_generation()`] taken before entering the wait loop.
///
/// # Returns
///
/// * `Ok(Key)` - When a key press is received without intervening background console output.
/// * `Err(())` - When [`console_output_generation()`] changes, signaling that the caller should refresh the prompt.
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
        crate::task::preemptible(|| stall(Duration::from_millis(10)));
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
///
/// # Arguments
///
/// * `prompt` - Prompt string displayed at the start of the line (and re-displayed on `Ctrl+C`).
/// * `buf` - Destination slice to store the entered ASCII bytes (excluding the terminating newline).
///
/// # Returns
///
/// Number of bytes written into `buf`.
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

/// Global software Scroll Lock state flag.
pub static SCROLL_LOCK: AtomicBool = AtomicBool::new(false);

/// Checks whether Scroll Lock is active (via BDA `0x417` bit `0x10` or software toggle).
///
/// # Returns
///
/// `true` if Scroll Lock is currently engaged, `false` otherwise.
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
///
/// # Returns
///
/// `true` if Scroll Lock is now active, `false` if deactivated.
pub fn toggle_scroll_lock() -> bool {
    let current = SCROLL_LOCK.load(Ordering::Relaxed);
    let new_val = !current;
    SCROLL_LOCK.store(new_val, Ordering::Relaxed);
    new_val
}

/// Sets the software Scroll Lock state.
///
/// # Arguments
///
/// * `active` - `true` to enable Scroll Lock, `false` to disable it.
pub fn set_scroll_lock(active: bool) {
    SCROLL_LOCK.store(active, Ordering::Relaxed);
}

/// Returns the maximum scroll offset available in the scrollback buffer.
///
/// # Returns
///
/// Maximum number of lines by which the viewport can be shifted upward.
pub fn max_scroll_offset() -> usize {
    let (_cols, rows) = screen_size();
    let console = CONSOLE.lock();
    let total = console.scrollback.total_lines();
    total.saturating_sub(rows.saturating_sub(1))
}

/// Writes a string directly to the active display viewport without recording it in the scrollback buffer.
fn write_viewport_str(s: &str) {
    if is_standalone_video() {
        crate::video::console::write_str(s);
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.write_str(s);
        });
    }
}

/// Sets the active display viewport colors without modifying the persistent [`Console::current_attr`].
fn set_viewport_color(fg: Color, bg: Color) {
    if is_standalone_video() {
        crate::video::console::set_colors(color_to_rgb(fg), color_to_rgb(bg));
    } else {
        uefi::system::with_stdout(|stdout| {
            let _ = stdout.set_color(fg, bg);
        });
    }
}

/// Renders a single historical scrollback line onto the display viewport, grouping contiguous runs
/// of identical color attributes to minimize state switches.
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

/// Formats the bottom status banner displayed while viewing historical lines in Scroll Lock mode.
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
///
/// # Arguments
///
/// * `offset` - Number of lines scrolled upward from the bottom (`0` for live view).
/// * `prompt` - Interactive shell prompt string to redraw when `offset == 0`.
/// * `line_text` - Current uncommitted input line text to redraw when `offset == 0`.
/// * `cursor_pos` - Character offset of the cursor within `line_text`.
/// * `prompt_color` - Foreground [`Color`] used to render `prompt`.
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


