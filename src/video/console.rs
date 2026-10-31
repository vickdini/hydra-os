//! # Video Subsystem: Autonomous Framebuffer Text Console
//!
//! Provides a hardware-accelerated text console with ANSI escape sequence decoding,
//! configurable cursor styles, vertical scrolling, and color attribute management.
//!
//! ## Architectural Role & Design Rationale
//!
//! When UEFI Boot Services are exited, firmware text output (`SimpleTextOutput`) ceases functioning.
//! The [`VideoConsole`] takes over console output directly onto the GOP linear [`Framebuffer`].
//! It supports full standard terminal semantics: line wrapping, newline handling (`\n`), carriage returns (`\r`),
//! tab stops, backspace erasure, hardware color palettes, and ANSI/VT100 cursor control sequences.
//!
//! ## Key Types & Interfaces
//!
//! - [`VIDEO_CONSOLE`]: Global spinlock-protected singleton instance.
//! - [`VideoConsole`]: Core terminal emulator maintaining cursor state and colors.
//! - `CursorShape`: Visual representation of the terminal cursor (`Underline`, `Block`, `Bar`).
//! - [`clear_screen()`], [`write_str()`], [`set_colors()`]: Helper functions for global console printing.

use core::fmt::{self, Write};
use spin::Mutex;

use super::font::{FONT_HEIGHT, FONT_WIDTH};
use super::framebuffer::Framebuffer;

/// Global autonomous video console singleton.
pub static VIDEO_CONSOLE: Mutex<Option<VideoConsole>> = Mutex::new(None);

/// Cursor visual rendering style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorShape {
    /// 3-pixel underline at the bottom of the 16-pixel font cell.
    Underline,
    /// Solid full-height (8x16) character inversion block.
    Block,
    /// 2-pixel vertical bar on the left edge of the cell.
    Bar,
}

/// High-performance text console running directly on the hardware framebuffer.
pub struct VideoConsole {
    framebuffer: Framebuffer,
    cursor_col: usize,
    cursor_row: usize,
    max_cols: usize,
    max_rows: usize,
    fg: (u8, u8, u8),
    bg: (u8, u8, u8),
    cursor_enabled: bool,
    cursor_drawn: bool,
    cursor_shape: CursorShape,
    cursor_drawn_col: usize,
    cursor_drawn_row: usize,
    cursor_drawn_shape: CursorShape,
    esc_state: EscState,
    esc_params: [u16; 8],
    esc_nparams: usize,
    esc_has_param: bool,
    default_fg: (u8, u8, u8),
    default_bg: (u8, u8, u8),
}

impl VideoConsole {
    /// Creates a new VideoConsole wrapping the given Framebuffer.
    pub fn new(framebuffer: Framebuffer) -> Self {
        let max_cols = framebuffer.width() / FONT_WIDTH;
        let max_rows = framebuffer.height() / FONT_HEIGHT;

        Self {
            framebuffer,
            cursor_col: 0,
            cursor_row: 0,
            max_cols,
            max_rows,
            fg: (220, 220, 220), // Light Gray default text
            bg: (0, 0, 0),        // Black default background
            cursor_enabled: true,
            cursor_drawn: false,
            cursor_shape: CursorShape::Underline,
            cursor_drawn_col: 0,
            cursor_drawn_row: 0,
            cursor_drawn_shape: CursorShape::Underline,
            esc_state: EscState::Ground,
            esc_params: [0; 8],
            esc_nparams: 0,
            esc_has_param: false,
            default_fg: (220, 220, 220),
            default_bg: (0, 0, 0),
        }
    }

    /// Returns the total number of character columns supported across the screen.
    pub fn cols(&self) -> usize {
        self.max_cols
    }

    /// Returns the total number of character rows supported across the screen.
    pub fn rows(&self) -> usize {
        self.max_rows
    }

    /// Returns the active `(col, row)` text cursor coordinates.
    pub fn cursor_pos(&self) -> (usize, usize) {
        (self.cursor_col, self.cursor_row)
    }

    /// Updates foreground and background RGB colors for subsequently rendered text.
    pub fn set_color(&mut self, fg: (u8, u8, u8), bg: (u8, u8, u8)) {
        self.default_fg = fg;
        self.default_bg = bg;
        self.fg = fg;
        self.bg = bg;
    }

    fn cursor_rect(&self, col: usize, row: usize, shape: CursorShape) -> (usize, usize, usize, usize) {
        let col = col.min(self.max_cols.saturating_sub(1));
        let row = row.min(self.max_rows.saturating_sub(1));
        let px = col * FONT_WIDTH;
        let py = row * FONT_HEIGHT;
        match shape {
            CursorShape::Underline => {
                let h = 3;
                let offset_y = FONT_HEIGHT.saturating_sub(h);
                (px, py + offset_y, FONT_WIDTH, h)
            }
            CursorShape::Block => (px, py, FONT_WIDTH, FONT_HEIGHT),
            CursorShape::Bar => (px, py, 2, FONT_HEIGHT),
        }
    }

    /// Displays the hardware cursor at current cursor_pos using lossless XOR color inversion.
    pub fn show_cursor(&mut self) {
        if !self.cursor_enabled {
            return;
        }
        if self.cursor_drawn {
            if self.cursor_drawn_col == self.cursor_col
                && self.cursor_drawn_row == self.cursor_row
                && self.cursor_drawn_shape == self.cursor_shape
            {
                return;
            }
            self.hide_cursor();
        }
        let (x, y, w, h) = self.cursor_rect(self.cursor_col, self.cursor_row, self.cursor_shape);
        self.framebuffer.invert_rect(x, y, w, h);
        self.cursor_drawn = true;
        self.cursor_drawn_col = self.cursor_col;
        self.cursor_drawn_row = self.cursor_row;
        self.cursor_drawn_shape = self.cursor_shape;
    }

    /// Hides the hardware cursor by reversing the XOR color inversion.
    pub fn hide_cursor(&mut self) {
        if self.cursor_drawn {
            let (x, y, w, h) = self.cursor_rect(
                self.cursor_drawn_col,
                self.cursor_drawn_row,
                self.cursor_drawn_shape,
            );
            self.framebuffer.invert_rect(x, y, w, h);
            self.cursor_drawn = false;
        }
    }

    /// Toggles the cursor state for periodic blinking.
    pub fn toggle_cursor(&mut self) {
        if self.cursor_drawn {
            self.hide_cursor();
        } else if self.cursor_enabled {
            self.show_cursor();
        }
    }

    /// Enables or disables the visual cursor.
    pub fn set_cursor_enabled(&mut self, enabled: bool) {
        if self.cursor_enabled != enabled {
            self.cursor_enabled = enabled;
            if !enabled && self.cursor_drawn {
                self.hide_cursor();
            }
        }
    }

    /// Returns whether the visual cursor is enabled.
    pub fn is_cursor_enabled(&self) -> bool {
        self.cursor_enabled
    }

    /// Configures the cursor rendering shape (Underline, Block, or Bar).
    pub fn set_cursor_shape(&mut self, shape: CursorShape) {
        if self.cursor_shape != shape {
            let was_drawn = self.cursor_drawn;
            if was_drawn {
                self.hide_cursor();
            }
            self.cursor_shape = shape;
            if was_drawn && self.cursor_enabled {
                self.show_cursor();
            }
        }
    }

    /// Returns the current cursor rendering shape.
    pub fn cursor_shape(&self) -> CursorShape {
        self.cursor_shape
    }

    /// Moves the cursor to the specified column and row coordinate.
    pub fn set_cursor_pos(&mut self, col: usize, row: usize) {
        let was_drawn = self.cursor_drawn;
        if was_drawn {
            self.hide_cursor();
        }
        self.cursor_col = col.min(self.max_cols.saturating_sub(1));
        self.cursor_row = row.min(self.max_rows.saturating_sub(1));
        if was_drawn && self.cursor_enabled {
            self.show_cursor();
        }
    }

    /// Clears the entire text console with the background color and homes the cursor.
    pub fn clear(&mut self) {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        self.framebuffer.clear(self.bg.0, self.bg.1, self.bg.2);
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    /// Advances the cursor to the beginning of the next line, scrolling if at the bottom.
    pub fn new_line(&mut self) {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        self.cursor_col = 0;
        if self.cursor_row + 1 < self.max_rows {
            self.cursor_row += 1;
        } else {
            self.framebuffer.scroll_up(FONT_HEIGHT, self.bg);
        }
    }

    /// Renders a single character or processes a control byte (`\n`, `\r`, `\t`, backspace).
    pub fn write_char(&mut self, c: char) {
        if self.ansi_feed(c) {
            return;
        }
        if self.cursor_drawn {
            self.hide_cursor();
        }
        match c {
            '\r' => {
                self.cursor_col = 0;
            }
            '\n' => {
                self.new_line();
            }
            '\t' => {
                let tab_target = (self.cursor_col + 4) & !3;
                let next_col = tab_target.min(self.max_cols);
                while self.cursor_col < next_col {
                    self.framebuffer.draw_char(
                        self.cursor_col * FONT_WIDTH,
                        self.cursor_row * FONT_HEIGHT,
                        ' ',
                        self.fg,
                        self.bg,
                    );
                    self.cursor_col += 1;
                }
            }
            '\x08' => {
                // Backspace
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                    self.framebuffer.draw_char(
                        self.cursor_col * FONT_WIDTH,
                        self.cursor_row * FONT_HEIGHT,
                        ' ',
                        self.fg,
                        self.bg,
                    );
                }
            }
            printable => {
                if self.cursor_col >= self.max_cols {
                    self.new_line();
                }

                self.framebuffer.draw_char(
                    self.cursor_col * FONT_WIDTH,
                    self.cursor_row * FONT_HEIGHT,
                    printable,
                    self.fg,
                    self.bg,
                );
                self.cursor_col += 1;
            }
        }
    }

    /// Writes a UTF-8 string slice to the graphical console.
    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }

    /// Obtains a mutable reference to the underlying linear [`Framebuffer`].
    pub fn framebuffer_mut(&mut self) -> &mut Framebuffer {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        &mut self.framebuffer
    }

    /// Obtains an immutable reference to the underlying linear [`Framebuffer`].
    pub fn framebuffer(&self) -> &Framebuffer {
        &self.framebuffer
    }
}

impl Write for VideoConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

/// Returns true if the autonomous video console has been initialized.
pub fn is_active() -> bool {
    VIDEO_CONSOLE.lock().is_some()
}

/// Off-screen copy the console draws into while a compositor owns the screen, and the
/// real framebuffer address to return to.
static SHADOW: Mutex<Option<(alloc::vec::Vec<u8>, usize)>> = Mutex::new(None);

/// Gives the screen to a compositor: the console keeps drawing, into a shadow copy of
/// the framebuffer. Returns the real framebuffer (address, width, height, stride in
/// pixels, BGR order) for the compositor to draw on.
pub fn release_display() -> Option<(*mut u8, usize, usize, usize, bool)> {
    let mut guard = VIDEO_CONSOLE.lock();
    let console = guard.as_mut()?;
    let mut shadow = SHADOW.lock();
    let fb = console.framebuffer_mut();
    let info = (fb.base_ptr(), fb.width(), fb.height(), fb.stride(), fb.is_bgr());
    if shadow.is_none() {
        let mut copy = alloc::vec![0u8; fb.size()];
        unsafe { core::ptr::copy_nonoverlapping(fb.base_ptr(), copy.as_mut_ptr(), fb.size()) };
        let real = fb.base_ptr() as usize;
        fb.set_base(copy.as_mut_ptr());
        *shadow = Some((copy, real));
        return Some((real as *mut u8, info.1, info.2, info.3, info.4));
    }
    let real = shadow.as_ref().unwrap().1 as *mut u8;
    Some((real, info.1, info.2, info.3, info.4))
}

/// Returns the screen to the console, showing what it drew in the meantime.
pub fn reclaim_display() {
    let mut guard = VIDEO_CONSOLE.lock();
    let console = match guard.as_mut() {
        Some(c) => c,
        None => return,
    };
    if let Some((copy, real)) = SHADOW.lock().take() {
        let fb = console.framebuffer_mut();
        unsafe { core::ptr::copy_nonoverlapping(copy.as_ptr(), real as *mut u8, fb.size().min(copy.len())) };
        fb.set_base(real as *mut u8);
    }
}

/// True while a compositor owns the screen.
pub fn display_released() -> bool {
    SHADOW.lock().is_some()
}

/// Writes a string to the autonomous video console if active.
pub fn write_str(s: &str) {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.write_str(s);
    }
}

/// Sets the current foreground and background colors for the autonomous video console.
pub fn set_colors(fg: (u8, u8, u8), bg: (u8, u8, u8)) {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.set_color(fg, bg);
    }
}

/// Clears the autonomous video console screen.
pub fn clear_screen() {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.clear();
    }
}

/// Returns the current (col, row) of the video console cursor.
pub fn cursor_position() -> (usize, usize) {
    let guard = VIDEO_CONSOLE.lock();
    if let Some(ref console) = *guard {
        console.cursor_pos()
    } else {
        (0, 0)
    }
}

/// Sets the current (col, row) of the video console cursor.
pub fn set_cursor_position(col: usize, row: usize) {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.set_cursor_pos(col, row);
    }
}

/// Returns the (cols, rows) dimensions of the video console matrix.
pub fn dimensions() -> (usize, usize) {
    let guard = VIDEO_CONSOLE.lock();
    if let Some(ref console) = *guard {
        (console.cols(), console.rows())
    } else {
        (80, 25)
    }
}

/// Displays the video console cursor at the current position.
pub fn show_cursor() {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.show_cursor();
    }
}

/// Erases the video console cursor from the screen.
pub fn hide_cursor() {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.hide_cursor();
    }
}

/// Toggles the cursor state for blinking.
pub fn toggle_cursor() {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.toggle_cursor();
    }
}

/// Enables or disables the visual cursor.
pub fn set_cursor_enabled(enabled: bool) {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.set_cursor_enabled(enabled);
    }
}

/// Returns whether the visual cursor is enabled.
pub fn is_cursor_enabled() -> bool {
    let guard = VIDEO_CONSOLE.lock();
    if let Some(ref console) = *guard {
        console.is_cursor_enabled()
    } else {
        false
    }
}

/// Sets the visual cursor rendering shape.
pub fn set_cursor_shape(shape: CursorShape) {
    let mut guard = VIDEO_CONSOLE.lock();
    if let Some(ref mut console) = *guard {
        console.set_cursor_shape(shape);
    }
}

/// Returns the current cursor rendering shape.
pub fn cursor_shape() -> CursorShape {
    let guard = VIDEO_CONSOLE.lock();
    if let Some(ref console) = *guard {
        console.cursor_shape()
    } else {
        CursorShape::Underline
    }
}

/// ANSI escape sequence parser state (ECMA-48 subset used by terminal programs).
#[derive(Clone, Copy, PartialEq, Eq)]
enum EscState {
    Ground,
    Escape,
    /// `ESC (`, `ESC )` and similar: swallow one more character.
    EscapeArg,
    Csi,
}

/// Standard 8-colour ANSI palette (normal, bright).
const ANSI_COLORS: [(u8, u8, u8); 16] = [
    (0, 0, 0),
    (205, 49, 49),
    (13, 188, 121),
    (229, 229, 16),
    (36, 114, 200),
    (188, 63, 188),
    (17, 168, 205),
    (220, 220, 220),
    (102, 102, 102),
    (241, 76, 76),
    (35, 209, 139),
    (245, 245, 67),
    (59, 142, 234),
    (214, 112, 214),
    (41, 184, 219),
    (255, 255, 255),
];

impl VideoConsole {
    /// Consumes `c` if it is part of an escape sequence. Returns true when handled.
    fn ansi_feed(&mut self, c: char) -> bool {
        match self.esc_state {
            EscState::Ground => {
                if c == '\x1b' {
                    self.esc_state = EscState::Escape;
                    return true;
                }
                c == '\x07' // BEL: no sound, just swallow it
            }
            EscState::Escape => {
                self.esc_state = match c {
                    '[' => {
                        self.esc_params = [0; 8];
                        self.esc_nparams = 0;
                        self.esc_has_param = false;
                        EscState::Csi
                    }
                    '(' | ')' | '#' | '%' => EscState::EscapeArg,
                    _ => EscState::Ground,
                };
                true
            }
            EscState::EscapeArg => {
                self.esc_state = EscState::Ground;
                true
            }
            EscState::Csi => {
                match c {
                    '0'..='9' => {
                        let i = self.esc_nparams.min(7);
                        self.esc_params[i] = self.esc_params[i].saturating_mul(10).saturating_add(c as u16 - '0' as u16);
                        self.esc_has_param = true;
                    }
                    ';' => {
                        self.esc_nparams = (self.esc_nparams + 1).min(7);
                    }
                    '?' | '>' | '=' | ' ' => {}
                    '\x40'..='\x7e' => {
                        let n = if self.esc_has_param || self.esc_nparams > 0 { self.esc_nparams + 1 } else { 0 };
                        self.esc_state = EscState::Ground;
                        self.csi_dispatch(c, n);
                    }
                    _ => self.esc_state = EscState::Ground,
                }
                true
            }
        }
    }

    fn csi_param(&self, i: usize, default: usize) -> usize {
        let v = self.esc_params[i] as usize;
        if v == 0 {
            default
        } else {
            v
        }
    }

    /// Paints columns `from..to` of row `row` with the background colour.
    fn erase_cells(&mut self, row: usize, from: usize, to: usize) {
        if from >= to {
            return;
        }
        self.framebuffer.fill_rect(
            from * FONT_WIDTH,
            row * FONT_HEIGHT,
            (to - from) * FONT_WIDTH,
            FONT_HEIGHT,
            self.bg.0,
            self.bg.1,
            self.bg.2,
        );
    }

    fn csi_dispatch(&mut self, cmd: char, nparams: usize) {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        let (cols, rows) = (self.max_cols, self.max_rows);
        match cmd {
            'A' => self.cursor_row = self.cursor_row.saturating_sub(self.csi_param(0, 1)),
            'B' => self.cursor_row = (self.cursor_row + self.csi_param(0, 1)).min(rows - 1),
            'C' => self.cursor_col = (self.cursor_col + self.csi_param(0, 1)).min(cols - 1),
            'D' => self.cursor_col = self.cursor_col.saturating_sub(self.csi_param(0, 1)),
            'G' => self.cursor_col = (self.csi_param(0, 1) - 1).min(cols - 1),
            'd' => self.cursor_row = (self.csi_param(0, 1) - 1).min(rows - 1),
            'H' | 'f' => {
                self.cursor_row = (self.csi_param(0, 1) - 1).min(rows - 1);
                self.cursor_col = (self.csi_param(1, 1) - 1).min(cols - 1);
            }
            'K' => {
                let row = self.cursor_row;
                match self.esc_params[0] {
                    0 => self.erase_cells(row, self.cursor_col, cols),
                    1 => self.erase_cells(row, 0, self.cursor_col + 1),
                    _ => self.erase_cells(row, 0, cols),
                }
            }
            'J' => match self.esc_params[0] {
                0 => {
                    let row = self.cursor_row;
                    self.erase_cells(row, self.cursor_col, cols);
                    for r in row + 1..rows {
                        self.erase_cells(r, 0, cols);
                    }
                }
                1 => {
                    for r in 0..self.cursor_row {
                        self.erase_cells(r, 0, cols);
                    }
                    let row = self.cursor_row;
                    self.erase_cells(row, 0, self.cursor_col + 1);
                }
                _ => {
                    for r in 0..rows {
                        self.erase_cells(r, 0, cols);
                    }
                }
            },
            'X' => {
                let row = self.cursor_row;
                let n = self.csi_param(0, 1);
                self.erase_cells(row, self.cursor_col, (self.cursor_col + n).min(cols));
            }
            'm' => {
                for i in 0..nparams.max(1) {
                    match self.esc_params[i] {
                        0 => {
                            self.fg = self.default_fg;
                            self.bg = self.default_bg;
                        }
                        1 => {}
                        7 => core::mem::swap(&mut self.fg, &mut self.bg),
                        30..=37 => self.fg = ANSI_COLORS[(self.esc_params[i] - 30) as usize],
                        39 => self.fg = self.default_fg,
                        40..=47 => self.bg = ANSI_COLORS[(self.esc_params[i] - 40) as usize],
                        49 => self.bg = self.default_bg,
                        90..=97 => self.fg = ANSI_COLORS[(self.esc_params[i] - 90 + 8) as usize],
                        100..=107 => self.bg = ANSI_COLORS[(self.esc_params[i] - 100 + 8) as usize],
                        _ => {}
                    }
                }
            }
            _ => {} // modes, scrolling regions, reports: not needed for a text console
        }
    }
}
