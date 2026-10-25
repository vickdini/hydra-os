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
        }
    }

    pub fn cols(&self) -> usize {
        self.max_cols
    }

    pub fn rows(&self) -> usize {
        self.max_rows
    }

    pub fn cursor_pos(&self) -> (usize, usize) {
        (self.cursor_col, self.cursor_row)
    }

    pub fn set_color(&mut self, fg: (u8, u8, u8), bg: (u8, u8, u8)) {
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

    pub fn clear(&mut self) {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        self.framebuffer.clear(self.bg.0, self.bg.1, self.bg.2);
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

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

    pub fn write_char(&mut self, c: char) {
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

    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.write_char(c);
        }
    }

    pub fn framebuffer_mut(&mut self) -> &mut Framebuffer {
        if self.cursor_drawn {
            self.hide_cursor();
        }
        &mut self.framebuffer
    }

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

