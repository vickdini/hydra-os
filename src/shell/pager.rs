//! # Shell Subsystem: Interactive Terminal Text Pager
//!
//! Provides an in-memory multi-page text viewer (`TextPager`) and convenience pagination
//! entry point (`paginate_text`) supporting `less`/`more`-style keyboard navigation.
//!
//! ## Architectural Role & Design Rationale
//! Diagnostic listings such as `help` manuals or large file dumps frequently exceed the vertical
//! row capacity of the UEFI text console or bare-metal framebuffer. `TextPager` buffers lines
//! in a fixed-size array and renders a scrollable viewport with an inverted status bar when
//! the line count exceeds the visible screen height, while printing short outputs inline without
//! clearing the screen.
//!
//! ## Key Types & Interfaces
//! - `TextPager`: Fixed-capacity line buffer and interactive viewport renderer.
//! - `paginate_text`: Splits a multi-line string slice and displays it via `TextPager`.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Queries console dimensions and reads keystrokes via [`crate::console`]
//! - Concurrency: Single-threaded synchronous modal loop during interactive pagination

use uefi::proto::console::text::{Color, Key, ScanCode};
use crate::console::{clear_screen, get_key, screen_size, set_color};

/// Maximum number of lines stored in a `TextPager` instance.
const MAX_PAGER_LINES: usize = 128;
/// Maximum byte length of a single line stored in `TextPager`.
const MAX_LINE_LEN: usize = 88;

/// In-memory pager buffer for formatted command outputs (e.g., `help`, `more`, `less`).
///
/// # Concurrency & Thread Safety
/// Stack-allocated per command invocation and used exclusively on the calling shell thread.
pub struct TextPager {
    /// Fixed-size storage array for buffered text lines.
    lines: [[u8; MAX_LINE_LEN]; MAX_PAGER_LINES],
    /// Valid UTF-8 byte length of each buffered line in `lines`.
    lens: [usize; MAX_PAGER_LINES],
    /// Total number of lines currently stored in the pager.
    count: usize,
}

impl TextPager {
    /// Creates a new empty `TextPager` buffer.
    pub const fn new() -> Self {
        Self {
            lines: [[0u8; MAX_LINE_LEN]; MAX_PAGER_LINES],
            lens: [0; MAX_PAGER_LINES],
            count: 0,
        }
    }

    /// Appends a single line of text to the pager buffer, truncating at [`MAX_LINE_LEN`] bytes.
    ///
    /// Silently drops the line if [`MAX_PAGER_LINES`] has already been reached.
    ///
    /// # Arguments
    ///
    /// * `s` - Single-line UTF-8 string slice to append.
    pub fn push(&mut self, s: &str) {
        if self.count >= MAX_PAGER_LINES {
            return;
        }
        let bytes = s.as_bytes();
        let len = bytes.len().min(MAX_LINE_LEN);
        self.lines[self.count][..len].copy_from_slice(&bytes[..len]);
        self.lens[self.count] = len;
        self.count += 1;
    }

    /// Returns the buffered line at `idx`, or `""` if `idx` is out of bounds.
    ///
    /// # Arguments
    ///
    /// * `idx` - Zero-based line index (`0..self.len()`).
    pub fn line(&self, idx: usize) -> &str {
        if idx < self.count {
            let len = self.lens[idx];
            core::str::from_utf8(&self.lines[idx][..len]).unwrap_or("")
        } else {
            ""
        }
    }

    /// Returns the number of lines currently buffered in the pager.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the pager contains no lines.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Displays the buffered lines interactively with line-by-line and page-by-page scrolling.
    ///
    /// If the buffered line count fits within a single terminal screen height, prints the lines
    /// directly without clearing the screen or entering the interactive key loop. Otherwise,
    /// supports `Up`/`Down`/`j`/`k`, `PgUp`/`PgDn`/`Space`/`b`, `Home`/`End`/`g`/`G`, and `q`/`Esc`.
    ///
    /// # Arguments
    ///
    /// * `title` - Banner title displayed in the inverted bottom status bar.
    pub fn display(&self, title: &str) {
        let (_cols, rows) = screen_size();
        let page_size = rows.saturating_sub(2).max(1);

        // If the content fits entirely on one screen, print directly without pagination
        if self.count <= page_size + 1 {
            for i in 0..self.count {
                crate::println!("{}", self.line(i));
            }
            return;
        }

        let mut top = 0;

        loop {
            clear_screen();
            let bottom = (top + page_size).min(self.count);

            for i in top..bottom {
                crate::println!("{}", self.line(i));
            }
            // Fill remaining screen rows with blank lines
            for _ in (bottom - top)..page_size {
                crate::println!();
            }

            // Inverted status bar
            set_color(Color::Black, Color::Cyan);
            let pct = if self.count > 0 { (bottom * 100) / self.count } else { 100 };
            crate::print!(
                "-- {} (lines {}-{} of {} [{}%]) [↑/↓: scroll, PgUp/PgDn: page, q: quit] --",
                title,
                top + 1,
                bottom,
                self.count,
                pct
            );
            set_color(Color::White, Color::Black);

            let key = get_key();
            match key {
                Key::Printable(ch) => {
                    let code = u16::from(ch);
                    let c = char::from(ch);
                    if c == 'q' || c == 'Q' || code == 3 || code == 27 {
                        clear_screen();
                        break;
                    } else if c == ' ' || code == 6 {
                        // Space or Ctrl+F: page down
                        if top + page_size < self.count {
                            top = (top + page_size).min(self.count.saturating_sub(page_size));
                        }
                    } else if c == 'b' || c == 'B' {
                        // 'b': page up
                        top = top.saturating_sub(page_size);
                    } else if c == 'j' || c == 'J' || c == '\r' || c == '\n' || code == 14 {
                        // 'j', Enter, or Ctrl+N: scroll down 1 line
                        if top + 1 < self.count {
                            top += 1;
                        }
                    } else if c == 'k' || c == 'K' || code == 16 {
                        // 'k' or Ctrl+P: scroll up 1 line
                        top = top.saturating_sub(1);
                    } else if c == 'g' {
                        // 'g': jump to top
                        top = 0;
                    } else if c == 'G' {
                        // 'G': jump to bottom
                        top = self.count.saturating_sub(page_size);
                    }
                }
                Key::Special(ScanCode::UP) => {
                    top = top.saturating_sub(1);
                }
                Key::Special(ScanCode::DOWN) => {
                    if top + 1 < self.count {
                        top += 1;
                    }
                }
                Key::Special(ScanCode::PAGE_UP) => {
                    top = top.saturating_sub(page_size);
                }
                Key::Special(ScanCode::PAGE_DOWN) => {
                    if top + page_size < self.count {
                        top = (top + page_size).min(self.count.saturating_sub(page_size));
                    }
                }
                Key::Special(ScanCode::HOME) => {
                    top = 0;
                }
                Key::Special(ScanCode::END) => {
                    top = self.count.saturating_sub(page_size);
                }
                Key::Special(ScanCode::ESCAPE) => {
                    clear_screen();
                    break;
                }
                _ => {}
            }
        }
    }
}

/// Paginates an arbitrary multi-line UTF-8 text string using `TextPager`.
///
/// Splits `text` on line boundaries, populates a `TextPager`, and invokes [`TextPager::display`].
///
/// # Arguments
///
/// * `title` - Title displayed in the bottom status bar.
/// * `text` - Multi-line UTF-8 string content to paginate.
pub fn paginate_text(title: &str, text: &str) {
    let mut pager = TextPager::new();
    for line in text.lines() {
        pager.push(line);
    }
    pager.display(title);
}
