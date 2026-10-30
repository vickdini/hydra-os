//! # Video Subsystem: Double-Buffered Framebuffer Compositor
//!
//! Provides a high-performance, tear-free 2D rendering canvas and compositor.
//!
//! ## Architectural Role & Design Rationale
//!
//! Drawing directly to physical Video RAM (VRAM) over PCIe or legacy buses causes severe
//! visible flickering, screen tearing, and sluggish redraw performance.
//!
//! The [`Compositor`] maintains an in-memory double buffer (`Vec<u32>`) in fast system RAM.
//! All window primitives, geometric gradients, wallpaper meshes, desktop taskbars, and
//! mouse pointer sprites are drawn off-screen. Once the frame is assembled, a single contiguous
//! blit transfers the complete raster image to the physical UEFI GOP linear framebuffer.
//!
//! ## Key Types & Interfaces
//!
//! - [`Compositor`]: 32-bit ARGB off-screen canvas with alpha-blending and geometry primitives.
//! - [`Color`]: Packed 32-bit ARGB color helpers (hex conversion, alpha blending, gradients).
//!
//! ## Privilege Level & Memory Context
//!
//! - Allocation: Backed by the dynamic microkernel heap (`alloc::vec::Vec`).
//! - Execution: Ring 0 microkernel core.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use super::font::{get_char_glyph, FONT_HEIGHT, FONT_WIDTH};
use super::framebuffer::Framebuffer;

/// Packed 32-bit ARGB color utilities.
pub struct Color;

impl Color {
    /// Constructs a packed 32-bit ARGB pixel from raw component bytes.
    #[inline(always)]
    pub const fn argb(a: u8, r: u8, g: u8, b: u8) -> u32 {
        ((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }

    /// Constructs an opaque 32-bit RGB pixel (`alpha = 255`).
    #[inline(always)]
    pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
        Self::argb(255, r, g, b)
    }

    /// Extracts the alpha channel (0..255).
    #[inline(always)]
    pub const fn a(c: u32) -> u8 {
        ((c >> 24) & 0xFF) as u8
    }

    /// Extracts the red channel (0..255).
    #[inline(always)]
    pub const fn r(c: u32) -> u8 {
        ((c >> 16) & 0xFF) as u8
    }

    /// Extracts the green channel (0..255).
    #[inline(always)]
    pub const fn g(c: u32) -> u8 {
        ((c >> 8) & 0xFF) as u8
    }

    /// Extracts the blue channel (0..255).
    #[inline(always)]
    pub const fn b(c: u32) -> u8 {
        (c & 0xFF) as u8
    }

    /// Performs linear alpha blending between a background pixel and a foreground pixel with alpha.
    #[inline(always)]
    pub fn blend(bg: u32, fg: u32, alpha: u8) -> u32 {
        if alpha == 255 {
            return fg;
        }
        if alpha == 0 {
            return bg;
        }

        let a = alpha as u32;
        let inv_a = 255 - a;

        let r = ((Self::r(fg) as u32 * a) + (Self::r(bg) as u32 * inv_a)) / 255;
        let g = ((Self::g(fg) as u32 * a) + (Self::g(bg) as u32 * inv_a)) / 255;
        let b = ((Self::b(fg) as u32 * a) + (Self::b(bg) as u32 * inv_a)) / 255;

        Self::rgb(r as u8, g as u8, b as u8)
    }
}

/// Double-buffered 32-bit off-screen rendering canvas.
pub struct Compositor {
    width: usize,
    height: usize,
    pixels: Vec<u32>,
}

impl Compositor {
    /// Creates a new off-screen canvas with the given pixel dimensions.
    pub fn new(width: usize, height: usize) -> Self {
        let total = width.saturating_mul(height);
        Self {
            width,
            height,
            pixels: vec![0u32; total],
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    /// Sets the entire canvas to a uniform background color.
    pub fn clear(&mut self, color: u32) {
        self.pixels.fill(color);
    }

    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    pub fn pixels_mut(&mut self) -> &mut [u32] {
        &mut self.pixels
    }

    /// Sets a single pixel to the given color without bounds checking.
    #[inline(always)]
    pub fn put_pixel(&mut self, x: usize, y: usize, color: u32) {
        if x < self.width && y < self.height {
            self.pixels[y * self.width + x] = color;
        }
    }

    /// Blends a pixel using its embedded alpha channel into the canvas.
    #[inline(always)]
    pub fn blend_pixel(&mut self, x: usize, y: usize, color: u32) {
        if x < self.width && y < self.height {
            let idx = y * self.width + x;
            let bg = self.pixels[idx];
            let alpha = Color::a(color);
            self.pixels[idx] = Color::blend(bg, color, alpha);
        }
    }

    /// Fills an opaque rectangular region.
    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize, color: u32) {
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        for py in y..y_end {
            let row_start = py * self.width;
            for px in x..x_end {
                self.pixels[row_start + px] = color;
            }
        }
    }

    /// Fills a translucent rectangular region with global alpha blending.
    pub fn fill_rect_alpha(&mut self, x: usize, y: usize, w: usize, h: usize, color: u32, alpha: u8) {
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        for py in y..y_end {
            let row_start = py * self.width;
            for px in x..x_end {
                let idx = row_start + px;
                let bg = self.pixels[idx];
                self.pixels[idx] = Color::blend(bg, color, alpha);
            }
        }
    }

    /// Draws an outlined rectangular border.
    pub fn draw_rect_outline(&mut self, x: usize, y: usize, w: usize, h: usize, color: u32, border: usize) {
        if w == 0 || h == 0 || border == 0 {
            return;
        }
        // Top and bottom borders
        self.fill_rect(x, y, w, border, color);
        self.fill_rect(x, y + h.saturating_sub(border), w, border, color);
        // Left and right borders
        self.fill_rect(x, y, border, h, color);
        self.fill_rect(x + w.saturating_sub(border), y, border, h, color);
    }

    /// Fills a vertical linear color gradient between two colors.
    pub fn draw_gradient_v(&mut self, x: usize, y: usize, w: usize, h: usize, top_col: u32, bottom_col: u32) {
        if h == 0 {
            return;
        }
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        let r1 = Color::r(top_col) as i32;
        let g1 = Color::g(top_col) as i32;
        let b1 = Color::b(top_col) as i32;

        let r2 = Color::r(bottom_col) as i32;
        let g2 = Color::g(bottom_col) as i32;
        let b2 = Color::b(bottom_col) as i32;

        for py in y..y_end {
            let t = (py - y) as i32;
            let total_h = h as i32;

            let r = (r1 + ((r2 - r1) * t) / total_h) as u8;
            let g = (g1 + ((g2 - g1) * t) / total_h) as u8;
            let b = (b1 + ((b2 - b1) * t) / total_h) as u8;
            let row_color = Color::rgb(r, g, b);

            let row_start = py * self.width;
            for px in x..x_end {
                self.pixels[row_start + px] = row_color;
            }
        }
    }

    /// Renders a single 8x16 font glyph.
    pub fn draw_char(&mut self, x: usize, y: usize, c: char, fg: u32, bg: Option<u32>) {
        if x + FONT_WIDTH > self.width || y + FONT_HEIGHT > self.height {
            return;
        }

        let glyph = get_char_glyph(c);
        for row in 0..FONT_HEIGHT {
            let row_byte = glyph[row];
            let py = y + row;
            let row_offset = py * self.width;

            for col in 0..FONT_WIDTH {
                let is_lit = (row_byte >> (7 - col)) & 1 == 1;
                let px = x + col;
                if is_lit {
                    self.pixels[row_offset + px] = fg;
                } else if let Some(bg_col) = bg {
                    self.pixels[row_offset + px] = bg_col;
                }
            }
        }
    }

    /// Renders an ASCII text string at the specified coordinates.
    pub fn draw_string(&mut self, mut x: usize, y: usize, text: &str, fg: u32, bg: Option<u32>) {
        for c in text.chars() {
            if x + FONT_WIDTH > self.width {
                break;
            }
            self.draw_char(x, y, c, fg, bg);
            x += FONT_WIDTH;
        }
    }

    /// Renders the mouse cursor arrow sprite at `(cx, cy)` with a 1px dark shadow outline.
    pub fn draw_cursor(&mut self, cx: usize, cy: usize) {
        // High-definition 12x19 cursor sprite bitmap:
        // 'X' = black outline (#111111), '.' = white interior (#FFFFFF), ' ' = transparent
        const CURSOR_SPRITE: [&str; 19] = [
            "X           ",
            "XX          ",
            "X.X         ",
            "X..X        ",
            "X...X       ",
            "X....X      ",
            "X.....X     ",
            "X......X    ",
            "X.......X   ",
            "X........X  ",
            "X.....XXXX  ",
            "X..X..X     ",
            "X.X X..X    ",
            "XX   X..X   ",
            "X     X..X  ",
            "       X..X ",
            "        XX  ",
            "            ",
            "            ",
        ];

        let outline_col = Color::rgb(18, 18, 18);
        let fill_col = Color::rgb(255, 255, 255);

        for (row_idx, line) in CURSOR_SPRITE.iter().enumerate() {
            let py = cy + row_idx;
            if py >= self.height {
                break;
            }
            for (col_idx, ch) in line.chars().enumerate() {
                let px = cx + col_idx;
                if px >= self.width {
                    break;
                }
                match ch {
                    'X' => self.put_pixel(px, py, outline_col),
                    '.' => self.put_pixel(px, py, fill_col),
                    _ => {}
                }
            }
        }
    }

    /// Flushes the complete in-memory canvas to the physical hardware Framebuffer.
    pub fn flip(&self, fb: &mut Framebuffer) {
        let fb_stride = fb.stride();
        let fb_is_bgr = fb.is_bgr();
        let fb_base = fb.base_ptr();
        let copy_width = self.width.min(fb.width());
        let copy_height = self.height.min(fb.height());

        for py in 0..copy_height {
            let src_row = py * self.width;
            let dst_offset = py * fb_stride * 4;

            unsafe {
                let dst_ptr = fb_base.add(dst_offset) as *mut u32;
                if !fb_is_bgr {
                    core::ptr::copy_nonoverlapping(
                        self.pixels.as_ptr().add(src_row),
                        dst_ptr,
                        copy_width,
                    );
                } else {
                    // Convert ARGB to BGRA format for hardware display
                    for px in 0..copy_width {
                        let argb = self.pixels[src_row + px];
                        let r = (argb >> 16) & 0xFF;
                        let g = (argb >> 8) & 0xFF;
                        let b = argb & 0xFF;
                        let bgra = (b << 16) | (g << 8) | r;
                        *dst_ptr.add(px) = bgra;
                    }
                }
            }
        }
    }
}
