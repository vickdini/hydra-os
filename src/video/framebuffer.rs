use super::font::{get_char_glyph, FONT_HEIGHT, FONT_WIDTH};
use super::gop::VideoModeInfo;

/// Direct linear pixel buffer controller for the hardware display.
pub struct Framebuffer {
    base_ptr: *mut u8,
    size: usize,
    width: usize,
    height: usize,
    stride: usize,
    is_bgr: bool,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// Constructs a Framebuffer instance from detected video mode info.
    pub fn new(info: VideoModeInfo) -> Self {
        Self {
            base_ptr: info.base_ptr,
            size: info.size,
            width: info.width,
            height: info.height,
            stride: info.stride,
            is_bgr: info.is_bgr,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn stride(&self) -> usize {
        self.stride
    }

    pub fn is_bgr(&self) -> bool {
        self.is_bgr
    }

    pub fn base_ptr(&self) -> *mut u8 {
        self.base_ptr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Sets a single pixel to the given RGB color.
    #[inline]
    pub fn put_pixel(&mut self, x: usize, y: usize, r: u8, g: u8, b: u8) {
        if x >= self.width || y >= self.height {
            return;
        }

        let pixel_offset = (y * self.stride + x) * 4;
        if pixel_offset + 3 >= self.size {
            return;
        }

        unsafe {
            let ptr = self.base_ptr.add(pixel_offset);
            if self.is_bgr {
                *ptr = b;
                *ptr.add(1) = g;
                *ptr.add(2) = r;
                *ptr.add(3) = 0;
            } else {
                *ptr = r;
                *ptr.add(1) = g;
                *ptr.add(2) = b;
                *ptr.add(3) = 0;
            }
        }
    }

    /// Fills a rectangular region with an RGB color.
    pub fn fill_rect(
        &mut self,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        r: u8,
        g: u8,
        b: u8,
    ) {
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        for py in y..y_end {
            for px in x..x_end {
                self.put_pixel(px, py, r, g, b);
            }
        }
    }

    /// Inverts the RGB color channels in a rectangular region (lossless reversible XOR).
    pub fn invert_rect(&mut self, x: usize, y: usize, w: usize, h: usize) {
        if x >= self.width || y >= self.height {
            return;
        }
        let x_end = (x + w).min(self.width);
        let y_end = (y + h).min(self.height);

        for py in y..y_end {
            let row_offset = (py * self.stride + x) * 4;
            let count = (x_end - x) * 4;
            if row_offset + count <= self.size {
                unsafe {
                    let ptr = self.base_ptr.add(row_offset);
                    for i in 0..count {
                        if i % 4 != 3 {
                            *ptr.add(i) = !*ptr.add(i);
                        }
                    }
                }
            }
        }
    }

    /// Clears the entire display to a single RGB color.
    pub fn clear(&mut self, r: u8, g: u8, b: u8) {
        self.fill_rect(0, 0, self.width, self.height, r, g, b);
    }

    /// Renders an 8x16 ASCII glyph at the specified pixel coordinates.
    pub fn draw_char(
        &mut self,
        x: usize,
        y: usize,
        c: char,
        fg: (u8, u8, u8),
        bg: (u8, u8, u8),
    ) {
        if x + FONT_WIDTH > self.width || y + FONT_HEIGHT > self.height {
            return;
        }

        let glyph = get_char_glyph(c);
        for row in 0..FONT_HEIGHT {
            let row_byte = glyph[row];
            for col in 0..FONT_WIDTH {
                let is_lit = (row_byte >> (7 - col)) & 1 == 1;
                let (r, g, b) = if is_lit { fg } else { bg };
                self.put_pixel(x + col, y + row, r, g, b);
            }
        }
    }

    /// Renders a text string at the given pixel coordinates.
    pub fn draw_string(
        &mut self,
        mut x: usize,
        y: usize,
        text: &str,
        fg: (u8, u8, u8),
        bg: (u8, u8, u8),
    ) {
        for c in text.chars() {
            if x + FONT_WIDTH > self.width {
                break;
            }
            self.draw_char(x, y, c, fg, bg);
            x += FONT_WIDTH;
        }
    }

    /// Scrolls the screen contents upwards by `pixel_rows` and clears the exposed bottom area.
    pub fn scroll_up(&mut self, pixel_rows: usize, bg: (u8, u8, u8)) {
        if pixel_rows == 0 || pixel_rows >= self.height {
            self.clear(bg.0, bg.1, bg.2);
            return;
        }

        let bytes_per_row = self.stride * 4;
        let copy_bytes = (self.height - pixel_rows) * bytes_per_row;
        let src_offset = pixel_rows * bytes_per_row;

        unsafe {
            core::ptr::copy(
                self.base_ptr.add(src_offset),
                self.base_ptr,
                copy_bytes,
            );
        }

        // Clear the newly opened region at the bottom of the screen
        let clear_y = self.height - pixel_rows;
        self.fill_rect(0, clear_y, self.width, pixel_rows, bg.0, bg.1, bg.2);
    }
}
