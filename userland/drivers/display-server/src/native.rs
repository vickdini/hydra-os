//! # The native core: pictures, the cursor and the vertical blank
//!
//! `docs/display-input-design.md` section 5 ("the native core interface inside the display
//! service"): what is not Linux about showing a picture. The Linux DRM layer (`kms.rs`)
//! decides *what* shows; this module puts it on a [`Target`] (the screen the kernel lends,
//! or memory in the host tests):
//!
//! - [`draw_rect`] (wave 11): a rectangle of the screen made right: each row composed in
//!   RAM from a client's buffer (only the damaged rows and columns when the caller knows
//!   them) with the cursor blended on top (premultiplied alpha, as DRM's cursor planes),
//!   red and blue swapped for an RGB screen, then written only where it differs from
//!   what the screen shows ([`Shadow`]); the screen is never read back (a real
//!   framebuffer is slow to read) and never shows the picture without its cursor;
//! - [`Vblank`]: the emulated vertical blank of the firmware framebuffer (60 Hz): a flip
//!   completes at the first blank after its picture was copied, so a compositor draws at
//!   most 60 pictures a second.
//!
//! A real graphics driver later replaces the copies with a scanout address and the emulated
//! blank with its interrupt; the interface to `kms.rs` ([`Screen`]) stays.

/// The screen being drawn on: `stride` pixels per line, 4 bytes per pixel.
#[derive(Clone, Copy)]
pub struct Target {
    /// First pixel.
    pub ptr: *mut u8,
    /// Pixels per line in memory.
    pub stride: usize,
    /// Visible size.
    pub width: u32,
    /// Visible lines.
    pub height: u32,
    /// Bytes B, G, R, X in memory (DRM's XRGB8888 as it is); otherwise red and blue swap.
    pub bgr: bool,
}

/// A client buffer as a picture: `len` bytes at `base` (the service's view of it), the
/// picture starting `offset` bytes in, `pitch` bytes per line, `width` x `height` pixels.
#[derive(Clone, Copy)]
pub struct Src {
    /// The buffer's first byte.
    pub base: *const u8,
    /// Its size.
    pub len: u64,
    /// The picture's first byte.
    pub offset: u64,
    /// Bytes per line.
    pub pitch: u32,
    /// Pixels per line.
    pub width: u32,
    /// Lines.
    pub height: u32,
}

/// A cursor image: `w` x `h` premultiplied ARGB pixels, `w * 4` bytes per line.
#[derive(Clone, Copy)]
pub struct Cursor {
    /// The image's first byte.
    pub base: *const u8,
    /// Its buffer's size.
    pub len: u64,
    /// Width.
    pub w: u32,
    /// Height.
    pub h: u32,
}

/// What the Linux layer needs from the screen.
pub trait Screen: Send {
    /// Visible size.
    fn size(&self) -> (u32, u32);
    /// Asks the kernel for the screen (a session's first picture): `SCREEN_SHOWN` or
    /// `SCREEN_HIDDEN`, or a negative errno.
    fn take(&mut self) -> i64;
    /// Gives the screen back to the console.
    fn give(&mut self);
    /// The state as last told by the kernel (`SCREEN_*`).
    fn state(&self) -> u32;
    /// Starts drawing: the target if the screen shows the session now (the kernel may take
    /// it back at any moment; [`Screen::end`] must follow).
    fn begin(&mut self) -> Option<Target>;
    /// Drawing ends.
    fn end(&mut self);
    /// The monotonic clock in nanoseconds.
    fn now_ns(&self) -> u64;
}

/// Copies picture row `fy` from column `fx` to `dst` (room for `cap` bytes) as far as the
/// picture goes; the bytes written.
fn copy_row(s: &Src, fx: u32, fy: u32, dst: *mut u8, cap: usize) -> usize {
    if fy >= s.height || fx >= s.width {
        return 0;
    }
    let want = (cap / 4).min((s.width - fx) as usize) * 4;
    let Some(start) = (fy as u64).checked_mul(s.pitch as u64).and_then(|r| r.checked_add(s.offset)).and_then(|r| r.checked_add(fx as u64 * 4)) else { return 0 };
    if start >= s.len {
        return 0;
    }
    let n = want.min((s.len - start) as usize) & !3;
    // SAFETY: `start..start + n` lies inside the buffer; `dst` has room for `cap >= n` bytes
    unsafe { core::ptr::copy_nonoverlapping(s.base.add(start as usize), dst, n) };
    n
}

/// Swaps bytes 0 and 2 of each pixel (BGRX <-> RGBX).
fn swap_rb(px: &mut [u8]) {
    for p in px.chunks_exact_mut(4) {
        p.swap(0, 2);
    }
}

/// Blends premultiplied source pixel `s` (B, G, R, A) over `d` (B, G, R, X), in place.
pub fn blend(d: &mut [u8], s: &[u8]) {
    let a = s[3] as u32;
    if a == 0 {
        return;
    }
    for i in 0..3 {
        d[i] = (s[i] as u32 + d[i] as u32 * (255 - a) / 255).min(255) as u8;
    }
}

// wave11 GG begin
/// What the screen shows, kept in RAM (`width` x `height` pixels as the screen holds them:
/// BGRX, or RGBX on an RGB screen). The screen is written only where a newly composed row
/// differs from this copy, in whole blocks of [`BLOCK`] pixels (64 bytes: one
/// write-combining burst). Not valid until a whole picture went out (or after the console
/// drew on the screen): then rows are written whole.
pub struct Shadow {
    px: alloc::vec::Vec<u8>,
    width: u32,
    height: u32,
    valid: bool,
}

/// Pixels per compared and written block.
pub const BLOCK: usize = 16;
/// Unchanged blocks between two changed ones that are written anyway (one write instead
/// of two short ones).
const GAP: usize = 2;

impl Shadow {
    /// A copy for a `width` x `height` screen (its memory comes with the first picture).
    pub const fn new(width: u32, height: u32) -> Self {
        Self { px: alloc::vec::Vec::new(), width, height, valid: false }
    }

    /// The screen was drawn on by someone else (the console): the next picture is
    /// written whole.
    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Whether the copy matches the screen.
    #[allow(dead_code)]
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    fn ensure(&mut self) {
        let n = self.width as usize * self.height as usize * 4;
        if self.px.len() != n {
            self.px = alloc::vec![0u8; n];
            self.valid = false;
        }
    }
}

/// The cursor where it is on the screen.
#[derive(Clone, Copy)]
pub struct Placed<'a> {
    /// Its image.
    pub cur: &'a Cursor,
    /// Its top left corner on the screen.
    pub x: i32,
    /// Its top left corner on the screen.
    pub y: i32,
}

/// How much of a draw reached the screen.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Drawn {
    /// Pixels composed (the rectangle's area).
    pub composed: u64,
    /// Pixels written to the screen.
    pub written: u64,
}

/// Blends the cursor's part of screen row `sy` that falls in columns `x0..x0 + line/4`
/// over `line` (BGRX, the picture).
fn blend_cursor_row(line: &mut [u8], x0: u32, sy: i32, p: &Placed) {
    let r = sy - p.y;
    if r < 0 || r >= p.cur.h as i32 {
        return;
    }
    let n = (line.len() / 4) as i32;
    // Columns of the line the cursor covers: [c0, c1) in line coordinates
    let c0 = (p.x - x0 as i32).max(0);
    let c1 = (p.x + p.cur.w as i32 - x0 as i32).min(n);
    if c0 >= c1 {
        return;
    }
    let cx0 = (x0 as i32 + c0 - p.x) as u64;
    let cstart = r as u64 * p.cur.w as u64 * 4 + cx0 * 4;
    let len = (c1 - c0) as usize * 4;
    if cstart + len as u64 > p.cur.len {
        return;
    }
    // SAFETY: inside the cursor's buffer (checked above)
    let cpx = unsafe { core::slice::from_raw_parts(p.cur.base.add(cstart as usize), len) };
    let d = &mut line[c0 as usize * 4..c1 as usize * 4];
    for (d, s) in d.chunks_exact_mut(4).zip(cpx.chunks_exact(4)) {
        blend(d, s);
    }
}

/// Puts rows `y0..y1`, columns `x0..x1` of the screen right: each row is composed in RAM
/// first (the picture from `src` seen at `crtc`, black where there is none, the cursor
/// blended on top where it is, red and blue swapped for an RGB screen), then only the
/// blocks that differ from what the screen shows ([`Shadow`]) are written. So the screen
/// never shows a half-made row: the cursor is never erased to be drawn again (no
/// flicker), and an unchanged picture or a small cursor move costs (almost) no writes to
/// the framebuffer, which on real hardware is slow memory. The screen is never read.
#[allow(clippy::too_many_arguments)]
pub fn draw_rect(t: &Target, sh: &mut Shadow, src: Option<&Src>, crtc: (u32, u32), cursor: Option<&Placed>, x0: u32, y0: u32, x1: u32, y1: u32) -> Drawn {
    let mut out = Drawn::default();
    let (x1, y1) = (x1.min(t.width).min(t.stride as u32).min(sh.width), y1.min(t.height).min(sh.height));
    if x0 >= x1 || y0 >= y1 {
        return out;
    }
    sh.ensure();
    let whole = x0 == 0 && y0 == 0 && x1 == sh.width.min(t.width) && y1 == sh.height.min(t.height);
    let compare = sh.valid;
    let n = (x1 - x0) as usize;
    let mut row = alloc::vec![0u8; n * 4];
    for y in y0..y1 {
        let got = match src.map(|s| (s, crtc.0.checked_add(x0), crtc.1.checked_add(y))) {
            Some((s, Some(fx), Some(fy))) => copy_row(s, fx, fy, row.as_mut_ptr(), n * 4),
            _ => 0,
        };
        row[got..].fill(0);
        if let Some(p) = cursor {
            blend_cursor_row(&mut row, x0, y as i32, p);
        }
        if !t.bgr {
            swap_rb(&mut row);
        }
        out.composed += n as u64;
        let so = (y as usize * sh.width as usize + x0 as usize) * 4;
        let shown = &mut sh.px[so..so + n * 4];
        let dst = t.ptr.wrapping_add((y as usize * t.stride + x0 as usize) * 4);
        if !compare {
            shown.copy_from_slice(&row);
            // SAFETY: (y, x0..x1) lies inside the target's visible area
            unsafe { core::ptr::copy_nonoverlapping(row.as_ptr(), dst, n * 4) };
            out.written += n as u64;
            continue;
        }
        if shown[..] == row[..] {
            continue;
        }
        // Runs of changed blocks (short gaps of unchanged ones included). Blocks follow the
        // screen's own 16-pixel grid (absolute columns), so a write covers whole 64-byte
        // lines (one write-combining burst each), whatever column the rectangle starts at
        let off = x0 as usize % BLOCK;
        let blocks = (n + off).div_ceil(BLOCK);
        let span = |i: usize| ((i * BLOCK).saturating_sub(off) * 4, ((i + 1) * BLOCK - off).min(n) * 4);
        let mut b = 0;
        while b < blocks {
            let differs = |i: usize, shown: &[u8]| {
                let (s, e) = span(i);
                shown[s..e] != row[s..e]
            };
            if !differs(b, shown) {
                b += 1;
                continue;
            }
            let start = b;
            let mut end = b + 1;
            let mut k = end;
            while k < blocks && k <= end + GAP {
                if differs(k, shown) {
                    end = k + 1;
                }
                k += 1;
            }
            let (s, e) = (span(start).0, span(end - 1).1);
            shown[s..e].copy_from_slice(&row[s..e]);
            // SAFETY: bytes s..e of the row lie inside the target's visible area
            unsafe { core::ptr::copy_nonoverlapping(row.as_ptr().add(s), dst.add(s), e - s) };
            out.written += ((e - s) / 4) as u64;
            b = end;
        }
    }
    if whole {
        sh.valid = true;
    }
    // The write-combining buffers drained now, not at some later instruction: the picture
    // (or the cursor's last partial line) reaches the screen at once
    if out.written > 0 {
        store_fence();
    }
    out
}

/// `sfence`: every earlier store, write-combining ones included, is visible before any
/// later one.
fn store_fence() {
    // SAFETY: an ordering instruction, no memory operands
    unsafe { core::arch::asm!("sfence", options(nostack, preserves_flags)) };
}
// wave11 GG end

/// The emulated vertical blank: blank `k` happens at `k * period_ns` on the monotonic clock.
#[derive(Clone, Copy)]
pub struct Vblank {
    /// Nanoseconds between blanks (16,666,667 at 60 Hz).
    pub period_ns: u64,
}

impl Vblank {
    /// The blank for a refresh rate of `mhz` millihertz.
    pub fn new(mhz: u32) -> Self {
        Self { period_ns: 1_000_000_000_000 / mhz.max(1) as u64 }
    }

    /// The number of the first blank strictly after `t_ns`.
    pub fn next_after(&self, t_ns: u64) -> u64 {
        t_ns / self.period_ns + 1
    }

    /// When blank `k` happens.
    pub fn time_of(&self, k: u64) -> u64 {
        k * self.period_ns
    }

    /// The blank counter at `t_ns` (the last blank at or before it).
    pub fn count_at(&self, t_ns: u64) -> u64 {
        t_ns / self.period_ns
    }
}
