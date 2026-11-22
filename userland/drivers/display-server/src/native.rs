//! # The native core: pictures, the cursor and the vertical blank
//!
//! `docs/display-input-design.md` section 5 ("the native core interface inside the display
//! service"): what is not Linux about showing a picture. The Linux DRM layer (`kms.rs`)
//! decides *what* shows; this module puts it on a [`Target`] (the screen the kernel lends,
//! or memory in the host tests):
//!
//! - [`copy_rect`]: a rectangle of a client's buffer onto the screen (only the damaged rows
//!   and columns when the caller knows them), swapping red and blue for an RGB screen;
//! - [`compose_cursor`]: the cursor's area recomposed from the picture under it with the
//!   cursor blended on top (premultiplied alpha, as DRM's cursor planes); the screen is
//!   never read back (a real framebuffer is slow to read);
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

/// Copies rows `y0..y1`, columns `x0..x1` of the screen from `src` seen at `crtc` (the
/// picture's pixel that shows at the screen's top left); black where there is no picture.
/// The screen is only written, never read back, and only through raw pointers (the kernel
/// may point it elsewhere at any moment); an RGB screen gets each row swapped in RAM first.
#[allow(clippy::too_many_arguments)]
pub fn copy_rect(t: &Target, src: Option<&Src>, crtc: (u32, u32), x0: u32, y0: u32, x1: u32, y1: u32) {
    let (x1, y1) = (x1.min(t.width).min(t.stride as u32), y1.min(t.height));
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let len = (x1 - x0) as usize * 4;
    let mut row = if t.bgr { alloc::vec::Vec::new() } else { alloc::vec![0u8; len] };
    for y in y0..y1 {
        // (y, x0..x1) lies inside the target's visible area
        let dst = t.ptr.wrapping_add((y as usize * t.stride + x0 as usize) * 4);
        let pic = src.map(|s| (s, crtc.0.checked_add(x0), crtc.1.checked_add(y)));
        if t.bgr {
            let n = match pic {
                Some((s, Some(fx), Some(fy))) => copy_row(s, fx, fy, dst, len),
                _ => 0,
            };
            // SAFETY: the rest of the row inside the visible area
            unsafe { core::ptr::write_bytes(dst.add(n), 0, len - n) };
        } else {
            let n = match pic {
                Some((s, Some(fx), Some(fy))) => copy_row(s, fx, fy, row.as_mut_ptr(), len),
                _ => 0,
            };
            row[n..].fill(0);
            swap_rb(&mut row[..n]);
            // SAFETY: as above
            unsafe { core::ptr::copy_nonoverlapping(row.as_ptr(), dst, len) };
        }
    }
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

/// Recomposes the screen area of the cursor at `(x, y)`: the picture under it (as
/// [`copy_rect`] would), then the cursor blended on top. Returns the area drawn
/// `(x, y, w, h)` (to be repaired from the picture when the cursor moves).
pub fn compose_cursor(t: &Target, src: Option<&Src>, crtc: (u32, u32), cur: &Cursor, x: i32, y: i32) -> (i32, i32, u32, u32) {
    let mut row = alloc::vec![0u8; cur.w as usize * 4];
    for r in 0..cur.h as i32 {
        let sy = y + r;
        if sy < 0 || sy >= t.height as i32 {
            continue;
        }
        let c0 = (-x).max(0);
        let c1 = (cur.w as i32).min(t.width as i32 - x);
        if c0 >= c1 {
            continue;
        }
        let (sx0, n) = ((x + c0) as u32, (c1 - c0) as usize);
        let line = &mut row[..n * 4];
        let got = match src.map(|s| (s, crtc.0.checked_add(sx0), crtc.1.checked_add(sy as u32))) {
            Some((s, Some(fx), Some(fy))) => copy_row(s, fx, fy, line.as_mut_ptr(), n * 4),
            _ => 0,
        };
        line[got..].fill(0);
        let cstart = r as u64 * cur.w as u64 * 4 + c0 as u64 * 4;
        if cstart + n as u64 * 4 <= cur.len {
            // SAFETY: inside the cursor's buffer (checked above)
            let cpx = unsafe { core::slice::from_raw_parts(cur.base.add(cstart as usize), n * 4) };
            for (d, s) in line.chunks_exact_mut(4).zip(cpx.chunks_exact(4)) {
                blend(d, s);
            }
        }
        if !t.bgr {
            swap_rb(line);
        }
        // SAFETY: (sy, sx0..sx0 + n) lies inside the target's visible area
        unsafe { core::ptr::copy_nonoverlapping(line.as_ptr(), t.ptr.add((sy as usize * t.stride + sx0 as usize) * 4), n * 4) };
    }
    (x, y, cur.w, cur.h)
}

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
