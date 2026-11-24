//! # Boot Splash: the Hydra Logo Instead of Boot Messages
//!
//! As on Windows, booting shows the Hydra logo on a black screen with a ring of moving
//! dots under it, not the kernel's messages. The messages still go to the serial port
//! (COM1) and to the console's scrollback, and the console keeps drawing them off screen
//! (the shadow framebuffer a compositor also uses, see [`super::console::release_display`]).
//!
//! The logo stays until:
//! - the desktop (KWin, at the SDDM login screen) takes the screen: it simply draws over it;
//! - the text is needed: the Hydra shell stays instead of the desktop, the desktop is not
//!   installed, Esc is pressed, the desktop has not appeared after [`REVEAL_AFTER_TICKS`],
//!   or the kernel panics. The console then shows everything printed so far.
//!
//! Boot messages on screen (no splash): the UEFI load option `debug` (or `verbose`,
//! `nosplash`) of the boot entry, or QEMU's fw_cfg `opt/hydra/boot` = `debug` or `shell`
//! (the test harnesses).
//!
//! The image is `hydra_logo.bin`, made from `assets/boot/hydra-logo.png` by
//! `tools/boot-logo/make_logo.py`. Drawing uses integer arithmetic only.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

/// The logo: `HLG1`, width, height (u16 LE), raw DEFLATE of RGB rows composited on black.
static LOGO: &[u8] = include_bytes!("hydra_logo.bin");

/// Boot messages stay off the screen (set at the start of boot when the splash is wanted).
static QUIET: AtomicBool = AtomicBool::new(false);
/// The logo is on the real screen and the dots move.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The console should take the screen back (Esc, or the timeout); done by [`poll`].
static REVEAL_DUE: AtomicBool = AtomicBool::new(false);
/// The desktop is being started (`linux plasma` set it): the logo waits for it.
static DESKTOP_STARTING: AtomicBool = AtomicBool::new(false);
/// Timer ticks (100 Hz) since the splash appeared.
static TICKS: AtomicU32 = AtomicU32::new(0);
/// The text comes back when the desktop has not taken the screen after this many ticks.
const REVEAL_AFTER_TICKS: u32 = 150 * 100;

/// The spinner, drawn by the timer interrupt; the lock also orders drawing against the
/// end of the splash.
static SPINNER: Mutex<Option<Spinner>> = Mutex::new(None);

/// Whether boot messages stay off the screen (the console checks before drawing).
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Whether the logo is showing.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Decides at the start of boot whether the logo replaces the boot messages: yes, unless
/// the boot entry asks for them (`debug`, `verbose`, `nosplash`) or QEMU's `opt/hydra/boot`
/// is `debug` or `shell`. Allocates nothing (the heap is not set up yet).
pub fn decide() {
    // The boot entry's load options (UTF-16)
    // wave11 GH: the boot words (load options, \hydra\options.txt, the start menu)
    let opts = crate::arch::bootopts::words().text();
    let mut buf = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/boot", &mut buf).map(|n| &buf[..n]);
    QUIET.store(wants_splash(Some(opts), fw), Ordering::Relaxed);
}

/// UCS-2 load options `opts` as lower-case ASCII (other characters as `?`), at most 256
/// characters: the text and its length.
pub fn options_text(opts: &[u8]) -> ([u8; 256], usize) {
    let mut text = [0u8; 256];
    let mut n = 0;
    for c in opts.chunks_exact(2) {
        if n == text.len() {
            break;
        }
        text[n] = if c[1] == 0 { c[0].to_ascii_lowercase() } else { b'?' };
        n += 1;
    }
    (text, n)
}

/// Whether the logo replaces the boot messages, given the boot entry's load options as
/// lower-case ASCII (`opts`) and QEMU's `opt/hydra/boot` fw_cfg value (`fw`).
pub fn wants_splash(opts: Option<&[u8]>, fw: Option<&[u8]>) -> bool {
    let mut want = true;
    if let Some(text) = opts {
        for word in [&b"debug"[..], b"verbose", b"nosplash"] {
            if text.windows(word.len()).any(|w| w == word) {
                want = false;
            }
        }
    }
    if let Some(v) = fw {
        if v.starts_with(b"debug") || v.starts_with(b"shell") {
            want = false;
        }
    }
    want
}

/// Shows the logo, once the framebuffer console exists ([`super::init_gop`]): the console
/// moves to a black off-screen copy and the logo goes on the real screen.
pub fn start() {
    if !is_quiet() || is_active() {
        return;
    }
    let Some((fb, w, h, stride, bgr)) = super::console::hide_behind_splash() else {
        QUIET.store(false, Ordering::Relaxed);
        return;
    };
    let screen = Screen { fb: fb as *mut u32, w, h, stride, bgr };
    // Black, then the logo centred a little above the middle
    for y in 0..h {
        for x in 0..w {
            screen.put(x, y, 0, 0, 0);
        }
    }
    let logo_h = (h * 38 / 100).min(w * 60 / 100 * 512 / 535).max(16);
    let logo_top = (h * 42 / 100).saturating_sub(logo_h / 2);
    if let Some((lw, lh, rgb)) = decode_logo() {
        let dw = (lw * logo_h / lh).max(1);
        draw_scaled(&screen, &rgb, lw, lh, (w.saturating_sub(dw)) / 2, logo_top, dw, logo_h);
    }
    // The dots: a ring under the logo
    let radius = (h / 36).max(10);
    let dot = (h * 16 / 230).max(32); // in 1/16 pixel
    let cy = (h * 78 / 100).min(h.saturating_sub(radius + 8));
    let half = radius + dot / 16 + 2;
    let spinner = Spinner {
        screen,
        x0: (w / 2).saturating_sub(half),
        y0: cy.saturating_sub(half),
        size: 2 * half,
        radius,
        dot,
        cover: alloc::vec![0u8; 4 * half * half],
    };
    let mut spinner = spinner;
    spinner.draw(0);
    *SPINNER.lock() = Some(spinner);
    TICKS.store(0, Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Release);
}

/// Timer interrupt (100 Hz, boot processor): moves the dots; asks for the text when the
/// desktop is too long in coming.
pub fn tick() {
    if !ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let t = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if t >= REVEAL_AFTER_TICKS {
        REVEAL_DUE.store(true, Ordering::Relaxed);
    }
    if t % 2 != 0 {
        return;
    }
    if let Some(mut g) = SPINNER.try_lock() {
        if ACTIVE.load(Ordering::Acquire) {
            if let Some(s) = g.as_mut() {
                s.draw(t);
            }
        }
    }
}

/// Esc was pressed: the text console comes back at the next [`poll`].
pub fn request_reveal() {
    if is_active() {
        REVEAL_DUE.store(true, Ordering::Relaxed);
    }
}

/// Called where the console waits for keys (task context): shows the text when asked.
pub fn poll() {
    if REVEAL_DUE.swap(false, Ordering::Relaxed) {
        end();
    }
}

/// `linux plasma` is starting the desktop: the logo stays until it shows.
pub fn desktop_starting() {
    DESKTOP_STARTING.store(true, Ordering::Relaxed);
}

/// Whether `linux plasma` started the desktop.
pub fn is_desktop_starting() -> bool {
    DESKTOP_STARTING.load(Ordering::Relaxed)
}

/// Stops the dots (the caller then hands the screen on).
fn stop() -> bool {
    QUIET.store(false, Ordering::Relaxed);
    let was = ACTIVE.swap(false, Ordering::AcqRel);
    if was {
        // Waits for a frame being drawn; later ticks see ACTIVE false
        *SPINNER.lock() = None;
    }
    was
}

/// A compositor takes the screen (it draws over the logo); the console stays off screen.
pub fn compositor_took() {
    stop();
}

/// The text console takes the screen back, showing what was printed during boot.
pub fn end() {
    let quiet = QUIET.load(Ordering::Relaxed);
    if !stop() {
        if quiet && !super::console::display_released() {
            // Before the framebuffer console existed: the firmware console shows the text
            crate::console::redraw_from_scrollback();
        }
        return;
    }
    super::console::reclaim_display();
    crate::console::redraw_from_scrollback();
}

/// Kernel panic: the console shows at once, over the boot logo or a desktop session,
/// without waiting on locks the panicking code may hold.
pub fn panic_reveal() {
    QUIET.store(false, Ordering::Relaxed);
    ACTIVE.store(false, Ordering::Release);
    super::console::panic_reclaim();
}

/// The real framebuffer.
struct Screen {
    fb: *mut u32,
    w: usize,
    h: usize,
    stride: usize,
    bgr: bool,
}

// The framebuffer is memory the kernel maps for good
unsafe impl Send for Screen {}

impl Screen {
    #[inline]
    fn put(&self, x: usize, y: usize, r: u8, g: u8, b: u8) {
        if x >= self.w || y >= self.h {
            return;
        }
        let v = if self.bgr {
            (r as u32) << 16 | (g as u32) << 8 | b as u32
        } else {
            (b as u32) << 16 | (g as u32) << 8 | r as u32
        };
        unsafe { self.fb.add(y * self.stride + x).write_volatile(v) };
    }
}

/// The logo's width, height and RGB pixels.
fn decode_logo() -> Option<(usize, usize, Vec<u8>)> {
    if LOGO.len() < 8 || &LOGO[..4] != b"HLG1" {
        return None;
    }
    let w = u16::from_le_bytes([LOGO[4], LOGO[5]]) as usize;
    let h = u16::from_le_bytes([LOGO[6], LOGO[7]]) as usize;
    let rgb = crate::compress::inflate_with_capacity(&LOGO[8..], w * h * 3).ok()?;
    (rgb.len() >= w * h * 3).then_some((w, h, rgb))
}

/// Draws the `sw`×`sh` RGB image scaled to `dw`×`dh` at (`x0`, `y0`): bilinear samples,
/// several per pixel when shrinking.
fn draw_scaled(s: &Screen, rgb: &[u8], sw: usize, sh: usize, x0: usize, y0: usize, dw: usize, dh: usize) {
    // Source position of a destination coordinate, in 1/256 pixel
    let step_x = (sw << 8) / dw;
    let step_y = (sh << 8) / dh;
    let nx = sw.div_ceil(dw).max(1);
    let ny = sh.div_ceil(dh).max(1);
    let sample = |fx: usize, fy: usize| -> [usize; 3] {
        // fx, fy: source position of a pixel centre, 1/256 pixel
        let fx = fx.saturating_sub(128).min((sw - 1) << 8);
        let fy = fy.saturating_sub(128).min((sh - 1) << 8);
        let (x, y) = (fx >> 8, fy >> 8);
        let (ax, ay) = (fx & 255, fy & 255);
        let x1 = (x + 1).min(sw - 1);
        let y1 = (y + 1).min(sh - 1);
        let mut out = [0usize; 3];
        for (c, o) in out.iter_mut().enumerate() {
            let p = |xx: usize, yy: usize| rgb[(yy * sw + xx) * 3 + c] as usize;
            let top = p(x, y) * (256 - ax) + p(x1, y) * ax;
            let bot = p(x, y1) * (256 - ax) + p(x1, y1) * ax;
            *o = (top * (256 - ay) + bot * ay) >> 16;
        }
        out
    };
    for oy in 0..dh {
        for ox in 0..dw {
            let mut acc = [0usize; 3];
            for j in 0..ny {
                for i in 0..nx {
                    let fx = ox * step_x + (step_x * (2 * i + 1)) / (2 * nx);
                    let fy = oy * step_y + (step_y * (2 * j + 1)) / (2 * ny);
                    let v = sample(fx, fy);
                    for c in 0..3 {
                        acc[c] += v[c];
                    }
                }
            }
            let n = nx * ny;
            s.put(x0 + ox, y0 + oy, (acc[0] / n) as u8, (acc[1] / n) as u8, (acc[2] / n) as u8);
        }
    }
}

/// sin(2πi/128) × 1024.
const SIN: [i32; 128] = [
    0, 50, 100, 150, 200, 249, 297, 345, 392, 438, 483, 526, 569, 610, 650, 688, 724, 759, 792, 822, 851, 878, 903, 926,
    946, 964, 980, 993, 1004, 1013, 1019, 1023, 1024, 1023, 1019, 1013, 1004, 993, 980, 964, 946, 926, 903, 878, 851, 822,
    792, 759, 724, 688, 650, 610, 569, 526, 483, 438, 392, 345, 297, 249, 200, 150, 100, 50, 0, -50, -100, -150, -200,
    -249, -297, -345, -392, -438, -483, -526, -569, -610, -650, -688, -724, -759, -792, -822, -851, -878, -903, -926,
    -946, -964, -980, -993, -1004, -1013, -1019, -1023, -1024, -1023, -1019, -1013, -1004, -993, -980, -964, -946, -926,
    -903, -878, -851, -822, -792, -759, -724, -688, -650, -610, -569, -526, -483, -438, -392, -345, -297, -249, -200,
    -150, -100, -50,
];

/// sin of `a` turns/1024, × 1024 (interpolated).
fn sin_turn(a: i32) -> i32 {
    let a = a.rem_euclid(1024);
    let i = (a >> 3) as usize;
    let f = a & 7;
    (SIN[i] * (8 - f) + SIN[(i + 1) % 128] * f) / 8
}

/// Integer square root.
fn isqrt(v: u32) -> u32 {
    if v < 2 {
        return v;
    }
    let mut x = v;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + v / x) / 2;
    }
    x
}

/// Dots chasing each other round a ring, slow at the top and fast at the bottom.
struct Spinner {
    screen: Screen,
    /// Top left corner and side of the square the dots move in.
    x0: usize,
    y0: usize,
    size: usize,
    /// Ring radius (pixels) and dot radius (1/16 pixel).
    radius: usize,
    dot: usize,
    /// Coverage of each pixel of the square (0..=16), redrawn each frame.
    cover: Vec<u8>,
}

/// Dots, ticks between them, and ticks per turn.
const DOTS: u32 = 5;
const DOT_DELAY: u32 = 9;
const CYCLE: u32 = 190;
/// The dots' colour.
const DOT_RGB: (u32, u32, u32) = (215, 250, 240);

impl Spinner {
    /// Draws the frame of tick `t`.
    fn draw(&mut self, t: u32) {
        let size = self.size;
        let cover = &mut self.cover;
        cover.fill(0);
        let c16 = (self.size * 8) as i32; // centre of the square, 1/16 pixel
        let r = self.radius as i32;
        let d = self.dot as i32;
        for i in 0..DOTS {
            let u = (t + CYCLE * 4 - i * DOT_DELAY) % CYCLE;
            let frac = (u * 1024 / CYCLE) as i32;
            // Eased position: speed 1 - 0.8·cos(2π·frac)
            let a = frac - sin_turn(frac) * 130 / 1024;
            let px = c16 + r * 16 * sin_turn(a) / 1024;
            let py = c16 - r * 16 * sin_turn(a + 256) / 1024;
            let reach = (d / 16 + 2) as i32;
            let (bx, by) = (px / 16, py / 16);
            for y in (by - reach).max(0)..=(by + reach).min(self.size as i32 - 1) {
                for x in (bx - reach).max(0)..=(bx + reach).min(self.size as i32 - 1) {
                    let dx = x * 16 + 8 - px;
                    let dy = y * 16 + 8 - py;
                    let dist = isqrt((dx * dx + dy * dy) as u32) as i32;
                    let cov = (d + 8 - dist).clamp(0, 16) as u8;
                    let slot = &mut cover[y as usize * self.size + x as usize];
                    *slot = (*slot).max(cov);
                }
            }
        }
        for y in 0..size {
            for x in 0..size {
                let c = self.cover[y * size + x] as u32;
                let (r, g, b) = DOT_RGB;
                self.screen.put(self.x0 + x, self.y0 + y, (r * c / 16) as u8, (g * c / 16) as u8, (b * c / 16) as u8);
            }
        }
    }
}
