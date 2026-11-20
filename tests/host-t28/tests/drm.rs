//! `drm.rs`: the DRM/KMS device: version and capabilities, master rights, dumb buffers
//! and their mmap space, framebuffers, mode setting onto the (fake) boot framebuffer
//! with format conversion, page flips and their events, the cursor (alpha blended),
//! properties and blobs, PRIME export/import, VT switches and the session-gone check.
//!
//! The display state is one global: every test holds `common::serial()` and drops all
//! its files before it ends. Buffers come from the shared frame pool.

mod common;

use std::sync::Arc;

use hydra_hosttests_t28::compat::linux::chardev::{makedev, CharDevice};
use hydra_hosttests_t28::compat::linux::{drm, evdev};
use hydra_hosttests_t28::fake;
use hydra_hosttests_t28::fs::FileDescriptor;
use hydra_hosttests_t28::memory::frame_allocator::FRAME_ALLOCATOR;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ENXIO: i64 = -6;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EOPNOTSUPP: i64 = -95;
const ERESTARTSYS: i64 = -512;

const W: u32 = 64;
const H: u32 = 48;
const CRTC: u32 = 40;
const ENCODER: u32 = 41;
const CONNECTOR: u32 = 42;
const XR24: u32 = 0x3432_5258;
const AR24: u32 = 0x3432_5241;

type Dev = Arc<dyn CharDevice>;

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = common::serial();
    common::global_frames();
    let fresh = fake::DISPLAY.lock().unwrap().is_none();
    if fresh {
        fake::set_display(W as usize, H as usize, false);
    }
    fake::with_display(|d| {
        d.fb.fill(0);
        d.refuse = false;
        d.panicked = false;
        d.bgr = false;
    });
    fake::SIGNAL_PENDING.set(false);
    fake::clear_on_wait();
    g
}

fn open() -> Dev {
    drm::open(0, true).unwrap()
}

fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn get32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn get64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// `ioctl(DRM_IOWR(nr, b.len()))` with `b` in and out.
fn io(f: &Dev, nr: u64, b: &mut [u8]) -> i64 {
    let cmd = (3u64 << 30) | ((b.len() as u64) << 16) | (0x64 << 8) | nr;
    f.ioctl(cmd, b.as_mut_ptr() as u64)
}
/// A request without argument (`DRM_IO(nr)`).
fn io0(f: &Dev, nr: u64) -> i64 {
    f.ioctl((0x64 << 8) | nr, 0)
}

/// A dumb buffer: (handle, pitch, size).
fn dumb(f: &Dev, w: u32, h: u32) -> (u32, u32, u64) {
    let mut b = [0u8; 32];
    put32(&mut b, 0, h);
    put32(&mut b, 4, w);
    put32(&mut b, 8, 32);
    assert_eq!(io(f, 0xB2, &mut b), 0);
    (get32(&b, 16), get32(&b, 20), get64(&b, 24))
}

/// ADDFB2 of a whole buffer.
fn addfb2(f: &Dev, handle: u32, w: u32, h: u32, pitch: u32, format: u32) -> Result<u32, i64> {
    let mut b = [0u8; 104];
    put32(&mut b, 4, w);
    put32(&mut b, 8, h);
    put32(&mut b, 12, format);
    put32(&mut b, 20, handle);
    put32(&mut b, 36, pitch);
    match io(f, 0xB8, &mut b) {
        0 => Ok(get32(&b, 0)),
        e => Err(e),
    }
}

/// The host address of byte `off` of the buffer `handle` (through the device's mmap space).
fn bo_ptr(f: &Dev, handle: u32, off: u64) -> *mut u8 {
    let mut b = [0u8; 16];
    put32(&mut b, 0, handle);
    assert_eq!(io(f, 0xB3, &mut b), 0);
    let pgoff = get64(&b, 8) / 4096 + off / 4096;
    let frame = f.mmap_object().unwrap().get_page(pgoff).expect("page");
    (frame.start_address().as_u64() + off % 4096) as *mut u8
}

/// Fills buffer `handle` (pitch `pitch`) with pixel `px` (B, G, R, A bytes).
fn fill(f: &Dev, handle: u32, pitch: u32, h: u32, px: [u8; 4]) {
    for y in 0..h as u64 {
        for x in 0..(pitch / 4) as u64 {
            let off = y * pitch as u64 + x * 4;
            unsafe { core::ptr::copy_nonoverlapping(px.as_ptr(), bo_ptr(f, handle, off), 4) };
        }
    }
}

fn setcrtc(f: &Dev, fb: u32, x: u32, y: u32, w: u32, h: u32) -> i64 {
    let mut conn = [CONNECTOR];
    let mut b = [0u8; 104];
    put64(&mut b, 0, conn.as_mut_ptr() as u64);
    put32(&mut b, 8, 1);
    put32(&mut b, 12, CRTC);
    put32(&mut b, 16, fb);
    put32(&mut b, 20, x);
    put32(&mut b, 24, y);
    put32(&mut b, 32, 1);
    b[40..42].copy_from_slice(&(w as u16).to_le_bytes());
    b[50..52].copy_from_slice(&(h as u16).to_le_bytes());
    io(f, 0xA2, &mut b)
}

fn frames_used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

#[test]
fn open_and_identity() {
    let _g = setup();
    assert_eq!(drm::open(1, false).err(), Some(ENXIO));
    let f = open();
    assert_eq!(f.rdev(), makedev(226, 0));
    assert_eq!(f.path(), "/dev/dri/card0");
    assert!(f.nonblock());
    f.set_nonblock(false);
    assert!(!f.nonblock());
    assert_eq!(f.poll_events(), 0x4);
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    f.add_wait_queues(&mut ws);
    assert_eq!(ws.queues.len(), 1);
    // Not a DRM request
    assert_eq!(f.ioctl(0x5401, 0), -25);
    // VERSION: numbers and the three strings, cut to the caller's lengths
    let (mut name, mut date, mut desc) = ([0u8; 4], [0u8; 32], [0u8; 64]);
    let mut b = [0u8; 64];
    put64(&mut b, 16, name.len() as u64);
    put64(&mut b, 24, name.as_mut_ptr() as u64);
    put64(&mut b, 32, date.len() as u64);
    put64(&mut b, 40, date.as_mut_ptr() as u64);
    put64(&mut b, 48, desc.len() as u64);
    put64(&mut b, 56, desc.as_mut_ptr() as u64);
    assert_eq!(io(&f, 0x00, &mut b), 0);
    assert_eq!((get32(&b, 0), get32(&b, 4)), (1, 0));
    assert_eq!(&name, b"hydr");
    assert_eq!(get64(&b, 16), 8);
    assert_eq!(&date[..8], b"20261031");
    assert_eq!(&desc[..25], b"Hydra kernel mode setting");
    // Lengths only (null pointers)
    let mut b = [0u8; 64];
    assert_eq!(io(&f, 0x00, &mut b), 0);
    assert_eq!(get64(&b, 48), 25);
    // A bad string pointer faults
    put64(&mut b, 16, 4);
    put64(&mut b, 24, fake::BAD_PTR);
    assert_eq!(io(&f, 0x00, &mut b), EFAULT);
    // GET_UNIQUE: the display adapter's PCI slot (no adapter found: QEMU's default)
    let mut slot = [0u8; 32];
    let mut b = [0u8; 16];
    put64(&mut b, 0, 32);
    put64(&mut b, 8, slot.as_mut_ptr() as u64);
    assert_eq!(io(&f, 0x01, &mut b), 0);
    assert_eq!(get64(&b, 0), 12);
    assert_eq!(&slot[..12], b"0000:00:02.0");
    put64(&mut b, 8, fake::BAD_PTR);
    assert_eq!(io(&f, 0x01, &mut b), EFAULT);
    // GET_MAGIC
    let mut b = [0u8; 4];
    assert_eq!(io(&f, 0x02, &mut b), 0);
    assert!(get32(&b, 0) > 0);
    // Faulting argument pointers
    let cmd = (3u64 << 30) | (16 << 16) | (0x64 << 8) | 0x0c;
    assert_eq!(f.ioctl(cmd, fake::BAD_PTR), EFAULT);
    assert_eq!(f.ioctl(cmd, 0), EFAULT);
    // Unknown request numbers
    assert_eq!(io(&f, 0xFF, &mut [0u8; 8]), EINVAL);
}

#[test]
fn set_version_caps_and_client_caps() {
    let _g = setup();
    let f = open();
    let mut b = [0u8; 16];
    put32(&mut b, 0, u32::MAX); // -1: just ask
    assert_eq!(io(&f, 0x07, &mut b), 0);
    assert_eq!((get32(&b, 0), get32(&b, 4), get32(&b, 8)), (1, 4, 1));
    put32(&mut b, 0, 1);
    put32(&mut b, 4, 3);
    assert_eq!(io(&f, 0x07, &mut b), 0);
    put32(&mut b, 0, 1);
    put32(&mut b, 4, 5);
    assert_eq!(io(&f, 0x07, &mut b), EINVAL);
    put32(&mut b, 0, 2);
    assert_eq!(io(&f, 0x07, &mut b), EINVAL);
    for (cap, want) in [(1u64, 1u64), (2, 1), (3, 24), (4, 0), (5, 3), (6, 1), (7, 0), (8, 64), (9, 64), (0x10, 0), (0x11, 0), (0x12, 1), (0x13, 0), (0x14, 0), (0x15, 0)] {
        let mut b = [0u8; 16];
        put64(&mut b, 0, cap);
        assert_eq!(io(&f, 0x0c, &mut b), 0, "cap {cap:#x}");
        assert_eq!(get64(&b, 8), want, "cap {cap:#x}");
    }
    let mut b = [0u8; 16];
    put64(&mut b, 0, 0x99);
    assert_eq!(io(&f, 0x0c, &mut b), EINVAL);
    let cc = |cap: u64, v: u64| {
        let mut b = [0u8; 16];
        put64(&mut b, 0, cap);
        put64(&mut b, 8, v);
        io(&f, 0x0d, &mut b)
    };
    assert_eq!(cc(1, 1), 0);
    assert_eq!(cc(4, 1), 0);
    assert_eq!(cc(3, 1), EOPNOTSUPP);
    assert_eq!(cc(9, 1), EINVAL);
    // Universal planes show the two planes
    let mut planes = [0u32; 4];
    let mut b = [0u8; 16];
    put64(&mut b, 0, planes.as_mut_ptr() as u64);
    put32(&mut b, 8, 4);
    assert_eq!(io(&f, 0xB5, &mut b), 0);
    assert_eq!(get32(&b, 8), 0);
    assert_eq!(cc(2, 1), 0);
    put32(&mut b, 8, 4);
    assert_eq!(io(&f, 0xB5, &mut b), 0);
    assert_eq!(get32(&b, 8), 2);
    assert_eq!(&planes[..2], &[43, 44]);
    assert_eq!(cc(2, 0), 0);
}

#[test]
fn master_rights() {
    let _g = setup();
    let a = open();
    let b = open();
    // The first opener is master
    assert_eq!(io(&a, 0x11, &mut [0u8; 4]), 0);
    assert_eq!(io(&b, 0x11, &mut [0u8; 4]), EACCES);
    assert_eq!(io0(&b, 0x1e), EBUSY);
    assert_eq!(io0(&b, 0x1f), EINVAL);
    // Mastership moves after DROP_MASTER
    assert_eq!(io0(&a, 0x1f), 0);
    assert_eq!(io0(&b, 0x1e), 0);
    assert_eq!(io(&b, 0x11, &mut [0u8; 4]), 0);
    // SET_MASTER again by the master: fine
    assert_eq!(io0(&b, 0x1e), 0);
    assert!(drm::showing());
    // Non-masters cannot set modes, flip, move the cursor or set properties
    assert_eq!(setcrtc(&a, 100, 0, 0, W, H), EACCES);
    assert_eq!(io(&a, 0xB0, &mut [0u8; 24]), EACCES);
    assert_eq!(io(&a, 0xA3, &mut [0u8; 28]), EACCES);
    let mut sp = [0u8; 16];
    put32(&mut sp, 8, 1);
    put32(&mut sp, 12, CONNECTOR);
    assert_eq!(io(&a, 0xAB, &mut sp), EACCES);
    drop(b);
    // The master closed: the console has the screen again, the next opener may take it
    assert!(!drm::showing());
    assert_eq!(io0(&a, 0x1e), 0);
    drop(a);
}

#[test]
fn dumb_buffers_and_their_mmap_space() {
    let _g = setup();
    let before = frames_used();
    let f = open();
    let (h1, pitch, size) = dumb(&f, 10, 3);
    assert_eq!(pitch, 64); // 40 bytes rounded to 64
    assert_eq!(size, 4096);
    let (h2, pitch2, size2) = dumb(&f, 100, 50);
    assert_eq!((pitch2, size2), (448, (448 * 50 + 4095) & !4095));
    assert_ne!(h1, h2);
    assert_eq!(frames_used() - before, (size + size2) / 4096 * 4096);
    // Invalid sizes
    for (w, h, bpp) in [(0, 1, 32), (1, 0, 32), (1, 1, 0), (1, 1, 33), (8193, 1, 32), (1, 8193, 32)] {
        let mut b = [0u8; 32];
        put32(&mut b, 0, h);
        put32(&mut b, 4, w);
        put32(&mut b, 8, bpp);
        assert_eq!(io(&f, 0xB2, &mut b), EINVAL);
    }
    // MAP_DUMB: offsets far apart, the pages of each buffer in its range, a guard page
    let off = |h: u32| {
        let mut b = [0u8; 16];
        put32(&mut b, 0, h);
        assert_eq!(io(&f, 0xB3, &mut b), 0);
        get64(&b, 8) / 4096
    };
    let (p1, p2) = (off(h1), off(h2));
    assert!(p2 > p1 + 1);
    let space = f.mmap_object().unwrap();
    assert!(space.get_page(p1).is_some());
    assert!(space.get_page(p1 + 1).is_none()); // the guard page
    assert!(space.get_page(p1 - 1).is_none() || p1 - 1 >= 0x10_0000);
    assert!(space.get_page(0).is_none());
    // Writes through one mapping are seen by the other's frames
    unsafe { *bo_ptr(&f, h2, 4096 + 7) = 0x5A };
    let frame = space.get_page(p2 + 1).unwrap();
    assert_eq!(unsafe { *((frame.start_address().as_u64() + 7) as *const u8) }, 0x5A);
    let mut b = [0u8; 16];
    put32(&mut b, 0, 999);
    assert_eq!(io(&f, 0xB3, &mut b), ENOENT);
    // DESTROY_DUMB and GEM_CLOSE drop the handles; the frames go when the last user does
    let mut b = [0u8; 4];
    put32(&mut b, 0, h1);
    assert_eq!(io(&f, 0xB4, &mut b), 0);
    assert_eq!(io(&f, 0xB4, &mut b), ENOENT);
    assert!(space.get_page(p1).is_none());
    let mut b = [0u8; 8];
    put32(&mut b, 0, h2);
    assert_eq!(io(&f, 0x09, &mut b), 0);
    assert_eq!(io(&f, 0x09, &mut b), EINVAL);
    assert_eq!(frames_used(), before);
    drop(f);
}

#[test]
fn framebuffers() {
    let _g = setup();
    let f = open();
    let other = open();
    let (h, pitch, _) = dumb(&f, W, H);
    // Formats, sizes and pitches are checked
    assert_eq!(addfb2(&f, h, W, H, pitch, 0x3231_564e), Err(EINVAL));
    assert_eq!(addfb2(&f, 77, W, H, pitch, XR24), Err(ENOENT));
    assert_eq!(addfb2(&f, h, 0, H, pitch, XR24), Err(EINVAL));
    assert_eq!(addfb2(&f, h, W, 0, pitch, XR24), Err(EINVAL));
    assert_eq!(addfb2(&f, h, W, H, W * 4 - 1, XR24), Err(EINVAL));
    assert_eq!(addfb2(&f, h, W, H + 1, pitch, XR24), Err(EINVAL));
    // A modifier other than linear
    let mut b = [0u8; 104];
    put32(&mut b, 4, W);
    put32(&mut b, 8, H);
    put32(&mut b, 12, XR24);
    put32(&mut b, 16, 2);
    put32(&mut b, 20, h);
    put32(&mut b, 36, pitch);
    put64(&mut b, 72, 1);
    assert_eq!(io(&f, 0xB8, &mut b), EINVAL);
    let fb = addfb2(&f, h, W, H, pitch, AR24).unwrap();
    // Legacy ADDFB: bpp/depth pairs
    let mut b = [0u8; 28];
    put32(&mut b, 4, W);
    put32(&mut b, 8, H);
    put32(&mut b, 12, pitch);
    put32(&mut b, 16, 32);
    put32(&mut b, 20, 24);
    put32(&mut b, 24, h);
    assert_eq!(io(&f, 0xAE, &mut b), 0);
    let fb_legacy = get32(&b, 0);
    put32(&mut b, 20, 16);
    assert_eq!(io(&f, 0xAE, &mut b), EINVAL);
    put32(&mut b, 20, 32);
    assert_eq!(io(&f, 0xAE, &mut b), 0);
    // GETFB / GETFB2: the handle only for the owner
    let mut b = [0u8; 28];
    put32(&mut b, 0, fb);
    assert_eq!(io(&f, 0xAD, &mut b), 0);
    assert_eq!((get32(&b, 4), get32(&b, 8), get32(&b, 12), get32(&b, 16), get32(&b, 20), get32(&b, 24)), (W, H, pitch, 32, 32, h));
    assert_eq!(io(&other, 0xAD, &mut b), 0);
    assert_eq!(get32(&b, 24), 0);
    put32(&mut b, 0, fb_legacy);
    assert_eq!(io(&f, 0xAD, &mut b), 0);
    assert_eq!(get32(&b, 20), 24);
    put32(&mut b, 0, 5);
    assert_eq!(io(&f, 0xAD, &mut b), ENOENT);
    let mut b = [0u8; 104];
    put32(&mut b, 0, fb);
    assert_eq!(io(&f, 0xCE, &mut b), 0);
    assert_eq!((get32(&b, 12), get32(&b, 20), get32(&b, 36), get32(&b, 52)), (AR24, h, pitch, 0));
    assert_eq!(io(&other, 0xCE, &mut b), 0);
    assert_eq!(get32(&b, 20), 0);
    put32(&mut b, 0, 5);
    assert_eq!(io(&f, 0xCE, &mut b), ENOENT);
    // GETRESOURCES lists the caller's framebuffers and the fixed objects
    let (mut fbs, mut crtcs, mut conns, mut encs) = ([0u32; 8], [0u32; 1], [0u32; 1], [0u32; 1]);
    let mut b = [0u8; 64];
    put64(&mut b, 0, fbs.as_mut_ptr() as u64);
    put64(&mut b, 8, crtcs.as_mut_ptr() as u64);
    put64(&mut b, 16, conns.as_mut_ptr() as u64);
    put64(&mut b, 24, encs.as_mut_ptr() as u64);
    put32(&mut b, 32, 8);
    put32(&mut b, 36, 1);
    put32(&mut b, 40, 1);
    put32(&mut b, 44, 1);
    assert_eq!(io(&f, 0xA0, &mut b), 0);
    assert_eq!(get32(&b, 32), 3);
    assert!(fbs[..3].contains(&fb));
    assert_eq!((crtcs[0], conns[0], encs[0]), (CRTC, CONNECTOR, ENCODER));
    assert_eq!((get32(&b, 48), get32(&b, 52), get32(&b, 56), get32(&b, 60)), (1, 4096, 1, 4096));
    // Too small an array is left alone (counts only)
    let mut b = [0u8; 64];
    put64(&mut b, 0, fbs.as_mut_ptr() as u64);
    put32(&mut b, 32, 1);
    assert_eq!(io(&f, 0xA0, &mut b), 0);
    assert_eq!(io(&other, 0xA0, &mut [0u8; 64]), 0);
    // RMFB: only the owner; DIRTYFB of a framebuffer not shown is fine
    let mut b = [0u8; 4];
    put32(&mut b, 0, fb_legacy);
    assert_eq!(io(&other, 0xAF, &mut b), ENOENT);
    assert_eq!(io(&f, 0xAF, &mut b), 0);
    assert_eq!(io(&f, 0xAF, &mut b), ENOENT);
    let mut b = [0u8; 24];
    put32(&mut b, 0, fb);
    assert_eq!(io(&f, 0xB1, &mut b), 0);
    put32(&mut b, 0, 3);
    assert_eq!(io(&f, 0xB1, &mut b), ENOENT);
    // A file's framebuffers die with it
    drop(f);
    let mut b = [0u8; 28];
    put32(&mut b, 0, fb);
    assert_eq!(io(&other, 0xAD, &mut b), ENOENT);
    drop(other);
}

#[test]
fn width_overflow_in_addfb_is_refused() {
    let _g = setup();
    let f = open();
    let (h, _pitch, _) = dumb(&f, 16, 16);
    // width * 4 wraps to 4 in 32 bits: such a framebuffer would claim 2^30 pixels per row
    // of a 4-byte pitch. Bug fixed (wave TW, Group 28): it was accepted
    assert_eq!(addfb2(&f, h, 0x4000_0001, 1, 4, XR24), Err(EINVAL));
    // offset + pitch * height past the buffer, with values that wrap
    let mut b = [0u8; 104];
    put32(&mut b, 4, 1);
    put32(&mut b, 8, u32::MAX);
    put32(&mut b, 12, XR24);
    put32(&mut b, 20, h);
    put32(&mut b, 36, u32::MAX);
    put32(&mut b, 52, u32::MAX);
    assert_eq!(io(&f, 0xB8, &mut b), EINVAL);
    drop(f);
}

#[test]
fn mode_setting_shows_the_framebuffer() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    // XRGB pixel 0x00112233: bytes B=0x33 G=0x22 R=0x11
    fill(&f, h, pitch, H, [0x33, 0x22, 0x11, 0x00]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    // Wrong CRTC, wrong connector, mode not the screen's, unknown framebuffer
    let mut b = [0u8; 104];
    put32(&mut b, 12, 7);
    assert_eq!(io(&f, 0xA2, &mut b), ENOENT);
    let mut bad_conn = [99u32];
    let mut b = [0u8; 104];
    put64(&mut b, 0, bad_conn.as_mut_ptr() as u64);
    put32(&mut b, 8, 1);
    put32(&mut b, 12, CRTC);
    assert_eq!(io(&f, 0xA2, &mut b), ENOENT);
    put64(&mut b, 0, fake::BAD_PTR);
    assert_eq!(io(&f, 0xA2, &mut b), EFAULT);
    assert_eq!(setcrtc(&f, fb, 0, 0, W + 1, H), EINVAL);
    assert_eq!(setcrtc(&f, 4242, 0, 0, W, H), ENOENT);
    // A viewport beyond the framebuffer; one whose x + width wraps in 32 bits (bug fixed,
    // wave TW, Group 28: it passed the check)
    assert_eq!(setcrtc(&f, fb, 1, 0, W, H), ENOSPC);
    assert_eq!(setcrtc(&f, fb, u32::MAX - 10, 0, W, H), ENOSPC);
    assert_eq!(setcrtc(&f, fb, 0, u32::MAX - 10, W, H), ENOSPC);
    // "The current framebuffer" with nothing shown yet
    assert_eq!(setcrtc(&f, u32::MAX, 0, 0, W, H), EINVAL);
    let evs_before = fake::with_display(|d| d.releases);
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    assert!(drm::showing());
    assert!(evdev::routing());
    assert_eq!(fake::with_display(|d| d.releases), evs_before + 1);
    // The screen is RGB-ordered (bgr = false): red and blue swapped on the way
    assert_eq!(fake::pixel(0, 0), [0x11, 0x22, 0x33, 0x00]);
    assert_eq!(fake::pixel(W as usize - 1, H as usize - 1), [0x11, 0x22, 0x33, 0x00]);
    // GETCRTC reports the framebuffer and the mode
    let mut b = [0u8; 104];
    put32(&mut b, 12, CRTC);
    assert_eq!(io(&f, 0xA1, &mut b), 0);
    assert_eq!((get32(&b, 16), get32(&b, 28), get32(&b, 32)), (fb, 256, 1));
    assert_eq!(u16::from_le_bytes([b[40], b[41]]), W as u16);
    assert_eq!(u16::from_le_bytes([b[50], b[51]]), H as u16);
    assert_eq!(&b[72..77], b"64x48");
    put32(&mut b, 12, 1);
    assert_eq!(io(&f, 0xA1, &mut b), ENOENT);
    // fb -1: the one shown
    assert_eq!(setcrtc(&f, u32::MAX, 0, 0, W, H), 0);
    // CRTC_GET_SEQUENCE says it is active
    let mut b = [0u8; 24];
    assert_eq!(io(&f, 0x3b, &mut b), 0);
    assert_eq!(get32(&b, 4), 1);
    // A primary plane on the CRTC while showing
    let mut b = [0u8; 32];
    put32(&mut b, 0, 43);
    assert_eq!(io(&f, 0xB6, &mut b), 0);
    assert_eq!(get32(&b, 4), CRTC);
    // A change to the pixels shows after DIRTYFB
    fill(&f, h, pitch, 1, [0, 0, 0xFF, 0]);
    let mut b = [0u8; 24];
    put32(&mut b, 0, fb);
    assert_eq!(io(&f, 0xB1, &mut b), 0);
    assert_eq!(fake::pixel(5, 0), [0xFF, 0, 0, 0]);
    // Removing the shown framebuffer blanks the screen
    let mut b = [0u8; 4];
    put32(&mut b, 0, fb);
    assert_eq!(io(&f, 0xAF, &mut b), 0);
    assert_eq!(fake::pixel(5, 0), [0, 0, 0, 0]);
    let mut b = [0u8; 104];
    put32(&mut b, 12, CRTC);
    assert_eq!(io(&f, 0xA1, &mut b), 0);
    assert_eq!((get32(&b, 16), get32(&b, 32)), (0, 0));
    // Turning the CRTC off gives the screen back
    let mut b = [0u8; 104];
    put32(&mut b, 12, CRTC);
    assert_eq!(io(&f, 0xA2, &mut b), 0);
    assert!(!drm::showing());
    assert!(!evdev::routing());
    drop(f);
}

#[test]
fn a_bgr_screen_and_a_viewport() {
    let _g = setup();
    fake::with_display(|d| d.bgr = true);
    let f = open();
    // A framebuffer twice as wide: the viewport starts at column W
    let (h, pitch, _) = dumb(&f, 2 * W, H);
    fill(&f, h, pitch, H, [1, 2, 3, 4]);
    for y in 0..H as u64 {
        for x in W as u64..2 * W as u64 {
            unsafe { core::ptr::copy_nonoverlapping([9u8, 8, 7, 6].as_ptr(), bo_ptr(&f, h, y * pitch as u64 + x * 4), 4) };
        }
    }
    let fb = addfb2(&f, h, 2 * W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, W, 0, W, H), 0);
    // BGR screen: bytes copied as they are
    assert_eq!(fake::pixel(0, 0), [9, 8, 7, 6]);
    // The console cannot lend the screen (no framebuffer): ENXIO, nothing shown
    drop(f);
    fake::with_display(|d| d.refuse = true);
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), ENXIO);
    drop(f);
}

#[test]
fn page_flips_post_events() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    fake::TICKS.set(5000);
    let flip = |crtc: u32, fb: u32, flags: u32, data: u64| {
        let mut b = [0u8; 24];
        put32(&mut b, 0, crtc);
        put32(&mut b, 4, fb);
        put32(&mut b, 8, flags);
        put64(&mut b, 16, data);
        io(&f, 0xB0, &mut b)
    };
    assert_eq!(flip(1, fb, 1, 0), ENOENT);
    assert_eq!(flip(CRTC, fb, 4, 0), EINVAL);
    assert_eq!(flip(CRTC, 555, 1, 0), ENOENT);
    assert_eq!(flip(CRTC, fb, 1, 0xABCD), 0);
    assert!(drm::showing());
    assert_eq!(f.poll_events(), 0x5);
    // Without the event flag: no event
    assert_eq!(flip(CRTC, fb, 0, 0), 0);
    // The event: FLIP_COMPLETE, 32 bytes, user data, time, sequence, CRTC
    let mut small = [0u8; 16];
    assert_eq!(f.read(&mut small), EINVAL);
    let mut b = [0u8; 64];
    assert_eq!(f.read(&mut b), 32);
    assert_eq!((get32(&b, 0), get32(&b, 4), get64(&b, 8)), (2, 32, 0xABCD));
    let us = 5000u64 * 10_000;
    assert_eq!((get32(&b, 16), get32(&b, 20)), ((us / 1_000_000) as u32, (us % 1_000_000) as u32));
    assert_eq!(get32(&b, 24), (us / 16_667) as u32);
    assert_eq!(get32(&b, 28), CRTC);
    assert_eq!(f.read(&mut b), EAGAIN);
    // WAIT_VBLANK: answers at once; with the event flag it queues a VBLANK event
    let mut v = [0u8; 24];
    put32(&mut v, 0, 0x0400_0000);
    put64(&mut v, 8, 77);
    assert_eq!(io(&f, 0x3a, &mut v), 0);
    assert_eq!(get32(&v, 4), (us / 16_667) as u32);
    assert_eq!(get64(&v, 8), us / 1_000_000);
    let mut v2 = [0u8; 24];
    assert_eq!(io(&f, 0x3a, &mut v2), 0);
    // Two events in one read
    assert_eq!(flip(CRTC, fb, 1, 5), 0);
    assert_eq!(f.read(&mut b), 64);
    assert_eq!((get32(&b, 0), get64(&b, 8)), (1, 77));
    assert_eq!((get32(&b, 32), get64(&b, 40)), (2, 5));
    drop(f);
}

#[test]
fn blocking_event_reads() {
    let _g = setup();
    let f = drm::open(0, false).unwrap();
    let mut b = [0u8; 32];
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(f.read(&mut b), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    // An event arrives while the reader sleeps
    let f2 = f.clone();
    fake::on_wait(move || {
        let mut v = [0u8; 24];
        put32(&mut v, 0, 0x0400_0000);
        io(&f2, 0x3a, &mut v);
    });
    assert_eq!(f.read(&mut b), 32);
    fake::clear_on_wait();
    drop(f);
}

/// An ARGB cursor buffer: every pixel `px`.
fn cursor_bo(f: &Dev, px: [u8; 4]) -> u32 {
    let (h, pitch, _) = dumb(f, 64, 64);
    assert_eq!(pitch, 256);
    fill(f, h, pitch, 64, px);
    h
}

fn cursor(f: &Dev, flags: u32, x: i32, y: i32, w: u32, hgt: u32, handle: u32) -> i64 {
    let mut b = [0u8; 28];
    put32(&mut b, 0, flags);
    put32(&mut b, 4, CRTC);
    put32(&mut b, 8, x as u32);
    put32(&mut b, 12, y as u32);
    put32(&mut b, 16, w);
    put32(&mut b, 20, hgt);
    put32(&mut b, 24, handle);
    io(f, 0xA3, &mut b)
}

#[test]
fn the_cursor_is_blended_and_moved() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    fill(&f, h, pitch, H, [100, 100, 100, 0]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    // Half-transparent premultiplied white (128 = alpha): out = src + dst * (255 - a) / 255
    let c = cursor_bo(&f, [128, 128, 128, 128]);
    assert_eq!(cursor(&f, 1, 0, 0, 65, 64, c), EINVAL);
    assert_eq!(cursor(&f, 1, 0, 0, 64, 64, 999), ENOENT);
    assert_eq!(cursor(&f, 1 | 2, 10, 10, 4, 4, c), 0);
    let blended = (128 + 100 * 127 / 255) as u8;
    assert_eq!(fake::pixel(10, 10), [blended, blended, blended, 0]);
    assert_eq!(fake::pixel(13, 13), [blended, blended, blended, 0]);
    assert_eq!(fake::pixel(14, 14), [100, 100, 100, 0]);
    assert_eq!(fake::pixel(9, 9), [100, 100, 100, 0]);
    // Moving repairs the old place
    assert_eq!(cursor(&f, 2, 30, 20, 0, 0, 0), 0);
    assert_eq!(fake::pixel(10, 10), [100, 100, 100, 0]);
    assert_eq!(fake::pixel(30, 20), [blended, blended, blended, 0]);
    // Partly off screen (negative and past the edge): clipped
    assert_eq!(cursor(&f, 2, -2, -2, 0, 0, 0), 0);
    assert_eq!(fake::pixel(0, 0), [blended, blended, blended, 0]);
    assert_eq!(fake::pixel(30, 20), [100, 100, 100, 0]);
    assert_eq!(cursor(&f, 2, W as i32 - 1, H as i32 - 1, 0, 0, 0), 0);
    assert_eq!(fake::pixel(W as usize - 1, H as usize - 1), [blended, blended, blended, 0]);
    // A fully transparent cursor leaves the picture
    let clear = cursor_bo(&f, [0, 0, 0, 0]);
    assert_eq!(cursor(&f, 1 | 2, 5, 5, 8, 8, clear), 0);
    assert_eq!(fake::pixel(5, 5), [100, 100, 100, 0]);
    // Handle 0 hides it
    assert_eq!(cursor(&f, 1, 0, 0, 0, 0, 0), 0);
    // CURSOR2 is the same request
    let mut b = [0u8; 36];
    put32(&mut b, 0, 2);
    assert_eq!(io(&f, 0xBB, &mut b), 0);
    drop(f);
}

#[test]
fn dpms_and_properties() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    fill(&f, h, pitch, H, [7, 7, 7, 0]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    let setprop = |prop: u32, value: u64| {
        let mut b = [0u8; 16];
        put64(&mut b, 0, value);
        put32(&mut b, 8, prop);
        put32(&mut b, 12, CONNECTOR);
        io(&f, 0xAB, &mut b)
    };
    // DPMS off: nothing is drawn; on: repainted
    assert_eq!(setprop(1, 3), 0);
    fill(&f, h, pitch, H, [9, 9, 9, 0]);
    let mut d = [0u8; 24];
    put32(&mut d, 0, fb);
    assert_eq!(io(&f, 0xB1, &mut d), 0);
    assert_eq!(fake::pixel(1, 1), [7, 7, 7, 0]);
    assert_eq!(setprop(1, 0), 0);
    assert_eq!(fake::pixel(1, 1), [9, 9, 9, 0]);
    assert_eq!(setprop(1, 4), EINVAL);
    assert_eq!(setprop(2, 0), EPERM);
    assert_eq!(setprop(3, 0), EPERM);
    assert_eq!(setprop(4, 0), ENOENT);
    let mut b = [0u8; 16];
    put32(&mut b, 12, ENCODER);
    assert_eq!(io(&f, 0xAB, &mut b), ENOENT);
    // OBJ_SETPROPERTY: the connector (typed or not); other objects refuse
    let objset = |obj: u32, ty: u32, prop: u32, v: u64| {
        let mut b = [0u8; 24];
        put64(&mut b, 0, v);
        put32(&mut b, 8, prop);
        put32(&mut b, 12, obj);
        put32(&mut b, 16, ty);
        io(&f, 0xBA, &mut b)
    };
    assert_eq!(objset(CONNECTOR, 0xc0c0_c0c0, 1, 1), 0);
    assert_eq!(objset(CONNECTOR, 0, 1, 0), 0);
    assert_eq!(objset(CRTC, 0xcccc_cccc, 1, 0), EINVAL);
    assert_eq!(objset(43, 0xeeee_eeee, 1, 0), EINVAL);
    assert_eq!(objset(ENCODER, 0xe0e0_e0e0, 1, 0), EINVAL);
    assert_eq!(objset(99, 0, 1, 0), ENOENT);
    // OBJ_GETPROPERTIES
    let objget = |obj: u32| {
        let (mut ids, mut vals) = ([0u32; 4], [0u64; 4]);
        let mut b = [0u8; 32];
        put64(&mut b, 0, ids.as_mut_ptr() as u64);
        put64(&mut b, 8, vals.as_mut_ptr() as u64);
        put32(&mut b, 16, 4);
        put32(&mut b, 20, obj);
        let r = io(&f, 0xB9, &mut b);
        (r, get32(&b, 16), ids, vals)
    };
    let (r, n, ids, vals) = objget(CONNECTOR);
    assert_eq!((r, n), (0, 3));
    assert_eq!(&ids[..3], &[1, 2, 3]);
    assert_eq!(vals[0], 0);
    assert_eq!(objget(43).3[0], 1);
    assert_eq!(objget(44).3[0], 2);
    assert_eq!(objget(CRTC).1, 0);
    assert_eq!(objget(ENCODER).1, 0);
    assert_eq!(objget(7).0, ENOENT);
    // GETPROPERTY: names, flags, values and enum names
    for (id, name, flags, nvals, nenums) in [(1u32, "DPMS", 8u32, 4u32, 4u32), (2, "EDID", 16 | 4, 0, 0), (3, "non-desktop", 2 | 4, 2, 0), (4, "type", 8 | 4, 3, 3)] {
        let (mut vals, mut enums) = ([0u64; 4], [0u8; 40 * 4]);
        let mut b = [0u8; 64];
        put64(&mut b, 0, vals.as_mut_ptr() as u64);
        put64(&mut b, 8, enums.as_mut_ptr() as u64);
        put32(&mut b, 16, id);
        put32(&mut b, 56, 4);
        put32(&mut b, 60, 4);
        assert_eq!(io(&f, 0xAA, &mut b), 0);
        assert_eq!(&b[24..24 + name.len()], name.as_bytes());
        assert_eq!(b[24 + name.len()], 0);
        assert_eq!((get32(&b, 20), get32(&b, 56), get32(&b, 60)), (flags, nvals, nenums));
        if id == 4 {
            assert_eq!(&enums[48..55], b"Primary");
            assert_eq!(vals[..3], [0, 1, 2]);
        }
    }
    let mut b = [0u8; 64];
    put32(&mut b, 16, 9);
    assert_eq!(io(&f, 0xAA, &mut b), ENOENT);
    // Blobs: create, read (length first), destroy
    let mut data = *b"blobdata";
    let mut b = [0u8; 16];
    put64(&mut b, 0, data.as_mut_ptr() as u64);
    put32(&mut b, 8, 8);
    assert_eq!(io(&f, 0xBD, &mut b), 0);
    let id = get32(&b, 12);
    put32(&mut b, 8, 0);
    assert_eq!(io(&f, 0xBD, &mut b), EINVAL);
    put32(&mut b, 8, (1 << 20) + 1);
    assert_eq!(io(&f, 0xBD, &mut b), EINVAL);
    put64(&mut b, 0, fake::BAD_PTR);
    put32(&mut b, 8, 4);
    assert_eq!(io(&f, 0xBD, &mut b), EFAULT);
    let mut out = [0u8; 8];
    let mut g = [0u8; 16];
    put32(&mut g, 0, id);
    assert_eq!(io(&f, 0xAC, &mut g), 0);
    assert_eq!(get32(&g, 4), 8);
    put32(&mut g, 4, 8);
    put64(&mut g, 8, out.as_mut_ptr() as u64);
    assert_eq!(io(&f, 0xAC, &mut g), 0);
    assert_eq!(&out, b"blobdata");
    let mut d = [0u8; 4];
    put32(&mut d, 0, id);
    assert_eq!(io(&f, 0xBE, &mut d), 0);
    assert_eq!(io(&f, 0xBE, &mut d), ENOENT);
    assert_eq!(io(&f, 0xAC, &mut g), ENOENT);
    drop(f);
}

#[test]
fn encoder_connector_planes_gamma() {
    let _g = setup();
    let f = open();
    let mut b = [0u8; 20];
    put32(&mut b, 0, ENCODER);
    assert_eq!(io(&f, 0xA6, &mut b), 0);
    assert_eq!((get32(&b, 4), get32(&b, 8), get32(&b, 12)), (5, CRTC, 1));
    put32(&mut b, 0, 1);
    assert_eq!(io(&f, 0xA6, &mut b), ENOENT);
    // GETCONNECTOR: the one mode, the properties, the encoder, 96 dpi size
    let (mut enc, mut modes, mut props, mut vals) = ([0u32; 1], [0u8; 68], [0u32; 3], [0u64; 3]);
    let mut b = [0u8; 80];
    put64(&mut b, 0, enc.as_mut_ptr() as u64);
    put64(&mut b, 8, modes.as_mut_ptr() as u64);
    put64(&mut b, 16, props.as_mut_ptr() as u64);
    put64(&mut b, 24, vals.as_mut_ptr() as u64);
    put32(&mut b, 32, 1);
    put32(&mut b, 36, 3);
    put32(&mut b, 40, 1);
    put32(&mut b, 48, CONNECTOR);
    assert_eq!(io(&f, 0xA7, &mut b), 0);
    assert_eq!(enc[0], ENCODER);
    assert_eq!(props, [1, 2, 3]);
    assert_eq!(u16::from_le_bytes([modes[4], modes[5]]), W as u16);
    assert_eq!(u16::from_le_bytes([modes[14], modes[15]]), H as u16);
    let (ht, vt) = (W + 160, H + 30);
    assert_eq!(get32(&modes, 0), ht * vt * 60 / 1000);
    assert_eq!(get32(&modes, 24), 60);
    assert_eq!(get32(&modes, 32), 0x48);
    assert_eq!((get32(&b, 52), get32(&b, 60), get32(&b, 64), get32(&b, 68)), (15, 1, W * 254 / 960, H * 254 / 960));
    put32(&mut b, 48, 1);
    assert_eq!(io(&f, 0xA7, &mut b), ENOENT);
    // GETPLANE: formats per plane; no CRTC while nothing is shown
    let mut fmts = [0u32; 4];
    let mut b = [0u8; 32];
    put32(&mut b, 0, 43);
    put32(&mut b, 20, 4);
    put64(&mut b, 24, fmts.as_mut_ptr() as u64);
    assert_eq!(io(&f, 0xB6, &mut b), 0);
    assert_eq!((get32(&b, 4), get32(&b, 20)), (0, 2));
    assert_eq!(&fmts[..2], &[XR24, AR24]);
    put32(&mut b, 0, 44);
    put32(&mut b, 20, 4);
    assert_eq!(io(&f, 0xB6, &mut b), 0);
    assert_eq!(get32(&b, 20), 1);
    put32(&mut b, 0, 45);
    assert_eq!(io(&f, 0xB6, &mut b), ENOENT);
    assert_eq!(io(&f, 0xB7, &mut [0u8; 48]), EINVAL);
    assert_eq!(io(&f, 0xBC, &mut [0u8; 56]), EINVAL);
    // Gamma: a 256-entry identity ramp, accepted but not applied
    let (mut r, mut g, mut bl) = ([0u16; 256], [0u16; 256], [0u16; 256]);
    let mut b = [0u8; 32];
    put32(&mut b, 0, CRTC);
    put32(&mut b, 4, 256);
    put64(&mut b, 8, r.as_mut_ptr() as u64);
    put64(&mut b, 16, g.as_mut_ptr() as u64);
    put64(&mut b, 24, bl.as_mut_ptr() as u64);
    assert_eq!(io(&f, 0xA4, &mut b), 0);
    assert_eq!((r[1], g[255], bl[128]), (0x101, 0xFFFF, 0x8080));
    assert_eq!(io(&f, 0xA5, &mut b), 0);
    put32(&mut b, 4, 255);
    assert_eq!(io(&f, 0xA4, &mut b), EINVAL);
    put32(&mut b, 0, 1);
    assert_eq!(io(&f, 0xA5, &mut b), ENOENT);
    put32(&mut b, 0, CRTC);
    put32(&mut b, 4, 256);
    put64(&mut b, 16, fake::BAD_PTR);
    assert_eq!(io(&f, 0xA4, &mut b), EFAULT);
    // CRTC_GET_SEQUENCE while off
    let mut b = [0u8; 24];
    assert_eq!(io(&f, 0x3b, &mut b), 0);
    assert_eq!(get32(&b, 4), 0);
    drop(f);
}

#[test]
fn prime_export_and_import() {
    let _g = setup();
    fake::FDS.with_borrow_mut(|f| *f = Default::default());
    let f = open();
    let (h, _pitch, size) = dumb(&f, 32, 32);
    unsafe { *bo_ptr(&f, h, 3) = 0x77 };
    // HANDLE_TO_FD with O_CLOEXEC
    let mut b = [0u8; 12];
    put32(&mut b, 0, h);
    put32(&mut b, 4, 0o2000000);
    assert_eq!(io(&f, 0x2d, &mut b), 0);
    let fd = get32(&b, 8) as usize;
    assert!(fake::FDS.with_borrow(|t| t.cloexec(fd)));
    let buf = match fake::FDS.with_borrow(|t| t.get(fd).cloned()) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("no dma-buf descriptor"),
    };
    // The DMA-BUF maps the same pages from offset 0
    let pages = buf.mmap_object().unwrap();
    let frame = pages.get_page(0).unwrap();
    assert_eq!(unsafe { *((frame.start_address().as_u64() + 3) as *const u8) }, 0x77);
    assert!(pages.get_page(size / 4096).is_none());
    assert_eq!(buf.read(&mut [0u8; 4]), EINVAL);
    assert_eq!(buf.ioctl(0x4008_6200, 0), 0);
    assert_eq!(buf.ioctl(0x4008_6201, 0), 0);
    assert_eq!(buf.ioctl(0x4004_6201, 0), 0);
    assert_eq!(buf.ioctl(0x1234, 0), -25);
    assert_eq!(buf.poll_events(), 0x5);
    let mut ws = hydra_hosttests_t28::task::wait::WaitSet::new();
    buf.add_wait_queues(&mut ws);
    assert!(ws.queues.is_empty());
    assert_eq!((buf.rdev(), buf.path()), (0, "/dmabuf:".to_string()));
    buf.set_nonblock(true);
    assert!(buf.nonblock());
    let st = buf.stat();
    assert_eq!((st.st_mode, st.st_size, st.st_dev), (0o100600, size as i64, 0xd));
    // FD_TO_HANDLE: the same handle in the exporting file, a new one elsewhere
    let mut b = [0u8; 12];
    put32(&mut b, 8, fd as u32);
    assert_eq!(io(&f, 0x2e, &mut b), 0);
    assert_eq!(get32(&b, 0), h);
    let g = open();
    assert_eq!(io(&g, 0x2e, &mut b), 0);
    let h2 = get32(&b, 0);
    unsafe { *bo_ptr(&g, h2, 3) = 0x78 };
    assert_eq!(unsafe { *bo_ptr(&f, h, 3) }, 0x78);
    // Not a descriptor, not a DMA-BUF, unknown handle
    put32(&mut b, 8, 900);
    assert_eq!(io(&f, 0x2e, &mut b), -9);
    fake::FDS.with_borrow_mut(|t| t.install(901, FileDescriptor::Device(g.clone())));
    put32(&mut b, 8, 901);
    assert_eq!(io(&f, 0x2e, &mut b), EINVAL);
    let mut b = [0u8; 12];
    put32(&mut b, 0, 4444);
    assert_eq!(io(&f, 0x2d, &mut b), ENOENT);
    // A full descriptor table
    fake::FDS.with_borrow_mut(|t| t.limit = t.next);
    put32(&mut b, 0, h);
    assert_eq!(io(&f, 0x2d, &mut b), -24);
    fake::FDS.with_borrow_mut(|f| *f = Default::default());
    drop((f, g, buf));
}

#[test]
fn set_master_restores_the_last_picture() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    fill(&f, h, pitch, H, [5, 6, 7, 0]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    let c = cursor_bo(&f, [255, 255, 255, 255]);
    assert_eq!(cursor(&f, 3, 1, 1, 2, 2, c), 0);
    // A session switch: drop master; another client scribbles; master back
    assert_eq!(io0(&f, 0x1f), 0);
    fake::with_display(|d| d.fb.fill(0));
    assert_eq!(io0(&f, 0x1e), 0);
    assert_eq!(fake::pixel(10, 10), [7, 6, 5, 0]);
    assert_eq!(fake::pixel(1, 1), [255, 255, 255, 0]);
    // Again while already master: repainted too
    fake::with_display(|d| d.fb.fill(0));
    assert_eq!(io0(&f, 0x1e), 0);
    assert_eq!(fake::pixel(10, 10), [7, 6, 5, 0]);
    drop(f);
}

#[test]
fn vt_switches_hide_and_show_the_session() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    fill(&f, h, pitch, H, [1, 1, 1, 0]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    assert!(fake::spawned("vtd") >= 1);
    let vtd = fake::spawned_entry("vtd").unwrap();
    // Run the switch task until it has nothing to do (it then sleeps: a caught panic)
    let run = || {
        let r = std::panic::catch_unwind(vtd);
        assert!(r.is_err());
    };
    // Ctrl+Alt+F1: the console shows, input goes back to Hydra
    drm::request_vt_switch(false);
    run();
    assert!(drm::session_hidden());
    assert!(!evdev::routing());
    assert!(fake::with_display(|d| d.console_owns));
    // While hidden nothing is drawn
    fake::with_display(|d| d.fb.fill(0));
    let mut d = [0u8; 24];
    put32(&mut d, 0, fb);
    assert_eq!(io(&f, 0xB1, &mut d), 0);
    assert_eq!(fake::pixel(0, 0), [0, 0, 0, 0]);
    assert_eq!(cursor(&f, 2, 3, 3, 0, 0, 0), 0);
    // Hiding twice changes nothing
    drm::request_vt_switch(false);
    run();
    assert!(drm::session_hidden());
    // Ctrl+Alt+F2: repainted, input routed again
    drm::request_vt_switch(true);
    run();
    assert!(!drm::session_hidden());
    assert!(evdev::routing());
    assert_eq!(fake::pixel(0, 0), [1, 1, 1, 0]);
    drm::request_vt_switch(true);
    run();
    // The master closing while hidden: the console keeps the screen it already has
    drm::request_vt_switch(false);
    run();
    let reclaims = fake::with_display(|d| d.reclaims);
    drop(f);
    assert_eq!(fake::with_display(|d| d.reclaims), reclaims);
    assert!(!drm::showing());
    assert!(!drm::session_hidden());
    // A switch with no session does nothing
    drm::request_vt_switch(true);
    run();
    assert!(!drm::showing());
}

#[test]
fn a_session_gone_without_master_returns_the_screen() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    // logind drops mastership first, then the desktop closes its file
    assert_eq!(io0(&f, 0x1f), 0);
    let before = fake::spawned("drmgone");
    drop(f);
    assert!(drm::showing(), "the last picture stays during the grace time");
    assert_eq!(fake::spawned("drmgone"), before + 1);
    // A new session within the grace time: the check leaves the screen to it
    let g = open();
    let check = fake::spawned_entry("drmgone").unwrap();
    check();
    assert!(drm::showing());
    drop(g); // the master closing gives the screen back
    assert!(!drm::showing());
    // Nobody came: the console takes the screen back
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    assert_eq!(io0(&f, 0x1f), 0);
    drop(f);
    let slept = fake::SLEPT_MS.get();
    fake::spawned_entry("drmgone").unwrap()();
    assert_eq!(fake::SLEPT_MS.get() - slept, 10_000);
    assert!(!drm::showing());
}

#[test]
fn a_panic_screen_is_not_overwritten() {
    let _g = setup();
    let f = open();
    let (h, pitch, _) = dumb(&f, W, H);
    fill(&f, h, pitch, H, [3, 3, 3, 0]);
    let fb = addfb2(&f, h, W, H, pitch, XR24).unwrap();
    let c = cursor_bo(&f, [255, 255, 255, 255]);
    fake::with_display(|d| d.panicked = true);
    assert_eq!(setcrtc(&f, fb, 0, 0, W, H), 0);
    assert_eq!(cursor(&f, 3, 0, 0, 4, 4, c), 0);
    assert_eq!(fake::pixel(0, 0), [0, 0, 0, 0]);
    fake::with_display(|d| d.panicked = false);
    drop(f);
}
