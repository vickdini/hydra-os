//! display-server's DRM layer (`kms.rs`) against a fake caller and screen: the calls a
//! compositor makes, the 60 Hz pacing, completions held back behind the console, PRIME,
//! master rules and closes.

use std::sync::Arc;

use crate::fakes::{FakeEnv, FakeScreen, ScreenView};
use crate::kms::*;
use crate::proto::{SCREEN_CONSOLE, SCREEN_HIDDEN, SCREEN_SHOWN};

const W: u32 = 64;
const H: u32 = 32;
const PERIOD: u64 = 16_666_666;

fn ioc(dir: u64, size: usize, nr: u64) -> u64 {
    dir << 30 | (size as u64) << 16 | 0x64 << 8 | nr
}
fn iowr(size: usize, nr: u64) -> u64 {
    ioc(3, size, nr)
}

/// A call with Linux's own encoding: `_IO(nr)` (no argument block) or `_IOW` of `b`.
fn call_io(k: &mut Kms, env: &FakeEnv, file: u32, nr: u64) -> i64 {
    k.ioctl(env, file, ioc(0, 0, nr), 0)
}
fn call_iow(k: &mut Kms, env: &FakeEnv, file: u32, nr: u64, b: &mut [u8]) -> i64 {
    k.ioctl(env, file, ioc(1, b.len(), nr), b.as_mut_ptr() as u64)
}

fn new() -> (Kms, Arc<ScreenView>, FakeEnv) {
    let (s, v) = FakeScreen::new(W, H, true);
    (Kms::new(s, "0000:00:02.0".into(), 60_000), v, FakeEnv::default())
}

/// `ioctl` with an argument block of `size` bytes, given and returned.
fn call(k: &mut Kms, env: &FakeEnv, file: u32, nr: u64, b: &mut [u8]) -> i64 {
    k.ioctl(env, file, iowr(b.len(), nr), b.as_mut_ptr() as u64)
}

/// A dumb buffer of `w` x `h`: (handle, pitch, size).
fn dumb(k: &mut Kms, env: &FakeEnv, f: u32, w: u32, h: u32) -> (u32, u32, u64) {
    let mut b = [0u8; 32];
    put32(&mut b, 0, h);
    put32(&mut b, 4, w);
    put32(&mut b, 8, 32);
    assert_eq!(call(k, env, f, 0xB2, &mut b), 0);
    (get32(&b, 16), get32(&b, 20), get64(&b, 24))
}

fn addfb2(k: &mut Kms, env: &FakeEnv, f: u32, handle: u32, pitch: u32, w: u32, h: u32) -> i64 {
    let mut b = [0u8; 104];
    put32(&mut b, 4, w);
    put32(&mut b, 8, h);
    put32(&mut b, 12, FMT_XRGB8888);
    put32(&mut b, 20, handle);
    put32(&mut b, 36, pitch);
    let r = call(k, env, f, 0xB8, &mut b);
    if r < 0 {
        r
    } else {
        get32(&b, 0) as i64
    }
}

fn setcrtc(k: &mut Kms, env: &FakeEnv, f: u32, fb: u32) -> i64 {
    let conn = [CONNECTOR_ID];
    let mut b = [0u8; 104];
    put64(&mut b, 0, conn.as_ptr() as u64);
    put32(&mut b, 8, 1);
    put32(&mut b, 12, CRTC_ID);
    put32(&mut b, 16, fb);
    put32(&mut b, 32, 1);
    b[36..104].copy_from_slice(&mode_info(W, H));
    call(k, env, f, 0xA2, &mut b)
}

fn flip(k: &mut Kms, env: &FakeEnv, f: u32, fb: u32, data: u64) -> i64 {
    let mut b = [0u8; 24];
    put32(&mut b, 0, CRTC_ID);
    put32(&mut b, 4, fb);
    put32(&mut b, 8, 1);
    put64(&mut b, 16, data);
    call(k, env, f, 0xB0, &mut b)
}

/// The bytes of buffer `handle` of file `f` (through `mmap`'s lookup).
fn fill(k: &Kms, map_off: u64, size: u64, v: u32) {
    let bo = k.mmap_file(7, map_off, size).unwrap();
    let p = bo.mem.ptr() as *mut u32;
    for i in 0..(size / 4) as usize {
        unsafe { *p.add(i) = v };
    }
}

fn map_off(k: &mut Kms, env: &FakeEnv, f: u32, handle: u32) -> u64 {
    let mut b = [0u8; 16];
    put32(&mut b, 0, handle);
    assert_eq!(call(k, env, f, 0xB3, &mut b), 0);
    get64(&b, 8)
}

/// A compositor's start: open, a full-screen buffer filled with `v`, a framebuffer, SETCRTC.
fn desktop(k: &mut Kms, env: &FakeEnv, v: u32) -> (u32, u32, u64) {
    k.open(7);
    let (h, pitch, size) = dumb(k, env, 7, W, H);
    let off = map_off(k, env, 7, h);
    fill(k, off, size, v);
    let fb = addfb2(k, env, 7, h, pitch, W, H) as u32;
    assert_eq!(setcrtc(k, env, 7, fb), 0);
    (fb, h, off)
}

#[test]
fn version_caps_and_resources() {
    let (mut k, _v, env) = new();
    k.open(3);
    let mut name = [0u8; 16];
    let mut b = [0u8; 64];
    put64(&mut b, 16, 15);
    put64(&mut b, 24, name.as_mut_ptr() as u64);
    assert_eq!(call(&mut k, &env, 3, 0x00, &mut b), 0);
    assert_eq!(&name[..8], b"hydradrm");
    let mut c = [0u8; 16];
    put64(&mut c, 0, 1);
    assert_eq!(call(&mut k, &env, 3, 0x0c, &mut c), 0);
    assert_eq!(get64(&c, 8), 1);
    put64(&mut c, 0, 3); // SET_CLIENT_CAP ATOMIC
    assert_eq!(call(&mut k, &env, 3, 0x0d, &mut c), EOPNOTSUPP);
    let mut r = [0u8; 64];
    assert_eq!(call(&mut k, &env, 3, 0xA0, &mut r), 0);
    assert_eq!((get32(&r, 36), get32(&r, 40), get32(&r, 44)), (1, 1, 1));
    // Not a DRM request
    assert_eq!(k.ioctl(&env, 3, 0x5401, 0), ENOTTY);
    // GET_UNIQUE: the adapter's slot
    let mut slot = [0u8; 32];
    let mut u = [0u8; 16];
    put64(&mut u, 0, 32);
    put64(&mut u, 8, slot.as_mut_ptr() as u64);
    assert_eq!(call(&mut k, &env, 3, 0x01, &mut u), 0);
    assert_eq!(&slot[..12], b"0000:00:02.0");
}

#[test]
fn first_picture_takes_the_screen_and_shows_it() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 0xFF12_3456);
    assert_eq!(v.takes.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(v.pixel(0, 0), 0xFF12_3456);
    assert_eq!(v.pixel(W - 1, H - 1), 0xFF12_3456);
    assert_eq!(v.open.load(std::sync::atomic::Ordering::SeqCst), 0, "begin/end balanced");
    assert!(k.shown());
}

#[test]
fn flips_complete_at_the_next_vertical_blank_only() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    v.set_now(10 * PERIOD + 5);
    assert_eq!(flip(&mut k, &env, 7, fb, 0xAB), 0);
    // Nothing yet: the event waits for blank 11
    assert!(k.take_events(7, 64).is_none());
    assert_eq!(k.poll_bits(7), 0x4);
    let due = k.next_due(v.now.load(std::sync::atomic::Ordering::SeqCst)).unwrap();
    assert_eq!(due, 11 * PERIOD);
    // A second flip before the first completed: busy, as Linux
    assert_eq!(flip(&mut k, &env, 7, fb, 0xAC), EBUSY);
    v.set_now(due);
    assert_eq!(k.vblank_tick(due), 1);
    assert_eq!(k.woke, vec![7]);
    assert_eq!(k.poll_bits(7), 0x5);
    let ev = k.take_events(7, 64).unwrap().unwrap();
    assert_eq!(ev.len(), 32);
    assert_eq!(get32(&ev, 0), EV_FLIP);
    assert_eq!(get64(&ev, 8), 0xAB);
    assert_eq!(get32(&ev, 24), 11, "the blank's sequence");
    let us = 11 * PERIOD / 1000;
    assert_eq!((get32(&ev, 16) as u64, get32(&ev, 20) as u64), (us / 1_000_000, us % 1_000_000));
    // Now the next flip is accepted
    assert_eq!(flip(&mut k, &env, 7, fb, 0xAD), 0);
}

#[test]
fn completions_are_held_back_while_the_console_shows() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    assert_eq!(flip(&mut k, &env, 7, fb, 1), 0);
    // Ctrl+Alt+F1
    v.state.store(SCREEN_HIDDEN, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    assert!(k.hidden() && !k.shown());
    assert!(k.next_due(0).is_none(), "no blank to wait for");
    for t in 1..10 {
        assert_eq!(k.vblank_tick(t * PERIOD), 0);
    }
    assert!(k.take_events(7, 64).is_none(), "kwin keeps waiting: it stops drawing");
    assert_eq!(k.stats.held, 9);
    // Calls made meanwhile are counted
    let mut r = [0u8; 64];
    call(&mut k, &env, 7, 0xA0, &mut r);
    assert_eq!(k.stats.ioctls_hidden, 1);
    // Ctrl+Alt+F2: repainted, and the completion comes at the next blank
    fill(&k, k.mmap_file(7, 0x10_0000 * 4096, 4).map(|b| b.map_pgoff * 4096).unwrap(), (W * H * 4) as u64, 0xFF00_FF00);
    v.state.store(SCREEN_SHOWN, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    assert_eq!(v.pixel(5, 5), 0xFF00_FF00, "repainted from the current picture");
    let due = k.next_due(20 * PERIOD + 1).unwrap();
    assert_eq!(due, 21 * PERIOD);
    assert_eq!(k.vblank_tick(due), 1);
    assert!(k.take_events(7, 64).is_some());
}

#[test]
fn nothing_is_drawn_while_hidden() {
    let (mut k, v, env) = new();
    let (fb, h, off) = desktop(&mut k, &env, 1);
    v.state.store(SCREEN_HIDDEN, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    fill(&k, off, (W * H * 4) as u64, 2);
    let before = k.stats.presents;
    assert_eq!(flip(&mut k, &env, 7, fb, 1), 0);
    assert_eq!(k.stats.presents, before);
    assert_eq!(v.pixel(0, 0), 1);
    let _ = h;
}

#[test]
fn take_while_hidden_draws_nothing_until_shown() {
    let (mut k, v, env) = new();
    v.take_hidden.store(1, std::sync::atomic::Ordering::SeqCst);
    let _ = desktop(&mut k, &env, 9);
    assert!(k.hidden());
    assert_eq!(v.pixel(0, 0), 0x5555_5555, "the console's screen was not touched");
}

#[test]
fn damage_copies_only_the_clips() {
    let (mut k, v, env) = new();
    let (fb, _h, off) = desktop(&mut k, &env, 1);
    fill(&k, off, (W * H * 4) as u64, 3);
    // drm_clip_rect {x1, y1, x2, y2}
    let clip: [u16; 4] = [2, 3, 6, 5];
    let mut b = [0u8; 24];
    put32(&mut b, 0, fb);
    put32(&mut b, 12, 1);
    put64(&mut b, 16, clip.as_ptr() as u64);
    assert_eq!(call(&mut k, &env, 7, 0xB1, &mut b), 0);
    assert_eq!(v.pixel(2, 3), 3);
    assert_eq!(v.pixel(5, 4), 3);
    assert_eq!(v.pixel(6, 4), 1, "outside the clip");
    assert_eq!(v.pixel(2, 5), 1, "outside the clip");
    // No clips: the whole picture
    put32(&mut b, 12, 0);
    assert_eq!(call(&mut k, &env, 7, 0xB1, &mut b), 0);
    assert_eq!(v.pixel(W - 1, H - 1), 3);
}

#[test]
fn cursor_moves_repair_the_picture() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 0x0101_0101);
    let (ch, _p, csize) = dumb(&mut k, &env, 7, 64, 64);
    let coff = map_off(&mut k, &env, 7, ch);
    fill(&k, coff, csize, 0xFFFF_FFFF);
    let mut b = [0u8; 36];
    put32(&mut b, 0, 3); // BO | MOVE
    put32(&mut b, 4, CRTC_ID);
    put32(&mut b, 8, 10);
    put32(&mut b, 12, 10);
    put32(&mut b, 16, 4);
    put32(&mut b, 20, 4);
    put32(&mut b, 24, ch);
    assert_eq!(call(&mut k, &env, 7, 0xBB, &mut b), 0);
    // (the cursor blends colour; the picture keeps its X byte)
    assert_eq!(v.pixel(10, 10) & 0xFF_FFFF, 0xFF_FFFF);
    assert_eq!(v.pixel(14, 10), 0x0101_0101);
    put32(&mut b, 0, 2); // MOVE
    put32(&mut b, 8, 30);
    assert_eq!(call(&mut k, &env, 7, 0xBB, &mut b), 0);
    assert_eq!(v.pixel(10, 10), 0x0101_0101, "old place repaired");
    assert_eq!(v.pixel(30, 10) & 0xFF_FFFF, 0xFF_FFFF);
    // Too big a cursor, and a non-master
    put32(&mut b, 0, 1);
    put32(&mut b, 16, 65);
    assert_eq!(call(&mut k, &env, 7, 0xBB, &mut b), EINVAL);
    k.open(8);
    assert_eq!(call(&mut k, &env, 8, 0xBB, &mut b), EACCES);
}

#[test]
fn prime_export_and_import_share_the_buffer() {
    let (mut k, _v, env) = new();
    k.open(7);
    let (h, _p, size) = dumb(&mut k, &env, 7, W, H);
    let mut b = [0u8; 12];
    put32(&mut b, 0, h);
    put32(&mut b, 4, 0o2000000);
    assert_eq!(call(&mut k, &env, 7, 0x2d, &mut b), 0);
    let fd = get32(&b, 8);
    assert_eq!(fd, 100);
    // The DMA-BUF maps the same memory
    let via_buf = k.mmap_dmabuf(500, 0, size).unwrap();
    let off = map_off(&mut k, &env, 7, h);
    let via_file = k.mmap_file(7, off, size).unwrap();
    assert!(Arc::ptr_eq(&via_buf, &via_file));
    assert_eq!(k.mmap_dmabuf(500, 0, size + 4096).err(), Some(EINVAL));
    // Importing it into the same file gives the same handle; into another file a new one
    let mut i = [0u8; 12];
    put32(&mut i, 8, fd);
    assert_eq!(call(&mut k, &env, 7, 0x2e, &mut i), 0);
    assert_eq!(get32(&i, 0), h);
    k.open(8);
    assert_eq!(call(&mut k, &env, 8, 0x2e, &mut i), 0);
    let h8 = get32(&i, 0);
    assert!(Arc::ptr_eq(&k.files[&8].handles[&h8], &via_buf));
    // A descriptor that is no DMA-BUF of ours
    put32(&mut i, 8, 55);
    assert_eq!(call(&mut k, &env, 8, 0x2e, &mut i), EBADF);
    // The buffer outlives every GEM handle while the DMA-BUF lives (GEM_CLOSE: _IOW, 8 bytes)
    let weak = Arc::downgrade(&via_buf);
    drop((via_buf, via_file));
    let mut g = [0u8; 8];
    put32(&mut g, 0, h);
    assert_eq!(call_iow(&mut k, &env, 7, 0x09, &mut g), 0);
    put32(&mut g, 0, h8);
    assert_eq!(call_iow(&mut k, &env, 8, 0x09, &mut g), 0);
    assert!(weak.upgrade().is_some() && k.mmap_dmabuf(500, 0, 4096).is_ok());
    k.dmabuf_closed(500);
    assert_eq!(k.mmap_dmabuf(500, 0, 4096).err(), Some(EBADF));
    assert!(weak.upgrade().is_none(), "the last reference went with the DMA-BUF");
}

#[test]
fn mmap_offsets_are_checked() {
    let (mut k, _v, env) = new();
    k.open(7);
    let (h, _p, size) = dumb(&mut k, &env, 7, 16, 16);
    let off = map_off(&mut k, &env, 7, h);
    assert!(k.mmap_file(7, off, size).is_ok());
    assert_eq!(k.mmap_file(7, off + 1, 10).err(), Some(EINVAL));
    assert_eq!(k.mmap_file(7, off, size + 4096).err(), Some(EINVAL));
    assert_eq!(k.mmap_file(7, 4096, 4096).err(), Some(EINVAL));
    // After the last handle went, the offset no longer maps (DESTROY_DUMB: 4 bytes)
    let mut g = [0u8; 4];
    put32(&mut g, 0, h);
    assert_eq!(call(&mut k, &env, 7, 0xB4, &mut g), 0);
    assert_eq!(k.mmap_file(7, off, 4096).err(), Some(EINVAL));
}

#[test]
fn create_dumb_rejects_bad_sizes_and_reports_no_memory() {
    let (mut k, _v, env) = new();
    k.open(7);
    let mut b = [0u8; 32];
    put32(&mut b, 0, 10);
    put32(&mut b, 4, 9000);
    put32(&mut b, 8, 32);
    assert_eq!(call(&mut k, &env, 7, 0xB2, &mut b), EINVAL);
    put32(&mut b, 4, 10);
    *env.no_mem.borrow_mut() = true;
    assert_eq!(call(&mut k, &env, 7, 0xB2, &mut b), ENOMEM);
    assert_eq!(call(&mut k, &env, 7, 0xB2, &mut b), 0);
    assert_eq!(get32(&b, 20), 64, "pitch rounded to 64 bytes");
}

#[test]
fn master_rules() {
    let (mut k, _v, env) = new();
    k.open(1);
    k.open(2);
    // SET_MASTER / DROP_MASTER are _IO; AUTH_MAGIC is _IOW of 4 bytes
    let mut b = [0u8; 4];
    assert_eq!(call_io(&mut k, &env, 2, 0x1e), EBUSY, "1 is master");
    assert_eq!(call_iow(&mut k, &env, 2, 0x11, &mut b), EACCES);
    assert_eq!(call_iow(&mut k, &env, 1, 0x11, &mut b), 0);
    assert_eq!(call_io(&mut k, &env, 1, 0x1f), 0);
    assert_eq!(call_io(&mut k, &env, 1, 0x1f), EINVAL);
    assert_eq!(call_io(&mut k, &env, 2, 0x1e), 0);
    assert_eq!(setcrtc(&mut k, &env, 1, 100), EACCES);
}

#[test]
fn closing_the_master_gives_the_screen_back() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    assert_eq!(flip(&mut k, &env, 7, fb, 1), 0);
    k.close(7);
    assert_eq!(v.gives.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(v.state.load(std::sync::atomic::Ordering::SeqCst), SCREEN_CONSOLE);
    assert!(k.pending.is_empty(), "its completions went with it");
    assert!(!k.shown());
}

#[test]
fn a_session_without_master_keeps_the_screen_for_the_grace_time() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    // logind dropped mastership before the desktop closed its file
    assert_eq!(call_io(&mut k, &env, 7, 0x1f), 0);
    v.set_now(5_000_000_000);
    k.close(7);
    assert_eq!(v.gives.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!k.check_gone(5_000_000_000 + GONE_GRACE_NS - 1));
    assert!(k.check_gone(5_000_000_000 + GONE_GRACE_NS));
    assert_eq!(v.gives.load(std::sync::atomic::Ordering::SeqCst), 1);
    // A new session within the grace time keeps it
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    assert_eq!(call_io(&mut k, &env, 7, 0x1f), 0);
    k.close(7);
    k.open(9);
    assert!(!k.check_gone(u64::MAX / 2));
    assert_eq!(v.gives.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn wait_vblank_event_comes_at_the_blank() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    v.set_now(3 * PERIOD + 7);
    let mut b = [0u8; 24];
    put32(&mut b, 0, 0x0400_0000);
    put64(&mut b, 8, 0x77);
    assert_eq!(call(&mut k, &env, 7, 0x3a, &mut b), 0);
    assert_eq!(get32(&b, 4), 3);
    assert!(k.take_events(7, 64).is_none());
    assert_eq!(k.vblank_tick(4 * PERIOD), 1);
    let ev = k.take_events(7, 64).unwrap().unwrap();
    assert_eq!((get32(&ev, 0), get64(&ev, 8)), (EV_VBLANK, 0x77));
}

#[test]
fn reads_take_whole_events_only() {
    let (mut k, _v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    assert_eq!(flip(&mut k, &env, 7, fb, 1), 0);
    k.vblank_tick(u64::MAX / 4);
    assert_eq!(k.take_events(7, 16), Some(Err(EINVAL)));
    assert_eq!(k.take_events(7, 64).map(|r| r.map(|v| v.len())), Some(Ok(32)));
    assert!(k.take_events(7, 64).is_none());
    assert!(k.take_events(99, 64).is_none());
}

#[test]
fn rmfb_of_the_shown_picture_blacks_the_screen() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 0xFFFF_FFFF);
    let mut b = [0u8; 4];
    put32(&mut b, 0, fb);
    assert_eq!(call(&mut k, &env, 8, 0xAF, &mut b), ENOENT, "not its owner (and no such file)");
    assert_eq!(call(&mut k, &env, 7, 0xAF, &mut b), 0);
    assert_eq!(v.pixel(3, 3), 0);
    assert_eq!(call(&mut k, &env, 7, 0xAF, &mut b), ENOENT);
}

#[test]
fn panic_state_drops_the_screen() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    v.state.store(crate::proto::SCREEN_PANIC, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    assert!(!k.shown());
    let before = k.stats.presents;
    let _ = flip(&mut k, &env, 7, fb, 1);
    assert_eq!(k.stats.presents, before, "nothing drawn over the panic message");
}

#[test]
fn another_files_buffer_is_not_mapped_by_its_offset() {
    let (mut k, _v, env) = new();
    k.open(7);
    k.open(8);
    let (h, _p, size) = dumb(&mut k, &env, 7, 16, 16);
    let off = map_off(&mut k, &env, 7, h);
    assert!(k.mmap_file(7, off, size).is_ok());
    assert_eq!(k.mmap_file(8, off, size).err(), Some(EACCES), "file 8 holds no handle to it");
    // A length that would wrap is refused, not wrapped past the check
    assert_eq!(k.mmap_file(7, off, u64::MAX - 100).err(), Some(EINVAL));
    let mut b = [0u8; 12];
    put32(&mut b, 0, h);
    assert_eq!(call(&mut k, &env, 7, 0x2d, &mut b), 0);
    assert_eq!(k.mmap_dmabuf(500, 4096, u64::MAX - 100).err(), Some(EINVAL));
}

#[test]
fn a_flip_on_the_blank_itself_waits_for_the_next() {
    let (mut k, v, env) = new();
    let (fb, ..) = desktop(&mut k, &env, 1);
    v.set_now(5 * PERIOD);
    assert_eq!(flip(&mut k, &env, 7, fb, 1), 0);
    assert_eq!(k.next_due(5 * PERIOD), Some(6 * PERIOD));
}

#[test]
fn a_stale_console_notice_does_not_drop_a_new_session() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    // The screen thread saw "console" (an earlier give), but the session took it again
    // since: the status page says shown, and the session keeps the screen
    assert_eq!(v.state.load(std::sync::atomic::Ordering::SeqCst), SCREEN_SHOWN);
    k.state_changed();
    assert!(k.shown());
    // Taken back for real (a panic): dropped
    v.state.store(SCREEN_CONSOLE, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    assert!(!k.shown());
}

#[test]
fn far_cursor_positions_are_clamped() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    let (ch, _p, _s) = dumb(&mut k, &env, 7, 64, 64);
    let mut b = [0u8; 36];
    put32(&mut b, 0, 3);
    put32(&mut b, 4, CRTC_ID);
    put32(&mut b, 8, i32::MAX as u32);
    put32(&mut b, 12, i32::MIN as u32);
    put32(&mut b, 16, 64);
    put32(&mut b, 20, 64);
    put32(&mut b, 24, ch);
    assert_eq!(call(&mut k, &env, 7, 0xBB, &mut b), 0);
    put32(&mut b, 0, 2);
    assert_eq!(call(&mut k, &env, 7, 0xBB, &mut b), 0, "moving again repairs without overflow");
    assert_eq!(v.pixel(0, 0), 1);
}

#[test]
fn vblank_events_held_behind_the_console_are_capped() {
    let (mut k, v, env) = new();
    let _ = desktop(&mut k, &env, 1);
    v.state.store(SCREEN_HIDDEN, std::sync::atomic::Ordering::SeqCst);
    k.state_changed();
    let mut b = [0u8; 24];
    put32(&mut b, 0, 0x0400_0000);
    for _ in 0..PENDING_MAX {
        assert_eq!(call(&mut k, &env, 7, 0x3a, &mut b), 0);
    }
    assert_eq!(call(&mut k, &env, 7, 0x3a, &mut b), EBUSY);
    assert_eq!(k.pending.len(), PENDING_MAX);
}

#[test]
fn too_many_damage_rectangles_repaint_everything() {
    let (mut k, v, env) = new();
    let (fb, _h, off) = desktop(&mut k, &env, 1);
    fill(&k, off, (W * H * 4) as u64, 4);
    let clips = vec![0u16; 4 * 300];
    let mut b = [0u8; 24];
    put32(&mut b, 0, fb);
    put32(&mut b, 12, 300);
    put64(&mut b, 16, clips.as_ptr() as u64);
    assert_eq!(call(&mut k, &env, 7, 0xB1, &mut b), 0);
    assert_eq!(v.pixel(W - 1, H - 1), 4);
}

#[test]
fn set_master_needs_the_capability_or_an_earlier_mastership() {
    let (mut k, _v, env) = new();
    k.open(1); // first opener: master
    k.open(2);
    assert_eq!(call_io(&mut k, &env, 1, 0x1f), 0);
    *env.unprivileged.borrow_mut() = true;
    assert_eq!(call_io(&mut k, &env, 2, 0x1e), EACCES, "an unprivileged file that never was master");
    assert_eq!(call_io(&mut k, &env, 1, 0x1e), 0, "the earlier master takes it back");
    assert_eq!(call_io(&mut k, &env, 1, 0x1f), 0);
    *env.unprivileged.borrow_mut() = false;
    assert_eq!(call_io(&mut k, &env, 2, 0x1e), 0, "CAP_SYS_ADMIN (logind)");
}

#[test]
fn dumb_buffers_are_limited_per_file_and_in_all() {
    let (mut k, _v, env) = new();
    k.limits = (64 * 1024, 96 * 1024);
    k.open(7);
    k.open(8);
    // 64x64x4 = 16 KiB each
    let mut hs = Vec::new();
    for _ in 0..4 {
        hs.push(dumb(&mut k, &env, 7, 64, 64).0);
    }
    let mut b = [0u8; 32];
    put32(&mut b, 0, 64);
    put32(&mut b, 4, 64);
    put32(&mut b, 8, 32);
    assert_eq!(call(&mut k, &env, 7, 0xB2, &mut b), ENOMEM, "file 7 holds 64 KiB");
    let _ = dumb(&mut k, &env, 8, 64, 64);
    let _ = dumb(&mut k, &env, 8, 64, 64);
    assert_eq!(call(&mut k, &env, 8, 0xB2, &mut b), ENOMEM, "96 KiB alive in all");
    // A buffer that goes gives its bytes back
    let mut g = [0u8; 4];
    put32(&mut g, 0, hs[0]);
    assert_eq!(call(&mut k, &env, 7, 0xB4, &mut g), 0);
    assert_eq!(call(&mut k, &env, 8, 0xB2, &mut b), 0);
    // Closing a file frees what it made
    k.close(7);
    assert_eq!(call(&mut k, &env, 8, 0xB2, &mut b), 0);
}
