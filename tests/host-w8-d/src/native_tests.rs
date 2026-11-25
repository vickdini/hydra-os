//! display-server's native core (`native.rs`): copies, the cursor, the vertical blank.

use crate::native::*;

/// A copy as the old `copy_rect` made it: everything in the rectangle written (a copy of
/// the screen that is not valid yet), no cursor.
fn copy_rect(t: &Target, src: Option<&Src>, crtc: (u32, u32), x0: u32, y0: u32, x1: u32, y1: u32) {
    let mut sh = Shadow::new(t.width, t.height);
    draw_rect(t, &mut sh, src, crtc, None, x0, y0, x1, y1);
}

/// The cursor drawn over the picture in its own area (the old `compose_cursor`).
fn compose_cursor(t: &Target, src: Option<&Src>, crtc: (u32, u32), cur: &Cursor, x: i32, y: i32) -> (i32, i32, u32, u32) {
    let mut sh = Shadow::new(t.width, t.height);
    let p = Placed { cur, x, y };
    let (x0, y0) = (x.max(0) as u32, y.max(0) as u32);
    let (x1, y1) = ((x + cur.w as i32).max(0) as u32, (y + cur.h as i32).max(0) as u32);
    draw_rect(t, &mut sh, src, crtc, Some(&p), x0, y0, x1, y1);
    (x, y, cur.w, cur.h)
}

fn target(buf: &mut [u8], w: u32, h: u32, stride: usize, bgr: bool) -> Target {
    assert!(buf.len() >= stride * h as usize * 4);
    Target { ptr: buf.as_mut_ptr(), stride, width: w, height: h, bgr }
}

fn px(buf: &[u8], stride: usize, x: usize, y: usize) -> u32 {
    let i = (y * stride + x) * 4;
    u32::from_le_bytes(buf[i..i + 4].try_into().unwrap())
}

/// A picture whose pixel (x, y) is `0xFF000000 | y << 12 | x`.
fn picture(w: u32, h: u32, pitch: u32) -> Vec<u8> {
    let mut v = vec![0u8; (pitch * h) as usize];
    for y in 0..h {
        for x in 0..w {
            let i = (y * pitch + x * 4) as usize;
            v[i..i + 4].copy_from_slice(&(0xFF00_0000 | y << 12 | x).to_le_bytes());
        }
    }
    v
}

fn src(v: &[u8], w: u32, h: u32, pitch: u32) -> Src {
    Src { base: v.as_ptr(), len: v.len() as u64, offset: 0, pitch, width: w, height: h }
}

#[test]
fn copy_whole_picture_with_padding() {
    let (w, h, stride) = (8u32, 4u32, 10usize);
    let pic = picture(w, h, 64);
    let mut scr = vec![0xAAu8; stride * h as usize * 4];
    let t = target(&mut scr, w, h, stride, true);
    copy_rect(&t, Some(&src(&pic, w, h, 64)), (0, 0), 0, 0, w, h);
    for y in 0..h as usize {
        for x in 0..w as usize {
            assert_eq!(px(&scr, stride, x, y), 0xFF00_0000 | (y as u32) << 12 | x as u32);
        }
        // The padding past the visible width is never written
        assert_eq!(px(&scr, stride, 9, y), 0xAAAA_AAAA);
    }
}

#[test]
fn copy_only_the_damaged_rect() {
    let (w, h) = (8u32, 6u32);
    let pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, w as usize, true);
    copy_rect(&t, Some(&src(&pic, w, h, w * 4)), (0, 0), 2, 1, 5, 3);
    for y in 0..h as usize {
        for x in 0..w as usize {
            let inside = (2..5).contains(&x) && (1..3).contains(&y);
            assert_eq!(px(&scr, w as usize, x, y) != 0, inside, "({x},{y})");
        }
    }
}

#[test]
fn copy_clips_and_blacks_out_past_the_picture() {
    let (w, h) = (8u32, 4u32);
    // A smaller picture seen from (2, 1): the rest of the screen goes black
    let pic = picture(6, 4, 24);
    let mut scr = vec![0x11u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, w as usize, true);
    copy_rect(&t, Some(&src(&pic, 6, 4, 24)), (2, 1), 0, 0, 100, 100);
    assert_eq!(px(&scr, 8, 0, 0), 0xFF00_0000 | 1 << 12 | 2);
    assert_eq!(px(&scr, 8, 3, 2), 0xFF00_0000 | 3 << 12 | 5);
    assert_eq!(px(&scr, 8, 4, 0), 0, "past the picture's width");
    assert_eq!(px(&scr, 8, 0, 3), 0, "past the picture's height");
    // No picture at all: black (a target made afresh: `px` borrowed the buffer meanwhile)
    let t = target(&mut scr, w, h, w as usize, true);
    copy_rect(&t, None, (0, 0), 0, 0, w, h);
    assert!(scr.iter().all(|&b| b == 0));
}

#[test]
fn copy_never_reads_past_a_short_buffer() {
    let (w, h) = (4u32, 4u32);
    let pic = picture(4, 2, 16); // only 2 rows really there
    let s = Src { base: pic.as_ptr(), len: pic.len() as u64, offset: 0, pitch: 16, width: 4, height: 4 };
    let mut scr = vec![0x77u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, 4, true);
    copy_rect(&t, Some(&s), (0, 0), 0, 0, w, h);
    assert_eq!(px(&scr, 4, 1, 1), 0xFF00_0000 | 1 << 12 | 1);
    assert_eq!(px(&scr, 4, 1, 3), 0);
}

#[test]
fn rgb_screens_get_red_and_blue_swapped() {
    let pic = vec![0x01, 0x02, 0x03, 0xFF];
    let mut scr = vec![0u8; 4];
    let t = target(&mut scr, 1, 1, 1, false);
    copy_rect(&t, Some(&src(&pic, 1, 1, 4)), (0, 0), 0, 0, 1, 1);
    assert_eq!(&scr, &[0x03, 0x02, 0x01, 0xFF]);
}

#[test]
fn blend_is_premultiplied_over() {
    let mut d = [100u8, 100, 100, 0];
    blend(&mut d, &[0, 0, 0, 0]);
    assert_eq!(d, [100, 100, 100, 0], "transparent leaves the picture");
    blend(&mut d, &[10, 20, 30, 255]);
    assert_eq!(&d[..3], &[10, 20, 30], "opaque replaces");
    let mut d = [200u8, 200, 200, 0];
    blend(&mut d, &[50, 50, 50, 128]);
    assert_eq!(d[0], (50 + 200 * 127 / 255) as u8);
}

#[test]
fn cursor_is_composed_from_the_picture_not_the_screen() {
    let (w, h) = (8u32, 8u32);
    let pic = picture(w, h, w * 4);
    let mut scr = vec![0x99u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, w as usize, true);
    // A 2x2 cursor: opaque white at (0,0), transparent elsewhere
    let mut cur = vec![0u8; 16];
    cur[0..4].copy_from_slice(&[255, 255, 255, 255]);
    let c = Cursor { base: cur.as_ptr(), len: 16, w: 2, h: 2 };
    let area = compose_cursor(&t, Some(&src(&pic, w, h, w * 4)), (0, 0), &c, 3, 4);
    assert_eq!(area, (3, 4, 2, 2));
    assert_eq!(px(&scr, 8, 3, 4), 0xFFFF_FFFF);
    // Transparent cursor pixels show the picture (the 0x99 screen contents never leak in)
    assert_eq!(px(&scr, 8, 4, 4), 0xFF00_0000 | 4 << 12 | 4);
    assert_eq!(px(&scr, 8, 3, 5), 0xFF00_0000 | 5 << 12 | 3);
    // Outside the cursor nothing was touched
    assert_eq!(px(&scr, 8, 5, 4), 0x9999_9999);
}

#[test]
fn cursor_clips_at_every_edge() {
    let (w, h) = (4u32, 4u32);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, 4, true);
    let cur = vec![0xFFu8; 64 * 64 * 4];
    let c = Cursor { base: cur.as_ptr(), len: cur.len() as u64, w: 64, h: 64 };
    for (x, y) in [(-63, -63), (3, 3), (-10, 2), (2, -10), (100, 100), (-100, -100)] {
        compose_cursor(&t, None, (0, 0), &c, x, y);
    }
    assert_eq!(px(&scr, 4, 0, 0), 0x00FF_FFFF);
    assert_eq!(px(&scr, 4, 3, 3), 0x00FF_FFFF);
}

#[test]
fn vblank_paces_at_sixty_hertz() {
    let v = Vblank::new(60_000);
    assert_eq!(v.period_ns, 16_666_666);
    assert_eq!(v.next_after(0), 1);
    assert_eq!(v.next_after(16_666_665), 1);
    assert_eq!(v.next_after(16_666_666), 2);
    assert_eq!(v.time_of(3), 49_999_998);
    assert_eq!(v.count_at(49_999_998), 3);
    // Flipping as fast as possible, each flip waiting for its completion: 60 a second
    let (mut t, mut n) = (0u64, 0);
    while t < 1_000_000_000 {
        t = v.time_of(v.next_after(t));
        n += 1;
    }
    assert!((59..=61).contains(&n), "{n} completions in a second");
}

// wave11 GG: the copy of what the screen shows, and writes only where rows change

/// A screen of `w` x `h` (stride = w) as a target, its copy made valid by a first full draw.
fn shown_screen(scr: &mut [u8], pic: &[u8], w: u32, h: u32, cur: Option<&Placed>) -> (Target, Shadow) {
    let t = target(scr, w, h, w as usize, true);
    let mut sh = Shadow::new(w, h);
    let d = draw_rect(&t, &mut sh, Some(&src(pic, w, h, w * 4)), (0, 0), cur, 0, 0, w, h);
    assert_eq!(d.written, (w * h) as u64, "a copy not yet valid writes everything");
    assert!(sh.is_valid());
    (t, sh)
}

/// Fills the screen behind `t` with `b` (what is not written later keeps it).
fn poison(t: &Target, w: u32, h: u32, b: u8) {
    unsafe { core::ptr::write_bytes(t.ptr, b, (w * h * 4) as usize) };
}

#[test]
fn an_unchanged_picture_writes_nothing() {
    let (w, h) = (40u32, 10u32);
    let pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, w, h);
    assert_eq!(d, Drawn { composed: (w * h) as u64, written: 0 });
}

#[test]
fn a_changed_pixel_writes_its_block_only() {
    let (w, h) = (40u32, 10u32);
    let mut pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    poison(&t, w, h, 0xEE);
    let i = ((5 * w + 20) * 4) as usize;
    pic[i..i + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, w, h);
    assert_eq!(d.written, BLOCK as u64, "one block");
    assert_eq!(px(&scr, w as usize, 20, 5), 0x1234_5678);
    // The block (pixels 16..32 of row 5) was written whole, nothing else
    assert_eq!(px(&scr, w as usize, 16, 5), 0xFF00_0000 | 5 << 12 | 16);
    assert_eq!(px(&scr, w as usize, 15, 5), 0xEEEE_EEEE);
    assert_eq!(px(&scr, w as usize, 32, 5), 0xEEEE_EEEE);
    assert_eq!(px(&scr, w as usize, 20, 4), 0xEEEE_EEEE);
}

#[test]
fn nearby_changes_merge_into_one_write() {
    let (w, h) = (128u32, 1u32);
    let mut pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    poison(&t, w, h, 0xEE);
    // Blocks 0 and 2 change (one unchanged block between): one run of 3 blocks
    for x in [0usize, 33] {
        pic[x * 4] ^= 0xFF;
    }
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, w, h);
    assert_eq!(d.written, 3 * BLOCK as u64);
    assert_eq!(px(&scr, w as usize, 20, 0), 0xFF00_0000 | 20, "the gap was written too");
    // Blocks far apart: two writes, the middle untouched
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    poison(&t, w, h, 0xEE);
    for x in [0usize, 120] {
        pic[x * 4] ^= 0xFF;
    }
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, w, h);
    assert_eq!(d.written, 2 * BLOCK as u64);
    assert_eq!(px(&scr, w as usize, 60, 0), 0xEEEE_EEEE);
}

#[test]
fn the_cursor_moves_without_ever_leaving_the_screen() {
    let (w, h) = (64u32, 32u32);
    let pic = picture(w, h, w * 4);
    let cur = vec![255u8; 8 * 8 * 4]; // an opaque white 8x8 cursor
    let c = Cursor { base: cur.as_ptr(), len: cur.len() as u64, w: 8, h: 8 };
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let a = Placed { cur: &c, x: 10, y: 10 };
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, Some(&a));
    assert_eq!(px(&scr, w as usize, 12, 12), 0xFFFF_FFFF);
    // Move by 3 pixels: the old area, then the new one, each composed with the cursor at
    // its new place. Pixels white before and after are never written with the picture.
    poison(&t, w, h, 0xEE);
    let b = Placed { cur: &c, x: 13, y: 10 };
    let s = src(&pic, w, h, w * 4);
    draw_rect(&t, &mut sh, Some(&s), (0, 0), Some(&b), 10, 10, 18, 18);
    draw_rect(&t, &mut sh, Some(&s), (0, 0), Some(&b), 13, 10, 21, 18);
    // Columns 10..13 became picture again, the cursor is at 13..21
    assert_eq!(px(&scr, w as usize, 11, 12), 0xFF00_0000 | 12 << 12 | 11);
    assert_eq!(px(&scr, w as usize, 14, 12), 0xFFFF_FFFF);
    assert_eq!(px(&scr, w as usize, 20, 12), 0xFFFF_FFFF);
    // Row 20 (below both areas) was not touched
    assert_eq!(px(&scr, w as usize, 12, 20), 0xEEEE_EEEE);
}

#[test]
fn an_invalidated_copy_rewrites_everything() {
    let (w, h) = (20u32, 4u32);
    let pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    // The console drew over the screen
    poison(&t, w, h, 0x33);
    sh.invalidate();
    // A partial draw writes its rectangle whole but does not make the copy valid
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, 5, 2);
    assert_eq!(d.written, 10);
    assert!(!sh.is_valid());
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 0, 0, w, h);
    assert_eq!(d.written, (w * h) as u64);
    assert!(sh.is_valid());
    assert_eq!(px(&scr, w as usize, 19, 3), 0xFF00_0000 | 3 << 12 | 19);
}

#[test]
fn rgb_screens_compare_in_screen_order() {
    let pic = vec![0x01u8, 0x02, 0x03, 0xFF];
    let mut scr = vec![0u8; 4];
    let t = target(&mut scr, 1, 1, 1, false);
    let mut sh = Shadow::new(1, 1);
    draw_rect(&t, &mut sh, Some(&src(&pic, 1, 1, 4)), (0, 0), None, 0, 0, 1, 1);
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, 1, 1, 4)), (0, 0), None, 0, 0, 1, 1);
    assert_eq!(d.written, 0);
    assert_eq!(&scr, &[0x03, 0x02, 0x01, 0xFF]);
}

#[test]
fn draws_clip_to_the_screen_and_the_copy() {
    let (w, h) = (8u32, 4u32);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let t = target(&mut scr, w, h, w as usize, true);
    let mut sh = Shadow::new(w, h);
    assert_eq!(draw_rect(&t, &mut sh, None, (0, 0), None, 9, 0, 20, 20), Drawn::default());
    assert_eq!(draw_rect(&t, &mut sh, None, (0, 0), None, 0, 0, 100, 100).composed, (w * h) as u64);
}

#[test]
fn blocks_follow_the_screens_grid_not_the_rectangles() {
    // A rectangle from column 10: its first block is columns 10..16, the next 16..32
    let (w, h) = (64u32, 1u32);
    let mut pic = picture(w, h, w * 4);
    let mut scr = vec![0u8; (w * h * 4) as usize];
    let (t, mut sh) = shown_screen(&mut scr, &pic, w, h, None);
    poison(&t, w, h, 0xEE);
    pic[20 * 4] ^= 0xFF;
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 10, 0, 50, 1);
    assert_eq!(d.written, BLOCK as u64, "columns 16..32");
    assert_eq!(px(&scr, w as usize, 15, 0), 0xEEEE_EEEE);
    assert_eq!(px(&scr, w as usize, 16, 0), 0xFF00_0000 | 16);
    assert_eq!(px(&scr, w as usize, 31, 0), 0xFF00_0000 | 31);
    assert_eq!(px(&scr, w as usize, 32, 0), 0xEEEE_EEEE);
    // A change in the partial first block (columns 10..16) writes only those 6 pixels
    pic[12 * 4] ^= 0xFF;
    let d = draw_rect(&t, &mut sh, Some(&src(&pic, w, h, w * 4)), (0, 0), None, 10, 0, 50, 1);
    assert_eq!(d.written, 6);
    assert_eq!(px(&scr, w as usize, 9, 0), 0xEEEE_EEEE);
}
