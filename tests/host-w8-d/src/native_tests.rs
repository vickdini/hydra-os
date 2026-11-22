//! display-server's native core (`native.rs`): copies, the cursor, the vertical blank.

use crate::native::*;

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
