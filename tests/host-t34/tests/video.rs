//! `src/video/*`: the framebuffer primitives, the text console (with its ANSI subset), the
//! GOP set-up, the boot splash and the font.

mod common;
use common::*;
use k::video::console::{self as vc, CursorShape, VideoConsole};
use k::video::font::{get_char_glyph, FONT_HEIGHT, FONT_WIDTH};
use k::video::framebuffer::Framebuffer;
use k::video::gop::{mode_info_for, VideoModeInfo};
use uefi::proto::console::gop::PixelFormat;

/// A leaked framebuffer of `w`x`h` (stride `stride`).
fn fb(w: usize, h: usize, stride: usize, bgr: bool) -> (Framebuffer, &'static mut [u8]) {
    let mem: &'static mut [u8] = Box::leak(vec![0u8; stride * h * 4].into_boxed_slice());
    let info = mode_info_for(mem.as_mut_ptr(), mem.len(), w, h, stride, if bgr { PixelFormat::Bgr } else { PixelFormat::Rgb });
    (Framebuffer::new(info), mem)
}

// ----------------------------------------------------------------------------- font

#[test]
fn glyphs_and_the_fallback() {
    assert_eq!((FONT_WIDTH, FONT_HEIGHT), (8, 16));
    assert!(get_char_glyph(' ').iter().all(|&r| r == 0));
    assert!(get_char_glyph('A').iter().any(|&r| r != 0));
    // Outside printable ASCII: the same fallback glyph for all
    let unknown = get_char_glyph('\u{1}');
    assert_eq!(get_char_glyph('é'), unknown);
    assert_eq!(get_char_glyph('\u{7f}'), unknown);
    assert_ne!(get_char_glyph('~'), unknown);
}

// ---------------------------------------------------------------------- framebuffer

#[test]
fn pixels_in_both_byte_orders() {
    let (mut f, mem) = fb(4, 2, 4, false);
    assert_eq!((f.width(), f.height(), f.stride(), f.is_bgr(), f.size()), (4, 2, 4, false, 32));
    f.put_pixel(1, 1, 10, 20, 30);
    assert_eq!(px(mem, 4, 1, 1), [10, 20, 30, 0]);
    let (mut g, mem2) = fb(4, 2, 4, true);
    assert!(g.is_bgr());
    g.put_pixel(3, 0, 10, 20, 30);
    assert_eq!(px(mem2, 4, 3, 0), [30, 20, 10, 0]);
    // Outside the screen: nothing
    f.put_pixel(4, 0, 1, 1, 1);
    f.put_pixel(0, 2, 1, 1, 1);
    assert_eq!(mem.iter().filter(|&&b| b != 0).count(), 3);
}

#[test]
fn a_stride_wider_than_the_screen() {
    let (mut f, mem) = fb(3, 2, 5, false);
    f.clear(9, 9, 9);
    // Padding pixels are not drawn
    assert_eq!(px(mem, 5, 2, 1), [9, 9, 9, 0]);
    assert_eq!(px(mem, 5, 3, 1), [0, 0, 0, 0]);
    assert_eq!(px(mem, 5, 4, 0), [0, 0, 0, 0]);
}

#[test]
fn pixels_beyond_the_buffer_are_refused() {
    // A buffer smaller than the mode says: the last pixel would overrun
    let mem: &'static mut [u8] = Box::leak(vec![0u8; 15].into_boxed_slice());
    let info = VideoModeInfo { base_ptr: mem.as_mut_ptr(), size: 15, width: 4, height: 1, stride: 4, is_bgr: false, text_cols: 0, text_rows: 0 };
    let mut f = Framebuffer::new(info);
    f.put_pixel(3, 0, 1, 2, 3);
    f.put_pixel(2, 0, 1, 2, 3);
    assert_eq!(&mem[8..12], &[1, 2, 3, 0]);
    assert_eq!(&mem[12..15], &[0, 0, 0]);
    f.invert_rect(0, 0, 4, 1);
    assert_eq!(&mem[8..12], &[1, 2, 3, 0], "a row beyond the buffer is not inverted");
}

#[test]
fn rectangles_are_clipped() {
    let (mut f, mem) = fb(8, 8, 8, false);
    f.fill_rect(6, 6, 10, 10, 1, 2, 3);
    assert_eq!(mem.chunks(4).filter(|p| p[0] == 1).count(), 4);
    assert_eq!(px(mem, 8, 7, 7), [1, 2, 3, 0]);
    // Inversion keeps the fourth byte and can be undone
    f.invert_rect(6, 6, 5, 5);
    assert_eq!(px(mem, 8, 7, 7), [254, 253, 252, 0]);
    assert_eq!(px(mem, 8, 5, 5), [0, 0, 0, 0]);
    f.invert_rect(6, 6, 5, 5);
    assert_eq!(px(mem, 8, 6, 6), [1, 2, 3, 0]);
    // Starting outside: nothing
    f.invert_rect(8, 0, 2, 2);
    f.invert_rect(0, 8, 2, 2);
    assert_eq!(mem.chunks(4).filter(|p| p[0] != 0).count(), 4);
}

#[test]
fn characters_are_drawn_from_the_font() {
    let (mut f, mem) = fb(16, 16, 16, false);
    f.draw_char(8, 0, 'H', (255, 255, 255), (0, 0, 1));
    let glyph = get_char_glyph('H');
    for row in 0..16 {
        for col in 0..8 {
            let lit = (glyph[row] >> (7 - col)) & 1 == 1;
            assert_eq!(px(mem, 16, 8 + col, row)[0], if lit { 255 } else { 0 }, "row {} col {}", row, col);
            assert_eq!(px(mem, 16, 8 + col, row)[2], if lit { 255 } else { 1 });
        }
    }
    // A cell that does not fit is not drawn at all
    let before = mem.to_vec();
    f.draw_char(9, 0, 'H', (255, 0, 0), (0, 0, 0));
    f.draw_char(0, 1, 'H', (255, 0, 0), (0, 0, 0));
    assert_eq!(mem.to_vec(), before);
}

#[test]
fn scrolling_moves_lines_up() {
    let (mut f, mem) = fb(2, 4, 2, false);
    for y in 0..4 {
        f.fill_rect(0, y, 2, 1, y as u8 + 1, 0, 0);
    }
    f.scroll_up(1, (9, 9, 9));
    let col: Vec<u8> = (0..4).map(|y| px(mem, 2, 0, y)[0]).collect();
    assert_eq!(col, vec![2, 3, 4, 9]);
    // Everything or nothing: a clear
    f.scroll_up(4, (7, 7, 7));
    assert!((0..4).all(|y| px(mem, 2, 1, y)[0] == 7));
    f.scroll_up(0, (5, 5, 5));
    assert!((0..4).all(|y| px(mem, 2, 0, y)[0] == 5));
    // Drawing elsewhere
    let mut other = vec![0u8; mem.len()];
    f.set_base(other.as_mut_ptr());
    assert_eq!(f.base_ptr(), other.as_mut_ptr());
    f.put_pixel(0, 0, 1, 1, 1);
    assert_eq!(other[0], 1);
    assert_eq!(mem[0], 5);
}

// --------------------------------------------------------------------------- the GOP

#[test]
fn mode_information() {
    let mut mem = [0u8; 16];
    let i = mode_info_for(mem.as_mut_ptr(), 4096, 1024, 768, 1088, PixelFormat::Bgr);
    assert_eq!((i.size, i.width, i.height, i.stride, i.is_bgr, i.text_cols, i.text_rows), (4096, 1024, 768, 1088, true, 128, 48));
    assert!(!mode_info_for(mem.as_mut_ptr(), 1, 8, 16, 8, PixelFormat::Rgb).is_bgr);
    // Other formats (bit masks, blt only) are drawn as RGB
    assert!(!mode_info_for(mem.as_mut_ptr(), 1, 8, 16, 8, PixelFormat::BltOnly).is_bgr);
}

#[test]
fn installing_the_framebuffer_maps_it_and_starts_the_console() {
    let _g = setup();
    assert!(k::video::get_video_info().is_none());
    assert!(!vc::is_active());
    // Before Hydra's page table exists: no mapping
    let mem: &'static mut [u8] = Box::leak(vec![0u8; 8192 + 64].into_boxed_slice());
    let info = mode_info_for(mem.as_mut_ptr(), mem.len(), 32, 64, 32, PixelFormat::Bgr);
    k::video::gop::install(info);
    assert!(!fake::logged("map_range"));
    assert!(vc::is_active());
    let got = k::video::get_video_info().unwrap();
    assert_eq!((got.base_ptr, got.size, got.width, got.height, got.stride, got.is_bgr, got.text_cols, got.text_rows), (mem.as_mut_ptr(), mem.len(), 32, 64, 32, true, 4, 4));
    // With it: the framebuffer's pages are mapped (3 pages for 8 KiB + 64 bytes)
    *k::memory::paging::KERNEL_SPACE.lock() = Some(k::memory::paging::AddressSpace);
    k::video::gop::install(info);
    *k::memory::paging::KERNEL_SPACE.lock() = None;
    let page = mem.as_ptr() as u64 & !0xfff;
    assert!(fake::logged(&format!("map_range {:#x} {:#x} 3", page, page)));
}

#[test]
fn without_gop_the_firmware_console_stays() {
    let _g = setup();
    // The fake firmware has no graphics output protocol
    assert_eq!(k::video::init_gop().unwrap_err(), "Failed to find GraphicsOutput protocol handle");
    assert!(!vc::is_active());
}

// ------------------------------------------------------------------- the text console

fn console(w: usize, h: usize) -> (VideoConsole, &'static mut [u8]) {
    let (f, mem) = fb(w, h, w, false);
    (VideoConsole::new(f), mem)
}

/// Whether text cell `(col, row)` has any pixel that is not black.
fn cell_lit(mem: &[u8], stride: usize, col: usize, row: usize) -> bool {
    (0..16).any(|y| (0..8).any(|x| px(mem, stride, col * 8 + x, row * 16 + y)[..3] != [0, 0, 0]))
}

#[test]
fn text_layout() {
    let (mut c, mem) = console(80, 48);
    assert_eq!((c.cols(), c.rows(), c.cursor_pos()), (10, 3, (0, 0)));
    c.write_str("ab\tc");
    // A tab goes to the next multiple of 4
    assert_eq!(c.cursor_pos(), (5, 0));
    assert!(cell_lit(mem, 80, 0, 0) && cell_lit(mem, 80, 4, 0));
    assert!(!cell_lit(mem, 80, 2, 0));
    c.write_str("\r");
    assert_eq!(c.cursor_pos(), (0, 0));
    c.write_str("\x08");
    assert_eq!(c.cursor_pos(), (0, 0));
    c.write_str("xyz\x08");
    assert_eq!(c.cursor_pos(), (2, 0));
    assert!(!cell_lit(mem, 80, 2, 0), "backspace erases");
    // Wrapping at the right edge
    c.write_str("\n0123456789Z");
    assert_eq!(c.cursor_pos(), (1, 2));
    // A tab at the end of the line stops at the edge
    c.write_str("\n\n");
    c.write_str("01234567\t");
    assert_eq!(c.cursor_pos().0, 10);
    use core::fmt::Write;
    write!(c, "{}", 5).unwrap();
    assert_eq!(c.cursor_pos(), (1, 2));
}

#[test]
fn the_bottom_line_scrolls() {
    let (mut c, mem) = console(16, 32);
    c.write_str("A\nB");
    assert!(cell_lit(mem, 16, 0, 0) && cell_lit(mem, 16, 0, 1));
    c.write_str("\n");
    // 'B' moved to the first row, the last row is empty
    assert_eq!(c.cursor_pos(), (0, 1));
    let b = get_char_glyph('B');
    let lit_rows: Vec<bool> = (0..16).map(|y| px(mem, 16, 0, y)[0] != 0 || (1..8).any(|x| px(mem, 16, x, y)[0] != 0)).collect();
    assert_eq!(lit_rows, b.iter().map(|&r| r != 0).collect::<Vec<_>>());
    assert!(!cell_lit(mem, 16, 0, 1));
    c.clear();
    assert!(mem.iter().all(|&x| x == 0));
    assert_eq!(c.cursor_pos(), (0, 0));
}

#[test]
fn cursor_shapes_and_visibility() {
    let (mut c, mem) = console(32, 32);
    let lit = |mem: &[u8]| -> Vec<(usize, usize)> { (0..32).flat_map(|y| (0..32).map(move |x| (x, y))).filter(|&(x, y)| px(mem, 32, x, y)[0] != 0).collect() };
    assert_eq!(c.cursor_shape(), CursorShape::Underline);
    c.show_cursor();
    // Underline: the last 3 rows of the cell
    assert_eq!(lit(mem).len(), 8 * 3);
    assert!(lit(mem).iter().all(|&(x, y)| x < 8 && (13..16).contains(&y)));
    c.show_cursor(); // already there: unchanged
    assert_eq!(lit(mem).len(), 24);
    c.set_cursor_shape(CursorShape::Bar);
    assert_eq!(lit(mem).len(), 2 * 16);
    c.set_cursor_shape(CursorShape::Bar);
    c.set_cursor_shape(CursorShape::Block);
    assert_eq!(lit(mem).len(), 8 * 16);
    // Moving it redraws it at the new cell, clamped to the screen
    c.set_cursor_pos(9, 9);
    assert_eq!(c.cursor_pos(), (3, 1));
    assert!(lit(mem).iter().all(|&(x, y)| x >= 24 && y >= 16));
    c.toggle_cursor();
    assert!(lit(mem).is_empty());
    c.toggle_cursor();
    assert_eq!(lit(mem).len(), 128);
    c.hide_cursor();
    c.hide_cursor();
    assert!(lit(mem).is_empty());
    // A shape change while hidden draws nothing
    c.set_cursor_shape(CursorShape::Underline);
    assert!(lit(mem).is_empty());
    // Disabled: never shown; disabling hides it
    c.show_cursor();
    c.set_cursor_enabled(false);
    assert!(lit(mem).is_empty());
    assert!(!c.is_cursor_enabled());
    c.show_cursor();
    c.toggle_cursor();
    assert!(lit(mem).is_empty());
    c.set_cursor_enabled(false);
    c.set_cursor_enabled(true);
    c.set_cursor_pos(0, 0);
    assert!(lit(mem).is_empty());
    // A cursor moved while shown, then text written: the old one is erased first
    c.show_cursor();
    c.write_str(" ");
    assert!(lit(mem).is_empty());
    c.show_cursor();
    c.new_line();
    assert!(lit(mem).is_empty());
    c.show_cursor();
    c.clear();
    assert!(lit(mem).is_empty());
    c.show_cursor();
    let _ = c.framebuffer_mut();
    assert!(lit(mem).is_empty());
    assert_eq!(c.framebuffer().width(), 32);
}

#[test]
fn ansi_cursor_movement() {
    let (mut c, _) = console(80, 80); // 10 x 5
    c.write_str("\x1b[3;4H");
    assert_eq!(c.cursor_pos(), (3, 2));
    c.write_str("\x1b[A");
    assert_eq!(c.cursor_pos(), (3, 1));
    c.write_str("\x1b[9A");
    assert_eq!(c.cursor_pos(), (3, 0));
    c.write_str("\x1b[2B");
    assert_eq!(c.cursor_pos(), (3, 2));
    c.write_str("\x1b[99B");
    assert_eq!(c.cursor_pos(), (3, 4));
    c.write_str("\x1b[4C");
    assert_eq!(c.cursor_pos(), (7, 4));
    c.write_str("\x1b[99C");
    assert_eq!(c.cursor_pos(), (9, 4));
    c.write_str("\x1b[2D");
    assert_eq!(c.cursor_pos(), (7, 4));
    c.write_str("\x1b[99D");
    assert_eq!(c.cursor_pos(), (0, 4));
    c.write_str("\x1b[5G");
    assert_eq!(c.cursor_pos(), (4, 4));
    c.write_str("\x1b[99G");
    assert_eq!(c.cursor_pos(), (9, 4));
    c.write_str("\x1b[2d");
    assert_eq!(c.cursor_pos(), (9, 1));
    c.write_str("\x1b[f");
    assert_eq!(c.cursor_pos(), (0, 0));
    c.write_str("\x1b[99;99f");
    assert_eq!(c.cursor_pos(), (9, 4));
    c.write_str("\x1b[0;0H");
    assert_eq!(c.cursor_pos(), (0, 0));
    // Private modes and unknown finals are swallowed
    c.write_str("\x1b[?25l\x1b[>c\x1b[=1h\x1b[ q\x1b[1;24r");
    assert_eq!(c.cursor_pos(), (0, 0));
    // Many parameters do not overflow
    c.write_str("\x1b[1;2;3;4;5;6;7;8;9;10;11H");
    assert_eq!(c.cursor_pos(), (1, 0));
    c.write_str("\x1b[99999999999H");
    assert_eq!(c.cursor_pos(), (0, 4));
}

#[test]
fn ansi_escapes_that_are_not_csi() {
    let (mut c, mem) = console(80, 16);
    // A charset selection eats one character; other escapes end at once; BEL is silent
    c.write_str("\x1b(B\x1b)0\x1b#8\x1b%G\x1b7\x07");
    assert_eq!(c.cursor_pos(), (0, 0));
    assert!(mem.iter().all(|&b| b == 0));
    // A control character inside a CSI ends it; the text after is printed
    c.write_str("\x1b[1\x01X");
    assert_eq!(c.cursor_pos(), (1, 0));
}

#[test]
fn ansi_erasing() {
    let (mut c, mem) = console(80, 48); // 10 x 3
    let fill = |c: &mut VideoConsole| {
        c.write_str("\x1b[H");
        for _ in 0..3 {
            c.write_str("##########");
        }
        c.write_str("\x1b[2;5H");
    };
    let lit = |mem: &[u8]| -> Vec<Vec<bool>> { (0..3).map(|r| (0..10).map(|col| cell_lit(mem, 80, col, r)).collect()).collect() };
    let row = |s: &str| -> Vec<bool> { s.chars().map(|ch| ch == '#').collect() };
    fill(&mut c);
    c.write_str("\x1b[K");
    assert_eq!(lit(mem)[1], row("####......"));
    fill(&mut c);
    c.write_str("\x1b[1K");
    assert_eq!(lit(mem)[1], row(".....#####"));
    fill(&mut c);
    c.write_str("\x1b[2K");
    assert_eq!(lit(mem)[1], row(".........."));
    assert_eq!(lit(mem)[0], row("##########"));
    fill(&mut c);
    c.write_str("\x1b[J");
    assert_eq!(lit(mem), vec![row("##########"), row("####......"), row("..........")]);
    fill(&mut c);
    c.write_str("\x1b[1J");
    assert_eq!(lit(mem), vec![row(".........."), row(".....#####"), row("##########")]);
    fill(&mut c);
    c.write_str("\x1b[2J");
    assert!(mem.iter().all(|&b| b == 0));
    fill(&mut c);
    c.write_str("\x1b[3X");
    assert_eq!(lit(mem)[1], row("####...###"));
    c.write_str("\x1b[99X");
    assert_eq!(lit(mem)[1], row("####......"));
    // The cursor does not move
    assert_eq!(c.cursor_pos(), (4, 1));
}

#[test]
fn ansi_colours() {
    let (mut c, mem) = console(80, 16);
    let colour_at = |mem: &[u8], col: usize| -> ([u8; 3], [u8; 3]) {
        // The background is the cell's top-left pixel ('_' has no pixel there); the
        // foreground is a pixel of the underscore
        let bg = px(mem, 80, col * 8, 0);
        let g = get_char_glyph('_');
        let row = (0..16).find(|&r| g[r] != 0).unwrap();
        let x = (0..8).find(|&x| (g[row] >> (7 - x)) & 1 == 1).unwrap();
        let fg = px(mem, 80, col * 8 + x, row);
        ([fg[0], fg[1], fg[2]], [bg[0], bg[1], bg[2]])
    };
    c.set_color((200, 200, 200), (0, 0, 10));
    c.write_str("_");
    assert_eq!(colour_at(mem, 0), ([200, 200, 200], [0, 0, 10]));
    c.write_str("\x1b[31;42m_");
    assert_eq!(colour_at(mem, 1), ([205, 49, 49], [13, 188, 121]));
    c.write_str("\x1b[7m_");
    assert_eq!(colour_at(mem, 2), ([13, 188, 121], [205, 49, 49]));
    c.write_str("\x1b[0;1;95;104m_");
    assert_eq!(colour_at(mem, 3), ([214, 112, 214], [59, 142, 234]));
    c.write_str("\x1b[39;49m_");
    assert_eq!(colour_at(mem, 4), ([200, 200, 200], [0, 0, 10]));
    c.write_str("\x1b[37;47m\x1b[m_");
    assert_eq!(colour_at(mem, 5), ([200, 200, 200], [0, 0, 10]));
    c.write_str("\x1b[30;107;58m_");
    assert_eq!(colour_at(mem, 6), ([0, 0, 0], [255, 255, 255]));
    c.write_str("\x1b[97;40m_");
    assert_eq!(colour_at(mem, 7), ([255, 255, 255], [0, 0, 0]));
}

// -------------------------------------------------------------- the global console

#[test]
fn global_console_without_a_framebuffer() {
    let _g = setup();
    vc::write_str("x");
    vc::set_colors((1, 1, 1), (2, 2, 2));
    vc::clear_screen();
    vc::set_cursor_position(3, 3);
    vc::show_cursor();
    vc::hide_cursor();
    vc::toggle_cursor();
    vc::set_cursor_enabled(true);
    vc::set_cursor_shape(CursorShape::Bar);
    vc::reclaim_display();
    vc::panic_reclaim();
    assert_eq!(vc::cursor_position(), (0, 0));
    assert_eq!(vc::dimensions(), (80, 25));
    assert!(!vc::is_cursor_enabled());
    assert_eq!(vc::cursor_shape(), CursorShape::Underline);
    assert!(vc::release_display().is_none());
    assert!(vc::hide_behind_splash().is_none());
    assert!(!vc::display_released());
}

#[test]
fn global_console_operations() {
    let _g = setup();
    let mem = video(80, 32);
    assert_eq!(vc::dimensions(), (10, 2));
    vc::set_colors((255, 0, 0), (0, 0, 0));
    vc::write_str("A");
    assert!(mem.chunks(4).any(|p| p[..3] == [255, 0, 0]));
    vc::set_cursor_position(4, 1);
    assert_eq!(vc::cursor_position(), (4, 1));
    vc::set_cursor_shape(CursorShape::Block);
    assert_eq!(vc::cursor_shape(), CursorShape::Block);
    assert!(vc::is_cursor_enabled());
    vc::show_cursor();
    assert_eq!(px(mem, 80, 32, 16)[..3], [255, 255, 255]);
    vc::toggle_cursor();
    assert_eq!(px(mem, 80, 32, 16)[..3], [0, 0, 0]);
    vc::toggle_cursor();
    vc::hide_cursor();
    vc::set_cursor_enabled(false);
    assert!(!vc::is_cursor_enabled());
    vc::clear_screen();
    assert!(mem.iter().all(|&b| b == 0));
}

#[test]
fn a_compositor_borrows_the_screen() {
    let _g = setup();
    let mem = video(80, 32);
    vc::write_str("before");
    let snapshot = mem.to_vec();
    let (addr, w, h, stride, bgr) = vc::release_display().unwrap();
    assert_eq!((addr, w, h, stride, bgr), (mem.as_mut_ptr(), 80, 32, 80, false));
    assert!(vc::display_released());
    // The console keeps drawing, off screen
    vc::write_str("X");
    assert_eq!(mem.to_vec(), snapshot);
    // A second borrower gets the same real framebuffer
    assert_eq!(vc::release_display().unwrap().0, mem.as_mut_ptr());
    // The boot logo cannot hide the console while a compositor has it
    assert!(vc::hide_behind_splash().is_none());
    // Back: what was drawn meanwhile shows
    vc::reclaim_display();
    assert!(!vc::display_released());
    assert_ne!(mem.to_vec(), snapshot);
    assert!(cell_lit(mem, 80, 6, 0));
    vc::reclaim_display();
}

#[test]
fn a_panic_takes_the_screen_back() {
    let _g = setup();
    let mem = video(80, 32);
    vc::release_display().unwrap();
    vc::write_str("panic text");
    assert!(mem.iter().all(|&b| b == 0));
    vc::panic_reclaim();
    assert!(vc::panicked());
    assert!(cell_lit(mem, 80, 0, 0));
    assert!(!vc::display_released());
    // Again (nothing borrowed): nothing to do
    vc::panic_reclaim();
}

// -------------------------------------------------------------------------- splash

#[test]
fn whether_the_logo_is_wanted() {
    use k::video::splash::{options_text, wants_splash};
    assert!(wants_splash(None, None));
    assert!(wants_splash(Some(b"quiet ro"), Some(b"desktop")));
    for o in [&b"debug"[..], b"x verbose", b"nosplash=1"] {
        assert!(!wants_splash(Some(o), None));
    }
    assert!(!wants_splash(None, Some(b"debug")));
    assert!(!wants_splash(Some(b""), Some(b"shell-test")));
    let opts: Vec<u8> = "NoSplash".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let (t, n) = options_text(&opts);
    assert_eq!(&t[..n], b"nosplash");
    let long: Vec<u8> = std::iter::repeat([b'a', 0]).take(300).flatten().collect();
    assert_eq!(options_text(&long).1, 256);
    assert_eq!(options_text(&[0x16, 0x04]).0[0], b'?');
}

#[test]
fn deciding_reads_fw_cfg() {
    let _g = setup();
    k::video::splash::decide();
    assert!(k::video::splash::is_quiet());
    fake::with(|s| s.fwcfg.insert("opt/hydra/boot".into(), b"debug".to_vec()));
    k::video::splash::decide();
    assert!(!k::video::splash::is_quiet());
}

#[test]
fn the_logo_and_the_dots() {
    use k::video::splash;
    let _g = setup();
    // Without a framebuffer console the logo cannot show: the messages stay on screen
    splash::decide();
    splash::start();
    assert!(!splash::is_active());
    assert!(!splash::is_quiet());
    // Not wanted: nothing
    let mem = video(320, 240);
    splash::start();
    assert!(!splash::is_active());
    splash::decide();
    k::console::print_raw("hidden message\n");
    splash::start();
    assert!(splash::is_active());
    // The logo is drawn on the real screen, centred a little above the middle
    let lit = |x: usize, y: usize| px(mem, 320, x, y)[..3] != [0, 0, 0];
    assert!((90..230).any(|x| (50..150).any(|y| lit(x, y))), "the logo");
    assert!(!lit(0, 0) && !lit(319, 239));
    // The dots: in a square under the logo
    let dots = |mem: &[u8]| -> Vec<u8> { (170..200).flat_map(|y| (140..180).map(move |x| (x, y))).map(|(x, y)| px(mem, 320, x, y)[1]).collect() };
    let first = dots(mem);
    assert!(first.iter().any(|&g| g > 200));
    splash::start(); // already showing
    // Odd ticks do not draw; even ones move the dots
    splash::tick();
    assert_eq!(dots(mem), first);
    splash::tick();
    assert_ne!(dots(mem), first);
    // The console draws off screen meanwhile
    let before = dots(mem);
    vc::write_str("more");
    assert_eq!(dots(mem), before);
    assert!(!cell_lit(mem, 320, 0, 0));
    // Esc: the text comes back at the next poll, with what was printed
    splash::request_reveal();
    assert!(splash::is_active());
    splash::poll();
    assert!(!splash::is_active());
    assert!(cell_lit(mem, 320, 0, 0), "the boot messages are on screen");
    // Ticks after the end do nothing
    splash::tick();
    splash::request_reveal();
    splash::poll();
}

#[test]
fn the_text_comes_back_when_the_desktop_is_late() {
    use k::video::splash;
    let _g = setup();
    video(160, 120);
    splash::decide();
    splash::start();
    assert!(splash::is_active());
    for _ in 0..15_000 {
        splash::tick();
    }
    assert!(splash::is_active());
    splash::poll();
    assert!(!splash::is_active());
}

#[test]
fn a_desktop_draws_over_the_logo() {
    use k::video::splash;
    let _g = setup();
    let mem = video(160, 120);
    splash::decide();
    splash::start();
    splash::desktop_starting();
    assert!(splash::is_desktop_starting());
    // KWin takes the screen: the logo stops, the console stays off screen
    let (addr, ..) = vc::release_display().unwrap();
    assert_eq!(addr, mem.as_mut_ptr());
    assert!(!splash::is_active());
    assert!(!splash::is_quiet());
    assert!(vc::display_released());
    // A later end (the session ended) shows the console
    splash::end();
    assert!(vc::display_released(), "a compositor still owns the screen");
}

#[test]
fn ending_before_the_framebuffer_redraws_the_firmware_console() {
    use k::video::splash;
    let _g = setup();
    splash::decide();
    k::console::print_raw("early\n");
    assert_eq!(uefi_fake::take().text, "", "quiet: nothing on the firmware console");
    splash::end();
    assert!(!splash::is_quiet());
    assert!(uefi_fake::take().text.contains("early"));
    // Not quiet any more: a second end does nothing
    splash::end();
    assert_eq!(uefi_fake::take().text, "");
}

#[test]
fn a_panic_shows_the_console_over_the_logo() {
    use k::video::splash;
    let _g = setup();
    let mem = video(160, 120);
    splash::decide();
    splash::start();
    // After the takeover the console draws into its off-screen copy
    k::console::enable_standalone_video(true);
    k::console::print_raw("before the panic\n");
    assert!(!cell_lit(mem, 160, 0, 0));
    splash::panic_reveal();
    assert!(!splash::is_active());
    assert!(!splash::is_quiet());
    assert!(cell_lit(mem, 160, 0, 0));
}

#[test]
fn the_logo_in_bgr_order() {
    use k::video::splash;
    let _g = setup();
    let mem: &'static mut [u8] = Box::leak(vec![0u8; 200 * 150 * 4].into_boxed_slice());
    k::video::gop::install(mode_info_for(mem.as_mut_ptr(), mem.len(), 200, 150, 200, PixelFormat::Bgr));
    splash::decide();
    splash::start();
    // The dots' colour (215, 250, 240) at full cover, stored as a u32: B G R in BGR mode
    let count = |want: [u8; 4]| mem.chunks(4).filter(|p| **p == want).count();
    assert!(count([240, 250, 215, 0]) > 10);
    assert_eq!(count([215, 250, 240, 0]), 0);
    splash::compositor_took();
}

#[test]
fn erasing_from_past_the_last_column_and_hiding_the_cursor_for_escapes() {
    let (mut c, mem) = console(80, 32);
    c.write_str("0123456789");
    assert_eq!(c.cursor_pos(), (10, 0));
    // Nothing to erase right of the cursor
    c.write_str("\x1b[K");
    assert!(cell_lit(mem, 80, 9, 0));
    // A shown cursor is taken away before an escape moves it
    c.write_str("\x1b[2;1H");
    c.show_cursor();
    c.write_str("\x1b[1;1H");
    assert!((0..16).all(|y| (0..8).all(|x| px(mem, 80, x, 16 + y)[..3] == [0, 0, 0])));
}

#[test]
fn a_panic_does_not_wait_for_a_held_console() {
    let _g = setup();
    let mem = video(80, 32);
    vc::release_display().unwrap();
    vc::write_str("hidden");
    // The console is locked (the panicking code held it): the copy is skipped
    let held = vc::VIDEO_CONSOLE.lock();
    vc::panic_reclaim();
    drop(held);
    assert!(mem.iter().all(|&b| b == 0));
    assert!(vc::display_released());
    vc::reclaim_display();
}

#[test]
fn the_dots_are_clipped_on_a_narrow_screen() {
    use k::video::splash;
    let _g = setup();
    // 16 pixels wide: the dots' square (28 pixels) does not fit
    let mem = video(16, 200);
    splash::decide();
    splash::start();
    assert!(splash::is_active());
    splash::tick();
    splash::tick();
    assert!(mem.chunks(4).any(|p| p[1] > 200));
    splash::compositor_took();
}
