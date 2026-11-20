//! `src/console.rs`: colours, the scrollback, output routing (firmware console, framebuffer,
//! serial), FixedBuf, keys and line input, scroll lock and the scrollback viewport.

mod common;
use common::*;
use core::fmt::Write;
use core::time::Duration;
use k::console::{self as c, ScrollbackBuffer};
use uefi::proto::console::text::{Color, Key, ScanCode};

const ALL: [Color; 16] = [
    Color::Black, Color::Blue, Color::Green, Color::Cyan, Color::Red, Color::Magenta, Color::Brown, Color::LightGray,
    Color::DarkGray, Color::LightBlue, Color::LightGreen, Color::LightCyan, Color::LightRed, Color::LightMagenta,
    Color::Yellow, Color::White,
];

#[test]
fn colour_numbers_and_rgb() {
    for (i, col) in ALL.iter().enumerate() {
        assert_eq!(c::color_to_u8(*col), i as u8);
        assert_eq!(c::u8_to_color(i as u8) as u8, *col as u8);
        // The high nibble is ignored for the foreground
        assert_eq!(c::u8_to_color(0xF0 | i as u8) as u8, *col as u8);
    }
    for (i, col) in ALL[..8].iter().enumerate() {
        assert_eq!(c::u8_to_bg_color((i as u8) << 4 | 0x0F) as u8, *col as u8);
    }
    // Background bit 7 (blink) is ignored
    assert_eq!(c::u8_to_bg_color(0xF0) as u8, Color::LightGray as u8);
    let rgb: Vec<(u8, u8, u8)> = ALL.iter().map(|&col| c::color_to_rgb(col)).collect();
    assert_eq!(rgb[0], (0, 0, 0));
    assert_eq!(rgb[1], (0, 0, 170));
    assert_eq!(rgb[6], (170, 85, 0));
    assert_eq!(rgb[8], (85, 85, 85));
    assert_eq!(rgb[14], (255, 255, 85));
    assert_eq!(rgb[15], (255, 255, 255));
    // All 16 differ
    let mut uniq = rgb.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 16);
}

fn line(sb: &ScrollbackBuffer, i: usize) -> Option<(String, Vec<u8>)> {
    let mut l = [0u8; 128];
    let mut a = [0u8; 128];
    let n = sb.get_line_with_attrs(i, &mut l, &mut a)?;
    Some((String::from_utf8_lossy(&l[..n]).to_string(), a[..n].to_vec()))
}

#[test]
fn the_scrollback_keeps_lines_and_colours() {
    let mut sb = Box::new(ScrollbackBuffer::new());
    assert_eq!(sb.total_lines(), 0);
    assert!(line(&sb, 0).is_none());
    sb.push_str("red\r\n", 0x04);
    sb.push_str("half", 0x1E);
    assert_eq!(sb.total_lines(), 2);
    assert_eq!(line(&sb, 0).unwrap(), ("red".into(), vec![4; 3]));
    // The line being written counts, with its colours
    assert_eq!(line(&sb, 1).unwrap(), ("half".into(), vec![0x1E; 4]));
    sb.push_str(" done\n", 0x02);
    assert_eq!(line(&sb, 1).unwrap().0, "half done");
    assert_eq!(line(&sb, 1).unwrap().1, [vec![0x1E; 4], vec![0x02; 5]].concat());
    assert!(line(&sb, 2).is_none());
    // A long line wraps at 128 characters
    sb.push_str(&"x".repeat(130), 0x0F);
    assert_eq!(sb.total_lines(), 4);
    assert_eq!(line(&sb, 2).unwrap().0.len(), 128);
    assert_eq!(line(&sb, 3).unwrap().0, "xx");
    // An empty line
    sb.push_str("\n\n", 0x0F);
    assert_eq!(line(&sb, 4).unwrap().0, "");
    sb.clear();
    assert_eq!(sb.total_lines(), 0);
}

#[test]
fn the_scrollback_keeps_the_last_512_lines() {
    let mut sb = Box::new(ScrollbackBuffer::new());
    for i in 0..600 {
        sb.push_str(&format!("line {}\n", i), 0x0F);
    }
    assert_eq!(sb.total_lines(), 512);
    assert_eq!(line(&sb, 0).unwrap().0, "line 88");
    assert_eq!(line(&sb, 511).unwrap().0, "line 599");
    sb.push_str("tail", 0x0F);
    assert_eq!(sb.total_lines(), 513);
    assert_eq!(line(&sb, 512).unwrap().0, "tail");
    assert_eq!(c::Console::new().current_attr, 0x0F);
}

#[test]
fn fixed_buffers_truncate() {
    let mut b = c::FixedBuf::new();
    assert_eq!(b.as_str(), "");
    write!(b, "pid {} at {:#x}", 7, 0x1000).unwrap();
    assert_eq!(b.as_str(), "pid 7 at 0x1000");
    let mut b = c::FixedBuf::new();
    b.write_str(&"a".repeat(200)).unwrap();
    assert_eq!(b.as_str().len(), 160);
    // A multi-byte character cut in half: nothing rather than invalid text
    let mut b = c::FixedBuf::new();
    b.write_str(&"a".repeat(159)).unwrap();
    b.write_str("é").unwrap();
    assert_eq!(b.as_str(), "");
}

#[test]
fn serial_output_translates_newlines() {
    let _g = setup();
    x86_64::instructions::port::take_writes();
    c::serial_write("a\nb");
    assert_eq!(x86_64::instructions::port::take_writes(), vec![(0x3F8, b'a' as u32), (0x3F8, b'\r' as u32), (0x3F8, b'\n' as u32), (0x3F8, b'b' as u32)]);
    let mut s = c::SerialOnly;
    write!(s, "{}", 42).unwrap();
    assert_eq!(x86_64::instructions::port::take_writes().len(), 2);
}

#[test]
fn serial_output_waits_for_the_transmitter() {
    use x86_64::instructions::port;
    let _g = setup();
    // Busy twice, then empty: the byte goes out after the third status read
    port::queue_read(0x3FD, 0);
    port::queue_read(0x3FD, 0);
    c::serial_write("z");
    assert_eq!(port::take_writes(), vec![(0x3F8, b'z' as u32)]);
    // A line that never empties: the wait is bounded and the byte still goes out
    port::set_default(0x3FD, 0);
    c::serial_write("y");
    assert_eq!(port::take_writes(), vec![(0x3F8, b'y' as u32)]);
    port::set_default(0x3FD, 0x20);
}

#[test]
fn output_goes_to_the_firmware_console_before_the_takeover() {
    let _g = setup();
    let g0 = c::console_output_generation();
    c::print_raw("hello\n");
    assert_eq!(uefi_fake::take().text, "hello\r\n");
    assert_eq!(c::console_output_generation(), g0 + 1);
    assert_eq!(scrollback(), vec!["hello"]);
    // Colours: the attribute byte and the firmware's colour
    c::set_color(Color::Yellow, Color::Blue);
    assert_eq!(c::CONSOLE.lock().current_attr, 0x1E);
    assert_eq!(uefi_fake::take().attrs, vec![0x1E]);
    c::print_raw("x");
    let cons = c::CONSOLE.lock();
    let mut l = [0u8; 128];
    let mut a = [0u8; 128];
    cons.scrollback.get_line_with_attrs(1, &mut l, &mut a).unwrap();
    assert_eq!(a[0], 0x1E);
    drop(cons);
    c::clear_screen();
    assert_eq!(uefi_fake::take().clears, 1);
    assert_eq!(scrollback().len(), 2, "clearing the screen keeps the scrollback");
    c::clear_scrollback();
    assert!(scrollback().is_empty());
}

#[test]
fn output_goes_to_the_framebuffer_and_serial_after_the_takeover() {
    let _g = setup();
    let fb = video(80, 32);
    c::enable_standalone_video(true);
    assert!(c::is_standalone_video());
    x86_64::instructions::port::take_writes();
    c::set_color(Color::White, Color::Black);
    c::print_raw("A\n");
    // On the framebuffer (glyph pixels lit), on COM1, not on the firmware console
    assert!(fb.iter().any(|&b| b != 0));
    assert_eq!(x86_64::instructions::port::take_writes().len(), 3);
    assert!(uefi_fake::take().text.is_empty());
    assert_eq!(k::video::console::cursor_position(), (0, 1));
    c::clear_screen();
    assert!(fb.iter().all(|&b| b == 0));
    assert_eq!(c::screen_size(), (10, 2));
}

#[test]
fn output_during_the_boot_logo_goes_to_serial_only() {
    let _g = setup();
    video(64, 64);
    k::video::splash::decide();
    assert!(k::video::splash::is_quiet());
    x86_64::instructions::port::take_writes();
    c::print_raw("boot message\n");
    c::set_color(Color::Red, Color::Black);
    c::clear_screen();
    assert_eq!(uefi_fake::take().text, "");
    assert_eq!(x86_64::instructions::port::take_writes().len(), "boot message\n".len() + 1);
    assert_eq!(scrollback(), vec!["boot message"]);
    k::video::splash::compositor_took();
}

#[test]
fn kernel_messages_and_task_output() {
    let _g = setup();
    // kprintln: the kernel log and the screen, never the task's fd 1
    k::kprintln!("[boot] {}", 1);
    assert_eq!(fake::take_klog(), "[boot] 1\n");
    assert!(uefi_fake::take().text.contains("[boot] 1"));
    assert_eq!(fake::take_out(), "");
    // println: the task's fd 1
    k::println!("to fd {}", 1);
    assert_eq!(fake::take_out(), "to fd 1\n");
    assert!(uefi_fake::take().text.is_empty());
    k::print!("no newline");
    assert_eq!(fake::take_out(), "no newline");
    // No fd 1, or no heap yet: straight to the screen
    fake::with(|s| s.no_fd1 = true);
    k::println!("direct");
    assert!(uefi_fake::take().text.contains("direct"));
    fake::with(|s| {
        s.no_fd1 = false;
        s.heap_uninit = true;
    });
    k::println!();
    assert_eq!(uefi_fake::take().text, "\r\n");
    assert_eq!(fake::take_out(), "");
}

#[test]
fn screen_size_and_cursor_on_the_firmware_console() {
    let _g = setup();
    assert_eq!(c::screen_size(), (80, 25));
    // No text mode: the classic size
    uefi_fake::set_mode_number(-1);
    assert_eq!(c::screen_size(), (80, 25));
    uefi_fake::set_mode_number(3);
    assert_eq!(c::screen_size(), (80, 25), "a mode the firmware does not answer");
    uefi_fake::set_mode_number(0);
    c::set_cursor_position(10, 5);
    assert_eq!(c::cursor_position(), (10, 5));
    c::show_cursor();
    c::hide_cursor();
    c::toggle_cursor();
    c::set_cursor_enabled(true);
    assert_eq!(uefi_fake::take().cursor, vec![true, false, true]);
    assert!(c::is_cursor_enabled());
    c::set_cursor_shape(c::CursorShape::Block);
    assert_eq!(c::cursor_shape(), c::CursorShape::Underline);
    assert_eq!(c::probe_scancode(ScanCode::ESCAPE), 0x17);
}

#[test]
fn cursor_on_the_framebuffer() {
    let _g = setup();
    let fb = video(80, 48);
    c::enable_standalone_video(true);
    c::set_cursor_position(3, 2);
    assert_eq!(c::cursor_position(), (3, 2));
    c::set_cursor_shape(c::CursorShape::Block);
    assert_eq!(c::cursor_shape(), c::CursorShape::Block);
    c::show_cursor();
    // The block inverts the cell at (24, 32)
    assert_eq!(px(fb, 80, 24, 32), [255, 255, 255, 0]);
    c::toggle_cursor();
    assert_eq!(px(fb, 80, 24, 32), [0, 0, 0, 0]);
    c::toggle_cursor();
    c::hide_cursor();
    assert!(fb.iter().all(|&b| b == 0));
    c::set_cursor_enabled(false);
    assert!(!c::is_cursor_enabled());
}

#[test]
fn keys_come_from_the_firmware_then_the_keyboard() {
    let _g = setup();
    fake::with(|s| {
        s.uefi_keys.push_back(fake::key('f'));
        s.keys.push_back(fake::key('k'));
    });
    assert!(!c::is_hardware_mode());
    assert_eq!(c::read_key(), Some(fake::key('f')));
    assert_eq!(c::read_key(), None);
    c::set_hardware_mode(true);
    assert!(c::is_hardware_mode());
    assert_eq!(c::read_key(), Some(fake::key('k')));
    assert_eq!(c::read_key(), None);
}

#[test]
fn escape_during_the_boot_logo_shows_the_messages() {
    let _g = setup();
    video(64, 64);
    k::video::splash::decide();
    k::video::splash::start();
    assert!(k::video::splash::is_active());
    c::set_hardware_mode(true);
    // Esc as a character, then as a scan code (the first ended the logo)
    fake::with(|s| s.keys.extend([fake::key('\u{1b}'), fake::special(0x17)]));
    assert_eq!(c::read_key(), None);
    assert!(!k::video::splash::is_active());
    assert_eq!(c::read_key(), Some(fake::special(0x17)));
}

#[test]
fn interrupt_keys() {
    let _g = setup();
    c::set_hardware_mode(true);
    assert!(!c::check_interrupt());
    fake::with(|s| s.keys.extend([fake::key('\u{3}'), fake::key('\u{1c}'), fake::key('c'), fake::special(1)]));
    assert!(c::check_interrupt());
    assert!(c::check_interrupt());
    assert!(!c::check_interrupt());
    assert!(!c::check_interrupt());
}

#[test]
fn stalls() {
    let _g = setup();
    // Firmware: the boot services' stall (the fake answers at once)
    c::stall(Duration::from_millis(5));
    assert_eq!(fake::with(|s| s.clock_ns), 0);
    // Hardware with the timer and interrupts: a sleep
    c::set_hardware_mode(true);
    c::stall(Duration::from_millis(30));
    assert_eq!(fake::with(|s| s.clock_ns), 30_000_000);
    // Interrupts off: a TSC spin (the clock does not move)
    x86_64::instructions::interrupts::disable();
    c::stall(Duration::from_nanos(100));
    x86_64::instructions::interrupts::enable();
    assert_eq!(fake::with(|s| s.clock_ns), 30_000_000);
}

#[test]
fn waiting_for_a_key_blinks_the_cursor() {
    let _g = setup();
    let fb = video(80, 48);
    c::enable_standalone_video(true);
    c::set_hardware_mode(true);
    // The key arrives after 0.75 s: the cursor blinked once (shown, then off at 0.5 s)
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 750_000_000 && st.keys.is_empty() && !st.log.contains(&"k".to_string()) {
                st.keys.push_back(fake::key('k'));
                st.log.push("k".into());
            }
        }))
    });
    assert_eq!(c::get_key(), fake::key('k'));
    assert_eq!(fake::with(|s| s.clock_ns), 750_000_000);
    // The cursor is hidden after the key
    assert!(fb.iter().all(|&b| b == 0));
}

#[test]
fn waiting_for_a_key_or_other_output() {
    let _g = setup();
    c::set_hardware_mode(true);
    fake::with(|s| s.keys.push_back(fake::key('a')));
    let g = c::console_output_generation();
    assert_eq!(c::get_key_or_refresh(g), Ok(fake::key('a')));
    // Output appears after 1.2 s
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 1_200_000_000 {
                c::inc_console_output_generation();
                st.on_sleep = None;
            }
        }))
    });
    assert_eq!(c::get_key_or_refresh(g), Err(()));
    assert_eq!(fake::with(|s| s.clock_ns), 1_200_000_000);
}

#[test]
fn backspace_on_both_consoles() {
    let _g = setup();
    uefi_fake::place_cursor(5, 2);
    c::backspace();
    let s = uefi_fake::take();
    assert_eq!(s.moves, vec![(4, 2), (4, 2)]);
    assert_eq!(s.text, " ");
    // At the start of the line: nothing
    uefi_fake::place_cursor(0, 2);
    c::backspace();
    assert!(uefi_fake::take().moves.is_empty());
    video(80, 32);
    c::enable_standalone_video(true);
    k::video::console::write_str("ab");
    c::backspace();
    assert_eq!(k::video::console::cursor_position(), (1, 0));
}

#[test]
fn reading_a_line() {
    let _g = setup();
    c::set_hardware_mode(true);
    let keys = vec![
        fake::key('l'),
        fake::key('x'),
        fake::key('\u{8}'),
        fake::key('s'),
        fake::special(ScanCode::UP.0),
        fake::special(ScanCode::DOWN.0),
        fake::special(ScanCode::LEFT.0),
        fake::special(ScanCode::RIGHT.0),
        fake::special(ScanCode::HOME.0),
        fake::special(ScanCode::END.0),
        fake::special(ScanCode::FUNCTION_1.0),
        fake::key('é'),
        fake::key('!'),
        fake::special(ScanCode::DELETE.0),
        fake::key('\r'),
    ];
    fake::with(|s| s.keys.extend(keys));
    let mut buf = [0u8; 16];
    let n = c::read_line("> ", &mut buf);
    assert_eq!(&buf[..n], b"ls");
    assert_eq!(fake::take_out(), "> lxs!\n");
    // Ctrl+C starts again; a full buffer ignores more; Enter as \n
    fake::with(|s| s.keys.extend([fake::key('a'), fake::key('\u{3}'), fake::key('b'), fake::key('c'), fake::key('d'), fake::key('\u{8}'), fake::key('\u{8}'), fake::key('\u{8}'), fake::key('\u{8}'), fake::special(ScanCode::DELETE.0), fake::key('e'), fake::key('f'), fake::key('g'), fake::key('\n')]));
    let mut small = [0u8; 2];
    let n = c::read_line("$ ", &mut small);
    assert_eq!(&small[..n], b"ef");
    // ("d" and "g" do not fit: not taken, not echoed)
    assert_eq!(fake::take_out(), "$ a^C\n$ bcef\n");
}

#[test]
fn scroll_lock_switches() {
    let _g = setup();
    c::set_hardware_mode(true);
    assert!(!c::is_scroll_lock_active());
    assert!(c::toggle_scroll_lock());
    assert!(c::is_scroll_lock_active());
    assert!(!c::toggle_scroll_lock());
    c::set_scroll_lock(true);
    assert!(c::SCROLL_LOCK.load(core::sync::atomic::Ordering::Relaxed));
    // Set in software: answered without the BIOS data area, in either mode
    c::set_hardware_mode(false);
    assert!(c::is_scroll_lock_active());
    c::set_scroll_lock(false);
}

#[test]
fn redraw_from_the_scrollback() {
    let _g = setup();
    c::set_color(Color::LightRed, Color::Black);
    c::print_raw("one\n");
    c::set_color(Color::White, Color::Black);
    c::print_raw("two\n");
    uefi_fake::take();
    c::redraw_from_scrollback();
    let s = uefi_fake::take();
    assert_eq!(s.clears, 1);
    assert_eq!(s.text.replace('\r', ""), "one\ntwo\n");
    // Each line in its colour, then the default, and the console's colour at the end
    assert_eq!(s.attrs, vec![0x0C, 0x0F, 0x0F, 0x0F, 0x0F]);
    // An unfinished last line: the cursor stays after it
    c::print_raw("three");
    uefi_fake::take();
    c::redraw_from_scrollback();
    assert_eq!(uefi_fake::take().text.replace('\r', ""), "one\ntwo\nthree");
}

#[test]
fn redraw_shows_only_the_last_screenful() {
    let _g = setup();
    for i in 0..40 {
        c::print_raw(&format!("l{}\n", i));
    }
    uefi_fake::take();
    c::redraw_from_scrollback();
    let text = uefi_fake::take().text.replace('\r', "");
    // 24 lines above the prompt row
    assert!(text.starts_with("l16\n"), "{}", text);
    assert!(text.ends_with("l39\n"));
    // Nothing recorded: only the clear
    c::clear_scrollback();
    c::redraw_from_scrollback();
    assert_eq!(uefi_fake::take().text, "");
}

#[test]
fn the_scrollback_viewport() {
    let _g = setup();
    for i in 0..30 {
        c::print_raw(&format!("line {}\n", i));
    }
    assert_eq!(c::max_scroll_offset(), 6);
    uefi_fake::take();
    // Scrolled up 3 lines: lines 4..=27 (1-based 4-27 of 30) and the status line
    c::draw_scroll_viewport(3, "$ ", "ls", 0, Color::LightGreen);
    let s = uefi_fake::take();
    let text = s.text.replace('\r', "");
    assert!(text.starts_with("line 3\n"), "{}", text);
    assert!(text.contains("line 26\n"));
    assert!(!text.contains("line 27"));
    assert!(text.ends_with("-- SCROLL LOCK (up 3 lines, lines 4-27 of 30) [UP/DOWN or PgUp/PgDn, ESC to exit] --"));
    assert!(s.attrs.contains(&0x30), "black on cyan status line");
    // Scrolled past the top: empty rows, then a status line starting at 0
    c::draw_scroll_viewport(40, "$ ", "", 0, Color::LightGreen);
    let text = uefi_fake::take().text.replace('\r', "");
    assert!(text.starts_with("\n\n"));
    assert!(text.ends_with("(up 40 lines, lines 0-0 of 30) [UP/DOWN or PgUp/PgDn, ESC to exit] --"));
    // Live view: the last 24 lines, the prompt and line, the cursor in the line
    c::draw_scroll_viewport(0, "$ ", "echo hi", 4, Color::Yellow);
    let s = uefi_fake::take();
    let text = s.text.replace('\r', "");
    assert!(text.starts_with("line 6\n"));
    assert!(text.ends_with("line 29\n$ echo hi"));
    assert!(s.attrs.contains(&0x0E));
    assert_eq!(*s.moves.last().unwrap(), (6, 24));
}

#[test]
fn the_viewport_with_a_short_history_and_a_partial_line() {
    let _g = setup();
    c::print_raw("only\npartial");
    uefi_fake::take();
    c::draw_scroll_viewport(0, "> ", "", 0, Color::White);
    let text = uefi_fake::take().text.replace('\r', "");
    assert_eq!(text, "only\npartial\n> ");
    // Colour runs: one switch per run of equal attributes
    c::clear_scrollback();
    c::set_color(Color::Red, Color::Black);
    c::print_raw("ab");
    c::set_color(Color::Green, Color::Black);
    c::print_raw("cd\n");
    uefi_fake::take();
    c::draw_scroll_viewport(0, "", "", 0, Color::White);
    let s = uefi_fake::take();
    assert_eq!(s.attrs[..3], [0x04, 0x02, 0x0F]);
}

#[test]
fn the_viewport_on_the_framebuffer() {
    let _g = setup();
    let fb = video(80, 48); // 10 x 3
    c::enable_standalone_video(true);
    // An empty line, a coloured one
    c::print_raw("\n");
    c::set_color(Color::LightRed, Color::Black);
    c::print_raw("red\n");
    c::draw_scroll_viewport(0, "$", "", 0, Color::Yellow);
    assert_eq!(k::video::console::cursor_position(), (1, 2));
    // "red" in light red (255, 85, 85) on the second row
    assert!(fb.chunks(4).any(|p| p[..3] == [255, 85, 85]));
    c::draw_scroll_viewport(1, "$", "", 0, Color::Yellow);
    assert!(fb.chunks(4).any(|p| p[..3] == [0, 170, 170]), "the status line's cyan");
    c::redraw_from_scrollback();
    assert!(fb.chunks(4).any(|p| p[..3] == [255, 85, 85]));
}
