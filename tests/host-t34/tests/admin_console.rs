//! `src/admin/console.rs`: waiting for keys and console control for the ring-3 line editor.

mod common;
use common::*;
use k::admin::console::{ctl, read};
use k::admin::proto::*;

#[test]
fn a_waiting_key_is_answered_at_once() {
    let _g = setup();
    fake::with(|s| s.uefi_keys.extend([fake::key('a'), fake::special(SC_UP as u16)]));
    let e = read(1000, u64::MAX);
    assert_eq!((e.kind, e.code), (KEY_CHAR, 'a' as u32));
    let e = read(0, u64::MAX);
    assert_eq!((e.kind, e.code), (KEY_SPECIAL, SC_UP));
    assert_eq!(e.generation, k::console::console_output_generation());
    // No wait asked and no key: none, without showing the cursor
    let e = read(0, u64::MAX);
    assert_eq!(e.kind, KEY_NONE);
    assert!(uefi_fake::take().cursor.is_empty());
}

#[test]
fn a_wait_ends_at_its_timeout() {
    let _g = setup();
    let t0 = fake::ticks();
    let e = read(95, u64::MAX);
    assert_eq!(e.kind, KEY_NONE);
    // 95 ms = 10 ticks (rounded up), not less
    assert_eq!(fake::ticks() - t0, 10);
    // The cursor shows while waiting and hides afterwards
    assert_eq!(uefi_fake::take().cursor, vec![true, false]);
}

#[test]
fn a_key_typed_while_waiting_ends_the_wait() {
    let _g = setup();
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 300_000_000 && st.uefi_keys.is_empty() && !st.log.contains(&"typed".to_string()) {
                st.uefi_keys.push_back(fake::key('z'));
                st.log.push("typed".into());
            }
        }))
    });
    let e = read(u64::MAX, u64::MAX);
    assert_eq!((e.kind, e.code), (KEY_CHAR, 'z' as u32));
    assert_eq!(fake::ticks(), 30);
}

#[test]
fn other_output_on_the_console_ends_the_wait() {
    let _g = setup();
    let seen = k::console::console_output_generation();
    fake::with(|s| {
        s.on_sleep = Some(Box::new(|st: &mut fake::State| {
            if st.clock_ns >= 200_000_000 {
                k::console::inc_console_output_generation();
                st.on_sleep = None;
            }
        }))
    });
    let e = read(u64::MAX, seen);
    assert_eq!(e.kind, KEY_REFRESH);
    assert_eq!(e.generation, seen + 1);
    // Output already newer than what the caller saw: at the first look
    let t = fake::ticks();
    let e = read(5000, seen);
    assert_eq!(e.kind, KEY_REFRESH);
    assert_eq!(fake::ticks(), t);
}

#[test]
fn the_cursor_blinks_on_the_framebuffer_while_waiting() {
    let _g = setup();
    let fb = video(80, 32);
    k::console::enable_standalone_video(true);
    // Half-second blinks: after 1.2 s the cursor toggled twice
    let e = read(1200, u64::MAX);
    assert_eq!(e.kind, KEY_NONE);
    // Hidden at the end: the screen is black again
    assert!(fb.iter().all(|&b| b == 0));
}

#[test]
fn cursor_and_screen_control_on_the_firmware_console() {
    let _g = setup();
    uefi_fake::place_cursor(7, 3);
    assert_eq!(ctl(&[CTL_CURSOR_GET, 0, 0, 0], b""), Some([7, 3]));
    assert_eq!(ctl(&[CTL_CURSOR_SET, 12, 4, 0], b""), Some([0, 0]));
    assert_eq!(uefi_fake::take().moves, vec![(12, 4)]);
    assert_eq!(ctl(&[CTL_SIZE, 0, 0, 0], b""), Some([80, 25]));
    ctl(&[CTL_CLEAR, 0, 0, 0], b"").unwrap();
    assert_eq!(uefi_fake::take().clears, 1);
    // The firmware console has one cursor shape, always on
    ctl(&[CTL_CURSOR_ENABLE, 0, 0, 0], b"").unwrap();
    assert_eq!(uefi_fake::take().cursor, vec![false]);
    ctl(&[CTL_CURSOR_SHAPE, 1, 0, 0], b"").unwrap();
    assert_eq!(ctl(&[CTL_CURSOR_INFO, 0, 0, 0], b""), Some([1, 0]));
    ctl(&[CTL_CURSOR_SHOW, 1, 0, 0], b"").unwrap();
    ctl(&[CTL_CURSOR_SHOW, 0, 0, 0], b"").unwrap();
    assert_eq!(uefi_fake::take().cursor, vec![true, false]);
    assert_eq!(ctl(&[99, 0, 0, 0], b""), None);
}

#[test]
fn cursor_shapes_on_the_framebuffer() {
    let _g = setup();
    video(160, 64);
    k::console::enable_standalone_video(true);
    for (code, want) in [(0, 0), (1, 1), (2, 2), (7, 2)] {
        ctl(&[CTL_CURSOR_SHAPE, code, 0, 0], b"").unwrap();
        assert_eq!(ctl(&[CTL_CURSOR_INFO, 0, 0, 0], b""), Some([1, want]));
    }
    ctl(&[CTL_CURSOR_ENABLE, 0, 0, 0], b"").unwrap();
    assert_eq!(ctl(&[CTL_CURSOR_INFO, 0, 0, 0], b"").unwrap()[0], 0);
    ctl(&[CTL_CURSOR_SET, 5, 2, 0], b"").unwrap();
    assert_eq!(ctl(&[CTL_CURSOR_GET, 0, 0, 0], b""), Some([5, 2]));
    assert_eq!(ctl(&[CTL_SIZE, 0, 0, 0], b""), Some([20, 4]));
}

#[test]
fn scroll_lock_and_scrollback() {
    let _g = setup();
    // After the takeover (the BIOS data area is not consulted)
    k::console::set_hardware_mode(true);
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 3, 0, 0], b""), Some([0, 0]));
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 1, 0, 0], b""), Some([1, 0]));
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 3, 0, 0], b""), Some([1, 0]));
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 2, 0, 0], b""), Some([0, 0]));
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 2, 0, 0], b""), Some([1, 0]));
    assert_eq!(ctl(&[CTL_SCROLL_LOCK, 0, 0, 0], b""), Some([0, 0]));
    // 30 lines on a 25-row screen: 6 lines can be scrolled back (one row is the prompt's)
    for i in 0..30 {
        k::console::print_raw(&format!("line {}\n", i));
    }
    assert_eq!(ctl(&[CTL_MAX_SCROLL, 0, 0, 0], b""), Some([6, 0]));
    ctl(&[CTL_CLEAR_SCROLLBACK, 0, 0, 0], b"").unwrap();
    assert_eq!(ctl(&[CTL_MAX_SCROLL, 0, 0, 0], b""), Some([0, 0]));
    let g = k::console::console_output_generation();
    assert_eq!(ctl(&[CTL_GENERATION, 0, 0, 0], b""), Some([g, 0]));
}

#[test]
fn the_viewport_draws_the_prompt_and_line() {
    let _g = setup();
    k::console::print_raw("history\n");
    uefi_fake::take();
    // prompt "$ ", text "ls -l", cursor at 2, prompt colour 14 (yellow)
    ctl(&[CTL_VIEWPORT, 0, 2, 14], b"$ \0ls -l").unwrap();
    let s = uefi_fake::take();
    // (the firmware console's writer turns every "\n" into "\r\n")
    assert!(s.text.replace('\r', "").ends_with("history\n$ ls -l"), "{:?}", s.text);
    assert!(s.attrs.contains(&0x0E));
    assert_eq!(*s.moves.last().unwrap(), (4, 1));
    // No NUL: all prompt; a bad colour number: light green
    ctl(&[CTL_VIEWPORT, 0, 0, 99], b"> ").unwrap();
    let s = uefi_fake::take();
    assert!(s.text.ends_with("> "));
    assert!(s.attrs.contains(&0x0A));
    // Text that is not UTF-8: nothing but the history
    ctl(&[CTL_VIEWPORT, 0, 0, 1], b"\xff").unwrap();
    assert!(uefi_fake::take().text.replace('\r', "").ends_with("history\n"));
}
