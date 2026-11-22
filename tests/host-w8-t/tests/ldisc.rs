//! tty-server's line discipline (moved from the kernel's `tty.rs`).

mod common;

use common::FakeMem;
use hydra_hosttests_w8_t::ldisc::*;
use hydra_hosttests_w8_t::proto::LX_CONS_KEY_SPECIAL;

fn feed(t: &mut Tty, s: &[u8]) -> (Vec<u8>, Vec<u32>) {
    let (mut e, mut sig) = (Vec::new(), Vec::new());
    feed_input(t, s, &mut e, &mut sig);
    (e, sig)
}

#[test]
fn termios_bytes_round_trip() {
    let t = Termios::default();
    let b = t.to_bytes();
    assert_eq!(Termios::from_bytes(&b), t);
    assert_eq!(b[17], 3, "VINTR is ^C");
    assert_eq!(u32::from_le_bytes([b[12], b[13], b[14], b[15]]) & ICANON, ICANON);
}

#[test]
fn canonical_line_with_echo() {
    let mut t = Tty::new();
    let (echo, sig) = feed(&mut t, b"hi\r");
    assert!(sig.is_empty());
    assert_eq!(echo, b"hi\r\n", "CR becomes NL (ICRNL), echoed as CR LF");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"hi\n");
    assert!(take_input(&mut t, 100).is_none(), "nothing more: the reader waits");
}

#[test]
fn partial_line_is_not_readable() {
    let mut t = Tty::new();
    feed(&mut t, b"abc");
    assert!(!t.has_input());
    assert!(peek_input(&t, 10).is_none());
}

#[test]
fn erase_kill_and_word_erase() {
    let mut t = Tty::new();
    let (echo, _) = feed(&mut t, b"abx\x7fc\n");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"abc\n");
    assert!(echo.windows(3).any(|w| w == b"\x08 \x08"));
    feed(&mut t, b"junk\x15ok\n");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"ok\n");
    feed(&mut t, b"one two\x17three\n");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"one three\n");
}

#[test]
fn eof_marker() {
    let mut t = Tty::new();
    feed(&mut t, b"\x04");
    assert_eq!(take_input(&mut t, 10).unwrap(), b"", "^D alone is end-of-file");
    assert!(!t.has_input(), "the marker is used up");
    feed(&mut t, b"ab\x04");
    assert_eq!(take_input(&mut t, 10).unwrap(), b"ab", "^D after a partial line pushes it out");
    assert!(!t.has_input(), "and no second end-of-file is left");
}

#[test]
fn reads_take_one_line_at_a_time_and_respect_the_size() {
    let mut t = Tty::new();
    feed(&mut t, b"one\ntwo\n");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"one\n");
    assert_eq!(take_input(&mut t, 2).unwrap(), b"tw");
    assert_eq!(take_input(&mut t, 100).unwrap(), b"o\n");
}

#[test]
fn peek_does_not_take() {
    let mut t = Tty::new();
    feed(&mut t, b"x\n");
    let (b, used) = peek_input(&t, 10).unwrap();
    assert_eq!((b.as_slice(), used), (&b"x\n"[..], 2));
    assert!(t.has_input());
    commit(&mut t, used);
    assert!(!t.has_input());
}

#[test]
fn isig_characters() {
    let mut t = Tty::new();
    let (echo, sig) = feed(&mut t, b"ab\x03");
    assert_eq!(sig, vec![SIGINT]);
    assert_eq!(echo, b"ab^C\r\n");
    assert!(t.line.is_empty(), "the line is dropped");
    let (_, sig) = feed(&mut t, b"\x1c\x1a");
    assert_eq!(sig, vec![SIGQUIT, SIGTSTP]);
}

#[test]
fn raw_mode_and_vmin_zero() {
    let mut t = Tty::new();
    let mut tm = t.termios;
    tm.lflag &= !(ICANON | 0o10 | 0o1); // ~ICANON ~ECHO ~ISIG
    t.termios = tm;
    let (echo, sig) = feed(&mut t, b"\x03x");
    assert!(echo.is_empty() && sig.is_empty(), "no echo, ^C is a byte");
    assert_eq!(take_input(&mut t, 10).unwrap(), b"\x03x");
    assert!(take_input(&mut t, 10).is_none(), "VMIN=1 waits");
    t.termios.cc[6] = 0;
    assert_eq!(take_input(&mut t, 10).unwrap(), b"", "VMIN=0 returns at once");
}

#[test]
fn output_processing() {
    let t = Tty::new();
    let mut out = Vec::new();
    process_output(&t, b"a\nb", &mut out);
    assert_eq!(out, b"a\r\nb");
    let mut raw = Tty::new();
    raw.termios.oflag = 0;
    let mut out = Vec::new();
    process_output(&raw, b"a\n", &mut out);
    assert_eq!(out, b"a\n");
}

#[test]
fn console_keys_as_bytes() {
    assert_eq!(key_bytes('a' as u32), b"a");
    assert_eq!(key_bytes(8), vec![0x7f], "backspace sends DEL");
    assert_eq!(key_bytes(0xE9), "\u{e9}".as_bytes());
    assert_eq!(key_bytes(LX_CONS_KEY_SPECIAL | 1), b"\x1b[A");
    assert_eq!(key_bytes(LX_CONS_KEY_SPECIAL | 4), b"\x1b[D");
    assert_eq!(key_bytes(LX_CONS_KEY_SPECIAL | 0x17), vec![0x1b]);
    assert!(key_bytes(LX_CONS_KEY_SPECIAL | 0x40).is_empty());
    assert!(key_bytes(0xD800).is_empty(), "not a character");
}

#[test]
fn ioctl_get_and_set_termios() {
    let mut t = Tty::new();
    let mem = FakeMem::default();
    let mut fx = Effects::default();
    assert_eq!(ioctl(&mut t, TCGETS, 0x1000, &mem, (24, 80), &mut fx), 0);
    assert_eq!(mem.at(0x1000).len(), 36);
    assert_eq!(ioctl(&mut t, TCGETS2, 0x2000, &mem, (24, 80), &mut fx), 0);
    let b2 = mem.at(0x2000);
    assert_eq!(b2.len(), 44);
    assert_eq!(u32::from_le_bytes([b2[36], b2[37], b2[38], b2[39]]), 38400);
    // Raw mode with a half-typed line: the line becomes readable
    feed(&mut t, b"half");
    let mut raw = Termios::default();
    raw.lflag &= !ICANON;
    mem.put(0x3000, &raw.to_bytes()).unwrap();
    assert_eq!(ioctl(&mut t, TCSETS2, 0x3000, &mem, (24, 80), &mut fx), 0);
    assert!(fx.input_changed);
    assert_eq!(take_input(&mut t, 10).unwrap(), b"half");
    // TCSETSF flushes
    feed(&mut t, b"zz");
    assert_eq!(ioctl(&mut t, TCSETSF, 0x3000, &mem, (24, 80), &mut fx), 0);
    assert!(!t.has_input());
    assert_eq!(ioctl(&mut t, TCSETS, 0, &mem, (24, 80), &mut fx), EFAULT);
}

#[test]
fn ioctl_window_size_and_groups() {
    let mut t = Tty::new();
    let mem = FakeMem::default();
    let mut fx = Effects::default();
    assert_eq!(ioctl(&mut t, TIOCGWINSZ, 0x10, &mem, (25, 100), &mut fx), 0);
    assert_eq!(&mem.at(0x10)[..4], &[25, 0, 100, 0], "the default until set");
    mem.put(0x20, &[33, 0, 101, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(ioctl(&mut t, TIOCSWINSZ, 0x20, &mem, (25, 100), &mut fx), 0);
    assert!(fx.resized);
    let mut fx2 = Effects::default();
    assert_eq!(ioctl(&mut t, TIOCSWINSZ, 0x20, &mem, (25, 100), &mut fx2), 0);
    assert!(!fx2.resized, "the same size again is no change");
    assert_eq!(ioctl(&mut t, TIOCGWINSZ, 0x30, &mem, (25, 100), &mut fx), 0);
    assert_eq!(&mem.at(0x30)[..4], &[33, 0, 101, 0]);
    mem.put(0x40, &77i32.to_le_bytes()).unwrap();
    assert_eq!(ioctl(&mut t, TIOCSPGRP, 0x40, &mem, (25, 100), &mut fx), 0);
    assert_eq!(ioctl(&mut t, TIOCGPGRP, 0x44, &mem, (25, 100), &mut fx), 0);
    assert_eq!(mem.at(0x44), 77i32.to_le_bytes());
    t.session = 9;
    assert_eq!(ioctl(&mut t, TIOCGSID, 0x48, &mem, (25, 100), &mut fx), 0);
    assert_eq!(mem.at(0x48), 9i32.to_le_bytes());
    feed(&mut t, b"ab\n");
    assert_eq!(ioctl(&mut t, FIONREAD, 0x50, &mem, (25, 100), &mut fx), 0);
    assert_eq!(mem.at(0x50), 3i32.to_le_bytes());
    assert_eq!(ioctl(&mut t, TCFLSH, 0, &mem, (25, 100), &mut fx), 0);
    assert!(!t.has_input());
    assert_eq!(ioctl(&mut t, 0x1234, 0, &mem, (25, 100), &mut fx), EINVAL);
    assert_eq!(canonical_request(TCSETSW2), TCSETSW);
}
