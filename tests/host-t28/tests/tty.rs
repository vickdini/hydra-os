//! `tty.rs`: the console terminal: keys as terminal input, the line discipline (canonical
//! editing, echo, ISIG signals, raw mode, end-of-file), output processing, job control
//! for background readers, the terminal and virtual terminal ioctls.
//!
//! The console terminal is one global, so every test holds `common::serial()` and starts
//! from `attach_session`.

mod common;

use hydra_hosttests_t28::compat::linux::tty;
use hydra_hosttests_t28::fake;
use uefi::proto::console::text::{Key, ScanCode};

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EAGAIN: i64 = -11;
const ERESTARTSYS: i64 = -512;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSF: u64 = 0x5404;
const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ISIG: u32 = 0o1;

fn p<T>(v: &mut [T]) -> u64 {
    v.as_mut_ptr() as u64
}

/// The console attached to session 10 (foreground group 10), the caller in it.
fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = common::serial();
    tty::attach_session(10, 10);
    fake::IDS.set((10, 10));
    fake::SESSIONS.with_borrow_mut(|m| {
        m.clear();
        m.insert(10, (10, 10));
    });
    fake::KEYS.with_borrow_mut(|k| k.clear());
    fake::take_console();
    fake::take_group_signals();
    fake::SIGNAL_PENDING.set(false);
    fake::IGNORES.set(false);
    fake::clear_on_wait();
    g
}

fn read_now(n: usize) -> (i64, Vec<u8>) {
    let mut b = vec![0u8; n];
    let r = tty::read(&mut b, true);
    b.truncate(r.max(0) as usize);
    (r, b)
}

fn termios() -> [u8; 36] {
    let mut t = [0u8; 36];
    assert_eq!(tty::ioctl(TCGETS, p(&mut t)), 0);
    t
}

fn set_lflag(lflag: u32) {
    let mut t = termios();
    t[12..16].copy_from_slice(&lflag.to_le_bytes());
    assert_eq!(tty::ioctl(TCSETS, p(&mut t)), 0);
}

fn lflag() -> u32 {
    u32::from_le_bytes(termios()[12..16].try_into().unwrap())
}

#[test]
fn session_attach_and_detach() {
    let _g = setup();
    assert!(tty::attached());
    tty::set_nonblock(true);
    assert!(tty::nonblock());
    // Attaching resets the mode and the file's O_NONBLOCK
    set_lflag(0);
    tty::attach_session(11, 12);
    assert!(!tty::nonblock());
    assert_eq!(lflag() & (ICANON | ECHO | ISIG), ICANON | ECHO | ISIG);
    let mut sid = [0i32];
    assert_eq!(tty::ioctl(0x5429, p(&mut sid)), 0);
    assert_eq!(sid[0], 11);
    tty::detach_session();
    assert!(!tty::attached());
    // Detached, keys are the Hydra shell's: pump leaves them
    fake::type_keys("ab");
    tty::pump();
    assert_eq!(fake::KEYS.with_borrow(|k| k.len()), 2);
    assert!(!tty::has_input());
}

#[test]
fn canonical_line_with_echo() {
    let _g = setup();
    fake::type_keys("hi\r");
    assert!(tty::readable());
    assert!(tty::has_input());
    // Echo with CR LF, the line ends in a newline (ICRNL)
    assert_eq!(fake::take_console(), b"hi\r\n");
    assert!(tty::INPUT_WQ.wakes() > 0);
    assert_eq!(read_now(64), (3, b"hi\n".to_vec()));
    // Nothing more: EAGAIN without blocking
    assert_eq!(read_now(64).0, EAGAIN);
}

#[test]
fn canonical_reads_stop_at_a_newline() {
    let _g = setup();
    fake::type_keys("one\rtwo\r");
    tty::pump();
    assert_eq!(read_now(64), (4, b"one\n".to_vec()));
    // A small buffer takes part of the line
    assert_eq!(read_now(2), (2, b"tw".to_vec()));
    assert_eq!(read_now(64), (2, b"o\n".to_vec()));
}

#[test]
fn line_editing_keys() {
    let _g = setup();
    // Erase (DEL and backspace), kill (^U), word erase (^W)
    fake::type_keys("abc\u{7f}\u{8}x");
    tty::pump();
    assert_eq!(fake::take_console(), b"abc\x08 \x08\x08 \x08x");
    fake::type_keys("\u{15}");
    tty::pump();
    assert_eq!(fake::take_console(), b"\x08 \x08\x08 \x08");
    fake::type_keys("foo bar  \u{17}\r");
    tty::pump();
    let echo = fake::take_console();
    assert!(echo.starts_with(b"foo bar  "));
    assert_eq!(read_now(64), (5, b"foo \n".to_vec()));
    // Erase on an empty line echoes nothing
    fake::type_keys("\u{7f}");
    tty::pump();
    assert!(fake::take_console().is_empty());
    // Control characters echo as ^X (ECHOCTL)
    fake::type_keys("\u{1}\r");
    tty::pump();
    assert_eq!(fake::take_console(), b"^A\r\n");
    assert_eq!(read_now(64), (2, vec![1, b'\n']));
}

#[test]
fn end_of_file_marks() {
    let _g = setup();
    // ^D on a partial line ends the read without a newline (the ^D itself is used up, as
    // on Linux); on an empty line: 0, once per ^D
    fake::type_keys("ab\u{4}\u{4}");
    tty::pump();
    assert_eq!(read_now(64), (2, b"ab".to_vec()));
    assert_eq!(read_now(64), (0, vec![]));
    // Bug fixed (wave TW, Group 28): the first ^D stayed queued and the reader after got
    // a second, spurious end-of-file (a shell started after `cat` exited at once)
    assert_eq!(read_now(64).0, EAGAIN);
    // A buffer too small for the line: the rest, then the end of the line
    fake::type_keys("abc\u{4}");
    tty::pump();
    assert_eq!(read_now(2), (2, b"ab".to_vec()));
    assert_eq!(read_now(64), (1, b"c".to_vec()));
    assert_eq!(read_now(64).0, EAGAIN);
    // FIONREAD counts up to the end-of-file mark
    fake::type_keys("xyz\u{4}q\r");
    let mut n = [0i32];
    assert_eq!(tty::ioctl(0x541B, p(&mut n)), 0);
    assert_eq!(n[0], 3);
}

#[test]
fn isig_characters_signal_the_foreground_group() {
    let _g = setup();
    fake::type_keys("abc\u{3}");
    tty::pump();
    assert_eq!(fake::take_group_signals(), vec![(10, 2)]);
    // The partial line is dropped; ^C echoes
    assert_eq!(fake::take_console(), b"abc^C\r\n");
    assert_eq!(read_now(8).0, EAGAIN);
    fake::type_keys("\u{1c}\u{1a}");
    tty::pump();
    assert_eq!(fake::take_group_signals(), vec![(10, 3), (10, 20)]);
    // Without ISIG they are ordinary input
    set_lflag(ICANON | ECHO);
    fake::type_keys("\u{3}\r");
    tty::pump();
    assert!(fake::take_group_signals().is_empty());
    assert_eq!(read_now(8), (2, vec![3, b'\n']));
}

#[test]
fn raw_mode_and_special_keys() {
    let _g = setup();
    set_lflag(0);
    // Cursor and editing keys become escape sequences; backspace sends DEL
    fake::KEYS.with_borrow_mut(|k| {
        for code in [1u16, 2, 3, 4, 5, 6, 8, 9, 10, 0x17, 0x30] {
            k.push_back(Key::Special(ScanCode(code)));
        }
        k.push_back(Key::Printable(uefi::Char16::try_from('\u{8}').unwrap()));
        k.push_back(Key::Printable(uefi::Char16::try_from('é').unwrap()));
    });
    tty::pump();
    let (n, b) = read_now(128);
    let want: Vec<u8> = [&b"\x1b[A\x1b[B\x1b[C\x1b[D\x1b[H\x1b[F\x1b[3~\x1b[5~\x1b[6~\x1b"[..], &[0x7f], "é".as_bytes()].concat();
    assert_eq!(b, want);
    assert_eq!(n as usize, want.len());
    // No echo with ECHO off
    assert!(fake::take_console().is_empty());
    // Raw with echo: each byte echoed
    set_lflag(ECHO);
    fake::type_keys("k");
    tty::pump();
    assert_eq!(fake::take_console(), b"k");
    assert_eq!(read_now(8), (1, b"k".to_vec()));
}

#[test]
fn raw_mode_vmin_zero_returns_at_once() {
    let _g = setup();
    let mut t = termios();
    t[12..16].copy_from_slice(&0u32.to_le_bytes());
    t[17 + 6] = 0; // VMIN
    assert_eq!(tty::ioctl(TCSETS, p(&mut t)), 0);
    let mut b = [0u8; 8];
    assert_eq!(tty::read(&mut b, false), 0);
}

#[test]
fn leaving_canonical_mode_makes_the_partial_line_readable() {
    let _g = setup();
    fake::type_keys("par");
    tty::pump();
    assert_eq!(read_now(8).0, EAGAIN);
    set_lflag(0);
    assert_eq!(read_now(8), (3, b"par".to_vec()));
    // TCSETSF flushes pending input
    set_lflag(ICANON);
    fake::type_keys("gone\r");
    tty::pump();
    let mut t = termios();
    assert_eq!(tty::ioctl(TCSETSF, p(&mut t)), 0);
    assert_eq!(read_now(8).0, EAGAIN);
    // termios2 variants map onto the same requests
    let mut t2 = [0u8; 44];
    assert_eq!(tty::ioctl(0x802c_542a, p(&mut t2)), 0);
    assert_eq!(&t2[..36], &t);
    assert_eq!(u32::from_le_bytes(t2[36..40].try_into().unwrap()), 38400);
    for req in [0x402c_542b, 0x402c_542c, 0x402c_542d, 0x5403] {
        assert_eq!(tty::ioctl(req, p(&mut t2)), 0, "{req:#x}");
    }
}

#[test]
fn flush_and_flow_control() {
    let _g = setup();
    fake::type_keys("x\r");
    tty::pump();
    assert_eq!(tty::ioctl(0x540B, 1), 0); // TCOFLUSH: input stays
    assert!(tty::has_input());
    assert_eq!(tty::ioctl(0x540B, 0), 0); // TCIFLUSH
    assert!(!tty::has_input());
    fake::type_keys("y\r");
    tty::pump();
    assert_eq!(tty::ioctl(0x540B, 2), 0); // TCIOFLUSH
    assert!(!tty::has_input());
    assert_eq!(tty::ioctl(0x540A, 1), 0); // TCXONC
    assert_eq!(tty::ioctl(0x540E, 0), 0); // TIOCSCTTY
    assert_eq!(tty::ioctl(0x5422, 0), 0); // TIOCNOTTY
    assert_eq!(tty::ioctl(0x9999, 0), EINVAL);
    assert_eq!(tty::NOT_A_TTY, -25);
}

#[test]
fn window_size_and_process_groups() {
    let _g = setup();
    // The console's size until TIOCSWINSZ
    fake::CONSOLE_SIZE.set((132, 43));
    let mut ws = [0u16; 4];
    assert_eq!(tty::ioctl(0x5413, p(&mut ws)), 0);
    assert_eq!(&ws[..2], &[43, 132]);
    let mut new = [50u16, 200, 0, 0];
    assert_eq!(tty::ioctl(0x5414, p(&mut new)), 0);
    assert_eq!(tty::ioctl(0x5413, p(&mut ws)), 0);
    assert_eq!(&ws[..2], &[50, 200]);
    let mut pg = [0i32];
    assert_eq!(tty::ioctl(0x5410, { pg[0] = 77; p(&mut pg) }), 0);
    pg[0] = 0;
    assert_eq!(tty::ioctl(0x540F, p(&mut pg)), 0);
    assert_eq!(pg[0], 77);
}

#[test]
fn ioctl_faults() {
    let _g = setup();
    for req in [TCGETS, TCSETS, 0x5413, 0x5414, 0x540F, 0x5410, 0x5429, 0x541B] {
        assert_eq!(tty::ioctl(req, fake::BAD_PTR), EFAULT, "{req:#x}");
        assert_eq!(tty::ioctl(req, 0), EFAULT, "{req:#x}");
    }
}

#[test]
fn background_readers_get_sigttin() {
    let _g = setup();
    // The caller's group (20) is not the foreground group (10)
    fake::SESSIONS.with_borrow_mut(|m| m.insert(10, (10, 20)));
    let mut b = [0u8; 4];
    assert_eq!(tty::read(&mut b, true), ERESTARTSYS);
    assert_eq!(fake::take_group_signals(), vec![(20, 21)]);
    // Ignoring SIGTTIN: EIO
    fake::IGNORES.set(true);
    assert_eq!(tty::read(&mut b, true), -5);
    // A process of another session is not stopped
    fake::SESSIONS.with_borrow_mut(|m| m.insert(10, (99, 20)));
    assert_eq!(tty::read(&mut b, true), EAGAIN);
    // An empty buffer reads nothing at once
    assert_eq!(tty::read(&mut [], false), 0);
}

#[test]
fn blocking_read_waits_for_a_line() {
    let _g = setup();
    let mut b = [0u8; 16];
    // A signal ends the wait
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(tty::read(&mut b, false), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    // Keys arrive while it sleeps
    let mut sent = false;
    fake::on_wait(move || {
        if !sent {
            fake::type_keys("late\r");
            sent = true;
        }
    });
    assert_eq!(tty::read(&mut b, false), 5);
    assert_eq!(&b[..5], b"late\n");
    fake::clear_on_wait();
}

#[test]
fn output_processing() {
    let _g = setup();
    assert_eq!(tty::write(b"a\nb\n"), 4);
    assert_eq!(fake::take_console(), b"a\r\nb\r\n");
    // Without OPOST the bytes go out as they are
    let mut t = termios();
    t[4..8].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(tty::ioctl(TCSETS, p(&mut t)), 0);
    assert_eq!(tty::write(b"a\nb"), 3);
    assert_eq!(fake::take_console(), b"a\nb");
    // Bytes that are not UTF-8 are printed one by one (the valid ones)
    assert_eq!(tty::write(&[b'o', 0xFF, b'k']), 3);
    assert_eq!(fake::take_console(), b"ok");
}

#[test]
fn traced_reads_and_mode_changes() {
    let _g = setup();
    use std::sync::atomic::Ordering;
    let tr = &hydra_hosttests_t28::compat::linux::TRACE_SYSCALLS;
    tr.store(true, Ordering::Relaxed);
    set_lflag(ICANON | ECHO | ISIG);
    fake::type_keys("t\r");
    assert_eq!(read_now(8), (2, b"t\n".to_vec()));
    tr.store(false, Ordering::Relaxed);
}

#[test]
fn virtual_terminal_ioctls() {
    let _g = setup();
    let mut v = [0i32];
    assert_eq!(tty::ioctl(0x5600, p(&mut v)), 0); // VT_OPENQRY
    let first = v[0];
    assert!(first >= 2);
    assert_eq!(tty::ioctl(0x5600, p(&mut v)), 0);
    assert_eq!(v[0], first + 1);
    let mut mode = [0xFFu8; 8];
    assert_eq!(tty::ioctl(0x5601, p(&mut mode)), 0);
    assert_eq!(mode, [0; 8]);
    for req in [0x5602, 0x5605, 0x5607, 0x5608, 0x4B3A, 0x4B45] {
        assert_eq!(tty::ioctl(req, 0), 0);
    }
    assert_eq!(tty::ioctl(0x5606, 3), 0); // VT_ACTIVATE
    assert_eq!(tty::active_vt(), 3);
    let mut st = [0u16; 3];
    assert_eq!(tty::ioctl(0x5603, p(&mut st)), 0);
    assert_eq!(st[0], 3);
    let next = first as u32 + 2;
    assert_eq!(st[2], ((1u32 << next.min(16)) - 1) as u16);
    let mut i = [9i32];
    assert_eq!(tty::ioctl(0x4B3B, p(&mut i)), 0);
    assert_eq!(i[0], 0);
    assert_eq!(tty::ioctl(0x4B44, p(&mut i)), 0);
    assert_eq!(i[0], 3);
    let mut kb = [0u8];
    assert_eq!(tty::ioctl(0x4B33, p(&mut kb)), 0);
    assert_eq!(kb[0], 2);
    assert_eq!(tty::ioctl(0x5600, fake::BAD_PTR), EFAULT);
    tty::ioctl(0x5606, 1);
}
