//! The line discipline, moved from the kernel's `src/compat/linux/tty.rs` (wave 8): termios,
//! canonical line editing with echo (erase, kill, word erase, end-of-file), raw mode, the
//! `ISIG` characters (Ctrl+C, Ctrl+\, Ctrl+Z) as signals for the foreground group, output
//! processing (`ONLCR`), console keys as ANSI escape sequences, and the terminal `ioctl`s
//! shared by the console and the pseudo-terminals (`TCGETS`, `TCSETS*`, `TIOCGWINSZ`, ...).
//!
//! Plain logic (no system calls): the caller's memory is reached through [`Mem`], so the
//! host tests (`tests/host-w8-t`) run it as it is.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::proto::LX_CONS_KEY_SPECIAL;

// c_iflag
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
// c_oflag
const OPOST: u32 = 0o1;
const ONLCR: u32 = 0o4;
// c_cflag
const B38400: u32 = 0o17;
const CS8: u32 = 0o60;
const CREAD: u32 = 0o200;
// c_lflag
const ISIG: u32 = 0o1;
/// `ICANON`.
pub const ICANON: u32 = 0o2;
const ECHO: u32 = 0o10;
const ECHOE: u32 = 0o20;
const ECHOK: u32 = 0o40;
const ECHOCTL: u32 = 0o1000;
const ECHOKE: u32 = 0o4000;
const IEXTEN: u32 = 0o100000;

// c_cc indices
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VSUSP: usize = 10;
const VWERASE: usize = 14;

/// Signals the line discipline raises.
pub const SIGINT: u32 = 2;
/// `SIGQUIT`.
pub const SIGQUIT: u32 = 3;
/// `SIGTSTP`.
pub const SIGTSTP: u32 = 20;
/// `SIGWINCH`.
pub const SIGWINCH: u32 = 28;

pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const ENOTTY: i64 = -25;

// The terminal requests
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;
pub const TCXONC: u64 = 0x540A;
pub const TCFLSH: u64 = 0x540B;
pub const TIOCSCTTY: u64 = 0x540E;
pub const TIOCGPGRP: u64 = 0x540F;
pub const TIOCSPGRP: u64 = 0x5410;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TIOCSWINSZ: u64 = 0x5414;
pub const FIONREAD: u64 = 0x541B;
pub const TIOCNOTTY: u64 = 0x5422;
pub const TIOCGSID: u64 = 0x5429;
// termios2 variants carry the same 36 bytes plus input/output speeds (used by glibc)
pub const TCGETS2: u64 = 0x802c_542a;
pub const TCSETS2: u64 = 0x402c_542b;
pub const TCSETSW2: u64 = 0x402c_542c;
pub const TCSETSF2: u64 = 0x402c_542d;

/// The caller's memory, as the requests read and write it.
pub trait Mem {
    /// `len` bytes at `ptr`.
    fn get(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64>;
    /// Writes `data` at `ptr`.
    fn put(&self, ptr: u64, data: &[u8]) -> Result<(), i64>;
}

/// Kernel `struct termios` (36 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; 19],
}

impl Termios {
    /// A new terminal's settings (cooked, echo, signals).
    pub const fn default() -> Self {
        let mut cc = [0u8; 19];
        cc[VINTR] = 3;
        cc[VQUIT] = 0x1c;
        cc[VERASE] = 0x7f;
        cc[VKILL] = 0x15;
        cc[VEOF] = 4;
        cc[VTIME] = 0;
        cc[VMIN] = 1;
        cc[8] = 0x11; // VSTART
        cc[9] = 0x13; // VSTOP
        cc[VSUSP] = 0x1a;
        cc[12] = 0x12; // VREPRINT
        cc[13] = 0x0f; // VDISCARD
        cc[VWERASE] = 0x17;
        cc[15] = 0x16; // VLNEXT
        Self {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc,
        }
    }

    /// The 36 bytes of Linux's `struct termios`.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        b[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        b[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        b[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        b[16] = self.line;
        b[17..36].copy_from_slice(&self.cc);
        b
    }

    /// From the 36 bytes of Linux's `struct termios` (at least 36 bytes).
    pub fn from_bytes(b: &[u8]) -> Self {
        let u = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let mut cc = [0u8; 19];
        cc.copy_from_slice(&b[17..36]);
        Self { iflag: u(0), oflag: u(4), cflag: u(8), lflag: u(12), line: b[16], cc }
    }
}

/// Terminal state: termios settings, line editing and the input queue for `read`.
pub struct Tty {
    pub termios: Termios,
    /// Line being edited in canonical mode.
    pub line: Vec<u8>,
    /// Input ready for `read`; `None` marks an end-of-file (Ctrl+D) boundary.
    pub ready: VecDeque<Option<u8>>,
    /// Session holding the terminal (0: none).
    pub session: u64,
    /// Foreground process group (receives Ctrl+C).
    pub fg_pgrp: u64,
    /// `(rows, cols)` once set (`TIOCSWINSZ`).
    pub winsize: Option<(u16, u16)>,
}

impl Default for Tty {
    fn default() -> Self {
        Self::new()
    }
}

impl Tty {
    /// A terminal with the default settings and nothing typed.
    pub const fn new() -> Self {
        Self { termios: Termios::default(), line: Vec::new(), ready: VecDeque::new(), session: 0, fg_pgrp: 0, winsize: None }
    }

    /// Whether `read` would return data (or end-of-file) now.
    pub fn has_input(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Whether the terminal is in canonical mode.
    pub fn canonical(&self) -> bool {
        self.termios.lflag & ICANON != 0
    }

    /// Bytes `FIONREAD` counts (up to the next end-of-file marker).
    pub fn readable_bytes(&self) -> usize {
        self.ready.iter().take_while(|b| b.is_some()).count()
    }

    /// Back to the default settings with nothing typed (the console's attach).
    pub fn reset(&mut self) {
        self.termios = Termios::default();
        self.line.clear();
        self.ready.clear();
    }
}

/// Output processing (`ONLCR`: newline -> CR LF) of program output, appended to `out`.
pub fn process_output(t: &Tty, data: &[u8], out: &mut Vec<u8>) {
    let oflag = t.termios.oflag;
    if oflag & OPOST != 0 && oflag & ONLCR != 0 {
        for &b in data {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
    } else {
        out.extend_from_slice(data);
    }
}

/// The bytes a console key sends ([`LX_CONS_KEY_SPECIAL`] marks a UEFI scan code).
pub fn key_bytes(key: u32) -> Vec<u8> {
    if key & LX_CONS_KEY_SPECIAL == 0 {
        let Some(c) = char::from_u32(key) else { return Vec::new() };
        if c == '\u{8}' {
            return alloc::vec![0x7f]; // Backspace sends DEL, as on a Linux console
        }
        let mut buf = [0u8; 4];
        return c.encode_utf8(&mut buf).as_bytes().to_vec();
    }
    match key & 0xFFFF {
        1 => b"\x1b[A".to_vec(),
        2 => b"\x1b[B".to_vec(),
        3 => b"\x1b[C".to_vec(),
        4 => b"\x1b[D".to_vec(),
        5 => b"\x1b[H".to_vec(),
        6 => b"\x1b[F".to_vec(),
        8 => b"\x1b[3~".to_vec(),
        9 => b"\x1b[5~".to_vec(),
        10 => b"\x1b[6~".to_vec(),
        0x17 => alloc::vec![0x1b], // Escape
        _ => Vec::new(),
    }
}

/// Feeds input bytes through the line discipline: echo goes to `echo`, and `ISIG`
/// characters add the signal to raise (in the foreground group) to `signals`.
pub fn feed_input(t: &mut Tty, bytes: &[u8], echo: &mut Vec<u8>, signals: &mut Vec<u32>) {
    for &b in bytes {
        if let Some(sig) = input_byte(t, b, echo) {
            signals.push(sig);
        }
    }
}

/// Feeds one input byte through the line discipline; the signal to raise, if any.
fn input_byte(t: &mut Tty, mut b: u8, echo: &mut Vec<u8>) -> Option<u32> {
    let tm = t.termios;
    if tm.iflag & ICRNL != 0 && b == b'\r' {
        b = b'\n';
    }
    if tm.lflag & ISIG != 0 {
        let sig = if b == tm.cc[VINTR] {
            Some(SIGINT)
        } else if b == tm.cc[VQUIT] {
            Some(SIGQUIT)
        } else if b == tm.cc[VSUSP] {
            Some(SIGTSTP)
        } else {
            None
        };
        if let Some(sig) = sig {
            t.line.clear();
            if tm.lflag & ECHO != 0 {
                echo.extend_from_slice(&[b'^', b.wrapping_add(0x40), b'\r', b'\n']);
            }
            return Some(sig);
        }
    }
    if tm.lflag & ICANON != 0 {
        if b == tm.cc[VERASE] || b == 0x08 {
            if t.line.pop().is_some() && tm.lflag & ECHO != 0 {
                echo.extend_from_slice(b"\x08 \x08");
            }
        } else if b == tm.cc[VKILL] {
            for _ in 0..t.line.len() {
                if tm.lflag & ECHO != 0 {
                    echo.extend_from_slice(b"\x08 \x08");
                }
            }
            t.line.clear();
        } else if b == tm.cc[VWERASE] {
            while matches!(t.line.last(), Some(b' ')) {
                t.line.pop();
                echo.extend_from_slice(b"\x08 \x08");
            }
            while matches!(t.line.last(), Some(c) if *c != b' ') {
                t.line.pop();
                echo.extend_from_slice(b"\x08 \x08");
            }
        } else if b == tm.cc[VEOF] {
            let line = core::mem::take(&mut t.line);
            t.ready.extend(line.into_iter().map(Some));
            t.ready.push_back(None);
        } else if b == b'\n' {
            t.line.push(b);
            let line = core::mem::take(&mut t.line);
            t.ready.extend(line.into_iter().map(Some));
            if tm.lflag & ECHO != 0 {
                echo.extend_from_slice(b"\r\n");
            }
        } else {
            t.line.push(b);
            if tm.lflag & ECHO != 0 {
                if b < 0x20 && tm.lflag & ECHOCTL != 0 {
                    echo.extend_from_slice(&[b'^', b + 0x40]);
                } else {
                    echo.push(b);
                }
            }
        }
    } else {
        t.ready.push_back(Some(b));
        if tm.lflag & ECHO != 0 {
            echo.push(b);
        }
    }
    None
}

/// What a `read` of at most `max` bytes would take: the bytes and how many queue entries
/// they use (an end-of-file marker counts), without taking them ([`commit`] does). A line
/// in canonical mode, otherwise what is there. `None`: the reader must wait.
pub fn peek_input(t: &Tty, max: usize) -> Option<(Vec<u8>, usize)> {
    let canon = t.canonical();
    if !t.ready.is_empty() {
        let mut out = Vec::new();
        let mut used = 0;
        for e in t.ready.iter() {
            if out.len() >= max {
                break;
            }
            used += 1;
            match e {
                Some(b) => {
                    out.push(*b);
                    if canon && *b == b'\n' {
                        break;
                    }
                }
                // End-of-file marker (^D): ends this read, 0 bytes if nothing came before
                // it. Used up either way, as on Linux
                None => break,
            }
        }
        return Some((out, used));
    }
    if !canon && t.termios.cc[VMIN] == 0 {
        return Some((Vec::new(), 0));
    }
    None
}

/// Takes `used` queue entries (what [`peek_input`] counted).
pub fn commit(t: &mut Tty, used: usize) {
    for _ in 0..used {
        t.ready.pop_front();
    }
}

/// Takes input for `read` (at most `max` bytes): [`peek_input`] and [`commit`] at once.
pub fn take_input(t: &mut Tty, max: usize) -> Option<Vec<u8>> {
    let (b, used) = peek_input(t, max)?;
    commit(t, used);
    Some(b)
}

/// What a terminal request did besides its answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// The window size changed (the caller sends `SIGWINCH` to the foreground group).
    pub resized: bool,
    /// Input may have become readable (a mode change, a flush): wake readers.
    pub input_changed: bool,
}

/// The canonical request number (termios2's set requests are the plain ones).
pub fn canonical_request(request: u64) -> u64 {
    match request {
        TCSETS2 => TCSETS,
        TCSETSW2 => TCSETSW,
        TCSETSF2 => TCSETSF,
        r => r,
    }
}

/// A terminal request on `t` (the ones the console and pseudo-terminals share; the callers
/// decide `TIOCSCTTY`, `TIOCNOTTY` and `TIOCSPGRP`'s checks first). `default_size` gives
/// `(rows, cols)` until `TIOCSWINSZ`. `EINVAL` for requests it does not know.
pub fn ioctl(t: &mut Tty, request: u64, arg: u64, mem: &dyn Mem, default_size: (u16, u16), fx: &mut Effects) -> i64 {
    let ok = |r: Result<(), i64>| r.map_or_else(|e| e, |()| 0);
    let request = canonical_request(request);
    match request {
        TCGETS | TCGETS2 => {
            let b = t.termios.to_bytes();
            let mut full = [0u8; 44];
            full[..36].copy_from_slice(&b);
            full[36..40].copy_from_slice(&38400u32.to_le_bytes());
            full[40..44].copy_from_slice(&38400u32.to_le_bytes());
            let len = if request == TCGETS2 { 44 } else { 36 };
            ok(mem.put(arg, &full[..len]))
        }
        TCSETS | TCSETSW | TCSETSF => match mem.get(arg, 36) {
            Ok(b) => {
                t.termios = Termios::from_bytes(&b);
                if request == TCSETSF {
                    t.ready.clear();
                    t.line.clear();
                }
                // Leaving canonical mode makes the half-typed line readable
                if !t.canonical() && !t.line.is_empty() {
                    let line = core::mem::take(&mut t.line);
                    t.ready.extend(line.into_iter().map(Some));
                }
                fx.input_changed = true;
                0
            }
            Err(e) => e,
        },
        TCXONC => 0,
        TCFLSH => {
            if arg == 0 || arg == 2 {
                t.ready.clear();
                t.line.clear();
            }
            0
        }
        TIOCGWINSZ => {
            let (rows, cols) = t.winsize.unwrap_or(default_size);
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&rows.to_le_bytes());
            b[2..4].copy_from_slice(&cols.to_le_bytes());
            ok(mem.put(arg, &b))
        }
        TIOCSWINSZ => match mem.get(arg, 8) {
            Ok(b) => {
                let size = Some((u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]])));
                fx.resized = t.winsize != size;
                t.winsize = size;
                0
            }
            Err(e) => e,
        },
        TIOCGPGRP => ok(mem.put(arg, &(t.fg_pgrp as i32).to_le_bytes())),
        TIOCSPGRP => match mem.get(arg, 4) {
            Ok(b) => {
                t.fg_pgrp = i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                0
            }
            Err(e) => e,
        },
        TIOCGSID => ok(mem.put(arg, &(t.session as i32).to_le_bytes())),
        TIOCSCTTY | TIOCNOTTY => 0,
        FIONREAD => ok(mem.put(arg, &(t.readable_bytes() as i32).to_le_bytes())),
        _ => EINVAL,
    }
}
