//! # Console Terminal (TTY Line Discipline)
//!
//! Turns the Hydra console (PS/2 keyboard + framebuffer) into a Linux terminal for Linux
//! processes: termios state, canonical line editing with echo (erase, kill, end-of-file),
//! raw mode for readline-style programs, keys for cursor movement as ANSI escape
//! sequences, `ISIG` characters (Ctrl+C, Ctrl+\) sent as signals to the foreground process
//! group, and the terminal `ioctl`s (`TCGETS`, `TCSETS*`, `TIOCGWINSZ`, `TIOCGPGRP`, ...).
//!
//! The console belongs to Linux processes only while a session holds it (see
//! [`attach_session`]); otherwise the Hydra shell reads the keyboard directly.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;
use uefi::proto::console::text::{Key, ScanCode};

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
const ICANON: u32 = 0o2;
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

const ENOTTY: i64 = -25;
const EINVAL: i64 = -22;
const EFAULT: i64 = -14;
const EAGAIN: i64 = -11;

/// Kernel `struct termios` (36 bytes).
#[derive(Clone, Copy)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
}

impl Termios {
    const fn default() -> Self {
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

    fn to_bytes(&self) -> [u8; 36] {
        let mut b = [0u8; 36];
        b[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        b[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        b[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        b[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        b[16] = self.line;
        b[17..36].copy_from_slice(&self.cc);
        b
    }

    fn from_bytes(b: &[u8]) -> Self {
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let mut cc = [0u8; 19];
        cc.copy_from_slice(&b[17..36]);
        Self { iflag: u(0), oflag: u(4), cflag: u(8), lflag: u(12), line: b[16], cc }
    }
}

struct Tty {
    termios: Termios,
    /// Line being edited in canonical mode.
    line: Vec<u8>,
    /// Input ready for `read`; `None` marks an end-of-file (Ctrl+D) boundary.
    ready: VecDeque<Option<u8>>,
    /// Session holding the terminal (0 = the Hydra shell owns the console).
    session: u64,
    /// Foreground process group (receives Ctrl+C).
    fg_pgrp: u64,
    winsize: Option<(u16, u16)>,
}

static TTY: Mutex<Tty> = Mutex::new(Tty {
    termios: Termios::default(),
    line: Vec::new(),
    ready: VecDeque::new(),
    session: 0,
    fg_pgrp: 0,
    winsize: None,
});

/// Gives the console to the Linux session led by `sid` with foreground group `pgrp`,
/// resetting the terminal to its default (cooked) mode.
pub fn attach_session(sid: u64, pgrp: u64) {
    let mut t = TTY.lock();
    t.session = sid;
    t.fg_pgrp = pgrp;
    t.termios = Termios::default();
    t.line.clear();
    t.ready.clear();
}

/// Returns the console to the Hydra shell.
pub fn detach_session() {
    let mut t = TTY.lock();
    t.session = 0;
    t.fg_pgrp = 0;
    t.line.clear();
    t.ready.clear();
}

/// True while a Linux session owns the console.
pub fn attached() -> bool {
    TTY.lock().session != 0
}

fn out(bytes: &[u8]) {
    if let Ok(s) = core::str::from_utf8(bytes) {
        crate::console::print_raw(s);
    } else {
        for &b in bytes {
            let c = [b];
            if let Ok(s) = core::str::from_utf8(&c) {
                crate::console::print_raw(s);
            }
        }
    }
}

/// Writes program output with output processing (`ONLCR`: newline -> CR LF).
pub fn write(data: &[u8]) -> usize {
    let oflag = TTY.lock().termios.oflag;
    if oflag & OPOST != 0 && oflag & ONLCR != 0 && data.contains(&b'\n') {
        let mut v = Vec::with_capacity(data.len() + 8);
        for &b in data {
            if b == b'\n' {
                v.push(b'\r');
            }
            v.push(b);
        }
        out(&v);
    } else {
        out(data);
    }
    data.len()
}

fn key_bytes(key: Key) -> Vec<u8> {
    match key {
        Key::Printable(c) => {
            let c = char::from(c);
            match c {
                '\u{8}' => alloc::vec![0x7f], // Backspace sends DEL, as on a Linux console
                _ => {
                    let mut buf = [0u8; 4];
                    c.encode_utf8(&mut buf).as_bytes().to_vec()
                }
            }
        }
        Key::Special(ScanCode(code)) => match code {
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
        },
    }
}

/// Feeds one input byte through the line discipline. Returns a signal to raise, if any.
fn input_byte(t: &mut Tty, mut b: u8, echo: &mut Vec<u8>) -> Option<u32> {
    let tm = t.termios;
    if tm.iflag & ICRNL != 0 && b == b'\r' {
        b = b'\n';
    }
    if tm.lflag & ISIG != 0 {
        let sig = if b == tm.cc[VINTR] {
            Some(super::proc::SIGINT)
        } else if b == tm.cc[VQUIT] {
            Some(super::proc::SIGQUIT)
        } else if b == tm.cc[VSUSP] {
            Some(super::proc::SIGTSTP)
        } else {
            None
        };
        if let Some(sig) = sig {
            t.line.clear();
            if tm.lflag & ECHO != 0 {
                echo.extend_from_slice(&[b'^', b + 0x40, b'\r', b'\n']);
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

/// Moves pending keystrokes into the terminal. Safe to call whenever no kernel lock is
/// held (read paths and returns to user mode).
pub fn pump() {
    let mut keys = Vec::new();
    {
        let t = match TTY.try_lock() {
            Some(t) => t,
            None => return,
        };
        if t.session == 0 {
            return;
        }
    }
    while let Some(k) = crate::console::read_key() {
        keys.push(k);
    }
    if keys.is_empty() {
        return;
    }
    let mut echo = Vec::new();
    let mut signals = Vec::new();
    let fg = {
        let mut t = TTY.lock();
        for k in keys {
            for b in key_bytes(k) {
                if let Some(sig) = input_byte(&mut t, b, &mut echo) {
                    signals.push(sig);
                }
            }
        }
        t.fg_pgrp
    };
    if !echo.is_empty() {
        out(&echo);
    }
    for sig in signals {
        super::proc::post_group(fg, sig);
    }
}

/// True if input is buffered for `read` (does not pull new keystrokes; see [`pump`]).
pub fn has_input() -> bool {
    TTY.try_lock().map_or(false, |t| !t.ready.is_empty())
}

/// Bytes available to `read` right now.
pub fn readable() -> bool {
    pump();
    !TTY.lock().ready.is_empty()
}

/// `read` from the terminal: blocks until a line (canonical mode) or at least one byte
/// (raw mode) is available.
pub fn read(buf: &mut [u8], nonblock: bool) -> i64 {
    if buf.is_empty() {
        return 0;
    }
    // A background process reading the terminal is stopped with SIGTTIN (EIO if it
    // ignores or blocks that signal), as on Linux
    let (_, pid) = super::proc::current_ids();
    if let Some((sid, pgid)) = super::proc::session_of(pid) {
        let (tty_sid, fg) = {
            let t = TTY.lock();
            (t.session, t.fg_pgrp)
        };
        if tty_sid == sid && fg != 0 && pgid != fg {
            if super::proc::ignores_or_blocks(super::proc::SIGTTIN) {
                return -5;
            }
            super::proc::post_group(pgid, super::proc::SIGTTIN);
            return super::proc::ERESTARTSYS;
        }
    }
    loop {
        pump();
        {
            let mut t = TTY.lock();
            let canon = t.termios.lflag & ICANON != 0;
            if !t.ready.is_empty() {
                let mut n = 0;
                while n < buf.len() {
                    match t.ready.front() {
                        Some(Some(b)) => {
                            buf[n] = *b;
                            n += 1;
                            t.ready.pop_front();
                            if canon && buf[n - 1] == b'\n' {
                                break;
                            }
                        }
                        Some(None) => {
                            // End-of-file marker: ends this read (0 bytes if nothing before it)
                            if n == 0 {
                                t.ready.pop_front();
                            }
                            break;
                        }
                        None => break,
                    }
                }
                if super::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed) {
                    crate::println!("[tty] read -> {:?} (canon={}, left={})", core::str::from_utf8(&buf[..n]).unwrap_or("?"), canon, t.ready.len());
                }
                return n as i64;
            }
            if !canon && t.termios.cc[VMIN] == 0 {
                return 0;
            }
        }
        if nonblock {
            return EAGAIN;
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        crate::task::sleep_ticks(1);
    }
}

fn copy_out(ptr: u64, data: &[u8]) -> bool {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    true
}

fn copy_in(ptr: u64, len: usize) -> Option<Vec<u8>> {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
        return None;
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Some(v)
}

/// Terminal `ioctl`s.
pub fn ioctl(request: u64, arg: u64) -> i64 {
    const TCGETS: u64 = 0x5401;
    const TCSETS: u64 = 0x5402;
    const TCSETSW: u64 = 0x5403;
    const TCSETSF: u64 = 0x5404;
    const TCXONC: u64 = 0x540A;
    const TCFLSH: u64 = 0x540B;
    const TIOCSCTTY: u64 = 0x540E;
    const TIOCGPGRP: u64 = 0x540F;
    const TIOCSPGRP: u64 = 0x5410;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const FIONREAD: u64 = 0x541B;
    const TIOCNOTTY: u64 = 0x5422;
    const TIOCGSID: u64 = 0x5429;

    // termios2 variants carry the same 36 bytes plus input/output speeds (used by glibc)
    const TCGETS2: u64 = 0x802c_542a;
    const TCSETS2: u64 = 0x402c_542b;
    const TCSETSW2: u64 = 0x402c_542c;
    const TCSETSF2: u64 = 0x402c_542d;
    let request = match request {
        TCSETS2 => TCSETS,
        TCSETSW2 => TCSETSW,
        TCSETSF2 => TCSETSF,
        r => r,
    };

    match request {
        TCGETS | TCGETS2 => {
            let b = TTY.lock().termios.to_bytes();
            let mut full = [0u8; 44];
            full[..36].copy_from_slice(&b);
            full[36..40].copy_from_slice(&38400u32.to_le_bytes());
            full[40..44].copy_from_slice(&38400u32.to_le_bytes());
            let len = if request == TCGETS2 { 44 } else { 36 };
            if copy_out(arg, &full[..len]) {
                0
            } else {
                EFAULT
            }
        }
        TCSETS | TCSETSW | TCSETSF => match copy_in(arg, 36) {
            Some(b) => {
                let mut t = TTY.lock();
                t.termios = Termios::from_bytes(&b);
                if super::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed) {
                    crate::println!("[tty] set lflag={:#o} req={:#x} line={} ready={}", t.termios.lflag, request, t.line.len(), t.ready.len());
                }
                if request == TCSETSF {
                    t.ready.clear();
                    t.line.clear();
                }
                // Leaving canonical mode makes the half-typed line readable
                if t.termios.lflag & ICANON == 0 && !t.line.is_empty() {
                    let line = core::mem::take(&mut t.line);
                    t.ready.extend(line.into_iter().map(Some));
                }
                0
            }
            None => EFAULT,
        },
        TCXONC => 0,
        TCFLSH => {
            let mut t = TTY.lock();
            if arg == 0 || arg == 2 {
                t.ready.clear();
                t.line.clear();
            }
            0
        }
        TIOCGWINSZ => {
            let (cols, rows) = match TTY.lock().winsize {
                Some((r, c)) => (c as usize, r as usize),
                None => crate::video::console::dimensions(),
            };
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&(rows as u16).to_le_bytes());
            b[2..4].copy_from_slice(&(cols as u16).to_le_bytes());
            if copy_out(arg, &b) {
                0
            } else {
                EFAULT
            }
        }
        TIOCSWINSZ => match copy_in(arg, 8) {
            Some(b) => {
                TTY.lock().winsize = Some((u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]])));
                0
            }
            None => EFAULT,
        },
        TIOCGPGRP => {
            let pg = TTY.lock().fg_pgrp as i32;
            if copy_out(arg, &pg.to_le_bytes()) {
                0
            } else {
                EFAULT
            }
        }
        TIOCSPGRP => match copy_in(arg, 4) {
            Some(b) => {
                TTY.lock().fg_pgrp = i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                0
            }
            None => EFAULT,
        },
        TIOCGSID => {
            let sid = TTY.lock().session as i32;
            if copy_out(arg, &sid.to_le_bytes()) {
                0
            } else {
                EFAULT
            }
        }
        TIOCSCTTY | TIOCNOTTY => 0,
        FIONREAD => {
            pump();
            let n = TTY.lock().ready.iter().take_while(|b| b.is_some()).count() as i32;
            if copy_out(arg, &n.to_le_bytes()) {
                0
            } else {
                EFAULT
            }
        }
        _ => EINVAL,
    }
}

/// `ENOTTY` for terminal requests on other descriptors.
pub const NOT_A_TTY: i64 = ENOTTY;
