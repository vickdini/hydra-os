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
//!
//! The line discipline itself ([`Tty`], [`feed_input`], [`take_input`], [`tty_ioctl`])
//! is shared with pseudo-terminals ([`super::pty`]).
//!
//! **Wave 8 (Group T):** the terminal service `tty-server` serves the console terminal and
//! the pseudo-terminals; this file stays as the switch back (`lx=kernel`, `lx.tty=kernel`).
//! While the terminals are forwarded ([`crate::lx::console::forwarded`]), the public entry
//! points below hand the console's `read`, `write`, `ioctl`, attach and readiness to
//! `crate::lx::console`, and [`pump`] does nothing (tty-server takes the keys).

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

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

    /// Serializes the `termios` structure into a 36-byte array matching Linux `struct termios`.
    ///
    /// # Returns
    ///
    /// 36-byte packed termios array.
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

    /// Deserializes a `termios` structure from a 36-byte slice matching Linux `struct termios`.
    ///
    /// # Arguments
    ///
    /// * `b` - Source 36-byte slice.
    ///
    /// # Returns
    ///
    /// Populated [`Termios`] instance.
    fn from_bytes(b: &[u8]) -> Self {
        let u = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let mut cc = [0u8; 19];
        cc.copy_from_slice(&b[17..36]);
        Self { iflag: u(0), oflag: u(4), cflag: u(8), lflag: u(12), line: b[16], cc }
    }
}

/// Terminal state: termios settings, line editing and the input queue for `read`.
pub(crate) struct Tty {
    termios: Termios,
    /// Line being edited in canonical mode.
    line: Vec<u8>,
    /// Input ready for `read`; `None` marks an end-of-file (Ctrl+D) boundary.
    ready: VecDeque<Option<u8>>,
    /// Session holding the terminal (0 = the Hydra shell owns the console).
    pub(crate) session: u64,
    /// Foreground process group (receives Ctrl+C).
    pub(crate) fg_pgrp: u64,
    pub(crate) winsize: Option<(u16, u16)>,
    /// `O_NONBLOCK` of the console's open file description (shared by every process
    /// that inherited it, as on Linux).
    nonblock: bool,
}

impl Tty {
    pub(crate) const fn new() -> Self {
        Self {
            termios: Termios::default(),
            line: Vec::new(),
            ready: VecDeque::new(),
            session: 0,
            fg_pgrp: 0,
            winsize: None,
            nonblock: false,
        }
    }

}

static TTY: Mutex<Tty> = Mutex::new(Tty::new());

/// Readers of the terminal (and `poll`/`select` on it), woken by keystrokes.
pub static INPUT_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();

/// `O_NONBLOCK` state of the console file description (`fcntl(F_GETFL/F_SETFL)`).
///
/// # Returns
///
/// `true` if non-blocking mode is set; `false` otherwise.
pub fn nonblock() -> bool {
    TTY.lock().nonblock
}

/// Sets the non-blocking state (`O_NONBLOCK`) of the console terminal.
///
/// # Arguments
///
/// * `on` - `true` to enable non-blocking operations; `false` to block.
pub fn set_nonblock(on: bool) {
    TTY.lock().nonblock = on;
}

/// Gives the console to the Linux session led by `sid` with foreground group `pgrp`,
/// resetting the terminal to its default (cooked) mode.
///
/// # Arguments
///
/// * `sid` - Session ID.
/// * `pgrp` - Foreground process group ID.
pub fn attach_session(sid: u64, pgrp: u64) {
    // wave8 GT: the console terminal is tty-server's
    TTY.lock().nonblock = false;
    crate::lx::console::attach(sid, pgrp);
}

/// Returns the console to the Hydra shell.
pub fn detach_session() {
    crate::lx::console::detach();
}

/// True while a Linux session owns the console.
///
/// # Returns
///
/// `true` if attached to a Linux session; `false` if owned by Hydra shell.
pub fn attached() -> bool {
    crate::lx::console::attached()
}

/// Prints raw bytes to the console output.
///
/// # Arguments
///
/// * `bytes` - Byte slice to print.
pub(crate) fn out_raw(bytes: &[u8]) {
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

/// Applies output processing (`ONLCR`: newline -> CR LF) to program output.
///
/// # Arguments
///
/// * `t` - Active Tty state.
/// * `data` - Raw output bytes.
/// * `out` - Destination processed byte buffer.
pub(crate) fn process_output(t: &Tty, data: &[u8], out: &mut Vec<u8>) {
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

/// Writes program output to the console.
///
/// # Arguments
///
/// * `data` - Raw bytes to write.
///
/// # Returns
///
/// Number of bytes processed and output, or a negative Linux errno (forwarded).
pub fn write(data: &[u8]) -> i64 {
    // wave8 GT: `data` is the caller's own buffer (`vfs::stream_io`), forwarded as such
    crate::lx::console::write(data.as_ptr() as u64, data.len())
}

/// [`write`] in the kernel: output processing with the kernel's termios, then the console
/// (also tty-server's stand-in while it is not online).
///
/// # Arguments
///
/// * `data` - Raw bytes to write.
///
/// # Returns
///
/// Number of bytes processed and output.
pub fn write_kernel(data: &[u8]) -> usize {
    let mut v = Vec::with_capacity(data.len() + 8);
    process_output(&TTY.lock(), data, &mut v);
    out_raw(&v);
    data.len()
}


/// True if input is buffered for `read` (does not pull new keystrokes; see [`pump`]).
///
/// # Returns
///
/// `true` if input is buffered; `false` otherwise.
pub fn has_input() -> bool {
    crate::lx::console::readable()
}

/// `read` from the terminal: blocks until a line (canonical mode) or at least one byte
/// (raw mode) is available.
///
/// # Arguments
///
/// * `buf` - Destination buffer to read into.
/// * `nonblock` - Non-blocking mode flag.
///
/// # Returns
///
/// Number of bytes read, `0` on EOF, or negative Linux errno on error.
pub fn read(buf: &mut [u8], nonblock: bool) -> i64 {
    if buf.is_empty() {
        return 0;
    }
    // wave8 GT: `buf` is the caller's own buffer (`vfs::stream_io`), forwarded as such
    crate::lx::console::read(buf.as_mut_ptr() as u64, buf.len(), nonblock)
}

/// Copies byte slice to user memory after prefaulting.
///
/// # Arguments
///
/// * `ptr` - User pointer to write into.
/// * `data` - Source bytes.
///
/// # Returns
///
/// `true` on success; `false` on fault.
fn copy_out(ptr: u64, data: &[u8]) -> bool {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, data.len() as u64, true) {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    true
}

/// Copies bytes from user memory into kernel vector after prefaulting.
///
/// # Arguments
///
/// * `ptr` - User pointer to read from.
/// * `len` - Byte count.
///
/// # Returns
///
/// `Some(Vec<u8>)` on success, or `None` on fault.
fn copy_in(ptr: u64, len: usize) -> Option<Vec<u8>> {
    if ptr == 0 || !crate::memory::vm::prefault_current(ptr, len as u64, false) {
        return None;
    }
    let mut v = alloc::vec![0u8; len];
    unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, v.as_mut_ptr(), len) };
    Some(v)
}

/// Active virtual terminal (`VT_ACTIVATE`), as display managers see it.
static ACTIVE_VT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);
/// Next virtual terminal `VT_OPENQRY` hands out.
static NEXT_VT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(2);

/// Virtual terminal `ioctl`s on the console. Hydra has one text console: VT numbers only
/// tell sessions apart (the login manager decides which one owns the display), so
/// allocating and switching VTs just records them. `None` for other requests.
///
/// # Arguments
///
/// * `request` - ioctl request code.
/// * `arg` - User pointer or argument value.
///
/// # Returns
///
/// `Some(result)` if handled, or `None` if unhandled.
pub(crate) fn vt_ioctl(request: u64, arg: u64) -> Option<i64> {
    use core::sync::atomic::Ordering::Relaxed;
    let put = |bytes: &[u8]| super::vfs::copy_out(arg, bytes).map_or_else(|e| e, |()| 0);
    Some(match request {
        0x5600 => put(&(NEXT_VT.fetch_add(1, Relaxed) as i32).to_le_bytes()), // VT_OPENQRY
        0x5601 => put(&[0u8; 8]),                                              // VT_GETMODE: VT_AUTO
        0x5602 | 0x5605 | 0x5607 | 0x5608 => 0, // VT_SETMODE, VT_RELDISP, VT_WAITACTIVE, VT_DISALLOCATE
        0x5603 => {
            // VT_GETSTATE: active VT, signal, bitmask of VTs in use
            let active = ACTIVE_VT.load(Relaxed) as u16;
            let used = ((1u32 << NEXT_VT.load(Relaxed).min(16)) - 1) as u16;
            let mut st = [0u8; 6];
            st[..2].copy_from_slice(&active.to_le_bytes());
            st[4..].copy_from_slice(&used.to_le_bytes());
            put(&st)
        }
        0x5606 => {
            // VT_ACTIVATE
            ACTIVE_VT.store(arg as u32, Relaxed);
            0
        }
        0x4B3A | 0x4B45 => 0,                    // KDSETMODE, KDSKBMODE
        0x4B3B => put(&0i32.to_le_bytes()),      // KDGETMODE: KD_TEXT
        0x4B44 => put(&3i32.to_le_bytes()),      // KDGKBMODE: K_UNICODE
        0x4B33 => put(&[2u8]),                   // KDGKBTYPE: KB_101
        _ => return None,
    })
}

/// Console terminal `ioctl`s.
///
/// # Arguments
///
/// * `request` - ioctl request code.
/// * `arg` - User pointer or argument value.
///
/// # Returns
///
/// Result code, or negative Linux errno on error.
pub fn ioctl(request: u64, arg: u64) -> i64 {
    crate::lx::console::ioctl(request, arg)
}

/// [`ioctl`] in the kernel (also tty-server's stand-in while it is not online).
///
/// # Arguments
///
/// * `request` - ioctl request code.
/// * `arg` - User pointer or argument value.
///
/// # Returns
///
/// Result code, or negative Linux errno on error.
pub fn ioctl_kernel(request: u64, arg: u64) -> i64 {
    if let Some(r) = vt_ioctl(request, arg) {
        return r;
    }

    let default_size = || {
        let (cols, rows) = crate::video::console::dimensions();
        (rows as u16, cols as u16)
    };
    tty_ioctl(&TTY, request, arg, &default_size).0
}

/// Terminal `ioctl`s on `tty`. `default_size` gives (rows, cols) until `TIOCSWINSZ`.
/// Returns the result and whether the window size changed (the caller sends `SIGWINCH`).
///
/// # Arguments
///
/// * `tty` - Target terminal mutex.
/// * `request` - ioctl command code.
/// * `arg` - User argument.
/// * `default_size` - Callback providing fallback window dimensions.
///
/// # Returns
///
/// `(result_code, was_resized)` tuple.
pub(crate) fn tty_ioctl(tty: &Mutex<Tty>, request: u64, arg: u64, default_size: &dyn Fn() -> (u16, u16)) -> (i64, bool) {
    let mut resized = false;
    let r = tty_ioctl_inner(tty, request, arg, default_size, &mut resized);
    (r, resized)
}

/// Internal handler implementing standard POSIX terminal ioctls on a terminal state.
///
/// # Arguments
///
/// * `tty` - Target terminal mutex.
/// * `request` - ioctl request code.
/// * `arg` - User parameter.
/// * `default_size` - Callback returning default dimensions.
/// * `resized` - Out parameter flag set to true if window was resized.
///
/// # Returns
///
/// ioctl return value or negative Linux errno.
fn tty_ioctl_inner(tty: &Mutex<Tty>, request: u64, arg: u64, default_size: &dyn Fn() -> (u16, u16), resized: &mut bool) -> i64 {
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
            let b = tty.lock().termios.to_bytes();
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
                let mut t = tty.lock();
                t.termios = Termios::from_bytes(&b);
                if super::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed) {
                    crate::kprintln!("[tty] set lflag={:#o} req={:#x} line={} ready={}", t.termios.lflag, request, t.line.len(), t.ready.len());
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
            let mut t = tty.lock();
            if arg == 0 || arg == 2 {
                t.ready.clear();
                t.line.clear();
            }
            0
        }
        TIOCGWINSZ => {
            let (rows, cols) = tty.lock().winsize.unwrap_or_else(default_size);
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
                let size = Some((u16::from_le_bytes([b[0], b[1]]), u16::from_le_bytes([b[2], b[3]])));
                let mut t = tty.lock();
                *resized = t.winsize != size;
                t.winsize = size;
                0
            }
            None => EFAULT,
        },
        TIOCGPGRP => {
            let pg = tty.lock().fg_pgrp as i32;
            if copy_out(arg, &pg.to_le_bytes()) {
                0
            } else {
                EFAULT
            }
        }
        TIOCSPGRP => match copy_in(arg, 4) {
            Some(b) => {
                tty.lock().fg_pgrp = i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
                0
            }
            None => EFAULT,
        },
        TIOCGSID => {
            let sid = tty.lock().session as i32;
            if copy_out(arg, &sid.to_le_bytes()) {
                0
            } else {
                EFAULT
            }
        }
        TIOCSCTTY | TIOCNOTTY => 0,
        FIONREAD => {
            let n = tty.lock().ready.iter().take_while(|b| b.is_some()).count() as i32;
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
