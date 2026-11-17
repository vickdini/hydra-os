//! System calls and small helpers: the admin interface, native file calls, colours.

use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::*;

/// Native `open` (`rdi` path, `rsi` length, `rdx` flags: 0 read).
const SYS_OPEN: u64 = 9;
/// Native `close`.
const SYS_CLOSE: u64 = 10;
/// Native `read` (`rdi` fd, `rsi` buffer, `rdx` count).
const SYS_READ: u64 = 11;
/// Native `pipe` (`rdi` -> `[read fd, write fd]`).
const SYS_PIPE: u64 = 12;
/// Native `dup2`.
const SYS_DUP2: u64 = 13;

/// A native system call with three arguments.
pub fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") num as i64 => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

/// An admin call failure: the errno and the kernel's message, if any.
pub struct AdminError {
    pub errno: i64,
    pub message: String,
}

impl AdminError {
    /// The kernel's message, or a short name of the errno.
    pub fn text(&self) -> &str {
        if self.message.is_empty() {
            errno_name(self.errno)
        } else {
            &self.message
        }
    }
}

/// A short name of an admin errno.
pub fn errno_name(e: i64) -> &'static str {
    match e {
        EPERM => "not an authorized admin console",
        ENOENT => "not found",
        EIO => "input/output error",
        EACCES => "permission denied",
        EFAULT => "bad address",
        EINVAL => "invalid argument",
        ENOSYS => "operation not supported by this kernel",
        _ => "error",
    }
}

/// Calls admin operation `op`; answers its bytes.
pub fn admin(op: u32, args: [u64; 4], input: &[u8]) -> Result<Vec<u8>, AdminError> {
    let mut cap = 4096usize;
    loop {
        let mut out = alloc::vec![0u8; cap];
        let mut call = AdminCall {
            op,
            flags: 0,
            args,
            in_ptr: input.as_ptr() as u64,
            in_len: input.len() as u64,
            out_ptr: out.as_mut_ptr() as u64,
            out_cap: cap as u64,
            err_len: 0,
        };
        let r = syscall3(SYS_ADMIN, &mut call as *mut AdminCall as u64, 0, 0);
        if r < 0 {
            let n = (call.err_len as usize).min(cap);
            let message = String::from(core::str::from_utf8(&out[..n]).unwrap_or(""));
            return Err(AdminError { errno: -r, message });
        }
        let need = r as usize;
        if need <= cap {
            out.truncate(need);
            return Ok(out);
        }
        cap = need + 4096;
    }
}

/// Calls admin operation `op` and reads its answer as record `T`.
pub fn admin_rec<T: Copy + Default>(op: u32, args: [u64; 4], input: &[u8]) -> Result<T, AdminError> {
    admin(op, args, input).map(|a| read_record(&a, 0).unwrap_or_default())
}

/// Calls admin operation `op` and reads its answer as a `u64`.
pub fn admin_u64(op: u32, args: [u64; 4], input: &[u8]) -> Result<u64, AdminError> {
    admin_rec::<u64>(op, args, input)
}

/// The records of an answer after a header of `skip` bytes.
pub fn records<T: Copy + Default>(answer: &[u8], skip: usize, count: usize) -> Vec<T> {
    let size = core::mem::size_of::<T>();
    (0..count).map_while(|i| read_record::<T>(answer, skip + i * size)).collect()
}

/// `a`, a NUL, then `b` (two-part admin inputs).
pub fn two(a: &str, b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + 1 + b.len());
    v.extend_from_slice(a.as_bytes());
    v.push(0);
    v.extend_from_slice(b);
    v
}

/// Words joined by NULs (admin inputs with several arguments).
pub fn nul_join<S: AsRef<str>>(words: &[S]) -> Vec<u8> {
    let mut v = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            v.push(0);
        }
        v.extend_from_slice(w.as_ref().as_bytes());
    }
    v
}

// UEFI text colours (as `uefi::proto::console::text::Color`)
pub const BLACK: u64 = 0;
pub const LIGHT_GRAY: u64 = 7;
pub const DARK_GRAY: u64 = 8;
pub const LIGHT_BLUE: u64 = 9;
pub const LIGHT_GREEN: u64 = 10;
pub const LIGHT_CYAN: u64 = 11;
pub const LIGHT_RED: u64 = 12;
pub const LIGHT_MAGENTA: u64 = 13;
pub const YELLOW: u64 = 14;
pub const WHITE: u64 = 15;

/// Sets the console colours (as the kernel shell's `set_color(fg, Black)`). Nothing while
/// the output goes to a pipe or a file.
pub fn color(fg: u64) {
    if crate::redirected() {
        return;
    }
    let _ = admin(ADMIN_CONSOLE_COLOR, [fg, BLACK, 0, 0], &[]);
}

/// Console control (`CTL_*`): answers its two numbers.
pub fn ctl(code: u64, a1: u64, a2: u64, a3: u64, input: &[u8]) -> [u64; 2] {
    match admin(ADMIN_CONSOLE_CTL, [code, a1, a2, a3], input) {
        Ok(a) if a.len() >= 16 => [u64::from_le_bytes(a[0..8].try_into().unwrap()), u64::from_le_bytes(a[8..16].try_into().unwrap())],
        _ => [0, 0],
    }
}

/// Waits for a key (see `ADMIN_CONSOLE_READ`).
pub fn read_key(timeout_ms: u64, seen_generation: u64) -> KeyEvent {
    admin_rec(ADMIN_CONSOLE_READ, [timeout_ms, seen_generation, 0, 0], &[]).unwrap_or_default()
}

/// Whether Ctrl+C (or Ctrl+\) was pressed: checked by long-running commands. Other keys
/// pressed meanwhile are dropped, as in the kernel shell.
pub fn interrupted() -> bool {
    let k = read_key(0, u64::MAX);
    k.kind == KEY_CHAR && (k.code == 3 || k.code == 28)
}

/// Writes bytes to standard output.
pub fn write_out(data: &[u8]) {
    hydra_rt::sys::write(1, data);
}

/// Opens a pool file for reading.
pub fn open_read(path: &str) -> Result<u64, i64> {
    let r = syscall3(SYS_OPEN, path.as_ptr() as u64, path.len() as u64, 0);
    if r < 0 {
        Err(r)
    } else {
        Ok(r as u64)
    }
}

/// Reads from `fd` into `buf`.
pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    syscall3(SYS_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Closes `fd`.
pub fn close(fd: u64) {
    syscall3(SYS_CLOSE, fd, 0, 0);
}

/// Makes a pipe: `(read fd, write fd)`.
pub fn pipe() -> Option<(u64, u64)> {
    let mut fds = [0u64; 2];
    if syscall3(SYS_PIPE, fds.as_mut_ptr() as u64, 0, 0) < 0 {
        None
    } else {
        Some((fds[0], fds[1]))
    }
}

/// `dup2(old, new)`.
pub fn dup2(old: u64, new: u64) -> i64 {
    syscall3(SYS_DUP2, old, new, 0)
}

/// What the kernel knows of a pool path: `(kind, size)`.
pub fn lookup(path: &str) -> Result<LookupRecord, AdminError> {
    admin_rec(ADMIN_LOOKUP, [0; 4], path.as_bytes())
}

/// Reads a whole pool file (at most `limit` bytes).
///
/// # Errors
/// The kernel's message (as the kernel shell printed it).
pub fn read_file(path: &str, limit: usize) -> Result<Vec<u8>, String> {
    match lookup(path) {
        Err(e) => return Err(String::from(e.text())),
        Ok(r) if r.kind != KIND_FILE as u64 => return Err(String::from("Target path is not a regular file")),
        Ok(_) => {}
    }
    let fd = open_read(path).map_err(|_| String::from("ZFS I/O error"))?;
    let mut data = Vec::new();
    let mut chunk = alloc::vec![0u8; 65536];
    while data.len() < limit {
        let want = (limit - data.len()).min(chunk.len());
        let r = read(fd, &mut chunk[..want]);
        if r <= 0 {
            break;
        }
        data.extend_from_slice(&chunk[..r as usize]);
    }
    close(fd);
    Ok(data)
}

/// Parses a number: decimal, or hexadecimal with `0x` (the kernel shell's parser).
pub use crate::parse::parse_u64 as parse_num;
