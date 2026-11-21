//! # `execve`'s front half (wave 7, Group 7-5; `docs/vfs-design.md` 12.2, B.4.4)
//!
//! The kernel builds the new image (its ELF loader, the commit in the caller's trap: the
//! back half), but it asks here first which files to run (`LX_KCALL_EXEC`): the program, the
//! interpreters of `#!` scripts (up to [`LX_EXEC_DEPTH`] levels, `ELOOP` past them) and the
//! ELF interpreter (`PT_INTERP`). Each file is walked, permission-checked and read by
//! vfs-server in the program's own context (direct calls `LX_VFS_OP_EXEC`/`LX_VFS_OP_READ`,
//! carrying the program's `LxCall`). The answer is an `LxExecPlan`
//! ([`crate::execplan::encode_plan`]) in the kernel's output buffer, or
//! [`LX_EXEC_KERNEL`]: the kernel resolves the files itself (paths into `/proc`, `/sys`,
//! `/dev`, mounts, vfs-server down or restarting, paths too long for a direct call).
//!
//! Set-user-ID, file capabilities, `nosuid`, `no_new_privs` and tracing stay the kernel's:
//! they are process state it still owns (step 7 moves them).

use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::svccall::dcall;

use crate::client::Cx;
use crate::execplan::{self, Interp};

const ELOOP: i64 = -40;
/// `AT_SYMLINK_NOFOLLOW`.
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
/// Bytes of a file's head asked for (the `#!` line, the ELF and program headers).
const HEAD: usize = 1024;
/// A direct call's room for input and output together.
const DCALL_ROOM: usize = 3072;

/// Front halves answered with a plan, handed to the kernel, and failed, since start.
pub static PLANS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// See [`PLANS`].
pub static TO_KERNEL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Why the front half stops: the kernel does it, or `execve` fails.
enum Stop {
    Kernel,
    Fail(i64),
}

/// A dcall answer that means "the kernel does it" (vfs-server's own, or vfs-server not
/// running, restarting, not allowed, or a call that did not fit).
fn kernel_answer(r: i64) -> bool {
    const EPERM: i64 = -1;
    const EIO: i64 = -5;
    const E2BIG: i64 = -7;
    const EINTR: i64 = -4;
    const ENOSYS: i64 = -38;
    matches!(r, LX_VFS_KERNEL | EPERM | EIO | E2BIG | EINTR | ENOSYS)
}

/// The bytes of a plain repr(C) struct.
fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: a plain repr(C) struct of integers
    unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) }
}

/// What vfs-server found for one file.
struct Found {
    ino: u64,
    head: Vec<u8>,
    real: Vec<u8>,
}

/// Walks `path` for the program (`c`) with vfs-server.
fn walk(c: &LxCall, flags: u32, path: &[u8], abs: &[u8]) -> Result<Found, Stop> {
    let mut input = Vec::with_capacity(core::mem::size_of::<LxCall>() + 16 + path.len() + abs.len());
    input.extend_from_slice(bytes_of(c));
    let e = LxVfsExecIn { flags, path_len: path.len() as u32, abs_len: abs.len() as u32, head_max: HEAD as u32 };
    input.extend_from_slice(bytes_of(&e));
    input.extend_from_slice(path);
    input.extend_from_slice(abs);
    let os = core::mem::size_of::<LxVfsExecOut>();
    if input.len() + os + 64 > DCALL_ROOM {
        return Err(Stop::Kernel);
    }
    let mut out = alloc::vec![0u8; DCALL_ROOM - input.len()];
    let r = dcall(LXS_VFS, LX_VFS_OP_EXEC, &input, &mut out);
    if kernel_answer(r) {
        return Err(Stop::Kernel);
    }
    if r < 0 {
        return Err(Stop::Fail(r));
    }
    // SAFETY: the output starts with an LxVfsExecOut (plain data)
    let o: LxVfsExecOut = unsafe { core::ptr::read_unaligned(out.as_ptr() as *const LxVfsExecOut) };
    let (h, rl) = (o.head_len as usize, o.real_len as usize);
    if os + h + rl > out.len() {
        return Err(Stop::Kernel);
    }
    Ok(Found { ino: o.ino, head: out[os..os + h].to_vec(), real: out[os + h..os + h + rl].to_vec() })
}

/// `len` bytes of pool object `ino` at `off`.
fn read(ino: u64, off: u64, len: u64) -> Option<Vec<u8>> {
    let mut input = [0u8; 24];
    input[..8].copy_from_slice(&ino.to_le_bytes());
    input[8..16].copy_from_slice(&off.to_le_bytes());
    input[16..].copy_from_slice(&len.to_le_bytes());
    let mut out = alloc::vec![0u8; len as usize];
    let r = dcall(LXS_VFS, LX_VFS_OP_READ, &input, &mut out);
    if r < 0 || r as u64 != len {
        return None;
    }
    Some(out)
}

/// `LX_KCALL_EXEC(dirfd, out, path, flags, in, in_len)`: the input holds the base path of
/// `dirfd`, the working directory's path and the path to run, each NUL-terminated.
pub fn front(cx: &Cx) -> (i64, u64) {
    let r = match plan(cx) {
        Ok(()) => {
            PLANS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            0
        }
        Err(Stop::Kernel) => {
            TO_KERNEL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            LX_EXEC_KERNEL
        }
        Err(Stop::Fail(e)) => e,
    };
    (r, 0)
}

fn plan(cx: &Cx) -> Result<(), Stop> {
    let a = cx.args;
    // The kernel's copy of the path (not the caller's memory: read once)
    let bases = cx.copy_in(a[4], a[5] as usize).map_err(|_| Stop::Kernel)?;
    let mut parts = bases.split(|&b| b == 0);
    let base = parts.next().unwrap_or(b"/").to_vec();
    let cwd = parts.next().unwrap_or(b"/").to_vec();
    let path = parts.next().unwrap_or(b"").to_vec();
    if path.is_empty() {
        return Err(Stop::Kernel);
    }
    let mut c = cx.c;
    let mut nofollow = a[3] & AT_SYMLINK_NOFOLLOW != 0;
    let mut cur = path;
    let mut cur_base = base;
    let mut pre: Vec<Vec<u8>> = Vec::new();
    let mut depth = 0;
    let (found, abs) = loop {
        let abs = execplan::join_path(&cur_base, &cur);
        let flags = LX_VFS_EXEC_REAL | if nofollow { LX_VFS_EXEC_NOFOLLOW } else { 0 };
        let f = walk(&c, flags, &cur, &abs)?;
        let Some((interp, arg)) = execplan::parse_shebang(&f.head) else { break (f, abs) };
        depth += 1;
        if depth > LX_EXEC_DEPTH {
            return Err(Stop::Fail(ELOOP));
        }
        pre = execplan::script_prefix(&pre, &interp, arg.as_deref(), &cur);
        // Interpreters are looked up as with AT_FDCWD
        cur = interp;
        cur_base = cwd.clone();
        c.at_kind = LX_AT_CWD;
        nofollow = false;
    };
    // The ELF interpreter (from the root, no exec permission asked: the kernel's rule)
    let interp_path = match execplan::elf_interp(&found.head) {
        Interp::None => Vec::new(),
        Interp::Path(p) => p,
        Interp::At(off, len) => execplan::trim_nul(&read(found.ino, off, len).ok_or(Stop::Kernel)?).to_vec(),
    };
    let mut interp_ino = 0;
    if !interp_path.is_empty() {
        match walk(&c, LX_VFS_EXEC_FROM_ROOT | LX_VFS_EXEC_NOCHECK, &interp_path, &[]) {
            Ok(f) => interp_ino = f.ino,
            // (not found: the kernel fails the exec with ENOENT, as its loader does)
            Err(Stop::Fail(_)) => {}
            Err(Stop::Kernel) => return Err(Stop::Kernel),
        }
    }
    let lexical = found.real.is_empty();
    let shown = if lexical { abs } else { found.real };
    // (the kernel's copy area: the input, then the room for the plan)
    let room = (LX_DATA_SIZE).saturating_sub(a[5] as usize);
    let Some(bytes) = execplan::encode_plan(found.ino, interp_ino, &shown, lexical, &pre, &interp_path, room) else { return Err(Stop::Kernel) };
    cx.copy_out(a[1], &bytes).map_err(|_| Stop::Kernel)?;
    Ok(())
}
