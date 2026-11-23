//! # The terminal service's kernel side (wave 8, Group T)
//!
//! Since wave 8 the terminals live in a ring-3 service of their own, `tty-server`
//! (`userland/drivers/tty-server`, service `LXS_TTY`, endpoint `0x2C`;
//! `docs/display-input-design.md` sections 3.2 and 5): the line discipline, termios, the
//! pseudo-terminals (`/dev/ptmx`, `/dev/pts/N`), window sizes, controlling terminals, job
//! control signals and hang-ups. What stays in the kernel is in this file:
//!
//! - **The console terminal's kernel half.** The Linux programs hydra-shell runs in the
//!   foreground (`linux chroot ...`, every suite test) keep the kernel's console descriptors
//!   (`ConsoleIn/Out/Err`); `compat/linux/tty.rs` hands their `read`, `write` and `ioctl` to
//!   [`read`], [`write`] and [`ioctl`], which forward them to tty-server ([`LX_KCALL_TTY`],
//!   the caller's process group and session in the call header). tty-server prints with the
//!   console-write primitive and takes keys with the console-keys primitive, a wait that
//!   returns the keys typed while a Linux program owns the console and every attach and
//!   detach ([`attach`]/[`detach`], from `admin/linux.rs` through `tty.rs`). It tells the
//!   kernel whether a `read` would return ([`readable`], for `poll`).
//! - **Opening a pseudo-terminal** ([`open_pty`]): `vfs.rs::open_pty_path` asks tty-server
//!   to install the object, as `lx::dev_open` does for a claimed major. `stat`, `chmod` and
//!   `chown` of `/dev/pts/N` and `vhangup` go to tty-server too ([`pty_stat`],
//!   [`pty_setattr`], [`hangup`]).
//! - **Process identity** stays in the kernel (decision 11): tty-server asks for a process's
//!   session, whether a group is in a session, and posts signals to groups ([`LX_OBJ_TTY`]).
//!
//! When tty-server is not online (a crash, or before it started), console writes are
//! printed straight away (with `ONLCR`), console reads fail with `EIO`, and the console's
//! `ioctl`s are answered by the kernel's copy. `lx=kernel` or `lx.tty=kernel` sends
//! everything back to `tty.rs` and `pty.rs` ([`forwarded`]).
//!
//! The encodings (keys, the `stat` answer) are plain functions, host-tested in
//! `tests/host-w8-t`; the kernel glue is `cfg(target_os = "uefi")`.
//!
//! [`LX_KCALL_TTY`]: crate::ipc::protocol::LX_KCALL_TTY
//! [`LX_OBJ_TTY`]: crate::ipc::protocol::LX_OBJ_TTY

/// `LX_CONS_KEY_SPECIAL` of `ipc/protocol.rs` (a key that is not a character; the host
/// tests check the two agree).
pub const KEY_SPECIAL: u32 = 0x8000_0000;

/// Device numbers: `/dev/tty` 5:0, `/dev/ptmx` 5:2, slaves from major 136.
pub const TTY_RDEV: u64 = 5 << 8;
/// `/dev/ptmx`.
pub const PTMX_RDEV: u64 = 5 << 8 | 2;
/// The first slave major.
pub const PTS_MAJOR: u64 = 136;

/// Linux `makedev`.
pub fn makedev(major: u64, minor: u64) -> u64 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
}

/// The device number of `/dev/pts/index`.
pub fn pts_rdev(index: u64) -> u64 {
    makedev(PTS_MAJOR + (index >> 8), index & 0xFF)
}

/// Most slaves: Linux's eight majors 136..143 of 256 minors each.
pub const PTS_MAX: u64 = 2048;

/// The slave number a `/dev/pts/` name gives: decimal, no sign, no leading zero, below
/// [`PTS_MAX`].
pub fn pts_index(n: &str) -> Option<u64> {
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0')) || n.len() > 6 {
        return None;
    }
    n.parse::<u64>().ok().filter(|&i| i < PTS_MAX)
}

/// The device number a terminal path opens (`/dev/ptmx`, `/dev/pts/N`, `/dev/tty`).
pub fn path_rdev(abs: &str) -> Option<u64> {
    match abs {
        "/dev/ptmx" => Some(PTMX_RDEV),
        "/dev/tty" => Some(TTY_RDEV),
        _ => abs.strip_prefix("/dev/pts/").and_then(pts_index).map(pts_rdev),
    }
}

/// A console key as tty-server gets it: a character, or [`KEY_SPECIAL`] with the UEFI scan
/// code.
pub fn encode_key(printable: Option<char>, scan: u16) -> u32 {
    match printable {
        Some(c) => c as u32 & !KEY_SPECIAL,
        None => KEY_SPECIAL | scan as u32,
    }
}

/// [`crate::ipc::protocol::LX_TTY_K_STAT`]'s answer from a slave's mode, owner and group.
pub fn pack_stat(mode: u32, uid: u32, gid: u32) -> i64 {
    ((mode & 0o7777) as u64 | ((gid as u64) & 0xF_FFFF) << 12 | ((uid as u64) & 0x7FFF_FFFF) << 32) as i64
}

/// The `(mode, uid, gid)` of a [`pack_stat`] answer.
pub fn unpack_stat(v: i64) -> (u32, u32, u32) {
    let v = v as u64;
    ((v & 0o7777) as u32, (v >> 32) as u32 & 0x7FFF_FFFF, ((v >> 12) & 0xF_FFFF) as u32)
}

/// `(fg, leader)` of a [`crate::ipc::protocol::LX_TTY_K_HANGUP`] answer.
pub fn unpack_hangup(v: i64) -> (u64, u64) {
    let v = v as u64;
    (v & 0xFFFF_FFFF, v >> 32)
}

/// The signals tty-server may post to a process group: the terminal's own (`SIGHUP`,
/// `SIGINT`, `SIGQUIT`, `SIGCONT`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`, `SIGWINCH`). The kernel
/// refuses any other, so a confused or compromised tty-server cannot `SIGKILL` anyone.
pub fn tty_group_signal(sig: u64) -> bool {
    matches!(sig, 1 | 2 | 3 | 18 | 20 | 21 | 22 | 28)
}

/// The signals tty-server may post to a session leader (a hang-up: `SIGHUP`, `SIGCONT`).
pub fn tty_leader_signal(sig: u64) -> bool {
    matches!(sig, 1 | 18)
}

/// While tty-server is down: the signal a console key still sends to the program that owns
/// the console (Ctrl+C, Ctrl+\, Ctrl+Z), so a stuck program can be stopped.
pub fn fallback_signal(printable: Option<char>) -> Option<u32> {
    match printable {
        Some('\u{3}') => Some(2),
        Some('\u{1c}') => Some(3),
        Some('\u{1a}') => Some(20),
        _ => None,
    }
}

#[cfg(target_os = "uefi")]
pub use kernel::*;

/// The host builds (`tests/host-t30` compiles `lx/mod.rs` with this file): never forwarded.
#[cfg(not(target_os = "uefi"))]
pub fn forwarded() -> bool {
    false
}

/// The host builds: the in-kernel copy's pump (see the kernel's `trap_pump`).
#[cfg(not(target_os = "uefi"))]
pub fn trap_pump() {}

/// See the kernel's [`ctl`](kernel::ctl): the host builds have no tty-server (`-EPERM`).
#[cfg(not(target_os = "uefi"))]
pub fn ctl<H>(_h: H, _a: u64, _b: u64, _c: u64) -> i64 {
    -1
}

#[cfg(target_os = "uefi")]
mod kernel {
    use spin::Mutex;

    #[allow(unused_imports)]
    use crate::compat::linux::chardev::CharDevice;
    use crate::fs::FileDescriptor;
    use crate::ipc::protocol::*;
    use crate::lx::svc;

    const EPERM: i64 = -1;
    const EIO: i64 = -5;
    const EFAULT: i64 = -14;
    const EINVAL: i64 = -22;
    const ENOSYS: i64 = -38;

    /// Who holds the console, and tty-server's word for `poll`.
    struct Cons {
        /// Attach generation (grows at every attach and detach).
        gen: u64,
        /// The session holding the console (0: hydra-shell).
        sid: u64,
        /// Its group as the console was given.
        pgrp: u64,
        /// Whether a console `read` would return now, as tty-server told it for `gen`.
        ready: bool,
    }
    static STATE: Mutex<Cons> = Mutex::new(Cons { gen: 0, sid: 0, pgrp: 0, ready: false });

    /// Runs `f` on the console state (interrupts off: the keyboard's queue is taken inside).
    fn with_state<R>(f: impl FnOnce(&mut Cons) -> R) -> R {
        x86_64::instructions::interrupts::without_interrupts(|| f(&mut STATE.lock()))
    }

    /// Whether the terminals are tty-server's (not `lx=kernel`, `lx.tty=kernel` or
    /// `lx.tty=linux`).
    #[inline]
    pub fn forwarded() -> bool {
        !super::super::all_kernel() && svc::mode(LXS_TTY) == svc::SvcMode::Forward && svc::endpoint_of(LXS_TTY) == ENDPOINT_TTY_SERVER
    }

    /// Whether a Linux session holds the console (for the trap path: one load).
    static ATTACHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    /// On every return to user mode (`arch/idt.rs`): the in-kernel copy's pump when the
    /// terminals are not forwarded; when they are and tty-server is down while a Linux program
    /// owns the console, Ctrl+C, Ctrl+\ and Ctrl+Z still signal that program (other keys are
    /// dropped: its reads fail meanwhile), so the console is never wedged by the service.
    #[inline]
    pub fn trap_pump() {
        if !forwarded() {
            crate::compat::linux::tty::pump();
            return;
        }
        if !ATTACHED.load(core::sync::atomic::Ordering::Acquire) || online() {
            return;
        }
        let Some((sid, pgrp)) = STATE.try_lock().map(|s| (s.sid, s.pgrp)) else { return };
        if sid == 0 {
            return;
        }
        while let Some(k) = crate::console::read_key() {
            let printable = match k {
                uefi::proto::console::text::Key::Printable(c) => Some(char::from(c)),
                _ => None,
            };
            if let Some(sig) = super::fallback_signal(printable) {
                crate::compat::linux::tty::out_raw(b"^C\r\n");
                crate::compat::linux::proc::post_group(pgrp, sig);
            }
        }
    }

    /// Whether tty-server serves now.
    pub fn online() -> bool {
        svc::online(LXS_TTY)
    }

    /// Gives the console to Linux session `sid` (foreground group `pgrp`): tty-server resets
    /// the terminal and takes the keys from now on.
    pub fn attach(sid: u64, pgrp: u64) {
        with_state(|s| {
            s.gen += 1;
            s.sid = sid;
            s.pgrp = pgrp;
            s.ready = false;
        });
        ATTACHED.store(sid != 0, core::sync::atomic::Ordering::Release);
        crate::compat::linux::tty::INPUT_WQ.wake_all();
    }

    /// Gives the console back to hydra-shell.
    pub fn detach() {
        attach(0, 0);
    }

    /// Whether a Linux session holds the console.
    pub fn attached() -> bool {
        with_state(|s| s.sid != 0)
    }

    /// Whether a console `read` would return now.
    pub fn readable() -> bool {
        // (a dead tty-server's last word does not count: its reads fail at once anyway)
        with_state(|s| s.ready) && online()
    }

    /// The caller's thread group, process group and session.
    fn ids() -> (u64, u64, u64) {
        // wave9 G7a: through the process-identity primitive
        let (_, pid) = crate::compat::linux::proc::current_ids();
        crate::lx::proc::task_pgrp(pid).map_or((pid, 0, 0), |p| (pid, p.pgid, p.sid))
    }

    /// A console call's arguments 4 and 5: the attach generation, and the session and group
    /// it gave the console (`sid | pgrp << 32`).
    fn attach_args() -> (u64, u64) {
        with_state(|s| (s.gen, (s.sid & 0xFFFF_FFFF) | s.pgrp << 32))
    }

    /// `LX_KCALL_TTY(args)` to tty-server for the current thread (`dev`: the device an open
    /// names), with its process group and session in the header. The caller holds the
    /// kernel lock.
    fn kcall(args: [u64; 6], dev: u64) -> i64 {
        let Some(x) = svc::host(svc::host_of(LXS_TTY)) else { return ENOSYS };
        let (tgid, pgid, sid) = ids();
        let mut c = LxCall::EMPTY;
        c.nr = LX_KCALL_TTY;
        c.args = args;
        c.dev = dev;
        c.svc = LXS_TTY as u32;
        c.tgid = tgid;
        c.pgid = pgid as u32;
        c.sid = sid as u32;
        super::super::call_ident(x, c, true)
    }

    /// `read` of the console terminal into the caller's `buf` (`len` bytes).
    pub fn read(buf: u64, len: usize, nonblock: bool) -> i64 {
        if len == 0 {
            return 0;
        }
        if !online() {
            return EIO;
        }
        let (g, sp) = attach_args();
        let r = kcall([LX_TTY_K_READ, buf, len as u64, nonblock as u64, g, sp], 0);
        if r == ENOSYS {
            return EIO; // (tty-server went away meanwhile)
        }
        if r == LX_TTY_BGREAD {
            // A background process reading the terminal is stopped with SIGTTIN (EIO if it
            // ignores or blocks that signal), as on Linux
            use crate::compat::linux::proc;
            if proc::ignores_or_blocks(proc::SIGTTIN) {
                return EIO;
            }
            let (_, pgid, _) = ids();
            proc::post_group(pgid, proc::SIGTTIN);
            return proc::ERESTARTSYS;
        }
        r
    }

    /// `write` of the caller's `buf` (`len` bytes) to the console terminal.
    pub fn write(buf: u64, len: usize) -> i64 {
        if len == 0 {
            return 0;
        }
        let print = || match crate::compat::linux::vfs::copy_in(buf, len) {
            Ok(d) => crate::compat::linux::tty::write_kernel(&d) as i64,
            Err(e) => e,
        };
        if !online() {
            // tty-server is gone (or not started yet): the console itself still prints
            return print();
        }
        let (g, sp) = attach_args();
        match kcall([LX_TTY_K_WRITE, buf, len as u64, 0, g, sp], 0) {
            // (tty-server went away meanwhile: the console prints it)
            r @ (ENOSYS | EIO) if !online() => {
                let _ = r;
                print()
            }
            r => r,
        }
    }

    /// A terminal `ioctl` on the console (the VT requests stay the kernel's: one text
    /// console, see `tty::vt_ioctl`).
    pub fn ioctl(request: u64, arg: u64) -> i64 {
        if let Some(r) = crate::compat::linux::tty::vt_ioctl(request, arg) {
            return r;
        }
        if !online() {
            return crate::compat::linux::tty::ioctl_kernel(request, arg);
        }
        let (g, sp) = attach_args();
        match kcall([LX_TTY_K_IOCTL, request, arg, 0, g, sp], 0) {
            ENOSYS if !online() => crate::compat::linux::tty::ioctl_kernel(request, arg),
            r => r,
        }
    }

    /// Opens a terminal path (`/dev/ptmx`, `/dev/pts/N`, `/dev/tty`) as tty-server's object.
    /// `None`: not one of them, or `/dev/tty` of a process whose terminal is the console.
    pub fn open_pty(abs: &str, flags: u32) -> Option<Result<FileDescriptor, i64>> {
        let rdev = super::path_rdev(abs)?;
        if svc::host(svc::host_of(LXS_TTY)).is_none() {
            // (tty-server never started: `/dev/tty` is the console's, the rest fail)
            return if rdev == super::TTY_RDEV { None } else { Some(Err(EIO)) };
        }
        let fd = kcall([LX_TTY_K_OPEN, rdev, flags as u64, 0, 0, 0], rdev);
        if fd == LX_TTY_NOTMINE {
            return None;
        }
        if fd < 0 {
            return Some(Err(fd));
        }
        // The descriptor tty-server installed: its object becomes the opened file (the
        // caller installs it again with the open's own flags)
        let taken = crate::task::with_current_fds_mut(|t| t.set_fd(fd as usize, None));
        Some(match taken {
            Some(FileDescriptor::Device(d))
                if d.as_server().is_some_and(|o| o.svc() == svc::host_of(LXS_TTY) && matches!(o.kind(), LX_OBJ_KIND_PTY_M | LX_OBJ_KIND_PTY_S)) =>
            {
                Ok(FileDescriptor::Device(d))
            }
            Some(other) => {
                drop(other);
                Err(EIO)
            }
            None => Err(EIO),
        })
    }

    /// `(mode, uid, gid)` of `/dev/pts/index` (`-ENOENT` when it does not exist).
    pub fn pty_stat(index: u64) -> Result<(u32, u32, u32), i64> {
        let r = kcall([LX_TTY_K_STAT, index, 0, 0, 0, 0], 0);
        if r < 0 {
            Err(r)
        } else {
            Ok(super::unpack_stat(r))
        }
    }

    /// `chmod`/`chown` of `/dev/pts/index` by the caller.
    pub fn pty_setattr(index: u64, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>) -> i64 {
        let w = |v: Option<u32>| v.map_or(u64::MAX, |v| v as u64);
        kcall([LX_TTY_K_SETATTR, index, w(mode), w(uid), w(gid), 0], 0)
    }

    /// `vhangup` of session `sid`'s pseudo-terminal: `(leader, foreground group)` to signal.
    pub fn hangup(sid: u64) -> Option<(u64, u64)> {
        if !online() {
            return None;
        }
        let r = kcall([LX_TTY_K_HANGUP, sid, 0, 0, 0, 0], 0);
        if r < 0 {
            return None;
        }
        let (fg, leader) = super::unpack_hangup(r);
        Some((leader, fg))
    }

    /// The console key as tty-server gets it.
    fn key_code(k: uefi::proto::console::text::Key) -> u32 {
        use uefi::proto::console::text::{Key, ScanCode};
        match k {
            Key::Printable(c) => super::encode_key(Some(char::from(c)), 0),
            Key::Special(ScanCode(code)) => super::encode_key(None, code),
        }
    }

    /// [`LX_TTY_CONS_WAIT`]: keys and attach changes for tty-server (its console thread).
    fn cons_wait(buf: u64, cap: u64) -> i64 {
        let head = core::mem::size_of::<LxConsState>();
        if cap < head as u64 + 4 || cap > 64 * 1024 {
            return EINVAL;
        }
        let Ok(b) = crate::compat::linux::vfs::copy_in(buf, 8) else { return EFAULT };
        let seen = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
        let max = (cap as usize - head) / 4;
        let deadline = crate::arch::pit::ticks() + 100;
        let mut waits = crate::task::wait::WaitSet::new();
        waits.add(crate::task::wait::QueueRef::Static(&crate::compat::linux::tty::INPUT_WQ));
        loop {
            waits.register();
            if !forwarded() {
                return EPERM;
            }
            // (the keys are taken under the state's lock: a detach cannot slip in between and
            // leave hydra-shell's keys to the old session)
            let mut keys: alloc::vec::Vec<u32> = alloc::vec::Vec::new();
            let (gen, sid, pgrp) = with_state(|s| {
                if s.sid != 0 && s.gen == seen {
                    while keys.len() < max {
                        match crate::console::read_key() {
                            Some(k) => keys.push(key_code(k)),
                            None => break,
                        }
                    }
                }
                (s.gen, s.sid, s.pgrp)
            });
            let now = crate::arch::pit::ticks();
            if gen != seen || !keys.is_empty() || now >= deadline {
                let (cols, rows) = crate::video::console::dimensions();
                let st = LxConsState { gen, sid, pgrp, nkeys: keys.len() as u32, cols: cols.min(0xFFFF) as u16, rows: rows.min(0xFFFF) as u16 };
                // SAFETY: a plain `repr(C)` record of integers
                let raw = unsafe { core::slice::from_raw_parts(&st as *const LxConsState as *const u8, head) };
                let mut out = alloc::vec::Vec::with_capacity(head + 4 * keys.len());
                out.extend_from_slice(raw);
                for k in &keys {
                    out.extend_from_slice(&k.to_le_bytes());
                }
                if crate::compat::linux::vfs::copy_out(buf, &out).is_err() {
                    return EFAULT;
                }
                return keys.len() as i64;
            }
            waits.wait(Some(deadline));
        }
    }

    /// `SYS_LX_OBJ` op [`LX_OBJ_TTY`] from host `h`: tty-server's console and process
    /// identity primitives (sub-op `a`).
    pub fn ctl(h: SvcId, a: u64, b: u64, c: u64) -> i64 {
        if h != svc::host_of(LXS_TTY) || h == 0 || !forwarded() {
            return EPERM;
        }
        // wave9 G7a: sessions, groups and their signals through the process-identity
        // primitives (`lx::proc`)
        use crate::lx::proc as mech;
        match a {
            LX_TTY_CONS_WRITE => {
                if c > 1 << 20 {
                    return EINVAL;
                }
                match crate::compat::linux::vfs::copy_in(b, c as usize) {
                    Ok(d) => {
                        crate::compat::linux::tty::out_raw(&d);
                        c as i64
                    }
                    Err(e) => e,
                }
            }
            LX_TTY_CONS_WAIT => cons_wait(b, c),
            LX_TTY_CONS_READY => {
                // (an answer for an older attach generation does not count)
                let changed = with_state(|s| {
                    let changed = s.gen == b && s.ready != (c != 0);
                    if s.gen == b {
                        s.ready = c != 0;
                    }
                    changed
                });
                if changed {
                    crate::compat::linux::tty::INPUT_WQ.wake_all();
                }
                0
            }
            LX_TTY_SESS => match mech::task_pgrp(b) {
                Some(p) => (p.sid | p.pgid << 32) as i64,
                None => -3,
            },
            LX_TTY_PGRP_IN => match mech::pgrp_in_session(b, c) {
                Some(true) => 0,
                Some(false) => 1,
                None => -3,
            },
            LX_TTY_SIGGRP => {
                // `b` = group | session << 32: only the group's members in that session (the
                // terminal's), only terminal signals; tty-server cannot reach anyone else
                let (pgid, sid) = (b & 0xFFFF_FFFF, b >> 32);
                if !super::tty_group_signal(c) || pgid == 0 || sid == 0 {
                    return EINVAL;
                }
                match mech::pgrp_signal(pgid, Some(sid), c as u32) {
                    0 => -3,
                    n => n as i64,
                }
            }
            LX_TTY_SIGPROC => {
                // A session leader's hang-up only: `SIGHUP`/`SIGCONT` to a process that leads
                // its session (a reused pid that does not is refused)
                if !super::tty_leader_signal(c) || b == 0 {
                    return EINVAL;
                }
                if mech::task_pgrp(b).map(|p| p.sid) != Some(b) {
                    return -3;
                }
                crate::compat::linux::proc::post_process(b, c as u32);
                0
            }
            _ => EINVAL,
        }
    }

}
