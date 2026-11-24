//! # tty-server: the terminals, a Linux service of their own (wave 8, Group T)
//!
//! The line discipline, the pseudo-terminals and the console terminal, moved out of the
//! kernel (`src/compat/linux/{tty,pty}.rs`; `docs/display-input-design.md` sections 3.2, 3.6
//! and 5). Service `LXS_TTY`, endpoint [`ENDPOINT_TTY_SERVER`].
//!
//! - **Pseudo-terminals** are this service's objects (kinds [`LX_OBJ_KIND_PTY_M`] and
//!   [`LX_OBJ_KIND_PTY_S`]): the kernel's `open` of `/dev/ptmx`, `/dev/pts/N` and `/dev/tty`
//!   comes as [`LX_KCALL_TTY`] `LX_TTY_K_OPEN`; `read`, `write` and `ioctl` on them come by
//!   descriptor; `poll` reads their readiness words.
//! - **The console terminal** keeps the kernel's descriptors: their `read`, `write` and
//!   `ioctl` come as `LX_KCALL_TTY` calls; a console thread waits in the kernel for keys and
//!   for hydra-shell giving the console to a Linux program or taking it back
//!   (`LX_TTY_CONS_WAIT`), and output goes to the console with `LX_TTY_CONS_WRITE`.
//! - **Sessions** stay the kernel's (decision 11): the caller's group and session come in
//!   the header of the kernel's calls; for others this service asks (`LX_TTY_SESS`,
//!   `LX_TTY_PGRP_IN`) and signals groups with `LX_TTY_SIGGRP`.
//!
//! **Restarts** (FailObjects, decision 12): a crash fails the pty objects (the programs in
//! terminal windows and ssh sessions end, the desktop stays); the console prints straight
//! from the kernel meanwhile; the new instance serves new terminals.
//!
//! The state and its rules are plain code ([`ldisc`], [`ttys`]), host-tested in
//! `tests/host-w8-t`; this file is the glue to the kernel.

#![no_std]
#![no_main]

extern crate alloc;

// (some items serve only the host tests, tests/host-w8-t)
#[allow(dead_code)]
mod ldisc;
mod lock;
// wave10 GV2: /dev/pts, redirected here by vfs-server
mod devpts;
#[allow(dead_code)]
mod ttys;

/// The kernel's protocol (the name the shared files use).
use hydra_rt::protocol as proto;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

use crate::lock::YLock;
use crate::ttys::{Ans, Caller, Io, Iov, Ttys};

hydra_rt::entry!(main);

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const O_NONBLOCK: u64 = 0o4000;
const O_NOCTTY: u64 = 0o400;
const O_CLOEXEC: u64 = 0o2000000;

/// Every terminal.
static TTYS: YLock<Ttys> = YLock::new(Ttys::new());

/// The object area (readiness words) and whether a watched word changed since the doorbell.
static AREA: AtomicU64 = AtomicU64::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);

/// Stack of the console thread.
const CONSOLE_STACK: usize = 64 * 1024;

fn main(args: &[&str]) {
    let cfg = svcrt::Config {
        name: "tty-server",
        endpoint: ENDPOINT_TTY_SERVER,
        workers: svcrt::workers_arg(args, 2),
        subscribe: Some(1 << LX_NOTE_EXIT),
    };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[tty-server] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    svcrt::objs::init(svc.area, ENDPOINT_TTY_SERVER);
    AREA.store(svc.area as u64, Ordering::Release);
    // The console's attach state before the first call (a restarted instance finds a program
    // on the console)
    if let Some((st, _)) = cons_poll(u64::MAX) {
        CONS_SEEN.store(st.gen, Ordering::Release);
        with(|t, g| t.cons_state(st.gen, st.sid, st.pgrp, st.cols, st.rows, g));
    }
    if let Err(e) = svc.online() {
        println!("[tty-server] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // The console thread: keys and attach changes from the kernel
    match sys::map_anon(CONSOLE_STACK) {
        // SAFETY: a fresh stack of its own (16-byte aligned, minus a return address)
        Ok(stack) => {
            if let Err(e) = unsafe { sys::thread_create(console_thread, stack + CONSOLE_STACK as u64 - 8, 0) } {
                println!("[tty-server] no console thread: {}", e);
            }
        }
        Err(e) => println!("[tty-server] no console thread stack: {}", e),
    }
    loop {
        match svc.recv(100) {
            Event::Request(id, _) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        flush();
    }
}

// ----------------------------------------------------------------------
// Readiness words (with an edge count that also grows when new bytes arrive)
// ----------------------------------------------------------------------

/// Sets slot `slot`'s poll bits; marks it for the doorbell if someone waits for it.
fn set_ready(slot: u32, bits: u32, arrived: bool) {
    let area = AREA.load(Ordering::Acquire);
    if area == 0 || slot as usize >= LX_OBJ_SLOTS {
        return;
    }
    let p = (area + LX_OBJ_OFF as u64 + 16 * slot as u64) as *mut u32;
    // SAFETY: the slot lies in the mapped object area; only this service writes it
    unsafe {
        let (old, edges) = (core::ptr::read_volatile(p), core::ptr::read_volatile(p.add(1)));
        let bump = bits & !old != 0 || (arrived && bits != 0);
        core::ptr::write_volatile(p.add(2) as *mut u64, 0);
        core::ptr::write_volatile(p.add(1), if bump { edges.wrapping_add(1) } else { edges });
        core::ptr::write_volatile(p, bits);
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    let (w, b) = (slot as usize / 64, 1u64 << (slot % 64));
    let watched = (area + LX_OBJ_WATCHED_OFF as u64) as *const AtomicU64;
    let changed = (area + LX_OBJ_CHANGED_OFF as u64) as *const AtomicU64;
    // SAFETY: the bitmaps lie in the object area; the kernel takes changed bits by swaps
    unsafe {
        if (*watched.add(w)).load(Ordering::SeqCst) & b != 0 {
            (*changed.add(w)).fetch_or(b, Ordering::AcqRel);
            DIRTY.store(true, Ordering::Release);
        }
    }
}

/// Rings the doorbell if watched words changed.
fn flush() {
    if DIRTY.swap(false, Ordering::AcqRel) {
        sys::svc_signal(ENDPOINT_TTY_SERVER, LX_SIGNAL_OBJS);
    }
}

// ----------------------------------------------------------------------
// The glue: what the state asks of the kernel
// ----------------------------------------------------------------------

/// [`Io`] for the service: client memory and readiness at once; answers, signals and
/// console output gathered and done after the state's lock is let go ([`Glue::finish`]).
#[derive(Default)]
struct Glue {
    completes: Vec<(u64, i64)>,
    /// `(group?, group or leader, session, signal)`.
    signals: Vec<(bool, u64, u64, u32)>,
}

impl Io for Glue {
    fn put(&mut self, id: u64, iov: &Iov, data: &[u8]) -> Result<(), i64> {
        let mut o = 0usize;
        for &(p, l) in &iov.0 {
            if o >= data.len() {
                break;
            }
            let n = (l as usize).min(data.len() - o);
            if p == 0 {
                return Err(EFAULT);
            }
            sys::lx_write(id, p, &data[o..o + n])?;
            o += n;
        }
        Ok(())
    }

    fn complete(&mut self, id: u64, result: i64) {
        self.completes.push((id, result));
    }

    fn signal_group(&mut self, pgid: u64, sid: u64, sig: u32) {
        self.signals.push((true, pgid, sid, sig));
    }

    fn signal_proc(&mut self, pid: u64, sig: u32) {
        self.signals.push((false, pid, 0, sig));
    }

    fn ready(&mut self, slot: u32, bits: u32, arrived: bool) {
        set_ready(slot, bits, arrived);
    }

    fn cons_out(&mut self, data: &[u8]) {
        // At once, under the state's lock: echo and program output reach the console in the
        // order the terminal produced them
        let mut o = 0;
        while o < data.len() {
            let n = (data.len() - o).min(64 * 1024);
            let _ = sys::lx_obj(LX_OBJ_TTY, LX_TTY_CONS_WRITE, data[o..].as_ptr() as u64, n as u64);
            o += n;
        }
    }

    fn cons_ready(&mut self, gen: u64, readable: bool) {
        // At once, under the state's lock: two threads' words must reach the kernel in the
        // order the state changed
        let _ = sys::lx_obj(LX_OBJ_TTY, LX_TTY_CONS_READY, gen, readable as u64);
    }

    fn pgrp_in(&mut self, pgid: u64, sid: u64) -> i64 {
        sys::lx_obj(LX_OBJ_TTY, LX_TTY_PGRP_IN, pgid, sid).map_or_else(|e| e, |v| v as i64)
    }
}

impl Glue {
    /// Does what was gathered (the lock is let go): console output first (an echo before
    /// the program's answer), then answers, signals, the console's readiness, the doorbell.
    fn finish(self) {
        for (id, r) in self.completes {
            let _ = sys::lx_complete(id, r);
        }
        for (group, who, sid, sig) in self.signals {
            if group {
                let _ = sys::lx_obj(LX_OBJ_TTY, LX_TTY_SIGGRP, (who & 0xFFFF_FFFF) | sid << 32, sig as u64);
            } else {
                let _ = sys::lx_obj(LX_OBJ_TTY, LX_TTY_SIGPROC, who, sig as u64);
            }
        }
        flush();
    }
}

/// Runs `f` on the terminals under their lock, then does what it gathered.
fn with<R>(f: impl FnOnce(&mut Ttys, &mut Glue) -> R) -> R {
    let mut g = Glue::default();
    let r = {
        let mut t = TTYS.lock();
        f(&mut t, &mut g)
    };
    g.finish();
    r
}

/// The caller's memory for an `ioctl` (the call's page or the client memory primitives).
struct CxMem<'a>(&'a Cx);

impl ldisc::Mem for CxMem<'_> {
    fn get(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        self.0.copy_in(ptr, len)
    }
    fn put(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        self.0.copy_out(ptr, data)
    }
}

// ----------------------------------------------------------------------
// Calls
// ----------------------------------------------------------------------

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        // wave10 GV2: a path call vfs-server redirected here (`/dev/pts`)
        _ if c.redirs > 0 && c.redir_obj & 0xFF == LX_VFS_PSEUDO_DEVPTS => pts_call(&cx),
        LX_KCALL_TTY => kcall(&cx),
        0 | 19 if c.obj != LX_OBJ_NONE => obj_read(&cx),
        1 | 20 if c.obj != LX_OBJ_NONE => obj_write(&cx),
        16 if c.obj != LX_OBJ_NONE => obj_ioctl(&cx),
        _ => (ENOSYS, 0),
    };
    flush();
    r
}

// wave10 GV2 begin: /dev/pts path calls
/// A path call under `/dev/pts` (vfs-server's redirect; `redir_tail` is where `pts` starts):
/// the stat family, access, readlink, open, chmod, chown. What is not decided here goes to
/// the kernel (service 0: nothing happened here).
fn pts_call(cx: &Cx) -> Answer {
    use devpts::Pts;
    const ENOENT: i64 = -2;
    const EPERM: i64 = -1;
    const EACCES: i64 = -13;
    const ENOTDIR: i64 = -20;
    const O_DIRECTORY: u64 = 0o200000;
    const O_PATH: u64 = 0o10000000;
    let a = cx.args;
    // (vfs-server's walk test call, redirected here: as linux-server answers it)
    if cx.nr == LX_VFS_WALK_NR {
        return (0x10000 * cx.c.svc as i64 + 0x100 * (cx.c.redir_obj & 0xFF) as i64 + (cx.c.redir_tail & 0xFF) as i64, 0);
    }
    let kernel = || svcrt::redirect(cx.page(), 0, 0, 0);
    let path_ptr = match cx.nr {
        2 | 4 | 6 | 21 | 89 | 90 | 92 | 94 | 137 => a[0],
        _ => a[1],
    };
    let Ok(p) = cx.user_cstr(path_ptr) else { return kernel() };
    let Some(tail) = p.get(cx.c.redir_tail as usize..) else { return kernel() };
    // (review 3: a walk that started in /dev/pts: the rest is below `pts`)
    let target = if cx.c.redir_obj & devpts::PTS_BELOW != 0 {
        let mut t = b"pts/".to_vec();
        t.extend_from_slice(tail);
        devpts::parse(&t)
    } else {
        devpts::parse(tail)
    };
    let node = match target {
        Pts::Kernel => return kernel(),
        Pts::Missing if matches!(cx.nr, 2 | 257) && (if cx.nr == 2 { a[1] } else { a[2] }) & 0o100 != 0 => return (EPERM, 0),
        Pts::Missing => return (ENOENT, 0),
        Pts::NotDir => return (ENOTDIR, 0),
        Pts::Dir => None,
        // (review 5: /dev/pts/ptmx: char 5:2, mode 0 (root opens it), inode 2)
        Pts::Ptmx => {
            return match cx.nr {
                4 | 6 | 262 | 332 => {
                    let (out, x) = match cx.nr {
                        4 | 6 => (a[1], false),
                        262 => (a[2], false),
                        _ => (a[4], true),
                    };
                    let rdev = (5 << 8) | 2;
                    let r = if x { cx.copy_out(out, &devpts::statx_bytes(2, 0o020000, 0, 0, rdev, 1)) } else { cx.copy_out(out, &devpts::stat_bytes(2, 0o020000, 0, 0, rdev, 1)) };
                    (r.err().unwrap_or(0), 0)
                }
                2 | 257 => {
                    let flags = if cx.nr == 2 { a[1] } else { a[2] };
                    if flags & O_PATH != 0 {
                        return kernel();
                    }
                    if flags & 0o200 != 0 && flags & 0o100 != 0 {
                        return (-17, 0); // EEXIST
                    }
                    if cx.c.euid != 0 {
                        return (EACCES, 0);
                    }
                    (open(cx, (5 << 8) | 2, flags, &caller(cx, true)), 0)
                }
                21 | 269 | 439 => (if cx.c.euid == 0 { 0 } else { EACCES }, 0),
                89 | 267 => (-22, 0),
                137 => (cx.copy_out(a[1], &devpts::statfs_bytes()).err().unwrap_or(0), 0),
                _ => (EPERM, 0),
            };
        }
        Pts::Node(i) => match TTYS.lock().stat(i) {
            Some(n) => Some((i, n)),
            // (review 5: devpts makes no names: O_CREAT of a missing one is EPERM)
            None if matches!(cx.nr, 2 | 257) && (if cx.nr == 2 { a[1] } else { a[2] }) & 0o100 != 0 => return (EPERM, 0),
            None => return (ENOENT, 0),
        },
    };
    // (mode with type, uid, gid, inode, device number, links)
    let (mode, uid, gid, ino, rdev, nlink) = match node {
        None => (0o040755, 0, 0, 1u64, 0u64, 2u32),
        Some((i, (m, u, g))) => (0o020000 | (m & 0o7777), u, g, i as u64 + 3, pts_rdev(i as u64), 1),
    };
    let r = match cx.nr {
        4 | 6 | 262 | 332 => {
            let (out, x) = match cx.nr {
                4 | 6 => (a[1], false),
                262 => (a[2], false),
                _ => (a[4], true),
            };
            let r = if x { cx.copy_out(out, &devpts::statx_bytes(ino, mode, uid, gid, rdev, nlink)) } else { cx.copy_out(out, &devpts::stat_bytes(ino, mode, uid, gid, rdev, nlink as u64)) };
            r.err().unwrap_or(0)
        }
        21 | 269 | 439 => {
            let (want, flags) = match cx.nr {
                21 => (a[1] as u32, 0),
                269 => (a[2] as u32, 0),
                _ => (a[2] as u32, a[3]),
            };
            // (AT_EACCESS: the effective ids; else the real ones)
            let id = if flags & 0x200 != 0 { cx.c.euid } else { cx.c.uid };
            if want & 7 == 0 || devpts::may(mode, uid, gid, id, want & 7, &|g| cx.in_group(g)) { 0 } else { EACCES }
        }
        89 | 267 => -22, // EINVAL: no links here
        137 => cx.copy_out(a[1], &devpts::statfs_bytes()).err().unwrap_or(0),
        2 | 257 => {
            let flags = if cx.nr == 2 { a[1] } else { a[2] };
            match node {
                // (a directory handle to list, an O_PATH handle: the kernel's; wave11 GF:
                // vfs-server opens the directory itself, `LX_TTY_K_LIST` lists it)
                None => return kernel(),
                Some(_) if flags & O_PATH != 0 => return kernel(),
                Some(_) if flags & O_DIRECTORY != 0 => ENOTDIR,
                // (review 5: O_CREAT|O_EXCL of an existing slave)
                Some(_) if flags & 0o300 == 0o300 => -17, // EEXIST
                Some(_) => open(cx, rdev, flags, &caller(cx, true)),
            }
        }
        90 | 268 | 452 | 92 | 94 | 260 => match node {
            None => EPERM,
            Some((i, _)) => {
                let opt = |v: u64| if v as u32 == u32::MAX { None } else { Some(v as u32) };
                let (m, u, g) = match cx.nr {
                    90 => (Some(a[1] as u32), None, None),
                    268 | 452 => (Some(a[2] as u32), None, None),
                    92 | 94 => (None, opt(a[1]), opt(a[2])),
                    _ => (None, opt(a[2]), opt(a[3])),
                };
                TTYS.lock().setattr(i, cx.c.euid, m, u, g, &|g| cx.in_group(g))
            }
        },
        _ => EPERM,
    };
    (r, 0)
}
// wave10 GV2 end

/// An [`Ans`] as the worker's answer.
fn answer(a: Ans) -> Answer {
    match a {
        Ans::Now(r) => (r, 0),
        Ans::Pending => (0, LX_REPLY_PENDING),
    }
}

/// The caller of `cx` with its group and session: from the header when the kernel filled
/// them, else asked.
fn caller(cx: &Cx, ask: bool) -> Caller {
    let mut w = Caller { tgid: cx.c.tgid, pgid: cx.c.pgid as u64, sid: cx.c.sid as u64, euid: cx.c.euid };
    if w.sid == 0 && ask {
        if let Ok(v) = sys::lx_obj(LX_OBJ_TTY, LX_TTY_SESS, cx.c.tgid, 0) {
            w.sid = v & 0xFFFF_FFFF;
            w.pgid = v >> 32;
        }
    }
    w
}

/// The buffers of `read`/`write` (0, 1) or `readv`/`writev` (19, 20).
fn iov_of(cx: &Cx) -> Result<Iov, i64> {
    match cx.nr {
        19 | 20 => {
            let count = cx.args[2];
            if count > 1024 {
                return Err(EINVAL);
            }
            let raw = cx.copy_in_any(cx.args[1], count as usize * 16)?;
            let mut v = Vec::with_capacity(count as usize);
            for c in raw.chunks_exact(16) {
                let (p, l) = (Cx::u64_at(c, 0), Cx::u64_at(c, 8));
                if (l as i64) < 0 {
                    return Err(EINVAL);
                }
                if l > 0 {
                    v.push((p, l));
                }
            }
            let iov = Iov(v);
            if !iov.fits() {
                return Err(EINVAL);
            }
            Ok(iov)
        }
        _ => Ok(Iov::one(cx.args[1], cx.args[2])),
    }
}

/// Most bytes one write takes (a larger one gets a short count, as terminals may give).
const MAX_WRITE: u64 = 1 << 20;

/// The bytes of a write's buffers, at most [`MAX_WRITE`] of them.
fn gather(cx: &Cx, iov: &Iov) -> Result<Vec<u8>, i64> {
    let mut out = Vec::with_capacity(iov.total().min(MAX_WRITE as usize));
    for &(p, l) in &iov.0 {
        let n = l.min(MAX_WRITE - out.len() as u64);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&cx.copy_in(p, n as usize)?);
    }
    Ok(out)
}

fn obj_read(cx: &Cx) -> Answer {
    let iov = match iov_of(cx) {
        Ok(v) => v,
        Err(e) => return (e, 0),
    };
    let slot = cx.c.obj as u32;
    answer(with(|t, g| t.read(slot, cx.id, cx.c.tgid, iov, cx.nonblock(), g)))
}

fn obj_write(cx: &Cx) -> Answer {
    let data = match iov_of(cx).and_then(|iov| gather(cx, &iov)) {
        Ok(d) => d,
        Err(e) => return (e, 0),
    };
    let slot = cx.c.obj as u32;
    answer(with(|t, g| t.write(slot, cx.id, cx.c.tgid, data, cx.nonblock(), g)))
}

fn obj_ioctl(cx: &Cx) -> Answer {
    let slot = cx.c.obj as u32;
    let (req, arg) = (cx.args[1], cx.args[2]);
    let who = caller(cx, matches!(req, ldisc::TIOCSCTTY | ldisc::TIOCSPGRP));
    let mem = CxMem(cx);
    match with(|t, g| t.ioctl(slot, req, arg, &who, &mem, g)) {
        Ok(r) => (r, 0),
        // TIOCGPTPEER: a slave descriptor for the caller
        Err(flags) => {
            let new = match svcrt::objs::alloc() {
                Ok(s) => s,
                Err(e) => return (e, 0),
            };
            match with(|t, g| t.open_peer(slot, new, &who, g)) {
                Ok((index, node)) => (install_slave(cx, new, index, node, flags as u64), 0),
                Err(e) => {
                    svcrt::objs::free(new);
                    (e, 0)
                }
            }
        }
    }
}

/// Installs a descriptor for object `slot` in the caller's table (`flags`: the open's
/// `O_CLOEXEC`/`O_NONBLOCK`); on failure the slot is closed and freed.
#[allow(clippy::too_many_arguments)]
fn install(cx: &Cx, slot: u32, kind: u32, flags: u64, node: (u32, u32, u32), name: &[u8], tag: u64, key: u64) -> i64 {
    let (mode, uid, gid) = node;
    let mut d = LxObjDesc { slot, kind, flags: (flags & (O_CLOEXEC | O_NONBLOCK)) as u32, mode, uid, gid, name_len: 0, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag, key };
    let n = name.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&name[..n]);
    d.name_len = n as u32;
    match sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0) {
        Ok(fd) => fd as i64,
        Err(e) => {
            // The kernel does not tell us of this object's end: forget it here
            with(|t, g| t.closed(slot, g));
            svcrt::objs::free(slot);
            e
        }
    }
}

/// Installs slave `/dev/pts/index` (object `slot`, node `(mode, uid, gid)`).
fn install_slave(cx: &Cx, slot: u32, index: u32, node: (u32, u32, u32), flags: u64) -> i64 {
    let name = alloc::format!("/dev/pts/{}", index);
    let rdev = pts_rdev(index as u64);
    install(cx, slot, LX_OBJ_KIND_PTY_S, flags, node, name.as_bytes(), index as u64 + 3, rdev)
}

/// `/dev/pts/index`'s device number (`makedev(136 + index / 256, index % 256)`).
fn pts_rdev(index: u64) -> u64 {
    let (major, minor) = (136 + (index >> 8), index & 0xFF);
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & !0xFF) << 12)
}

/// [`LX_KCALL_TTY`]: the kernel's calls for a program.
fn kcall(cx: &Cx) -> Answer {
    let a = cx.args;
    let who = caller(cx, false);
    // A console call carries the attach state it was made in (`args[4]` generation,
    // `args[5]` session | group << 32): a program's first call may come before the console
    // thread saw its attach
    if matches!(a[0], LX_TTY_K_READ | LX_TTY_K_WRITE | LX_TTY_K_IOCTL) && a[4] != 0 {
        with(|t, g| t.cons_state(a[4], a[5] & 0xFFFF_FFFF, a[5] >> 32, 0, 0, g));
    }
    match a[0] {
        LX_TTY_K_OPEN => (open(cx, a[1], a[2], &who), 0),
        LX_TTY_K_READ => {
            let iov = Iov::one(a[1], a[2]);
            answer(with(|t, g| t.cons_read(cx.id, &who, iov, a[3] != 0, LX_TTY_BGREAD, g)))
        }
        LX_TTY_K_WRITE => match gather(cx, &Iov::one(a[1], a[2])) {
            Ok(d) => (with(|t, g| t.cons_write(&d, g)), 0),
            Err(e) => (e, 0),
        },
        LX_TTY_K_IOCTL => {
            let mem = CxMem(cx);
            (with(|t, g| t.cons_ioctl(a[1], a[2], &who, &mem, g)), 0)
        }
        LX_TTY_K_STAT => {
            let r = TTYS.lock().stat(a[1] as u32);
            match r {
                Some((mode, uid, gid)) => (pack_stat(mode, uid, gid), 0),
                None => (ttys::ENOENT, 0),
            }
        }
        LX_TTY_K_SETATTR => {
            let opt = |v: u64| if v == u64::MAX { None } else { Some(v as u32) };
            (TTYS.lock().setattr(a[1] as u32, cx.c.euid, opt(a[2]), opt(a[3]), opt(a[4]), &|g| cx.in_group(g)), 0)
        }
        // wave11 GF: `getdents64` of a `/dev/pts` directory handle (the kernel's, for the
        // program): the entries from index a[3] into its buffer
        LX_TTY_K_LIST => {
            let live = TTYS.lock().live_indexes();
            let all = devpts::entries(&live);
            let (out, next) = devpts::dirents64(&all, a[3] as usize, (a[2] as usize).min(1 << 16));
            if out.is_empty() && next < all.len() {
                (EINVAL, 0)
            } else if out.is_empty() {
                ((next as i64) << 32, 0)
            } else {
                match cx.copy_out(a[1], &out) {
                    Ok(()) => (out.len() as i64 | (next as i64) << 32, 0),
                    Err(e) => (e, 0),
                }
            }
        }
        LX_TTY_K_HANGUP => match with(|t, g| t.hangup(a[1], g)) {
            Some((fg, leader)) => (((fg & 0xFFFF_FFFF) | leader << 32) as i64, 0),
            None => (ttys::ESRCH, 0),
        },
        _ => (EINVAL, 0),
    }
}

/// `LX_TTY_K_STAT`'s answer (the kernel's `lx::console::pack_stat`).
fn pack_stat(mode: u32, uid: u32, gid: u32) -> i64 {
    ((mode & 0o7777) as u64 | ((gid as u64) & 0xF_FFFF) << 12 | ((uid as u64) & 0x7FFF_FFFF) << 32) as i64
}

/// `LX_TTY_K_OPEN` of device `rdev` with open flags `flags`.
fn open(cx: &Cx, rdev: u64, flags: u64, who: &Caller) -> i64 {
    let (major, minor) = ((rdev >> 8) & 0xFFF, (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00));
    let slot = match svcrt::objs::alloc() {
        Ok(s) => s,
        Err(e) => return e,
    };
    match (major, minor) {
        (5, 2) => match with(|t, g| t.open_master(slot, cx.c.euid, g)) {
            Ok(_) => install(cx, slot, LX_OBJ_KIND_PTY_M, flags, (0o020666, 0, 0), b"/dev/ptmx", 2, rdev),
            Err(e) => {
                svcrt::objs::free(slot);
                e
            }
        },
        (5, 0) => match with(|t, g| t.open_controlling(slot, who, g)) {
            None => {
                svcrt::objs::free(slot);
                LX_TTY_NOTMINE
            }
            Some(Err(e)) => {
                svcrt::objs::free(slot);
                e
            }
            Some(Ok((index, node))) => install_slave(cx, slot, index, node, flags),
        },
        (136..=143, 0..=255) => {
            let index = (((major - 136) << 8) | (minor & 0xFF)) as u32;
            // (the access the open asks for: O_RDONLY 4, O_WRONLY 2, O_RDWR 6)
            let want = match flags & 3 {
                0 => 4,
                1 => 2,
                _ => 6,
            };
            match with(|t, g| t.open_slave(index, slot, flags & O_NOCTTY != 0, want, who, &|gid| cx.in_group(gid), g)) {
                Ok(node) => install_slave(cx, slot, index, node, flags),
                Err(e) => {
                    svcrt::objs::free(slot);
                    e
                }
            }
        }
        _ => {
            svcrt::objs::free(slot);
            -6 // ENXIO
        }
    }
}

// ----------------------------------------------------------------------
// Notifications and the console thread
// ----------------------------------------------------------------------

/// A notification from the kernel.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_CLOSE if b == LX_OBJ_KIND_PTY_M as u64 || b == LX_OBJ_KIND_PTY_S as u64 => {
            with(|t, g| t.closed(a as u32, g));
            set_ready(a as u32, 0, false);
            svcrt::objs::free(a as u32);
        }
        LX_NOTE_INTERRUPT => {
            with(|t, g| t.interrupt(a, g));
        }
        LX_NOTE_EXIT => TTYS.lock().exited(a),
        _ => {}
    }
}

/// The attach generation the console thread starts from.
static CONS_SEEN: AtomicU64 = AtomicU64::new(u64::MAX);

/// One `LX_TTY_CONS_WAIT` (`seen`: the attach generation known): the console's state and the
/// keys typed. `None`: not forwarded (`-EPERM`, `lx.tty=kernel`) or another error.
fn cons_poll(seen: u64) -> Option<(LxConsState, Vec<u32>)> {
    const CAP: usize = 4096;
    let head = core::mem::size_of::<LxConsState>();
    let mut buf = alloc::vec![0u8; CAP];
    buf[..8].copy_from_slice(&seen.to_le_bytes());
    let n = sys::lx_obj(LX_OBJ_TTY, LX_TTY_CONS_WAIT, buf.as_mut_ptr() as u64, CAP as u64).ok()?;
    // SAFETY: the kernel wrote a whole `LxConsState` at the head
    let st: LxConsState = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const LxConsState) };
    let n = (n as usize).min((CAP - head) / 4).min(st.nkeys as usize);
    let keys = (0..n).map(|i| u32::from_le_bytes(buf[head + 4 * i..head + 4 * i + 4].try_into().unwrap_or([0; 4]))).collect();
    Some((st, keys))
}

/// The console thread: waits in the kernel for console keys and attach changes, and feeds
/// them to the console terminal.
extern "C" fn console_thread(_arg: u64) -> ! {
    let mut seen = CONS_SEEN.load(Ordering::Acquire);
    loop {
        match cons_poll(seen) {
            Some((st, keys)) => {
                seen = st.gen;
                with(|t, g| {
                    t.cons_state(st.gen, st.sid, st.pgrp, st.cols, st.rows, g);
                    t.cons_keys(st.gen, &keys, g);
                });
            }
            // Not forwarded (`lx.tty=kernel`: the kernel's tty.rs has the console), or an
            // error: look again later
            None => sys::sleep_ms(2000),
        }
    }
}
