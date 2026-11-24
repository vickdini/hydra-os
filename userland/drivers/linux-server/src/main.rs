//! # Hydra's Linux server (linux-server)
//!
//! The Linux personality is moving out of the kernel into this program, step by step
//! (`docs/linux-server-design.md`). Step 1 builds the machinery and moves its first tenant,
//! the key retention service ([`keys`]: `add_key`, `request_key`, `keyctl`, `/proc/keys`).
//!
//! ## How it runs
//!
//! The supervisor starts it (`workers=N`) and restarts it when it dies; when it dies, every
//! Linux program ends (the user's crash policy, carried out by the kernel's `src/lx`).
//!
//! - **Workers** (`N` threads): each attaches a syscall page (`SYS_LX_CTL`) and loops in
//!   `SYS_LX_REPLY_RECV`: the kernel puts a forwarded Linux system call in the page (an
//!   [`LxCall`]: number, arguments, the caller's identity) and hands the CPU straight to the
//!   worker; the worker serves it and answers, which hands the CPU straight back to the
//!   caller and waits for the next call. A call may also be answered later ("pending",
//!   `SYS_LX_COMPLETE`), by any thread.
//! - **The main thread** serves the endpoint [`ENDPOINT_LINUX_SERVER`]: the supervisor's
//!   heartbeats, kernel requests made while the kernel may hold locks
//!   ([`MSG_LX_PROC_KEYS`]), and the notification ring in the window (processes forking,
//!   exec'ing and ending, signals for pending calls), which it drains when the kernel rings.
//!
//! Every call carries the ring position at the time it was made: a worker first takes the
//! notifications up to there ([`notes::drain_to`]), so a call never overtakes the events
//! that came before it (a child's first call comes after its fork is known).

#![no_std]
#![no_main]

extern crate alloc;

// (client, fdio, obj, timeout: shared with lx-net and lx-ipc, which use more of them)
#[allow(unused_imports)]
mod client;
mod exec; // wave7 G7-5
mod execplan; // wave7 G7-5
#[allow(dead_code)]
mod fdio;
mod lock;
// wave6 G20: linux-server's client of net-server, for the direct-call probe
// (`LX_NULL_SVC_RTT`). (wave10 G10-C: the network, IPC, keys and bpf pieces are lx-net's,
// lx-ipc's and lx-sec's alone: no switch back co-locates them here any more)
#[path = "../../lx-net/src/netc.rs"]
#[allow(dead_code)]
mod netc;
mod notes;
#[allow(dead_code)]
mod obj;
// wave7 G7-4 begin: /sys (the pseudo file system), on the kernel's protocol
mod pseudo;
pub(crate) use hydra_rt::protocol as proto;
// wave7 G7-4 end
#[allow(dead_code)]
mod timeout;

/// This program's name (log lines of the shared files).
pub const NAME: &str = "linux-server";

/// The close hook of `obj.rs` (wave 8): the last descriptor of an object of `kind` went.
pub fn on_closed(slot: u32, kind: u32) {
    if kind == LX_OBJ_KIND_PSEUDO {
        pseudo::closed(slot); // wave7 G7-4
    }
}

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use hydra_rt::protocol::*;
use hydra_rt::{println, svcrt, sys, Message, Server};

use crate::client::Cx;
use crate::lock::YLock;

hydra_rt::entry!(main);

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

/// Pending test calls ([`LX_NULL_PENDING`]): `(request ID, tick due)`, answered by the main
/// thread.
static PENDING: YLock<Vec<(u64, u64)>> = YLock::new(Vec::new());

fn main(args: &[&str]) {
    // The service runtime (wave 6, `hydra_rt::svcrt`): workers, endpoint, object area
    let cfg = svcrt::Config { name: "linux-server", endpoint: ENDPOINT_LINUX_SERVER, workers: svcrt::workers_arg(args, 4), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[linux-server] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    notes::init(svc.window().as_mut_ptr());
    pseudo::init(args); // wave7 G7-4
    obj::init(svc.area, ENDPOINT_LINUX_SERVER); // (wave 8: the doorbell's endpoint)
    if let Err(e) = svc.online() {
        println!("[linux-server] cannot go online: {}", e);
        sys::exit_group(1);
    }
    serve_endpoint(&mut svc.srv)
}

/// The main thread: heartbeats, kernel requests and notifications.
fn serve_endpoint(srv: &mut Server) -> ! {
    loop {
        timeout::update_clock();
        let now = sys::uptime_ticks();
        let timeout = match next_deadline(now) {
            Some(d) => d.saturating_sub(now).clamp(1, 100),
            None => 100,
        };
        match sys::svc_recv_notify(srv.endpoint, timeout) {
            Ok((0, _)) => {}
            Ok((id, req)) => {
                let reply = match req.label as u32 {
                    MSG_SUPERVISOR_PING => Message::new(MSG_SUPERVISOR_PONG as u64, [req.args[0], 1, 0, 0]),
                    _ => Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0]),
                };
                let _ = sys::svc_reply(srv.endpoint, id, &reply);
            }
            Err(_) => {}
        }
        notes::drain_all();
        complete_due();
        obj::flush();
    }
}

/// Answers the blocked calls whose timeout passed and returns the earliest deadline still
/// waiting (the main thread sleeps until then).
pub fn next_deadline(now: u64) -> Option<u64> {
    if PENDING.lock().is_empty() {
        None
    } else {
        Some(now + 1)
    }
}

/// Answers the pending test calls whose time has come.
fn complete_due() {
    let now = sys::uptime_ticks();
    let due: Vec<u64> = {
        let mut p = PENDING.lock();
        let d = p.iter().filter(|(_, t)| *t <= now).map(|(id, _)| *id).collect();
        p.retain(|(_, t)| *t > now);
        d
    };
    for id in due {
        let _ = sys::lx_complete(id, 42);
    }
}

/// A signal arrived for the caller of pending request `id`: a pending test call is
/// answered `-EINTR` at once.
pub fn interrupted(id: u64) {
    let found = {
        let mut p = PENDING.lock();
        let before = p.len();
        p.retain(|(i, _)| *i != id);
        p.len() != before
    };
    if found {
        let _ = sys::lx_complete(id, -4);
    }
}

/// Serves one forwarded call (in syscall page `page`): `(result, SYS_LX_REPLY_RECV flags)`.
fn serve(c: &LxCall, page: *mut u8) -> (i64, u64) {
    notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        LX_NULL_NR => null_call(&cx),
        // wave6 G23: mmap of a server object (only the test object has memory so far)
        9 if c.obj != LX_OBJ_NONE => match obj::kind_of(c.obj as u32) {
            LX_OBJ_KIND_TEST => (obj::test_mmap(&cx), 0),
            _ => (-19, 0), // ENODEV
        },
        LX_DCALL_NR => dcall_serve(&cx), // wave6 G20
        // (wave7 G7-5: vfs-server's open of a FIFO node redirected to the IPC service is
        // `ipcsvc::dispatch`'s since wave 8, tried before this pseudo-file arm)
        // wave7 G7-4: a path call the file service redirected here (`/proc`, `/sys`)
        n if c.redirs != 0 && pseudo::is_path_call(n) => pseudo::redirected(&cx),
        // wave 6 (Group 19): a test call the test service redirected here
        LX_TEST_NR if c.redir_obj != 0 => (0x5000 + c.redir_obj as i64 + 0x100 * c.redirs as i64 + c.redir_tail as i64, 0),
        // wave7 G7-1: vfs-server's walk test call it redirected here (a path under `/proc`,
        // `/sys`, `/dev`): `0x10000 * service + 0x100 * object + tail` (tail's low byte)
        LX_VFS_WALK_NR if c.redirs != 0 => (0x10000 * c.svc as i64 + 0x100 * (c.redir_obj & 0xFF) as i64 + (c.redir_tail & 0xFF) as i64, 0),
        // read, write, readv, writev, ioctl on a server object; the kernel's own calls on one
        0 | 1 | 16 | 19 | 20 | 276 | LX_KCALL_REOPEN | LX_KCALL_FCNTL | LX_KCALL_PSEEK | LX_KCALL_PREAD if c.obj != LX_OBJ_NONE => object_io(&cx), // (wave7 G7-4: PSEEK, PREAD)
        // (wave8 GX2: sockets, pipes, eventfd, pidfd, signalfd, timerfd, message queues and
        // System V went to `netsvc`/`ipcsvc` above)
        // wave7 G7-5: execve's front half (the kernel asks; vfs-server resolves the files)
        LX_KCALL_EXEC => exec::front(&cx),
        _ => (ENOSYS, 0),
    };
    obj::flush();
    r
}

/// `read`, `write`, `readv`, `writev` and `ioctl` on the server object in `cx.c.obj`.
fn object_io(cx: &Cx) -> (i64, u64) {
    const EINVAL_: i64 = -22;
    const ENOTTY: i64 = -25;
    match (obj::kind_of(cx.c.obj as u32), cx.nr) {
        (LX_OBJ_KIND_TEST, _) => (obj::test_io(cx), 0),
        (LX_OBJ_KIND_PSEUDO, _) => pseudo::io(cx), // wave7 G7-4
        // (wave8 GX2: the network and IPC kinds are `netsvc`'s/`ipcsvc`'s, served before)
        (_, 16) => (ENOTTY, 0),
        _ => (EINVAL_, 0),
    }
}

/// Hydra's test call ([`LX_NULL_NR`]).
fn null_call(cx: &Cx) -> (i64, u64) {
    match cx.args[0] {
        LX_NULL_RETURN => (0, 0),
        LX_NULL_PENDING => {
            let due = sys::uptime_ticks() + cx.args[1] / 10;
            PENDING.lock().push((cx.id, due));
            // The main thread answers it: it must look at the clock sooner than it would
            let _ = sys::lx_ctl(LX_CTL_WAKE);
            (0, LX_REPLY_PENDING)
        }
        LX_NULL_COPY => {
            let len = cx.args[2] as usize;
            if len > 4096 {
                return (EINVAL, 0);
            }
            let mut buf = match cx.copy_in(cx.args[1], len) {
                Ok(b) => b,
                Err(e) => return (e, 0),
            };
            for b in buf.iter_mut() {
                *b = b.wrapping_add(1);
            }
            match cx.copy_out(cx.args[1], &buf) {
                Ok(()) => (len as i64, 0),
                Err(e) => (if e == 0 { EFAULT } else { e }, 0),
            }
        }
        LX_NULL_OBJ => (obj::test_new(cx, cx.args[1]), 0),
        LX_NULL_OBJ_CLOSES => (obj::TEST_CLOSES.load(Ordering::Relaxed) as i64, 0),
        // wave6 G20: the round trip of a call to net-server (the direct path's probe)
        LX_NULL_SVC_RTT => (netc::ping_rtt(cx.args[1], cx.args[2] & 1 != 0), 0),
        // wave6 G20: `arg1` direct calls (null) to service `arg2`, timed
        LX_NULL_DCALL_RTT => {
            let t0 = sys::lx_timer(LX_TIMER_NOW, 0, 0);
            for _ in 0..cx.args[1] {
                let r = hydra_rt::svccall::dcall(cx.args[2] as u8, LX_DCALL_OP_NULL, &[], &mut []);
                if r < 0 {
                    return (r, 0);
                }
            }
            (sys::lx_timer(LX_TIMER_NOW, 0, 0) - t0, 0)
        }
        // wave6 G20: one direct call to service `arg1`, operation `arg2`, input the 8 bytes
        // of `arg3`; the result (op 1 echo: the 8 bytes back as the result)
        LX_NULL_DCALL => {
            let mut out = [0u8; 8];
            let r = hydra_rt::svccall::dcall(cx.args[1] as u8, cx.args[2], &cx.args[3].to_le_bytes(), &mut out);
            if cx.args[2] == LX_DCALL_OP_ECHO && r == 8 {
                (u64::from_le_bytes(out) as i64, 0)
            } else {
                (r, 0)
            }
        }
        _ => (EINVAL, 0),
    }
}

/// wave6 G20: a direct call from another service (or another worker of ours): the null
/// operation, an echo of the input, the identity the kernel passed (delegation).
fn dcall_serve(cx: &Cx) -> (i64, u64) {
    let a = hydra_rt::svccall::DcallArgs::of(&cx.c);
    match a.op {
        LX_DCALL_OP_NULL => (0, 0),
        LX_DCALL_OP_ECHO => {
            let data = match cx.copy_in(a.input, a.input_len) {
                Ok(d) => d,
                Err(e) => return (e, 0),
            };
            let n = data.len().min(a.output_cap);
            match cx.copy_out(a.output, &data[..n]) {
                Ok(()) => (n as i64, 0),
                Err(e) => (e, 0),
            }
        }
        LX_DCALL_OP_WHO => (cx.c.tgid as i64, 0),
        _ => (EINVAL, 0),
    }
}
