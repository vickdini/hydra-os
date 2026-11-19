//! # Hydra's test service (svc-test, wave 6)
//!
//! A second Linux-facing service beside linux-server, on its own endpoint
//! ([`ENDPOINT_SVC_TEST`]) and in its own process, built on the service runtime
//! (`hydra_rt::svcrt`). It proves the routing core of `docs/linux-services-design.md`
//! (section 3): the kernel routes the test call [`LX_TEST_NR`] here by number, calls on its
//! objects here by descriptor, `open` of a character device of major [`SVC_TEST_MAJOR`]
//! here by major, and it can redirect a call to linux-server. Killing it (`service kill
//! svc_test`) fails only its own callers and objects: linux-server and every program live.
//!
//! [`LX_TEST_NR`] operations (`arg0`):
//! - [`LX_TEST_NULL`]: 0 at once (the cost of a forwarded call to a second service);
//! - [`LX_TEST_OBJ`]: a new test object (read: `svc-test <slot>`; write `r`/`w`/`c`: readable,
//!   writable, cleared);
//! - [`LX_TEST_PENDING`]: answered later (`arg1` ms) with [`LX_TEST_PENDING_RESULT`];
//! - [`LX_TEST_REDIRECT`]: redirected to linux-server (object `arg1`, tail `arg2`);
//! - [`LX_TEST_WHO`]: this process's id;
//! - [`LX_TEST_COPY`]: adds 1 to each of `arg2` bytes at `arg1` (client memory);
//! - [`LX_TEST_REDIR_LOOP`]: redirects to itself for ever (the kernel stops it: `-ELOOP`).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, objs, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

hydra_rt::entry!(main);

const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;

/// Pending test calls: `(request id, tick due)`.
static PENDING: spin::Mutex<Vec<(u64, u64)>> = spin::Mutex::new(Vec::new());
/// Per live object slot: the device number it was opened as (0: made by `LX_TEST_OBJ`).
static OBJECTS: spin::Mutex<BTreeMap<u32, u64>> = spin::Mutex::new(BTreeMap::new());
/// Objects closed since start (their last descriptor went).
static CLOSES: AtomicU64 = AtomicU64::new(0);

fn main(args: &[&str]) {
    // With `lx.test=linux` (or `kernel`) no service id names this endpoint: nothing to serve
    // (exiting without registering: the supervisor does not restart it)
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[svc-test] no service id names endpoint {:#x}: not started", ENDPOINT_SVC_TEST);
        sys::exit(0);
    }
    let cfg = svcrt::Config { name: "svc-test", endpoint: ENDPOINT_SVC_TEST, workers: svcrt::workers_arg(args, 2), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[svc-test] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    objs::init(svc.area, ENDPOINT_SVC_TEST);
    if let Err(e) = svc.online() {
        println!("[svc-test] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // Opens of character devices of the test major come here (after online: the kernel
    // routes them only to a service that serves)
    if let Err(e) = sys::lx_svc(LX_SVC_CLAIM_MAJOR, SVC_TEST_MAJOR, 0, 0) {
        println!("[svc-test] cannot claim major {}: {}", SVC_TEST_MAJOR, e);
    }
    loop {
        let timeout = if PENDING.lock().is_empty() { 100 } else { 1 };
        match svc.recv(timeout) {
            Event::Request(id, _) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        complete_due();
        objs::flush();
    }
}

/// A notification from the kernel.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_CLOSE if b == LX_OBJ_KIND_SVCTEST as u64 => {
            OBJECTS.lock().remove(&(a as u32));
            objs::set(a as u32, 0, 0);
            objs::free(a as u32);
            CLOSES.fetch_add(1, Ordering::Relaxed);
        }
        LX_NOTE_INTERRUPT => {
            let found = {
                let mut p = PENDING.lock();
                let before = p.len();
                p.retain(|(i, _)| *i != a);
                p.len() != before
            };
            if found {
                let _ = sys::lx_complete(a, EINTR);
            }
        }
        _ => {}
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
        let _ = sys::lx_complete(id, LX_TEST_PENDING_RESULT);
    }
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        LX_TEST_NR => test_call(&cx),
        LX_DCALL_NR => dcall_serve(&cx), // wave6 G20
        LX_KCALL_DEVOPEN => (new_object(&cx, c.dev, c.args[1]), 0),
        0 | 1 | 16 if c.obj != LX_OBJ_NONE => (object_io(&cx), 0),
        _ => (ENOSYS, 0),
    };
    objs::flush();
    r
}

// wave6 G20 begin
/// A direct call from another service (`SYS_SVC_DCALL`): the test operations of
/// `LX_DCALL_OP_*` (null, echo, who, peek, slow).
fn dcall_serve(cx: &Cx) -> Answer {
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
        LX_DCALL_OP_PEEK => {
            // 8 bytes at the address in the input, read from the program the call is for
            let Ok(d) = cx.copy_in(a.input, 8) else { return (EINVAL, 0) };
            let addr = u64::from_le_bytes(d[..8].try_into().unwrap_or([0; 8]));
            let mut v = [0u8; 8];
            match sys::lx_read(cx.c.on_behalf, addr, &mut v) {
                Ok(()) => (u64::from_le_bytes(v) as i64 & i64::MAX, 0),
                Err(e) => (e, 0),
            }
        }
        LX_DCALL_OP_SLOW => {
            let Ok(d) = cx.copy_in(a.input, 8) else { return (EINVAL, 0) };
            sys::sleep_ms(u64::from_le_bytes(d[..8].try_into().unwrap_or([0; 8])).min(10_000));
            (0, 0)
        }
        _ => (EINVAL, 0),
    }
}
// wave6 G20 end

/// [`LX_TEST_NR`].
fn test_call(cx: &Cx) -> Answer {
    match cx.args[0] {
        LX_TEST_NULL => (0, 0),
        LX_TEST_OBJ => (new_object(cx, 0, cx.args[1]), 0),
        LX_TEST_PENDING => {
            PENDING.lock().push((cx.id, sys::uptime_ticks() + cx.args[1] / 10));
            // The main thread answers it: it must look at the clock sooner than it would
            let _ = sys::lx_ctl(LX_CTL_WAKE);
            (0, LX_REPLY_PENDING)
        }
        LX_TEST_REDIRECT => svcrt::redirect(cx.page(), LXS_LINUX, cx.args[1], cx.args[2] as u32),
        LX_TEST_REDIR_LOOP => svcrt::redirect(cx.page(), LXS_TEST, 1, 0),
        LX_TEST_WHO => (sys::getpid() as i64, 0),
        LX_TEST_COPY => {
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
                Err(e) => (e, 0),
            }
        }
        7 => (CLOSES.load(Ordering::Relaxed) as i64, 0),
        _ => (EINVAL, 0),
    }
}

/// A new test object for the caller (`dev`: the device number it is opened as, 0 for none),
/// `flags`: `O_CLOEXEC`/`O_NONBLOCK`; its descriptor.
fn new_object(cx: &Cx, dev: u64, flags: u64) -> i64 {
    let slot = match objs::alloc() {
        Ok(s) => s,
        Err(e) => return e,
    };
    OBJECTS.lock().insert(slot, dev);
    let (mode, name): (u32, &[u8]) = if dev != 0 { (0o020600, b"/dev/svctest") } else { (0o100600, b"anon_inode:[svc-test]") };
    match objs::install(cx, slot, LX_OBJ_KIND_SVCTEST, flags as u32 & 0o2004000, mode, name, 0) {
        Ok(fd) => {
            // Writable from the start
            objs::set(slot, 0x104, 0);
            fd
        }
        Err(e) => {
            OBJECTS.lock().remove(&slot);
            objs::free(slot);
            e
        }
    }
}

/// `read`/`write`/`ioctl` on a test object.
fn object_io(cx: &Cx) -> i64 {
    let slot = cx.c.obj as u32;
    let Some(dev) = OBJECTS.lock().get(&slot).copied() else { return -9 };
    match cx.nr {
        0 => {
            let text = if dev != 0 { alloc::format!("svc-test dev {}:{} slot {}\n", (dev >> 8) & 0xFFF, dev & 0xFF, slot) } else { alloc::format!("svc-test {}\n", slot) };
            let n = text.len().min(cx.args[2] as usize);
            match cx.copy_out(cx.args[1], &text.as_bytes()[..n]) {
                Ok(()) => n as i64,
                Err(e) => e,
            }
        }
        1 => {
            let len = (cx.args[2] as usize).min(64);
            let data = match cx.copy_in(cx.args[1], len) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let mut ready = objs::ready(slot);
            for b in &data {
                match b {
                    b'r' => ready |= 0x41,
                    b'w' => ready |= 0x104,
                    b'c' => ready = 0,
                    _ => {}
                }
            }
            objs::set(slot, ready, 0);
            len as i64
        }
        _ => ENOTTY,
    }
}
