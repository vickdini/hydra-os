//! # lx-ipc: Linux IPC objects, a service of their own (wave 8, Group X2)
//!
//! Split out of linux-server (`docs/linux-services-design.md`, sections 2 and 9.3): Unix
//! sockets ([`unix`]), pipes and FIFOs ([`pipe`]), eventfd, timerfd, signalfd, pidfd, POSIX
//! message queues ([`mqueue`]) and System V messages and semaphores ([`sysv`]). The kernel
//! routes these calls here by number, by socket family (`AF_UNIX`) and by object (service id
//! `LXS_IPC`, endpoint [`ENDPOINT_LX_IPC`]); vfs-server redirects the open of a FIFO node
//! here. linux-server builds the same files and serves them when `lx.ipc=linux` puts them
//! back there; `lx.ipc=kernel` (or `lx=kernel`) sends them to the kernel's own copies.
//!
//! ## Restarts (Transparent, wave 9)
//!
//! When lx-ipc dies the supervisor starts it again and programs see only a pause: the
//! bytes in pipes and Unix sockets live in a kept data arena ([`arena`]), every pipe,
//! socket, connection, eventfd, timerfd and signalfd has a kept record ([`kstore`]), and
//! the new instance takes the old one's objects back before it goes online ([`restore`]);
//! waiting calls are sent again by the kernel. Message queues and System V tables are kept
//! too (each written whole at each change: they are small and rarely used). A second crash
//! within 30 s drops to FailObjects (the kept objects are dropped, the old objects fail:
//! the desktop session ends, `src/lx/desktop.rs`).

#![no_std]
#![no_main]

extern crate alloc;

// linux-server's small shared files (wave 8: one source)
#[path = "../../linux-server/src/client.rs"]
#[allow(unused_imports)]
mod client;
#[path = "../../linux-server/src/fdio.rs"]
mod fdio;
#[path = "../../linux-server/src/lock.rs"]
mod lock;
#[path = "../../linux-server/src/obj.rs"]
#[allow(dead_code)]
mod obj;
#[path = "../../linux-server/src/timeout.rs"]
#[allow(dead_code)]
mod timeout;

mod arena; // wave9 GX3
mod eventfd;
mod ipcsvc;
mod kstore; // wave9 GX3
mod mqueue;
#[path = "nlstub.rs"]
mod netlink;
mod pidfd;
mod pipe;
mod restore; // wave9 GX3
mod signalfd;
mod sysv;
mod timerfd;
mod unix;

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Event};
use hydra_rt::{println, sys, Message};

use crate::client::Cx;

hydra_rt::entry!(main);

/// This program's name (log lines of the shared files).
pub const NAME: &str = "lx-ipc";

const ENOSYS: i64 = -38;

fn main(args: &[&str]) {
    // With `lx.ipc=linux` (or `kernel`) no service id names this endpoint: nothing to serve
    // (exiting without registering: the supervisor does not restart it)
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[lx-ipc] no service id names endpoint {:#x}: not started (IPC objects are served elsewhere)", ENDPOINT_LX_IPC);
        sys::exit(0);
    }
    let cfg = svcrt::Config { name: "lx-ipc", endpoint: ENDPOINT_LX_IPC, workers: svcrt::workers_arg(args, 3), subscribe: Some(1 << LX_NOTE_EXIT) };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[lx-ipc] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    obj::init(svc.area, ENDPOINT_LX_IPC);
    // wave9 GX3: the kept objects, and the old instance's objects taken back
    let adopted = restore::start();
    restore::sweep(&adopted);
    if let Err(e) = svc.online() {
        println!("[lx-ipc] cannot go online: {}", e);
        sys::exit_group(1);
    }
    loop {
        timeout::update_clock();
        let now = sys::uptime_ticks();
        let wait = ipcsvc::tick(now).map_or(100, |d| d.saturating_sub(now).clamp(1, 100));
        match svc.recv(wait) {
            Event::Request(id, req) => {
                let reply = match req.label as u32 {
                    MSG_LX_PROC_NET_UNIX => proc_net_unix(svc.window()),
                    _ => Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0]),
                };
                svc.reply(id, &reply);
            }
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        ipcsvc::main_work(sys::uptime_ticks());
        obj::flush();
    }
}

/// One notification: process exits, signals for pending calls, last closes, timers.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_EXIT => ipcsvc::on_exit(a),
        LX_NOTE_INTERRUPT => {
            ipcsvc::interrupted(a);
        }
        LX_NOTE_CLOSE => obj::closed(a as u32, b as u32),
        LX_NOTE_TIMER => {
            ipcsvc::timer(a);
        }
        _ => {}
    }
}

/// The close hook of `obj.rs`: the last descriptor of one of our objects went.
pub fn on_closed(slot: u32, kind: u32) {
    ipcsvc::closed(slot, kind);
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = ipcsvc::dispatch(&cx).unwrap_or((ENOSYS, 0));
    obj::flush();
    r
}

/// `/proc/net/unix` (Group 13), into the window like `/proc/keys`.
fn proc_net_unix(win: &mut [u8]) -> Message {
    // Sockets closed before the reader asked are gone first (their ends may come in a
    // second round: a socket let go from a closed socket's queue)
    svcrt::notes::drain_all();
    unix::gc();
    svcrt::notes::drain_all();
    svcrt::notes::drain_all();
    let text = unix::proc_net_unix();
    let len = text.len().min(LX_PROC_KEYS_TEXT_MAX);
    win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len].copy_from_slice(&text.as_bytes()[..len]);
    Message::new(MSG_LX_REPLY as u64, [len as u64, 0, 0, 0])
}
