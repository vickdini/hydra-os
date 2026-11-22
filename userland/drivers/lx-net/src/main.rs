//! # lx-net: Linux network sockets, a service of their own (wave 8, Group X2)
//!
//! Split out of linux-server (`docs/linux-services-design.md`, sections 2 and 9.3):
//! `AF_INET` and `AF_INET6` sockets as net-server's client ([`inet`], [`sockopt`], [`netc`]),
//! `AF_NETLINK` routing and uevent sockets ([`netlink`]), blocked calls and readiness
//! ([`socket`]). The kernel routes these calls here by socket family and by object (service
//! id `LXS_NET`, endpoint [`ENDPOINT_LX_NET`]). linux-server builds the same files and serves
//! them when `lx.net=linux` puts them back there; `lx.net=kernel` (or `lx=kernel`) sends them
//! to the kernel's own copies.
//!
//! ## Restarts (Transparent)
//!
//! net-server holds the connections; lx-net holds only what each socket is. Every socket
//! keeps a record in the service's kept-state object ([`sockkept`]: its net-server handles,
//! addresses, flags, options), written before the answer of a call that changed it. When
//! lx-net dies, calls to it wait (the kernel's Transparent class); the new instance takes
//! the kernel's list of its live objects (`LX_SVC_LIST`), rebuilds each socket from its
//! record, adopts them (`LX_SVC_ADOPT`), closes in net-server only the handles nobody
//! adopted, and goes online: a download or an ssh session goes on after a pause. A second
//! crash within 30 s resets the kept state (the restart ladder): the sockets then fail
//! (FailObjects) and their handles are closed.

#![no_std]
#![no_main]

extern crate alloc;

// linux-server's small shared files (wave 8: one source)
#[path = "../../linux-server/src/client.rs"]
#[allow(unused_imports)]
mod client;
#[path = "../../linux-server/src/lock.rs"]
mod lock;
#[path = "../../linux-server/src/obj.rs"]
#[allow(dead_code)]
mod obj;
#[path = "../../linux-server/src/timeout.rs"]
#[allow(dead_code)]
mod timeout;

mod inet;
#[allow(dead_code)] // (ping_rtt: linux-server's test call)
mod netc;
#[allow(dead_code)] // (pin/deliver: message queues co-located in linux-server)
mod netlink;
mod netsvc;
mod socket;
mod sockkept;
mod sockopt;

use alloc::vec::Vec;

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Event};
use hydra_rt::{println, sys, Message};

use crate::client::Cx;

hydra_rt::entry!(main);

/// This program's name (log lines of the shared files).
pub const NAME: &str = "lx-net";

const ENOSYS: i64 = -38;

fn main(args: &[&str]) {
    // With `lx.net=linux` (or `kernel`) no service id names this endpoint: nothing to serve
    // (exiting without registering: the supervisor does not restart it)
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[lx-net] no service id names endpoint {:#x}: not started (sockets are served elsewhere)", ENDPOINT_LX_NET);
        sys::exit(0);
    }
    netc::set_tag(NETS_CLIENT_LXNET);
    let cfg = svcrt::Config { name: "lx-net", endpoint: ENDPOINT_LX_NET, workers: svcrt::workers_arg(args, 2), subscribe: Some(1 << LX_NOTE_EXIT) };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[lx-net] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    obj::init(svc.area, ENDPOINT_LX_NET);
    // The previous instance's sockets, before the first call comes (or a clean start)
    restore();
    if let Err(e) = svc.online() {
        println!("[lx-net] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // net-server's events missed while we were away: every socket's readiness again
    netsvc::main_work(NOTIFY_LX_NET);
    let mut bits = 0;
    loop {
        timeout::update_clock();
        let now = sys::uptime_ticks();
        let wait = netsvc::tick(now).map_or(100, |d| d.saturating_sub(now).clamp(1, 100));
        match svc.recv(wait) {
            Event::Request(id, req) => {
                let reply = match req.label as u32 {
                    MSG_LX_PROC_NET => proc_net(svc.window(), &req),
                    _ => Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0]),
                };
                svc.reply(id, &reply);
            }
            Event::Notify(b) => bits |= b,
            Event::Idle => {}
        }
        svcrt::notes::drain_all();
        netsvc::main_work(core::mem::take(&mut bits));
        obj::flush();
    }
}

/// Maps the kept state and takes back the previous instance's sockets (a Transparent
/// restart), or starts clean: every handle a previous instance left in net-server closed.
fn restore() {
    let size = sockkept::SIZE;
    let adopted = match sys::lx_svc_kept(size) {
        // SAFETY: the kernel mapped the object for this process's life
        Ok(p) => {
            let a = unsafe { sockkept::open(p, size) };
            if a.bad_records > 0 {
                println!("[lx-net] kept state: {} damaged records dropped", a.bad_records);
            }
            adopt()
        }
        Err(e) => {
            println!("[lx-net] no kept-state object ({}): sockets will not survive a restart", e);
            None
        }
    };
    match adopted {
        Some((n, dead)) => {
            let keep = inet::kept_handles();
            let closed = netc::reset_keep(&keep);
            println!("[lx-net] restarted: {} sockets taken back, {} not ({} net-server handles kept, {} closed)", n, dead, keep.len(), closed);
        }
        None => {
            sockkept::keep_only(&[]);
            netc::reset();
        }
    }
}

/// The kernel's list of this service's live objects, rebuilt from their records and
/// adopted: `Some((taken back, marked dead))`, `None` when there is nothing to adopt (a
/// first start, or a restart that is not Transparent: the kernel made them stale).
fn adopt() -> Option<(usize, usize)> {
    let mut found: Vec<LxSvcObj> = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut start = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, start) {
        if n == 0 {
            break;
        }
        found.extend_from_slice(&buf[..n]);
        start = buf[n - 1].slot + 1;
    }
    if found.is_empty() {
        return None;
    }
    // Which objects their records still describe (the others go stale)
    let mut good: Vec<(u32, u32, u32)> = Vec::new();
    let mut dead = 0;
    for o in &found {
        let rec = o.key as u32;
        let ok = o.key <= u32::MAX as u64
            && match (o.kind, sockkept::get(rec)) {
                (LX_OBJ_KIND_INET, Some(d)) => inet::kept_ok(&d),
                (LX_OBJ_KIND_NETLINK, Some(d)) => netlink::kept_ok(&d),
                _ => false,
            };
        if ok {
            good.push((o.slot, o.kind, rec));
        } else {
            let _ = sys::lx_svc_dead(o.slot);
            dead += 1;
        }
    }
    if sys::lx_svc_adopt().is_err() {
        return None;
    }
    let mut n = 0;
    let mut recs = Vec::new();
    for &(slot, kind, rec) in &good {
        let ok = if kind == LX_OBJ_KIND_INET { inet::restore(slot, rec) } else { netlink::restore(slot, rec) };
        if ok {
            n += 1;
            recs.push(rec);
        } else {
            dead += 1;
        }
    }
    // Records of sockets closed meanwhile (or not taken back) go
    sockkept::keep_only(&recs);
    Some((n, dead))
}

/// One notification: process exits, signals for pending calls, last closes.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_EXIT => netsvc::on_exit(a),
        LX_NOTE_INTERRUPT => {
            netsvc::interrupted(a);
        }
        LX_NOTE_CLOSE => obj::closed(a as u32, b as u32),
        _ => {}
    }
}

/// The close hook of `obj.rs`: the last descriptor of one of our objects went.
pub fn on_closed(slot: u32, kind: u32) {
    netsvc::closed(slot, kind);
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = netsvc::dispatch(&cx).unwrap_or((ENOSYS, 0));
    obj::flush();
    r
}

/// `/proc/net/tcp`, `tcp6`, `udp`, `udp6` (see [`MSG_LX_PROC_NET`]).
fn proc_net(win: &mut [u8], req: &Message) -> Message {
    svcrt::notes::drain_all();
    let text = inet::proc_net(req.args[0], req.args[1] != 0);
    let len = text.len().min(LX_PROC_KEYS_TEXT_MAX);
    win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len].copy_from_slice(&text.as_bytes()[..len]);
    Message::new(MSG_LX_REPLY as u64, [len as u64, 0, 0, 0])
}
