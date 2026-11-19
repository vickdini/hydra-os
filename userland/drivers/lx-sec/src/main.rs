//! # lx-sec: the Linux key retention service and bpf, a service of their own (wave 6)
//!
//! The first piece split out of linux-server (`docs/linux-services-design.md`, step X1):
//! `add_key`, `request_key`, `keyctl` and `/proc/keys` ([`keys`]), and `bpf` ([`bpf`]). The
//! kernel routes these calls here by number (service id `LXS_SEC`, endpoint
//! [`ENDPOINT_LX_SEC`]) and calls on bpf descriptors by their owner. The same `keys.rs` and
//! `bpf.rs` also build into linux-server, which serves them when `lx.sec=linux` puts them
//! back there.
//!
//! ## Restarts
//!
//! When lx-sec dies the supervisor starts it again, and no program ends:
//! - **keys restart invisibly.** Every change of the key table is written to the service's
//!   kept-state object ([`kept`]) before the answer leaves the worker; a new instance reads
//!   the keyrings back (dropping the anchors of processes that ended meanwhile). Key calls
//!   made during the gap wait for the new instance (the kernel's Transparent class).
//! - **bpf objects fail** (FailObjects): maps, programs and links of the old instance are
//!   gone and their descriptors fail `EBADF`. The device programs the kernel was handed are
//!   kept, attached again and handed over again, so device control does not lapse.

#![no_std]
#![no_main]

extern crate alloc;

mod bpf;
mod client;
mod kept;
mod keys;
mod lock;
mod obj;

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

use crate::client::Caller;

hydra_rt::entry!(main);

const ENOSYS: i64 = -38;

fn main(args: &[&str]) {
    // With `lx.sec=linux` (or `kernel`) no service id names this endpoint: nothing to serve
    // (exiting without registering: the supervisor does not restart it)
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[lx-sec] no service id names endpoint {:#x}: not started (keys and bpf are served elsewhere)", ENDPOINT_LX_SEC);
        sys::exit(0);
    }
    let cfg = svcrt::Config {
        name: "lx-sec",
        endpoint: ENDPOINT_LX_SEC,
        workers: svcrt::workers_arg(args, 2),
        subscribe: Some(1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT),
    };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[lx-sec] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    svcrt::objs::init(svc.area, ENDPOINT_LX_SEC);
    // What the previous instance kept: the keyrings before the first call comes
    let keys = restore();
    if let Err(e) = svc.online() {
        println!("[lx-sec] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // ... and the device programs the kernel held, handed over again right after going
    // online (going online without adopting objects ends the old instance's list)
    let devices = if kept::get().is_some() { bpf::restore_devices() } else { 0 };
    if keys + devices > 0 {
        println!("[lx-sec] restarted: {} keys and {} device programs kept", keys, devices);
    }
    loop {
        match svc.recv(100) {
            Event::Request(id, req) => {
                let reply = match req.label as u32 {
                    MSG_LX_PROC_KEYS => proc_keys(svc.window(), &req),
                    _ => Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0]),
                };
                svc.reply(id, &reply);
            }
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        svcrt::objs::flush();
    }
}

/// Maps the kept-state object and takes back the keyrings it holds (their number).
fn restore() -> usize {
    let Some((base, size)) = kept_object() else { return 0 };
    // SAFETY: the kernel mapped the object for this process's life
    match unsafe { kept::Kept::open(base, size) } {
        Some(k) => kept::set(k),
        None => {
            println!("[lx-sec] kept-state object too small ({} bytes, {} needed)", size, kept::SIZE);
            return 0;
        }
    }
    keys::restore()
}

/// The kept-state object (`LX_SVC_KEPT`: zeroed the first time, the same memory for every
/// later instance until the restart ladder resets it): `(address, size)`.
fn kept_object() -> Option<(*mut u8, usize)> {
    let size = (kept::SIZE + 0xFFF) & !0xFFF;
    match sys::lx_svc_kept(size) {
        Ok(p) => Some((p, size)),
        Err(e) => {
            println!("[lx-sec] no kept-state object ({}): keys will not survive a restart", e);
            None
        }
    }
}

/// One notification: process events for the keyrings, last closes of bpf descriptors.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_FORK => keys::on_fork(a, b),
        LX_NOTE_EXEC => keys::on_exec(a, b),
        LX_NOTE_EXIT => keys::on_exit(a),
        LX_NOTE_CLOSE => obj::closed(a as u32, b as u32),
        _ => {}
    }
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        248..=250 => keys::dispatch(&cx).unwrap_or(ENOSYS),
        321 => bpf::sys_bpf(&cx),
        _ => ENOSYS,
    };
    svcrt::objs::flush();
    (r, 0)
}

/// `/proc/keys` for the caller the kernel describes (`MSG_LX_PROC_KEYS`: its groups in the
/// window, the text back into it).
fn proc_keys(win: &mut [u8], req: &Message) -> Message {
    let o = LX_PROC_KEYS_GROUPS_OFF;
    let n = (u32::from_le_bytes([win[o], win[o + 1], win[o + 2], win[o + 3]]) as usize).min(LX_GROUPS);
    let mut groups = [0u32; LX_GROUPS];
    for (i, g) in groups[..n].iter_mut().enumerate() {
        let p = o + 4 + i * 4;
        *g = u32::from_le_bytes([win[p], win[p + 1], win[p + 2], win[p + 3]]);
    }
    let a = req.args;
    let caller = Caller::new(a[0], a[1], a[2] as u32, (a[2] >> 32) as u32, a[3], &groups[..n]);
    // The calls made before this request count (as for a forwarded call)
    svcrt::notes::drain_all();
    let text = keys::proc_keys(&caller);
    let len = text.len().min(LX_PROC_KEYS_TEXT_MAX);
    win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len].copy_from_slice(&text.as_bytes()[..len]);
    Message::new(MSG_LX_REPLY as u64, [len as u64, 0, 0, 0])
}
