//! # lx-proc: the Linux process service (wave 10, Group 7b-1)
//!
//! The *policy* of process identity as a service of its own (`docs/linux-services-design.md`
//! sections 2.1-2.3; decision 11): who may change their user and group ids, groups,
//! process group and session, resource limits, `prctl` attributes, namespaces and UTS
//! names, and who may read the kernel log or turn accounting on. The *data* stay in the
//! kernel (credentials, the process table, limits, namespace ids, UTS names, the log ring):
//! lx-proc reads them and changes them only through the kernel's primitives (`SYS_LX_OBJ`
//! op 75, `LX_OBJ_PROCID`, `src/lx/procsvc.rs`).
//!
//! The kernel routes these calls here by number (service id `LXS_PROC`, endpoint
//! [`ENDPOINT_LX_PROC`]): setuid, setgid, setreuid, setregid, setresuid, setresgid,
//! setfsuid, setfsgid, setgroups, setpgid, getpgid, setsid, getsid, setrlimit, prlimit64,
//! prctl, unshare, setns, sethostname, setdomainname, syslog, acct (and `uname` when
//! routed here; the kernel answers it itself: a read). The rules are in
//! [`policy`] (pure, host-tested), the kernel's wave 9 rules among them (`proc_rules.rs`,
//! one copy for both). `lx.proc=kernel` (or `lx=kernel`) sends the calls back to the
//! kernel's own copy until 10-C deletes it.
//!
//! ## Restarts
//!
//! lx-proc keeps nothing (every datum is the kernel's), so it restarts invisibly
//! (Transparent): calls made during the gap wait for the new instance, and a call cut by
//! the crash is sent again when making it twice gives the same result (the kernel's
//! `restart_policy::idempotent` lists them), otherwise it fails with `EIO`.

#![no_std]
#![no_main]

extern crate alloc;

mod policy;

/// The protocol's names (the kernel's `ipc/protocol.rs`).
pub mod proto {
    pub use hydra_rt::protocol::*;
}

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

use policy::{Call, Kernel, Mem, Out};

hydra_rt::entry!(main);

const ENOSYS: i64 = -38;

fn main(args: &[&str]) {
    // Switched back (`lx.proc=kernel`, `lx=kernel`): the supervisor does not start it; if it
    // runs anyway, nothing names its endpoint and it ends
    if sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[lx-proc] no service id names endpoint {:#x}: not started (process calls are the kernel's)", ENDPOINT_LX_PROC);
        sys::exit(0);
    }
    let cfg = svcrt::Config { name: "lx-proc", endpoint: ENDPOINT_LX_PROC, workers: svcrt::workers_arg(args, 2), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[lx-proc] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    if let Err(e) = svc.online() {
        println!("[lx-proc] cannot go online: {}", e);
        sys::exit_group(1);
    }
    println!("[lx-proc] online (endpoint {:#x}, {} workers)", ENDPOINT_LX_PROC, cfg.workers);
    loop {
        match svc.recv(100) {
            Event::Request(id, _req) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
    }
}

/// The kernel's primitives for the request being served.
struct Sys {
    req: u64,
}

impl Kernel for Sys {
    fn op(&self, sub: u64, io: &mut LxProcIo) -> i64 {
        match sys::lx_obj(LX_OBJ_PROCID, self.req, sub, io as *mut LxProcIo as u64) {
            Ok(v) => v as i64,
            Err(e) => e,
        }
    }
}

/// The caller's memory, through the call being served.
struct CallerMem<'a>(&'a Cx);

impl Mem for CallerMem<'_> {
    fn copy_in(&self, ptr: u64, len: usize) -> Result<alloc::vec::Vec<u8>, i64> {
        self.0.copy_in(ptr, len)
    }
    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        self.0.copy_out(ptr, data)
    }
    fn cstr(&self, ptr: u64) -> Result<alloc::vec::Vec<u8>, i64> {
        self.0.user_cstr(ptr)
    }
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    let cx = Cx::from_call(c, page);
    let call = Call { nr: c.nr, args: c.args, tgid: c.tgid, caps: c.caps };
    match policy::serve(&Sys { req: c.id }, &CallerMem(&cx), &call) {
        Out::Ret(r) => (r, 0),
        // The kernel's own code answers (service 0)
        Out::Kernel => svcrt::redirect(page, 0, 0, 0),
    }
}
