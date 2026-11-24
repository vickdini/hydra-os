//! *stub* `crate::lx`: the forwarding to the ring-3 Linux server. Calls are recorded and
//! answered with what the test set.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::cell::{Cell, RefCell};

use crate::compat::linux::chardev::CharDevice;

// wave10 G8-1 begin: the tracing calls' rule (real) and a *stub* of the kernel's half
// (`src/lx/trace.rs`): the facts from the fake tasks (the caller, the pidfd's process),
// decided by the real `decide`
#[path = "../../../../src/lx/ptrace_rules.rs"]
pub mod ptrace_rules;
pub mod trace {
    use super::ptrace_rules::*;
    fn ids(t: &crate::task::Task) -> ([u32; 3], [u32; 3]) {
        ([t.uid, t.euid, t.suid], [t.gid, t.egid, t.sgid])
    }
    pub fn check(nr: u64, a: &[u64; 6], _extra: u32) -> Result<(), i64> {
        let (uid, gid, caps, me) = crate::task::with_current_task_mut(|t| {
            let (u, g) = ids(t);
            (u, g, t.caps.effective, t.tgid)
        })
        .ok_or(ESRCH)?;
        let who = Who { uid, gid, caps, perm: caps, in_userns: false, seccomp: false, suspended: false };
        let pid = match nr {
            NR_PIDFD_GETFD => crate::compat::linux::pidfd::pid_of(a[0])?,
            _ => a[0],
        };
        let t = crate::task::SCHEDULER.lock().with_process(pid, |t| {
            let (u, g) = ids(t);
            Target { tgid: t.tgid, tid: t.tgid, uid: u, gid: g, same: t.tgid == me, service: t.service.is_some(), within: true, same_ns: true, owned: false, tracer_cap: false, dumpable: 1, perm: t.caps.effective }
        });
        decide(&Facts { nr, who, t: [t, None], ..Facts::default() })
    }
}
// wave10 G8-1 end

/// *stub* wave8 GT: `crate::lx::console` (the terminals are never tty-server's here, so
/// the in-kernel copies run; the rest is never reached).
pub mod console {
    pub fn forwarded() -> bool {
        false
    }
    pub fn attach(_sid: u64, _pgrp: u64) {}
    pub fn detach() {}
    pub fn attached() -> bool {
        false
    }
    pub fn readable() -> bool {
        false
    }
    pub fn read(_buf: u64, _len: usize, _nonblock: bool) -> i64 {
        -5
    }
    pub fn write(_buf: u64, len: usize) -> i64 {
        len as i64
    }
    pub fn ioctl(_request: u64, _arg: u64) -> i64 {
        -25
    }
    pub fn open_pty<T>(_abs: &str, _flags: u32) -> Option<Result<T, i64>> {
        None
    }
    pub fn pty_stat(_index: u64) -> Result<(u32, u32, u32), i64> {
        Err(-2)
    }
    pub fn pty_setattr(_index: u64, _mode: Option<u32>, _uid: Option<u32>, _gid: Option<u32>) -> i64 {
        -2
    }
    pub fn hangup(_sid: u64) -> Option<(u64, u64)> {
        None
    }
}

thread_local! {
    pub static STEP4: Cell<bool> = const { Cell::new(false) };
    /// Calls forwarded: (call number, arguments).
    pub static CALLS: RefCell<Vec<(u64, [u64; 6])>> = const { RefCell::new(Vec::new()) };
    /// What forwarded calls return.
    pub static ANSWER: Cell<i64> = const { Cell::new(0) };
    pub static NET_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
    pub static UNIX_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
    pub static KEYS_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn reset() {
    STEP4.set(false);
    CALLS.with_borrow_mut(|c| c.clear());
    ANSWER.set(0);
    NET_TEXT.with_borrow_mut(|t| *t = None);
    UNIX_TEXT.with_borrow_mut(|t| *t = None);
    KEYS_TEXT.with_borrow_mut(|t| *t = None);
}

/// The calls forwarded so far.
pub fn calls() -> Vec<(u64, [u64; 6])> {
    CALLS.with_borrow(|c| c.clone())
}

pub fn step4() -> bool {
    STEP4.get()
}

pub fn call_obj(nr: u64, args: [u64; 6], _dev: &Arc<dyn CharDevice>) -> i64 {
    CALLS.with_borrow_mut(|c| c.push((nr, args)));
    ANSWER.get()
}

pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    CALLS.with_borrow_mut(|c| c.push((nr, args)));
    ANSWER.get()
}

pub fn proc_net_text(_file: &str) -> Option<String> {
    NET_TEXT.with_borrow(|t| t.clone())
}

pub fn proc_net_unix_text() -> Option<String> {
    UNIX_TEXT.with_borrow(|t| t.clone())
}

pub fn proc_keys_text() -> Option<String> {
    KEYS_TEXT.with_borrow(|t| t.clone())
}

pub mod obj {
    /// *stub* A linux-server object: its kind, tag and slot are what the test made it with.
    pub struct ServerObject {
        pub kind: u32,
        pub tag: u64,
        pub slot: Option<u64>,
    }
    impl ServerObject {
        pub fn kind(&self) -> u32 {
            self.kind
        }
        pub fn tag(&self) -> u64 {
            self.tag
        }
        pub fn slot(&self) -> Option<u64> {
            self.slot
        }
    }
}

// wave9 G7a begin
/// *stub* `crate::lx::proc` (the kernel's process-identity primitives, `src/lx/proc.rs`,
/// tested in host-t29): the tree from the fake process table.
pub mod proc {
    use crate::compat::linux::proc::PROCS;
    /// *stub* wave10 G7b-1: no PR_SET_NAME names on the host: the executable's.
    pub fn comm_or_exe(_tid: u64, exe: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        let name = exe.rsplit('/').next().unwrap_or("").as_bytes();
        let n = name.len().min(15);
        out[..n].copy_from_slice(&name[..n]);
        out
    }
    /// *stub* wave10 G7b-2: prctl's dumpable flag (every process is dumpable on the host).
    pub struct ProcAttrs {
        pub dumpable: u8,
    }
    pub fn proc_attrs(_tgid: u64) -> ProcAttrs {
        ProcAttrs { dumpable: 1 }
    }
    /// *mirror* of the kernel's.
    pub struct Tree {
        pub ppid: u64,
        pub pgid: u64,
        pub sid: u64,
        pub threads: u64,
        pub start: u64,
        pub zombie: bool,
        pub pid_inits: alloc::vec::Vec<u64>,
    }
    pub fn task_tree(pid: u64) -> Option<Tree> {
        PROCS.lock().get(&pid).map(|p| Tree {
            ppid: p.ppid,
            pgid: p.pgid,
            sid: p.sid,
            threads: p.threads_alive().max(1) as u64,
            start: p.start_time,
            zombie: p.zombie,
            pid_inits: alloc::vec::Vec::new(),
        })
    }
}
// wave9 G7a end
