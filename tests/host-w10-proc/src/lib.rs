//! Group 7b-1's host build (wave 10): lx-proc's policy (`userland/drivers/lx-proc/src/
//! policy.rs`, with the kernel's `src/lx/proc_rules.rs` inside it) compiled from its own
//! source, run against [`Model`], a model of the kernel's op-75 primitives
//! (`src/lx/procsvc.rs`: the same sub-ops on a small process table), and [`Memory`], a
//! model of the caller's memory. The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (`LxProcIo`, the `LXP_*` sub-ops), as lx-proc sees it.
#[path = "../../../src/ipc/protocol.rs"]
#[allow(unused)]
pub mod protocol;

/// lx-proc's `proto` (in the service: `hydra_rt::protocol`).
pub mod proto {
    pub use crate::protocol::*;
}

/// The code under test.
#[path = "../../../userland/drivers/lx-proc/src/policy.rs"]
pub mod policy;

use std::cell::RefCell;
use std::collections::BTreeMap;

use proto::*;

const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EAGAIN: i64 = -11;

/// A thread of the model.
#[derive(Clone, Debug, Default)]
pub struct Thread {
    pub tgid: u64,
    pub uid: [u32; 3],
    pub gid: [u32; 3],
    pub eff: u64,
    pub perm: u64,
    pub keep: bool,
    pub userns: bool,
    pub nnp: bool,
    pub service: bool,
    pub comm: [u8; 16],
    pub pdeathsig: u64,
}

/// A process of the model.
#[derive(Clone, Debug)]
pub struct Proc {
    pub ppid: u64,
    pub pgid: u64,
    pub sid: u64,
    pub zombie: bool,
    pub groups: Vec<u32>,
    pub limits: [(u64, u64); 16],
    pub dumpable: u64,
    pub subreaper: bool,
    pub threads: u64,
    pub uts: (String, String),
}

/// The kernel as op 75 shows it.
#[derive(Default)]
pub struct Model {
    /// The request's caller thread.
    pub caller: u64,
    pub threads: BTreeMap<u64, Thread>,
    pub procs: BTreeMap<u64, Proc>,
    /// What `LXP_NS_FD` answers.
    pub ns_fd: Option<Result<(u64, u64), i64>>,
    /// What `LXP_NS_GET` answers, by process.
    pub ns: BTreeMap<u64, [u64; 13]>,
    /// `LXP_APPROVE`s: (thread, call).
    pub approved: Vec<(u64, u64)>,
    /// Compare-and-set sub-ops still to fail with `EAGAIN` (a race lost).
    pub races: u32,
    /// Sub-ops made, in order.
    pub ops: Vec<u64>,
}

/// The model behind the `Kernel` interface.
pub struct K(pub RefCell<Model>);

/// `CAP_*` bits.
pub const ALL_CAPS: u64 = (1 << 41) - 1;

impl Model {
    /// One process `pid` (its main thread `pid`) of user `uid`, root's capabilities when
    /// `uid` is 0; the caller.
    pub fn with(pid: u64, uid: u32) -> Model {
        let mut m = Model { caller: pid, ..Default::default() };
        m.add(pid, 1, uid);
        m
    }

    /// Adds process `pid` (parent `ppid`) of user `uid`, in its parent's group and session.
    pub fn add(&mut self, pid: u64, ppid: u64, uid: u32) {
        let caps = if uid == 0 { ALL_CAPS } else { 0 };
        let (pgid, sid) = self.procs.get(&ppid).map_or((1, 1), |p| (p.pgid, p.sid));
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"prog");
        self.threads.insert(pid, Thread { tgid: pid, uid: [uid; 3], gid: [uid; 3], eff: caps, perm: caps, comm, ..Default::default() });
        self.procs.insert(
            pid,
            Proc { ppid, pgid, sid, zombie: false, groups: vec![], limits: [(1024, 4096); 16], dumpable: 1, subreaper: false, threads: 1, uts: ("hydra".into(), "localdomain".into()) },
        );
    }

    fn race(&mut self) -> bool {
        if self.races > 0 {
            self.races -= 1;
            true
        } else {
            false
        }
    }
}

impl policy::Kernel for K {
    fn op(&self, sub: u64, io: &mut LxProcIo) -> i64 {
        let mut m = self.0.borrow_mut();
        m.ops.push(sub);
        let a = io.a;
        let caller = m.caller;
        let me = m.threads[&caller].tgid;
        let thread = |v: u64| if v == 0 { caller } else { v };
        let process = |v: u64| if v == 0 { me } else { v };
        match sub {
            LXP_TASK_GET => {
                let tid = thread(a[0]);
                let Some(t) = m.threads.get(&tid).cloned() else { return ESRCH };
                let p = m.procs[&t.tgid].clone();
                let mut flags = 0;
                flags |= if t.keep { LXP_F_KEEPCAPS } else { 0 };
                flags |= if t.userns { LXP_F_USERNS } else { 0 };
                flags |= if t.nnp { LXP_F_NNP } else { 0 };
                flags |= if t.service { LXP_F_SERVICE } else { 0 };
                flags |= if p.subreaper { LXP_F_SUBREAPER } else { 0 };
                io.a = [tid, t.tgid, t.uid[0] as u64, t.uid[1] as u64, t.uid[2] as u64, t.gid[0] as u64, t.gid[1] as u64, t.gid[2] as u64, t.eff, t.perm, flags, p.dumpable, t.pdeathsig, p.threads, p.groups.len() as u64, 0];
                io.b = [0; 256];
                io.b[..16].copy_from_slice(&t.comm);
                0
            }
            LXP_CREDS_SET => {
                let tid = thread(a[0]);
                let Some(t) = m.threads.get_mut(&tid) else { return ESRCH };
                t.uid = [a[1] as u32, a[2] as u32, a[3] as u32];
                t.gid = [a[4] as u32, a[5] as u32, a[6] as u32];
                0
            }
            LXP_GROUPS_SET => {
                let n = a[2] as usize;
                // SAFETY: the policy passes its own vector's pointer and length
                let g = if n == 0 { vec![] } else { unsafe { std::slice::from_raw_parts(a[1] as *const u32, n) }.to_vec() };
                let pid = process(a[0]);
                match m.procs.get_mut(&pid) {
                    Some(p) => {
                        p.groups = g;
                        0
                    }
                    None => ESRCH,
                }
            }
            LXP_PGRP_GET => {
                let pid = process(a[0]);
                let Some(p) = m.procs.get(&pid) else { return ESRCH };
                let used = m.procs.iter().any(|(&q, r)| r.pgid == pid && q != pid);
                io.a[..6].copy_from_slice(&[pid, p.ppid, p.pgid, p.sid, p.zombie as u64, used as u64]);
                0
            }
            LXP_PGRP_SET => {
                if m.race() {
                    return EAGAIN;
                }
                let pid = a[0];
                let used = m.procs.iter().any(|(&q, r)| r.pgid == pid && q != pid);
                let Some(p) = m.procs.get_mut(&pid) else { return ESRCH };
                if (p.pgid, p.sid) != (a[1], a[2]) {
                    return EAGAIN;
                }
                if a[5] == 1 && used {
                    return -1;
                }
                p.pgid = a[3];
                if a[4] == 1 {
                    p.sid = pid;
                }
                0
            }
            LXP_LIMIT_GET => {
                if a[1] >= 16 {
                    return EINVAL;
                }
                let Some(p) = m.procs.get(&process(a[0])) else { return ESRCH };
                let l = p.limits[a[1] as usize];
                io.a[..3].copy_from_slice(&[l.0, l.1, 1024]);
                0
            }
            LXP_LIMIT_SET => {
                if m.race() {
                    return EAGAIN;
                }
                let Some(p) = m.procs.get_mut(&process(a[0])) else { return ESRCH };
                let l = &mut p.limits[a[1] as usize];
                if *l != (a[2], a[3]) {
                    return EAGAIN;
                }
                *l = (a[4], a[5]);
                0
            }
            LXP_ATTR_SET => {
                let tid = thread(a[0]);
                let tgid = m.threads[&tid].tgid;
                match a[1] {
                    LXP_ATTR_COMM => {
                        let mut c = [0u8; 16];
                        c[..15].copy_from_slice(&io.b[..15]);
                        m.threads.get_mut(&tid).unwrap().comm = c;
                    }
                    LXP_ATTR_DUMPABLE => m.procs.get_mut(&tgid).unwrap().dumpable = a[2],
                    LXP_ATTR_PDEATHSIG => m.threads.get_mut(&tid).unwrap().pdeathsig = a[2],
                    LXP_ATTR_SUBREAPER => m.procs.get_mut(&tgid).unwrap().subreaper = a[2] != 0,
                    LXP_ATTR_KEEPCAPS => m.threads.get_mut(&tid).unwrap().keep = a[2] != 0,
                    LXP_ATTR_NNP => m.threads.get_mut(&tid).unwrap().nnp = true,
                    _ => return EINVAL,
                }
                0
            }
            LXP_NS_FD => match m.ns_fd {
                Some(Ok((p, k))) => {
                    io.a[0] = p;
                    io.a[1] = k;
                    0
                }
                Some(Err(e)) => e,
                None => -9,
            },
            LXP_NS_GET => match m.ns.get(&process(a[0])) {
                Some(f) => {
                    io.a[..13].copy_from_slice(f);
                    0
                }
                None => ESRCH,
            },
            LXP_PID_GET => {
                if m.procs.get(&a[0]).is_some_and(|p| !p.zombie) {
                    io.a[0] = a[0];
                    0
                } else {
                    ESRCH
                }
            }
            LXP_UTS_GET => {
                let (h, d) = m.procs[&me].uts.clone();
                io.b = [0; 256];
                io.b[..h.len()].copy_from_slice(h.as_bytes());
                io.b[65..65 + d.len()].copy_from_slice(d.as_bytes());
                0
            }
            LXP_UTS_SET => {
                let v = String::from_utf8_lossy(&io.b[..a[1] as usize]).into_owned();
                let p = m.procs.get_mut(&me).unwrap();
                if a[0] == 1 {
                    p.uts.1 = v;
                } else {
                    p.uts.0 = v;
                }
                0
            }
            LXP_APPROVE => {
                m.approved.push((caller, a[0]));
                0
            }
            _ => EINVAL,
        }
    }
}

/// The caller's memory: readable regions, and what was written.
#[derive(Default)]
pub struct Memory {
    pub regions: BTreeMap<u64, Vec<u8>>,
    pub written: RefCell<BTreeMap<u64, Vec<u8>>>,
    /// Addresses at which writes fault.
    pub bad_out: Vec<u64>,
}

impl Memory {
    /// Memory with `data` at `addr`.
    pub fn with(addr: u64, data: &[u8]) -> Memory {
        let mut m = Memory::default();
        m.regions.insert(addr, data.to_vec());
        m
    }
}

impl policy::Mem for Memory {
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        for (&base, v) in &self.regions {
            if ptr >= base && ptr + len as u64 <= base + v.len() as u64 {
                let o = (ptr - base) as usize;
                return Ok(v[o..o + len].to_vec());
            }
        }
        Err(EFAULT)
    }
    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 || self.bad_out.contains(&ptr) {
            return Err(EFAULT);
        }
        self.written.borrow_mut().insert(ptr, data.to_vec());
        Ok(())
    }
    fn cstr(&self, ptr: u64) -> Result<Vec<u8>, i64> {
        for (&base, v) in &self.regions {
            if ptr >= base && ptr < base + v.len() as u64 {
                let o = (ptr - base) as usize;
                return match v[o..].iter().position(|&c| c == 0) {
                    Some(n) => Ok(v[o..o + n].to_vec()),
                    None => Err(EFAULT),
                };
            }
        }
        Err(EFAULT)
    }
}

#[cfg(test)]
mod tests;
