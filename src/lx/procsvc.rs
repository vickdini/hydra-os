//! # lx-proc's primitives: `SYS_LX_OBJ` op 75, `LX_OBJ_PROCID` (wave 10, Group 7b-1)
//!
//! lx-proc (`userland/drivers/lx-proc`) decides the process-identity calls (the setuid
//! family, `setgroups`, `setpgid`/`setsid`, limits, `prctl`, `unshare`/`setns`, UTS names,
//! `syslog`, `acct`); the data stay in the kernel (decision 11). This is its way in: one
//! sub-op per primitive of [`super::proc`] (and of the namespace and UTS code), run for the
//! caller of one of lx-proc's own requests, with an [`LxProcIo`] in lx-proc's memory. The
//! kernel decides nothing here.
//!
//! Only the host of `LXS_PROC` while lx-proc is its own process may ask, and only naming a
//! request it is serving (whose caller is "the caller" of every sub-op).

use crate::ipc::protocol::*;
use crate::task::TaskId;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINVAL: i64 = -22;

/// `SYS_LX_OBJ(LX_OBJ_PROCID, req, sub, io)` from host `h`.
pub fn ctl(h: SvcId, req: u64, sub: u64, io: u64) -> i64 {
    if h == 0 || h != super::svc::host_of(LXS_PROC) || super::svc::endpoint_of(LXS_PROC) != ENDPOINT_LX_PROC {
        return EPERM;
    }
    if lx_req_svc(req) != h {
        return ESRCH;
    }
    let Some(client) = super::client_of(req) else { return ESRCH };
    let Some(tgid) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.tgid) else { return ESRCH };
    // Only the words travel, unless the sub-op reads or writes the bytes too (the copies are
    // most of a sub-op's cost)
    let words = core::mem::size_of::<[u64; 16]>();
    let (bytes_in, bytes_out) = match sub {
        LXP_ATTR_SET | LXP_UTS_SET => (true, false),
        LXP_TASK_GET | LXP_UTS_GET => (false, true),
        _ => (false, false),
    };
    let mut x = LxProcIo::EMPTY;
    let size_in = if bytes_in { core::mem::size_of::<LxProcIo>() } else { words };
    // SAFETY: a plain repr(C) struct of integers: any bytes are a valid value
    if let Err(e) = super::copy::read_user(io, unsafe { core::slice::from_raw_parts_mut(&mut x as *mut LxProcIo as *mut u8, size_in) }) {
        return e;
    }
    let r = run(client, tgid, sub, &mut x);
    if r >= 0 {
        let size_out = if bytes_out { core::mem::size_of::<LxProcIo>() } else { words };
        // SAFETY: as above, read as its bytes
        if let Err(e) = super::copy::write_user(io, unsafe { core::slice::from_raw_parts(&x as *const LxProcIo as *const u8, size_out) }) {
            return e;
        }
    }
    r
}

/// Thread `tid`'s process.
fn tgid_of_thread(tid: u64) -> Option<u64> {
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| t.tgid)
}

/// Sub-op `sub` for thread `client` of process `tgid` (the request's caller).
fn run(client: u64, tgid: u64, sub: u64, x: &mut LxProcIo) -> i64 {
    use super::proc as mech;
    let a = x.a;
    // 0 names the caller's thread or process
    let thread = |v: u64| if v == 0 { client } else { v };
    let process = |v: u64| if v == 0 { tgid } else { v };
    match sub {
        LXP_TASK_GET => task_get(thread(a[0]), a[1] == 1, x),
        LXP_CREDS_SET => {
            let c = mech::Creds { uid: [a[1] as u32, a[2] as u32, a[3] as u32], gid: [a[4] as u32, a[5] as u32, a[6] as u32] };
            if !mech::task_creds_set(thread(a[0]), c) {
                return ESRCH;
            }
            crate::compat::linux::ident_changed();
            0
        }
        LXP_GROUPS_GET => {
            let Some(groups) = crate::compat::linux::proc::PROCS.lock().get(&process(a[0])).map(|p| p.groups.clone()) else { return ESRCH };
            if groups.len() as u64 > a[2] {
                return EINVAL;
            }
            let bytes: alloc::vec::Vec<u8> = groups.iter().flat_map(|g| g.to_le_bytes()).collect();
            if !bytes.is_empty() {
                if let Err(e) = crate::compat::linux::vfs::copy_out(a[1], &bytes) {
                    return e;
                }
            }
            groups.len() as i64
        }
        LXP_GROUPS_SET => {
            if a[2] > 65536 {
                return EINVAL;
            }
            let bytes = if a[2] == 0 {
                alloc::vec::Vec::new()
            } else {
                match crate::compat::linux::vfs::copy_in(a[1], a[2] as usize * 4) {
                    Ok(b) => b,
                    Err(e) => return e,
                }
            };
            let groups: alloc::vec::Vec<u32> = bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
            match crate::compat::linux::proc::PROCS.lock().get_mut(&process(a[0])) {
                Some(p) => p.groups = groups,
                None => return ESRCH,
            }
            crate::compat::linux::ident_changed();
            0
        }
        LXP_PGRP_GET => {
            let Some((p, used)) = mech::task_pgrp_probe(process(a[0])) else { return ESRCH };
            x.a[..6].copy_from_slice(&[p.pid, p.ppid, p.pgid, p.sid, p.zombie as u64, used as u64]);
            0
        }
        LXP_PGRP_SET => mech::task_pgrp_cas(a[0], (a[1], a[2]), a[3], a[4] == 1, a[5] == 1),
        LXP_LIMIT_GET => {
            if a[1] as usize >= crate::compat::linux::limits::NLIMITS {
                return EINVAL;
            }
            let l = mech::task_limits(process(a[0]))[a[1] as usize];
            x.a[..3].copy_from_slice(&[l.0, l.1, crate::fs::MAX_FDS as u64]);
            0
        }
        LXP_LIMIT_SET => {
            if a[1] as usize >= crate::compat::linux::limits::NLIMITS {
                return EINVAL;
            }
            mech::task_limits_cas(process(a[0]), a[1] as usize, (a[2], a[3]), (a[4], a[5]))
        }
        LXP_ATTR_SET => attr_set(thread(a[0]), a, &x.b),
        LXP_NS_GET => {
            let Some(f) = crate::compat::linux::ns::ns_facts(process(a[0]), tgid) else { return ESRCH };
            x.a[..13].copy_from_slice(&f);
            0
        }
        LXP_NS_FD => {
            let Some(fds) = crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.fds.clone()) else { return ESRCH };
            let r = crate::compat::linux::ns::ns_fd_target(&fds.lock(), a[0], a[1]);
            match r {
                Ok((pid, kinds)) => {
                    x.a[0] = pid;
                    x.a[1] = kinds;
                    0
                }
                Err(e) => e,
            }
        }
        LXP_PID_GET => {
            let sys = mech::pid_from_view(a[0], mech::pid_ns_init(tgid));
            match crate::compat::linux::proc::tgid_of(sys) {
                Some(p) => {
                    x.a[0] = p;
                    0
                }
                None => ESRCH,
            }
        }
        LXP_UTS_GET => {
            let (id, (host, dom)) = crate::compat::linux::extra::uts_names_of(tgid);
            x.a[0] = id;
            x.b = [0; 256];
            let (h, d) = (host.as_bytes(), dom.as_bytes());
            x.b[..h.len().min(64)].copy_from_slice(&h[..h.len().min(64)]);
            x.b[65..65 + d.len().min(64)].copy_from_slice(&d[..d.len().min(64)]);
            0
        }
        LXP_UTS_SET => {
            if a[1] > 64 || a[0] > 1 {
                return EINVAL;
            }
            let mut v = alloc::string::String::from_utf8_lossy(&x.b[..a[1] as usize]).into_owned();
            // (a replaced byte takes 3: the name stays within 64 bytes, cut at a character)
            while v.len() > 64 {
                v.pop();
            }
            crate::compat::linux::extra::uts_set_of(tgid, a[0] == 1, v);
            0
        }
        LXP_APPROVE => {
            if mech::approve(client, a[0], a[1]) {
                0
            } else {
                -11 // EAGAIN: every slot holds another thread's mark
            }
        }
        _ => EINVAL,
    }
}

/// `LXP_TASK_GET` of thread `tid` (with `process`, `tid` names a process: its first live
/// thread).
fn task_get(tid: u64, process: bool, x: &mut LxProcIo) -> i64 {
    let get = |t: &crate::task::Task| {
        let mut flags = 0;
        if t.caps.keep {
            flags |= LXP_F_KEEPCAPS;
        }
        if t.caps.in_userns {
            flags |= LXP_F_USERNS;
        }
        if t.seccomp.no_new_privs {
            flags |= LXP_F_NNP;
        }
        if t.service.is_some() {
            flags |= LXP_F_SERVICE;
        }
        (
            [t.id.0, t.tgid, t.uid as u64, t.euid as u64, t.suid as u64, t.gid as u64, t.egid as u64, t.sgid as u64, t.caps.effective, t.caps.permitted, flags],
            alloc::string::String::from(t.exe_path()),
        )
    };
    let got = if process { crate::task::SCHEDULER.lock().with_process(tid, |t| get(t)) } else { crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| get(t)) };
    let Some((w, exe)) = got else { return ESRCH };
    let (tid, tgid) = (w[0], w[1]);
    x.a[..11].copy_from_slice(&w);
    let pa = super::proc::proc_attrs(tgid);
    if pa.subreaper {
        x.a[10] |= LXP_F_SUBREAPER;
    }
    x.a[11] = pa.dumpable as u64;
    x.a[12] = super::proc::thread_attrs(tid).pdeathsig as u64;
    x.a[13] = crate::compat::linux::proc::thread_ids_of(tgid).len() as u64;
    x.a[14] = crate::compat::linux::proc::PROCS.lock().get(&tgid).map_or(0, |p| p.groups.len() as u64);
    x.b = [0; 256];
    x.b[..16].copy_from_slice(&super::proc::comm_or_exe(tid, &exe));
    0
}

/// `LXP_ATTR_SET` on thread `tid`.
fn attr_set(tid: u64, a: [u64; 16], b: &[u8; 256]) -> i64 {
    use super::proc as mech;
    let Some(tgid) = tgid_of_thread(tid) else { return ESRCH };
    let on_task = |f: &mut dyn FnMut(&mut crate::task::Task)| crate::task::SCHEDULER.lock().with_task_mut(TaskId(tid), |t| f(t)).map_or(ESRCH, |()| 0);
    match a[1] {
        LXP_ATTR_COMM => {
            let mut comm = [0u8; 16];
            let n = b[..15].iter().position(|&c| c == 0).unwrap_or(15);
            comm[..n].copy_from_slice(&b[..n]);
            mech::thread_attrs_set(tid, tgid, |t| t.comm = Some(comm));
            0
        }
        LXP_ATTR_DUMPABLE => {
            mech::proc_attrs_set(tgid, |p| p.dumpable = a[2].min(2) as u8);
            0
        }
        LXP_ATTR_PDEATHSIG => {
            mech::thread_attrs_set(tid, tgid, |t| t.pdeathsig = a[2].min(64) as u32);
            0
        }
        LXP_ATTR_SUBREAPER => {
            mech::proc_attrs_set(tgid, |p| p.subreaper = a[2] != 0);
            0
        }
        LXP_ATTR_KEEPCAPS => on_task(&mut |t| t.caps.keep = a[2] != 0),
        LXP_ATTR_NNP => on_task(&mut |t| t.seccomp.no_new_privs = true),
        LXP_ATTR_CAPS => {
            let r = on_task(&mut |t| {
                t.caps.effective = a[2];
                t.caps.permitted = a[3];
            });
            crate::compat::linux::ident_changed();
            r
        }
        _ => EINVAL,
    }
}
