//! # Process identity: today's policy as pure rules (wave 9, Group 7a)
//!
//! Today's rules for changing process identity, as pure functions: each takes the current
//! state and the request and returns the new state or an errno. The kernel's system calls
//! apply them with the primitives (`src/lx/proc.rs`); lx-proc takes them over in wave 10.

use super::Pgrp;

const EPERM: i64 = -1;
const EINVAL: i64 = -22;

/// `-1` as an id: "leave it".
pub const KEEP: u32 = u32::MAX;
const ESRCH: i64 = -3;

/// `setuid`/`setgid`: privileged (`CAP_SETUID`/`CAP_SETGID`) sets all three ids;
/// otherwise only the effective one, to the real or the saved id.
pub fn set_id(cur: [u32; 3], new: u32, privileged: bool) -> Result<[u32; 3], i64> {
    if privileged {
        Ok([new; 3])
    } else if new == cur[0] || new == cur[2] {
        Ok([cur[0], new, cur[2]])
    } else {
        Err(EPERM)
    }
}

/// `setreuid`/`setregid` (`KEEP` leaves an id): the real id may become the real or
/// effective one, the effective id any of the three; the saved id follows the effective
/// one when the real id is set, or the effective id is set to other than the real one.
pub fn set_re(cur: [u32; 3], r: u32, e: u32, privileged: bool) -> Result<[u32; 3], i64> {
    let ok_r = r == KEEP || privileged || r == cur[0] || r == cur[1];
    let ok_e = e == KEEP || privileged || e == cur[0] || e == cur[1] || e == cur[2];
    if !ok_r || !ok_e {
        return Err(EPERM);
    }
    let mut n = cur;
    if r != KEEP {
        n[0] = r;
    }
    if e != KEEP {
        n[1] = e;
    }
    if r != KEEP || (e != KEEP && e != n[0]) {
        n[2] = n[1];
    }
    Ok(n)
}

/// `setresuid`/`setresgid` (`KEEP` leaves an id): unprivileged, each new id must be one
/// of the three current ones.
pub fn set_res(cur: [u32; 3], new: [u32; 3], privileged: bool) -> Result<[u32; 3], i64> {
    let ok = |v: u32| v == KEEP || privileged || cur.contains(&v);
    if !new.iter().all(|&v| ok(v)) {
        return Err(EPERM);
    }
    let mut n = cur;
    for k in 0..3 {
        if new[k] != KEEP {
            n[k] = new[k];
        }
    }
    Ok(n)
}

/// `setpgid(target, pgid)` by process `caller` (`target` already resolved, `pgid` 0 =
/// `target`): the group `target` joins.
pub fn setpgid(caller: u64, target: Option<Pgrp>, pgid: u64) -> Result<u64, i64> {
    // Linux: a negative group id is EINVAL
    if (pgid as i32) < 0 {
        return Err(EINVAL);
    }
    let t = target.filter(|t| t.pid == caller || t.ppid == caller).ok_or(ESRCH)?;
    if t.sid == t.pid {
        return Err(EPERM); // a session leader cannot change its group
    }
    Ok(if pgid == 0 { t.pid } else { pgid })
}

/// `setsid()` by `me`: allowed unless it leads its group or another process (zombies
/// too) is in the group its pid names (`group_used`). The new session's id.
pub fn setsid(me: Option<Pgrp>, group_used: bool) -> Result<u64, i64> {
    if group_used {
        return Err(EPERM);
    }
    match me {
        Some(p) if p.pgid != p.pid => Ok(p.pid),
        Some(_) => Err(EPERM),
        None => Err(ESRCH),
    }
}

/// `setrlimit`/`prlimit64` of one limit from `old` to `new`: soft above hard is EINVAL;
/// raising the hard limit needs `CAP_SYS_RESOURCE`; `RLIMIT_NOFILE`'s hard limit cannot
/// pass the descriptor table (`max_fds`, Linux's `fs.nr_open`).
pub fn set_limit(res: usize, old: (u64, u64), new: (u64, u64), cap_resource: bool, max_fds: u64) -> Result<(), i64> {
    const RLIMIT_NOFILE: usize = 7;
    if new.0 > new.1 {
        return Err(EINVAL);
    }
    if new.1 > old.1 && !cap_resource {
        return Err(EPERM);
    }
    if res == RLIMIT_NOFILE && new.1 > max_fds && new.1 != old.1 {
        return Err(EPERM);
    }
    Ok(())
}
