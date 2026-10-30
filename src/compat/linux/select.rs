//! # `select` / `pselect6`
//!
//! Waits until descriptors in the read, write or exception sets become ready, using the
//! same readiness rules as `poll` ([`crate::fs::FileDescriptor::poll_events`]), sleeping on
//! the descriptors' wait queues in between.

use alloc::vec::Vec;

const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

const POLLIN: u32 = 0x001;
const POLLOUT: u32 = 0x004;
const POLLERR: u32 = 0x008;
const POLLHUP: u32 = 0x010;

fn read_set(ptr: u64, words: usize) -> Result<Option<Vec<u64>>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    if !crate::memory::vm::prefault_current(ptr, (words * 8) as u64, true) {
        return Err(EFAULT);
    }
    Ok(Some((0..words).map(|i| unsafe { *((ptr + i as u64 * 8) as *const u64) }).collect()))
}

fn write_set(ptr: u64, set: &[u64]) {
    for (i, w) in set.iter().enumerate() {
        unsafe { *((ptr + i as u64 * 8) as *mut u64) = *w };
    }
}

fn is_set(set: &Option<Vec<u64>>, fd: usize) -> bool {
    set.as_ref().map_or(false, |s| s[fd / 64] & (1 << (fd % 64)) != 0)
}

/// Common implementation. `timeout_ns`: None waits forever.
fn do_select(nfds: u64, rp: u64, wp: u64, ep: u64, timeout_ns: Option<u64>) -> i64 {
    if nfds > crate::fs::MAX_FDS as u64 {
        return EINVAL;
    }
    let nfds = nfds as usize;
    let words = (nfds + 63) / 64;
    let (r, w, e) = match (read_set(rp, words), read_set(wp, words), read_set(ep, words)) {
        (Ok(r), Ok(w), Ok(e)) => (r, w, e),
        _ => return EFAULT,
    };
    let deadline = timeout_ns.map(|ns| crate::arch::pit::ticks() + (ns + 9_999_999) / 10_000_000);
    let mut waits = crate::task::wait::WaitSet::new();
    crate::task::with_current_fds_mut(|fds| {
        for fd in 0..nfds {
            if is_set(&r, fd) || is_set(&w, fd) || is_set(&e, fd) {
                if let Some(d) = fds.get(fd) {
                    d.add_wait_queues(&mut waits);
                }
            }
        }
    });
    loop {
        waits.register();
        super::tty::pump();
        crate::net::stack::kick();
        let mut out_r = alloc::vec![0u64; words];
        let mut out_w = alloc::vec![0u64; words];
        let out_e = alloc::vec![0u64; words];
        let mut count = 0i64;
        let mut bad = false;
        crate::task::with_current_fds_mut(|fds| {
            for fd in 0..nfds {
                let (wr, ww, we) = (is_set(&r, fd), is_set(&w, fd), is_set(&e, fd));
                if !(wr || ww || we) {
                    continue;
                }
                let ev = match fds.get(fd) {
                    Some(d) => d.poll_events(),
                    None => {
                        bad = true;
                        return;
                    }
                };
                if wr && ev & (POLLIN | POLLHUP | POLLERR) != 0 {
                    out_r[fd / 64] |= 1 << (fd % 64);
                    count += 1;
                }
                if ww && ev & (POLLOUT | POLLERR) != 0 {
                    out_w[fd / 64] |= 1 << (fd % 64);
                    count += 1;
                }
            }
        });
        if bad {
            return EBADF;
        }
        let timed_out = deadline.map_or(false, |d| crate::arch::pit::ticks() >= d);
        if count > 0 || timed_out {
            if rp != 0 {
                write_set(rp, &out_r);
            }
            if wp != 0 {
                write_set(wp, &out_w);
            }
            if ep != 0 {
                write_set(ep, &out_e);
            }
            return count;
        }
        if super::proc::signal_pending() {
            return super::proc::ERESTARTSYS;
        }
        waits.wait(deadline);
    }
}

fn read_pair(ptr: u64) -> Option<(i64, i64)> {
    if !crate::memory::vm::prefault_current(ptr, 16, false) {
        return None;
    }
    Some(unsafe { (*(ptr as *const i64), *((ptr + 8) as *const i64)) })
}

/// `select(nfds, readfds, writefds, exceptfds, struct timeval *timeout)`
pub fn sys_select(a: [u64; 6]) -> i64 {
    let timeout = if a[4] == 0 {
        None
    } else {
        match read_pair(a[4]) {
            Some((s, us)) if s >= 0 && us >= 0 => Some(s as u64 * 1_000_000_000 + us as u64 * 1000),
            Some(_) => return EINVAL,
            None => return EFAULT,
        }
    };
    do_select(a[0], a[1], a[2], a[3], timeout)
}

/// `pselect6(nfds, readfds, writefds, exceptfds, struct timespec *timeout, sigmask data)`
pub fn sys_pselect6(a: [u64; 6]) -> i64 {
    let timeout = if a[4] == 0 {
        None
    } else {
        match read_pair(a[4]) {
            Some((s, ns)) if s >= 0 && ns >= 0 => Some(s as u64 * 1_000_000_000 + ns as u64),
            Some(_) => return EINVAL,
            None => return EFAULT,
        }
    };
    do_select(a[0], a[1], a[2], a[3], timeout)
}
