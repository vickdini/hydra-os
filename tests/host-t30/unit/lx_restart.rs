//! Tests of `src/lx/restart.rs`: the per-service restart state, waiting for a restarting
//! service, sending calls again, installs lost in a restart, `SYS_LX_SVC` ops 16..23.

use super::*;

/// Every service back to FailObjects, up, nothing kept; the install ring empty.
pub(crate) fn reset() {
    state(|s| {
        for v in s.iter_mut() {
            *v = Svc::NEW;
        }
    });
    for i in 0..MAX_SVC {
        RESTARTING[i].store(false, Ordering::Release);
        DOWN[i].store(false, Ordering::Release);
    }
    *INSTALLS.lock() = [(0, 0, -1); 64];
    INSTALL_NEXT.store(0, Ordering::Release);
    RESENT.store(0, Ordering::Release);
    WAITED.store(0, Ordering::Release);
    FAILED.store(0, Ordering::Release);
}

/// Marks service `svc` given up (or not) by the ladder.
pub(crate) fn set_down(svc: u8, on: bool) {
    DOWN[idx(svc)].store(on, Ordering::Release);
}

/// Marks service `svc` restarting (or not): its callers wait.
pub(crate) fn set_restarting(svc: u8, on: bool) {
    RESTARTING[idx(svc)].store(on, Ordering::Release);
}
