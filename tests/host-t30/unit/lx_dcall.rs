//! Tests of `src/lx/dcall.rs`: calls between services, delegation, posts.

use super::*;

/// The default call order, no delegations, counters at 0.
pub(crate) fn reset() {
    for a in ALLOW.iter() {
        a.store(0, Ordering::Release);
    }
    ALLOW_SET.store(false, Ordering::Release);
    *DELEG.lock() = [(0, 0); 64];
    DCALLS.store(0, Ordering::Release);
    DCALLS_REFUSED.store(0, Ordering::Release);
    POSTS.store(0, Ordering::Release);
}
