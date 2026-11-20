//! Tests of `src/lx/timer.rs`: the services' timers.

use super::*;

/// No timers armed.
pub(crate) fn reset() {
    with(|t| {
        t.by_time.clear();
        t.by_cookie.clear();
        set_next(t);
    });
}
