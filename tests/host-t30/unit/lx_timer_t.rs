//! `src/lx/timer.rs`: arming, cancelling, firing to each host's ring, the vvar page.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::{handler, notes, start, world};

#[test]
fn timers_fire_into_the_ring_of_the_host_that_armed_them() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        let a = s.call.args;
        (sys_timer(a[1], a[2], a[3]), 0)
    }));
    let call = |op, cookie, ns| crate::lx::tests::objs::test_call_args(0, [op, cookie, ns, 0, 0]);
    assert_eq!(next_due(), u64::MAX);
    assert!(!fire());
    assert_eq!(call(LX_TIMER_ARM, 7, 50_000_000), 0);
    assert_eq!(call(LX_TIMER_ARM, 8, 30_000_000), 0);
    // Armed again: the new deadline replaces the old
    assert_eq!(call(LX_TIMER_ARM, 8, 20_000_000), 0);
    assert_eq!(next_due(), 20_000_000);
    assert_eq!(call(LX_TIMER_ARM, 9, 25_000_000), 0);
    assert_eq!(call(LX_TIMER_CANCEL, 9, 0), 0);
    assert_eq!(call(LX_TIMER_CANCEL, 99, 0), 0);
    // Not due yet
    assert!(!fire());
    crate::world::NOW_NS.store(40_000_000, core::sync::atomic::Ordering::Release);
    assert_eq!(call(LX_TIMER_NOW, 0, 0), 40_000_000);
    on_tick();
    assert_eq!(notes(s.x).into_iter().filter(|e| e[0] == LX_NOTE_TIMER).collect::<Vec<_>>(), vec![[LX_NOTE_TIMER, 8, 20_000_000, 0]]);
    assert_eq!(next_due(), 50_000_000);
    // A busy list waits for the next tick
    crate::world::NOW_NS.store(60_000_000, core::sync::atomic::Ordering::Release);
    let g = TIMERS.lock();
    assert!(!fire());
    drop(g);
    assert!(fire());
    assert_eq!(next_due(), u64::MAX);
    // Unknown op; the vvar page
    assert_eq!(call(77, 0, 0), EINVAL);
    assert_eq!(call(LX_TIMER_VVAR, 0, 0), ENOMEM);
    crate::fake::rec(|r| r.vvar = Some(0x7FF0_0000));
    assert_eq!(call(LX_TIMER_VVAR, 0, 0), 0x7FF0_0000);
    // The host went away: its timers go
    assert_eq!(call(LX_TIMER_ARM, 1, 1 << 40), 0);
    clear(LXS_TEST);
    assert_eq!(next_due(), u64::MAX);
}

#[test]
fn at_most_64_fire_per_tick_and_programs_may_not_arm() {
    let sim = world();
    assert_eq!(sys_timer(LX_TIMER_ARM, 1, 1), -1);
    let _ = start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, 0)));
    with(|t| {
        for c in 0..70u64 {
            t.by_cookie.insert((LXS_TEST, c), 1);
            t.by_time.insert((1, LXS_TEST, c), ());
        }
        // A timer of a host that does not exist
        t.by_cookie.insert((15, 1), 1);
        t.by_time.insert((1, 15, 1), ());
        set_next(t);
    });
    crate::world::NOW_NS.store(10, core::sync::atomic::Ordering::Release);
    assert!(fire());
    assert_eq!(with(|t| t.by_time.len()), 71 - 64);
    assert!(fire());
    assert_eq!(with(|t| t.by_time.len()), 0);
}

#[test]
fn the_vvar_needs_an_address_space_and_too_many_timers_fail() {
    let sim = world();
    let r = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(crate::world::Task::server(301, 300, ENDPOINT_SVC_TEST), move || {
        r2.lock().unwrap().push(sys_timer(LX_TIMER_VVAR, 0, 0));
        with(|t| {
            for c in 0..=MAX_TIMERS as u64 {
                t.by_cookie.insert((LXS_TEST, 1_000_000 + c), 5);
            }
        });
        r2.lock().unwrap().push(sys_timer(LX_TIMER_ARM, 1, 5));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![EINVAL, ENOSPC]);
}
