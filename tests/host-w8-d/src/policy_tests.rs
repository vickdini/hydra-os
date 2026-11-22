//! The screen owner's decisions (`src/ipc/screen/policy.rs`).

use crate::ipc::protocol::{SCREEN_CONSOLE, SCREEN_HIDDEN, SCREEN_PANIC, SCREEN_SHOWN};
use crate::ipc::screen::policy::*;

const ALL: [u32; 4] = [SCREEN_CONSOLE, SCREEN_SHOWN, SCREEN_HIDDEN, SCREEN_PANIC];
const EVENTS: [Event; 6] = [Event::Take, Event::Give, Event::Hide, Event::Show, Event::Gone, Event::Panic];

#[test]
fn take_lends_the_screen_and_routes_input() {
    let (st, a) = step(SCREEN_CONSOLE, Event::Take, true);
    assert_eq!(st, SCREEN_SHOWN);
    assert!(a.release && a.zap && a.notify && !a.reclaim);
    assert_eq!(a.route, Some(true));
    assert!(needs_release(SCREEN_CONSOLE, Event::Take));
}

#[test]
fn take_without_a_console_to_lend_changes_nothing() {
    assert_eq!(step(SCREEN_CONSOLE, Event::Take, false), (SCREEN_CONSOLE, Actions::default()));
}

#[test]
fn take_while_hidden_stays_hidden_and_takes_nothing() {
    assert!(!needs_release(SCREEN_HIDDEN, Event::Take));
    assert_eq!(step(SCREEN_HIDDEN, Event::Take, false), (SCREEN_HIDDEN, Actions::default()));
    assert_eq!(step(SCREEN_SHOWN, Event::Take, false), (SCREEN_SHOWN, Actions::default()));
}

#[test]
fn hide_zaps_before_the_console_repaints() {
    let (st, a) = step(SCREEN_SHOWN, Event::Hide, false);
    assert_eq!(st, SCREEN_HIDDEN);
    assert!(a.zap && a.reclaim && a.notify && !a.release);
    assert_eq!(a.route, Some(false));
}

#[test]
fn show_lends_again() {
    assert!(needs_release(SCREEN_HIDDEN, Event::Show));
    let (st, a) = step(SCREEN_HIDDEN, Event::Show, true);
    assert_eq!(st, SCREEN_SHOWN);
    assert!(a.release && a.zap && a.notify);
    assert_eq!(a.route, Some(true));
    // The console could not lend: still hidden
    assert_eq!(step(SCREEN_HIDDEN, Event::Show, false).0, SCREEN_HIDDEN);
}

#[test]
fn hot_keys_without_a_session_do_nothing() {
    for ev in [Event::Hide, Event::Show] {
        assert_eq!(step(SCREEN_CONSOLE, ev, true), (SCREEN_CONSOLE, Actions::default()));
    }
    assert_eq!(step(SCREEN_SHOWN, Event::Show, true), (SCREEN_SHOWN, Actions::default()));
    assert_eq!(step(SCREEN_HIDDEN, Event::Hide, true), (SCREEN_HIDDEN, Actions::default()));
}

#[test]
fn give_and_gone_return_the_screen() {
    for ev in [Event::Give, Event::Gone] {
        let (st, a) = step(SCREEN_SHOWN, ev, false);
        assert_eq!(st, SCREEN_CONSOLE);
        assert!(a.zap && a.reclaim && a.notify);
        assert_eq!(a.route, Some(false));
        // From hidden the console shows already: no repaint, input is the console's
        let (st, a) = step(SCREEN_HIDDEN, ev, false);
        assert_eq!(st, SCREEN_CONSOLE);
        assert!(a.zap && !a.reclaim && a.route.is_none());
        assert_eq!(step(SCREEN_CONSOLE, ev, false), (SCREEN_CONSOLE, Actions::default()));
    }
}

#[test]
fn panic_is_final() {
    for st in [SCREEN_CONSOLE, SCREEN_SHOWN, SCREEN_HIDDEN] {
        assert_eq!(step(st, Event::Panic, false).0, SCREEN_PANIC);
    }
    for ev in EVENTS {
        assert_eq!(step(SCREEN_PANIC, ev, true), (SCREEN_PANIC, Actions::default()));
    }
}

#[test]
fn every_lend_is_followed_by_a_zap_and_every_reclaim_comes_with_one() {
    for st in ALL {
        for ev in EVENTS {
            for ok in [false, true] {
                let (new, a) = step(st, ev, ok);
                if a.release || a.reclaim {
                    assert!(a.zap, "{st} {ev:?}");
                }
                if new != st {
                    assert!(a.notify, "{st} {ev:?}");
                }
                // Input goes to the session exactly when it starts showing
                assert_eq!(a.route == Some(true), new == SCREEN_SHOWN && st != SCREEN_SHOWN, "{st} {ev:?}");
            }
        }
    }
}

#[test]
fn pages_of_the_mapping() {
    let base = 0xC000_0000;
    assert_eq!(page_of(0, base, 1000, true), Page::Framebuffer(base));
    assert_eq!(page_of(999, base, 1000, true), Page::Framebuffer(base + 999 * 4096));
    assert_eq!(page_of(5, base, 1000, false), Page::Sink);
    assert_eq!(page_of(1000, base, 1000, true), Page::Status);
    assert_eq!(page_of(1000, base, 1000, false), Page::Status);
    assert_eq!(page_of(1001, base, 1000, true), Page::None);
    assert_eq!(fb_pages(1280 * 800 * 4), 1000);
    assert_eq!(fb_pages(4097), 2);
}

#[test]
fn wait_value_and_switch_owner() {
    assert_eq!(wait_value(SCREEN_HIDDEN, 7), (7 << 8) | 2);
    assert_eq!(wait_value(SCREEN_SHOWN, u64::MAX) & 0xFF, 1);
    assert!(wait_value(SCREEN_SHOWN, u64::MAX) >= 0);
    assert!(service_switch(SCREEN_SHOWN) && service_switch(SCREEN_HIDDEN));
    assert!(!service_switch(SCREEN_CONSOLE) && !service_switch(SCREEN_PANIC));
}
