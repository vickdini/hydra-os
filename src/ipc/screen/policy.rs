//! # The screen's owner: the decisions (wave 8, Group D)
//!
//! Pure code, no locks and no hardware: who owns the screen after each event, what the
//! kernel must do for it, and where a page of the display service's screen mapping leads.
//! `src/ipc/screen.rs` holds the state and carries the actions out; the host tests
//! (`tests/host-w8-d`) run every transition here.

use crate::ipc::protocol::{SCREEN_CONSOLE, SCREEN_HIDDEN, SCREEN_PANIC, SCREEN_SHOWN};

/// What happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// The display service wants the screen for its session (its first picture).
    Take,
    /// The display service gives the screen back (no session needs it).
    Give,
    /// Ctrl+Alt+F1: the console shows; the session keeps running unseen.
    Hide,
    /// Ctrl+Alt+F2: back to the session.
    Show,
    /// The display service went away (crashed, killed, restarted).
    Gone,
    /// The kernel panicked.
    Panic,
}

/// What the kernel does for a transition, in this order: the console lends the screen
/// (`release`), the mapping is pointed at the new pages (`zap`: every page refaults),
/// input is routed (`route`), the console takes the screen back (`reclaim`), the service is
/// told (`notify`: the generation moves on).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Actions {
    /// `console::release_display` before the mapping leads to the framebuffer.
    pub release: bool,
    /// Zap the service's mapping (after the state word changed).
    pub zap: bool,
    /// Route input: `Some(true)` to the session, `Some(false)` back to the console (held
    /// keys released).
    pub route: Option<bool>,
    /// `console::reclaim_display` (after the zap: nothing the service writes reaches the
    /// screen any more).
    pub reclaim: bool,
    /// The state changed: bump the generation, wake the service's wait.
    pub notify: bool,
}

/// The state after `ev` in state `st`, with what to do; `release_ok` tells whether the
/// console could lend the screen (a `Take` or `Show` that cannot keeps the old state).
pub fn step(st: u32, ev: Event, release_ok: bool) -> (u32, Actions) {
    let none = Actions::default();
    if st == SCREEN_PANIC {
        // The console keeps the screen for good
        return (SCREEN_PANIC, none);
    }
    match (st, ev) {
        (_, Event::Panic) => (SCREEN_PANIC, Actions { zap: false, notify: true, ..none }),
        (SCREEN_CONSOLE, Event::Take) if release_ok => (SCREEN_SHOWN, Actions { release: true, zap: true, route: Some(true), notify: true, ..none }),
        (SCREEN_HIDDEN, Event::Show) if release_ok => (SCREEN_SHOWN, Actions { release: true, zap: true, route: Some(true), notify: true, ..none }),
        (SCREEN_SHOWN, Event::Hide) => (SCREEN_HIDDEN, Actions { zap: true, route: Some(false), reclaim: true, notify: true, ..none }),
        (SCREEN_SHOWN, Event::Give | Event::Gone) => (SCREEN_CONSOLE, Actions { zap: true, route: Some(false), reclaim: true, notify: true, ..none }),
        // Hidden: the console shows already; input is the console's already
        (SCREEN_HIDDEN, Event::Give | Event::Gone) => (SCREEN_CONSOLE, Actions { zap: true, notify: true, ..none }),
        _ => (st, none),
    }
}

/// Whether the console must lend the screen for `ev` in state `st` (asked before [`step`],
/// whose `release_ok` is the console's answer).
pub fn needs_release(st: u32, ev: Event) -> bool {
    matches!((st, ev), (SCREEN_CONSOLE, Event::Take) | (SCREEN_HIDDEN, Event::Show))
}

/// Where page `pgoff` of the service's screen mapping leads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// The framebuffer's page at this physical address.
    Framebuffer(u64),
    /// The scratch page (the console owns the screen: writes go nowhere).
    Sink,
    /// The status page.
    Status,
    /// Past the mapping.
    None,
}

/// The page behind `pgoff` of a mapping of a `fb_pages`-page framebuffer at `fb_phys`,
/// while the screen is lent (`lent`) or not.
pub fn page_of(pgoff: u64, fb_phys: u64, fb_pages: u64, lent: bool) -> Page {
    if pgoff < fb_pages {
        if lent {
            Page::Framebuffer(fb_phys + pgoff * 4096)
        } else {
            Page::Sink
        }
    } else if pgoff == fb_pages {
        Page::Status
    } else {
        Page::None
    }
}

/// Pages of a framebuffer of `bytes` bytes.
pub fn fb_pages(bytes: u64) -> u64 {
    bytes.div_ceil(4096)
}

/// The value [`SCREEN_WAIT`](crate::ipc::protocol::SCREEN_WAIT) returns: the state and the
/// generation.
pub fn wait_value(state: u32, gen: u64) -> i64 {
    (state as u64 | (gen & 0x007F_FFFF_FFFF_FFFF) << 8) as i64
}

/// Whether a hot key's switch is the display service's to carry out (it holds the screen
/// in a session, shown or hidden); otherwise the kernel's own DRM device (`lx=kernel`)
/// gets it.
pub fn service_switch(st: u32) -> bool {
    st == SCREEN_SHOWN || st == SCREEN_HIDDEN
}
