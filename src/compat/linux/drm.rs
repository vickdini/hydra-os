//! # DRM/KMS display device (`/dev/dri/card0`)
//!
//! A kernel mode-setting driver for the boot framebuffer, in the spirit of Linux's
//! `simpledrm`: one CRTC, one encoder and one connected virtual connector whose only mode is
//! the firmware's resolution. Clients allocate "dumb" buffers, `mmap` them, wrap them in
//! framebuffers and show them with the legacy `SETCRTC`/`PAGE_FLIP` calls; page flips
//! complete at once and post a `DRM_EVENT_FLIP_COMPLETE` on the descriptor. The cursor is
//! a 64x64 ARGB buffer blended over the picture when it is shown (`MODE_CURSOR`).
//!
//! Atomic mode setting is not offered (`SET_CLIENT_CAP(ATOMIC)` fails), so compositors use
//! the legacy path. There is no render node. Buffers can be exported as DMA-BUF descriptors
//! (PRIME) that map the same pages, and imported back into a GEM handle.
//!
//! Showing a framebuffer takes the screen from the text console (as a Linux VT switch to a
//! graphical session does) and routes the keyboard and mouse to the evdev devices; when
//! the master closes the device the console gets the screen back.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::task::wait::WaitQueue;


/// 0 = nothing to do, 1 = switch to the console, 2 = back to the session.
static VT_REQUEST: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static VT_WQ: WaitQueue = WaitQueue::new();
static SESSION_HIDDEN: AtomicBool = AtomicBool::new(false);

/// True while a DRM session runs but the console is shown (Ctrl+Alt+F2 returns to it).
///
/// # Returns
///
/// `true` if DRM session is active but hidden; `false` otherwise.
pub fn session_hidden() -> bool {
    // wave8 GD: or the display service's session (`ipc::screen`)
    SESSION_HIDDEN.load(Ordering::Acquire) || screen_hook_hidden()
}

// wave8 GD begin: the hot keys' switch target when the display service serves the screen
// (`ipc::screen` installs these hooks when the service maps the screen; `keyboard.rs`
// keeps calling [`request_vt_switch`] and [`session_hidden`] in both modes)
/// `ipc::screen`'s switch: `true` if it took the switch (its service's session holds the
/// screen).
static SCREEN_SWITCH: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
/// `ipc::screen`'s "session hidden".
static SCREEN_HIDDEN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Installs the display service's switch and "hidden" hooks.
pub fn set_screen_hooks(switch: fn(bool) -> bool, hidden: fn() -> bool) {
    SCREEN_HIDDEN.store(hidden as usize, Ordering::Release);
    SCREEN_SWITCH.store(switch as usize, Ordering::Release);
}

fn screen_hook_hidden() -> bool {
    let h = SCREEN_HIDDEN.load(Ordering::Acquire);
    // SAFETY: stored from a `fn() -> bool` by `set_screen_hooks`
    h != 0 && unsafe { core::mem::transmute::<usize, fn() -> bool>(h) }()
}

fn screen_hook_switch(to_session: bool) -> bool {
    let h = SCREEN_SWITCH.load(Ordering::Acquire);
    // SAFETY: stored from a `fn(bool) -> bool` by `set_screen_hooks`
    h != 0 && unsafe { core::mem::transmute::<usize, fn(bool) -> bool>(h) }(to_session)
}

// wave8 GD end

/// Keyboard interrupt: asks the `vtd` task to switch between the session (`to_session`)
/// and the console. The copying happens in task context, not in the interrupt.
///
/// # Arguments
///
/// * `to_session` - `true` to switch to graphical session; `false` to switch to text console.
pub fn request_vt_switch(to_session: bool) {
    // wave8 GD: the display service's session first
    if screen_hook_switch(to_session) {
        return;
    }
    VT_REQUEST.store(if to_session { 2 } else { 1 }, Ordering::Release);
    VT_WQ.wake_all();
}
