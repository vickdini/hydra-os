//! inotify events of a request, collected and handed back with the answer:
//! `crate::compat::linux::inotify`.

use crate::zfs::fsproto::Event;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// File was modified.
pub const IN_MODIFY: u32 = 0x2;
/// Metadata changed.
pub const IN_ATTRIB: u32 = 0x4;
/// Writable file was closed.
pub const IN_CLOSE_WRITE: u32 = 0x8;
/// File was moved from X.
pub const IN_MOVED_FROM: u32 = 0x40;
/// File was moved to Y.
pub const IN_MOVED_TO: u32 = 0x80;
/// File/directory created in watched directory.
pub const IN_CREATE: u32 = 0x100;
/// File/directory deleted from watched directory.
pub const IN_DELETE: u32 = 0x200;
/// Watched file/directory was itself deleted.
pub const IN_DELETE_SELF: u32 = 0x400;
/// Watched file/directory was itself moved.
pub const IN_MOVE_SELF: u32 = 0x800;
/// Subject of this event is a directory.
pub const IN_ISDIR: u32 = 0x4000_0000;

static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
static COOKIE: AtomicU32 = AtomicU32::new(1);

/// Events are always collected (the kernel drops those nobody watches).
///
/// # Returns
/// Always returns `true`.
pub fn active() -> bool {
    true
}

/// Every directory may be watched (the kernel decides).
///
/// # Arguments
/// * `_ino` - Inode number.
///
/// # Returns
/// Always returns `true`.
pub fn watched(_ino: u64) -> bool {
    true
}

/// A cookie pairing a rename's two events.
///
/// # Returns
/// Unique monotonically increasing event cookie.
pub fn cookie() -> u32 {
    COOKIE.fetch_add(1, Ordering::Relaxed)
}

/// Records an event for the reply.
///
/// # Arguments
/// * `ino` - Target inode number.
/// * `mask` - Inotify event mask.
/// * `cookie` - Event pair cookie.
/// * `name` - Associated entry name.
pub fn event(ino: u64, mask: u32, cookie: u32, name: &[u8]) {
    EVENTS.lock().push(Event { ino, mask, cookie, name: name.to_vec() });
}

/// The events recorded since the last call.
///
/// # Returns
/// Vector of recorded [`Event`] structs.
pub fn take() -> Vec<Event> {
    core::mem::take(&mut *EVENTS.lock())
}
