//! The notification ring in the server's window ([`LX_NOTES_OFF`]): the kernel appends
//! process events (fork, exec, exit, a signal for a pending call) and advances the head;
//! the server takes them in order and advances the tail. One lock serializes the taking,
//! and the tail moves only after an entry was handled, so a worker that sees the tail at
//! or past its call's position knows every earlier event has been applied.

use core::sync::atomic::{fence, AtomicU64, Ordering};

use hydra_rt::protocol::{LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF, LX_NOTE_CLOSE, LX_NOTE_EXEC, LX_NOTE_EXIT, LX_NOTE_FORK, LX_NOTE_INTERRUPT};

use crate::lock::YLock;

/// The window's address (0: not set yet).
static BASE: AtomicU64 = AtomicU64::new(0);
/// Serializes taking notifications.
static TAKING: YLock<()> = YLock::new(());
/// The tail as this process last wrote it (a call checks it without touching the window).
static DONE: AtomicU64 = AtomicU64::new(0);

/// Sets the window (the kernel empties the ring when the server goes online).
pub fn init(window: *mut u8) {
    BASE.store(window as u64 + LX_NOTES_OFF as u64, Ordering::Release);
}

fn word(i: usize) -> *mut u64 {
    (BASE.load(Ordering::Acquire) as *mut u64).wrapping_add(i)
}

fn head() -> u64 {
    // SAFETY: the ring header in the mapped window
    unsafe { core::ptr::read_volatile(word(0)) }
}

fn tail() -> u64 {
    // SAFETY: as `head`
    unsafe { core::ptr::read_volatile(word(1)) }
}

/// Takes the notifications posted before position `seq` (a call's `note_seq`).
pub fn drain_to(seq: u64) {
    if DONE.load(Ordering::Acquire) >= seq || BASE.load(Ordering::Acquire) == 0 || tail() >= seq {
        return;
    }
    let _g = TAKING.lock();
    take(seq);
}

/// Takes every notification posted so far.
pub fn drain_all() {
    if BASE.load(Ordering::Acquire) == 0 || tail() >= head() {
        return;
    }
    let _g = TAKING.lock();
    take(head());
}

/// Handles entries from the tail up to `seq` (with [`TAKING`] held).
fn take(seq: u64) {
    let end = seq.min(head());
    fence(Ordering::Acquire);
    let mut t = tail();
    while t < end {
        let e = (BASE.load(Ordering::Acquire) - LX_NOTES_OFF as u64 + LX_NOTES_ENTRY_OFF as u64 + (t % LX_NOTES) * 32) as *const u64;
        // SAFETY: the entry lies in the mapped window
        let (kind, a, b) = unsafe { (core::ptr::read_volatile(e), core::ptr::read_volatile(e.add(1)), core::ptr::read_volatile(e.add(2))) };
        match kind {
            LX_NOTE_FORK => crate::keys::on_fork(a, b),
            LX_NOTE_EXEC => crate::keys::on_exec(a, b),
            LX_NOTE_EXIT => {
                crate::keys::on_exit(a);
                crate::mqueue::on_exit(a);
                crate::sysv::on_exit(a);
            }
            LX_NOTE_INTERRUPT => crate::interrupted(a),
            LX_NOTE_CLOSE => crate::obj::closed(a as u32, b as u32),
            _ => {}
        }
        t += 1;
        // SAFETY: as `head`; only the server writes the tail
        unsafe { core::ptr::write_volatile(word(1), t) };
        DONE.store(t, Ordering::Release);
    }
}
