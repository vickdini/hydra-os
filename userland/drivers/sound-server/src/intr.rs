//! Signals for calls that are not waiting yet (plain Rust, host-tested in
//! `tests/host-w8-s`): a signal's `LX_NOTE_INTERRUPT` can be taken while the call it names is
//! still being served, before the call parks itself as a waiter. The note is remembered
//! here, and the call checks before it parks (both under the waiters' lock), so it is never
//! left waiting unsignalled.

use alloc::collections::VecDeque;

/// How many such notes are remembered (the oldest go first: calls that were answered at once
/// never ask).
pub const KEEP: usize = 64;

/// Remembers a signal for call `id`.
pub fn note(recent: &mut VecDeque<u64>, id: u64) {
    if recent.len() >= KEEP {
        recent.pop_front();
    }
    recent.push_back(id);
}

/// Whether a signal came for call `id` (and forgets it).
pub fn take(recent: &mut VecDeque<u64>, id: u64) -> bool {
    match recent.iter().position(|x| *x == id) {
        Some(i) => {
            recent.remove(i);
            true
        }
        None => false,
    }
}
