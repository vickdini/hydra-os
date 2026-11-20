//! *stub* `crate::host`: the test thread's segment registers, for the host builds of
//! `src/arch/segments.rs` (Group 32 replaced its `asm!` with calls to `crate::host`). Only the
//! descriptor logic of that file is used here; the loads are recorded per thread.

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static SEGS: RefCell<HashMap<&'static str, u16>> = RefCell::new(HashMap::new());
}

/// The fake CPU's segment register `r` (0 until loaded).
pub fn read_seg(r: &'static str) -> u16 {
    SEGS.with_borrow(|s| s.get(r).copied().unwrap_or(0))
}

/// Loads segment register `r` (or `ldtr`) of the fake CPU.
pub fn load_seg(r: &'static str, v: u16) {
    SEGS.with_borrow_mut(|s| {
        s.insert(r, v);
    });
}
