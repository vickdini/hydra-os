//! *stub* `crate::lx`: the forwarding to the ring-3 Linux server. Calls are recorded and
//! answered with what the test set.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::cell::{Cell, RefCell};

use crate::compat::linux::chardev::CharDevice;

thread_local! {
    pub static STEP4: Cell<bool> = const { Cell::new(false) };
    /// Calls forwarded: (call number, arguments).
    pub static CALLS: RefCell<Vec<(u64, [u64; 6])>> = const { RefCell::new(Vec::new()) };
    /// What forwarded calls return.
    pub static ANSWER: Cell<i64> = const { Cell::new(0) };
    pub static NET_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
    pub static UNIX_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
    pub static KEYS_TEXT: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub fn reset() {
    STEP4.set(false);
    CALLS.with_borrow_mut(|c| c.clear());
    ANSWER.set(0);
    NET_TEXT.with_borrow_mut(|t| *t = None);
    UNIX_TEXT.with_borrow_mut(|t| *t = None);
    KEYS_TEXT.with_borrow_mut(|t| *t = None);
}

/// The calls forwarded so far.
pub fn calls() -> Vec<(u64, [u64; 6])> {
    CALLS.with_borrow(|c| c.clone())
}

pub fn step4() -> bool {
    STEP4.get()
}

pub fn call_obj(nr: u64, args: [u64; 6], _dev: &Arc<dyn CharDevice>) -> i64 {
    CALLS.with_borrow_mut(|c| c.push((nr, args)));
    ANSWER.get()
}

pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    CALLS.with_borrow_mut(|c| c.push((nr, args)));
    ANSWER.get()
}

pub fn proc_net_text(_file: &str) -> Option<String> {
    NET_TEXT.with_borrow(|t| t.clone())
}

pub fn proc_net_unix_text() -> Option<String> {
    UNIX_TEXT.with_borrow(|t| t.clone())
}

pub fn proc_keys_text() -> Option<String> {
    KEYS_TEXT.with_borrow(|t| t.clone())
}

pub mod obj {
    /// *stub* A linux-server object: its kind, tag and slot are what the test made it with.
    pub struct ServerObject {
        pub kind: u32,
        pub tag: u64,
        pub slot: Option<u64>,
    }
    impl ServerObject {
        pub fn kind(&self) -> u32 {
            self.kind
        }
        pub fn tag(&self) -> u64 {
            self.tag
        }
        pub fn slot(&self) -> Option<u64> {
            self.slot
        }
    }
}
