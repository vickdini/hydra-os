//! Group 6b-1's host build (wave 9): vfs-server's inotify/fanotify rules
//! (`vfs-server/src/notify/logic.rs`) and the kernel's side of the event records
//! (`src/lx/notifyfwd.rs`, its plain part), compiled from their own sources through
//! `#[path]`. The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/notify/logic.rs"]
pub mod logic;

/// The kernel's protocol, at the path the kernel's files use.
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

#[path = "../../../src/lx/notifyfwd.rs"]
pub mod notifyfwd;

#[cfg(test)]
mod tests;
