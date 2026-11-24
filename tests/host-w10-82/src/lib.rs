//! Group 8-2's host build (wave 10): the plain parts of System V shared memory in lx-ipc,
//! compiled from their own sources through `#[path]`:
//!
//! - the kernel's attachment table (`src/lx/shm_table.rs`): counts across `shmat`, `shmdt`,
//!   `fork`, exit/`execve`, failed attaches, a fresh lx-ipc (generations), the notes;
//! - lx-ipc's System V text and structures (`lx-ipc/src/sysvtext.rs`): `/proc/sysvipc/*`
//!   lines, `shmid64_ds`, `shminfo`, `shm_info`, the limits, the info call's chunks;
//! - lx-proc's /proc paths (`procfs/path.rs`, moved from linux-server by 7b-2): `/proc/sysvipc/{shm,sem,msg}`.
//!
//! The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol, where the kernel's files find it.
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

/// linux-server's name for it (`crate::proto`).
pub use ipc::protocol as proto;

/// The kernel's `src/lx` file under test.
pub mod lx {
    #[path = "../../../../src/lx/shm_table.rs"]
    pub mod shm_table;
}

#[path = "../../../userland/drivers/lx-ipc/src/sysvtext.rs"]
pub mod sysvtext;

/// linux-server's pseudo file system paths.
pub mod pseudo {
    #[path = "../../../../userland/drivers/lx-proc/src/procfs/path.rs"]
    pub mod path;
}

#[cfg(test)]
mod tests;
