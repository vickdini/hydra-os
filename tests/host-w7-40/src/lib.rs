//! Group 7-4's host build: the decisions and encodings of the kernel's info primitives
//! (`src/lx/info.rs`; its gathering from the kernel's tables is `cfg(target_os = "uefi")`
//! and runs in QEMU) and the pseudo file systems: lx-proc's `/proc` (`procfs/path.rs`: which
//! file a redirected path names; `procfs/text.rs`: the files' text; wave 10 Group 7b-2 moved
//! them from linux-server) and linux-server's `/sys` (`pseudo/sys.rs`), compiled from their
//! own sources through `#[path]` under the module names they use.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol, where the kernel's files find it.
pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}

/// linux-server's name for it (`crate::proto`).
pub use ipc::protocol as proto;

/// The kernel's `src/lx` files under test.
pub mod lx {
    #[path = "../../../../src/lx/info.rs"]
    pub mod info;
}

/// lx-proc's `/proc` logic (wave 10 Group 7b-2).
pub mod pseudo {
    #[path = "../../../../userland/drivers/lx-proc/src/procfs/path.rs"]
    pub mod path;
    #[path = "../../../../userland/drivers/lx-proc/src/procfs/text.rs"]
    pub mod text;
}

/// linux-server's `/sys` logic.
pub mod sysfs {
    #[path = "../../../../userland/drivers/linux-server/src/pseudo/sys.rs"]
    pub mod sys;
}

#[cfg(test)]
mod tests;
