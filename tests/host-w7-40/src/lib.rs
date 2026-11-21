//! Group 7-4's host build: the decisions and encodings of the kernel's info primitives
//! (`src/lx/info.rs`; its gathering from the kernel's tables is `cfg(target_os = "uefi")`
//! and runs in QEMU) and linux-server's pseudo file systems (`pseudo/path.rs`: which file a
//! redirected path names; `pseudo/text.rs`: the files' text), compiled from their own
//! sources through `#[path]` under the module names they use.

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

/// linux-server's pseudo file system logic.
pub mod pseudo {
    #[path = "../../../../userland/drivers/linux-server/src/pseudo/path.rs"]
    pub mod path;
    #[path = "../../../../userland/drivers/linux-server/src/pseudo/text.rs"]
    pub mod text;
}

#[cfg(test)]
mod tests;
