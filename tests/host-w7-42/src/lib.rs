//! Host build of vfs-server's kept-state format (wave 7, Group 7-6).
//!
//! `kept.rs` and `locks.rs` with 7-3's `mtab.rs` and `tmpfs.rs` (whose encoders fill the snapshot), compiled
//! through `#[path]` at the module paths the server uses. The tests are in `kept_tests.rs` and `locks_tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/mtab.rs"]
pub mod mtab;
#[path = "../../../userland/drivers/vfs-server/src/tmpfs.rs"]
pub mod tmpfs;
#[path = "../../../userland/drivers/vfs-server/src/kept.rs"]
pub mod kept;
#[path = "../../../userland/drivers/vfs-server/src/locks.rs"]
pub mod locks;

/// The kernel's protocol (service ids).
#[path = "../../../src/ipc/protocol.rs"]
pub mod proto;

/// The ZFS request protocol (attributes) and the on-disk types it uses.
pub mod fs {
    #[path = "../../../../src/fs/zfs/types.rs"]
    pub mod types;
    #[path = "../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
}

#[cfg(test)]
mod kept_tests;
#[cfg(test)]
mod locks_tests;
