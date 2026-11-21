//! Host build of vfs-server's mount tables and tmpfs (wave 7, Group 7-3).
//!
//! The server's files are compiled through `#[path]` at the module paths the server uses
//! (`crate::mtab`, `crate::tmpfs`); they depend on `core` and `alloc` only, so nothing is
//! stubbed. The tests are in `mount_tests.rs` and `tmpfs_tests.rs`.

extern crate alloc;

#[path = "../../../userland/drivers/vfs-server/src/mtab.rs"]
pub mod mtab;
#[path = "../../../userland/drivers/vfs-server/src/tmpfs.rs"]
pub mod tmpfs;

#[cfg(test)]
mod mount_tests;
#[cfg(test)]
mod tmpfs_tests;
