//! Host build of the mount changes vfs-server decides (wave 8, Group F).
//!
//! `compat/linux/mntrec.rs` (the table format the kernel and vfs-server exchange) and
//! vfs-server's `ktab.rs` (the kernel's mount rules on that format) are pure Rust and are
//! compiled here through `#[path]` at the module paths vfs-server uses. Tests:
//! `mntrec_tests.rs` (encode/decode, hash, checks, root changes) and `ktab_tests.rs`
//! (mount, bind, move, remount, propagation, umount, pivot_root).

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../src/compat/linux/mntrec.rs"]
pub mod mntrec;
#[path = "../../../userland/drivers/vfs-server/src/ktab.rs"]
pub mod ktab;

#[cfg(test)]
mod mntrec_tests;
#[cfg(test)]
mod ktab_tests;
