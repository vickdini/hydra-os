//! Host build of the input service's pure parts (wave 8, Group I): the kernel's raw input
//! ring and input-server's translation, compiled through `#[path]` with the kernel's
//! protocol at the module path both use (`super::protocol`). Tests in `ring_tests.rs` and
//! `xlate_tests.rs`.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (ring layout, record kinds).
#[path = "../../../src/ipc/protocol.rs"]
pub mod protocol;

#[path = "../../../src/ipc/input_ring.rs"]
pub mod input_ring;

#[path = "../../../userland/drivers/input-server/src/xlate.rs"]
pub mod xlate;

#[cfg(test)]
mod ring_tests;
#[cfg(test)]
mod xlate_tests;
