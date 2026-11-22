//! Host build of the device announcement formats (wave 8, Group H): `src/lx/uevent.rs`
//! through `#[path]`. Tests in `uevent_tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../src/lx/uevent.rs"]
pub mod uevent;

#[cfg(test)]
mod uevent_tests;
