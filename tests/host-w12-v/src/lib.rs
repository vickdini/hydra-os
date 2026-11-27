//! Group V's host build (wave 12): plain parts of lx-ipc, compiled from their own sources
//! through `#[path]`:
//!
//! - `lx-ipc/src/sockcall.rs`: which calls on a pipe, eventfd, ... of lx-ipc's answer
//!   `ENOTSOCK` (PulseAudio's `pa_write()` and Firefox's audio).
//!
//! The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/lx-ipc/src/sockcall.rs"]
pub mod sockcall;

#[cfg(test)]
mod tests;
