//! Group N's host build (wave 10): net-server's live-slot marks (`net-server/src/marks.rs`),
//! compiled from their own source. The tests are in `tests.rs`.
#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/net-server/src/marks.rs"]
pub mod marks;

#[cfg(test)]
mod tests;
