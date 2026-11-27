//! Group D's host build (wave 11): lx-net's link traffic counters (`linkstats.rs`), compiled
//! from their own sources. Tests in `tests.rs`.
#![allow(dead_code)]

extern crate alloc;

#[path = "../../../userland/drivers/lx-net/src/linkstats.rs"]
pub mod linkstats;

#[cfg(test)]
mod tests;
