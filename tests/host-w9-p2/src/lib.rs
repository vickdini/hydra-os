//! Group P2's host build (wave 9): hydra-rt's `memfast.rs` (its own unit tests run here; the
//! symbols are not exported in a test build, so the host's own `memcpy` stays).
#![allow(dead_code)]

#[path = "../../../userland/drivers/hydra-rt/src/memfast.rs"]
pub mod memfast;
