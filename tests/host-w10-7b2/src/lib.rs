//! Group 7b-2's host build (wave 10): the pure part of the kernel's `/proc` snapshots
//! (`src/lx/procsnap.rs`: positions of `lseek`, the piece a read returns, when a seek makes
//! the text again; the descriptor itself is `cfg(target_os = "uefi")` and runs in QEMU) and
//! the restart rule of the remake call (`src/lx/restart_policy.rs`), compiled from their own
//! sources.

#![allow(dead_code)]

extern crate alloc;

/// The code under test.
#[path = "../../../src/lx/procsnap.rs"]
pub mod procsnap;

#[cfg(test)]
mod tests;
