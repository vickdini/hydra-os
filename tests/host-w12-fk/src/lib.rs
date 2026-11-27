//! Group FK's host build (wave 12): the FreeBSD personality's pure files, compiled from
//! their own sources (`src/personality/abi.rs`, `fbsd_xlat.rs`, `fbsd_tmp.rs`). Tests in
//! `tests.rs`.
#![allow(dead_code)]

extern crate alloc;

/// The personality module's pure files, under the names they have in the kernel.
pub mod personality {
    #[path = "../../../../src/personality/abi.rs"]
    pub mod abi;
    #[path = "../../../../src/personality/fbsd_xlat.rs"]
    pub mod fbsd_xlat;
    #[path = "../../../../src/personality/fbsd_tmp.rs"]
    pub mod fbsd_tmp;
}

#[cfg(test)]
mod tests;
