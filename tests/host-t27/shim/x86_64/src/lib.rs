//! Drop-in replacement for the `x86_64` crate in host tests.
//!
//! Everything is re-exported from the real crate, except the TLB flush
//! instructions: `invlpg` and a CR3 reload are privileged and would crash a
//! normal process. Here they only count calls, so tests can assert that the
//! kernel flushes after changing a page table entry.
//!
//! `tests/host/Cargo.toml` imports this crate under the name `x86_64`, so
//! kernel files compiled by the test crate pick it up unchanged.

#![no_std]

use core::sync::atomic::{AtomicUsize, Ordering};

pub use real::*;

/// Number of single-page TLB flushes requested so far (all threads).
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Number of full TLB flushes requested so far (all threads).
pub static TLB_FLUSH_ALLS: AtomicUsize = AtomicUsize::new(0);

pub mod instructions {
    pub use real::instructions::*;

    pub mod tlb {
        pub use real::instructions::tlb::*;

        /// Host stand-in for `invlpg`.
        pub fn flush(_addr: real::VirtAddr) {
            crate::TLB_FLUSHES.fetch_add(1, super::super::Ordering::Relaxed);
        }

        /// Host stand-in for a CR3 reload.
        pub fn flush_all() {
            crate::TLB_FLUSH_ALLS.fetch_add(1, super::super::Ordering::Relaxed);
        }
    }
}
