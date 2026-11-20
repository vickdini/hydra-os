//! Drop-in replacement for the `x86_64` crate in host tests.
//!
//! Everything is re-exported from the real crate, except privileged instructions:
//! `invlpg` and a CR3 reload only count calls, and `cli`/`sti`
//! (`interrupts::without_interrupts`) simply run the closure, since a normal process has
//! no interrupt flag to change.
//!
//! `tests/host-t28/Cargo.toml` imports this crate under the name `x86_64`, so kernel
//! files compiled by the test crate pick it up unchanged.

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

    /// Host stand-ins for `cli`/`sti`.
    pub mod interrupts {
        /// Runs `f` (no interrupts to mask on the host).
        pub fn without_interrupts<F: FnOnce() -> R, R>(f: F) -> R {
            f()
        }
        /// The host has no interrupt flag: reported as off.
        pub fn are_enabled() -> bool {
            false
        }
        /// No-op on the host.
        pub fn enable() {}
        /// No-op on the host.
        pub fn disable() {}
    }
}
