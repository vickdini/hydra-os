//! Drop-in replacement for the `x86_64` crate in Group 31's host tests.
//!
//! Everything is re-exported from the real crate, except the privileged
//! instructions the scheduler and its callers execute, which would crash a
//! normal process:
//! - the TLB flushes (`invlpg`, a CR3 reload) only count calls;
//! - `Cr3::read` returns the calling thread's fake CR3 ([`set_cr3`]): each test
//!   thread plays one CPU;
//! - `cli`/`sti`/`hlt` change or read a per-thread fake interrupt flag.
//!
//! `tests/host-t31/Cargo.toml` imports this crate under the name `x86_64`, so
//! kernel files compiled by the test crate pick it up unchanged.

use core::sync::atomic::{AtomicUsize, Ordering};
use std::cell::Cell;

pub use real::*;

/// Number of single-page TLB flushes requested so far (all threads).
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Number of full TLB flushes requested so far (all threads).
pub static TLB_FLUSH_ALLS: AtomicUsize = AtomicUsize::new(0);
/// Number of `hlt` instructions "executed" (all threads).
pub static HALTS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// The calling thread's (CPU's) CR3 value.
    static CR3: Cell<u64> = const { Cell::new(0x1000) };
    /// The calling thread's (CPU's) interrupt flag.
    static IF: Cell<bool> = const { Cell::new(false) };
}

/// Sets the calling thread's fake CR3 (must be 4 KiB aligned).
pub fn set_cr3(v: u64) {
    CR3.with(|c| c.set(v & !0xFFF));
}

/// The calling thread's fake CR3.
pub fn cr3() -> u64 {
    CR3.with(|c| c.get())
}

pub mod registers {
    pub use real::registers::*;

    pub mod control {
        pub use real::registers::control::*;

        /// Host stand-in for CR3: reads the thread's fake value.
        pub struct Cr3;

        impl Cr3 {
            pub fn read() -> (real::structures::paging::PhysFrame, real::registers::control::Cr3Flags) {
                let f = real::structures::paging::PhysFrame::containing_address(real::PhysAddr::new(crate::cr3()));
                (f, real::registers::control::Cr3Flags::empty())
            }
        }
    }
}

pub mod instructions {
    pub use real::instructions::*;

    /// Host stand-in for `hlt`: counts.
    pub fn hlt() {
        crate::HALTS.fetch_add(1, super::Ordering::Relaxed);
    }

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

    pub mod interrupts {
        /// The thread's fake interrupt flag.
        pub fn are_enabled() -> bool {
            crate::IF.with(|f| f.get())
        }
        /// `sti`.
        pub fn enable() {
            crate::IF.with(|f| f.set(true));
        }
        /// `cli`.
        pub fn disable() {
            crate::IF.with(|f| f.set(false));
        }
        /// Runs `f` with the fake flag clear, then restores it.
        pub fn without_interrupts<F: FnOnce() -> R, R>(f: F) -> R {
            let was = are_enabled();
            disable();
            let r = f();
            if was {
                enable();
            }
            r
        }
        /// `sti; hlt`: sets the flag and counts a halt.
        pub fn enable_and_hlt() {
            enable();
            super::hlt();
        }
    }
}
