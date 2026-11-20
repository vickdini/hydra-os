//! Drop-in replacement for the `x86_64` crate in Group 30's host tests.
//!
//! Everything is re-exported from the real crate, except what a normal process may not
//! execute:
//!
//! - the TLB flush instructions (`invlpg`, a CR3 reload): they only count calls;
//! - `cli`/`sti` and `without_interrupts`: the interrupt flag is a per-thread variable (each
//!   fake task runs on a thread of its own, so it is per task, as the saved RFLAGS is);
//! - port I/O: reads return what the test put in [`PORTS`], writes are recorded there.
//!
//! `tests/host-t30/Cargo.toml` imports this crate under the name `x86_64`, so kernel files
//! compiled by the test crate pick it up unchanged.

use core::sync::atomic::{AtomicUsize, Ordering};

pub use real::*;

/// Number of single-page TLB flushes requested so far (all threads).
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Number of full TLB flushes requested so far (all threads).
pub static TLB_FLUSH_ALLS: AtomicUsize = AtomicUsize::new(0);

/// The fake I/O ports: port number -> last value written (or set by a test for reads).
pub static PORTS: std::sync::Mutex<std::collections::BTreeMap<u16, u32>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

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

    /// The interrupt flag, per thread (per fake task).
    pub mod interrupts {
        use std::cell::Cell;

        thread_local! {
            static IF: Cell<bool> = const { Cell::new(true) };
            static CLI: Cell<u64> = const { Cell::new(0) };
        }

        /// Whether "interrupts" are on for this thread.
        pub fn are_enabled() -> bool {
            IF.with(|f| f.get())
        }

        /// `sti`.
        pub fn enable() {
            IF.with(|f| f.set(true));
        }

        /// `cli` (counted).
        pub fn disable() {
            CLI.with(|c| c.set(c.get() + 1));
            IF.with(|f| f.set(false));
        }

        /// How many times this thread disabled interrupts.
        pub fn disables() -> u64 {
            CLI.with(|c| c.get())
        }

        /// As the real crate's: runs `f` with the flag off, restoring it after.
        pub fn without_interrupts<F, R>(f: F) -> R
        where
            F: FnOnce() -> R,
        {
            let saved = are_enabled();
            if saved {
                disable();
            }
            let r = f();
            if saved {
                enable();
            }
            r
        }
    }

    /// Fake port I/O over [`crate::PORTS`].
    pub mod port {
        use core::marker::PhantomData;

        /// A port of width `T` (u8, u16 or u32).
        pub struct Port<T> {
            port: u16,
            _t: PhantomData<T>,
        }

        impl<T: Copy + TryFrom<u32> + Into<u32>> Port<T> {
            pub const fn new(port: u16) -> Self {
                Self { port, _t: PhantomData }
            }
            /// # Safety
            /// None on the host (kept `unsafe` like the real one).
            pub unsafe fn read(&mut self) -> T {
                let v = crate::PORTS.lock().unwrap().get(&self.port).copied().unwrap_or(0);
                T::try_from(v).ok().expect("port value fits")
            }
            /// # Safety
            /// None on the host.
            pub unsafe fn write(&mut self, v: T) {
                crate::PORTS.lock().unwrap().insert(self.port, v.into());
            }
        }
    }
}
