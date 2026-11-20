//! Drop-in replacement for the `x86_64` crate in Group 34's host tests.
//!
//! Everything is re-exported from the real crate, except the instructions a normal
//! process may not execute:
//! - the TLB flushes (counted, as in `tests/host`'s shim);
//! - `cli`/`sti`/`hlt`: interrupts are a per-thread flag; `hlt` panics with `"hlt"` so a
//!   test can catch a halt loop (`loop { hlt() }`) with `catch_unwind`;
//! - port I/O: writes are logged per thread, reads answer per-thread queued values (or a
//!   default per port, `0x20` "transmitter empty" for the serial line status).
//!
//! `tests/host-t34/Cargo.toml` imports this crate under the name `x86_64`, so kernel
//! files compiled by the test crate pick it up unchanged.

use core::sync::atomic::{AtomicUsize, Ordering};

pub use real::*;

/// Number of single-page TLB flushes requested so far (all threads).
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Number of full TLB flushes requested so far (all threads).
pub static TLB_FLUSH_ALLS: AtomicUsize = AtomicUsize::new(0);

pub mod instructions {
    pub use real::instructions::*;

    /// Host stand-in for `hlt`: ends a halt loop with a panic the test can catch.
    pub fn hlt() {
        panic!("hlt");
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

    /// Interrupts as a per-thread flag (enabled at the start, as in a kernel thread).
    pub mod interrupts {
        use std::cell::Cell;
        thread_local! {
            static ENABLED: Cell<bool> = const { Cell::new(true) };
            static CHANGES: Cell<usize> = const { Cell::new(0) };
        }
        /// Whether "interrupts" are on for this thread.
        pub fn are_enabled() -> bool {
            ENABLED.with(|e| e.get())
        }
        /// `sti`.
        pub fn enable() {
            ENABLED.with(|e| e.set(true));
            CHANGES.with(|c| c.set(c.get() + 1));
        }
        /// `cli`.
        pub fn disable() {
            ENABLED.with(|e| e.set(false));
            CHANGES.with(|c| c.set(c.get() + 1));
        }
        /// How often this thread switched interrupts on or off.
        pub fn changes() -> usize {
            CHANGES.with(|c| c.get())
        }
        /// Runs `f` with interrupts off, restoring the previous state.
        pub fn without_interrupts<F: FnOnce() -> R, R>(f: F) -> R {
            let was = are_enabled();
            if was {
                disable();
            }
            let r = f();
            if was {
                enable();
            }
            r
        }
        /// `int3`: does nothing on the host.
        pub fn int3() {}
    }

    /// Port I/O, logged per thread.
    pub mod port {
        use std::cell::RefCell;
        use std::collections::{BTreeMap, VecDeque};
        use std::marker::PhantomData;

        thread_local! {
            static WRITES: RefCell<Vec<(u16, u32)>> = const { RefCell::new(Vec::new()) };
            static READS: RefCell<BTreeMap<u16, VecDeque<u32>>> = const { RefCell::new(BTreeMap::new()) };
            static DEFAULTS: RefCell<BTreeMap<u16, u32>> = const { RefCell::new(BTreeMap::new()) };
        }

        /// Writes to ports by this thread so far, `(port, value)`; cleared.
        pub fn take_writes() -> Vec<(u16, u32)> {
            WRITES.with(|w| std::mem::take(&mut *w.borrow_mut()))
        }
        /// Queues `v` as the answer of the next read of `port` on this thread.
        pub fn queue_read(port: u16, v: u32) {
            READS.with(|r| r.borrow_mut().entry(port).or_default().push_back(v));
        }
        /// The answer of reads of `port` when nothing is queued (default: 0x20 for a
        /// serial line status register, 0 otherwise).
        pub fn set_default(port: u16, v: u32) {
            DEFAULTS.with(|d| d.borrow_mut().insert(port, v));
        }
        fn read(port: u16) -> u32 {
            if let Some(v) = READS.with(|r| r.borrow_mut().get_mut(&port).and_then(|q| q.pop_front())) {
                return v;
            }
            DEFAULTS.with(|d| d.borrow().get(&port).copied()).unwrap_or(if port & 7 == 5 { 0x20 } else { 0 })
        }

        /// A value a port moves.
        pub trait PortValue: Copy {
            fn to_u32(self) -> u32;
            fn from_u32(v: u32) -> Self;
        }
        impl PortValue for u8 {
            fn to_u32(self) -> u32 { self as u32 }
            fn from_u32(v: u32) -> Self { v as u8 }
        }
        impl PortValue for u16 {
            fn to_u32(self) -> u32 { self as u32 }
            fn from_u32(v: u32) -> Self { v as u16 }
        }
        impl PortValue for u32 {
            fn to_u32(self) -> u32 { self }
            fn from_u32(v: u32) -> Self { v }
        }

        /// A read-write port.
        pub struct Port<T> {
            port: u16,
            _t: PhantomData<T>,
        }
        impl<T: PortValue> Port<T> {
            pub const fn new(port: u16) -> Self {
                Port { port, _t: PhantomData }
            }
            pub unsafe fn read(&mut self) -> T {
                T::from_u32(read(self.port))
            }
            pub unsafe fn write(&mut self, v: T) {
                let p = self.port;
                WRITES.with(|w| w.borrow_mut().push((p, v.to_u32())));
            }
        }
        /// A read-only port.
        pub type PortReadOnly<T> = Port<T>;
        /// A write-only port.
        pub type PortWriteOnly<T> = Port<T>;
    }
}

/// Registers: `CR3` reads answer a fixed page table root (reading it is privileged).
pub mod registers {
    pub use real::registers::*;
    pub mod control {
        pub use real::registers::control::*;
        /// Host stand-in for `CR3`.
        pub struct Cr3;
        impl Cr3 {
            /// A fixed root at 0x1234_5000.
            pub fn read() -> (real::structures::paging::PhysFrame, Cr3Flags) {
                (real::structures::paging::PhysFrame::containing_address(real::PhysAddr::new(0x1234_5000)), Cr3Flags::empty())
            }
        }
    }
}
