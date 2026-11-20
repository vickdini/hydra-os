//! Drop-in replacement for the `x86_64` crate in Group 32's host tests (arch + memory).
//!
//! Everything is re-exported from the real crate, except what a normal process may not
//! execute: TLB flushes, `cli`/`sti`/`hlt`, port I/O, control registers and descriptor
//! table loads. Here each of those acts on per-thread fake state that tests can set and
//! inspect (every `#[test]` runs on its own thread):
//!
//! - TLB flushes count calls ([`TLB_FLUSHES`], [`TLB_FLUSH_ALLS`]; global, as in the lead's
//!   shim) and are logged per thread ([`hw::FLUSHED`]),
//! - the interrupt flag is a per-thread bool ([`hw::if_flag`]), `hlt` counts and calls a hook,
//! - port I/O goes to a per-thread scripted bus ([`hw::set_port_handler`]) and is logged,
//! - CR0/CR2/CR3/CR4 are per-thread values ([`hw::CR`]),
//! - `lgdt`/`lidt`/`load_tss` are recorded.
//!
//! `tests/host-t32/Cargo.toml` imports this crate under the name `x86_64`, so kernel files
//! compiled by the test crate pick it up unchanged.

#![no_std]

extern crate std;

use core::sync::atomic::{AtomicUsize, Ordering};

pub use real::*;

/// Number of single-page TLB flushes requested so far (all threads).
pub static TLB_FLUSHES: AtomicUsize = AtomicUsize::new(0);
/// Number of full TLB flushes requested so far (all threads).
pub static TLB_FLUSH_ALLS: AtomicUsize = AtomicUsize::new(0);

/// The fake hardware state behind the shimmed instructions (per thread).
pub mod hw {
    use std::boxed::Box;
    use std::cell::{Cell, RefCell};
    use std::vec::Vec;

    /// One port access, as the scripted bus sees it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PortOp {
        pub port: u16,
        /// Access width in bytes (1, 2 or 4).
        pub width: u8,
        /// `Some(value)` for a write, `None` for a read.
        pub write: Option<u32>,
    }

    type Handler = Box<dyn FnMut(PortOp) -> u32>;

    std::thread_local! {
        static IF: Cell<bool> = const { Cell::new(true) };
        static HLTS: Cell<usize> = const { Cell::new(0) };
        static HLT_HOOK: RefCell<Option<Box<dyn FnMut()>>> = RefCell::new(None);
        static PORTS: RefCell<Option<Handler>> = RefCell::new(None);
        /// Every port access, in order: (port, width, Some(written) / None for a read, value read).
        pub static PORT_LOG: RefCell<Vec<(u16, u8, Option<u32>, u32)>> = const { RefCell::new(Vec::new()) };
        /// CR0, CR2 (index 2), CR3, CR4.
        pub static CR: RefCell<[u64; 5]> = const { RefCell::new([0x8005_0033, 0, 0, 0x1000, 0x6A0]) };
        /// Descriptor table loads: ("lgdt"/"lidt", base, limit) and ("ltr", selector, 0).
        pub static TABLES: RefCell<Vec<(&'static str, u64, u16)>> = const { RefCell::new(Vec::new()) };
        /// Single-page flushes on this thread (address).
        pub static FLUSHED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
        /// Full flushes on this thread.
        pub static FLUSHED_ALL: Cell<usize> = const { Cell::new(0) };
        /// Control register writes on this thread: (register, value).
        pub static CR_WRITES: RefCell<Vec<(usize, u64)>> = const { RefCell::new(Vec::new()) };
    }

    /// The interrupt flag of this thread's fake CPU.
    pub fn if_flag() -> bool {
        IF.get()
    }
    pub fn set_if(on: bool) {
        IF.set(on)
    }
    /// `hlt` instructions executed on this thread.
    pub fn hlts() -> usize {
        HLTS.get()
    }
    /// Runs `f` at every `hlt` (to let a waiting loop's condition change).
    pub fn set_hlt_hook(f: Option<Box<dyn FnMut()>>) {
        HLT_HOOK.with_borrow_mut(|h| *h = f);
    }
    pub(crate) fn hlt() {
        HLTS.set(HLTS.get() + 1);
        // With interrupts off nothing wakes the CPU again (the kernel's halt for good)
        if !IF.get() {
            panic!("hlt with interrupts off: this CPU stops here");
        }
        let hook = HLT_HOOK.with_borrow_mut(|h| h.take());
        if let Some(mut f) = hook {
            f();
            HLT_HOOK.with_borrow_mut(|h| {
                if h.is_none() {
                    *h = Some(f)
                }
            });
        }
    }

    /// Scripts the port bus: `f` answers every access (its return value is what a read
    /// gives; ignored for writes). Without a handler reads give all ones (no device).
    pub fn set_port_handler(f: impl FnMut(PortOp) -> u32 + 'static) {
        PORTS.with_borrow_mut(|h| *h = Some(Box::new(f)));
    }
    /// Removes the handler and clears the log.
    pub fn clear_ports() {
        PORTS.with_borrow_mut(|h| *h = None);
        PORT_LOG.with_borrow_mut(|l| l.clear());
    }
    /// The writes logged so far: (port, value).
    pub fn port_writes() -> Vec<(u16, u32)> {
        PORT_LOG.with_borrow(|l| l.iter().filter_map(|&(p, _, w, _)| w.map(|v| (p, v))).collect())
    }
    pub(crate) fn port(op: PortOp) -> u32 {
        let h = PORTS.with_borrow_mut(|h| h.take());
        let v = match h {
            Some(mut f) => {
                let v = f(op);
                PORTS.with_borrow_mut(|slot| {
                    if slot.is_none() {
                        *slot = Some(f)
                    }
                });
                v
            }
            None => u32::MAX,
        };
        let mask = match op.width {
            1 => 0xFF,
            2 => 0xFFFF,
            _ => u32::MAX,
        };
        PORT_LOG.with_borrow_mut(|l| l.push((op.port, op.width, op.write, v & mask)));
        v & mask
    }
    pub fn cr(i: usize) -> u64 {
        CR.with_borrow(|c| c[i])
    }
    /// Sets a control register as a write by the kernel would (logged in [`CR_WRITES`]).
    pub fn set_cr(i: usize, v: u64) {
        CR_WRITES.with_borrow_mut(|w| w.push((i, v)));
        CR.with_borrow_mut(|c| c[i] = v)
    }
}

pub mod instructions {
    pub use real::instructions::*;

    /// `hlt`: counts, and runs the thread's hook ([`crate::hw::set_hlt_hook`]).
    pub fn hlt() {
        crate::hw::hlt()
    }

    pub mod tlb {
        pub use real::instructions::tlb::*;

        /// Host stand-in for `invlpg`.
        pub fn flush(addr: real::VirtAddr) {
            crate::TLB_FLUSHES.fetch_add(1, super::super::Ordering::Relaxed);
            crate::hw::FLUSHED.with_borrow_mut(|v| v.push(addr.as_u64()));
        }

        /// Host stand-in for a CR3 reload.
        pub fn flush_all() {
            crate::TLB_FLUSH_ALLS.fetch_add(1, super::super::Ordering::Relaxed);
            crate::hw::FLUSHED_ALL.set(crate::hw::FLUSHED_ALL.get() + 1);
        }
    }

    pub mod interrupts {
        /// The thread's fake interrupt flag.
        pub fn are_enabled() -> bool {
            crate::hw::if_flag()
        }
        pub fn enable() {
            crate::hw::set_if(true)
        }
        pub fn disable() {
            crate::hw::set_if(false)
        }
        pub fn enable_and_hlt() {
            crate::hw::set_if(true);
            crate::hw::hlt();
        }
        pub fn without_interrupts<F: FnOnce() -> R, R>(f: F) -> R {
            let was = crate::hw::if_flag();
            crate::hw::set_if(false);
            let r = f();
            if was {
                crate::hw::set_if(true);
            }
            r
        }
    }

    pub mod tables {
        use real::structures::DescriptorTablePointer;

        /// # Safety
        /// Safe on the host: recorded only.
        pub unsafe fn lgdt(p: &DescriptorTablePointer) {
            crate::hw::TABLES.with_borrow_mut(|t| t.push(("lgdt", p.base.as_u64(), p.limit)));
        }
        /// # Safety
        /// Safe on the host: recorded only.
        pub unsafe fn lidt(p: &DescriptorTablePointer) {
            crate::hw::TABLES.with_borrow_mut(|t| t.push(("lidt", p.base.as_u64(), p.limit)));
        }
        /// # Safety
        /// Safe on the host: recorded only.
        pub unsafe fn load_tss(sel: real::structures::gdt::SegmentSelector) {
            crate::hw::TABLES.with_borrow_mut(|t| t.push(("ltr", sel.0 as u64, 0)));
        }
    }

    pub mod port {
        use core::marker::PhantomData;

        /// Widths a port can be accessed with.
        pub trait PortValue: Copy {
            const WIDTH: u8;
            fn to_u32(self) -> u32;
            fn from_u32(v: u32) -> Self;
        }
        impl PortValue for u8 {
            const WIDTH: u8 = 1;
            fn to_u32(self) -> u32 {
                self as u32
            }
            fn from_u32(v: u32) -> Self {
                v as u8
            }
        }
        impl PortValue for u16 {
            const WIDTH: u8 = 2;
            fn to_u32(self) -> u32 {
                self as u32
            }
            fn from_u32(v: u32) -> Self {
                v as u16
            }
        }
        impl PortValue for u32 {
            const WIDTH: u8 = 4;
            fn to_u32(self) -> u32 {
                self
            }
            fn from_u32(v: u32) -> Self {
                v
            }
        }

        /// An I/O port on the thread's scripted bus.
        #[derive(Debug)]
        pub struct Port<T> {
            port: u16,
            _t: PhantomData<T>,
        }
        pub type PortReadOnly<T> = Port<T>;
        pub type PortWriteOnly<T> = Port<T>;

        impl<T: PortValue> Port<T> {
            pub const fn new(port: u16) -> Self {
                Port { port, _t: PhantomData }
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn read(&mut self) -> T {
                T::from_u32(crate::hw::port(crate::hw::PortOp { port: self.port, width: T::WIDTH, write: None }))
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write(&mut self, v: T) {
                crate::hw::port(crate::hw::PortOp { port: self.port, width: T::WIDTH, write: Some(v.to_u32()) });
            }
        }
    }
}

pub mod registers {
    pub use real::registers::*;

    /// CR0..CR4 as per-thread values ([`crate::hw::CR`]).
    pub mod control {
        pub use real::registers::control::{Cr0Flags, Cr3Flags, Cr4Flags};
        use real::structures::paging::PhysFrame;
        use real::PhysAddr;

        pub struct Cr0;
        impl Cr0 {
            pub fn read() -> Cr0Flags {
                Cr0Flags::from_bits_truncate(crate::hw::cr(0))
            }
            pub fn read_raw() -> u64 {
                crate::hw::cr(0)
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write(f: Cr0Flags) {
                crate::hw::set_cr(0, f.bits())
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write_raw(v: u64) {
                crate::hw::set_cr(0, v)
            }
        }
        pub struct Cr2;
        impl Cr2 {
            pub fn read_raw() -> u64 {
                crate::hw::cr(2)
            }
        }
        pub struct Cr3;
        impl Cr3 {
            pub fn read() -> (PhysFrame, Cr3Flags) {
                let v = crate::hw::cr(3);
                (PhysFrame::containing_address(PhysAddr::new(v & 0x000F_FFFF_FFFF_F000)), Cr3Flags::from_bits_truncate(v & 0xFFF))
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write(f: PhysFrame, flags: Cr3Flags) {
                crate::hw::set_cr(3, f.start_address().as_u64() | flags.bits())
            }
        }
        pub struct Cr4;
        impl Cr4 {
            pub fn read() -> Cr4Flags {
                Cr4Flags::from_bits_truncate(crate::hw::cr(4))
            }
            pub fn read_raw() -> u64 {
                crate::hw::cr(4)
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write(f: Cr4Flags) {
                crate::hw::set_cr(4, f.bits())
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn write_raw(v: u64) {
                crate::hw::set_cr(4, v)
            }
            /// # Safety
            /// Safe on the host.
            pub unsafe fn update(f: impl FnOnce(&mut Cr4Flags)) {
                let mut v = Self::read();
                f(&mut v);
                Self::write(v)
            }
        }
    }
}
