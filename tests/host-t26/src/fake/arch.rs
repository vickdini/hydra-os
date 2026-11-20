//! *stub* `crate::arch`: clocks, randomness, CPUs, the boot disk and the syscall frame.

use std::cell::Cell;

thread_local! {
    /// Timer ticks (1000 Hz).
    pub static TICKS: Cell<u64> = const { Cell::new(1_000) };
    /// CPUs online.
    pub static CPUS: Cell<usize> = const { Cell::new(2) };
    /// Whether the boot volume had the live flag.
    pub static LIVE: Cell<bool> = const { Cell::new(false) };
}

pub fn reset() {
    TICKS.set(1_000);
    CPUS.set(2);
    LIVE.set(false);
}

pub mod pit {
    use super::TICKS;
    pub fn ticks() -> u64 {
        TICKS.get()
    }
    pub fn frequency_hz() -> u64 {
        1000
    }
    pub fn now_ns() -> u64 {
        TICKS.get() * 1_000_000
    }
}

/// *stub* Deterministic bytes (a counter) instead of RDRAND.
pub mod random {
    pub fn fill(buf: &mut [u8]) {
        static NEXT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(1);
        for b in buf {
            *b = NEXT.fetch_add(37, core::sync::atomic::Ordering::Relaxed);
        }
    }
}

pub mod rtc {
    /// A fixed instant (2026-01-01T00:00:00Z).
    pub fn now() -> (u64, u32) {
        (1_767_225_600, 0)
    }
}

pub mod smp {
    pub const MAX_CPUS: usize = 16;
    pub fn online() -> usize {
        super::CPUS.get()
    }
}

pub mod bootdisk {
    pub struct Info {
        pub live: bool,
    }
    pub fn info() -> Info {
        Info { live: super::LIVE.get() }
    }
}

pub mod syscall {
    /// The saved user registers at syscall entry (same fields and order as the kernel).
    #[repr(C)]
    #[derive(Default, Clone, Debug)]
    pub struct SyscallFrame {
        pub r9: u64,
        pub r8: u64,
        pub r10: u64,
        pub rdx: u64,
        pub rsi: u64,
        pub rdi: u64,
        pub rax: u64,
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub rip: u64,
        pub rflags: u64,
        pub rsp: u64,
    }

    impl SyscallFrame {
        /// A frame for call `nr` with arguments `a` (test helper).
        pub fn call(nr: u64, a: [u64; 6]) -> Self {
            SyscallFrame { rax: nr, rdi: a[0], rsi: a[1], rdx: a[2], r10: a[3], r8: a[4], r9: a[5], ..Default::default() }
        }
    }
}
