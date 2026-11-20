//! *stub* `crate::memory`: user memory is host memory; an address below [`vm::BAD_BELOW`]
//! (or in a range a test marks bad) faults.

use std::cell::RefCell;

thread_local! {
    static BAD: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

pub fn reset() {
    BAD.with_borrow_mut(|b| b.clear());
}

/// Makes `[addr, addr + len)` fault for the rest of the test.
pub fn make_bad(addr: u64, len: u64) {
    BAD.with_borrow_mut(|b| b.push((addr, len)));
}

pub mod vm {
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Addresses below this fault (tests pass small numbers as bad pointers).
    pub const BAD_BELOW: u64 = 0x10000;

    pub fn prefault_current(addr: u64, len: u64, _write: bool) -> bool {
        // As the kernel's: nothing to fault in for no bytes
        if len == 0 {
            return true;
        }
        if addr < BAD_BELOW {
            return false;
        }
        let end = addr.saturating_add(len);
        !super::BAD.with_borrow(|b| b.iter().any(|&(a, l)| addr < a + l && a < end.max(addr + 1)))
    }

    /// *stub* An address space, as far as `/proc` looks at it.
    #[derive(Default)]
    pub struct Mm {
        /// `(start, end, environment end)` of the argument area.
        pub args: (u64, u64, u64),
        pub auxv: Vec<u8>,
        pub maps: String,
        /// (virtual bytes, anonymous pages, file pages)
        pub usage: (u64, u64, u64),
    }

    impl Mm {
        pub fn maps_text(&self) -> String {
            self.maps.clone()
        }
        pub fn memory_usage(&self) -> (u64, u64, u64) {
            self.usage
        }
    }
}

pub mod paging {
    /// *stub* The kernel's page tables are the host's.
    pub fn with_kernel_tables<R>(f: impl FnOnce() -> R) -> R {
        f()
    }
}

pub mod frame_allocator {
    /// *stub* Memory figures for `/proc/meminfo`.
    pub struct Frames {
        pub total: u64,
        pub free: u64,
    }
    impl Frames {
        pub fn total_usable_memory(&self) -> u64 {
            self.total
        }
        pub fn free_memory(&self) -> u64 {
            self.free
        }
    }
    pub static FRAME_ALLOCATOR: spin::Mutex<Frames> = spin::Mutex::new(Frames { total: 8 << 30, free: 6 << 30 });
}
