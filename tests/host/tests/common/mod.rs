//! Helpers shared by several test binaries.

#![allow(dead_code)]

pub mod elf;

pub const GIB: u64 = 1 << 30;

/// Base and size of the physical memory given to the kernel's global
/// `FRAME_ALLOCATOR` by [`global_frames`]. It sits at 2 GiB, clear of the
/// per-test arenas (1 GiB + slot * 16 MiB).
pub const GLOBAL_BASE: u64 = 2 * GIB;
pub const GLOBAL_SIZE: u64 = 64 << 20;

/// Hand the global frame allocator its memory, once per test binary. Code
/// such as `memory::vm` allocates page tables and user pages from it.
pub fn global_frames() {
    use hydra_hosttests::memory::frame_allocator::{FRAME_ALLOCATOR, PAGE_SIZE};
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let arena = Arena::at(GLOBAL_BASE, GLOBAL_SIZE);
        let mut fa = FRAME_ALLOCATOR.lock();
        fa.add_region(x86_64::PhysAddr::new(arena.base), arena.size / PAGE_SIZE);
        fa.init_refcounts();
        std::mem::forget(arena); // lives for the whole test binary
    });
}

/// Serialises tests that share global state (the frame allocator, TLB
/// counters), so their before/after accounting is exact. A failed test
/// poisons the lock; later tests still run.
pub fn serial() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Committed, zeroed memory at a fixed address just above 1 GiB, released on
/// drop. Kernel code that dereferences physical or fixed user addresses can
/// run against it. Within one test binary, every test must use its own `slot`.
pub struct Arena {
    pub base: u64,
    pub size: u64,
}

pub const ARENA_SIZE: u64 = 4 << 20; // 4 MiB; the refcount table alone needs ~1.3 MiB

impl Arena {
    /// Each test passes its own `slot`, so parallel tests never overlap.
    pub fn new(slot: u64) -> Arena {
        Arena::at(GIB + slot * (16 << 20), ARENA_SIZE)
    }

    /// Arena of any size at an explicit address.
    pub fn at(base: u64, size: u64) -> Arena {
        assert!(os::map(base, size), "could not reserve test memory at {base:#x}");
        Arena { base, size }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        os::unmap(self.base, self.size);
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn VirtualAlloc(addr: *mut c_void, size: usize, ty: u32, prot: u32) -> *mut c_void;
        fn VirtualFree(addr: *mut c_void, size: usize, ty: u32) -> i32;
    }
    pub fn map(base: u64, size: u64) -> bool {
        const MEM_COMMIT_RESERVE: u32 = 0x3000;
        const PAGE_READWRITE: u32 = 0x04;
        unsafe { VirtualAlloc(base as _, size as usize, MEM_COMMIT_RESERVE, PAGE_READWRITE) as u64 == base }
    }
    pub fn unmap(base: u64, _size: u64) {
        const MEM_RELEASE: u32 = 0x8000;
        unsafe { VirtualFree(base as _, 0, MEM_RELEASE) };
    }
}

#[cfg(unix)]
mod os {
    use std::ffi::c_void;
    extern "C" {
        fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut c_void;
        fn munmap(addr: *mut c_void, len: usize) -> i32;
    }
    pub fn map(base: u64, size: u64) -> bool {
        const PROT_RW: i32 = 0x3;
        const MAP_PRIVATE_ANON: i32 = 0x02 | 0x20;
        const MAP_FIXED_NOREPLACE: i32 = 0x10_0000;
        let p = unsafe { mmap(base as _, size as usize, PROT_RW, MAP_PRIVATE_ANON | MAP_FIXED_NOREPLACE, -1, 0) };
        p as u64 == base
    }
    pub fn unmap(base: u64, size: u64) {
        unsafe { munmap(base as _, size as usize) };
    }
}

/// Gives programs a different low address-space layout (see
/// `vm::init_low_layout`) until dropped, then restores the default, in
/// which only the first GiB is the program's. The layout is global, so
/// hold `serial()` while one is active, and keep the guard alive until every
/// `Mm` made under it has been dropped (`Mm::drop` reads the layout).
pub struct LowLayout;

impl LowLayout {
    /// The kernel keeps the 1 GiB slots that `ranges` touch.
    pub fn kernel_at(ranges: &[(u64, u64)]) -> LowLayout {
        hydra_hosttests::memory::vm::init_low_layout(ranges);
        LowLayout
    }
}

impl Drop for LowLayout {
    fn drop(&mut self) {
        hydra_hosttests::memory::vm::init_low_layout(&[(GIB, hydra_hosttests::memory::vm::USER_SPACE_START)]);
    }
}
