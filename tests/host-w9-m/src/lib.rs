//! Host build of `src/fs/tmem.rs` (wave 9, Group M) with a fake frame allocator: "physical"
//! frames are host pages, counted so tests see every reference given back.
extern crate alloc;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Fake memory state.
pub mod fake {
    use super::*;
    /// Frame -> references.
    pub static REFS: Mutex<Option<HashMap<u64, i64>>> = Mutex::new(None);
    /// Free and total bytes the allocator reports.
    pub static FREE: AtomicU64 = AtomicU64::new(1 << 30);
    pub static TOTAL: AtomicU64 = AtomicU64::new(2 << 30);
    /// Allocations still allowed (u64::MAX: unlimited).
    pub static ALLOWED: AtomicU64 = AtomicU64::new(u64::MAX);
    pub fn live() -> usize {
        REFS.lock().unwrap().as_ref().map_or(0, |m| m.values().filter(|&&r| r > 0).count())
    }
    /// Every test thread shares the statics: one test at a time.
    pub static SERIAL: Mutex<()> = Mutex::new(());
}

pub mod memory {
    pub mod frame_allocator {
        use super::super::fake;
        use std::sync::atomic::Ordering;
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        use x86_64::PhysAddr;
        pub struct Fa;
        impl Fa {
            pub fn free_memory(&self) -> u64 {
                fake::FREE.load(Ordering::Relaxed)
            }
            pub fn total_usable_memory(&self) -> u64 {
                fake::TOTAL.load(Ordering::Relaxed)
            }
        }
        pub static FRAME_ALLOCATOR: spin::Mutex<Fa> = spin::Mutex::new(Fa);
        pub fn alloc_user_frame() -> Option<PhysFrame<Size4KiB>> {
            if fake::ALLOWED.load(Ordering::Relaxed) == 0 {
                return None;
            }
            let a = fake::ALLOWED.load(Ordering::Relaxed);
            if a != u64::MAX {
                fake::ALLOWED.store(a - 1, Ordering::Relaxed);
            }
            let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
            let p = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
            fake::REFS.lock().unwrap().get_or_insert_with(Default::default).insert(p, 1);
            fake::FREE.store(fake::FREE.load(Ordering::Relaxed).saturating_sub(4096), Ordering::Relaxed);
            Some(PhysFrame::containing_address(PhysAddr::new(p)))
        }
        pub fn frame_refcount(f: PhysFrame<Size4KiB>) -> u16 {
            let g = fake::REFS.lock().unwrap();
            g.as_ref().and_then(|m| m.get(&f.start_address().as_u64()).copied()).unwrap_or(0).max(0) as u16
        }
        /// A mapping's reference (the fake's PTE).
        pub fn frame_ref_inc(f: PhysFrame<Size4KiB>) {
            *fake::REFS.lock().unwrap().get_or_insert_with(Default::default).entry(f.start_address().as_u64()).or_insert(0) += 1;
        }
        pub fn frame_ref_dec(f: PhysFrame<Size4KiB>) {
            let a = f.start_address().as_u64();
            let mut g = fake::REFS.lock().unwrap();
            let r = g.get_or_insert_with(Default::default).entry(a).or_insert(0);
            *r -= 1;
            assert!(*r >= 0, "frame freed twice");
        }
        pub fn phys_to_virt(p: u64) -> *mut u8 {
            p as *mut u8
        }
    }
    pub mod vm {
        use x86_64::structures::paging::{PhysFrame, Size4KiB};
        pub const PAGE_SIZE: u64 = 4096;
        pub trait MappedObject: Send + Sync {
            fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>>;
            /// wave10 GV1
            fn inode(&self) -> Option<u64> {
                None
            }
        }
    }
}

/// *stub* wave10 GV1: the address spaces' unmapping of cut pages (recorded).
pub mod compat {
    pub mod linux {
        pub mod mm {
            pub static UNMAPS: std::sync::Mutex<Vec<(u64, u64)>> = std::sync::Mutex::new(Vec::new());
            pub fn unmap_past(ino: u64, size: u64) {
                UNMAPS.lock().unwrap().push((ino, size));
            }
            /// wave11 GK: *stub* the page cache's give-back (tmpfs asks it when memory is short)
            pub fn cache_shrink(_want: usize) {}
        }
    }
}

pub mod arch {
    pub mod rtc {
        pub static NOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1_700_000_000);
        pub fn now() -> (u64, u32) {
            (NOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed), 5)
        }
    }
}

pub mod ipc {
    pub mod protocol {
        #[repr(C)]
        #[derive(Clone, Copy, Default, Debug)]
        pub struct LxTmemAttr {
            pub size: u64,
            pub blocks: u64,
            pub mtime_ns: u64,
            pub inst: u64,
        }
        pub const LX_TMEM_ATTR: u64 = 1;
        pub const LX_TMEM_LIMIT: u64 = 2;
        pub const LX_TMEM_USAGE: u64 = 3;
    }
}

pub mod fs {
    pub mod zfs {
        pub mod fsproto {
            #[derive(Debug, Clone, Copy, Default)]
            pub struct Attr {
                pub size: u64,
                pub blocks: u64,
                pub mtime: (i64, u32),
                pub ctime: (i64, u32),
            }
        }
    }
    #[path = "../../../../src/fs/tmem.rs"]
    pub mod tmem;
}

/// vfs-server's `size=` parser (its file uses `hydra_rt`: the function is copied by text).
pub mod vfs_parse {
    include!("vfs_parse.rs");
}

pub fn _unused() -> u64 {
    AtomicU64::new(0).load(Ordering::Relaxed)
}
