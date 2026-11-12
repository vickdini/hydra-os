//! Tests for the Linux memory syscalls in `src/compat/linux/mm.rs`: argument
//! validation in `mmap`/`munmap`/`mprotect`/`brk`/`mremap`/`madvise`/
//! `mincore`, mapping each kind of file descriptor, and the shared
//! per-inode page cache (`InodeObject`).
//!
//! These wrappers sit in front of the real `Mm` (tests/vm.rs). Descriptors,
//! inode contents and the current task's address space come from the fakes
//! in `src/fake.rs`.

mod common;

use std::sync::Arc;

use hydra_hosttests::compat::linux::chardev::CharDevice;
use hydra_hosttests::compat::linux::memfd::MemFd;
use hydra_hosttests::compat::linux::mm::*;
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;
use hydra_hosttests::memory::frame_allocator::{frame_refcount, FRAME_ALLOCATOR};
use hydra_hosttests::memory::vm::{MappedObject, Mm, BufferObject, LOW_USER_END, LOW_USER_START, PAGE_SIZE, PROT_READ, PROT_WRITE, USER_SPACE_START};
use spin::Mutex;

const P: u64 = PAGE_SIZE;
const RW: u64 = (PROT_READ | PROT_WRITE) as u64;
const A: u64 = USER_SPACE_START + 0x2000_0000;
const EBADF: i64 = -9;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ANON_PRIVATE: u64 = MAP_ANONYMOUS | MAP_PRIVATE;

fn used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

/// Fresh address space and fakes; checks for leaked frames afterwards.
fn with_mm(f: impl FnOnce(&Mutex<Mm>)) {
    let _g = common::serial();
    common::global_frames();
    fake::reset();
    let before = used();
    {
        let mm = Mutex::new(Mm::new().unwrap());
        f(&mm);
        fake::FDS.with_borrow_mut(|f| f.open.clear()); // drop descriptors before the pool check
    }
    assert_eq!(used(), before, "frames leaked");
}

fn peek(mm: &Mutex<Mm>, addr: u64, len: usize) -> Vec<u8> {
    let mut m = mm.lock();
    m.prefault(addr, len as u64, false).unwrap();
    (0..len as u64).map(|i| unsafe { *(m.translate(addr + i).unwrap().as_u64() as *const u8) }).collect()
}

fn install(fd: usize, d: FileDescriptor) {
    fake::FDS.with_borrow_mut(|f| f.install(fd, d));
}

// ------------------------------------------------------------------ mmap

#[test]
fn mmap_validates_arguments() {
    with_mm(|mm| {
        assert_eq!(sys_mmap(mm, 0, 0, RW, ANON_PRIVATE, -1, 0), EINVAL, "zero length");
        assert_eq!(sys_mmap(mm, 0, P, RW, ANON_PRIVATE, -1, 100), EINVAL, "unaligned offset");
        assert_eq!(sys_mmap(mm, 0, P, RW, MAP_ANONYMOUS, -1, 0), EINVAL, "neither SHARED nor PRIVATE");
        assert_eq!(sys_mmap(mm, A + 1, P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0), EINVAL);
    });
}

#[test]
fn anonymous_mappings() {
    with_mm(|mm| {
        let a = sys_mmap(mm, 0, 3 * P, RW, ANON_PRIVATE, -1, 0);
        assert!(a > 0 && a as u64 % P == 0);
        assert!(!mm.lock().find_vma(a as u64).unwrap().shared);
        let s = sys_mmap(mm, 0, P, RW, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        assert!(mm.lock().find_vma(s as u64).unwrap().shared);
        assert_eq!(sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0), A as i64);
        assert_eq!(sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0), -17, "EEXIST");
    });
}

#[test]
fn map_32bit_places_mappings_in_the_low_window() {
    // Below 2 GiB: Hydra's low user window [64 KiB, 1 GiB) (Linux uses [1 GiB, 2 GiB),
    // which is kernel space here); a free hint is used first
    const LO: u64 = LOW_USER_START;
    const HI: u64 = LOW_USER_END;
    with_mm(|mm| {
        let a = sys_mmap(mm, 0, 4 * P, RW, ANON_PRIVATE | MAP_32BIT, -1, 0) as u64;
        assert!(a >= LO && a + 4 * P <= HI, "{a:#x} outside the window");
        let b = sys_mmap(mm, 0, P, RW, ANON_PRIVATE | MAP_32BIT, -1, 0) as u64;
        assert!(b >= LO && b + P <= HI && (b + P <= a || b >= a + 4 * P), "second mapping overlaps or escapes");
        assert_eq!(sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_32BIT, -1, 0), A as i64, "free hint taken as is");
        // A taken hint falls back to the window, not to the top of the address space
        let c = sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_32BIT, -1, 0) as u64;
        assert!(c >= LO && c + P <= HI, "{c:#x}");
        // The window full: ENOMEM rather than a high address
        assert_eq!(sys_mmap(mm, LO, HI - LO, RW, ANON_PRIVATE | MAP_FIXED, -1, 0), LO as i64);
        assert_eq!(sys_mmap(mm, 0, P, RW, ANON_PRIVATE | MAP_32BIT, -1, 0), ENOMEM);
    });
}

#[test]
fn fd_minus_one_without_map_anonymous_is_anonymous() {
    // What Linux does too: a private mapping of fd -1 is treated as anonymous.
    with_mm(|mm| {
        assert!(sys_mmap(mm, 0, P, RW, MAP_PRIVATE, -1, 0) > 0);
    });
}

#[test]
fn bad_descriptors() {
    with_mm(|mm| {
        assert_eq!(sys_mmap(mm, 0, P, RW, MAP_PRIVATE, -2, 0), EBADF);
        assert_eq!(sys_mmap(mm, 0, P, RW, MAP_PRIVATE, 7, 0), EBADF, "not open");
        let efd = hydra_hosttests::compat::linux::eventfd::EventFd::new(0, 0);
        install(8, FileDescriptor::EventFd(efd));
        assert_eq!(sys_mmap(mm, 0, P, RW, MAP_PRIVATE, 8, 0), ENODEV, "eventfd cannot be mapped");
    });
}

#[test]
fn mapping_a_memfd_shares_its_pages() {
    with_mm(|mm| {
        let m = MemFd::new("pool");
        m.lock().write_at(0, &vec![5u8; 2 * P as usize]);
        install(4, FileDescriptor::MemFd { memfd: m.clone(), flags: 2 });
        let a = sys_mmap(mm, 0, 2 * P, RW, MAP_SHARED, 4, P) as u64;
        mm.lock().write_bytes(a, b"hi").unwrap();
        let mut buf = [0u8; 3];
        m.lock().read_at(P as usize, &mut buf);
        assert_eq!(&buf, b"hi\x05", "offset P maps the second page, writes reach the memfd");
        let name = mm.lock().find_vma(a).unwrap().name.clone();
        assert_eq!(name.as_deref(), Some("/memfd:pool (deleted)"), "as /proc/<pid>/maps shows it");
    });
}

#[test]
fn mapping_a_zfs_file() {
    with_mm(|mm| {
        let ino = 9001;
        let content: Vec<u8> = (0..P as usize + 100).map(|i| i as u8).collect();
        fake::INODES.with_borrow_mut(|m| m.insert(ino, content.clone()));
        let vnode = Arc::new(Mutex::new(fake::Vnode { ino, path: "/usr/lib/libz.so".into(), readable: true }));
        install(5, FileDescriptor::Vnode(vnode));
        let a = sys_mmap(mm, 0, 2 * P, PROT_READ as u64, MAP_PRIVATE, 5, 0) as u64;
        assert_eq!(peek(mm, a + P, 100), &content[P as usize..], "page cache filled from ZFS");
        assert_eq!(mm.lock().find_vma(a).unwrap().name.as_deref(), Some("/usr/lib/libz.so"));
        assert_eq!(fake::INODE_REFS.with_borrow(|r| r[&ino]), 1, "mapping holds the inode open");
    });
}

#[test]
fn write_only_files_cannot_be_mapped() {
    with_mm(|mm| {
        fake::INODES.with_borrow_mut(|m| m.insert(9002, vec![0; 10]));
        let vnode = Arc::new(Mutex::new(fake::Vnode { ino: 9002, path: "/tmp/w".into(), readable: false }));
        install(5, FileDescriptor::Vnode(vnode));
        assert_eq!(sys_mmap(mm, 0, P, PROT_READ as u64, MAP_SHARED, 5, 0), EACCES);
        install(6, FileDescriptor::File { path: "/tmp/w".into(), readable: false });
        assert_eq!(sys_mmap(mm, 0, P, PROT_READ as u64, MAP_SHARED, 6, 0), EACCES);
    });
}

#[test]
fn path_based_file_descriptors_resolve_their_inode() {
    with_mm(|mm| {
        fake::INODES.with_borrow_mut(|m| m.insert(9003, b"legacy".to_vec()));
        fake::INODE_PATHS.with_borrow_mut(|m| m.insert("/etc/motd".into(), 9003));
        install(6, FileDescriptor::File { path: "/etc/motd".into(), readable: true });
        let a = sys_mmap(mm, 0, P, PROT_READ as u64, MAP_PRIVATE, 6, 0) as u64;
        assert_eq!(peek(mm, a, 6), b"legacy");
        install(7, FileDescriptor::File { path: "/gone".into(), readable: true });
        assert_eq!(sys_mmap(mm, 0, P, PROT_READ as u64, MAP_PRIVATE, 7, 0), ENODEV);
    });
}

struct FrameBuffer(Arc<BufferObject>);

/// Boilerplate `CharDevice` methods these mmap tests do not exercise.
macro_rules! device_basics {
    () => {
        fn read(&self, _buf: &mut [u8]) -> i64 {
            0
        }
        fn poll_events(&self) -> u32 {
            0
        }
        fn add_wait_queues(&self, _waits: &mut hydra_hosttests::task::wait::WaitSet) {}
        fn rdev(&self) -> u64 {
            0
        }
        fn set_nonblock(&self, _on: bool) {}
        fn nonblock(&self) -> bool {
            false
        }
    };
}

impl CharDevice for FrameBuffer {
    device_basics!();
    fn path(&self) -> String {
        "/dev/fb0".into()
    }
    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Ok(self.0.clone())
    }
}

struct NoMmap;

impl CharDevice for NoMmap {
    device_basics!();
    fn path(&self) -> String {
        "/dev/null".into()
    }
    // mmap_object: the trait default (ENODEV)
}

#[test]
fn device_mappings() {
    with_mm(|mm| {
        let fb = BufferObject::new(vec![0xAB; P as usize].into_boxed_slice());
        install(3, FileDescriptor::Device(Arc::new(FrameBuffer(fb))));
        let a = sys_mmap(mm, 0, P, RW, MAP_SHARED, 3, 0) as u64;
        assert_eq!(peek(mm, a, 2), [0xAB, 0xAB]);
        assert_eq!(mm.lock().find_vma(a).unwrap().name.as_deref(), Some("/dev/fb0"));
        install(4, FileDescriptor::Device(Arc::new(NoMmap)));
        assert_eq!(sys_mmap(mm, 0, P, RW, MAP_SHARED, 4, 0), ENODEV);
    });
}

// ------------------------------------------------------------ inode cache

#[test]
fn inode_objects_are_shared_and_release_the_inode() {
    with_mm(|_| {
        let ino = 9100;
        fake::INODES.with_borrow_mut(|m| m.insert(ino, vec![1; 3 * P as usize]));
        let a = inode_object(ino);
        let b = inode_object(ino);
        assert!(Arc::ptr_eq(&a, &b), "one page cache per inode");
        assert_eq!(fake::INODE_REFS.with_borrow(|r| r[&ino]), 1);
        let p = a.get_page(2).unwrap();
        assert_eq!(b.get_page(2), Some(p), "cached");
        assert!(a.get_page(3).is_none(), "past EOF");
        drop((a, b));
        assert_eq!(fake::INODE_REFS.with_borrow(|r| r[&ino]), 0, "released with the last mapping");
    });
}

#[test]
fn inode_read_errors_do_not_leak_frames() {
    with_mm(|_| {
        fake::INODES.with_borrow_mut(|m| m.insert(9101, vec![1; 100]));
        fake::INODE_READ_FAILS.set(true);
        let o = inode_object(9101);
        assert!(o.get_page(0).is_none());
    });
}

#[test]
fn inode_source_for_exec() {
    with_mm(|_| {
        fake::INODES.with_borrow_mut(|m| m.insert(9102, vec![7; 100_000]));
        let src = inode_source(9102).unwrap();
        assert_eq!((src.head.len(), src.len), (65_536, 100_000));
        assert_eq!(inode_source(424242).err(), Some(-2));
    });
}

#[test]
fn current_mm_comes_from_the_task() {
    with_mm(|_| {
        assert!(current_mm().is_none());
        let mm = Arc::new(Mutex::new(Mm::new().unwrap()));
        fake::TASK_MM.with_borrow_mut(|m| *m = Some(mm.clone()));
        assert!(Arc::ptr_eq(&current_mm().unwrap(), &mm));
        fake::TASK_MM.with_borrow_mut(|m| *m = None);
    });
}

// ------------------------------------------------- munmap, mprotect, brk

#[test]
fn munmap_validation() {
    with_mm(|mm| {
        sys_mmap(mm, A, 2 * P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0);
        assert_eq!(sys_munmap(mm, A + 1, P), EINVAL);
        assert_eq!(sys_munmap(mm, A, 0), EINVAL);
        assert_eq!(sys_munmap(mm, 0xFFFF_8000_0000_0000, P), EINVAL, "kernel range");
        assert_eq!(sys_munmap(mm, A, u64::MAX), EINVAL, "overflow");
        assert_eq!(sys_munmap(mm, A, 1), 0, "length rounds up to a page");
        assert!(mm.lock().find_vma(A).is_none());
        assert!(mm.lock().find_vma(A + P).is_some());
    });
}

#[test]
fn mprotect_and_brk_pass_through() {
    with_mm(|mm| {
        sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0);
        assert_eq!(sys_mprotect(mm, A, P, PROT_READ as u64), 0);
        assert_eq!(mm.lock().find_vma(A).unwrap().prot, PROT_READ);
        assert_eq!(sys_mprotect(mm, A + 8 * P, P, PROT_READ as u64), ENOMEM);
        {
            let mut m = mm.lock();
            m.brk_start = A + 16 * P;
            m.brk = A + 16 * P;
        }
        assert_eq!(sys_brk(mm, 0), (A + 16 * P) as i64);
        assert_eq!(sys_brk(mm, A + 18 * P), (A + 18 * P) as i64);
    });
}

#[test]
fn mremap_flag_validation() {
    with_mm(|mm| {
        sys_mmap(mm, A, P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0);
        assert_eq!(sys_mremap(mm, A, P, 2 * P, 4, 0), EINVAL, "unknown flag");
        assert_eq!(sys_mremap(mm, A, P, P, MREMAP_FIXED, A + 64 * P), EINVAL, "FIXED needs MAYMOVE");
        assert_eq!(sys_mremap(mm, A, P, 2 * P, 0, 0), A as i64, "grow in place");
        let to = A + 64 * P;
        assert_eq!(sys_mremap(mm, A, 2 * P, 2 * P, MREMAP_MAYMOVE | MREMAP_FIXED, to), to as i64);
    });
}

// -------------------------------------------------------- madvise, mincore

#[test]
fn madvise_dontneed_drops_pages() {
    with_mm(|mm| {
        sys_mmap(mm, A, 2 * P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0);
        mm.lock().write_bytes(A, b"data").unwrap();
        assert_eq!(sys_madvise(mm, A + 1, P, MADV_DONTNEED), EINVAL);
        assert_eq!(sys_madvise(mm, A, P, 3 /* MADV_WILLNEED */), 0, "hints are accepted");
        assert_eq!(peek(mm, A, 4), b"data", "and change nothing");
        assert_eq!(sys_madvise(mm, A, P, MADV_DONTNEED), 0);
        assert_eq!(peek(mm, A, 4), [0; 4], "anonymous pages read back as zero");
        assert_eq!(sys_madvise(mm, A, P, MADV_FREE), 0);
    });
}

#[test]
#[ignore = "BUG (security): sys_madvise never checks that the range is user memory, and \
            Mm::discard walks whatever tables the address leads to. Every process's PML4 shares \
            the kernel half, so madvise(kernel_addr, len, MADV_DONTNEED) from any process clears \
            kernel page-table entries and frees kernel frames \
            (src/compat/linux/mm.rs, sys_madvise; src/memory/vm.rs, discard)"]
fn madvise_cannot_touch_kernel_memory() {
    let _g = common::serial();
    common::global_frames();
    let mm = Mutex::new(Mm::new().unwrap());
    // Build a stand-in for the shared kernel half: PML4[256] -> PDPT -> PD -> PT -> one page,
    // mapped at 0xffff_8000_0000_0000 like the kernel's own mappings (no USER bit).
    let (pdpt, pd, pt, page) = {
        let mut fa = FRAME_ALLOCATOR.lock();
        let mut f = || fa.allocate_zeroed_frame().unwrap().start_address().as_u64();
        (f(), f(), f(), f())
    };
    let link = |table: u64, idx: usize, to: u64| unsafe { *(table as *mut u64).add(idx) = to | 0x3 };
    link(mm.lock().cr3(), 256, pdpt);
    link(pdpt, 0, pd);
    link(pd, 0, pt);
    link(pt, 0, page);
    unsafe { *(page as *mut u64) = 0x4B45_524E_454C }; // "KERNEL"
    let kernel = 0xFFFF_8000_0000_0000u64;

    let r = sys_madvise(&mm, kernel, P, MADV_DONTNEED);

    let pte = unsafe { *(pt as *const u64) };
    let intact = pte & 1 == 1 && pte & !0xFFF == page;
    let refs = frame_refcount(x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(page)));
    // Detach the fake kernel half before `mm` drops (it only frees the user half).
    unsafe { *(mm.lock().cr3() as *mut u64).add(256) = 0 };
    assert!(intact, "madvise from user space cleared a kernel page-table entry (returned {r})");
    assert_eq!(refs, 1, "kernel frame refcount changed");
    assert_ne!(r, 0, "Linux rejects ranges outside the user address space (EINVAL/ENOMEM)");
}

#[test]
fn mincore_reports_mapped_pages() {
    with_mm(|mm| {
        sys_mmap(mm, A, 3 * P, RW, ANON_PRIVATE | MAP_FIXED, -1, 0);
        let mut vec = [0u8; 3];
        // No current Mm (`vm::CURRENT_MM` is null), so the result is written straight to `vec`.
        assert_eq!(sys_mincore(mm, A, 3 * P, vec.as_mut_ptr() as u64), 0);
        assert_eq!(vec, [1, 1, 1]);
        assert_eq!(sys_mincore(mm, A + 1, P, vec.as_mut_ptr() as u64), EINVAL);
        assert_eq!(sys_mincore(mm, A, 4 * P, vec.as_mut_ptr() as u64), ENOMEM, "last page unmapped");
    });
}
