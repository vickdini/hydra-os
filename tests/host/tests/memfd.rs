//! Tests for `memfd_create` files (`src/compat/linux/memfd.rs`): a sparse
//! array of physical pages with read/write cursors, truncation, and mapping
//! support (`MappedObject`). Also used for SysV shared memory, Wayland
//! keymaps and secretmem.
//!
//! Pages come from the shared frame pool (`common::global_frames`). This
//! binary installs a counting global allocator, so tests can also see how
//! much kernel *heap* an operation needs.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use hydra_hosttests::compat::linux::memfd::*;
use hydra_hosttests::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests::memory::vm::{Backing, MappedObject, Mm, PAGE_SIZE, PROT_READ, PROT_WRITE, USER_SPACE_START};

const P: usize = PAGE_SIZE as usize;

// ------------------------------------------------------- heap accounting

struct Counting;

static HEAP: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        HEAP.fetch_add(l.size() as isize, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        HEAP.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        HEAP.fetch_add(new as isize - l.size() as isize, Ordering::Relaxed);
        System.realloc(p, l, new)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn frames_used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

/// Exclusive use of the frame pool and heap counter; checks frame leaks.
fn isolated(f: impl FnOnce()) {
    let _g = common::serial();
    common::global_frames();
    let before = frames_used();
    f();
    assert_eq!(frames_used(), before, "frames leaked");
}

fn read_all(m: &mut MemFd) -> Vec<u8> {
    let mut buf = vec![0xFFu8; m.size()];
    let n = m.read_at(0, &mut buf);
    buf.truncate(n);
    buf
}

// ------------------------------------------------------------- basics

#[test]
fn new_memfd_is_empty() {
    isolated(|| {
        let m = MemFd::new("wayland-keymap");
        let m = m.lock();
        assert_eq!((m.name.as_str(), m.size(), m.cursor, m.seals), ("wayland-keymap", 0, 0, 0));
        assert_eq!((MFD_CLOEXEC, MFD_ALLOW_SEALING), (1, 2), "Linux values");
    });
}

#[test]
fn write_and_read_advance_the_cursor() {
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        assert_eq!(m.write(b"hello "), Ok(6));
        assert_eq!(m.write(b"world"), Ok(5));
        assert_eq!((m.size(), m.cursor), (11, 11));
        let mut buf = [0u8; 4];
        assert_eq!(m.read(&mut buf), Ok(0), "cursor at end of file");
        m.cursor = 0;
        assert_eq!(m.read(&mut buf), Ok(4));
        assert_eq!(&buf, b"hell");
        assert_eq!(m.cursor, 4);
    });
}

#[test]
fn positional_io_spans_pages() {
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        let data: Vec<u8> = (0..3 * P + 17).map(|i| (i * 13) as u8).collect();
        assert_eq!(m.write_at(P - 5, &data), data.len());
        assert_eq!(m.size(), P - 5 + data.len());
        let mut back = vec![0u8; data.len()];
        assert_eq!(m.read_at(P - 5, &mut back), data.len());
        assert_eq!(back, data);
        assert_eq!(m.cursor, 0, "positional I/O leaves the cursor alone");
    });
}

#[test]
fn reads_stop_at_end_of_file() {
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        m.write_at(0, b"abc");
        let mut buf = [9u8; 10];
        assert_eq!(m.read_at(1, &mut buf), 2);
        assert_eq!(&buf[..3], b"bc\x09");
        assert_eq!(m.read_at(3, &mut buf), 0);
        assert_eq!(m.read_at(100, &mut buf), 0);
    });
}

#[test]
fn writing_past_the_end_leaves_a_zero_hole() {
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        m.write_at(2 * P + 10, b"tail");
        assert_eq!(m.size(), 2 * P + 14);
        let all = read_all(&mut m);
        assert!(all[..2 * P + 10].iter().all(|&b| b == 0));
        assert_eq!(&all[2 * P + 10..], b"tail");
    });
}

// ----------------------------------------------------------- truncate

#[test]
fn truncate_shrinks_and_frees_pages() {
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        m.write_at(0, &vec![1u8; 4 * P]);
        let before = frames_used();
        m.truncate(P + 1).unwrap();
        assert_eq!(m.size(), P + 1);
        assert_eq!(frames_used(), before - 2 * PAGE_SIZE, "pages past the new end are freed");
    });
}

#[test]
fn shrink_then_grow_reads_zeros_not_old_data() {
    // POSIX: bytes past a truncation point read as zero after re-extension.
    isolated(|| {
        let m = MemFd::new("x");
        let mut m = m.lock();
        m.write_at(0, &vec![b'A'; 2 * P]);
        m.truncate(100).unwrap();
        m.truncate(2 * P).unwrap();
        let all = read_all(&mut m);
        assert!(all[..100].iter().all(|&b| b == b'A'));
        assert!(all[100..].iter().all(|&b| b == 0), "old data resurfaced after truncate");
    });
}

#[test]
fn growing_does_not_allocate_pages() {
    isolated(|| {
        let m = MemFd::new("x");
        let before = frames_used();
        m.lock().truncate(100 * P).unwrap();
        assert_eq!(m.lock().size(), 100 * P);
        assert_eq!(frames_used(), before, "growing is sparse");
    });
}

#[test]
fn sparse_size_does_not_cost_heap() {
    isolated(|| {
        let m = MemFd::new("x");
        let heap = HEAP.load(Ordering::Relaxed);
        m.lock().truncate(16 << 30).unwrap();
        let grew = HEAP.load(Ordering::Relaxed) - heap;
        assert!(grew < 1 << 20, "a sparse 16 GiB memfd took {} MiB of kernel heap", grew >> 20);
    });
}

#[test]
fn absurd_sizes_are_refused_without_losing_data() {
    isolated(|| {
        let m = MemFd::new("x");
        m.lock().write_at(0, b"keep me");
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| m.lock().truncate(usize::MAX)));
        let mut buf = [0u8; 7];
        let n = m.lock().read_at(0, &mut buf);
        assert!(r.is_ok() && n == 7 && &buf == b"keep me", "data lost after truncate(usize::MAX)");
        assert_eq!(r.unwrap(), Err(-27), "EFBIG, as Linux past MAX_LFS_FILESIZE");
        assert_eq!(m.lock().write_at(usize::MAX - 2, b"abc"), 0, "a write ending past the largest size writes nothing");
    });
}

// ------------------------------------------------------- page handling

#[test]
#[ignore = "BUG (low): reading a hole allocates a physical page for it (read_at goes through \
            page(), which allocates on demand); Linux reads holes as zeros without allocating \
            (src/compat/linux/memfd.rs, read_at)"]
fn reading_holes_does_not_allocate() {
    isolated(|| {
        let m = MemFd::new("x");
        m.lock().truncate(50 * P).unwrap();
        let before = frames_used();
        let mut buf = vec![0u8; 50 * P];
        assert_eq!(m.lock().read_at(0, &mut buf), 50 * P);
        assert_eq!(frames_used(), before, "{} pages allocated to read zeros", (frames_used() - before) / PAGE_SIZE);
    });
}

#[test]
fn frames_for_grows_and_returns_every_page() {
    isolated(|| {
        let m = MemFd::new("x");
        let frames = m.lock().frames_for(3 * P - 1).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(m.lock().size(), 3 * P - 1, "grown to the mapping length");
        let mut sorted = frames.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), 3, "distinct frames");
        assert_eq!(m.get_page(1), Some(frames[1]), "same frames the mapping path sees");
    });
}

#[test]
fn mapped_object_pages_stop_at_end_of_file() {
    isolated(|| {
        let m = MemFd::new("x");
        m.lock().write_at(0, &vec![7u8; P + 1]);
        assert!(m.get_page(0).is_some());
        assert!(m.get_page(1).is_some(), "partial last page is mappable");
        assert!(m.get_page(2).is_none(), "past EOF: SIGBUS");
    });
}

#[test]
fn shared_mapping_and_file_io_see_the_same_bytes() {
    isolated(|| {
        let m = MemFd::new("shm");
        m.lock().truncate(2 * P).unwrap();
        let mut mm = Mm::new().unwrap();
        let a = USER_SPACE_START + 0x100_0000;
        let obj: std::sync::Arc<dyn MappedObject> = m.clone();
        mm.mmap(a, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE, true, true, false, Backing::Object { obj, pgoff: 0 }).unwrap();
        mm.write_bytes(a + PAGE_SIZE + 3, b"via mmap").unwrap();
        let mut buf = [0u8; 8];
        m.lock().read_at(P + 3, &mut buf);
        assert_eq!(&buf, b"via mmap", "MAP_SHARED writes reach the file");

        m.lock().write_at(0, b"via write");
        let phys = mm.translate(a).unwrap_or_else(|| {
            mm.handle_fault(a, false, false).unwrap();
            mm.translate(a).unwrap()
        });
        let seen = unsafe { std::slice::from_raw_parts(phys.as_u64() as *const u8, 9) };
        assert_eq!(seen, b"via write", "file writes show through the mapping");
    });
}

#[test]
fn dropping_frees_every_page() {
    isolated(|| {
        let m = MemFd::new("x");
        m.lock().write_at(0, &vec![1u8; 10 * P]);
        assert!(frames_used() > 0);
        drop(m); // `isolated` checks the pool is back where it started
    });
}
