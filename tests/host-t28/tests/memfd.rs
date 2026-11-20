//! `memfd.rs` (mostly tested in `tests/host/tests/memfd.rs`): sparse pages, cursors,
//! truncation, mapping, frame accounting — the behaviour the device layer relies on
//! when it shares memory (Wayland keymaps, SysV shm, DRM-like sharing).

mod common;

use hydra_hosttests_t28::compat::linux::memfd::{MemFd, MAX_SIZE, MFD_ALLOW_SEALING, MFD_CLOEXEC};
use hydra_hosttests_t28::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests_t28::memory::vm::MappedObject;

const P: usize = 4096;

fn frames_used() -> u64 {
    FRAME_ALLOCATOR.lock().allocated_memory()
}

/// Exclusive use of the frame pool; checks that nothing leaked.
fn isolated(f: impl FnOnce()) {
    let _g = common::serial();
    common::global_frames();
    let before = frames_used();
    f();
    assert_eq!(frames_used(), before, "frames leaked");
}

#[test]
fn sequential_and_positional_io() {
    isolated(|| {
        assert_eq!((MFD_CLOEXEC, MFD_ALLOW_SEALING), (1, 2));
        let m = MemFd::new("keymap");
        let mut m = m.lock();
        assert_eq!((m.name.as_str(), m.size(), m.cursor, m.seals), ("keymap", 0, 0, 0));
        assert_eq!(m.write(b"hello "), Ok(6));
        assert_eq!(m.write(b"world"), Ok(5));
        let mut b = [0u8; 4];
        assert_eq!(m.read(&mut b), Ok(0));
        m.cursor = 6;
        assert_eq!(m.read(&mut b), Ok(4));
        assert_eq!(&b, b"worl");
        // Across a page boundary
        let data: Vec<u8> = (0..2 * P + 9).map(|i| i as u8).collect();
        assert_eq!(m.write_at(P - 3, &data), data.len());
        let mut back = vec![0u8; data.len()];
        assert_eq!(m.read_at(P - 3, &mut back), data.len());
        assert_eq!(back, data);
        let end = m.size();
        assert_eq!(m.read_at(end, &mut back), 0);
    });
}

#[test]
fn holes_are_free_and_read_as_zero() {
    isolated(|| {
        let before = frames_used();
        let m = MemFd::new("sparse");
        let mut m = m.lock();
        assert_eq!(m.truncate(1 << 30), Ok(()));
        assert_eq!(frames_used(), before, "a large size costs no pages");
        let mut b = [7u8; 16];
        assert_eq!(m.read_at(5 * P, &mut b), 16);
        assert_eq!(b, [0; 16]);
        assert_eq!(m.write_at(3 * P + 1, b"x"), 1);
        assert_eq!(frames_used() - before, P as u64);
    });
}

#[test]
fn truncation_zeroes_the_tail_and_frees_pages() {
    isolated(|| {
        let m = MemFd::new("t");
        let mut m = m.lock();
        m.write_at(0, &vec![0xAB; 3 * P]);
        let before = frames_used();
        assert_eq!(m.truncate(P + 10), Ok(()));
        assert_eq!(before - frames_used(), P as u64);
        // Grow again: the cut part reads as zeros
        m.truncate(2 * P).unwrap();
        let mut b = vec![0u8; 20];
        m.read_at(P, &mut b);
        assert_eq!(&b[..10], &[0xAB; 10]);
        assert_eq!(&b[10..], &[0; 10]);
        assert_eq!(m.truncate(MAX_SIZE + 1), Err(-27));
        assert_eq!(m.size(), 2 * P);
        // Writes ending past the largest size, or overflowing, write nothing
        assert_eq!(m.write_at(MAX_SIZE, b"ab"), 0);
        assert_eq!(m.write_at(usize::MAX, b"ab"), 0);
    });
}

#[test]
fn mapping_and_frames_for() {
    isolated(|| {
        let m = MemFd::new("map");
        {
            let mut g = m.lock();
            g.write_at(0, b"first page");
            let frames = g.frames_for(3 * P - 1).unwrap();
            assert_eq!(frames.len(), 3);
            assert_eq!(g.size(), 3 * P - 1);
            assert_eq!(unsafe { *(frames[0].start_address().as_u64() as *const u8) }, b'f');
        }
        // The mapped object hands out the same frames, and none past the end
        let f0 = m.get_page(0).unwrap();
        assert_eq!(unsafe { *(f0.start_address().as_u64() as *const u8) }, b'f');
        assert!(m.get_page(2).is_some());
        assert!(m.get_page(3).is_none());
        assert!(!m.tracks_writes());
        m.page_written(0);
        m.sync();
        drop(m);
    });
}
