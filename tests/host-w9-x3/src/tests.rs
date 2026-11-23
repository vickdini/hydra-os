//! Tests of lx-ipc's kept arena and records (see `lib.rs`).

use crate::arena::{Arena, Chain, HDR, IMG, UNIT};
use crate::kstore;

/// An arena over a fresh buffer of `units` units (leaked: chains point into it).
fn arena(units: usize) -> (Arena, *mut u8) {
    let buf: &'static mut [u8] = Box::leak(vec![0u8; units * UNIT].into_boxed_slice());
    let p = buf.as_mut_ptr();
    // SAFETY: the buffer lives for the test process
    (unsafe { Arena::new(p, units * UNIT) }, p)
}

/// The same memory seen by a new instance (a restart): every unit free again.
fn reopen(p: *mut u8, units: usize) -> Arena {
    // SAFETY: as in `arena`
    unsafe { Arena::new(p, units * UNIT) }
}

fn bytes(c: &Chain, a: &Arena) -> Vec<u8> {
    let mut v = Vec::new();
    c.copy(a, 0, c.bytes, &mut v);
    v
}

#[test]
fn alloc_first_fit_and_free() {
    let (a, _) = arena(256);
    let x = a.alloc(3).unwrap();
    let y = a.alloc(2).unwrap();
    assert_eq!((x, y), (0, 3));
    a.free(x, 3);
    // the hole at the start is used first, and a run that does not fit there goes after
    assert_eq!(a.alloc(4).unwrap(), 5);
    assert_eq!(a.alloc(2).unwrap(), 0);
    assert_eq!(a.used(), 2 + 4 + 2);
    assert_eq!(a.alloc(0), None);
    assert_eq!(a.alloc(1000), None);
    // a full arena
    let (b, _) = arena(64);
    assert_eq!(b.alloc(64), Some(0));
    assert_eq!(b.alloc(1), None);
    b.free(10, 1);
    assert_eq!(b.alloc(1), Some(10));
}

#[test]
fn alloc_skips_full_words() {
    let (a, _) = arena(1024);
    assert_eq!(a.alloc(200), Some(0));
    assert_eq!(a.alloc(70), Some(200));
    a.free(5, 1);
    assert_eq!(a.alloc(2), Some(270));
    assert_eq!(a.alloc(1), Some(5));
}

#[test]
fn mark_rejects_overlap_and_outside() {
    let (a, _) = arena(128);
    assert!(a.mark(10, 4));
    assert!(!a.mark(12, 4));
    assert!(!a.mark(126, 4));
    assert!(!a.mark(0, 0));
    assert!(a.mark(14, 2));
    assert_eq!(a.used(), 6);
    assert_eq!(a.alloc(10), Some(0));
    assert_eq!(a.alloc(1), Some(16));
}

#[test]
fn chain_push_copy_consume() {
    let (a, _) = arena(512);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"hello ", 0));
    assert!(c.push(&a, b"meta", b"world", 0));
    assert_eq!(c.bytes, 11);
    assert_eq!(bytes(&c, &a), b"hello world");
    assert_eq!(c.meta(&a, 1), b"meta");
    let mut v = Vec::new();
    c.copy(&a, 3, 5, &mut v);
    assert_eq!(v, b"lo wo");
    c.consume(4);
    assert_eq!((c.head_pos, c.bytes), (4, 7));
    assert_eq!(bytes(&c, &a), b"o world");
    c.consume(2);
    // the first segment went (its units only after release)
    assert_eq!((c.segs.len(), c.head_pos, c.bytes), (1, 0, 5));
    let used = a.used();
    c.release(&a);
    assert!(a.used() < used);
    c.consume(100);
    assert_eq!((c.segs.len(), c.bytes), (0, 0));
    c.release(&a);
    assert_eq!(a.used(), 0);
}

#[test]
fn chain_append_uses_spare_room() {
    let (a, _) = arena(512);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"ab", 1000));
    assert_eq!(c.append(&a, b"cdef"), 4);
    assert_eq!(c.segs.len(), 1);
    assert_eq!(bytes(&c, &a), b"abcdef");
    // no room beyond the segment's units
    let room = c.segs[0].units as usize * UNIT - HDR - 6;
    let big = vec![7u8; room + 10];
    assert_eq!(c.append(&a, &big), room);
    // a segment with metadata takes no appended bytes
    assert!(c.push(&a, b"m", b"x", 500));
    assert_eq!(c.append(&a, b"y"), 0);
}

#[test]
fn image_restore_round_trip() {
    let (a, p) = arena(1024);
    let mut c = Chain::new();
    for i in 0..20u8 {
        assert!(c.push(&a, &[i], &vec![i; 100 + i as usize * 37], 64));
        c.append(&a, &[i; 10]);
    }
    c.consume(250);
    c.release(&a);
    let img = c.image();
    let want = bytes(&c, &a);
    let metas: Vec<Vec<u8>> = (0..c.segs.len()).map(|i| c.meta(&a, i).to_vec()).collect();
    // a new instance over the same memory
    let b = reopen(p, 1024);
    let r = Chain::restore(&b, &img).expect("restored");
    assert_eq!(bytes(&r, &b), want);
    assert_eq!((r.head_pos, r.bytes, r.segs.len()), (c.head_pos, c.bytes, c.segs.len()));
    assert_eq!((0..r.segs.len()).map(|i| r.meta(&b, i).to_vec()).collect::<Vec<_>>(), metas);
    // exactly the chain's units are taken
    assert_eq!(b.used(), c.segs.iter().map(|s| s.units as usize).sum::<usize>());
}

#[test]
fn restore_of_empty_image() {
    let (a, _) = arena(64);
    let c = Chain::new();
    let r = Chain::restore(&a, &c.image()).unwrap();
    assert_eq!((r.bytes, r.segs.len()), (0, 0));
    // an empty image that says it has bytes is damaged
    let mut img = c.image();
    img[16] = 1;
    assert!(Chain::restore(&a, &img).is_none());
    assert!(Chain::restore(&a, &img[..10]).is_none());
}

#[test]
fn crash_before_commit_keeps_the_old_queue() {
    let (a, p) = arena(512);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"one", 200));
    let committed = c.image();
    // after the commit: bytes appended to the tail, a new segment linked; no new record
    c.append(&a, b"-more");
    assert!(c.push(&a, &[], b"two", 0));
    let b = reopen(p, 512);
    let r = Chain::restore(&b, &committed).unwrap();
    assert_eq!(bytes(&r, &b), b"one");
    // the new segment's units are free in the new instance
    assert_eq!(b.used(), r.segs[0].units as usize);
}

#[test]
fn damaged_chains_are_refused_and_take_nothing() {
    let (a, p) = arena(512);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"aaaa", 0));
    assert!(c.push(&a, &[], b"bbbb", 0));
    assert!(c.push(&a, &[], b"cccc", 0));
    let img = c.image();
    let second = c.segs[1].unit as usize;
    // a bad check word in the middle segment
    // SAFETY: the test's own buffer
    unsafe { *p.add(second * UNIT + 12) ^= 0x55 };
    let b = reopen(p, 512);
    assert!(Chain::restore(&b, &img).is_none());
    assert_eq!(b.used(), 0);
    unsafe { *p.add(second * UNIT + 12) ^= 0x55 };
    // a byte count that does not add up
    let mut bad = img;
    bad[16] = 99;
    assert!(Chain::restore(&b, &bad).is_none());
    // fewer segments than the chain has
    let mut bad = img;
    bad[20] = 2;
    assert!(Chain::restore(&b, &bad).is_none());
    // a head offset past the head's data
    let mut bad = img;
    bad[4] = 50;
    assert!(Chain::restore(&b, &bad).is_none());
    // a unit outside the arena
    let mut bad = img;
    bad[0..4].copy_from_slice(&100_000u32.to_le_bytes());
    assert!(Chain::restore(&b, &bad).is_none());
    assert_eq!(b.used(), 0);
    // and the good image still works
    assert!(Chain::restore(&b, &img).is_some());
}

#[test]
fn two_chains_cannot_share_a_segment() {
    let (a, p) = arena(256);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"shared", 0));
    let img = c.image();
    let b = reopen(p, 256);
    assert!(Chain::restore(&b, &img).is_some());
    assert!(Chain::restore(&b, &img).is_none());
}

#[test]
fn image_layout() {
    let (a, _) = arena(64);
    let mut c = Chain::new();
    assert!(c.push(&a, &[], b"xy", 0));
    let img = c.image();
    assert_eq!(img.len(), IMG);
    assert_eq!(u32::from_le_bytes(img[0..4].try_into().unwrap()), c.segs[0].unit + 1);
    assert_eq!(u32::from_le_bytes(img[12..16].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(img[20..24].try_into().unwrap()), 1);
}

#[test]
fn push_fails_cleanly_when_full() {
    let (a, _) = arena(4);
    let mut c = Chain::new();
    assert!(!c.push(&a, &[], &vec![0u8; 4 * UNIT], 0));
    assert_eq!((c.bytes, a.used()), (0, 0));
    assert!(c.push(&a, &[], &vec![1u8; UNIT], 0));
    assert_eq!(a.used(), 2);
}

#[test]
fn records_ids_and_restart() {
    // Not kept (linux-server): ids are handed out, keys are 0, writes do nothing
    let id = kstore::id();
    assert!(id >= 1);
    assert_eq!(kstore::key(id), 0);
    assert!(!kstore::put(id, b"x"));
    kstore::release(id);
    assert_eq!(kstore::id(), id);
    kstore::release(id);
    // Kept: a record area, records written, then "a restart" over the same memory
    let size = kstore::SIZE;
    let buf: &'static mut [u8] = Box::leak(vec![0u8; size].into_boxed_slice());
    let p = buf.as_mut_ptr();
    let (a, found) = unsafe { kstore::open(p, size) };
    assert!(a.fresh && found.is_empty());
    let x = kstore::id();
    let y = kstore::id();
    assert_eq!(kstore::key(x), x);
    let mut w = kstore::W::new(kstore::K_EFD);
    w.u64(5).u8(1);
    assert!(kstore::put(x, &w.0));
    assert!(kstore::put(y, &[kstore::K_PIPE, 1, 2]));
    assert!(!kstore::put(y, &vec![0u8; kstore::REC + 1]));
    let (_, found) = unsafe { kstore::open(p, size) };
    assert_eq!(found.len(), 2);
    assert_eq!(found[0], (x, w.0.clone()));
    // the restart keeps x only: y's record is cleared, its id handed out again
    kstore::keep_only(&[x]);
    assert_eq!(kstore::id(), y);
    let (_, found) = unsafe { kstore::open(p, size) };
    assert_eq!(found.iter().map(|f| f.0).collect::<Vec<_>>(), vec![x]);
    kstore::keep_only(&[x]);
    kstore::release(x);
    let (_, found) = unsafe { kstore::open(p, size) };
    assert!(found.is_empty());
    kstore::keep_only(&[]);
    // record bytes read back
    let mut w = kstore::W::new(9);
    w.u8(1).u32(2).u64(3).bytes(b"name").raw(&[7, 8]);
    let mut r = kstore::R::new(&w.0);
    assert_eq!((r.u8(), r.u8(), r.u32(), r.u64()), (Some(9), Some(1), Some(2), Some(3)));
    assert_eq!(r.bytes(), Some(&b"name"[..]));
    assert_eq!(r.raw(2), Some(&[7u8, 8][..]));
    assert_eq!(r.u8(), None);
    // ids past the records are not kept
    assert_eq!(kstore::key(kstore::UNKEPT_BASE), 0);
    // calls in flight: a page-less partial tells the kernel; a page gets the words
    hydra_rt::sys::CALLS.lock().unwrap().clear();
    kstore::partial(core::ptr::null_mut(), 77, 5);
    assert_eq!(hydra_rt::sys::CALLS.lock().unwrap().as_slice(), &[(71, 77, 5, 0)]);
    let mut page = vec![0u64; 512];
    let pp = page.as_mut_ptr() as *mut u8;
    kstore::resend_safe(pp, 9, true);
    assert_eq!(page[0x1F8 / 8], 9);
    kstore::partial(pp, 9, 3);
    assert_eq!((page[0x1E8 / 8], page[0x1F0 / 8], page[0x1F8 / 8]), (9, 3, 0));
    // review fixes: a record that does not fit is refused, not written in part
    let (_, _) = unsafe { kstore::open(p, size) };
    let id = kstore::id();
    assert!(!kstore::put_logged(id, &vec![0u8; kstore::REC + 1]));
    assert!(kstore::put_logged(id, &[kstore::K_EFD, 1]));
    kstore::release(id);
    // waiting calls' answers are published only by flush (after the owner's record), in order
    hydra_rt::sys::CALLS.lock().unwrap().clear();
    let mut pend: kstore::Pend = vec![(5, 7), (6, 8)];
    assert!(hydra_rt::sys::CALLS.lock().unwrap().is_empty());
    kstore::flush(&mut pend);
    assert!(pend.is_empty());
    assert_eq!(hydra_rt::sys::CALLS.lock().unwrap().as_slice(), &[(71, 5, 7, 0), (71, 6, 8, 0)]);
    // a token record of the most tokens fits a record
    assert!(2 + kstore::TOKENS_MAX * 8 <= kstore::REC);
    kstore::keep_only(&[]);
}

#[test]
fn crc32c_hardware_matches_table() {
    use hydra_rt::kept::{crc32c, crc32c_table};
    // the standard check value of CRC-32C
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32c_table(b"123456789"), 0xE306_9283);
    let mut s = 1u32;
    for len in 0..300usize {
        let v: Vec<u8> = (0..len)
            .map(|_| {
                s = s.wrapping_mul(1103515245).wrapping_add(12345);
                (s >> 16) as u8
            })
            .collect();
        assert_eq!(crc32c(&v), crc32c_table(&v), "len {}", len);
    }
}

#[test]
fn largest_unix_socket_record_fits() {
    // unix.rs persist_sock: 49 bytes of fields, then two names (tag, node, length, at most
    // 108 bytes: sun_path; read_addr/path_of refuse longer addresses)
    let name = 1 + 8 + 1 + 108;
    assert!(49 + 2 * name <= kstore::REC);
}
