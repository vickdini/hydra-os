//! `src/fs/tmem.rs`: in-memory tmpfs files.
use hydra_hosttests_w9_m::fake;
use hydra_hosttests_w9_m::fs::tmem::{self, TmemFile};
use hydra_hosttests_w9_m::fs::zfs::fsproto::Attr;
use hydra_hosttests_w9_m::memory::vm::MappedObject;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    let g = fake::SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fake::ALLOWED.store(u64::MAX, Ordering::Relaxed);
    fake::FREE.store(1 << 30, Ordering::Relaxed);
    fake::TOTAL.store(2 << 30, Ordering::Relaxed);
    tmem::ENABLED.store(true, Ordering::Relaxed);
    g
}

fn file(ino: u64, inst: u32) -> Arc<TmemFile> {
    tmem::make(ino, inst)
}

#[test]
fn write_read_holes_and_size() {
    let _g = serial();
    let f = file(1001, 9001);
    assert_eq!(f.size(), 0);
    assert_eq!(f.write(Some(10_000), b"hello").unwrap(), 5);
    assert_eq!(f.size(), 10_005);
    let mut b = [7u8; 16];
    assert_eq!(f.read(0, &mut b), 16);
    assert!(b.iter().all(|&x| x == 0), "a hole reads zeros");
    let mut b = [0u8; 10];
    assert_eq!(f.read(10_000, &mut b), 5);
    assert_eq!(&b[..5], b"hello");
    assert_eq!(f.read(20_000, &mut b), 0);
    assert_eq!(f.resident(), 1, "only the page written is held");
    assert_eq!(f.write(None, b"XY").unwrap(), 2);
    assert_eq!(f.size(), 10_007);
    let big: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
    assert_eq!(f.write(Some(4000), &big).unwrap(), big.len());
    let mut back = vec![0u8; big.len()];
    assert_eq!(f.read(4000, &mut back), big.len());
    assert_eq!(back, big);
    assert_eq!(f.write(Some(tmem::MAX_SIZE), b"x"), Err(-27));
    tmem::forget(1001);
}

#[test]
fn truncate_frees_and_zeroes() {
    let _g = serial();
    let f = file(1002, 9002);
    f.write(Some(0), &[0xAB; 3 * 4096]).unwrap();
    assert_eq!(f.resident(), 3);
    f.truncate(5000).unwrap();
    assert_eq!(f.size(), 5000);
    assert_eq!(f.resident(), 2);
    f.truncate(3 * 4096).unwrap();
    let mut b = [1u8; 100];
    assert_eq!(f.read(5000, &mut b), 100);
    assert!(b.iter().all(|&x| x == 0), "the tail past a cut reads zeros after regrowth");
    let mut b = [0u8; 4];
    f.read(4996, &mut b);
    assert_eq!(b, [0xAB; 4]);
    assert!(f.truncate(tmem::MAX_SIZE + 1).is_err());
    tmem::forget(1002);
}

#[test]
fn shrinking_unmaps_the_cut_pages_everywhere() {
    // wave10 GV1: a truncation to a smaller size asks every address space to unmap the
    // file's pages past the end; growing does not
    let _g = serial();
    let f = file(1012, 9012);
    assert_eq!(f.inode(), Some(1012));
    hydra_hosttests_w9_m::compat::linux::mm::UNMAPS.lock().unwrap().clear();
    f.truncate(3 * 4096).unwrap();
    f.truncate(4096 + 10).unwrap();
    let u = hydra_hosttests_w9_m::compat::linux::mm::UNMAPS.lock().unwrap().clone();
    assert_eq!(u, vec![(1012, 4096 + 10)]);
    tmem::forget(1012);
}

#[test]
fn frames_go_back() {
    let _g = serial();
    let before = fake::live();
    {
        let f = file(1003, 9003);
        f.write(Some(0), &[1; 8 * 4096]).unwrap();
        assert_eq!(fake::live(), before + 8);
        // A mapping keeps the object after the name is gone
        let map: Arc<dyn MappedObject> = f.clone();
        tmem::forget(1003);
        assert!(tmem::get(1003).is_none());
        drop(f);
        assert!(map.get_page(0).is_some());
        assert_eq!(fake::live(), before + 8);
    }
    assert_eq!(fake::live(), before, "every frame given back");
}

#[test]
fn mapping_pages_are_the_files() {
    let _g = serial();
    let f = file(1004, 9004);
    f.truncate(2 * 4096).unwrap();
    let p = f.get_page(1).expect("a page inside the file");
    unsafe { *(p.start_address().as_u64() as *mut u8).add(7) = 0x5A };
    let mut b = [0u8; 1];
    f.read(4096 + 7, &mut b);
    assert_eq!(b[0], 0x5A, "read sees what the mapping wrote");
    f.write(Some(4096 + 8), &[0x66]).unwrap();
    assert_eq!(unsafe { *(p.start_address().as_u64() as *const u8).add(8) }, 0x66, "the mapping sees write()");
    assert_eq!(f.get_page(1), Some(p), "the same frame each time");
    assert!(f.get_page(2).is_none(), "past the end: SIGBUS");
    tmem::forget(1004);
}

#[test]
fn size_limit_and_memory_reserve() {
    let _g = serial();
    tmem::set_limit(9005, 3 * 4096);
    let f = file(1005, 9005);
    let n = f.write(Some(0), &[2; 5 * 4096]).unwrap();
    assert_eq!(n, 3 * 4096, "a short write at the limit");
    assert_eq!(f.write(Some(n as u64), &[2; 10]), Err(-28), "then ENOSPC");
    assert_eq!(tmem::usage(9005).unwrap(), (3 * 4096, 3 * 4096, 1));
    f.truncate(0).unwrap();
    assert_eq!(tmem::usage(9005).unwrap().1, 0, "truncation gives the room back");
    f.truncate(8 * 4096).unwrap();
    assert!(f.get_page(3).is_some() && f.get_page(4).is_some() && f.get_page(5).is_some());
    assert!(f.get_page(6).is_none(), "a fault past the limit: SIGBUS");
    f.truncate(0).unwrap();
    fake::FREE.store(1 << 20, Ordering::Relaxed);
    assert_eq!(f.write(Some(0), b"x"), Err(-28), "memory short");
    f.truncate(4096).unwrap();
    assert!(f.get_page(0).is_none());
    fake::FREE.store(1 << 30, Ordering::Relaxed);
    fake::ALLOWED.store(0, Ordering::Relaxed);
    assert_eq!(f.write(Some(0), b"x"), Err(-28), "the allocator fails");
    assert!(f.get_page(0).is_none());
    fake::ALLOWED.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(tmem::usage(9005).unwrap().1, 0, "failed allocations take no room");
    tmem::forget(1005);
    tmem::drop_instance(9005);
    assert!(tmem::usage(9005).is_none());
}

#[test]
fn created_decides_by_mount_and_shm_dir() {
    let _g = serial();
    tmem::add_shm_dir(50);
    tmem::add_shm_dir(50);
    assert!(tmem::shm_dir(50) && !tmem::shm_dir(51));
    tmem::created(50, 2001, None);
    assert_eq!(tmem::get(2001).unwrap().inst(), tmem::SHM_INST);
    tmem::created(77, 2002, Some(9006));
    assert_eq!(tmem::get(2002).unwrap().inst(), 9006);
    tmem::created(51, 2003, None);
    assert!(tmem::get(2003).is_none(), "an ordinary directory: pool data");
    tmem::created(51, 2001, None);
    assert!(tmem::get(2001).is_none(), "a reused inode number made elsewhere loses its old entry");
    tmem::ENABLED.store(false, Ordering::Relaxed);
    tmem::created(50, 2004, None);
    assert!(tmem::get(2004).is_none(), "switched off: pool data");
    tmem::ENABLED.store(true, Ordering::Relaxed);
    tmem::forget(2002);
}

#[test]
fn names_and_last_close() {
    let _g = serial();
    tmem::add_shm_dir(60);
    tmem::created(60, 3001, None);
    assert!(tmem::may_move(3001, 60));
    assert!(!tmem::may_move(3001, 61), "out of /dev/shm: EXDEV");
    assert!(tmem::may_move(3999, 61), "not an in-memory file");
    tmem::unlinked(3001, true, false);
    assert!(tmem::get(3001).is_some(), "another name left");
    tmem::unlinked(3001, false, true);
    assert!(tmem::get(3001).is_some(), "open: kept to the last close");
    tmem::released(3001);
    assert!(tmem::get(3001).is_none());
    tmem::created(60, 3002, None);
    tmem::released(3002);
    assert!(tmem::get(3002).is_some(), "a close of a named file keeps it");
    tmem::unlinked(3002, false, false);
    assert!(tmem::get(3002).is_none(), "no name, not open: gone");
    tmem::released(3999);
    tmem::unlinked(3999, false, false);
}

#[test]
fn drop_instance_keeps_open_orphans() {
    let _g = serial();
    tmem::created(1, 4001, Some(9007));
    tmem::created(1, 4002, Some(9007));
    tmem::created(1, 4003, Some(9008));
    tmem::unlinked(4002, false, true);
    tmem::drop_instance(9007);
    assert!(tmem::get(4001).is_none());
    assert!(tmem::get(4002).is_some(), "an open file goes at its last close");
    assert!(tmem::get(4003).is_some(), "another instance stays");
    tmem::released(4002);
    tmem::forget(4003);
    tmem::drop_instance(tmem::SHM_INST);
}

#[test]
fn overlay_and_times() {
    let _g = serial();
    let f = file(5001, 9009);
    let mut a = Attr { size: 0, blocks: 99, mtime: (5, 0), ctime: (5, 0) };
    f.overlay(&mut a);
    assert_eq!((a.size, a.blocks, a.mtime), (0, 0, (5, 0)), "no data change yet: the pool's times");
    f.write(Some(0), &[1; 5000]).unwrap();
    let mut a = Attr { size: 0, blocks: 0, mtime: (5, 0), ctime: (5, 0) };
    f.overlay(&mut a);
    assert_eq!((a.size, a.blocks), (5000, 16));
    assert!(a.mtime.0 > 5 && a.ctime == a.mtime);
    f.times_set();
    let mut a = Attr { size: 0, blocks: 0, mtime: (5, 0), ctime: (6, 0) };
    f.overlay(&mut a);
    assert_eq!((a.mtime, a.ctime), ((5, 0), (6, 0)), "times set by utimensat win again");
    tmem::forget(5001);
}

#[test]
fn ctl_answers() {
    let _g = serial();
    let f = file(6001, 9010);
    f.write(Some(0), b"abc").unwrap();
    let got = std::cell::RefCell::new(Vec::new());
    let out = |v: &[u8]| {
        *got.borrow_mut() = v.to_vec();
        0
    };
    assert_eq!(tmem::ctl(1, 6001, 0, &out), 0);
    let v = got.borrow().clone();
    assert_eq!(u64::from_le_bytes(v[0..8].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(v[24..32].try_into().unwrap()), 9010);
    assert_eq!(tmem::ctl(1, 6999, 0, &out), -2);
    assert_eq!(tmem::ctl(2, 9010, 1 << 20, &out), 0);
    assert_eq!(tmem::ctl(2, 0, 1 << 20, &out), -22, "/dev/shm has no size=");
    assert_eq!(tmem::ctl(3, 9010, 0, &out), 0);
    let v = got.borrow().clone();
    assert_eq!(u64::from_le_bytes(v[0..8].try_into().unwrap()), 1 << 20);
    assert_eq!(tmem::ctl(3, 4242, 0, &out), -2);
    assert_eq!(tmem::ctl(9, 0, 0, &out), -22);
    tmem::forget(6001);
    tmem::drop_instance(9010);
}

#[test]
fn sizes_parse() {
    let _g = serial();
    assert_eq!(tmem::parse_size("mode=1777,size=1m"), Some(1 << 20));
    assert_eq!(tmem::parse_size("size=4096"), Some(4096));
    assert_eq!(tmem::parse_size("size=2G"), Some(2 << 30));
    assert_eq!(tmem::parse_size("size=8k"), Some(8192));
    assert_eq!(tmem::parse_size("size=50%"), Some((2u64 << 30) / 100 * 50));
    assert_eq!(tmem::parse_size("size=x"), None);
    assert_eq!(tmem::parse_size("mode=700"), None);
    assert_eq!(tmem::limit_bytes(1 << 63 | 25), (2u64 << 30) / 100 * 25);
    assert_eq!(tmem::limit_bytes(1234), 1234);
    tmem::set_limit(9011, 0);
    assert_eq!(tmem::usage(9011).unwrap().0, 1 << 30, "the default: half of the memory");
    tmem::drop_instance(9011);
    tmem::make(7001, 9012).write(Some(0), b"a").unwrap();
    let (files, pages) = tmem::totals();
    assert!(files >= 1 && pages >= 1);
    tmem::forget(7001);
}

#[test]
fn vfs_server_parser_matches() {
    use hydra_hosttests_w9_m::vfs_parse::parse_size as p;
    assert_eq!(p("size=1m"), Some(1 << 20));
    assert_eq!(p("size=10%"), Some(1 << 63 | 10));
    assert_eq!(p("size=200%"), Some(1 << 63 | 100));
    assert_eq!(p("size=9999999999999g"), None);
    assert_eq!(p("nr_inodes=5"), None);
    // The copy is vfs-server's text
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../userland/drivers/vfs-server/src/tmem.rs")).unwrap().replace('\r', "");
    let copy = include_str!("../src/vfs_parse.rs").replace(char::from(13), "");
    let body = &copy[copy.find("/// `size=`").unwrap()..];
    assert!(src.contains(body), "src/vfs_parse.rs is out of date with vfs-server/src/tmem.rs");
}

// Review fixes (pre-merge review of w9-tmpfs)

#[test]
fn reserve_is_checked_per_page() {
    let _g = serial();
    let f = file(8001, 9020);
    f.write(Some(0), &[1; 4096]).unwrap();
    // The reserve is 32 MiB here (2 GiB / 64): room for 2 more pages only
    fake::FREE.store((32 << 20) + 2 * 4096 - 1, Ordering::Relaxed);
    let n = f.write(Some(4096), &[2; 5 * 4096]).unwrap();
    assert_eq!(n, 2 * 4096, "one large write stops at the reserve");
    assert_eq!(f.write(Some(3 * 4096), b"x"), Err(-28));
    assert_eq!(f.write(Some(0), &[9; 4096]).unwrap(), 4096, "overwriting held pages needs no memory");
    fake::FREE.store(1 << 30, Ordering::Relaxed);
    tmem::forget(8001);
    tmem::drop_instance(9020);
}

#[test]
fn truncated_pages_still_mapped_stay_counted() {
    use hydra_hosttests_w9_m::memory::frame_allocator::{frame_ref_dec, frame_ref_inc};
    let _g = serial();
    tmem::set_limit(9021, 4 * 4096);
    let f = file(8002, 9021);
    f.truncate(4 * 4096).unwrap();
    // Another process maps the first two pages (each PTE holds a reference)
    let p0 = f.get_page(0).unwrap();
    let p1 = f.get_page(1).unwrap();
    frame_ref_inc(p0);
    frame_ref_inc(p1);
    f.get_page(2).unwrap();
    f.truncate(0).unwrap();
    assert_eq!(tmem::usage(9021).unwrap().1, 2 * 4096, "the mapped pages stay counted after the cut");
    f.truncate(4 * 4096).unwrap();
    assert!(f.get_page(0).is_some() && f.get_page(1).is_some());
    assert!(f.get_page(2).is_none(), "size= still holds while the old pages are mapped");
    // The mapper lets them go: the room comes back
    frame_ref_dec(p0);
    frame_ref_dec(p1);
    assert!(f.get_page(2).is_some() && f.get_page(3).is_some());
    let before = fake::live();
    tmem::forget(8002);
    drop(f);
    tmem::drop_instance(9021);
    assert!(fake::live() <= before);
}

#[test]
fn growing_zeroes_what_a_mapping_wrote_past_the_end() {
    let _g = serial();
    let f = file(8003, 9022);
    f.write(Some(0), b"abc").unwrap();
    let p = f.get_page(0).unwrap();
    unsafe { *(p.start_address().as_u64() as *mut u8).add(10) = 0x77 };
    f.truncate(100).unwrap();
    let mut b = [0xFFu8; 8];
    f.read(8, &mut b);
    assert_eq!(b, [0; 8]);
    tmem::forget(8003);
}
