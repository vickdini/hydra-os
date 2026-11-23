//! vfs-server's FUSE wire format and tables (wave 9, Group 6b-2).

use hydra_hosttests_w9_fuse::wire::*;

fn attr(ino: u64, mode: u32, size: u64) -> Vec<u8> {
    let mut a = vec![0u8; ATTR];
    a[0..8].copy_from_slice(&ino.to_le_bytes());
    a[8..16].copy_from_slice(&size.to_le_bytes());
    a[60..64].copy_from_slice(&mode.to_le_bytes());
    a
}

#[test]
fn request_header_layout() {
    let who = Who { uid: 1000, gid: 100, pid: 42 };
    let m = request(LOOKUP, 6, 9, who, &[b"ab\0", b"c"]);
    assert_eq!(m.len(), IN_HEADER + 4);
    assert_eq!(u32_at(&m, 0) as usize, m.len());
    assert_eq!(u32_at(&m, 4), LOOKUP);
    assert_eq!(unique_of(&m), 6);
    assert_eq!(u64_at(&m, 16), 9);
    assert_eq!((u32_at(&m, 24), u32_at(&m, 28), u32_at(&m, 32)), (1000, 100, 42));
    assert_eq!(&m[IN_HEADER..], b"ab\0c");
}

#[test]
fn le_and_cstr() {
    assert_eq!(le(&[1, 2], &[4, 8]), vec![1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(cstr(b"x"), b"x\0".to_vec());
    assert_eq!(rw_args(7, 8, 9).len(), 40);
    assert_eq!(u32_at(&[1, 2], 0), 0); // short: 0, never a panic
    assert_eq!(u64_at(&[], 0), 0);
}

#[test]
fn init_reply_needs_protocol_7_and_clamps_max_write() {
    let mut b = le(&[7, 31, 0, 0, 0, 1 << 20], &[4, 4, 4, 4, 4, 4]);
    assert_eq!(init_reply(0, &b), Some(128 * 1024));
    b[20..24].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(init_reply(0, &b), Some(4096));
    assert_eq!(init_reply(0, &b[..8]), Some(4096));
    assert_eq!(init_reply(-5, &b), None);
    let six = le(&[6, 31], &[4, 4]);
    assert_eq!(init_reply(0, &six), None);
    assert_eq!(init_reply(0, &[]), None);
    assert_eq!(u32_at(&init_args(), 0), 7);
}

#[test]
fn reply_header_checks() {
    let mut r = le(&[16, 0, 4], &[4, 4, 8]);
    assert_eq!(reply_header(&r), Some((0, 4)));
    r[4..8].copy_from_slice(&(-2i32).to_le_bytes());
    assert_eq!(reply_header(&r), Some((-2, 4)));
    r[4..8].copy_from_slice(&5i32.to_le_bytes());
    assert_eq!(reply_header(&r), None, "positive error");
    r[4..8].copy_from_slice(&(-5000i32).to_le_bytes());
    assert_eq!(reply_header(&r), None, "not an errno");
    // A notification (unique 0) carries its code in the error field
    let n = le(&[16, 2, 0], &[4, 4, 8]);
    assert_eq!(reply_header(&n), Some((2, 0)));
    assert_eq!(reply_header(&r[..10]), None);
    let mut long = r.clone();
    long[4..8].copy_from_slice(&0i32.to_le_bytes());
    long.push(0);
    assert_eq!(reply_header(&long), None, "length is not the write's");
}

#[test]
fn entry_and_attr_out() {
    let mut e = le(&[5, 0, 2, 3, 500_000_000, 0], &[8, 8, 8, 8, 4, 4]);
    e.extend(attr(77, S_IFREG | 0o644, 12));
    let (nodeid, ems, ams, a) = entry(&e).unwrap();
    assert_eq!((nodeid, ems, ams), (5, 2500, 3000));
    assert_eq!(u64_at(a, 0), 77);
    assert_eq!(attr_mode(a), S_IFREG | 0o644);
    let mut zero = e.clone();
    zero[0..8].copy_from_slice(&0u64.to_le_bytes());
    assert!(entry(&zero).is_none(), "node 0: a negative entry");
    assert!(entry(&e[..100]).is_none());
    let mut ao = le(&[1, 0, 0], &[8, 4, 4]);
    ao.extend(attr(3, S_IFDIR | 0o755, 0));
    let (ms, a) = attr_out(&ao).unwrap();
    assert_eq!(ms, 1000);
    assert_eq!(attr_mode(a), S_IFDIR | 0o755);
    assert!(attr_out(&ao[..50]).is_none());
    assert_eq!(valid_ms(1 << 40, 0), 3600 * 1000, "at most an hour");
}

#[test]
fn nodes_intern_and_names() {
    let mut n = Nodes::new();
    assert_eq!(n.nodeid(1), Some(1));
    assert_eq!(n.nodeid(0), None);
    assert_eq!(n.nodeid(9), None);
    let a = n.intern(100, 1, b"a");
    assert_eq!(a, 2);
    assert_eq!(n.intern(100, 1, b"a"), a, "known node: same local number");
    let b = n.intern(200, a, b"b");
    assert_eq!(n.name_of(b), Some((a, &b"b"[..])));
    // Moved: its name and directory follow
    assert_eq!(n.intern(200, 1, b"c"), b);
    assert_eq!(n.name_of(b), Some((1, &b"c"[..])));
    assert_eq!(n.name_of(1), None, "the root");
    assert_eq!(n.name_of(42), None);
    // The root keeps its place whatever name it is found by
    assert_eq!(n.intern(1, 5, b"x"), 1);
    assert_eq!(n.name_of(1), None);
}

#[test]
fn nodes_attribute_cache() {
    let mut n = Nodes::new();
    let a = attr(1, S_IFDIR, 0);
    n.cache(1, &a, 100, 1000);
    assert!(n.cached(1, 1050).is_some());
    assert!(n.cached(1, 1100).is_none(), "expired");
    n.cache(1, &a, 0, 1000);
    assert!(n.cached(1, 1000).is_none(), "valid 0: not kept");
    n.cache(1, &a, 100, 1000);
    n.uncache(Some(1));
    assert!(n.cached(1, 1001).is_none());
    n.cache(1, &a, 100, 1000);
    n.uncache(None);
    assert!(n.cached(1, 1001).is_none());
    n.cache(1, &a[..10], 100, 1000);
    assert!(n.cached(1, 1001).is_none(), "short attributes are not kept");
    n.cache(99, &a, 100, 1000); // (an unknown node: nothing)
}

#[test]
fn handles_and_releases() {
    let mut h = Handles::default();
    assert_eq!(h.get(Want::Read), None);
    h.set(Want::Read, 1);
    h.set(Want::Write, 2);
    h.set(Want::Dir, 3);
    assert_eq!((h.get(Want::Read), h.get(Want::Write), h.get(Want::Dir)), (Some(1), Some(2), Some(3)));
    let r = h.releases();
    let ops: Vec<u32> = r.iter().map(|x| x.0).collect();
    assert_eq!(ops, vec![FLUSH, RELEASE, RELEASE, RELEASEDIR], "a written handle is flushed first");
    assert_eq!(u64_at(&r[1].1, 0), 2);
    assert_eq!(u32_at(&r[1].1, 8), 1, "release of the write handle has its flags");
    assert!(Handles::default().releases().is_empty());
    assert_eq!(Want::Write.open(), (OPEN, &[2u32, 1][..]));
    assert_eq!(Want::Dir.open().0, OPENDIR);
    assert_eq!(Want::Read.open(), (OPEN, &[0u32][..]));
}

#[test]
fn inode_numbers_and_connections() {
    let i = ino(0x8001, 5);
    assert_eq!(i >> 62, 1);
    assert_eq!(split(i), Some((0x8001, 5)));
    assert_eq!(split(5), None, "a pool object");
    assert_eq!(split(ino(0x0003, 5)), None, "the kernel's own client's");
    let mut next = 0;
    let live = |c: u16| c == 0x8001;
    assert_eq!(next_conn(&mut next, live), Some(0x8002), "a live number is skipped");
    let mut last = 0x3FFF;
    assert_eq!(next_conn(&mut last, |_| false), Some(0x8001), "wraps to 1");
    assert_eq!(next_conn(&mut last, |_| true), None, "all live: none, never a hang");
    assert!(setattr_size(&le(&[8], &[4])));
    assert!(!setattr_size(&le(&[1], &[4])));
}

#[test]
fn nodes_with_a_base_refuse_older_numbers() {
    let mut old = Nodes::new();
    let a = old.intern(100, 1, b"a");
    let mut n = Nodes::with_base(2 << 32);
    assert_eq!(n.nodeid(a), None, "a number of the earlier instance");
    assert_eq!(n.nodeid(1), Some(1), "the root stays");
    let b = n.intern(100, 1, b"a");
    assert_eq!(b, (2 << 32) + 2);
    assert_eq!(n.nodeid(b), Some(100));
    assert_eq!(n.name_of(b), Some((1, &b"a"[..])));
    let c = n.intern(300, b, b"c");
    assert_eq!(n.name_of(c), Some((b, &b"c"[..])));
    n.cache(c, &attr(3, S_IFREG, 1), 10, 0);
    assert!(n.cached(c, 5).is_some());
    assert_eq!(n.nodeid((2 << 32) + 1), None);
    assert_eq!(n.nodeid((2 << 32) + 99), None, "past the table");
}

#[test]
fn conn_records_round_trip() {
    let r = ConnRec { conn: 0x8005, slot: 17, mounted: true, initialized: true, owner: (1000, 1001, true), max_write: 65536, next_unique: 1234 };
    assert_eq!(ConnRec::decode(&r.encode()), Some(r));
    let r2 = ConnRec { mounted: false, initialized: false, owner: (0, 0, false), ..r };
    assert_eq!(ConnRec::decode(&r2.encode()), Some(r2));
    assert_eq!(ConnRec::decode(&[0u8; CONN_REC]), None, "an empty record");
    assert_eq!(ConnRec::decode(&r.encode()[..10]), None);
    let mut small = r;
    small.max_write = 1;
    assert_eq!(ConnRec::decode(&small.encode()).unwrap().max_write, 4096);
}

#[test]
fn iov_totals_never_wrap() {
    let max = 256 * 1024;
    assert_eq!(iov_total(&[(1, 16), (2, 100)], max), Some(116));
    assert_eq!(iov_total(&[], max), Some(0));
    assert_eq!(iov_total(&[(1, 1 << 63), (2, 1 << 63)], max), None, "two 2^63 lengths wrap to 0");
    assert_eq!(iov_total(&[(1, u64::MAX), (2, 1)], max), None);
    assert_eq!(iov_total(&[(1, max + 1)], max), None, "one part over the limit");
    assert_eq!(iov_total(&[(1, max)], max), Some(max));
    assert_eq!(iov_total(&[(1, max), (2, 1)], max), None);
}
