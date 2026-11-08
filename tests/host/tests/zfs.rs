//! Tests for the hardware-independent ZFS pieces: the on-disk structures and
//! checksums in `src/fs/zfs/types.rs`, and the file-server wire protocol in
//! `src/fs/zfs/fsproto.rs`. The pool, DMU and ZPL layers need a block device
//! and are exercised by the in-kernel `zfs selftest` instead.

use hydra_hosttests::fs::zfs::fsproto::*;
use hydra_hosttests::fs::zfs::types::*;

// ---------------------------------------------------------------- Fletcher4

#[test]
fn fletcher4_empty_is_zero() {
    assert_eq!(Fletcher4::compute(&[]), Fletcher4::default());
}

#[test]
fn fletcher4_running_sums() {
    // Words 1 and 2: a=1,b=1,c=1,d=1 then a=3,b=4,c=5,d=6.
    let f = Fletcher4::compute(&[1, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(f, Fletcher4 { a: 3, b: 4, c: 5, d: 6 });
}

#[test]
fn fletcher4_reads_little_endian_words() {
    let f = Fletcher4::compute(&[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(f.a, 0x1234_5678);
}

#[test]
fn fletcher4_zero_pads_trailing_bytes() {
    assert_eq!(Fletcher4::compute(&[1, 0, 0, 0, 5]), Fletcher4::compute(&[1, 0, 0, 0, 5, 0, 0, 0]));
}

#[test]
fn fletcher4_is_order_sensitive() {
    let a = Fletcher4::compute(&[1, 0, 0, 0, 2, 0, 0, 0]);
    let b = Fletcher4::compute(&[2, 0, 0, 0, 1, 0, 0, 0]);
    assert_eq!(a.a, b.a, "plain sum is the same");
    assert_ne!(a, b, "higher-order sums detect the swap");
}

#[test]
fn fletcher4_wraps_instead_of_overflowing() {
    let block = vec![0xFFu8; ZFS_BLOCK_SIZE * 64];
    let f = Fletcher4::compute(&block);
    assert_eq!(f.a, 0xFFFF_FFFF * (block.len() as u64 / 4));
}

// ------------------------------------------------------- layout & constants

#[test]
fn on_disk_sizes() {
    assert_eq!(std::mem::size_of::<BlockPointer>(), 64);
    assert_eq!(std::mem::size_of::<DnodePhys>(), DNODE_SIZE);
    assert_eq!(BP_PER_BLOCK, 64);
    assert_eq!(ZFS_BLOCK_SIZE % DNODE_SIZE, 0);
}

#[test]
fn block_pointer_hole() {
    assert!(BlockPointer::HOLE.is_hole());
    assert_eq!(BlockPointer::empty(), BlockPointer::HOLE);
    let bp = BlockPointer { block: 42, ..BlockPointer::HOLE };
    assert!(!bp.is_hole());
}

// ------------------------------------------------------------------- Dnodes

#[test]
fn dnode_type_from_u8() {
    use DnodeType::*;
    let expected = [None, PlainFile, Directory, Dataset, MasterNode, Symlink, Special];
    for (v, t) in expected.iter().enumerate() {
        assert_eq!(DnodeType::from_u8(v as u8), *t);
        assert_eq!(*t as u8, v as u8);
    }
    assert_eq!(DnodeType::from_u8(7), None);
    assert_eq!(DnodeType::from_u8(255), None);
}

#[test]
fn dnode_type_from_mode() {
    assert_eq!(DnodeType::from_mode(S_IFREG | 0o644), DnodeType::PlainFile);
    assert_eq!(DnodeType::from_mode(S_IFDIR | 0o755), DnodeType::Directory);
    assert_eq!(DnodeType::from_mode(S_IFLNK | 0o777), DnodeType::Symlink);
    for special in [S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK] {
        assert_eq!(DnodeType::from_mode(special | 0o600), DnodeType::Special);
    }
    assert_eq!(DnodeType::from_mode(0o644), DnodeType::None);
}

#[test]
fn dtype_from_mode_matches_linux_dirent_values() {
    let cases = [
        (S_IFREG, 8), (S_IFDIR, 4), (S_IFLNK, 10), (S_IFCHR, 2),
        (S_IFBLK, 6), (S_IFIFO, 1), (S_IFSOCK, 12), (0, 0),
    ];
    for (mode, dt) in cases {
        assert_eq!(dtype_from_mode(mode | 0o7777), dt, "mode {mode:o}");
    }
}

#[test]
fn dnode_empty_defaults() {
    let d = DnodePhys::empty();
    assert_eq!(d.nlevels, 1);
    assert_eq!(d.kind(), DnodeType::None);
    assert!(d.blkptr.iter().all(BlockPointer::is_hole));
    assert!(d.to_bytes().iter().enumerate().all(|(i, &b)| b == 0 || i == std::mem::offset_of!(DnodePhys, nlevels)), "only nlevels set");
}

#[test]
fn dnode_bytes_round_trip() {
    let mut d = DnodePhys::empty();
    d.mode = S_IFREG | 0o640;
    d.nlink = 3;
    d.uid = 1000;
    d.gid = 100;
    d.size = 123_456_789;
    d.mtime = -5; // pre-epoch timestamps are valid
    d.mtime_ns = 999_999_999;
    d.obj_type = DnodeType::PlainFile as u8;
    d.flags = DNODE_FLAG_INLINE | DNODE_FLAG_XATTR;
    d.blkptr[2] = BlockPointer { block: 77, birth_txg: 9, lsize: 4096, level: 1, ..BlockPointer::HOLE };
    d.bonus[0] = 0xAB;
    d.bonus[DNODE_BONUS_SIZE - 1] = 0xCD;

    let bytes = d.to_bytes();
    assert_eq!(&bytes[0..4], &(S_IFREG | 0o640).to_le_bytes(), "mode is the first field, little-endian");
    let back = DnodePhys::from_bytes(&bytes);
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!(back.kind(), DnodeType::PlainFile);
    assert_eq!((back.size, back.mtime, back.mtime_ns), (123_456_789, -5, 999_999_999));
    assert_eq!(back.blkptr[2].block, 77);
    assert_eq!((back.bonus[0], back.bonus[DNODE_BONUS_SIZE - 1]), (0xAB, 0xCD));
}

#[test]
fn dnode_from_bytes_ignores_trailing_data() {
    let mut buf = vec![0u8; DNODE_SIZE * 2];
    buf[..DNODE_SIZE].copy_from_slice(&DnodePhys::empty().to_bytes());
    buf[DNODE_SIZE..].fill(0xFF);
    assert_eq!(DnodePhys::from_bytes(&buf).nlevels, 1);
}

// ---------------------------------------------------- labels & uberblocks

fn label() -> VdevLabel {
    let mut name = [0u8; 32];
    name[..9].copy_from_slice(b"hydrapool");
    VdevLabel {
        magic: VDEV_LABEL_MAGIC,
        version: POOL_VERSION,
        pool_guid: 0x1234_5678_9ABC_DEF0,
        total_blocks: 1 << 20,
        bitmap_start: 1,
        bitmap_blocks: 32,
        ub_start: 33,
        ub_count: UBERBLOCK_RING,
        data_start: 65,
        pool_name: name,
        checksum: Fletcher4::default(),
    }
}

fn uberblock(txg: u64) -> Uberblock {
    Uberblock {
        magic: ZFS_UBERBLOCK_MAGIC,
        version: POOL_VERSION,
        txg,
        timestamp: 1_700_000_000,
        meta_dnode: DnodePhys::empty(),
        next_obj: 10,
        free_obj_head: 0,
        root_obj: 2,
        datasets_obj: 3,
        allocated_blocks: 500,
        snapshot_txg: 0,
        checksum: Fletcher4::default(),
    }
}

#[test]
fn label_magic_spells_pool_format() {
    assert_eq!(&VDEV_LABEL_MAGIC.to_le_bytes(), b"HYDRAZF2");
}

#[test]
fn vdev_label_seal_and_verify() {
    let mut l = label();
    assert!(!l.is_valid(), "unsealed label must not verify");
    l.seal();
    assert!(l.is_valid());

    let mut tampered = l;
    tampered.total_blocks += 1;
    assert!(!tampered.is_valid(), "field change must break the checksum");

    let mut wrong_magic = label();
    wrong_magic.magic ^= 1;
    wrong_magic.seal();
    assert!(!wrong_magic.is_valid(), "checksum alone is not enough");

    let mut wrong_version = label();
    wrong_version.version = POOL_VERSION + 1;
    wrong_version.seal();
    assert!(!wrong_version.is_valid());
}

#[test]
fn uberblock_seal_and_verify() {
    let mut ub = uberblock(7);
    ub.seal();
    assert!(ub.is_valid());

    let mut tampered = ub;
    tampered.meta_dnode.size = 1; // damage deep inside the embedded dnode
    assert!(!tampered.is_valid());

    let mut other = uberblock(8);
    other.seal();
    assert_ne!(ub.checksum, other.checksum, "txg is covered by the checksum");

    let mut bad_magic = uberblock(7);
    bad_magic.magic = 0;
    bad_magic.seal();
    assert!(!bad_magic.is_valid());
}

// ------------------------------------------------------------ suid_killed

#[test]
fn suid_killed_always_drops_setuid() {
    assert_eq!(suid_killed(0o4755, 0, &[]), 0o755);
    assert_eq!(suid_killed(0o4700, 5, &[5]), 0o700);
}

#[test]
fn suid_killed_drops_setgid_when_group_executable() {
    assert_eq!(suid_killed(0o2775, 100, &[100]), 0o775);
    assert_eq!(suid_killed(0o6755, 100, &[100]), 0o755);
}

#[test]
fn suid_killed_keeps_setgid_for_mandatory_locking_if_in_group() {
    // setgid without group-exec marks mandatory locking; keep it for group members.
    assert_eq!(suid_killed(0o2664, 100, &[50, 100]), 0o2664);
    assert_eq!(suid_killed(0o2664, 100, &[50]), 0o664, "non-members lose it");
}

#[test]
fn suid_killed_leaves_plain_modes_alone() {
    for m in [0o644, 0o755, 0o1777, 0o000] {
        assert_eq!(suid_killed(m, 0, &[]), m);
    }
}

// ------------------------------------------------------------ Attr helpers

#[test]
fn attr_kind_and_is_dir() {
    let dir = Attr { mode: S_IFDIR | 0o755, ..Attr::default() };
    let file = Attr { mode: S_IFREG | 0o644, ..Attr::default() };
    assert!(dir.is_dir() && !file.is_dir());
    assert_eq!(dir.kind(), DnodeType::Directory);
    assert_eq!(file.kind(), DnodeType::PlainFile);
}

#[test]
fn zap_entry_from_bytes() {
    let e = ZapEntry::new(b"README.md", 42, DnodeType::PlainFile);
    assert_eq!((e.name_str(), e.object_id, e.is_valid), ("README.md", 42, true));
    let lossy = ZapEntry::new(&[b'a', 0xFF, b'b'], 1, DnodeType::PlainFile);
    assert_eq!(lossy.name_str(), "a\u{FFFD}b");
}

// --------------------------------------------------------- Writer / Reader

fn full_attr() -> Attr {
    Attr {
        ino: 0xFFFF_0000_0000_0001,
        mode: S_IFREG | 0o4751,
        nlink: 0xFFFF_FFFF,
        uid: 1000,
        gid: 0xFFFF_FFFE,
        rdev: 0x0801,
        size: u64::MAX,
        blocks: 9,
        atime: (-1, 999_999_999),
        mtime: (i64::MAX, 0),
        ctime: (i64::MIN, 1),
        generation: 3,
        birth_txg: 4,
        has_xattr: true,
    }
}

fn assert_attr_eq(a: &Attr, b: &Attr) {
    assert_eq!(
        (a.ino, a.mode, a.nlink, a.uid, a.gid, a.rdev, a.size, a.blocks),
        (b.ino, b.mode, b.nlink, b.uid, b.gid, b.rdev, b.size, b.blocks)
    );
    assert_eq!((a.atime, a.mtime, a.ctime), (b.atime, b.mtime, b.ctime));
    assert_eq!((a.generation, a.birth_txg, a.has_xattr), (b.generation, b.birth_txg, b.has_xattr));
}

#[test]
fn attr_round_trip() {
    for attr in [full_attr(), Attr::default(), Attr { has_xattr: false, ..full_attr() }] {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        assert!(w.attr(&attr));
        assert_eq!(w.len(), 14 * 8, "fixed 14-word encoding");
        assert_attr_eq(&Reader::new(&buf).attr(), &attr);
    }
}

#[test]
fn setattr_round_trip_preserves_presence() {
    let cases = [
        SetAttr::default(),
        SetAttr { mode: Some(0), ..SetAttr::default() }, // Some(0) is not None
        SetAttr { size: Some(0), kill_suid: true, ..SetAttr::default() },
        SetAttr {
            mode: Some(0o755),
            uid: Some(0),
            gid: Some(u32::MAX),
            size: Some(1 << 40),
            atime: Some((-1, 5)),
            mtime: Some((0, 0)),
            kill_suid: false,
        },
    ];
    for s in cases {
        let mut buf = [0u8; 128];
        assert!(Writer::new(&mut buf).setattr(&s));
        let r = Reader::new(&buf).setattr();
        assert_eq!((r.mode, r.uid, r.gid, r.size), (s.mode, s.uid, s.gid, s.size));
        assert_eq!((r.atime, r.mtime, r.kill_suid), (s.atime, s.mtime, s.kill_suid));
    }
}

#[test]
fn readdir_entries_stream() {
    let entries = [
        ReaddirEntry { name: b".".to_vec(), ino: 2, dtype: DT_DIR, next_cookie: 1 },
        ReaddirEntry { name: b"..".to_vec(), ino: 1, dtype: DT_DIR, next_cookie: 2 },
        ReaddirEntry { name: b"a file with spaces".to_vec(), ino: 99, dtype: DT_REG, next_cookie: 3 },
        ReaddirEntry { name: Vec::new(), ino: 0, dtype: DT_UNKNOWN, next_cookie: u64::MAX },
    ];
    let mut buf = [0u8; 1024];
    let mut w = Writer::new(&mut buf);
    for e in &entries {
        assert!(w.entry(e));
    }
    let used = w.len();
    let mut r = Reader::new(&buf[..used]);
    for e in &entries {
        let got = r.entry();
        assert_eq!((got.name, got.ino, got.dtype, got.next_cookie), (e.name.clone(), e.ino, e.dtype, e.next_cookie));
    }
}

#[test]
fn event_round_trip() {
    let ev = Event { ino: 12, mask: 0x8000_0100, cookie: 0xDEAD_BEEF, name: b"new.txt".to_vec() };
    let mut buf = [0u8; 64];
    assert!(Writer::new(&mut buf).event(&ev));
    let got = Reader::new(&buf).event();
    assert_eq!((got.ino, got.mask, got.cookie, got.name), (12, 0x8000_0100, 0xDEAD_BEEF, b"new.txt".to_vec()));
}

#[test]
fn writer_refuses_to_overflow() {
    let mut buf = [0u8; 12];
    let mut w = Writer::new(&mut buf);
    assert!(w.u64(1));
    assert!(!w.u64(2), "only 4 bytes left");
    assert_eq!(w.len(), 8, "failed write consumes nothing");
}

#[test]
fn writer_bytes_is_all_or_nothing() {
    let mut buf = [0u8; 10];
    let mut w = Writer::new(&mut buf);
    assert!(!w.bytes(b"1234567"), "4-byte length + 7 bytes does not fit in 10");
    assert_eq!(w.len(), 0, "length prefix must not be written alone");
    assert!(w.bytes(b"123456"));
    assert_eq!(w.len(), 10);
}

#[test]
fn writer_reports_full_buffer_for_large_records() {
    let mut buf = [0u8; 100];
    assert!(!Writer::new(&mut buf).attr(&full_attr()), "attr needs 112 bytes");
}

#[test]
fn reader_past_end_yields_zeroes() {
    let mut r = Reader::new(&[1, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(r.u64(), 1);
    assert_eq!(r.u64(), 0);
    assert_eq!(r.bytes(), &[] as &[u8]);
}

#[test]
fn reader_bytes_with_bogus_length_is_empty() {
    let mut buf = vec![0xFF, 0xFF, 0xFF, 0x7F];
    buf.extend_from_slice(b"short");
    assert_eq!(Reader::new(&buf).bytes(), &[] as &[u8]);
}

#[test]
fn protocol_labels_are_unique() {
    let labels = [
        FS_ROOT, FS_LOOKUP, FS_RESOLVE, FS_GETATTR, FS_SETATTR, FS_READ, FS_WRITE, FS_CREATE,
        FS_MKNOD, FS_MKDIR, FS_SYMLINK, FS_READLINK, FS_LINK, FS_UNLINK, FS_RMDIR, FS_RENAME,
        FS_READDIR, FS_STATFS, FS_OPEN_REF, FS_RELEASE, FS_NOTIFY, FS_SYNC, FS_SYNC_IF_DIRTY,
        FS_SNAPSHOT, FS_POOL_STATUS, FS_OBJECT_INFO, FS_DATASETS, FS_SELFTEST, FS_VERIFY, FS_FSCK,
        FS_RESOLVE_MNT, FS_GETXATTR, FS_SETXATTR, FS_LISTXATTR, FS_REMOVEXATTR, FS_REPLY,
    ];
    let mut sorted = labels.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len());
    assert!(labels.iter().all(|l| l >> 8 == 0x31), "all in the 0x31xx file-server range");
}

#[test]
fn protocol_errnos_match_linux() {
    let cases = [
        (EPERM, 1), (ENOENT, 2), (EIO, 5), (E2BIG, 7), (EEXIST, 17), (EXDEV, 18), (ENOTDIR, 20),
        (EISDIR, 21), (EINVAL, 22), (EFBIG, 27), (ENOSPC, 28), (EMLINK, 31), (ERANGE, 34),
        (ENAMETOOLONG, 36), (ENOTEMPTY, 39), (ELOOP, 40), (ENODATA, 61),
    ];
    for (got, want) in cases {
        assert_eq!(got, -want);
    }
}

#[test]
fn shared_buffer_regions_do_not_overlap() {
    assert!(MAX_IO <= EVENT_OFFSET, "data area must end before the event area");
    assert!(EVENT_OFFSET + EVENT_SPACE <= 256 * 1024);
}
