//! Tests of vfs-server's inotify/fanotify rules and the kernel's event records.

use crate::ipc::protocol::{notify_hash, LX_FSEV_FILE, LX_FSEV_PERM, LX_FSEV_ZFS, LX_NOTE_FSDATA, LX_NOTE_FSEVENT, LX_VFS_NOTIFY_MAP_LEN};
use crate::logic::*;
use crate::notifyfwd::{self, encode, Ev, MAX_ENTRIES, TAIL_MAX};

fn ev<'a>(kind: u64, tail: &'a [u8]) -> Ev<'a> {
    Ev { kind, ino: 77, mask: 0x102, cookie: 9, dir: 5, pid: 1234, tid: 1235, id: 42, tail }
}

/// Feeds the entries of `e` to an assembler; the event it gives back.
fn roundtrip(e: &Ev) -> Option<KEvent> {
    let mut ents = [[0u64; 4]; MAX_ENTRIES];
    let n = encode(e, &mut ents);
    assert!(n >= 2);
    let mut a = Assembler::default();
    let mut out = None;
    for ent in &ents[..n] {
        let r = match ent[0] {
            LX_NOTE_FSEVENT => a.head(ent[1], ent[2], ent[3]),
            LX_NOTE_FSDATA => a.data(ent[1], ent[2], ent[3]),
            _ => panic!("kind"),
        };
        if r.is_some() {
            assert!(out.is_none(), "one event per record");
            out = r;
        }
    }
    assert_eq!(a.broken, 0);
    out
}

#[test]
fn record_roundtrip_keeps_every_field() {
    for name in [&b""[..], b"a", b"file-with-a-longer-name.txt", &[b'x'; 300][..]] {
        for kind in [LX_FSEV_ZFS, LX_FSEV_FILE, LX_FSEV_PERM] {
            let e = ev(kind, name);
            let k = roundtrip(&e).expect("event");
            assert_eq!((k.kind, k.ino, k.mask, k.cookie, k.dir, k.pid, k.tid, k.id), (kind, 77, 0x102, 9, 5, 1234, 1235, 42));
            assert_eq!(k.tail, name);
        }
    }
}

#[test]
fn record_entry_counts_and_long_tails() {
    let mut ents = [[0u64; 4]; MAX_ENTRIES];
    // 24 bytes of fixed payload: one data entry without a tail
    assert_eq!(encode(&ev(0, b""), &mut ents), 2);
    assert_eq!(encode(&ev(0, &[1; 24]), &mut ents), 3);
    assert_eq!(encode(&ev(0, &[1; 25]), &mut ents), 4);
    // a path longer than TAIL_MAX is cut there
    let long = alloc::vec![b'p'; TAIL_MAX + 100];
    let k = roundtrip(&ev(1, &long)).unwrap();
    assert_eq!(k.tail.len(), TAIL_MAX);
    // too little room: nothing
    let mut small = [[0u64; 4]; 2];
    assert_eq!(encode(&ev(0, b"abc"), &mut small), 0);
}

#[test]
fn assembler_drops_cut_records() {
    let mut ents = [[0u64; 4]; MAX_ENTRIES];
    let n = encode(&ev(0, b"name-of-thirty-two-bytes-exactly"), &mut ents);
    let mut a = Assembler::default();
    // data without a head
    assert!(a.data(1, 2, 3).is_none());
    assert_eq!(a.broken, 1);
    // a head, part of the data, then a new head: the first is dropped
    a.head(ents[0][1], ents[0][2], ents[0][3]);
    a.data(ents[1][1], ents[1][2], ents[1][3]);
    a.head(ents[0][1], ents[0][2], ents[0][3]);
    assert_eq!(a.broken, 2);
    let mut got = None;
    for e in &ents[1..n] {
        got = got.or(a.data(e[1], e[2], e[3]));
    }
    assert_eq!(got.unwrap().tail, b"name-of-thirty-two-bytes-exactly");
    // a head with an impossible length
    assert!(a.head(1, 2, 3 << 8).is_none());
    assert_eq!(a.broken, 3);
}

#[test]
fn masks_of_the_kernel_side() {
    assert_eq!(notifyfwd::perm_mask(false, false) as u64, FAN_OPEN_PERM);
    assert_eq!(notifyfwd::perm_mask(true, true) as u64, FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_ONDIR);
    assert_eq!(notifyfwd::file_mask(FAN_ACCESS, true) as u64, FAN_ACCESS | FAN_ONDIR);
    assert_eq!(notifyfwd::open_mask(true), FAN_OPEN | FAN_OPEN_EXEC);
    assert_eq!(notifyfwd::dir_of("/a/b"), Some("/a"));
    assert_eq!(notifyfwd::dir_of("/a"), Some("/"));
    assert_eq!(notifyfwd::dir_of("a"), None);
    assert_eq!(notifyfwd::parent_of("/a/b"), 0);
    assert_eq!(notifyfwd::bits(), 0);
    assert!(!notifyfwd::want_zfs() && !notifyfwd::want_close_write() && !notifyfwd::want_fan());
    assert_eq!(notifyfwd::on_open(1, 2, "/x", false, false), Ok(()));
    notifyfwd::zfs_event(1, 2, 3, b"n");
    notifyfwd::file_event(1, 2, "/x", 1, false);
}

#[test]
fn hash_stays_in_the_map() {
    for ino in [0u64, 1, 2, 1 << 40, u64::MAX, 0x8000_0000_0000_0001] {
        assert!(notify_hash(ino) < LX_VFS_NOTIFY_MAP_LEN * 8);
    }
    // neighbours spread
    let bits: alloc::collections::BTreeSet<usize> = (1000..1100u64).map(notify_hash).collect();
    assert!(bits.len() > 90);
}

// ----------------------------------------------------------------------
// inotify
// ----------------------------------------------------------------------

fn records(b: &[u8]) -> alloc::vec::Vec<(i32, u32, u32, alloc::vec::Vec<u8>)> {
    let mut v = alloc::vec::Vec::new();
    let mut off = 0;
    while off + 16 <= b.len() {
        let wd = i32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        let mask = u32::from_le_bytes(b[off + 4..off + 8].try_into().unwrap());
        let cookie = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap());
        let len = u32::from_le_bytes(b[off + 12..off + 16].try_into().unwrap()) as usize;
        let name: alloc::vec::Vec<u8> = b[off + 16..off + 16 + len].iter().copied().take_while(|&c| c != 0).collect();
        v.push((wd, mask, cookie, name));
        off += 16 + len;
    }
    v
}

#[test]
fn inotify_watches_and_masks() {
    let mut i = Inotify::new();
    assert_eq!(i.add_watch(10, true, IN_ALL_EVENTS), Ok((1, true)));
    // the same inode again: the same descriptor, mask replaced or added to
    assert_eq!(i.add_watch(10, true, IN_MODIFY), Ok((1, false)));
    assert_eq!(i.watches[&1].mask, IN_MODIFY);
    assert_eq!(i.add_watch(10, true, IN_ATTRIB | IN_MASK_ADD), Ok((1, false)));
    assert_eq!(i.watches[&1].mask, IN_MODIFY | IN_ATTRIB);
    assert_eq!(i.add_watch(10, true, IN_ATTRIB | IN_MASK_CREATE), Err(EEXIST));
    assert_eq!(i.add_watch(11, false, IN_ATTRIB | IN_ONLYDIR), Err(ENOTDIR));
    assert_eq!(i.add_watch(11, false, 0), Err(EINVAL));
    assert_eq!(i.add_watch(11, false, IN_ATTRIB | IN_MASK_ADD | IN_MASK_CREATE), Err(EINVAL));
    assert_eq!(i.add_watch(11, false, IN_ATTRIB), Ok((2, true)));
    assert!(in_init_ok(IN_NONBLOCK | IN_CLOEXEC) && !in_init_ok(1));
}

#[test]
fn inotify_events_read_and_coalesce() {
    let mut i = Inotify::new();
    i.add_watch(10, true, IN_ALL_EVENTS).unwrap();
    assert_eq!(i.event(10, 0x100, 0, b"file"), (true, None));
    // an identical unread event is coalesced
    assert_eq!(i.event(10, 0x100, 0, b"file"), (false, None));
    assert_eq!(i.event(99, 0x100, 0, b"other"), (false, None));
    i.event(10, IN_MODIFY, 0, b"file");
    assert_eq!(i.bytes, 64);
    // a buffer too small for the first record
    assert_eq!(i.read(16), Err(EINVAL));
    let b = i.read(40).unwrap();
    assert_eq!(records(&b), alloc::vec![(1, 0x100, 0, b"file".to_vec())]);
    let b = i.read(4096).unwrap();
    assert_eq!(records(&b), alloc::vec![(1, IN_MODIFY, 0, b"file".to_vec())]);
    assert!(i.read(4096).unwrap().is_empty());
    assert_eq!(i.bytes, 0);
}

#[test]
fn inotify_delete_self_and_oneshot_end_the_watch() {
    let mut i = Inotify::new();
    let (wd, _) = i.add_watch(20, false, IN_DELETE_SELF).unwrap();
    assert_eq!(i.event(20, IN_DELETE_SELF, 0, b""), (true, Some(wd)));
    let r = records(&i.read(4096).unwrap());
    assert_eq!(r, alloc::vec![(wd, IN_DELETE_SELF, 0, alloc::vec![]), (wd, IN_IGNORED, 0, alloc::vec![])]);
    assert!(i.watches.is_empty() && i.by_ino.is_empty());
    let (wd, _) = i.add_watch(21, false, IN_MODIFY | IN_ONESHOT).unwrap();
    // an unwanted event leaves a one-shot watch alone
    assert_eq!(i.event(21, IN_ATTRIB, 0, b""), (false, None));
    assert_eq!(i.event(21, IN_MODIFY, 0, b""), (true, Some(wd)));
    assert!(i.rm_watch(wd).is_none());
}

#[test]
fn inotify_overflow_and_restore() {
    let mut i = Inotify::new();
    i.add_watch(30, true, IN_ALL_EVENTS).unwrap();
    for n in 0..MAX_QUEUED + 5 {
        i.event(30, 0x100, 0, alloc::format!("f{}", n).as_bytes());
    }
    assert_eq!(i.queue.len(), MAX_QUEUED + 1);
    assert_eq!(records(i.queue.back().unwrap()), alloc::vec![(-1, IN_Q_OVERFLOW, 0, alloc::vec![])]);
    // a restart: watches back by descriptor, the next one after them, one overflow event
    let mut j = Inotify::new();
    j.restore_watch(7, Watch { ino: 40, mask: IN_MODIFY });
    j.restore_watch(7, Watch { ino: 41, mask: IN_MODIFY });
    j.restore_watch(0, Watch { ino: 42, mask: IN_MODIFY });
    j.overflow();
    j.overflow();
    assert_eq!(j.watches.len(), 1);
    assert_eq!(j.add_watch(43, false, IN_MODIFY), Ok((8, true)));
    assert_eq!(j.queue.len(), 1);
}

// ----------------------------------------------------------------------
// fanotify
// ----------------------------------------------------------------------

#[test]
fn fanotify_init_rules() {
    assert_eq!(fan_init_ok(FAN_CLASS_NOTIF, 0, true), Ok(()));
    assert_eq!(fan_init_ok(FAN_CLASS_NOTIF, 0, false), Err(EPERM));
    assert_eq!(fan_init_ok(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0, false), Ok(()));
    assert_eq!(fan_init_ok(FAN_REPORT_NAME, 0, true), Err(EINVAL));
    assert_eq!(fan_init_ok(FAN_CLASS_MASK, 0, true), Err(EINVAL));
    assert_eq!(fan_init_ok(FAN_REPORT_FID | 0x8, 0, true), Err(EINVAL));
    assert_eq!(fan_init_ok(0, 3, true), Err(EINVAL));
    assert_eq!(fan_init_ok(1 << 40, 0, true), Err(EINVAL));
}

#[test]
fn fanotify_marks_and_interest() {
    let mut g = Fanotify::new(FAN_CLASS_NOTIF, 0, false, 1);
    let m = g.mark_check(FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS).unwrap();
    assert_eq!(g.mark(m, 50, FAN_OPEN | FAN_ACCESS), Ok(Some(Mark { mask: FAN_OPEN | FAN_ACCESS, ignore: 0 })));
    assert_eq!(g.interest(50, 0, FAN_OPEN, false), FAN_OPEN);
    assert_eq!(g.interest(51, 50, FAN_OPEN, false), 0); // no ON_CHILD
    let m2 = g.mark_check(FAN_MARK_ADD, FAN_MODIFY | FAN_EVENT_ON_CHILD).unwrap();
    g.mark(m2, 60, FAN_MODIFY | FAN_EVENT_ON_CHILD).unwrap();
    assert_eq!(g.interest(61, 60, FAN_MODIFY, false), FAN_MODIFY);
    assert_eq!(g.interest(61, 60, FAN_MODIFY, true), 0); // a directory without ONDIR
    // ignore marks
    let mi = g.mark_check(FAN_MARK_ADD | FAN_MARK_IGNORED_MASK, FAN_ACCESS).unwrap();
    g.mark(mi, 50, FAN_ACCESS).unwrap();
    assert_eq!(g.interest(50, 0, FAN_ACCESS | FAN_OPEN, false), FAN_OPEN);
    // removal
    let mr = g.mark_check(FAN_MARK_REMOVE, FAN_OPEN | FAN_ACCESS).unwrap();
    assert_eq!(g.mark(mr, 50, FAN_OPEN | FAN_ACCESS), Ok(Some(Mark { mask: 0, ignore: FAN_ACCESS })));
    let mri = g.mark_check(FAN_MARK_REMOVE | FAN_MARK_IGNORED_MASK, FAN_ACCESS).unwrap();
    assert_eq!(g.mark(mri, 50, FAN_ACCESS), Ok(None));
    assert_eq!(g.mark(mr, 50, FAN_OPEN), Err(ENOENT));
    // checks
    assert_eq!(g.mark_check(0, FAN_OPEN), Err(EINVAL));
    assert_eq!(g.mark_check(FAN_MARK_ADD, 0), Err(EINVAL));
    assert_eq!(g.mark_check(FAN_MARK_ADD, FAN_OPEN_PERM), Err(EINVAL)); // a notification group
    assert_eq!(g.mark_check(FAN_MARK_ADD, FAN_CREATE), Err(EINVAL)); // not FID
    assert_eq!(g.mark_check(FAN_MARK_ADD | FAN_MARK_MOUNT | FAN_MARK_FILESYSTEM, FAN_OPEN), Err(EINVAL));
    assert_eq!(g.mark_check(1 << 20, FAN_OPEN), Err(EINVAL));
    // mount mark: everything; flush
    let mm = g.mark_check(FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CLOSE_WRITE).unwrap();
    g.mark(mm, 0, FAN_CLOSE_WRITE).unwrap();
    assert!(g.wants_all());
    assert_eq!(g.interest(999, 0, FAN_CLOSE_WRITE, false), FAN_CLOSE_WRITE);
    g.flush(MarkKind::Mount);
    g.flush(MarkKind::Inode);
    assert!(!g.wants_all() && g.inodes.is_empty());
    // unprivileged groups: inode marks only
    let u = Fanotify::new(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0, true, 1);
    assert_eq!(u.mark_check(FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CREATE), Err(EPERM));
    assert_eq!(u.mark_check(FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CREATE), Err(EPERM));
    let p = Fanotify::new(0x4, 0, false, 1); // FAN_CLASS_CONTENT
    assert!(p.mark_check(FAN_MARK_ADD, FAN_OPEN_PERM).is_ok());
}

#[test]
fn fanotify_descriptor_events_records_and_merge() {
    let mut g = Fanotify::new(FAN_CLASS_NOTIF, 0, false, 1);
    let m = g.mark_check(FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE).unwrap();
    g.mark(m, 70, FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE).unwrap();
    assert!(g.file_event(70, 0, b"/tmp/r", FAN_OPEN, 100, 101));
    // the same file and process: merged
    assert!(g.file_event(70, 0, b"/tmp/r", FAN_ACCESS, 100, 101));
    assert!(!g.file_event(70, 0, b"/tmp/r", FAN_ACCESS, 100, 101));
    assert!(!g.file_event(71, 0, b"/tmp/x", FAN_ACCESS, 100, 101));
    assert_eq!(g.queue.len(), 1);
    assert_eq!(g.queue[0].mask, FAN_OPEN | FAN_ACCESS);
    assert_eq!(g.queue[0].name, b"r");
    assert_eq!(g.queued_bytes(), 24);
    let evs = g.take(4096).unwrap();
    let rec = g.record(&evs[0], 5, g.shown_pid(&evs[0], 1, true));
    assert_eq!(rec.len(), 24);
    assert_eq!(u32::from_le_bytes(rec[0..4].try_into().unwrap()), 24);
    assert_eq!(rec[4], 3);
    assert_eq!(u64::from_le_bytes(rec[8..16].try_into().unwrap()), FAN_OPEN | FAN_ACCESS);
    assert_eq!(i32::from_le_bytes(rec[16..20].try_into().unwrap()), 5);
    assert_eq!(i32::from_le_bytes(rec[20..24].try_into().unwrap()), 100);
    // a buffer too small
    g.file_event(70, 0, b"/tmp/r", FAN_CLOSE_NOWRITE, 100, 101);
    assert_eq!(g.take(10), Err(EINVAL));
    // pids: hidden from an unprivileged group's other processes and other PID namespaces
    let ev = g.queue[0].clone();
    assert_eq!(g.shown_pid(&ev, 1, false), 0);
    let u = Fanotify::new(FAN_REPORT_FID, 0, true, 1);
    assert_eq!(u.shown_pid(&ev, 1, true), 0);
    assert_eq!(u.shown_pid(&ev, 100, true), 100);
    let t = Fanotify::new(FAN_REPORT_TID, 0, false, 1);
    assert_eq!(t.shown_pid(&ev, 1, true), 101);
}

#[test]
fn fanotify_fid_records_and_entry_events() {
    let mut g = Fanotify::new(FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0, true, 1);
    let m = g.mark_check(FAN_MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_ONDIR).unwrap();
    g.mark(m, 80, FAN_CREATE | FAN_DELETE | FAN_ONDIR).unwrap();
    // descriptor events never go to file-handle groups as zfs events of the object
    assert!(g.fs_event(80, 0x100, b"a", 7, 7));
    assert!(g.fs_event(80, 0x100 | IN_ISDIR, b"sub", 7, 7));
    assert!(!g.fs_event(81, 0x100, b"x", 7, 7));
    assert!(!g.fs_event(80, IN_MODIFY, b"a", 7, 7));
    let evs = g.take(4096).unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[1].mask, FAN_CREATE | FAN_ONDIR);
    let info = g.info(&evs[0]);
    // DFID_NAME: header 4, fsid 8, handle 8+8, "a\0" padded to 4
    assert_eq!(info[0], 2);
    assert_eq!(u16::from_le_bytes([info[2], info[3]]) as usize, info.len());
    assert_eq!(u64::from_le_bytes(info[20..28].try_into().unwrap()), 80);
    assert_eq!(&info[28..30], b"a\0");
    assert_eq!(info.len() % 4, 0);
    assert_eq!(g.record_len(&evs[0]), 24 + info.len());
    // FID only: entry events report the directory
    let f = Fanotify::new(FAN_REPORT_FID, 0, false, 1);
    let r = f.info(&FanEvent { mask: FAN_CREATE, ino: 80, dir: 80, name: b"a".to_vec(), path: alloc::vec![], pid: 0, tid: 0, perm: None });
    assert_eq!(r[0], 1);
    assert_eq!(u64::from_le_bytes(r[20..28].try_into().unwrap()), 80);
    // a descriptor group gets no information records
    let d = Fanotify::new(FAN_CLASS_NOTIF, 0, false, 1);
    assert!(d.info(&evs[0]).is_empty());
    assert!(!Fanotify::new(FAN_CLASS_NOTIF, 0, false, 1).fs_event(80, 0x100, b"a", 1, 1));
    // self events
    let mut s = Fanotify::new(FAN_REPORT_FID, 0, false, 1);
    let ms = s.mark_check(FAN_MARK_ADD, FAN_ATTRIB | FAN_DELETE_SELF).unwrap();
    s.mark(ms, 90, FAN_ATTRIB | FAN_DELETE_SELF).unwrap();
    assert!(s.fs_event(90, IN_ATTRIB, b"", 1, 1));
    assert!(!s.fs_event(90, 0x100, b"", 1, 1));
}

#[test]
fn fanotify_permission_questions() {
    let mut g = Fanotify::new(0x4, 0, false, 1);
    let m = g.mark_check(FAN_MARK_ADD, FAN_OPEN_PERM).unwrap();
    g.mark(m, 95, FAN_OPEN_PERM).unwrap();
    assert!(g.has_perm());
    assert!(!g.perm_event(96, 0, b"/x", FAN_OPEN_PERM, 1, 1, 7));
    assert!(g.perm_event(95, 0, b"/r", FAN_OPEN_PERM, 1, 1, 7));
    // permission events are never merged
    assert!(g.perm_event(95, 0, b"/r", FAN_OPEN_PERM, 1, 1, 8));
    assert_eq!(g.open_questions(), alloc::vec![7, 8]);
    let evs = g.take(4096).unwrap();
    g.fd_ids.insert(4, evs[0].perm.unwrap());
    let mut resp = alloc::vec::Vec::new();
    resp.extend_from_slice(&4i32.to_le_bytes());
    resp.extend_from_slice(&FAN_DENY.to_le_bytes());
    assert_eq!(g.response(&resp), Ok((7, true)));
    assert_eq!(g.response(&resp), Err(ENOENT));
    assert_eq!(g.response(&resp[..4]), Err(EINVAL));
    let mut bad = resp.clone();
    bad[4] = 3;
    assert_eq!(g.response(&bad), Err(EINVAL));
}

#[test]
fn fanotify_overflow_and_unlimited_queue() {
    let mut g = Fanotify::new(FAN_CLASS_NOTIF, 0, false, 1);
    let m = g.mark_check(FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_OPEN).unwrap();
    g.mark(m, 0, FAN_OPEN).unwrap();
    for n in 0..QUEUE_MAX as u64 + 3 {
        g.file_event(n + 1, 0, b"/f", FAN_OPEN, 1, 1);
    }
    assert_eq!(g.queue.len(), QUEUE_MAX + 1);
    assert_eq!(g.queue.back().unwrap().mask, FAN_Q_OVERFLOW);
    g.overflow();
    assert_eq!(g.queue.len(), QUEUE_MAX + 1);
    let mut u = Fanotify::new(FAN_UNLIMITED_QUEUE, 0, false, 1);
    u.mark(m, 0, FAN_OPEN).unwrap();
    for n in 0..QUEUE_MAX as u64 + 3 {
        u.file_event(n + 1, 0, b"/f", FAN_OPEN, 1, 1);
    }
    assert_eq!(u.queue.len(), QUEUE_MAX + 3);
}

#[test]
fn kept_records_roundtrip() {
    let all = [
        KRec::InGroup { slot: 3 },
        KRec::FanGroup { slot: 4, flags: FAN_REPORT_FID | FAN_CLOEXEC, f_flags: 0o2, unprivileged: true, owner: 77 },
        KRec::InWatch { slot: 3, wd: 12, ino: 1 << 40, mask: IN_MODIFY | IN_ONESHOT },
        KRec::InWatch { slot: 3, wd: -1, ino: stand_in_ino(b"/proc/x"), mask: 1 },
        KRec::FanMark { slot: 4, kind: MarkKind::Inode, ino: 9, mark: Mark { mask: FAN_OPEN, ignore: FAN_ACCESS } },
        KRec::FanMark { slot: 4, kind: MarkKind::Mount, ino: 0, mark: Mark { mask: FAN_OPEN, ignore: 0 } },
        KRec::FanMark { slot: 4, kind: MarkKind::Filesystem, ino: 0, mark: Mark { mask: 1, ignore: 2 } },
    ];
    for r in all {
        let b = r.encode();
        assert_eq!(KRec::decode(&b), Some(r));
        assert_eq!(KRec::decode(&b).unwrap().slot(), r.slot());
    }
    assert_eq!(KRec::decode(&[0u8; KREC_SIZE]), None);
    assert_eq!(KRec::decode(&[1u8; 8]), None);
    let mut bad = KRec::FanMark { slot: 1, kind: MarkKind::Inode, ino: 1, mark: Mark::default() }.encode();
    bad[1] = 9;
    assert_eq!(KRec::decode(&bad), None);
    assert_ne!(stand_in_ino(b"/a"), stand_in_ino(b"/b"));
    assert!(stand_in_ino(b"/a") >> 63 == 1);
}
