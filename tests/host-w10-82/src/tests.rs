//! Group 8-2's host tests (wave 10).

use crate::ipc::protocol::{lx_mmap_answer, lx_mmap_parts, lx_shm_key, LxShmStat, LX_VFS_PSEUDO_PROC};
use crate::lx::shm_table::{Info, Note, Table};
use crate::pseudo::path::{classify, File, Target};
use crate::sysvtext::*;
use alloc::string::String;

// ---------------------------------------------------------------------------------------
// The kernel's attachment table

/// One successful `shmat` of `id` at `addr` by `pid` at time `now`.
fn attach(t: &mut Table, pid: u64, addr: u64, id: i32, now: i64) -> Option<Note> {
    let g = t.pre_attach(id);
    t.attached(pid, addr, id, 8192, 0xAB, g, now)
}

#[test]
fn shmat_and_shmdt_count_and_stamp_without_notes() {
    let mut t = Table::new();
    assert_eq!(t.info(5), Info::default());
    assert_eq!(attach(&mut t, 10, 0x1000, 5, 100), None);
    assert_eq!(attach(&mut t, 11, 0x9000, 5, 101), None);
    assert_eq!(t.info(5), Info { nattch: 2, atime: 101, dtime: 0, lpid: 11, removed: false });
    let (a, n) = t.detach(10, 0x1000, 102).unwrap();
    assert_eq!((a.id, a.len), (5, 8192));
    assert_eq!(n, None, "not removed: nothing to tell");
    assert_eq!(t.info(5), Info { nattch: 1, atime: 101, dtime: 102, lpid: 10, removed: false });
    let (_, n) = t.detach(11, 0x9000, 103).unwrap();
    assert_eq!(n, None, "the last one of a segment that stays: nothing either");
    assert_eq!(t.info(5), Info { nattch: 0, atime: 101, dtime: 103, lpid: 11, removed: false }, "times stay while the segment does");
    assert!(t.detach(11, 0x9000, 104).is_none(), "no attachment there any more");
    assert!(t.is_empty());
    assert_eq!((t.made, t.dropped), (2, 2));
}

#[test]
fn detach_needs_the_exact_address_and_process() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    assert!(t.detach(10, 0x2000, 2).is_none());
    assert!(t.detach(11, 0x1000, 2).is_none());
    assert_eq!(t.nattch(5), 1);
}

#[test]
fn rmid_with_attachments_left_tells_the_last_one() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    attach(&mut t, 11, 0x1000, 5, 1);
    assert_eq!(t.rmid(5), 2);
    assert!(t.info(5).removed);
    assert_eq!(t.detach(10, 0x1000, 2).unwrap().1, None);
    assert_eq!(t.forget(11, 3), alloc::vec![Note { id: 5, pid: 11 }], "exit of the last holder");
    t.forget_id(5);
    assert_eq!(t.info(5), Info::default());
    // a segment removed with nothing attached: 0, lx-ipc lets it go at once
    assert_eq!(t.rmid(6), 0);
}

#[test]
fn a_shmat_in_flight_counts_and_a_failed_one_gives_its_count_back() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 7, 50);
    let g = t.pre_attach(7);
    assert_eq!(t.nattch(7), 2, "an IPC_RMID now sees the attach in flight");
    assert_eq!(t.undo(7, 11, g), None);
    assert_eq!(t.info(7), Info { nattch: 1, atime: 50, dtime: 0, lpid: 10, removed: false }, "an undo stamps nothing");
    // the only count of a removed segment undone: the note
    let g = t.pre_attach(8);
    t.rmid(8);
    assert_eq!(t.undo(8, 11, g), Some(Note { id: 8, pid: 11 }));
    assert_eq!(t.nattch(8), 0);
}

#[test]
fn fork_copies_the_attachments_and_exit_drops_them() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    attach(&mut t, 10, 0x3000, 6, 1);
    attach(&mut t, 12, 0x1000, 5, 1);
    t.fork(10, 20, 7);
    assert_eq!((t.nattch(5), t.nattch(6)), (3, 2));
    assert_eq!((t.info(5).atime, t.info(5).lpid), (7, 10), "fork stamps as Linux's shm_open: the parent");
    t.fork(20, 21, 8);
    assert_eq!((t.nattch(5), t.nattch(6)), (4, 3));
    assert!(t.forget(20, 9).is_empty());
    assert_eq!((t.nattch(5), t.nattch(6)), (3, 2));
    assert_eq!((t.info(6).dtime, t.info(6).lpid), (9, 20), "exit stamps as shm_close");
    assert!(t.detach(10, 0x1000, 10).is_some(), "the parent's own are untouched");
    assert!(t.forget(99, 10).is_empty(), "a process without attachments");
    t.rmid(5);
    t.rmid(6);
    let mut notes = t.forget(21, 11);
    notes.extend(t.forget(10, 11));
    notes.extend(t.forget(12, 11));
    notes.sort_by_key(|n| n.id);
    assert_eq!(notes.iter().map(|n| n.id).collect::<alloc::vec::Vec<_>>(), [5, 6], "one note per removed segment");
    assert!(t.is_empty());
    assert_eq!((t.nattch(5), t.nattch(6)), (0, 0));
}

#[test]
fn shm_remap_over_an_attachment_drops_it() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    t.rmid(5);
    let n = attach(&mut t, 10, 0x1000, 6, 2).unwrap();
    assert_eq!(n, Note { id: 5, pid: 10 });
    assert_eq!((t.nattch(5), t.nattch(6)), (0, 1));
}

#[test]
fn a_fresh_service_makes_the_old_attachments_count_for_nothing() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    let g_old = t.pre_attach(5); // in flight across the reset
    let g0 = t.generation();
    t.reset();
    assert_eq!(t.generation(), g0 + 1);
    assert_eq!(t.info(5), Info::default(), "the new lx-ipc may give id 5 to a new segment");
    attach(&mut t, 11, 0x5000, 5, 2);
    assert_eq!(t.nattch(5), 1);
    // the old attachment going: no count change, no stamp, no note
    t.rmid(5);
    assert_eq!(t.detach(10, 0x1000, 3).unwrap().1, None);
    assert_eq!(t.forget(10, 3), alloc::vec![]);
    assert_eq!(t.info(5).dtime, 0);
    // the attach in flight from before: its undo does nothing; if it completes it never counts
    assert_eq!(t.undo(5, 12, g_old), None);
    assert_eq!(t.attached(12, 0x7000, 5, 4096, 0xAB, g_old, 4), None);
    assert_eq!(t.nattch(5), 1);
    assert_eq!(t.forget(12, 4), alloc::vec![]);
    t.fork(11, 30, 5);
    assert_eq!(t.nattch(5), 2);
}

#[test]
fn a_segment_let_go_counts_nothing_more() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    t.forget_id(5); // (a racing RMID let it go)
    assert_eq!(t.detach(10, 0x1000, 2).unwrap().1, None);
    assert_eq!(t.info(5), Info::default(), "no stale facts left behind");
}

#[test]
fn a_stale_entry_of_a_reused_pid_is_replaced_at_fork() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x1000, 5, 1);
    attach(&mut t, 20, 0x1000, 6, 1); // left behind (as if 20's exit was missed)
    t.fork(10, 20, 2);
    assert_eq!((t.nattch(5), t.nattch(6)), (2, 0));
}

#[test]
fn find_and_overlapping_attachments() {
    let mut t = Table::new();
    attach(&mut t, 10, 0x10000, 5, 1); // 0x10000..0x12000
    attach(&mut t, 10, 0x20000, 6, 1); // 0x20000..0x22000
    attach(&mut t, 11, 0x10000, 5, 1);
    assert_eq!(t.find(10, 0x20000).map(|a| (a.id, a.obj)), Some((6, 0xAB)));
    assert_eq!(t.find(10, 0x21000), None);
    let ov = |s: u64, e: u64| t.overlapping(10, s, e).iter().map(|(a, _)| *a).collect::<alloc::vec::Vec<_>>();
    assert_eq!(ov(0x11000, 0x11001), [0x10000]);
    assert_eq!(ov(0x12000, 0x20000), alloc::vec::Vec::<u64>::new(), "between the two: none");
    assert_eq!(ov(0, u64::MAX), [0x10000, 0x20000], "only process 10's");
    assert_eq!(ov(0x21fff, 0x30000), [0x20000]);
}

#[test]
fn an_attach_counted_before_a_forget_does_not_bring_the_segment_back() {
    let mut t = Table::new();
    let g = t.pre_attach(9);
    t.forget_id(9); // lx-ipc let the segment go meanwhile (a fresh start of its ids)
    assert_eq!(t.attached(10, 0x1000, 9, 4096, 0xAB, g, 5), None);
    assert_eq!(t.info(9), Info::default(), "no stale facts made by the attach");
}

#[test]
fn shm_stat_layout_is_five_words() {
    assert_eq!(core::mem::size_of::<LxShmStat>(), 40);
}

// ---------------------------------------------------------------------------------------
// lx-ipc's System V text and structures

fn view() -> ShmView {
    ShmView { ids: Ids { key: 0x1234, id: 32769, mode: 0o600 | SHM_DEST, uid: 1000, gid: 100, cuid: 1000, cgid: 100 }, size: 65536, cpid: 77, lpid: 78, nattch: 2, atime: 1700000000, dtime: 0, ctime: 1699999999 }
}

#[test]
fn proc_shm_line_has_linux_columns() {
    let l = shm_line(&view(), 0);
    let f: alloc::vec::Vec<&str> = l.split_whitespace().collect();
    assert_eq!(f, ["4660", "32769", "1600", "65536", "77", "78", "2", "1000", "100", "1000", "100", "1700000000", "0", "1699999999", "0", "0"]);
    assert!(l.ends_with('\n'));
    // the widths of Linux's format: "%10d %10d  %4o %21lu %5u %5u  %5lu ..."
    assert!(l.starts_with("      4660      32769  1600                 65536    77    78      2  1000"));
    assert_eq!(SHM_HEADER.split_whitespace().count(), 16);
    // the header's columns line up with the values (ipcs reads by fields, people by eye)
    assert_eq!(SHM_HEADER.find("shmid").unwrap() + 5, l.find("32769").unwrap() + 5);
}

#[test]
fn proc_sem_and_msg_lines() {
    let i = Ids { key: -1, id: 5, mode: 0o640, uid: 1, gid: 2, cuid: 3, cgid: 4 };
    let s = sem_line(&i, 3, 10, 11);
    assert_eq!(s.split_whitespace().collect::<alloc::vec::Vec<_>>(), ["-1", "5", "640", "3", "1", "2", "3", "4", "10", "11"]);
    assert_eq!(SEM_HEADER.split_whitespace().count(), 10);
    let m = msg_line(&i, 100, 2, 7, 8, 20, 21, 22);
    assert_eq!(m.split_whitespace().collect::<alloc::vec::Vec<_>>(), ["-1", "5", "640", "100", "2", "7", "8", "1", "2", "3", "4", "20", "21", "22"]);
    assert_eq!(MSG_HEADER.split_whitespace().count(), 14);
    assert_eq!(header(0), SHM_HEADER);
    assert_eq!(header(1), SEM_HEADER);
    assert_eq!(header(2), MSG_HEADER);
}

#[test]
fn shmid_ds_layout() {
    let b = shmid_ds(&view(), 9);
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    assert_eq!(u32_at(0), 0x1234, "key");
    assert_eq!((u32_at(4), u32_at(8), u32_at(12), u32_at(16)), (1000, 100, 1000, 100));
    assert_eq!(u16::from_le_bytes([b[20], b[21]]) as u32, 0o600 | SHM_DEST);
    assert_eq!(u16::from_le_bytes([b[24], b[25]]), 9, "seq");
    assert_eq!(u64_at(48), 65536);
    assert_eq!((u64_at(56), u64_at(64), u64_at(72)), (1700000000, 0, 1699999999));
    assert_eq!((u32_at(80), u32_at(84)), (77, 78));
    assert_eq!(u64_at(88), 2);
    assert!(b[96..].iter().all(|&x| x == 0));
}

#[test]
fn shminfo_and_shm_info() {
    let b = shminfo();
    let v: alloc::vec::Vec<u64> = b.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!(v, [1 << 40, 1, 4096, 4096, (1u64 << 40) >> 12]);
    let i = shm_info(3, 17, 5);
    assert_eq!(i32::from_le_bytes(i[0..4].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(i[8..16].try_into().unwrap()), 17);
    assert_eq!(u64::from_le_bytes(i[16..24].try_into().unwrap()), 5);
    assert!(i[24..].iter().all(|&x| x == 0));
}

#[test]
fn limits() {
    assert!(!new_size_ok(0));
    assert!(new_size_ok(1));
    assert!(new_size_ok(SHMMAX));
    assert!(!new_size_ok(SHMMAX + 1));
    assert_eq!((pages(1), pages(4096), pages(4097)), (1, 1, 2));
    // the /proc/sys/kernel values linux-server shows
    let s = |p: &str| crate::pseudo::path::STATIC.iter().find(|(q, _)| *q == p).unwrap().1;
    assert_eq!(s("sys/kernel/shmmax"), alloc::format!("{}\n", SHMMAX).as_bytes());
    assert_eq!(s("sys/kernel/shmall"), alloc::format!("{}\n", SHMALL).as_bytes());
    assert_eq!(s("sys/kernel/shmmni"), alloc::format!("{}\n", SHMMNI).as_bytes());
}

#[test]
fn info_call_chunks_whole_lines() {
    let lines: alloc::vec::Vec<String> = (0..10).map(|i| alloc::format!("line {:02} ......\n", i)).collect();
    let len = lines[0].len();
    let (a, next) = chunk(&lines, 0, len * 3 + 2);
    assert_eq!(a.len(), len * 3);
    assert_eq!(next, 3);
    let mut all = a;
    let mut cur = next;
    while cur != 0 {
        let (b, n) = chunk(&lines, cur, len * 3 + 2);
        assert!(!b.is_empty());
        all.extend(b);
        cur = n;
    }
    assert_eq!(all, lines.concat().into_bytes());
    // a line longer than the room is cut, never skipped or looped on
    let (c, n) = chunk(&lines, 4, 5);
    assert_eq!((c.as_slice(), n), (&lines[4].as_bytes()[..5], 5));
    // past the end
    assert_eq!(chunk(&lines, 10, 100), (alloc::vec![], 0));
    assert_eq!(chunk(&lines, 99, 100), (alloc::vec![], 0));
}

#[test]
fn answer_and_key_encodings() {
    // shmat's answer: lx-ipc's handle, the key in the page field (the kernel maps from page 0)
    for key in [0i32, 0x1234, -1, i32::MIN] {
        let a = lx_mmap_answer(4095, key as u32 as u64, true);
        assert!(a >= 0);
        assert_eq!(lx_mmap_parts(a), (4095, key as u32 as u64, true));
    }
    assert_eq!(lx_shm_key(0), 0x1_0000_0000);
    assert_eq!(lx_shm_key(-1), 0x1_FFFF_FFFF);
    assert!(lx_shm_key(32769) > 2, "never X3's record and arena keys");
}

// ---------------------------------------------------------------------------------------
// /proc/sysvipc paths

#[test]
fn proc_sysvipc_paths() {
    let c = |t: &[u8]| classify(LX_VFS_PSEUDO_PROC, t);
    assert_eq!(c(b"sysvipc/shm"), Target::File(File::SysvIpc(0)));
    assert_eq!(c(b"sysvipc/sem"), Target::File(File::SysvIpc(1)));
    assert_eq!(c(b"sysvipc/msg"), Target::File(File::SysvIpc(2)));
    assert_eq!(c(b"sysvipc/shm/"), Target::Kernel, "a trailing slash: the kernel's rules");
    assert_eq!(c(b"sysvipc"), Target::Kernel, "the directory: the kernel's");
    assert_eq!(c(b"sysvipc/foo"), Target::Kernel);
    assert_eq!(c(b"./sysvipc//shm"), Target::File(File::SysvIpc(0)));
}
