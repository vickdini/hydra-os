//! Tests of the snapshot rules.

use crate::procsnap::*;

const EINVAL: i64 = -22;
const ENXIO: i64 = -6;

#[test]
fn seek_set_cur_end() {
    assert_eq!(seek_to(5, 100, 0, 0), Ok(0));
    assert_eq!(seek_to(5, 100, 42, 0), Ok(42));
    // past the end is allowed (a read there returns 0 bytes)
    assert_eq!(seek_to(5, 100, 1000, 0), Ok(1000));
    assert_eq!(seek_to(5, 100, 10, 1), Ok(15));
    assert_eq!(seek_to(5, 100, -5, 1), Ok(0));
    assert_eq!(seek_to(5, 100, -6, 1), Err(EINVAL));
    assert_eq!(seek_to(5, 100, 0, 2), Ok(100));
    assert_eq!(seek_to(5, 100, -100, 2), Ok(0));
    assert_eq!(seek_to(5, 100, -101, 2), Err(EINVAL));
    assert_eq!(seek_to(5, 100, -1, 0), Err(EINVAL));
}

#[test]
fn seek_overflow_and_bad_whence() {
    assert_eq!(seek_to(i64::MAX as u64, 0, 1, 1), Err(EINVAL));
    assert_eq!(seek_to(0, i64::MAX as u64, 1, 2), Err(EINVAL));
    assert_eq!(seek_to(0, 10, 0, 5), Err(EINVAL));
    assert_eq!(seek_to(0, 10, 0, u32::MAX), Err(EINVAL));
}

#[test]
fn seek_data_and_hole() {
    assert_eq!(seek_to(0, 10, 3, 3), Ok(3));
    assert_eq!(seek_to(0, 10, 3, 4), Ok(10));
    assert_eq!(seek_to(0, 10, 10, 3), Err(ENXIO));
    assert_eq!(seek_to(0, 10, 10, 4), Err(ENXIO));
    assert_eq!(seek_to(0, 10, -1, 3), Err(EINVAL));
    assert_eq!(seek_to(0, 0, 0, 3), Err(ENXIO));
}

#[test]
fn snapshot_bytes_are_capped() {
    assert!(may_charge(0, 0, 4096));
    assert!(may_charge(TOTAL_CAP - 10, 0, 10));
    assert!(!may_charge(TOTAL_CAP - 10, 0, 11));
    assert!(may_charge(0, USER_CAP - 1, 1));
    assert!(!may_charge(0, USER_CAP, 1));
    assert!(!may_charge(usize::MAX, 0, 1));
    assert!(!may_charge(0, usize::MAX, 1));
    assert!(USER_CAP <= TOTAL_CAP);
}

#[test]
fn read_pieces() {
    assert_eq!(piece(10, 0, 4), 0..4);
    assert_eq!(piece(10, 8, 4), 8..10);
    assert_eq!(piece(10, 10, 4), 10..10);
    assert_eq!(piece(10, 1000, 4), 10..10);
    assert_eq!(piece(10, u64::MAX, 4), 10..10);
    assert_eq!(piece(10, 2, usize::MAX), 2..10);
    assert_eq!(piece(0, 0, 4), 0..0);
    assert_eq!(piece(10, 3, 0), 3..3);
}

#[test]
fn only_a_rewind_of_made_text_remakes() {
    assert!(remakes_on_seek(3, 0, 0));
    assert!(!remakes_on_seek(0, 0, 0)); // fixed text
    assert!(!remakes_on_seek(3, 1, 0));
    assert!(!remakes_on_seek(3, 0, 1)); // SEEK_CUR 0 is a position query
    assert!(!remakes_on_seek(3, 0, 2));
}

#[test]
fn a_sequence_of_reads_and_rewinds() {
    // a model of the descriptor: text, position; rewinds bring new text
    let mut text: Vec<u8> = b"cpu 1 2 3\n".to_vec();
    let mut pos = 0u64;
    let read = |text: &Vec<u8>, pos: &mut u64, n: usize| {
        let r = piece(text.len(), *pos, n);
        *pos += r.len() as u64;
        text[r].to_vec()
    };
    assert_eq!(read(&text, &mut pos, 4), b"cpu ");
    assert_eq!(read(&text, &mut pos, 100), b"1 2 3\n");
    assert_eq!(read(&text, &mut pos, 100), b"");
    if remakes_on_seek(3, 0, 0) {
        text = b"cpu 4 5 6 7\n".to_vec();
    }
    pos = seek_to(pos, text.len() as u64, 0, 0).unwrap();
    assert_eq!(read(&text, &mut pos, 100), b"cpu 4 5 6 7\n");
}

// ---------------------------------------------------------------- wave11 GP: directories

fn dir_text(entries: &[(u64, u8, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    for &(ino, t, n) in entries {
        v.extend_from_slice(&ino.to_le_bytes());
        v.push(t);
        v.push(n.len() as u8);
        v.extend_from_slice(n);
    }
    v
}

/// The (ino, d_off, type, name) of each linux_dirent64 record in `b`.
fn records(b: &[u8]) -> Vec<(u64, u64, u8, String)> {
    let mut v = Vec::new();
    let mut at = 0;
    while at < b.len() {
        let ino = u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        let off = u64::from_le_bytes(b[at + 8..at + 16].try_into().unwrap());
        let len = u16::from_le_bytes([b[at + 16], b[at + 17]]) as usize;
        assert_eq!(len % 8, 0);
        let t = b[at + 18];
        let name = &b[at + 19..at + len];
        let end = name.iter().position(|&c| c == 0).unwrap();
        v.push((ino, off, t, String::from_utf8(name[..end].to_vec()).unwrap()));
        at += len;
    }
    v
}

#[test]
fn dir_entries_parse_and_stop_at_a_cut() {
    let t = dir_text(&[(5, 4, b"12"), (6, 10, b"self")]);
    let e = dir_entries(&t);
    assert_eq!(e, vec![(5, 4, &b"12"[..]), (6, 10, &b"self"[..])]);
    // a cut-off last entry is left out
    assert_eq!(dir_entries(&t[..t.len() - 1]).len(), 1);
    assert_eq!(dir_entries(&t[..5]).len(), 0);
    assert!(dir_entries(&[]).is_empty());
}

#[test]
fn dirent64_lists_dot_dotdot_then_entries_in_pieces() {
    let t = dir_text(&[(5, 4, b"12"), (6, 10, b"self"), (7, 8, b"version")]);
    let (all, next) = dirent64(&t, 1, 0, 4096).unwrap();
    let r = records(&all);
    assert_eq!(next, 5);
    assert_eq!(r.iter().map(|x| x.3.as_str()).collect::<Vec<_>>(), [".", "..", "12", "self", "version"]);
    assert_eq!(r[0].0, 1);
    assert_eq!(r[2], (5, 3, 4, "12".to_string()));
    assert_eq!(r[4].1, 5);
    // a small buffer: one record at a time, continuing from the index
    let (one, n1) = dirent64(&t, 1, 0, 24).unwrap();
    assert_eq!((records(&one).len(), n1), (1, 1));
    let (two, n2) = dirent64(&t, 1, n1, 48).unwrap();
    assert_eq!((records(&two).len(), n2), (2, 3));
    // not even one fits: EINVAL; at the end: nothing
    assert_eq!(dirent64(&t, 1, 0, 10), Err(EINVAL));
    assert_eq!(dirent64(&t, 1, 5, 4096), Ok((Vec::new(), 5)));
    assert_eq!(dirent64(&t, 1, 99, 4096), Ok((Vec::new(), 99)));
    // an empty directory still has . and ..
    let (e, n) = dirent64(&[], 9, 0, 4096).unwrap();
    assert_eq!((records(&e).len(), n), (2, 2));
}
