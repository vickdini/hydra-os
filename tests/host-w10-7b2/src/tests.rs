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
