//! `zil.rs`: the log format (records, generations, torn records, the header, the state
//! record, the replay loop).

use crate::zil::*;
use std::collections::{BTreeMap, BTreeSet};

fn buf(n: usize) -> Vec<u8> {
    vec![0u8; n]
}

fn ops(log: &Log, s: &Scan) -> Vec<(u32, Vec<u8>, (u64, u32), i64, u64)> {
    s.ops.iter().map(|r| (r.op, log.payload(r.payload).to_vec(), r.time, r.status, r.value)).collect()
}

#[test]
fn records_round_trip_in_order() {
    let mut b = buf(HDR_SIZE + 4096);
    let mut log = Log::attach(&mut b);
    assert_eq!(log.header(), None);
    assert!(log.reset(0xAB, 7, b"state"));
    assert_eq!(log.header(), Some(Header { guid: 0xAB, gen: 7, attempts: 0 }));
    assert!(log.append(0x3108, (100, 5), 0, 42, b"create a"));
    assert!(log.append(0x310E, (101, 6), -2, 0, b""));
    assert!(log.append(0x3107, (102, 7), 0, 3, b"odd"));
    let s = log.scan(7);
    assert!(!s.torn);
    assert_eq!(log.payload(s.state.unwrap()), b"state");
    assert_eq!(
        ops(&log, &s),
        vec![
            (0x3108, b"create a".to_vec(), (100, 5), 0, 42),
            (0x310E, vec![], (101, 6), -2, 0),
            (0x3107, b"odd".to_vec(), (102, 7), 0, 3)
        ]
    );
    assert_eq!(s.end, log.used());
    assert_eq!(s.next_seq, 4);
    // 8-byte aligned records
    assert_eq!(s.end % 8, 0);
}

#[test]
fn a_torn_last_record_ends_the_log() {
    let mut b = buf(HDR_SIZE + 4096);
    let (end_two, last_at);
    {
        let mut log = Log::attach(&mut b);
        log.reset(1, 3, b"");
        log.append(1, (0, 0), 0, 0, b"first");
        log.append(2, (0, 0), 0, 0, b"second");
        end_two = log.used();
        log.append(3, (0, 0), 0, 0, b"third record");
        last_at = end_two;
    }
    // A kill in the middle of copying the payload: the checksum fails
    let mut torn = b.clone();
    torn[last_at + REC_HEAD + 2] ^= 0x55;
    let log = Log::attach(&mut torn);
    let s = log.scan(3);
    assert!(s.torn);
    assert_eq!(s.ops.len(), 2);
    assert_eq!(s.end, end_two);
    // A kill before the magic was written: the log simply ends there
    let mut nomagic = b.clone();
    nomagic[last_at..last_at + 4].copy_from_slice(&[0; 4]);
    let log = Log::attach(&mut nomagic);
    let s = log.scan(3);
    assert!(!s.torn);
    assert_eq!(s.ops.len(), 2);
    // A length that runs past the buffer
    let mut long = b.clone();
    long[last_at + 8..last_at + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    let log = Log::attach(&mut long);
    assert_eq!(log.scan(3).ops.len(), 2);
    // The appends then continue after the second record
    let mut log = Log::attach(&mut torn);
    let s = log.scan(3);
    log.resume(3, &s);
    assert!(log.append(9, (0, 0), 0, 0, b"after"));
    let s = log.scan(3);
    assert!(!s.torn);
    assert_eq!(s.ops.iter().map(|r| r.op).collect::<Vec<_>>(), vec![1, 2, 9]);
}

#[test]
fn an_older_generation_is_not_replayed() {
    let mut b = buf(HDR_SIZE + 8192);
    let mut log = Log::attach(&mut b);
    log.reset(1, 5, b"s5");
    for i in 0..6 {
        log.append(i, (0, 0), 0, 0, b"5");
    }
    // The commit of txg 6: a new generation over the old records
    log.reset(1, 6, b"s6");
    log.append(77, (0, 0), 0, 0, b"x");
    let s = log.scan(6);
    assert_eq!(s.ops.iter().map(|r| r.op).collect::<Vec<_>>(), vec![77]);
    // (the old records past the end have the magic but not the generation)
    assert!(s.torn);
    // The old generation finds no state record of its own: nothing at all
    let s5 = log.scan(5);
    assert_eq!(s5.state, None);
    assert!(s5.ops.is_empty());
    assert_eq!(s5.end, HDR_SIZE);
}

#[test]
fn a_kill_between_state_record_and_header_leaves_the_old_generation() {
    let mut b = buf(HDR_SIZE + 4096);
    {
        let mut log = Log::attach(&mut b);
        log.reset(9, 10, b"");
        log.append(1, (0, 0), 0, 0, b"a");
    }
    let header_before = b[..HDR_SIZE].to_vec();
    {
        let mut log = Log::attach(&mut b);
        log.reset(9, 11, b"");
    }
    // The new state record is written, the header write did not happen
    b[..HDR_SIZE].copy_from_slice(&header_before);
    let log = Log::attach(&mut b);
    let h = log.header().unwrap();
    assert_eq!(h.gen, 10);
    // gen 10's records are gone (overwritten): the import is at txg 11 anyway, so this log
    // is ignored; and if it were scanned for gen 10 it would yield nothing
    assert!(log.scan(10).ops.is_empty());
    assert_eq!(log.scan(10).state, None);
}

#[test]
fn a_damaged_header_means_no_log() {
    let mut b = buf(HDR_SIZE + 4096);
    let mut log = Log::attach(&mut b);
    log.reset(1, 2, b"");
    drop(log);
    for at in [0usize, 9, 17, 25, 33] {
        let mut c = b.clone();
        c[at] ^= 1;
        assert_eq!(Log::attach(&mut c).header(), None, "byte {}", at);
    }
    // The attempts counter is outside the checksum
    let mut c = b.clone();
    let mut log = Log::attach(&mut c);
    assert_eq!(log.begin_replay(), 0);
    assert_eq!(log.begin_replay(), 1);
    assert_eq!(log.header().unwrap().attempts, 2);
    // A reset starts the count over
    log.reset(1, 3, b"");
    assert_eq!(log.header().unwrap().attempts, 0);
}

#[test]
fn appends_stop_when_full_and_without_a_generation() {
    let mut b = buf(HDR_SIZE + 256);
    let mut log = Log::attach(&mut b);
    // No generation yet
    assert!(!log.append(1, (0, 0), 0, 0, b""));
    assert!(log.reset(1, 1, b""));
    assert!(log.append(1, (0, 0), 0, 0, &[7u8; 64]));
    let used = log.used();
    assert!(!log.append(2, (0, 0), 0, 0, &[7u8; 200]));
    assert_eq!(log.used(), used);
    // A state that does not fit: no usable log, and a header no import matches
    assert!(!log.reset(1, 2, &[0u8; 1024]));
    assert_eq!(log.gen(), 0);
    assert!(!log.append(1, (0, 0), 0, 0, b""));
    assert_eq!(log.header().unwrap().gen, 0);
    // gen 0 is never a log
    assert!(!log.reset(1, 0, b""));
}

#[test]
fn the_state_record_round_trips() {
    let mut open = BTreeMap::new();
    open.insert(5u64, 1u32);
    open.insert(1 << 40, 3);
    let mut orphans = BTreeSet::new();
    orphans.insert(1u64 << 40);
    let e = encode_state(&open, &orphans);
    assert_eq!(decode_state(&e), Some((open.clone(), orphans.clone())));
    assert_eq!(decode_state(&encode_state(&BTreeMap::new(), &BTreeSet::new())), Some((BTreeMap::new(), BTreeSet::new())));
    // Truncated or with bytes left over: not a state record
    assert_eq!(decode_state(&e[..e.len() - 1]), None);
    let mut more = e.clone();
    more.push(0);
    assert_eq!(decode_state(&more), None);
    assert_eq!(decode_state(&[]), None);
    let mut huge = e.clone();
    huge[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(decode_state(&huge), None);
}

#[test]
fn records_out_of_place_end_the_log() {
    // An op record first (no state record): no log
    let mut b = buf(HDR_SIZE + 4096);
    let mut log = Log::attach(&mut b);
    log.reset(1, 4, b"");
    log.append(1, (0, 0), 0, 0, b"a");
    drop(log);
    // Change the state record's kind to an op (and fix its checksum the way put does)
    let mut c = b.clone();
    c[HDR_SIZE + 4..HDR_SIZE + 8].copy_from_slice(&KIND_OP.to_le_bytes());
    let sum = checksum(&[&c[HDR_SIZE..HDR_SIZE + 56], &[]]);
    c[HDR_SIZE + 56..HDR_SIZE + 64].copy_from_slice(&sum.to_le_bytes());
    let log = Log::attach(&mut c);
    let s = log.scan(4);
    assert_eq!(s.state, None);
    assert!(s.ops.is_empty());
    assert!(s.torn);
}

#[test]
fn the_checksum_sees_every_byte_and_the_part_boundaries() {
    let data: Vec<u8> = (0..100u8).collect();
    let base = checksum(&[&data]);
    for i in 0..data.len() {
        let mut d = data.clone();
        d[i] ^= 0x80;
        assert_ne!(checksum(&[&d]), base, "byte {}", i);
    }
    assert_ne!(checksum(&[b"ab", b"c"]), checksum(&[b"a", b"bc"]));
    assert_ne!(checksum(&[b"a"]), checksum(&[b"a\0"]));
    assert_ne!(checksum(&[]), checksum(&[b""]));
}

#[test]
fn replay_applies_in_order_and_counts_differences() {
    let mut b = buf(HDR_SIZE + 4096);
    let mut log = Log::attach(&mut b);
    log.reset(1, 1, b"");
    log.append(1, (10, 0), 0, 100, b"a");
    log.append(2, (11, 0), 0, 101, b"b");
    log.append(3, (12, 0), -17, 0, b"c");
    let s = log.scan(1);
    // A model: values from a counter that the requests move (as object numbers are)
    let run = |log: &Log, s: &Scan, start: u64| {
        let mut next = start;
        let mut seen = Vec::new();
        let r = replay(log, s, |op, req, t| {
            seen.push((op, req.to_vec(), t));
            if op == 3 {
                return (-17, 0);
            }
            next += 1;
            (0, next - 1)
        });
        (r, seen)
    };
    let (r1, seen1) = run(&log, &s, 100);
    assert_eq!(r1, Replayed { applied: 3, mismatches: 0, first_mismatch: 0 });
    // Replaying twice from the same start gives the same results
    let (r2, seen2) = run(&log, &s, 100);
    assert_eq!(r1, r2);
    assert_eq!(seen1, seen2);
    assert_eq!(seen1[1], (2, b"b".to_vec(), (11, 0)));
    // From another start the object numbers differ: reported
    let (r3, _) = run(&log, &s, 200);
    assert_eq!(r3.mismatches, 2);
    assert_eq!(r3.first_mismatch, 1);
}
