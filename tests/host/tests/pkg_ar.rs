//! Tests for the Unix `ar` archive reader in `src/pkg/ar.rs`, which unpacks
//! `.deb` packages. Inputs are built here with a small encoder that follows
//! the System V / GNU format.

use hydra_hosttests::pkg::ar::{ArArchive, AR_HEADER_SIZE, AR_MAGIC};

/// One 60-byte member header plus data and its alignment pad.
fn member(name: &str, data: &[u8]) -> Vec<u8> {
    let mut h = format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", name, 0, 0, 0, "100644", data.len()).into_bytes();
    assert_eq!(h.len(), AR_HEADER_SIZE);
    h.extend_from_slice(data);
    if data.len() % 2 == 1 {
        h.push(b'\n');
    }
    h
}

fn archive(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = AR_MAGIC.to_vec();
    for (name, data) in members {
        out.extend(member(name, data));
    }
    out
}

fn deb() -> Vec<u8> {
    archive(&[
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", b"CONTROL"),     // odd length: exercises the pad byte
        ("data.tar.xz/", b"DATA-PAYLOAD"), // GNU-style trailing slash
    ])
}

#[test]
fn rejects_bad_magic() {
    assert!(ArArchive::new(b"!<arch>").is_err(), "too short");
    assert!(ArArchive::new(b"!<arch>\r\n").is_err());
    assert!(ArArchive::new(b"PK\x03\x04....").is_err());
    assert!(ArArchive::new(AR_MAGIC).is_ok(), "empty archive is valid");
}

#[test]
fn empty_archive_has_no_entries() {
    assert_eq!(ArArchive::new(AR_MAGIC).unwrap().entries().count(), 0);
}

#[test]
fn iterates_members_in_order_with_padding() {
    let data = deb();
    let ar = ArArchive::new(&data).unwrap();
    let got: Vec<(&str, usize, &[u8])> = ar.entries().map(|e| (e.name, e.size, e.data)).collect();
    assert_eq!(
        got,
        vec![
            ("debian-binary", 4, &b"2.0\n"[..]),
            ("control.tar.xz", 7, &b"CONTROL"[..]),
            ("data.tar.xz", 12, &b"DATA-PAYLOAD"[..]),
        ]
    );
}

#[test]
fn get_entry_by_exact_name() {
    let data = deb();
    let ar = ArArchive::new(&data).unwrap();
    assert_eq!(ar.get_entry("debian-binary").unwrap().data, b"2.0\n");
    assert!(ar.get_entry("missing").is_none());
}

#[test]
fn get_entry_matches_prefix_for_any_compression() {
    // Callers ask for "data.tar" without knowing whether it is .gz, .xz or .zst.
    let data = deb();
    let ar = ArArchive::new(&data).unwrap();
    assert_eq!(ar.get_entry("data.tar").unwrap().name, "data.tar.xz");
    assert_eq!(ar.get_entry("control.tar").unwrap().name, "control.tar.xz");
}

#[test]
fn stops_at_corrupt_header_trailer() {
    let mut data = deb();
    let second = AR_MAGIC.len() + AR_HEADER_SIZE + 4;
    data[second + 58] = b'X';
    let names: Vec<_> = ArArchive::new(&data).unwrap().entries().map(|e| e.name).collect();
    assert_eq!(names, vec!["debian-binary"]);
}

#[test]
fn stops_at_non_numeric_size() {
    let mut data = deb();
    data[AR_MAGIC.len() + 48] = b'z';
    assert_eq!(ArArchive::new(&data).unwrap().entries().count(), 0);
}

#[test]
fn stops_when_member_runs_past_end() {
    let mut data = archive(&[("a", b"0123456789")]);
    data.truncate(data.len() - 1);
    assert_eq!(ArArchive::new(&data).unwrap().entries().count(), 0);

    // Header itself truncated.
    let data = archive(&[("a", b"xy")]);
    assert_eq!(ArArchive::new(&data[..AR_MAGIC.len() + 30]).unwrap().entries().count(), 0);
}

#[test]
fn huge_declared_size_does_not_overflow() {
    let mut data = AR_MAGIC.to_vec();
    let h = format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", "big", 0, 0, 0, "100644", "9999999999");
    data.extend_from_slice(h.as_bytes());
    assert_eq!(ArArchive::new(&data).unwrap().entries().count(), 0);
}

#[test]
fn final_odd_member_without_pad_byte_is_still_read() {
    let mut data = archive(&[("odd", b"abc")]);
    assert_eq!(data.pop(), Some(b'\n'));
    let e: Vec<_> = ArArchive::new(&data).unwrap().entries().collect();
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].data, b"abc");
}
