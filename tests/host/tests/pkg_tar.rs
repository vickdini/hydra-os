//! Tests for the tar extractor in `src/pkg/tar.rs`, which installs root
//! filesystems and `.deb` payloads into ZFS. Writes go to the fake
//! `ZfsClient`, so each test can inspect exactly which paths were created.

use std::collections::BTreeMap;

use hydra_hosttests::fake;
use hydra_hosttests::pkg::tar::{TarArchive, TAR_BLOCK_SIZE};

/// Entry for the test tar writer.
struct E<'a> {
    name: &'a str,
    kind: u8,
    data: &'a [u8],
    link: &'a str,
    prefix: &'a str,
}

fn file<'a>(name: &'a str, data: &'a [u8]) -> E<'a> {
    E { name, kind: b'0', data, link: "", prefix: "" }
}
fn dir(name: &str) -> E<'_> {
    E { name, kind: b'5', data: b"", link: "", prefix: "" }
}
fn symlink<'a>(name: &'a str, target: &'a str) -> E<'a> {
    E { name, kind: b'2', data: b"", link: target, prefix: "" }
}

fn header(e: &E) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..e.name.len()].copy_from_slice(e.name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[124..136].copy_from_slice(format!("{:011o}\0", e.data.len()).as_bytes());
    h[156] = e.kind;
    h[157..157 + e.link.len()].copy_from_slice(e.link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[345..345 + e.prefix.len()].copy_from_slice(e.prefix.as_bytes());
    // Checksum: computed with the field as spaces (the extractor ignores it,
    // but keep the archives valid for real tools).
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn tar(entries: &[E]) -> Vec<u8> {
    let mut out = Vec::new();
    for e in entries {
        out.extend_from_slice(&header(e));
        out.extend_from_slice(e.data);
        out.resize(out.len().next_multiple_of(TAR_BLOCK_SIZE), 0);
    }
    out.extend_from_slice(&[0u8; 1024]); // end-of-archive marker
    out
}

fn files() -> BTreeMap<String, Vec<u8>> {
    fake::ZFS_FILES.with_borrow(|m| m.clone())
}

fn dirs() -> Vec<String> {
    fake::ZFS_DIRS.with_borrow(|v| v.clone())
}

#[test]
fn extracts_files_dirs_and_symlinks() {
    fake::reset();
    let busybox = vec![0x7Fu8; 1000]; // spans two blocks
    let data = tar(&[
        dir("bin/"),
        file("bin/busybox", &busybox),
        symlink("bin/sh", "busybox"),
        file("etc/hostname", b"hydra\n"),
    ]);
    let s = TarArchive::new(&data).extract_to_zfs().unwrap();
    assert_eq!((s.files_extracted, s.dirs_created, s.symlinks_recorded), (2, 1, 1));
    assert_eq!(s.total_bytes, 1006);
    assert_eq!(dirs(), vec!["/bin"]);
    let f = files();
    assert_eq!(f["/bin/busybox"], busybox);
    assert_eq!(f["/etc/hostname"], b"hydra\n");
    assert_eq!(f["/bin/sh"], b"busybox", "symlinks are recorded as their target text");
    assert_eq!(fake::ZFS_SYNCS.get(), 1, "one sync at the end, not per file");
}

#[test]
fn leading_dot_slash_and_root_are_normalised() {
    fake::reset();
    let data = tar(&[file("./usr/lib/a", b"a"), file("/opt/b", b"b"), dir("./"), dir("."), dir("/")]);
    let s = TarArchive::new(&data).extract_to_zfs().unwrap();
    assert_eq!(s.dirs_created, 0, "the archive root itself is not a directory to create");
    assert!(files().contains_key("/usr/lib/a"));
    assert!(files().contains_key("/opt/b"));
}

#[test]
fn hidden_files_under_dot_slash_keep_their_dot() {
    fake::reset();
    let data = tar(&[file("./.bashrc", b"alias ll='ls -l'\n"), dir("./.config/")]);
    TarArchive::new(&data).extract_to_zfs().unwrap();
    assert!(files().contains_key("/.bashrc"));
    assert_eq!(dirs(), vec!["/.config"]);
}

#[test]
fn hidden_files_without_prefix_keep_their_dot() {
    fake::reset();
    let data = tar(&[file(".bashrc", b"alias ll='ls -l'\n"), dir(".config/")]);
    TarArchive::new(&data).extract_to_zfs().unwrap();
    assert!(files().contains_key("/.bashrc"), "got {:?}", files().keys().collect::<Vec<_>>());
    assert_eq!(dirs(), vec!["/.config"]);
}

#[test]
fn ustar_prefix_is_joined() {
    fake::reset();
    let mut e = file("libfoo.so.1", b"ELF");
    e.prefix = "usr/lib/x86_64-linux-gnu";
    TarArchive::new(&tar(&[e])).extract_to_zfs().unwrap();
    assert_eq!(files()["/usr/lib/x86_64-linux-gnu/libfoo.so.1"], b"ELF");
}

#[test]
fn gnu_long_names_apply_to_the_next_entry_only() {
    fake::reset();
    let long = format!("usr/share/{}/file.txt", "very-long-directory-name".repeat(6));
    assert!(long.len() > 100);
    let mut name_data = long.clone().into_bytes();
    name_data.push(0);
    let data = tar(&[
        E { name: "././@LongLink", kind: b'L', data: &name_data, link: "", prefix: "" },
        file("truncated-name", b"payload"),
        file("short", b"x"),
    ]);
    let s = TarArchive::new(&data).extract_to_zfs().unwrap();
    assert_eq!(s.files_extracted, 2);
    let f = files();
    assert_eq!(f[&format!("/{long}")], b"payload");
    assert!(!f.contains_key("/truncated-name"));
    assert_eq!(f["/short"], b"x");
}

#[test]
fn nul_type_flag_means_regular_file() {
    fake::reset();
    let mut e = file("old-style", b"v7");
    e.kind = 0;
    TarArchive::new(&tar(&[e])).extract_to_zfs().unwrap();
    assert_eq!(files()["/old-style"], b"v7");
}

#[test]
fn hard_links_and_special_files_are_skipped() {
    fake::reset();
    let data = tar(&[
        E { name: "hard", kind: b'1', data: b"", link: "target", prefix: "" },
        E { name: "dev/null", kind: b'3', data: b"", link: "", prefix: "" },
        E { name: "fifo", kind: b'6', data: b"", link: "", prefix: "" },
        file("after", b"still read"),
    ]);
    let s = TarArchive::new(&data).extract_to_zfs().unwrap();
    assert_eq!((s.files_extracted, s.dirs_created, s.symlinks_recorded), (1, 0, 0));
    assert_eq!(files().len(), 1);
}

#[test]
fn stops_at_the_zero_block() {
    fake::reset();
    let mut data = tar(&[file("a", b"1")]);
    data.extend_from_slice(&header(&file("ghost", b"")));
    TarArchive::new(&data).extract_to_zfs().unwrap();
    assert!(!files().contains_key("/ghost"));
}

#[test]
fn archive_without_end_marker_is_fine() {
    fake::reset();
    let mut data = tar(&[file("a", b"12345")]);
    data.truncate(1024); // header + one data block, no zero blocks
    assert_eq!(TarArchive::new(&data).extract_to_zfs().unwrap().files_extracted, 1);
}

#[test]
fn truncated_data_is_an_error() {
    fake::reset();
    let data = tar(&[file("big", &[1u8; 2000])]);
    assert!(TarArchive::new(&data[..512 + 1024]).extract_to_zfs().is_err());
}

#[test]
fn empty_and_tiny_inputs() {
    fake::reset();
    let s = TarArchive::new(&[]).extract_to_zfs().unwrap();
    assert_eq!(s.files_extracted, 0);
    assert_eq!(fake::ZFS_SYNCS.get(), 1);
    assert_eq!(TarArchive::new(&[0u8; 100]).extract_to_zfs().unwrap().files_extracted, 0);
}

#[test]
fn write_failures_are_skipped_not_counted() {
    fake::reset();
    fake::ZFS_WRITE_FAILS.with_borrow_mut(|v| v.push("/bad".into()));
    let s = TarArchive::new(&tar(&[file("bad", b"x"), file("good", b"yy")])).extract_to_zfs().unwrap();
    assert_eq!((s.files_extracted, s.total_bytes), (1, 2));
}

#[test]
fn size_field_variants() {
    // GNU tar pads with leading zeros and a NUL; some writers use spaces.
    for field in [&b"00000000005\0"[..], b"          5\0", b"5\0          ", b"00000000005 "] {
        fake::reset();
        let mut data = tar(&[file("f", b"hello")]);
        data[124..136].copy_from_slice(field);
        TarArchive::new(&data).extract_to_zfs().unwrap();
        assert_eq!(files()["/f"], b"hello", "size field {:?}", String::from_utf8_lossy(field));
    }
}

#[test]
fn many_entries() {
    fake::reset();
    let bodies: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; i * 37]).collect();
    let names: Vec<String> = (0..100).map(|i| format!("data/f{i:03}")).collect();
    let entries: Vec<E> = names.iter().zip(&bodies).map(|(n, b)| file(n, b)).collect();
    let s = TarArchive::new(&tar(&entries)).extract_to_zfs().unwrap();
    assert_eq!(s.files_extracted, 100);
    let f = files();
    for (n, b) in names.iter().zip(&bodies) {
        assert_eq!(&f[&format!("/{n}")], b);
    }
}
