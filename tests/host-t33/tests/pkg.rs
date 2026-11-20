//! The root file system installer (`src/pkg/rootfs.rs`) unpacking tar archives into the fake
//! pool: every entry kind, GNU long names, pax headers, hard links to later entries,
//! replacing what is there, directory times, gzip; plus the `ar`/`tar` readers it sits with.

use std::io::Write;
use std::sync::Mutex;

use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs};
use hydra_hosttests_t33::fs::client::ZfsClient;
use hydra_hosttests_t33::fs::zfs::types::DnodeType;
use hydra_hosttests_t33::pkg::{rootfs, ArArchive, TarArchive};

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    fakefs::pool();
    g
}

fn octal(field: &mut [u8], v: u64) {
    let s = format!("{:0w$o}\0", v, w = field.len() - 1);
    field.copy_from_slice(s.as_bytes());
}

/// One tar entry (header + body padded to 512).
fn entry(name: &str, kind: u8, mode: u32, body: &[u8], link: &str) -> Vec<u8> {
    entry_full(name, kind, mode, body, link, 1_600_000_000, 0, None)
}

#[allow(clippy::too_many_arguments)]
fn entry_full(name: &str, kind: u8, mode: u32, body: &[u8], link: &str, mtime: u64, rdev: u64, prefix: Option<&str>) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], mode as u64);
    octal(&mut h[108..116], 1000);
    octal(&mut h[116..124], 100);
    octal(&mut h[124..136], body.len() as u64);
    octal(&mut h[136..148], mtime);
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    octal(&mut h[329..337], rdev >> 8);
    octal(&mut h[337..345], rdev & 0xFF);
    if let Some(p) = prefix {
        h[345..345 + p.len()].copy_from_slice(p.as_bytes());
    }
    let mut v = h;
    v.extend_from_slice(body);
    v.resize(v.len().div_ceil(512) * 512, 0);
    v
}

fn finish(mut v: Vec<u8>) -> Vec<u8> {
    v.extend_from_slice(&[0u8; 1024]);
    v
}

fn lookup(p: &str) -> (u64, DnodeType) {
    ZfsClient::lookup(p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn link(p: &str) -> u64 {
    ZfsClient::resolve(0, p.as_bytes(), false).unwrap()
}

fn read(p: &str) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    let n = ZfsClient::read_file_by_path(p, &mut b).unwrap();
    b.truncate(n);
    b
}

#[test]
fn every_entry_kind_is_installed() {
    let _g = serial();
    fakefs::test_dir("rootfs1");
    let mut a = Vec::new();
    a.extend(entry("./", b'5', 0o755, b"", ""));
    a.extend(entry_full("./etc/", b'5', 0o755, b"", "", 1_500_000_000, 0, None));
    for d in ["./dev/", "./usr/", "./usr/share/", "./usr/prefixed/", "./opt/"] {
        a.extend(entry(d, b'5', 0o755, b"", ""));
    }
    a.extend(entry("./etc/hostname", b'0', 0o644, b"hydra\n", ""));
    a.extend(entry("./etc/empty", 0, 0o600, b"", ""));
    a.extend(entry("./etc/contig", b'7', 0o644, b"c", ""));
    a.extend(entry("./etc/hn-link", b'2', 0o777, b"", "hostname"));
    // A hard link to a file that comes later: retried at the end
    a.extend(entry("./etc/early", b'1', 0o644, b"", "etc/late"));
    a.extend(entry("./etc/late", b'0', 0o644, b"late", ""));
    a.extend(entry("./etc/hard", b'1', 0o644, b"", "./etc/hostname"));
    a.extend(entry_full("./dev/null", b'3', 0o666, b"", "", 0, (1 << 8) | 3, None));
    a.extend(entry_full("./dev/sda", b'4', 0o660, b"", "", 0, (8 << 8) | 0, None));
    a.extend(entry("./dev/fifo", b'6', 0o644, b"", ""));
    a.extend(entry("./dev/sock", b'S', 0o644, b"", "")); // unknown kind: skipped
    a.extend(entry("./opt/missing-link", b'1', 0o644, b"", "nowhere")); // never resolvable
    // GNU long name and long link
    let long = format!("usr/share/{}", "n".repeat(150));
    let mut ln = long.clone().into_bytes();
    ln.push(0);
    a.extend(entry("././@LongLink", b'L', 0, &ln, ""));
    a.extend(entry("ignored", b'0', 0o644, b"long", ""));
    let target = format!("/{}", "t".repeat(120));
    let mut lk = target.clone().into_bytes();
    lk.push(0);
    a.extend(entry("././@LongLink", b'K', 0, &lk, ""));
    a.extend(entry("usr/longlink", b'2', 0o777, b"", "ignored"));
    // pax: path and linkpath, a global header
    let rec = |k: &str, v: &str| {
        let body = format!(" {k}={v}\n");
        let mut n = body.len() + 1;
        while format!("{n}{body}").len() != n {
            n += 1;
        }
        format!("{n}{body}")
    };
    let pax = format!("{}{}{}", rec("path", "usr/pax-name"), rec("linkpath", "pax-target"), rec("mtime", "1"));
    a.extend(entry("PaxHeader", b'x', 0, pax.as_bytes(), ""));
    a.extend(entry("short", b'2', 0o777, b"", "short-target"));
    a.extend(entry("pax_global_header", b'g', 0, b"20 comment=nothing\n", ""));
    // The ustar prefix field
    a.extend(entry_full("file.txt", b'0', 0o640, b"pre", "", 1, 0, Some("usr/prefixed")));
    let sum = rootfs::install(&finish(a), "/rootfs1").unwrap();
    assert_eq!(read("/rootfs1/etc/hostname"), b"hydra\n");
    let (h, _) = lookup("/rootfs1/etc/hostname");
    let a = ZfsClient::getattr(h).unwrap();
    assert_eq!((a.mode & 0o7777, a.uid, a.gid, a.mtime.0), (0o644, 1000, 100, 1_600_000_000));
    assert_eq!(ZfsClient::readlink(link("/rootfs1/etc/hn-link")), Ok(b"hostname".to_vec()));
    assert_eq!(lookup("/rootfs1/etc/hard").0, h, "a hard link");
    assert_eq!(lookup("/rootfs1/etc/early").0, lookup("/rootfs1/etc/late").0, "deferred hard link");
    let null = ZfsClient::getattr(lookup("/rootfs1/dev/null").0).unwrap();
    assert_eq!((null.mode, null.rdev), (0o020666, 0x103));
    assert_eq!(ZfsClient::getattr(lookup("/rootfs1/dev/sda").0).unwrap().mode, 0o060660);
    assert_eq!(ZfsClient::getattr(lookup("/rootfs1/dev/fifo").0).unwrap().mode, 0o010644);
    assert!(ZfsClient::lookup("/rootfs1/dev/sock").is_err());
    assert_eq!(read(&format!("/rootfs1/{long}")), b"long");
    assert_eq!(ZfsClient::readlink(link("/rootfs1/usr/longlink")), Ok(target.into_bytes()));
    assert_eq!(ZfsClient::readlink(link("/rootfs1/usr/pax-name")), Ok(b"pax-target".to_vec()));
    assert_eq!(read("/rootfs1/usr/prefixed/file.txt"), b"pre");
    // Directory times are put back last
    assert_eq!(ZfsClient::getattr(lookup("/rootfs1/etc").0).unwrap().mtime.0, 1_500_000_000);
    assert_eq!(sum.files, 6);
    assert_eq!(sum.dirs, 6, "the archive root is not counted");
    assert_eq!(sum.symlinks, 3);
    assert_eq!(sum.hardlinks, 2, "early (once, though it was retried) and hard; the missing one is skipped");
    assert_eq!(sum.devices, 3);
    assert_eq!(sum.bytes, 6 + 1 + 4 + 4 + 3);
    assert_eq!(sum.skipped, 2, "the unknown kind and the unresolvable link");
    let out = fake::console_take();
    assert!(out.contains("Unpacking") && out.contains("Committing to disk"));
}

#[test]
fn what_is_there_is_replaced_but_directories_stay() {
    let _g = serial();
    fakefs::test_dir("rootfs2");
    with_fs(|fs| {
        let d = fs.mkdir_p(fakefs::ROOT_INO, "rootfs2");
        fs.put(d, "file-to-dir", b"old");
        fs.mkdir_p(d, "dir-stays");
        fs.put(d, "replaced", b"old contents");
    });
    let mut a = Vec::new();
    a.extend(entry("file-to-dir/", b'5', 0o700, b"", ""));
    a.extend(entry("dir-stays", b'0', 0o644, b"x", ""));
    a.extend(entry("replaced", b'0', 0o644, b"new", ""));
    a.extend(entry("dir-stays/", b'5', 0o750, b"", "")); // an existing directory is kept
    let sum = rootfs::install(&finish(a), "/rootfs2").unwrap();
    assert_eq!(lookup("/rootfs2/file-to-dir").1, DnodeType::Directory);
    assert_eq!(lookup("/rootfs2/dir-stays").1, DnodeType::Directory);
    assert_eq!(ZfsClient::getattr(lookup("/rootfs2/dir-stays").0).unwrap().mode & 0o777, 0o750);
    assert_eq!(read("/rootfs2/replaced"), b"new");
    assert_eq!(sum.skipped, 1);
}

#[test]
fn gzip_large_sizes_and_bad_archives() {
    let _g = serial();
    fakefs::test_dir("rootfs3");
    // A gzip archive
    let tar = finish(entry("hello", b'0', 0o644, b"compressed", ""));
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&tar).unwrap();
    let gz = enc.finish().unwrap();
    let sum = rootfs::install(&gz, "/rootfs3/gz").unwrap();
    assert_eq!(sum.files, 1);
    assert_eq!(read("/rootfs3/gz/hello"), b"compressed");
    assert!(fake::console_take().contains("Decompressing"));
    // A broken gzip stream
    assert!(rootfs::install(&[0x1F, 0x8B, 8, 0, 0, 0], "/rootfs3/bad").is_err());
    // GNU base-256 size field
    let mut e = entry("b256", b'0', 0o644, b"abc", "");
    e[124..136].fill(0);
    e[124] = 0x80;
    e[135] = 3;
    let sum = rootfs::install(&finish(e), "/rootfs3/b256").unwrap();
    assert_eq!((sum.files, sum.bytes), (1, 3));
    // A body past the end of the archive
    let mut t = entry("trunc", b'0', 0o644, &[7u8; 2000], "");
    t.truncate(1024);
    assert_eq!(rootfs::install(&t, "/rootfs3/t").unwrap_err(), "truncated tar archive");
    // The destination cannot be made
    with_fs(|fs| fs.put(fakefs::ROOT_INO, "rootfs3-file", b""));
    assert!(rootfs::install(&finish(Vec::new()), "/rootfs3-file/x").is_err());
    // An entry that fails is a warning, not the end
    let mut a = Vec::new();
    a.extend(entry("ok", b'0', 0o644, b"1", ""));
    a.extend(entry("ok/inside", b'0', 0o644, b"2", "")); // parent is a file
    let sum = rootfs::install(&finish(a), "/rootfs3/w").unwrap();
    assert_eq!((sum.files, sum.skipped), (1, 1), "the failed entry is skipped, not also counted as a file");
    assert!(fake::console_take().contains("warning: ok/inside"));
}

#[test]
fn progress_every_500_entries() {
    let _g = serial();
    fakefs::test_dir("rootfs4");
    let mut a = Vec::new();
    for i in 0..500 {
        a.extend(entry(&format!("f{i}"), b'0', 0o644, b"", ""));
    }
    rootfs::install(&finish(a), "/rootfs4").unwrap();
    assert!(fake::console_take().contains("500 entries, 0 MiB written"));
}

#[test]
fn ar_and_tar_readers() {
    // ar: a .deb-like archive with an odd-sized member (padded)
    let mut ar = b"!<arch>\n".to_vec();
    let mut member = |name: &str, data: &[u8]| {
        let mut h = format!("{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", name, 0, 0, 0, "100644", data.len()).into_bytes();
        assert_eq!(h.len(), 60);
        ar.append(&mut h);
        ar.extend_from_slice(data);
        if data.len() % 2 == 1 {
            ar.push(b'\n');
        }
    };
    member("debian-binary", b"2.0\n");
    member("data.tar/", b"odd");
    let a = ArArchive::new(&ar).unwrap();
    let names: Vec<String> = a.entries().map(|e| e.name.to_string()).collect();
    assert_eq!(names, vec!["debian-binary", "data.tar"]);
    assert!(ArArchive::new(b"not an archive").is_err());
    assert_eq!(a.get_entry("debian-binary").unwrap().data, b"2.0
");
    assert!(a.get_entry("control.tar").is_none());
}

#[test]
fn the_plain_tar_extractor_writes_through_the_client() {
    let _g = serial();
    let mut t = Vec::new();
    t.extend(entry("./tarx/", b'5', 0o755, b"", ""));
    t.extend(entry("./tarx/a.txt", b'0', 0o644, b"plain", ""));
    t.extend(entry("tarx/ln", b'2', 0o777, b"", "a.txt"));
    let sum = TarArchive::new(&finish(t)).extract_to_zfs().unwrap();
    assert_eq!((sum.files_extracted, sum.dirs_created, sum.total_bytes), (1, 1, 5));
    assert_eq!(read("/tarx/a.txt"), b"plain");
}
