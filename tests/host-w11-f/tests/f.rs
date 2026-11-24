//! Group F's host tests (wave 11): the SETATTR request vfs-server's FUSE changes send, the
//! `/dev/pts` listing tty-server answers, and where an efivars unlink's path is redirected.

use hydra_hosttests_w11_f::calls::served;
use hydra_hosttests_w11_f::ctx::{Ctx, Node};
use hydra_hosttests_w11_f::devpts;
use hydra_hosttests_w11_f::fake::{Fake, ROOT};
use hydra_hosttests_w11_f::fuse::wire;

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ----------------------------------------------------------------------
// FUSE SETATTR
// ----------------------------------------------------------------------

#[test]
fn setattr_in_has_linux_layout_and_valid_bits() {
    let b = wire::setattr_in(Some(0o640), Some(1000), Some(100), Some(4096), Some((11, 22)), Some((33, 44)));
    assert_eq!(b.len(), 88);
    assert_eq!(u32_at(&b, 0), 1 | 2 | 4 | 8 | 16 | 32);
    assert_eq!(u64_at(&b, 8), 0, "no file handle");
    assert_eq!(u64_at(&b, 16), 4096, "size");
    assert_eq!(u64_at(&b, 32), 11, "atime");
    assert_eq!(u64_at(&b, 40), 33, "mtime");
    assert_eq!(u32_at(&b, 56), 22, "atimensec");
    assert_eq!(u32_at(&b, 60), 44, "mtimensec");
    assert_eq!(u32_at(&b, 68), 0o640, "mode");
    assert_eq!(u32_at(&b, 76), 1000, "uid");
    assert_eq!(u32_at(&b, 80), 100, "gid");
}

#[test]
fn setattr_in_sets_only_what_is_given() {
    let b = wire::setattr_in(None, None, None, Some(0), None, None);
    assert_eq!(u32_at(&b, 0), 8, "a truncation: FATTR_SIZE only");
    assert_eq!(u64_at(&b, 16), 0);
    let b = wire::setattr_in(Some(0o600), None, None, None, None, None);
    assert_eq!(u32_at(&b, 0), 1);
    assert_eq!(u32_at(&b, 68), 0o600);
    let b = wire::setattr_in(None, Some(7), None, None, None, None);
    assert_eq!(u32_at(&b, 0), 2);
    assert_eq!(u32_at(&b, 80), 0, "gid not given: 0");
    let b = wire::setattr_in(None, None, None, None, None, Some((5, 6)));
    assert_eq!(u32_at(&b, 0), 32);
    assert_eq!(u64_at(&b, 32), 0, "atime not given");
    let b = wire::setattr_in(None, None, None, None, None, None);
    assert_eq!(u32_at(&b, 0), 0);
    assert_eq!(b.len(), 88);
}

// ----------------------------------------------------------------------
// /dev/pts listed
// ----------------------------------------------------------------------

/// The records of a `getdents64` buffer: `(ino, off, type, name)`.
fn records(b: &[u8]) -> Vec<(u64, i64, u8, String)> {
    let mut v = Vec::new();
    let mut o = 0;
    while o < b.len() {
        let reclen = u16::from_le_bytes([b[o + 16], b[o + 17]]) as usize;
        assert!(reclen >= 24 && reclen % 8 == 0, "record length {reclen}");
        let name_end = b[o + 19..o + reclen].iter().position(|&c| c == 0).unwrap();
        v.push((u64_at(b, o), u64_at(b, o + 8) as i64, b[o + 18], String::from_utf8(b[o + 19..o + 19 + name_end].to_vec()).unwrap()));
        o += reclen;
    }
    v
}

#[test]
fn pts_entries_are_dots_ptmx_and_the_slaves() {
    let e = devpts::entries(&[0, 3, 12]);
    let names: Vec<String> = e.iter().map(|x| String::from_utf8(x.1.clone()).unwrap()).collect();
    assert_eq!(names, [".", "..", "ptmx", "0", "3", "12"]);
    assert_eq!(e[2].0, 2, "ptmx is inode 2");
    assert_eq!(e[3].0, 3, "slave N is inode N + 3");
    assert_eq!(e[5].0, 15);
    assert_eq!((e[0].2, e[2].2, e[4].2), (4, 2, 2), "DT_DIR, DT_CHR");
    assert_eq!(devpts::entries(&[]).len(), 3, "no slaves: the dots and ptmx");
}

#[test]
fn pts_dirents_fill_the_buffer_and_go_on_from_the_offset() {
    let e = devpts::entries(&[0, 1, 2]);
    let (all, next) = devpts::dirents64(&e, 0, 4096);
    assert_eq!(next, 6);
    let r = records(&all);
    assert_eq!(r.len(), 6);
    assert_eq!(r[0], (1, 1, 4, ".".into()));
    assert_eq!(r[3], (3, 4, 2, "0".into()));
    assert_eq!(r[5].1, 6, "d_off: the next entry's index");
    // Two records' room: the first two, then the rest from there
    let (part, next) = devpts::dirents64(&e, 0, 48);
    assert_eq!(records(&part).len(), 2);
    assert_eq!(next, 2);
    let (rest, end) = devpts::dirents64(&e, next, 4096);
    assert_eq!(records(&rest).len(), 4);
    assert_eq!(end, 6);
    // Too small for one record: nothing (the caller answers EINVAL)
    let (none, at) = devpts::dirents64(&e, 0, 10);
    assert!(none.is_empty());
    assert_eq!(at, 0);
    // At the end: nothing more
    let (none, at) = devpts::dirents64(&e, 6, 4096);
    assert!(none.is_empty());
    assert_eq!(at, 6);
}

// ----------------------------------------------------------------------
// efivars unlinks
// ----------------------------------------------------------------------

#[test]
fn efivars_tail_starts_below_sys() {
    assert_eq!(served::efivars_tail(b"/sys/firmware/efi/efivars/Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c"), Some(5));
    assert_eq!(served::efivars_tail(b"firmware/efi/efivars/X-1"), Some(0));
    assert_eq!(served::efivars_tail(b"/a/sys/firmware/efi/efivars/X"), Some(7), "the last one counts");
    assert_eq!(served::efivars_tail(b"/sys/xfirmware/efi/efivars/X"), None, "a name that only ends like it");
    assert_eq!(served::efivars_tail(b"/sys/firmware/efi/X"), None);
    assert_eq!(served::efivars_tail(b"X-1"), None, "relative to the directory: the kernel's");
}

#[test]
fn the_efivars_directory_is_found_from_the_root() {
    let fs = Fake::new();
    let sys = fs.mkdir(ROOT, "sys", 0o755);
    let fw = fs.mkdir(sys, "firmware", 0o755);
    let efi = fs.mkdir(fw, "efi", 0o755);
    let vars = fs.mkdir(efi, "efivars", 0o755);
    let other = fs.mkdir(efi, "other", 0o755);
    let cx = Ctx::new(0, 0, 0, Node::new(0, ROOT));
    assert!(served::is_efivars_dir(&fs, &cx, Node::new(0, vars)));
    assert!(!served::is_efivars_dir(&fs, &cx, Node::new(0, other)));
    assert!(!served::is_efivars_dir(&fs, &cx, Node::new(0, efi)));
    // Another root (a chroot without /sys/firmware): never
    let cx2 = Ctx::new(0, 0, 0, Node::new(0, other));
    assert!(!served::is_efivars_dir(&fs, &cx2, Node::new(0, vars)));
}
