//! tmpfs: the tree, data through a fake store, limits, kept state.

use crate::mount::{seal, unseal};
use crate::tmpfs::*;
use std::collections::BTreeMap;

/// Data objects as byte vectors; counts creates and frees.
#[derive(Default)]
struct Store {
    objs: BTreeMap<u64, Vec<u8>>,
    next: u64,
    freed: Vec<u64>,
    fail_create: bool,
}

impl DataStore for Store {
    fn create(&mut self) -> Result<u64, i64> {
        if self.fail_create {
            return Err(-12);
        }
        self.next += 1;
        self.objs.insert(self.next, Vec::new());
        Ok(self.next)
    }
    fn write(&mut self, key: u64, off: u64, data: &[u8]) -> Result<(), i64> {
        let o = self.objs.get_mut(&key).ok_or(-9i64)?;
        let end = off as usize + data.len();
        if o.len() < end {
            o.resize(end, 0);
        }
        o[off as usize..end].copy_from_slice(data);
        Ok(())
    }
    fn read(&mut self, key: u64, off: u64, buf: &mut [u8]) -> Result<(), i64> {
        let o = self.objs.get(&key).ok_or(-9i64)?;
        for (i, b) in buf.iter_mut().enumerate() {
            *b = *o.get(off as usize + i).unwrap_or(&0);
        }
        Ok(())
    }
    fn truncate(&mut self, key: u64, size: u64, old: u64) -> Result<(), i64> {
        assert!(size < old);
        let o = self.objs.get_mut(&key).ok_or(-9i64)?;
        o.truncate(size as usize);
        Ok(())
    }
    fn free(&mut self, key: u64) {
        self.objs.remove(&key);
        self.freed.push(key);
    }
}

const T0: Ts = (100, 0);
const T1: Ts = (200, 5);
const MEM: u64 = 1 << 30;
const TMPF: u32 = 0x544d_5046;

fn fs() -> Tmpfs {
    Tmpfs::new(1, TmpfsOpts::parse("", 0, 0, MEM).unwrap(), T0)
}

fn names(t: &Tmpfs, dir: u64) -> Vec<String> {
    t.readdir(dir, 0, 1000).unwrap().into_iter().map(|e| String::from_utf8(e.name).unwrap()).collect()
}

#[test]
fn opts_defaults_and_parse() {
    let o = TmpfsOpts::parse("", 1000, 100, MEM).unwrap();
    assert_eq!((o.mode, o.uid, o.gid, o.size, o.nr_inodes), (0o1777, 1000, 100, MEM / 2, MEM / 4096 / 2));
    let o = TmpfsOpts::parse("size=10m,nr_inodes=1k,mode=755,uid=5,gid=6,huge=never", 0, 0, MEM).unwrap();
    assert_eq!((o.mode, o.uid, o.gid, o.size, o.nr_inodes), (0o755, 5, 6, 10 << 20, 1024));
    assert_eq!(TmpfsOpts::parse("size=50%", 0, 0, MEM).unwrap().size, MEM / 2);
    assert_eq!(TmpfsOpts::parse("size=1", 0, 0, MEM).unwrap().size, 4096, "rounded up to a page");
    assert_eq!(TmpfsOpts::parse("nr_blocks=3", 0, 0, MEM).unwrap().size, 3 * 4096);
    assert_eq!(TmpfsOpts::parse("size=1G", 0, 0, MEM).unwrap().size, 1 << 30);
    assert_eq!(TmpfsOpts::parse("size=0", 0, 0, MEM).unwrap().size, 0, "0: no limit");
    assert_eq!(TmpfsOpts::parse(" mode=700 , ,", 0, 0, MEM).unwrap().mode, 0o700);
    for bad in ["size=x", "size=0%", "size=101%", "mode=9", "uid=-1", "gid=a", "nr_inodes=1q", "size=99999999999999999g"] {
        assert_eq!(TmpfsOpts::parse(bad, 0, 0, MEM), Err(EINVAL), "{bad}");
    }
}

#[test]
fn opts_show() {
    let o = TmpfsOpts::parse("size=10m,nr_inodes=100,mode=700,uid=5,gid=6", 0, 0, MEM).unwrap();
    assert_eq!(o.show(), "size=10240k,nr_inodes=100,mode=700,uid=5,gid=6");
    let o = TmpfsOpts { mode: 0o1777, uid: 0, gid: 0, size: 0, nr_inodes: 0 };
    assert_eq!(o.show(), "mode=1777");
    let o = TmpfsOpts { mode: 0o755, uid: 0, gid: 0, size: 0, nr_inodes: 7 };
    assert_eq!(o.show(), "nr_inodes=7,mode=755");
}

#[test]
fn root_and_lookup() {
    let t = fs();
    let a = t.getattr(ROOT).unwrap();
    assert!(a.is_dir());
    assert_eq!((a.mode, a.nlink, a.ino, a.btime), (S_IFDIR | 0o1777, 2, 1, T0));
    assert_eq!(t.lookup(ROOT, b"."), Ok(ROOT));
    assert_eq!(t.lookup(ROOT, b".."), Ok(ROOT));
    assert_eq!(t.parent(ROOT), Ok(ROOT));
    assert_eq!(t.lookup(ROOT, b"x"), Err(ENOENT));
    assert_eq!(t.lookup(ROOT, &[b'a'; 256]), Err(ENAMETOOLONG));
    assert_eq!(t.lookup(99, b"x"), Err(ENOENT));
    assert_eq!(t.getattr(99), Err(ENOENT));
    assert_eq!(t.inodes(), 1);
}

#[test]
fn mknod_kinds() {
    let mut t = fs();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 1, 2, T1).unwrap();
    let a = t.getattr(f).unwrap();
    assert_eq!((a.mode, a.uid, a.gid, a.nlink, a.size, a.ctime), (S_IFREG | 0o644, 1, 2, 1, 0, T1));
    assert!(!a.is_dir());
    let c = t.mknod(ROOT, b"c", S_IFCHR | 0o600, 0x0103, 0, 0, T1).unwrap();
    assert_eq!(t.getattr(c).unwrap().rdev, 0x0103);
    let p = t.mknod(ROOT, b"p", S_IFIFO | 0o600, 7, 0, 0, T1).unwrap();
    assert_eq!(t.getattr(p).unwrap().rdev, 0, "only devices keep rdev");
    t.mknod(ROOT, b"s", S_IFSOCK | 0o600, 0, 0, 0, T1).unwrap();
    assert_eq!(t.mknod(ROOT, b"d", S_IFDIR | 0o600, 0, 0, 0, T1), Err(EPERM));
    assert_eq!(t.mknod(ROOT, b"l", S_IFLNK | 0o600, 0, 0, 0, T1), Err(EINVAL));
    assert_eq!(t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T1), Err(EEXIST));
    assert_eq!(t.mknod(ROOT, b".", 0o644, 0, 0, 0, T1), Err(EEXIST));
    assert_eq!(t.mknod(ROOT, b"", 0o644, 0, 0, 0, T1), Err(ENOENT));
    assert_eq!(t.mknod(ROOT, b"a/b", 0o644, 0, 0, 0, T1), Err(EINVAL));
    assert_eq!(t.mknod(ROOT, &[b'a'; 256], 0o644, 0, 0, 0, T1), Err(ENAMETOOLONG));
    t.mknod(ROOT, &[b'a'; 255], 0o644, 0, 0, 0, T1).unwrap();
    assert_eq!(t.mknod(f, b"x", 0o644, 0, 0, 0, T1), Err(ENOTDIR));
    assert_eq!(t.mknod(99, b"x", 0o644, 0, 0, 0, T1), Err(ENOENT));
    let r = t.getattr(ROOT).unwrap();
    assert_eq!((r.mtime, r.size), (T1, 5 * 20));
}

#[test]
fn mkdir_links_and_setgid() {
    let mut t = fs();
    let d = t.mkdir(ROOT, b"d", 0o2755, 5, 6, T1).unwrap();
    assert_eq!(t.getattr(ROOT).unwrap().nlink, 3);
    assert_eq!(t.getattr(d).unwrap().nlink, 2);
    assert_eq!(t.lookup(d, b".."), Ok(ROOT));
    // A set-group-ID directory gives its group, and the bit to subdirectories
    let f = t.mknod(d, b"f", 0o644, 0, 7, 8, T1).unwrap();
    assert_eq!(t.getattr(f).unwrap().gid, 6);
    assert_eq!(t.getattr(f).unwrap().mode & S_ISGID, 0);
    let s = t.mkdir(d, b"s", 0o755, 7, 8, T1).unwrap();
    let a = t.getattr(s).unwrap();
    assert_eq!((a.gid, a.mode & S_ISGID), (6, S_ISGID));
    assert_eq!(t.mkdir(ROOT, b"d", 0o755, 0, 0, T1), Err(EEXIST));
    assert_eq!(t.mkdir(99, b"d", 0o755, 0, 0, T1), Err(ENOENT));
}

#[test]
fn symlink_and_readlink() {
    let mut t = fs();
    let l = t.symlink(ROOT, b"l", b"/etc/passwd", 3, 4, T1).unwrap();
    let a = t.getattr(l).unwrap();
    assert_eq!((a.mode, a.size, a.blocks), (S_IFLNK | 0o777, 11, 0));
    assert_eq!(t.readlink(l).unwrap(), b"/etc/passwd");
    assert_eq!(t.readlink(ROOT), Err(EINVAL));
    assert_eq!(t.readlink(99), Err(ENOENT));
    assert_eq!(t.symlink(ROOT, b"e", b"", 0, 0, T1), Err(ENOENT));
    assert_eq!(t.symlink(ROOT, b"e", &[b'x'; 4096], 0, 0, T1), Err(ENAMETOOLONG));
    assert_eq!(t.read(l, 0, 1, &mut Store::default()), Err(EINVAL));
}

#[test]
fn hard_links_and_unlink() {
    let mut t = fs();
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"a", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, b"hello", &mut s, T0).unwrap();
    let d = t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    t.link(f, d, b"b", T1).unwrap();
    assert_eq!(t.getattr(f).unwrap().nlink, 2);
    assert_eq!(t.getattr(f).unwrap().ctime, T1);
    assert_eq!(t.link(d, ROOT, b"x", T1), Err(EPERM));
    assert_eq!(t.link(f, ROOT, b"a", T1), Err(EEXIST));
    assert_eq!(t.link(f, ROOT, b"..", T1), Err(EEXIST));
    assert_eq!(t.link(f, ROOT, b"", T1), Err(ENOENT));
    assert_eq!(t.link(f, f, b"x", T1), Err(ENOTDIR));
    assert_eq!(t.link(99, ROOT, b"x", T1), Err(ENOENT));
    t.unlink(ROOT, b"a", &mut s, T1).unwrap();
    assert_eq!(t.getattr(f).unwrap().nlink, 1);
    assert!(s.freed.is_empty());
    assert_eq!(t.unlink(ROOT, b"d", &mut s, T1), Err(EISDIR));
    assert_eq!(t.unlink(ROOT, b".", &mut s, T1), Err(EISDIR));
    assert_eq!(t.unlink(ROOT, b"zz", &mut s, T1), Err(ENOENT));
    t.unlink(d, b"b", &mut s, T1).unwrap();
    assert_eq!(t.getattr(f), Err(ENOENT));
    assert_eq!(s.freed, vec![1]);
    assert_eq!(t.statfs().bfree, t.statfs().blocks, "pages given back");
}

#[test]
fn open_files_outlive_unlink() {
    let mut t = fs();
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"a", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, b"data", &mut s, T0).unwrap();
    t.open(f).unwrap();
    t.open(f).unwrap();
    assert!(t.has_open());
    t.unlink(ROOT, b"a", &mut s, T1).unwrap();
    assert_eq!(t.getattr(f).unwrap().nlink, 0);
    assert_eq!(t.read(f, 0, 10, &mut s).unwrap(), b"data");
    assert_eq!(t.link(f, ROOT, b"again", T1), Err(ENOENT));
    t.release(f, &mut s);
    assert!(t.getattr(f).is_ok());
    t.release(f, &mut s);
    assert_eq!(t.getattr(f), Err(ENOENT));
    assert!(!t.has_open());
    assert_eq!(t.open(f), Err(ENOENT));
    t.release(f, &mut s); // a stale release does nothing
    t.release(ROOT, &mut s); // nor does one of the root
    assert!(t.getattr(ROOT).is_ok());
}

#[test]
fn rmdir_rules() {
    let mut t = fs();
    let mut s = Store::default();
    let d = t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    t.mknod(d, b"f", 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.rmdir(ROOT, b"d", &mut s, T1), Err(ENOTEMPTY));
    assert_eq!(t.rmdir(d, b"f", &mut s, T1), Err(ENOTDIR));
    assert_eq!(t.rmdir(ROOT, b".", &mut s, T1), Err(EINVAL));
    assert_eq!(t.rmdir(ROOT, b"..", &mut s, T1), Err(ENOTEMPTY));
    assert_eq!(t.rmdir(ROOT, b"zz", &mut s, T1), Err(ENOENT));
    t.unlink(d, b"f", &mut s, T1).unwrap();
    t.open(d).unwrap();
    t.rmdir(ROOT, b"d", &mut s, T1).unwrap();
    assert_eq!(t.getattr(ROOT).unwrap().nlink, 2);
    // An open removed directory: nothing can be made in it
    assert_eq!(t.getattr(d).unwrap().nlink, 0);
    assert_eq!(t.mknod(d, b"x", 0o644, 0, 0, 0, T1), Err(ENOENT));
    assert_eq!(t.readdir(d, 0, 10).unwrap().len(), 2);
    t.release(d, &mut s);
    assert_eq!(t.getattr(d), Err(ENOENT));
}

#[test]
fn readdir_cookies_are_stable() {
    let mut t = fs();
    let mut s = Store::default();
    for n in ["c", "a", "b"] {
        t.mknod(ROOT, n.as_bytes(), 0o644, 0, 0, 0, T0).unwrap();
    }
    let d = t.mkdir(ROOT, b"dir", 0o755, 0, 0, T0).unwrap();
    assert_eq!(names(&t, ROOT), [".", "..", "c", "a", "b", "dir"], "creation order");
    let all = t.readdir(ROOT, 0, 100).unwrap();
    assert_eq!(all[5].dtype, 4);
    assert_eq!(all[2].dtype, 8);
    assert_eq!(all[5].ino, d);
    // Three, then remove one already listed and add one, then the rest
    let first = t.readdir(ROOT, 0, 3).unwrap();
    assert_eq!(first.len(), 3);
    t.unlink(ROOT, b"c", &mut s, T1).unwrap();
    t.mknod(ROOT, b"z", 0o644, 0, 0, 0, T1).unwrap();
    let rest = t.readdir(ROOT, first[2].next, 100).unwrap();
    let rest: Vec<_> = rest.iter().map(|e| String::from_utf8(e.name.clone()).unwrap()).collect();
    assert_eq!(rest, ["a", "b", "dir", "z"]);
    assert_eq!(t.readdir(ROOT, 1, 1).unwrap()[0].name, b"..");
    assert!(t.readdir(ROOT, 1000, 10).unwrap().is_empty());
    assert_eq!(t.readdir(ROOT, 0, 0).unwrap().len(), 0);
    let f = t.lookup(ROOT, b"a").unwrap();
    assert_eq!(t.readdir(f, 0, 10), Err(ENOTDIR));
    assert_eq!(t.readdir(d, 0, 10).unwrap()[1].ino, ROOT);
}

#[test]
fn write_read_truncate() {
    let mut t = fs();
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.read(f, 0, 10, &mut s).unwrap(), b"");
    assert!(s.objs.is_empty(), "no object before data");
    assert_eq!(t.write(f, 0, b"", &mut s, T1), Ok(0));
    assert_eq!(t.write(f, 10, b"xy", &mut s, T1), Ok(2));
    let a = t.getattr(f).unwrap();
    assert_eq!((a.size, a.blocks, a.mtime), (12, 8, T1));
    assert_eq!(t.read(f, 0, 100, &mut s).unwrap(), b"\0\0\0\0\0\0\0\0\0\0xy");
    assert_eq!(t.read(f, 11, 100, &mut s).unwrap(), b"y");
    assert_eq!(t.read(f, 12, 100, &mut s).unwrap(), b"");
    t.truncate(f, 11, &mut s, T1).unwrap();
    t.truncate(f, 20, &mut s, T1).unwrap();
    assert_eq!(&t.read(f, 8, 100, &mut s).unwrap(), b"\0\0x\0\0\0\0\0\0\0\0\0", "truncated bytes come back as zeros");
    // Truncating a file with no data makes no object
    let g = t.mknod(ROOT, b"g", 0o644, 0, 0, 0, T0).unwrap();
    t.truncate(g, 5000, &mut s, T1).unwrap();
    assert_eq!(t.getattr(g).unwrap().blocks, 16);
    assert_eq!(t.read(g, 4990, 100, &mut s).unwrap(), vec![0u8; 10]);
    t.truncate(g, 0, &mut s, T1).unwrap();
    assert_eq!(s.objs.len(), 1);
    assert_eq!(t.truncate(ROOT, 0, &mut s, T1), Err(EISDIR));
    assert_eq!(t.write(ROOT, 0, b"x", &mut s, T1), Err(EISDIR));
    assert_eq!(t.read(ROOT, 0, 1, &mut s), Err(EISDIR));
    let l = t.symlink(ROOT, b"l", b"x", 0, 0, T0).unwrap();
    assert_eq!(t.write(l, 0, b"x", &mut s, T1), Err(EINVAL));
    assert_eq!(t.truncate(l, 0, &mut s, T1), Err(EINVAL));
    assert_eq!(t.truncate(f, MAX_FILE + 1, &mut s, T1), Err(EFBIG));
    assert_eq!(t.write(f, MAX_FILE, b"x", &mut s, T1), Err(EFBIG));
    assert_eq!(t.write(f, u64::MAX, b"x", &mut s, T1), Err(EFBIG));
    assert_eq!(t.write(99, 0, b"x", &mut s, T1), Err(ENOENT));
    // A store that cannot make objects
    let h = t.mknod(ROOT, b"h", 0o644, 0, 0, 0, T0).unwrap();
    s.fail_create = true;
    assert_eq!(t.write(h, 0, b"x", &mut s, T1), Err(-12));
    assert_eq!(t.getattr(h).unwrap().size, 0);
    t.check().unwrap();
}

#[test]
fn data_key_for_handles() {
    let mut t = fs();
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    let k = t.data_key(f, &mut s).unwrap();
    assert_eq!(t.data_key(f, &mut s), Ok(k));
    t.write(f, 0, b"q", &mut s, T0).unwrap();
    assert_eq!(s.objs[&k], b"q");
    assert_eq!(t.data_key(ROOT, &mut s), Err(EINVAL));
}

#[test]
fn size_limit_enospc() {
    let mut t = Tmpfs::new(1, TmpfsOpts::parse("size=8k,nr_inodes=4", 0, 0, MEM).unwrap(), T0);
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, &[1u8; 4096], &mut s, T1).unwrap();
    t.write(f, 4096, &[1u8; 4096], &mut s, T1).unwrap();
    assert_eq!(t.write(f, 8192, b"x", &mut s, T1), Err(ENOSPC));
    assert_eq!(t.getattr(f).unwrap().size, 8192);
    t.write(f, 100, b"overwrite fits", &mut s, T1).unwrap();
    let g = t.mknod(ROOT, b"g", 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.truncate(g, 1, &mut s, T1), Err(ENOSPC));
    let st = t.statfs();
    assert_eq!((st.bsize, st.blocks, st.bfree, st.files, st.ffree, st.namelen), (4096, 2, 0, 4, 1, 255));
    t.truncate(f, 4096, &mut s, T1).unwrap();
    t.truncate(g, 4096, &mut s, T1).unwrap();
    // nr_inodes: root, f, g, and one more
    t.mkdir(ROOT, b"d", 0o755, 0, 0, T1).unwrap();
    assert_eq!(t.mknod(ROOT, b"e", 0o644, 0, 0, 0, T1), Err(ENOSPC));
    // A hard link and a rename take no inode
    t.link(f, ROOT, b"f2", T1).unwrap();
    t.rename(ROOT, b"f2", ROOT, b"f3", 0, &mut s, T1).unwrap();
    t.check().unwrap();
}

#[test]
fn setattr_changes() {
    let mut t = fs();
    let mut s = Store::default();
    let f = t.mknod(ROOT, b"f", 0o4755, 0, 0, 0, T0).unwrap();
    let a = t.setattr(f, &SetAttr { mode: Some(S_IFDIR | 0o600), uid: Some(9), gid: Some(8), ..Default::default() }, &mut s, T1).unwrap();
    assert_eq!((a.mode, a.uid, a.gid, a.ctime, a.mtime), (S_IFREG | 0o600, 9, 8, T1, T0));
    let a = t.setattr(f, &SetAttr { atime: Some((1, 2)), mtime: Some((3, 4)), size: Some(10), ..Default::default() }, &mut s, (300, 0)).unwrap();
    assert_eq!((a.atime, a.mtime, a.size, a.ctime), ((1, 2), (3, 4), 10, (300, 0)));
    assert_eq!(t.setattr(99, &SetAttr::default(), &mut s, T1), Err(ENOENT));
    assert_eq!(t.setattr(ROOT, &SetAttr { size: Some(1), ..Default::default() }, &mut s, T1), Err(EISDIR));
}

#[test]
fn rename_plain_and_over() {
    let mut t = fs();
    let mut s = Store::default();
    let a = t.mknod(ROOT, b"a", 0o644, 0, 0, 0, T0).unwrap();
    let b = t.mknod(ROOT, b"b", 0o644, 0, 0, 0, T0).unwrap();
    t.write(b, 0, b"old", &mut s, T0).unwrap();
    t.rename(ROOT, b"a", ROOT, b"c", 0, &mut s, T1).unwrap();
    assert_eq!(t.lookup(ROOT, b"c"), Ok(a));
    assert_eq!(t.lookup(ROOT, b"a"), Err(ENOENT));
    assert_eq!(t.getattr(a).unwrap().ctime, T1);
    assert_eq!(t.rename(ROOT, b"c", ROOT, b"b", RENAME_NOREPLACE, &mut s, T1), Err(EEXIST));
    t.rename(ROOT, b"c", ROOT, b"b", 0, &mut s, T1).unwrap();
    assert_eq!(t.lookup(ROOT, b"b"), Ok(a));
    assert_eq!(t.getattr(b), Err(ENOENT), "replaced file freed");
    assert_eq!(s.freed.len(), 1);
    assert_eq!(names(&t, ROOT), [".", "..", "b"]);
    // Two names of one file: nothing happens
    t.link(a, ROOT, b"h", T1).unwrap();
    t.rename(ROOT, b"b", ROOT, b"h", 0, &mut s, T1).unwrap();
    assert_eq!(names(&t, ROOT), [".", "..", "b", "h"]);
    // Itself
    t.rename(ROOT, b"b", ROOT, b"b", 0, &mut s, T1).unwrap();
    assert_eq!(t.rename(ROOT, b"zz", ROOT, b"y", 0, &mut s, T1), Err(ENOENT));
    assert_eq!(t.rename(ROOT, b".", ROOT, b"y", 0, &mut s, T1), Err(EBUSY));
    assert_eq!(t.rename(ROOT, b"b", ROOT, b"..", 0, &mut s, T1), Err(EBUSY));
    assert_eq!(t.rename(ROOT, b"b", ROOT, b"y", RENAME_WHITEOUT, &mut s, T1), Err(EINVAL));
    assert_eq!(t.rename(ROOT, b"b", ROOT, b"y", RENAME_NOREPLACE | RENAME_EXCHANGE, &mut s, T1), Err(EINVAL));
    assert_eq!(t.rename(ROOT, b"b", ROOT, b"y", 8, &mut s, T1), Err(EINVAL));
    assert_eq!(t.rename(ROOT, b"b", a, b"y", 0, &mut s, T1), Err(ENOTDIR));
    assert_eq!(t.rename(ROOT, b"b", ROOT, b"a/b", 0, &mut s, T1), Err(EINVAL));
    t.check().unwrap();
}

#[test]
fn rename_into_removed_directory() {
    let mut t = fs();
    let mut s = Store::default();
    let d = t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.open(d).unwrap();
    t.rmdir(ROOT, b"d", &mut s, T1).unwrap();
    assert_eq!(t.rename(ROOT, b"f", d, b"f", 0, &mut s, T1), Err(ENOENT));
}

#[test]
fn rename_directories() {
    let mut t = fs();
    let mut s = Store::default();
    let d1 = t.mkdir(ROOT, b"d1", 0o755, 0, 0, T0).unwrap();
    let d2 = t.mkdir(ROOT, b"d2", 0o755, 0, 0, T0).unwrap();
    let sub = t.mkdir(d1, b"sub", 0o755, 0, 0, T0).unwrap();
    t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    // Into itself
    assert_eq!(t.rename(ROOT, b"d1", sub, b"x", 0, &mut s, T1), Err(EINVAL));
    assert_eq!(t.rename(ROOT, b"d1", d1, b"x", 0, &mut s, T1), Err(EINVAL));
    // Kinds
    assert_eq!(t.rename(ROOT, b"d1", ROOT, b"f", 0, &mut s, T1), Err(ENOTDIR));
    assert_eq!(t.rename(ROOT, b"f", ROOT, b"d1", 0, &mut s, T1), Err(EISDIR));
    assert_eq!(t.rename(ROOT, b"d2", ROOT, b"d1", 0, &mut s, T1), Err(ENOTEMPTY));
    // Over a directory below itself
    let deep = t.mkdir(sub, b"deep", 0o755, 0, 0, T0).unwrap();
    assert_eq!(t.rename(ROOT, b"d1", sub, b"deep", 0, &mut s, T1), Err(EINVAL));
    t.rmdir(sub, b"deep", &mut s, T1).unwrap();
    let _ = deep;
    // Move sub from d1 to d2: link counts and ..
    t.rename(d1, b"sub", d2, b"sub", 0, &mut s, T1).unwrap();
    assert_eq!(t.lookup(sub, b".."), Ok(d2));
    assert_eq!((t.getattr(d1).unwrap().nlink, t.getattr(d2).unwrap().nlink), (2, 3));
    // Over an empty directory
    t.rename(ROOT, b"d2", ROOT, b"d1", 0, &mut s, T1).unwrap();
    assert_eq!(t.getattr(d1), Err(ENOENT));
    assert_eq!(t.lookup(ROOT, b"d1"), Ok(d2));
    assert_eq!(t.getattr(ROOT).unwrap().nlink, 3);
    t.check().unwrap();
}

#[test]
fn rename_exchange() {
    let mut t = fs();
    let mut s = Store::default();
    let d = t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    let e = t.mkdir(d, b"e", 0o755, 0, 0, T0).unwrap();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.rename(ROOT, b"f", ROOT, b"none", RENAME_EXCHANGE, &mut s, T1), Err(ENOENT));
    // File <-> directory across parents
    t.rename(ROOT, b"f", d, b"e", RENAME_EXCHANGE, &mut s, T1).unwrap();
    assert_eq!(t.lookup(ROOT, b"f"), Ok(e));
    assert_eq!(t.lookup(d, b"e"), Ok(f));
    assert_eq!(t.lookup(e, b".."), Ok(ROOT));
    assert_eq!((t.getattr(ROOT).unwrap().nlink, t.getattr(d).unwrap().nlink), (4, 2));
    // Two directories across parents
    let x = t.mkdir(d, b"x", 0o755, 0, 0, T0).unwrap();
    t.rename(ROOT, b"f", d, b"x", RENAME_EXCHANGE, &mut s, T1).unwrap();
    assert_eq!((t.lookup(x, b".."), t.lookup(e, b"..")), (Ok(ROOT), Ok(d)));
    t.check().unwrap();
    // A directory with its own child: refused
    t.mkdir(x, b"g", 0o755, 0, 0, T0).unwrap();
    assert_eq!(t.rename(ROOT, b"f", x, b"g", RENAME_EXCHANGE, &mut s, T1), Err(EINVAL));
    assert_eq!(t.rename(x, b"g", ROOT, b"f", RENAME_EXCHANGE, &mut s, T1), Err(EINVAL));
    t.rename(ROOT, b"f", ROOT, b"f", RENAME_EXCHANGE, &mut s, T1).unwrap();
    t.check().unwrap();
}

#[test]
fn xattrs() {
    let mut t = fs();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    let p = t.mknod(ROOT, b"p", S_IFIFO | 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.getxattr(f, b"user.a"), Err(ENODATA));
    t.setxattr(f, b"user.a", b"1", 0, T1).unwrap();
    assert_eq!(t.getattr(f).unwrap().ctime, T1);
    t.setxattr(f, b"trusted.b", b"22", XATTR_CREATE, T1).unwrap();
    assert_eq!(t.setxattr(f, b"user.a", b"x", XATTR_CREATE, T1), Err(EEXIST));
    assert_eq!(t.setxattr(f, b"user.z", b"x", XATTR_REPLACE, T1), Err(ENODATA));
    t.setxattr(f, b"user.a", b"333", XATTR_REPLACE, T1).unwrap();
    assert_eq!(t.getxattr(f, b"user.a").unwrap(), b"333");
    assert_eq!(t.listxattr(f).unwrap(), b"trusted.b\0user.a\0");
    assert_eq!(t.setxattr(f, b"system.x", b"", 0, T1), Err(EOPNOTSUPP));
    assert_eq!(t.setxattr(f, b"", b"", 0, T1), Err(ERANGE));
    assert_eq!(t.setxattr(f, b"user.big", &vec![0u8; 65537], 0, T1), Err(ERANGE));
    assert_eq!(t.setxattr(f, b"user.big", &vec![0u8; 65530], 0, T1), Err(ENOSPC));
    assert_eq!(t.setxattr(p, b"user.a", b"", 0, T1), Err(EPERM));
    t.setxattr(p, b"security.selinux", b"x", 0, T1).unwrap();
    t.removexattr(f, b"user.a", T1).unwrap();
    assert_eq!(t.removexattr(f, b"user.a", T1), Err(ENODATA));
    assert_eq!(t.getxattr(99, b"user.a"), Err(ENOENT));
    assert_eq!(t.listxattr(99), Err(ENOENT));
}

#[test]
fn link_count_limit() {
    let mut t = fs();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    for i in 1..LINK_MAX {
        t.link(f, ROOT, format!("l{i}").as_bytes(), T0).unwrap();
    }
    assert_eq!(t.link(f, ROOT, b"one-more", T0), Err(EMLINK));
}

#[test]
fn kept_state_round_trip() {
    let mut t = fs();
    let mut s = Store::default();
    let d = t.mkdir(ROOT, b"d", 0o2755, 3, 4, T0).unwrap();
    let f = t.mknod(d, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, b"abc", &mut s, T1).unwrap();
    t.symlink(ROOT, b"l", b"d/f", 0, 0, T1).unwrap();
    t.mknod(ROOT, b"c", S_IFCHR | 0o600, 0x501, 0, 0, T1).unwrap();
    t.setxattr(f, b"user.k", b"v", 0, T1).unwrap();
    t.open(f).unwrap();
    t.unlink(ROOT, b"c", &mut s, T1).unwrap();
    let bytes = t.encode();
    let back = Tmpfs::decode(&bytes).unwrap();
    assert_eq!(back, t);
    // The data stays in the store: the restored tree reads it
    assert_eq!(back.read(f, 0, 10, &mut s).unwrap(), b"abc");
    // A page-sized kept object has trailing zeros
    let mut padded = bytes.clone();
    padded.resize(bytes.len() + 4096, 0);
    assert_eq!(Tmpfs::decode(&padded).unwrap(), t);
    // Damage anywhere is caught
    for i in [0, 5, 20, 30, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[i] ^= 0x40;
        assert_eq!(Tmpfs::decode(&bad), Err(EINVAL), "byte {i}");
    }
    assert_eq!(Tmpfs::decode(&bytes[..bytes.len() - 1]), Err(EINVAL));
    assert_eq!(Tmpfs::decode(&[]), Err(EINVAL));
}

/// Changes the body of a sealed tree and seals it again (so only `check` can object).
fn reseal(bytes: &[u8], f: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = unseal(TMPF, 1, bytes).unwrap().to_vec();
    f(&mut body);
    seal(TMPF, 1, &body)
}

#[test]
fn check_finds_damage_behind_a_good_checksum() {
    let mut t = fs();
    let mut s = Store::default();
    let d = t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    let f = t.mknod(d, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, b"x", &mut s, T0).unwrap();
    let bytes = t.encode();
    assert_eq!(Tmpfs::decode(&reseal(&bytes, |_| {})).unwrap(), t);
    // Header: id, mode, uid, gid (4 each), size, nr_inodes, next_ino, used_pages (8 each)
    let used = reseal(&bytes, |b| b[40] = 9);
    assert_eq!(Tmpfs::decode(&used), Err(EINVAL), "page count");
    let next = reseal(&bytes, |b| b[32] = 2);
    assert_eq!(Tmpfs::decode(&next), Err(EINVAL), "inode numbers above next_ino");
    let trailing = reseal(&bytes, |b| b.push(0));
    assert_eq!(Tmpfs::decode(&trailing), Err(EINVAL), "bytes after the tree");
    let count = reseal(&bytes, |b| b[48..56].copy_from_slice(&u64::MAX.to_le_bytes()));
    assert_eq!(Tmpfs::decode(&count), Err(EINVAL), "absurd count");
    // The root's kind byte (after node count 8 and its inode 8): not a directory
    let root_kind = reseal(&bytes, |b| b[64] = 3);
    assert!(Tmpfs::decode(&root_kind).is_err());
    let bad_kind = reseal(&bytes, |b| b[64] = 9);
    assert_eq!(Tmpfs::decode(&bad_kind), Err(EINVAL));
}

#[test]
fn set_create_reap_and_kept() {
    let mut set = TmpfsSet::new();
    let mut s = Store::default();
    let (a, root) = set.create("size=1m", 5, 6, MEM, T0).unwrap();
    let (b, _) = set.create("", 0, 0, MEM, T0).unwrap();
    assert_eq!((a, b, root), (1, 2, ROOT));
    assert_eq!(set.create("size=bad", 0, 0, MEM, T0), Err(EINVAL));
    assert_eq!(set.get(a).unwrap().getattr(ROOT).unwrap().uid, 5);
    let t = set.get_mut(b).unwrap();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.write(f, 0, b"x", &mut s, T0).unwrap();
    t.open(f).unwrap();
    let kept = set.encode();
    assert_eq!(TmpfsSet::decode(&kept).unwrap(), set);
    let mut bad = kept.clone();
    bad[30] ^= 1;
    assert_eq!(TmpfsSet::decode(&bad), Err(EINVAL));
    // Nothing mounted: a goes now, b waits for its open file
    assert_eq!(set.reap(&|_| false, &mut s), vec![a]);
    assert!(set.get(b).is_some());
    set.get_mut(b).unwrap().release(f, &mut s);
    assert_eq!(s.freed.len(), 0, "f is still linked");
    assert_eq!(set.reap(&|n| n == 7, &mut s), vec![b]);
    assert_eq!(s.freed.len(), 1, "destroy frees the data");
    assert!(set.all.is_empty());
    let (c, _) = set.create("", 0, 0, MEM, T0).unwrap();
    assert_eq!(c, 3, "instance numbers are not reused");
    assert_eq!(set.reap(&|_| true, &mut s), Vec::<u32>::new());
}

#[test]
fn review_fixes() {
    let mut t = fs();
    let mut s = Store::default();
    // A huge size= is refused, not wrapped to "no limit"
    assert_eq!(TmpfsOpts::parse("size=18446744073709551615", 0, 0, MEM), Err(EINVAL));
    // No link into a removed (still open) directory
    let p = t.mkdir(ROOT, b"p", 0o755, 0, 0, T0).unwrap();
    let d = t.mkdir(p, b"d", 0o755, 0, 0, T0).unwrap();
    let f = t.mknod(ROOT, b"f", 0o644, 0, 0, 0, T0).unwrap();
    t.open(d).unwrap();
    t.rmdir(p, b"d", &mut s, T1).unwrap();
    assert_eq!(t.link(f, d, b"x", T1), Err(ENOENT));
    // Its parent removed too: `..` is gone
    assert_eq!(t.lookup(d, b".."), Ok(p));
    t.rmdir(ROOT, b"p", &mut s, T1).unwrap();
    assert_eq!(t.lookup(d, b".."), Err(ENOENT));
    assert_eq!(t.lookup(d, b"."), Ok(d));
    t.release(d, &mut s);
    // Stray mode bits are not kept
    let q = t.mknod(ROOT, b"q", 0o1000000 | S_IFIFO | 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.getattr(q).unwrap().mode, S_IFIFO | 0o644);
    // Missing directories are ENOENT, files ENOTDIR
    assert_eq!(t.rename(99, b"f", ROOT, b"g", 0, &mut s, T1), Err(ENOENT));
    assert_eq!(t.rename(ROOT, b"f", 99, b"g", 0, &mut s, T1), Err(ENOENT));
    assert_eq!(t.rename(ROOT, b"f", f, b"g", 0, &mut s, T1), Err(ENOTDIR));
    t.check().unwrap();
}

#[test]
fn directory_link_limit_on_rename() {
    let mut t = Tmpfs::new(1, TmpfsOpts { mode: 0o755, uid: 0, gid: 0, size: 0, nr_inodes: 0 }, T0);
    let mut s = Store::default();
    let full = t.mkdir(ROOT, b"full", 0o755, 0, 0, T0).unwrap();
    for i in 0..(LINK_MAX - 2) {
        t.mkdir(full, format!("{i}").as_bytes(), 0o755, 0, 0, T0).unwrap();
    }
    assert_eq!(t.getattr(full).unwrap().nlink, LINK_MAX);
    assert_eq!(t.mkdir(full, b"one-more", 0o755, 0, 0, T0), Err(EMLINK));
    t.mkdir(ROOT, b"d", 0o755, 0, 0, T0).unwrap();
    assert_eq!(t.rename(ROOT, b"d", full, b"d", 0, &mut s, T1), Err(EMLINK));
    // Exchanging a directory for a file across parents also adds a link
    t.mknod(full, b"file", 0o644, 0, 0, 0, T0).unwrap();
    assert_eq!(t.rename(ROOT, b"d", full, b"file", RENAME_EXCHANGE, &mut s, T1), Err(EMLINK));
    assert_eq!(t.rename(full, b"file", ROOT, b"d", RENAME_EXCHANGE, &mut s, T1), Err(EMLINK));
    // Within one directory nothing changes in the counts
    t.mknod(ROOT, b"g", 0o644, 0, 0, 0, T0).unwrap();
    t.rename(ROOT, b"d", ROOT, b"g", RENAME_EXCHANGE, &mut s, T1).unwrap();
    t.check().unwrap();
}
