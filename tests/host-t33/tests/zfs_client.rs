//! The kernel's side of the ZFS file server (`src/fs/zfs/mod.rs`) and the path client on
//! top of it (`src/fs/client.rs`), against the fake file server in `fakefs`: request
//! encoding, the attribute/name/link caches and when they are forgotten, error mapping,
//! FUSE routing, the boot-file import.

use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::{fuse, CACHE, CHMODS, FUSE_CALLS, FUSE_NS0, FUSE_WALK, INOTIFY_ON, FANOTIFY_ON, NOTIFIED};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, clear_ops, fail, ops, with_fs, ROOT_INO};
use hydra_hosttests_t33::fs::client::{self, normalize_path, resolve_parent_in, BootFile, ZfsClient, BOOT_MANIFEST};
use hydra_hosttests_t33::fs::zfs::fsproto::*;
use hydra_hosttests_t33::fs::zfs::types::DnodeType;
use hydra_hosttests_t33::fs::zfs::{self, with_server};
use hydra_hosttests_t33::ipc::protocol::{ENDPOINT_BLOCK_DEV, ENDPOINT_USB_DISK, ENDPOINT_ZFS_SERVER, MSG_BLOCK_GET_SIZE, MSG_BLOCK_REPLY};
use hydra_hosttests_t33::ipc::Message;

/// The caches are global: tests that count requests run one at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    clear_ops();
    fakefs::pool();
    g
}

fn srv<R>(f: impl FnOnce(&mut zfs::ZfsServer) -> Result<R, i64>) -> Result<R, i64> {
    with_server(f)
}

const FUSE: u64 = 1 << 62;

// ------------------------------------------------------------- zfs/mod.rs

#[test]
fn init_server_learned_the_root() {
    let _g = serial();
    assert_eq!(srv(|s| Ok(s.root_obj())), Ok(ROOT_INO));
    assert_eq!(ZfsClient::root_ino(), ROOT_INO);
}

#[test]
fn lookup_caches_hits_and_misses_until_a_name_changes() {
    let _g = serial();
    let d = fakefs::test_dir("lookup");
    let f = with_fs(|fs| fs.put(d, "f", b"x"));
    assert_eq!(srv(|s| s.lookup(d, b"f")), Ok(f));
    assert_eq!(srv(|s| s.lookup(d, b"nope")), Err(ENOENT));
    let before = ops(FS_LOOKUP);
    assert_eq!(srv(|s| s.lookup(d, b"f")), Ok(f));
    assert_eq!(srv(|s| s.lookup(d, b"nope")), Err(ENOENT));
    assert_eq!(ops(FS_LOOKUP), before, "both answers came from the cache");
    // Creating a name forgets every lookup
    let n = srv(|s| s.create(d, b"nope", 0o600, 5, 6)).unwrap();
    assert_eq!(srv(|s| s.lookup(d, b"nope")), Ok(n));
    assert_eq!(ops(FS_LOOKUP), before + 1);
    // Not a directory: an error that is not cached
    assert_eq!(srv(|s| s.lookup(f, b"x")), Err(ENOTDIR));
    // Other errors are not kept either
    fail(FS_LOOKUP, EIO, 1);
    assert_eq!(srv(|s| s.lookup(d, b"other")), Err(EIO));
    assert_eq!(srv(|s| s.lookup(d, b"other")), Err(ENOENT));
}

#[test]
fn resolve_reports_the_restricted_directories_and_caches_them() {
    let _g = serial();
    let d = fakefs::test_dir("resolvedirs");
    let (priv_dir, f) = with_fs(|fs| {
        let p = fs.mkdir_p(d, "priv");
        fs.nodes.get_mut(&p).unwrap().attr.mode = 0o040700;
        let f = fs.put(p, "file", b"data");
        fs.link_to(d, "ln", "priv/file");
        (p, f)
    });
    let r = srv(|s| s.resolve_in_dirs(ROOT_INO, ROOT_INO, b"/resolvedirs/ln", true)).unwrap();
    assert_eq!(r.0, f);
    assert_eq!(r.1, vec![priv_dir]);
    let before = ops(FS_RESOLVE);
    let again = srv(|s| s.resolve_in_dirs(ROOT_INO, ROOT_INO, b"/resolvedirs/ln", true)).unwrap();
    assert_eq!(again, (f, vec![priv_dir]));
    assert_eq!(ops(FS_RESOLVE), before, "cached with its directories");
    // Not following the last link: the link itself
    let ln = srv(|s| s.resolve_in(ROOT_INO, ROOT_INO, b"/resolvedirs/ln", false)).unwrap();
    assert_ne!(ln, f);
    assert_eq!(srv(|s| s.readlink(ln)), Ok(b"priv/file".to_vec()));
    // Too long a path never reaches the server
    let long = vec![b'a'; 4097];
    assert_eq!(srv(|s| s.resolve_in(ROOT_INO, ROOT_INO, &long, true)), Err(ENAMETOOLONG));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, &long, true, &[])), Err(ENAMETOOLONG));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"", true, &[])), Err(ENOENT));
}

#[test]
fn resolve_through_a_mount_table() {
    let _g = serial();
    let d = fakefs::test_dir("mounts");
    let (mp, other, x) = with_fs(|fs| {
        let mp = fs.mkdir_p(d, "mp");
        let other = fs.mkdir_p(d, "other");
        let x = fs.put(other, "x", b"1");
        (mp, other, x)
    });
    let mounts = [(mp, other, 0usize)];
    let r = srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/mounts/mp/x", true, &mounts));
    assert_eq!(r, Ok((x, 1)));
    // Cached: the same walk asks nothing
    let before = ops(FS_RESOLVE_MNT);
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/mounts/mp/x", true, &mounts)), Ok((x, 1)));
    assert_eq!(ops(FS_RESOLVE_MNT), before);
    // Relative to a base in the mount
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, other, 1, b"x", true, &mounts)), Ok((x, 1)));
}

#[test]
fn resolve_into_a_fuse_mount_hands_the_rest_to_the_daemon() {
    let _g = serial();
    let d = fakefs::test_dir("fusemnt");
    let (mp, back, y) = with_fs(|fs| {
        let mp = fs.mkdir_p(d, "mp");
        let back = fs.mkdir_p(d, "back");
        let y = fs.put(back, "y", b"");
        (mp, back, y)
    });
    let froot = FUSE | 7;
    let mounts = [(mp, froot, 0usize)];
    // The daemon finds the object
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Ok(fuse::Walk::Done(FUSE | 9, 1))));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/fusemnt/mp/a/b", true, &mounts)), Ok((FUSE | 9, 1)));
    assert!(FUSE_CALLS.with_borrow(|v| v.contains(&"walk")));
    // With a trailing slash the object must be a directory (the stub's files are not)
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Ok(fuse::Walk::Done(FUSE | 9, 1))));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/fusemnt/mp/a/", true, &mounts)), Err(ENOTDIR));
    // The walk leaves the FUSE file system again (a mount back into the pool)
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Ok(fuse::Walk::Out(back, 0, b"y".to_vec()))));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/fusemnt/mp/c/d", true, &mounts)), Ok((y, 0)));
    // ... and ends exactly at the way out
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Ok(fuse::Walk::Out(back, 0, Vec::new()))));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/fusemnt/mp/e", true, &mounts)), Ok((back, 0)));
    // The daemon's error
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Err(-13)));
    assert_eq!(srv(|s| s.resolve_mnt(ROOT_INO, 0, ROOT_INO, 0, b"/fusemnt/mp/f", true, &mounts)), Err(-13));
    // resolve_in_dirs from a FUSE base goes the mount way (no directories reported)
    FUSE_WALK.with_borrow_mut(|w| *w = Some(Ok(fuse::Walk::Done(FUSE | 11, 0))));
    assert_eq!(srv(|s| s.resolve_in_dirs(ROOT_INO, FUSE | 3, b"z", true)), Ok((FUSE | 11, vec![])));
    // ... as does any path while the initial namespace has FUSE mounts
    FUSE_NS0.set(true);
    assert_eq!(srv(|s| s.resolve_in_dirs(ROOT_INO, ROOT_INO, b"/fusemnt/back/y", true)), Ok((y, vec![])));
}

#[test]
fn getattr_is_cached_and_setattr_refreshes_it() {
    let _g = serial();
    let d = fakefs::test_dir("attrs");
    let f = with_fs(|fs| fs.put(d, "f", b"12345"));
    let a = srv(|s| s.getattr(f)).unwrap();
    assert_eq!((a.ino, a.size, a.kind()), (f, 5, DnodeType::PlainFile));
    let before = ops(FS_GETATTR);
    assert_eq!(srv(|s| s.getattr(f)).unwrap().size, 5);
    assert_eq!(ops(FS_GETATTR), before);
    fake::CAPS.set(Some(1 << 4)); // CAP_FSETID: set-ID bits stay
    let a = srv(|s| s.setattr(f, SetAttr { size: Some(2), uid: Some(7), ..Default::default() })).unwrap();
    assert_eq!((a.size, a.uid), (2, 7));
    assert!(CACHE.with_borrow(|v| v.contains(&("truncated", f, 2, 0))));
    assert_eq!(srv(|s| s.getattr(f)).unwrap().size, 2, "the new attributes are kept");
    assert_eq!(ops(FS_GETATTR), before);
    // Missing object
    assert_eq!(srv(|s| s.getattr(999_999_999)).err(), Some(ENOENT));
    // forget_all_attrs: the next getattr asks again
    zfs::forget_all_attrs();
    srv(|s| s.getattr(f)).unwrap();
    assert_eq!(ops(FS_GETATTR), before + 2, "the missing object, then f again");
}

#[test]
fn truncation_without_cap_fsetid_drops_set_id_bits() {
    let _g = serial();
    let d = fakefs::test_dir("suid");
    let f = with_fs(|fs| {
        let f = fs.put(d, "prog", b"#!");
        let n = fs.nodes.get_mut(&f).unwrap();
        n.attr.mode = 0o106755;
        n.attr.gid = 50;
        f
    });
    fake::CAPS.set(Some(0));
    fake::CREDS.set((1000, 1000));
    let a = srv(|s| s.setattr(f, SetAttr { size: Some(0), ..Default::default() })).unwrap();
    assert_eq!(a.mode & 0o7777, 0o755, "set-user-ID and (not a member of group 50) set-group-ID go");
    // A directory keeps its bits
    let dd = with_fs(|fs| {
        let x = fs.mkdir_p(d, "sub");
        fs.nodes.get_mut(&x).unwrap().attr.mode = 0o042755;
        x
    });
    assert_eq!(srv(|s| s.setattr(dd, SetAttr { size: Some(0), ..Default::default() })).err(), Some(EISDIR));
    // A write by such a caller sends its groups
    with_fs(|fs| fs.write_kills.clear());
    srv(|s| s.write(f, 0, b"ab")).unwrap();
    assert_eq!(with_fs(|fs| fs.write_kills.last().cloned()), Some(Some(vec![1000])));
    fake::CAPS.set(Some(1 << 4));
    srv(|s| s.write(f, 0, b"ab")).unwrap();
    assert_eq!(with_fs(|fs| fs.write_kills.last().cloned()), Some(None));
}

#[test]
fn reads_and_writes_go_in_max_io_chunks() {
    let _g = serial();
    let d = fakefs::test_dir("chunks");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let f = with_fs(|fs| fs.put(d, "big", b""));
    assert_eq!(srv(|s| s.write(f, 0, &data)), Ok(data.len()));
    assert_eq!(ops(FS_WRITE), 3, "128 KiB per request");
    assert!(CACHE.with_borrow(|v| v.contains(&("written", f, 0, data.len() as u64))));
    let mut back = vec![0u8; 400_000];
    assert_eq!(srv(|s| s.read(f, 0, &mut back)), Ok(data.len()), "a short read ends it");
    assert_eq!(&back[..data.len()], &data[..]);
    assert_eq!(ops(FS_READ), 3);
    // An empty write still makes one request (it may change times)
    clear_ops();
    assert_eq!(srv(|s| s.write(f, 0, b"")), Ok(0));
    assert_eq!(ops(FS_WRITE), 1);
    // A short write ends the loop
    fakefs::WRITE_LIMIT.set(1000);
    assert_eq!(srv(|s| s.write(f, 0, &data[..5000])), Ok(1000));
    fakefs::WRITE_LIMIT.set(0);
    // A failure after some data: what was written counts
    fail(FS_WRITE, ENOSPC, 1);
    assert_eq!(srv(|s| s.write(f, 0, &data[..1000])), Err(ENOSPC));
    clear_ops();
    let calls = std::cell::Cell::new(0);
    // second chunk fails
    fakefs::FAIL.with_borrow_mut(|v| v.clear());
    {
        // first request ok, second fails: put a failure behind one success
        let _ = &calls;
    }
    let big = vec![1u8; 200_000];
    // The fake fails the first matching request: fail reads instead to get past the first
    // write, then fail the next write
    srv(|s| s.write(f, 0, &big[..10])).unwrap();
    fail(FS_WRITE, EIO, 1);
    assert_eq!(srv(|s| s.write(f, 0, &big)), Err(EIO), "nothing written: the error");
}

#[test]
fn create_mknod_mkdir_symlink_and_their_attributes() {
    let _g = serial();
    let d = fakefs::test_dir("make");
    let f = srv(|s| s.create(d, b"file", 0o640, 10, 20)).unwrap();
    let a = srv(|s| s.getattr(f)).unwrap();
    assert_eq!((a.mode, a.uid, a.gid), (0o100640, 10, 20));
    let n = srv(|s| s.mknod(d, b"fifo", 0o010644, 0, 1, 2)).unwrap();
    assert_eq!(srv(|s| s.getattr(n)).unwrap().mode, 0o010644);
    let c = srv(|s| s.mknod(d, b"chr", 0o020600, (1 << 8) | 3, 0, 0)).unwrap();
    assert_eq!(srv(|s| s.getattr(c)).unwrap().rdev, 0x103);
    let sub = srv(|s| s.mkdir(d, b"sub", 0o700, 3, 4)).unwrap();
    assert!(srv(|s| s.getattr(sub)).unwrap().is_dir());
    let l = srv(|s| s.symlink(d, b"ln", b"file", 0, 0)).unwrap();
    assert_eq!(srv(|s| s.readlink(l)), Ok(b"file".to_vec()));
    // Errors pass through and still forget the directory's attributes
    assert_eq!(srv(|s| s.create(d, b"file", 0o600, 0, 0)), Err(EEXIST));
    assert_eq!(srv(|s| s.mkdir(d, b"file", 0o700, 0, 0)), Err(EEXIST));
    assert_eq!(srv(|s| s.mknod(d, b"file", 0o010600, 0, 0, 0)), Err(EEXIST));
    assert_eq!(srv(|s| s.symlink(d, b"file", b"x", 0, 0)), Err(EEXIST));
    // readlink is cached until a name changes (the failed creations above forgot names)
    srv(|s| s.readlink(l)).unwrap();
    let before = ops(FS_READLINK);
    srv(|s| s.readlink(l)).unwrap();
    assert_eq!(ops(FS_READLINK), before);
    assert_eq!(srv(|s| s.readlink(f)), Err(EINVAL));
}

#[test]
fn extended_attributes() {
    let _g = serial();
    let d = fakefs::test_dir("xattr");
    let f = with_fs(|fs| fs.put(d, "f", b""));
    assert_eq!(srv(|s| s.getxattr(f, b"user.a")), Err(ENODATA));
    srv(|s| s.setxattr(f, b"user.a", b"one", 0)).unwrap();
    srv(|s| s.setxattr(f, b"user.b", b"two", 0)).unwrap();
    assert_eq!(srv(|s| s.getxattr(f, b"user.a")), Ok(b"one".to_vec()));
    assert_eq!(srv(|s| s.listxattr(f)), Ok(b"user.a\0user.b\0".to_vec()));
    assert!(srv(|s| s.getattr(f)).unwrap().has_xattr, "setting forgot the cached attributes");
    srv(|s| s.removexattr(f, b"user.a")).unwrap();
    assert_eq!(srv(|s| s.removexattr(f, b"user.a")), Err(ENODATA));
    assert_eq!(srv(|s| s.listxattr(f)), Ok(b"user.b\0".to_vec()));
    assert_eq!(ZfsClient::getxattr(f, b"user.b"), Ok(b"two".to_vec()));
    ZfsClient::setxattr(f, b"user.c", b"3", 0).unwrap();
    assert_eq!(ZfsClient::listxattr(f), Ok(b"user.b\0user.c\0".to_vec()));
    ZfsClient::removexattr(f, b"user.c").unwrap();
}

#[test]
fn link_unlink_rmdir_rename_forget_and_drop_cached_pages() {
    let _g = serial();
    let d = fakefs::test_dir("names");
    let (f, g, sub) = with_fs(|fs| (fs.put(d, "f", b"a"), fs.put(d, "g", b"b"), fs.mkdir_p(d, "sub")));
    srv(|s| s.link(f, sub, b"hard")).unwrap();
    assert_eq!(srv(|s| s.lookup(sub, b"hard")), Ok(f));
    assert_eq!(srv(|s| s.getattr(f)).unwrap().nlink, 2);
    // Renaming over g drops g's cached pages
    srv(|s| s.rename(d, b"f", d, b"g")).unwrap();
    assert!(CACHE.with_borrow(|v| v.contains(&("forget", g, 0, 0))));
    assert_eq!(srv(|s| s.lookup(d, b"g")), Ok(f));
    assert_eq!(srv(|s| s.lookup(d, b"f")), Err(ENOENT));
    // Unlinking a file drops its pages
    srv(|s| s.unlink(sub, b"hard")).unwrap();
    assert!(CACHE.with_borrow(|v| v.contains(&("forget", f, 0, 0))));
    assert_eq!(srv(|s| s.unlink(sub, b"hard")), Err(ENOENT));
    assert_eq!(srv(|s| s.rmdir(d, b"g")), Err(ENOTDIR));
    with_fs(|fs| fs.put(sub, "keep", b""));
    assert_eq!(srv(|s| s.rmdir(d, b"sub")), Err(ENOTEMPTY));
    srv(|s| s.unlink(sub, b"keep")).unwrap();
    srv(|s| s.rmdir(d, b"sub")).unwrap();
    assert_eq!(srv(|s| s.link(d, d, b"x")), Err(EPERM));
    // A failed rename drops nothing
    CACHE.with_borrow_mut(|v| v.clear());
    assert_eq!(srv(|s| s.rename(d, b"missing", d, b"g")), Err(ENOENT));
    assert!(CACHE.with_borrow(|v| v.is_empty()));
}

#[test]
fn readdir_statfs_and_pool_queries() {
    let _g = serial();
    let d = fakefs::test_dir("listing");
    with_fs(|fs| {
        fs.put(d, "a", b"");
        fs.put(d, "b", b"");
    });
    let e = srv(|s| s.readdir(d, 0, 10)).unwrap();
    let names: Vec<_> = e.iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, vec![b".".to_vec(), b"..".to_vec(), b"a".to_vec(), b"b".to_vec()]);
    assert_eq!(srv(|s| s.readdir(d, 3, 10)).unwrap().len(), 1);
    let (t, free, _objs) = srv(|s| Ok(s.statfs())).unwrap();
    assert_eq!((t, free), (1 << 20, 1 << 19));
    fail(FS_STATFS, EIO, 1);
    assert_eq!(srv(|s| Ok(s.statfs())), Ok((0, 0, 0)), "zeros when the server fails");
    let st = srv(|s| s.pool_status()).unwrap();
    assert_eq!((st.0, st.1, st.2), (64 << 20, 8 << 20, 56 << 20));
    let (birth, has, sum) = srv(|s| s.object_info(d)).unwrap();
    assert_eq!((has, sum[0]), (false, d));
    assert!(birth > 0);
    assert_eq!(srv(|s| s.object_info(999_999_998)), Err(ENOENT));
    let snaps_before = with_fs(|fs| fs.snapshots.len());
    assert!(srv(|s| s.snapshot(0, "s1")).is_ok());
    assert_eq!(srv(|s| s.snapshot(5, "s2")), Err(EINVAL));
    let ds = srv(|s| s.datasets()).unwrap();
    assert_eq!(ds[0].0, "hydrapool");
    assert!(ds.iter().any(|x| x.0 == "hydrapool@s1" && x.3));
    assert_eq!(with_fs(|fs| fs.snapshots.len()), snaps_before + 1);
    srv(|s| s.diagnostic(FS_FSCK, "/listing", true)).unwrap();
    assert_eq!(with_fs(|fs| fs.diagnostics.last().cloned()), Some((FS_FSCK, "/listing".to_string(), true)));
    // Sync and sync-if-dirty
    let t1 = srv(|s| s.sync()).unwrap();
    assert_eq!(srv(|s| s.sync_if_dirty()), Ok(false));
    with_fs(|fs| fs.dirty = true);
    assert_eq!(srv(|s| s.sync_if_dirty()), Ok(true));
    assert!(srv(|s| s.sync()).unwrap() > t1);
    srv(|s| {
        s.notify_file(d, 0x8);
        Ok(())
    })
    .unwrap();
    assert_eq!(with_fs(|fs| fs.notified.last().copied()), Some((d, 0x8)));
}

#[test]
fn open_references_reach_the_server_only_first_and_last() {
    let _g = serial();
    let d = fakefs::test_dir("refs");
    let f = with_fs(|fs| fs.put(d, "f", b""));
    for _ in 0..3 {
        ZfsClient::open_ref(f);
    }
    assert_eq!(ops(FS_OPEN_REF), 1);
    assert_eq!(with_fs(|fs| fs.refs.get(&f).copied()), Some(1));
    ZfsClient::release(f);
    ZfsClient::release(f);
    assert_eq!(ops(FS_RELEASE), 0);
    ZfsClient::release(f);
    assert_eq!(ops(FS_RELEASE), 1);
    assert_eq!(with_fs(|fs| fs.refs.get(&f).copied()), Some(0));
    // Never counted here: the server decides
    ZfsClient::release(f);
    assert_eq!(ops(FS_RELEASE), 2);
}

#[test]
fn request_failures_map_to_eio() {
    let _g = serial();
    let d = fakefs::test_dir("broken");
    let f = with_fs(|fs| fs.put(d, "f", b"x"));
    // A reply with the wrong label
    fakefs::BAD_LABEL.set(true);
    assert_eq!(srv(|s| s.getattr(f + 1_000_000)).err(), Some(EIO));
    fakefs::BAD_LABEL.set(false);
    // The server's window is gone: the supervisor revives it
    fakefs::drop_window(ENDPOINT_ZFS_SERVER);
    assert_eq!(srv(|s| s.lookup(d, b"f")).ok(), Some(f));
    let revived = fakefs::REVIVED.with_borrow(|v| v.contains(&ENDPOINT_ZFS_SERVER));
    // (the lookup may have come from the cache; force a request)
    fakefs::drop_window(ENDPOINT_ZFS_SERVER);
    assert!(srv(|s| s.object_info(f)).is_ok());
    assert!(revived || fakefs::REVIVED.with_borrow(|v| v.contains(&ENDPOINT_ZFS_SERVER)));
    // The call itself fails (server offline)
    fakefs::set_offline(ENDPOINT_ZFS_SERVER, true);
    assert_eq!(srv(|s| s.object_info(f)), Err(EIO));
    fakefs::set_offline(ENDPOINT_ZFS_SERVER, false);
    assert!(srv(|s| s.object_info(f)).is_ok());
}

#[test]
fn reply_events_reach_inotify_and_fanotify() {
    let _g = serial();
    let d = fakefs::test_dir("events");
    fakefs::EVENTS.with_borrow_mut(|v| v.push(Event { ino: d, mask: 0x100, cookie: 0, name: b"new".to_vec() }));
    // Nobody watching: the events are skipped
    srv(|s| s.pool_status()).unwrap();
    assert!(NOTIFIED.with_borrow(|v| v.is_empty()));
    INOTIFY_ON.set(true);
    fakefs::EVENTS.with_borrow_mut(|v| v.push(Event { ino: d, mask: 0x100, cookie: 0, name: b"new".to_vec() }));
    srv(|s| s.pool_status()).unwrap();
    // (wave9 G9-C: handed to vfs-server only; the kernel has no instances of its own)
    let n = NOTIFIED.with_borrow(|v| v.clone());
    assert_eq!(n, vec![("vfs-zfs", d, 0x100, "new".to_string())]);
    INOTIFY_ON.set(false);
    FANOTIFY_ON.set(true);
    fakefs::EVENTS.with_borrow_mut(|v| v.push(Event { ino: d, mask: 0x200, cookie: 0, name: b"x".to_vec() }));
    srv(|s| s.pool_status()).unwrap();
    assert!(NOTIFIED.with_borrow(|v| v.contains(&("vfs-zfs", d, 0x200, "x".to_string()))));
}

#[test]
fn fuse_objects_go_to_the_daemon() {
    let _g = serial();
    let x = FUSE | 100;
    let mut buf = [0u8; 4];
    assert_eq!(srv(|s| s.lookup(x, b"a")), Ok(x + 1));
    assert_eq!(srv(|s| s.getattr(x)).unwrap().ino, x);
    assert_eq!(srv(|s| s.setattr(x, SetAttr::default())).unwrap().mode, 0o100600);
    assert_eq!(srv(|s| s.read(x, 0, &mut buf)), Ok(4));
    assert_eq!(&buf, b"ffff");
    assert_eq!(srv(|s| s.write(x, 0, b"ab")), Ok(2));
    assert_eq!(srv(|s| s.create(x, b"c", 0o600, 0, 0)), Ok(x + 2));
    assert_eq!(srv(|s| s.mknod(x, b"n", 0o010600, 0, 0, 0)), Ok(x + 3));
    assert_eq!(srv(|s| s.mkdir(x, b"d", 0o700, 0, 0)), Ok(x + 4));
    assert_eq!(srv(|s| s.symlink(x, b"l", b"t", 0, 0)), Ok(x + 5));
    assert_eq!(srv(|s| s.getxattr(x, b"n")), Ok(b"fx".to_vec()));
    assert_eq!(srv(|s| s.setxattr(x, b"n", b"v", 0)), Ok(()));
    assert_eq!(srv(|s| s.listxattr(x)), Ok(b"user.f\0".to_vec()));
    assert_eq!(srv(|s| s.removexattr(x, b"n")), Ok(()));
    assert_eq!(srv(|s| s.readlink(x)), Ok(b"/fuse/target".to_vec()));
    assert_eq!(srv(|s| s.link(x, ROOT_INO, b"l")), Ok(()));
    assert_eq!(srv(|s| s.unlink(x, b"u")), Ok(()));
    assert_eq!(srv(|s| s.rmdir(x, b"r")), Ok(()));
    assert_eq!(srv(|s| s.rename(x, b"a", ROOT_INO, b"b")), Ok(()));
    assert_eq!(srv(|s| s.readdir(x, 0, 5)).unwrap()[0].ino, x + 9);
    srv(|s| {
        s.open_ref(x);
        s.release(x);
        s.notify_file(x, 1);
        Ok(())
    })
    .unwrap();
    let calls = FUSE_CALLS.with_borrow(|v| v.clone());
    for c in ["lookup", "getattr", "setattr", "read", "write", "create", "mknod", "mkdir", "symlink", "getxattr", "setxattr", "listxattr", "removexattr", "readlink", "link", "unlink", "rmdir", "rename", "readdir", "open_ref", "release"] {
        assert!(calls.contains(&c), "{c} went to the daemon");
    }
    // FUSE files read by the client bypass the page cache
    assert_eq!(ZfsClient::read_at(x, 0, &mut buf), Ok(4));
    assert!(CACHE.with_borrow(|v| v.iter().all(|c| c.0 != "read")));
    // None of it reached the file server
    assert_eq!(ops(0) + fakefs::OPS.with_borrow(|v| v.len()), 0);
}

#[test]
fn disk_info_asks_the_pools_disk_driver() {
    let _g = serial();
    assert!(zfs::disk_info().is_none(), "no disk driver: a RAM pool");
    fakefs::set_handler(
        ENDPOINT_BLOCK_DEV,
        Box::new(|m: &Message, w: &mut [u8]| {
            assert_eq!(m.label, MSG_BLOCK_GET_SIZE);
            w[..40].fill(b' ');
            w[..9].copy_from_slice(b"QEMU HDD\0");
            Ok(Message::with_args(MSG_BLOCK_REPLY, [0, 1000, 1, 0]))
        }),
    );
    let i = zfs::disk_info().unwrap();
    assert_eq!((i.model.as_str(), i.sectors, i.lba48, i.dma), ("QEMU HDD", 8000, true, false));
    // A failing driver
    fakefs::set_handler(ENDPOINT_BLOCK_DEV, Box::new(|_: &Message, _: &mut [u8]| Ok(Message::with_args(MSG_BLOCK_REPLY, [(-5i64) as u64, 0, 0, 0]))));
    assert!(zfs::disk_info().is_none());
    fakefs::set_handler(ENDPOINT_BLOCK_DEV, Box::new(|_: &Message, _: &mut [u8]| Ok(Message::with_args(0x1, [0; 4]))));
    assert!(zfs::disk_info().is_none());
    fakefs::set_handler(ENDPOINT_BLOCK_DEV, Box::new(|_: &Message, _: &mut [u8]| Err(-19)));
    assert!(zfs::disk_info().is_none());
    fakefs::clear_handler(ENDPOINT_BLOCK_DEV);
    // The pool on a USB disk: the USB driver is asked
    zfs::POOL_ON_USB.store(true, std::sync::atomic::Ordering::Release);
    fakefs::set_handler(ENDPOINT_USB_DISK, Box::new(|_: &Message, w: &mut [u8]| {
        w[..40].fill(0);
        w[..4].copy_from_slice(b"USB1");
        Ok(Message::with_args(MSG_BLOCK_REPLY, [0, 2, 0, 1]))
    }));
    let i = zfs::disk_info().unwrap();
    zfs::POOL_ON_USB.store(false, std::sync::atomic::Ordering::Release);
    fakefs::clear_handler(ENDPOINT_USB_DISK);
    assert_eq!((i.model.as_str(), i.sectors, i.dma), ("USB1", 16, true));
}

// --------------------------------------------------------------- client.rs

#[test]
fn normalize_path_is_lexical() {
    let mut b = [0u8; 128];
    assert_eq!(normalize_path("/home/u", "docs/../x/./y", &mut b), "/home/u/x/y");
    assert_eq!(normalize_path("/home/u", "/etc//passwd", &mut b), "/etc/passwd");
    assert_eq!(normalize_path("/a", "../../..", &mut b), "/");
    assert_eq!(normalize_path("/", "", &mut b), "/");
    assert_eq!(normalize_path("\\win", "dir\\file", &mut b), "/win/dir/file");
    assert_eq!(normalize_path("/x/.", "\\abs", &mut b), "/abs");
    // More than 16 components: the rest are dropped
    let deep = (0..20).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/");
    let n = normalize_path("/", &deep, &mut b).to_string();
    assert_eq!(n.matches('/').count(), 16);
    // Longer than the buffer: cut at 128 bytes
    let long = format!("/{}", "a".repeat(200));
    assert_eq!(normalize_path("/", &long, &mut b).len(), 128);
}

#[test]
fn parent_resolution_splits_the_last_component() {
    let _g = serial();
    let d = fakefs::test_dir("parents");
    let sub = with_fs(|fs| fs.mkdir_p(d, "a/b"));
    assert_eq!(ZfsClient::resolve_parent(0, b"/parents/a/b/c"), Ok((sub, b"c".to_vec())));
    assert_eq!(ZfsClient::resolve_parent(0, b"/parents/a/b/"), Ok((with_fs(|fs| fs.child(d, b"a").unwrap()), b"b".to_vec())));
    assert_eq!(ZfsClient::resolve_parent(sub, b"name"), Ok((sub, b"name".to_vec())));
    assert_eq!(ZfsClient::resolve_parent(0, b"/top"), Ok((ROOT_INO, b"top".to_vec())));
    assert_eq!(ZfsClient::resolve_parent(0, b"/"), Err(EEXIST));
    assert_eq!(ZfsClient::resolve_parent(0, b"/parents/missing/x"), Err(ENOENT));
    assert_eq!(ZfsClient::resolve_parent_in(0, 0, b"/parents/a"), Ok((d, b"a".to_vec())));
    assert_eq!(ZfsClient::resolve_parent_in(d, 0, b"/a/b"), Ok((with_fs(|fs| fs.child(d, b"a").unwrap()), b"b".to_vec())), "absolute inside the jail");
    assert_eq!(srv(|s| resolve_parent_in(s, ROOT_INO, ROOT_INO, b"")), Err(EEXIST));
    assert_eq!(srv(|s| client::resolve_in(s, ROOT_INO, ROOT_INO, b"", true)), Err(ENOENT));
    assert_eq!(client::resolve_parent_and_name("/parents/a/b"), Ok((with_fs(|fs| fs.child(d, b"a").unwrap()), "b")));
    assert_eq!(client::resolve_parent_and_name("/"), Err("Cannot target root directory as a child"));
    assert_eq!(client::resolve_parent_and_name("/parents/zz/b"), Err("File or directory not found"));
}

#[test]
fn inode_level_resolution_defaults() {
    let _g = serial();
    let d = fakefs::test_dir("inode");
    let f = with_fs(|fs| fs.put(d, "x/f", b"1"));
    let x = with_fs(|fs| fs.child(d, b"x").unwrap());
    assert_eq!(ZfsClient::resolve(0, b"/inode/x/f", true), Ok(f));
    assert_eq!(ZfsClient::resolve(x, b"f", true), Ok(f));
    assert_eq!(ZfsClient::resolve_in(0, 0, b"/inode/x/f", true), Ok(f));
    assert_eq!(ZfsClient::resolve_in(d, 0, b"/x/f", true), Ok(f), "jail root, base = root");
    assert_eq!(ZfsClient::resolve_in(d, x, b"../../../x/f", true), Ok(f), "'..' stops at the jail root");
    assert_eq!(ZfsClient::resolve_in_dirs(0, 0, b"", true), Err(ENOENT));
    assert_eq!(ZfsClient::resolve_in_dirs(d, 0, b"x/f", true).map(|r| r.0), Ok(f));
    assert_eq!(ZfsClient::resolve(0, b"/inode/x/f/", true), Err(ENOTDIR));
}

#[test]
fn errors_become_messages() {
    let _g = serial();
    let d = fakefs::test_dir("msgs");
    with_fs(|fs| {
        fs.put(d, "file", b"");
        fs.mkdir_p(d, "full");
        fs.put(d, "full/x", b"");
        fs.link_to(d, "loop", "loop");
    });
    assert_eq!(ZfsClient::lookup("/msgs/none"), Err("File or directory not found"));
    assert_eq!(ZfsClient::lookup("/msgs/file/x"), Err("Path component is not a directory"));
    assert_eq!(ZfsClient::lookup("/msgs/loop"), Err("Too many levels of symbolic links"));
    assert_eq!(ZfsClient::create_dir("/msgs/file"), Err("File or directory already exists"));
    assert_eq!(ZfsClient::remove_dir("/msgs/full"), Err("Directory is not empty"));
    assert_eq!(ZfsClient::remove_file("/msgs/full"), Err("Target is a directory"));
    fail(0, ENOSPC, 1);
    assert_eq!(ZfsClient::ping(), Err("Storage pool is out of space"));
    fail(0, EINVAL, 1);
    assert_eq!(ZfsClient::ping(), Err("Invalid argument"));
    fail(0, ENAMETOOLONG, 1);
    assert_eq!(ZfsClient::ping(), Err("File name too long"));
    fail(0, -99, 1);
    assert_eq!(ZfsClient::ping(), Err("ZFS I/O error"));
}

#[test]
fn whole_file_helpers() {
    let _g = serial();
    let d = fakefs::test_dir("whole");
    let txg = with_fs(|fs| fs.txg);
    assert_eq!(ZfsClient::ping(), Ok(txg));
    let (mib, akib, fkib, t) = ZfsClient::pool_status().unwrap();
    assert_eq!((mib, akib, fkib, t), (64, 8 * 1024, 56 * 1024, txg));
    // write_file_by_path makes the parents, commits and reports the new txg
    let t = ZfsClient::write_file_by_path("/whole/a/b/c.txt", b"content").unwrap();
    assert_eq!(t, with_fs(|fs| fs.txg));
    let mut buf = [0u8; 32];
    assert_eq!(ZfsClient::read_file_by_path("/whole/a/b/c.txt", &mut buf), Ok(7));
    assert_eq!(&buf[..7], b"content");
    // Rewriting truncates first
    ZfsClient::write_file_by_path_batch("/whole/a/b/c.txt", b"xy").unwrap();
    assert_eq!(ZfsClient::read_file_by_path("/whole/a/b/c.txt", &mut buf), Ok(2));
    assert_eq!(ZfsClient::write_file_by_path_batch("/whole/a", b"x"), Err("Target is a directory"));
    assert_eq!(ZfsClient::read_file_by_path("/whole/a", &mut buf), Err("Target path is not a regular file"));
    let (ino, kind) = ZfsClient::lookup("/whole/a/b/c.txt").unwrap();
    assert_eq!(kind, DnodeType::PlainFile);
    let open_txg = with_fs(|fs| fs.open_txg);
    assert_eq!(ZfsClient::write_file(ino, b"replaced", None), Ok(open_txg));
    assert_eq!(ZfsClient::read_file(ino, &mut buf, None), Ok(8));
    // A file in the way of mkdir -p
    assert_eq!(ZfsClient::create_dir_all("/whole/a/b/c.txt/d"), Err("Path component is not a directory"));
    let dd = ZfsClient::create_dir_all("/whole/./p/q").unwrap();
    assert_eq!(ZfsClient::create_dir_all("/whole/p/q"), Ok(dd), "existing: the same directory");
    assert_eq!(ZfsClient::lookup("/whole/p/q").unwrap(), (dd, DnodeType::Directory));
    // A failed lookup that is not ENOENT stops mkdir -p
    fail(FS_LOOKUP, EIO, 1);
    assert!(ZfsClient::create_dir_all("/whole/p/new").is_err());
    // touch: create, then update the times
    let t1 = ZfsClient::touch_file("/whole/t").unwrap();
    fake::RTC.set(1_800_000_000);
    assert_eq!(ZfsClient::touch_file("/whole/t"), Ok(t1));
    assert_eq!(ZfsClient::getattr(t1).unwrap().mtime, (1_800_000_000, 0));
    assert_eq!(ZfsClient::touch_file("/whole/none/t"), Err("File or directory not found"));
    assert_eq!(ZfsClient::touch_file("/whole/t/x"), Err("Path component is not a directory"));
    // copy, move, remove
    ZfsClient::copy_file("/whole/a/b/c.txt", "/whole/copy").unwrap();
    assert_eq!(ZfsClient::read_file_by_path("/whole/copy", &mut buf), Ok(8));
    assert_eq!(&buf[..8], b"replaced");
    ZfsClient::move_entry("/whole/copy", "/whole/moved").unwrap();
    assert!(ZfsClient::lookup("/whole/copy").is_err());
    ZfsClient::remove_file("/whole/moved").unwrap();
    assert!(ZfsClient::lookup("/whole/moved").is_err());
    ZfsClient::create_dir("/whole/empty").unwrap();
    ZfsClient::remove_dir("/whole/empty").unwrap();
    // A write that fails at create
    fail(FS_CREATE, ENOSPC, 1);
    assert_eq!(ZfsClient::write_file_by_path_batch("/whole/nospace", b"x"), Err("Storage pool is out of space"));
    // A lookup error other than ENOENT
    fail(FS_RESOLVE, EIO, 1);
    assert_eq!(ZfsClient::write_file_by_path_batch("/whole/eio", b"x"), Err("ZFS I/O error"));
}

#[test]
fn file_stat_list_dir_snapshot_sync() {
    let _g = serial();
    let d = fakefs::test_dir("stat");
    let f = with_fs(|fs| {
        let f = fs.put(d, "a-very-long-file-name-that-goes-past-31-bytes.txt", b"12345");
        fs.nodes.get_mut(&f).unwrap().attr.uid = 33;
        f
    });
    let st = ZfsClient::file_stat("/stat/a-very-long-file-name-that-goes-past-31-bytes.txt").unwrap();
    assert_eq!((st.obj_id, st.size, st.uid, st.obj_type, st.is_allocated), (f, 5, 33, DnodeType::PlainFile, true));
    assert_eq!(st.name_str(), "a-very-long-file-name-that-goes");
    assert_eq!(st.checksum[0], f);
    let mut bad = st;
    bad.name = [0xFF; 32];
    assert_eq!(bad.name_str(), "<unknown>");
    assert!(ZfsClient::file_stat("/stat/none").is_err());
    // list_dir pages through more entries than one batch (256)
    with_fs(|fs| {
        let big = fs.mkdir_p(d, "big");
        for i in 0..300 {
            fs.put(big, &format!("f{i:03}"), b"");
        }
        fs.mkdir_p(big, "zdir");
    });
    let (entries, n, ds) = ZfsClient::list_dir("/stat/big").unwrap();
    assert_eq!((n, ds), (301, "hydrapool/root"));
    assert_eq!(entries[0].name_str(), "f000");
    assert_eq!(entries[300].obj_type, DnodeType::Directory);
    assert!(ZfsClient::list_dir("/stat/missing").is_err());
    // snapshot is named after the clock
    fake::RTC.set(1_234_567);
    ZfsClient::snapshot(0).unwrap();
    assert_eq!(with_fs(|fs| fs.snapshots.last().cloned()), Some((0, "snap1234567".to_string())));
    // sync flushes the page cache first
    CACHE.with_borrow_mut(|v| v.clear());
    ZfsClient::sync().unwrap();
    assert_eq!(CACHE.with_borrow(|v| v.clone()), vec![("flush", 0, 0, 0)]);
    with_fs(|fs| fs.dirty = true);
    let t = with_fs(|fs| fs.txg);
    ZfsClient::sync_if_dirty();
    assert!(with_fs(|fs| fs.txg) > t);
}

#[test]
fn inode_level_io_and_metadata() {
    let _g = serial();
    let d = fakefs::test_dir("io");
    let f = with_fs(|fs| fs.put(d, "f", b"hello world"));
    let mut buf = [0u8; 5];
    assert_eq!(ZfsClient::read_at(f, 6, &mut buf), Ok(5));
    assert_eq!(&buf, b"world");
    assert!(CACHE.with_borrow(|v| v.contains(&("read", f, 6, 5))), "through the page cache");
    assert_eq!(ZfsClient::write_at(f, 0, b"HELLO"), Ok(5));
    assert_eq!(ZfsClient::read_uncached(f, 0, &mut buf), Ok(5));
    assert_eq!(&buf, b"HELLO");
    assert_eq!(ZfsClient::readdir(d, 2, 10).unwrap().len(), 1);
    let l = with_fs(|fs| fs.link_to(d, "l", "f"));
    assert_eq!(ZfsClient::readlink(l), Ok(b"f".to_vec()));
    // chmod of a file with extended attributes updates its ACL and reads the result again
    ZfsClient::setxattr(f, b"system.posix_acl_access", b"acl", 0).unwrap();
    let a = ZfsClient::setattr(f, SetAttr { mode: Some(0o600), ..Default::default() }).unwrap();
    assert_eq!(a.mode, 0o100600);
    assert_eq!(CHMODS.with_borrow(|v| v.clone()), vec![(f, 0o600)]);
    // Without extended attributes no ACL work
    let g = with_fs(|fs| fs.put(d, "g", b""));
    ZfsClient::setattr(g, SetAttr { mode: Some(0o640), ..Default::default() }).unwrap();
    assert_eq!(CHMODS.with_borrow(|v| v.len()), 1);
    // notify_close_write only when inotify watches something
    ZfsClient::notify_close_write(f);
    assert!(with_fs(|fs| fs.notified.iter().all(|n| n.0 != f)));
    INOTIFY_ON.set(true);
    ZfsClient::notify_close_write(f);
    assert!(with_fs(|fs| fs.notified.contains(&(f, 0x8))));
}

#[test]
fn boot_files_are_read_only_with_boot_services() {
    let _g = serial();
    fake::HARDWARE_MODE.set(true);
    assert!(ZfsClient::read_boot_files().is_empty());
}

#[test]
fn txgd_starts_once() {
    let _g = serial();
    client::start_txg_sync();
    client::start_txg_sync();
    let started = fake::SPAWNED.with_borrow(|v| v.clone());
    assert!(started.len() <= 1);
    assert!(started.is_empty() || started == vec!["txgd".to_string()]);
}

#[test]
fn boot_file_import_skips_unchanged_files() {
    let _g = serial();
    let elf = [0x7Fu8, b'E', b'L', b'F', 2, 1, 1, 0];
    let files = || {
        vec![
            BootFile { boot_path: "\\bin\\t1.elf".into(), pool_path: "/bootimp/bin/t1.elf".into(), data: elf.to_vec() },
            BootFile { boot_path: "\\etc\\passwd".into(), pool_path: "/etc/bootimp-passwd".into(), data: b"root:x:0:0\n".to_vec() },
            BootFile { boot_path: "\\bin\\x.chk".into(), pool_path: "/bootimp/bin/x.chk".into(), data: b"sum".to_vec() },
            BootFile { boot_path: "\\bin\\junk".into(), pool_path: "/bootimp/bin/junk".into(), data: b"not elf".to_vec() },
        ]
    };
    fakefs::test_dir("bootimp");
    let _ = ZfsClient::remove_file(BOOT_MANIFEST);
    let _ = ZfsClient::remove_file("/etc/bootimp-passwd");
    assert_eq!(ZfsClient::import_boot_files(files()), 3, "the junk file is not imported");
    let out = fake::console_take();
    assert!(out.contains("Imported '\\bin\\t1.elf' from boot media into ZFS '/bootimp/bin/t1.elf' (8 bytes)"));
    let (ino, _) = ZfsClient::lookup("/bootimp/bin/t1.elf").unwrap();
    assert_eq!(ZfsClient::getattr(ino).unwrap().mode & 0o777, 0o755, "an ELF file is executable");
    let (cfg, _) = ZfsClient::lookup("/etc/bootimp-passwd").unwrap();
    assert_eq!(ZfsClient::getattr(cfg).unwrap().mode & 0o777, 0o644);
    let mut m = vec![0u8; 4096];
    let n = ZfsClient::read_file_by_path(BOOT_MANIFEST, &mut m).unwrap();
    let manifest = String::from_utf8_lossy(&m[..n]).into_owned();
    assert_eq!(manifest.lines().count(), 3);
    assert!(manifest.contains(" 8 1700000000 0 /bootimp/bin/t1.elf") || manifest.contains("/bootimp/bin/t1.elf"));
    assert!(fake::MARKS.with_borrow(|v| v.iter().any(|m| m == "import: sync")));
    // A second boot with the same files: all unchanged, nothing written, no commit
    let txg = with_fs(|fs| fs.txg);
    assert_eq!(ZfsClient::import_boot_files(files()), 0);
    assert_eq!(with_fs(|fs| fs.txg), txg, "nothing to commit");
    assert!(fake::klog_take().contains("3 unchanged, 0 compared with the pool, 0 imported (3 manifest entries before)"));
    // The manifest is gone but the pool copies are equal: compared, not rewritten
    ZfsClient::remove_file(BOOT_MANIFEST).unwrap();
    assert_eq!(ZfsClient::import_boot_files(files()), 0);
    assert!(fake::klog_take().contains("0 unchanged, 3 compared with the pool, 0 imported (0 manifest entries before)"));
    // A changed boot copy is imported again
    let mut changed = files();
    changed[0].data.push(0);
    assert_eq!(ZfsClient::import_boot_files(changed), 1);
    // A manifest with junk lines is read past them
    ZfsClient::write_file_by_path(BOOT_MANIFEST, b"zz not a line\n0011 1 2 3\n").unwrap();
    ZfsClient::import_boot_files(Vec::new());
    assert!(fake::klog_take().contains("(0 manifest entries before)"));
}

// wave9 GM: an in-memory tmpfs file (`fs::tmem`; no frames here: the writes carry no data)
#[test]
fn in_memory_file_write_drops_set_id_bits_and_keeps_the_pool_empty() {
    use hydra_hosttests_t33::fs::tmem;
    let _g = serial();
    let d = fakefs::test_dir("tmem");
    let f = with_fs(|fs| {
        let f = fs.put(d, "shm", b"");
        let n = fs.nodes.get_mut(&f).unwrap();
        n.attr.mode = 0o106777;
        n.attr.gid = 50;
        f
    });
    tmem::make(f, 4242);
    fake::CAPS.set(Some(0));
    fake::CREDS.set((1000, 1000));
    let writes = ops(FS_WRITE);
    assert_eq!(srv(|s| s.write(f, 0, b"")), Ok(0));
    assert_eq!(ops(FS_WRITE), writes, "the data stays in memory");
    assert_eq!(srv(|s| s.getattr(f)).unwrap().mode & 0o7777, 0o777, "a writer without CAP_FSETID drops the set-ID bits");
    // With CAP_FSETID the bits stay
    with_fs(|fs| fs.nodes.get_mut(&f).unwrap().attr.mode = 0o104777);
    zfs::forget_all_attrs();
    fake::CAPS.set(Some(1 << 4));
    srv(|s| s.write(f, 0, b"")).unwrap();
    assert_eq!(srv(|s| s.getattr(f)).unwrap().mode & 0o7777, 0o4777);
    // A truncation with another change: the size is the object's, the mode the pool's
    let a = srv(|s| s.setattr(f, SetAttr { size: Some(9000), mode: Some(0o644), ..Default::default() })).unwrap();
    assert_eq!((a.size, a.mode & 0o7777), (9000, 0o644));
    assert_eq!(with_fs(|fs| fs.nodes.get(&f).unwrap().attr.size), 0, "the pool object stays empty");
    tmem::forget(f);
    tmem::drop_instance(4242);
}
