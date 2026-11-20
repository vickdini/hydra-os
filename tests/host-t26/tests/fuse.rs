//! fuse.rs: a daemon's file system mounted in the initial namespace and used through the
//! VFS, the protocol's corner cases, and the device.
mod common;
use common::*;
use hydra_hosttests_t26::testkit_fuse::{self as tf, Daemon};
use lx::fuse;

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// Opens /dev/fuse, fills a daemon and mounts it at /mnt/f.
fn mounted(fill: impl FnOnce(&mut Daemon)) -> std::rc::Rc<std::cell::RefCell<Daemon>> {
    let fd = tf::open_dev_fuse();
    assert!(fd >= 0);
    let mut d = Daemon::new(fd);
    fill(&mut d);
    let d = d.install();
    assert_eq!(tf::mount(fd, "/mnt/f", ",allow_other"), 0);
    d
}

#[test]
fn files_of_the_daemon_through_the_vfs() {
    let _e = setup();
    let d = mounted(|d| {
        let docs = d.add(1, "docs", S_IFDIR | 0o755, &[], "");
        d.add(docs, "readme", S_IFREG | 0o644, b"hello fuse", "");
        d.add(1, "link", S_IFLNK | 0o777, &[], "docs/readme");
    });
    let st = stat("/mnt/f/docs/readme").unwrap();
    assert_eq!(st.st_mode, S_IFREG | 0o644);
    assert_eq!(st.st_size, 10);
    assert_ne!(st.st_dev, 0x801);
    let ino_user = st.st_ino;
    assert!(ino_user > 1000);
    // The root of the mount
    assert_eq!(stat("/mnt/f").unwrap().st_mode, S_IFDIR | 0o755);
    // Through the daemon's symbolic link
    assert_eq!(stat("/mnt/f/link").unwrap().st_size, 10);
    assert_eq!(lstat("/mnt/f/link").unwrap().st_mode, S_IFLNK | 0o777);
    // Missing, and below a file
    assert_eq!(stat("/mnt/f/nothing").unwrap_err(), ENOENT);
    assert_eq!(stat("/mnt/f/docs/readme/x").unwrap_err(), ENOTDIR);
    // `..` leaves the mount
    memfs::mkfile("/mnt/sibling", b"s");
    assert!(stat("/mnt/f/../sibling").is_ok());
    assert!(stat("/mnt/f/docs/../../sibling").is_ok());
    // INIT came first, then lookups
    let ops = d.borrow().ops();
    assert_eq!(ops[0], tf::INIT);
    assert!(ops.contains(&tf::LOOKUP) && ops.contains(&tf::GETATTR) && ops.contains(&tf::READLINK));
    // The request header carries the caller
    let r = d.borrow().seen.iter().find(|r| r.opcode == tf::LOOKUP).cloned().unwrap();
    assert_eq!(r.pid as u64, task::SELF_PID);
}

#[test]
fn read_write_and_list() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "data", S_IFREG | 0o666, b"0123456789", "");
        d.add(1, "sub", S_IFDIR | 0o755, &[], "");
    });
    // getdents of the mount root
    let fd = open("/mnt/f", O_RDONLY | O_DIRECTORY);
    assert!(fd >= 0, "{}", fd);
    assert_eq!(list_dir(fd), vec!["data", "sub"]);
    // Reads and writes through the file server client
    let ino = stat("/mnt/f/data").unwrap();
    let _ = ino;
    let f = open("/mnt/f/data", O_RDWR);
    let fino = vnode(f).lock().ino;
    assert!(fuse::is_fuse(fino));
    let mut b = [0u8; 4];
    assert_eq!(fuse::read(fino, 2, &mut b).unwrap(), 4);
    assert_eq!(&b, b"2345");
    assert_eq!(fuse::write(fino, 8, b"ABCD").unwrap(), 4);
    let id = d.borrow().find(1, b"data").unwrap();
    assert_eq!(d.borrow().nodes[&id].data, b"01234567ABCD");
    // The handles were opened once each
    let opens = d.borrow().ops().iter().filter(|&&o| o == tf::OPEN).count();
    assert_eq!(opens, 2);
    assert_eq!(fuse::read(fino, 0, &mut b).unwrap(), 4);
    assert_eq!(d.borrow().ops().iter().filter(|&&o| o == tf::OPEN).count(), 2);
    // Closing releases the daemon's handles (FLUSH, RELEASE x2, RELEASEDIR)
    close(f);
    close(fd);
    d.borrow_mut().serve();
    let ops = d.borrow().ops();
    assert!(ops.contains(&tf::FLUSH) && ops.contains(&tf::RELEASE) && ops.contains(&tf::RELEASEDIR));
}

#[test]
fn reads_and_writes_in_pieces() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "big", S_IFREG | 0o666, &vec![9u8; 300_000], "");
    });
    let f = open("/mnt/f/big", O_RDWR);
    let ino = vnode(f).lock().ino;
    // More than one 128 KiB request
    let mut b = vec![0u8; 300_000];
    assert_eq!(fuse::read(ino, 0, &mut b).unwrap(), 300_000);
    let reads = d.borrow().ops().iter().filter(|&&o| o == tf::READ).count();
    assert_eq!(reads, 3);
    // A short read stops
    d.borrow_mut().read_cap = Some(10);
    let mut b = vec![0u8; 100];
    assert_eq!(fuse::read(ino, 0, &mut b).unwrap(), 10);
    // Writes go in max_write pieces (4096 from INIT); a short write stops
    let before = d.borrow().ops().iter().filter(|&&o| o == tf::WRITE).count();
    assert_eq!(fuse::write(ino, 0, &vec![1u8; 10000]).unwrap(), 10000);
    let writes = d.borrow().ops().iter().filter(|&&o| o == tf::WRITE).count() - before;
    assert_eq!(writes, 3);
    d.borrow_mut().write_cap = Some(100);
    assert_eq!(fuse::write(ino, 0, &vec![1u8; 10000]).unwrap(), 100);
}

#[test]
fn directory_operations() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"x", "");
    });
    assert_eq!(sys(83, &[cstr("/mnt/f/newdir"), 0o755]), 0);
    let nd = d.borrow().find(1, b"newdir").unwrap();
    assert_eq!(d.borrow().nodes[&nd].mode & S_IFDIR, S_IFDIR);
    // open(O_CREAT) uses CREATE and keeps the handle for writing
    let fd = openat(AT_FDCWD, "/mnt/f/newdir/file", O_CREAT | O_WRONLY, 0o640);
    assert!(fd >= 0, "{}", fd);
    assert!(d.borrow().ops().contains(&tf::CREATE));
    assert_eq!(sys(88, &[cstr("../f"), cstr("/mnt/f/newdir/sl")]), 0);
    let b = buf(32);
    assert_eq!(sys(89, &[cstr("/mnt/f/newdir/sl"), b, 32]), 4);
    assert_eq!(read(b, 4), b"../f");
    // readlink of a non-link: EINVAL without asking
    assert_eq!(sys(89, &[cstr("/mnt/f/f"), b, 32]), EINVAL);
    assert_eq!(sys(86, &[cstr("/mnt/f/f"), cstr("/mnt/f/hard")]), 0);
    assert_eq!(sys(82, &[cstr("/mnt/f/newdir/file"), cstr("/mnt/f/moved")]), 0);
    assert!(d.borrow().find(1, b"moved").is_some());
    assert_eq!(sys(87, &[cstr("/mnt/f/moved")]), 0);
    assert_eq!(sys(87, &[cstr("/mnt/f/newdir/sl")]), 0);
    assert_eq!(sys(84, &[cstr("/mnt/f/newdir")]), 0);
    assert!(d.borrow().find(1, b"newdir").is_none());
    // mknod of a FIFO
    assert_eq!(sys(133, &[cstr("/mnt/f/fifo"), 0o010644, 0]), 0);
    assert!(d.borrow().ops().contains(&tf::MKNOD));
    // Links and renames out of the file system: EXDEV
    memfs::mkfile("/pool-file", b"");
    assert_eq!(sys(86, &[cstr("/pool-file"), cstr("/mnt/f/x")]), EXDEV);
    assert_eq!(sys(82, &[cstr("/mnt/f/f"), cstr("/pool-moved")]), EXDEV);
}

#[test]
fn create_falls_back_to_mknod() {
    let _e = setup();
    let d = mounted(|_| {});
    d.borrow_mut().errors.insert(tf::CREATE, -38);
    let fd = openat(AT_FDCWD, "/mnt/f/n", O_CREAT | O_RDWR, 0o600);
    assert!(fd >= 0, "{}", fd);
    let ops = d.borrow().ops();
    assert!(ops.contains(&tf::CREATE) && ops.contains(&tf::MKNOD));
    // Other errors are reported
    d.borrow_mut().errors.insert(tf::CREATE, -28);
    assert_eq!(openat(AT_FDCWD, "/mnt/f/m", O_CREAT | O_RDWR, 0o600), -28);
}

#[test]
fn attributes_xattrs_and_statfs() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"abc", "");
    });
    assert_eq!(sys(90, &[cstr("/mnt/f/f"), 0o600]), 0);
    let id = d.borrow().find(1, b"f").unwrap();
    assert_eq!(d.borrow().nodes[&id].mode, S_IFREG | 0o600);
    assert_eq!(sys(76, &[cstr("/mnt/f/f"), 1]), 0);
    assert_eq!(d.borrow().nodes[&id].data, b"a");
    assert_eq!(sys(92, &[cstr("/mnt/f/f"), 5, u32::MAX as u64]), 0);
    assert_eq!(d.borrow().nodes[&id].uid, 5);
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/mnt/f/f"), 0, 0]), 0);
    // Extended attributes
    let v = hydra_hosttests_t26::fake::leak(b"val".to_vec());
    assert_eq!(sys(188, &[cstr("/mnt/f/f"), cstr("user.k"), v, 3, 0]), 0);
    let b = buf(32);
    assert_eq!(sys(191, &[cstr("/mnt/f/f"), cstr("user.k"), b, 32]), 3);
    assert_eq!(sys(194, &[cstr("/mnt/f/f"), b, 32]), 7);
    assert_eq!(sys(197, &[cstr("/mnt/f/f"), cstr("user.k")]), 0);
    assert_eq!(sys(197, &[cstr("/mnt/f/f"), cstr("user.k")]), ENODATA);
    // A daemon without xattrs: EOPNOTSUPP
    d.borrow_mut().errors.insert(tf::GETXATTR, -38);
    assert_eq!(sys(191, &[cstr("/mnt/f/f"), cstr("user.k"), b, 32]), EOPNOTSUPP);
    // statfs: the daemon's figures
    let sb = buf(120);
    assert_eq!(sys(137, &[cstr("/mnt/f/f"), sb]), 0);
    let v = read(sb, 120);
    let q = |i: usize| u64::from_le_bytes(v[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(q(0), 0x6573_5546);
    assert_eq!(q(1), 4096);
    assert_eq!(q(2), 1000);
    assert_eq!(q(8), 200);
    assert_eq!(q(9), 1024);
    let fd = open("/mnt/f/f", O_RDONLY);
    assert_eq!(sys(138, &[fd as u64, sb]), 0);
    // Defaults when the daemon gives zeros, or has no statfs
    d.borrow_mut().statfs_zero = true;
    assert_eq!(sys(138, &[fd as u64, sb]), 0);
    let v = read(sb, 120);
    assert_eq!(u64::from_le_bytes(v[8..16].try_into().unwrap()), 512);
    assert_eq!(u64::from_le_bytes(v[64..72].try_into().unwrap()), 255);
    d.borrow_mut().errors.insert(tf::STATFS, -38);
    assert_eq!(sys(138, &[fd as u64, sb]), 0);
    d.borrow_mut().errors.insert(tf::STATFS, -5);
    assert_eq!(sys(138, &[fd as u64, sb]), -5);
    assert_eq!(sys(137, &[cstr("/mnt/f/f"), sb]), -5);
}

#[test]
fn attribute_cache_and_invalidation() {
    let _e = setup();
    let d = mounted(|d| {
        d.attr_valid = 60;
        d.add(1, "f", S_IFREG | 0o644, b"abc", "");
    });
    let count = |d: &std::rc::Rc<std::cell::RefCell<Daemon>>| d.borrow().ops().iter().filter(|&&o| o == tf::GETATTR).count();
    let ino = vfs_ino("/mnt/f/f");
    stat("/mnt/f/f").unwrap();
    let before = count(&d);
    stat("/mnt/f/f").unwrap();
    fuse::getattr(ino).unwrap();
    assert_eq!(count(&d), before, "cached attributes are used");
    // An INVAL_INODE notification for the node forgets them
    let id = d.borrow().find(1, b"f").unwrap();
    let mut n = Vec::new();
    n.extend_from_slice(&(16u32 + 24).to_le_bytes());
    n.extend_from_slice(&2i32.to_le_bytes());
    n.extend_from_slice(&0u64.to_le_bytes());
    n.extend_from_slice(&id.to_le_bytes());
    n.extend_from_slice(&[0u8; 16]);
    assert_eq!(d.borrow().write_raw(&n), 40);
    fuse::getattr(ino).unwrap();
    assert_eq!(count(&d), before + 1);
    // A notification for an unknown node changes nothing; another kind forgets all
    let mut n2 = n.clone();
    n2[16..24].copy_from_slice(&999u64.to_le_bytes());
    assert_eq!(d.borrow().write_raw(&n2), 40);
    let mut n3 = n.clone();
    n3[4..8].copy_from_slice(&3i32.to_le_bytes());
    assert_eq!(d.borrow().write_raw(&n3), 40);
    fuse::getattr(ino).unwrap();
    assert_eq!(count(&d), before + 2);
    // The clock passes the validity: asked again
    hydra_hosttests_t26::fake::arch::TICKS.set(hydra_hosttests_t26::fake::arch::TICKS.get() + 61_000);
    fuse::getattr(ino).unwrap();
    assert_eq!(count(&d), before + 3);
    // A write forgets the node's attributes
    fuse::write(ino, 0, b"z").unwrap();
    fuse::getattr(ino).unwrap();
    assert_eq!(count(&d), before + 4);
}

fn vfs_ino(path: &str) -> u64 {
    let fd = open(path, O_PATH);
    let i = vnode(fd).lock().ino;
    close(fd);
    i
}

#[test]
fn short_replies_and_errors() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"abc", "");
    });
    let ino = vfs_ino("/mnt/f/f");
    d.borrow_mut().short_attr = true;
    assert_eq!(fuse::getattr(ino).unwrap_err(), -5);
    d.borrow_mut().short_attr = false;
    d.borrow_mut().errors.insert(tf::OPEN, -13);
    let mut b = [0u8; 2];
    assert_eq!(fuse::read(ino, 0, &mut b).unwrap_err(), EACCES);
    // Write tries O_RDWR, then O_WRONLY: both refused
    assert_eq!(fuse::write(ino, 0, b"x").unwrap_err(), EACCES);
    assert_eq!(d.borrow().ops().iter().filter(|&&o| o == tf::OPEN).count(), 3);
    // A lookup reply without a node ID is ENOENT
    d.borrow_mut().errors.insert(tf::LOOKUP, 0);
    assert_eq!(fuse::lookup(vfs_ino("/mnt/f"), b"f").unwrap_err(), ENOENT);
}

#[test]
fn permission_of_the_mount_owner() {
    let _e = setup();
    let fd = tf::open_dev_fuse();
    let mut d = Daemon::new(fd);
    d.add(1, "f", S_IFREG | 0o644, b"x", "");
    let _d = d.install();
    // No allow_other: only the mounting user (uid 0 here) may use it
    assert_eq!(tf::mount(fd, "/mnt/p", ""), 0);
    assert!(stat("/mnt/p/f").is_ok());
    become_user(1000);
    assert_eq!(stat("/mnt/p/f").unwrap_err(), EACCES);
}

#[test]
fn mount_options_and_errors() {
    let _e = setup();
    let fd = tf::open_dev_fuse();
    let _d = Daemon::new(fd).install();
    memfs::mkdir_p("/mnt/o");
    let m = |data: &str, fstype: &str, flags: u64| {
        let a = [cstr("src"), cstr("/mnt/o"), cstr(fstype), flags, cstr(data), 0];
        lx::mount::dispatch(165, a).unwrap()
    };
    // Missing options; not a /dev/fuse descriptor; a bad descriptor
    assert_eq!(m("fd=3", "fuse", 0), EINVAL);
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(m(&format!("fd={},rootmode=40000,user_id=0,group_id=0", c), "fuse", 0), EBADF);
    assert_eq!(m("fd=99,rootmode=40000,user_id=0,group_id=0", "fuse", 0), EBADF);
    let dev: std::sync::Arc<dyn lx::chardev::CharDevice> = std::sync::Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let dfd = install(FileDescriptor::Device(dev));
    assert_eq!(m(&format!("fd={},rootmode=40000,user_id=0,group_id=0", dfd), "fuse", 0), EINVAL);
    // A good one, with flags shown in /proc/mounts
    assert_eq!(m(&format!("fd={},rootmode=40000,user_id=7,group_id=8,allow_other,other", fd), "fuse.sshfs", 1 | 2 | 4 | 8), 0);
    let text = fuse::ns0_mounts_text();
    assert_eq!(text, "src /mnt/o fuse.sshfs ro,nosuid,nodev,noexec,relatime,user_id=7,group_id=8,allow_other 0 0\n");
    let info = fuse::ns0_mountinfo_text();
    assert!(info.starts_with("4000 2069 0:"));
    assert!(info.contains(" /mnt/o ro,nosuid,nodev,noexec - fuse.sshfs src "));
    // Mounted once only
    assert_eq!(m(&format!("fd={},rootmode=40000,user_id=0,group_id=0", fd), "fuse", 0), EINVAL);
    // Not a directory; no data; no capability
    memfs::mkfile("/mnt/file", b"");
    let a = [cstr("src"), cstr("/mnt/file"), cstr("fuse"), 0, cstr("fd=1"), 0];
    assert_eq!(lx::mount::dispatch(165, a).unwrap(), ENOTDIR);
    let a = [cstr("src"), cstr("/mnt/o"), cstr("fuse"), 0, 0, 0];
    assert_eq!(lx::mount::dispatch(165, a).unwrap(), EINVAL);
    task::set_caps(0);
    let a = [cstr("src"), cstr("/mnt/o"), cstr("fuse"), 0, cstr("x"), 0];
    assert_eq!(lx::mount::dispatch(165, a).unwrap(), EPERM);
    assert!(fuse::is_fuse_type("fuse") && fuse::is_fuse_type("fuse.x") && !fuse::is_fuse_type("fusectl"));
}

#[test]
fn unmount_ends_the_connection() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"x", "");
    });
    assert!(fuse::ns0_any());
    let root = vfs_ino("/mnt/f");
    assert_eq!(fuse::ns0_mountpoint(root), memfs::lookup("/mnt/f"));
    assert_eq!(lx::mount::dispatch(166, [cstr("/mnt/f"), 0, 0, 0, 0, 0]).unwrap(), 0);
    assert!(!fuse::ns0_any());
    // The daemon reads ENODEV now
    let mut b = [0u8; 64];
    assert_eq!(d.borrow().dev.read(&mut b), -19);
    assert_eq!(d.borrow().dev.poll_events(), 0xC);
    assert_eq!(d.borrow().dev.write(&[0u8; 16]), EINVAL);
    // Operations on its inodes: ENOTCONN
    assert_eq!(fuse::getattr(root).unwrap_err(), -107);
    assert!(!fuse::ns0_remove(root));
}

#[test]
fn daemon_exit_aborts() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"x", "");
    });
    let ino = vfs_ino("/mnt/f/f");
    let fd = d.borrow().fd;
    task::wait::clear_on_wait();
    drop(d);
    close(fd); // the last reference to the device: the connection aborts
    assert_eq!(fuse::getattr(ino).unwrap_err(), -107);
}

#[test]
fn device_reads_and_writes() {
    let _e = setup();
    let fd = tf::open_dev_fuse();
    let dev = match desc(fd) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!(),
    };
    assert_eq!(dev.rdev(), fuse::RDEV);
    assert_eq!(dev.path(), "/dev/fuse");
    assert_eq!(dev.poll_events(), 0x4);
    // Nothing queued: EAGAIN when non-blocking, ERESTARTSYS on a signal, else it waits
    dev.set_nonblock(true);
    assert!(dev.nonblock());
    let mut b = [0u8; 256];
    assert_eq!(dev.read(&mut b), EAGAIN);
    dev.set_nonblock(false);
    lx::proc::SIGNAL.set(true);
    assert_eq!(dev.read_unlocked(&mut b), Some(-512));
    lx::proc::SIGNAL.set(false);
    // Mount queues INIT; a too small buffer is EINVAL
    let a = [cstr("s"), cstr("/mnt"), cstr("fuse"), 0, cstr(&format!("fd={},rootmode=40000,user_id=0,group_id=0", fd)), 0];
    memfs::mkdir_p("/mnt");
    assert_eq!(lx::mount::dispatch(165, a).unwrap(), 0);
    assert_eq!(dev.poll_events(), 0x5);
    let mut small = [0u8; 8];
    assert_eq!(dev.read(&mut small), EINVAL);
    let n = dev.read(&mut b);
    assert_eq!(n, 56);
    assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), tf::INIT);
    let unique = u64::from_le_bytes(b[8..16].try_into().unwrap());
    // Malformed replies
    assert_eq!(dev.write(&[0u8; 8]), EINVAL);
    let mut r = vec![0u8; 16];
    r[0..4].copy_from_slice(&20u32.to_le_bytes());
    assert_eq!(dev.write(&r), EINVAL); // length mismatch
    r[0..4].copy_from_slice(&16u32.to_le_bytes());
    r[4..8].copy_from_slice(&1i32.to_le_bytes());
    r[8..16].copy_from_slice(&5u64.to_le_bytes());
    assert_eq!(dev.write(&r), EINVAL); // positive error
    r[4..8].copy_from_slice(&0i32.to_le_bytes());
    assert_eq!(dev.write(&r), ENOENT); // no such request
    // An INIT reply of another major version aborts
    let mut init = Vec::new();
    init.extend_from_slice(&40u32.to_le_bytes());
    init.extend_from_slice(&0i32.to_le_bytes());
    init.extend_from_slice(&unique.to_le_bytes());
    for v in [6u32, 0, 0, 0, 0, 0] {
        init.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(dev.write(&init), 40);
    assert_eq!(dev.read(&mut b), -19);
}

#[test]
fn init_failures_abort() {
    let _e = setup();
    for (err, short) in [(-5i32, None), (0, Some(4usize))] {
        let fd = tf::open_dev_fuse();
        let mut d = Daemon::new(fd);
        if err != 0 {
            d.errors.insert(tf::INIT, err);
        }
        d.init_short = short;
        let d = d.install();
        let target = format!("/mnt/i{}", fd);
        assert_eq!(tf::mount(fd, &target, ""), 0);
        // The first request waits for INIT, which aborts the connection: ENOTCONN
        assert_eq!(stat(&format!("{}/x", target)).unwrap_err(), -107);
        drop(d);
        task::wait::clear_on_wait();
    }
}

#[test]
fn max_write_from_init() {
    let _e = setup();
    let d = mounted(|d| {
        d.max_write = 1 << 20; // clamped to 128 KiB
        d.add(1, "f", S_IFREG | 0o666, b"", "");
    });
    let ino = vfs_ino("/mnt/f/f");
    let before = d.borrow().ops().iter().filter(|&&o| o == tf::WRITE).count();
    assert_eq!(fuse::write(ino, 0, &vec![2u8; 200_000]).unwrap(), 200_000);
    assert_eq!(d.borrow().ops().iter().filter(|&&o| o == tf::WRITE).count() - before, 2);
}

#[test]
fn signals_interrupt_requests() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"x", "");
    });
    let ino = vfs_ino("/mnt/f/f");
    // A request the daemon read and holds: a signal then sends INTERRUPT, and the daemon
    // answers the held request with EINTR
    d.borrow_mut().hold.push(tf::GETATTR);
    let dd = d.clone();
    task::wait::on_wait(move || {
        dd.borrow_mut().serve();
        if !dd.borrow().held.is_empty() {
            lx::proc::SIGNAL.set(true);
        }
    });
    let r = fuse::getattr(ino);
    lx::proc::SIGNAL.set(false);
    assert_eq!(r.unwrap_err(), -4);
    assert!(d.borrow().ops().contains(&tf::INTERRUPT));
    d.borrow_mut().hold.clear();
    // A request still queued when the signal comes is taken back (no INTERRUPT)
    task::wait::clear_on_wait();
    lx::proc::SIGNAL.set(true);
    let before = d.borrow().seen.len();
    assert_eq!(fuse::getattr(ino).unwrap_err(), -4);
    lx::proc::SIGNAL.set(false);
    d.borrow_mut().serve();
    assert_eq!(d.borrow().seen.len(), before);
    // SIGKILL: no waiting at all
    lx::proc::SIGKILL.set(true);
    assert_eq!(fuse::getattr(ino).unwrap_err(), -4);
    lx::proc::SIGKILL.set(false);
    // The held one answered late is dropped quietly
    d.borrow_mut().hold.clear();
    d.borrow_mut().release_held();
}

#[test]
fn abort_while_waiting() {
    let _e = setup();
    let d = mounted(|d| {
        d.add(1, "f", S_IFREG | 0o644, b"x", "");
    });
    let ino = vfs_ino("/mnt/f/f");
    d.borrow_mut().hold.push(tf::GETATTR);
    let dd = d.clone();
    task::wait::on_wait(move || {
        dd.borrow_mut().serve();
        // The daemon dies with the request read
        if !dd.borrow().held.is_empty() {
            let c = dd.borrow().dev.as_fuse().unwrap();
            c.abort();
        }
    });
    assert_eq!(fuse::getattr(ino).unwrap_err(), -107);
}

#[test]
fn walk_and_names() {
    let _e = setup();
    let d = mounted(|d| {
        let a = d.add(1, "a", S_IFDIR | 0o755, &[], "");
        let b = d.add(a, "b", S_IFDIR | 0o755, &[], "");
        d.add(b, "file", S_IFREG | 0o644, b"f", "");
        d.add(1, "abs", S_IFLNK | 0o777, &[], "/etc");
        d.add(1, "loop", S_IFLNK | 0o777, &[], "loop");
    });
    let _ = d;
    let file = vfs_ino("/mnt/f/a/b/file");
    // name_of walks up by remembered names; the root has none
    let (dir, name) = fuse::name_of(file).unwrap();
    assert_eq!(name, b"file");
    let (dir2, name2) = fuse::name_of(dir).unwrap();
    assert_eq!(name2, b"b");
    assert!(fuse::name_of(vfs_ino("/mnt/f")).is_none());
    let _ = dir2;
    // getcwd inside the mount: the path through the mount point
    assert_eq!(sys(80, &[cstr("/mnt/f/a/b")]), 0);
    let cb = buf(64);
    let n = sys(79, &[cb, 64]);
    assert_eq!(read(cb, n as usize - 1), b"/mnt/f/a/b");
    // A link to an absolute path goes on from the root
    memfs::mkdir_p("/etc");
    assert_eq!(stat("/mnt/f/abs").unwrap().st_ino, memfs::lookup("/etc").unwrap());
    // A loop
    assert_eq!(stat("/mnt/f/loop").unwrap_err(), ELOOP);
    // dev and user inode numbers
    assert_eq!(fuse::dev(file) >> 8, 0);
    assert!(fuse::user_ino(file) > 1000);
    assert_eq!(fuse::ns0_mnt_of(file), 1);
    assert_eq!(fuse::ns0_mnt_of(5), 0);
    assert_eq!(fuse::ns0_list().len(), 1);
    // `..` inside the file system
    assert_eq!(fuse::lookup_attr(dir, b"..").unwrap().0, fuse::name_of(dir).unwrap().0);
    assert_eq!(fuse::lookup_attr(dir, b".").unwrap().0, dir);
    assert_eq!(fuse::lookup_attr(dir, b"").unwrap().0, dir);
}

#[test]
fn walk_through_nested_mounts() {
    let _e = setup();
    // A pool directory mounted inside the FUSE tree (mount list built by hand)
    let d = mounted(|d| {
        d.add(1, "inner", S_IFDIR | 0o755, &[], "");
    });
    let _ = d;
    let root = vfs_ino("/mnt/f");
    let inner = vfs_ino("/mnt/f/inner");
    let pooldir = memfs::mkdir_p("/elsewhere");
    let target = memfs::mkfile("/elsewhere/t", b"");
    let mp = memfs::lookup("/mnt/f").unwrap();
    let mounts = [(mp, root, 0usize), (inner, pooldir, 1usize)];
    let mut links = 0;
    match fuse::walk(root, 1, b"inner/t", true, &mounts, memfs::root(), 0, &mut links).unwrap() {
        fuse::Walk::Out(i, m, rest) => {
            assert_eq!((i, m), (pooldir, 2));
            assert_eq!(rest, b"t");
        }
        _ => panic!("should leave the FUSE file system"),
    }
    let _ = target;
    // `..` at the FUSE root leaves through the mount point
    match fuse::walk(root, 1, b"../x", true, &mounts, memfs::root(), 0, &mut links).unwrap() {
        fuse::Walk::Out(i, m, rest) => {
            assert_eq!((i, m), (mp, 0));
            assert_eq!(rest, b"../x");
        }
        _ => panic!(),
    }
    // `..` at the walk's root stays
    match fuse::walk(root, 1, b"..", true, &mounts, root, 1, &mut links).unwrap() {
        fuse::Walk::Done(i, _) => assert_eq!(i, root),
        _ => panic!(),
    }
}

/// Bug found by this crate (fixed): connection numbers wrapped after 16384 opens of
/// `/dev/fuse` and a new connection replaced a live one in the table, so the old file
/// system's inodes reached the new daemon's nodes; dead connections also stayed in the
/// table forever.
#[test]
fn connection_numbers_are_not_reused_while_alive() {
    let _e = setup();
    let a = fuse::open(0).unwrap();
    let ida = a.as_fuse().unwrap().id;
    for _ in 0..16400 {
        let x = fuse::open(0).unwrap();
        assert_ne!(x.as_fuse().unwrap().id, ida);
    }
    // A closed daemon's connection is gone: its root finds no connection
    let b = fuse::open(0).unwrap();
    let root = b.as_fuse().unwrap().root();
    drop(b);
    assert_eq!(fuse::getattr(root).unwrap_err(), -107);
    assert!(fuse::name_of(root + 5).is_none());
    assert_eq!(fuse::user_ino(root + 5), 6);
}
