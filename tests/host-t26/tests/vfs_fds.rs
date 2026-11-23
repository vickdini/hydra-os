//! vfs.rs: descriptor calls (dup, fcntl, close_range, lseek, getdents64, statfs, fsync,
//! fstat of every kind of descriptor).
mod common;
use common::*;
use std::sync::Arc;

#[test]
fn dup_family() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let fd = open("/f", O_RDONLY | O_CLOEXEC);
    let d = sys(32, &[fd as u64]);
    assert!(d > fd);
    assert!(Arc::ptr_eq(&vnode(fd), &vnode(d)));
    assert!(!task::with_current_fds_mut(|f| f.cloexec(d as usize)));
    assert_eq!(sys(32, &[500]), EBADF);
    assert_eq!(sys(33, &[fd as u64, 40]), 40);
    assert_eq!(sys(33, &[500, 41]), EBADF);
    // dup3: same fd is EINVAL; O_CLOEXEC sets the flag
    assert_eq!(sys(292, &[fd as u64, fd as u64, 0]), EINVAL);
    assert_eq!(sys(292, &[fd as u64, 50, O_CLOEXEC]), 50);
    assert!(task::with_current_fds_mut(|f| f.cloexec(50)));
    assert_eq!(sys(292, &[500, 51, 0]), EBADF);
    // A full table
    lx::limits::NOFILE.set(1);
    assert_eq!(sys(32, &[fd as u64]), -24);
}

#[test]
fn fcntl_descriptor_flags() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let fd = open("/f", O_RDWR) as u64;
    assert_eq!(sys(72, &[fd, 1, 0]), 0); // F_GETFD
    assert_eq!(sys(72, &[fd, 2, 1]), 0); // F_SETFD
    assert_eq!(sys(72, &[fd, 1, 0]), 1);
    let d = sys(72, &[fd, 0, 10]); // F_DUPFD
    assert_eq!(d, 10);
    let d2 = sys(72, &[fd, 1030, 10]); // F_DUPFD_CLOEXEC
    assert_eq!(d2, 11);
    assert!(task::with_current_fds_mut(|f| f.cloexec(11)));
    assert_eq!(sys(72, &[fd, 0, 5000]), EINVAL);
    assert_eq!(sys(72, &[999, 1, 0]), EBADF);
    // F_GETFL / F_SETFL of a pool file
    assert_eq!(sys(72, &[fd, 3, 0]), 2);
    assert_eq!(sys(72, &[fd, 4, O_APPEND | O_NONBLOCK | O_TRUNC]), 0);
    assert_eq!(sys(72, &[fd, 3, 0]), (2 | O_APPEND | O_NONBLOCK) as i64);
    // Unknown commands are not ours
    assert_eq!(sys_opt(72, &[fd, 9999, 0]), None);
}

#[test]
fn fcntl_status_flags_of_other_descriptors() {
    let _e = setup();
    // A by-name file
    let f = install(FileDescriptor::File { path: "/dev/null".into(), cursor: hydra_hosttests_t26::fs::FileCursor::new(0), readable: false, writable: true, append: false, shown: None });
    assert_eq!(sys(72, &[f as u64, 3, 0]), 1);
    assert_eq!(sys(72, &[f as u64, 4, O_APPEND]), 0);
    assert_eq!(sys(72, &[f as u64, 3, 0]), (1 | O_APPEND) as i64);
    let rw = install(FileDescriptor::file("/dev/zero"));
    assert_eq!(sys(72, &[rw as u64, 3, 0]), 2);
    let ro = install(FileDescriptor::File { path: "/dev/zero".into(), cursor: hydra_hosttests_t26::fs::FileCursor::new(0), readable: true, writable: false, append: false, shown: None });
    assert_eq!(sys(72, &[ro as u64, 3, 0]), 0);
    // A memfd keeps its flags
    let m = install(FileDescriptor::MemFd { memfd: lx::memfd::MemFd::new("m"), flags: 2 });
    assert_eq!(sys(72, &[m as u64, 4, O_NONBLOCK]), 0);
    assert_eq!(sys(72, &[m as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    // An internet socket
    let s = Arc::new(spin::Mutex::new(lx::inet::InetSocket::default()));
    let sfd = install(FileDescriptor::Inet(s.clone()));
    assert_eq!(sys(72, &[sfd as u64, 4, O_NONBLOCK]), 0);
    assert!(s.lock().nonblock);
    assert_eq!(sys(72, &[sfd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    // The console
    let c = install(FileDescriptor::ConsoleOut);
    assert_eq!(sys(72, &[c as u64, 4, O_NONBLOCK]), 0);
    assert!(lx::tty::nonblock());
    assert_eq!(sys(72, &[c as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    // eventfd, timerfd (wave9 G9-C: inotify instances are vfs-server's)
    let e = lx::eventfd::EventFd::new(0);
    let efd = install(FileDescriptor::EventFd(e.clone()));
    assert_eq!(sys(72, &[efd as u64, 4, O_NONBLOCK]), 0);
    assert!(e.lock().nonblocking);
    assert_eq!(sys(72, &[efd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    let t = Arc::new(lx::timerfd::TimerFd::default());
    let tfd = install(FileDescriptor::TimerFd(t.clone()));
    assert_eq!(sys(72, &[tfd as u64, 4, O_NONBLOCK]), 0);
    assert!(t.get_nonblock());
    assert_eq!(sys(72, &[tfd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    // A device, a Unix socket, a signalfd, a pty
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let dfd = install(FileDescriptor::Device(d.clone()));
    assert_eq!(sys(72, &[dfd as u64, 4, O_NONBLOCK]), 0);
    assert!(d.nonblock());
    assert_eq!(sys(72, &[dfd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    let u = lx::unix::UnixSocket::new(3);
    let ufd = install(FileDescriptor::Unix(u.clone()));
    assert_eq!(sys(72, &[ufd as u64, 4, O_NONBLOCK]), 0);
    assert_eq!(sys(72, &[ufd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    let sg = Arc::new(lx::signalfd::SignalFd::default());
    let sgfd = install(FileDescriptor::SignalFd(sg.clone()));
    assert_eq!(sys(72, &[sgfd as u64, 4, O_NONBLOCK]), 0);
    assert_eq!(sys(72, &[sgfd as u64, 3, 0]), O_NONBLOCK as i64);
    let p = lx::pty::PtyFile::named("/dev/pts/0", false);
    let pfd = install(FileDescriptor::Pty(p.clone()));
    assert_eq!(sys(72, &[pfd as u64, 4, O_NONBLOCK]), 0);
    assert_eq!(sys(72, &[pfd as u64, 3, 0]), (2 | O_NONBLOCK) as i64);
    // Pipe ends: the write end reports O_WRONLY
    let pipe = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(pipe.clone()));
    let w = install(FileDescriptor::PipeWrite(pipe.clone()));
    assert_eq!(sys(72, &[w as u64, 4, O_NONBLOCK]), 0);
    assert!(pipe.lock().write_nonblock && !pipe.lock().read_nonblock);
    assert_eq!(sys(72, &[w as u64, 3, 0]), (1 | O_NONBLOCK) as i64);
    assert_eq!(sys(72, &[r as u64, 3, 0]), 0);
    // A legacy socket has no flags here
    let so = install(FileDescriptor::Socket(Arc::new(spin::Mutex::new(Default::default()))));
    assert_eq!(sys_opt(72, &[so as u64, 3, 0]), None);
    assert_eq!(sys_opt(72, &[so as u64, 4, 0]), None);
}

#[test]
fn fcntl_seals_and_server_pipes() {
    let _e = setup();
    let m = lx::memfd::MemFd::new("m");
    let fd = install(FileDescriptor::MemFd { memfd: m.clone(), flags: 2 }) as u64;
    assert_eq!(sys(72, &[fd, 1034, 0]), 0);
    assert_eq!(sys(72, &[fd, 1033, 0x8]), 0);
    assert_eq!(sys(72, &[fd, 1034, 0]), 0x8);
    assert_eq!(sys(72, &[fd, 1033, 0x1]), 0); // F_SEAL_SEAL
    assert_eq!(sys(72, &[fd, 1033, 0x2]), EPERM);
    assert_eq!(sys(72, &[fd, 1033, 0x8]), 0); // already set: fine
    memfs::mkfile("/f", b"");
    let ffd = open("/f", O_RDONLY) as u64;
    assert_eq!(sys(72, &[ffd, 1034, 0]), EINVAL);
    assert_eq!(sys(72, &[ffd, 1033, 1]), EINVAL);
    // F_GETPIPE_SZ on a linux-server pipe goes to the server
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::server(16, Some(1)));
    let sfd = install(FileDescriptor::Device(d)) as u64;
    hydra_hosttests_t26::fake::lx::ANSWER.set(65536);
    assert_eq!(sys(72, &[sfd, 1032, 0]), 65536);
    assert_eq!(hydra_hosttests_t26::fake::lx::calls()[0], (0x6782, [sfd, 1032, 0, 0, 0, 0]));
}

#[test]
fn fcntl_record_locks_go_to_locks() {
    let _e = setup();
    memfs::mkfile("/f", b"0123456789");
    let fd = open("/f", O_RDWR) as u64;
    let fl = buf(32);
    write(fl, &[1u8, 0, 0, 0]); // F_WRLCK, SEEK_SET, start 0, len 0
    assert_eq!(sys(72, &[fd, 6, fl]), 0);
    // An OFD lock conflicts with the process's POSIX lock (another owner)
    assert_eq!(sys(72, &[fd, 37, fl]), EAGAIN);
}

#[test]
fn close_range_call() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let fds: Vec<i64> = (0..5).map(|_| open("/f", O_RDONLY)).collect();
    assert_eq!(sys(436, &[fds[1] as u64, fds[2] as u64, 4]), 0); // CLOEXEC
    assert!(task::with_current_fds_mut(|f| f.cloexec(fds[1] as usize) && f.cloexec(fds[2] as usize) && !f.cloexec(fds[3] as usize)));
    assert_eq!(sys(436, &[fds[3] as u64, u32::MAX as u64, 0]), 0);
    assert!(desc(fds[3]).is_none() && desc(fds[4]).is_none());
    assert!(desc(fds[2]).is_some());
    assert_eq!(sys(436, &[5, 4, 0]), EINVAL);
    assert_eq!(sys(436, &[0, 4, 1]), EINVAL);
}

#[test]
fn lseek_files_and_directories() {
    let _e = setup();
    memfs::mkfile("/f", b"0123456789");
    let fd = open("/f", O_RDONLY) as u64;
    assert_eq!(sys(8, &[fd, 4, 0]), 4);
    assert_eq!(sys(8, &[fd, 2, 1]), 6);
    assert_eq!(sys(8, &[fd, (-3i64) as u64, 2]), 7);
    assert_eq!(sys(8, &[fd, (-30i64) as u64, 0]), EINVAL);
    assert_eq!(sys(8, &[fd, 3, 3]), 3); // SEEK_DATA
    assert_eq!(sys(8, &[fd, 10, 3]), -6);
    assert_eq!(sys(8, &[fd, 3, 4]), 10); // SEEK_HOLE
    assert_eq!(sys(8, &[fd, 11, 4]), -6);
    assert_eq!(sys(8, &[fd, 0, 9]), EINVAL);
    // A directory: only rewinds and telldir cookies
    memfs::mkdir_p("/d");
    let dfd = open("/d", O_RDONLY) as u64;
    assert_eq!(sys(8, &[dfd, 5, 0]), 5);
    assert_eq!(sys(8, &[dfd, 0, 1]), 5);
    assert_eq!(sys(8, &[dfd, 1, 1]), EINVAL);
    assert_eq!(sys(8, &[dfd, 0, 2]), EINVAL);
    // A device with positions; one without; something else
    let mut dev = lx::chardev::TestDev::new("/proc/1/mem", 0);
    dev.seek_result = Some(4096);
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(dev);
    let devfd = install(FileDescriptor::Device(d)) as u64;
    assert_eq!(sys(8, &[devfd, 4096, 0]), 4096);
    let d2: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let devfd2 = install(FileDescriptor::Device(d2)) as u64;
    assert_eq!(sys_opt(8, &[devfd2, 0, 0]), None);
    // A file whose inode went away
    memfs::with(|fs| fs.inodes.remove(&vnode(fd as i64).lock().ino));
    assert_eq!(sys(8, &[fd, 0, 0]), ENOENT);
}

#[test]
fn getdents_lists_a_directory() {
    let _e = setup();
    memfs::mkdir_p("/d/sub");
    memfs::mkfile("/d/a", b"");
    memfs::mklink("/d/l", "a");
    let fd = open("/d", O_RDONLY | O_DIRECTORY);
    let names = list_dir(fd);
    assert_eq!(names, vec![".", "..", "a", "l", "sub"]);
    // Again at the end: 0
    assert_eq!(sys(217, &[fd as u64, buf(4096), 4096]), 0);
    // Rewind and read with a tiny buffer: EINVAL
    sys(8, &[fd as u64, 0, 0]);
    assert_eq!(sys(217, &[fd as u64, buf(8), 8]), EINVAL);
    // Record layout: d_ino, d_off, reclen, type
    let b = buf(4096);
    let n = sys(217, &[fd as u64, b, 4096]);
    let data = read(b, n as usize);
    let reclen = u16::from_le_bytes([data[16], data[17]]) as usize;
    assert_eq!(reclen, 24);
    assert_eq!(data[18], 4); // DT_DIR for "."
    assert_eq!(i64::from_le_bytes(data[8..16].try_into().unwrap()), 1);
    // Bad descriptors
    assert_eq!(sys(217, &[(-1i64) as u64, b, 4096]), EBADF);
    assert_eq!(sys(217, &[300, b, 4096]), EBADF);
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(sys(217, &[c as u64, b, 4096]), ENOTDIR);
    memfs::mkfile("/file", b"");
    let ffd = open("/file", O_RDONLY);
    assert_eq!(sys(217, &[ffd as u64, b, 4096]), ENOTDIR);
    // A bad buffer
    sys(8, &[fd as u64, 0, 0]);
    assert_eq!(sys(217, &[fd as u64, 16, 4096]), EFAULT);
    memfs::fail("readdir", -5);
    assert_eq!(sys(217, &[fd as u64, b, 4096]), -5);
}

#[test]
fn getdents_of_proc() {
    let _e = setup();
    let pd = memfs::mkdir_p("/proc");
    let _ = pd;
    task::add_process(400, 0);
    let fd = open("/proc", O_RDONLY | O_DIRECTORY);
    let names = list_dir(fd);
    assert!(names.contains(&"self".to_string()));
    assert!(names.contains(&"thread-self".to_string()));
    assert!(names.contains(&"cpuinfo".to_string()));
    assert!(names.contains(&"net".to_string()));
    assert!(names.contains(&"400".to_string()));
    assert!(names.contains(&format!("{}", task::SELF_PID)));
    assert!(!names.contains(&"kmsg".to_string()));
    // A small buffer that holds nothing
    sys(8, &[fd as u64, 0, 0]);
    assert_eq!(sys(217, &[fd as u64, buf(8), 8]), EINVAL);
    assert_eq!(sys(217, &[fd as u64, 16, 4096]), EFAULT);
}

#[test]
fn getdents_of_proc_directories() {
    let _e = setup();
    lx::proc::with(task::SELF_PID, |p| p.threads = vec![task::SELF_PID, 101]);
    // /proc/self
    let fd = open("/proc/self", O_RDONLY);
    let names = list_dir(fd);
    assert!(names.contains(&"fd".to_string()) && names.contains(&"exe".to_string()) && names.contains(&"mountinfo".to_string()));
    // /proc/self/task
    let fd = open("/proc/self/task", O_RDONLY);
    assert_eq!(list_dir(fd), vec![".", "..", "100", "101"]);
    // /proc/self/ns
    let fd = open("/proc/self/ns", O_RDONLY);
    let ns = list_dir(fd);
    assert_eq!(ns.len(), 10);
    assert!(ns.contains(&"pid_for_children".to_string()));
    // /proc/self/fd: the open descriptors
    let fd = open("/proc/self/fd", O_RDONLY);
    let open_fds = list_dir(fd);
    assert!(open_fds.contains(&format!("{}", fd)));
    // Another process's descriptors
    let other = task::add_process(410, 0);
    other.lock().alloc_fd(FileDescriptor::ConsoleIn).unwrap();
    other.lock().alloc_fd(FileDescriptor::ConsoleOut).unwrap();
    let fd = open("/proc/410/fd", O_RDONLY);
    assert_eq!(list_dir(fd), vec![".", "..", "0", "1"]);
    lx::extra::deny(410);
    let fd = open("/proc/410/fd", O_RDONLY);
    assert_eq!(list_dir(fd), vec![".", ".."]);
    // Small buffer; a bad buffer
    let fd = open("/proc/self/task", O_RDONLY);
    assert_eq!(sys(217, &[fd as u64, buf(8), 8]), EINVAL);
    assert_eq!(sys(217, &[fd as u64, 16, 4096]), EFAULT);
}

#[test]
fn proc_directory_as_dirfd() {
    let _e = setup();
    let fd = open("/proc/self/fd", O_RDONLY);
    // Lookups relative to a /proc directory descriptor find nothing in the pool
    assert_eq!(fstatat(fd as u64, "999", 0).unwrap_err(), ENOENT);
    // ... but its own entries are the descriptors
    assert!(fstatat(fd as u64, &format!("{}", fd), 0).is_ok());
}

#[test]
fn statfs_reports_the_file_system() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let b = buf(120);
    assert_eq!(sys(137, &[cstr("/f"), b]), 0);
    let v = read(b, 120);
    let q = |i: usize| i64::from_le_bytes(v[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(q(0), 0x2fc1_2fc1);
    assert_eq!(q(1), 4096);
    assert_eq!(q(2), 1_000_000);
    assert_eq!(q(3), 500_000);
    assert_eq!(i32::from_le_bytes(v[56..60].try_into().unwrap()), lx::fanotify::POOL_FSID[0]);
    assert_eq!(q(8), 255);
    let magic = |p: &str| {
        assert_eq!(sys(137, &[cstr(p), b]), 0);
        i64::from_le_bytes(read(b, 8).try_into().unwrap())
    };
    assert_eq!(magic("/proc/self/status"), 0x9fa0);
    assert_eq!(magic("/dev/pts/0"), 0x1cd1);
    assert_eq!(magic("/dev/ptmx"), 0x1cd1);
    assert_eq!(magic("/sys/class"), 0x6265_6572);
    assert_eq!(magic("/sys/fs/cgroup/x"), 0x6367_7270);
    assert_eq!(magic("/sys/firmware/efi/efivars"), 0xde5e_81e4);
    assert_eq!(sys(137, &[cstr(""), b]), ENOENT);
    assert_eq!(sys(137, &[cstr("/f"), 16]), EFAULT);
    hydra_hosttests_t26::fake::zfs_server::UP.set(false);
    assert_eq!(sys(137, &[cstr("/f"), b]), -5);
}

#[test]
fn fstatfs_by_descriptor_kind() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let b = buf(120);
    let magic = |fd: i64| {
        assert_eq!(sys(138, &[fd as u64, b]), 0);
        i64::from_le_bytes(read(b, 8).try_into().unwrap())
    };
    assert_eq!(magic(open("/f", O_RDONLY)), 0x2fc1_2fc1);
    assert_eq!(magic(install(FileDescriptor::Pty(lx::pty::PtyFile::named("/dev/ptmx", false)))), 0x1cd1);
    assert_eq!(magic(install(FileDescriptor::file("/proc/version"))), 0x9fa0);
    assert_eq!(magic(install(FileDescriptor::ConsoleIn)), 0x2fc1_2fc1);
    assert_eq!(sys(138, &[900, b]), EBADF);
}

#[test]
fn sync_calls() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    assert_eq!(sys(162, &[]), 0);
    assert_eq!(hydra_hosttests_t26::fake::counter("sync"), 1);
    assert_eq!(hydra_hosttests_t26::fake::counter("blockdev_flush"), 1);
    let fd = open("/f", O_RDWR) as u64;
    assert_eq!(sys(74, &[fd]), 0);
    assert_eq!(sys(75, &[fd]), 0);
    assert_eq!(sys(74, &[(-1i64) as u64]), EBADF);
    assert_eq!(sys(74, &[333]), EBADF);
    // A pipe has no fsync; syncfs takes it
    let p = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    let pfd = install(FileDescriptor::PipeRead(p)) as u64;
    assert_eq!(sys(74, &[pfd]), EINVAL);
    assert_eq!(sys(306, &[pfd]), 0);
    // A device with its own fsync
    let mut dev = lx::chardev::TestDev::new("/dev/sda", 0);
    dev.fsync_result = Some(-5);
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(dev);
    let dfd = install(FileDescriptor::Device(d)) as u64;
    assert_eq!(sys(74, &[dfd]), -5);
    // A failed write-back
    memfs::fail("sync", -5);
    assert_eq!(sys(74, &[fd]), -5);
}

#[test]
fn fstat_of_every_kind() {
    let _e = setup();
    use lx::types::LinuxStat;
    let check = |fd: i64| -> LinuxStat { fstat(fd).unwrap() };
    memfs::mkfile("/f", b"abc");
    assert_eq!(check(open("/f", O_RDONLY)).st_size, 3);
    assert_eq!(check(install(FileDescriptor::file("/dev/null"))).st_mode, 0o020666);
    assert_eq!(check(install(FileDescriptor::Pty(lx::pty::PtyFile::named("/dev/ptmx", false)))).st_dev, lx::pty::PTS_DEV);
    let u = check(install(FileDescriptor::Unix(lx::unix::UnixSocket::new(42))));
    assert_eq!((u.st_ino, u.st_mode), (42, 0o140777));
    assert_eq!(check(install(FileDescriptor::Socket(Arc::new(spin::Mutex::new(Default::default()))))).st_mode, 0o140777);
    assert_eq!(check(install(FileDescriptor::ConsoleErr)).st_ino, 0x401);
    let m = lx::memfd::MemFd::new("m");
    m.lock().write_at(0, &[1u8; 1000]);
    let ms = check(install(FileDescriptor::MemFd { memfd: m, flags: 0 }));
    assert_eq!((ms.st_mode, ms.st_size, ms.st_blocks), (0o100444, 1000, 2));
    let mw = check(install(FileDescriptor::MemFd { memfd: lx::memfd::MemFd::new("w"), flags: 2 }));
    assert_eq!(mw.st_mode, 0o100666);
    let p = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    assert_eq!(check(install(FileDescriptor::PipeWrite(p))).st_mode, 0o010600);
    assert_eq!(check(install(FileDescriptor::Inet(Arc::new(spin::Mutex::new(Default::default()))))).st_mode, 0o140777);
    for d in [
        FileDescriptor::EventFd(lx::eventfd::EventFd::new(0)),
        FileDescriptor::Epoll(Arc::new(spin::Mutex::new(Default::default()))),
        FileDescriptor::SignalFd(Arc::new(Default::default())),
        FileDescriptor::TimerFd(Arc::new(Default::default())),
        FileDescriptor::PidFd(Arc::new(lx::pidfd::PidFd { pid: 3 })),
    ] {
        let st = check(install(d));
        assert_eq!(st.st_mode, 0o600);
        assert_eq!(st.st_dev, 0xd);
    }
    // A device reports its own stat
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    assert_eq!(check(install(FileDescriptor::Device(d))).st_mode, 0);
    assert_eq!(fstat(-1).unwrap_err(), EBADF);
    assert_eq!(fstat(700).unwrap_err(), EBADF);
    // A by-name file that is not a pseudo file is not ours
    let x = install(FileDescriptor::file("/not/pseudo"));
    assert_eq!(sys_opt(5, &[x as u64, buf(256)]), None);
    // Anonymous objects are owned by the caller
    become_user(1000);
    let st = check(install(FileDescriptor::EventFd(lx::eventfd::EventFd::new(0))));
    assert_eq!((st.st_uid, st.st_gid), (1000, 1000));
}
