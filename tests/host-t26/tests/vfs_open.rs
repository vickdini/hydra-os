//! vfs.rs: `open` (flags, creation, permissions, special files).
mod common;
use common::*;

#[test]
fn create_applies_umask_and_owner() {
    let _e = setup();
    memfs::mkdir_p("/tmp");
    memfs::chmod(memfs::lookup("/tmp").unwrap(), 0o777);
    become_user(1000);
    let fd = openat(AT_FDCWD, "/tmp/new", O_CREAT | O_WRONLY, 0o666);
    assert!(fd >= 0, "{}", fd);
    let ino = memfs::lookup("/tmp/new").unwrap();
    let a = memfs::attr(ino);
    assert_eq!(a.mode, 0o100644);
    assert_eq!((a.uid, a.gid), (1000, 1000));
    // creat(path, 0444) still returns a writable descriptor
    let fd2 = sys(85, &[cstr("/tmp/ro"), 0o444]);
    assert!(fd2 >= 0);
    assert!(vnode(fd2).lock().writable());
    assert_eq!(memfs::attr(memfs::lookup("/tmp/ro").unwrap()).mode, 0o100444);
    // The open file records the path, offset 0, the access mode
    let f = vnode(fd);
    let f = f.lock();
    assert_eq!(f.path, "/tmp/new");
    assert_eq!(f.flags & 3, 1);
    assert!(!f.is_dir);
    assert_eq!(memfs::refs(ino), 1);
}

#[test]
fn create_flags() {
    let _e = setup();
    memfs::mkfile("/f", b"data");
    memfs::mkdir_p("/d");
    assert_eq!(openat(AT_FDCWD, "/f", O_CREAT | O_EXCL | O_WRONLY, 0o600), EEXIST);
    assert!(openat(AT_FDCWD, "/f", O_CREAT | O_WRONLY, 0o600) >= 0);
    // A trailing slash names a directory, which O_CREAT does not make
    assert_eq!(openat(AT_FDCWD, "/g/", O_CREAT | O_WRONLY, 0o600), EISDIR);
    // Missing parent
    assert_eq!(openat(AT_FDCWD, "/none/g", O_CREAT | O_WRONLY, 0o600), ENOENT);
    // O_TMPFILE is not supported
    assert_eq!(openat(AT_FDCWD, "/d", 0o20200000 | O_RDWR, 0o600), EOPNOTSUPP);
    // O_CREAT through a dangling symlink creates its target
    memfs::mklink("/d/link", "target");
    let fd = openat(AT_FDCWD, "/d/link", O_CREAT | O_WRONLY, 0o600);
    assert!(fd >= 0, "{}", fd);
    assert!(memfs::lookup("/d/target").is_some());
    // ... but not with O_EXCL (the link itself exists)
    memfs::mklink("/d/link2", "target2");
    assert_eq!(openat(AT_FDCWD, "/d/link2", O_CREAT | O_EXCL | O_WRONLY, 0o600), EEXIST);
    // An absolute dangling target
    memfs::mklink("/d/link3", "/d/abs-target");
    assert!(openat(AT_FDCWD, "/d/link3", O_CREAT | O_WRONLY, 0o600) >= 0);
    assert!(memfs::lookup("/d/abs-target").is_some());
    // A creation loop
    memfs::mklink("/d/l1", "l2");
    memfs::mklink("/d/l2", "l1");
    assert_eq!(openat(AT_FDCWD, "/d/l1", O_CREAT | O_WRONLY, 0o600), ELOOP);
}

#[test]
fn file_type_checks() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    memfs::mkdir_p("/d");
    memfs::mklink("/l", "/f");
    assert_eq!(open("/f", O_RDONLY | O_DIRECTORY), ENOTDIR);
    assert_eq!(open("/d", O_WRONLY), EISDIR);
    assert_eq!(open("/d", O_RDWR), EISDIR);
    let dfd = open("/d", O_RDONLY);
    assert!(vnode(dfd).lock().is_dir);
    assert_eq!(open("/l", O_RDONLY | O_NOFOLLOW), ELOOP);
    // O_PATH opens the link itself
    let p = open("/l", O_PATH | O_NOFOLLOW);
    assert!(p >= 0);
    assert_eq!(vnode(p).lock().ino, memfs::lookup("/l").unwrap());
    assert!(!vnode(p).lock().readable());
}

#[test]
fn truncate_and_cloexec_flags() {
    let _e = setup();
    let ino = memfs::mkfile("/f", b"0123456789");
    let fd = open("/f", O_WRONLY | O_TRUNC | O_CLOEXEC);
    assert!(fd >= 0);
    assert_eq!(memfs::data(ino).len(), 0);
    assert!(task::with_current_fds_mut(|f| f.cloexec(fd as usize)));
    // O_TRUNC with O_RDONLY does not truncate (but asks for write permission)
    memfs::with(|fs| fs.write(ino, 0, b"abc").unwrap());
    let fd2 = open("/f", O_RDONLY | O_TRUNC);
    assert!(fd2 >= 0);
    assert_eq!(memfs::data(ino).len(), 3);
    // Kept flags
    let fd3 = open("/f", O_RDWR | O_APPEND | O_NONBLOCK | O_CREAT);
    assert_eq!(vnode(fd3).lock().flags, (O_RDWR | O_APPEND | O_NONBLOCK) as u32);
}

#[test]
fn permission_checks_on_open() {
    let _e = setup();
    let secret = memfs::mkfile("/secret", b"s");
    memfs::chmod(secret, 0o600);
    let mine = memfs::mkfile("/mine", b"m");
    memfs::chown(mine, 1000, 1000);
    memfs::chmod(mine, 0o400);
    let ro_dir = memfs::mkdir_p("/rodir");
    memfs::chmod(ro_dir, 0o755);
    become_user(1000);
    assert_eq!(open("/secret", O_RDONLY), EACCES);
    assert!(open("/mine", O_RDONLY) >= 0);
    assert_eq!(open("/mine", O_WRONLY), EACCES);
    assert_eq!(open("/mine", O_RDONLY | O_TRUNC), EACCES);
    assert_eq!(openat(AT_FDCWD, "/rodir/x", O_CREAT | O_WRONLY, 0o600), EACCES);
    // The path is noted for access policies either way
    assert!(lx::abac::NOTED.with_borrow(|n| n.iter().any(|(i, p)| *i == secret && p == "/secret")));
    // Group and other bits
    let g = memfs::mkfile("/grp", b"g");
    memfs::chown(g, 0, 1000);
    memfs::chmod(g, 0o640);
    assert!(open("/grp", O_RDONLY) >= 0);
    let o = memfs::mkfile("/oth", b"o");
    memfs::chmod(o, 0o604);
    assert!(open("/oth", O_RDONLY) >= 0);
    // A supplementary group
    let s = memfs::mkfile("/supp", b"x");
    memfs::chown(s, 0, 2000);
    memfs::chmod(s, 0o060);
    assert_eq!(open("/supp", O_RDONLY), EACCES);
    lx::proc::with(task::SELF_PID, |p| p.groups.push(2000));
    assert!(open("/supp", O_RDWR) >= 0);
}

#[test]
fn root_and_execute_permission() {
    let _e = setup();
    let f = memfs::mkfile("/noexec", b"#!");
    memfs::chmod(f, 0o644);
    let d = memfs::mkdir_p("/dir");
    memfs::chmod(d, 0o000);
    // root reads and writes anything
    memfs::chmod(f, 0o000);
    assert!(open("/noexec", O_RDWR) >= 0);
    // ... and searches any directory
    memfs::mkfile("/dir/x", b"");
    assert!(stat("/dir/x").is_ok());
    // execute needs an x bit (access(X_OK))
    assert_eq!(sys(21, &[cstr("/noexec"), 1]), EACCES);
    memfs::chmod(f, 0o100);
    assert_eq!(sys(21, &[cstr("/noexec"), 1]), 0);
}

#[test]
fn access_policies_take_away() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chmod(f, 0o666);
    become_user(1000);
    lx::abac::policy(true, false);
    assert_eq!(open("/f", O_RDONLY), EACCES);
}

#[test]
fn landlock_on_open() {
    let _e = setup();
    memfs::mkfile("/f", b"abc");
    memfs::mkdir_p("/d");
    lx::landlock::refuse(lx::landlock::WRITE_FILE);
    assert!(open("/f", O_RDONLY) >= 0);
    assert_eq!(open("/f", O_WRONLY), EACCES);
    // Making a file needs MAKE_REG
    lx::landlock::refuse(lx::landlock::MAKE_REG);
    assert_eq!(openat(AT_FDCWD, "/d/new", O_CREAT | O_WRONLY, 0o600), EACCES);
    // TRUNCATE refused: open works, ftruncate later fails
    lx::landlock::refuse(lx::landlock::TRUNCATE);
    let fd = open("/f", O_WRONLY);
    assert!(fd >= 0);
    assert!(vnode(fd).lock().no_truncate);
    assert_eq!(sys(77, &[fd as u64, 0]), EACCES);
    assert_eq!(open("/f", O_WRONLY | O_TRUNC), EACCES);
    // Files outside the pool are checked too
    lx::landlock::refuse(lx::landlock::READ_FILE);
    assert_eq!(open("/proc/version", O_RDONLY), EACCES);
    lx::landlock::refuse(lx::landlock::READ_DIR);
    assert_eq!(open("/d", O_RDONLY), EACCES);
}

#[test]
fn pseudo_files_open_by_name() {
    let _e = setup();
    let fd = open("/dev/null", O_RDWR);
    match desc(fd) {
        Some(FileDescriptor::File { path, readable, writable, shown, .. }) => {
            assert_eq!(path, "/dev/null");
            assert!(readable && writable);
            assert!(shown.is_none());
        }
        _ => panic!(),
    }
    let ro = open("/proc/version", O_RDONLY);
    match desc(ro) {
        Some(FileDescriptor::File { readable, writable, .. }) => assert!(readable && !writable),
        _ => panic!(),
    }
    // cgroup.procs: only root may write
    become_user(1000);
    assert_eq!(open("/sys/fs/cgroup/cgroup.procs", O_WRONLY), EACCES);
    assert!(open("/sys/fs/cgroup/cgroup.procs", O_RDONLY) >= 0);
}

#[test]
fn device_control_on_named_devices() {
    let _e = setup();
    lx::bpf::deny(lx::bpf::DEV_CHAR, 1, 3);
    assert_eq!(open("/dev/null", O_RDONLY), EPERM);
    assert!(open("/dev/zero", O_RDONLY) >= 0);
    let checks = lx::bpf::CHECKS.with_borrow(|c| c.clone());
    assert!(checks.contains(&(lx::bpf::DEV_CHAR, 1, 5, lx::bpf::DEV_READ)));
}

#[test]
fn per_process_proc_files_are_captured() {
    let _e = setup();
    let fd = open("/proc/self/comm", O_RDONLY);
    match desc(fd) {
        Some(FileDescriptor::MemFd { memfd, flags }) => {
            assert_eq!(flags, 0);
            assert_eq!(memfd.lock().data, b"test-program\n");
        }
        _ => panic!("not captured"),
    }
    // A process that does not exist
    assert_eq!(open("/proc/999/comm", O_RDONLY), ENOENT);
    assert_eq!(open("/proc/999/stat", O_RDONLY), ENOENT);
}

#[test]
fn magic_links_reopen() {
    let _e = setup();
    let ino = memfs::mkfile("/f", b"x");
    let fd = open("/f", O_RDONLY);
    let again = open(&format!("/proc/self/fd/{}", fd), O_RDONLY);
    assert!(again >= 0);
    assert_eq!(vnode(again).lock().ino, ino);
    assert!(!std::sync::Arc::ptr_eq(&vnode(fd), &vnode(again)));
    // Through /proc/<own pid>/fd/N and /dev/fd/N
    assert!(open(&format!("/proc/{}/fd/{}", task::SELF_PID, fd), O_RDONLY) >= 0);
    // /proc/self/exe opens the executable
    let exe = memfs::mkfile("/usr/bin/test-program", b"\x7fELF");
    let efd = open("/proc/self/exe", O_RDONLY);
    assert_eq!(vnode(efd).lock().ino, exe);
}

#[test]
fn reopen_pipes_and_memfds() {
    let _e = setup();
    let pipe = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(pipe.clone()));
    let readers = pipe.lock().readers_count();
    let w = open(&format!("/dev/fd/{}", r), O_WRONLY);
    assert!(matches!(desc(w), Some(FileDescriptor::PipeWrite(_))));
    let r2 = open(&format!("/proc/self/fd/{}", r), O_RDONLY);
    assert!(matches!(desc(r2), Some(FileDescriptor::PipeRead(_))));
    assert_eq!(pipe.lock().readers_count(), readers + 1);
    // A memfd reopens with the new flags
    let m = lx::memfd::MemFd::new("buf");
    let mfd = install(FileDescriptor::MemFd { memfd: m.clone(), flags: 0 });
    let again = open(&format!("/proc/self/fd/{}", mfd), O_RDWR);
    match desc(again) {
        Some(FileDescriptor::MemFd { memfd, flags }) => {
            assert!(std::sync::Arc::ptr_eq(&memfd, &m));
            assert_eq!(flags, O_RDWR as u32);
        }
        _ => panic!(),
    }
    // A linux-server pipe: the server makes the new end
    let dev: std::sync::Arc<dyn lx::chardev::CharDevice> = std::sync::Arc::new(lx::chardev::TestDev::server(16, Some(4)));
    let sfd = install(FileDescriptor::Device(dev));
    hydra_hosttests_t26::fake::lx::ANSWER.set(9);
    assert_eq!(open(&format!("/proc/self/fd/{}", sfd), O_RDONLY), 9);
    assert_eq!(hydra_hosttests_t26::fake::lx::calls()[0].0, 0x6780);
    hydra_hosttests_t26::fake::lx::ANSWER.set(-24);
    assert_eq!(open(&format!("/proc/self/fd/{}", sfd), O_RDONLY), -24);
}

#[test]
fn proc_mem_opens_a_device() {
    let _e = setup();
    let fd = open("/proc/self/mem", O_RDWR);
    match desc(fd) {
        Some(FileDescriptor::Device(d)) => assert_eq!(d.path(), format!("/proc/{}/mem", task::SELF_PID)),
        _ => panic!(),
    }
    assert!(open(&format!("/proc/self/task/{}/mem", task::SELF_PID), O_RDONLY) >= 0);
    assert_eq!(open("/proc/12345/mem", O_RDONLY), -3);
}

#[test]
fn read_only_mounts_and_efivars() {
    let _e = setup();
    // An efivars name opens the variable (here: the firmware has none -> ENOENT)
    memfs::mkdir_p("/sys/firmware/efi/efivars");
    let r = open("/sys/firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c", O_RDONLY);
    assert!(r < 0);
}

#[test]
fn descriptor_table_full() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    lx::limits::NOFILE.set(1);
    let fd = open("/f", O_RDONLY);
    assert_eq!(fd, 0);
    assert_eq!(open("/f", O_RDONLY), -24);
}
