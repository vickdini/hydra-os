//! vfs.rs: directory entry operations, attributes, access checks, links, working directory.
mod common;
use common::*;

fn mkdir(p: &str, mode: u64) -> i64 {
    sys(83, &[cstr(p), mode])
}

#[test]
fn mkdir_and_rmdir() {
    let _e = setup();
    assert_eq!(mkdir("/a", 0o777), 0);
    let a = memfs::lookup("/a").unwrap();
    assert_eq!(memfs::attr(a).mode, 0o040755); // umask 022
    assert_eq!(mkdir("/a", 0o777), EEXIST);
    assert_eq!(mkdir("/none/b", 0o777), ENOENT);
    // mkdirat relative to a directory descriptor
    let dfd = open("/a", O_RDONLY | O_DIRECTORY);
    assert_eq!(sys(258, &[dfd as u64, cstr("sub"), 0o700]), 0);
    assert_eq!(memfs::attr(memfs::lookup("/a/sub").unwrap()).mode, 0o040700);
    // rmdir of a non-empty, then empty directory
    assert_eq!(sys(84, &[cstr("/a")]), ENOTEMPTY);
    assert_eq!(sys(84, &[cstr("/a/sub")]), 0);
    assert_eq!(sys(84, &[cstr("/a/sub")]), ENOENT);
    // unlinkat with AT_REMOVEDIR
    assert_eq!(sys(263, &[AT_FDCWD, cstr("/a"), 0x200]), 0);
    assert!(memfs::lookup("/a").is_none());
    // The parent must be a directory and writable
    memfs::mkfile("/file", b"");
    assert_eq!(mkdir("/file/x", 0o777), ENOTDIR);
    let ro = memfs::mkdir_p("/ro");
    memfs::chmod(ro, 0o555);
    become_user(1000);
    assert_eq!(mkdir("/ro/x", 0o777), EACCES);
    // ... but an existing name is EEXIST first
    memfs::mkdir_p("/ro/exists");
    assert_eq!(mkdir("/ro/exists", 0o777), EEXIST);
}

#[test]
fn mkdir_landlock_and_server_errors() {
    let _e = setup();
    lx::landlock::refuse(lx::landlock::MAKE_DIR);
    assert_eq!(mkdir("/x", 0o777), EACCES);
    lx::landlock::reset();
    memfs::fail("mkdir", -28);
    assert_eq!(mkdir("/x", 0o777), -28);
}

#[test]
fn unlink_files() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    memfs::mkdir_p("/d");
    assert_eq!(sys(87, &[cstr("/d")]), EISDIR);
    assert_eq!(sys(87, &[cstr("/f")]), 0);
    assert_eq!(sys(87, &[cstr("/f")]), ENOENT);
    // Removing "." makes the file server answer
    assert!(sys(87, &[cstr("/d/.")]) < 0);
    lx::landlock::refuse(lx::landlock::REMOVE_FILE);
    memfs::mkfile("/g", b"");
    assert_eq!(sys(87, &[cstr("/g")]), EACCES);
    lx::landlock::reset();
    lx::abac::policy(false, true);
    assert_eq!(sys(87, &[cstr("/g")]), EACCES);
}

#[test]
fn sticky_directories() {
    let _e = setup();
    let tmp = memfs::mkdir_p("/tmp");
    memfs::chmod(tmp, 0o1777);
    let theirs = memfs::mkfile("/tmp/theirs", b"");
    memfs::chown(theirs, 2000, 2000);
    let mine = memfs::mkfile("/tmp/mine", b"");
    memfs::chown(mine, 1000, 1000);
    become_user(1000);
    assert_eq!(sys(87, &[cstr("/tmp/theirs")]), EPERM);
    assert_eq!(sys(82, &[cstr("/tmp/theirs"), cstr("/tmp/stolen")]), EPERM);
    assert_eq!(sys(87, &[cstr("/tmp/mine")]), 0);
    // The directory's owner may remove anything
    memfs::chown(tmp, 1000, 1000);
    assert_eq!(sys(87, &[cstr("/tmp/theirs")]), 0);
    // Replacing someone else's file by rename is refused too
    memfs::chown(tmp, 0, 0);
    let other = memfs::mkfile("/tmp/other", b"");
    memfs::chown(other, 2000, 2000);
    let mine2 = memfs::mkfile("/tmp/mine2", b"");
    memfs::chown(mine2, 1000, 1000);
    assert_eq!(sys(82, &[cstr("/tmp/mine2"), cstr("/tmp/other")]), EPERM);
}

#[test]
fn rename_cases() {
    let _e = setup();
    let f = memfs::mkfile("/a/f", b"data");
    memfs::mkdir_p("/b");
    assert_eq!(sys(82, &[cstr("/a/f"), cstr("/b/g")]), 0);
    assert_eq!(memfs::lookup("/b/g"), Some(f));
    assert!(memfs::lookup("/a/f").is_none());
    // renameat2 with RENAME_NOREPLACE
    memfs::mkfile("/b/h", b"");
    assert_eq!(sys(316, &[AT_FDCWD, cstr("/b/g"), AT_FDCWD, cstr("/b/h"), 1]), EEXIST);
    assert_eq!(sys(316, &[AT_FDCWD, cstr("/b/g"), AT_FDCWD, cstr("/b/new"), 1]), 0);
    // RENAME_EXCHANGE is not supported
    assert_eq!(sys(316, &[AT_FDCWD, cstr("/b/new"), AT_FDCWD, cstr("/b/h"), 2]), EINVAL);
    // renameat relative to descriptors
    let d = open("/b", O_RDONLY);
    assert_eq!(sys(264, &[d as u64, cstr("new"), d as u64, cstr("newer")]), 0);
    assert!(memfs::lookup("/b/newer").is_some());
    // Missing source
    assert_eq!(sys(82, &[cstr("/b/none"), cstr("/b/x")]), ENOENT);
    // Without write permission on a directory
    let ro = memfs::mkdir_p("/ro");
    memfs::chmod(ro, 0o555);
    memfs::mkfile("/ro/x", b"");
    become_user(1000);
    assert_eq!(sys(82, &[cstr("/ro/x"), cstr("/ro/y")]), EACCES);
}

#[test]
fn rename_policies() {
    let _e = setup();
    memfs::mkfile("/a/f", b"");
    memfs::mkfile("/b/g", b"");
    // Moving a file away from its folder needs the delete right
    lx::abac::policy(false, true);
    assert_eq!(sys(82, &[cstr("/a/f"), cstr("/b/f")]), EACCES);
    // Replacing a file needs it too
    assert_eq!(sys(82, &[cstr("/a/f"), cstr("/a/g")]), 0);
    memfs::mkfile("/a/h", b"");
    assert_eq!(sys(82, &[cstr("/a/g"), cstr("/a/h")]), EACCES);
    lx::abac::reset();
    // Landlock: the move's rights
    lx::landlock::refuse(lx::landlock::REMOVE_FILE);
    assert_eq!(sys(82, &[cstr("/a/h"), cstr("/b/h")]), EXDEV);
    lx::landlock::refuse(lx::landlock::MAKE_SYM);
    assert_eq!(sys(82, &[cstr("/a/h"), cstr("/b/g")]), 0);
}

#[test]
fn hard_links() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"x");
    assert_eq!(sys(86, &[cstr("/f"), cstr("/g")]), 0);
    assert_eq!(memfs::lookup("/g"), Some(f));
    assert_eq!(memfs::attr(f).nlink, 2);
    assert_eq!(sys(86, &[cstr("/f"), cstr("/g")]), EEXIST);
    assert_eq!(sys(86, &[cstr("/none"), cstr("/h")]), ENOENT);
    // linkat with AT_EMPTY_PATH links the descriptor's file
    let fd = open("/f", O_RDONLY);
    assert_eq!(sys(265, &[fd as u64, cstr(""), AT_FDCWD, cstr("/h"), 0x1000]), 0);
    assert_eq!(memfs::lookup("/h"), Some(f));
    assert_eq!(sys(265, &[fd as u64, cstr(""), AT_FDCWD, cstr("/i"), 0]), ENOENT);
    assert_eq!(sys(265, &[99, cstr(""), AT_FDCWD, cstr("/i"), 0x1000]), EBADF);
    // AT_SYMLINK_FOLLOW links the target rather than the link
    memfs::mklink("/sl", "/f");
    assert_eq!(sys(265, &[AT_FDCWD, cstr("/sl"), AT_FDCWD, cstr("/j"), 0x400]), 0);
    assert_eq!(memfs::lookup("/j"), Some(f));
    assert_eq!(sys(265, &[AT_FDCWD, cstr("/sl"), AT_FDCWD, cstr("/k"), 0]), 0);
    assert_eq!(memfs::lookup("/k"), memfs::lookup("/sl"));
    // Landlock refuses linking into a directory without MAKE_REG
    lx::landlock::refuse(lx::landlock::MAKE_REG);
    assert_eq!(sys(86, &[cstr("/f"), cstr("/l")]), EXDEV);
}

#[test]
fn symlinks_and_readlink() {
    let _e = setup();
    memfs::mkdir_p("/d");
    assert_eq!(sys(88, &[cstr("../target"), cstr("/d/link")]), 0);
    let b = buf(64);
    assert_eq!(sys(89, &[cstr("/d/link"), b, 64]), 9);
    assert_eq!(read(b, 9), b"../target");
    // Truncated to the buffer
    assert_eq!(sys(89, &[cstr("/d/link"), b, 3]), 3);
    assert_eq!(sys(89, &[cstr("/d/link"), b, 0]), EINVAL);
    // symlinkat
    let d = open("/d", O_RDONLY);
    assert_eq!(sys(266, &[cstr("/abs"), d as u64, cstr("l2")]), 0);
    assert_eq!(sys(267, &[d as u64, cstr("l2"), b, 64]), 4);
    assert_eq!(sys(88, &[cstr("x"), cstr("/d/link")]), EEXIST);
    assert_eq!(sys(88, &[cstr(""), cstr("/d/l3")]), ENOENT);
    // readlink of something that is not a link
    assert_eq!(sys(89, &[cstr("/d"), b, 64]), EINVAL);
    assert_eq!(sys(89, &[cstr("/dev/null"), b, 64]), EINVAL);
    assert_eq!(sys(89, &[cstr("/proc"), b, 64]), EINVAL);
    assert_eq!(sys(89, &[cstr("/proc/7777"), b, 64]), ENOENT);
    // /proc links
    let n = sys(89, &[cstr("/proc/self"), b, 64]);
    assert_eq!(read(b, n as usize), format!("{}", task::SELF_PID).as_bytes());
    task::add_process(320, 0);
    assert_eq!(sys(89, &[cstr("/proc/320/root"), b, 64]), 1);
    assert_eq!(read(b, 1), b"/");
    lx::landlock::refuse(lx::landlock::MAKE_SYM);
    assert_eq!(sys(88, &[cstr("t"), cstr("/d/l9")]), EACCES);
}

#[test]
fn fd_links_of_every_kind() {
    let _e = setup();
    use std::sync::Arc;
    let b = buf(128);
    let rl = |fd: i64| -> String {
        let n = sys(89, &[cstr(&format!("/proc/self/fd/{}", fd)), b, 128]);
        assert!(n > 0, "readlink fd {}: {}", fd, n);
        String::from_utf8(read(b, n as usize)).unwrap()
    };
    memfs::mkfile("/some/file", b"");
    assert_eq!(rl(open("/some/file", O_RDONLY)), "/some/file");
    assert_eq!(rl(install(FileDescriptor::file("/dev/zero"))), "/dev/zero");
    assert_eq!(rl(install(FileDescriptor::ConsoleIn)), "/dev/tty1");
    let p = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    assert!(rl(install(FileDescriptor::PipeRead(p))).starts_with("pipe:["));
    assert!(rl(install(FileDescriptor::Socket(Arc::new(spin::Mutex::new(Default::default()))))).starts_with("socket:["));
    assert!(rl(install(FileDescriptor::Inet(Arc::new(spin::Mutex::new(Default::default()))))).starts_with("socket:["));
    assert_eq!(rl(install(FileDescriptor::Unix(lx::unix::UnixSocket::new(55)))), "socket:[55]");
    assert_eq!(rl(install(FileDescriptor::TimerFd(Arc::new(Default::default())))), "anon_inode:[timerfd]");
    assert_eq!(rl(install(FileDescriptor::PidFd(Arc::new(lx::pidfd::PidFd { pid: 1 })))), "anon_inode:[pidfd]");
    assert_eq!(rl(install(FileDescriptor::Epoll(Arc::new(spin::Mutex::new(Default::default()))))), "anon_inode:[eventpoll]");
    assert_eq!(rl(install(FileDescriptor::EventFd(lx::eventfd::EventFd::new(0)))), "anon_inode:[eventfd]");
    assert_eq!(rl(install(FileDescriptor::SignalFd(Arc::new(Default::default())))), "anon_inode:[signalfd]");
    assert_eq!(rl(install(FileDescriptor::MemFd { memfd: lx::memfd::MemFd::new("m"), flags: 2 })), "/memfd: (deleted)");
    assert_eq!(rl(install(FileDescriptor::Pty(lx::pty::PtyFile::named("/dev/pts/4", false)))), "/dev/pts/4");
    let d: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::new("/dev/dri/card0", 0));
    assert_eq!(rl(install(FileDescriptor::Device(d))), "/dev/dri/card0");
    let ino = sys_inotify();
    assert_eq!(rl(ino), "anon_inode:inotify");
    // Another process's descriptors are not shown as links here
    assert!(sys(89, &[cstr("/proc/1/fd/0"), b, 128]) < 0);
}

fn sys_inotify() -> i64 {
    lx::inotify::sys_init1(0)
}

#[test]
fn chmod_chown_and_times() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    assert_eq!(sys(90, &[cstr("/f"), 0o4755]), 0);
    assert_eq!(memfs::attr(f).mode, 0o104755);
    let fd = open("/f", O_RDONLY);
    assert_eq!(sys(91, &[fd as u64, 0o600]), 0);
    assert_eq!(memfs::attr(f).mode, 0o100600);
    assert_eq!(sys(268, &[AT_FDCWD, cstr("/f"), 0o640]), 0);
    // fchmodat2 with AT_EMPTY_PATH and bad flags
    assert_eq!(sys(452, &[fd as u64, cstr(""), 0o644, 0x1000]), 0);
    assert_eq!(memfs::attr(f).mode, 0o100644);
    assert_eq!(sys(452, &[fd as u64, cstr(""), 0o644, 0x8]), EINVAL);
    assert_eq!(sys(452, &[fd as u64, cstr(""), 0o644, 0]), ENOENT);
    // chown by root clears set-ID bits
    assert_eq!(sys(90, &[cstr("/f"), 0o6755]), 0);
    assert_eq!(sys(92, &[cstr("/f"), 1000, 1000]), 0);
    let a = memfs::attr(f);
    assert_eq!((a.uid, a.gid), (1000, 1000));
    assert_eq!(a.mode & 0o6000, 0);
    // -1 leaves a field
    assert_eq!(sys(93, &[fd as u64, u32::MAX as u64, 50]), 0);
    assert_eq!((memfs::attr(f).uid, memfs::attr(f).gid), (1000, 50));
    // lchown changes the link itself
    let l = memfs::mklink("/l", "/f");
    assert_eq!(sys(94, &[cstr("/l"), 7, 7]), 0);
    assert_eq!(memfs::attr(l).uid, 7);
    assert_eq!(memfs::attr(f).uid, 1000);
    // fchownat with AT_SYMLINK_NOFOLLOW
    assert_eq!(sys(260, &[AT_FDCWD, cstr("/l"), 8, 8, 0x100]), 0);
    assert_eq!(memfs::attr(l).uid, 8);
    // fchmod on a non-pool descriptor is not ours
    let nfd = install(FileDescriptor::ConsoleIn);
    assert_eq!(sys_opt(91, &[nfd as u64, 0o600]), None);
    assert_eq!(sys_opt(93, &[nfd as u64, 0, 0]), None);
}

#[test]
fn ownership_rules_for_users() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chown(f, 1000, 1000);
    let other = memfs::mkfile("/o", b"");
    become_user(1000);
    // The owner may chmod; others not
    assert_eq!(sys(90, &[cstr("/f"), 0o600]), 0);
    assert_eq!(sys(90, &[cstr("/o"), 0o777]), EPERM);
    let _ = other;
    // The owner may change the group to one of its own, not the owner
    assert_eq!(sys(92, &[cstr("/f"), u32::MAX as u64, 1000]), 0);
    assert_eq!(sys(92, &[cstr("/f"), 0, u32::MAX as u64]), EPERM);
    assert_eq!(sys(92, &[cstr("/f"), u32::MAX as u64, 3000]), EPERM);
    lx::proc::with(task::SELF_PID, |p| p.groups.push(3000));
    assert_eq!(sys(92, &[cstr("/f"), 1000, 3000]), 0);
    // utimensat with explicit times needs ownership; NULL times do not
    let t = buf(32);
    write(t, &[5u64.to_le_bytes(), 6u64.to_le_bytes(), 7u64.to_le_bytes(), 8u64.to_le_bytes()].concat());
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/o"), t, 0]), EPERM);
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/o"), 0, 0]), 0);
    assert_eq!(sys(280, &[AT_FDCWD, cstr("/f"), t, 0]), 0);
    let a = memfs::attr(f);
    assert_eq!(a.atime, (5, 6));
    assert_eq!(a.mtime, (7, 8));
}

#[test]
fn truncate_and_fallocate() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"0123456789");
    assert_eq!(sys(76, &[cstr("/f"), 4]), 0);
    assert_eq!(memfs::data(f), b"0123");
    assert_eq!(sys(76, &[cstr("/f"), (-1i64) as u64]), EINVAL);
    let fd = open("/f", O_RDWR);
    assert_eq!(sys(77, &[fd as u64, 8]), 0);
    assert_eq!(memfs::data(f).len(), 8);
    let ro = open("/f", O_RDONLY);
    assert_eq!(sys(77, &[ro as u64, 1]), EINVAL);
    // fallocate grows, keeps with KEEP_SIZE, refuses other modes
    assert_eq!(sys(285, &[fd as u64, 0, 0, 20]), 0);
    assert_eq!(memfs::data(f).len(), 20);
    assert_eq!(sys(285, &[fd as u64, 0, 0, 5]), 0);
    assert_eq!(memfs::data(f).len(), 20);
    assert_eq!(sys(285, &[fd as u64, 1, 0, 100]), 0);
    assert_eq!(memfs::data(f).len(), 20);
    assert_eq!(sys(285, &[fd as u64, 2, 0, 100]), EOPNOTSUPP);
    assert_eq!(sys(285, &[fd as u64, 0, 0, 0]), EINVAL);
    assert_eq!(sys(285, &[ro as u64, 0, 0, 30]), EBADF);
    // fallocate on a memfd grows it
    let m = lx::memfd::MemFd::new("m");
    let mfd = install(FileDescriptor::MemFd { memfd: m.clone(), flags: 2 });
    assert_eq!(sys(285, &[mfd as u64, 0, 0, 4096]), 0);
    assert_eq!(m.lock().size(), 4096);
    assert_eq!(sys(285, &[mfd as u64, 1, 0, 8192]), 0);
    assert_eq!(m.lock().size(), 4096);
    assert_eq!(sys(285, &[mfd as u64, 0, (-1i64) as u64, 1]), EINVAL);
    assert_eq!(sys(285, &[mfd as u64, 4, 0, 1]), EOPNOTSUPP);
    assert_eq!(sys(285, &[mfd as u64, 0, i64::MAX as u64, 2]), -27);
    m.lock().seals |= 4;
    assert_eq!(sys(285, &[mfd as u64, 0, 0, 10000]), EPERM);
    // truncate needs write permission; Landlock's TRUNCATE right
    let r = memfs::mkfile("/r", b"r");
    memfs::chmod(r, 0o644);
    become_user(9);
    assert_eq!(sys(76, &[cstr("/r"), 0]), EPERM);
    task::set_ids(0, 0);
    lx::landlock::refuse(lx::landlock::TRUNCATE);
    assert_eq!(sys(76, &[cstr("/r"), 0]), EACCES);
    // ftruncate/fallocate on a non-pool descriptor are not ours
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(sys_opt(77, &[c as u64, 0]), None);
    assert_eq!(sys_opt(285, &[c as u64, 0, 0, 1]), None);
}

#[test]
fn access_checks() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chown(f, 1000, 1000);
    memfs::chmod(f, 0o640);
    become_user(1000);
    assert_eq!(sys(21, &[cstr("/f"), 4]), 0);
    assert_eq!(sys(21, &[cstr("/f"), 2]), 0);
    assert_eq!(sys(21, &[cstr("/f"), 1]), EACCES);
    assert_eq!(sys(21, &[cstr("/f"), 0]), 0);
    assert_eq!(sys(21, &[cstr("/none"), 0]), ENOENT);
    assert_eq!(sys(21, &[cstr("/dev/null"), 6]), 0);
    // access uses the real ids, faccessat2 with AT_EACCESS the effective ones
    task::current(|t| (t.euid, t.egid) = (2000, 2000));
    assert_eq!(sys(269, &[AT_FDCWD, cstr("/f"), 4]), 0);
    assert_eq!(sys(439, &[AT_FDCWD, cstr("/f"), 4, 0x200]), EACCES);
    // /proc/self/fd/N checks the open file
    task::current(|t| t.euid = 1000);
    let fd = open("/f", O_PATH);
    assert_eq!(sys(21, &[cstr(&format!("/proc/self/fd/{}", fd)), 4]), 0);
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(sys(21, &[cstr(&format!("/proc/self/fd/{}", c)), 4]), 0);
    assert_eq!(sys(21, &[cstr(""), 0]), ENOENT);
}

#[test]
fn working_directory() {
    let _e = setup();
    let d = memfs::mkdir_p("/home/user/src");
    let b = buf(64);
    assert_eq!(sys(80, &[cstr("/home/user/src")]), 0);
    assert_eq!(sys(79, &[b, 64]), 15);
    assert_eq!(read(b, 15), b"/home/user/src\0");
    assert_eq!(task::with_current_fds_mut(|f| f.cwd_ino), d);
    assert_eq!(sys(79, &[b, 4]), ERANGE);
    assert_eq!(sys(79, &[16, 64]), EFAULT);
    assert_eq!(sys(80, &[cstr("..")]), 0);
    assert_eq!(sys(79, &[b, 64]), 11);
    // Not a directory, missing, no search permission
    memfs::mkfile("/home/f", b"");
    assert_eq!(sys(80, &[cstr("/home/f")]), ENOTDIR);
    assert_eq!(sys(80, &[cstr("/none")]), ENOENT);
    let locked = memfs::mkdir_p("/locked");
    memfs::chmod(locked, 0o700);
    // fchdir
    let fd = open("/home/user/src", O_RDONLY);
    assert_eq!(sys(81, &[fd as u64]), 0);
    assert_eq!(sys(79, &[b, 64]), 15);
    assert_eq!(sys(81, &[99]), EBADF);
    become_user(1000);
    assert_eq!(sys(80, &[cstr("/locked")]), EACCES);
}

#[test]
fn chdir_builds_the_physical_path() {
    let _e = setup();
    // Through a symlink, the lexical path (no mount namespace): the physical one is built
    memfs::mkdir_p("/real/dir");
    memfs::mklink("/alias", "/real");
    assert_eq!(sys(80, &[cstr("/alias/dir")]), 0);
    let b = buf(64);
    let n = sys(79, &[b, 64]);
    assert_eq!(read(b, n as usize - 1), b"/real/dir");
    // A chroot: paths are from the new root
    let j = memfs::mkdir_p("/jail/inner");
    let _ = j;
    assert_eq!(sys(161, &[cstr("/jail")]), 0);
    assert_eq!(sys(80, &[cstr("/inner")]), 0);
    let n = sys(79, &[b, 64]);
    assert_eq!(read(b, n as usize - 1), b"/inner");
    assert_eq!(sys(80, &[cstr("/")]), 0);
    let n = sys(79, &[b, 64]);
    assert_eq!(read(b, n as usize - 1), b"/");
}

#[test]
fn umask_call() {
    let _e = setup();
    assert_eq!(sys(95, &[0o077]), 0o022);
    assert_eq!(sys(95, &[0o7777]), 0o077);
    assert_eq!(task::with_current_fds_mut(|f| f.umask), 0o777);
}

#[test]
fn mknod_rules() {
    let _e = setup();
    memfs::mkdir_p("/d");
    // A FIFO and a regular file anyone may make
    assert_eq!(sys(133, &[cstr("/d/fifo"), 0o010644, 0]), 0);
    assert_eq!(memfs::attr(memfs::lookup("/d/fifo").unwrap()).mode, 0o010644);
    assert_eq!(sys(259, &[AT_FDCWD, cstr("/d/reg"), 0o100600, 0]), 0);
    // A device node needs root and passes device control
    assert_eq!(sys(133, &[cstr("/d/null"), 0o020666, (1 << 8) | 3]), 0);
    assert_eq!(memfs::attr(memfs::lookup("/d/null").unwrap()).rdev, (1 << 8) | 3);
    lx::bpf::deny(lx::bpf::DEV_BLOCK, 8, 0);
    assert_eq!(sys(133, &[cstr("/d/sda"), 0o060660, 8 << 8]), EPERM);
    lx::landlock::refuse(lx::landlock::MAKE_FIFO);
    assert_eq!(sys(133, &[cstr("/d/f2"), 0o010644, 0]), EACCES);
    lx::landlock::reset();
    let d = memfs::lookup("/d").unwrap();
    memfs::chmod(d, 0o777);
    become_user(1000);
    assert_eq!(sys(133, &[cstr("/d/c"), 0o020600, 0x101]), EPERM);
    assert_eq!(sys(133, &[cstr("/d/fifo2"), 0o010600, 0]), 0);
}

