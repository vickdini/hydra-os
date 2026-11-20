//! vfs.rs: path resolution, stat and open against the in-memory pool.
mod common;
use common::*;

#[test]
fn stat_reports_pool_attributes() {
    let _e = setup();
    let ino = memfs::mkfile("/etc/hostname", b"hydra\n");
    let st = stat("/etc/hostname").unwrap();
    assert_eq!(st.st_ino, ino);
    assert_eq!(st.st_mode, 0o100644);
    assert_eq!(st.st_size, 6);
    assert_eq!(st.st_dev, 0x0801);
    assert_eq!(st.st_blksize, 4096);
    assert_eq!(st.st_nlink, 1);
    let a = memfs::attr(ino);
    assert_eq!(st.st_mtime, a.mtime.0);
}

#[test]
fn missing_names_and_non_directories() {
    let _e = setup();
    memfs::mkfile("/etc/passwd", b"root");
    assert_eq!(stat("/etc/nothing").unwrap_err(), ENOENT);
    assert_eq!(stat("/etc/passwd/x").unwrap_err(), ENOTDIR);
    assert_eq!(stat("/etc/passwd/").unwrap_err(), ENOTDIR);
    assert!(stat("/etc/").is_ok());
}

#[test]
fn symbolic_links_followed_or_not() {
    let _e = setup();
    let target = memfs::mkfile("/data/real", b"0123456789");
    let link = memfs::mklink("/data/link", "real");
    memfs::mklink("/abs", "/data/real");
    assert_eq!(stat("/data/link").unwrap().st_ino, target);
    assert_eq!(stat("/abs").unwrap().st_ino, target);
    let l = lstat("/data/link").unwrap();
    assert_eq!(l.st_ino, link);
    assert_eq!(l.st_mode & 0o170000, 0o120000);
    // A loop
    memfs::mklink("/loop1", "loop2");
    memfs::mklink("/loop2", "loop1");
    assert_eq!(stat("/loop1").unwrap_err(), ELOOP);
    // A dangling link: stat fails, lstat works
    memfs::mklink("/dangling", "/no/such");
    assert_eq!(stat("/dangling").unwrap_err(), ENOENT);
    assert!(lstat("/dangling").is_ok());
}

#[test]
fn dot_dot_and_relative_paths() {
    let _e = setup();
    let d = memfs::mkdir_p("/home/u/work");
    let f = memfs::mkfile("/home/u/notes", b"x");
    assert_eq!(stat("/home/u/work/../notes").unwrap().st_ino, f);
    // `..` at the root stays there
    assert_eq!(stat("/../../home/u/notes").unwrap().st_ino, f);
    // Relative to the working directory
    task::with_current_fds_mut(|t| {
        t.cwd_ino = d;
        t.cwd_path = String::from("/home/u/work");
    });
    assert_eq!(stat("../notes").unwrap().st_ino, f);
    assert_eq!(stat(".").unwrap().st_ino, d);
}

#[test]
fn bad_path_arguments() {
    let _e = setup();
    // Empty path
    assert_eq!(sys(4, &[cstr(""), buf(256)]), ENOENT);
    // Bad pointer
    assert_eq!(sys(4, &[8, buf(256)]), EFAULT);
    assert_eq!(sys(4, &[0, buf(256)]), EFAULT);
    // A component longer than NAME_MAX
    let long = format!("/{}", "a".repeat(256));
    assert_eq!(sys(4, &[cstr(&long), buf(256)]), -36);
    // A path of PATH_MAX or more
    let huge = "/a".repeat(2100);
    assert_eq!(sys(4, &[cstr(&huge), buf(256)]), -36);
    // stat into a bad buffer
    memfs::mkfile("/f", b"");
    assert_eq!(sys(4, &[cstr("/f"), 16]), EFAULT);
}

#[test]
fn search_permission_on_every_directory() {
    let _e = setup();
    let d = memfs::mkdir_p("/private");
    memfs::chmod(d, 0o700);
    memfs::mkfile("/private/secret", b"s");
    become_user(1000);
    assert_eq!(stat("/private/secret").unwrap_err(), EACCES);
    // The directory itself may be stat'd
    assert!(stat("/private").is_ok());
    // A group member may search a 0710 directory of its group
    memfs::chmod(d, 0o710);
    memfs::chown(d, 0, 1000);
    assert!(stat("/private/secret").is_ok());
}

#[test]
fn stat_with_lstat_and_statx_calls() {
    let _e = setup();
    let ino = memfs::mkfile("/x", b"abc");
    let b = buf(256);
    assert_eq!(sys(4, &[cstr("/x"), b]), 0);
    assert_eq!(stat_at(b).st_ino, ino);
    assert_eq!(sys(6, &[cstr("/x"), b]), 0);
    // statx: mask, size, mode, inode
    let sx = buf(256);
    assert_eq!(sys(332, &[AT_FDCWD, cstr("/x"), 0, 0x7ff, sx]), 0);
    let v = read(sx, 256);
    assert_eq!(u32::from_le_bytes(v[0..4].try_into().unwrap()), 0x17FF);
    assert_eq!(u16::from_le_bytes(v[28..30].try_into().unwrap()), 0o100644);
    assert_eq!(u64::from_le_bytes(v[32..40].try_into().unwrap()), ino);
    assert_eq!(u64::from_le_bytes(v[40..48].try_into().unwrap()), 3);
    assert_eq!(u32::from_le_bytes(v[136..140].try_into().unwrap()), 8); // st_dev major
    assert_eq!(sys(332, &[AT_FDCWD, cstr("/none"), 0, 0x7ff, sx]), ENOENT);
}

#[test]
fn empty_path_stats_the_descriptor() {
    let _e = setup();
    let ino = memfs::mkfile("/f", b"12");
    let fd = open("/f", O_RDONLY);
    assert!(fd >= 0);
    assert_eq!(fstatat(fd as u64, "", 0x1000).unwrap().st_ino, ino);
    assert_eq!(fstatat(fd as u64, "", 0).unwrap_err(), ENOENT);
    assert_eq!(fstatat(77, "", 0x1000).unwrap_err(), EBADF);
}

#[test]
fn dirfd_relative_lookups() {
    let _e = setup();
    memfs::mkdir_p("/srv/www");
    let f = memfs::mkfile("/srv/www/index", b"<html>");
    let dfd = open("/srv", O_RDONLY | O_DIRECTORY);
    assert!(dfd >= 0);
    assert_eq!(fstatat(dfd as u64, "www/index", 0).unwrap().st_ino, f);
    // Not a directory descriptor
    let ffd = open("/srv/www/index", O_RDONLY);
    assert_eq!(fstatat(ffd as u64, "x", 0).unwrap_err(), -20);
    // Not a descriptor at all
    assert_eq!(fstatat(500, "x", 0).unwrap_err(), EBADF);
    // Absolute paths ignore dirfd
    assert_eq!(fstatat(500, "/srv/www/index", 0).unwrap().st_ino, f);
}

#[test]
fn pseudo_files_and_devices_stat() {
    let _e = setup();
    let st = stat("/dev/null").unwrap();
    assert_eq!(st.st_mode, 0o020666);
    assert_eq!(st.st_rdev, (1 << 8) | 3);
    let st = stat("/dev/full").unwrap();
    assert_eq!(st.st_rdev, (1 << 8) | 7);
    let st = stat("/proc/version").unwrap();
    assert_eq!(st.st_mode & 0o170000, 0o100000);
    // The console and its terminals
    let st = stat("/dev/tty1").unwrap();
    assert_eq!(st.st_mode, 0o020620);
    assert_eq!(st.st_ino, 0x401);
    assert!(stat("/dev/console").is_ok());
    // /proc/self is a link when not followed
    let l = lstat("/proc/self").unwrap();
    assert_eq!(l.st_mode, 0o120777);
    // A /proc/<pid> of a process that does not exist; 1 always does
    assert_eq!(stat("/proc/4242").unwrap_err(), ENOENT);
    assert!(stat("/proc/1").is_ok());
    assert!(stat(&format!("/proc/{}", task::SELF_PID)).is_ok());
}

#[test]
fn pty_paths_stat_through_the_pty_layer() {
    let _e = setup();
    lx::pty::SLAVES.with_borrow_mut(|s| s.push(3));
    let st = stat("/dev/pts/3").unwrap();
    assert_eq!(st.st_mode, 0o020620);
    assert_eq!(stat("/dev/pts/9").unwrap_err(), ENOENT);
}

#[test]
fn own_descriptor_links_in_proc() {
    let _e = setup();
    let ino = memfs::mkfile("/f", b"z");
    let fd = open("/f", O_RDONLY);
    let p = format!("/proc/self/fd/{}", fd);
    assert_eq!(stat(&p).unwrap().st_ino, ino);
    assert_eq!(lstat(&p).unwrap().st_mode, 0o120700);
    let p2 = format!("/dev/fd/{}", fd);
    assert_eq!(stat(&p2).unwrap().st_ino, ino);
    // A descriptor fstat does not know (a legacy socket): the link stats as itself
    let sfd = install(FileDescriptor::Socket(std::sync::Arc::new(spin::Mutex::new(Default::default()))));
    assert!(stat(&format!("/proc/self/fd/{}", sfd)).is_ok());
}

#[test]
fn links_in_the_pool_to_files_served_by_name() {
    let _e = setup();
    // /etc/mtab -> ../proc/self/mounts: the server cannot follow it there
    memfs::mklink("/etc/mtab", "../proc/self/mounts");
    let st = stat("/etc/mtab").unwrap();
    assert_eq!(st.st_mode & 0o170000, 0o100000);
    // Opening it opens the /proc file
    let fd = open("/etc/mtab", O_RDONLY);
    assert!(fd >= 0);
    match desc(fd) {
        Some(FileDescriptor::File { path, .. }) => assert_eq!(path, "/proc/self/mounts"),
        _ => panic!("not a by-name file"),
    }
    // A chain through a directory link
    memfs::mklink("/pp", "/proc");
    assert!(stat("/pp/version").is_ok());
}

#[test]
fn proc_root_of_another_process() {
    let _e = setup();
    let f = memfs::mkfile("/.flatpak-info", b"[Application]");
    task::add_process(300, 0);
    // /proc/300/root/... resolves in that process's root (the same pool root here)
    assert_eq!(stat("/proc/300/root/.flatpak-info").unwrap().st_ino, f);
    // Not for a process the caller may not inspect
    lx::extra::deny(300);
    assert_eq!(stat("/proc/300/root/.flatpak-info").unwrap_err(), EPERM);
    // A missing process
    assert_eq!(stat("/proc/301/root/.flatpak-info").unwrap_err(), ENOENT);
}

#[test]
fn file_server_down() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    hydra_hosttests_t26::fake::zfs_server::UP.set(false);
    assert_eq!(stat("/f").unwrap_err(), -5);
}

#[test]
fn chroot_and_empty_root() {
    let _e = setup();
    let jail = memfs::mkdir_p("/jail");
    let inside = memfs::mkfile("/jail/etc/conf", b"c");
    memfs::mkfile("/outside", b"o");
    assert_eq!(sys(161, &[cstr("/jail")]), 0);
    assert_eq!(task::with_current_fds_mut(|f| f.root_ino), jail);
    assert_eq!(stat("/etc/conf").unwrap().st_ino, inside);
    assert_eq!(stat("/outside").unwrap_err(), ENOENT);
    assert_eq!(stat("/../../etc/conf").unwrap().st_ino, inside);
    // Not a directory, missing, no permission
    assert_eq!(sys(161, &[cstr("/etc/conf")]), ENOTDIR);
    assert_eq!(sys(161, &[cstr("/nope")]), ENOENT);
    // Without CAP_SYS_CHROOT
    task::set_caps(0);
    assert_eq!(sys(161, &[cstr("/etc")]), EPERM);
}

#[test]
fn chroot_into_proc_gives_an_empty_root() {
    let _e = setup();
    task::add_process(310, 0);
    lx::proc::with(task::SELF_PID, |p| p.fs_peer = 310);
    assert_eq!(sys(161, &[cstr("/proc/self/fd")]), 0);
    assert_eq!(task::with_current_fds_mut(|f| f.root_ino), u64::MAX);
    // The peer sharing the root moved too
    let peer_root = task::with_other(310, |t| t.fds.lock().root_ino).unwrap();
    assert_eq!(peer_root, u64::MAX);
    // Nothing resolves now
    assert_eq!(stat("/etc").unwrap_err(), ENOENT);
    assert_eq!(open("/etc", O_RDONLY), ENOENT);
    // chdir to / or . works, elsewhere fails
    assert_eq!(sys(80, &[cstr("/")]), 0);
    assert_eq!(sys(80, &[cstr("elsewhere")]), ENOENT);
    assert_eq!(sys(80, &[cstr("")]), ENOENT);
}

#[test]
fn chroot_needs_search_permission() {
    let _e = setup();
    let d = memfs::mkdir_p("/locked");
    memfs::chmod(d, 0o700);
    become_user(1000);
    task::set_caps(1 << 18);
    assert_eq!(sys(161, &[cstr("/locked")]), EACCES);
}
