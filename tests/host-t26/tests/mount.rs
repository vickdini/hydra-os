//! mount.rs: mount namespaces (the table, bind/tmpfs/named mounts, remount, move, umount,
//! pivot_root), lookups through the table, and the new mount API.
mod common;
use common::*;
use core::sync::atomic::{AtomicU64, Ordering};
use lx::mount;

const MS_RDONLY: u64 = 1;
const MS_NOSUID: u64 = 2;
const MS_NOEXEC: u64 = 8;
const MS_REMOUNT: u64 = 32;
const MS_BIND: u64 = 4096;
const MS_MOVE: u64 = 8192;
const MS_REC: u64 = 16384;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SHARED: u64 = 1 << 20;
const EBUSY: i64 = -16;
const EROFS: i64 = -30;
const ENODEV: i64 = -19;

static NS: AtomicU64 = AtomicU64::new(5000);

/// Moves the current process into a new mount namespace (a copy of the initial one).
fn unshare() -> u64 {
    let id = NS.fetch_add(1, Ordering::Relaxed);
    let fds = task::current(|t| t.fds.clone());
    mount::copy_ns(0, id, &fds);
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = id);
    id
}

fn mnt(src: &str, target: &str, fstype: &str, flags: u64, data: &str) -> i64 {
    let p = |s: &str| if s.is_empty() { 0 } else { cstr(s) };
    mount::dispatch(165, [p(src), cstr(target), p(fstype), flags, p(data), 0]).unwrap()
}

fn umount(target: &str, flags: u64) -> i64 {
    mount::dispatch(166, [cstr(target), flags, 0, 0, 0, 0]).unwrap()
}

fn info() -> String {
    mount::mountinfo(task::SELF_PID).unwrap()
}

#[test]
fn initial_namespace_is_fixed() {
    let _e = setup();
    memfs::mkdir_p("/mnt");
    assert_eq!(mnt("tmpfs", "/mnt", "tmpfs", 0, ""), EPERM);
    assert_eq!(umount("/mnt", 0), EPERM);
    assert!(mount::mountinfo(task::SELF_PID).is_none());
    assert!(mount::mounts(task::SELF_PID).is_none());
    assert!(mount::resolve(0, b"/mnt", true).is_none());
    assert!(mount::resolve_parent(0, b"/mnt/x").is_none());
    assert!(mount::canonical("/mnt").is_none());
    assert!(!mount::is_named_mountpoint("/proc"));
    assert_eq!(mount::check_write(), 0);
    assert_eq!(mount::exec_flags(), (false, false));
    assert!(!mount::last_is_tmpfs());
    assert_eq!(mount::dispatch(1, [0; 6]), None);
}

#[test]
fn a_new_namespace_lists_the_standard_mounts() {
    let _e = setup();
    memfs::mkdir_p("/proc");
    memfs::mkdir_p("/sys/fs/cgroup");
    memfs::mkdir_p("/dev/pts");
    memfs::mkdir_p("/run");
    unshare();
    let text = info();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 7);
    assert!(lines[0].contains(" / / rw,relatime shared:") && lines[0].ends_with("- zfs hydrapool/root rw"));
    assert!(lines[1].contains(" /proc rw,nosuid,noexec,relatime shared:") && lines[1].contains("- proc proc rw"));
    assert!(text.contains(" /dev/pts ") && text.contains("- devpts devpts"));
    // The parent of /sys/fs/cgroup is /sys
    let id_sys: &str = lines[2].split(' ').next().unwrap();
    assert_eq!(lines[3].split(' ').nth(1).unwrap(), id_sys);
    let mounts = mount::mounts(task::SELF_PID).unwrap();
    assert!(mounts.starts_with("hydrapool/root / zfs rw 0 0\nproc /proc proc rw 0 0\n"));
    // /proc/self/mountinfo shows it
    let fd = open("/proc/self/mountinfo", O_RDONLY);
    assert!(fd >= 0);
    // A path that is a named mount point
    assert!(mount::is_named_mountpoint("/proc"));
    assert!(!mount::is_named_mountpoint("/home"));
}

#[test]
fn bind_mounts_show_another_tree() {
    let _e = setup();
    let f = memfs::mkfile("/src/file", b"x");
    memfs::mkdir_p("/dst");
    unshare();
    assert_eq!(mnt("/src", "/dst", "", MS_BIND, ""), 0);
    assert_eq!(stat("/dst/file").unwrap().st_ino, f);
    // `..` from the mounted tree's root leaves through the mount point
    memfs::mkfile("/beside", b"");
    assert!(stat("/dst/../beside").is_ok());
    // The mount is listed
    assert!(info().contains(" /dst rw "));
    // Its root is held while mounted
    assert!(memfs::refs(memfs::lookup("/src").unwrap()) >= 1);
    // A file onto a directory: ENOTDIR; a missing source: ENOENT
    assert_eq!(mnt("/src/file", "/dst", "", MS_BIND, ""), ENOTDIR);
    assert_eq!(mnt("/nope", "/dst", "", MS_BIND, ""), ENOENT);
    assert_eq!(mnt("", "/dst", "", MS_BIND, ""), EFAULT);
    // umount
    assert_eq!(umount("/dst", 0), 0);
    assert_eq!(stat("/dst/file").unwrap_err(), ENOENT);
    assert_eq!(umount("/dst", 0), EINVAL); // no longer a mount point
}

#[test]
fn recursive_binds_and_busy_unmounts() {
    let _e = setup();
    memfs::mkdir_p("/a/inner");
    let deep = memfs::mkfile("/b/deep", b"");
    memfs::mkdir_p("/c");
    unshare();
    assert_eq!(mnt("/b", "/a/inner", "", MS_BIND, ""), 0);
    assert_eq!(stat("/a/inner/deep").unwrap().st_ino, deep);
    // Without MS_REC the submount is not copied
    assert_eq!(mnt("/a", "/c", "", MS_BIND, ""), 0);
    assert_eq!(stat("/c/inner/deep").unwrap_err(), ENOENT);
    assert_eq!(umount("/c", 0), 0);
    // With MS_REC it is
    assert_eq!(mnt("/a", "/c", "", MS_BIND | MS_REC, ""), 0);
    assert_eq!(stat("/c/inner/deep").unwrap().st_ino, deep);
    assert!(info().contains(" /c/inner "));
    // A mount with submounts is busy unless detached
    assert_eq!(umount("/c", 0), EBUSY);
    assert_eq!(umount("/c", 2), 0);
    assert!(!info().contains(" /c/inner "));
    assert_eq!(umount("/c", 0x10), EINVAL); // unknown flag
    // The root cannot be unmounted
    assert_eq!(umount("/", 0), EINVAL);
}

#[test]
fn tmpfs_mounts() {
    let _e = setup();
    memfs::mkdir_p("/tmp");
    unshare();
    assert_eq!(mnt("tmpfs", "/tmp", "tmpfs", MS_NOSUID, "mode=0750,uid=12,gid=34,size=1M"), 0);
    // A fresh hidden directory of the pool with the options' owner and mode
    let dir = memfs::lookup("/.hydra-tmpfs").unwrap();
    assert_eq!(memfs::attr(dir).mode & 0o7777, 0o700);
    let root = stat("/tmp").unwrap();
    assert_eq!(root.st_mode & 0o7777, 0o750);
    assert_eq!((root.st_uid, root.st_gid), (12, 34));
    // Files made there live in that tree
    let fd = openat(AT_FDCWD, "/tmp/scratch", O_CREAT | O_WRONLY, 0o600);
    assert!(fd >= 0, "{}", fd);
    assert!(mount::last_is_tmpfs());
    // statfs reports tmpfs
    let b = buf(120);
    assert_eq!(sys(137, &[cstr("/tmp/scratch"), b]), 0);
    assert_eq!(read_u64(b), 0x0102_1994);
    // Mount info
    assert!(info().contains(" /tmp rw,nosuid - tmpfs tmpfs rw"));
    // Bug found by this crate (fixed): back in the initial namespace, the stale note of
    // the last lookup made statfs of pool files report tmpfs
    let ns = lx::proc::with(task::SELF_PID, |p| core::mem::replace(&mut p.ns.mnt, 0));
    assert!(!mount::last_is_tmpfs());
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = ns);
    // Unmounting removes the tree
    close(fd);
    assert_eq!(umount("/tmp", 0), 0);
    let entries = memfs::with(|fs| fs.readdir(dir, 2, 100).unwrap().len());
    assert_eq!(entries, 0);
    // Default options: mode 1777, owner the caller
    become_user(0);
    assert_eq!(mnt("none", "/tmp", "ramfs", 0, ""), 0);
    assert_eq!(stat("/tmp").unwrap().st_mode & 0o7777, 0o1777);
    // The file server failing
    memfs::fail("mkdir", -28);
    memfs::mkdir_p("/tmp2");
    assert_eq!(mnt("tmpfs", "/tmp2", "tmpfs", 0, ""), -28);
}

#[test]
fn read_only_and_other_per_mount_flags() {
    let _e = setup();
    let f = memfs::mkfile("/data/f", b"abc");
    memfs::mkdir_p("/ro");
    unshare();
    assert_eq!(mnt("/data", "/ro", "", MS_BIND | MS_RDONLY | MS_NOEXEC, ""), 0);
    // Writes there fail with EROFS, reads work
    assert!(open("/ro/f", O_RDONLY) >= 0);
    assert_eq!(open("/ro/f", O_WRONLY), EROFS);
    assert_eq!(mount::exec_flags(), (true, false));
    assert_eq!(openat(AT_FDCWD, "/ro/new", O_CREAT | O_WRONLY, 0o600), EROFS);
    assert_eq!(sys(83, &[cstr("/ro/d"), 0o755]), EROFS);
    assert_eq!(sys(90, &[cstr("/ro/f"), 0o600]), EROFS);
    // The same tree through its own path is writable
    assert!(open("/data/f", O_WRONLY) >= 0);
    assert_eq!(mount::check_write(), 0);
    // Remount read-write
    assert_eq!(mnt("", "/ro", "", MS_REMOUNT | MS_BIND, ""), 0);
    assert!(open("/ro/f", O_WRONLY) >= 0);
    assert!(info().contains(" /ro rw "));
    // Remount of something that is not a mount point
    assert_eq!(mnt("", "/data", "", MS_REMOUNT, ""), EINVAL);
    let _ = f;
}

#[test]
fn propagation_changes_are_recorded() {
    let _e = setup();
    memfs::mkdir_p("/a");
    memfs::mkdir_p("/b");
    unshare();
    assert_eq!(mnt("/b", "/a", "", MS_BIND, ""), 0);
    assert!(!info().lines().last().unwrap().contains("shared:"));
    assert_eq!(mnt("", "/a", "", MS_SHARED, ""), 0);
    assert!(info().lines().last().unwrap().contains("shared:"));
    // Recursively from the root
    assert_eq!(mnt("", "/", "", MS_PRIVATE | MS_REC, ""), 0);
    assert!(!info().contains("shared:"));
    // On a path that is not a mount point: its mount
    assert_eq!(mnt("", "/b", "", MS_SHARED, ""), 0);
}

#[test]
fn move_mounts() {
    let _e = setup();
    let f = memfs::mkfile("/src/f", b"");
    memfs::mkdir_p("/old");
    memfs::mkdir_p("/new");
    unshare();
    assert_eq!(mnt("/src", "/old", "", MS_BIND, ""), 0);
    assert_eq!(mnt("/old", "/new", "", MS_MOVE, ""), 0);
    assert_eq!(stat("/new/f").unwrap().st_ino, f);
    assert_eq!(stat("/old/f").unwrap_err(), ENOENT);
    assert!(info().contains(" /new rw"));
    // Not a mount, the root, into itself
    assert_eq!(mnt("/src", "/old", "", MS_MOVE, ""), EINVAL);
    assert_eq!(mnt("/", "/old", "", MS_MOVE, ""), EINVAL);
    memfs::mkdir_p("/src/sub");
    assert_eq!(mnt("/new", "/new/sub", "", MS_MOVE, ""), EINVAL);
    assert_eq!(mnt("", "/old", "", MS_MOVE, ""), EFAULT);
}

#[test]
fn named_file_systems_are_served_by_name() {
    let _e = setup();
    memfs::mkdir_p("/newroot/proc");
    memfs::mkdir_p("/newroot/dev");
    memfs::mkdir_p("/newroot/sys");
    memfs::mkdir_p("/dev");
    memfs::mkdir_p("/sys");
    unshare();
    assert_eq!(mnt("proc", "/newroot/proc", "proc", MS_NOSUID, ""), 0);
    // Its files are /proc's
    assert_eq!(mount::canonical("/newroot/proc/version").as_deref(), Some("/proc/version"));
    assert_eq!(stat("/newroot/proc/version").unwrap().st_mode & 0o170000, 0o100000);
    assert!(mount::is_named_mountpoint("/newroot/proc"));
    // readlink of the mount point itself is not a link
    assert_eq!(sys(89, &[cstr("/newroot/proc"), buf(8), 8]), EINVAL);
    // devtmpfs and sysfs are binds of the system's /dev and /sys
    assert_eq!(mnt("udev", "/newroot/dev", "devtmpfs", 0, ""), 0);
    // (a tree of the pool, not a named mount: nothing to map)
    assert_eq!(mount::canonical("/newroot/dev/null"), None);
    assert_eq!(mnt("sysfs", "/newroot/sys", "sysfs", 0, ""), 0);
    // Other known types are named; unknown ones fail
    assert_eq!(mnt("mqueue", "/newroot/sys", "mqueue", 0, ""), 0);
    assert_eq!(mnt("x", "/newroot/sys", "overlay", 0, ""), ENODEV);
    assert_eq!(mnt("x", "/newroot/sys", "", 0, ""), EFAULT);
    // A file target for a new file system: ENOTDIR
    memfs::mkfile("/newroot/file", b"");
    assert_eq!(mnt("proc", "/newroot/file", "proc", 0, ""), ENOTDIR);
    // The initial table's own named mounts map nothing (they are where Hydra serves them)
    assert_eq!(mount::canonical("/proc/version"), None);
    // A pool mount on top of a named one hides it
    memfs::mkdir_p("/hide");
    assert_eq!(mnt("/hide", "/newroot/proc", "", MS_BIND, ""), 0);
    assert_eq!(mount::canonical("/newroot/proc/version"), None);
}

#[test]
fn bind_of_a_device_served_by_name() {
    let _e = setup();
    memfs::mkfile("/sandbox/null", b"");
    unshare();
    assert_eq!(mnt("/dev/null", "/sandbox/null", "", MS_BIND, ""), 0);
    assert_eq!(mount::canonical("/sandbox/null").as_deref(), Some("/dev/null"));
    let st = stat("/sandbox/null").unwrap();
    assert_eq!(st.st_mode & 0o170000, 0o020000);
    // A bind source given as /proc/self/fd/N of a by-name file
    let fd = open("/dev/zero", O_RDONLY);
    memfs::mkfile("/sandbox/zero", b"");
    assert_eq!(mnt(&format!("/proc/self/fd/{}", fd), "/sandbox/zero", "", MS_BIND, ""), 0);
    assert_eq!(mount::canonical("/sandbox/zero").as_deref(), Some("/dev/zero"));
}

#[test]
fn magic_descriptor_paths_as_targets() {
    let _e = setup();
    let f = memfs::mkfile("/src/f", b"");
    memfs::mkdir_p("/target");
    unshare();
    let d = open("/target", O_PATH | O_DIRECTORY);
    assert_eq!(mnt("/src", &format!("/proc/self/fd/{}", d), "", MS_BIND, ""), 0);
    assert_eq!(stat("/target/f").unwrap().st_ino, f);
}

#[test]
fn pivot_root_swaps_the_root() {
    let _e = setup();
    let f = memfs::mkfile("/newroot/etc/conf", b"");
    memfs::mkdir_p("/newroot/oldroot");
    memfs::mkfile("/outside", b"");
    unshare();
    task::add_process(600, 0);
    let ns = lx::proc::with(task::SELF_PID, |q| q.ns.mnt);
    lx::proc::with(600, |p| p.ns.mnt = ns);
    // new_root must be a mount
    assert_eq!(mount::dispatch(155, [cstr("/newroot"), cstr("/newroot/oldroot"), 0, 0, 0, 0]).unwrap(), EINVAL);
    assert_eq!(mnt("/newroot", "/newroot", "", MS_BIND, ""), 0);
    // put_old must be under new_root
    memfs::mkdir_p("/elsewhere");
    assert_eq!(mount::dispatch(155, [cstr("/newroot"), cstr("/elsewhere"), 0, 0, 0, 0]).unwrap(), EINVAL);
    assert_eq!(mount::dispatch(155, [cstr("/newroot"), cstr("/newroot/oldroot"), 0, 0, 0, 0]).unwrap(), 0);
    // Now / is the new root; the old one is under /oldroot
    assert_eq!(stat("/etc/conf").unwrap().st_ino, f);
    assert!(stat("/oldroot/outside").is_ok());
    assert_eq!(stat("/outside").unwrap_err(), ENOENT);
    let text = info();
    assert!(text.contains(" / / ") || text.lines().any(|l| l.split(' ').nth(4) == Some("/")));
    assert!(text.contains(" /oldroot "));
    assert!(text.contains(" /oldroot/proc "));
    // The other process of the namespace moved too
    let r = task::with_other(600, |t| t.fds.lock().root_ino).unwrap();
    assert_eq!(r, memfs::lookup("/newroot").unwrap());
    // Missing paths
    assert_eq!(mount::dispatch(155, [cstr("/none"), cstr("/oldroot"), 0, 0, 0, 0]).unwrap(), ENOENT);
    assert_eq!(mount::dispatch(155, [cstr("/"), cstr("/none"), 0, 0, 0, 0]).unwrap(), ENOENT);
    // The current root is not a new root
    assert_eq!(mount::dispatch(155, [cstr("/"), cstr("/oldroot"), 0, 0, 0, 0]).unwrap(), EINVAL);
}

#[test]
fn caller_needs_cap_sys_admin() {
    let _e = setup();
    memfs::mkdir_p("/m");
    unshare();
    task::set_caps(0);
    assert_eq!(mnt("tmpfs", "/m", "tmpfs", 0, ""), EPERM);
    assert_eq!(umount("/m", 0), EPERM);
    assert_eq!(mount::dispatch(155, [cstr("/"), cstr("/m"), 0, 0, 0, 0]).unwrap(), EPERM);
}

#[test]
fn unmount_lenient_paths() {
    let _e = setup();
    memfs::mkdir_p("/a");
    memfs::mkdir_p("/proc");
    unshare();
    // A named mount whose mount point is not in the pool
    assert_eq!(mnt("proc", "/proc", "proc", 0, ""), 0);
    assert_eq!(umount("/proc", 0), 0);
    // Remount of a named mount by its path when the path does not resolve
    assert_eq!(mnt("", "/dev/pts", "", MS_REMOUNT | MS_RDONLY, ""), 0);
    assert!(info().lines().any(|l| l.contains(" /dev/pts ro")));
    assert_eq!(umount("/nonexistent/x", 0), EINVAL);
}

#[test]
fn lookups_through_the_table() {
    let _e = setup();
    let f = memfs::mkfile("/src/f", b"");
    memfs::mkdir_p("/dst");
    unshare();
    assert_eq!(mnt("/src", "/dst", "", MS_BIND, ""), 0);
    // resolve and resolve_parent through the table
    assert_eq!(mount::resolve(0, b"/dst/f", true).unwrap().unwrap(), f);
    assert_eq!(mount::last_mount(), 8);
    let (p, name) = mount::resolve_parent(0, b"/dst/f").unwrap().unwrap();
    assert_eq!(p, memfs::lookup("/src").unwrap());
    assert_eq!(name, b"f");
    let (p2, n2) = mount::resolve_parent(0, b"f2").unwrap().unwrap();
    assert_eq!(p2, memfs::root());
    assert_eq!(n2, b"f2");
    assert_eq!(mount::resolve_parent(0, b"/dst/").unwrap().unwrap().1, b"dst");
    assert_eq!(mount::resolve_parent(0, b"/").unwrap().unwrap_err(), -17);
    assert_eq!(mount::resolve_parent(0, b"/dst/..").unwrap().unwrap_err(), -17);
    // A working directory inside the mount
    assert_eq!(sys(80, &[cstr("/dst")]), 0);
    let b = buf(32);
    let n = sys(79, &[b, 32]);
    assert_eq!(read(b, n as usize - 1), b"/dst");
    assert_eq!(stat("f").unwrap().st_ino, f);
    assert_eq!(stat("../dst/f").unwrap().st_ino, f);
    // A directory descriptor inside the mount: lookups start in that mount
    let d = open("/dst", O_RDONLY);
    assert_eq!(vnode(d).lock().mnt, 8);
    assert_eq!(fstatat(d as u64, "f", 0).unwrap().st_ino, f);
    assert_eq!(sys(81, &[d as u64]), 0);
    assert_eq!(task::with_current_fds_mut(|t| t.cwd_mnt), 8);
    // The thread's notes go when it exits
    mount::forget_thread(task::SELF_PID);
    assert_eq!(mount::last_mount(), 0);
    assert_eq!(mount::noted_base(), 0);
}

#[test]
fn other_process_roots() {
    let _e = setup();
    let f = memfs::mkfile("/jail/etc/x", b"");
    let jail = memfs::lookup("/jail").unwrap();
    let ns = unshare();
    // Another process in the namespace, chrooted in /jail
    let fds = task::add_process(700, 0);
    fds.lock().root_ino = jail;
    lx::proc::with(700, |p| p.ns.mnt = ns);
    let r = mount::process_root(700).unwrap();
    assert_eq!(r.0, ns);
    assert_eq!(r.1, jail);
    assert_eq!(mount::resolve_foreign(r, 0, 0, b"etc/x", true).unwrap(), f);
    assert_eq!(mount::last_foreign(), Some(r));
    mount::clear_foreign();
    assert_eq!(mount::last_foreign(), None);
    // A pending foreign lookup is taken once
    mount::note_foreign(r);
    assert_eq!(mount::take_foreign(), Some(r));
    assert_eq!(mount::take_foreign(), None);
    // The initial namespace's process root
    task::add_process(701, 0);
    let r0 = mount::process_root(701).unwrap();
    assert_eq!(r0.0, 0);
    assert!(mount::resolve_foreign(r0, 0, 0, b"jail/etc/x", true).is_ok());
    // A zombie or missing process
    lx::proc::with(701, |p| p.zombie = true);
    assert!(mount::process_root(701).is_none());
    assert!(mount::process_root(999).is_none());
    // Its namespace's default root and mount
    let fds2 = task::add_process(702, 0);
    let _ = fds2;
    lx::proc::with(702, |p| p.ns.mnt = ns);
    let r2 = mount::process_root(702).unwrap();
    assert_eq!((r2.1, r2.2), (memfs::root(), 1));
    // A missing namespace
    assert_eq!(mount::resolve_foreign((ns + 1000, 1, 1), 0, 0, b"x", true).unwrap_err(), ENOENT);
}

#[test]
fn open_through_proc_pid_root_and_its_descriptor() {
    let _e = setup();
    let f = memfs::mkfile("/jail/etc/x", b"");
    let jail = memfs::lookup("/jail").unwrap();
    let ns = unshare();
    let fds = task::add_process(710, 0);
    fds.lock().root_ino = jail;
    lx::proc::with(710, |p| p.ns.mnt = ns);
    // Back to the initial namespace ourselves
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = 0);
    task::with_current_fds_mut(|t| (t.root_mnt, t.cwd_mnt) = (0, 0));
    let d = open("/proc/710/root/etc", O_RDONLY | O_DIRECTORY);
    assert!(d >= 0, "{}", d);
    assert!(vnode(d).lock().foreign.is_some());
    // Lookups relative to it stay in that root
    assert_eq!(fstatat(d as u64, "x", 0).unwrap().st_ino, f);
    assert_eq!(fstatat(d as u64, "../../etc/x", 0).unwrap().st_ino, f);
}

#[test]
fn copy_of_a_namespace_and_collection() {
    let _e = setup();
    memfs::mkdir_p("/a");
    let f = memfs::mkfile("/b/f", b"");
    let ns1 = unshare();
    assert_eq!(mnt("/b", "/a", "", MS_BIND, ""), 0);
    // A child namespace copies the table (with new mount IDs)
    let ns2 = NS.fetch_add(1, Ordering::Relaxed);
    let fds = task::current(|t| t.fds.clone());
    mount::copy_ns(ns1, ns2, &fds);
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = ns2);
    assert_eq!(stat("/a/f").unwrap().st_ino, f);
    let first_id = |t: &str| t.lines().next().unwrap().split(' ').next().unwrap().to_string();
    let t2 = info();
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = ns1);
    let t1 = info();
    assert_ne!(first_id(&t1), first_id(&t2));
    // When no process uses ns1 any more, the next mount call drops its table
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = ns2);
    memfs::mkdir_p("/c");
    assert_eq!(mnt("/b", "/c", "", MS_BIND, ""), 0);
    lx::proc::with(task::SELF_PID, |p| p.ns.mnt = ns1);
    assert!(mount::mountinfo(task::SELF_PID).is_none());
}

#[test]
fn tmpfs_trees_go_with_their_last_mount() {
    let _e = setup();
    memfs::mkdir_p("/t");
    memfs::mkdir_p("/t2");
    let ns1 = unshare();
    assert_eq!(mnt("tmpfs", "/t", "tmpfs", 0, ""), 0);
    let fd = openat(AT_FDCWD, "/t/sub/../f", O_CREAT | O_WRONLY, 0o600);
    assert!(fd < 0); // sub does not exist
    assert_eq!(sys(83, &[cstr("/t/sub"), 0o755]), 0);
    assert!(openat(AT_FDCWD, "/t/sub/f", O_CREAT | O_WRONLY, 0o600) >= 0);
    // A bind of the tmpfs keeps the tree when the original goes
    assert_eq!(mnt("/t", "/t2", "", MS_BIND, ""), 0);
    assert_eq!(umount("/t", 0), 0);
    assert!(stat("/t2/sub/f").is_ok());
    // A namespace that dies with its tmpfs: the tree goes at the next collection
    let tmpdir = memfs::lookup("/.hydra-tmpfs").unwrap();
    let before = memfs::with(|fs| fs.readdir(tmpdir, 2, 100).unwrap().len());
    assert_eq!(before, 1);
    let _ = ns1;
    let ns2 = unshare();
    let _ = ns2;
    memfs::mkdir_p("/z");
    assert_eq!(mnt("/z", "/z", "", MS_BIND, ""), 0);
    let after = memfs::with(|fs| fs.readdir(tmpdir, 2, 100).unwrap().len());
    assert_eq!(after, 0);
}

// ------------------------------------------------------------ new mount API

fn fsopen(fs: &str, flags: u64) -> i64 {
    mount::dispatch_new(430, [cstr(fs), flags, 0, 0, 0, 0])
}

fn fsconfig(fd: i64, cmd: u64, key: &str, value: &str, aux: u64) -> i64 {
    let p = |s: &str| if s.is_empty() { 0 } else { cstr(s) };
    mount::dispatch_new(431, [fd as u64, cmd, p(key), p(value), aux, 0])
}

fn fsmount(fd: i64, flags: u64, attr: u64) -> i64 {
    mount::dispatch_new(432, [fd as u64, flags, attr, 0, 0, 0])
}

fn move_mount(from_fd: i64, from: &str, to_fd: i64, to: &str, flags: u64) -> i64 {
    let p = |s: &str| if s.is_empty() { 0 } else { cstr(s) };
    mount::dispatch_new(429, [from_fd as u64, p(from), to_fd as u64, p(to), flags, 0])
}

#[test]
fn fsopen_fsconfig_fsmount_move_mount() {
    let _e = setup();
    memfs::mkdir_p("/mnt");
    // Only in a namespace of one's own
    assert_eq!(fsopen("tmpfs", 0), EPERM);
    unshare();
    assert_eq!(fsopen("tmpfs", 2), EINVAL);
    assert_eq!(fsopen("ext4", 0), ENODEV);
    let ctx = fsopen("tmpfs", 1);
    assert!(ctx >= 0);
    assert!(task::with_current_fds_mut(|t| t.cloexec(ctx as usize)));
    match desc(ctx) {
        Some(FileDescriptor::Device(d)) => {
            assert_eq!(d.path(), "anon_inode:[fscontext]");
            let mut b = [0u8; 4];
            assert_eq!(d.read(&mut b), EINVAL);
            assert_eq!(d.poll_events(), 0);
            assert_eq!(d.rdev(), 0);
            assert!(!d.nonblock());
            d.set_nonblock(true);
        }
        _ => panic!(),
    }
    // Options
    assert_eq!(fsconfig(ctx, 0, "ro", "", 0), 0);
    assert_eq!(fsconfig(ctx, 0, "rw", "", 0), 0);
    assert_eq!(fsconfig(ctx, 0, "noswap", "", 0), 0);
    assert_eq!(fsconfig(ctx, 0, "", "", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 0, "x", "v", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 1, "mode", "0700", 0), 0);
    assert_eq!(fsconfig(ctx, 1, "source", "mytmp", 0), 0);
    assert_eq!(fsconfig(ctx, 1, "source", "again", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 1, "mode", "", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 1, "", "x", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 1, "k", "v", 1), EINVAL);
    assert_eq!(fsconfig(ctx, 2, "k", "v", 1), EINVAL);
    assert_eq!(fsconfig(ctx, 5, "k", "", 3), EINVAL);
    assert_eq!(fsconfig(ctx, 99, "", "", 0), EOPNOTSUPP);
    assert_eq!(fsconfig(ctx, 7, "", "", 0), EINVAL); // reconfigure without fspick
    // fsmount before CMD_CREATE
    assert_eq!(fsmount(ctx, 0, 0), EINVAL);
    assert_eq!(fsconfig(ctx, 6, "x", "", 0), EINVAL);
    assert_eq!(fsconfig(ctx, 6, "", "", 0), 0);
    assert_eq!(fsconfig(ctx, 8, "", "", 0), EBUSY);
    assert_eq!(fsmount(ctx, 2, 0), EINVAL);
    assert_eq!(fsmount(ctx, 0, 0x100_000), EINVAL); // MOUNT_ATTR_IDMAP
    let m = fsmount(ctx, 1, 0x1 | 0x8 | 0x10);
    assert!(m >= 0, "{}", m);
    assert_eq!(fsmount(ctx, 0, 0), EBUSY);
    // Detached: its path is "/"
    match desc(m) {
        Some(FileDescriptor::Device(d)) => assert_eq!(d.path(), "/"),
        _ => panic!(),
    }
    // Attach it
    assert_eq!(move_mount(m, "", AT_FDCWD as i64, "/mnt", 4), 0);
    assert!(info().contains(" /mnt ro,noexec,noatime - tmpfs mytmp ro"));
    match desc(m) {
        Some(FileDescriptor::Device(d)) => assert_eq!(d.path(), "/mnt"),
        _ => panic!(),
    }
    // Moving the attached mount object again moves the mount
    memfs::mkdir_p("/mnt2");
    assert_eq!(move_mount(m, "", AT_FDCWD as i64, "/mnt2", 4), 0);
    assert!(info().contains(" /mnt2 "));
    // Bad flags, empty paths without the flags, a non-mount descriptor
    assert_eq!(move_mount(m, "", AT_FDCWD as i64, "/mnt", 0x100), EINVAL);
    assert_eq!(move_mount(m, "", AT_FDCWD as i64, "/mnt", 0), ENOENT);
    assert_eq!(move_mount(AT_FDCWD as i64, "/mnt2", AT_FDCWD as i64, "", 0), ENOENT);
    assert_eq!(fsconfig(900, 0, "ro", "", 0), EBADF);
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(fsconfig(c, 0, "ro", "", 0), EINVAL);
    assert_eq!(fsconfig(m, 0, "ro", "", 0), EINVAL); // a mount, not a context
    assert_eq!(fsmount(m, 0, 0), EINVAL);
    // move_mount by path: an attached mount
    memfs::mkdir_p("/mnt3");
    assert_eq!(move_mount(AT_FDCWD as i64, "/mnt2", AT_FDCWD as i64, "/mnt3", 0), 0);
    assert!(info().contains(" /mnt3 "));
}

#[test]
fn open_tree_clone_and_mount_setattr() {
    let _e = setup();
    let f = memfs::mkfile("/src/f", b"");
    memfs::mkdir_p("/dst");
    // A plain open_tree is an O_PATH descriptor (any namespace)
    let p = mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 0, 0, 0, 0]);
    assert!(p >= 0);
    assert_eq!(vnode(p).lock().flags & 0o10000000, 0o10000000);
    let p2 = mount::dispatch_new(428, [p as u64, 0, 0x1000, 0, 0, 0]);
    assert!(p2 >= 0);
    assert_eq!(mount::dispatch_new(428, [p as u64, 0, 0, 0, 0, 0]), ENOENT);
    assert_eq!(mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 0x40000000, 0, 0, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 0x8000, 0, 0, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 1, 0, 0, 0]), EPERM);
    unshare();
    let t = mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 1 | 0o2000000, 0, 0, 0]);
    assert!(t >= 0);
    // mount_setattr on the detached clone: kept for when it is attached
    let attr = buf(32);
    write(attr, &[1u64.to_le_bytes(), 0u64.to_le_bytes(), MS_SHARED.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [t as u64, 0, 0x1000, attr, 32, 0]), 0);
    assert_eq!(move_mount(t, "", AT_FDCWD as i64, "/dst", 4), 0);
    assert_eq!(stat("/dst/f").unwrap().st_ino, f);
    let last = info().lines().last().unwrap().to_string();
    assert!(last.contains(" /dst ro") && last.contains("shared:"));
    // On the attached one: goes to the mount
    write(attr, &[0u64.to_le_bytes(), 1u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [t as u64, 0, 0x1000, attr, 32, 0]), 0);
    assert!(info().lines().last().unwrap().contains(" /dst rw"));
    // By path, recursively; atime modes
    write(attr, &[0x10u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0x8000, attr, 32, 0]), 0);
    assert!(info().lines().last().unwrap().contains("noatime"));
    // Errors: flags, size, trailing bytes, unknown attributes, idmap, propagation
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0x2, attr, 32, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, attr, 16, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, attr, 5000, 0]), -7);
    let big = buf(64);
    write(big, &[0u8; 32]);
    write(big + 40, &[1]);
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, big, 64, 0]), -7);
    write(attr, &[0x4000u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, attr, 32, 0]), EINVAL);
    write(attr, &[0x10_0000u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, attr, 32, 0]), EINVAL);
    write(attr, &[0u64.to_le_bytes(), 0u64.to_le_bytes(), 3u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, attr, 32, 0]), EINVAL);
    write(attr, &[0u8; 32]);
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, 0, 0, attr, 32, 0]), ENOENT);
    assert_eq!(mount::dispatch_new(442, [AT_FDCWD, cstr("/dst"), 0, 16, 32, 0]), EFAULT);
    // A recursive clone
    memfs::mkdir_p("/src/sub");
    memfs::mkdir_p("/other");
    memfs::mkdir_p("/dst2");
    assert_eq!(mnt("/other", "/src/sub", "", MS_BIND, ""), 0);
    let rt = mount::dispatch_new(428, [AT_FDCWD, cstr("/src"), 1 | 0x8000, 0, 0, 0]);
    write(attr, &[MS_NOSUID.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(mount::dispatch_new(442, [rt as u64, 0, 0x1000, attr, 32, 0]), 0);
    assert_eq!(move_mount(rt, "", AT_FDCWD as i64, "/dst2", 4), 0);
    assert!(info().contains(" /dst2/sub "));
}

#[test]
fn fspick_reconfigures() {
    let _e = setup();
    memfs::mkdir_p("/m");
    unshare();
    assert_eq!(mnt("tmpfs", "/m", "tmpfs", 0, ""), 0);
    assert_eq!(mount::dispatch_new(433, [AT_FDCWD, cstr("/m"), 0x10, 0, 0, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(433, [AT_FDCWD, 0, 0, 0, 0, 0]), ENOENT);
    memfs::mkdir_p("/notmnt");
    assert_eq!(mount::dispatch_new(433, [AT_FDCWD, cstr("/notmnt"), 0, 0, 0, 0]), EINVAL);
    let c = mount::dispatch_new(433, [AT_FDCWD, cstr("/m"), 1, 0, 0, 0]);
    assert!(c >= 0);
    assert_eq!(fsconfig(c, 0, "ro", "", 0), 0);
    assert_eq!(fsconfig(c, 7, "", "", 0), 0);
    assert!(info().contains(" /m ro"));
    assert_eq!(fsconfig(c, 6, "", "", 0), EBUSY);
    assert_eq!(fsmount(c, 0, 0), EINVAL);
    assert_eq!(fsconfig(c, 0, "rw", "", 0), 0);
    assert_eq!(fsconfig(c, 7, "", "", 0), 0);
    assert!(info().contains(" /m rw"));
}

#[test]
fn statmount_and_listmount() {
    let _e = setup();
    // In the initial namespace: the fixed table
    let req = buf(24);
    write(req, &[24u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec(), u64::MAX.to_le_bytes().to_vec(), 0u64.to_le_bytes().to_vec()].concat());
    let ids = buf(8 * 32);
    let n = mount::dispatch_new(458, [req, ids, 32, 0, 0, 0]);
    assert_eq!(n, 7);
    let first = read_u64(ids);
    assert_eq!(first, (1 << 32) + 22);
    // Reverse, after a cursor
    write(req + 16, &((1u64 << 32) + 25).to_le_bytes());
    assert_eq!(mount::dispatch_new(458, [req, ids, 32, 1, 0, 0]), 3);
    assert_eq!(read_u64(ids), (1 << 32) + 24);
    // Children of a mount (/sys: cgroup)
    write(req, &[24u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec(), ((1u64 << 32) + 23).to_le_bytes().to_vec(), 0u64.to_le_bytes().to_vec()].concat());
    assert_eq!(mount::dispatch_new(458, [req, ids, 32, 0, 0, 0]), 1);
    assert_eq!(read_u64(ids), (1 << 32) + 27);
    write(req + 8, &((1u64 << 32) + 99).to_le_bytes());
    assert_eq!(mount::dispatch_new(458, [req, ids, 32, 0, 0, 0]), ENOENT);
    assert_eq!(mount::dispatch_new(458, [req, ids, 32, 2, 0, 0]), EINVAL);
    write(req, &8u32.to_le_bytes());
    assert_eq!(mount::dispatch_new(458, [req, ids, 32, 0, 0, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(458, [16, ids, 32, 0, 0, 0]), EFAULT);
    write(req, &[24u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec(), u64::MAX.to_le_bytes().to_vec(), 0u64.to_le_bytes().to_vec()].concat());
    assert_eq!(mount::dispatch_new(458, [req, 16, 32, 0, 0, 0]), EFAULT);
    // statmount of the root mount, everything
    write(req, &[24u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec(), ((1u64 << 32) + 2069).to_le_bytes().to_vec(), 0x2ffu64.to_le_bytes().to_vec()].concat());
    let out = buf(2048);
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 0, 0, 0]), 0);
    let v = read(out, 2048);
    let u32a = |o: usize| u32::from_le_bytes(v[o..o + 4].try_into().unwrap());
    let u64a = |o: usize| u64::from_le_bytes(v[o..o + 8].try_into().unwrap());
    assert_eq!(u64a(8), 0x2ff);
    assert_eq!(u64a(24), 0x2fc1_2fc1);
    assert_eq!(u64a(40), (1 << 32) + 2069);
    assert_eq!(u32a(56), 2069);
    assert_eq!(u64a(72), MS_SHARED);
    assert_eq!(u64a(80), 1);
    let s = |o: usize| {
        let at = 512 + u32a(o) as usize;
        let end = v[at..].iter().position(|&c| c == 0).unwrap() + at;
        String::from_utf8(v[at..end].to_vec()).unwrap()
    };
    assert_eq!(s(36), "zfs");
    assert_eq!(s(108), "/");
    assert_eq!(s(104), "/");
    assert_eq!(s(124), "hydrapool/root");
    assert_eq!(s(4), "xattr");
    // proc: its attributes
    write(req + 8, &((1u64 << 32) + 22).to_le_bytes());
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 0, 0, 0]), 0);
    let v = read(out, 2048);
    assert_eq!(u64::from_le_bytes(v[64..72].try_into().unwrap()), 2 | 4 | 8);
    // Too small a buffer; a bad one; flags; a missing mount; a short request
    assert_eq!(mount::dispatch_new(457, [req, out, 100, 0, 0, 0]), -75);
    assert_eq!(mount::dispatch_new(457, [req, 16, 2048, 0, 0, 0]), EFAULT);
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 1, 0, 0]), EINVAL);
    write(req + 8, &((1u64 << 32) + 5).to_le_bytes());
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 0, 0, 0]), ENOENT);
    write(req, &4u32.to_le_bytes());
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 0, 0, 0]), EINVAL);
    assert_eq!(mount::dispatch_new(457, [16, out, 2048, 0, 0, 0]), EFAULT);
    // In a namespace of one's own: its table (with the read-only option and ns id)
    memfs::mkdir_p("/x");
    let ns = unshare();
    assert_eq!(mnt("tmpfs", "/x", "tmpfs", MS_RDONLY, ""), 0);
    let last_id: u64 = info().lines().last().unwrap().split(' ').next().unwrap().parse().unwrap();
    write(req, &[24u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec(), ((1u64 << 32) + last_id).to_le_bytes().to_vec(), 0x41u64.to_le_bytes().to_vec()].concat());
    assert_eq!(mount::dispatch_new(457, [req, out, 2048, 0, 0, 0]), 0);
    let v = read(out, 2048);
    assert_eq!(u32::from_le_bytes(v[32..36].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(v[112..120].try_into().unwrap()), ns);
    assert_eq!(u64::from_le_bytes(v[24..32].try_into().unwrap()), 0x0102_1994);
}

// wave7 G7-7 begin: the generations and the file service's copy of a table
#[test]
fn the_file_services_view_follows_every_change() {
    let _e = setup();
    memfs::mkdir_p("/data");
    memfs::mkdir_p("/ro");
    memfs::mkdir_p("/tmp");
    memfs::mkdir_p("/newroot/proc");
    memfs::mkfile("/sandbox/null", b"");
    // Not a namespace the kernel knows yet
    assert_eq!(mount::vfs_table(987_654).unwrap_err(), -3);
    assert_eq!(mount::vfs_gen(987_654), None);
    let ns = unshare();
    let g0 = mount::vfs_gen(ns).unwrap();
    assert!(g0 > 0);
    let (g, root, t0) = mount::vfs_table(ns).unwrap();
    assert_eq!((g, root), (g0, 1));
    // The root is a pool tree; the standard named mounts are where Hydra serves them
    assert_eq!(t0[0].kind, mount::VFS_TREE);
    assert!(t0[1..].iter().all(|m| m.kind == mount::VFS_HOLE));
    // A read-only bind: a new generation, a tree with its flags and mount point
    assert_eq!(mnt("/data", "/ro", "", MS_BIND | MS_RDONLY, ""), 0);
    let g1 = mount::vfs_gen(ns).unwrap();
    assert!(g1 > g0);
    let (_, _, t1) = mount::vfs_table(ns).unwrap();
    let ro = t1.last().unwrap();
    assert_eq!((ro.kind, ro.flags & 1, ro.parent), (mount::VFS_TREE, 1, 1));
    assert_eq!(ro.mountpoint, memfs::lookup("/ro").unwrap());
    assert_eq!(ro.root, memfs::lookup("/data").unwrap());
    // tmpfs
    assert_eq!(mnt("tmpfs", "/tmp", "tmpfs", 0, ""), 0);
    assert_eq!(mount::vfs_table(ns).unwrap().2.last().unwrap().kind, mount::VFS_TMPFS);
    // proc somewhere else and a bind of a device served by name: the kernel's below them
    assert_eq!(mnt("proc", "/newroot/proc", "proc", 0, ""), 0);
    assert_eq!(mount::vfs_table(ns).unwrap().2.last().unwrap().kind, mount::VFS_KERNEL);
    assert_eq!(mnt("/dev/null", "/sandbox/null", "", MS_BIND, ""), 0);
    assert_eq!(mount::vfs_table(ns).unwrap().2.last().unwrap().kind, mount::VFS_KERNEL);
    // Even a failed call moves the generation (nothing is lost by taking a table again)
    let g2 = mount::vfs_gen(ns).unwrap();
    assert!(umount("/nowhere", 0) < 0);
    assert!(mount::vfs_gen(ns).unwrap() > g2);
    // An unmount empties the slot; statmount/listmount do not move it
    let before = mount::vfs_table(ns).unwrap().2.len();
    assert_eq!(umount("/ro", 0), 0);
    let (g3, _, t3) = mount::vfs_table(ns).unwrap();
    assert_eq!(t3.len(), before);
    assert_eq!(t3[1 + 6].kind, mount::VFS_HOLE);
    let _ = mount::dispatch_new(458, [0, 0, 0, 0, 0, 0]);
    assert_eq!(mount::vfs_gen(ns), Some(g3));
    // A nosymfollow mount: the kernel walks this table
    assert_eq!(mnt("/data", "/ro", "", MS_BIND | 256, ""), 0);
    assert_eq!(mount::vfs_gen(ns), None);
    assert_eq!(mount::vfs_table(ns).unwrap_err(), -95);
}

#[test]
fn the_initial_namespace_has_a_generation_for_its_fuse_mounts() {
    let _e = setup();
    let (g, root, t) = mount::vfs_table(0).unwrap();
    assert_eq!(root, 0);
    assert_eq!(mount::vfs_gen(0), Some(g));
    assert!(t.iter().all(|m| m.kind == mount::VFS_KERNEL && m.parent == 0));
    mount::bump(0);
    assert!(mount::vfs_gen(0).unwrap() > g);
}
// wave7 G7-7 end
