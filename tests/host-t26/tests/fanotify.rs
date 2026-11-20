//! fanotify.rs: groups, marks, events from the file layer and the file server, reading
//! records, permission events, file handles.
mod common;
use common::*;
use lx::fanotify as fan;
use std::sync::Arc;

const FAN_ACCESS: u64 = 0x1;
const FAN_MODIFY: u64 = 0x2;
const FAN_ATTRIB: u64 = 0x4;
const FAN_CLOSE_WRITE: u64 = 0x8;
const FAN_CLOSE_NOWRITE: u64 = 0x10;
const FAN_OPEN: u64 = 0x20;
const FAN_CREATE: u64 = 0x100;
const FAN_DELETE: u64 = 0x200;
const FAN_DELETE_SELF: u64 = 0x400;
const FAN_OPEN_EXEC: u64 = 0x1000;
const FAN_Q_OVERFLOW: u64 = 0x4000;
const FAN_OPEN_PERM: u64 = 0x1_0000;
const FAN_OPEN_EXEC_PERM: u64 = 0x4_0000;
const FAN_ON_CHILD: u64 = 0x0800_0000;
const FAN_ONDIR: u64 = 0x4000_0000;
const FAN_CLASS_CONTENT: u64 = 0x4;
const FAN_REPORT_FID: u64 = 0x200;
const FAN_REPORT_DIR_FID: u64 = 0x400;
const FAN_REPORT_NAME: u64 = 0x800;
const FAN_NONBLOCK: u64 = 2;
const MARK_ADD: u64 = 1;
const MARK_REMOVE: u64 = 2;
const MARK_MOUNT: u64 = 0x10;
const MARK_IGNORED: u64 = 0x20;
const MARK_FLUSH: u64 = 0x80;
const MARK_FS: u64 = 0x100;

fn init(flags: u64, f_flags: u64) -> i64 {
    fan::dispatch(300, [flags, f_flags, 0, 0, 0, 0])
}

fn mark(fd: i64, flags: u64, mask: u64, path: &str) -> i64 {
    fan::dispatch(301, [fd as u64, flags, mask, AT_FDCWD, if path.is_empty() { 0 } else { cstr(path) }, 0])
}

fn dev(fd: i64) -> Arc<dyn lx::chardev::CharDevice> {
    match desc(fd) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!(),
    }
}

/// Reads the group's records: (mask, fd, pid, info bytes).
fn events(fd: i64) -> Vec<(u64, i32, i32, Vec<u8>)> {
    let d = dev(fd);
    let mut b = vec![0u8; 65536];
    let n = d.read_unlocked(&mut b).unwrap();
    assert!(n >= 0, "read: {}", n);
    let mut out = Vec::new();
    let mut o = 0;
    while o < n as usize {
        let len = u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
        assert_eq!(b[o + 4], 3);
        let mask = u64::from_le_bytes(b[o + 8..o + 16].try_into().unwrap());
        let efd = i32::from_le_bytes(b[o + 16..o + 20].try_into().unwrap());
        let pid = i32::from_le_bytes(b[o + 20..o + 24].try_into().unwrap());
        out.push((mask, efd, pid, b[o + 24..o + len].to_vec()));
        o += len;
    }
    out
}

#[test]
fn init_checks() {
    let _e = setup();
    assert!(!fan::active() || true);
    assert_eq!(init(1 << 20, 0), EINVAL);
    assert_eq!(init(0xc, 0), EINVAL); // both classes
    assert_eq!(init(0, 3), EINVAL); // bad access mode
    assert_eq!(init(0, 1 << 30), EINVAL);
    assert_eq!(init(FAN_REPORT_NAME, 0), EINVAL); // NAME without DIR_FID
    assert_eq!(init(FAN_REPORT_FID | FAN_CLASS_CONTENT, 0), EINVAL);
    let g = init(1 | FAN_NONBLOCK, 0);
    assert!(g >= 0);
    assert!(fan::active());
    assert!(task::with_current_fds_mut(|t| t.cloexec(g as usize)));
    let d = dev(g);
    assert_eq!(d.path(), "anon_inode:[fanotify]");
    assert!(d.nonblock());
    assert_eq!(d.rdev(), 0);
    d.set_nonblock(false);
    let mut b = [0u8; 4];
    assert_eq!(d.read(&mut b), EINVAL);
    // Unprivileged: file handles needed, no admin flags
    become_user(1000);
    assert_eq!(init(0, 0), EPERM);
    assert_eq!(init(FAN_REPORT_FID | 0x10, 0), EPERM);
    assert!(init(FAN_REPORT_FID, 0) >= 0);
    // A full table
    lx::limits::NOFILE.set(1);
    assert_eq!(init(FAN_REPORT_FID, 0), -24);
}

#[test]
fn mark_checks() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let g = init(0, 0);
    assert_eq!(mark(g, MARK_ADD | 0x10000, FAN_OPEN, "/f"), EINVAL);
    assert_eq!(mark(g, MARK_ADD | MARK_REMOVE, FAN_OPEN, "/f"), EINVAL);
    assert_eq!(mark(g, MARK_ADD | MARK_MOUNT | MARK_FS, FAN_OPEN, "/f"), EINVAL);
    assert_eq!(mark(g, MARK_ADD, 0, "/f"), EINVAL);
    assert_eq!(mark(g, MARK_ADD, 1 << 40, "/f"), EINVAL);
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN_PERM, "/f"), EINVAL); // notification class
    assert_eq!(mark(g, MARK_ADD, FAN_CREATE, "/f"), EINVAL); // needs file handles
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN, "/none"), ENOENT);
    assert_eq!(mark(g, MARK_ADD | 8, FAN_OPEN, "/f"), ENOTDIR); // ONLYDIR
    assert_eq!(mark(g, MARK_REMOVE, FAN_OPEN, "/f"), ENOENT);
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN, "/f"), 0);
    assert_eq!(mark(g, MARK_REMOVE, FAN_OPEN, "/f"), 0);
    assert_eq!(mark(g, MARK_REMOVE, FAN_OPEN, "/f"), ENOENT); // gone with nothing left
    assert_eq!(mark(g, MARK_FLUSH, 0, ""), 0);
    assert_eq!(mark(g, MARK_FLUSH | MARK_MOUNT, 0, ""), 0);
    assert_eq!(mark(g, MARK_FLUSH | MARK_FS, 0, ""), 0);
    // Not a group; not a descriptor
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(mark(c, MARK_ADD, FAN_OPEN, "/f"), EINVAL);
    let td: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let t = install(FileDescriptor::Device(td));
    assert_eq!(mark(t, MARK_ADD, FAN_OPEN, "/f"), EINVAL);
    assert_eq!(mark(900, MARK_ADD, FAN_OPEN, "/f"), EBADF);
    assert_eq!(fan::dispatch(301, [g as u64, MARK_ADD, FAN_OPEN, AT_FDCWD, 16, 0]), EFAULT);
    // A mount mark with directory entry events
    let f = init(FAN_REPORT_FID | FAN_REPORT_DIR_FID, 0);
    assert_eq!(mark(f, MARK_ADD | MARK_MOUNT, FAN_CREATE, "/"), EINVAL);
    // An unprivileged group: inode marks on readable files only
    become_user(1000);
    let u = init(FAN_REPORT_FID, 0);
    assert_eq!(mark(u, MARK_ADD | MARK_FS, FAN_OPEN, "/"), EPERM);
    let s = memfs::mkfile("/secret", b"");
    memfs::chmod(s, 0o600);
    assert_eq!(mark(u, MARK_ADD, FAN_OPEN, "/secret"), EACCES);
    assert_eq!(mark(u, MARK_ADD, FAN_OPEN, "/f"), 0);
}

#[test]
fn opens_and_closes_are_reported_with_descriptors() {
    let _e = setup();
    let ino = memfs::mkfile("/watched", b"data");
    memfs::mkfile("/other", b"");
    let g = init(FAN_NONBLOCK, O_RDONLY);
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN | FAN_CLOSE_NOWRITE | FAN_CLOSE_WRITE | FAN_ACCESS | FAN_MODIFY, "/watched"), 0);
    let fd = open("/watched", O_RDONLY);
    let _ = open("/other", O_RDONLY);
    close(fd);
    let ev = events(g);
    // Open and close-nowrite of one process on one file merge into one record
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, FAN_OPEN | FAN_CLOSE_NOWRITE);
    assert_eq!(ev[0].2 as u64, task::SELF_PID);
    // The record's descriptor is open on the file and makes no events itself
    let efd = ev[0].1 as i64;
    assert_eq!(vnode(efd).lock().ino, ino);
    assert!(vnode(efd).lock().nonotify);
    close(efd);
    // Nothing queued now: EAGAIN (non-blocking)
    let mut b = vec![0u8; 256];
    assert_eq!(dev(g).read_unlocked(&mut b), Some(EAGAIN));
    assert_eq!(dev(g).poll_events(), 0);
    // Writing: open, modify, close-write
    let w = open("/watched", O_WRONLY);
    vnode(w).lock().fan(FAN_MODIFY);
    close(w);
    assert_eq!(dev(g).poll_events(), 0x41);
    let n = buf(4);
    assert_eq!(dev(g).ioctl(0x541B, n), 0);
    assert_eq!(read_i32(n), 24);
    assert_eq!(dev(g).ioctl(0x541B, 16), EFAULT);
    assert_eq!(dev(g).ioctl(0x1234, n), -25);
    let ev = events(g);
    assert_eq!(ev[0].0, FAN_OPEN | FAN_MODIFY | FAN_CLOSE_WRITE);
}

#[test]
fn reading_waits_and_buffers() {
    let _e = setup();
    memfs::mkfile("/w", b"");
    let g = init(0, 0);
    mark(g, MARK_ADD, FAN_OPEN, "/w");
    // Nothing yet: a signal ends the wait
    lx::proc::SIGNAL.set(true);
    let mut b = vec![0u8; 256];
    assert_eq!(dev(g).read_unlocked(&mut b), Some(-4));
    lx::proc::SIGNAL.set(false);
    // A blocking read gets what arrives while it waits
    task::wait::on_wait(|| {
        let _ = open("/w", O_RDONLY);
    });
    assert_eq!(dev(g).read_unlocked(&mut b), Some(24));
    task::wait::clear_on_wait();
    // A buffer too small for one record: EINVAL; two records only partly fit
    memfs::mkfile("/w2", b"");
    mark(g, MARK_ADD, FAN_OPEN, "/w2");
    let _ = open("/w", O_RDONLY);
    let _ = open("/w2", O_RDONLY);
    let mut small = vec![0u8; 10];
    assert_eq!(dev(g).read_unlocked(&mut small), Some(EINVAL));
    let mut one = vec![0u8; 30];
    assert_eq!(dev(g).read_unlocked(&mut one), Some(24));
    // The reader's table is full: the event cannot be given
    lx::limits::NOFILE.set(1);
    assert_eq!(dev(g).read_unlocked(&mut b), Some(-24));
}

#[test]
fn ignore_masks_children_and_directories() {
    let _e = setup();
    memfs::mkfile("/d/a", b"");
    memfs::mkfile("/d/b", b"");
    memfs::mkdir_p("/d/sub");
    let g = init(FAN_NONBLOCK, 0);
    // A directory mark with ON_CHILD sees its files
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN | FAN_ON_CHILD, "/d"), 0);
    let _ = open("/d/a", O_RDONLY);
    let ev = events(g);
    assert_eq!(ev.len(), 1);
    // Ignore b
    assert_eq!(mark(g, MARK_ADD | MARK_IGNORED, FAN_OPEN, "/d/b"), 0);
    let _ = open("/d/b", O_RDONLY);
    assert_eq!(dev(g).poll_events(), 0);
    // Subdirectories only with FAN_ONDIR
    let _ = open("/d/sub", O_RDONLY);
    assert_eq!(dev(g).poll_events(), 0);
    assert_eq!(mark(g, MARK_ADD, FAN_ONDIR, "/d"), 0);
    let _ = open("/d/sub", O_RDONLY);
    let ev = events(g);
    assert_eq!(ev[0].0, FAN_OPEN | FAN_ONDIR);
    // Removing the ignore mask; removing everything
    assert_eq!(mark(g, MARK_REMOVE | MARK_IGNORED, FAN_OPEN, "/d/b"), 0);
    assert_eq!(mark(g, MARK_REMOVE, FAN_OPEN | FAN_ON_CHILD | FAN_ONDIR, "/d"), 0);
    let _ = open("/d/a", O_RDONLY);
    assert_eq!(dev(g).poll_events(), 0);
}

#[test]
fn mount_and_filesystem_marks_see_everything() {
    let _e = setup();
    memfs::mkfile("/x/y", b"");
    let g = init(FAN_NONBLOCK, 0);
    assert_eq!(mark(g, MARK_ADD | MARK_MOUNT, FAN_OPEN, "/"), 0);
    let _ = open("/x/y", O_RDONLY);
    assert_eq!(events(g).len(), 1);
    assert_eq!(mark(g, MARK_FLUSH | MARK_MOUNT, 0, ""), 0);
    assert_eq!(mark(g, MARK_ADD | MARK_FS, FAN_OPEN | FAN_ONDIR, "/"), 0);
    let _ = open("/x", O_RDONLY);
    assert_eq!(events(g)[0].0, FAN_OPEN | FAN_ONDIR);
    // A directory without FAN_ONDIR: only ignores apply
    assert_eq!(mark(g, MARK_REMOVE | MARK_FS, FAN_ONDIR, "/"), 0);
    let _ = open("/x", O_RDONLY);
    assert_eq!(dev(g).poll_events(), 0);
    // The ignore mask takes FAN_ONDIR into the mark
    assert_eq!(mark(g, MARK_ADD | MARK_IGNORED | MARK_FS, FAN_OPEN | FAN_ONDIR, "/"), 0);
    let _ = open("/x/y", O_RDONLY);
    assert_eq!(dev(g).poll_events(), 0);
}

#[test]
fn file_handle_groups_get_directory_events() {
    let _e = setup();
    let d = memfs::mkdir_p("/dir");
    let g = init(FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME, 0);
    assert_eq!(mark(g, MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_ATTRIB | FAN_ONDIR, "/dir"), 0);
    fan::fs_event(d, 0x100, b"newfile");
    let ev = events(g);
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, FAN_CREATE);
    assert_eq!(ev[0].1, -1); // no descriptor
    // A DFID_NAME record: type 2, the fsid, an 8-byte handle (the directory), the name
    let info = &ev[0].3;
    assert_eq!(info[0], 2);
    assert_eq!(u16::from_le_bytes([info[2], info[3]]) as usize, info.len());
    assert_eq!(i32::from_le_bytes(info[4..8].try_into().unwrap()), fan::POOL_FSID[0]);
    assert_eq!(u32::from_le_bytes(info[12..16].try_into().unwrap()), 8);
    assert_eq!(u64::from_le_bytes(info[20..28].try_into().unwrap()), d);
    assert_eq!(&info[28..35], b"newfile");
    // A subdirectory made: with FAN_ONDIR
    fan::fs_event(d, 0x4000_0100, b"subdir");
    assert_eq!(events(g)[0].0, FAN_CREATE | FAN_ONDIR);
    // Attributes of the directory itself: DFID (no name) and FID records
    fan::fs_event(d, 0x4000_0004, b"");
    let ev = events(g);
    assert_eq!(ev[0].0, FAN_ATTRIB | FAN_ONDIR);
    assert_eq!(ev[0].3[0], 3);
    // Events nobody asked for, or of the wrong kind
    fan::fs_event(d, 0x2, b"");
    fan::fs_event(d, 0x2, b"x");
    assert_eq!(dev(g).poll_events(), 0);
    // A notification group never gets them
    let n = init(FAN_NONBLOCK, 0);
    mark(n, MARK_ADD, FAN_OPEN, "/dir");
    fan::fs_event(d, 0x100, b"zz");
    assert_eq!(dev(n).poll_events(), 0);
}

#[test]
fn fid_records_by_flags() {
    let _e = setup();
    let d = memfs::mkdir_p("/dir");
    let f = memfs::mkfile("/dir/f", b"");
    // FID only: an entry event reports the directory as the object
    let g = init(FAN_NONBLOCK | FAN_REPORT_FID, 0);
    mark(g, MARK_ADD, FAN_DELETE | FAN_DELETE_SELF | FAN_OPEN | FAN_ON_CHILD, "/dir");
    fan::fs_event(d, 0x200, b"gone");
    let ev = events(g);
    assert_eq!(ev[0].3[0], 1);
    assert_eq!(u64::from_le_bytes(ev[0].3[20..28].try_into().unwrap()), d);
    // A file opened in the directory: its FID; pid as seen
    let _ = open("/dir/f", O_RDONLY);
    let ev = events(g);
    assert_eq!(ev[0].0, FAN_OPEN);
    assert_eq!(u64::from_le_bytes(ev[0].3[20..28].try_into().unwrap()), f);
    // DIR_FID with FID: the file's directory and the file
    let h = init(FAN_NONBLOCK | FAN_REPORT_FID | FAN_REPORT_DIR_FID, 0);
    mark(h, MARK_ADD, FAN_OPEN | FAN_ON_CHILD | FAN_DELETE, "/dir");
    let _ = open("/dir/f", O_RDONLY);
    let ev = events(h);
    let info = &ev[0].3;
    assert_eq!(info[0], 3);
    let len = u16::from_le_bytes([info[2], info[3]]) as usize;
    assert_eq!(info[len], 1);
    // An entry event with DIR_FID: no FID record
    fan::fs_event(d, 0x200, b"x");
    let ev = events(h);
    assert_eq!(ev[0].3.len(), u16::from_le_bytes([ev[0].3[2], ev[0].3[3]]) as usize);
    // Self deletion on a file mark
    let s = init(FAN_NONBLOCK | FAN_REPORT_FID, 0);
    mark(s, MARK_ADD, FAN_DELETE_SELF, "/dir/f");
    fan::fs_event(f, 0x400, b"");
    assert_eq!(events(s)[0].0, FAN_DELETE_SELF);
}

#[test]
fn unprivileged_groups_hide_other_pids() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    become_user(1000);
    let g = init(FAN_NONBLOCK | FAN_REPORT_FID, 0);
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN, "/f"), 0);
    let ino = memfs::lookup("/f").unwrap();
    // An event by another process (another pid as the current ids)
    task::current(|t| t.tgid = 555);
    fan::file_event(ino, 0, "/f", FAN_OPEN, false);
    task::current(|t| t.tgid = task::SELF_PID);
    fan::file_event(ino, 0, "/f", FAN_OPEN | 0x20, false);
    let ev = events(g);
    assert_eq!(ev[0].2, 0);
    assert_eq!(ev[1].2 as u64, task::SELF_PID);
}

#[test]
fn report_tid() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let g = init(FAN_NONBLOCK | 0x100, 0);
    mark(g, MARK_ADD, FAN_OPEN, "/f");
    task::current(|t| t.id.0 = 777);
    let _ = open("/f", O_RDONLY);
    task::current(|t| t.id.0 = task::SELF_PID);
    assert_eq!(events(g)[0].2, 777);
}

#[test]
fn queue_overflow() {
    let _e = setup();
    let g = init(FAN_NONBLOCK, 0);
    assert_eq!(mark(g, MARK_ADD | MARK_FS, FAN_ACCESS, "/"), 0);
    for i in 0..16390u64 {
        fan::file_event(1_000_000 + i, 0, "/x", FAN_ACCESS, false);
    }
    let n = buf(4);
    dev(g).ioctl(0x541B, n);
    assert_eq!(read_i32(n) as usize, 24 * 16385);
    // The last record is the overflow (once), with no descriptor
    let d = dev(g);
    let mut all = Vec::new();
    loop {
        let mut b = vec![0u8; 24 * 1000];
        match d.read_unlocked(&mut b) {
            Some(n) if n > 0 => all.extend_from_slice(&b[..n as usize]),
            _ => break,
        }
        if all.len() >= 24 * 16385 {
            break;
        }
        // Each record opened a descriptor in the reader: close them
        task::with_current_fds_mut(|t| {
            for fd in t.open_fds() {
                if fd > g as usize {
                    let _ = t.close(fd);
                }
            }
        });
    }
    let last = &all[all.len() - 24..];
    assert_eq!(u64::from_le_bytes(last[8..16].try_into().unwrap()), FAN_Q_OVERFLOW);
    assert_eq!(i32::from_le_bytes(last[16..20].try_into().unwrap()), -1);
    // An unlimited queue keeps everything
    let u = init(FAN_NONBLOCK | 0x10, 0);
    assert_eq!(mark(u, MARK_ADD | MARK_FS, FAN_MODIFY, "/"), 0);
    for i in 0..16390u64 {
        fan::file_event(2_000_000 + i, 0, "/x", FAN_MODIFY, false);
    }
    dev(u).ioctl(0x541B, n);
    assert_eq!(read_i32(n) as usize, 24 * 16390);
}

#[test]
fn permission_events_allow_or_deny() {
    let _e = setup();
    memfs::mkfile("/guarded", b"");
    let g = init(FAN_CLASS_CONTENT, O_RDONLY);
    assert_eq!(mark(g, MARK_ADD, FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_OPEN, "/guarded"), 0);
    let d = dev(g);
    let answer = std::rc::Rc::new(std::cell::Cell::new(2u32)); // FAN_DENY
    let (d2, a2) = (d.clone(), answer.clone());
    task::wait::on_wait(move || {
        let mut b = vec![0u8; 256];
        if let Some(n) = d2.read_unlocked(&mut b) {
            if n >= 24 {
                let efd = i32::from_le_bytes(b[16..20].try_into().unwrap());
                let mut r = efd.to_le_bytes().to_vec();
                r.extend_from_slice(&a2.get().to_le_bytes());
                assert_eq!(d2.write(&r), 8);
            }
        }
    });
    assert_eq!(open("/guarded", O_RDONLY), EPERM);
    answer.set(1); // FAN_ALLOW
    let fd = open("/guarded", O_RDONLY);
    assert!(fd >= 0);
    task::wait::clear_on_wait();
    // An exec's open asks both permission events
    let ino = memfs::lookup("/guarded").unwrap();
    task::wait::on_wait({
        let d3 = d.clone();
        move || {
            let mut b = vec![0u8; 4096];
            if let Some(n) = d3.read_unlocked(&mut b) {
                let mut o = 0;
                while o + 24 <= n.max(0) as usize {
                    let mask = u64::from_le_bytes(b[o + 8..o + 16].try_into().unwrap());
                    let efd = i32::from_le_bytes(b[o + 16..o + 20].try_into().unwrap());
                    if mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM) != 0 {
                        assert_eq!(mask, FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM);
                        let mut r = efd.to_le_bytes().to_vec();
                        r.extend_from_slice(&1u32.to_le_bytes());
                        assert_eq!(d3.write(&r), 8);
                    }
                    o += 24;
                }
            }
        }
    });
    assert_eq!(fan::on_open(ino, 0, "/guarded", false, true), Ok(()));
    task::wait::clear_on_wait();
    // SIGKILL lets the open through; a closed group too
    lx::proc::SIGKILL.set(true);
    assert_eq!(fan::on_open(ino, 0, "/guarded", false, false), Ok(()));
    lx::proc::SIGKILL.set(false);
    // Bad responses
    assert_eq!(d.write(&[0u8; 4]), EINVAL);
    let mut r = 5i32.to_le_bytes().to_vec();
    r.extend_from_slice(&3u32.to_le_bytes());
    assert_eq!(d.write(&r), EINVAL);
    let mut r = 5i32.to_le_bytes().to_vec();
    r.extend_from_slice(&(1u32 | 0x40).to_le_bytes());
    assert_eq!(d.write(&r), EINVAL);
    let mut r = 999i32.to_le_bytes().to_vec();
    r.extend_from_slice(&1u32.to_le_bytes());
    assert_eq!(d.write(&r), ENOENT);
    // The group closes while an open waits: allowed
    let ino2 = memfs::mkfile("/g2", b"");
    let g2 = init(FAN_CLASS_CONTENT, 0);
    mark(g2, MARK_ADD, FAN_OPEN_PERM, "/g2");
    task::wait::on_wait(move || {
        task::with_current_fds_mut(|t| {
            let _ = t.close(g2 as usize);
        });
    });
    drop(d);
    let _ = ino2;
    assert!(open("/g2", O_RDONLY) >= 0);
}

#[test]
fn parent_of_path_and_handles() {
    let _e = setup();
    let d = memfs::mkdir_p("/a/b");
    let f = memfs::mkfile("/a/b/c", b"");
    let _g = init(0, 0);
    assert_eq!(fan::parent_of_path("/a/b/c"), d);
    assert_eq!(fan::parent_of_path("/a"), memfs::root());
    assert_eq!(fan::parent_of_path("rel"), 0);
    // name_to_handle_at
    let h = buf(32);
    write(h, &16u32.to_le_bytes());
    let mid = buf(4);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a/b/c"), h, mid, 0), 0);
    let v = read(h, 16);
    assert_eq!(u32::from_le_bytes(v[0..4].try_into().unwrap()), 8);
    assert_eq!(i32::from_le_bytes(v[4..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(v[8..16].try_into().unwrap()), f);
    assert_eq!(read_i32(mid), 2069);
    // Errors
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a/b/c"), h, mid, 0x2), EINVAL);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr(""), h, mid, 0), ENOENT);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, 16, h, mid, 0), EFAULT);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/none"), h, mid, 0), ENOENT);
    assert_eq!(fan::name_to_handle_at(777, cstr("x"), h, mid, 0), EBADF);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a"), 16, mid, 0), EFAULT);
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a"), h, 16, 0), EFAULT);
    write(h, &200u32.to_le_bytes());
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a"), h, mid, 0), EINVAL);
    write(h, &4u32.to_le_bytes());
    assert_eq!(fan::name_to_handle_at(AT_FDCWD, cstr("/a"), h, mid, 0), -75);
    assert_eq!(read_u32(h), 8);
    // AT_EMPTY_PATH: the descriptor's object
    let fd = open("/a/b", O_RDONLY);
    write(h, &16u32.to_le_bytes());
    assert_eq!(fan::name_to_handle_at(fd as u64, cstr(""), h, mid, 0x1000), 0);
    assert_eq!(u64::from_le_bytes(read(h + 8, 8).try_into().unwrap()), d);
    // open_by_handle_at
    write(h, &[8u32.to_le_bytes().to_vec(), 1i32.to_le_bytes().to_vec(), f.to_le_bytes().to_vec()].concat());
    let o = fan::open_by_handle_at(AT_FDCWD, h, O_RDONLY | O_CLOEXEC);
    assert!(o >= 0);
    assert_eq!(vnode(o).lock().ino, f);
    assert!(task::with_current_fds_mut(|t| t.cloexec(o as usize)));
    write(h + 8, &12345678u64.to_le_bytes());
    assert_eq!(fan::open_by_handle_at(AT_FDCWD, h, 0), -116);
    write(h, &4u32.to_le_bytes());
    assert_eq!(fan::open_by_handle_at(AT_FDCWD, h, 0), -116);
    assert_eq!(fan::open_by_handle_at(AT_FDCWD, 16, 0), EFAULT);
    lx::limits::NOFILE.set(1);
    write(h, &[8u32.to_le_bytes().to_vec(), 1i32.to_le_bytes().to_vec(), f.to_le_bytes().to_vec()].concat());
    assert_eq!(fan::open_by_handle_at(AT_FDCWD, h, 0), -24);
    task::set_caps(0);
    assert_eq!(fan::open_by_handle_at(AT_FDCWD, h, 0), EPERM);
}
