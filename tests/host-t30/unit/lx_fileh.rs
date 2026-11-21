//! Tests of `src/lx/fileh.rs` (wave 7, Group 7-2): the file service's calls (shapes, claims,
//! routing entries), the call context from the descriptor table, both forwarding paths with
//! the redirect to the kernel, the handle operations and the change notes.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::{frame, handler, notes, seen, start, world};
use crate::lx::{entry, entry_svc, fast_entry, forward, obj, set_forwarding, Fast};
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::Arc as StdArc;

/// Every global of this file back to its boot state (`lx::tests::reset_all`).
pub(crate) fn reset() {
    for c in CLAIMED.iter() {
        c.store(0, Ordering::Release);
    }
    ROUTING.store(false, Ordering::Release);
    for m in TO_KERNEL.iter() {
        m.0.store(0, Ordering::Release);
        m.1.store(0, Ordering::Release);
    }
    for c in [&SERVED, &TO_KERNEL_CALLS, &KEPT, &NOTES] {
        c.store(0, Ordering::Release);
    }
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
}

fn vnode(ino: u64, dir: bool, path: &str) -> FileDescriptor {
    let v = crate::fs::Vnode { path: path.into(), ino, is_dir: dir, offset: 77, flags: 0o2, mnt: 5, ..Default::default() };
    FileDescriptor::Vnode(StdArc::new(spin::Mutex::new(v)))
}

/// Claims `nr` for the file service as vfs-server would.
fn claim_nr(nr: u64) {
    assert_eq!(ctl(svc::host_of(LXS_VFS), LX_FH_CLAIM, nr, 1, 0), 0);
}

// ----------------------------------------------------------------------
// Shapes, claims, entries
// ----------------------------------------------------------------------

#[test]
fn every_moved_number_has_its_shape() {
    assert_eq!(shape(4), Some(Shape::Path));
    assert_eq!(shape(257), Some(Shape::At0));
    assert_eq!(shape(332), Some(Shape::At0));
    assert_eq!(shape(316), Some(Shape::At0At2));
    assert_eq!(shape(266), Some(Shape::At1));
    assert_eq!(shape(217), Some(Shape::Handle));
    // read, write, fstat, close stay with the kernel's handles
    for nr in [0, 1, 5, 3, 8, 9, 72] {
        assert_eq!(shape(nr), None, "{nr}");
    }
}

#[test]
fn a_call_goes_to_the_file_service_only_once_claimed() {
    let _sim = world();
    assert_eq!(entry(4), 0);
    claim_nr(4);
    let e = entry(4);
    assert_ne!(e & T_VFS, 0);
    assert_ne!(e & T_SERVER, 0);
    assert_eq!(entry_svc(e), LXS_VFS);
    assert!(claimed(4));
    // given back
    assert_eq!(ctl(svc::host_of(LXS_VFS), LX_FH_CLAIM, 4, 0, 0), 0);
    assert_eq!(entry(4), 0);
    // a number that is not a file-service call
    assert_eq!(ctl(svc::host_of(LXS_VFS), LX_FH_CLAIM, 0, 1, 0), EINVAL);
}

#[test]
fn claims_are_ignored_when_switched_back() {
    let _sim = world();
    claim_nr(6);
    set_forwarding(false);
    assert_eq!(entry(6), 0);
    set_forwarding(true);
    assert_ne!(entry(6), 0);
    svc::tests::set_mode(LXS_VFS, svc::SvcMode::Kernel);
    set_forwarding(true);
    assert_eq!(entry(6), 0);
    assert_eq!(entry_for(6, true, false), 0);
    assert_eq!(entry_for(6, false, true), 0);
}

#[test]
fn only_the_file_service_may_use_the_operations() {
    let _sim = world();
    assert_eq!(ctl(LXS_LINUX, LX_FH_CLAIM, 4, 1, 0), EPERM);
    assert_eq!(ctl(svc::host_of(LXS_VFS), 99, 0, 0, 0), EINVAL);
    // a request that is not the service's own
    assert_eq!(ctl(svc::host_of(LXS_VFS), LX_FH_SEEK, 1 << LX_REQ_SVC_SHIFT, 3, 0), ESRCH);
}

// ----------------------------------------------------------------------
// The call context
// ----------------------------------------------------------------------

#[test]
fn paths_join_lexically() {
    assert_eq!(join_path("/home/u", b"a/b"), "/home/u/a/b");
    assert_eq!(join_path("/home/u", b"../x/./y//"), "/home/x/y");
    assert_eq!(join_path("/home/u", b"/etc/hosts"), "/etc/hosts");
    assert_eq!(join_path("/", b".."), "/");
    assert_eq!(join_path("/a", b""), "/a");
}

#[test]
fn plain_objects_are_pool_objects() {
    assert!(plain_ino(0));
    assert!(plain_ino(34));
    assert!(!plain_ino(u64::MAX));
    assert!(!plain_ino(u64::MAX - 1));
    assert!(!plain_ino(1 << 62 | 5));
}

#[test]
fn the_context_comes_from_the_table() {
    let mut t = crate::fs::FdTable::new();
    t.root_ino = 3;
    t.root_mnt = 1;
    t.cwd_ino = 40;
    t.cwd_mnt = 2;
    t.umask = 0o027;
    t.set_fd(3, Some(vnode(50, true, "/d")));
    t.set_fd(4, Some(vnode(60, false, "/d/f")));
    t.set_fd(5, Some(FileDescriptor::File { path: "/proc/1".into(), readable: true, writable: false }));
    let mut c = LxCall::EMPTY;
    c.args = [3, 0, 5, 0, 0, 0];
    let held = fill(&mut c, &t, Shape::At0At2, true).unwrap().unwrap();
    assert_eq!((c.root, c.root_mnt, c.cwd, c.cwd_mnt, c.umask), (3, 1, 40, 2, 0o027));
    assert_eq!((c.at_kind, c.at_ino, c.at_mnt, c.fh_off, c.fh_flags), (LX_AT_DIR, 50, 5, 77, 0o2));
    assert_eq!(c.at2_kind, LX_AT_OTHER);
    assert!(held[0].is_some() && held[1].is_none());
    assert_eq!(c.fs_flags & LX_FS_FOREIGN, 0);
    // AT_FDCWD, a file, a bad number
    let mut c = LxCall::EMPTY;
    c.args = [(-100i64) as u64, 4, 0, 0, 0, 0];
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_eq!(c.at_kind, LX_AT_CWD);
    fill(&mut c, &t, Shape::At1, true).unwrap().unwrap();
    assert_eq!((c.at_kind, c.at_ino), (LX_AT_FILE, 60));
    c.args[0] = 900;
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_eq!(c.at_kind, LX_AT_OTHER);
    c.args[0] = (-5i64) as u64;
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_eq!(c.at_kind, LX_AT_OTHER);
}

#[test]
fn a_call_on_something_else_than_a_handle_stays_in_the_kernel() {
    let mut t = crate::fs::FdTable::new();
    t.set_fd(5, Some(FileDescriptor::File { path: "/proc/1".into(), readable: true, writable: false }));
    t.set_fd(6, Some(vnode(1 << 62 | 9, false, "/fuse/f")));
    let mut c = LxCall::EMPTY;
    c.args[0] = 5;
    assert!(fill(&mut c, &t, Shape::Handle, true).unwrap().is_none());
    c.args[0] = 6;
    assert!(fill(&mut c, &t, Shape::Handle, true).unwrap().is_none());
    c.args[0] = 7;
    assert!(fill(&mut c, &t, Shape::Handle, true).unwrap().is_none());
}

#[test]
fn foreign_roots_and_busy_files_are_marked() {
    let mut t = crate::fs::FdTable::new();
    t.root_ino = u64::MAX;
    let v = vnode(70, true, "/x");
    if let FileDescriptor::Vnode(f) = &v {
        f.lock().foreign = Some((1, 2, 3));
    }
    t.set_fd(3, Some(v.clone()));
    let mut c = LxCall::EMPTY;
    c.args[0] = 3;
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_ne!(c.fs_flags & LX_FS_FOREIGN, 0);
    assert_eq!(c.at_kind, LX_AT_OTHER);
    // The lock-free path never waits for an open file's lock
    if let FileDescriptor::Vnode(f) = &v {
        let _g = f.lock();
        assert!(fill(&mut c, &t, Shape::At0, false).is_err());
    }
}

#[test]
fn the_callers_state_becomes_flags() {
    let _sim = world();
    let mut c = LxCall::EMPTY;
    assert_eq!(fs_flags_global(&c), 0);
    crate::fake::FS_FLAGS.store(31, Ordering::Release);
    assert_eq!(fs_flags_global(&c), LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_INOTIFY | LX_FS_ABAC | LX_FS_MOUNTS);
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
    c.mnt_ns = 4;
    assert_eq!(fs_flags_global(&c), LX_FS_MOUNTS);
}

// ----------------------------------------------------------------------
// Forwarding
// ----------------------------------------------------------------------

#[test]
fn a_claimed_path_call_is_answered_by_the_file_service() {
    let sim = world();
    claim_nr(4);
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        (0, 0)
    }));
    crate::task::with_current_fds_mut(|t| {
        t.cwd_ino = 44;
        t.umask = 0o077;
    });
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(4, [0x1000, 0x2000, 0, 0, 0, 0])), Some(0));
    let c = calls.lock().unwrap()[0];
    assert_eq!((c.nr, c.svc, c.cwd, c.umask, c.at_kind), (4, LXS_VFS as u32, 44, 0o077, LX_AT_CWD));
    assert_eq!(c.ngroups, 2);
    assert_eq!(SERVED.load(Ordering::Relaxed), 1);
    // And on the lock-free path
    crate::world::bkl_exit();
    match fast_entry(&frame(4, [0x1000, 0x2000, 0, 0, 0, 0])) {
        Some(Fast::Call(0)) => {}
        _ => panic!("not answered on the lock-free path"),
    }
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(calls.lock().unwrap()[1].cwd, 44);
}

#[test]
fn a_redirect_to_the_kernel_lets_the_kernel_answer_once() {
    let sim = world();
    claim_nr(262);
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |_| {
        n2.fetch_add(1, Ordering::AcqRel);
        (LX_REDIRECT_KERNEL, LX_REPLY_REDIRECT)
    }));
    // Lock-free path: not answered, and the ordinary path does not ask again
    assert!(fast_entry(&frame(262, [(-100i64) as u64, 0x1000, 0x2000, 0, 0, 0])).is_none());
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(262, [(-100i64) as u64, 0x1000, 0x2000, 0, 0, 0])), None);
    assert_eq!(n.load(Ordering::Acquire), 1);
    // The ordinary path alone
    assert_eq!(forward(&frame(262, [(-100i64) as u64, 0x1000, 0x2000, 0, 0, 0])), None);
    assert_eq!(n.load(Ordering::Acquire), 2);
    assert_eq!(TO_KERNEL_CALLS.load(Ordering::Relaxed), 2);
}

#[test]
fn a_stale_mark_for_another_call_is_not_taken() {
    let _sim = world();
    set_mark(100, 262);
    assert!(!take_mark(100, 4));
    // (taking clears it)
    assert!(!take_mark(100, 262));
    set_mark(100, 262);
    assert!(!take_mark(101, 262));
    assert!(take_mark(100, 262));
}

#[test]
fn another_service_may_redirect_to_the_kernel_too() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, handler(|_| (0, LX_REPLY_REDIRECT)));
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(LX_TEST_NR, [LX_TEST_REDIRECT, 0, 0, 0, 0, 0])), None);
    crate::world::bkl_exit();
    assert!(fast_entry(&frame(LX_TEST_NR, [LX_TEST_REDIRECT, 0, 0, 0, 0, 0])).is_none());
}

#[test]
fn calls_on_handles_go_to_the_service_and_the_rest_to_the_kernel() {
    let sim = world();
    claim_nr(217);
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        (24, 0)
    }));
    let (dir, pipe) = crate::task::with_current_fds_mut(|t| {
        let d = t.alloc_fd(vnode(90, true, "/usr")).unwrap();
        let p = t.alloc_fd(FileDescriptor::File { path: "/proc".into(), readable: true, writable: false }).unwrap();
        (d, p)
    });
    match fast_entry(&frame(217, [dir as u64, 0x3000, 4096, 0, 0, 0])) {
        Some(Fast::Call(24)) => {}
        _ => panic!("getdents64 on a directory handle not forwarded"),
    }
    let c = calls.lock().unwrap()[0];
    assert_eq!((c.at_kind, c.at_ino, c.fh_off), (LX_AT_DIR, 90, 77));
    // Not a handle: the kernel, at once and without asking again
    assert!(fast_entry(&frame(217, [pipe as u64, 0x3000, 4096, 0, 0, 0])).is_none());
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(217, [pipe as u64, 0x3000, 4096, 0, 0, 0])), None);
    assert_eq!(forward(&frame(217, [55, 0x3000, 4096, 0, 0, 0])), None);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(forward(&frame(217, [dir as u64, 0x3000, 4096, 0, 0, 0])), Some(24));
}

#[test]
fn without_the_service_the_kernel_answers() {
    let _sim = world();
    claim_nr(4);
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(4, [0x1000, 0x2000, 0, 0, 0, 0])), None);
    crate::world::bkl_exit();
    assert!(fast_entry(&frame(4, [0x1000, 0x2000, 0, 0, 0, 0])).is_none());
    assert!(KEPT.load(Ordering::Relaxed) >= 1);
}

// ----------------------------------------------------------------------
// The handle operations
// ----------------------------------------------------------------------

fn desc(ino: u64, dir: bool, kind: u32, at: i32, path: &[u8], flags: u32) -> LxFhDesc {
    let mut d = LxFhDesc::EMPTY;
    d.ino = ino;
    d.mnt = 9;
    d.is_dir = dir as u32;
    d.path_kind = kind;
    d.at_fd = at;
    d.flags = flags;
    d.path[..path.len()].copy_from_slice(path);
    d.path_len = path.len() as u32;
    d
}

#[test]
fn install_makes_a_handle_with_its_shown_path() {
    let _sim = world();
    let mut t = crate::fs::FdTable::new();
    t.cwd_path = "/home/u".into();
    let fd = install_in(&mut t, &desc(12, false, LX_FHP_CWD, 0, b"a/../b.txt", 0o2 | 0o2000000 | 0o100)).unwrap();
    match t.get(fd) {
        Some(FileDescriptor::Vnode(f)) => {
            let f = f.lock();
            assert_eq!((f.ino, f.mnt, f.is_dir, f.path.as_str()), (12, 9, false, "/home/u/b.txt"));
            // O_CREAT is not kept; the access mode is
            assert_eq!(f.flags, 0o2);
        }
        _ => panic!("no handle"),
    }
    assert!(t.cloexec.contains(&fd));
    assert!(crate::fake::rec(|r| r.open_refs.contains(&12)));
    let d = install_in(&mut t, &desc(13, true, LX_FHP_AT, fd as i32, b"x", 0)).unwrap();
    assert!(matches!(t.get(d), Some(FileDescriptor::Vnode(f)) if f.lock().path == "/home/u/b.txt/x"));
    assert!(!t.cloexec.contains(&d));
    let a = install_in(&mut t, &desc(14, false, LX_FHP_ABS, 0, b"/etc//hosts", 0)).unwrap();
    assert!(matches!(t.get(a), Some(FileDescriptor::Vnode(f)) if f.lock().path == "/etc/hosts"));
    assert_eq!(install_in(&mut t, &desc(15, false, LX_FHP_AT, 600, b"x", 0)), Err(EBADF));
    assert_eq!(install_in(&mut t, &desc(15, false, LX_FHP_AT, -3, b"x", 0)), Err(EBADF));
    assert_eq!(install_in(&mut t, &desc(15, false, 7, 0, b"x", 0)), Err(EINVAL));
    assert_eq!(install_in(&mut t, &desc(u64::MAX, false, LX_FHP_ABS, 0, b"/x", 0)), Err(EINVAL));
    t.max = t.fds.len();
    for slot in t.fds.iter_mut() {
        if slot.is_none() {
            *slot = Some(FileDescriptor::File { path: "/x".into(), readable: true, writable: false });
        }
    }
    assert_eq!(install_in(&mut t, &desc(16, false, LX_FHP_ABS, 0, b"/x", 0)), Err(EMFILE));
}

#[test]
fn chdir_seek_and_info() {
    let _sim = world();
    let mut t = crate::fs::FdTable::new();
    t.cwd_path = "/home".into();
    assert_eq!(chdir_in(&mut t, &desc(30, true, LX_FHP_CWD, 0, b"u", 0)), Ok(()));
    assert_eq!((t.cwd_ino, t.cwd_mnt, t.cwd_path.as_str()), (30, 9, "/home/u"));
    assert_eq!(chdir_in(&mut t, &desc(31, false, LX_FHP_CWD, 0, b"f", 0)), Err(EINVAL));
    t.set_fd(3, Some(vnode(50, true, "/d")));
    t.set_fd(4, Some(FileDescriptor::File { path: "/proc".into(), readable: true, writable: false }));
    assert_eq!(seek_in(&t, 3, 1234), Ok(()));
    let i = info_in(&t, 3).unwrap();
    assert_eq!((i.ino, i.off, i.mnt, i.kind, i.flags), (50, 1234, 5, LX_AT_DIR, 0o2));
    assert_eq!(info_in(&t, 4).unwrap().kind, LX_AT_OTHER);
    assert_eq!(info_in(&t, 9).map(|_| ()), Err(EBADF));
    assert_eq!(info_in(&t, (-1i64) as u64).map(|_| ()), Err(EBADF));
    assert_eq!(seek_in(&t, 4, 1), Err(EINVAL));
    assert_eq!(seek_in(&t, 9, 1), Err(EBADF));
    assert_eq!(seek_in(&t, (-1i64) as u64, 1), Err(EBADF));
}

#[test]
fn the_service_installs_and_seeks_for_the_caller_it_serves() {
    let sim = world();
    claim_nr(257);
    claim_nr(217);
    let out = StdArc::new(StdAtomicU64::new(0));
    let o2 = out.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        if s.call.nr == 257 {
            let d = desc(21, false, LX_FHP_ABS, 0, b"/tmp/f", 0o2000000);
            (obj::obj_ctl(LX_FH_INSTALL, s.call.id, &d as *const LxFhDesc as u64, 0), 0)
        } else {
            assert_eq!(obj::obj_ctl(LX_FH_SEEK, s.call.id, s.call.args[0], 999), 0);
            let mut info = LxFhInfo::default();
            assert_eq!(obj::obj_ctl(LX_FH_INFO, s.call.id, s.call.args[0], &mut info as *mut LxFhInfo as u64), 0);
            o2.store(info.off, Ordering::Release);
            (0, 0)
        }
    }));
    crate::world::bkl_enter();
    let fd = forward(&frame(257, [(-100i64) as u64, 0x1000, 0, 0, 0, 0])).unwrap();
    assert!(fd >= 0);
    let path = crate::task::with_current_fds_mut(|t| match t.get(fd as usize) {
        Some(FileDescriptor::Vnode(f)) => f.lock().path.clone(),
        _ => String::new(),
    });
    assert_eq!(path, "/tmp/f");
    assert_eq!(forward(&frame(217, [fd as u64, 0x1000, 100, 0, 0, 0])), Some(0));
    assert_eq!(out.load(Ordering::Acquire), 999);
}

#[test]
fn chdir_through_the_service() {
    let sim = world();
    claim_nr(80);
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        let d = desc(33, true, LX_FHP_CWD, 0, b"sub", 0);
        (obj::obj_ctl(LX_FH_CHDIR, s.call.id, &d as *const LxFhDesc as u64, 0), 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(80, [0x1000, 0, 0, 0, 0, 0])), Some(0));
    let cwd = crate::task::with_current_fds_mut(|t| (t.cwd_ino, t.cwd_path.clone()));
    assert_eq!(cwd, (33, "/sub".into()));
}

#[test]
fn changes_reach_the_kernels_caches() {
    let _sim = world();
    let h = svc::host_of(LXS_VFS);
    let size = 4096u64;
    assert_eq!(ctl(h, LX_FH_CHANGED, 7, LX_FHC_TRUNC, &size as *const u64 as u64), 0);
    assert_eq!(ctl(h, LX_FH_CHANGED, 7, LX_FHC_NAMES | LX_FHC_ATTR, 0), 0);
    assert_eq!(ctl(h, LX_FH_CHANGED, 0, LX_FHC_ALL_ATTRS, 0), 0);
    assert_eq!(ctl(h, LX_FH_CHANGED, 7, LX_FHC_TRUNC, 0), EFAULT);
    let (t, f) = crate::fake::rec(|r| (r.fs_truncated.clone(), r.fs_forgot.clone()));
    assert_eq!(t, vec![(7, 4096)]);
    assert_eq!(f, vec![(7, 3), (u64::MAX, 1), (7, 3), (u64::MAX, 2)]);
}

#[test]
fn the_kernels_changes_are_noted_for_the_service() {
    let sim = world();
    // Offline: nothing
    kernel_changed(5);
    assert_eq!(NOTES.load(Ordering::Relaxed), 0);
    let s = start(&sim, LXS_VFS, 400, 1, true, handler(|_| (0, 0)));
    kernel_changed(5);
    kernel_changed(0);
    assert_eq!(NOTES.load(Ordering::Relaxed), 2);
    let n = notes(s.x);
    assert!(n.contains(&[LX_NOTE_FSCHANGE, 5, 0, 0]));
    assert!(n.contains(&[LX_NOTE_FSCHANGE, 0, 0, 0]));
    assert!(summary().contains("notes 2"));
}

#[test]
fn chroot_and_pivot_root_move_roots() {
    let sim = world();
    let mut t = crate::fs::FdTable::new();
    assert_eq!(chroot_in(&mut t, &desc(70, true, LX_FHP_ABS, 0, b"/jail", 0)), Ok(()));
    assert_eq!((t.root_ino, t.root_mnt), (70, 9));
    assert_eq!(chroot_in(&mut t, &desc(71, false, LX_FHP_ABS, 0, b"/f", 0)), Err(EINVAL));
    // pivot_root of one table: root at the old root, cwd elsewhere
    t.cwd_ino = 5;
    t.cwd_path = "/x".into();
    assert!(reroot_table(&mut t, (70, 9), (80, 2)));
    assert_eq!((t.root_ino, t.root_mnt, t.cwd_ino, t.cwd_path.as_str()), (80, 2, 5, "/x"));
    assert!(!reroot_table(&mut t, (70, 9), (81, 2)));
    // Through the service: process 100 in namespace 0 (the running task)
    crate::compat::linux::proc::PROCS.lock().get_mut(&100).unwrap().pid = 100;
    let h = svc::host_of(LXS_VFS);
    let arg = [0u64, 0, 90, 3];
    assert_eq!(ctl(h, LX_FH_REROOT, 0, arg.as_ptr() as u64, 0), 1);
    let roots = crate::task::with_current_fds_mut(|t| (t.root_ino, t.root_mnt, t.cwd_ino, t.cwd_path.clone()));
    assert_eq!(roots, (90, 3, 90, "/".into()));
    // Another namespace: nobody
    assert_eq!(ctl(h, LX_FH_REROOT, 7, arg.as_ptr() as u64, 0), 0);
    let bad = [0u64, 0, u64::MAX, 3];
    assert_eq!(ctl(h, LX_FH_REROOT, 0, bad.as_ptr() as u64, 0), EINVAL);
    assert_eq!(ctl(h, LX_FH_REROOT, 0, 8, 0), EFAULT);
    drop(sim);
}
