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
    for m in TO_KERNEL.iter() {
        m.0.store(0, Ordering::Release);
        m.1.store(0, Ordering::Release);
    }
    for c in [&SERVED, &TO_KERNEL_CALLS, &KEPT, &NOTES] {
        c.store(0, Ordering::Release);
    }
    for c in KEPT_BY.iter() {
        c.store(0, Ordering::Release);
    }
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
}

fn vnode(ino: u64, dir: bool, path: &str) -> FileDescriptor {
    let v = crate::fs::Vnode { path: path.into(), ino, is_dir: dir, offset: 77, flags: 0o2, mnt: 5, ..Default::default() };
    FileDescriptor::Vnode(StdArc::new(spin::Mutex::new(v)))
}

/// A path in user memory (the copy-in table copies it).
fn p() -> u64 {
    crate::fake::user_space_on();
    static PATH: &[u8] = b"/etc/hosts\0";
    PATH.as_ptr() as u64
}

/// Room for output in user memory.
fn o() -> u64 {
    crate::fake::user_space_on();
    let v: &'static mut [u8] = Box::leak(vec![0u8; 8192].into_boxed_slice());
    v.as_mut_ptr() as u64
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
fn claims_route_also_with_lx_kernel() {
    // wave9 G9-C: the file service has no switch back; `lx=kernel` leaves it forwarded
    let _sim = world();
    assert_eq!(entry_for(6), 0, "not claimed");
    claim_nr(6);
    set_forwarding(false);
    assert_ne!(entry(6), 0);
    set_forwarding(true);
    assert_ne!(entry(6), 0);
    assert_ne!(entry_for(6), 0);
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
    assert_eq!(fs_flags_global(&mut c), 0);
    crate::fake::FS_FLAGS.store(31, Ordering::Release);
    // (wave9 G9-C: fanotify/inotify bits never: the kernel has no instances of its own)
    assert_eq!(fs_flags_global(&mut c), LX_FS_LANDLOCK | LX_FS_ABAC);
    // wave9 G6b-3: the domain's id travels with the call; ABAC only for a caller with a subject
    assert_eq!(c.ll_dom, 7);
    crate::fake::FS_FLAGS.store(31 | 32, Ordering::Release);
    assert_eq!(fs_flags_global(&mut c), LX_FS_LANDLOCK);
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
    assert_eq!(fs_flags_global(&mut c), 0);
    assert_eq!(c.ll_dom, 0);
    // a table the service cannot have (no generation)
    c.mnt_ns = 4;
    assert_eq!(fs_flags_global(&mut c), LX_FS_MOUNTS);
}

// wave7 G7-7 begin
#[test]
fn callers_with_mounts_carry_their_tables_generation() {
    let _sim = world();
    crate::fake::MNT_TABLES.lock().clear();
    let mut c = LxCall::EMPTY;
    // The initial namespace: FUSE mounts no longer keep calls in the kernel
    crate::fake::FS_FLAGS.store(16, Ordering::Release);
    assert_eq!(fs_flags_global(&mut c), 0);
    assert_eq!(c.mnt_gen, 0);
    crate::fake::MNT_TABLES.lock().push((0, 9, 0, alloc::vec![]));
    assert_eq!(fs_flags_global(&mut c), 0);
    assert_eq!(c.mnt_gen, 9);
    // A namespace the service can be given (listed), and one it cannot (not listed)
    crate::fake::MNT_TABLES.lock().push((5, 12, 1, alloc::vec![]));
    c.mnt_ns = 5;
    assert_eq!(fs_flags_global(&mut c), 0);
    assert_eq!(c.mnt_gen, 12);
    c.mnt_ns = 6;
    assert_eq!(fs_flags_global(&mut c), LX_FS_MOUNTS);
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
    crate::fake::MNT_TABLES.lock().clear();
}

#[test]
fn a_namespace_in_a_mount_is_not_kept_by_the_kernel_any_more() {
    let _sim = world();
    let mut c = LxCall::EMPTY;
    c.nr = 4;
    c.mnt_ns = 5;
    c.root_mnt = 1;
    c.cwd_mnt = 3;
    assert!(!kernel_only(&c));
    // The initial namespace's mounts are FUSE ones: the kernel's
    c.mnt_ns = 0;
    assert!(kernel_only(&c));
}

#[test]
fn the_service_gets_a_copy_of_a_mount_table() {
    use crate::compat::linux::mount::VfsMount;
    use crate::ipc::protocol::{LxMntHead, LxMntRec, LX_FH_MNTTAB};
    let _sim = world();
    let h = svc::host_of(LXS_VFS);
    let mounts = alloc::vec![
        VfsMount { kind: 1, flags: 0, parent: 0, mountpoint: 0, root: 34 },
        VfsMount::default(),
        VfsMount { kind: 2, flags: 1, parent: 1, mountpoint: 40, root: 77 },
    ];
    crate::fake::MNT_TABLES.lock().push((7, 21, 1, mounts));
    let hl = core::mem::size_of::<LxMntHead>();
    let rl = core::mem::size_of::<LxMntRec>();
    let mut buf = alloc::vec![0u8; hl + 4 * rl];
    assert_eq!(ctl(h, LX_FH_MNTTAB, 7, buf.as_mut_ptr() as u64, 4), 3);
    let head: LxMntHead = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const LxMntHead) };
    assert_eq!(head, LxMntHead { gen: 21, root: 1, n: 3 });
    let rec = |i: usize| -> LxMntRec { unsafe { core::ptr::read_unaligned(buf.as_ptr().add(hl + i * rl) as *const LxMntRec) } };
    assert_eq!(rec(0), LxMntRec { kind: 1, flags: 0, parent: 0, pad: 0, mountpoint: 0, root: 34 });
    assert_eq!(rec(1), LxMntRec::default());
    assert_eq!(rec(2), LxMntRec { kind: 2, flags: 1, parent: 1, pad: 0, mountpoint: 40, root: 77 });
    // Less room: the head says how many there are, only `cap` records written
    let mut small = alloc::vec![0xAAu8; hl + rl + 4];
    assert_eq!(ctl(h, LX_FH_MNTTAB, 7, small.as_mut_ptr() as u64, 1), 3);
    assert_eq!(&small[hl + rl..], &[0xAA; 4]);
    // No such namespace; a bad buffer; another service
    assert_eq!(ctl(h, LX_FH_MNTTAB, 8, buf.as_mut_ptr() as u64, 4), ESRCH);
    assert_eq!(ctl(h, LX_FH_MNTTAB, 7, 8, 4), EFAULT);
    assert_eq!(ctl(h + 1, LX_FH_MNTTAB, 7, buf.as_mut_ptr() as u64, 4), EPERM);
    crate::fake::MNT_TABLES.lock().clear();
}
// wave7 G7-7 end

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
    assert_eq!(forward(&frame(4, [p(), o(), 0, 0, 0, 0])), Some(0));
    let c = calls.lock().unwrap()[0];
    assert_eq!((c.nr, c.svc, c.cwd, c.umask, c.at_kind), (4, LXS_VFS as u32, 44, 0o077, LX_AT_CWD));
    assert_eq!(c.ngroups, 2);
    assert_eq!(SERVED.load(Ordering::Relaxed), 1);
    // And on the lock-free path
    crate::world::bkl_exit();
    match fast_entry(&frame(4, [p(), o(), 0, 0, 0, 0])) {
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
    assert!(fast_entry(&frame(262, [(-100i64) as u64, p(), o(), 0, 0, 0])).is_none());
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(262, [(-100i64) as u64, p(), o(), 0, 0, 0])), None);
    assert_eq!(n.load(Ordering::Acquire), 1);
    // The ordinary path alone
    assert_eq!(forward(&frame(262, [(-100i64) as u64, p(), o(), 0, 0, 0])), None);
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
    match fast_entry(&frame(217, [dir as u64, o(), 4096, 0, 0, 0])) {
        Some(Fast::Call(24)) => {}
        _ => panic!("getdents64 on a directory handle not forwarded"),
    }
    let c = calls.lock().unwrap()[0];
    assert_eq!((c.at_kind, c.at_ino, c.fh_off), (LX_AT_DIR, 90, 77));
    // Not a handle: the kernel, at once and without asking again
    assert!(fast_entry(&frame(217, [pipe as u64, o(), 4096, 0, 0, 0])).is_none());
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(217, [pipe as u64, o(), 4096, 0, 0, 0])), None);
    assert_eq!(forward(&frame(217, [55, o(), 4096, 0, 0, 0])), None);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(forward(&frame(217, [dir as u64, o(), 4096, 0, 0, 0])), Some(24));
}

#[test]
fn without_the_service_the_kernel_answers() {
    let _sim = world();
    claim_nr(4);
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(4, [p(), o(), 0, 0, 0, 0])), None);
    crate::world::bkl_exit();
    assert!(fast_entry(&frame(4, [p(), o(), 0, 0, 0, 0])).is_none());
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
    let fd = forward(&frame(257, [(-100i64) as u64, p(), 0, 0, 0, 0])).unwrap();
    assert!(fd >= 0);
    let path = crate::task::with_current_fds_mut(|t| match t.get(fd as usize) {
        Some(FileDescriptor::Vnode(f)) => f.lock().path.clone(),
        _ => String::new(),
    });
    assert_eq!(path, "/tmp/f");
    assert_eq!(forward(&frame(217, [fd as u64, p(), 100, 0, 0, 0])), Some(0));
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
    assert_eq!(forward(&frame(80, [p(), 0, 0, 0, 0, 0])), Some(0));
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
    assert_eq!(ctl(h, LX_FH_CHANGED, 8, LX_FHC_GONE, 0), 0);
    let (t, f) = crate::fake::rec(|r| (r.fs_truncated.clone(), r.fs_forgot.clone()));
    assert_eq!(t, vec![(7, 4096), (8, u64::MAX)]);
    // (an unlinked object's attributes go too)
    assert_eq!(f, vec![(7, 3), (u64::MAX, 1), (7, 3), (u64::MAX, 2), (8, 3)]);
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

// wave7 G7-6: a restarted vfs-server lists the live mount namespaces
#[test]
fn the_live_mount_namespaces_are_listed() {
    let sim = world();
    {
        let mut p = crate::compat::linux::proc::PROCS.lock();
        let base = p.get(&100).unwrap().clone();
        for (pid, mnt, zombie) in [(101u64, 7u64, false), (102, 7, false), (103, 9, true), (104, 12, false)] {
            let mut q = base.clone();
            q.pid = pid;
            q.ns.mnt = mnt;
            q.zombie = zombie;
            p.insert(pid, q);
        }
    }
    let h = svc::host_of(LXS_VFS);
    let mut buf = [u64::MAX; 8];
    // 0 (process 100), 7 once, not 9 (only a zombie), 12
    assert_eq!(ctl(h, LX_FH_NSLIST, buf.as_mut_ptr() as u64, 8, 0), 3);
    assert_eq!(&buf[..4], &[0, 7, 12, u64::MAX]);
    // Less room: the count still says how many there are
    let mut one = [u64::MAX; 2];
    assert_eq!(ctl(h, LX_FH_NSLIST, one.as_mut_ptr() as u64, 1, 0), 3);
    assert_eq!(one, [0, u64::MAX]);
    assert_eq!(ctl(h, LX_FH_NSLIST, 0, 0, 0), 3);
    assert_eq!(ctl(h, LX_FH_NSLIST, 8, 4, 0), EFAULT);
    // Only the file service's host
    assert_eq!(ctl(svc::host_of(LXS_VFS) + 1, LX_FH_NSLIST, buf.as_mut_ptr() as u64, 8, 0), EPERM);
    drop(sim);
}

#[test]
fn the_proc_directory_is_not_a_handle() {
    let mut t = crate::fs::FdTable::new();
    t.set_fd(3, Some(vnode(50, true, "/proc")));
    let mut c = LxCall::EMPTY;
    c.args[0] = 3;
    assert!(fill(&mut c, &t, Shape::Handle, true).unwrap().is_none());
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_eq!(c.at_kind, LX_AT_OTHER);
}

#[test]
fn lookups_from_the_trees_served_by_name_are_the_kernels() {
    assert!(pseudo_path("/proc"));
    assert!(pseudo_path("/dev/pts"));
    assert!(pseudo_path("/sys/fs/cgroup"));
    assert!(!pseudo_path("/devices"));
    assert!(!pseudo_path("/home/dev"));
    let mut t = crate::fs::FdTable::new();
    t.cwd_path = "/dev".into();
    t.set_fd(3, Some(vnode(50, true, "/sys/class")));
    let mut c = LxCall::EMPTY;
    c.args[0] = 3;
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_ne!(c.fs_flags & LX_FS_FOREIGN, 0);
    assert_eq!(c.at_kind, LX_AT_OTHER);
}


#[test]
fn calls_the_service_would_send_back_stay_in_the_kernel() {
    let sim = world();
    claim_nr(4);
    claim_nr(87);
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |_| {
        n2.fetch_add(1, Ordering::AcqRel);
        (0, 0)
    }));
    // (wave9 G9-C: the kernel has no inotify instances of its own any more, so a caller's
    // unlink is never kept for them: both go to the service)
    crate::fake::FS_FLAGS.store(4, Ordering::Release);
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(4, [p(), o(), 0, 0, 0, 0])), Some(0));
    assert_eq!(forward(&frame(87, [p(), 0, 0, 0, 0, 0])), Some(0));
    crate::world::bkl_exit();
    assert_eq!(n.load(Ordering::Acquire), 2);
    assert_eq!(KEPT_BY[5].load(Ordering::Relaxed), 0);
    // FUSE mounts of the initial namespace: the service has the table now (wave7 G7-7)
    crate::fake::FS_FLAGS.store(16, Ordering::Release);
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(4, [p(), o(), 0, 0, 0, 0])), Some(0));
    assert_eq!(n.load(Ordering::Acquire), 3);
    assert!(kernel_by_nr(8).starts_with("vfs to kernel by call"));
    assert_eq!(kernel_mask(332) & LX_FS_INOTIFY, 0);
    // wave9 G6b-3: vfs-server checks Landlock and ABAC for what it serves; the rest stays
    assert_eq!(kernel_mask(257) & (LX_FS_LANDLOCK | LX_FS_ABAC), 0);
    assert_ne!(kernel_mask(257) & LX_FS_FANOTIFY, 0);
    assert_eq!(kernel_mask(87) & (LX_FS_LANDLOCK | LX_FS_ABAC), 0);
    assert_eq!(kernel_mask(165) & LX_FS_LANDLOCK, 0);
    assert_eq!(kernel_mask(21) & LX_FS_ABAC, 0);
    // wave10 GV1: mknod, linkat, the xattr calls and utime(s) are served (and checked) there too
    assert_eq!(kernel_mask(133) & (LX_FS_LANDLOCK | LX_FS_ABAC), 0, "mknod is served");
    assert_eq!(kernel_mask(265) & LX_FS_LANDLOCK, 0, "linkat is served");
    assert_eq!(kernel_mask(188) & LX_FS_ABAC, 0, "setxattr is served");
    assert_eq!(kernel_mask(235) & LX_FS_LANDLOCK, 0, "utimes is served");
    assert_ne!(kernel_mask(87) & LX_FS_FOREIGN, 0, "a foreign root stays the kernel's");
}

#[test]
fn creating_opens_of_policy_callers_go_to_the_service() {
    // wave9 G6b-3 kept them here (vfs-server sent them back); wave10 GV1: vfs-server makes
    // files, checking Landlock and ABAC itself
    let mut c = LxCall::EMPTY;
    c.nr = 257;
    c.fs_flags = LX_FS_LANDLOCK;
    assert!(!kernel_only(&c), "a plain open is checked by vfs-server");
    c.args[2] = 0o100 | 1;
    assert!(!kernel_only(&c));
    c.nr = 2;
    c.args = [0, 0o100, 0, 0, 0, 0];
    c.fs_flags = LX_FS_ABAC;
    assert!(!kernel_only(&c));
    c.fs_flags = 0;
    assert!(!kernel_only(&c), "a caller without rules: vfs-server walks first");
}

// wave10 GV1 begin
#[test]
fn path_calls_are_counted_unclaimed_but_not_data_calls() {
    assert!(is_path_call(257) && is_path_call(133) && is_path_call(188) && is_path_call(80));
    assert!(!is_path_call(74) && !is_path_call(285) && !is_path_call(217) && !is_path_call(78), "data and directory reads");
    assert!(!is_path_call(0) && !is_path_call(202) && !is_path_call(600));
    count_unclaimed(259);
    count_unclaimed(202);
    let s = kernel_by_nr(64);
    assert!(s.starts_with("vfs to kernel by call (nr:sent/kept/unclaimed):"), "{}", s);
    assert!(s.contains(" 259:0/0/1") || s.contains(" 259:0/0/"), "{}", s);
    assert!(!s.contains(" 202:"), "{}", s);
}

#[test]
fn label_changes_reach_the_kernels_abac_caches() {
    crate::fake::reset();
    assert_eq!(changed(42, crate::ipc::protocol::LX_FHC_LABELS | LX_FHC_ATTR, 0), 0);
    crate::fake::rec(|r| {
        assert!(r.fs_forgot.contains(&(0, 64)), "labels forgotten");
        assert!(r.fs_forgot.contains(&(42, 3)), "the object's attributes forgotten");
    });
}

#[test]
fn the_tmem_sub_ops_vfs_server_uses() {
    use crate::ipc::protocol::{LX_TMEM_MAY_MOVE, LX_TMEM_MNT, LX_TMEM_TIMES, LX_TMEM_TRUNC, LX_TMEM_UNLINKED};
    crate::fake::reset();
    // (no in-memory files here: the stub's tmem is off)
    assert_eq!(tmem(LX_TMEM_MNT, 0, 0), -2, "the initial namespace has no tmpfs mounts");
    assert_eq!(tmem(LX_TMEM_MNT, 5 << 32 | 8, 0), -2, "not a tmpfs");
    assert_eq!(tmem(LX_TMEM_TRUNC, 99, 0), -2, "not an in-memory file");
    assert_eq!(tmem(LX_TMEM_TIMES, 99, 0), 0);
    assert_eq!(tmem(LX_TMEM_MAY_MOVE, 99, 1), 0);
    assert_eq!(tmem(LX_TMEM_UNLINKED, 99, 0), 0);
    crate::fake::rec(|r| assert!(r.fs_forgot.contains(&(99, 7))));
}

#[test]
fn device_programs_mark_mknod_calls() {
    let mut c = LxCall::EMPTY;
    c.nr = 133;
    crate::fake::FS_FLAGS.store(64, Ordering::Release);
    let f = fs_flags_global(&mut c);
    assert_ne!(f & crate::ipc::protocol::LX_FS_DEVCG, 0);
    c.nr = 87;
    assert_eq!(fs_flags_global(&mut c) & crate::ipc::protocol::LX_FS_DEVCG, 0, "only mknod");
    crate::fake::FS_FLAGS.store(0, Ordering::Release);
    c.nr = 259;
    assert_eq!(fs_flags_global(&mut c) & crate::ipc::protocol::LX_FS_DEVCG, 0);
}
// wave10 GV1 end

#[test]
fn landlocks_truncate_refusal_goes_with_the_handle() {
    // wave9 G6b-3: LX_FH_NOTRUNC at install, shown again in the handle's flags
    let mut t = crate::fs::FdTable::new();
    let mut d = LxFhDesc::EMPTY;
    d.ino = 77;
    d.flags = crate::ipc::protocol::LX_FH_NOTRUNC | 2;
    d.path_len = 2;
    d.path[..2].copy_from_slice(b"/f");
    let fd = install_in(&mut t, &d).unwrap();
    let f = match t.get(fd) {
        Some(FileDescriptor::Vnode(f)) => f.clone(),
        _ => unreachable!(),
    };
    assert!(f.lock().no_truncate);
    let i = info_of_open(&f.lock()).unwrap();
    assert_eq!(i.flags & crate::ipc::protocol::LX_FH_NOTRUNC, crate::ipc::protocol::LX_FH_NOTRUNC);
    assert_eq!(i.flags & 3, 2);
    d.flags = 0;
    let fd = install_in(&mut t, &d).unwrap();
    if let Some(FileDescriptor::Vnode(f)) = t.get(fd) {
        assert!(!f.lock().no_truncate);
        assert_eq!(info_of_open(&f.lock()).unwrap().flags & crate::ipc::protocol::LX_FH_NOTRUNC, 0);
    }
}


#[test]
fn a_call_on_an_o_path_descriptor_is_the_kernels() {
    let mut t = crate::fs::FdTable::new();
    let v = vnode(50, true, "/d");
    if let FileDescriptor::Vnode(f) = &v {
        f.lock().flags = 0o10000000 | 0o200000;
    }
    t.set_fd(3, Some(v));
    let mut c = LxCall::EMPTY;
    c.args[0] = 3;
    assert!(fill(&mut c, &t, Shape::Handle, true).unwrap().is_none());
    // (as a directory for *at calls it still serves)
    fill(&mut c, &t, Shape::At0, true).unwrap().unwrap();
    assert_eq!(c.at_kind, LX_AT_DIR);
}

#[test]
fn claims_and_the_routing_switch_do_not_race() {
    let _sim = world();
    claim_nr(4);
    set_forwarding(false);
    claim_nr(6);
    // (wave9 G9-C: `lx=kernel` leaves the file service forwarded)
    assert_ne!(entry(4), 0);
    assert_ne!(entry(6), 0);
    set_forwarding(true);
    assert_ne!(entry(4), 0);
    assert_ne!(entry(6), 0);
}

// wave9 G6b-1 begin: inotify/fanotify calls go to vfs-server
#[test]
fn notify_calls_shapes_and_no_kernel_bits() {
    for nr in [253u64, 294, 300, 254, 255] {
        assert_eq!(shape(nr), Some(Shape::Notify));
        assert!(is_notify_call(nr));
        assert_eq!(kernel_mask(nr), 0);
    }
    assert_eq!(shape(301), Some(Shape::NotifyAt3));
    assert!(is_notify_call(301) && kernel_mask(301) == 0);
    assert!(takes_notify_obj(254) && takes_notify_obj(255) && takes_notify_obj(301));
    assert!(!takes_notify_obj(253) && !takes_notify_obj(294) && !takes_notify_obj(300));
    assert!(!is_notify_call(257) && kernel_mask(257) != 0);
    // claimed like any file-service call: the routing entry names vfs-server
    assert_eq!(entry_for(254) & T_VFS, if claimed(254) { T_VFS } else { 0 });
}

#[test]
fn notify_call_on_a_non_object_stays_in_the_kernel() {
    // `inotify_add_watch(0, ...)`: descriptor 0 is no vfs-server object, so `fill` leaves the
    // call to the kernel (its own instance, or EBADF/EINVAL there)
    let t = crate::fs::FdTable::new();
    let mut c = LxCall::EMPTY;
    c.nr = 254;
    c.args[0] = 0;
    assert!(matches!(fill(&mut c, &t, Shape::Notify, true), Ok(None)));
    // `inotify_init1` has no object: filled
    let mut c = LxCall::EMPTY;
    c.nr = 294;
    assert!(matches!(fill(&mut c, &t, Shape::Notify, true), Ok(Some(_))));
}
// wave9 G6b-1 end

// wave9 GP2 begin: open's handle made from the answer
#[test]
fn an_open_answered_with_a_handle_gets_it_in_the_callers_table() {
    let sim = world();
    claim_nr(2);
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        s.set_redir_obj(4242);
        (LX_REDIR_FH as i64 | (5i64 | 1 << 16) << 32, LX_REPLY_REDIRECT)
    }));
    crate::world::bkl_enter();
    let fd = forward(&frame(2, [p(), 0o2000000 | 0o200000, 0, 0, 0, 0])).expect("answered");
    assert!(calls.lock().unwrap()[0].flags & LX_CALL_FHANSWER != 0);
    crate::task::with_current_fds_mut(|t| {
        match t.get(fd as usize) {
            Some(FileDescriptor::Vnode(f)) => {
                let f = f.lock();
                assert_eq!((f.ino, f.mnt, f.is_dir, f.path.as_str()), (4242, 5, true, "/etc/hosts"));
            }
            _ => panic!("no handle"),
        }
        assert!(t.cloexec.contains(&(fd as usize)));
    });
    assert_eq!(SERVED.load(Ordering::Relaxed), 1);
}

#[test]
fn a_handle_answer_is_coded_below_every_result() {
    let mut c = LxCall::EMPTY;
    c.nr = 257;
    // (not allowed by the call, or an inode too large: the kernel answers)
    assert_eq!(fh_answer(&c, (LX_REDIR_FH as u64 | 3 << 32, 9)), LX_TO_KERNEL);
    c.flags = LX_CALL_FHANSWER;
    assert_eq!(fh_answer(&c, (LX_REDIR_FH as u64, 1 << 45)), LX_TO_KERNEL);
    assert_eq!(fh_answer(&c, (LX_REDIR_FH as u64, 0)), LX_TO_KERNEL);
    let r = fh_answer(&c, (LX_REDIR_FH as u64 | (0xFFFF | 1 << 16) << 32, (1 << 45) - 1));
    assert!(r < -4200);
    assert_eq!(fh_decode(r), Some(((1 << 45) - 1, 0xFFFF, true)));
    assert_eq!(fh_decode(fh_answer(&c, (LX_REDIR_FH as u64 | 2 << 32, 7))), Some((7, 2, false)));
    for v in [0i64, 5, -1, -4095, -4102, i64::MAX] {
        assert_eq!(fh_decode(v), None);
    }
    c.nr = 4;
    assert_eq!(fh_answer(&c, (LX_REDIR_FH as u64, 9)), LX_TO_KERNEL);
}
// wave9 GP2 end

// wave9 GP2: on the lock-free path the handle goes to the ordinary path, which makes it
// without asking the file service again
#[test]
fn a_handle_answer_on_the_lock_free_path_is_made_on_the_ordinary_path() {
    let sim = world();
    claim_nr(257);
    let n = StdArc::new(StdAtomicU64::new(0));
    let n2 = n.clone();
    start(&sim, LXS_VFS, 400, 1, true, handler(move |s| {
        n2.fetch_add(1, Ordering::AcqRel);
        s.set_redir_obj(77);
        (LX_REDIR_FH as i64 | 3i64 << 32, LX_REPLY_REDIRECT)
    }));
    let f = frame(257, [(-100i64) as u64, p(), 0, 0, 0, 0]);
    assert!(fast_entry(&f).is_none());
    assert_eq!(n.load(Ordering::Acquire), 1);
    crate::world::bkl_enter();
    let fd = forward(&f).expect("made");
    assert_eq!(n.load(Ordering::Acquire), 1);
    crate::task::with_current_fds_mut(|t| match t.get(fd as usize) {
        Some(FileDescriptor::Vnode(v)) => {
            let v = v.lock();
            assert_eq!((v.ino, v.mnt, v.is_dir), (77, 3, false));
        }
        _ => panic!("no handle"),
    });
    // (taken once: the next ordinary call asks the service)
    assert!(forward(&f).is_some());
    assert_eq!(n.load(Ordering::Acquire), 2);
}
