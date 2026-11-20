//! inotify.rs and locks.rs.
mod common;
use common::*;
use lx::{inotify, locks};

fn inotify_obj(fd: i64) -> std::sync::Arc<inotify::Inotify> {
    match desc(fd) {
        Some(FileDescriptor::Inotify(i)) => i,
        _ => panic!(),
    }
}

fn records(i: &inotify::Inotify) -> Vec<(i32, u32, u32, Vec<u8>)> {
    let mut b = vec![0u8; 4096];
    let n = i.read(&mut b);
    assert!(n >= 0, "{}", n);
    let mut out = Vec::new();
    let mut o = 0;
    while o < n as usize {
        let wd = i32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let mask = u32::from_le_bytes(b[o + 4..o + 8].try_into().unwrap());
        let cookie = u32::from_le_bytes(b[o + 8..o + 12].try_into().unwrap());
        let len = u32::from_le_bytes(b[o + 12..o + 16].try_into().unwrap()) as usize;
        let name: Vec<u8> = b[o + 16..o + 16 + len].iter().take_while(|&&c| c != 0).copied().collect();
        out.push((wd, mask, cookie, name));
        o += 16 + len;
    }
    out
}

#[test]
fn inotify_watches_and_events() {
    let _e = setup();
    let d = memfs::mkdir_p("/w");
    let f = memfs::mkfile("/w/f", b"");
    assert_eq!(inotify::sys_init1(1), EINVAL);
    let fd = inotify::sys_init1(0o4000 | 0o2000000);
    assert!(task::with_current_fds_mut(|t| t.cloexec(fd as usize)));
    let i = inotify_obj(fd);
    assert!(i.get_nonblock());
    // Watches
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/w"), 0), EINVAL);
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/w"), 0x100 | 0x2000_0000 | 0x1000_0000), EINVAL);
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/none"), 0x100), ENOENT);
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/w/f"), 0x100 | 0x0100_0000), ENOTDIR);
    let wd = inotify::sys_add_watch(fd as u64, cstr("/w"), 0x100 | 0x200);
    assert_eq!(wd, 1);
    assert!(inotify::active());
    assert!(inotify::watched(d));
    assert!(!inotify::watched(f));
    // Same inode again: same wd; MASK_CREATE refuses; MASK_ADD adds
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/w/"), 0x100 | 0x1000_0000), EEXIST);
    assert_eq!(inotify::sys_add_watch(fd as u64, cstr("/w"), 0x2 | 0x2000_0000), 1);
    let wf = inotify::sys_add_watch(fd as u64, cstr("/w/f"), 0x2 | 0x8000_0000); // oneshot
    assert_eq!(wf, 2);
    // Not an inotify descriptor
    assert_eq!(inotify::sys_add_watch(50, cstr("/w"), 0x100), EINVAL);
    // Events: named entries, coalescing, file events, oneshot
    assert_eq!(i.read(&mut [0u8; 64]), EAGAIN);
    inotify::event(d, 0x100, 0, b"new");
    inotify::event(d, 0x100, 0, b"new"); // identical: coalesced
    inotify::event(d, 0x2, 0, b"");
    inotify::event(d, 0x4, 0, b""); // not wanted
    inotify::event(f, 0x2, 0, b"");
    inotify::event(f, 0x2, 0, b""); // oneshot gone
    assert_eq!(i.poll_events(), 1);
    assert_eq!(i.pending_bytes(), 32 + 16 + 16 + 16);
    let r = records(&i);
    assert_eq!(r, vec![(1, 0x100, 0, b"new".to_vec()), (1, 0x2, 0, vec![]), (2, 0x2, 0, vec![]), (2, 0x8000, 0, vec![])]);
    assert_eq!(i.poll_events(), 0);
    // Rename cookies pair up
    let c = inotify::cookie();
    assert_ne!(inotify::cookie(), c);
    // A buffer too small for the first record; partial reads
    inotify::event(d, 0x200, 0, b"gone");
    inotify::event(d, 0x2, 0, b"");
    assert_eq!(i.read(&mut [0u8; 10]), EINVAL);
    let mut b = vec![0u8; 40];
    assert_eq!(i.read(&mut b), 32);
    assert_eq!(i.read(&mut b), 16);
    // rm_watch: IN_IGNORED queued; unknown wd
    assert_eq!(inotify::sys_rm_watch(fd as u64, 1), 0);
    assert_eq!(inotify::sys_rm_watch(fd as u64, 1), EINVAL);
    assert_eq!(inotify::sys_rm_watch(50, 1), EINVAL);
    assert_eq!(records(&i), vec![(1, 0x8000, 0, vec![])]);
    // DELETE_SELF removes the watch
    let w3 = inotify::sys_add_watch(fd as u64, cstr("/w/f"), 0x400);
    inotify::event(f, 0x400, 0, b"");
    assert_eq!(records(&i), vec![(w3 as i32, 0x400, 0, vec![]), (w3 as i32, 0x8000, 0, vec![])]);
    // Symlinks: followed unless IN_DONT_FOLLOW
    let l = memfs::mklink("/w/l", "f");
    let wl = inotify::sys_add_watch(fd as u64, cstr("/w/l"), 0x2 | 0x0200_0000);
    inotify::event(l, 0x2, 0, b"");
    assert_eq!(records(&i)[0].0, wl as i32);
    // The descriptor closes: its watches stop counting
    close(fd);
    drop(i);
    // Full table
    install(FileDescriptor::ConsoleIn);
    lx::limits::NOFILE.set(1);
    assert_eq!(inotify::sys_init1(0), -24);
}

#[test]
fn inotify_blocking_reads_and_overflow() {
    let _e = setup();
    let d = memfs::mkdir_p("/w");
    let fd = inotify::sys_init1(0);
    let i = inotify_obj(fd);
    inotify::sys_add_watch(fd as u64, cstr("/w"), 0xfff);
    lx::proc::SIGNAL.set(true);
    assert_eq!(i.read(&mut [0u8; 64]), -512);
    lx::proc::SIGNAL.set(false);
    task::wait::on_wait(move || inotify::event(d, 0x100, 0, b"x"));
    assert_eq!(i.read(&mut [0u8; 64]), 32);
    task::wait::clear_on_wait();
    i.set_nonblock(true);
    // 16384 queued at most, then one overflow record
    for k in 0..16390u32 {
        inotify::event(d, 0x100, 0, format!("n{}", k).as_bytes());
    }
    assert_eq!(i.pending_bytes(), 16384 * 32 + 16);
    let mut b = vec![0u8; 16384 * 32 + 16];
    assert_eq!(i.read(&mut b), (16384 * 32 + 16) as i64);
    let last = &b[16384 * 32..];
    assert_eq!(i32::from_le_bytes(last[0..4].try_into().unwrap()), -1);
    assert_eq!(u32::from_le_bytes(last[4..8].try_into().unwrap()), 0x4000);
}

// ------------------------------------------------------------------ locks

fn flk(kind: i16, whence: i16, start: i64, len: i64, pid: i32) -> u64 {
    let mut v = Vec::new();
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(&whence.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    v.extend_from_slice(&start.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&[0u8; 4]);
    hydra_hosttests_t26::fake::leak(v)
}

fn getlk(fd: i64, kind: i16, start: i64, len: i64, ofd: bool) -> (i16, i64, i64, i32) {
    let p = flk(kind, 0, start, len, 0);
    assert_eq!(locks::fcntl(fd as u64, if ofd { 36 } else { 5 }, p, ofd), 0);
    let v = read(p, 32);
    (
        i16::from_le_bytes([v[0], v[1]]),
        i64::from_le_bytes(v[8..16].try_into().unwrap()),
        i64::from_le_bytes(v[16..24].try_into().unwrap()),
        i32::from_le_bytes(v[24..28].try_into().unwrap()),
    )
}

#[test]
fn record_locks() {
    let _e = setup();
    memfs::mkfile("/f", b"0123456789");
    let a = open("/f", O_RDWR);
    let b = open("/f", O_RDWR);
    // Our POSIX lock on 0..9
    assert_eq!(locks::fcntl(a as u64, 6, flk(1, 0, 0, 10, 0), false), 0);
    // The same process sees no conflict; an OFD lock (another owner) does
    assert_eq!(getlk(b, 1, 0, 5, false).0, 2);
    let (k, s, l, pid) = getlk(b, 1, 0, 5, true);
    assert_eq!((k, s, l, pid), (1, 0, 10, task::SELF_PID as i32));
    assert_eq!(locks::fcntl(b as u64, 37, flk(0, 0, 5, 1, 0), true), EAGAIN);
    // Beyond the lock: free
    assert_eq!(locks::fcntl(b as u64, 37, flk(0, 0, 10, 0, 0), true), 0);
    let (k, s, l, pid) = getlk(a, 1, 20, 1, false);
    assert_eq!((k, s, l, pid), (0, 10, 0, -1)); // the OFD read lock to EOF
    // Split our lock by unlocking the middle; /proc/locks shows the pieces
    assert_eq!(locks::fcntl(a as u64, 6, flk(2, 0, 3, 2, 0), false), 0);
    let text = locks::proc_locks();
    assert!(text.contains("POSIX  ADVISORY  WRITE 100 08:01:"));
    assert!(text.contains(" 0 2\n") && text.contains(" 5 9\n"));
    assert!(text.contains("OFDLCK ADVISORY  READ  -1") && text.contains(" 10 EOF\n"));
    // Merging touching locks of the same kind
    assert_eq!(locks::fcntl(a as u64, 6, flk(1, 0, 3, 2, 0), false), 0);
    assert_eq!(locks::proc_locks().matches("POSIX").count(), 1);
    // Closing any descriptor of the file drops the process's POSIX locks
    let c = open("/f", O_RDONLY);
    close(c);
    assert_eq!(locks::proc_locks().matches("POSIX").count(), 0);
    // The OFD lock goes with its description
    close(b);
    assert_eq!(locks::proc_locks(), "");
}

#[test]
fn record_lock_arguments() {
    let _e = setup();
    memfs::mkfile("/f", b"0123456789");
    let rw = open("/f", O_RDWR) as u64;
    let ro = open("/f", O_RDONLY) as u64;
    let wo = open("/f", O_WRONLY) as u64;
    assert_eq!(locks::fcntl(ro, 6, flk(1, 0, 0, 1, 0), false), EBADF);
    assert_eq!(locks::fcntl(wo, 6, flk(0, 0, 0, 1, 0), false), EBADF);
    assert_eq!(locks::fcntl(rw, 6, flk(5, 0, 0, 1, 0), false), EINVAL);
    assert_eq!(locks::fcntl(rw, 37, flk(1, 0, 0, 1, 7), true), EINVAL); // OFD with a pid
    assert_eq!(locks::fcntl(rw, 6, flk(1, 9, 0, 1, 0), false), EINVAL);
    assert_eq!(locks::fcntl(rw, 6, flk(1, 0, -5, 1, 0), false), EINVAL);
    assert_eq!(locks::fcntl(rw, 6, flk(1, 0, i64::MAX, 1, 0), false), 0);
    assert_eq!(locks::fcntl(rw, 6, flk(1, 1, i64::MAX, i64::MAX, 0), false), 0);
    assert_eq!(locks::fcntl(rw, 6, 16, false), EFAULT);
    assert_eq!(locks::fcntl(900, 6, flk(1, 0, 0, 1, 0), false), EBADF);
    assert_eq!(locks::fcntl(rw, 5, flk(2, 0, 0, 1, 0), false), EINVAL); // F_GETLK of UNLCK
    // SEEK_CUR and SEEK_END; a negative length locks before the start
    sys(8, &[rw, 4, 0]);
    assert_eq!(locks::fcntl(rw, 6, flk(1, 1, 0, 2, 0), false), 0);
    assert!(locks::proc_locks().contains(" 4 5\n"));
    assert_eq!(locks::fcntl(rw, 6, flk(1, 2, -2, 2, 0), false), 0);
    assert!(locks::proc_locks().contains(" 8 9\n") || locks::proc_locks().contains(" 4 9\n"));
    assert_eq!(locks::fcntl(rw, 6, flk(1, 0, 20, -5, 0), false), 0);
    assert!(locks::proc_locks().contains(" 15 19\n"));
    assert_eq!(locks::fcntl(rw, 6, flk(1, 0, 2, -5, 0), false), EINVAL);
    // F_GETLK result can't be written
    let p = flk(1, 0, 0, 1, 0);
    hydra_hosttests_t26::fake::memory::make_bad(p, 32);
    let _ = p;
    // An O_PATH or non-file descriptor
    let op = open("/f", O_PATH) as u64;
    assert_eq!(locks::fcntl(op, 6, flk(1, 0, 0, 1, 0), false), EBADF);
    let cons = install(FileDescriptor::ConsoleIn) as u64;
    assert_eq!(locks::fcntl(cons, 6, flk(1, 0, 0, 1, 0), false), EBADF);
    // SEEK_END on a file whose inode went away
    memfs::with(|fs| fs.inodes.remove(&vnode(rw as i64).lock().ino));
    assert_eq!(locks::fcntl(rw, 6, flk(1, 2, 0, 1, 0), false), ENOENT);
}

#[test]
fn waiting_for_record_locks() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let a = open("/f", O_RDWR) as u64;
    let b = open("/f", O_RDWR) as u64;
    assert_eq!(locks::fcntl(a, 37, flk(1, 0, 0, 0, 0), true), 0);
    // F_OFD_SETLKW waits; the holder unlocks during the wait
    task::wait::on_wait(move || {
        assert_eq!(locks::fcntl(a, 37, flk(2, 0, 0, 0, 0), true), 0);
    });
    assert_eq!(locks::fcntl(b, 38, flk(1, 0, 0, 0, 0), true), 0);
    task::wait::clear_on_wait();
    // A signal ends a wait
    lx::proc::SIGNAL.set(true);
    assert_eq!(locks::fcntl(a, 38, flk(0, 0, 0, 0, 0), true), -4);
    assert_eq!(locks::fcntl(a, 7, flk(0, 0, 0, 0, 0), false), -4);
    lx::proc::SIGNAL.set(false);
    // Another process's POSIX lock conflicts; its exit releases it
    task::current(|t| t.tgid = 900);
    assert_eq!(locks::fcntl(b, 37, flk(2, 0, 0, 0, 0), true), 0);
    assert_eq!(locks::fcntl(a, 6, flk(1, 0, 0, 0, 0), false), 0);
    task::current(|t| t.tgid = task::SELF_PID);
    assert_eq!(locks::fcntl(a, 6, flk(0, 0, 0, 0, 0), false), EAGAIN);
    locks::process_exited(900);
    assert_eq!(locks::fcntl(a, 6, flk(0, 0, 0, 0, 0), false), 0);
}

#[test]
fn flock_whole_files() {
    let _e = setup();
    memfs::mkfile("/f", b"");
    let a = open("/f", O_RDONLY) as u64;
    let b = open("/f", O_RDONLY) as u64;
    assert_eq!(locks::flock(a, 3), EINVAL);
    assert_eq!(locks::flock(a, 2), 0); // LOCK_EX
    assert_eq!(locks::flock(b, 1 | 4), EAGAIN); // LOCK_SH | LOCK_NB
    // A duplicate shares the lock (same description)
    let d = sys(32, &[a]) as u64;
    assert_eq!(locks::flock(d, 2 | 4), 0);
    // Conversion to shared lets others share
    assert_eq!(locks::flock(a, 1), 0);
    assert_eq!(locks::flock(b, 1 | 4), 0);
    assert!(locks::proc_locks().contains("FLOCK  ADVISORY  READ "));
    // flock and record locks do not conflict
    let w = open("/f", O_RDWR) as u64;
    assert_eq!(locks::fcntl(w, 6, flk(1, 0, 0, 0, 0), false), 0);
    // Unlock; a blocking lock waits for the holder to let go
    assert_eq!(locks::flock(b, 8), 0);
    task::wait::on_wait(move || {
        assert_eq!(locks::flock(a, 8), 0);
    });
    assert_eq!(locks::flock(b, 2), 0);
    task::wait::clear_on_wait();
    // The description closing releases it
    close(b as i64);
    assert_eq!(locks::flock(a, 2 | 4), 0);
    // Other descriptors: nothing to conflict with; missing ones EBADF
    let p = hydra_hosttests_t26::fs::pipe::PipeBuffer::new();
    let pfd = install(FileDescriptor::PipeRead(p)) as u64;
    assert_eq!(locks::flock(pfd, 2), 0);
    assert_eq!(locks::flock(999, 2), EBADF);
    // A full call through fcntl in the VFS: F_SETLK
    assert_eq!(sys(72, &[w, 6, flk(2, 0, 0, 0, 0)]), 0);
}
