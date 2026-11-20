//! `pty.rs`: pseudo-terminal pairs: master/slave data flow through the shared line
//! discipline, locking, controlling terminals, hangup, the pty ioctls, stat/chmod of
//! `/dev/pts/N`, and end-of-file/EIO when one side closes.
//!
//! Pairs live in one global table: each test uses its own session ids, and never
//! assumes which slave number it gets.

mod common;

use std::sync::Arc;

use hydra_hosttests_t28::compat::linux::pty::{self, makedev, PtyFile, PTMX_MAJOR, PTMX_MINOR, PTS_DEV, PTS_MAJOR};
use hydra_hosttests_t28::fake;

const EAGAIN: i64 = -11;
const EIO: i64 = -5;
const EFAULT: i64 = -14;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;
const ERESTARTSYS: i64 = -512;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGPTLCK: u64 = 0x8004_5439;
const TIOCGPTPEER: u64 = 0x5441;
const TIOCPKT: u64 = 0x5420;

fn no_peer(_f: Arc<PtyFile>, _flags: u32) -> i64 {
    panic!("no peer expected")
}

fn ioctl(f: &PtyFile, req: u64, arg: u64) -> i64 {
    f.ioctl(req, arg, &no_peer)
}

/// A master, unlocked, and its index.
fn pair() -> (Arc<PtyFile>, u32) {
    let m = pty::open_master(1000, true);
    let mut n = [0u32];
    assert_eq!(ioctl(&m, TIOCGPTN, n.as_mut_ptr() as u64), 0);
    let mut zero = [0u32];
    assert_eq!(ioctl(&m, TIOCSPTLCK, zero.as_mut_ptr() as u64), 0);
    (m, n[0])
}

fn read_all(f: &PtyFile) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    let n = f.read(&mut b);
    assert!(n >= 0, "read failed: {n}");
    b.truncate(n as usize);
    b
}

#[test]
fn makedev_and_paths() {
    assert_eq!(makedev(PTMX_MAJOR, PTMX_MINOR), 0x502);
    assert_eq!(pty::slave_index("/dev/pts/12"), Some(12));
    assert_eq!(pty::slave_index("/dev/pts/x"), None);
    assert_eq!(pty::slave_index("/dev/tty1"), None);
}

#[test]
fn master_and_slave_exchange_data() {
    fake::IDS.set((501, 501));
    let (m, n) = pair();
    assert_eq!(m.pty.index, n);
    assert!(pty::indices().contains(&n));
    let s = pty::open_slave(n, true, true).unwrap();
    assert_eq!(m.path(), "/dev/ptmx");
    assert_eq!(s.path(), format!("/dev/pts/{n}"));
    assert_eq!(s.pty.slave_path(), format!("/dev/pts/{n}"));
    // Master writes are slave input, echoed back to the master
    assert_eq!(m.write(b"ls\r"), 3);
    assert_eq!(read_all(&s), b"ls\n");
    assert_eq!(read_all(&m), b"ls\r\n");
    // Slave output gets ONLCR
    assert_eq!(s.write(b"a\nb"), 3);
    assert_eq!(m.poll_events() & 0x1, 0x1);
    let mut fionread = [0u32];
    assert_eq!(ioctl(&m, 0x541B, fionread.as_mut_ptr() as u64), 0);
    assert_eq!(fionread[0], 4);
    assert_eq!(read_all(&m), b"a\r\nb");
    // Nothing to read: EAGAIN on non-blocking ends
    let mut b = [0u8; 8];
    assert_eq!(m.read(&mut b), EAGAIN);
    assert_eq!(s.read(&mut b), EAGAIN);
    assert_eq!(s.read(&mut []), 0);
    // write_nowait from both ends
    assert_eq!(s.write_nowait(b"k\n"), 2);
    assert_eq!(read_all(&m), b"k\r\n");
    assert_eq!(m.write_nowait(b"z\r"), 2);
    assert_eq!(read_all(&s), b"z\n");
    let _ = read_all(&m); // the echo
    // Non-blocking flag
    assert!(s.get_nonblock());
    s.set_nonblock(false);
    assert!(!s.get_nonblock());
}

#[test]
fn locked_slaves_cannot_open() {
    let m = pty::open_master(0, false);
    let mut n = [0u32];
    ioctl(&m, TIOCGPTN, n.as_mut_ptr() as u64);
    let mut lck = [7u32];
    assert_eq!(ioctl(&m, TIOCGPTLCK, lck.as_mut_ptr() as u64), 0);
    assert_eq!(lck[0], 1);
    assert_eq!(pty::open_slave(n[0], false, true).err(), Some(EIO));
    assert_eq!(ioctl(&m, TIOCSPTLCK, fake::BAD_PTR), EFAULT);
    assert_eq!(ioctl(&m, TIOCGPTN, 0), EFAULT);
    // No such pair
    assert_eq!(pty::open_slave(99_999, false, true).err(), Some(ENOENT));
}

#[test]
fn poll_events_of_both_ends() {
    let (m, n) = pair();
    assert_eq!(m.poll_events(), 0x4);
    let s = pty::open_slave(n, true, true).unwrap();
    assert_eq!(s.poll_events(), 0x4);
    m.write(b"x\r");
    assert_eq!(s.poll_events(), 0x4 | 0x1);
    drop(s);
    // The last slave closed: POLLHUP on the master, and EIO once its output is read
    assert_eq!(m.poll_events() & 0x10, 0x10);
    let _ = read_all(&m);
    let mut b = [0u8; 4];
    assert_eq!(m.read(&mut b), EIO);
}

#[test]
fn closing_the_master_ends_the_slave() {
    let (m, n) = pair();
    let s = pty::open_slave(n, true, true).unwrap();
    drop(m);
    assert!(!pty::indices().contains(&n));
    let mut b = [0u8; 4];
    assert_eq!(s.read(&mut b), 0);
    assert_eq!(s.write(b"x"), EIO);
    assert_eq!(s.poll_events() & 0x10, 0x10);
    // write_nowait drops the output quietly
    assert_eq!(s.write_nowait(b"gone"), 4);
    assert_eq!(pty::open_slave(n, false, true).err(), Some(ENOENT));
}

#[test]
fn slave_writers_wait_when_the_master_does_not_read() {
    let (m, n) = pair();
    let s = pty::open_slave(n, true, true).unwrap();
    let chunk = vec![b'x'; 16 * 1024];
    for _ in 0..4 {
        assert_eq!(s.write(&chunk), chunk.len() as i64);
    }
    // 64 KiB queued: full
    assert_eq!(s.poll_events() & 0x4, 0);
    assert_eq!(s.write(b"y"), EAGAIN);
    // Blocking: a signal ends the wait; the master reading makes room
    s.set_nonblock(false);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(s.write(b"y"), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    let m2 = m.clone();
    fake::on_wait(move || {
        let mut b = vec![0u8; 4096];
        m2.read(&mut b);
    });
    assert_eq!(s.write(b"y"), 1);
    fake::clear_on_wait();
}

#[test]
fn blocking_reads() {
    let (m, n) = pair();
    let s = pty::open_slave(n, false, true).unwrap();
    m.set_nonblock(false);
    let mut b = [0u8; 8];
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(s.read(&mut b), ERESTARTSYS);
    assert_eq!(m.read(&mut b), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    // The slave waits until the master types a line
    let m2 = m.clone();
    fake::on_wait(move || {
        m2.write(b"go\r");
    });
    assert_eq!(s.read(&mut b), 3);
    assert_eq!(&b[..3], b"go\n");
    fake::clear_on_wait();
}

#[test]
fn signals_go_to_the_foreground_group() {
    fake::IDS.set((610, 610));
    fake::SESSIONS.with_borrow_mut(|m| m.insert(610, (610, 611)));
    let (m, n) = pair();
    // A session leader without a terminal acquires it on open
    let s = pty::open_slave(n, true, false).unwrap();
    assert_eq!(pty::controlling_tty(610).map(|p| p.index), Some(n));
    fake::take_group_signals();
    m.write(b"\x03");
    assert_eq!(fake::take_group_signals(), vec![(611, 2)]);
    // TIOCGPGRP/TIOCSPGRP act on the slave's terminal from both ends
    let mut pg = [0i32];
    assert_eq!(ioctl(&m, 0x540F, pg.as_mut_ptr() as u64), 0);
    assert_eq!(pg[0], 611);
    // A window size change signals SIGWINCH
    let mut ws = [30u16, 100, 0, 0];
    assert_eq!(ioctl(&s, 0x5414, ws.as_mut_ptr() as u64), 0);
    assert_eq!(fake::take_group_signals(), vec![(611, 28)]);
    // The same size again: no signal
    assert_eq!(ioctl(&s, 0x5414, ws.as_mut_ptr() as u64), 0);
    assert!(fake::take_group_signals().is_empty());
    let mut got = [0u16; 4];
    assert_eq!(ioctl(&m, 0x5413, got.as_mut_ptr() as u64), 0);
    assert_eq!(&got[..2], &[30, 100]);
    // /dev/tty for the session
    let t = pty::open_controlling(true).expect("controlling terminal");
    assert_eq!(t.path(), format!("/dev/pts/{n}"));
    // vhangup: the session loses it; earlier slave descriptors are dead
    assert_eq!(pty::hangup(610), Some((610, 611)));
    assert!(pty::controlling_tty(610).is_none());
    let mut b = [0u8; 4];
    assert_eq!(s.read(&mut b), 0);
    assert_eq!(s.write(b"x"), EIO);
    assert!(pty::hangup(610).is_none());
    // A slave opened after the hangup works
    let s2 = pty::open_slave(n, true, true).unwrap();
    assert_eq!(s2.write(b"ok"), 2);
    drop(t);
    fake::SESSIONS.with_borrow_mut(|m| m.remove(&610));
}

#[test]
fn signals_without_a_foreground_group_are_dropped() {
    let (m, n) = pair();
    let _s = pty::open_slave(n, true, true).unwrap();
    fake::take_group_signals();
    m.write(b"\x03");
    assert!(fake::take_group_signals().is_empty());
    // No session: no controlling terminal to open
    fake::IDS.set((620, 620));
    assert!(pty::open_controlling(false).is_none());
}

#[test]
fn tiocsctty_takes_the_terminal() {
    fake::IDS.set((630, 630));
    fake::SESSIONS.with_borrow_mut(|m| m.insert(630, (630, 631)));
    let (m, n) = pair();
    let s = pty::open_slave(n, true, true).unwrap();
    assert!(pty::controlling_tty(630).is_none());
    assert_eq!(ioctl(&s, 0x540E, 0), 0);
    assert_eq!(pty::controlling_tty(630).map(|p| p.index), Some(n));
    // Without a session nothing changes, still 0
    fake::IDS.set((632, 632));
    assert_eq!(ioctl(&m, 0x540E, 0), 0);
    fake::SESSIONS.with_borrow_mut(|m| m.remove(&630));
}

#[test]
fn packet_mode_and_peer() {
    let (m, n) = pair();
    let mut v = [0u32];
    assert_eq!(ioctl(&m, TIOCPKT, v.as_mut_ptr() as u64), 0);
    v[0] = 1;
    assert_eq!(ioctl(&m, TIOCPKT, v.as_mut_ptr() as u64), EINVAL);
    assert_eq!(ioctl(&m, TIOCPKT, 0), EFAULT);
    // TIOCGPTPEER opens the slave and hands it to the caller's callback
    let r = m.ioctl(TIOCGPTPEER, 0o4000 | 2, &|f: Arc<PtyFile>, flags| {
        assert!(!f.master);
        assert!(f.get_nonblock());
        assert_eq!(flags, 0o4000 | 2);
        42
    });
    assert_eq!(r, 42);
    // Locked again: the peer cannot open
    let mut one = [1u32];
    ioctl(&m, TIOCSPTLCK, one.as_mut_ptr() as u64);
    assert_eq!(m.ioctl(TIOCGPTPEER, 0, &no_peer), EIO);
    // Pty requests on the slave are terminal requests (and unknown there)
    let s = {
        let mut zero = [0u32];
        ioctl(&m, TIOCSPTLCK, zero.as_mut_ptr() as u64);
        pty::open_slave(n, true, true).unwrap()
    };
    assert_eq!(ioctl(&s, TIOCGPTN, v.as_mut_ptr() as u64), EINVAL);
    // Terminal requests that fail do not wake
    assert_eq!(ioctl(&s, 0x5401, fake::BAD_PTR), EFAULT);
}

#[test]
fn leaving_canonical_mode_wakes_readers() {
    let (m, n) = pair();
    let s = pty::open_slave(n, true, true).unwrap();
    m.write(b"abc");
    let mut b = [0u8; 8];
    assert_eq!(s.read(&mut b), EAGAIN);
    let mut t = [0u8; 36];
    assert_eq!(ioctl(&s, 0x5401, t.as_mut_ptr() as u64), 0);
    t[12..16].copy_from_slice(&0u32.to_le_bytes());
    let before = s.pty.wq.wakes();
    assert_eq!(ioctl(&s, 0x5402, t.as_mut_ptr() as u64), 0);
    assert!(s.pty.wq.wakes() > before);
    assert_eq!(s.read(&mut b), 3);
    // Default window size of a pty: 24 x 80
    let mut ws = [0u16; 4];
    let (m2, _) = pair();
    assert_eq!(ioctl(&m2, 0x5413, ws.as_mut_ptr() as u64), 0);
    assert_eq!(&ws[..2], &[24, 80]);
}

#[test]
fn stat_and_chmod_of_slave_nodes() {
    let ptmx = pty::stat_path("/dev/ptmx").unwrap().unwrap();
    assert_eq!((ptmx.st_mode, ptmx.st_rdev, ptmx.st_dev, ptmx.st_ino), (0o020666, 0x502, PTS_DEV, 2));
    for d in ["/dev/pts", "/dev/pts/"] {
        let dir = pty::stat_path(d).unwrap().unwrap();
        assert_eq!((dir.st_mode, dir.st_nlink, dir.st_ino), (0o040755, 2, 1));
    }
    assert!(pty::stat_path("/dev/null").is_none());
    assert_eq!(pty::stat_path("/dev/pts/99999").unwrap().err(), Some(ENOENT));

    let (m, n) = pair();
    let path = format!("/dev/pts/{n}");
    let st = pty::stat_path(&path).unwrap().unwrap();
    assert_eq!(st.st_mode, 0o020620);
    assert_eq!((st.st_uid, st.st_gid), (1000, 5));
    assert_eq!(st.st_rdev, makedev(PTS_MAJOR + (n as u64 >> 8), n as u64 & 0xFF));
    assert_eq!(st.st_ino, n as u64 + 3);
    assert_eq!(m.stat().st_rdev, 0x502);
    let s = pty::open_slave(n, true, true).unwrap();
    assert_eq!(s.stat().st_rdev, st.st_rdev);

    // The owner may change the mode and group; not give the node away
    assert_eq!(pty::setattr_path(&path, 1000, Some(0o100600), None, Some(7)), Some(0));
    let st = pty::stat_path(&path).unwrap().unwrap();
    assert_eq!((st.st_mode, st.st_gid), (0o020600, 7));
    assert_eq!(pty::setattr_path(&path, 1000, None, Some(0), None), Some(-1));
    assert_eq!(pty::setattr_path(&path, 1000, None, Some(1000), None), Some(0));
    assert_eq!(pty::setattr_path(&path, 2000, Some(0o666), None, None), Some(-1));
    // Root may
    assert_eq!(pty::setattr_path(&path, 0, None, Some(0), None), Some(0));
    assert_eq!(pty::stat_path(&path).unwrap().unwrap().st_uid, 0);
    assert_eq!(pty::setattr_path("/dev/pts/99999", 0, None, None, None), Some(ENOENT));
    assert!(pty::setattr_path("/dev/tty", 0, None, None, None).is_none());
}
