//! tty-server's terminals: pseudo-terminal pairs (moved from the kernel's `pty.rs`), the
//! console terminal, waiting calls, sessions and hang-ups.

mod common;

use common::{FakeIo, FakeMem};
use hydra_hosttests_w8_t::ldisc::{self, Termios};
use hydra_hosttests_w8_t::ttys::*;

const M: u32 = 10; // master slot
const S: u32 = 11; // slave slot
const BG: i64 = -4110;

fn who(tgid: u64, pgid: u64, sid: u64) -> Caller {
    Caller { tgid, pgid, sid, euid: 1000 }
}

/// A pair: master in slot M, unlocked, slave in slot S (no controlling terminal).
fn pair(io: &mut FakeIo) -> Ttys {
    let mut t = Ttys::new();
    let index = t.open_master(M, 1000, io).unwrap();
    assert_eq!(index, 0);
    let mem = FakeMem::with(0x100, &0u32.to_le_bytes());
    assert_eq!(t.ioctl(M, TIOCSPTLCK, 0x100, &who(1, 1, 1), &mem, io), Ok(0));
    t.open_slave(0, S, true, &who(1, 1, 1), io).unwrap();
    t
}

fn rd(t: &mut Ttys, slot: u32, id: u64, n: u64, io: &mut FakeIo) -> Ans {
    t.read(slot, id, 50, Iov::one(0x5000, n), false, io)
}

fn wr(t: &mut Ttys, slot: u32, id: u64, data: &[u8], io: &mut FakeIo) -> Ans {
    t.write(slot, id, 50, data.to_vec(), false, io)
}

#[test]
fn master_write_slave_reads_a_line_master_reads_the_echo() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(wr(&mut t, M, 1, b"hello\n", &mut io), Ans::Now(6));
    assert_eq!(io.ready[&S] & POLLIN, POLLIN, "the slave is readable");
    assert_eq!(rd(&mut t, S, 2, 100, &mut io), Ans::Now(6));
    assert_eq!(io.got(2).unwrap(), b"hello\n");
    assert_eq!(io.ready[&M] & POLLIN, POLLIN, "the echo waits for the master");
    assert_eq!(rd(&mut t, M, 3, 100, &mut io), Ans::Now(7));
    assert_eq!(io.got(3).unwrap(), b"hello\r\n");
    assert_eq!(io.ready[&M] & POLLIN, 0);
}

#[test]
fn slave_write_gets_onlcr() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(wr(&mut t, S, 1, b"out\n", &mut io), Ans::Now(4));
    assert_eq!(rd(&mut t, M, 2, 100, &mut io), Ans::Now(5));
    assert_eq!(io.got(2).unwrap(), b"out\r\n");
}

#[test]
fn waiting_reads_are_completed_by_the_other_side() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(rd(&mut t, S, 7, 100, &mut io), Ans::Pending);
    assert_eq!(rd(&mut t, M, 8, 100, &mut io), Ans::Pending);
    wr(&mut t, M, 1, b"ls\n", &mut io);
    assert_eq!(io.answer(7), Some(3));
    assert_eq!(io.got(7).unwrap(), b"ls\n");
    assert_eq!(io.answer(8), Some(4), "the master reader got the echo");
    assert_eq!(io.got(8).unwrap(), b"ls\r\n");
    // a partial line completes nobody
    assert_eq!(rd(&mut t, S, 9, 100, &mut io), Ans::Pending);
    wr(&mut t, M, 2, b"ab", &mut io);
    assert_eq!(io.answer(9), None);
    wr(&mut t, M, 3, b"\r", &mut io);
    assert_eq!(io.answer(9), Some(3));
}

#[test]
fn nonblocking_reads_and_empty_reads() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(t.read(M, 1, 50, Iov::one(0x1, 10), true, &mut io), Ans::Now(EAGAIN));
    assert_eq!(t.read(S, 2, 50, Iov::one(0x1, 10), true, &mut io), Ans::Now(EAGAIN));
    assert_eq!(t.read(S, 3, 50, Iov::one(0x1, 0), false, &mut io), Ans::Now(0));
    assert_eq!(t.read(99, 4, 50, Iov::one(0x1, 10), false, &mut io), Ans::Now(EBADF));
}

#[test]
fn output_limit_makes_slave_writers_wait() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let big = vec![b'x'; OUTPUT_LIMIT];
    assert_eq!(wr(&mut t, S, 1, &big, &mut io), Ans::Now(OUTPUT_LIMIT as i64));
    assert_eq!(io.ready[&S] & POLLOUT, 0, "not writable while full");
    assert_eq!(t.write(S, 2, 50, b"y".to_vec(), true, &mut io), Ans::Now(EAGAIN));
    assert_eq!(wr(&mut t, S, 3, b"z\n", &mut io), Ans::Pending);
    assert_eq!(rd(&mut t, M, 4, 4096, &mut io), Ans::Now(4096));
    assert_eq!(io.answer(3), Some(2), "room made: the writer's bytes went in");
    assert_eq!(io.ready[&S] & POLLOUT, POLLOUT);
    // and they come after the earlier bytes
    let mut all = io.got(4).unwrap();
    for id in 10..40 {
        if let Ans::Now(n) = t.read(M, id, 50, Iov::one(0x5000, 4096), true, &mut io) {
            if n > 0 {
                all.extend(io.got(id).unwrap());
            }
        }
    }
    assert_eq!(all.len(), OUTPUT_LIMIT + 3);
    assert!(all.ends_with(b"xz\r\n"));
}

#[test]
fn master_close_hangs_the_slave_up() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    // the slave is session 40's controlling terminal, foreground group 41
    let mem = FakeMem::default();
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(40, 41, 40), &mem, &mut io), Ok(0));
    assert_eq!(rd(&mut t, S, 5, 10, &mut io), Ans::Pending);
    t.closed(M, &mut io);
    assert_eq!(io.answer(5), Some(0), "a waiting reader sees end-of-file");
    assert_eq!(rd(&mut t, S, 6, 10, &mut io), Ans::Now(0));
    assert_eq!(wr(&mut t, S, 7, b"q", &mut io), Ans::Now(EIO));
    assert_eq!(io.ready[&S] & POLLHUP, POLLHUP);
    assert!(io.signals.contains(&(false, 40, 1)), "SIGHUP to the session leader");
    assert!(io.signals.contains(&(false, 40, 18)), "SIGCONT to the session leader");
    assert!(io.signals.contains(&(true, 41, 1)), "SIGHUP to the foreground group");
    // the number stays taken while the old slave lives (as devpts: ttyname of the old slave
    // never names the new pair), and the old /dev/pts/0 cannot be opened any more
    assert_eq!(t.open_master(12, 1000, &mut io), Ok(1));
    assert_eq!(t.open_slave(0, 13, true, &who(1, 1, 1), &mut io), Err(ENOENT));
    assert_eq!(t.pair_count(), 2);
    t.closed(S, &mut io);
    assert_eq!(t.pair_count(), 1, "the old pair is gone with its last end");
    assert_eq!(t.open_master(14, 1000, &mut io), Ok(0), "and its number is free");
}

#[test]
fn tiocsctty_follows_linux() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::default();
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(60, 60, 59), &mem, &mut io), Ok(EPERM), "not a session leader");
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io), Ok(0));
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io), Ok(0), "again: already ours");
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(80, 80, 80), &mem, &mut io), Ok(EPERM), "another session's");
    let root = Caller { tgid: 90, pgid: 90, sid: 90, euid: 0 };
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 0, &root, &mem, &mut io), Ok(EPERM), "root without force");
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 1, &root, &mem, &mut io), Ok(0), "root with force steals it");
    // a session that has a terminal already (the console) takes no second one
    t.cons_state(1, 100, 100, 80, 25, &mut io);
    assert_eq!(t.ioctl(S, ldisc::TIOCSCTTY, 1, &Caller { tgid: 100, pgid: 100, sid: 100, euid: 0 }, &mem, &mut io), Ok(EPERM));
    t.open_slave(0, 30, false, &who(100, 100, 100), &mut io).unwrap();
    assert_eq!(t.ioctl(S, ldisc::TIOCGSID, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x10), 90i32.to_le_bytes(), "opening did not make it the console session's either");
}

#[test]
fn dev_tty_ignores_the_slave_lock_and_hung_descriptors_fail() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::with(0x100, &1u32.to_le_bytes());
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io).unwrap();
    assert_eq!(t.ioctl(M, TIOCSPTLCK, 0x100, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(t.open_slave(0, 30, true, &who(1, 1, 1), &mut io), Err(EIO), "by name: locked");
    assert!(matches!(t.open_controlling(31, &who(71, 70, 70), &mut io), Some(Ok(_))), "/dev/tty: the caller's own");
    t.hangup(70, &mut io);
    assert_eq!(t.ioctl(S, ldisc::TCGETS, 0x200, &who(1, 1, 1), &mem, &mut io), Ok(EIO), "a hung-up descriptor");
}

#[test]
fn output_flush_empties_what_waits_for_the_master() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    wr(&mut t, S, 1, b"pending output", &mut io);
    let mem = FakeMem::default();
    assert_eq!(t.ioctl(S, ldisc::TCFLSH, 1, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(t.read(M, 2, 50, Iov::one(0x1, 100), true, &mut io), Ans::Now(EAGAIN));
}

#[test]
fn iov_sums() {
    assert!(Iov(vec![(1, 10), (2, 20)]).fits());
    assert!(!Iov(vec![(1, i64::MAX as u64), (2, 1)]).fits());
    assert_eq!(Iov(vec![(1, u64::MAX), (2, 5)]).total(), usize::MAX, "saturates");
}

#[test]
fn new_input_is_an_edge_for_slave_pollers() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    wr(&mut t, M, 1, b"a
", &mut io);
    io.ready_log.clear();
    wr(&mut t, M, 2, b"b
", &mut io);
    assert!(io.ready_log.iter().any(|&(s, b, arrived)| s == S && b & POLLIN != 0 && arrived), "a second line while readable");
}

#[test]
fn master_close_without_a_session_sends_nothing() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    t.closed(M, &mut io);
    assert!(io.signals.is_empty());
}

#[test]
fn last_slave_close_fails_master_reads() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(rd(&mut t, M, 5, 10, &mut io), Ans::Pending);
    t.closed(S, &mut io);
    assert_eq!(io.answer(5), Some(EIO));
    assert_eq!(rd(&mut t, M, 6, 10, &mut io), Ans::Now(EIO));
    assert_eq!(io.ready[&M] & POLLHUP, POLLHUP);
    t.closed(M, &mut io);
    assert_eq!(t.pair_count(), 0);
}

#[test]
fn master_reads_wait_before_any_slave_opened() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.open_master(M, 0, &mut io).unwrap();
    assert_eq!(rd(&mut t, M, 1, 10, &mut io), Ans::Pending, "no EIO before a slave was opened");
}

#[test]
fn locked_slave_and_numbers() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.open_master(M, 1000, &mut io).unwrap();
    assert_eq!(t.open_slave(0, S, true, &who(1, 1, 1), &mut io), Err(EIO), "locked until unlockpt");
    assert_eq!(t.open_slave(5, S, true, &who(1, 1, 1), &mut io), Err(ENOENT));
    let mem = FakeMem::default();
    assert_eq!(t.ioctl(M, TIOCGPTN, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x10), 0u32.to_le_bytes());
    assert_eq!(t.ioctl(M, TIOCGPTLCK, 0x14, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x14), 1u32.to_le_bytes());
    assert_eq!(t.open_master(20, 1000, &mut io), Ok(1), "the next pair is /dev/pts/1");
    assert_eq!(t.ioctl(S, TIOCGPTN, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(EBADF), "no such slot");
}

#[test]
fn stat_and_setattr_rules() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(t.stat(0), Some((0o620, 1000, 5)));
    assert_eq!(t.stat(1), None);
    assert_eq!(t.setattr(0, 2000, Some(0o600), None, None), EPERM, "not the owner");
    assert_eq!(t.setattr(0, 1000, Some(0o600), None, Some(7)), 0, "the owner sets mode and group");
    assert_eq!(t.setattr(0, 1000, None, Some(0), None), EPERM, "only root gives it away");
    assert_eq!(t.setattr(0, 0, None, Some(33), None), 0);
    assert_eq!(t.stat(0), Some((0o600, 33, 7)));
    assert_eq!(t.setattr(4, 0, None, None, None), ENOENT);
}

#[test]
fn opening_without_noctty_acquires_a_controlling_terminal() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    // not a session leader: nothing
    t.open_slave(0, 30, false, &who(60, 60, 59), &mut io).unwrap();
    // a session leader: the terminal becomes its own
    t.open_slave(0, 31, false, &who(70, 70, 70), &mut io).unwrap();
    let mem = FakeMem::default();
    assert_eq!(t.ioctl(S, ldisc::TIOCGSID, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x10), 70i32.to_le_bytes());
    // /dev/tty of that session opens the same slave
    match t.open_controlling(32, &who(71, 70, 70), &mut io) {
        Some(Ok((0, (mode, _, _)))) => assert_eq!(mode & 0o170000, 0o020000),
        other => panic!("{:?}", other.map(|r| r.map(|x| x.0))),
    }
    assert!(t.open_controlling(33, &who(80, 80, 80), &mut io).is_none(), "another session's /dev/tty is not ours");
    // a second session leader does not take it
    t.open_slave(0, 34, false, &who(90, 90, 90), &mut io).unwrap();
    assert_eq!(t.ioctl(S, ldisc::TIOCGSID, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x10), 70i32.to_le_bytes());
}

#[test]
fn ctrl_c_signals_the_foreground_group() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::with(0x20, &77i32.to_le_bytes());
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io).unwrap();
    assert_eq!(t.ioctl(S, ldisc::TIOCSPGRP, 0x20, &who(70, 70, 70), &mem, &mut io), Ok(0));
    wr(&mut t, M, 1, b"\x03", &mut io);
    assert_eq!(io.signals, vec![(true, 77, 2)]);
    wr(&mut t, M, 2, b"\x1a", &mut io);
    assert_eq!(io.signals.last(), Some(&(true, 77, 20)));
}

#[test]
fn tiocspgrp_checks_the_session() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::with(0x20, &77i32.to_le_bytes());
    mem.put_i32(0x24, -5);
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io).unwrap();
    assert_eq!(t.ioctl(S, ldisc::TIOCSPGRP, 0x20, &who(80, 80, 80), &mem, &mut io), Ok(ENOTTY), "not the caller's terminal");
    io.pgrps.insert((77, 70), 1);
    assert_eq!(t.ioctl(S, ldisc::TIOCSPGRP, 0x20, &who(70, 70, 70), &mem, &mut io), Ok(EPERM), "a group of another session");
    io.pgrps.insert((77, 70), ESRCH);
    assert_eq!(t.ioctl(S, ldisc::TIOCSPGRP, 0x20, &who(70, 70, 70), &mem, &mut io), Ok(ESRCH), "no such group");
    assert_eq!(t.ioctl(S, ldisc::TIOCSPGRP, 0x24, &who(70, 70, 70), &mem, &mut io), Ok(EINVAL));
    // a terminal no session holds takes any group (as before the move)
    let mut io2 = FakeIo::default();
    let mut t2 = pair(&mut io2);
    io2.pgrps.insert((77, 0), 1);
    assert_eq!(t2.ioctl(S, ldisc::TIOCSPGRP, 0x20, &who(80, 80, 80), &mem, &mut io2), Ok(0));
}

#[test]
fn resize_sends_sigwinch_once() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::with(0x30, &[33, 0, 101, 0, 0, 0, 0, 0]);
    mem.put_i32(0x40, 9);
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(9, 9, 9), &mem, &mut io).unwrap();
    assert_eq!(t.ioctl(M, ldisc::TIOCSWINSZ, 0x30, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(io.signals, vec![(true, 9, 28)]);
    assert_eq!(t.ioctl(M, ldisc::TIOCSWINSZ, 0x30, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(io.signals.len(), 1, "the same size: no signal");
    assert_eq!(t.ioctl(S, ldisc::TIOCGWINSZ, 0x50, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(&mem.at(0x50)[..4], &[33, 0, 101, 0]);
}

#[test]
fn raw_mode_change_wakes_a_reader_with_a_half_line() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    wr(&mut t, M, 1, b"abc", &mut io);
    assert_eq!(rd(&mut t, S, 2, 10, &mut io), Ans::Pending);
    let mut raw = Termios::default();
    raw.lflag &= !ldisc::ICANON;
    let mem = FakeMem::with(0x60, &raw.to_bytes());
    assert_eq!(t.ioctl(S, ldisc::TCSETS, 0x60, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(io.answer(2), Some(3));
    assert_eq!(io.got(2).unwrap(), b"abc");
}

#[test]
fn master_only_requests() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::with(0x10, &0u32.to_le_bytes());
    mem.put_i32(0x14, 1);
    assert_eq!(t.ioctl(M, TIOCPKT, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(t.ioctl(M, TIOCPKT, 0x14, &who(1, 1, 1), &mem, &mut io), Ok(EINVAL));
    wr(&mut t, S, 1, b"abc", &mut io);
    assert_eq!(t.ioctl(M, ldisc::FIONREAD, 0x20, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x20), 3u32.to_le_bytes());
    assert_eq!(t.ioctl(M, TIOCGPTPEER, 0o2, &who(1, 1, 1), &mem, &mut io), Err(0o2));
    assert_eq!(t.ioctl(S, TIOCGPTPEER, 0o2, &who(1, 1, 1), &mem, &mut io), Ok(EINVAL), "not on the slave");
    let (index, (mode, uid, gid)) = t.open_peer(M, 40, &who(1, 1, 1), &mut io).unwrap();
    assert_eq!((index, mode, uid, gid), (0, 0o020620, 1000, 5));
    assert_eq!(t.open_peer(S, 41, &who(1, 1, 1), &mut io), Err(ENOTTY));
}

#[test]
fn signals_and_exits_end_waiting_calls() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(rd(&mut t, S, 5, 10, &mut io), Ans::Pending);
    assert!(t.interrupt(5, &mut io));
    assert_eq!(io.answer(5), Some(ERESTARTSYS));
    assert!(!t.interrupt(5, &mut io), "only once");
    // a process exit drops its calls (no answer: the kernel ended them)
    assert_eq!(t.read(S, 6, 77, Iov::one(0x1, 10), false, &mut io), Ans::Pending);
    t.exited(77);
    wr(&mut t, M, 1, b"x\n", &mut io);
    assert_eq!(io.answer(6), None);
    assert_eq!(rd(&mut t, S, 7, 10, &mut io), Ans::Now(2), "the bytes stayed for the next reader");
}

#[test]
fn session_leader_exit_gives_the_terminal_up() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::default();
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 70, 70), &mem, &mut io).unwrap();
    t.exited(70);
    assert_eq!(t.ioctl(S, ldisc::TIOCGSID, 0x10, &who(1, 1, 1), &mem, &mut io), Ok(0));
    assert_eq!(mem.at(0x10), 0i32.to_le_bytes());
    assert!(io.signals.is_empty(), "no signal for a pty (as Linux)");
}

#[test]
fn a_reader_whose_memory_is_gone_leaves_the_bytes() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    assert_eq!(rd(&mut t, S, 5, 10, &mut io), Ans::Pending);
    assert_eq!(rd(&mut t, S, 6, 10, &mut io), Ans::Pending);
    io.dead.push(5);
    wr(&mut t, M, 1, b"x\n", &mut io);
    assert_eq!(io.answer(5), Some(-14));
    assert_eq!(io.answer(6), Some(2));
    assert_eq!(io.got(6).unwrap(), b"x\n");
}

#[test]
fn vhangup_kills_earlier_slave_descriptors() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::default();
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(70, 71, 70), &mem, &mut io).unwrap();
    assert_eq!(rd(&mut t, S, 5, 10, &mut io), Ans::Pending);
    assert_eq!(t.hangup(70, &mut io), Some((71, 70)));
    assert_eq!(io.answer(5), Some(0));
    assert_eq!(rd(&mut t, S, 6, 10, &mut io), Ans::Now(0));
    assert_eq!(wr(&mut t, S, 7, b"x", &mut io), Ans::Now(EIO));
    assert_eq!(io.ready[&S] & (POLLIN | POLLHUP), POLLIN | POLLHUP);
    assert_eq!(t.hangup(70, &mut io), None, "the session has no terminal any more");
    // a new open works
    t.open_slave(0, 30, true, &who(1, 1, 1), &mut io).unwrap();
    assert_eq!(wr(&mut t, 30, 8, b"ok", &mut io), Ans::Now(2));
}

#[test]
fn readiness_words() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.open_master(M, 0, &mut io).unwrap();
    assert_eq!(io.ready[&M], POLLOUT, "a fresh master: writable only");
    let mem = FakeMem::with(0x100, &0u32.to_le_bytes());
    t.ioctl(M, TIOCSPTLCK, 0x100, &who(1, 1, 1), &mem, &mut io).unwrap();
    t.open_slave(0, S, true, &who(1, 1, 1), &mut io).unwrap();
    assert_eq!(io.ready[&S], POLLOUT, "a fresh slave: writable only");
    wr(&mut t, S, 1, b"a", &mut io);
    assert!(io.ready_log.iter().any(|&(s, b, arrived)| s == M && b & POLLIN != 0 && arrived), "new bytes count as an edge");
}

#[test]
fn console_attach_keys_echo_and_reads() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.cons_state(1, 100, 100, 128, 48, &mut io);
    let me = who(100, 100, 100);
    assert_eq!(t.cons_read(1, &me, Iov::one(0x1, 64), false, BG, &mut io), Ans::Pending);
    t.cons_keys(1, &['l' as u32, 's' as u32, '\r' as u32], &mut io);
    assert_eq!(io.cons, b"ls\r\n", "echo on the console");
    assert_eq!(io.answer(1), Some(3));
    assert_eq!(io.got(1).unwrap(), b"ls\n");
    // Ctrl+C: the foreground group
    t.cons_keys(1, &[3], &mut io);
    assert_eq!(io.signals, vec![(true, 100, 2)]);
    // window size defaults to the console's
    let mem = FakeMem::default();
    assert_eq!(t.cons_ioctl(ldisc::TIOCGWINSZ, 0x10, &mem, &mut io), 0);
    assert_eq!(&mem.at(0x10)[..4], &[48, 0, 128, 0]);
}

#[test]
fn console_readiness_is_told_to_the_kernel() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.cons_state(3, 100, 100, 80, 25, &mut io);
    assert_eq!(io.cons_ready.last(), Some(&(3, false)));
    t.cons_keys(3, &['a' as u32, '\r' as u32], &mut io);
    assert_eq!(io.cons_ready.last(), Some(&(3, true)));
    let n = io.cons_ready.len();
    t.cons_keys(3, &['b' as u32], &mut io);
    assert_eq!(io.cons_ready.len(), n, "told only when it changes");
    assert_eq!(t.cons_read(1, &who(100, 100, 100), Iov::one(0x1, 64), false, BG, &mut io), Ans::Now(2));
    assert_eq!(io.cons_ready.last(), Some(&(3, false)));
}

#[test]
fn console_background_readers_and_detach() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.cons_state(1, 100, 100, 80, 25, &mut io);
    assert_eq!(t.cons_read(1, &who(101, 105, 100), Iov::one(0x1, 8), false, BG, &mut io), Ans::Now(BG), "a background group of the session");
    assert_eq!(t.cons_read(2, &who(102, 102, 102), Iov::one(0x1, 8), true, BG, &mut io), Ans::Now(EAGAIN), "another session reads (nothing typed)");
    assert_eq!(t.cons_read(3, &who(100, 100, 100), Iov::one(0x1, 8), false, BG, &mut io), Ans::Pending);
    // the program is done: hydra-shell takes the console back
    t.cons_state(2, 0, 0, 80, 25, &mut io);
    assert_eq!(io.answer(3), Some(EIO));
    t.cons_keys(2, &['x' as u32], &mut io);
    assert!(io.cons.is_empty(), "keys are hydra-shell's while no session holds the console");
}

#[test]
fn console_attach_resets_the_terminal() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.cons_state(1, 100, 100, 80, 25, &mut io);
    let mut raw = Termios::default();
    raw.lflag = 0;
    let mem = FakeMem::with(0x60, &raw.to_bytes());
    assert_eq!(t.cons_ioctl(ldisc::TCSETS, 0x60, &mem, &mut io), 0);
    t.cons_keys(1, &['q' as u32], &mut io);
    t.cons_state(2, 200, 200, 80, 25, &mut io);
    assert_eq!(t.console.tty.termios, Termios::default(), "a new program gets a cooked terminal");
    assert!(!t.console.tty.has_input(), "and none of the old input");
    // the same generation again changes nothing
    t.cons_keys(2, &['a' as u32], &mut io);
    t.cons_state(2, 200, 200, 80, 25, &mut io);
    assert_eq!(t.console.tty.line, b"a");
}

#[test]
fn console_write_and_waiter_cap() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    assert_eq!(t.cons_write(b"a\nb", &mut io), 3);
    assert_eq!(io.cons, b"a\r\nb");
    for i in 0..MAX_CONSOLE_WAITERS as u64 {
        assert_eq!(t.cons_read(i + 1, &who(7, 7, 7), Iov::one(0x1, 8), false, BG, &mut io), Ans::Pending);
    }
    assert_eq!(t.cons_read(999, &who(7, 7, 7), Iov::one(0x1, 8), false, BG, &mut io), Ans::Now(EIO), "a cap on held requests");
}

#[test]
fn at_most_2048_pairs() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    for i in 0..MAX_PTYS {
        assert_eq!(t.open_master(100 + i, 0, &mut io), Ok(i));
    }
    assert_eq!(t.open_master(9999, 0, &mut io), Err(ENOSPC));
    t.closed(100 + 7, &mut io);
    assert_eq!(t.open_master(9999, 0, &mut io), Ok(7), "a closed number is used again");
}

#[test]
fn a_programs_first_call_may_come_before_its_attach() {
    let mut io = FakeIo::default();
    let mut t = Ttys::new();
    t.cons_state(1, 100, 100, 80, 25, &mut io);
    // the kernel's call carries generation 2 (session 200): applied first, the read waits
    t.cons_state(2, 200, 200, 0, 0, &mut io);
    assert_eq!(t.cons_read(5, &who(200, 200, 200), Iov::one(0x1, 8), false, BG, &mut io), Ans::Pending);
    // the console thread's older news changes nothing, its keys of generation 1 are dropped
    t.cons_state(1, 100, 100, 80, 25, &mut io);
    t.cons_keys(1, &['z' as u32, '\r' as u32], &mut io);
    assert_eq!(io.answer(5), None, "still waiting: not ended with EIO, not fed old keys");
    // its news of generation 2 is no change either; keys of generation 2 reach the reader
    t.cons_state(2, 200, 200, 80, 25, &mut io);
    t.cons_keys(2, &['o' as u32, 'k' as u32, '\r' as u32], &mut io);
    assert_eq!(io.answer(5), Some(3));
    assert_eq!(io.got(5).unwrap(), b"ok\n");
}

#[test]
fn hang_up_flushes_typed_input_and_signals_the_leaders_own_group() {
    let mut io = FakeIo::default();
    let mut t = pair(&mut io);
    let mem = FakeMem::default();
    t.ioctl(S, ldisc::TIOCSCTTY, 0, &who(40, 40, 40), &mem, &mut io).unwrap();
    wr(&mut t, M, 1, b"typed\n", &mut io);
    t.closed(M, &mut io);
    assert!(io.signals.contains(&(true, 40, 1)), "the foreground group (the leader's own) gets SIGHUP too");
    let mut io2 = FakeIo::default();
    let mut t2 = pair(&mut io2);
    t2.ioctl(S, ldisc::TIOCSCTTY, 0, &who(40, 40, 40), &mem, &mut io2).unwrap();
    wr(&mut t2, M, 1, b"typed\n", &mut io2);
    t2.hangup(40, &mut io2);
    t2.open_slave(0, 30, true, &who(1, 1, 1), &mut io2).unwrap();
    assert_eq!(t2.read(30, 9, 50, Iov::one(0x1, 10), true, &mut io2), Ans::Now(EAGAIN), "nothing typed before the hang-up is left");
}
