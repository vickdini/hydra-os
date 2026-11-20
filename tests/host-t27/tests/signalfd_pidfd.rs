//! `signalfd` (`src/compat/linux/signalfd.rs`) and pidfd (`src/compat/linux/pidfd.rs`):
//! signals read as records, and descriptors that name processes.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::pidfd::{self, install, pid_of, sys_pidfd_open, sys_pidfd_send_signal, PidFd};
use hydra_hosttests_t27::compat::linux::signalfd::{sys_signalfd4, SignalFd};
use hydra_hosttests_t27::fake::proc::{TakenSignal, PENDING};
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::lx::obj::ServerObject;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::Arc;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;

fn bit(sig: u32) -> u64 {
    1 << (sig - 1)
}

fn sfd(fd: i64) -> Arc<SignalFd> {
    match fake::fd::get(fd) {
        Some(FileDescriptor::SignalFd(s)) => s,
        _ => panic!("not a signalfd"),
    }
}

fn pend(signo: u32, code: i32, pid: u32, uid: u32, value: u64) {
    PENDING.with_borrow_mut(|q| q.push_back(TakenSignal { signo, code, pid, uid, value }));
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

// ------------------------------------------------------------------ signalfd

#[test]
fn signalfd4_checks_its_arguments() {
    fake::reset();
    let mask = bit(10);
    assert_eq!(sys_signalfd4(-1, ptr(&mask), 4, 0), EINVAL, "mask size");
    assert_eq!(sys_signalfd4(-1, ptr(&mask), 8, 1), EINVAL, "unknown flag");
    assert_eq!(sys_signalfd4(-1, 0, 8, 0), EFAULT);
    assert_eq!(sys_signalfd4(-2, ptr(&mask), 8, 0), EBADF);
    assert_eq!(sys_signalfd4(77, ptr(&mask), 8, 0), EINVAL, "not a signalfd");
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(sys_signalfd4(-1, ptr(&mask), 8, 0), EMFILE);
}

#[test]
fn reads_one_record_per_signal_and_never_kill_or_stop() {
    fake::reset();
    fake::IDS.set((5, 5));
    // SIGKILL and SIGSTOP are dropped from the mask
    let mask = bit(10) | bit(12) | bit(9) | bit(19);
    let fd = sys_signalfd4(-1, ptr(&mask), 8, NONBLOCK | CLOEXEC);
    assert!(fd >= 3);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    let s = sfd(fd);
    assert!(s.get_nonblock());
    let mut buf = [0u8; 128 * 3];
    assert_eq!(s.read(&mut buf), EAGAIN);
    assert_eq!(s.poll_events(), 0);
    pend(9, 0, 1, 0, 0); // SIGKILL: not ours to read
    assert_eq!(s.poll_events(), 0);
    pend(10, -1, 42, 1000, 0x1_2345_6789);
    pend(12, 0, 43, 1001, 0);
    pend(3, 0, 1, 0, 0); // not in the mask
    assert_eq!(s.poll_events(), 1);
    let mut small = [0u8; 127];
    assert_eq!(s.read(&mut small), EINVAL);
    assert_eq!(s.read(&mut buf), 256, "two records");
    let r = &buf[..128];
    assert_eq!(u32_at(r, 0), 10);
    assert_eq!(u32_at(r, 8) as i32, -1, "ssi_code");
    assert_eq!(u32_at(r, 12), 42, "ssi_pid");
    assert_eq!(u32_at(r, 16), 1000, "ssi_uid");
    assert_eq!(u32_at(r, 44), 0x2345_6789, "ssi_int");
    assert_eq!(u64::from_le_bytes(r[48..56].try_into().unwrap()), 0x1_2345_6789, "ssi_ptr");
    assert_eq!(u32_at(&buf[128..], 0), 12);
    assert_eq!(PENDING.with_borrow(|q| q.len()), 2, "SIGKILL and SIGQUIT stay");
}

#[test]
fn sigchld_records_carry_the_child() {
    fake::reset();
    let mask = bit(17);
    let fd = sys_signalfd4(-1, ptr(&mask), 8, NONBLOCK);
    fake::proc::SIGCHLD_DETAILS.set((1, 777, 3)); // CLD_EXITED, pid, status
    pend(17, 0, 0, 0, 0);
    let mut buf = [0u8; 128];
    assert_eq!(sfd(fd).read(&mut buf), 128);
    assert_eq!(u32_at(&buf, 8), 1);
    assert_eq!(u32_at(&buf, 12), 777);
    assert_eq!(u32_at(&buf, 40), 3);
}

#[test]
fn changing_the_mask_of_an_existing_signalfd() {
    fake::reset();
    let a = bit(10);
    let fd = sys_signalfd4(-1, ptr(&a), 8, NONBLOCK);
    pend(12, 0, 0, 0, 0);
    assert_eq!(sfd(fd).poll_events(), 0);
    let b = bit(12);
    assert_eq!(sys_signalfd4(fd, ptr(&b), 8, 0), fd);
    assert_eq!(sfd(fd).poll_events(), 1);
    sfd(fd).set_nonblock(false);
    assert!(!sfd(fd).get_nonblock());
}

#[test]
fn blocking_read_waits_for_a_signal() {
    fake::reset();
    let m = bit(10);
    let fd = sys_signalfd4(-1, ptr(&m), 8, 0);
    let s = sfd(fd);
    fake::on_wait(|_| pend(10, 0, 0, 0, 0));
    let mut buf = [0u8; 128];
    assert_eq!(s.read(&mut buf), 128);
    assert_eq!(fake::WAITS.get(), 1);
    // A handled signal arrives instead: the read restarts
    fake::reset();
    let fd = sys_signalfd4(-1, ptr(&m), 8, 0);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(sfd(fd).read(&mut buf), -512);
    fake::reset();
    let fd = sys_signalfd4(-1, ptr(&m), 8, 0);
    assert!(blocks(|| sfd(fd).read(&mut buf)));
}

// ------------------------------------------------------------------ pidfd

/// A linux-server object standing in for its pidfd or another kind.
struct ServerDev(ServerObject);
impl CharDevice for ServerDev {
    fn read(&self, _b: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _w: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::new()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_server(&self) -> Option<&ServerObject> {
        Some(&self.0)
    }
}

fn pidfd_obj(fd: i64) -> Arc<PidFd> {
    match fake::fd::get(fd) {
        Some(FileDescriptor::PidFd(p)) => p,
        _ => panic!("not a pidfd"),
    }
}

#[test]
fn pidfd_open_names_a_live_process() {
    fake::reset();
    assert_eq!(sys_pidfd_open(10, 1), EINVAL, "unknown flag");
    assert_eq!(sys_pidfd_open(0, 0), EINVAL);
    assert_eq!(sys_pidfd_open(-5i64 as u64, 0), EINVAL);
    assert_eq!(sys_pidfd_open(10, 0), ESRCH);
    fake::proc::LIVE.with_borrow_mut(|l| l.insert(10));
    let fd = sys_pidfd_open(10, NONBLOCK);
    assert!(fd >= 3);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)), "always close-on-exec");
    let p = pidfd_obj(fd);
    assert_eq!(p.pid, 10);
    assert!(p.get_nonblock());
    p.set_nonblock(false);
    assert!(!p.get_nonblock());
    assert_eq!(p.poll_events(), 0, "running");
    fake::proc::EXITED.with_borrow_mut(|e| e.insert(10));
    assert_eq!(p.poll_events(), 1, "POLLIN once it exited");
    assert_eq!(pid_of(fd as u64), Ok(10));
}

#[test]
fn pid_of_other_descriptors() {
    fake::reset();
    assert_eq!(pid_of(40), Err(EBADF));
    fake::fd::install(40, FileDescriptor::File { path: "/x".into(), readable: true, writable: false });
    assert_eq!(pid_of(40), Err(EINVAL));
    let kind = hydra_hosttests_t27::ipc::protocol::LX_OBJ_KIND_PIDFD;
    fake::fd::install(41, FileDescriptor::Device(Arc::new(ServerDev(ServerObject { kind, tag: 321 }))));
    assert_eq!(pid_of(41), Ok(321), "a pidfd of linux-server names its process");
    fake::fd::install(42, FileDescriptor::Device(Arc::new(ServerDev(ServerObject { kind: kind + 1, tag: 321 }))));
    assert_eq!(pid_of(42), Err(EINVAL), "another kind of server object");
}

#[test]
fn install_reports_a_full_table() {
    fake::reset();
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(install(5, false), EMFILE);
}

#[test]
fn pidfd_send_signal() {
    fake::reset();
    fake::proc::LIVE.with_borrow_mut(|l| l.insert(20));
    let fd = sys_pidfd_open(20, 0) as u64;
    assert_eq!(sys_pidfd_send_signal(fd, 15, 0, 1), EINVAL, "flags");
    assert_eq!(sys_pidfd_send_signal(fd, 65, 0, 0), EINVAL, "signal number");
    assert_eq!(sys_pidfd_send_signal(99, 15, 0, 0), EBADF);
    assert_eq!(sys_pidfd_send_signal(fd, 0, 0, 0), 0, "existence check");
    assert!(fake::proc::POSTED.with_borrow(|p| p.is_empty()));
    assert_eq!(sys_pidfd_send_signal(fd, 15, 0, 0), 0);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.clone()), vec![(20, 0, 15)]);
    fake::proc::DENY_SIGNAL.set(true);
    assert_eq!(sys_pidfd_send_signal(fd, 15, 0, 0), EPERM, "kill(2)'s permission check");
    fake::proc::DENY_SIGNAL.set(false);
    fake::proc::GONE.with_borrow_mut(|g| g.insert(20));
    assert_eq!(sys_pidfd_send_signal(fd, 15, 0, 0), ESRCH, "gone while posting");
    fake::proc::EXITED.with_borrow_mut(|e| e.insert(20));
    assert_eq!(sys_pidfd_send_signal(fd, 15, 0, 0), ESRCH, "exited");
    let _ = &pidfd::EXIT_WQ;
}
