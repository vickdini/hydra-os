//! `select` / `pselect6` (`src/compat/linux/select.rs`): descriptor sets in and out,
//! readiness from real kernel objects (eventfds, pipes), timeouts on the fake clock, signals
//! and the temporary signal mask.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::eventfd::EventFd;
use hydra_hosttests_t27::compat::linux::select::{sys_pselect6, sys_select};
use hydra_hosttests_t27::fs::FileDescriptor;
use std::sync::Arc;

const EBADF: i64 = -9;
const EINTR: i64 = -4;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ERESTARTSYS: i64 = -512;

type Set = [u64; 16];

fn set(fds: &[usize]) -> Set {
    let mut s = [0u64; 16];
    for &fd in fds {
        s[fd / 64] |= 1 << (fd % 64);
    }
    s
}

fn members(s: &Set) -> Vec<usize> {
    (0..1024).filter(|&fd| s[fd / 64] & (1 << (fd % 64)) != 0).collect()
}

fn eventfd(fd: usize, counter: u64) -> Arc<spin::Mutex<EventFd>> {
    let e = EventFd::new(0, 0);
    e.lock().counter = counter;
    fake::fd::install(fd, FileDescriptor::EventFd(e.clone()));
    e
}

fn file(fd: usize) {
    fake::fd::install(fd, FileDescriptor::File { path: "/etc/hostname".into(), readable: true, writable: true });
}

#[test]
fn reports_ready_descriptors_in_each_set() {
    fake::reset();
    eventfd(5, 1); // readable and writable
    eventfd(6, 0); // writable only
    file(70); // always both (second word of the set)
    let (mut r, mut w, mut e) = (set(&[5, 6, 70]), set(&[6, 70]), set(&[5]));
    let zero = Pair(0, 0);
    let n = sys_select([71, mptr(&mut r), mptr(&mut w), mptr(&mut e), ptr(&zero), 0]);
    assert_eq!(n, 4);
    assert_eq!(members(&r), vec![5, 70]);
    assert_eq!(members(&w), vec![6, 70]);
    assert_eq!(members(&e), Vec::<usize>::new(), "no exceptional conditions");
    assert_eq!(fake::TTY_PUMPS.get(), 1, "the terminal is pumped first");
    // Null sets are left alone
    let mut r = set(&[5]);
    assert_eq!(sys_select([6, mptr(&mut r), 0, 0, 0, 0]), 1);
}

#[test]
fn hang_up_and_errors_count_as_ready() {
    fake::reset();
    let pipe = hydra_hosttests_t27::fs::pipe::PipeBuffer::new();
    pipe.lock().drop_writer();
    fake::fd::install(8, FileDescriptor::PipeRead(pipe.clone()));
    fake::fd::install(9, FileDescriptor::PipeWrite(pipe.clone()));
    // No writer left: the read end hangs up (readable); no reader: the write end errors
    let (mut r, mut w) = (set(&[8]), set(&[9]));
    let zero = Pair(0, 0);
    assert_eq!(sys_select([10, mptr(&mut r), mptr(&mut w), 0, ptr(&zero), 0]), 2);
    assert_eq!(members(&r), vec![8], "POLLHUP is readable");
    assert_eq!(members(&w), vec![9], "room to write");
    pipe.lock().drop_reader();
    pipe.lock().write(&[0u8; 65536]).ok();
    let (mut r, mut w) = (set(&[]), set(&[9]));
    assert_eq!(sys_select([10, mptr(&mut r), mptr(&mut w), 0, ptr(&zero), 0]), 1);
    assert_eq!(members(&w), vec![9], "POLLERR is writable");
}

#[test]
fn argument_errors() {
    fake::reset();
    let mut r = set(&[3]);
    assert_eq!(sys_select([1025, mptr(&mut r), 0, 0, 0, 0]), EINVAL);
    assert_eq!(sys_select([4, mptr(&mut r), 0, 0, 0, 0]), EBADF, "fd 3 is not open");
    fake::bad_ptr(mptr(&mut r), 8);
    assert_eq!(sys_select([4, mptr(&mut r), 0, 0, 0, 0]), EFAULT);
    let mut w = set(&[]);
    let neg = Pair(-1, 0);
    assert_eq!(sys_select([0, 0, mptr(&mut w), 0, ptr(&neg), 0]), EINVAL);
    assert_eq!(sys_pselect6([0, 0, mptr(&mut w), 0, ptr(&neg), 0]), EINVAL);
    let mut t = Pair(1, 0);
    fake::bad_ptr(mptr(&mut t), 16);
    assert_eq!(sys_select([0, 0, 0, 0, mptr(&mut t), 0]), EFAULT);
    assert_eq!(sys_pselect6([0, 0, 0, 0, mptr(&mut t), 0]), EFAULT);
}

#[test]
fn timeouts_end_the_wait() {
    fake::reset();
    eventfd(5, 0);
    let mut r = set(&[5]);
    let t = Pair(1, 500_000); // 1.5 s (select: microseconds)
    let start = fake::now_ns();
    assert_eq!(sys_select([6, mptr(&mut r), 0, 0, ptr(&t), 0]), 0);
    assert_eq!(fake::LAST_DEADLINE.get(), Some(start + 1_500_000_000));
    assert_eq!(members(&r), Vec::<usize>::new(), "cleared on timeout");
    // pselect6: nanoseconds
    let mut r = set(&[5]);
    let t = Pair(0, 2_000);
    let start = fake::now_ns();
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, ptr(&t), 0]), 0);
    assert_eq!(fake::LAST_DEADLINE.get(), Some(start + 2_000));
}

#[test]
fn a_blocking_select_wakes_when_a_descriptor_becomes_ready() {
    fake::reset();
    let e = eventfd(5, 0);
    let mut r = set(&[5]);
    let e2 = e.clone();
    fake::on_wait(move |_| e2.lock().counter = 3);
    assert_eq!(sys_select([6, mptr(&mut r), 0, 0, 0, 0]), 1);
    assert_eq!(fake::WAITS.get(), 1);
    assert_eq!(fake::wait::LAST_QUEUES.get(), 1, "it slept on the eventfd's queue");
    assert_eq!(members(&r), vec![5]);
    // Nothing to wake it: it would block
    fake::reset();
    eventfd(5, 0);
    let mut r = set(&[5]);
    assert!(blocks(|| sys_select([6, mptr(&mut r), 0, 0, 0, 0])));
}

#[test]
fn signals_restart_select_but_interrupt_pselect_with_a_mask() {
    fake::reset();
    eventfd(5, 0);
    fake::SIGNAL_PENDING.set(true);
    let mut r = set(&[5]);
    assert_eq!(sys_select([6, mptr(&mut r), 0, 0, 0, 0]), ERESTARTSYS);
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, 0]), ERESTARTSYS, "no mask: restarted");
    let mask: u64 = 1 << 9;
    let arg = [ptr(&mask), 8u64];
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, ptr(&arg)]), EINTR);
    assert_eq!(fake::proc::TEMP_MASKS.with_borrow(|v| v.clone()), vec![mask], "in force during the wait");
    assert_eq!(fake::proc::RESTORED_MASKS.with_borrow(|v| v.clone()), vec![0x5a5a], "then the old one is back");
}

#[test]
fn pselect6_sigmask_argument() {
    fake::reset();
    file(5);
    let mut r = set(&[5]);
    // No mask pointer inside: no mask
    let none = [0u64, 8];
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, ptr(&none)]), 1);
    assert!(fake::proc::TEMP_MASKS.with_borrow(|v| v.is_empty()));
    // A successful wait with a mask still restores it
    let mask: u64 = 0xff;
    let arg = [ptr(&mask), 8u64];
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, ptr(&arg)]), 1);
    assert_eq!(fake::proc::RESTORED_MASKS.with_borrow(|v| v.len()), 1);
    let bad_len = [ptr(&mask), 16u64];
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, ptr(&bad_len)]), EINVAL);
    let mut gone = 0u64;
    fake::bad_ptr(mptr(&mut gone), 8);
    let bad_mask = [mptr(&mut gone), 8u64];
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, ptr(&bad_mask)]), EFAULT);
    let mut bad_arg = [0u64; 2];
    fake::bad_ptr(mptr(&mut bad_arg), 16);
    assert_eq!(sys_pselect6([6, mptr(&mut r), 0, 0, 0, mptr(&mut bad_arg)]), EFAULT);
}
