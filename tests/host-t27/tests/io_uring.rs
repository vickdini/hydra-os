//! io_uring (`src/compat/linux/io_uring.rs`): ring setup and the SQ/CQ arithmetic seen
//! through the mapped pages, opcode dispatch to the program's own system calls (answered
//! by a fake), links and link timeouts, waiting requests and the ring worker, timeouts,
//! cancellation, registered files and buffers, provided buffers and buffer rings, eventfd
//! notification, `MSG_RING`, the probe and registered ring descriptors.

mod common;
use common::*;

use hydra_hosttests_t27::arch::syscall::SyscallFrame;
use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::eventfd::EventFd;
use hydra_hosttests_t27::compat::linux::io_uring::dispatch;
use hydra_hosttests_t27::fake::proc::{Process, PROCS};
use hydra_hosttests_t27::fake::task::{run_daemon_steps, WORKERS, WORKER_ID};
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::lx::obj::ServerObject;
use hydra_hosttests_t27::memory::vm::MappedObject;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::Arc;

const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const ENXIO: i64 = -6;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ETIME: i64 = -62;
const EOPNOTSUPP: i64 = -95;
const ENOBUFS: i64 = -105;
const ECANCELED: i64 = -125;

const OFF_SQES_PG: u64 = 0x1000_0000 / 4096;
const OFF_CQ_PG: u64 = 0x800_0000 / 4096;

// SQE flags
const FIXED_FILE: u8 = 1;
const IO_LINK: u8 = 4;
const IO_HARDLINK: u8 = 8;
const BUFFER_SELECT: u8 = 32;
const CQE_SKIP: u8 = 64;

// Opcodes
const NOP: u8 = 0;
const READV: u8 = 1;
const WRITEV: u8 = 2;
const FSYNC: u8 = 3;
const READ_FIXED: u8 = 4;
const WRITE_FIXED: u8 = 5;
const POLL_ADD: u8 = 6;
const POLL_REMOVE: u8 = 7;
const SYNC_FILE_RANGE: u8 = 8;
const SENDMSG: u8 = 9;
const RECVMSG: u8 = 10;
const TIMEOUT: u8 = 11;
const TIMEOUT_REMOVE: u8 = 12;
const ACCEPT: u8 = 13;
const ASYNC_CANCEL: u8 = 14;
const LINK_TIMEOUT: u8 = 15;
const CONNECT: u8 = 16;
const FALLOCATE: u8 = 17;
const OPENAT: u8 = 18;
const CLOSE: u8 = 19;
const FILES_UPDATE: u8 = 20;
const STATX: u8 = 21;
const READ: u8 = 22;
const WRITE: u8 = 23;
const FADVISE: u8 = 24;
const MADVISE: u8 = 25;
const SEND: u8 = 26;
const RECV: u8 = 27;
const OPENAT2: u8 = 28;
const EPOLL_CTL: u8 = 29;
const PROVIDE_BUFFERS: u8 = 31;
const REMOVE_BUFFERS: u8 = 32;
const SHUTDOWN: u8 = 34;
const RENAMEAT: u8 = 35;
const UNLINKAT: u8 = 36;
const MKDIRAT: u8 = 37;
const SYMLINKAT: u8 = 38;
const LINKAT: u8 = 39;
const MSG_RING: u8 = 40;
const SOCKET: u8 = 45;
const FTRUNCATE: u8 = 55;
const BIND: u8 = 56;
const LISTEN: u8 = 57;

const CQE_F_BUFFER: u32 = 1;
const CQE_F_MORE: u32 = 2;

/// A submission queue entry.
#[derive(Clone, Copy, Default)]
struct Sqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    op_flags: u32,
    user_data: u64,
    buf_index: u16,
    file_index: u32,
}

impl Sqe {
    fn op(opcode: u8, fd: i32, user_data: u64) -> Sqe {
        Sqe { opcode, fd, user_data, ..Default::default() }
    }
    fn bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[0] = self.opcode;
        b[1] = self.flags;
        b[2..4].copy_from_slice(&self.ioprio.to_le_bytes());
        b[4..8].copy_from_slice(&self.fd.to_le_bytes());
        b[8..16].copy_from_slice(&self.off.to_le_bytes());
        b[16..24].copy_from_slice(&self.addr.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..32].copy_from_slice(&self.op_flags.to_le_bytes());
        b[32..40].copy_from_slice(&self.user_data.to_le_bytes());
        b[40..42].copy_from_slice(&self.buf_index.to_le_bytes());
        b[44..48].copy_from_slice(&self.file_index.to_le_bytes());
        b
    }
}

/// The program's view of a ring: its descriptor, its mapped pages and the offsets the
/// kernel reported.
#[derive(Clone)]
struct Ring {
    fd: u64,
    dev: Arc<dyn CharDevice>,
    mem: Arc<dyn MappedObject>,
    sq_entries: u32,
    cq_entries: u32,
    sq_off: [u32; 7],
    cq_off: [u32; 7],
    features: u32,
}

/// `struct io_uring_params`.
fn params(flags: u32, cq: u32) -> [u8; 120] {
    let mut p = [0u8; 120];
    p[4..8].copy_from_slice(&cq.to_le_bytes());
    p[8..12].copy_from_slice(&flags.to_le_bytes());
    p
}

fn setup(entries: u64, p: &mut [u8; 120]) -> i64 {
    dispatch(&SyscallFrame::default(), 425, [entries, mptr(p), 0, 0, 0, 0])
}

fn ring(entries: u64) -> Ring {
    ring_with(entries, 0, 0)
}

fn ring_with(entries: u64, flags: u32, cq: u32) -> Ring {
    let mut p = params(flags, cq);
    let fd = setup(entries, &mut p);
    assert!(fd >= 3, "setup: {fd}");
    let dev = match fake::fd::get(fd) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("not a device"),
    };
    let mem = dev.mmap_object().ok().expect("mappable");
    let w = |o: usize| u32::from_le_bytes(p[o..o + 4].try_into().unwrap());
    Ring {
        fd: fd as u64,
        dev,
        mem,
        sq_entries: w(0),
        cq_entries: w(4),
        sq_off: core::array::from_fn(|i| w(40 + i * 4)),
        cq_off: core::array::from_fn(|i| w(80 + i * 4)),
        features: w(20),
    }
}

impl Ring {
    /// Address of byte `off` of the ring area (through the mapping, at either offset).
    fn at(&self, off: u32, cq_mapping: bool) -> *mut u8 {
        let base = if cq_mapping { OFF_CQ_PG } else { 0 };
        let f = self.mem.get_page(base + (off / 4096) as u64).expect("ring page");
        (f.start_address().as_u64() + (off % 4096) as u64) as *mut u8
    }
    fn get(&self, off: u32) -> u32 {
        unsafe { (self.at(off, false) as *const u32).read_volatile() }
    }
    fn set(&self, off: u32, v: u32) {
        unsafe { (self.at(off, false) as *mut u32).write_volatile(v) }
    }
    fn sq_tail(&self) -> u32 {
        self.get(self.sq_off[1])
    }
    /// Queues `s` (not yet submitted).
    fn push(&self, s: Sqe) {
        let tail = self.sq_tail();
        let idx = tail & (self.sq_entries - 1);
        self.push_index(s, idx);
    }
    fn push_index(&self, s: Sqe, idx: u32) {
        let tail = self.sq_tail();
        let slot = tail & (self.sq_entries - 1);
        if idx < self.sq_entries {
            let off = idx as u64 * 64;
            let f = self.mem.get_page(OFF_SQES_PG + off / 4096).expect("sqe page");
            unsafe { ((f.start_address().as_u64() + off % 4096) as *mut [u8; 64]).write(s.bytes()) };
        }
        self.set(self.sq_off[6] + slot * 4, idx);
        self.set(self.sq_off[1], tail.wrapping_add(1));
    }
    fn enter(&self, n: u64, min: u64, flags: u64) -> i64 {
        dispatch(&SyscallFrame::default(), 426, [self.fd, n, min, flags, 0, 0])
    }
    /// Submits `sqes` and returns how many were taken.
    fn submit(&self, sqes: &[Sqe]) -> i64 {
        for s in sqes {
            self.push(*s);
        }
        self.enter(sqes.len() as u64, 0, 0)
    }
    /// Takes the completions: (user_data, res, flags).
    fn reap(&self) -> Vec<(u64, i64, u32)> {
        let mut out = Vec::new();
        let mut head = self.get(self.cq_off[0]);
        let tail = self.get(self.cq_off[1]);
        while head != tail {
            let off = self.cq_off[5] + (head & (self.cq_entries - 1)) * 16;
            let p = self.at(off, true);
            unsafe {
                out.push((
                    (p as *const u64).read_volatile(),
                    (p.add(8) as *const i32).read_volatile() as i64,
                    (p.add(12) as *const u32).read_volatile(),
                ));
            }
            head = head.wrapping_add(1);
        }
        self.set(self.cq_off[0], head);
        out
    }
    fn register(&self, op: u64, arg: u64, nr: u64) -> i64 {
        dispatch(&SyscallFrame::default(), 427, [self.fd, op, arg, nr, 0, 0])
    }
}

/// Installs an always-ready file at `fd`.
fn file(fd: usize) {
    fake::fd::install(fd, FileDescriptor::File { path: "/data".into(), readable: true, writable: true });
}

fn eventfd(fd: usize, counter: u64) -> Arc<spin::Mutex<EventFd>> {
    let e = EventFd::new(0, 0);
    e.lock().counter = counter;
    fake::fd::install(fd, FileDescriptor::EventFd(e.clone()));
    e
}

/// Answers nested calls: reads and writes move `len` bytes (`a[2]`), other calls succeed.
fn echo_syscalls() {
    fake::on_nested(|num, a| match num {
        0 | 1 | 17 | 18 | 19 | 20 | 44 | 45 => a[2] as i64,
        _ => 0,
    });
}

fn nested_calls() -> Vec<(u64, [u64; 6])> {
    fake::NESTED_CALLS.with_borrow(|v| v.clone())
}

fn timespec(sec: i64, nsec: i64) -> Box<[i64; 2]> {
    Box::new([sec, nsec])
}

/// A process with a worker that can start.
fn process(pid: u64) {
    fake::reset();
    fake::IDS.set((pid, pid));
    PROCS.lock().insert(pid, Process { zombie: false });
    WORKER_ID.set(Some(pid + 100_000));
}

/// Runs the ring worker for `rounds` sleeps, as its own task.
fn run_worker(step: impl FnMut(usize) -> bool + 'static) {
    let (_, pid) = fake::IDS.get();
    let entry = WORKERS.with_borrow(|w| w.last().expect("a worker was started").1);
    fake::IDS.set((pid + 100_000, pid));
    run_daemon_steps(entry, step);
    fake::IDS.set((pid, pid));
}
// ------------------------------------------------------------------ setup

#[test]
fn setup_sizes_and_reports_the_layout() {
    process(31_001);
    let r = ring(3);
    assert_eq!((r.sq_entries, r.cq_entries), (4, 8), "rounded up; CQ twice the SQ");
    assert_eq!(r.features, 1 | 2 | 4 | 8 | 16 | 32 | 64 | 256 | 512 | 2048 | 4096);
    assert_eq!(&r.sq_off[..6], &[0, 4, 8, 12, 16, 20]);
    assert_eq!(r.sq_off[6], 128 + 8 * 16, "the SQ array after the CQEs");
    assert_eq!(&r.cq_off[..7], &[64, 68, 72, 76, 80, 128, 84]);
    assert_eq!((r.get(8), r.get(12), r.get(72), r.get(76)), (3, 4, 7, 8), "masks and sizes in the ring");
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(r.fd as usize)));
    assert_eq!(r.dev.path(), "anon_inode:[io_uring]");
    assert_eq!(r.dev.rdev(), 0);
    let mut b = [0u8; 4];
    assert_eq!(r.dev.read(&mut b), EINVAL);
    r.dev.set_nonblock(true);
    assert!(!r.dev.nonblock());
    // The CQ mapping offset reaches the same pages; nothing past the end
    assert_eq!(r.mem.get_page(0), r.mem.get_page(OFF_CQ_PG));
    assert!(r.mem.get_page(1).is_none());
    assert!(r.mem.get_page(OFF_SQES_PG).is_some());
    assert!(r.mem.get_page(OFF_SQES_PG + 1).is_none());
}

#[test]
fn setup_errors() {
    process(31_002);
    let mut p = params(0, 0);
    assert_eq!(dispatch(&SyscallFrame::default(), 425, [4, 0, 0, 0, 0, 0]), EFAULT);
    assert_eq!(setup(0, &mut p), EINVAL);
    for bad in [1u32, 2, 4] {
        let mut p = params(bad, 0);
        assert_eq!(setup(4, &mut p), EINVAL, "IOPOLL/SQPOLL/SQ_AFF: {bad}");
    }
    let mut p = params(0, 0);
    p[30] = 1;
    assert_eq!(setup(4, &mut p), EINVAL, "reserved bytes");
    let mut p = params(0, 0);
    assert_eq!(setup(32769, &mut p), EINVAL, "too many without CLAMP");
    let mut p = params(8, 0);
    assert_eq!(setup(4, &mut p), EINVAL, "CQSIZE 0");
    let mut p = params(8, 2);
    assert_eq!(setup(4, &mut p), EINVAL, "CQ smaller than the SQ");
    let mut p = params(8, 70_000);
    assert_eq!(setup(4, &mut p), EINVAL, "CQ too big without CLAMP");
    fake::FRAME_BUDGET.set(Some(1));
    let mut p = params(0, 0);
    assert_eq!(setup(4, &mut p), ENOMEM);
    let live = fake::FRAMES_LIVE.get();
    fake::FRAME_BUDGET.set(Some(2));
    let mut p = params(0, 0);
    assert_eq!(setup(256, &mut p), ENOMEM, "three ring pages needed, two there");
    assert_eq!(fake::FRAMES_LIVE.get(), live, "the two taken were given back");
    fake::FRAME_BUDGET.set(None);
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    let before = fake::FRAMES_LIVE.get();
    let mut p = params(0, 0);
    assert_eq!(setup(4, &mut p), EMFILE);
    assert_eq!(fake::FRAMES_LIVE.get(), before, "the ring's frames were freed");
}

#[test]
fn setup_clamps_and_sizes_the_cq() {
    process(31_003);
    let r = ring_with(5, 8, 20); // CQSIZE
    assert_eq!((r.sq_entries, r.cq_entries), (8, 32));
    let r = ring_with(100_000, 16 | 8, 100_000); // CLAMP + CQSIZE
    assert_eq!((r.sq_entries, r.cq_entries), (32768, 65536));
    let r = ring_with(40_000, 16, 0);
    assert_eq!(r.sq_entries, 32768);
}

// ------------------------------------------------------------------ submission and completion

#[test]
fn nops_complete_in_order() {
    process(31_004);
    let r = ring(4);
    assert_eq!(r.dev.poll_events(), 0x104, "room to submit, nothing to reap");
    assert_eq!(r.submit(&[Sqe::op(NOP, 0, 1), Sqe::op(NOP, 0, 2)]), 2);
    assert_eq!(r.get(r.sq_off[0]), 2, "SQ head moved");
    assert_eq!(r.dev.poll_events(), 0x145);
    let mut w = WaitSet::new();
    r.dev.add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 1);
    assert_eq!(r.reap(), vec![(1, 0, 0), (2, 0, 0)]);
    assert_eq!(r.enter(0, 0, 0), 0, "nothing to submit");
    // Submitting fewer than queued
    r.push(Sqe::op(NOP, 0, 3));
    r.push(Sqe::op(NOP, 0, 4));
    assert_eq!(r.enter(1, 0, 0), 1);
    assert_eq!(r.enter(5, 0, 0), 1, "only one left");
    assert_eq!(r.reap(), vec![(3, 0, 0), (4, 0, 0)]);
    // A full SQ is not writable
    for i in 0..4 {
        r.push(Sqe::op(NOP, 0, 10 + i));
    }
    assert_eq!(r.dev.poll_events() & 0x104, 0);
    assert_eq!(r.enter(4, 0, 0), 4);
}

#[test]
fn bad_sq_indexes_are_dropped() {
    process(31_005);
    let r = ring(4);
    r.push_index(Sqe::op(NOP, 0, 1), 99);
    r.push(Sqe::op(NOP, 0, 2));
    assert_eq!(r.enter(2, 0, 0), 2, "both taken");
    assert_eq!(r.get(r.sq_off[5]), 1, "one dropped");
    assert_eq!(r.reap(), vec![(2, 0, 0)]);
}

#[test]
fn completion_queue_overflow() {
    process(31_006);
    let r = ring(2); // CQ of 4
    let sqes: Vec<Sqe> = (0..6).map(|i| Sqe::op(NOP, 0, i)).collect();
    r.submit(&sqes[..2]);
    r.submit(&sqes[2..4]);
    r.submit(&sqes[4..6]);
    assert_eq!(r.get(r.sq_off[4]) & 2, 2, "IORING_SQ_CQ_OVERFLOW");
    assert_eq!(r.reap().len(), 4);
    assert_eq!(r.dev.poll_events() & 1, 1, "overflowed completions still count as readable");
    assert_eq!(r.enter(0, 0, 0), 0, "enter flushes the overflow");
    assert_eq!(r.get(r.sq_off[4]) & 2, 0);
    assert_eq!(r.reap(), vec![(4, 0, 0), (5, 0, 0)]);
}

#[test]
fn enter_errors_and_waiting() {
    process(31_007);
    let r = ring(4);
    assert_eq!(r.enter(0, 0, 32), EINVAL, "unknown flag");
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [99, 0, 0, 0, 0, 0]), EBADF);
    file(50);
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [50, 0, 0, 0, 0, 0]), EOPNOTSUPP);
    let ev = eventfd(51, 0);
    let _ = ev;
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [51, 0, 0, 0, 0, 0]), EOPNOTSUPP);
    // GETEVENTS with min_complete 0 does not wait
    assert_eq!(r.enter(0, 0, 1), 0);
    r.push(Sqe::op(NOP, 0, 7));
    assert_eq!(r.enter(1, 1, 1), 1, "already there");
    r.reap();
    // Signals and timeouts end the wait
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(r.enter(0, 1, 1), EINTR);
    r.push(Sqe::op(NOP, 0, 8));
    assert_eq!(r.enter(1, 5, 1), 1, "submitted counts win over EINTR");
    fake::SIGNAL_PENDING.set(false);
    r.reap();
    let ts = timespec(0, 30_000_000);
    let arg = [0u64, 0, ptr(&*ts)];
    let start = fake::now_ns();
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [r.fd, 0, 1, 1 | 8, ptr(&arg[0]), 24]), ETIME);
    assert!(fake::now_ns() >= start + 30_000_000);
    r.push(Sqe::op(NOP, 0, 9));
    r.push(Sqe::op(NOP, 0, 10));
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [r.fd, 2, 5, 1 | 8, ptr(&arg[0]), 24]), 2, "timed out after submitting");
    r.reap();
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [r.fd, 0, 1, 1 | 8, ptr(&arg[0]), 16]), EINVAL, "argsz");
    let mut bad = [0u64; 3];
    fake::bad_ptr(mptr(&mut bad), 24);
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [r.fd, 0, 1, 1 | 8, mptr(&mut bad), 24]), EFAULT);
    let bad_ts = timespec(0, 2_000_000_000);
    let arg2 = [0u64, 0, ptr(&*bad_ts)];
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [r.fd, 0, 1, 1 | 8, ptr(&arg2[0]), 24]), EINVAL);
    // No timeout and nothing coming: would block
    assert!(blocks(|| r.enter(0, 1, 1)));
}

#[test]
fn opcodes_run_the_programs_system_calls() {
    process(31_008);
    let r = ring(64);
    file(5);
    echo_syscalls();
    let cur = u64::MAX;
    let table: Vec<(Sqe, u64, [u64; 6])> = vec![
        (Sqe { opcode: READ, fd: 5, addr: 0x1000, len: 10, off: cur, ..Default::default() }, 0, [5, 0x1000, 10, 0, 0, 0]),
        (Sqe { opcode: READ, fd: 5, addr: 0x1000, len: 10, off: 7, ..Default::default() }, 17, [5, 0x1000, 10, 7, 0, 0]),
        (Sqe { opcode: WRITE, fd: 5, addr: 0x2000, len: 3, off: cur, ..Default::default() }, 1, [5, 0x2000, 3, 0, 0, 0]),
        (Sqe { opcode: WRITE, fd: 5, addr: 0x2000, len: 3, off: 9, ..Default::default() }, 18, [5, 0x2000, 3, 9, 0, 0]),
        (Sqe { opcode: READV, fd: 5, addr: 0x3000, len: 2, off: cur, ..Default::default() }, 19, [5, 0x3000, 2, 0, 0, 0]),
        (Sqe { opcode: READV, fd: 5, addr: 0x3000, len: 2, off: 4, ..Default::default() }, 295, [5, 0x3000, 2, 4, 0, 0]),
        (Sqe { opcode: WRITEV, fd: 5, addr: 0x3000, len: 2, off: cur, ..Default::default() }, 20, [5, 0x3000, 2, 0, 0, 0]),
        (Sqe { opcode: WRITEV, fd: 5, addr: 0x3000, len: 2, off: 4, ..Default::default() }, 296, [5, 0x3000, 2, 4, 0, 0]),
        (Sqe { opcode: FSYNC, fd: 5, ..Default::default() }, 74, [5, 0, 0, 0, 0, 0]),
        (Sqe { opcode: FSYNC, fd: 5, op_flags: 1, ..Default::default() }, 75, [5, 0, 0, 0, 0, 0]),
        (Sqe { opcode: SYNC_FILE_RANGE, fd: 5, off: 1, len: 2, op_flags: 3, ..Default::default() }, 277, [5, 1, 2, 3, 0, 0]),
        (Sqe { opcode: SENDMSG, fd: 5, addr: 0x40, op_flags: 0x4000, ..Default::default() }, 46, [5, 0x40, 0x4000, 0, 0, 0]),
        (Sqe { opcode: RECVMSG, fd: 5, addr: 0x40, op_flags: 2, ..Default::default() }, 47, [5, 0x40, 2, 0, 0, 0]),
        (Sqe { opcode: SEND, fd: 5, addr: 0x50, len: 4, op_flags: 1, ..Default::default() }, 44, [5, 0x50, 4, 1, 0, 0]),
        (Sqe { opcode: RECV, fd: 5, addr: 0x50, len: 4, op_flags: 1, ..Default::default() }, 45, [5, 0x50, 4, 1, 0, 0]),
        (Sqe { opcode: ACCEPT, fd: 5, addr: 0x60, off: 0x68, op_flags: 0o4000, ..Default::default() }, 288, [5, 0x60, 0x68, 0o4000, 0, 0]),
        (Sqe { opcode: CONNECT, fd: 5, addr: 0x70, off: 16, ..Default::default() }, 42, [5, 0x70, 16, 0, 0, 0]),
        (Sqe { opcode: BIND, fd: 5, addr: 0x70, off: 16, ..Default::default() }, 49, [5, 0x70, 16, 0, 0, 0]),
        (Sqe { opcode: LISTEN, fd: 5, len: 9, ..Default::default() }, 50, [5, 9, 0, 0, 0, 0]),
        (Sqe { opcode: SHUTDOWN, fd: 5, len: 1, ..Default::default() }, 48, [5, 1, 0, 0, 0, 0]),
        (Sqe { opcode: SOCKET, fd: 2, off: 1, len: 6, ..Default::default() }, 41, [2, 1, 6, 0, 0, 0]),
        (Sqe { opcode: FALLOCATE, fd: 5, len: 1, off: 2, addr: 3, ..Default::default() }, 285, [5, 1, 2, 3, 0, 0]),
        (Sqe { opcode: FTRUNCATE, fd: 5, off: 100, ..Default::default() }, 77, [5, 100, 0, 0, 0, 0]),
        (Sqe { opcode: FADVISE, fd: 5, off: 1, len: 2, op_flags: 4, ..Default::default() }, 221, [5, 1, 2, 4, 0, 0]),
        (Sqe { opcode: MADVISE, addr: 0x9000, len: 4096, op_flags: 4, ..Default::default() }, 28, [0x9000, 4096, 4, 0, 0, 0]),
        (Sqe { opcode: OPENAT, fd: -100, addr: 0xa0, op_flags: 2, len: 0o644, ..Default::default() }, 257, [-100i64 as u64, 0xa0, 2, 0o644, 0, 0]),
        (Sqe { opcode: OPENAT2, fd: -100, addr: 0xa0, off: 0xb0, len: 24, ..Default::default() }, 437, [-100i64 as u64, 0xa0, 0xb0, 24, 0, 0]),
        (Sqe { opcode: CLOSE, fd: 9, ..Default::default() }, 3, [9, 0, 0, 0, 0, 0]),
        (Sqe { opcode: STATX, fd: -100, addr: 0xc0, op_flags: 0x100, len: 0x7ff, off: 0xd0, ..Default::default() }, 332, [-100i64 as u64, 0xc0, 0x100, 0x7ff, 0xd0, 0]),
        (Sqe { opcode: EPOLL_CTL, fd: 7, len: 1, off: 5, addr: 0xe0, ..Default::default() }, 233, [7, 1, 5, 0xe0, 0, 0]),
        (Sqe { opcode: RENAMEAT, fd: -100, addr: 0xa0, len: -100i32 as u32, off: 0xb0, op_flags: 1, ..Default::default() }, 316, [-100i64 as u64, 0xa0, -100i64 as u64, 0xb0, 1, 0]),
        (Sqe { opcode: UNLINKAT, fd: -100, addr: 0xa0, op_flags: 0x200, ..Default::default() }, 263, [-100i64 as u64, 0xa0, 0x200, 0, 0, 0]),
        (Sqe { opcode: MKDIRAT, fd: -100, addr: 0xa0, len: 0o755, ..Default::default() }, 258, [-100i64 as u64, 0xa0, 0o755, 0, 0, 0]),
        (Sqe { opcode: SYMLINKAT, fd: -100, addr: 0xa0, off: 0xb0, ..Default::default() }, 266, [0xa0, -100i64 as u64, 0xb0, 0, 0, 0]),
        (Sqe { opcode: LINKAT, fd: -100, addr: 0xa0, len: -100i32 as u32, off: 0xb0, op_flags: 0x400, ..Default::default() }, 265, [-100i64 as u64, 0xa0, -100i64 as u64, 0xb0, 0x400, 0]),
    ];
    for (i, (sqe, num, args)) in table.iter().enumerate() {
        fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
        let s = Sqe { user_data: i as u64, ..*sqe };
        assert_eq!(r.submit(&[s]), 1);
        assert_eq!(nested_calls(), vec![(*num, *args)], "opcode {}", sqe.opcode);
        let c = r.reap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, i as u64);
    }
    // Requests the implementation refuses
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    let refused = [
        Sqe { opcode: ACCEPT, fd: 5, ioprio: 1, ..Default::default() },
        Sqe { opcode: ACCEPT, fd: 5, file_index: 1, ..Default::default() },
        Sqe { opcode: OPENAT, fd: -100, file_index: 1, ..Default::default() },
        Sqe { opcode: OPENAT2, fd: -100, file_index: 1, ..Default::default() },
        Sqe { opcode: LINK_TIMEOUT, ..Default::default() },
        Sqe { opcode: 50, ..Default::default() },
        Sqe { opcode: NOP, flags: 0x80, ..Default::default() },
        Sqe { opcode: POLL_REMOVE, op_flags: 2, ..Default::default() },
    ];
    assert_eq!(r.submit(&refused), refused.len() as i64);
    assert!(r.reap().iter().all(|c| c.1 == EINVAL));
    assert!(nested_calls().is_empty());
}

#[test]
fn requests_on_missing_descriptors() {
    process(31_009);
    let r = ring(8);
    r.submit(&[Sqe::op(READ, 40, 1), Sqe::op(POLL_ADD, 40, 2), Sqe::op(READ, -1, 3)]);
    assert_eq!(r.reap(), vec![(1, EBADF, 0), (2, EBADF, 0), (3, EBADF, 0)]);
}

// ------------------------------------------------------------------ links

#[test]
fn linked_requests() {
    process(31_010);
    let r = ring(8);
    file(5);
    echo_syscalls();
    // An error breaks an IO_LINK chain
    let chain = [
        Sqe { flags: IO_LINK, ..Sqe::op(NOP, 0, 1) },
        Sqe { flags: IO_LINK, ..Sqe::op(READ, 40, 2) },
        Sqe::op(NOP, 0, 3),
    ];
    assert_eq!(r.submit(&chain), 3);
    assert_eq!(r.reap(), vec![(1, 0, 0), (2, EBADF, 0), (3, ECANCELED, 0)]);
    // ... but not a HARDLINK one
    let chain = [Sqe { flags: IO_HARDLINK, ..Sqe::op(READ, 40, 4) }, Sqe::op(NOP, 0, 5)];
    r.submit(&chain);
    assert_eq!(r.reap(), vec![(4, EBADF, 0), (5, 0, 0)]);
    // A short read breaks a chain
    fake::on_nested(|_, _| 3);
    let chain = [Sqe { flags: IO_LINK, len: 10, off: u64::MAX, ..Sqe::op(READ, 5, 6) }, Sqe::op(NOP, 0, 7)];
    r.submit(&chain);
    assert_eq!(r.reap(), vec![(6, 3, 0), (7, ECANCELED, 0)]);
    // A chain cut off by the submit count still runs (its last link fails on its own)
    r.push(Sqe { flags: IO_LINK, ..Sqe::op(NOP, 0, 8) });
    r.push(Sqe::op(NOP, 0, 9));
    assert_eq!(r.enter(1, 0, 0), 1);
    assert_eq!(r.reap(), vec![(8, 0, 0)]);
    assert_eq!(r.enter(1, 0, 0), 1);
    assert_eq!(r.reap(), vec![(9, 0, 0)]);
}

#[test]
fn link_timeouts() {
    process(31_011);
    let r = ring(8);
    let ts = timespec(1, 0);
    // The guarded request finishes at once: its timeout is cancelled
    let chain = [Sqe { flags: IO_LINK, ..Sqe::op(NOP, 0, 1) }, Sqe { addr: ptr(&*ts), len: 1, ..Sqe::op(LINK_TIMEOUT, 0, 2) }];
    r.submit(&chain);
    assert_eq!(r.reap(), vec![(1, 0, 0), (2, ECANCELED, 0)]);
    // A bad link timeout fails the request and the rest of the chain
    let chain = [
        Sqe { flags: IO_LINK, ..Sqe::op(NOP, 0, 3) },
        Sqe { flags: IO_LINK, addr: ptr(&*ts), len: 1, op_flags: 0x40, ..Sqe::op(LINK_TIMEOUT, 0, 4) },
        Sqe::op(NOP, 0, 5),
    ];
    r.submit(&chain);
    assert_eq!(r.reap(), vec![(3, ECANCELED, 0), (4, EINVAL, 0), (5, ECANCELED, 0)]);
    let chain = [Sqe { flags: IO_LINK, ..Sqe::op(NOP, 0, 6) }, Sqe { addr: 0, len: 1, ..Sqe::op(LINK_TIMEOUT, 0, 7) }];
    r.submit(&chain);
    assert_eq!(r.reap(), vec![(6, ECANCELED, 0), (7, EFAULT, 0)], "no timespec");
}

#[test]
fn a_waiting_request_with_a_link_timeout() {
    process(31_012);
    let r = ring(8);
    eventfd(5, 0);
    let ts = timespec(0, 50_000_000);
    let chain = [
        Sqe { flags: IO_LINK, len: 8, off: u64::MAX, ..Sqe::op(READ, 5, 1) },
        Sqe { flags: IO_LINK, addr: ptr(&*ts), len: 1, ..Sqe::op(LINK_TIMEOUT, 0, 2) },
        Sqe::op(NOP, 0, 3),
    ];
    r.submit(&chain);
    assert!(r.reap().is_empty(), "the read waits");
    assert_eq!(WORKERS.with_borrow(|w| w.len()), 1, "for the worker");
    let rr = r.clone();
    run_worker(move |n| match n {
        1 => {
            assert!(rr.reap().is_empty(), "not yet");
            assert_eq!(fake::LAST_DEADLINE.get().map(|d| d / fake::TICK_NS), Some(fake::ticks() + 5), "it sleeps until the timeout");
            true
        }
        _ => {
            assert_eq!(rr.reap(), vec![(1, ECANCELED, 0), (2, ETIME, 0), (3, ECANCELED, 0)]);
            false
        }
    });
}

#[test]
fn a_waiting_request_finishes_before_its_link_timeout() {
    process(31_013);
    let r = ring(8);
    let e = eventfd(5, 0);
    echo_syscalls();
    let ts = timespec(10, 0);
    let chain = [
        Sqe { flags: IO_LINK, len: 8, off: u64::MAX, ..Sqe::op(READ, 5, 1) },
        Sqe { flags: IO_LINK, addr: ptr(&*ts), len: 1, ..Sqe::op(LINK_TIMEOUT, 0, 2) },
        Sqe::op(NOP, 0, 3),
    ];
    r.submit(&chain);
    e.lock().counter = 1;
    let rr = r.clone();
    run_worker(move |_| {
        assert_eq!(rr.reap(), vec![(1, 8, 0), (2, ECANCELED, 0), (3, 0, 0)]);
        false
    });
}

// ------------------------------------------------------------------ waiting requests and the worker

#[test]
fn waiting_reads_finish_in_the_worker() {
    process(31_014);
    let r = ring(8);
    let e = eventfd(5, 0);
    echo_syscalls();
    // RWF_NOWAIT: no waiting
    r.submit(&[Sqe { len: 8, off: u64::MAX, op_flags: 8, ..Sqe::op(READ, 5, 1) }]);
    assert_eq!(r.reap(), vec![(1, EAGAIN, 0)]);
    // A read and a chained write wait for the eventfd
    let chain = [Sqe { flags: IO_LINK, len: 8, off: u64::MAX, ..Sqe::op(READ, 5, 2) }, Sqe { len: 8, off: u64::MAX, ..Sqe::op(WRITE, 5, 3) }];
    r.submit(&chain);
    r.submit(&[Sqe { len: 8, off: u64::MAX, ..Sqe::op(READV, 5, 4) }]);
    assert!(r.reap().is_empty());
    assert_eq!(WORKERS.with_borrow(|w| w.len()), 1, "one worker for the ring");
    let rr = r.clone();
    run_worker(move |n| match n {
        1 => {
            // Nothing ready: it keeps them and sleeps on the eventfd
            assert!(rr.reap().is_empty());
            assert_eq!(fake::wait::LAST_QUEUES.get(), 3, "its kick queue, and the eventfd's for each request");
            e.lock().counter = 1;
            true
        }
        _ => {
            assert_eq!(rr.reap(), vec![(2, 8, 0), (3, 8, 0), (4, 8, 0)], "the chain went on");
            false
        }
    });
}

#[test]
fn the_worker_ends_with_its_ring() {
    process(31_033);
    let r = ring(8);
    eventfd(5, 0);
    r.submit(&[Sqe { len: 8, ..Sqe::op(READ, 5, 1) }]);
    fake::fd::FDS.with_borrow_mut(|f| f.close(r.fd as usize).unwrap());
    let mut _last = Some(r);
    run_worker(move |_| {
        _last = None; // the program's last reference goes
        true
    });
}

#[test]
fn no_worker_no_progress_and_the_worker_leaves_with_its_process() {
    process(31_015);
    WORKER_ID.set(None);
    let r = ring(8);
    eventfd(5, 0);
    r.submit(&[Sqe { len: 8, ..Sqe::op(READ, 5, 1) }]);
    assert!(WORKERS.with_borrow(|w| w.is_empty()), "none could start");
    // A second waiting request tries again
    WORKER_ID.set(Some(31_015 + 100_000));
    r.submit(&[Sqe { len: 8, ..Sqe::op(READ, 5, 2) }]);
    assert_eq!(WORKERS.with_borrow(|w| w.len()), 1);
    // The process became a zombie: the worker leaves without sleeping
    PROCS.lock().get_mut(&31_015).unwrap().zombie = true;
    run_worker(|_| panic!("the worker slept"));
    // A worker nobody announced returns at once
    run_worker(|_| panic!("the worker slept"));
    // The ring's worker flag was cleared: a new request starts another
    PROCS.lock().get_mut(&31_015).unwrap().zombie = false;
    r.submit(&[Sqe { len: 8, ..Sqe::op(READ, 5, 3) }]);
    assert_eq!(WORKERS.with_borrow(|w| w.len()), 2);
}

#[test]
fn polls() {
    process(31_016);
    let r = ring(8);
    let e = eventfd(5, 0);
    // Ready now: the events that hit
    r.submit(&[Sqe { op_flags: 0x4 | 0x1, ..Sqe::op(POLL_ADD, 5, 1) }]);
    assert_eq!(r.reap(), vec![(1, 4, 0)], "writable, not readable");
    // Waits for POLLIN
    r.submit(&[Sqe { op_flags: 0x1, ..Sqe::op(POLL_ADD, 5, 2) }]);
    assert!(r.reap().is_empty());
    let rr = r.clone();
    run_worker(move |n| {
        match n {
            1 => e.lock().counter = 2,
            2 => {
                assert_eq!(rr.reap(), vec![(2, 1, 0)]);
                // Multishot: completes with MORE and stays armed
                rr.submit(&[Sqe { op_flags: 0x1, len: 1, ..Sqe::op(POLL_ADD, 5, 3) }]);
                assert_eq!(rr.reap(), vec![(3, 1, CQE_F_MORE)]);
            }
            3 => {
                assert_eq!(rr.reap(), vec![(3, 1, CQE_F_MORE)], "fires again");
                e.lock().counter = 0;
            }
            4 => {
                assert!(rr.reap().is_empty(), "not ready: no completion");
                // POLL_REMOVE cancels it
                rr.submit(&[Sqe { addr: 3, ..Sqe::op(POLL_REMOVE, 0, 4) }]);
                assert_eq!(rr.reap(), vec![(3, ECANCELED, 0), (4, 0, 0)]);
                rr.submit(&[Sqe { addr: 3, ..Sqe::op(POLL_REMOVE, 0, 5) }]);
                assert_eq!(rr.reap(), vec![(5, ENOENT, 0)]);
                // A poll waiting on a descriptor that gets closed
                rr.submit(&[Sqe { op_flags: 0x1, len: 1, ..Sqe::op(POLL_ADD, 5, 6) }]);
                assert!(rr.reap().is_empty());
                fake::fd::FDS.with_borrow_mut(|f| f.close(5).unwrap());
            }
            _ => {
                assert_eq!(rr.reap(), vec![(6, EBADF, 0)], "gone: ready, then EBADF");
                return false;
            }
        }
        true
    });
}

#[test]
fn timeouts() {
    process(31_017);
    let r = ring(8);
    let ts = timespec(0, 30_000_000);
    // By time
    r.submit(&[Sqe { addr: ptr(&*ts), len: 1, ..Sqe::op(TIMEOUT, 0, 1) }]);
    let rr = r.clone();
    let lp = ptr(Box::leak(timespec(100, 0)));
    let pp = ptr(Box::leak(timespec(0, 1)));
    run_worker(move |n| {
        match n {
            1 => assert!(rr.reap().is_empty()),
            2 => {
                assert_eq!(rr.reap(), vec![(1, ETIME, 0)]);
                // By count: two completions
                rr.submit(&[Sqe { addr: lp, len: 1, off: 2, ..Sqe::op(TIMEOUT, 0, 2) }]);
                rr.submit(&[Sqe::op(NOP, 0, 3), Sqe::op(NOP, 0, 4)]);
            }
            3 => {
                assert_eq!(rr.reap(), vec![(3, 0, 0), (4, 0, 0), (2, 0, 0)]);
                // Absolute: on the boot clock (in the past) and on the wall clock (1 s on)
                rr.submit(&[Sqe { addr: pp, len: 1, op_flags: 1, ..Sqe::op(TIMEOUT, 0, 5) }]);
                let (s, ns) = fake::rtc_now();
                let wall = Box::leak(timespec(s as i64 + 1, ns as i64));
                rr.submit(&[Sqe { addr: ptr(&*wall), len: 1, op_flags: 1 | 8, ..Sqe::op(TIMEOUT, 0, 6) }]);
            }
            _ => {
                assert_eq!(rr.reap(), vec![(5, ETIME, 0), (6, ETIME, 0)]);
                return false;
            }
        }
        true
    });
    // Invalid ones
    r.submit(&[
        Sqe { addr: ptr(&*ts), len: 2, ..Sqe::op(TIMEOUT, 0, 7) },
        Sqe { addr: ptr(&*ts), len: 1, op_flags: 0x10, ..Sqe::op(TIMEOUT, 0, 8) },
        Sqe { addr: 0, len: 1, ..Sqe::op(TIMEOUT, 0, 9) },
    ]);
    assert_eq!(r.reap(), vec![(7, EINVAL, 0), (8, EINVAL, 0), (9, EFAULT, 0)]);
}

#[test]
fn timeout_remove_and_update() {
    process(31_018);
    let r = ring(8);
    let long = timespec(100, 0);
    r.submit(&[Sqe { addr: ptr(&*long), len: 1, ..Sqe::op(TIMEOUT, 0, 1) }]);
    // Update to 20 ms
    let short = timespec(0, 20_000_000);
    r.submit(&[Sqe { addr: 1, off: ptr(&*short), op_flags: 2, ..Sqe::op(TIMEOUT_REMOVE, 0, 2) }]);
    assert_eq!(r.reap(), vec![(2, 0, 0)]);
    let rr = r.clone();
    run_worker(move |n| {
        if n == 1 {
            assert_eq!(fake::LAST_DEADLINE.get().map(|d| d / fake::TICK_NS), Some(fake::ticks() + 2), "the new time");
            return true;
        }
        assert_eq!(rr.reap(), vec![(1, ETIME, 0)]);
        false
    });
    r.submit(&[Sqe { addr: 1, off: ptr(&*short), op_flags: 2, ..Sqe::op(TIMEOUT_REMOVE, 0, 3) }]);
    assert_eq!(r.reap(), vec![(3, ENOENT, 0)], "already gone");
    r.submit(&[Sqe { addr: 1, off: 0, op_flags: 2, ..Sqe::op(TIMEOUT_REMOVE, 0, 4) }]);
    assert_eq!(r.reap(), vec![(4, EFAULT, 0)]);
    // Remove
    r.submit(&[Sqe { addr: ptr(&*long), len: 1, ..Sqe::op(TIMEOUT, 0, 5) }]);
    r.submit(&[Sqe { addr: 5, ..Sqe::op(TIMEOUT_REMOVE, 0, 6) }]);
    assert_eq!(r.reap(), vec![(5, ECANCELED, 0), (6, 0, 0)]);
    r.submit(&[Sqe { addr: 5, ..Sqe::op(TIMEOUT_REMOVE, 0, 7) }]);
    assert_eq!(r.reap(), vec![(7, ENOENT, 0)]);
}

#[test]
fn timeouts_in_chains() {
    process(31_019);
    let r = ring(8);
    let tp = ptr(Box::leak(timespec(0, 10_000_000)));
    let lp = ptr(Box::leak(timespec(100, 0)));
    // ETIME breaks an IO_LINK chain
    r.submit(&[Sqe { flags: IO_LINK, addr: tp, len: 1, ..Sqe::op(TIMEOUT, 0, 1) }, Sqe::op(NOP, 0, 2)]);
    let rr = r.clone();
    run_worker(move |n| {
        match n {
            1 => {}
            2 => {
                assert_eq!(rr.reap(), vec![(1, ETIME, 0), (2, ECANCELED, 0)]);
                // ... not a HARDLINK one
                rr.submit(&[Sqe { flags: IO_HARDLINK, addr: tp, len: 1, ..Sqe::op(TIMEOUT, 0, 3) }, Sqe::op(NOP, 0, 4)]);
            }
            3 => {
                assert_eq!(rr.reap(), vec![(3, ETIME, 0), (4, 0, 0)]);
                // A count reached: the chain goes on
                rr.submit(&[Sqe { flags: IO_LINK, addr: lp, len: 1, off: 1, ..Sqe::op(TIMEOUT, 0, 5) }, Sqe::op(NOP, 0, 6)]);
                rr.submit(&[Sqe::op(NOP, 0, 7)]);
            }
            _ => {
                assert_eq!(rr.reap(), vec![(7, 0, 0), (5, 0, 0), (6, 0, 0)]);
                return false;
            }
        }
        true
    });
}
#[test]
fn cancellation() {
    process(31_020);
    let r = ring(16);
    eventfd(5, 0);
    eventfd(6, 0);
    let long = timespec(100, 0);
    let read = |fd: i32, ud: u64| Sqe { len: 8, ..Sqe::op(READ, fd, ud) };
    r.submit(&[read(5, 1), read(5, 2), read(6, 3)]);
    // By user_data
    r.submit(&[Sqe { addr: 2, ..Sqe::op(ASYNC_CANCEL, 0, 10) }]);
    assert_eq!(r.reap(), vec![(2, ECANCELED, 0), (10, 0, 0)]);
    r.submit(&[Sqe { addr: 2, ..Sqe::op(ASYNC_CANCEL, 0, 11) }]);
    assert_eq!(r.reap(), vec![(11, ENOENT, 0)], "already gone");
    // By descriptor, all of them
    r.submit(&[read(5, 4)]);
    r.submit(&[Sqe { fd: 5, op_flags: 2 | 1, ..Sqe::op(ASYNC_CANCEL, 0, 12) }]);
    assert_eq!(r.reap(), vec![(1, ECANCELED, 0), (4, ECANCELED, 0), (12, 2, 0)]);
    // By descriptor, the first only
    r.submit(&[read(6, 5)]);
    r.submit(&[Sqe { fd: 6, op_flags: 2, ..Sqe::op(ASYNC_CANCEL, 0, 13) }]);
    assert_eq!(r.reap(), vec![(3, ECANCELED, 0), (13, 0, 0)]);
    // ANY: everything, with its link timeout and its chain
    let chain = [
        Sqe { flags: IO_LINK, ..read(6, 6) },
        Sqe { flags: IO_LINK, addr: ptr(&*long), len: 1, ..Sqe::op(LINK_TIMEOUT, 0, 7) },
        Sqe::op(NOP, 0, 8),
    ];
    r.submit(&chain);
    r.submit(&[Sqe { op_flags: 4, ..Sqe::op(ASYNC_CANCEL, 0, 14) }]);
    assert_eq!(r.reap(), vec![(5, ECANCELED, 0), (6, ECANCELED, 0), (7, ECANCELED, 0), (8, ECANCELED, 0), (14, 2, 0)]);
    r.submit(&[Sqe { op_flags: 1, ..Sqe::op(ASYNC_CANCEL, 0, 15) }]);
    assert_eq!(r.reap(), vec![(15, ENOENT, 0)], "nothing left");
}

#[test]
fn skip_success_completions() {
    process(31_021);
    let r = ring(8);
    r.submit(&[Sqe { flags: CQE_SKIP, ..Sqe::op(NOP, 0, 1) }, Sqe { flags: CQE_SKIP, ..Sqe::op(READ, 40, 2) }]);
    assert_eq!(r.reap(), vec![(2, EBADF, 0)], "failures still complete");
    // A skipped completion still counts for timeouts
    let long = timespec(100, 0);
    r.submit(&[Sqe { addr: ptr(&*long), len: 1, off: 1, ..Sqe::op(TIMEOUT, 0, 3) }]);
    r.submit(&[Sqe { flags: CQE_SKIP, ..Sqe::op(NOP, 0, 4) }]);
    let rr = r.clone();
    run_worker(move |_| {
        assert_eq!(rr.reap(), vec![(3, 0, 0)]);
        false
    });
}

// ------------------------------------------------------------------ registered resources

#[test]
fn registered_buffers_and_fixed_io() {
    process(31_022);
    let r = ring(8);
    file(5);
    echo_syscalls();
    let buf = vec![0u8; 4096];
    let base = buf.as_ptr() as u64;
    let iov = [(base, 4096u64)];
    assert_eq!(r.register(1, 0, 0), ENXIO, "nothing to unregister");
    assert_eq!(r.register(0, ptr(&iov), 0), EINVAL);
    assert_eq!(r.register(0, ptr(&iov), 16385), EINVAL);
    let mut bad = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad), 16);
    assert_eq!(r.register(0, mptr(&mut bad), 1), EFAULT);
    assert_eq!(r.register(0, ptr(&iov), 1), 0);
    assert_eq!(r.register(0, ptr(&iov), 1), EBUSY);
    r.submit(&[
        Sqe { addr: base + 100, len: 50, off: u64::MAX, buf_index: 0, ..Sqe::op(READ_FIXED, 5, 1) },
        Sqe { addr: base, len: 10, off: 8, ..Sqe::op(READ_FIXED, 5, 2) },
        Sqe { addr: base, len: 10, off: u64::MAX, ..Sqe::op(WRITE_FIXED, 5, 3) },
        Sqe { addr: base, len: 10, off: 4, ..Sqe::op(WRITE_FIXED, 5, 4) },
        Sqe { addr: base + 4090, len: 10, off: 0, ..Sqe::op(READ_FIXED, 5, 5) },
        Sqe { addr: base, len: 10, buf_index: 1, ..Sqe::op(WRITE_FIXED, 5, 6) },
    ]);
    assert_eq!(r.reap(), vec![(1, 50, 0), (2, 10, 0), (3, 10, 0), (4, 10, 0), (5, EFAULT, 0), (6, EFAULT, 0)]);
    let nums: Vec<u64> = nested_calls().iter().map(|c| c.0).collect();
    assert_eq!(nums, vec![0, 17, 1, 18]);
    assert_eq!(r.register(1, 0, 0), 0);
}

#[test]
fn registered_files() {
    process(31_023);
    let r = ring(8);
    file(5);
    file(6);
    // dup (F_DUPFD_CLOEXEC) hands out 100, 101, ...; close succeeds
    let next = std::rc::Rc::new(std::cell::Cell::new(100i64));
    let n2 = next.clone();
    fake::on_nested(move |num, a| match num {
        72 => {
            assert_eq!(a[1], 1030);
            let d = n2.get();
            n2.set(d + 1);
            file(d as usize);
            d
        }
        0 => a[2] as i64,
        _ => 0,
    });
    assert_eq!(r.register(3, 0, 0), ENXIO);
    assert_eq!(r.register(2, 0, 0), EINVAL, "count 0");
    assert_eq!(r.register(2, 0, 70_000), EINVAL);
    let fds = [5i32, -1, 6];
    assert_eq!(r.register(2, ptr(&fds), 3), 0);
    assert_eq!(r.register(2, ptr(&fds), 3), EBUSY);
    // Fixed-file reads go to the private duplicate
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    r.submit(&[
        Sqe { flags: FIXED_FILE, len: 4, off: u64::MAX, ..Sqe::op(READ, 0, 1) },
        Sqe { flags: FIXED_FILE, len: 4, off: u64::MAX, ..Sqe::op(READ, 1, 2) },
        Sqe { flags: FIXED_FILE, len: 4, off: u64::MAX, ..Sqe::op(READ, 9, 3) },
    ]);
    assert_eq!(r.reap(), vec![(1, 4, 0), (2, EBADF, 0), (3, EBADF, 0)]);
    assert_eq!(nested_calls()[0].1[0], 100);
    // FILES_UPDATE (opcode) and REGISTER_FILES_UPDATE: slot 1 gets fd 5, slot 0 is emptied
    let upd = [5i32];
    r.submit(&[Sqe { off: 1, addr: ptr(&upd), len: 1, ..Sqe::op(FILES_UPDATE, 0, 4) }]);
    assert_eq!(r.reap(), vec![(4, 1, 0)]);
    let empty = [-1i32];
    let up = { let mut b = [0u8; 16]; b[0..4].copy_from_slice(&0u32.to_le_bytes()); b[8..16].copy_from_slice(&ptr(&empty).to_le_bytes()); b };
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    assert_eq!(r.register(6, ptr(&up), 1), 1);
    assert_eq!(nested_calls(), vec![(3, [100, 0, 0, 0, 0, 0])], "the old duplicate is closed");
    // UPDATE2 past the end: EINVAL (the new duplicate is closed again)
    let up2 = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(&3u32.to_le_bytes()); b[8..16].copy_from_slice(&ptr(&upd).to_le_bytes()); b[24..28].copy_from_slice(&1u32.to_le_bytes()); b };
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    assert_eq!(r.register(14, ptr(&up2), 0), EINVAL);
    assert_eq!(nested_calls().iter().filter(|c| c.0 == 3).count(), 1);
    let mut bad = [0u8; 32];
    fake::bad_ptr(mptr(&mut bad), 32);
    assert_eq!(r.register(6, mptr(&mut bad), 1), EFAULT);
    r.submit(&[Sqe { off: 0, addr: mptr(&mut bad), len: 1, ..Sqe::op(FILES_UPDATE, 0, 5) }]);
    assert_eq!(r.reap(), vec![(5, EFAULT, 0)]);
    // CLOSE of a registered slot (file_index is slot + 1)
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    r.submit(&[Sqe { file_index: 2, ..Sqe::op(CLOSE, 0, 6) }, Sqe { file_index: 2, ..Sqe::op(CLOSE, 0, 7) }, Sqe { file_index: 9, ..Sqe::op(CLOSE, 0, 8) }]);
    assert_eq!(r.reap(), vec![(6, 0, 0), (7, EBADF, 0), (8, EBADF, 0)]);
    assert_eq!(nested_calls().len(), 1);
    // Unregister closes what is left
    fake::NESTED_CALLS.with_borrow_mut(|v| v.clear());
    assert_eq!(r.register(3, 0, 0), 0);
    assert_eq!(nested_calls(), vec![(3, [101, 0, 0, 0, 0, 0])]);
}

#[test]
fn registered_files_v2_sparse_and_dup_failures() {
    process(31_024);
    let r = ring(8);
    // FILES2: struct io_uring_rsrc_register { nr, flags, resv2, data, tags }, sparse
    let reg = { let mut b = [0u8; 32]; b[0..4].copy_from_slice(&4u32.to_le_bytes()); b };
    assert_eq!(r.register(13, ptr(&reg), 0), 0);
    let mut bad = [0u8; 32];
    fake::bad_ptr(mptr(&mut bad), 32);
    assert_eq!(r.register(13, mptr(&mut bad), 0), EFAULT);
    // A duplicate that fails: its error (or the count done so far)
    fake::on_nested(|num, _| if num == 72 { -24 } else { 0 });
    let fds = [5i32, 6];
    r.submit(&[Sqe { off: 0, addr: ptr(&fds), len: 2, ..Sqe::op(FILES_UPDATE, 0, 1) }]);
    assert_eq!(r.reap(), vec![(1, -24, 0)]);
    let mut first = true;
    fake::on_nested(move |num, _| {
        if num == 72 {
            if first {
                first = false;
                return 50;
            }
            return -24;
        }
        0
    });
    r.submit(&[Sqe { off: 0, addr: ptr(&fds), len: 2, ..Sqe::op(FILES_UPDATE, 0, 2) }]);
    assert_eq!(r.reap(), vec![(2, 1, 0)], "one updated before the failure");
    // Past the end after some: the count
    fake::on_nested(|num, _| if num == 72 { 60 } else { 0 });
    r.submit(&[Sqe { off: 3, addr: ptr(&fds), len: 2, ..Sqe::op(FILES_UPDATE, 0, 3) }]);
    assert_eq!(r.reap(), vec![(3, 1, 0)]);
    // Registering with a failing duplicate fails
    let r2 = ring(8);
    fake::on_nested(|num, _| if num == 72 { -9 } else { 0 });
    assert_eq!(r2.register(2, ptr(&fds), 2), -9);
}

#[test]
fn provided_buffers() {
    process(31_025);
    let r = ring(8);
    file(5);
    let mut bufs = vec![0u8; 400];
    let base = bufs.as_mut_ptr() as u64;
    // Three 100-byte buffers in group 7, IDs 10..12
    r.submit(&[Sqe { fd: 3, addr: base, len: 100, off: 10, buf_index: 7, ..Sqe::op(PROVIDE_BUFFERS, 3, 1) }]);
    assert_eq!(r.reap(), vec![(1, 0, 0)]);
    r.submit(&[Sqe { fd: 0, len: 100, ..Sqe::op(PROVIDE_BUFFERS, 0, 2) }, Sqe { fd: 1, len: 0, ..Sqe::op(PROVIDE_BUFFERS, 1, 3) }]);
    assert_eq!(r.reap(), vec![(2, EINVAL, 0), (3, EINVAL, 0)]);
    fake::on_nested(|num, a| if num == 0 || num == 45 { a[2] as i64 / 2 } else { 0 });
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 7, off: u64::MAX, ..Sqe::op(READ, 5, 4) }]);
    assert_eq!(r.reap(), vec![(4, 50, CQE_F_BUFFER | 10 << 16)]);
    assert_eq!(nested_calls().last().unwrap().1[1..3], [base, 100], "into buffer 10, its whole length");
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 7, len: 30, ..Sqe::op(RECV, 5, 5) }]);
    assert_eq!(r.reap(), vec![(5, 15, CQE_F_BUFFER | 11 << 16)], "at most len bytes");
    // Nothing read: the buffer goes back
    fake::on_nested(|_, _| 0);
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 7, off: u64::MAX, ..Sqe::op(READ, 5, 6) }]);
    assert_eq!(r.reap(), vec![(6, 0, 0)]);
    // Only reads and receives select buffers
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 7, ..Sqe::op(WRITE, 5, 7) }]);
    assert_eq!(r.reap(), vec![(7, EINVAL, 0)]);
    // REMOVE_BUFFERS
    r.submit(&[Sqe { fd: 5, buf_index: 7, ..Sqe::op(REMOVE_BUFFERS, 5, 8) }]);
    assert_eq!(r.reap(), vec![(8, 1, 0)], "one was left (12 went back)");
    r.submit(&[Sqe { fd: 1, buf_index: 7, ..Sqe::op(REMOVE_BUFFERS, 1, 9) }, Sqe { fd: 1, buf_index: 99, ..Sqe::op(REMOVE_BUFFERS, 1, 10) }]);
    assert_eq!(r.reap(), vec![(9, ENOENT, 0), (10, ENOENT, 0)]);
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 7, ..Sqe::op(READ, 5, 11) }]);
    assert_eq!(r.reap(), vec![(11, ENOBUFS, 0)]);
}

/// A page-aligned buffer ring: `entries` 16-byte entries (addr, len, bid; the tail in the
/// first entry's last two bytes).
#[repr(C, align(4096))]
struct BufRingMem([u8; 4096]);

#[test]
fn buffer_rings() {
    process(31_026);
    let r = ring(8);
    file(5);
    let mut mem = Box::new(BufRingMem([0u8; 4096]));
    let addr = mem.0.as_mut_ptr() as u64;
    let data = vec![0u8; 256];
    let entry = |m: &mut BufRingMem, i: usize, a: u64, len: u32, bid: u16| {
        m.0[i * 16..i * 16 + 8].copy_from_slice(&a.to_le_bytes());
        m.0[i * 16 + 8..i * 16 + 12].copy_from_slice(&len.to_le_bytes());
        m.0[i * 16 + 12..i * 16 + 14].copy_from_slice(&bid.to_le_bytes());
    };
    let reg = |a: u64, entries: u32, bgid: u16| {
        let mut b = [0u8; 40];
        b[0..8].copy_from_slice(&a.to_le_bytes());
        b[8..12].copy_from_slice(&entries.to_le_bytes());
        b[12..14].copy_from_slice(&bgid.to_le_bytes());
        b
    };
    assert_eq!(r.register(22, ptr(&reg(addr, 3, 1)), 1), EINVAL, "not a power of two");
    assert_eq!(r.register(22, ptr(&reg(addr + 8, 4, 1)), 1), EINVAL, "not page-aligned");
    assert_eq!(r.register(22, ptr(&reg(0, 4, 1)), 1), EINVAL);
    assert_eq!(r.register(22, ptr(&reg(addr, 65536, 1)), 1), EINVAL);
    assert_eq!(r.register(22, ptr(&reg(addr, 4, 1)), 1), 0);
    assert_eq!(r.register(22, ptr(&reg(addr, 4, 1)), 1), EEXIST);
    let mut bad = [0u8; 40];
    fake::bad_ptr(mptr(&mut bad), 40);
    assert_eq!(r.register(22, mptr(&mut bad), 1), EFAULT);
    // Empty ring: no buffer
    fake::on_nested(|num, a| if num == 0 { a[2] as i64 } else { 0 });
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 1, off: u64::MAX, ..Sqe::op(READ, 5, 1) }]);
    assert_eq!(r.reap(), vec![(1, ENOBUFS, 0)]);
    // Two entries, the tail at 2
    entry(&mut mem, 0, data.as_ptr() as u64, 64, 5);
    entry(&mut mem, 1, data.as_ptr() as u64 + 64, 32, 6);
    mem.0[14..16].copy_from_slice(&2u16.to_le_bytes());
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 1, off: u64::MAX, ..Sqe::op(READ, 5, 2) }]);
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 1, off: u64::MAX, ..Sqe::op(READ, 5, 3) }]);
    r.submit(&[Sqe { flags: BUFFER_SELECT, buf_index: 1, off: u64::MAX, ..Sqe::op(READ, 5, 4) }]);
    assert_eq!(r.reap(), vec![(2, 64, CQE_F_BUFFER | 5 << 16), (3, 32, CQE_F_BUFFER | 6 << 16), (4, ENOBUFS, 0)]);
    // A group with provided buffers cannot also have a ring
    r.submit(&[Sqe { fd: 1, addr: data.as_ptr() as u64, len: 8, buf_index: 2, ..Sqe::op(PROVIDE_BUFFERS, 1, 5) }]);
    r.reap();
    assert_eq!(r.register(22, ptr(&reg(addr, 4, 2)), 1), EEXIST);
    assert_eq!(r.register(23, ptr(&reg(0, 0, 1)), 1), 0);
    assert_eq!(r.register(23, ptr(&reg(0, 0, 1)), 1), EINVAL, "gone");
}

#[test]
fn eventfd_notification() {
    process(31_027);
    let r = ring(8);
    let e = eventfd(5, 0);
    let efd = 5i32;
    assert_eq!(r.register(5, 0, 0), ENXIO);
    let nine = 9i32;
    assert_eq!(r.register(4, ptr(&nine), 1), EBADF);
    let mut bad = 0i32;
    fake::bad_ptr(mptr(&mut bad), 4);
    assert_eq!(r.register(4, mptr(&mut bad), 1), EFAULT);
    assert_eq!(r.register(4, ptr(&efd), 1), 0);
    assert_eq!(r.register(7, ptr(&efd), 1), EBUSY);
    r.submit(&[Sqe::op(NOP, 0, 1), Sqe::op(NOP, 0, 2)]);
    assert_eq!(e.lock().counter, 2, "one count per completion");
    // IORING_CQ_EVENTFD_DISABLED
    r.set(r.cq_off[6], 1);
    r.submit(&[Sqe::op(NOP, 0, 3)]);
    assert_eq!(e.lock().counter, 2);
    r.set(r.cq_off[6], 0);
    assert_eq!(r.register(5, 0, 0), 0);
    r.submit(&[Sqe::op(NOP, 0, 4)]);
    assert_eq!(e.lock().counter, 2, "unregistered");
}

/// A linux-server object (an eventfd of the server, or another kind).
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

#[test]
fn server_eventfd_notification() {
    process(31_028);
    let r = ring(8);
    let kind = hydra_hosttests_t27::ipc::protocol::LX_OBJ_KIND_EVENTFD;
    fake::fd::install(5, FileDescriptor::Device(Arc::new(ServerDev(ServerObject { kind, tag: 1 }))));
    fake::fd::install(6, FileDescriptor::Device(Arc::new(ServerDev(ServerObject { kind: kind + 1, tag: 1 }))));
    let six = 6i32;
    assert_eq!(r.register(4, ptr(&six), 1), EBADF, "another kind of object");
    let five = 5i32;
    assert_eq!(r.register(4, ptr(&five), 1), 0);
    assert_eq!(r.register(4, ptr(&five), 1), EBUSY);
    r.submit(&[Sqe::op(NOP, 0, 1)]);
    assert_eq!(fake::LX_WRITES.with_borrow(|v| v.clone()), vec![1], "written later by a kernel task");
    r.set(r.cq_off[6], 1);
    r.submit(&[Sqe::op(NOP, 0, 2)]);
    assert_eq!(fake::LX_WRITES.with_borrow(|v| v.len()), 1);
    assert_eq!(r.register(5, 0, 0), 0);
}

#[test]
fn msg_ring_posts_to_another_ring() {
    process(31_029);
    let a = ring(8);
    let b = ring(8);
    a.submit(&[Sqe { off: 0xfeed, len: 42, ..Sqe::op(MSG_RING, b.fd as i32, 1) }]);
    assert_eq!(a.reap(), vec![(1, 0, 0)]);
    assert_eq!(b.reap(), vec![(0xfeed, 42, 0)]);
    file(5);
    a.submit(&[
        Sqe { addr: 1, ..Sqe::op(MSG_RING, b.fd as i32, 2) },
        Sqe::op(MSG_RING, 5, 3),
        Sqe::op(MSG_RING, 77, 4),
    ]);
    assert_eq!(a.reap(), vec![(2, EINVAL, 0), (3, EOPNOTSUPP, 0), (4, EBADF, 0)]);
    // Through a registered file
    let next = b.fd as i64 + 10;
    let bfd = b.fd;
    fake::on_nested(move |num, _| {
        if num == 72 {
            let d = fake::fd::get(bfd as i64).unwrap();
            fake::fd::install(next as usize, d);
            return next;
        }
        0
    });
    let fds = [b.fd as i32];
    assert_eq!(a.register(2, ptr(&fds), 1), 0);
    a.submit(&[Sqe { flags: FIXED_FILE, off: 7, len: 8, ..Sqe::op(MSG_RING, 0, 5) }, Sqe { flags: FIXED_FILE, ..Sqe::op(MSG_RING, 3, 6) }]);
    assert_eq!(a.reap(), vec![(5, 0, 0), (6, EBADF, 0)]);
    assert_eq!(b.reap(), vec![(7, 8, 0)]);
}

#[test]
fn probe_and_other_registrations() {
    process(31_030);
    let r = ring(8);
    let mut probe = vec![0u8; 16 + 64 * 8];
    assert_eq!(r.register(8, probe.as_mut_ptr() as u64, 64), 0);
    assert_eq!((probe[0], probe[1]), (57, 58), "last opcode, ops listed");
    let supported = |op: usize| probe[16 + op * 8 + 2] == 1;
    assert_eq!(probe[16 + 22 * 8], 22);
    for op in [0, 1, 22, 23, 40, 45, 57] {
        assert!(supported(op), "op {op}");
    }
    for op in [30, 33, 41, 46] {
        assert!(!supported(op), "op {op}");
    }
    let mut small = vec![0u8; 16 + 4 * 8];
    assert_eq!(r.register(8, small.as_mut_ptr() as u64, 4), 0);
    assert_eq!(small[1], 4);
    let mut bad = [0u8; 48];
    fake::bad_ptr(mptr(&mut bad), 48);
    assert_eq!(r.register(8, mptr(&mut bad), 4), EFAULT);
    assert_eq!(r.register(9, 0, 0), 1, "personality IDs");
    assert_eq!(r.register(9, 0, 0), 2);
    assert_eq!(r.register(10, 0, 0), 0);
    assert_eq!(r.register(11, 0, 0), EINVAL, "restrictions");
    assert_eq!(r.register(17, 0, 0), 0);
    assert_eq!(r.register(18, 0, 0), 0);
    let mut limits = [7u32; 2];
    assert_eq!(r.register(19, mptr(&mut limits), 2), 0);
    assert_eq!(limits, [0, 0]);
    assert_eq!(r.register(19, mptr(&mut bad), 2), EFAULT);
    assert_eq!(r.register(25, 0, 0), 0);
    assert_eq!(r.register(99, 0, 0), EINVAL);
    assert_eq!(dispatch(&SyscallFrame::default(), 427, [99, 8, 0, 0, 0, 0]), EBADF);
}

#[test]
fn disabled_rings() {
    process(31_031);
    let r = ring_with(4, 64, 0); // R_DISABLED
    assert_eq!(r.enter(0, 0, 0), EBADF);
    assert_eq!(r.register(12, 0, 0), 0);
    assert_eq!(r.enter(0, 0, 0), 0);
    assert_eq!(r.register(12, 0, 0), EBADF, "already enabled");
}

#[test]
fn registered_ring_descriptors() {
    process(31_032);
    let r = ring(8);
    // struct io_uring_rsrc_update: offset (any slot), data (the ring fd)
    let upd = |off: u32, data: u64| {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&off.to_le_bytes());
        b[8..16].copy_from_slice(&data.to_le_bytes());
        b
    };
    let mut u = upd(u32::MAX, r.fd);
    assert_eq!(r.register(20, mptr(&mut u), 1), 1);
    let slot = u32::from_le_bytes(u[0..4].try_into().unwrap());
    assert_eq!(slot, 0, "the first free slot, reported back");
    // io_uring_enter and io_uring_register through the registered index
    r.push(Sqe::op(NOP, 0, 1));
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [slot as u64, 1, 0, 16, 0, 0]), 1);
    assert_eq!(r.reap(), vec![(1, 0, 0)]);
    assert_eq!(dispatch(&SyscallFrame::default(), 427, [slot as u64, 9 | 1 << 31, 0, 0, 0, 0]), 1);
    assert_eq!(dispatch(&SyscallFrame::default(), 426, [5, 0, 0, 16, 0, 0]), EBADF, "nothing in slot 5");
    let mut fixed = upd(5, r.fd);
    assert_eq!(r.register(20, mptr(&mut fixed), 1), 1);
    let mut too_far = upd(16, r.fd);
    assert_eq!(r.register(20, mptr(&mut too_far), 1), EINVAL);
    let mut not_ring = upd(6, 99);
    assert_eq!(r.register(20, mptr(&mut not_ring), 1), EINVAL);
    assert_eq!(r.register(20, mptr(&mut u), 0), EINVAL);
    assert_eq!(r.register(20, mptr(&mut u), 17), EINVAL);
    let mut bad = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad), 16);
    assert_eq!(r.register(20, mptr(&mut bad), 1), EFAULT);
    // Unregister
    let mut un = upd(5, 0);
    assert_eq!(r.register(21, mptr(&mut un), 1), 1);
    assert_eq!(r.register(21, mptr(&mut un), 1), EINVAL, "already gone");
    // All 16 slots taken: no free one
    for s in 1..16u32 {
        let mut x = upd(s, r.fd);
        r.register(20, mptr(&mut x), 1);
    }
    let mut x = upd(0, r.fd);
    r.register(20, mptr(&mut x), 1);
    let mut any = upd(u32::MAX, r.fd);
    assert_eq!(r.register(20, mptr(&mut any), 1), EINVAL);
}
