//! io_uring: `io_uring_setup`, `io_uring_enter`, `io_uring_register`.
//!
//! - **Rings**: the submission and completion rings and the SQE array live in pages the
//!   program maps from the ring descriptor at Linux's offsets (`IORING_OFF_SQ_RING`,
//!   `IORING_OFF_CQ_RING`, `IORING_OFF_SQES`; one mapping serves both rings,
//!   `IORING_FEAT_SINGLE_MMAP`). The kernel reads and writes them through their frames.
//! - **Submission** (`io_uring_enter`) runs each request through the program's own system
//!   calls ([`super::nested`]): file I/O, sockets, opens, stats, renames and the rest. A
//!   request that would wait (a read or receive with nothing to read, an accept, a poll, a
//!   timeout) goes to the ring's worker instead.
//! - **The worker** is a kernel thread of the process (its address space, descriptor table
//!   and credentials, like Linux's io-wq workers), started for a ring's first waiting
//!   request. It sleeps on the descriptors its requests wait for and finishes each one when
//!   it is ready or its time comes, so completions arrive while the program waits anywhere
//!   (in `io_uring_enter`, in `epoll` on the ring or on a registered eventfd).
//! - **Also**: links (`IOSQE_IO_LINK`/`HARDLINK`, `LINK_TIMEOUT`), cancellation, multishot
//!   poll, registered files and buffers, provided buffers and buffer rings
//!   (`IOSQE_BUFFER_SELECT`), `CQE_SKIP_SUCCESS`, eventfd notification, `MSG_RING`, the
//!   opcode probe, registered ring descriptors, and `EXT_ARG` timeouts.
//! - **Not offered**: `SQPOLL`, `IOPOLL`, 128-byte SQEs and 32-byte CQEs (`io_uring_setup`
//!   refuses them, as a kernel without them would), splice/tee, zero-copy send, xattrs,
//!   futex and waitid requests (`-EINVAL` completions; the probe leaves them out).
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::arch::syscall::SyscallFrame;
use crate::memory::vm::MappedObject;
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const ENXIO: i64 = -6;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const EOPNOTSUPP: i64 = -95;
const ENOBUFS: i64 = -105;
const ETIME: i64 = -62;
const ECANCELED: i64 = -125;
const EALREADY: i64 = -114;

const POLLIN: u32 = 0x1;
const POLLOUT: u32 = 0x4;
const POLLERR: u32 = 0x8;
const POLLHUP: u32 = 0x10;

// Mapping offsets (in pages)
const OFF_CQ_RING_PG: u64 = 0x800_0000 / 4096;
const OFF_SQES_PG: u64 = 0x1000_0000 / 4096;

// Ring header layout (our choice; reported through io_uring_params)
const SQ_HEAD: usize = 0;
const SQ_TAIL: usize = 4;
const SQ_MASK: usize = 8;
const SQ_ENTRIES: usize = 12;
const SQ_FLAGS: usize = 16;
const SQ_DROPPED: usize = 20;
const CQ_HEAD: usize = 64;
const CQ_TAIL: usize = 68;
const CQ_MASK: usize = 72;
const CQ_ENTRIES: usize = 76;
const CQ_OVERFLOW: usize = 80;
const CQ_FLAGS: usize = 84;
const CQES: usize = 128;

// io_uring_setup flags
const SETUP_IOPOLL: u32 = 1;
const SETUP_SQPOLL: u32 = 2;
const SETUP_SQ_AFF: u32 = 4;
const SETUP_CQSIZE: u32 = 8;
const SETUP_CLAMP: u32 = 16;
const SETUP_ATTACH_WQ: u32 = 32;
const SETUP_R_DISABLED: u32 = 64;
const SETUP_SUBMIT_ALL: u32 = 128;
const SETUP_COOP_TASKRUN: u32 = 256;
const SETUP_TASKRUN_FLAG: u32 = 512;
const SETUP_SINGLE_ISSUER: u32 = 4096;
const SETUP_DEFER_TASKRUN: u32 = 8192;
const SETUP_OK: u32 = SETUP_CQSIZE | SETUP_CLAMP | SETUP_ATTACH_WQ | SETUP_R_DISABLED | SETUP_SUBMIT_ALL | SETUP_COOP_TASKRUN | SETUP_TASKRUN_FLAG | SETUP_SINGLE_ISSUER | SETUP_DEFER_TASKRUN;
const _: u32 = SETUP_IOPOLL | SETUP_SQPOLL | SETUP_SQ_AFF;

// Features: SINGLE_MMAP, NODROP, SUBMIT_STABLE, RW_CUR_POS, CUR_PERSONALITY, FAST_POLL,
// POLL_32BITS, EXT_ARG, NATIVE_WORKERS, CQE_SKIP, LINKED_FILE
const FEATURES: u32 = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 256 | 512 | 2048 | 4096;

// io_uring_enter flags
const ENTER_GETEVENTS: u64 = 1;
const ENTER_SQ_WAKEUP: u64 = 2;
const ENTER_SQ_WAIT: u64 = 4;
const ENTER_EXT_ARG: u64 = 8;
const ENTER_REGISTERED_RING: u64 = 16;

// SQE flags
const SQE_FIXED_FILE: u8 = 1;
const SQE_IO_DRAIN: u8 = 2;
const SQE_IO_LINK: u8 = 4;
const SQE_IO_HARDLINK: u8 = 8;
const SQE_ASYNC: u8 = 16;
const SQE_BUFFER_SELECT: u8 = 32;
const SQE_CQE_SKIP_SUCCESS: u8 = 64;
const SQE_FLAGS_OK: u8 = 0x7f;
const _: u8 = SQE_IO_DRAIN | SQE_ASYNC;

// CQE flags
const CQE_F_BUFFER: u32 = 1;
const CQE_F_MORE: u32 = 2;

// Opcodes
const OP_NOP: u8 = 0;
const OP_READV: u8 = 1;
const OP_WRITEV: u8 = 2;
const OP_FSYNC: u8 = 3;
const OP_READ_FIXED: u8 = 4;
const OP_WRITE_FIXED: u8 = 5;
const OP_POLL_ADD: u8 = 6;
const OP_POLL_REMOVE: u8 = 7;
const OP_SYNC_FILE_RANGE: u8 = 8;
const OP_SENDMSG: u8 = 9;
const OP_RECVMSG: u8 = 10;
const OP_TIMEOUT: u8 = 11;
const OP_TIMEOUT_REMOVE: u8 = 12;
const OP_ACCEPT: u8 = 13;
const OP_ASYNC_CANCEL: u8 = 14;
const OP_LINK_TIMEOUT: u8 = 15;
const OP_CONNECT: u8 = 16;
const OP_FALLOCATE: u8 = 17;
const OP_OPENAT: u8 = 18;
const OP_CLOSE: u8 = 19;
const OP_FILES_UPDATE: u8 = 20;
const OP_STATX: u8 = 21;
const OP_READ: u8 = 22;
const OP_WRITE: u8 = 23;
const OP_FADVISE: u8 = 24;
const OP_MADVISE: u8 = 25;
const OP_SEND: u8 = 26;
const OP_RECV: u8 = 27;
const OP_OPENAT2: u8 = 28;
const OP_EPOLL_CTL: u8 = 29;
const OP_PROVIDE_BUFFERS: u8 = 31;
const OP_REMOVE_BUFFERS: u8 = 32;
const OP_SHUTDOWN: u8 = 34;
const OP_RENAMEAT: u8 = 35;
const OP_UNLINKAT: u8 = 36;
const OP_MKDIRAT: u8 = 37;
const OP_SYMLINKAT: u8 = 38;
const OP_LINKAT: u8 = 39;
const OP_MSG_RING: u8 = 40;
const OP_SOCKET: u8 = 45;
const OP_FTRUNCATE: u8 = 55;
const OP_BIND: u8 = 56;
const OP_LISTEN: u8 = 57;
const OP_LAST: u8 = 57;

/// Opcodes this implementation runs (for `IORING_REGISTER_PROBE`).
const SUPPORTED: &[u8] = &[
    OP_NOP, OP_READV, OP_WRITEV, OP_FSYNC, OP_READ_FIXED, OP_WRITE_FIXED, OP_POLL_ADD, OP_POLL_REMOVE, OP_SYNC_FILE_RANGE, OP_SENDMSG,
    OP_RECVMSG, OP_TIMEOUT, OP_TIMEOUT_REMOVE, OP_ACCEPT, OP_ASYNC_CANCEL, OP_LINK_TIMEOUT, OP_CONNECT, OP_FALLOCATE, OP_OPENAT, OP_CLOSE,
    OP_FILES_UPDATE, OP_STATX, OP_READ, OP_WRITE, OP_FADVISE, OP_MADVISE, OP_SEND, OP_RECV, OP_OPENAT2, OP_EPOLL_CTL,
    OP_PROVIDE_BUFFERS, OP_REMOVE_BUFFERS, OP_SHUTDOWN, OP_RENAMEAT, OP_UNLINKAT, OP_MKDIRAT, OP_SYMLINKAT, OP_LINKAT, OP_MSG_RING,
    OP_SOCKET, OP_FTRUNCATE, OP_BIND, OP_LISTEN,
];

// ----------------------------------------------------------------------
// Ring memory
// ----------------------------------------------------------------------

/// The frames behind the rings and the SQE array.
struct RingMem {
    rings: Vec<PhysFrame<Size4KiB>>,
    sqes: Vec<PhysFrame<Size4KiB>>,
}

impl MappedObject for RingMem {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        if pgoff >= OFF_SQES_PG {
            self.sqes.get((pgoff - OFF_SQES_PG) as usize).copied()
        } else if pgoff >= OFF_CQ_RING_PG {
            self.rings.get((pgoff - OFF_CQ_RING_PG) as usize).copied()
        } else {
            self.rings.get(pgoff as usize).copied()
        }
    }
}

impl Drop for RingMem {
    fn drop(&mut self) {
        for f in self.rings.drain(..).chain(self.sqes.drain(..)) {
            crate::memory::frame_allocator::frame_ref_dec(f);
        }
    }
}

impl RingMem {
    fn alloc(pages: usize) -> Option<Vec<PhysFrame<Size4KiB>>> {
        let mut v = Vec::with_capacity(pages);
        for _ in 0..pages {
            match crate::memory::frame_allocator::alloc_user_frame() {
                Some(f) => v.push(f),
                None => {
                    for f in v {
                        crate::memory::frame_allocator::frame_ref_dec(f);
                    }
                    return None;
                }
            }
        }
        Some(v)
    }

    /// Kernel address of byte `off` of the ring area (never straddles a page for the
    /// aligned fields read here).
    fn at(&self, off: usize) -> *mut u8 {
        (self.rings[off / 4096].start_address().as_u64() + (off % 4096) as u64) as *mut u8
    }

    fn get(&self, off: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.at(off) as *const u32) }
    }

    fn set(&self, off: usize, v: u32) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        unsafe { core::ptr::write_volatile(self.at(off) as *mut u32, v) }
    }

    fn sqe(&self, idx: u32) -> [u8; 64] {
        let off = idx as usize * 64;
        let p = (self.sqes[off / 4096].start_address().as_u64() + (off % 4096) as u64) as *const [u8; 64];
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        unsafe { core::ptr::read_volatile(p) }
    }

    fn write_cqe(&self, slot: u32, user_data: u64, res: i32, flags: u32) {
        let off = CQES + slot as usize * 16;
        let p = self.at(off);
        unsafe {
            core::ptr::write_volatile(p as *mut u64, user_data);
            core::ptr::write_volatile(p.add(8) as *mut i32, res);
            core::ptr::write_volatile(p.add(12) as *mut u32, flags);
        }
    }
}

// ----------------------------------------------------------------------
// Requests
// ----------------------------------------------------------------------

/// A submission queue entry, decoded.
#[derive(Clone, Copy)]
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
    fn decode(b: &[u8; 64]) -> Sqe {
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Sqe {
            opcode: b[0],
            flags: b[1],
            ioprio: u16::from_le_bytes([b[2], b[3]]),
            fd: u32_at(4) as i32,
            off: u64_at(8),
            addr: u64_at(16),
            len: u32_at(24),
            op_flags: u32_at(28),
            user_data: u64_at(32),
            buf_index: u16::from_le_bytes([b[40], b[41]]),
            file_index: u32_at(44),
        }
    }

    fn linked(&self) -> bool {
        self.flags & (SQE_IO_LINK | SQE_IO_HARDLINK) != 0
    }
}

/// What a waiting request waits for.
#[derive(Clone, Copy)]
enum Wait {
    /// Descriptor `fd` showing one of `events`.
    Fd { fd: i32, events: u32 },
    /// A timeout: tick `at`, or `count` completions after `start` (if `count` > 0).
    Timeout { at: u64, count: u64, start: u64 },
}

/// A request waiting for the worker.
struct Pending {
    sqe: Sqe,
    wait: Wait,
    /// The rest of its link chain.
    chain: VecDeque<Sqe>,
    /// A `LINK_TIMEOUT` guarding it: `(deadline tick, its user_data)`.
    link_timeout: Option<(u64, u64)>,
}

/// How running a request went.
enum Outcome {
    /// Finished with `(res, cqe flags)`.
    Done(i64, u32),
    /// Must wait.
    Wait(Wait),
    /// Finished, and for a multishot poll still armed: post `(res, flags | MORE)` and wait.
    Again(i64, u32, Wait),
}

/// A registered buffer ring (`IORING_REGISTER_PBUF_RING`).
struct BufRing {
    addr: u64,
    mask: u32,
    head: u16,
}

/// A ring's mutable state.
struct State {
    sq_head: u32,
    cq_tail: u32,
    overflow: VecDeque<(u64, i32, u32)>,
    pending: Vec<Pending>,
    worker: bool,
    completions: u64,
    /// Registered files: the descriptor (a private duplicate) or -1.
    files: Vec<i32>,
    bufs: Vec<(u64, u64)>,
    provided: BTreeMap<u16, VecDeque<(u64, u32, u16)>>,
    buf_rings: BTreeMap<u16, BufRing>,
    eventfd: Option<(Arc<Mutex<super::eventfd::EventFd>>, bool)>,
    personalities: u16,
    enabled: bool,
}

/// An io_uring instance.
pub struct Ring {
    mem: Arc<RingMem>,
    sq_entries: u32,
    cq_entries: u32,
    sq_array: usize,
    st: Mutex<State>,
    /// Woken on every completion (waiters in `io_uring_enter`, poll/epoll on the ring).
    cq_wq: Arc<WaitQueue>,
    /// Wakes the worker (new waiting requests).
    kick: Arc<WaitQueue>,
    tgid: u64,
}

/// The ring descriptor's object.
struct RingDev(Arc<Ring>);

impl CharDevice for RingDev {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }
    fn poll_events(&self) -> u32 {
        let r = &self.0;
        let mut ev = 0;
        let st = r.st.lock();
        if st.cq_tail != r.mem.get(CQ_HEAD) || !st.overflow.is_empty() {
            ev |= 0x41; // POLLIN | POLLRDNORM
        }
        if r.mem.get(SQ_TAIL).wrapping_sub(st.sq_head) < r.sq_entries {
            ev |= 0x104; // POLLOUT | POLLWRNORM
        }
        ev
    }
    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.0.cq_wq.clone()));
    }
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> alloc::string::String {
        alloc::string::String::from("anon_inode:[io_uring]")
    }
    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Ok(self.0.mem.clone())
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_io_uring(&self) -> Option<Arc<Ring>> {
        Some(self.0.clone())
    }
}

/// Rings registered with `IORING_REGISTER_RING_FDS`, by (process, slot).
static RING_FDS: Mutex<BTreeMap<(u64, u32), Weak<Ring>>> = Mutex::new(BTreeMap::new());
/// Workers about to start: (task ID, its ring).
static NEW_WORKERS: Mutex<BTreeMap<u64, Weak<Ring>>> = Mutex::new(BTreeMap::new());

fn zero_frame() -> SyscallFrame {
    // SAFETY: SyscallFrame is plain register data
    unsafe { core::mem::zeroed() }
}

fn readiness(fd: i32) -> Option<u32> {
    if fd < 0 {
        return None;
    }
    crate::task::with_current_fds_mut(|fds| fds.get(fd as usize).map(|d| fds.readiness(d)))
}

fn ring_of(fd: u64, registered: bool) -> Result<Arc<Ring>, i64> {
    if registered {
        let tgid = super::proc::current_ids().1;
        return RING_FDS.lock().get(&(tgid, fd as u32)).and_then(|w| w.upgrade()).ok_or(EBADF);
    }
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    match desc {
        Some(crate::fs::FileDescriptor::Device(d)) => d.as_io_uring().ok_or(EOPNOTSUPP),
        Some(_) => Err(EOPNOTSUPP),
        None => Err(EBADF),
    }
}

impl Ring {
    /// Posts a completion (to the overflow list when the queue is full).
    fn post(&self, st: &mut State, user_data: u64, res: i64, flags: u32) {
        let res = res.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
        self.flush_overflow(st);
        if st.overflow.is_empty() && st.cq_tail.wrapping_sub(self.mem.get(CQ_HEAD)) < self.cq_entries {
            self.mem.write_cqe(st.cq_tail & (self.cq_entries - 1), user_data, res, flags);
            st.cq_tail = st.cq_tail.wrapping_add(1);
            self.mem.set(CQ_TAIL, st.cq_tail);
        } else {
            st.overflow.push_back((user_data, res, flags));
            self.mem.set(SQ_FLAGS, self.mem.get(SQ_FLAGS) | 2); // IORING_SQ_CQ_OVERFLOW
        }
        st.completions += 1;
        self.cq_wq.wake_all();
        if let Some((efd, _)) = &st.eventfd {
            // IORING_CQ_EVENTFD_DISABLED
            if self.mem.get(CQ_FLAGS) & 1 == 0 {
                let _ = efd.lock().write(&1u64.to_ne_bytes());
            }
        }
    }

    fn flush_overflow(&self, st: &mut State) {
        while let Some(&(u, r, f)) = st.overflow.front() {
            if st.cq_tail.wrapping_sub(self.mem.get(CQ_HEAD)) >= self.cq_entries {
                return;
            }
            self.mem.write_cqe(st.cq_tail & (self.cq_entries - 1), u, r, f);
            st.cq_tail = st.cq_tail.wrapping_add(1);
            self.mem.set(CQ_TAIL, st.cq_tail);
            st.overflow.pop_front();
        }
        self.mem.set(SQ_FLAGS, self.mem.get(SQ_FLAGS) & !2);
    }

    /// Posts `sqe`'s completion (unless `CQE_SKIP_SUCCESS` drops it).
    fn complete(&self, sqe: &Sqe, res: i64, flags: u32) {
        if sqe.flags & SQE_CQE_SKIP_SUCCESS != 0 && res >= 0 {
            self.st.lock().completions += 1;
            return;
        }
        let mut st = self.st.lock();
        self.post(&mut st, sqe.user_data, res, flags);
    }

    /// Fails the rest of a broken chain with `-ECANCELED`.
    fn cancel_chain(&self, chain: VecDeque<Sqe>) {
        for s in chain {
            let mut st = self.st.lock();
            self.post(&mut st, s.user_data, ECANCELED, 0);
        }
    }

    /// Runs a link chain from its first request; a request that must wait takes the rest
    /// of its chain along.
    fn run_chain(self: &Arc<Self>, mut chain: VecDeque<Sqe>, frame: &SyscallFrame) {
        while let Some(sqe) = chain.pop_front() {
            // A LINK_TIMEOUT right after guards this request
            let lt = if sqe.linked() && chain.front().is_some_and(|n| n.opcode == OP_LINK_TIMEOUT) { chain.pop_front() } else { None };
            let lt_deadline = match lt.map(|t| timeout_deadline(&t)) {
                Some(Err(e)) => {
                    // A bad link timeout fails the request and the chain
                    self.complete(&sqe, ECANCELED, 0);
                    self.complete(&lt.unwrap(), e, 0);
                    self.cancel_chain(chain);
                    return;
                }
                Some(Ok((at, _))) => Some((at, lt.unwrap().user_data)),
                None => None,
            };
            match self.exec(&sqe, frame) {
                Outcome::Done(res, flags) => {
                    self.complete(&sqe, res, flags);
                    if let Some(t) = lt {
                        self.complete(&t, ECANCELED, 0);
                    }
                    if !self.chain_goes_on(&sqe, res) {
                        self.cancel_chain(chain);
                        return;
                    }
                }
                Outcome::Again(res, flags, wait) => {
                    self.complete(&sqe, res, flags | CQE_F_MORE);
                    self.park(Pending { sqe, wait, chain, link_timeout: lt_deadline });
                    return;
                }
                Outcome::Wait(wait) => {
                    self.park(Pending { sqe, wait, chain, link_timeout: lt_deadline });
                    return;
                }
            }
        }
    }

    /// Whether a chain continues after `sqe` finished with `res`: an error (or a short read
    /// or write) breaks an `IO_LINK` chain, not a `HARDLINK` one.
    fn chain_goes_on(&self, sqe: &Sqe, res: i64) -> bool {
        if sqe.flags & SQE_IO_HARDLINK != 0 {
            return true;
        }
        let short = matches!(sqe.opcode, OP_READ | OP_WRITE | OP_RECV | OP_SEND | OP_READ_FIXED | OP_WRITE_FIXED) && res >= 0 && (res as u64) < sqe.len as u64;
        res >= 0 && !short
    }

    /// Hands a waiting request to the worker (starting it if needed).
    fn park(self: &Arc<Self>, p: Pending) {
        let start = {
            let mut st = self.st.lock();
            st.pending.push(p);
            !core::mem::replace(&mut st.worker, true)
        };
        if start {
            let id = crate::task::SCHEDULER.lock().spawn_process_worker("iou-wrk", worker_main);
            match id {
                Some(id) => {
                    NEW_WORKERS.lock().insert(id.0, Arc::downgrade(self));
                }
                None => self.st.lock().worker = false,
            }
        }
        self.kick.wake_all();
    }

    /// The descriptor a request names (a registered one with `IOSQE_FIXED_FILE`).
    fn file(&self, sqe: &Sqe) -> Result<i32, i64> {
        if sqe.flags & SQE_FIXED_FILE == 0 {
            return Ok(sqe.fd);
        }
        let st = self.st.lock();
        match st.files.get(sqe.fd as u32 as usize) {
            Some(&fd) if fd >= 0 => Ok(fd),
            _ => Err(EBADF),
        }
    }

    /// Takes a buffer from group `group` (provided buffers first, then a buffer ring).
    fn select_buffer(&self, group: u16) -> Option<(u64, u32, u16)> {
        let mut st = self.st.lock();
        if let Some(b) = st.provided.get_mut(&group).and_then(|q| q.pop_front()) {
            return Some(b);
        }
        let r = st.buf_rings.get_mut(&group)?;
        let tail = u16::from_le_bytes(copy_in(r.addr + 14, 2).ok()?.try_into().ok()?);
        if r.head == tail {
            return None;
        }
        let e = copy_in(r.addr + ((r.head as u32 & r.mask) as u64) * 16, 16).ok()?;
        r.head = r.head.wrapping_add(1);
        Some((u64::from_le_bytes(e[0..8].try_into().unwrap()), u32::from_le_bytes(e[8..12].try_into().unwrap()), u16::from_le_bytes([e[12], e[13]])))
    }

    /// Runs one request (or says what it waits for).
    fn exec(self: &Arc<Self>, sqe: &Sqe, frame: &SyscallFrame) -> Outcome {
        use Outcome::Done;
        if sqe.flags & !SQE_FLAGS_OK != 0 {
            return Done(EINVAL, 0);
        }
        let n = |num: u64, a: [u64; 6]| super::nested(frame, num, a);
        // Requests on a descriptor that may have to wait for it
        let needs = match sqe.opcode {
            OP_READ | OP_READV | OP_RECV | OP_RECVMSG | OP_ACCEPT | OP_READ_FIXED => POLLIN,
            OP_WRITE | OP_WRITEV | OP_SEND | OP_SENDMSG | OP_WRITE_FIXED => POLLOUT,
            _ => 0,
        };
        let fd = if needs != 0 || matches!(sqe.opcode, OP_FSYNC | OP_SYNC_FILE_RANGE | OP_FALLOCATE | OP_FADVISE | OP_CONNECT | OP_SHUTDOWN | OP_FTRUNCATE | OP_BIND | OP_LISTEN | OP_POLL_ADD) {
            match self.file(sqe) {
                Ok(fd) => fd as u64,
                Err(e) => return Done(e, 0),
            }
        } else {
            sqe.fd as i64 as u64
        };
        if needs != 0 {
            match readiness(fd as i32) {
                None => return Done(EBADF, 0),
                Some(ev) if ev & (needs | POLLERR | POLLHUP) == 0 => {
                    // RWF_NOWAIT: no waiting
                    if matches!(sqe.opcode, OP_READ | OP_WRITE | OP_READV | OP_WRITEV) && sqe.op_flags & 8 != 0 {
                        return Done(EAGAIN, 0);
                    }
                    return Outcome::Wait(Wait::Fd { fd: fd as i32, events: needs });
                }
                _ => {}
            }
        }
        // Buffer selection (reads and receives into a provided buffer)
        let mut buf = (sqe.addr, sqe.len);
        let mut cflags = 0;
        let mut picked = None;
        if sqe.flags & SQE_BUFFER_SELECT != 0 {
            if !matches!(sqe.opcode, OP_READ | OP_RECV) {
                return Done(EINVAL, 0);
            }
            match self.select_buffer(sqe.buf_index) {
                Some((addr, len, bid)) => {
                    buf = (addr, if sqe.len == 0 { len } else { sqe.len.min(len) });
                    cflags = CQE_F_BUFFER | (bid as u32) << 16;
                    picked = Some((addr, len, bid));
                }
                None => return Done(ENOBUFS, 0),
            }
        }
        let at = |off: u64| off == u64::MAX;
        let res = match sqe.opcode {
            OP_NOP => 0,
            OP_READ => {
                if at(sqe.off) {
                    n(0, [fd, buf.0, buf.1 as u64, 0, 0, 0])
                } else {
                    n(17, [fd, buf.0, buf.1 as u64, sqe.off, 0, 0])
                }
            }
            OP_WRITE => {
                if at(sqe.off) {
                    n(1, [fd, sqe.addr, sqe.len as u64, 0, 0, 0])
                } else {
                    n(18, [fd, sqe.addr, sqe.len as u64, sqe.off, 0, 0])
                }
            }
            OP_READV => {
                if at(sqe.off) {
                    n(19, [fd, sqe.addr, sqe.len as u64, 0, 0, 0])
                } else {
                    n(295, [fd, sqe.addr, sqe.len as u64, sqe.off, 0, 0])
                }
            }
            OP_WRITEV => {
                if at(sqe.off) {
                    n(20, [fd, sqe.addr, sqe.len as u64, 0, 0, 0])
                } else {
                    n(296, [fd, sqe.addr, sqe.len as u64, sqe.off, 0, 0])
                }
            }
            OP_READ_FIXED | OP_WRITE_FIXED => {
                let ok = self.st.lock().bufs.get(sqe.buf_index as usize).is_some_and(|&(b, l)| sqe.addr >= b && sqe.addr + sqe.len as u64 <= b + l);
                if !ok {
                    EFAULT
                } else if sqe.opcode == OP_READ_FIXED {
                    if at(sqe.off) { n(0, [fd, sqe.addr, sqe.len as u64, 0, 0, 0]) } else { n(17, [fd, sqe.addr, sqe.len as u64, sqe.off, 0, 0]) }
                } else if at(sqe.off) {
                    n(1, [fd, sqe.addr, sqe.len as u64, 0, 0, 0])
                } else {
                    n(18, [fd, sqe.addr, sqe.len as u64, sqe.off, 0, 0])
                }
            }
            OP_FSYNC => n(if sqe.op_flags & 1 != 0 { 75 } else { 74 }, [fd, 0, 0, 0, 0, 0]),
            OP_SYNC_FILE_RANGE => n(277, [fd, sqe.off, sqe.len as u64, sqe.op_flags as u64, 0, 0]),
            OP_SENDMSG => n(46, [fd, sqe.addr, sqe.op_flags as u64, 0, 0, 0]),
            OP_RECVMSG => n(47, [fd, sqe.addr, sqe.op_flags as u64, 0, 0, 0]),
            OP_SEND => n(44, [fd, sqe.addr, sqe.len as u64, sqe.op_flags as u64, 0, 0]),
            OP_RECV => n(45, [fd, buf.0, buf.1 as u64, sqe.op_flags as u64, 0, 0]),
            OP_ACCEPT => {
                if sqe.ioprio & 1 != 0 || sqe.file_index != 0 {
                    EINVAL // multishot accept, direct descriptors
                } else {
                    n(288, [fd, sqe.addr, sqe.off, sqe.op_flags as u64, 0, 0])
                }
            }
            OP_CONNECT => n(42, [fd, sqe.addr, sqe.off, 0, 0, 0]),
            OP_BIND => n(49, [fd, sqe.addr, sqe.off, 0, 0, 0]),
            OP_LISTEN => n(50, [fd, sqe.len as u64, 0, 0, 0, 0]),
            OP_SHUTDOWN => n(48, [fd, sqe.len as u64, 0, 0, 0, 0]),
            OP_SOCKET => n(41, [sqe.fd as u64, sqe.off, sqe.len as u64, 0, 0, 0]),
            OP_FALLOCATE => n(285, [fd, sqe.len as u64, sqe.off, sqe.addr, 0, 0]),
            OP_FTRUNCATE => n(77, [fd, sqe.off, 0, 0, 0, 0]),
            OP_FADVISE => n(221, [fd, sqe.off, sqe.len as u64, sqe.op_flags as u64, 0, 0]),
            OP_MADVISE => n(28, [sqe.addr, sqe.len as u64, sqe.op_flags as u64, 0, 0, 0]),
            OP_OPENAT => {
                if sqe.file_index != 0 {
                    EINVAL
                } else {
                    n(257, [sqe.fd as i64 as u64, sqe.addr, sqe.op_flags as u64, sqe.len as u64, 0, 0])
                }
            }
            OP_OPENAT2 => {
                if sqe.file_index != 0 {
                    EINVAL
                } else {
                    n(437, [sqe.fd as i64 as u64, sqe.addr, sqe.off, sqe.len as u64, 0, 0])
                }
            }
            OP_CLOSE => {
                if sqe.file_index != 0 {
                    // A registered file's slot
                    let slot = sqe.file_index as usize - 1;
                    let old = self.st.lock().files.get_mut(slot).map(|f| core::mem::replace(f, -1));
                    match old {
                        Some(f) if f >= 0 => n(3, [f as u64, 0, 0, 0, 0, 0]),
                        _ => EBADF,
                    }
                } else {
                    n(3, [sqe.fd as i64 as u64, 0, 0, 0, 0, 0])
                }
            }
            OP_STATX => n(332, [sqe.fd as i64 as u64, sqe.addr, sqe.op_flags as u64, sqe.len as u64, sqe.off, 0]),
            OP_EPOLL_CTL => n(233, [sqe.fd as i64 as u64, sqe.len as u64, sqe.off, sqe.addr, 0, 0]),
            OP_RENAMEAT => n(316, [sqe.fd as i64 as u64, sqe.addr, sqe.len as i32 as i64 as u64, sqe.off, sqe.op_flags as u64, 0]),
            OP_UNLINKAT => n(263, [sqe.fd as i64 as u64, sqe.addr, sqe.op_flags as u64, 0, 0, 0]),
            OP_MKDIRAT => n(258, [sqe.fd as i64 as u64, sqe.addr, sqe.len as u64, 0, 0, 0]),
            OP_SYMLINKAT => n(266, [sqe.addr, sqe.fd as i64 as u64, sqe.off, 0, 0, 0]),
            OP_LINKAT => n(265, [sqe.fd as i64 as u64, sqe.addr, sqe.len as i32 as i64 as u64, sqe.off, sqe.op_flags as u64, 0]),
            OP_FILES_UPDATE => self.update_files(sqe.off as u32, sqe.addr, sqe.len),
            OP_PROVIDE_BUFFERS => {
                if sqe.fd <= 0 || sqe.len == 0 {
                    EINVAL
                } else {
                    let mut st = self.st.lock();
                    let q = st.provided.entry(sqe.buf_index).or_default();
                    for i in 0..sqe.fd as u64 {
                        q.push_back((sqe.addr + i * sqe.len as u64, sqe.len, (sqe.off as u16).wrapping_add(i as u16)));
                    }
                    0
                }
            }
            OP_REMOVE_BUFFERS => {
                let mut st = self.st.lock();
                match st.provided.get_mut(&sqe.buf_index) {
                    Some(q) if !q.is_empty() => {
                        let k = (sqe.fd.max(0) as usize).min(q.len());
                        q.drain(..k);
                        k as i64
                    }
                    _ => ENOENT,
                }
            }
            OP_MSG_RING => {
                // IORING_MSG_DATA: post (off, len) to the target ring
                if sqe.addr != 0 {
                    EINVAL
                } else {
                    let target = if sqe.flags & SQE_FIXED_FILE != 0 { self.file(sqe).map(|f| f as u64) } else { Ok(sqe.fd as i64 as u64) };
                    match target.and_then(|f| ring_of(f, false)) {
                        Ok(t) => {
                            let mut st = t.st.lock();
                            t.post(&mut st, sqe.off, sqe.len as i32 as i64, 0);
                            0
                        }
                        Err(e) => e,
                    }
                }
            }
            OP_POLL_ADD => {
                // 32-bit event masks (IORING_FEAT_POLL_32BITS)
                let events = sqe.op_flags;
                return match readiness(fd as i32) {
                    None => Done(EBADF, 0),
                    Some(ev) => {
                        let hit = ev & (events | POLLERR | POLLHUP);
                        let wait = Wait::Fd { fd: fd as i32, events };
                        if hit == 0 {
                            Outcome::Wait(wait)
                        } else if sqe.len & 1 != 0 {
                            Outcome::Again(hit as i64, 0, wait) // IORING_POLL_ADD_MULTI
                        } else {
                            Done(hit as i64, 0)
                        }
                    }
                };
            }
            OP_POLL_REMOVE => {
                if sqe.op_flags & 6 != 0 {
                    EINVAL // updates are not supported
                } else {
                    self.cancel(|p| p.sqe.opcode == OP_POLL_ADD && p.sqe.user_data == sqe.addr, false)
                }
            }
            OP_TIMEOUT => {
                return match timeout_deadline(sqe) {
                    Ok((at, _)) => {
                        let start = self.st.lock().completions;
                        Outcome::Wait(Wait::Timeout { at, count: sqe.off, start })
                    }
                    Err(e) => Done(e, 0),
                };
            }
            OP_TIMEOUT_REMOVE => {
                if sqe.op_flags & 2 != 0 {
                    // IORING_TIMEOUT_UPDATE: a new time for it
                    let probe = Sqe { addr: sqe.off, op_flags: sqe.op_flags & !2, ..*sqe };
                    match timeout_deadline(&probe) {
                        Ok((at, _)) => {
                            let mut st = self.st.lock();
                            match st.pending.iter_mut().find(|p| p.sqe.opcode == OP_TIMEOUT && p.sqe.user_data == sqe.addr) {
                                Some(p) => {
                                    if let Wait::Timeout { at: a, .. } = &mut p.wait {
                                        *a = at;
                                    }
                                    drop(st);
                                    self.kick.wake_all();
                                    0
                                }
                                None => ENOENT,
                            }
                        }
                        Err(e) => e,
                    }
                } else {
                    self.cancel(|p| p.sqe.opcode == OP_TIMEOUT && p.sqe.user_data == sqe.addr, false)
                }
            }
            OP_ASYNC_CANCEL => {
                // IORING_ASYNC_CANCEL_ALL, _FD, _ANY
                let all = sqe.op_flags & (1 | 4) != 0;
                let by_fd = sqe.op_flags & 2 != 0;
                let any = sqe.op_flags & 4 != 0;
                let r = self.cancel(
                    |p| {
                        if any {
                            true
                        } else if by_fd {
                            matches!(p.wait, Wait::Fd { fd: f, .. } if f == sqe.fd) || p.sqe.fd == sqe.fd
                        } else {
                            p.sqe.user_data == sqe.addr
                        }
                    },
                    all,
                );
                if r == ENOENT && !all {
                    // Already finished (Linux: -EALREADY when running, -ENOENT when gone)
                    ENOENT
                } else {
                    r
                }
            }
            OP_LINK_TIMEOUT => EINVAL, // only right after a linked request
            _ => EINVAL,
        };
        if let Some((addr, len, bid)) = picked {
            if res <= 0 {
                // Nothing went into it: the buffer goes back to its group
                self.st.lock().provided.entry(sqe.buf_index).or_default().push_front((addr, len, bid));
                cflags = 0;
            }
        }
        Done(res, cflags)
    }

    /// Cancels waiting requests `matching` (all of them, or the first): each completes with
    /// `-ECANCELED`, its chain too. The count (all) or 0, `-ENOENT` if none.
    fn cancel(&self, matching: impl Fn(&Pending) -> bool, all: bool) -> i64 {
        let mut gone = Vec::new();
        {
            let mut st = self.st.lock();
            let mut i = 0;
            while i < st.pending.len() {
                if matching(&st.pending[i]) && (all || gone.is_empty()) {
                    gone.push(st.pending.remove(i));
                } else {
                    i += 1;
                }
            }
        }
        let count = gone.len() as i64;
        for p in gone {
            self.complete(&p.sqe, ECANCELED, 0);
            if let Some((_, ud)) = p.link_timeout {
                let mut st = self.st.lock();
                self.post(&mut st, ud, ECANCELED, 0);
            }
            self.cancel_chain(p.chain);
        }
        match count {
            0 => ENOENT,
            n if all => n,
            _ => 0,
        }
    }

    /// Replaces registered files from `offset` with the `nr` descriptors at `ptr` (-1 empties
    /// a slot). Returns how many were updated.
    fn update_files(&self, offset: u32, ptr: u64, nr: u32) -> i64 {
        let Ok(raw) = copy_in(ptr, nr as usize * 4) else { return EFAULT };
        let frame = zero_frame();
        let mut done = 0;
        for (i, c) in raw.chunks_exact(4).enumerate() {
            let fd = i32::from_le_bytes(c.try_into().unwrap());
            let slot = offset as usize + i;
            let dup = if fd >= 0 {
                // A private duplicate: the program may close its own
                let d = super::nested(&frame, 72, [fd as u64, 1030, 0, 0, 0, 0]); // F_DUPFD_CLOEXEC
                if d < 0 {
                    return if done == 0 { d } else { done };
                }
                d as i32
            } else {
                -1
            };
            let old = {
                let mut st = self.st.lock();
                if slot >= st.files.len() {
                    if dup >= 0 {
                        super::nested(&frame, 3, [dup as u64, 0, 0, 0, 0, 0]);
                    }
                    return if done == 0 { EINVAL } else { done };
                }
                core::mem::replace(&mut st.files[slot], dup)
            };
            if old >= 0 {
                super::nested(&frame, 3, [old as u64, 0, 0, 0, 0, 0]);
            }
            done += 1;
        }
        done
    }

    /// Submits up to `n` requests from the submission queue. Returns how many were taken.
    fn submit(self: &Arc<Self>, n: u32, frame: &SyscallFrame) -> i64 {
        let mut taken = 0;
        let mut chain: VecDeque<Sqe> = VecDeque::new();
        while taken < n {
            let next = {
                let mut st = self.st.lock();
                let tail = self.mem.get(SQ_TAIL);
                if st.sq_head == tail {
                    None
                } else {
                    let idx = self.mem.get(self.sq_array + (st.sq_head & (self.sq_entries - 1)) as usize * 4);
                    st.sq_head = st.sq_head.wrapping_add(1);
                    self.mem.set(SQ_HEAD, st.sq_head);
                    if idx >= self.sq_entries {
                        self.mem.set(SQ_DROPPED, self.mem.get(SQ_DROPPED) + 1);
                        Some(None)
                    } else {
                        Some(Some(Sqe::decode(&self.mem.sqe(idx))))
                    }
                }
            };
            let Some(sqe) = next else { break };
            taken += 1;
            let Some(sqe) = sqe else { continue };
            let linked = sqe.linked();
            chain.push_back(sqe);
            if !linked {
                self.run_chain(core::mem::take(&mut chain), frame);
            }
        }
        if !chain.is_empty() {
            // A chain cut off by the count: Linux fails its last link
            self.run_chain(chain, frame);
        }
        taken as i64
    }

    /// The worker's pass: finishes what is ready or due. Returns the next deadline.
    fn progress(self: &Arc<Self>, frame: &SyscallFrame) -> Option<u64> {
        let now = crate::arch::pit::ticks();
        let list = core::mem::take(&mut self.st.lock().pending);
        let mut keep = Vec::new();
        for mut p in list {
            if let Some((at, ud)) = p.link_timeout {
                if now >= at {
                    // The guarded request took too long
                    self.complete(&p.sqe, ECANCELED, 0);
                    let mut st = self.st.lock();
                    self.post(&mut st, ud, ETIME, 0);
                    drop(st);
                    self.cancel_chain(p.chain);
                    continue;
                }
            }
            match p.wait {
                Wait::Timeout { at, count, start } => {
                    let done_count = count > 0 && self.st.lock().completions.saturating_sub(start) >= count;
                    if done_count || now >= at {
                        let res = if done_count { 0 } else { ETIME };
                        self.complete(&p.sqe, res, 0);
                        // A timeout in a chain: ETIME breaks it unless hard-linked
                        if res == 0 || p.sqe.flags & SQE_IO_HARDLINK != 0 {
                            self.run_chain(p.chain, frame);
                        } else {
                            self.cancel_chain(p.chain);
                        }
                    } else {
                        keep.push(p);
                    }
                }
                Wait::Fd { fd, events } => {
                    let ready = readiness(fd).map_or(true, |ev| ev & (events | POLLERR | POLLHUP) != 0);
                    if !ready {
                        keep.push(p);
                        continue;
                    }
                    match self.exec(&p.sqe, frame) {
                        Outcome::Done(res, flags) => {
                            self.complete(&p.sqe, res, flags);
                            if let Some((_, ud)) = p.link_timeout {
                                let mut st = self.st.lock();
                                self.post(&mut st, ud, ECANCELED, 0);
                            }
                            if self.chain_goes_on(&p.sqe, res) {
                                self.run_chain(p.chain, frame);
                            } else {
                                self.cancel_chain(p.chain);
                            }
                        }
                        Outcome::Again(res, flags, wait) => {
                            // A multishot poll stays armed; it fires again after a wakeup
                            self.complete(&p.sqe, res, flags | CQE_F_MORE);
                            p.wait = wait;
                            keep.push(p);
                        }
                        Outcome::Wait(wait) => {
                            p.wait = wait;
                            keep.push(p);
                        }
                    }
                }
            }
        }
        let mut st = self.st.lock();
        keep.append(&mut st.pending);
        st.pending = keep;
        st.pending
            .iter()
            .flat_map(|p| {
                let t = match p.wait {
                    Wait::Timeout { at, .. } => Some(at),
                    _ => None,
                };
                t.into_iter().chain(p.link_timeout.map(|(a, _)| a))
            })
            .min()
    }
}

/// The deadline tick of a timeout request (`addr`: its timespec; `IORING_TIMEOUT_ABS`
/// counts on the monotonic clock, or the real-time one with `IORING_TIMEOUT_REALTIME`).
fn timeout_deadline(sqe: &Sqe) -> Result<(u64, ()), i64> {
    if sqe.op_flags & !(1 | 4 | 8 | 0x20) != 0 || sqe.len != 1 && sqe.opcode == OP_TIMEOUT {
        // Only ABS, BOOTTIME, REALTIME and ETIME_SUCCESS; one timespec
        return Err(EINVAL);
    }
    let abs = sqe.op_flags & 1 != 0;
    let realtime = sqe.op_flags & 8 != 0;
    match super::futex::deadline_tick(sqe.addr, !abs, realtime)? {
        Some(t) => Ok((t, ())),
        None => Err(EFAULT),
    }
}

/// The ring worker: a kernel thread of the ring's process.
fn worker_main() {
    let me = super::proc::current_ids().0;
    let Some(weak) = NEW_WORKERS.lock().remove(&me) else { return };
    let frame = zero_frame();
    loop {
        let Some(ring) = weak.upgrade() else { return };
        let gone = super::proc::PROCS.lock().get(&ring.tgid).map_or(true, |p| p.zombie);
        if gone {
            ring.st.lock().worker = false;
            return;
        }
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(ring.kick.clone()));
        let fds: Vec<i32> = ring
            .st
            .lock()
            .pending
            .iter()
            .filter_map(|p| match p.wait {
                Wait::Fd { fd, .. } => Some(fd),
                _ => None,
            })
            .collect();
        crate::task::with_current_fds_mut(|t| {
            for fd in &fds {
                if let Some(d) = t.get(*fd as usize) {
                    t.add_wait_queues_for(d, &mut waits);
                }
            }
        });
        waits.register();
        crate::net::stack::kick();
        let deadline = ring.progress(&frame);
        drop(ring);
        // Check now and then that the process is still there
        let check = crate::arch::pit::ticks() + 100;
        waits.wait(Some(deadline.map_or(check, |d| d.min(check))));
    }
}

// ----------------------------------------------------------------------
// System calls
// ----------------------------------------------------------------------

/// `io_uring_setup(entries, params)`.
fn setup(entries: u64, params: u64) -> i64 {
    let Ok(raw) = copy_in(params, 120) else { return EFAULT };
    let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
    let flags = u32_at(8);
    if flags & !SETUP_OK != 0 || raw[28..40].iter().any(|&b| b != 0) {
        return EINVAL;
    }
    if entries == 0 {
        return EINVAL;
    }
    let mut sq = (entries as u32).checked_next_power_of_two().unwrap_or(u32::MAX);
    if entries > 32768 || sq > 32768 {
        if flags & SETUP_CLAMP == 0 {
            return EINVAL;
        }
        sq = 32768;
    }
    let cq = if flags & SETUP_CQSIZE != 0 {
        let want = u32_at(4);
        if want == 0 {
            return EINVAL;
        }
        let mut c = want.checked_next_power_of_two().unwrap_or(u32::MAX);
        if want > 65536 || c > 65536 {
            if flags & SETUP_CLAMP == 0 {
                return EINVAL;
            }
            c = 65536;
        }
        if c < sq {
            return EINVAL;
        }
        c
    } else {
        sq * 2
    };
    let sq_array = (CQES + cq as usize * 16 + 63) & !63;
    let ring_bytes = sq_array + sq as usize * 4;
    let (Some(rings), Some(sqes)) = (RingMem::alloc((ring_bytes + 4095) / 4096), RingMem::alloc((sq as usize * 64 + 4095) / 4096)) else { return ENOMEM };
    let mem = Arc::new(RingMem { rings, sqes });
    mem.set(SQ_MASK, sq - 1);
    mem.set(SQ_ENTRIES, sq);
    mem.set(CQ_MASK, cq - 1);
    mem.set(CQ_ENTRIES, cq);
    let ring = Arc::new(Ring {
        mem,
        sq_entries: sq,
        cq_entries: cq,
        sq_array,
        st: Mutex::new(State {
            sq_head: 0,
            cq_tail: 0,
            overflow: VecDeque::new(),
            pending: Vec::new(),
            worker: false,
            completions: 0,
            files: Vec::new(),
            bufs: Vec::new(),
            provided: BTreeMap::new(),
            buf_rings: BTreeMap::new(),
            eventfd: None,
            personalities: 0,
            enabled: flags & SETUP_R_DISABLED == 0,
        }),
        cq_wq: WaitQueue::new_shared(),
        kick: WaitQueue::new_shared(),
        tgid: super::proc::current_ids().1,
    });
    // Parameters back: sizes, features and where the fields are
    let mut out = raw.clone();
    out[0..4].copy_from_slice(&sq.to_le_bytes());
    out[4..8].copy_from_slice(&cq.to_le_bytes());
    out[20..24].copy_from_slice(&FEATURES.to_le_bytes());
    let sq_off = [SQ_HEAD, SQ_TAIL, SQ_MASK, SQ_ENTRIES, SQ_FLAGS, SQ_DROPPED, sq_array, 0];
    for (i, v) in sq_off.iter().enumerate() {
        out[40 + i * 4..44 + i * 4].copy_from_slice(&(*v as u32).to_le_bytes());
    }
    out[72..80].fill(0);
    let cq_off = [CQ_HEAD, CQ_TAIL, CQ_MASK, CQ_ENTRIES, CQ_OVERFLOW, CQES, CQ_FLAGS, 0];
    for (i, v) in cq_off.iter().enumerate() {
        out[80 + i * 4..84 + i * 4].copy_from_slice(&(*v as u32).to_le_bytes());
    }
    out[112..120].fill(0);
    if copy_out(params, &out).is_err() {
        return EFAULT;
    }
    let dev: Arc<dyn CharDevice> = Arc::new(RingDev(ring));
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, true);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, arg, argsz)`.
fn enter(frame: &SyscallFrame, fd: u64, to_submit: u64, min_complete: u64, flags: u64, arg: u64, argsz: u64) -> i64 {
    if flags & !(ENTER_GETEVENTS | ENTER_SQ_WAKEUP | ENTER_SQ_WAIT | ENTER_EXT_ARG | ENTER_REGISTERED_RING) != 0 {
        return EINVAL;
    }
    let ring = match ring_of(fd, flags & ENTER_REGISTERED_RING != 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if !ring.st.lock().enabled {
        return EBADF; // IORING_SETUP_R_DISABLED until IORING_REGISTER_ENABLE_RINGS
    }
    let submitted = if to_submit > 0 { ring.submit(to_submit.min(u32::MAX as u64) as u32, frame) } else { 0 };
    {
        let mut st = ring.st.lock();
        ring.flush_overflow(&mut st);
    }
    if flags & ENTER_GETEVENTS == 0 || min_complete == 0 {
        return submitted;
    }
    // EXT_ARG: struct io_uring_getevents_arg { sigmask, sigmask_sz, min_wait_usec, ts }
    let deadline = if flags & ENTER_EXT_ARG != 0 && arg != 0 {
        if argsz != 24 {
            return EINVAL;
        }
        let Ok(a) = copy_in(arg, 24) else { return EFAULT };
        let ts = u64::from_le_bytes(a[16..24].try_into().unwrap());
        match super::futex::deadline_tick(ts, true, false) {
            Ok(d) => d,
            Err(e) => return e,
        }
    } else {
        None
    };
    let mut waits = WaitSet::new();
    waits.add(QueueRef::Shared(ring.cq_wq.clone()));
    loop {
        waits.register();
        let ready = {
            let mut st = ring.st.lock();
            ring.flush_overflow(&mut st);
            st.cq_tail.wrapping_sub(ring.mem.get(CQ_HEAD)) as u64
        };
        if ready >= min_complete {
            return submitted;
        }
        if super::proc::signal_pending() {
            return if submitted > 0 { submitted } else { EINTR };
        }
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            return if submitted > 0 { submitted } else { ETIME };
        }
        waits.wait(deadline);
    }
}

/// `io_uring_register(fd, opcode, arg, nr_args)`.
fn register(fd: u64, opcode: u64, arg: u64, nr: u64) -> i64 {
    let use_registered = opcode & (1 << 31) != 0;
    let opcode = opcode & !(1 << 31);
    let ring = match ring_of(fd, use_registered) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let frame = zero_frame();
    match opcode {
        // IORING_REGISTER_BUFFERS / UNREGISTER_BUFFERS
        0 => {
            if nr == 0 || nr > 16384 {
                return EINVAL;
            }
            let Ok(raw) = copy_in(arg, nr as usize * 16) else { return EFAULT };
            let mut st = ring.st.lock();
            if !st.bufs.is_empty() {
                return EBUSY;
            }
            st.bufs = raw.chunks_exact(16).map(|c| (u64::from_le_bytes(c[0..8].try_into().unwrap()), u64::from_le_bytes(c[8..16].try_into().unwrap()))).collect();
            0
        }
        1 => {
            let mut st = ring.st.lock();
            if st.bufs.is_empty() {
                return ENXIO;
            }
            st.bufs.clear();
            0
        }
        // IORING_REGISTER_FILES (and FILES2: struct io_uring_rsrc_register)
        2 | 13 => {
            let (ptr, count) = if opcode == 13 {
                let Ok(r) = copy_in(arg, 32) else { return EFAULT };
                (u64::from_le_bytes(r[16..24].try_into().unwrap()), u32::from_le_bytes(r[0..4].try_into().unwrap()) as u64)
            } else {
                (arg, nr)
            };
            if count == 0 || count > 65536 {
                return EINVAL;
            }
            {
                let mut st = ring.st.lock();
                if !st.files.is_empty() {
                    return EBUSY;
                }
                st.files = alloc::vec![-1; count as usize];
            }
            if ptr == 0 {
                return 0; // sparse
            }
            let r = ring.update_files(0, ptr, count as u32);
            if r < 0 { r } else { 0 }
        }
        // IORING_UNREGISTER_FILES
        3 => {
            let files = core::mem::take(&mut ring.st.lock().files);
            if files.is_empty() {
                return ENXIO;
            }
            for f in files.into_iter().filter(|&f| f >= 0) {
                super::nested(&frame, 3, [f as u64, 0, 0, 0, 0, 0]);
            }
            0
        }
        // IORING_REGISTER_EVENTFD / EVENTFD_ASYNC / UNREGISTER_EVENTFD
        4 | 7 => {
            let Ok(raw) = copy_in(arg, 4) else { return EFAULT };
            let efd = i32::from_le_bytes(raw.try_into().unwrap());
            let e = crate::task::with_current_fds_mut(|fds| match fds.get(efd as usize) {
                Some(crate::fs::FileDescriptor::EventFd(e)) => Some(e.clone()),
                _ => None,
            });
            let Some(e) = e else { return EBADF };
            let mut st = ring.st.lock();
            if st.eventfd.is_some() {
                return EBUSY;
            }
            st.eventfd = Some((e, opcode == 7));
            0
        }
        5 => {
            if ring.st.lock().eventfd.take().is_none() {
                ENXIO
            } else {
                0
            }
        }
        // IORING_REGISTER_FILES_UPDATE (and UPDATE2: struct io_uring_rsrc_update2)
        6 | 14 => {
            let Ok(raw) = copy_in(arg, if opcode == 14 { 32 } else { 16 }) else { return EFAULT };
            let off = u32::from_le_bytes(raw[0..4].try_into().unwrap());
            let fds = u64::from_le_bytes(raw[8..16].try_into().unwrap());
            let count = if opcode == 14 { u32::from_le_bytes(raw[24..28].try_into().unwrap()) as u64 } else { nr };
            ring.update_files(off, fds, count as u32)
        }
        // IORING_REGISTER_PROBE
        8 => {
            let cap = nr.min(256) as usize;
            let mut out = alloc::vec![0u8; 16 + cap * 8];
            out[0] = OP_LAST;
            out[1] = (OP_LAST as usize + 1).min(cap) as u8;
            for op in 0..=(OP_LAST as usize).min(cap.saturating_sub(1)) {
                out[16 + op * 8] = op as u8;
                if SUPPORTED.contains(&(op as u8)) {
                    out[16 + op * 8 + 2] = 1; // IO_URING_OP_SUPPORTED
                }
            }
            copy_out(arg, &out).map_or(EFAULT, |_| 0)
        }
        // IORING_REGISTER_PERSONALITY / UNREGISTER_PERSONALITY
        9 => {
            let mut st = ring.st.lock();
            st.personalities += 1;
            st.personalities as i64
        }
        10 => 0,
        // IORING_REGISTER_RESTRICTIONS
        11 => EINVAL,
        // IORING_REGISTER_ENABLE_RINGS
        12 => {
            let mut st = ring.st.lock();
            if st.enabled {
                return EBADF;
            }
            st.enabled = true;
            0
        }
        // IORING_REGISTER_IOWQ_AFF / UNREGISTER_IOWQ_AFF / IOWQ_MAX_WORKERS
        17 | 18 => 0,
        19 => {
            // Report "no limits" back
            copy_out(arg, &[0u8; 8]).map_or(EFAULT, |_| 0)
        }
        // IORING_REGISTER_RING_FDS / UNREGISTER_RING_FDS: struct io_uring_rsrc_update[]
        20 | 21 => {
            if nr == 0 || nr > 16 {
                return EINVAL;
            }
            let Ok(raw) = copy_in(arg, nr as usize * 16) else { return EFAULT };
            let tgid = super::proc::current_ids().1;
            let mut out = raw.clone();
            let mut done = 0;
            for (i, c) in raw.chunks_exact(16).enumerate() {
                let off = u32::from_le_bytes(c[0..4].try_into().unwrap());
                let data = u64::from_le_bytes(c[8..16].try_into().unwrap());
                let mut table = RING_FDS.lock();
                if opcode == 21 {
                    if table.remove(&(tgid, off)).is_none() {
                        break;
                    }
                } else {
                    let Ok(r) = (|| ring_of(data, false))() else { break };
                    let slot = if off == u32::MAX {
                        match (0..16u32).find(|s| !table.contains_key(&(tgid, *s))) {
                            Some(s) => s,
                            None => break,
                        }
                    } else if off < 16 {
                        off
                    } else {
                        break;
                    };
                    table.insert((tgid, slot), Arc::downgrade(&r));
                    out[i * 16..i * 16 + 4].copy_from_slice(&slot.to_le_bytes());
                }
                done += 1;
            }
            if opcode == 20 && copy_out(arg, &out).is_err() {
                return EFAULT;
            }
            if done == 0 { EINVAL } else { done }
        }
        // IORING_REGISTER_PBUF_RING / UNREGISTER_PBUF_RING: struct io_uring_buf_reg
        22 | 23 => {
            let Ok(raw) = copy_in(arg, 40) else { return EFAULT };
            let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let entries = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let bgid = u16::from_le_bytes([raw[12], raw[13]]);
            let mut st = ring.st.lock();
            if opcode == 23 {
                return if st.buf_rings.remove(&bgid).is_some() { 0 } else { EINVAL };
            }
            if !entries.is_power_of_two() || entries > 32768 || addr == 0 || addr & 4095 != 0 {
                return EINVAL;
            }
            if st.buf_rings.contains_key(&bgid) || st.provided.contains_key(&bgid) {
                return EEXIST;
            }
            st.buf_rings.insert(bgid, BufRing { addr, mask: entries - 1, head: 0 });
            0
        }
        // IORING_REGISTER_FILE_ALLOC_RANGE
        25 => 0,
        _ => EINVAL,
    }
}

/// System calls 425–427.
pub fn dispatch(frame: &SyscallFrame, num: u64, a: [u64; 6]) -> i64 {
    let _ = EPERM;
    let _ = EALREADY;
    match num {
        425 => setup(a[0], a[1]),
        426 => enter(frame, a[0], a[1], a[2], a[3], a[4], a[5]),
        _ => register(a[0], a[1], a[2], a[3]),
    }
}
