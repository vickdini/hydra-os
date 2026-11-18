//! # Linux forwarding: the kernel side of the ring-3 Linux server (wave 3, step 1)
//!
//! The Linux personality is moving out of the kernel into one ring-3 program,
//! `linux-server` (`userland/drivers/linux-server`), step by step
//! (`docs/linux-server-design.md`, section 7). This module is what every step builds on:
//!
//! - **The forwarding table** ([`forward`]): for each Linux system call number, whether the
//!   kernel answers it (as before) or the server does. Step 1 moves the key retention
//!   service (`add_key`, `request_key`, `keyctl`) and Hydra's test call [`LX_NULL_NR`].
//!   QEMU's fw_cfg `opt/hydra/lx=kernel` (or the boot entry's option word `lx=kernel`) sends
//!   them back to the in-kernel code, which stays until a later step deletes it, so a
//!   regression can be bisected inside one build.
//! - **The worker pool**: the server's worker threads each attach a *syscall page*
//!   ([`LxCall`], shared by the kernel and the server) and wait in `SYS_LX_REPLY_RECV`,
//!   which answers the call being served and waits for the next in one trap.
//! - **The direct switch**: a forwarded call goes to an idle worker by handing it the CPU
//!   straight away ([`crate::task::scheduler::Scheduler::direct_call`]), and the answer
//!   comes back the same way. There is no run-queue pass, no wake-up of another CPU and no
//!   machine-wide stop (today's hand-off stops every other system call entry): other CPUs
//!   and other processes keep running. With no idle worker the call is queued, and the
//!   next worker to finish takes it (the slow path).
//! - **Blocking calls**: a worker may answer "pending" ([`LX_REPLY_PENDING`]); the caller
//!   keeps sleeping and any server thread answers later with `SYS_LX_COMPLETE`.
//! - **Client memory**: `SYS_LX_READ`, `SYS_LX_WRITE`, `SYS_LX_READ_STR` copy between the
//!   caller's address space and the server, faulting pages in as the caller would
//!   (copy-on-write, file pages); bad addresses are `-EFAULT`. They name the request, so the
//!   server reaches only processes whose calls it is serving.
//! - **Notifications**: process events the server must know (fork, exec, exit, a signal for
//!   a pending call) go to a ring in its service window ([`LX_NOTES_OFF`]); each call carries
//!   the ring position at the time it was made, so the server never serves a call before
//!   the events that came before it.
//! - **The crash policy** (the user's decision 6): when linux-server dies, every call in
//!   flight fails with `-EIO` (its caller never hangs), every Linux program ends, the
//!   supervisor restarts the server, and the login screen starts again if it was running.
//!   The kernel, the drivers, hydra-shell and the emergency prompt stay up.
//!
//! ## Concurrency
//!
//! Since wave 4 the forwarded call and the worker's answer run without the kernel lock (see
//! "The lock-free path" below, and [`copy`] for the copy-in/copy-out table). The request
//! table is a spin lock taken with interrupts off (serving TLB flush requests while
//! waiting), never while the scheduler lock is held (the scheduler lock may be taken
//! inside it). The other entry points (`SYS_LX_CTL`, `SYS_LX_COMPLETE`, client memory, the
//! crash policy) still run under the kernel lock, and take the same locks.

pub mod copy;

pub mod obj;

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::arch::syscall::SyscallFrame;
use crate::ipc::protocol::{
    LxCall, LxCopy, ENDPOINT_LINUX_SERVER, LX_COPY_OFF, LX_DATA_OFF, LX_DATA_SIZE, LX_CALL_INTERRUPTED, LX_CTL_ATTACH, LX_CTL_ONLINE, LX_CTL_WAKE, LX_GROUPS, LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF,
    LX_NOTE_INTERRUPT, LX_NULL_NR, LX_OBJ_FLAGS_AT1, LX_REPLY_NONE, LX_REPLY_PENDING, NOTIFY_LX_NOTES,
};
use crate::ipc::service::ContiguousFrames;
use crate::task::TaskId;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EIO: i64 = -5;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const ENAMETOOLONG: i64 = -36;
const ENOSYS: i64 = -38;

// ----------------------------------------------------------------------
// The forwarding table
// ----------------------------------------------------------------------

/// Linux system call numbers the table covers (the rest always run in the kernel).
const TABLE_LEN: usize = 512;
/// Per system call number: 0 if the kernel answers it; otherwise the server does, and the
/// bits say what the call carries ([`T_SERVER`], [`T_FD0`], [`T_IPC`]).
static TABLE: [AtomicU8; TABLE_LEN] = [const { AtomicU8::new(0) }; TABLE_LEN];
/// Table bit: the server answers the call.
const T_SERVER: u8 = 1;
/// Table bit (Group 9): `args[0]` is a descriptor; the call carries its server object's slot
/// ([`LxCall::obj`]) and holds the descriptor while it is in flight.
const T_FD0: u8 = 2;
/// Table bit (Group 9): the call carries the caller's IPC namespace.
const T_IPC: u8 = 4;
/// Table bit (Group 9): the call carries the caller's umask.
const T_UMASK: u8 = 8;
/// Table bit (Group 9): the u32 that `args[1]` points to is a descriptor (bpf's attribute
/// block starts with one for the map element commands): its server object's slot goes in
/// [`LxCall::obj`], and `obj_flags` gets [`LX_OBJ_FLAGS_AT1`] and the descriptor in bits 32..62
/// (the server uses it only when its own reading of the attribute names the same one).
const T_FDAT1: u8 = 16;
/// [`LX_NULL_NR`] (outside the table) goes to the server.
static NULL_TO_SERVER: AtomicBool = AtomicBool::new(false);
/// The calls step 1 moved to the server: `add_key`, `request_key`, `keyctl`.
pub const MOVED: [u64; 3] = [248, 249, 250];
/// The calls step 2 moves (Group 9), with their table bits.
pub const MOVED_STEP2: &[(u64, u8)] = &[
    // mq_open, mq_unlink (by name, per IPC namespace)
    (240, T_IPC | T_UMASK),
    (241, T_IPC),
    // mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr (on a queue descriptor)
    (242, T_FD0),
    (243, T_FD0),
    (244, T_FD0),
    (245, T_FD0),
    // System V semaphores and messages (shared memory stays in the kernel): semget, semop,
    // semctl, semtimedop, msgget, msgsnd, msgrcv, msgctl
    (64, T_IPC),
    (65, T_IPC),
    (66, T_IPC),
    (220, T_IPC),
    (68, T_IPC),
    (69, T_IPC),
    (70, T_IPC),
    (71, T_IPC),
    // bpf (maps, programs, links: server objects; device programs come back to the kernel)
    (321, T_FDAT1),
];
/// The boot entry asked for the in-kernel code (`lx=kernel`).
pub static KERNEL_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);

/// Where a forwarded system call is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// The in-kernel code (as before the move).
    Kernel,
    /// linux-server.
    Server,
}

/// Sets up the forwarding table at boot: the moved calls go to the server, unless QEMU's
/// fw_cfg `opt/hydra/lx` is `kernel` or the boot entry has the option word `lx=kernel`.
pub fn init() {
    let mut cfg = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/lx", &mut cfg).map(|n| &cfg[..n]);
    let kernel = fw.is_some_and(|v| v.starts_with(b"kernel")) || KERNEL_BY_BOOT_OPTION.load(Ordering::Acquire);
    set_forwarding(!kernel);
    crate::kprintln!(
        "[lx] add_key, request_key, keyctl, mq_*, sem*, msg*, bpf: {}",
        if kernel { "in the kernel (switched back: lx=kernel)" } else { "forwarded to linux-server" }
    );
}

/// Routes the moved calls to the server (`true`) or to the in-kernel code.
pub fn set_forwarding(on: bool) {
    for nr in MOVED {
        TABLE[nr as usize].store(on as u8, Ordering::Release);
    }
    for &(nr, bits) in MOVED_STEP2 {
        TABLE[nr as usize].store(if on { T_SERVER | bits } else { 0 }, Ordering::Release);
    }
    NULL_TO_SERVER.store(on, Ordering::Release);
}

/// Where system call `nr` is answered.
pub fn route(nr: u64) -> Route {
    let server = if (nr as usize) < TABLE_LEN {
        TABLE[nr as usize].load(Ordering::Relaxed) != 0
    } else {
        nr == LX_NULL_NR && NULL_TO_SERVER.load(Ordering::Relaxed)
    };
    if server {
        Route::Server
    } else {
        Route::Kernel
    }
}

/// Whether the key calls go to the server (so `/proc/keys` must come from it too).
pub fn keys_forwarded() -> bool {
    route(250) == Route::Server
}

/// The forwarding trap, called for every Linux system call after `seccomp`, holding no
/// locks: `Some(result)` if the call was answered here (by the server, or Hydra's test call
/// in the kernel), `None` if the kernel's dispatcher answers it.
#[inline]
pub fn forward(frame: &SyscallFrame) -> Option<i64> {
    let nr = frame.rax;
    match route(nr) {
        Route::Kernel if nr == LX_NULL_NR => Some(0),
        Route::Kernel => None,
        Route::Server if !ONLINE.load(Ordering::Acquire) => Some(ENOSYS),
        Route::Server => Some(call(frame)),
    }
}

/// Forwards system call `nr` with `args` made on server object `dev` (a descriptor's
/// device; `args[0]` is the descriptor): `read`, `write`, `readv`, `writev` and `ioctl` on
/// it (wave 4, step 2). A stale object (its server went away) gives `-EBADF`.
pub fn call_obj(nr: u64, args: [u64; 6], dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>) -> i64 {
    let Some(o) = dev.as_server() else { return EBADF };
    let Some(slot) = o.slot() else { return EBADF };
    if !ONLINE.load(Ordering::Acquire) {
        return EBADF;
    }
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = args;
    c.obj = slot;
    c.obj_flags = o.flags();
    call_ident(c, false)
}

// ----------------------------------------------------------------------
// Requests and workers
// ----------------------------------------------------------------------

/// Most worker threads.
const MAX_WORKERS: usize = 16;
/// Calls in flight at once (queued, served, or pending).
const MAX_REQS: usize = 128;
/// No request.
const NONE: usize = usize::MAX;

/// Where a request is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RState {
    Free,
    /// Waiting for a worker.
    Queued,
    /// In a worker's syscall page, being served.
    Delivered,
    /// Answered "pending": its caller sleeps until `SYS_LX_COMPLETE`.
    Pending,
    /// Answered; the caller takes the result.
    Done,
    /// Ended without an answer (the server went away).
    Failed,
}

/// One forwarded call (small: the table is searched on every call; the call itself waits
/// in [`Lx::calls`] only while it is queued).
#[derive(Clone, Copy)]
struct Req {
    state: RState,
    id: u64,
    /// The calling thread.
    client: u64,
    /// Where the caller is in the scheduler's task table (a hint).
    client_idx: usize,
    result: i64,
    /// A signal arrived for the caller while the call was in the server.
    interrupted: bool,
    /// The call has copies ([`copy::describe`]): its header (and, while queued, its bytes)
    /// are in [`BUFS`] at the same index.
    has_copy: bool,
}

impl Req {
    const FREE: Self = Self { state: RState::Free, id: 0, client: 0, client_idx: 0, result: 0, interrupted: false, has_copy: false };
}

/// The copies of each request slot (the copy-in/copy-out table, [`copy`]): the header
/// always, the copied-in bytes while the call is queued, the output after the answer. A
/// slot's buffer belongs to whoever holds the request: written under the request table's
/// lock while the call is placed, delivered or answered, read by the caller alone once it
/// saw the answer (the slot is freed after that). Kernel memory, so a caller that dies with
/// its call in the server leaves nothing dangling.
struct CopyBufs([UnsafeCell<copy::CopyBuf>; MAX_REQS]);
// SAFETY: see the type: every access is ordered by the request table's lock
unsafe impl Sync for CopyBufs {}
static BUFS: CopyBufs = CopyBufs([const { UnsafeCell::new(copy::CopyBuf::EMPTY) }; MAX_REQS]);

/// Request slot `slot`'s copy buffer (see [`CopyBufs`] for who may use it when).
#[allow(clippy::mut_from_ref)]
fn buf_of(slot: usize) -> &'static mut copy::CopyBuf {
    // SAFETY: see CopyBufs
    unsafe { &mut *BUFS.0[slot].get() }
}

/// A worker thread of the server.
struct Worker {
    task: u64,
    /// Its syscall page.
    page: Arc<ContiguousFrames>,
    /// Waiting in `SYS_LX_REPLY_RECV` for a call (blocked).
    idle: bool,
    /// The request it serves (an index into `reqs`; [`NONE`]).
    req: usize,
    /// Where it is in the scheduler's task table (a hint).
    idx: usize,
}

impl Worker {
    /// Its syscall page, through the kernel's direct map.
    fn call_mut(&self) -> *mut LxCall {
        crate::memory::frame_allocator::phys_to_virt(self.page.base) as *mut LxCall
    }
}

struct Lx {
    /// The server process the workers belong to (0: none).
    server_tgid: u64,
    workers: alloc::vec::Vec<Worker>,
    reqs: [Req; MAX_REQS],
    /// The calls of queued requests (same index).
    calls: [LxCall; MAX_REQS],
    next_id: u64,
}

static LX: Mutex<Lx> = Mutex::new(Lx { server_tgid: 0, workers: alloc::vec::Vec::new(), reqs: [Req::FREE; MAX_REQS], calls: [LxCall::EMPTY; MAX_REQS], next_id: 1 });

/// Runs `f` on the request table with interrupts off (serving TLB flush requests while
/// waiting for the lock: the lock-free path takes it without the kernel lock).
fn lx<R>(f: impl FnOnce(&mut Lx) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut copy::lock_serving(&LX)))
}

/// The server's workers are attached and its endpoint registered: calls are forwarded.
static ONLINE: AtomicBool = AtomicBool::new(false);

/// Calls forwarded since boot: handed to a worker directly, and queued.
pub static DIRECT_CALLS: AtomicU64 = AtomicU64::new(0);
/// See [`DIRECT_CALLS`].
pub static QUEUED_CALLS: AtomicU64 = AtomicU64::new(0);
/// Calls that failed because the server went away.
pub static FAILED_CALLS: AtomicU64 = AtomicU64::new(0);

/// Whether linux-server is serving forwarded calls.
pub fn is_online() -> bool {
    ONLINE.load(Ordering::Acquire)
}

/// Delivers request `slot` (its call is `call`, its copies `copies`) to worker `wi`: the
/// call goes into the worker's syscall page, with the copy header (empty without copies)
/// and the copied-in bytes.
fn deliver(s: &mut Lx, slot: usize, wi: usize, call: &LxCall, copies: Option<&copy::CopyBuf>) {
    s.reqs[slot].state = RState::Delivered;
    let w = &mut s.workers[wi];
    let page = w.call_mut() as *mut u8;
    // SAFETY: the page is the worker's own and stays allocated while it is in the table;
    // the header and the copy area lie within it
    unsafe {
        core::ptr::write_volatile(w.call_mut(), *call);
        let hdr = page.add(LX_COPY_OFF) as *mut LxCopy;
        match copies {
            Some(b) => {
                let mut h = b.hdr;
                h.out_len = [0; 6];
                core::ptr::write_volatile(hdr, h);
                let data = b.used_bytes();
                core::ptr::copy_nonoverlapping(data.as_ptr(), page.add(LX_DATA_OFF), data.len().min(LX_DATA_SIZE));
            }
            None => core::ptr::write_volatile(hdr, LxCopy::EMPTY),
        }
    }
    w.idle = false;
    w.req = slot;
    HAS_WORK[wi].store(true, Ordering::SeqCst);
}

/// Gives worker `wi` the oldest queued request, if any.
fn take_queued(s: &mut Lx, wi: usize) -> bool {
    let next = s.reqs.iter().enumerate().filter(|(_, r)| r.state == RState::Queued).min_by_key(|(_, r)| r.id).map(|(i, _)| i);
    match next {
        Some(slot) => {
            let call = s.calls[slot];
            let copies = if s.reqs[slot].has_copy { Some(&*buf_of(slot)) } else { None };
            deliver(s, slot, wi, &call, copies);
            true
        }
        None => false,
    }
}

/// Frees request `id` if it is still in the table in state `state` (its caller died).
fn free_if(id: u64, state: RState) {
    lx(|s| {
        if let Some(r) = s.reqs.iter_mut().find(|r| r.id == id && r.state == state) {
            *r = Req::FREE;
        }
    });
}

/// Forwards the current Linux system call to the server and waits for the answer (the
/// path under the kernel lock, for callers the lock-free path does not take: traced tasks,
/// seccomp filters, tracing on).
fn call(frame: &SyscallFrame) -> i64 {
    let mut c = LxCall::EMPTY;
    c.nr = frame.rax;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    let bits = if (c.nr as usize) < TABLE_LEN { TABLE[c.nr as usize].load(Ordering::Relaxed) } else { 0 };
    // Group 9: the server object at args[0], held until the call is answered (a close on
    // another thread cannot overtake the call)
    let _held = if bits & T_FD0 != 0 {
        obj::current_fd(c.args[0]).map(|(dev, slot, flags)| {
            c.obj = slot;
            c.obj_flags = flags;
            dev
        })
    } else {
        None
    };
    let _held1 = if bits & T_FDAT1 != 0 {
        crate::compat::linux::vfs::copy_in(c.args[1], 4).ok().and_then(|b| {
            let fd = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            obj::current_fd(fd).map(|(dev, slot, flags)| {
                c.obj = slot;
                c.obj_flags = flags | LX_OBJ_FLAGS_AT1 | (fd & 0x3FFF_FFFF) << 32;
                dev
            })
        })
    } else {
        None
    };
    if bits & T_IPC != 0 {
        c.ipc_ns = crate::compat::linux::ns::ipc_ns();
    }
    if bits & T_UMASK != 0 {
        c.umask = crate::task::with_current_fds_mut(|f| f.umask) as u64;
    }
    call_ident(c, true)
}

/// [`call`] with the call's number, arguments and object filled in: adds the caller's
/// identity (and its groups when `groups`) and waits for the answer (under the kernel lock).
fn call_ident(mut c: LxCall, groups: bool) -> i64 {
    let mut sched = crate::task::SCHEDULER.lock();
    let my_idx = sched.current_index();
    let me = sched.current_task_mut(|t| {
        c.tid = t.id.0;
        c.tgid = t.tgid;
        c.uid = t.uid;
        c.euid = t.euid;
        c.suid = t.suid;
        c.gid = t.gid;
        c.egid = t.egid;
        c.sgid = t.sgid;
        c.caps = if t.caps.in_userns { 0 } else { t.caps.effective };
        t.id.0
    });
    drop(sched);
    let Some(me) = me else { return ENOSYS };
    if groups && c.nr != LX_NULL_NR {
        if let Some(p) = crate::compat::linux::proc::PROCS.lock().get(&c.tgid) {
            let n = p.groups.len().min(LX_GROUPS);
            c.groups[..n].copy_from_slice(&p.groups[..n]);
            c.ngroups = n as u64;
        }
    }
    // The waits of `call_with` need no kernel lock: let the worker's answer switch straight
    // back to this thread even from a CPU without it (a thread blocked under the lock could
    // only be woken through the scheduler), and take the lock again before going on
    let r = call_with(me, my_idx, c, true);
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    r
}

/// Forwards call `c` (its identity filled in) of task `me` (at `my_idx`, a hint) and waits
/// for the answer. `nobkl`: the lock-free path ([`fast_entry`]), whose waits do not need
/// the kernel lock.
fn call_with(me: u64, my_idx: usize, mut c: LxCall, nobkl: bool) -> i64 {
    c.note_seq = notes_head();
    // The copy-in table: the call's pointer arguments, copied now (a bad one fails here)
    let mut copies = None;
    let mut buf;
    if let Some(desc) = copy::describe(c.nr, &c.args) {
        buf = copy::CopyBuf::EMPTY;
        if let Err(e) = copy::fill(&mut buf, desc, &c.args) {
            return e;
        }
        copies = Some(&buf);
    }
    // Interrupts stay off from handing the call over until the answer is taken: nothing on
    // this CPU may come between (the yields switch with them off, and they come back so)
    x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(me, my_idx, c, copies, nobkl))
}

/// [`call_with`] with the copies made.
fn call_and_wait(me: u64, my_idx: usize, mut c: LxCall, copies: Option<&copy::CopyBuf>, nobkl: bool) -> i64 {
    let placed = lx(|s| {
        // Checked under the table's lock: `server_gone` clears ONLINE before it takes the
        // lock, so a call placed here is either failed by it or refused now
        if !ONLINE.load(Ordering::Acquire) {
            return Err(ENOSYS);
        }
        let Some(slot) = s.reqs.iter().position(|r| r.state == RState::Free) else { return Err(EAGAIN) };
        let id = s.next_id;
        s.next_id += 1;
        c.id = id;
        s.reqs[slot] = Req { state: RState::Queued, id, client: me, client_idx: my_idx, result: 0, interrupted: false, has_copy: copies.is_some() };
        REQ_DONE[slot].store(false, Ordering::SeqCst);
        if let Some(b) = copies {
            let kept = buf_of(slot);
            kept.hdr = b.hdr;
            kept.used = b.used;
        }
        // An idle worker takes it at once
        let target = match s.workers.iter().position(|w| w.idle) {
            Some(wi) => {
                deliver(s, slot, wi, &c, copies);
                Some((s.workers[wi].task, s.workers[wi].idx))
            }
            None => {
                s.calls[slot] = c;
                // Its bytes wait with it (the caller's stack is not reachable from the
                // worker that takes it)
                if let Some(b) = copies {
                    buf_of(slot).data[..b.used].copy_from_slice(b.used_bytes());
                }
                None
            }
        };
        Ok((slot, id, target))
    });
    let (slot, id, target) = match placed {
        Ok(p) => p,
        Err(e) => {
            if e == EAGAIN {
                crate::kprintln!("[lx] too many calls in flight");
            }
            return e;
        }
    };
    match target {
        Some((w, hint)) => {
            DIRECT_CALLS.fetch_add(1, Ordering::Relaxed);
            // The direct switch: this thread blocks, the worker runs next on this CPU. When
            // that cannot be done (the worker is still running, or blocked outside the
            // lock-free path, ...), the worker is woken the ordinary way; a worker still
            // running finds the call under the table's lock before it would block
            // (not if the answer came already: a worker running on another CPU may have
            // taken the call and answered it before this thread got here)
            if !direct_to(w, hint, Some(&REQ_DONE[slot]), nobkl) {
                crate::task::SCHEDULER.lock().unblock_task(TaskId(w));
            }
        }
        None => {
            QUEUED_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }
    wait_for(slot, id, &c.args, (c.tid, c.tgid), nobkl)
}

/// Waits for the answer to request `id` (in `slot`), copies its output to the caller's
/// pointers `args` (the copy-out table), and frees it.
///
/// No wake-up is lost: the answer is marked under the table's lock and the caller woken
/// after it, and the caller blocks only under the same lock after seeing no answer.
fn wait_for(slot: usize, id: u64, args: &[u64; 6], who: (u64, u64), nobkl: bool) -> i64 {
    loop {
        let done = lx(|s| {
            let r = &mut s.reqs[slot];
            if r.id != id {
                return Some((EIO, false));
            }
            match r.state {
                RState::Done | RState::Failed => {
                    let v = r.result;
                    let out = r.state == RState::Done && r.has_copy && copy::has_output(buf_of(slot));
                    if !out {
                        *r = Req::FREE;
                    }
                    Some((v, out))
                }
                _ => None,
            }
        });
        if let Some((v, out)) = done {
            if !out {
                return v;
            }
            // The output, from the slot's buffer (the request is still ours: nobody else
            // touches an answered request), then the slot goes
            let r = match copy::copy_out(buf_of(slot), args) {
                Ok(()) => v,
                Err(e) => e,
            };
            free_if(id, RState::Done);
            return r;
        }
        // A signal: a call not taken yet is withdrawn; one being served is marked (the
        // server may answer -EINTR; a pending one learns it through a notification). The
        // slow path: under the kernel lock (the notification wakes the server's endpoint)
        if crate::compat::linux::proc::signal_pending() {
            if !crate::arch::smp::bkl_held() {
                crate::arch::smp::bkl_enter();
            }
            let what = lx(|s| {
                let r = &mut s.reqs[slot];
                if r.id != id {
                    return Some(EIO);
                }
                match r.state {
                    RState::Queued => {
                        *r = Req::FREE;
                        Some(EINTR)
                    }
                    RState::Delivered | RState::Pending if !r.interrupted => {
                        r.interrupted = true;
                        if r.state == RState::Delivered {
                            if let Some(w) = s.workers.iter().find(|w| w.req == slot) {
                                // SAFETY: the worker's own page (see `deliver`)
                                unsafe {
                                    let p = w.call_mut();
                                    let f = core::ptr::read_volatile(&(*p).flags);
                                    core::ptr::write_volatile(&mut (*p).flags, f | LX_CALL_INTERRUPTED);
                                }
                            }
                            None
                        } else {
                            Some(0)
                        }
                    }
                    _ => None,
                }
            });
            match what {
                Some(0) => note(LX_NOTE_INTERRUPT, id, 0, 0),
                Some(v) => return v,
                None => {}
            }
        }
        // Block, unless the answer came meanwhile (checked under the lock the answer is
        // marked under)
        let blocked = lx(|s| {
            let r = &s.reqs[slot];
            if r.id != id || matches!(r.state, RState::Done | RState::Failed) {
                return false;
            }
            // A signal posted before the block finds the thread running and is only noted:
            // looked for after blocking (its poster wakes the thread after posting it)
            let mut sched = crate::task::SCHEDULER.lock();
            sched.block_current();
            // (once the call is marked interrupted, the server has been told: block)
            if !r.interrupted && crate::compat::linux::proc::signal_pending_for(who.0, who.1) {
                sched.current_task_mut(|t| t.state = crate::task::TaskState::Running);
                return false;
            }
            true
        });
        if blocked {
            lx_yield(nobkl);
        }
    }
}

/// Gives up the CPU (the task blocked itself first). Every register the compiler could keep
/// a value in across it is declared clobbered, so a task resumed here needs no FPU state:
/// the direct switch moves none ([`direct_to`]). Every place this module blocks uses it, so
/// a task the direct switch resumes has always stopped at one of them. `nobkl`: the task
/// is on the lock-free path (a CPU without the kernel lock may resume it).
#[inline(never)]
fn lx_yield(nobkl: bool) {
    if nobkl {
        crate::task::scheduler::BLOCK_NOBKL.store(1, Ordering::Relaxed);
    }
    // SAFETY: the yield vector switches tasks and comes back here
    unsafe { core::arch::asm!("int 0x81", clobber_abi("sysv64")) };
    crate::task::scheduler::BLOCK_NOBKL.store(0, Ordering::Relaxed);
}

/// The direct switch ([`Scheduler::direct_call`]): blocks the current task and hands the
/// CPU to `target` (blocked at one of this module's yield points; `hint`: where it is in
/// the task table), unless `guard` is set by then. `nobkl`: as for [`lx_yield`].
///
/// # Returns
///
/// `true` once this task runs again after the switch; `false` at once (nothing changed)
/// if the switch could not be done.
///
/// [`Scheduler::direct_call`]: crate::task::scheduler::Scheduler::direct_call
fn direct_to(target: u64, hint: usize, guard: Option<&'static AtomicBool>, nobkl: bool) -> bool {
    use crate::task::scheduler::{BLOCK_NOBKL, DIRECT_GUARD, DIRECT_HINT, DIRECT_TO};
    if crate::task::scheduler::handoff_active() {
        return false;
    }
    DIRECT_TO.store(target + 1, Ordering::Relaxed);
    DIRECT_HINT.store(hint as u64, Ordering::Relaxed);
    DIRECT_GUARD.store(guard.map_or(0, |g| g as *const AtomicBool as u64), Ordering::Relaxed);
    if nobkl {
        BLOCK_NOBKL.store(1, Ordering::Relaxed);
    }
    let failed: u64;
    // SAFETY: vector 0x82 switches to `target` and comes back here when this task runs
    // again (rax 0), or returns at once with rax 1
    unsafe { core::arch::asm!("int 0x82", inout("rax") 0u64 => failed, clobber_abi("sysv64")) };
    BLOCK_NOBKL.store(0, Ordering::Relaxed);
    failed == 0
}

// ----------------------------------------------------------------------
// The lock-free path (wave 4, Group 10)
// ----------------------------------------------------------------------
//
// A forwarded call and the worker's answer run without the kernel lock: the system call
// entry ([`fast_entry`], from `arch::syscall`) takes this path for every forwarded call of
// a Linux thread without a tracer or seccomp filter, and for every `SYS_LX_REPLY_RECV`.
//
// What protects what:
// - the request table and the worker list: the table's spin lock ([`LX`], interrupts off,
//   TLB requests served while waiting);
// - task states and the switch itself: the scheduler lock, taken once per switch (in the
//   direct-switch vector, `Scheduler::direct_call`);
// - the caller's identity: a per-CPU cache ([`IDENT`]) checked against the identity epoch
//   of `compat::linux` (bumped by everything that changes credentials, groups, seccomp,
//   tracing, or ends a task);
// - the copy-in table's user memory: the caller's address-space lock.
//
// Why nothing is lost: an answer (or a delivery to a worker) is marked under the table's
// lock and the waiter woken after it; a waiter blocks only under that lock after seeing
// nothing (so the wake finds it blocked), or through the direct switch, which blocks the
// switching task only if a flag set under the table's lock is still clear when the
// scheduler lock is held: a worker's `HAS_WORK` (a call was delivered to it), a caller's
// `REQ_DONE` (its call was answered: on two CPUs a worker may take and answer it before
// the caller gets to the switch). A caller also looks for a signal after blocking, under
// the scheduler lock (a signal posted just before only marks a running thread).
//
// Why nothing runs twice: a task switched away from without the kernel lock is marked
// `nobkl_wait`; only those may be resumed by a CPU without the lock; no CPU resumes (or
// frees) a task whose stack another CPU is still leaving (`arch::percpu::leaving`), nor
// one another CPU still runs (it may be ready already: it blocked itself and was woken
// before it yielded). Anything slow (a page to fault in, a signal, a dying task) takes the
// kernel lock first.

/// The thread IDs of the workers (0: none), readable without the table's lock: the system
/// call entry tells `SYS_LX_REPLY_RECV` (native call 52) from a Linux `getpeername` (52).
static WORKER_TIDS: [AtomicU64; MAX_WORKERS] = [const { AtomicU64::new(0) }; MAX_WORKERS];
/// Per request slot: the call was answered (or failed). The caller's direct switch to the
/// worker does not happen once this is set: on two CPUs a worker may take and answer the
/// call before its caller gets to the switch (the same rule as [`HAS_WORK`]).
static REQ_DONE: [AtomicBool; MAX_REQS] = [const { AtomicBool::new(false) }; MAX_REQS];
/// Per worker: a call was delivered to it that it has not taken yet (see the section).
static HAS_WORK: [AtomicBool; MAX_WORKERS] = [const { AtomicBool::new(false) }; MAX_WORKERS];

/// Whether thread `tid` is one of the server's workers.
fn is_worker(tid: u64) -> bool {
    tid != 0 && WORKER_TIDS.iter().any(|t| t.load(Ordering::Relaxed) == tid)
}

/// A CPU's cached identity of the Linux thread it runs (see [`ident`]).
#[derive(Clone, Copy)]
struct Ident {
    /// The identity epoch it was filled under (0: empty).
    epoch: u64,
    tid: u64,
    tgid: u64,
    ids: [u32; 6],
    caps: u64,
    ngroups: u64,
    groups: [u32; LX_GROUPS],
    /// The process's IPC namespace (`ns::ipc_ns`: unshare, setns and execve bump the
    /// identity epoch too).
    ipc_ns: u64,
}

/// Per CPU, used only by that CPU with interrupts off.
struct IdentCache([UnsafeCell<Ident>; crate::arch::smp::MAX_CPUS]);
// SAFETY: each CPU touches only its own entry, with interrupts off
unsafe impl Sync for IdentCache {}
static IDENT: IdentCache = IdentCache(
    [const { UnsafeCell::new(Ident { epoch: 0, tid: 0, tgid: 0, ids: [0; 6], caps: 0, ngroups: 0, groups: [0; LX_GROUPS], ipc_ns: 0 }) }; crate::arch::smp::MAX_CPUS],
);

/// The calling thread's identity for a forwarded call, from this CPU's cache when nothing
/// changed since it was filled; `None` for a thread the lock-free path does not serve (not
/// a Linux thread, a seccomp filter, a tracer). Interrupts off.
fn ident() -> Option<Ident> {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    let epoch = crate::compat::linux::ident_epoch();
    let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
    // SAFETY: this CPU's own entry, interrupts off
    let e = unsafe { &mut *IDENT.0[cpu].get() };
    if tid != 0 && e.tid == tid && e.epoch == epoch {
        return Some(*e);
    }
    let found = crate::task::SCHEDULER.lock().current_task_mut(|t| {
        let ok = t.personality == crate::task::TaskPersonality::Linux && t.seccomp.mode == 0;
        (ok, t.id.0, t.tgid, [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid], if t.caps.in_userns { 0 } else { t.caps.effective })
    })?;
    let (ok, tid, tgid, ids, caps) = found;
    if !ok || crate::compat::linux::ptrace::is_traced(tid) {
        return None;
    }
    let mut n = Ident { epoch, tid, tgid, ids, caps, ngroups: 0, groups: [0; LX_GROUPS], ipc_ns: 0 };
    // (never waiting for the process table: see `fast_entry`)
    let procs = crate::compat::linux::proc::PROCS.try_lock()?;
    if let Some(p) = procs.get(&tgid) {
        let k = p.groups.len().min(LX_GROUPS);
        n.groups[..k].copy_from_slice(&p.groups[..k]);
        n.ngroups = k as u64;
        n.ipc_ns = p.ns.ipc;
    }
    drop(procs);
    *e = n;
    Some(n)
}

/// What [`fast_entry`] did.
pub enum Fast {
    /// A forwarded Linux call, answered: deliver signals on the way out.
    Call(i64),
    /// A worker's `SYS_LX_REPLY_RECV`.
    Reply(i64),
}

/// The lock-free path's system call entry (called by `arch::syscall` before the kernel
/// lock, interrupts off): a forwarded call of a Linux thread without tracer or seccomp
/// filter, or a worker's `SYS_LX_REPLY_RECV`. `None`: the ordinary path.
pub fn fast_entry(frame: &SyscallFrame) -> Option<Fast> {
    let nr = frame.rax;
    if nr == crate::arch::syscall::SYS_LX_REPLY_RECV {
        let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
        if is_worker(tid) {
            let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
            return Some(Fast::Reply(reply_recv_as(tid, idx, frame.rdi as i64, frame.rsi, true)));
        }
        return None;
    }
    // During a driver call (whose caller may hold kernel locks) the ordinary path waits it
    // out first; this path never waits for a lock such a caller could hold
    if route(nr) != Route::Server
        || !ONLINE.load(Ordering::Acquire)
        || crate::compat::linux::TRACE_SYSCALLS.load(Ordering::Relaxed)
        || crate::task::scheduler::handoff_active()
    {
        return None;
    }
    let id = ident()?;
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.tid = id.tid;
    c.tgid = id.tgid;
    [c.uid, c.euid, c.suid, c.gid, c.egid, c.sgid] = id.ids;
    c.caps = id.caps;
    if nr != LX_NULL_NR {
        c.ngroups = id.ngroups;
        c.groups = id.groups;
    }
    // What Group 9's calls carry besides their arguments (see `call`), gathered without
    // waiting for any lock a kernel-lock holder could hold: the descriptor table is taken
    // with `try_lock` (busy: the ordinary path), the IPC namespace comes with the identity
    let bits = if (nr as usize) < TABLE_LEN { TABLE[nr as usize].load(Ordering::Relaxed) } else { 0 };
    let mut held: [Option<Arc<dyn crate::compat::linux::chardev::CharDevice>>; 2] = [None, None];
    if bits & T_IPC != 0 {
        c.ipc_ns = id.ipc_ns;
    }
    if bits & (T_FD0 | T_FDAT1 | T_UMASK) != 0 {
        // T_FDAT1: the descriptor is the first u32 of the attribute block at args[1]
        let at1 = if bits & T_FDAT1 != 0 {
            let mut b = [0u8; 4];
            copy::read_user(c.args[1], &mut b).ok().map(|()| u32::from_le_bytes(b) as u64)
        } else {
            None
        };
        let fds = crate::task::SCHEDULER.lock().current_fds()?;
        let Some(table) = fds.try_lock() else {
            drop_last(fds);
            return None;
        };
        if bits & T_UMASK != 0 {
            c.umask = table.umask as u64;
        }
        if bits & T_FD0 != 0 {
            if let Some((dev, slot, flags)) = obj::object_in(&table, c.args[0]) {
                c.obj = slot;
                c.obj_flags = flags;
                held[0] = Some(dev);
            }
        }
        if let Some(fd) = at1 {
            if let Some((dev, slot, flags)) = obj::object_in(&table, fd) {
                c.obj = slot;
                c.obj_flags = flags | LX_OBJ_FLAGS_AT1 | (fd & 0x3FFF_FFFF) << 32;
                held[1] = Some(dev);
            }
        }
        drop(table);
        drop_last(fds);
    }
    let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
    FAST_CALLS.fetch_add(1, Ordering::Relaxed);
    let r = call_with(id.tid, idx, c, true);
    // The server objects were held across the call (a close on another thread cannot
    // overtake it); the last reference, if a close came meanwhile, goes under the lock
    for h in held.into_iter().flatten() {
        drop_last(h);
    }
    Some(Fast::Call(r))
}

/// Drops `a`, taking the kernel lock first when this is its last reference (its drop may
/// close descriptors or post notifications as under the ordinary path).
fn drop_last<T: ?Sized>(a: Arc<T>) {
    if Arc::strong_count(&a) == 1 && !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
    }
    drop(a);
}

/// Calls forwarded on the lock-free path since boot.
pub static FAST_CALLS: AtomicU64 = AtomicU64::new(0);
/// Answers handed straight back to their caller (the direct switch), and answers whose
/// caller had to be woken the ordinary way (it was not blocked yet, ran elsewhere, or had
/// blocked under the kernel lock while the worker answered without it).
pub static REPLY_DIRECT: AtomicU64 = AtomicU64::new(0);
/// See [`REPLY_DIRECT`].
pub static REPLY_WOKEN: AtomicU64 = AtomicU64::new(0);

/// One line for `linux prof show`: how the forwarded calls went.
pub fn summary() -> alloc::string::String {
    alloc::format!(
        "{} calls forwarded ({} on the lock-free path; {} straight to an idle worker, {} queued, {} failed); answers: {} switched straight back, {} woken the ordinary way",
        DIRECT_CALLS.load(Ordering::Relaxed) + QUEUED_CALLS.load(Ordering::Relaxed),
        FAST_CALLS.load(Ordering::Relaxed),
        DIRECT_CALLS.load(Ordering::Relaxed),
        QUEUED_CALLS.load(Ordering::Relaxed),
        FAILED_CALLS.load(Ordering::Relaxed),
        REPLY_DIRECT.load(Ordering::Relaxed),
        REPLY_WOKEN.load(Ordering::Relaxed),
    )
}

/// Whether the calling Linux thread, back from a call on the lock-free path, may have a
/// signal to take or a stop to make (then `arch::syscall` delivers the ordinary way, under
/// the kernel lock). Interrupts off.
pub fn delivery_maybe() -> bool {
    let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    // SAFETY: this CPU's own entry, interrupts off
    let e = unsafe { &*IDENT.0[cpu].get() };
    if e.tid != tid || tid == 0 {
        return true;
    }
    crate::compat::linux::proc::delivery_maybe(tid, e.tgid)
}

// ----------------------------------------------------------------------
// Server side (native system calls of linux-server)
// ----------------------------------------------------------------------

/// The thread that made request `id` (served or pending), for the object primitives.
fn client_of(id: u64) -> Option<u64> {
    lx(|s| s.reqs.iter().find(|r| r.id == id && matches!(r.state, RState::Delivered | RState::Pending)).map(|r| r.client))
}

/// The calling task's ID and process, if it is linux-server.
fn server_caller() -> Result<(u64, u64), i64> {
    server_caller_at().map(|(id, tgid, _)| (id, tgid))
}

/// [`server_caller`], with the task's index in the scheduler's table.
fn server_caller_at() -> Result<(u64, u64, usize), i64> {
    let mut sched = crate::task::SCHEDULER.lock();
    let idx = sched.current_index();
    sched.current_task_mut(|t| (t.service == Some(ENDPOINT_LINUX_SERVER)).then_some((t.id.0, t.tgid, idx))).flatten().ok_or(EPERM)
}

/// `SYS_LX_CTL`: [`LX_CTL_ATTACH`] registers the calling thread as a worker and returns its
/// syscall page's address; [`LX_CTL_ONLINE`] starts forwarding (every worker attached, the
/// endpoint registered).
pub fn ctl(op: u64) -> i64 {
    let (me, tgid) = match server_caller() {
        Ok(v) => v,
        Err(e) => return e,
    };
    match op {
        LX_CTL_ATTACH => {
            // A new server process: the state of one that went away goes
            let old = lx(|s| s.server_tgid);
            if old != 0 && old != tgid {
                let alive = crate::task::SCHEDULER.lock().with_process(old, |_| ()).is_some();
                if alive {
                    return EBUSY;
                }
                lx(|s| {
                    s.workers.clear();
                    s.server_tgid = 0;
                    for t in WORKER_TIDS.iter() {
                        t.store(0, Ordering::Release);
                    }
                });
            }
            let Some(page) = ContiguousFrames::allocate(1) else { return ENOMEM };
            let addr = match crate::ipc::service::map_into_current(page.clone(), 1) {
                Ok(a) => a,
                Err(e) => return e,
            };
            lx(|s| {
                if s.workers.len() >= MAX_WORKERS {
                    return EBUSY;
                }
                s.server_tgid = tgid;
                let idx = crate::task::SCHEDULER.lock().current_index();
                WORKER_TIDS[s.workers.len()].store(me, Ordering::Release);
                HAS_WORK[s.workers.len()].store(false, Ordering::Release);
                s.workers.push(Worker { task: me, page, idle: false, req: NONE, idx });
                addr as i64
            })
        }
        LX_CTL_ONLINE => {
            let Some(win) = crate::ipc::service::window(ENDPOINT_LINUX_SERVER) else { return EINVAL };
            if lx(|s| s.server_tgid != tgid || s.workers.is_empty()) {
                return EINVAL;
            }
            // An empty notification ring
            let base = win.as_mut_ptr() as u64 + LX_NOTES_OFF as u64;
            // SAFETY: the window is 256 KiB, the ring's header is at its start
            unsafe {
                for i in 0..3 {
                    core::ptr::write_volatile((base as *mut u64).add(i), 0);
                }
            }
            NOTES_HEAD.store(0, Ordering::Release);
            NOTES.store(base, Ordering::Release);
            obj::online(win.as_mut_ptr() as u64);
            ONLINE.store(true, Ordering::Release);
            let n = lx(|s| s.workers.len());
            crate::kprintln!("[lx] linux-server online (process {}, {} workers)", tgid, n);
            0
        }
        LX_CTL_WAKE => {
            crate::ipc::service::notify(ENDPOINT_LINUX_SERVER, NOTIFY_LX_NOTES);
            0
        }
        _ => EINVAL,
    }
}

/// `SYS_LX_REPLY_RECV`: answers the call the calling worker serves with `result` (unless
/// `flags` has [`LX_REPLY_NONE`]; [`LX_REPLY_PENDING`]: the call goes on, answered later by
/// [`complete`]), then waits for the next call, which is in the worker's syscall page when
/// this returns 0. The answer hands the CPU straight back to its caller when this worker
/// has nothing else to do (the direct switch). (The path under the kernel lock; workers
/// normally come in through [`fast_entry`].)
pub fn reply_recv(result: i64, flags: u64) -> i64 {
    let (me, my_idx) = match server_caller_at() {
        Ok((me, _, idx)) => (me, idx),
        Err(e) => return e,
    };
    reply_recv_as(me, my_idx, result, flags, false)
}

/// [`reply_recv`] for worker `me` (at `my_idx`, a hint); `nobkl`: the lock-free path.
fn reply_recv_as(me: u64, my_idx: usize, result: i64, flags: u64, nobkl: bool) -> i64 {
    let answered = x86_64::instructions::interrupts::without_interrupts(|| {
        lx(|s| {
            let wi = s.workers.iter().position(|w| w.task == me)?;
            s.workers[wi].idx = my_idx;
            let mut wake = (0u64, 0u64, 0usize);
            let mut interrupted = 0u64;
            let cur = s.workers[wi].req;
            if flags & LX_REPLY_NONE == 0 && cur != NONE {
                let r = &mut s.reqs[cur];
                if r.state == RState::Delivered {
                    if flags & LX_REPLY_PENDING != 0 {
                        r.state = RState::Pending;
                        // Group 9: a signal that came while the call was served is told now
                        // (the caller already marked it and will not tell again)
                        if r.interrupted {
                            interrupted = r.id;
                        }
                    } else {
                        r.state = RState::Done;
                        r.result = result;
                        REQ_DONE[cur].store(true, Ordering::SeqCst);
                        wake = (r.client, r.id, r.client_idx);
                        // The output the server left in the page (copy-out table)
                        if r.has_copy {
                            let page = s.workers[wi].call_mut() as *const u8;
                            // SAFETY: the worker's page (see `deliver`); the header and copy
                            // area lie within it
                            let (out_len, data) = unsafe {
                                let h = core::ptr::read_volatile(page.add(LX_COPY_OFF) as *const LxCopy);
                                (h.out_len, core::slice::from_raw_parts(page.add(LX_DATA_OFF), LX_DATA_SIZE))
                            };
                            copy::take_output(buf_of(cur), &out_len, data);
                        }
                    }
                }
            }
            s.workers[wi].req = NONE;
            HAS_WORK[wi].store(false, Ordering::SeqCst);
            // A call waiting in the queue comes next; otherwise this worker goes idle
            let next = take_queued(s, wi);
            if !next {
                s.workers[wi].idle = true;
            }
            Some((wake, next, wi, interrupted))
        })
    });
    let Some(((client, id, hint), next, wi, interrupted)) = answered else { return EPERM };
    if interrupted != 0 {
        note(LX_NOTE_INTERRUPT, interrupted, 0, 0);
    }
    if client != 0 {
        // Straight back to the caller, unless a call was delivered to this worker meanwhile;
        // otherwise the caller is woken the ordinary way
        let switched = !next && x86_64::instructions::interrupts::without_interrupts(|| direct_to(client, hint, Some(&HAS_WORK[wi]), nobkl));
        if switched {
            REPLY_DIRECT.fetch_add(1, Ordering::Relaxed);
        } else {
            REPLY_WOKEN.fetch_add(1, Ordering::Relaxed);
            let mut sched = crate::task::SCHEDULER.lock();
            if !sched.unblock_task(TaskId(client)) && !sched.is_task_alive(TaskId(client)) {
                // Its caller died meanwhile: nobody takes the answer
                drop(sched);
                free_if(id, RState::Done);
            }
        }
    }
    if next {
        return 0;
    }
    wait_work(me, nobkl)
}

/// Waits (blocked) until a call is delivered to worker `me`, or one is queued. The worker
/// blocks only under the table's lock after seeing nothing, so a delivery (marked under the
/// same lock, the worker woken after it) is never missed.
fn wait_work(me: u64, nobkl: bool) -> i64 {
    loop {
        let st = x86_64::instructions::interrupts::without_interrupts(|| {
            lx(|s| {
                let Some(wi) = s.workers.iter().position(|w| w.task == me) else { return Err(ESRCH) };
                if s.workers[wi].req != NONE {
                    s.workers[wi].idle = false;
                    HAS_WORK[wi].store(false, Ordering::SeqCst);
                    return Ok(true);
                }
                if take_queued(s, wi) {
                    HAS_WORK[wi].store(false, Ordering::SeqCst);
                    return Ok(true);
                }
                s.workers[wi].idle = true;
                crate::task::SCHEDULER.lock().block_current();
                Ok(false)
            })
        });
        match st {
            Err(e) => return e,
            Ok(true) => {
                return 0;
            }
            Ok(false) => {}
        }
        x86_64::instructions::interrupts::without_interrupts(|| lx_yield(nobkl));
    }
}

/// `SYS_LX_COMPLETE`: answers pending request `id` with `result` (any server thread).
pub fn complete(id: u64, result: i64) -> i64 {
    if let Err(e) = server_caller() {
        return e;
    }
    let client = lx(|s| {
        let slot = s.reqs.iter().position(|r| r.id == id && r.state == RState::Pending)?;
        REQ_DONE[slot].store(true, Ordering::SeqCst);
        let r = &mut s.reqs[slot];
        r.state = RState::Done;
        r.result = result;
        Some(r.client)
    });
    let Some(client) = client else { return EINVAL };
    let mut sched = crate::task::SCHEDULER.lock();
    if !sched.unblock_task(TaskId(client)) && !sched.is_task_alive(TaskId(client)) {
        drop(sched);
        free_if(id, RState::Done);
    }
    0
}

// ----------------------------------------------------------------------
// Client memory
// ----------------------------------------------------------------------

/// Most bytes one client memory call copies.
const MAX_COPY: u64 = 1 << 20;

/// The address space of the caller of request `id` (being served or pending).
fn client_mm(id: u64) -> Result<Arc<Mutex<crate::memory::vm::Mm>>, i64> {
    let client = lx(|s| s.reqs.iter().find(|r| r.id == id && matches!(r.state, RState::Delivered | RState::Pending)).map(|r| r.client)).ok_or(ESRCH)?;
    crate::task::SCHEDULER.lock().with_task_mut(TaskId(client), |t| t.mm.clone()).flatten().ok_or(ESRCH)
}

/// The kernel address of `n` bytes at `addr` of address space `mm` (within one page),
/// faulted in as the client would (writable when `write`).
fn client_bytes(mm: &Arc<Mutex<crate::memory::vm::Mm>>, addr: u64, n: u64, write: bool) -> Result<*mut u8, i64> {
    if !crate::memory::vm::is_user_range(addr, n) {
        return Err(EFAULT);
    }
    let mut m = mm.lock();
    m.prefault(addr, n, write).map_err(|_| EFAULT)?;
    let phys = m.translate(addr).ok_or(EFAULT)?;
    Ok(crate::memory::frame_allocator::phys_to_virt(phys.as_u64()))
}

/// Client memory operations of [`client_mem`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MemOp {
    /// Client to server.
    Read,
    /// Server to client.
    Write,
    /// A NUL-terminated string, client to server (its length is returned, without the NUL).
    ReadStr,
}

/// `SYS_LX_READ` / `SYS_LX_WRITE` / `SYS_LX_READ_STR`: copies `len` bytes (at most `len` for
/// a string) between `addr` in the address space of request `id`'s caller and `buf` in the
/// server.
///
/// # Returns
///
/// The bytes copied (a string's length), `-EFAULT` for a bad address on either side,
/// `-ESRCH` if `id` is not a call the server is serving, `-ENAMETOOLONG` for a string with
/// no NUL within `len` bytes.
pub fn client_mem(op: MemOp, id: u64, addr: u64, len: u64, buf: u64) -> i64 {
    if let Err(e) = server_caller() {
        return e;
    }
    if len > MAX_COPY {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if !crate::memory::vm::is_user_range(buf, len) || !crate::memory::vm::prefault_current(buf, len, op != MemOp::Write) {
        return EFAULT;
    }
    let mm = match client_mm(id) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let mut done = 0u64;
    while done < len {
        let at = match addr.checked_add(done) {
            Some(a) => a,
            None => return EFAULT,
        };
        let n = (4096 - (at & 0xFFF)).min(len - done);
        let p = match client_bytes(&mm, at, n, op == MemOp::Write) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let s = (buf + done) as *mut u8;
        // SAFETY: both ranges were faulted in (the server's is in the current address space,
        // the client's is reached through the direct map) and do not overlap
        unsafe {
            match op {
                MemOp::Read => core::ptr::copy_nonoverlapping(p as *const u8, s, n as usize),
                MemOp::Write => core::ptr::copy_nonoverlapping(s as *const u8, p, n as usize),
                MemOp::ReadStr => {
                    let src = core::slice::from_raw_parts(p as *const u8, n as usize);
                    let end = src.iter().position(|&b| b == 0);
                    let k = end.unwrap_or(n as usize);
                    core::ptr::copy_nonoverlapping(src.as_ptr(), s, k);
                    if end.is_some() {
                        return (done + k as u64) as i64;
                    }
                }
            }
        }
        done += n;
    }
    if op == MemOp::ReadStr {
        return ENAMETOOLONG;
    }
    done as i64
}

/// `SYS_LX_PROC_INFO`: process `tgid`'s parent and credentials, stored at `out` as seven
/// u64: `[ppid, uid, euid, suid, gid, egid, sgid]` (`KEYCTL_SESSION_TO_PARENT`).
pub fn proc_info(tgid: u64, out: u64) -> i64 {
    if let Err(e) = server_caller() {
        return e;
    }
    let Some(ppid) = crate::compat::linux::proc::PROCS.lock().get(&tgid).map(|p| p.ppid) else { return ESRCH };
    let creds = crate::task::SCHEDULER.lock().with_process(tgid, |t| [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid]);
    let Some(c) = creds else { return ESRCH };
    let mut words = [0u8; 56];
    words[..8].copy_from_slice(&ppid.to_le_bytes());
    for (i, v) in c.iter().enumerate() {
        words[8 + i * 8..16 + i * 8].copy_from_slice(&(*v as u64).to_le_bytes());
    }
    crate::compat::linux::vfs::copy_out(out, &words).map_or_else(|e| e, |()| 0)
}

// ----------------------------------------------------------------------
// Notifications
// ----------------------------------------------------------------------

/// Kernel address of the notification ring's header in the server's window (0: offline).
static NOTES: AtomicU64 = AtomicU64::new(0);
/// Posting is serialized (the posters run under the kernel lock already; this keeps it so).
static NOTES_LOCK: Mutex<()> = Mutex::new(());
/// A copy of the ring's head (a forwarded call reads it without touching the window).
static NOTES_HEAD: AtomicU64 = AtomicU64::new(0);

/// The ring position: what has been posted so far.
fn notes_head() -> u64 {
    NOTES_HEAD.load(Ordering::Acquire)
}

/// Posts notification `kind` (`LX_NOTE_*`) with `a`, `b`, `c` to the server and wakes its
/// main thread. Safe with the scheduler lock held (no allocation, a deferred wake only).
pub fn note(kind: u64, a: u64, b: u64, c: u64) {
    let base = NOTES.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _g = NOTES_LOCK.lock();
        let w = base as *mut u64;
        // SAFETY: the ring (header and entries) lies in the server's 256 KiB window
        unsafe {
            let head = core::ptr::read_volatile(w);
            let tail = core::ptr::read_volatile(w.add(1));
            if head.wrapping_sub(tail) >= LX_NOTES {
                let d = core::ptr::read_volatile(w.add(2));
                core::ptr::write_volatile(w.add(2), d + 1);
            } else {
                let e = (base + (LX_NOTES_ENTRY_OFF - LX_NOTES_OFF) as u64 + (head % LX_NOTES) * 32) as *mut u64;
                core::ptr::write_volatile(e, kind);
                core::ptr::write_volatile(e.add(1), a);
                core::ptr::write_volatile(e.add(2), b);
                core::ptr::write_volatile(e.add(3), c);
                core::sync::atomic::fence(Ordering::Release);
                core::ptr::write_volatile(w, head + 1);
                NOTES_HEAD.store(head + 1, Ordering::Release);
            }
        }
    });
    crate::ipc::service::notify(ENDPOINT_LINUX_SERVER, NOTIFY_LX_NOTES);
}

// ----------------------------------------------------------------------
// The crash policy
// ----------------------------------------------------------------------

/// A recovery after a crash is in progress.
static RECOVERING: AtomicBool = AtomicBool::new(false);

/// The hook of the server's endpoint (`ipc::service::set_signal_hook`): called with
/// `SIGNAL_GONE` when the server went away (it died, hung, or was restarted by hand).
pub fn on_signal(bits: u64) {
    if bits == crate::ipc::service::SIGNAL_GONE {
        server_gone();
    } else if bits & crate::ipc::protocol::LX_SIGNAL_OBJS != 0 {
        obj::on_doorbell();
    }
}

/// The server went away: the calls in flight fail at once with `-EIO`, its remaining
/// threads end, and the crash policy runs ([`recover_task`]).
fn server_gone() {
    let was_online = ONLINE.swap(false, Ordering::AcqRel);
    NOTES.store(0, Ordering::Release);
    NOTES_HEAD.store(0, Ordering::Release);
    obj::offline();
    let mut clients = [0u64; MAX_REQS];
    let mut n = 0;
    let tgid = lx(|s| {
        let tgid = s.server_tgid;
        s.server_tgid = 0;
        s.workers.clear();
        for t in WORKER_TIDS.iter() {
            t.store(0, Ordering::Release);
        }
        for (i, r) in s.reqs.iter_mut().enumerate() {
            if matches!(r.state, RState::Queued | RState::Delivered | RState::Pending) {
                REQ_DONE[i].store(true, Ordering::SeqCst);
                r.state = RState::Failed;
                r.result = EIO;
                clients[n] = r.client;
                n += 1;
            }
        }
        tgid
    });
    FAILED_CALLS.fetch_add(n as u64, Ordering::Relaxed);
    let threads = {
        let mut sched = crate::task::SCHEDULER.lock();
        for &c in &clients[..n] {
            sched.unblock_task(TaskId(c));
        }
        if tgid != 0 {
            sched.kill_group(tgid)
        } else {
            0
        }
    };
    crate::kprintln!(
        "[lx] linux-server (process {}) went away: {} calls in flight failed with EIO, {} of its threads ended",
        tgid,
        n,
        threads
    );
    // The user's decision 6: every Linux program ends and the desktop comes back at the
    // login screen once the supervisor has restarted the server
    if (was_online || tgid != 0) && !RECOVERING.swap(true, Ordering::AcqRel) {
        crate::task::spawn("lx-recover", recover_task, crate::task::TaskPriority::Normal);
    }
}

/// The crash policy, in a kernel task of its own: ends every Linux program, waits for the
/// supervisor to restart linux-server, and starts the login screen again if it ran.
fn recover_task() {
    let n = crate::task::SCHEDULER.lock().kill_linux_tasks();
    crate::task::close_retired();
    crate::kprintln!("[lx] crash policy: ended {} Linux threads; waiting for linux-server to restart", n);
    // The supervisor restarts it (within about a second)
    let deadline = crate::arch::pit::ticks() + 60 * 100;
    while !is_online() && crate::arch::pit::ticks() < deadline {
        crate::task::sleep_ms(100);
    }
    if !is_online() {
        crate::kprintln!("[lx] linux-server did not come back; Linux system calls it serves fail with ENOSYS");
    } else if crate::admin::linux::display_manager_started() {
        // Threads that were still leaving the kernel are gone by now
        crate::task::close_retired();
        crate::kprintln!("[lx] linux-server is back: starting the login screen again");
        crate::admin::linux::plasma("/ubuntu", false);
    } else {
        crate::kprintln!("[lx] linux-server is back");
    }
    RECOVERING.store(false, Ordering::Release);
    crate::task::exit();
}

/// Called by the supervisor every second: a worker thread that died alone (killed by hand)
/// would leave its calls unanswered, so the whole server is ended and restarted.
pub fn watch() {
    if !is_online() {
        return;
    }
    let (tgid, workers, n) = lx(|s| {
        let mut w = [0u64; MAX_WORKERS];
        for (i, x) in s.workers.iter().enumerate() {
            w[i] = x.task;
        }
        (s.server_tgid, w, s.workers.len())
    });
    let mut sched = crate::task::SCHEDULER.lock();
    if let Some(dead) = workers[..n].iter().find(|&&t| !sched.is_task_alive(TaskId(t))) {
        crate::kprintln!("[lx] linux-server worker {} died: ending the server (process {})", dead, tgid);
        sched.kill_group(tgid);
    }
}

/// The forwarding state for the task dump (QEMU's `nmi`): each worker, each call in flight,
/// each CPU's LEAVING mark and the kernel lock's owner. Never waits for a lock.
pub fn dump() {
    use alloc::format;
    let w = crate::console::serial_write;
    w(&format!(
        "[lx] online {} bkl owner {} leaving [{}] fast calls {} direct {} queued {}\n",
        is_online(),
        crate::arch::smp::bkl_owner(),
        (0..crate::arch::smp::MAX_CPUS).map(|c| format!("{}", crate::arch::percpu::leaving_of(c))).collect::<alloc::vec::Vec<_>>().join(" "),
        FAST_CALLS.load(Ordering::Relaxed),
        DIRECT_CALLS.load(Ordering::Relaxed),
        QUEUED_CALLS.load(Ordering::Relaxed)
    ));
    let Some(s) = LX.try_lock() else {
        w("[lx] request table locked\n");
        return;
    };
    for (i, x) in s.workers.iter().enumerate() {
        w(&format!("[lx] worker {} task {} idle {} req {} has_work {}\n", i, x.task, x.idle, x.req as i64, HAS_WORK[i].load(Ordering::Relaxed)));
    }
    for (i, r) in s.reqs.iter().enumerate() {
        if r.state != RState::Free {
            w(&format!("[lx] req slot {} id {} {:?} client {} result {}\n", i, r.id, r.state, r.client, r.result));
        }
    }
}

/// `(online, workers, idle workers, calls in flight, direct, queued, failed)`, for the
/// `service` diagnostics.
pub fn stats() -> (bool, usize, usize, usize, u64, u64, u64) {
    let (w, idle, inflight) = lx(|s| (s.workers.len(), s.workers.iter().filter(|w| w.idle).count(), s.reqs.iter().filter(|r| r.state != RState::Free).count()));
    (
        is_online(),
        w,
        idle,
        inflight,
        DIRECT_CALLS.load(Ordering::Relaxed),
        QUEUED_CALLS.load(Ordering::Relaxed),
        FAILED_CALLS.load(Ordering::Relaxed),
    )
}

// ----------------------------------------------------------------------
// Kernel requests to the server's main thread
// ----------------------------------------------------------------------

/// `/proc/keys` for the calling Linux thread, from the server when the key calls are
/// forwarded (`None`: the in-kernel table answers). A hand-off call: the reader may hold
/// its descriptor table's lock.
pub fn proc_keys_text() -> Option<alloc::string::String> {
    use crate::ipc::protocol::{LX_PROC_KEYS_GROUPS_OFF, LX_PROC_KEYS_TEXT_MAX, LX_PROC_KEYS_TEXT_OFF, MSG_LX_PROC_KEYS};
    if !keys_forwarded() {
        return None;
    }
    if !is_online() {
        return Some(alloc::string::String::new());
    }
    let (tid, tgid, euid, egid, caps) = crate::task::with_current_task_mut(|t| (t.id.0, t.tgid, t.euid, t.egid, if t.caps.in_userns { 0 } else { t.caps.effective }))?;
    let groups: alloc::vec::Vec<u32> = crate::compat::linux::proc::PROCS.lock().get(&tgid).map(|p| p.groups.clone()).unwrap_or_default();
    let _window = crate::ipc::service::hold_window(ENDPOINT_LINUX_SERVER);
    let win = crate::ipc::service::window(ENDPOINT_LINUX_SERVER)?;
    let n = groups.len().min(1000);
    win[LX_PROC_KEYS_GROUPS_OFF..LX_PROC_KEYS_GROUPS_OFF + 4].copy_from_slice(&(n as u32).to_le_bytes());
    for (i, g) in groups[..n].iter().enumerate() {
        let o = LX_PROC_KEYS_GROUPS_OFF + 4 + i * 4;
        win[o..o + 4].copy_from_slice(&g.to_le_bytes());
    }
    let msg = crate::ipc::Message::with_args(MSG_LX_PROC_KEYS, [tid, tgid, euid as u64 | (egid as u64) << 32, caps]);
    let len = match crate::ipc::service::call(ENDPOINT_LINUX_SERVER, msg, crate::ipc::service::CALL_TIMEOUT_TICKS) {
        Ok(r) if (r.args[0] as i64) >= 0 => (r.args[0] as usize).min(LX_PROC_KEYS_TEXT_MAX),
        _ => 0,
    };
    let text = &win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len];
    Some(alloc::string::String::from_utf8_lossy(text).into_owned())
}
