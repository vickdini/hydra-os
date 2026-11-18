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
//!   straight away ([`crate::task::scheduler::Scheduler::direct_handover`]), and the answer
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
//! Everything here runs under the kernel lock (`arch::smp`), so a caller handing the CPU
//! to a worker, and a worker going idle, cannot interleave with another CPU's kernel code.
//! The request table is a spin lock taken with interrupts off, never while the scheduler
//! lock is held (the scheduler lock may be taken inside it).

pub mod obj;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::arch::syscall::SyscallFrame;
use crate::ipc::protocol::{
    LxCall, ENDPOINT_LINUX_SERVER, LX_CALL_INTERRUPTED, LX_CTL_ATTACH, LX_CTL_ONLINE, LX_CTL_WAKE, LX_GROUPS, LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF,
    LX_NOTE_INTERRUPT, LX_NULL_NR, LX_REPLY_NONE, LX_REPLY_PENDING, NOTIFY_LX_NOTES,
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
/// Table bit (Group 9): the call carries the caller's IPC namespace and umask.
const T_IPC: u8 = 4;
/// [`LX_NULL_NR`] (outside the table) goes to the server.
static NULL_TO_SERVER: AtomicBool = AtomicBool::new(false);
/// The calls step 1 moved to the server: `add_key`, `request_key`, `keyctl`.
pub const MOVED: [u64; 3] = [248, 249, 250];
/// The calls step 2 moves (Group 9), with their table bits.
pub const MOVED_STEP2: &[(u64, u8)] = &[
    // mq_open, mq_unlink (by name, per IPC namespace)
    (240, T_IPC),
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
    (321, 0),
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
    call_with(c, false)
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
}

impl Req {
    const FREE: Self = Self { state: RState::Free, id: 0, client: 0, client_idx: 0, result: 0, interrupted: false };
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

/// Runs `f` on the request table with interrupts off.
fn lx<R>(f: impl FnOnce(&mut Lx) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut LX.lock()))
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

/// Delivers request `slot` (its call is `call`) to worker `wi`: the call goes into the
/// worker's syscall page.
fn deliver(s: &mut Lx, slot: usize, wi: usize, call: &LxCall) {
    s.reqs[slot].state = RState::Delivered;
    let w = &mut s.workers[wi];
    // SAFETY: the page is the worker's own and stays allocated while it is in the table
    unsafe { core::ptr::write_volatile(w.call_mut(), *call) };
    w.idle = false;
    w.req = slot;
}

/// Gives worker `wi` the oldest queued request, if any.
fn take_queued(s: &mut Lx, wi: usize) -> bool {
    let next = s.reqs.iter().enumerate().filter(|(_, r)| r.state == RState::Queued).min_by_key(|(_, r)| r.id).map(|(i, _)| i);
    match next {
        Some(slot) => {
            let call = s.calls[slot];
            deliver(s, slot, wi, &call);
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

/// Forwards the current Linux system call to the server and waits for the answer.
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
    if bits & T_IPC != 0 {
        c.ipc_ns = crate::compat::linux::ns::ipc_ns();
        c.umask = crate::task::with_current_fds_mut(|f| f.umask) as u64;
    }
    call_with(c, true)
}

/// [`call`] with the call's number, arguments and object filled in: adds the caller's
/// identity (and its groups when `groups`) and waits for the answer.
fn call_with(mut c: LxCall, groups: bool) -> i64 {
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
    c.note_seq = notes_head();
    // Interrupts stay off from handing the call over until the answer is taken: nothing on
    // this CPU may come between (the yields switch with them off, and they come back so)
    x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(me, my_idx, c))
}

/// [`call`] with the call filled in.
fn call_and_wait(me: u64, my_idx: usize, mut c: LxCall) -> i64 {
    let placed = lx(|s| {
        let slot = s.reqs.iter().position(|r| r.state == RState::Free)?;
        let id = s.next_id;
        s.next_id += 1;
        c.id = id;
        s.reqs[slot] = Req { state: RState::Queued, id, client: me, client_idx: my_idx, result: 0, interrupted: false };
        // An idle worker takes it at once
        let target = match s.workers.iter().position(|w| w.idle) {
            Some(wi) => {
                deliver(s, slot, wi, &c);
                Some((s.workers[wi].task, s.workers[wi].idx))
            }
            None => {
                s.calls[slot] = c;
                None
            }
        };
        Some((slot, id, target))
    });
    let Some((slot, id, target)) = placed else {
        crate::kprintln!("[lx] too many calls in flight");
        return EAGAIN;
    };
    match target {
        Some((w, hint)) => {
            DIRECT_CALLS.fetch_add(1, Ordering::Relaxed);
            // The direct switch: this thread blocks, the worker runs next on this CPU
            let handed = crate::task::SCHEDULER.lock().direct_handover(w, hint);
            if handed.is_some() {
                switch_to_task(w);
            }
            // (Otherwise the worker is already runnable, woken by something else: it finds
            // the call when it runs)
        }
        None => {
            QUEUED_CALLS.fetch_add(1, Ordering::Relaxed);
        }
    }
    wait_for(slot, id)
}

/// Waits for the answer to request `id` (in `slot`) and frees it.
fn wait_for(slot: usize, id: u64) -> i64 {
    loop {
        let done = lx(|s| {
            let r = &mut s.reqs[slot];
            if r.id != id {
                return Some(EIO);
            }
            match r.state {
                RState::Done | RState::Failed => {
                    let v = r.result;
                    *r = Req::FREE;
                    Some(v)
                }
                _ => None,
            }
        });
        if let Some(v) = done {
            return v;
        }
        // A signal: a call not taken yet is withdrawn; one being served is marked (the
        // server may answer -EINTR; a pending one learns it through a notification)
        if crate::compat::linux::proc::signal_pending() {
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
        crate::task::SCHEDULER.lock().block_current();
        lx_yield();
    }
}

/// Gives up the CPU (the task blocked itself first). Every register the compiler could keep
/// a value in across it is declared clobbered, so a task resumed here needs no FPU state:
/// the direct switch moves none ([`switch_to_task`]). Every place this module blocks uses
/// it, so a task the direct switch resumes has always stopped at one of them.
#[inline(never)]
fn lx_yield() {
    // SAFETY: the yield vector switches tasks and comes back here
    unsafe { core::arch::asm!("int 0x81", clobber_abi("sysv64")) };
}

/// The direct switch: hands the CPU to `target`, which [`Scheduler::direct_handover`] made
/// ready (and the current task blocked), through the direct-switch vector; an ordinary
/// yield when that cannot be done (a driver call's hand-off in progress, ...).
///
/// [`Scheduler::direct_handover`]: crate::task::scheduler::Scheduler::direct_handover
fn switch_to_task(target: u64) {
    if crate::task::scheduler::handoff_active() {
        return lx_yield();
    }
    crate::task::scheduler::DIRECT_TO.store(target + 1, Ordering::Relaxed);
    let failed: u64;
    // SAFETY: vector 0x82 switches to `target` and comes back here when this task runs
    // again (rax 0), or returns at once with rax 1
    unsafe { core::arch::asm!("int 0x82", inout("rax") 0u64 => failed, clobber_abi("sysv64")) };
    if failed != 0 {
        lx_yield();
    }
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
/// has nothing else to do (the direct switch).
pub fn reply_recv(result: i64, flags: u64) -> i64 {
    let (me, my_idx) = match server_caller_at() {
        Ok((me, _, idx)) => (me, idx),
        Err(e) => return e,
    };
    let answered = lx(|s| {
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
                    wake = (r.client, r.id, r.client_idx);
                }
            }
        }
        s.workers[wi].req = NONE;
        // A call waiting in the queue comes next; otherwise this worker goes idle
        let next = take_queued(s, wi);
        if !next {
            s.workers[wi].idle = true;
        }
        Some((wake, next, interrupted))
    });
    let Some(((client, id, hint), next, interrupted)) = answered else { return EPERM };
    if interrupted != 0 {
        note(LX_NOTE_INTERRUPT, interrupted, 0, 0);
    }
    if client != 0 {
        let mut sched = crate::task::SCHEDULER.lock();
        if !next && sched.direct_handover(client, hint).is_some() {
            // Straight back to the caller; this worker waits for its next call
            drop(sched);
            switch_to_task(client);
        } else if !sched.unblock_task(TaskId(client)) && !sched.is_task_alive(TaskId(client)) {
            // Its caller died meanwhile: nobody takes the answer
            drop(sched);
            free_if(id, RState::Done);
        }
    }
    if next {
        return 0;
    }
    wait_work(me)
}

/// Waits (blocked) until a call is delivered to worker `me`, or one is queued.
fn wait_work(me: u64) -> i64 {
    loop {
        let st = lx(|s| {
            let Some(wi) = s.workers.iter().position(|w| w.task == me) else { return Err(ESRCH) };
            if s.workers[wi].req != NONE {
                s.workers[wi].idle = false;
                return Ok(true);
            }
            if take_queued(s, wi) {
                return Ok(true);
            }
            s.workers[wi].idle = true;
            Ok(false)
        });
        match st {
            Err(e) => return e,
            Ok(true) => {
                return 0;
            }
            Ok(false) => {}
        }
        crate::task::SCHEDULER.lock().block_current();
        lx_yield();
    }
}

/// `SYS_LX_COMPLETE`: answers pending request `id` with `result` (any server thread).
pub fn complete(id: u64, result: i64) -> i64 {
    if let Err(e) = server_caller() {
        return e;
    }
    let client = lx(|s| {
        let r = s.reqs.iter_mut().find(|r| r.id == id && r.state == RState::Pending)?;
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
        for r in s.reqs.iter_mut() {
            if matches!(r.state, RState::Queued | RState::Delivered | RState::Pending) {
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
