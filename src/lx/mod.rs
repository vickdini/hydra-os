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

pub mod timer;

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::arch::syscall::SyscallFrame;
use crate::ipc::protocol::{
    LxCall, LxCopy, ENDPOINT_LINUX_SERVER, LX_COPY_OFF, LX_DATA_OFF, LX_DATA_SIZE, LX_CALL_INTERRUPTED, LX_CTL_ATTACH, LX_CTL_ONLINE, LX_CTL_WAKE, LX_GROUPS, LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF,
    LX_NOTE_INTERRUPT, LX_NULL_NR, LX_OBJ_FLAGS_AT1, LX_OBJ_FLAGS_NETNS, LX_REPLY_NONE, LX_REPLY_PENDING, NOTIFY_LX_NOTES,
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
/// The calls step 4 moves (wave 5, Group 13), with their table bits: eventfd, eventfd2.
/// (Calls on a moved descriptor reach the server through the descriptor: `read`, `write`,
/// `ioctl`, the socket calls; `socket`/`socketpair` by family.)
pub const MOVED_STEP4: &[(u64, u8)] = &[(284, 0), (290, 0), (22, 0), (293, 0), (434, 0), (282, T_FD0), (289, T_FD0), (283, 0), (286, T_FD0), (287, T_FD0)];
/// Step 4's descriptors are made by the server (`lx=kernel` turns it off with the rest).
pub static STEP4: AtomicBool = AtomicBool::new(false);

/// Whether step 4's descriptors (Unix sockets, pipes, eventfd, timerfd, signalfd, pidfd)
/// are the server's: the kernel's dispatchers send the calls that make them there.
pub fn step4() -> bool {
    STEP4.load(Ordering::Relaxed) && ONLINE.load(Ordering::Acquire)
}

/// The boot entry asked for the in-kernel code (`lx=kernel`).
pub static KERNEL_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);

// ----------------------------------------------------------------------
// Socket routing (Group 12, wave 5): by address family and by descriptor kind
// ----------------------------------------------------------------------
//
// The socket calls cannot be routed by their number alone: `socket(AF_INET, ..)` belongs
// to the server once Internet sockets moved, `socket(AF_UNIX, ..)` to the kernel until Unix
// sockets move; `sendmsg(fd, ..)` belongs to whoever owns `fd`. Two table bits say so:
//
// - [`T_FAMILY`] (`socket`, `socketpair`): the server answers iff the address family in
//   `args[0]` is in [`FAMILIES`] (filled from [`MOVED_FAMILIES`]) and the server is online;
//   otherwise the kernel's dispatcher runs as before.
// - [`T_BYFD`] (the calls on a socket descriptor, [`BYFD_NUMBERS`]): the server answers iff
//   descriptor `args[0]` holds a server object; the call then carries the object exactly as
//   with [`T_FD0`]. Any other descriptor (a kernel socket, a file, a bad number) goes to the
//   kernel, which answers as before. The test is cheap: the descriptor table's lock-free
//   bitmap of server objects (`FdTable::srv_bits`), reached through a per-CPU cache, so a
//   call on a kernel descriptor costs a bit test and no lock.
//
// [`route`] still says `Server` for these numbers; [`forward`] and [`fast_entry`] make the
// per-call decision. The server dispatches the same way (`linux-server/src/socket.rs`: by
// family, then by the object's kind).

/// Table bit (Group 12): `socket`/`socketpair`: the server answers iff the family in
/// `args[0]` moved ([`FAMILIES`]).
const T_FAMILY: u8 = 32;
/// Table bit (Group 12): the server answers iff descriptor `args[0]` holds a server object
/// (which the call then carries, as with [`T_FD0`]); otherwise the kernel.
const T_BYFD: u8 = 64;
/// The address families whose `socket`/`socketpair` go to a server (bit `f` = family `f`).
static FAMILIES: AtomicU64 = AtomicU64::new(0);
/// Per address family: the server that answers its `socket`/`socketpair` (a [`Target`];
/// 0 while it is the kernel's). Only [`TARGET_LINUX`] exists today; a later step that
/// splits the Linux layer into several services gives a family another target here
/// (decision 9) without changing the routing itself.
static FAMILY_TARGET: [AtomicU8; 64] = [const { AtomicU8::new(0) }; 64];
/// A routing target: which server answers (0: the kernel).
pub type Target = u8;
/// The target linux-server (endpoint `ENDPOINT_LINUX_SERVER`).
pub const TARGET_LINUX: Target = 1;
/// The address families that moved to a server, with their target: one line per step.
pub const MOVED_FAMILIES: &[(u64, Target)] = &[
    // Group 12 (step 3): AF_INET, AF_INET6, AF_NETLINK
    (2, TARGET_LINUX),
    (10, TARGET_LINUX),
    (16, TARGET_LINUX),
    // Group 13 (step 4): AF_UNIX
    (1, TARGET_LINUX),
];
/// `socket`, `socketpair`: routed by family.
pub const BYFAMILY_NUMBERS: [u64; 2] = [41, 53];
/// The calls on a socket descriptor, routed by the descriptor: connect, accept, sendto,
/// recvfrom, sendmsg, recvmsg, shutdown, bind, listen, getsockname, getpeername,
/// setsockopt, getsockopt, accept4, recvmmsg, sendmmsg.
pub const BYFD_NUMBERS: &[u64] = &[42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 288, 299, 307];
/// Group 13: `read`, `write`, `readv`, `writev`, routed by descriptor like [`BYFD_NUMBERS`]
/// but decided only by the lock-free test (when it cannot be made, the kernel's
/// `vfs::stream_io` forwards a server object's call itself, under the kernel lock).
pub const BYFD_IO_NUMBERS: [u64; 4] = [0, 1, 19, 20];
/// Group 13, per CPU: the thread whose current `read`/`write` the lock-free entry found to
/// be on a kernel descriptor (`forward` then skips the test; a stale mark only sends a
/// call to the kernel's `vfs::stream_io`, which forwards a server object's call itself).
static IO_KERNEL: [AtomicU64; crate::arch::smp::MAX_CPUS] = [const { AtomicU64::new(0) }; crate::arch::smp::MAX_CPUS];

/// Group 13: `bind` and `connect` on a Unix socket of the server go through the kernel's
/// dispatcher first (`ServerObject::socket_call`): a path name's node is made or checked
/// in the caller's context there (the temporary `vfs_resolve` of step 4).
fn kernel_first(nr: u64, dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>) -> bool {
    (nr == 42 || nr == 49) && dev.as_server().is_some_and(|o| o.kind() == crate::ipc::protocol::LX_OBJ_KIND_UNIX)
}

/// Whether `socket`/`socketpair` of address family `family` go to the server.
pub fn family_moved(family: u64) -> bool {
    family < 64 && FAMILIES.load(Ordering::Relaxed) & (1 << family) != 0
}

/// The server that answers `socket`/`socketpair` of address family `family` (0: the kernel).
pub fn family_target(family: u64) -> Target {
    if family_moved(family) {
        FAMILY_TARGET[family as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

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
        "[lx] add_key, request_key, keyctl, mq_*, sem*, msg*, bpf, AF_INET/AF_INET6/AF_NETLINK/AF_UNIX sockets, eventfd, pipes, pidfd, signalfd, timerfd: {}",
        if kernel { "in the kernel (switched back: lx=kernel)" } else { "forwarded to linux-server" }
    );
}

/// Routes the moved calls to the server (`true`) or to the in-kernel code.
pub fn set_forwarding(on: bool) {
    for nr in MOVED {
        TABLE[nr as usize].store(on as u8, Ordering::Release);
    }
    for &(nr, bits) in MOVED_STEP2.iter().chain(MOVED_STEP4) {
        TABLE[nr as usize].store(if on { T_SERVER | bits } else { 0 }, Ordering::Release);
    }
    STEP4.store(on, Ordering::Release);
    // Socket routing (Group 12): the per-call bits only once some family moved, so that
    // nothing changes for the socket calls before
    let families = if on { MOVED_FAMILIES.iter().fold(0u64, |m, &(f, _)| m | 1 << f) } else { 0 };
    for &(f, t) in MOVED_FAMILIES {
        FAMILY_TARGET[f as usize].store(if on { t } else { 0 }, Ordering::Release);
    }
    FAMILIES.store(families, Ordering::Release);
    let sockets = families != 0;
    for nr in BYFAMILY_NUMBERS {
        TABLE[nr as usize].store(if sockets { T_SERVER | T_FAMILY } else { 0 }, Ordering::Release);
    }
    for &nr in BYFD_NUMBERS {
        TABLE[nr as usize].store(if sockets { T_SERVER | T_BYFD } else { 0 }, Ordering::Release);
    }
    // Group 13: read, write, readv, writev on server objects (pipes, Unix sockets, eventfd,
    // ...) take the lock-free path too; on any other descriptor they cost one bit test
    for nr in BYFD_IO_NUMBERS {
        TABLE[nr as usize].store(if on { T_SERVER | T_BYFD } else { 0 }, Ordering::Release);
    }
    NULL_TO_SERVER.store(on, Ordering::Release);
}

/// The table byte of system call `nr` (0: the kernel answers it).
#[inline]
fn table_bits(nr: u64) -> u8 {
    if (nr as usize) < TABLE_LEN {
        TABLE[nr as usize].load(Ordering::Relaxed)
    } else {
        0
    }
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
        Route::Server => {
            let bits = table_bits(nr);
            if bits & (T_FAMILY | T_BYFD) != 0 {
                // Routed per call (Group 12): while no server is online, sockets are the
                // kernel's (and no descriptor holds a live server object)
                if !ONLINE.load(Ordering::Acquire) || (bits & T_FAMILY != 0 && family_target(frame.rdi) != TARGET_LINUX) {
                    return None;
                }
                if bits & T_BYFD != 0 {
                    let o = if BYFD_IO_NUMBERS.contains(&nr) {
                        // (no locks for every read and write: the fast test or the kernel;
                        // `fast_entry` may have made it already for this very call)
                        let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
                        let tid = crate::task::CURRENT_TID.load(Ordering::Relaxed);
                        if tid != 0 && IO_KERNEL[cpu].swap(0, Ordering::Relaxed) == tid {
                            return None;
                        }
                        x86_64::instructions::interrupts::without_interrupts(|| ident().and_then(|id| byfd_fast(&id, frame.rdi).ok().flatten()))?
                    } else {
                        byfd_object(frame.rdi)?
                    };
                    if kernel_first(nr, &o.0) {
                        return None;
                    }
                    return Some(call(frame, Some(o)));
                }
            }
            if !ONLINE.load(Ordering::Acquire) {
                return Some(ENOSYS);
            }
            Some(call(frame, None))
        }
    }
}

/// The server object at descriptor `fd` of the calling thread (for a [`T_BYFD`] call on the
/// path under the kernel lock), `None` if `fd` holds anything else: through this CPU's
/// cached table and its bitmap when the identity cache serves the thread, otherwise with
/// the table's lock.
fn byfd_object(fd: u64) -> Option<(Arc<dyn crate::compat::linux::chardev::CharDevice>, u64, u64)> {
    let fast = x86_64::instructions::interrupts::without_interrupts(|| {
        let id = ident()?;
        byfd_fast(&id, fd).ok()
    });
    match fast {
        Some(r) => r,
        None => obj::current_fd(fd),
    }
}

/// The lock-free decision for a [`T_BYFD`] call (interrupts off): `Ok(None)` the kernel
/// answers (`fd` holds no server object), `Ok(Some(object))` the server does, `Err(())` it
/// cannot be told without waiting for a lock (the caller takes the ordinary path).
fn byfd_fast(id: &Ident, fd: u64) -> Result<Option<(Arc<dyn crate::compat::linux::chardev::CharDevice>, u64, u64)>, ()> {
    // Group 13: a cached table whose bit is clear says "the kernel" without touching the
    // table's reference count (every read and write of a kernel descriptor comes here). The
    // cache is this thread's table while its identity is unchanged (exec and unshare bump
    // the epoch), and the running thread holds that table, so its bits are alive.
    {
        let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
        // SAFETY: this CPU's own entry, interrupts off
        let e = unsafe { &*FDS.0[cpu].get() };
        if e.0 == id.tid && e.1 == id.epoch && e.3 != 0 {
            // SAFETY: see above
            let maybe = unsafe { &*(e.3 as *const crate::fs::SrvPtr) }.get().is_some_and(|b| b.maybe(fd));
            if !maybe {
                return Ok(None);
            }
        }
    }
    let (fds, srv) = cached_fds(id).ok_or(())?;
    // SAFETY: the bits live as long as the table, which `fds` holds
    let maybe = unsafe { &*srv }.get().is_some_and(|b| b.maybe(fd));
    let r = if !maybe {
        Ok(None)
    } else {
        match fds.try_lock() {
            Some(t) => Ok(obj::object_in(&t, fd)),
            None => Err(()),
        }
    };
    drop_last(fds);
    r
}

/// Per CPU (interrupts off): the descriptor table of the thread whose identity [`IDENT`]
/// holds, as a `Weak` (a cache must not keep a dead process's descriptors open) and the
/// address of its server-object bits. Valid while that identity is (exec and unshare,
/// which can give a thread another table, bump the identity epoch).
struct FdsCache([UnsafeCell<(u64, u64, alloc::sync::Weak<Mutex<crate::fs::FdTable>>, usize)>; crate::arch::smp::MAX_CPUS]);
// SAFETY: each CPU touches only its own entry, with interrupts off
unsafe impl Sync for FdsCache {}
static FDS: FdsCache = FdsCache([const { UnsafeCell::new((0, 0, alloc::sync::Weak::new(), 0)) }; crate::arch::smp::MAX_CPUS]);

/// The calling thread's descriptor table and the address of its server-object bits, from
/// this CPU's cache (`id` is its identity from [`ident`]); `None` if the table cannot be
/// had without waiting. Interrupts off.
fn cached_fds(id: &Ident) -> Option<(crate::fs::SharedFdTable, *const crate::fs::SrvPtr)> {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    // SAFETY: this CPU's own entry, interrupts off
    let e = unsafe { &mut *FDS.0[cpu].get() };
    if e.0 == id.tid && e.1 == id.epoch && e.3 != 0 {
        if let Some(t) = e.2.upgrade() {
            return Some((t, e.3 as *const crate::fs::SrvPtr));
        }
    }
    let fds = crate::task::SCHEDULER.lock().current_fds()?;
    let srv = fds.try_lock().map(|t| t.srv_bits() as *const crate::fs::SrvPtr as usize);
    let Some(srv) = srv else {
        drop_last(fds);
        return None;
    };
    let old = core::mem::replace(e, (id.tid, id.epoch, Arc::downgrade(&fds), srv));
    drop(old);
    Some((fds, srv as *const crate::fs::SrvPtr))
}

/// Forwards system call `nr` with `args` made on server object `dev` (a descriptor's
/// device; `args[0]` is the descriptor): `read`, `write`, `readv`, `writev` and `ioctl` on
/// it (wave 4, step 2). A stale object (its server went away) gives `-EBADF`.
pub fn call_obj(nr: u64, args: [u64; 6], dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>) -> i64 {
    call_obj_ino(nr, args, dev, 0)
}

/// [`call_obj`] with [`LxCall::ino`] (Group 13: the socket node of `bind`/`connect`).
pub fn call_obj_ino(nr: u64, args: [u64; 6], dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, ino: u64) -> i64 {
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
    c.ino = ino;
    call_ident(c, false)
}

/// Forwards call `nr` with `args` (no descriptor object) on behalf of the current thread:
/// the kernel's dispatchers route `socket`/`socketpair` by family and `pipe` this way, and
/// kernel code asks for server objects with the `LX_KCALL_*` numbers (Group 13). The
/// caller holds the kernel lock (an ordinary system call path).
pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    if !ONLINE.load(Ordering::Acquire) {
        return ENOSYS;
    }
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = args;
    call_ident(c, false)
}

/// A transfer between the server object `dev` and a kernel buffer (Group 13: `splice`,
/// `sendfile`, io_uring, aio's eventfd): `read` (`out` is filled) or `write` (`data` is
/// sent) of at most the copy area's size, never blocking: `-EAGAIN` when the object is
/// not ready (the caller waits on its readiness itself). The server posts no `SIGPIPE`.
/// The caller holds the kernel lock.
pub fn call_obj_kbuf(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, write: bool, data: &[u8], out: &mut [u8]) -> i64 {
    use crate::ipc::protocol::{LX_KBUF_ADDR, LX_OBJ_FLAGS_KBUF};
    let Some(o) = dev.as_server() else { return EBADF };
    let Some(slot) = o.slot() else { return EBADF };
    if !ONLINE.load(Ordering::Acquire) {
        return EBADF;
    }
    let n = if write { data.len() } else { out.len() }.min(LX_DATA_SIZE);
    let mut c = LxCall::EMPTY;
    c.nr = if write { 1 } else { 0 };
    c.args = [u64::MAX, LX_KBUF_ADDR, n as u64, 0, 0, 0];
    c.obj = slot;
    c.obj_flags = o.flags() | LX_OBJ_FLAGS_KBUF | 0o4000;
    let mut buf = copy::CopyBuf::EMPTY;
    if write {
        buf.data[..n].copy_from_slice(&data[..n]);
        buf.used = n;
        buf.hdr.in_off[1] = LX_DATA_OFF as u16;
        buf.hdr.in_len[1] = n as u16;
    } else {
        buf.used = n;
        buf.hdr.out_off[1] = LX_DATA_OFF as u16;
        buf.hdr.out_cap[1] = n as u16;
    }
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
    c.note_seq = notes_head();
    let kout = if write { None } else { Some(&mut out[..n]) };
    let r = x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(me, my_idx, c, copy::Src::Kernel(&buf), true, kout));
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    r
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
    /// Group 12: `SYS_LX_COMPLETE` came while the call was still being served (the server
    /// kept it as waiting and another of its threads finished it before the worker's
    /// "pending" answer reached the kernel): `result` holds the answer, and the "pending"
    /// answer turns into it.
    early: bool,
}

impl Req {
    const FREE: Self = Self { state: RState::Free, id: 0, client: 0, client_idx: 0, result: 0, interrupted: false, has_copy: false, early: false };
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

    // wave6 G22 begin
    /// Its syscall page's copy area (the copy-in table fills it straight from the caller's
    /// memory while the worker is idle: it reads the page only after `deliver`).
    #[allow(clippy::mut_from_ref)]
    fn data_mut(&self) -> &mut [u8; LX_DATA_SIZE] {
        // SAFETY: the page is the worker's own and stays allocated while it is in the table;
        // the copy area lies within it; only the request table's lock holder writes it
        unsafe { &mut *((crate::memory::frame_allocator::phys_to_virt(self.page.base) as *mut u8).add(LX_DATA_OFF) as *mut [u8; LX_DATA_SIZE]) }
    }
    // wave6 G22 end
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

/// Delivers request `slot` (its call is `call`, its copy header `hdr`) to worker `wi`: the
/// call goes into the worker's syscall page, with the copy header (empty without copies)
/// and the copied-in bytes `data` (`None`: already in the page, Group 22).
fn deliver(s: &mut Lx, slot: usize, wi: usize, call: &LxCall, hdr: &LxCopy, data: Option<&[u8]>) {
    s.reqs[slot].state = RState::Delivered;
    let w = &mut s.workers[wi];
    let page = w.call_mut() as *mut u8;
    // SAFETY: the page is the worker's own and stays allocated while it is in the table;
    // the header and the copy area lie within it
    unsafe {
        core::ptr::write_volatile(w.call_mut(), *call);
        let mut h = *hdr;
        h.out_len = [0; 6];
        core::ptr::write_volatile(page.add(LX_COPY_OFF) as *mut LxCopy, h);
        if let Some(data) = data {
            core::ptr::copy_nonoverlapping(data.as_ptr(), page.add(LX_DATA_OFF), data.len().min(LX_DATA_SIZE));
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
            let b = &*buf_of(slot);
            let (hdr, data) = if s.reqs[slot].has_copy { (b.hdr, Some(b.used_bytes())) } else { (LxCopy::EMPTY, None) };
            deliver(s, slot, wi, &call, &hdr, data);
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
fn call(frame: &SyscallFrame, byfd: Option<(Arc<dyn crate::compat::linux::chardev::CharDevice>, u64, u64)>) -> i64 {
    let mut c = LxCall::EMPTY;
    c.nr = frame.rax;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    let bits = table_bits(c.nr);
    // Group 9: the server object at args[0], held until the call is answered (a close on
    // another thread cannot overtake the call); Group 12: a T_BYFD call's, found already
    if bits & (T_FAMILY | T_BYFD) != 0 && crate::compat::linux::ns::net_isolated() {
        c.obj_flags |= LX_OBJ_FLAGS_NETNS;
    }
    let _held = if let Some((dev, slot, flags)) = byfd {
        c.obj = slot;
        c.obj_flags |= flags;
        Some(dev)
    } else if bits & T_FD0 != 0 {
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
    // wave6 G22 begin: the copy-in table: the call's pointer arguments are copied when the
    // call is placed, straight into the worker's page (`place`; a bad one fails there)
    let copies = match copy::describe(c.nr, &c.args) {
        Some(desc) => copy::Src::User(desc),
        None => copy::Src::None,
    };
    // wave6 G22 end
    // Interrupts stay off from handing the call over until the answer is taken: nothing on
    // this CPU may come between (the yields switch with them off, and they come back so)
    loop {
        let r = x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(me, my_idx, c, copies, nobkl, None));
        // A net wait ended (Group 12): the same call again, at once
        if r != crate::ipc::protocol::LX_RETRY {
            return r;
        }
        NET_RETRIES.fetch_add(1, Ordering::Relaxed);
        c.note_seq = notes_head();
        c.flags |= crate::ipc::protocol::LX_CALL_RETRIED;
    }
}

// ----------------------------------------------------------------------
// Net waits (Group 12, wave 5): blocked socket calls woken by net-server's doorbell
// ----------------------------------------------------------------------
//
// A socket call linux-server cannot answer yet (nothing to receive, no connection to
// accept, a connect in progress, no room to send) registers the net-server handle it waits
// on (`LX_OBJ_NETWAIT`) and is answered "pending". When net-server's doorbell lists that
// handle, the kernel's hook ([`net_event`]) completes the request with `LX_RETRY` and the
// caller makes the same call again ([`call_with`]): one wake-up, as when the sockets were the
// kernel's, instead of a hop through linux-server's main thread. No wake-up is lost: the
// registration compares the handle's readiness word with the one the server saw under the
// same lock the hook takes, and net-server writes the word before it lists the handle.

/// linux-server's main thread needs net-server's events (`LX_OBJ_RELAY`): it keeps calls
/// waiting with a deadline or with part of their work done.
static RELAY_SERVER: AtomicBool = AtomicBool::new(false);
/// Internet sockets someone waits on in `poll`/`select`/`epoll` (their readiness words must
/// follow net-server's): counted once per object ([`obj`]).
pub static WATCHED_NET: AtomicU64 = AtomicU64::new(0);

/// Whether net-server's doorbell must reach linux-server's main thread: it relays readiness
/// to the words of watched sockets and tries its own waiting calls again. Without either,
/// the words of sockets nobody polls may lag; the main thread catches up from net-server's
/// event ring when the relay is wanted again ([`relay_on`]).
pub fn relay_wanted() -> bool {
    RELAY_SERVER.load(Ordering::Acquire) || WATCHED_NET.load(Ordering::Acquire) != 0
}

/// The relay is wanted again: the main thread takes the events it missed now.
pub fn relay_on() {
    crate::ipc::service::notify(ENDPOINT_LINUX_SERVER, crate::ipc::protocol::NOTIFY_LX_NET);
}

/// `LX_OBJ_RELAY(on)`: linux-server keeps calls that need the relay (`on`) or none any more.
pub fn set_relay(on: bool) -> i64 {
    if !RELAY_SERVER.swap(on, Ordering::AcqRel) && on {
        relay_on();
    }
    0
}

/// Registered net waits: `(net-server handle, request id)`.
static NETWAITS: Mutex<alloc::vec::Vec<(u32, u64)>> = Mutex::new(alloc::vec::Vec::new());
/// Calls made again after a net wait ended.
pub static NET_RETRIES: AtomicU64 = AtomicU64::new(0);

fn netwaits<R>(f: impl FnOnce(&mut alloc::vec::Vec<(u32, u64)>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut NETWAITS.lock()))
}

/// `LX_OBJ_NETWAIT(id, handle, word)`: 1 if the word changed (try again), 0 registered.
pub fn netwait(id: u64, handle: u32, word: u64) -> i64 {
    if client_of(id).is_none() {
        return ESRCH;
    }
    netwaits(|w| {
        if crate::net::client::raw_word(handle) != word {
            return 1;
        }
        // Waits whose call ended otherwise (its process went) are dropped now and then
        if w.len() >= 256 {
            w.retain(|&(_, i)| client_of(i).is_some());
        }
        w.push((handle, id));
        0
    })
}

/// `LX_OBJ_NETCANCEL(id)`: 1 if request `id`'s net wait was still registered.
pub fn netcancel(id: u64) -> i64 {
    netwaits(|w| {
        let before = w.len();
        w.retain(|&(_, i)| i != id);
        (w.len() != before) as i64
    })
}

/// net-server listed `handles` in its event ring (`None`: anything may have changed, or it
/// went away): the requests waiting on them are made again.
pub fn net_event(handles: Option<&[u32]>) {
    let ids: alloc::vec::Vec<u64> = netwaits(|w| {
        let mut out = alloc::vec::Vec::new();
        if w.is_empty() {
            return out;
        }
        w.retain(|&(h, i)| {
            if handles.is_none_or(|hs| hs.contains(&h)) {
                out.push(i);
                false
            } else {
                true
            }
        });
        out
    });
    for id in ids {
        complete_as_kernel(id, crate::ipc::protocol::LX_RETRY);
    }
}

// wave6 G22 begin
/// Places call `c` of task `me` in the request table `s`: a free slot, an id, and an idle
/// worker that takes it at once (its page gets the call, and the user copies straight from
/// the caller's memory), or the queue (the copies wait in the slot's buffer). `Err`: the
/// copies need a page faulted in first, or a pointer is bad (nothing changed); `Ok(Err)`:
/// the call cannot be placed.
#[allow(clippy::type_complexity)]
fn place(s: &mut Lx, me: u64, my_idx: usize, c: &mut LxCall, copies: copy::Src<'_>) -> Result<Result<(usize, u64, Option<(u64, usize)>), i64>, copy::FillErr> {
    // Checked under the table's lock: `server_gone` clears ONLINE before it takes the
    // lock, so a call placed here is either failed by it or refused now
    if !ONLINE.load(Ordering::Acquire) {
        return Ok(Err(ENOSYS));
    }
    let Some(slot) = s.reqs.iter().position(|r| r.state == RState::Free) else { return Ok(Err(EAGAIN)) };
    // An idle worker takes it at once
    let wi = s.workers.iter().position(|w| w.idle);
    // The copies first (nothing is changed yet when they fail): user memory straight into
    // the idle worker's page (it reads the page only once the call is delivered), or into
    // the free slot's buffer (nobody else uses a free slot's buffer)
    let (hdr, used) = match copies {
        copy::Src::None => (LxCopy::EMPTY, 0),
        copy::Src::Kernel(b) => (b.hdr, b.used),
        copy::Src::User(desc) => {
            let data = match wi {
                Some(wi) => s.workers[wi].data_mut(),
                None => &mut buf_of(slot).data,
            };
            let mut h = LxCopy::EMPTY;
            let n = copy::fill(&mut h, data, desc, &c.args)?;
            (h, n)
        }
    };
    let has_copy = !matches!(copies, copy::Src::None);
    let id = s.next_id;
    s.next_id += 1;
    c.id = id;
    s.reqs[slot] = Req { state: RState::Queued, id, client: me, client_idx: my_idx, result: 0, interrupted: false, has_copy, early: false };
    REQ_DONE[slot].store(false, Ordering::SeqCst);
    if has_copy {
        let kept = buf_of(slot);
        kept.hdr = hdr;
        kept.used = used;
    }
    let target = match wi {
        Some(wi) => {
            let data = if let copy::Src::Kernel(b) = copies { Some(b.used_bytes()) } else { None };
            deliver(s, slot, wi, c, &hdr, data);
            Some((s.workers[wi].task, s.workers[wi].idx))
        }
        None => {
            s.calls[slot] = *c;
            // Its bytes wait with it (the caller's memory is not reachable from the worker
            // that takes it); user copies are there already
            if let copy::Src::Kernel(b) = copies {
                buf_of(slot).data[..b.used].copy_from_slice(b.used_bytes());
            }
            None
        }
    };
    Ok(Ok((slot, id, target)))
}
// wave6 G22 end

/// [`call_with`] with its copies `copies` (user copies are made when the call is placed).
/// `kout`: a kernel-buffer read ([`call_obj_kbuf`]): the output to `args[1]` goes there
/// instead of to user memory.
fn call_and_wait(me: u64, my_idx: usize, mut c: LxCall, copies: copy::Src<'_>, nobkl: bool, kout: Option<&mut [u8]>) -> i64 {
    // wave6 G22 begin: a page of a pointer argument not there yet is faulted in with the
    // table's lock let go, and the call placed again (a page that faults again at once, or
    // that cannot be faulted in, is a bad pointer)
    let mut last_missing = u64::MAX;
    let mut tries = 0;
    let placed = loop {
        match lx(|s| place(s, me, my_idx, &mut c, copies)) {
            Ok(p) => break p,
            Err(copy::FillErr::Missing(at, len)) => {
                tries += 1;
                if tries > 16 || at & !0xFFF == last_missing || !copy::fault_in(at, len, false) {
                    return EFAULT;
                }
                last_missing = at & !0xFFF;
            }
            Err(copy::FillErr::Fault) => return EFAULT,
        }
    };
    // wave6 G22 end
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
    wait_for(slot, id, &c.args, (c.tid, c.tgid), nobkl, kout)
}

/// Waits for the answer to request `id` (in `slot`), copies its output to the caller's
/// pointers `args` (the copy-out table), and frees it.
///
/// No wake-up is lost: the answer is marked under the table's lock and the caller woken
/// after it, and the caller blocks only under the same lock after seeing no answer.
fn wait_for(slot: usize, id: u64, args: &[u64; 6], who: (u64, u64), nobkl: bool, kout: Option<&mut [u8]>) -> i64 {
    let mut kout = kout;
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
            let r = if let Some(k) = kout.as_deref_mut() {
                // A kernel-buffer read: the bytes for args[1]
                let b = buf_of(slot);
                let n = (b.hdr.out_len[1] as usize).min(k.len());
                if n > 0 {
                    let o = b.hdr.out_off[1] as usize - LX_DATA_OFF;
                    k[..n].copy_from_slice(&b.data[o..o + n]);
                }
                v
            } else {
                match copy::copy_out(buf_of(slot), args) {
                    Ok(()) => v,
                    Err(e) => e,
                }
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
    /// The process is in a network namespace of its own (`ns::net_isolated`; unshare and
    /// setns bump the identity epoch).
    net: bool,
}

/// Per CPU, used only by that CPU with interrupts off.
struct IdentCache([UnsafeCell<Ident>; crate::arch::smp::MAX_CPUS]);
// SAFETY: each CPU touches only its own entry, with interrupts off
unsafe impl Sync for IdentCache {}
static IDENT: IdentCache = IdentCache(
    [const { UnsafeCell::new(Ident { epoch: 0, tid: 0, tgid: 0, ids: [0; 6], caps: 0, ngroups: 0, groups: [0; LX_GROUPS], ipc_ns: 0, net: false }) }; crate::arch::smp::MAX_CPUS],
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
    let mut n = Ident { epoch, tid, tgid, ids, caps, ngroups: 0, groups: [0; LX_GROUPS], ipc_ns: 0, net: false };
    // (never waiting for the process table: see `fast_entry`)
    let procs = crate::compat::linux::proc::PROCS.try_lock()?;
    if let Some(p) = procs.get(&tgid) {
        let k = p.groups.len().min(LX_GROUPS);
        n.groups[..k].copy_from_slice(&p.groups[..k]);
        n.ngroups = k as u64;
        n.ipc_ns = p.ns.ipc;
        n.net = p.ns.net != 0;
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
    // Group 13: read/write on a kernel descriptor, decided first and cheaply (this CPU's
    // cached descriptor table of this thread, its server-object bit clear)
    if nr <= 20 && BYFD_IO_NUMBERS.contains(&nr) {
        let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
        let tid = crate::task::CURRENT_TID.load(Ordering::Relaxed);
        // SAFETY: this CPU's own entry, interrupts off
        let e = unsafe { &*FDS.0[cpu].get() };
        if tid != 0 && e.0 == tid && e.1 == crate::compat::linux::ident_epoch() && e.3 != 0 {
            // SAFETY: the running thread holds that table (see `byfd_fast`)
            let maybe = unsafe { &*(e.3 as *const crate::fs::SrvPtr) }.get().is_some_and(|b| b.maybe(frame.rdi));
            if !maybe {
                IO_KERNEL[cpu].store(tid, Ordering::Relaxed);
                return None;
            }
        }
    }
    if route(nr) != Route::Server
        || !ONLINE.load(Ordering::Acquire)
        || crate::compat::linux::TRACE_SYSCALLS.load(Ordering::Relaxed)
        || crate::task::scheduler::handoff_active()
    {
        return None;
    }
    let id = ident()?;
    let bits = table_bits(nr);
    // Group 12: socket calls routed per call (see "Socket routing"); a kernel one takes the
    // ordinary path, whose `forward` finds it the kernel's again (one more bit test).
    // (Group 13: decided before the call is built: read and write on kernel descriptors
    // pass here too)
    if bits & T_FAMILY != 0 && family_target(frame.rdi) != TARGET_LINUX {
        return None;
    }
    let mut byfd = None;
    if bits & T_BYFD != 0 {
        match byfd_fast(&id, frame.rdi) {
            Ok(Some((dev, _, _))) if kernel_first(nr, &dev) => {
                drop_last(dev);
                return None;
            }
            Ok(Some(o)) => byfd = Some(o),
            Ok(None) => {
                // (Group 13: `forward` need not test a read or write again)
                if BYFD_IO_NUMBERS.contains(&nr) {
                    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
                    IO_KERNEL[cpu].store(id.tid, Ordering::Relaxed);
                }
                return None;
            }
            Err(()) => return None,
        }
    }
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
    let mut held: [Option<Arc<dyn crate::compat::linux::chardev::CharDevice>>; 2] = [None, None];
    if let Some((dev, slot, flags)) = byfd {
        c.obj = slot;
        c.obj_flags = flags;
        held[0] = Some(dev);
    }
    if bits & (T_FAMILY | T_BYFD) != 0 && id.net {
        c.obj_flags |= LX_OBJ_FLAGS_NETNS;
    }
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
    ) + &copy_summary()
}

// wave6 G22 begin
/// The user copies' faults: resumed at a fix-up, and pages faulted in for the copies.
fn copy_summary() -> alloc::string::String {
    alloc::format!(
        "; copies: {} faults fixed up, {} fault-ins",
        crate::arch::idt::UACCESS_FAULTS.load(Ordering::Relaxed),
        copy::FAULT_INS.load(Ordering::Relaxed)
    )
}
// wave6 G22 end

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
                    if flags & LX_REPLY_PENDING != 0 && !r.early {
                        r.state = RState::Pending;
                        // Group 9: a signal that came while the call was served is told now
                        // (the caller already marked it and will not tell again)
                        if r.interrupted {
                            interrupted = r.id;
                        }
                    } else {
                        r.state = RState::Done;
                        if !r.early {
                            r.result = result;
                        }
                        REQ_DONE[cur].store(true, Ordering::SeqCst);
                        wake = (r.client, r.id, r.client_idx);
                        // The output the server left in the page (copy-out table; a call
                        // completed early wrote its output itself)
                        if r.has_copy && !r.early {
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
    complete_as_kernel(id, result)
}

/// [`complete`] without the check that the server calls it (the net-server doorbell hook).
fn complete_as_kernel(id: u64, result: i64) -> i64 {
    let client = lx(|s| {
        // Still being served (its "pending" answer not given yet): kept for that answer
        if let Some(r) = s.reqs.iter_mut().find(|r| r.id == id && r.state == RState::Delivered && !r.early) {
            r.early = true;
            r.result = result;
            return Some(0);
        }
        let slot = s.reqs.iter().position(|r| r.id == id && r.state == RState::Pending)?;
        REQ_DONE[slot].store(true, Ordering::SeqCst);
        let r = &mut s.reqs[slot];
        r.state = RState::Done;
        r.result = result;
        Some(r.client)
    });
    let Some(client) = client else { return EINVAL };
    if client == 0 {
        return 0;
    }
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
    // Group 13: a page a userfaultfd handler must supply first, as for the caller's own
    // kernel accesses (`prefault_current`): wait for it, or EFAULT (UFFD_USER_MODE_ONLY)
    if crate::compat::linux::userfaultfd::active() {
        use crate::compat::linux::userfaultfd::{wait_fault, Waited};
        loop {
            let id = mm.lock().uffd_missing(addr);
            let Some(id) = id else { break };
            match wait_fault(id, addr & !0xFFF, write, true) {
                Waited::Again => continue,
                Waited::Proceed => break,
                Waited::Refuse => return Err(EFAULT),
            }
        }
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
    if note_quiet(kind, a, b, c) {
        crate::ipc::service::notify(ENDPOINT_LINUX_SERVER, NOTIFY_LX_NOTES);
    }
}

/// [`note`] without waking the main thread (the caller does, once for several); `false`
/// when no server is online.
pub fn note_quiet(kind: u64, a: u64, b: u64, c: u64) -> bool {
    let base = NOTES.load(Ordering::Acquire);
    if base == 0 {
        return false;
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
    true
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
    netwaits(|w| w.clear());
    RELAY_SERVER.store(false, Ordering::Release);
    WATCHED_NET.store(0, Ordering::Release);
    NOTES.store(0, Ordering::Release);
    NOTES_HEAD.store(0, Ordering::Release);
    obj::offline();
    timer::clear();
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

/// `/proc/net/tcp`, `tcp6`, `udp` or `udp6` (Group 12): from linux-server, whose sockets
/// they list, once Internet sockets moved; `None` while they are the kernel's.
pub fn proc_net_text(file: &str) -> Option<alloc::string::String> {
    use crate::ipc::protocol::{LX_PROC_KEYS_TEXT_MAX, LX_PROC_KEYS_TEXT_OFF, MSG_LX_PROC_NET};
    let code = match file {
        "tcp" => 0,
        "tcp6" => 1,
        "udp" => 2,
        "udp6" => 3,
        _ => return None,
    };
    if !family_moved(2) || !is_online() {
        return None;
    }
    let isolated = crate::compat::linux::ns::net_isolated() as u64;
    let _window = crate::ipc::service::hold_window(ENDPOINT_LINUX_SERVER);
    let win = crate::ipc::service::window(ENDPOINT_LINUX_SERVER)?;
    let msg = crate::ipc::Message::with_args(MSG_LX_PROC_NET, [code, isolated, 0, 0]);
    let len = match crate::ipc::service::call(ENDPOINT_LINUX_SERVER, msg, crate::ipc::service::CALL_TIMEOUT_TICKS) {
        Ok(r) if (r.args[0] as i64) >= 0 => (r.args[0] as usize).min(LX_PROC_KEYS_TEXT_MAX),
        _ => return None,
    };
    let text = &win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len];
    Some(alloc::string::String::from_utf8_lossy(text).into_owned())
}

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

/// Group 13: `/proc/net/unix` from the server when Unix sockets are its own (`None`: the
/// in-kernel table answers). A hand-off call, like `/proc/keys`.
pub fn proc_net_unix_text() -> Option<alloc::string::String> {
    use crate::ipc::protocol::{LX_PROC_KEYS_TEXT_MAX, LX_PROC_KEYS_TEXT_OFF, MSG_LX_PROC_NET_UNIX};
    if !step4() {
        return None;
    }
    let _window = crate::ipc::service::hold_window(ENDPOINT_LINUX_SERVER);
    let win = crate::ipc::service::window(ENDPOINT_LINUX_SERVER)?;
    let msg = crate::ipc::Message::with_args(MSG_LX_PROC_NET_UNIX, [0, 0, 0, 0]);
    let len = match crate::ipc::service::call(ENDPOINT_LINUX_SERVER, msg, crate::ipc::service::CALL_TIMEOUT_TICKS) {
        Ok(r) if (r.args[0] as i64) >= 0 => (r.args[0] as usize).min(LX_PROC_KEYS_TEXT_MAX),
        _ => 0,
    };
    let text = &win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len];
    Some(alloc::string::String::from_utf8_lossy(text).into_owned())
}
