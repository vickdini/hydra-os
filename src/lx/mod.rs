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

//!
//! ## Several services (wave 6, Group 19)
//!
//! Since decision 9 the forwarded calls go to *several* services ([`svc`]): each table entry
//! names a service id, and each serving process (a *host*) has its own request table,
//! workers, notification ring and object area. linux-server is the host of every piece not
//! split out yet; the test service (`svc-test`) is a second host. The direct switch and the
//! lock-free path work per host exactly as they did for the one server.

pub mod copy;

pub mod dcall; // wave6 G20
// wave7 G7-2: path calls and the kernel's file handles (the file service)
pub mod fileh;
// wave7 G7-4: the info primitives for the pseudo file systems in linux-server
pub mod info;

pub mod obj;

// wave6 G23 begin
pub mod mem;
// wave6 G23 end
// wave6 G24: lx-sec's kernel side (bpf map element copies)
pub mod sec;

pub mod svc;
// wave7 G7-5 begin: execve's front half and Unix socket names by the services
pub mod xexec;
pub mod xplan;
// wave7 G7-5 end

pub mod timer;

// wave8 GT begin: the terminal service's kernel side (the console terminal, pty opens)
pub mod console;
// wave8 GT end
// wave8 GX2: the desktop after an lx-ipc crash (FailObjects: the session ends, the login
// screen returns)
pub mod desktop;
// wave8 GH begin: device "remove"/"add" announcements around a device service's restart
pub mod hotplug;
pub mod uevent;
// wave8 GH end

// wave6 G21 begin: restart support for every service (design section 5)
pub mod restart;
pub mod restart_policy;

/// Whether calls to service `s` should be made: its host is online, or it is restarting and
/// its callers wait for it (Transparent and FailObjects; never EndLinux).
#[inline]
fn usable(s: SvcId) -> bool {
    svc::online(s) || restart::restarting(svc::host_of(s))
}

/// [`usable`] for host `x`.
#[inline]
fn host_usable(x: &Host) -> bool {
    x.is_online() || restart::restarting(x.id)
}

/// The internal answer of [`call_and_wait`] when the host is not online but restarting: the
/// caller waits for it ([`restart::wait_online`]) and makes the call then. (-4100 is
/// Group 19's `LX_REDIRECTED`.)
const LX_OFFLINE: i64 = -4101;
// wave6 G21 end

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::arch::syscall::SyscallFrame;
use crate::ipc::protocol::{
    lx_req_svc, LxCall, LxCopy, SvcId, LXS_IPC, LXS_LINUX, LXS_NET, LXS_SEC, LXS_TEST, LX_CALL_INTERRUPTED, LX_COPY_OFF, LX_CTL_ATTACH, LX_CTL_OBJAREA, LX_CTL_ONLINE, LX_CTL_WAKE,
    LX_DATA_OFF, LX_DATA_SIZE, LX_GROUPS, LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF, LX_NOTE_INTERRUPT, LX_NULL_NR, LX_OBJ_FLAGS_AT1, LX_OBJ_FLAGS_NETNS, LX_OBJ_NONE,
    LX_REDIRECTED, LX_REDIR_MAX, LX_REPLY_NONE, LX_REPLY_PENDING, LX_REPLY_REDIRECT, LX_REQ_SVC_SHIFT, LX_TEST_NR, NOTIFY_LX_NOTES,
};
use crate::ipc::service::ContiguousFrames;
use crate::task::TaskId;
use svc::{Host, RState, Req, Worker, MAX_REQS, MAX_WORKERS, NONE};

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
const ELOOP: i64 = -40;

/// A server object at a descriptor, held for the length of a forwarded call: the device,
/// its slot, its flags, and the host whose slot it is.
pub(crate) type HeldObj = (Arc<dyn crate::compat::linux::chardev::CharDevice>, u64, u64, SvcId);

// ----------------------------------------------------------------------
// The forwarding table
// ----------------------------------------------------------------------

/// Linux system call numbers the table covers (the rest always run in the kernel).
const TABLE_LEN: usize = 512;
/// The first Hydra-private number with an entry ([`PRIV`]).
pub const PRIV_BASE: u64 = 0x6700;
/// Hydra-private numbers with an entry: `PRIV_BASE..PRIV_BASE + PRIV_LEN`.
const PRIV_LEN: usize = 128;
/// Per Linux system call number: 0 if the kernel answers it; otherwise a service does: the
/// entry's bits say which (`T_SVC_SHIFT`) and what the call carries.
static TABLE: [AtomicU32; TABLE_LEN] = [const { AtomicU32::new(0) }; TABLE_LEN];
/// The entries of Hydra's private numbers (the test calls [`LX_NULL_NR`], [`LX_TEST_NR`]).
static PRIV: [AtomicU32; PRIV_LEN] = [const { AtomicU32::new(0) }; PRIV_LEN];
/// Entry bit: a service answers the call ("not the kernel").
pub const T_SERVER: u32 = 1;
/// Entry bit (Group 9): `args[0]` is a descriptor; the call carries its server object's slot
/// ([`LxCall::obj`]) and holds the descriptor while it is in flight.
pub const T_FD0: u32 = 2;
/// Entry bit (Group 9): the call carries the caller's IPC namespace.
pub const T_IPC: u32 = 4;
/// Entry bit (Group 9): the call carries the caller's umask.
pub const T_UMASK: u32 = 8;
/// Entry bit (Group 9): the u32 that `args[1]` points to is a descriptor (bpf's attribute
/// block starts with one for the map element commands): its server object's slot goes in
/// [`LxCall::obj`], and `obj_flags` gets [`LX_OBJ_FLAGS_AT1`] and the descriptor in bits 32..62
/// (the server uses it only when its own reading of the attribute names the same one).
pub const T_FDAT1: u32 = 16;
/// Entry bit (Group 12): `socket`/`socketpair`: the service is the family's ([`FAMILY_SVC`]).
pub const T_FAMILY: u32 = 32;
/// Entry bit (Group 12): the service is the owner of the server object at descriptor
/// `args[0]` (which the call then carries, as with [`T_FD0`]); otherwise the kernel.
pub const T_BYFD: u32 = 64;
/// Entry bits 8..11: the service that answers a call routed by its number.
pub const T_SVC_SHIFT: u32 = 8;
/// See [`T_SVC_SHIFT`].
pub const T_SVC_MASK: u32 = 0xF00;
/// Entry bit (wave 6): the call carries the caller's context: process group, session,
/// namespace ids (and root and cwd once the kernel has directory handles).
pub const T_FSCTX: u32 = 0x1000;
/// Entry bit (wave 6): the call may be sent again to a restarted service (defined; Group 21
/// decides with its own reviewed list at crash time).
pub const T_IDEMPOTENT: u32 = 0x2000;
/// Entry bit (wave 6, reserved): the service is decided by an argument (bits 16..31).
pub const T_BYARG: u32 = 0x4000;
/// Entry bit (wave 6, informational): the answer may be a redirect (any forwarded call may).
pub const T_REDIR: u32 = 0x8000;

/// The calls step 1 moved to the server: `add_key`, `request_key`, `keyctl` (keys: lx-sec).
pub const MOVED: &[(u64, u32, SvcId)] = &[(248, 0, LXS_SEC), (249, 0, LXS_SEC), (250, 0, LXS_SEC)];
/// The calls step 2 moved (Group 9), with their entry bits and service.
pub const MOVED_STEP2: &[(u64, u32, SvcId)] = &[
    // mq_open, mq_unlink (by name, per IPC namespace)
    (240, T_IPC | T_UMASK, LXS_IPC),
    (241, T_IPC, LXS_IPC),
    // mq_timedsend, mq_timedreceive, mq_notify, mq_getsetattr (on a queue descriptor)
    (242, T_FD0, LXS_IPC),
    (243, T_FD0, LXS_IPC),
    (244, T_FD0, LXS_IPC),
    (245, T_FD0, LXS_IPC),
    // System V semaphores and messages (shared memory stays in the kernel): semget, semop,
    // semctl, semtimedop, msgget, msgsnd, msgrcv, msgctl
    (64, T_IPC, LXS_IPC),
    (65, T_IPC, LXS_IPC),
    (66, T_IPC, LXS_IPC),
    (220, T_IPC, LXS_IPC),
    (68, T_IPC, LXS_IPC),
    (69, T_IPC, LXS_IPC),
    (70, T_IPC, LXS_IPC),
    (71, T_IPC, LXS_IPC),
    // bpf (maps, programs, links: server objects; device programs come back to the kernel)
    (321, T_FDAT1, LXS_SEC),
];
/// The calls step 4 moved (wave 5, Group 13): eventfd, eventfd2, pipe, pipe2, pidfd_open,
/// signalfd, signalfd4, timerfd_create, timerfd_settime, timerfd_gettime. (Calls on a moved
/// descriptor reach the service through the descriptor: `read`, `write`, `ioctl`, the socket
/// calls; `socket`/`socketpair` by family.)
pub const MOVED_STEP4: &[(u64, u32, SvcId)] = &[
    (284, 0, LXS_IPC),
    (290, 0, LXS_IPC),
    (22, 0, LXS_IPC),
    (293, 0, LXS_IPC),
    (434, 0, LXS_IPC),
    (282, T_FD0, LXS_IPC),
    (289, T_FD0, LXS_IPC),
    (283, 0, LXS_IPC),
    (286, T_FD0, LXS_IPC),
    (287, T_FD0, LXS_IPC),
];
/// Hydra's private test calls: linux-server's ([`LX_NULL_NR`]) and the test service's.
pub const MOVED_PRIV: &[(u64, u32, SvcId)] = &[(LX_NULL_NR, 0, LXS_LINUX), (LX_TEST_NR, 0, LXS_TEST), (crate::ipc::protocol::LX_TEST_CTX_NR, T_FSCTX, LXS_TEST)];
// wave7 G7-1 begin
/// vfs-server's private numbers: its walk test call (the caller's context; the root and
/// working directory filled by [`vfs_ctx`] until Group 7-2's fill covers them).
pub const MOVED_PRIV_VFS: &[(u64, u32, SvcId)] = &[(crate::ipc::protocol::LX_VFS_WALK_NR, T_FSCTX, crate::ipc::protocol::LXS_VFS)];

/// The caller's root and working directory for vfs-server (`LxCall::root`/`cwd`): their
/// object numbers in the root's own tree (0: the pool root), `u64::MAX` when they lie in a
/// mount (7-3's tables). Temporary: Group 7-2's fill replaces it.
fn vfs_ctx(c: &mut LxCall) {
    crate::task::with_current_fds_mut(|f| {
        c.root = if f.root_mnt != 0 { u64::MAX } else { f.root_ino };
        c.cwd = if f.cwd_mnt != 0 { u64::MAX } else { f.cwd_ino };
    });
}
// wave7 G7-1 end
/// Step 4's descriptors are made by the server (`lx=kernel` or `lx.ipc=kernel` turn it off).
pub static STEP4: AtomicBool = AtomicBool::new(false);

/// Whether step 4's descriptors (Unix sockets, pipes, eventfd, timerfd, signalfd, pidfd)
/// are the service's: the kernel's dispatchers send the calls that make them there.
pub fn step4() -> bool {
    // (wave6 G21: also while the service restarts: the calls wait for it)
    STEP4.load(Ordering::Relaxed) && usable(LXS_IPC)
}

/// The boot entry asked for the in-kernel code (`lx=kernel`).
pub static KERNEL_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);
/// Everything is answered in the kernel (`lx=kernel`).
static ALL_KERNEL: AtomicBool = AtomicBool::new(false);
/// The boot entry's `lx` words (`lx.<name>=kernel|linux`), kept for [`init`].
static BOOT_WORDS: Mutex<([u8; 256], usize)> = Mutex::new(([0; 256], 0));

/// Whether `lx=kernel` sent every moved call back to the kernel.
pub fn all_kernel() -> bool {
    ALL_KERNEL.load(Ordering::Relaxed)
}

/// The boot entry's option text (`admin::boot`): its words starting with `lx` are kept for
/// [`init`] (the per-service switch-back words, decision 17).
pub fn set_boot_words(text: &[u8]) {
    let mut w = BOOT_WORDS.lock();
    for word in text.split(|c| matches!(c, b' ' | b'\t' | 0)) {
        if word.starts_with(b"lx") && w.1 + word.len() < w.0.len() {
            let n = w.1;
            w.0[n..n + word.len()].copy_from_slice(word);
            w.0[n + word.len()] = b' ';
            w.1 += word.len() + 1;
        }
    }
}

// ----------------------------------------------------------------------
// Socket routing (Group 12, wave 5): by address family and by descriptor kind
// ----------------------------------------------------------------------
//
// The socket calls cannot be routed by their number alone: `socket(AF_INET, ..)` belongs
// to the network service, `socket(AF_UNIX, ..)` to the IPC service, `socket(AF_PACKET, ..)`
// to the kernel; `sendmsg(fd, ..)` belongs to whoever owns `fd`. Two entry bits say so:
//
// - [`T_FAMILY`] (`socket`, `socketpair`): the service is [`FAMILY_SVC`]`[args[0]]` (filled
//   from [`MOVED_FAMILIES`]) if it is online; otherwise the kernel's dispatcher runs.
// - [`T_BYFD`] (the calls on a socket descriptor, [`BYFD_NUMBERS`]): the owner of the server
//   object at descriptor `args[0]` answers; any other descriptor (a kernel socket, a file, a
//   bad number) goes to the kernel. The test is cheap: the descriptor table's lock-free
//   bitmap of server objects (`FdTable::srv_bits`), reached through a per-CPU cache, so a
//   call on a kernel descriptor costs a bit test and no lock.

/// The address families whose `socket`/`socketpair` go to a service (bit `f` = family `f`).
static FAMILIES: AtomicU64 = AtomicU64::new(0);
/// Per address family: the service that answers its `socket`/`socketpair` (0: the kernel).
pub static FAMILY_SVC: [AtomicU8; 64] = [const { AtomicU8::new(0) }; 64];
/// The address families that moved, with their service.
pub const MOVED_FAMILIES: &[(u64, SvcId)] = &[
    // Group 12 (step 3): AF_INET, AF_INET6, AF_NETLINK
    (2, LXS_NET),
    (10, LXS_NET),
    (16, LXS_NET),
    // Group 13 (step 4): AF_UNIX
    (1, LXS_IPC),
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

/// Whether `socket`/`socketpair` of address family `family` go to a service.
pub fn family_moved(family: u64) -> bool {
    family < 64 && FAMILIES.load(Ordering::Relaxed) & (1 << family) != 0
}

/// The service that answers `socket`/`socketpair` of address family `family` (0: the kernel).
#[inline]
pub fn family_svc(family: u64) -> SvcId {
    if family_moved(family) {
        FAMILY_SVC[family as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// Where a forwarded system call is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// The in-kernel code (as before the move).
    Kernel,
    /// A service.
    Server,
}

/// Where one call goes: the service it was routed to, and the host serving that service.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Target {
    /// The service (`LXS_*`).
    pub svc: SvcId,
    /// The host (the process's table).
    pub host: SvcId,
}

/// Sets up the registry and the forwarding table at boot: the moved calls go to their
/// services, unless QEMU's fw_cfg `opt/hydra/lx` or the boot entry's words send all of them
/// (`kernel`, `lx=kernel`) or some (`lx.<name>=kernel`) back to the in-kernel code, or
/// co-locate a split service in linux-server again (`lx.<name>=linux`).
pub fn init() {
    let mut words = [0u8; 400];
    let mut n = 0;
    let mut cfg = [0u8; 128];
    if let Some(k) = crate::arch::fwcfg::read_file_into("opt/hydra/lx", &mut cfg) {
        words[..k].copy_from_slice(&cfg[..k]);
        words[k] = b' ';
        n = k + 1;
    }
    {
        let b = BOOT_WORDS.lock();
        let k = b.1.min(words.len() - n);
        words[n..n + k].copy_from_slice(&b.0[..k]);
        n += k;
    }
    let kernel = svc::init(&words[..n]) || KERNEL_BY_BOOT_OPTION.load(Ordering::Acquire);
    ALL_KERNEL.store(kernel, Ordering::Release);
    set_forwarding(!kernel);
    crate::kprintln!(
        "[lx] add_key, request_key, keyctl, mq_*, sem*, msg*, bpf, AF_INET/AF_INET6/AF_NETLINK/AF_UNIX sockets, eventfd, pipes, pidfd, signalfd, timerfd: {}",
        if kernel { "in the kernel (switched back: lx=kernel)" } else { "forwarded to their services" }
    );
    svc::log_lines(kernel);
}

/// Routes the moved calls to their services (`true`; a service switched back with
/// `lx.<name>=kernel` stays in the kernel) or all to the in-kernel code.
pub fn set_forwarding(on: bool) {
    let ent = |bits: u32, s: SvcId| if on && svc::mode(s) == svc::SvcMode::Forward { T_SERVER | bits | (s as u32) << T_SVC_SHIFT } else { 0 };
    for &(nr, bits, s) in MOVED.iter().chain(MOVED_STEP2).chain(MOVED_STEP4) {
        TABLE[nr as usize].store(ent(bits, s), Ordering::Release);
    }
    for &(nr, bits, s) in MOVED_PRIV.iter().chain(MOVED_PRIV_VFS) {
        // (wave7 G7-1: + vfs-server's)
        PRIV[(nr - PRIV_BASE) as usize].store(ent(bits, s), Ordering::Release);
    }
    STEP4.store(on && svc::mode(LXS_IPC) == svc::SvcMode::Forward, Ordering::Release);
    // Socket routing (Group 12): the per-call bits only once some family moved, so that
    // nothing changes for the socket calls before
    let mut families = 0u64;
    for &(f, s) in MOVED_FAMILIES {
        let v = if on && svc::mode(s) == svc::SvcMode::Forward { s } else { 0 };
        FAMILY_SVC[f as usize].store(v, Ordering::Release);
        if v != 0 {
            families |= 1 << f;
        }
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
    // the test service's objects, ...) take the lock-free path too; on any other descriptor
    // they cost one bit test
    for nr in BYFD_IO_NUMBERS {
        TABLE[nr as usize].store(if on { T_SERVER | T_BYFD } else { 0 }, Ordering::Release);
    }
    // wave7 G7-2: the file service's calls (those vfs-server claimed)
    fileh::apply(on);
}

/// The entry of system call `nr` (0: the kernel answers it). One load.
#[inline]
pub fn entry(nr: u64) -> u32 {
    if (nr as usize) < TABLE_LEN {
        TABLE[nr as usize].load(Ordering::Relaxed)
    } else if nr.wrapping_sub(PRIV_BASE) < PRIV_LEN as u64 {
        PRIV[(nr - PRIV_BASE) as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}

/// The service an entry names for a call routed by its number.
#[inline]
pub fn entry_svc(e: u32) -> SvcId {
    ((e & T_SVC_MASK) >> T_SVC_SHIFT) as SvcId
}

/// Where system call `nr` is answered (the one function that turns a number into a route).
#[inline]
pub fn route(nr: u64) -> Route {
    if entry(nr) != 0 {
        Route::Server
    } else {
        Route::Kernel
    }
}

/// Where call `nr` with `args` of the calling thread goes, when it is decided by its number
/// or its family (`None`: the kernel; a call routed by its descriptor is decided with the
/// descriptor table, see [`forward`] and [`fast_entry`]).
pub fn by_args(nr: u64, args: &[u64; 6]) -> Option<Target> {
    let e = entry(nr);
    if e == 0 || e & T_BYFD != 0 {
        return None;
    }
    let s = if e & T_FAMILY != 0 { family_svc(args[0]) } else { entry_svc(e) };
    let h = svc::host_of(s);
    (s != 0 && h != 0).then_some(Target { svc: s, host: h })
}

/// [`LX_ROUTE_NR`](crate::ipc::protocol::LX_ROUTE_NR)`(nr, family)`: the service that answers
/// Linux call `nr` now (by family for `socket`/`socketpair`), 0 for the kernel (a call routed
/// by its descriptor: the service of its objects is not known from the number: 0).
fn route_query(nr: u64, family: u64) -> i64 {
    let e = entry(nr);
    if e == 0 || e & T_BYFD != 0 {
        return 0;
    }
    let s = if e & T_FAMILY != 0 { family_svc(family) } else { entry_svc(e) };
    if s != 0 && svc::online(s) {
        s as i64
    } else {
        0
    }
}

/// Whether the key calls go to a service (so `/proc/keys` must come from it too).
pub fn keys_forwarded() -> bool {
    route(250) == Route::Server
}

/// The forwarding trap, called for every Linux system call after `seccomp`, holding no
/// locks: `Some(result)` if the call was answered here (by a service, or Hydra's test call
/// in the kernel), `None` if the kernel's dispatcher answers it.
#[inline]
pub fn forward(frame: &SyscallFrame) -> Option<i64> {
    let nr = frame.rax;
    let e = entry(nr);
    if e == 0 {
        return if nr == LX_NULL_NR {
            Some(0)
        } else if nr == crate::ipc::protocol::LX_ROUTE_NR {
            Some(route_query(frame.rdi, frame.rsi))
        } else {
            None
        };
    }
    // wave7 G7-2 begin: the file service's calls (`fileh`), and a service's redirect to
    // the kernel
    if e & fileh::T_VFS != 0 {
        return fileh::forward(frame);
    }
    let r = forward_svc(frame, nr, e)?;
    if r == fileh::LX_TO_KERNEL {
        return None;
    }
    Some(r)
}

/// [`forward`] for the calls of every other service.
#[inline]
fn forward_svc(frame: &SyscallFrame, nr: u64, e: u32) -> Option<i64> {
    // wave7 G7-2 end
    if e & T_FAMILY != 0 {
        // Routed per call (Group 12): a family whose service is not online is the kernel's
        let s = family_svc(frame.rdi);
        // (wave6 G21: a restarting service's callers wait for it)
        if s == 0 || !usable(s) {
            return None;
        }
        return Some(call(frame, s, None));
    }
    if e & T_BYFD != 0 {
        let o = if BYFD_IO_NUMBERS.contains(&nr) {
            // (no locks for every read and write: the fast test or the kernel; `fast_entry`
            // may have made it already for this very call)
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
            // wave7 G7-5: the socket node by vfs-server (through linux-server) when it can
            return xexec::sock_call(frame, o);
        }
        let h = o.3;
        return Some(call(frame, h, Some(o)));
    }
    let s = entry_svc(e);
    if !usable(s) {
        // (wave6 G21: a service the ladder gave up fails with EIO)
        return Some(if restart::down(svc::host_of(s)) { EIO } else { ENOSYS });
    }
    Some(call(frame, s, None))
}

/// The server object at descriptor `fd` of the calling thread (for a [`T_BYFD`] call on the
/// path under the kernel lock), `None` if `fd` holds anything else: through this CPU's
/// cached table and its bitmap when the identity cache serves the thread, otherwise with
/// the table's lock.
fn byfd_object(fd: u64) -> Option<HeldObj> {
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
/// answers (`fd` holds no server object), `Ok(Some(object))` its owner does, `Err(())` it
/// cannot be told without waiting for a lock (the caller takes the ordinary path).
fn byfd_fast(id: &Ident, fd: u64) -> Result<Option<HeldObj>, ()> {
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
/// it (wave 4, step 2), to the object's owner. A stale object (its server went away) gives
/// `-EBADF`.
pub fn call_obj(nr: u64, args: [u64; 6], dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>) -> i64 {
    call_obj_ino(nr, args, dev, 0)
}

/// [`call_obj`] with [`LxCall::ino`] (Group 13: the socket node of `bind`/`connect`).
pub fn call_obj_ino(nr: u64, args: [u64; 6], dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, ino: u64) -> i64 {
    let Some(o) = dev.as_server() else { return EBADF };
    // (wave6 G21: an object of a dead instance fails with its kind's error; a restarting
    // service's live objects wait for it)
    let Some(slot) = o.slot() else { return obj::stale_errno(o) };
    let Some(x) = svc::host(o.svc()).filter(|x| host_usable(x)) else { return EBADF };
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = args;
    c.obj = slot;
    c.obj_flags = o.flags();
    c.ino = ino;
    c.svc = x.id as u32;
    call_ident(x, c, false)
}

/// The service of a call the kernel's dispatchers forward themselves ([`call_plain`]).
fn plain_svc(nr: u64, args: &[u64; 6]) -> SvcId {
    match nr {
        41 | 53 => family_svc(args[0]),
        crate::ipc::protocol::LX_KCALL_REOPEN | crate::ipc::protocol::LX_KCALL_PIDFD | crate::ipc::protocol::LX_KCALL_FCNTL | crate::ipc::protocol::LX_KCALL_FIFO => LXS_IPC,
        _ => entry_svc(entry(nr)),
    }
}

/// Forwards call `nr` with `args` (no descriptor object) on behalf of the current thread:
/// the kernel's dispatchers route `socket`/`socketpair` by family and `pipe` this way, and
/// kernel code asks for server objects with the `LX_KCALL_*` numbers (Group 13). The
/// caller holds the kernel lock (an ordinary system call path).
pub fn call_plain(nr: u64, args: [u64; 6]) -> i64 {
    let s = plain_svc(nr, &args);
    let Some(x) = svc::host(svc::host_of(s)).filter(|x| host_usable(x)) else { return ENOSYS };
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = args;
    c.svc = s as u32;
    call_ident(x, c, false)
}

/// Group 19: `open` of character device `rdev` whose major a service claimed
/// (`LX_SVC_CLAIM_MAJOR`): the service installs a descriptor of its own for the caller
/// (`LX_KCALL_DEVOPEN`, [`LxCall::dev`]) and the kernel takes that descriptor's object as the
/// opened device. `None`: no service claims the major (the kernel's drivers decide).
pub fn dev_open(rdev: u64, flags: u32) -> Option<Result<Arc<dyn crate::compat::linux::chardev::CharDevice>, i64>> {
    let major = (rdev >> 8) & 0xFFF;
    let s = svc::major_svc(major);
    // wave8 GD begin: the device service that claimed the major is being restarted: the
    // open waits for it (up to the restart's 30 s), never reaching the kernel's copy meanwhile
    let s = if s == 0 && major < 256 {
        let c = svc::MAJOR_SVC[major as usize].load(Ordering::Acquire);
        if c != 0 && svc::mode(c) == svc::SvcMode::Forward && !all_kernel() && restart::restarting(svc::host_of(c)) {
            match restart::wait_online(svc::host_of(c), &|| svc::major_svc(major) != 0) {
                // (gone again meanwhile: no device rather than the kernel's copy)
                Ok(()) => match svc::major_svc(major) {
                    0 => return Some(Err(-19)),
                    s => s,
                },
                Err(e) => return Some(Err(if e == EIO { -19 } else { e })),
            }
        } else if c != 0 && svc::mode(c) == svc::SvcMode::Forward && !all_kernel() {
            // Given up (not restarting): no device, rather than the kernel's copy beside a
            // service that held the device (and the screen) before
            return Some(Err(-19));
        } else {
            0
        }
    } else {
        s
    };
    // wave8 GD end
    if s == 0 {
        return None;
    }
    let x = svc::host(svc::host_of(s))?;
    let mut c = LxCall::EMPTY;
    c.nr = crate::ipc::protocol::LX_KCALL_DEVOPEN;
    c.args = [rdev, flags as u64, 0, 0, 0, 0];
    c.dev = rdev;
    c.svc = s as u32;
    let fd = call_ident(x, c, true);
    if fd < 0 {
        return Some(Err(fd));
    }
    // The descriptor the service installed: its object becomes the opened file (the
    // caller installs it again with the open's own flags)
    let taken = crate::task::with_current_fds_mut(|t| t.set_fd(fd as usize, None));
    match taken {
        Some(crate::fs::FileDescriptor::Device(d)) if d.as_server().is_some() => Some(Ok(d)),
        Some(other) => {
            drop(other);
            Some(Err(EIO))
        }
        None => Some(Err(EIO)),
    }
}

/// A transfer between the server object `dev` and a kernel buffer (Group 13: `splice`,
/// `sendfile`, io_uring, aio's eventfd): `read` (`out` is filled) or `write` (`data` is
/// sent) of at most the copy area's size, never blocking: `-EAGAIN` when the object is
/// not ready (the caller waits on its readiness itself). The server posts no `SIGPIPE`.
/// The caller holds the kernel lock.
pub fn call_obj_kbuf(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, write: bool, data: &[u8], out: &mut [u8]) -> i64 {
    call_obj_kbuf_nr(dev, if write { 1 } else { 0 }, write, data, out)
}

/// Group 19: queues `data` on the server's netlink socket `dev` as a received message (an
/// in-kernel message queue's `SIGEV_THREAD` notification for a socket of the network
/// service, when only the IPC service was switched back to the kernel).
pub fn call_obj_deliver(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, data: &[u8]) -> i64 {
    call_obj_kbuf_nr(dev, crate::ipc::protocol::LX_KCALL_NLDELIVER, true, data, &mut [])
}

/// [`call_obj_kbuf`] with call number `nr`.
fn call_obj_kbuf_nr(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, nr: u64, write: bool, data: &[u8], out: &mut [u8]) -> i64 {
    call_obj_kbuf_x(dev, nr, write, data, out, [0; 3])
}

// wave7 G7-4 begin
/// The kernel's `lseek` ([`LX_KCALL_PSEEK`](crate::ipc::protocol::LX_KCALL_PSEEK): `a` =
/// offset, `b` = whence) or `pread64` ([`LX_KCALL_PREAD`](crate::ipc::protocol::LX_KCALL_PREAD):
/// into `out`, `a` = offset) on linux-server's pseudo-file object `dev`.
pub fn call_obj_pseudo(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, nr: u64, a: u64, b: u64, out: &mut [u8]) -> i64 {
    call_obj_kbuf_x(dev, nr, false, &[], out, [a, b, 0])
}
// wave7 G7-4 end

/// [`call_obj_kbuf_nr`] with arguments 3..6 (wave7 G7-4).
fn call_obj_kbuf_x(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, nr: u64, write: bool, data: &[u8], out: &mut [u8], extra: [u64; 3]) -> i64 {
    use crate::ipc::protocol::{LX_KBUF_ADDR, LX_OBJ_FLAGS_KBUF};
    let Some(o) = dev.as_server() else { return EBADF };
    let Some(slot) = o.slot() else { return obj::stale_errno(o) };
    let Some(x) = svc::host(o.svc()).filter(|x| host_usable(x)) else { return EBADF };
    let n = if write { data.len() } else { out.len() }.min(LX_DATA_SIZE);
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [u64::MAX, LX_KBUF_ADDR, n as u64, extra[0], extra[1], extra[2]];
    c.obj = slot;
    c.obj_flags = o.flags() | LX_OBJ_FLAGS_KBUF | 0o4000;
    c.svc = x.id as u32;
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
    let mark = restart::install_mark();
    let mut r;
    loop {
        c.note_seq = x.notes_head();
        let kout = if write { None } else { Some(&mut out[..n]) };
        let mut redir = (0, 0);
        r = x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(x, me, my_idx, c, copy::Src::Kernel(&buf), true, kout, &mut redir));
        // wave6 G21: the service restarts (see `call_with`)
        match after_restart(x, r, &c, mark) {
            Ok(()) => continue,
            Err(e) => r = e,
        }
        break;
    }
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    // (a kernel-buffer transfer is never redirected)
    if r == LX_REDIRECTED {
        return EIO;
    }
    r
}

// ----------------------------------------------------------------------
// Requests and workers (one table per host, `svc::Host`)
// ----------------------------------------------------------------------

/// Calls forwarded since boot: handed to a worker directly, and queued (every host).
pub static DIRECT_CALLS: AtomicU64 = AtomicU64::new(0);
/// See [`DIRECT_CALLS`].
pub static QUEUED_CALLS: AtomicU64 = AtomicU64::new(0);
/// Calls that failed because their service went away.
pub static FAILED_CALLS: AtomicU64 = AtomicU64::new(0);
/// Calls redirected to another service.
pub static REDIRECTS: AtomicU64 = AtomicU64::new(0);

/// Whether linux-server is serving forwarded calls.
pub fn is_online() -> bool {
    svc::online(LXS_LINUX)
}

/// Delivers request `slot` of host `x` (its call is `call`, its copy header `hdr`) to
/// worker `wi`: the call goes into the worker's syscall page, with the copy header (empty
/// without copies) and the copied-in bytes `data` (`None`: already in the page, Group 22).
fn deliver(x: &Host, s: &mut svc::Lx, slot: usize, wi: usize, call: &LxCall, hdr: &LxCopy, data: Option<&[u8]>) {
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
    x.has_work[wi].store(true, Ordering::SeqCst);
}

/// Gives worker `wi` of host `x` the oldest queued request, if any.
fn take_queued(x: &Host, s: &mut svc::Lx, wi: usize) -> bool {
    let next = s.reqs.iter().enumerate().filter(|(_, r)| r.state == RState::Queued).min_by_key(|(_, r)| r.id).map(|(i, _)| i);
    match next {
        Some(slot) => {
            let call = s.calls[slot];
            let b = &*x.buf(slot);
            let (hdr, data) = if s.reqs[slot].has_copy { (b.hdr, Some(b.used_bytes())) } else { (LxCopy::EMPTY, None) };
            deliver(x, s, slot, wi, &call, &hdr, data);
            true
        }
        None => false,
    }
}

/// Frees request `id` of host `x` if it is still in the table in state `state` (its caller
/// died, or took its answer).
fn free_if(x: &Host, id: u64, state: RState) {
    x.lx(|s| {
        if let Some(r) = s.reqs.iter_mut().find(|r| r.id == id && r.state == state) {
            *r = Req::FREE;
        }
    });
}

/// Fills the context of a [`T_FSCTX`] call (process group, session, namespace ids) from
/// the process table; `false` if it is busy and `wait` is not allowed.
fn fill_ctx(c: &mut LxCall, wait: bool) -> bool {
    let procs = if wait { Some(crate::compat::linux::proc::PROCS.lock()) } else { crate::compat::linux::proc::PROCS.try_lock() };
    let Some(procs) = procs else { return false };
    if let Some(p) = procs.get(&c.tgid) {
        c.pgid = p.pgid as u32;
        c.sid = p.sid as u32;
        c.mnt_ns = p.ns.mnt as u32;
        c.net_ns = p.ns.net as u32;
        c.pid_ns = p.ns.pid as u32;
        c.user_ns = p.ns.user.is_some() as u32;
    }
    true
}

/// Forwards the current Linux system call to service `s` (a host id when `byfd` names the
/// object) and waits for the answer (the path under the kernel lock, for callers the
/// lock-free path does not take: traced tasks, seccomp filters, tracing on).
fn call(frame: &SyscallFrame, s: SvcId, byfd: Option<HeldObj>) -> i64 {
    let mut c = LxCall::EMPTY;
    c.nr = frame.rax;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.svc = s as u32;
    let bits = entry(c.nr);
    let hid = if byfd.is_some() { s } else { svc::host_of(s) };
    let Some(x) = svc::host(hid) else { return ENOSYS };
    // Group 9: the server object at args[0], held until the call is answered (a close on
    // another thread cannot overtake the call); Group 12: a T_BYFD call's, found already
    if bits & (T_FAMILY | T_BYFD) != 0 && crate::compat::linux::ns::net_isolated() {
        c.obj_flags |= LX_OBJ_FLAGS_NETNS;
    }
    let _held = if let Some((dev, slot, flags, _)) = byfd {
        c.obj = slot;
        c.obj_flags |= flags;
        Some(dev)
    } else if bits & T_FD0 != 0 {
        obj::current_fd(c.args[0]).filter(|o| o.3 == hid).map(|(dev, slot, flags, _)| {
            c.obj = slot;
            c.obj_flags = flags;
            dev
        })
    } else {
        None
    };
    let _held1 = if bits & T_FDAT1 != 0 {
        // wave6 G24: bpf's spare argument words cleared; the attribute block's head read
        // (the key and value pointers of a map element command, `sec.rs`)
        sec::bpf_clear(&mut c);
        crate::compat::linux::vfs::copy_in(c.args[1], sec::attr_len(&c)).ok().and_then(|b| {
            let fd = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
            obj::current_fd(fd).filter(|o| o.3 == hid).map(|(dev, slot, flags, _)| {
                c.obj = slot;
                c.obj_flags = flags | LX_OBJ_FLAGS_AT1 | (fd & 0x3FFF_FFFF) << 32;
                if let Some(o) = dev.as_server() {
                    sec::bpf_prepare(&mut c, &b, o.kind(), o.tag());
                }
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
    if bits & T_FSCTX != 0 {
        c.tgid = crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(0);
        fill_ctx(&mut c, true);
    }
    // wave7 G7-1 begin
    if c.nr == crate::ipc::protocol::LX_VFS_WALK_NR {
        vfs_ctx(&mut c);
    }
    // wave7 G7-1 end
    call_ident_raw(x, c, true) // (wave7 G7-2: a redirect to the kernel goes back to `forward`)
}

/// [`call`] with the call's number, arguments and object filled in: adds the caller's
/// identity (and its groups when `groups`) and waits for host `x`'s answer (under the
/// kernel lock).
fn call_ident(x: &'static Host, c: LxCall, groups: bool) -> i64 {
    // wave7 G7-2: the kernel's own callers have no kernel code to fall back to
    match call_ident_raw(x, c, groups) {
        fileh::LX_TO_KERNEL => ENOSYS,
        r => r,
    }
}

/// [`call_ident`], with a redirect to the kernel returned as [`fileh::LX_TO_KERNEL`].
fn call_ident_raw(x: &'static Host, mut c: LxCall, groups: bool) -> i64 {
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
    let r = call_with(x, me, my_idx, c, true);
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    r
}

/// Forwards call `c` (its identity filled in) of task `me` (at `my_idx`, a hint) to host
/// `x` and waits for the answer, following redirects to other services. `nobkl`: the
/// lock-free path ([`fast_entry`]), whose waits do not need the kernel lock.
fn call_with(x: &'static Host, me: u64, my_idx: usize, mut c: LxCall, nobkl: bool) -> i64 {
    let mut x = x;
    c.note_seq = x.notes_head();
    // wave6 G22 begin: the copy-in table: the call's pointer arguments are copied when the
    // call is placed, straight into the worker's page (`place`; a bad one fails there; a
    // redirect or a retry copies them again from the caller's memory)
    let copies = match copy::describe(c.nr, &c.args) {
        Some(desc) => copy::Src::User(sec::bpf_desc(*desc, c.nr, &c.args)), // (wave6 G24: bpf key/value)
        None => copy::Src::None,
    };
    // wave6 G22 end
    // wave6 G21: installs for this thread from here on belong to this call
    let mark = restart::install_mark();
    // Interrupts stay off from handing the call over until the answer is taken: nothing on
    // this CPU may come between (the yields switch with them off, and they come back so)
    loop {
        let mut redir = (0u64, 0u64);
        let r = x86_64::instructions::interrupts::without_interrupts(|| call_and_wait(x, me, my_idx, c, copies, nobkl, None, &mut redir));
        // A net wait ended (Group 12): the same call again, at once
        if r == crate::ipc::protocol::LX_RETRY {
            NET_RETRIES.fetch_add(1, Ordering::Relaxed);
            c.note_seq = x.notes_head();
            c.flags |= crate::ipc::protocol::LX_CALL_RETRIED;
            continue;
        }
        // A redirect (Group 19): the same call, with the same copies, to the service named
        if r == LX_REDIRECTED {
            if c.redirs >= LX_REDIR_MAX {
                return ELOOP;
            }
            let s = (redir.0 & 0xFF) as SvcId;
            // wave7 G7-2: service 0: the kernel's own code answers the call
            if s == 0 {
                return fileh::LX_TO_KERNEL;
            }
            // wave7 G7-4: a redirect to a service the kernel answers (`lx.proc=kernel`, `lx=kernel`):
            // nothing happened in the redirecting service, so the kernel's own code answers
            if svc::mode(s) == svc::SvcMode::Kernel || all_kernel() {
                // (wave7 G7-5: this also covers a FIFO open vfs-server sent to the IPC
                // service while that one is switched back, `lx.ipc=kernel`)
                return fileh::LX_TO_KERNEL;
            }
            let Some(nx) = svc::host(svc::host_of(s)).filter(|h| host_usable(h)) else { return ENOSYS };
            if nx.id != x.id {
                // (an object slot means nothing to another host)
                c.obj = LX_OBJ_NONE;
            }
            c.svc = s as u32;
            c.redir_obj = redir.1;
            c.redir_tail = (redir.0 >> 32) as u32;
            c.redirs += 1;
            x = nx;
            c.note_seq = x.notes_head();
            REDIRECTS.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // wave6 G21 begin: the service is restarting: wait for it, then send the call (again)
        match after_restart(x, r, &c, mark) {
            Ok(()) => {
                c.note_seq = x.notes_head();
                // wave8 GX2: a call sent again after a restart may have been under way (a
                // connect whose handshake went on meanwhile): the service is told
                if matches!(r, restart::LX_RESEND | restart::LX_RESEND_MAYBE) {
                    c.flags |= crate::ipc::protocol::LX_CALL_RETRIED;
                }
                continue;
            }
            Err(e) => return e,
        }
        // wave6 G21 end
    }
}

// wave6 G21 begin
/// What a caller does with host `x`'s answer `r` to call `c` (made since install count
/// `mark`) when the service went away or is restarting (`docs/linux-services-design.md`
/// 5.1): `Ok(())` make the call again (the service is back); `Err(v)` return `v` (every
/// ordinary answer is `Err(r)`).
fn after_restart(x: &'static Host, r: i64, c: &LxCall, mark: u64) -> Result<(), i64> {
    let online = || x.is_online();
    match r {
        LX_OFFLINE => restart::wait_online(x.id, &online),
        restart::LX_RESEND | restart::LX_RESEND_MAYBE => restart::resend(x.id, r, c.nr, &c.args, mark, &online),
        _ => Err(r),
    }
}
// wave6 G21 end

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
    crate::ipc::service::notify(svc::endpoint_of(LXS_NET), crate::ipc::protocol::NOTIFY_LX_NET);
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
/// Places call `c` of task `me` in host `x`'s request table `s`: a free slot, an id, and an
/// idle worker that takes it at once (its page gets the call, and the user copies straight
/// from the caller's memory), or the queue (the copies wait in the slot's buffer). `Err`:
/// the copies need a page faulted in first, or a pointer is bad (nothing changed);
/// `Ok(Err)`: the call cannot be placed.
#[allow(clippy::type_complexity)]
fn place(x: &Host, s: &mut svc::Lx, me: u64, my_idx: usize, c: &mut LxCall, copies: copy::Src<'_>) -> Result<Result<(usize, u64, Option<(u64, usize)>), i64>, copy::FillErr> {
    // Checked under the table's lock: `server_gone` clears `online` before it takes the
    // lock, so a call placed here is either failed by it or refused now
    if !x.online.load(Ordering::Acquire) {
        // (wave6 G21: a restarting service's caller waits for it; one given up: EIO)
        return Ok(Err(if restart::restarting(x.id) {
            LX_OFFLINE
        } else if restart::down(x.id) {
            EIO
        } else {
            ENOSYS
        }));
    }
    let Some(slot) = s.reqs.iter().position(|r| r.state == RState::Free).or_else(|| reclaim(s)) else { return Ok(Err(EAGAIN)) };
    // An idle worker takes it at once
    let wi = s.workers.iter().position(|w| w.idle);
    // The copies first (nothing is changed yet when they fail): user memory straight into
    // the idle worker's page (it reads the page only once the call is delivered), or into
    // the free slot's buffer (nobody else uses a free slot's buffer)
    let (hdr, used) = match copies {
        copy::Src::None => (LxCopy::EMPTY, 0),
        copy::Src::Kernel(b) => (b.hdr, b.used),
        copy::Src::User(ref desc) => {
            let data = match wi {
                Some(wi) => s.workers[wi].data_mut(),
                None => &mut x.buf(slot).data,
            };
            let mut h = LxCopy::EMPTY;
            let n = copy::fill(&mut h, data, desc, &c.args)?;
            (h, n)
        }
    };
    let has_copy = !matches!(copies, copy::Src::None);
    let id = (x.id as u64) << LX_REQ_SVC_SHIFT | (s.next_id & ((1 << LX_REQ_SVC_SHIFT) - 1));
    s.next_id += 1;
    c.id = id;
    s.reqs[slot] = Req { state: RState::Queued, id, client: me, client_idx: my_idx, result: 0, interrupted: false, has_copy, early: false, redir: (0, 0), partial: 0 }; // (wave8 GX2: partial)
    x.req_done[slot].store(false, Ordering::SeqCst);
    if has_copy {
        let kept = x.buf(slot);
        kept.hdr = hdr;
        kept.used = used;
    }
    let target = match wi {
        Some(wi) => {
            let data = if let copy::Src::Kernel(b) = copies { Some(b.used_bytes()) } else { None };
            deliver(x, s, slot, wi, c, &hdr, data);
            Some((s.workers[wi].task, s.workers[wi].idx))
        }
        None => {
            s.calls[slot] = *c;
            // Its bytes wait with it (the caller's memory is not reachable from the worker
            // that takes it); user copies are there already
            if let copy::Src::Kernel(b) = copies {
                x.buf(slot).data[..b.used].copy_from_slice(b.used_bytes());
            }
            None
        }
    };
    Ok(Ok((slot, id, target)))
}
// wave6 G22 end

/// A full request table (test wave, Group 30): frees the requests whose caller died before
/// it took their end, and returns the first slot freed. Nobody else frees those: a call
/// failed by its service's crash, or answered, whose caller was then killed before it ran
/// again (a blocked thread retired by `kill_linux_tasks` dies at once, its `wait_for` never
/// runs). Without this, each linux-server crash leaked one slot per program it ended.
fn reclaim(s: &mut svc::Lx) -> Option<usize> {
    let sched = crate::task::SCHEDULER.lock();
    let mut first = None;
    for (i, r) in s.reqs.iter_mut().enumerate() {
        if matches!(r.state, RState::Failed | RState::Done) && !sched.is_task_alive(TaskId(r.client)) {
            *r = Req::FREE;
            first.get_or_insert(i);
        }
    }
    first
}

/// [`call_with`] with its copies `copies` (user copies are made when the call is placed),
/// to host `x`. `kout`: a kernel-buffer read ([`call_obj_kbuf`]): the output to `args[1]`
/// goes there instead of to user memory. `redir`: set to the redirect's `(result word,
/// object)` when the answer is [`LX_REDIRECTED`].
#[allow(clippy::too_many_arguments)]
fn call_and_wait(x: &'static Host, me: u64, my_idx: usize, mut c: LxCall, copies: copy::Src<'_>, nobkl: bool, kout: Option<&mut [u8]>, redir: &mut (u64, u64)) -> i64 {
    // wave6 G22 begin: a page of a pointer argument not there yet is faulted in with the
    // table's lock let go, and the call placed again (a page that faults again at once, or
    // that cannot be faulted in, is a bad pointer)
    let mut last_missing = u64::MAX;
    let mut tries = 0;
    let placed = loop {
        match x.lx(|s| place(x, s, me, my_idx, &mut c, copies)) {
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
                crate::kprintln!("[lx] too many calls in flight ({})", crate::ipc::protocol::LXS_NAMES[x.id as usize]);
            }
            return e;
        }
    };
    match target {
        Some((w, hint)) => {
            DIRECT_CALLS.fetch_add(1, Ordering::Relaxed);
            x.direct.fetch_add(1, Ordering::Relaxed);
            // The direct switch: this thread blocks, the worker runs next on this CPU. When
            // that cannot be done (the worker is still running, or blocked outside the
            // lock-free path, ...), the worker is woken the ordinary way; a worker still
            // running finds the call under the table's lock before it would block
            // (not if the answer came already: a worker running on another CPU may have
            // taken the call and answered it before this thread got here)
            if !direct_to(w, hint, Some(&x.req_done[slot]), nobkl) {
                crate::task::SCHEDULER.lock().unblock_task(TaskId(w));
            }
        }
        None => {
            QUEUED_CALLS.fetch_add(1, Ordering::Relaxed);
            x.queued.fetch_add(1, Ordering::Relaxed);
        }
    }
    wait_for(x, slot, id, &c.args, (c.tid, c.tgid), nobkl, kout, redir)
}

/// Waits for the answer to request `id` (in `slot` of host `x`), copies its output to the
/// caller's pointers `args` (the copy-out table), and frees it.
///
/// No wake-up is lost: the answer is marked under the table's lock and the caller woken
/// after it, and the caller blocks only under the same lock after seeing no answer.
#[allow(clippy::too_many_arguments)]
fn wait_for(x: &'static Host, slot: usize, id: u64, args: &[u64; 6], who: (u64, u64), nobkl: bool, kout: Option<&mut [u8]>, redir: &mut (u64, u64)) -> i64 {
    let mut kout = kout;
    loop {
        let done = x.lx(|s| {
            let r = &mut s.reqs[slot];
            if r.id != id {
                return Some((EIO, false));
            }
            match r.state {
                RState::Done | RState::Failed => {
                    let v = r.result;
                    if v == LX_REDIRECTED && r.state == RState::Done {
                        *redir = r.redir;
                        *r = Req::FREE;
                        return Some((v, false));
                    }
                    let out = r.state == RState::Done && r.has_copy && copy::has_output(x.buf(slot));
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
                let b = x.buf(slot);
                let n = (b.hdr.out_len[1] as usize).min(k.len());
                if n > 0 {
                    let o = b.hdr.out_off[1] as usize - LX_DATA_OFF;
                    k[..n].copy_from_slice(&b.data[o..o + n]);
                }
                v
            } else {
                match copy::copy_out(x.buf(slot), args) {
                    Ok(()) => v,
                    Err(e) => e,
                }
            };
            free_if(x, id, RState::Done);
            return r;
        }
        // A signal: a call not taken yet is withdrawn; one being served is marked (the
        // server may answer -EINTR; a pending one learns it through a notification). The
        // slow path: under the kernel lock (the notification wakes the server's endpoint)
        if crate::compat::linux::proc::signal_pending() {
            if !crate::arch::smp::bkl_held() {
                crate::arch::smp::bkl_enter();
            }
            let what = x.lx(|s| {
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
                Some(0) => note_to(x.id, LX_NOTE_INTERRUPT, id, 0, 0),
                Some(v) => return v,
                None => {}
            }
        }
        // Block, unless the answer came meanwhile (checked under the lock the answer is
        // marked under)
        let blocked = x.lx(|s| {
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
    // The yield vector switches tasks and comes back here
    crate::ipc::service::int81();
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
    // Vector 0x82 switches to `target` and comes back here when this task runs again (0),
    // or returns at once with 1
    let failed = crate::ipc::service::int82();
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
// - the request table and the worker list: the host's table lock (`Host::table`, interrupts off,
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
// scheduler lock is held: a worker's `has_work` (a call was delivered to it), a caller's
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

// (The per-host flags `Host::req_done`, `Host::has_work` and `Host::worker_tids`, and the
// cross-host worker list `svc::worker_host`, are in `svc.rs`.)

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

// wave6 G20 begin
/// Thread `tid`'s identity from this CPU's cache, if it is there and still valid (a direct
/// call made for the program whose call a worker serves, `dcall`).
fn ident_of(tid: u64) -> Option<Ident> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
        // SAFETY: this CPU's own entry, interrupts off
        let e = unsafe { &*IDENT.0[cpu].get() };
        (tid != 0 && e.tid == tid && e.epoch == crate::compat::linux::ident_epoch()).then_some(*e)
    })
}
// wave6 G20 end

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
    // wave6 G20 begin: a worker's direct call to another service (`dcall`), on this path
    // too (Linux's msgsnd, the same number, goes on below)
    if nr == crate::arch::syscall::SYS_SVC_DCALL {
        let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
        if svc::worker_host(tid).is_some() {
            let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
            return Some(Fast::Reply(dcall::dcall(tid, idx, [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9], true)));
        }
    }
    // wave6 G20 end
    if nr == crate::arch::syscall::SYS_LX_REPLY_RECV {
        let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
        if let Some(x) = svc::worker_host(tid).and_then(svc::host) {
            let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
            return Some(Fast::Reply(reply_recv_as(x, tid, idx, frame.rdi as i64, frame.rsi, true)));
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
    // wave7 G7-1: vfs-server's walk test call takes the locked path (its root/cwd fill)
    if nr == crate::ipc::protocol::LX_VFS_WALK_NR {
        return None;
    }
    let bits = entry(nr);
    if bits == 0 || crate::compat::linux::TRACE_SYSCALLS.load(Ordering::Relaxed) || crate::task::scheduler::handoff_active() {
        return None;
    }
    let id = ident()?;
    // wave7 G7-2 begin: the file service's calls (`fileh`)
    if bits & fileh::T_VFS != 0 {
        return fileh::fast(&id, frame).map(Fast::Call);
    }
    // wave7 G7-2 end
    // Which service: by family, by descriptor, or by number (Groups 12 and 19). (Group 13:
    // decided before the call is built: read and write on kernel descriptors pass here too)
    let mut byfd = None;
    let (s, hid) = if bits & T_FAMILY != 0 {
        let s = family_svc(frame.rdi);
        if s == 0 {
            return None;
        }
        (s, svc::host_of(s))
    } else if bits & T_BYFD != 0 {
        match byfd_fast(&id, frame.rdi) {
            Ok(Some((dev, _, _, _))) if kernel_first(nr, &dev) => {
                drop_last(dev);
                return None;
            }
            Ok(Some(o)) => {
                let h = o.3;
                byfd = Some(o);
                (h, h)
            }
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
    } else {
        let s = entry_svc(bits);
        (s, svc::host_of(s))
    };
    let Some(x) = svc::host(hid).filter(|x| x.is_online()) else {
        if let Some(o) = byfd {
            drop_last(o.0);
        }
        return None;
    };
    let mut c = LxCall::EMPTY;
    c.nr = nr;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.tid = id.tid;
    c.tgid = id.tgid;
    [c.uid, c.euid, c.suid, c.gid, c.egid, c.sgid] = id.ids;
    c.caps = id.caps;
    c.svc = s as u32;
    if nr != LX_NULL_NR && nr != LX_TEST_NR {
        c.ngroups = id.ngroups;
        c.groups = id.groups;
    }
    // What Group 9's calls carry besides their arguments (see `call`), gathered without
    // waiting for any lock a kernel-lock holder could hold: the descriptor table is taken
    // with `try_lock` (busy: the ordinary path), the IPC namespace comes with the identity
    let mut held: [Option<Arc<dyn crate::compat::linux::chardev::CharDevice>>; 2] = [None, None];
    if let Some((dev, slot, flags, _)) = byfd {
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
    if bits & T_FSCTX != 0 && !fill_ctx(&mut c, false) {
        for h in held.into_iter().flatten() {
            drop_last(h);
        }
        return None;
    }
    // wave6 G24 begin: bpf (T_FDAT1 alone): the map's descriptor through this CPU's cached
    // descriptor table (`byfd_fast`), as the by-descriptor calls do, instead of the
    // scheduler's lock and the table's lock on every map lookup
    let fdat1_only = bits & (T_FD0 | T_FDAT1 | T_UMASK) == T_FDAT1;
    if fdat1_only {
        let mut head = [0u8; sec::ATTR_HEAD];
        sec::bpf_clear(&mut c);
        let n = sec::attr_len(&c);
        if copy::read_user(c.args[1], &mut head[..n]).is_ok() {
            let fd = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as u64;
            match byfd_fast(&id, fd) {
                Ok(Some((dev, slot, flags, h))) => {
                    if h == x.id {
                        c.obj = slot;
                        c.obj_flags = flags | LX_OBJ_FLAGS_AT1 | (fd & 0x3FFF_FFFF) << 32;
                        if let Some(o) = dev.as_server() {
                            sec::bpf_prepare(&mut c, &head, o.kind(), o.tag());
                        }
                    }
                    held[1] = Some(dev);
                }
                Ok(None) => {}
                Err(()) => {
                    for h in held.into_iter().flatten() {
                        drop_last(h);
                    }
                    return None;
                }
            }
        }
    }
    // wave6 G24 end
    if !fdat1_only && bits & (T_FD0 | T_FDAT1 | T_UMASK) != 0 {
        // T_FDAT1: the descriptor is the first u32 of the attribute block at args[1]
        // wave6 G24: bpf's spare argument words cleared, and the block's head read (`sec.rs`)
        let mut head = [0u8; sec::ATTR_HEAD];
        let at1 = if bits & T_FDAT1 != 0 {
            sec::bpf_clear(&mut c);
            let n = sec::attr_len(&c);
            copy::read_user(c.args[1], &mut head[..n]).ok().map(|()| u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as u64)
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
            if let Some((dev, slot, flags, h)) = obj::object_in(&table, c.args[0]) {
                if h == x.id {
                    c.obj = slot;
                    c.obj_flags = flags;
                }
                held[0] = Some(dev);
            }
        }
        if let Some(fd) = at1 {
            if let Some((dev, slot, flags, h)) = obj::object_in(&table, fd) {
                if h == x.id {
                    c.obj = slot;
                    c.obj_flags = flags | LX_OBJ_FLAGS_AT1 | (fd & 0x3FFF_FFFF) << 32;
                    // wave6 G24
                    if let Some(o) = dev.as_server() {
                        sec::bpf_prepare(&mut c, &head, o.kind(), o.tag());
                    }
                }
                held[1] = Some(dev);
            }
        }
        drop(table);
        drop_last(fds);
    }
    let idx = crate::task::scheduler::CURRENT_IDX.load(Ordering::Relaxed) as usize;
    FAST_CALLS.fetch_add(1, Ordering::Relaxed);
    let r = call_with(x, id.tid, idx, c, true);
    // The server objects were held across the call (a close on another thread cannot
    // overtake it); the last reference, if a close came meanwhile, goes under the lock
    for h in held.into_iter().flatten() {
        drop_last(h);
    }
    // wave7 G7-2: redirected to the kernel: the ordinary path (`forward` asks again)
    if r == fileh::LX_TO_KERNEL {
        return None;
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
    let mut per = alloc::string::String::new();
    for x in svc::hosts() {
        per.push_str(&alloc::format!(
            "; {}: {} direct, {} queued, {} failed",
            crate::ipc::protocol::LXS_NAMES[x.id as usize],
            x.direct.load(Ordering::Relaxed),
            x.queued.load(Ordering::Relaxed),
            x.failed.load(Ordering::Relaxed)
        ));
    }
    alloc::format!(
        "{} calls forwarded ({} on the lock-free path; {} straight to an idle worker, {} queued, {} failed, {} redirected); answers: {} switched straight back, {} woken the ordinary way{}",
        DIRECT_CALLS.load(Ordering::Relaxed) + QUEUED_CALLS.load(Ordering::Relaxed),
        FAST_CALLS.load(Ordering::Relaxed),
        DIRECT_CALLS.load(Ordering::Relaxed),
        QUEUED_CALLS.load(Ordering::Relaxed),
        FAILED_CALLS.load(Ordering::Relaxed),
        REDIRECTS.load(Ordering::Relaxed),
        REPLY_DIRECT.load(Ordering::Relaxed),
        REPLY_WOKEN.load(Ordering::Relaxed),
        per
    ) + "; " + &restart::summary() // wave6 G21
        + &copy_summary()
        + "; " + &fileh::summary() // wave7 G7-2
        + "; " + &xexec::summary() // wave7 G7-5
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
// Server side (native system calls of the services)
// ----------------------------------------------------------------------

/// The thread that made request `id` (served or pending), for the object primitives.
fn client_of(id: u64) -> Option<u64> {
    let x = svc::host(lx_req_svc(id))?;
    x.lx(|s| s.reqs.iter().find(|r| r.id == id && matches!(r.state, RState::Delivered | RState::Pending)).map(|r| r.client))
}

/// The calling task's ID, process and host id, if it is a service's process.
fn server_caller() -> Result<(u64, u64, SvcId), i64> {
    server_caller_at().map(|(id, tgid, h, _)| (id, tgid, h))
}

/// [`server_caller`], with the task's index in the scheduler's table.
fn server_caller_at() -> Result<(u64, u64, SvcId, usize), i64> {
    let (me, tgid, ep, idx) = {
        let mut sched = crate::task::SCHEDULER.lock();
        let idx = sched.current_index();
        sched.current_task_mut(|t| t.service.map(|ep| (t.id.0, t.tgid, ep, idx))).flatten().ok_or(EPERM)?
    };
    let h = svc::host_by_endpoint(ep).ok_or(EPERM)?;
    Ok((me, tgid, h, idx))
}

/// The calling service's host, if request `id` is one of its own (`-ESRCH` otherwise).
fn server_for(id: u64) -> Result<&'static Host, i64> {
    let (_, _, h) = server_caller()?;
    if lx_req_svc(id) != h {
        return Err(ESRCH);
    }
    svc::host(h).ok_or(ESRCH)
}

/// `SYS_LX_CTL`: [`LX_CTL_ATTACH`] registers the calling thread as a worker of its service
/// and returns its syscall page's address; [`LX_CTL_OBJAREA`] maps the service's object
/// area; [`LX_CTL_ONLINE`] starts forwarding (every worker attached, the endpoint
/// registered); [`LX_CTL_WAKE`] wakes the service's main thread.
pub fn ctl(op: u64) -> i64 {
    let (me, tgid, h) = match server_caller() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ep = svc::endpoint_of(h);
    match op {
        LX_CTL_ATTACH => {
            let x = svc::host_or_make(h, ep);
            // A new server process: the state of one that went away goes
            let old = x.lx(|s| s.server_tgid);
            if old != 0 && old != tgid {
                let alive = crate::task::SCHEDULER.lock().with_process(old, |_| ()).is_some();
                if alive {
                    return EBUSY;
                }
                x.lx(|s| {
                    s.workers.clear();
                    s.server_tgid = 0;
                    for t in x.worker_tids.iter() {
                        t.store(0, Ordering::Release);
                    }
                });
                svc::drop_workers(h);
            }
            let Some(page) = ContiguousFrames::allocate(1) else { return ENOMEM };
            let addr = match crate::ipc::service::map_into_current(page.clone(), 1) {
                Ok(a) => a,
                Err(e) => return e,
            };
            let r = x.lx(|s| {
                if s.workers.len() >= MAX_WORKERS {
                    return EBUSY;
                }
                s.server_tgid = tgid;
                let idx = crate::task::SCHEDULER.lock().current_index();
                x.worker_tids[s.workers.len()].store(me, Ordering::Release);
                x.has_work[s.workers.len()].store(false, Ordering::Release);
                s.workers.push(Worker { task: me, page, idle: false, req: NONE, idx });
                addr as i64
            });
            if r >= 0 {
                svc::add_worker(me, h);
            }
            r
        }
        LX_CTL_OBJAREA => {
            let x = svc::host_or_make(h, ep);
            obj::map_area(x)
        }
        LX_CTL_ONLINE => {
            let Some(x) = svc::host(h) else { return EINVAL };
            let Some(win) = crate::ipc::service::window(ep) else { return EINVAL };
            if x.lx(|s| s.server_tgid != tgid || s.workers.is_empty()) {
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
            x.notes_head.store(0, Ordering::Release);
            x.notes.store(base, Ordering::Release);
            // wave6 G21 begin: a Transparent restart's new instance adopted the old objects:
            // they stay; otherwise the old objects go stale (a new generation)
            let r = if restart::adopting(h) {
                obj::online_adopt(x)
            } else {
                if restart::keeps_objects(h) {
                    obj::offline(x);
                    hotplug::objects_failed(h); // wave8 GH (not adopted: they failed now)
                }
                obj::online(x)
            };
            if r != 0 {
                return ENOMEM;
            }
            // wave6 G21 end
            svc::take_ids(h, ep);
            x.online.store(true, Ordering::Release);
            // wave6 G21: callers waiting for the restart go on
            restart::online(h);
            // wave8 GH: devices announced "removed" by the previous instance come back
            hotplug::online(h);
            let n = x.lx(|s| s.workers.len());
            crate::kprintln!("[lx] {} online (process {}, endpoint {:#x}, {} workers)", crate::ipc::protocol::LXS_NAMES[h as usize], tgid, ep, n);
            0
        }
        LX_CTL_WAKE => {
            crate::ipc::service::notify(ep, NOTIFY_LX_NOTES);
            0
        }
        _ => EINVAL,
    }
}

/// `SYS_LX_REPLY_RECV`: answers the call the calling worker serves with `result` (unless
/// `flags` has [`LX_REPLY_NONE`]; [`LX_REPLY_PENDING`]: the call goes on, answered later by
/// [`complete`]; [`LX_REPLY_REDIRECT`]: the call goes to another service), then waits for
/// the next call, which is in the worker's syscall page when this returns 0. The answer
/// hands the CPU straight back to its caller when this worker has nothing else to do (the
/// direct switch). (The path under the kernel lock; workers normally come in through
/// [`fast_entry`].)
pub fn reply_recv(result: i64, flags: u64) -> i64 {
    let (me, h, my_idx) = match server_caller_at() {
        Ok((me, _, h, idx)) => (me, h, idx),
        Err(e) => return e,
    };
    let Some(x) = svc::host(h) else { return EPERM };
    reply_recv_as(x, me, my_idx, result, flags, false)
}

/// [`reply_recv`] for worker `me` of host `x` (at `my_idx`, a hint); `nobkl`: the lock-free
/// path.
fn reply_recv_as(x: &'static Host, me: u64, my_idx: usize, result: i64, flags: u64, nobkl: bool) -> i64 {
    let answered = x86_64::instructions::interrupts::without_interrupts(|| {
        x.lx(|s| {
            let wi = s.workers.iter().position(|w| w.task == me)?;
            s.workers[wi].idx = my_idx;
            let mut wake = (0u64, 0u64, 0usize);
            let mut interrupted = 0u64;
            let cur = s.workers[wi].req;
            if flags & LX_REPLY_NONE == 0 && cur != NONE {
                let page = s.workers[wi].call_mut();
                let r = &mut s.reqs[cur];
                if r.state == RState::Delivered {
                    if flags & LX_REPLY_PENDING != 0 && !r.early {
                        r.state = RState::Pending;
                        // Group 9: a signal that came while the call was served is told now
                        // (the caller already marked it and will not tell again)
                        if r.interrupted {
                            interrupted = r.id;
                        }
                    } else if flags & LX_REPLY_REDIRECT != 0 && !r.early {
                        // Group 19: the caller sends the call on to the service named
                        r.state = RState::Done;
                        r.result = LX_REDIRECTED;
                        // SAFETY: the worker's page (see `deliver`)
                        r.redir = (result as u64, unsafe { core::ptr::read_volatile(&(*page).redir_obj) });
                        x.req_done[cur].store(true, Ordering::SeqCst);
                        wake = (r.client, r.id, r.client_idx);
                    } else {
                        r.state = RState::Done;
                        if !r.early {
                            r.result = result;
                        }
                        x.req_done[cur].store(true, Ordering::SeqCst);
                        wake = (r.client, r.id, r.client_idx);
                        // The output the server left in the page (copy-out table; a call
                        // completed early wrote its output itself)
                        if r.has_copy && !r.early {
                            let page = page as *const u8;
                            // SAFETY: the worker's page (see `deliver`); the header and copy
                            // area lie within it
                            let (out_len, data) = unsafe {
                                let h = core::ptr::read_volatile(page.add(LX_COPY_OFF) as *const LxCopy);
                                (h.out_len, core::slice::from_raw_parts(page.add(LX_DATA_OFF), LX_DATA_SIZE))
                            };
                            copy::take_output(x.buf(cur), &out_len, data);
                        }
                    }
                }
            }
            s.workers[wi].req = NONE;
            x.has_work[wi].store(false, Ordering::SeqCst);
            // A call waiting in the queue comes next; otherwise this worker goes idle
            let next = take_queued(x, s, wi);
            if !next {
                s.workers[wi].idle = true;
            }
            Some((wake, next, wi, interrupted))
        })
    });
    let Some(((client, id, hint), next, wi, interrupted)) = answered else { return EPERM };
    if interrupted != 0 {
        note_to(x.id, LX_NOTE_INTERRUPT, interrupted, 0, 0);
    }
    if client != 0 {
        // Straight back to the caller, unless a call was delivered to this worker meanwhile;
        // otherwise the caller is woken the ordinary way
        let switched = !next && x86_64::instructions::interrupts::without_interrupts(|| direct_to(client, hint, Some(&x.has_work[wi]), nobkl));
        if switched {
            REPLY_DIRECT.fetch_add(1, Ordering::Relaxed);
        } else {
            REPLY_WOKEN.fetch_add(1, Ordering::Relaxed);
            let mut sched = crate::task::SCHEDULER.lock();
            if !sched.unblock_task(TaskId(client)) && !sched.is_task_alive(TaskId(client)) {
                // Its caller died meanwhile: nobody takes the answer
                drop(sched);
                free_if(x, id, RState::Done);
            }
        }
    }
    if next {
        return 0;
    }
    wait_work(x, me, nobkl)
}

/// Waits (blocked) until a call is delivered to worker `me` of host `x`, or one is queued.
/// The worker blocks only under the table's lock after seeing nothing, so a delivery
/// (marked under the same lock, the worker woken after it) is never missed.
fn wait_work(x: &'static Host, me: u64, nobkl: bool) -> i64 {
    loop {
        let st = x86_64::instructions::interrupts::without_interrupts(|| {
            x.lx(|s| {
                let Some(wi) = s.workers.iter().position(|w| w.task == me) else { return Err(ESRCH) };
                if s.workers[wi].req != NONE {
                    s.workers[wi].idle = false;
                    x.has_work[wi].store(false, Ordering::SeqCst);
                    return Ok(true);
                }
                if take_queued(x, s, wi) {
                    x.has_work[wi].store(false, Ordering::SeqCst);
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

/// `SYS_LX_COMPLETE`: answers pending request `id` with `result` (any thread of the
/// service the request belongs to).
pub fn complete(id: u64, result: i64) -> i64 {
    if let Err(e) = server_for(id) {
        return if e == ESRCH { EINVAL } else { e };
    }
    complete_as_kernel(id, result)
}

/// [`complete`] without the check that the service calls it (the net-server doorbell hook).
fn complete_as_kernel(id: u64, result: i64) -> i64 {
    let Some(x) = svc::host(lx_req_svc(id)) else { return EINVAL };
    let client = x.lx(|s| {
        // Still being served (its "pending" answer not given yet): kept for that answer
        if let Some(r) = s.reqs.iter_mut().find(|r| r.id == id && r.state == RState::Delivered && !r.early) {
            r.early = true;
            r.result = result;
            return Some(0);
        }
        let slot = s.reqs.iter().position(|r| r.id == id && r.state == RState::Pending)?;
        x.req_done[slot].store(true, Ordering::SeqCst);
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
        free_if(x, id, RState::Done);
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
    let client = client_of(id).ok_or(ESRCH)?;
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
/// service.
///
/// # Returns
///
/// The bytes copied (a string's length), `-EFAULT` for a bad address on either side,
/// `-ESRCH` if `id` is not a call the calling service is serving, `-ENAMETOOLONG` for a
/// string with no NUL within `len` bytes.
pub fn client_mem(op: MemOp, id: u64, addr: u64, len: u64, buf: u64) -> i64 {
    if let Err(e) = server_for(id) {
        // wave6 G20: or a request a dcall this thread serves was made for (delegation)
        if !dcall::may_use(id) {
            return e;
        }
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
    // wave9 G6b-2: the kernel buffers a FUSE kernel call lends (`call_vfs_fuse`)
    if (crate::ipc::protocol::FUSE_KBUF_OUT..crate::ipc::protocol::FUSE_KBUF_IN + crate::ipc::protocol::FUSE_KBUF_MAX as u64).contains(&addr) {
        return fuse_kbuf_mem(op, id, addr, len, buf);
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
// Notifications (one ring per host, in its window)
// ----------------------------------------------------------------------

/// Posts process event `kind` (`LX_NOTE_FORK`, `EXEC`, `EXIT`) with `a`, `b`, `c` to every
/// host that subscribed to it and wakes their main threads. Safe with the scheduler lock
/// held (no allocation, a deferred wake only).
pub fn note(kind: u64, a: u64, b: u64, c: u64) {
    for x in svc::hosts() {
        if kind < 64 && x.subs.load(Ordering::Relaxed) & (1 << kind) != 0 && note_quiet_to(x, kind, a, b, c) {
            crate::ipc::service::notify(x.endpoint.load(Ordering::Relaxed), NOTIFY_LX_NOTES);
        }
    }
}

/// Posts notification `kind` to host `h` only (an interrupt, a close, a timer) and wakes
/// its main thread.
pub fn note_to(h: SvcId, kind: u64, a: u64, b: u64, c: u64) {
    if let Some(x) = svc::host(h) {
        if note_quiet_to(x, kind, a, b, c) {
            crate::ipc::service::notify(x.endpoint.load(Ordering::Relaxed), NOTIFY_LX_NOTES);
        }
    }
}

/// [`note_to`] without waking the main thread (the caller does, once for several); `false`
/// when the host is not online.
pub(crate) fn note_quiet_to(x: &Host, kind: u64, a: u64, b: u64, c: u64) -> bool {
    let base = x.notes.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _g = x.notes_lock.lock();
        let w = base as *mut u64;
        // SAFETY: the ring (header and entries) lies in the host's 256 KiB window
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
                x.notes_head.store(head + 1, Ordering::Release);
            }
        }
    });
    true
}

// ----------------------------------------------------------------------
// The crash policy
// ----------------------------------------------------------------------

/// The hook of linux-server's endpoint (`ipc::service::set_signal_hook`).
pub fn on_signal(bits: u64) {
    on_signal_for::<{ crate::ipc::protocol::ENDPOINT_LINUX_SERVER }>(bits)
}

/// The hook of service endpoint `EP`: called with `SIGNAL_GONE` when its process went away
/// (it died, hung, or was restarted by hand), or with [`LX_SIGNAL_OBJS`] (the doorbell:
/// readiness words changed).
///
/// [`LX_SIGNAL_OBJS`]: crate::ipc::protocol::LX_SIGNAL_OBJS
pub fn on_signal_for<const EP: u32>(bits: u64) {
    let Some(h) = svc::host_by_endpoint(EP) else { return };
    if bits == crate::ipc::service::SIGNAL_GONE {
        server_gone(h);
    } else if bits & crate::ipc::protocol::LX_SIGNAL_OBJS != 0 {
        if let Some(x) = svc::host(h) {
            obj::on_doorbell(x);
        }
    }
}

/// Host `h`'s process went away: the calls in flight fail at once with `-EIO`, its remaining
/// threads end, and its crash policy runs: for linux-server every Linux program ends
/// ([`recover_task`], decision 6); for any other service only its own objects fail.
fn server_gone(h: SvcId) {
    let Some(x) = svc::host(h) else { return };
    // wave6 G21 begin: how this going-away is handled (the restart class and the ladder),
    // decided before `online` is cleared so that no caller sees "offline, not restarting"
    let decision = restart::gone(h);
    let class = decision.class;
    let resend = class == restart::RestartClass::Transparent && decision.restart;
    // wave6 G21 end
    let was_online = x.online.swap(false, Ordering::AcqRel);
    // wave8 GD begin: the display service: the console takes the screen at once
    if svc::host_of(crate::ipc::protocol::LXS_DISPLAY) == h {
        crate::ipc::screen::service_gone();
    }
    // wave8 GD end
    if svc::host_of(LXS_NET) == h {
        netwaits(|w| w.clear());
        RELAY_SERVER.store(false, Ordering::Release);
        // wave8 GX2 begin: a Transparent restart (lx-net) keeps its objects, and with them
        // the watched sockets they count (an adopted socket stays counted: zeroing the
        // count would stop the readiness relay for every socket polled across the restart)
        if !resend {
            WATCHED_NET.store(0, Ordering::Release);
        }
        // wave8 GX2 end
    }
    x.notes.store(0, Ordering::Release);
    x.notes_head.store(0, Ordering::Release);
    // wave6 G21: a Transparent restart keeps the objects for the new instance to adopt
    if !resend {
        obj::offline(x);
        // wave8 GH: a device service's objects failed: its devices are announced "removed"
        hotplug::objects_failed(h);
    }
    timer::clear(h);
    let mut clients = [0u64; MAX_REQS];
    let mut n = 0;
    let tgid = x.lx(|s| {
        let tgid = s.server_tgid;
        s.server_tgid = 0;
        // wave8 GX2 begin: the calls being served that their worker marked safe to send again
        // (no effect yet: `LX_CALL_RESEND_OFF` holds the request's id), read before the
        // workers' pages go
        let mut safe = [false; MAX_REQS];
        // ... and those that did part of their work and left the answer for it (a short write)
        let mut partial: [Option<i64>; MAX_REQS] = [None; MAX_REQS];
        if resend {
            for w in s.workers.iter() {
                if w.req < MAX_REQS && s.reqs[w.req].state == RState::Delivered {
                    let p = w.call_mut() as *const u8;
                    let id = s.reqs[w.req].id;
                    // SAFETY: the worker's syscall page (4 KiB) is alive while it is in the table
                    let (mark, pid, pres) = unsafe {
                        (
                            core::ptr::read_volatile(p.add(crate::ipc::protocol::LX_CALL_RESEND_OFF) as *const u64),
                            core::ptr::read_volatile(p.add(crate::ipc::protocol::LX_CALL_PARTIAL_OFF) as *const u64),
                            core::ptr::read_volatile(p.add(crate::ipc::protocol::LX_CALL_PARTIAL_OFF + 8) as *const i64),
                        )
                    };
                    safe[w.req] = mark != 0 && mark == id;
                    if pid != 0 && pid == id && pres > 0 {
                        partial[w.req] = Some(pres);
                    }
                }
            }
        }
        // wave8 GX2 end
        s.workers.clear();
        for t in x.worker_tids.iter() {
            t.store(0, Ordering::Release);
        }
        for (i, r) in s.reqs.iter_mut().enumerate() {
            if matches!(r.state, RState::Queued | RState::Delivered | RState::Pending) {
                x.req_done[i].store(true, Ordering::SeqCst);
                // wave6 G21: a Transparent restart's callers send their calls again (all
                // that had no effect yet; one being served only if it is idempotent)
                r.result = match (resend, r.state) {
                    (true, RState::Delivered) if partial[i].is_some() => partial[i].unwrap_or(EIO), // wave8 GX2
                    (true, RState::Delivered) if safe[i] => restart::LX_RESEND, // wave8 GX2
                    (true, RState::Pending) if r.partial > 0 => r.partial, // wave8 GX2: a waiting send's bytes already sent
                    (true, RState::Delivered) => restart::LX_RESEND_MAYBE,
                    (true, _) => restart::LX_RESEND,
                    _ => EIO,
                };
                r.state = RState::Failed;
                clients[n] = r.client;
                n += 1;
            }
        }
        tgid
    });
    svc::drop_workers(h);
    FAILED_CALLS.fetch_add(n as u64, Ordering::Relaxed);
    x.failed.fetch_add(n as u64, Ordering::Relaxed);
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
        "[lx] {} (process {}) went away: {} calls in flight {}, {} of its threads ended",
        crate::ipc::protocol::LXS_NAMES[h as usize],
        tgid,
        n,
        if resend { "wait to be sent again" } else { "failed with EIO" },
        threads
    );
    // The user's decision 6 (the EndLinux class, linux-server's): every Linux program ends
    // and the desktop comes back at the login screen once the supervisor has restarted the
    // server. The other classes (wave6 G21, `restart`): programs live
    if class == restart::RestartClass::EndLinux && (was_online || tgid != 0) && !x.recovering.swap(true, Ordering::AcqRel) {
        crate::task::spawn("lx-recover", recover_task, crate::task::TaskPriority::Normal);
    }
    // wave8 GX2 begin: lx-ipc's objects failed (not re-sent): the desktop, which lives on its
    // D-Bus and Wayland sockets, ends and the login screen comes back (`desktop`)
    if class != restart::RestartClass::EndLinux && !resend && svc::host_of(crate::ipc::protocol::LXS_IPC) == h && h != LXS_LINUX && (was_online || tgid != 0) {
        desktop::ipc_gone();
    }
    // wave8 GX2 end
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
    if let Some(x) = svc::host(LXS_LINUX) {
        x.recovering.store(false, Ordering::Release);
    }
    crate::task::exit();
}

/// Called by the supervisor every second: a worker thread that died alone (killed by hand)
/// would leave its calls unanswered, so the whole service is ended and restarted.
pub fn watch() {
    for x in svc::hosts() {
        if !x.is_online() {
            continue;
        }
        let (tgid, workers, n) = x.lx(|s| {
            let mut w = [0u64; MAX_WORKERS];
            for (i, k) in s.workers.iter().enumerate() {
                w[i] = k.task;
            }
            (s.server_tgid, w, s.workers.len())
        });
        let mut sched = crate::task::SCHEDULER.lock();
        if let Some(dead) = workers[..n].iter().find(|&&t| !sched.is_task_alive(TaskId(t))) {
            crate::kprintln!("[lx] {} worker {} died: ending the service (process {})", crate::ipc::protocol::LXS_NAMES[x.id as usize], dead, tgid);
            sched.kill_group(tgid);
        }
    }
}

/// The forwarding state for the task dump (QEMU's `nmi`): each host's workers and calls in
/// flight, each CPU's LEAVING mark and the kernel lock's owner. Never waits for a lock.
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
    for x in svc::hosts() {
        let name = crate::ipc::protocol::LXS_NAMES[x.id as usize];
        let Some(s) = x.table.try_lock() else {
            w(&format!("[lx] {}: request table locked\n", name));
            continue;
        };
        w(&format!("[lx] {}: online {}\n", name, x.is_online()));
        for (i, k) in s.workers.iter().enumerate() {
            w(&format!("[lx] {} worker {} task {} idle {} req {} has_work {}\n", name, i, k.task, k.idle, k.req as i64, x.has_work[i].load(Ordering::Relaxed)));
        }
        for (i, r) in s.reqs.iter().enumerate() {
            if r.state != RState::Free {
                w(&format!("[lx] {} req slot {} id {:#x} {:?} client {} result {}\n", name, i, r.id, r.state, r.client, r.result));
            }
        }
    }
}

/// `(online, workers, idle workers, calls in flight, direct, queued, failed)` of
/// linux-server, for the `service` diagnostics.
pub fn stats() -> (bool, usize, usize, usize, u64, u64, u64) {
    let Some(x) = svc::host(LXS_LINUX) else { return (false, 0, 0, 0, 0, 0, 0) };
    let (w, idle, inflight) = x.lx(|s| (s.workers.len(), s.workers.iter().filter(|w| w.idle).count(), s.reqs.iter().filter(|r| r.state != RState::Free).count()));
    (x.is_online(), w, idle, inflight, x.direct.load(Ordering::Relaxed), x.queued.load(Ordering::Relaxed), x.failed.load(Ordering::Relaxed))
}

// ----------------------------------------------------------------------
// Kernel requests to a service's main thread
// ----------------------------------------------------------------------

/// A hand-off request `msg` to the main thread of service `s`'s process, whose answer is
/// text in its window (`/proc/keys`, `/proc/net/*`); `prep` fills the window first.
fn window_text(s: SvcId, msg: crate::ipc::Message, prep: impl FnOnce(&mut [u8])) -> Option<alloc::string::String> {
    use crate::ipc::protocol::{LX_PROC_KEYS_TEXT_MAX, LX_PROC_KEYS_TEXT_OFF};
    let ep = svc::endpoint_of(s);
    let _window = crate::ipc::service::hold_window(ep);
    let win = crate::ipc::service::window(ep)?;
    prep(win);
    let len = match crate::ipc::service::call(ep, msg, crate::ipc::service::CALL_TIMEOUT_TICKS) {
        Ok(r) if (r.args[0] as i64) >= 0 => (r.args[0] as usize).min(LX_PROC_KEYS_TEXT_MAX),
        _ => return None,
    };
    let text = &win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + len];
    Some(alloc::string::String::from_utf8_lossy(text).into_owned())
}

/// `/proc/net/tcp`, `tcp6`, `udp` or `udp6` (Group 12): from the network service, whose
/// sockets they list, once Internet sockets moved; `None` while they are the kernel's.
pub fn proc_net_text(file: &str) -> Option<alloc::string::String> {
    use crate::ipc::protocol::MSG_LX_PROC_NET;
    let code = match file {
        "tcp" => 0,
        "tcp6" => 1,
        "udp" => 2,
        "udp6" => 3,
        _ => return None,
    };
    if !family_moved(2) || !svc::online(LXS_NET) {
        return None;
    }
    let isolated = crate::compat::linux::ns::net_isolated() as u64;
    window_text(LXS_NET, crate::ipc::Message::with_args(MSG_LX_PROC_NET, [code, isolated, 0, 0]), |_| {})
}

/// `/proc/keys` for the calling Linux thread, from the key service when the key calls are
/// forwarded (`None`: the in-kernel table answers). A hand-off call: the reader may hold
/// its descriptor table's lock.
pub fn proc_keys_text() -> Option<alloc::string::String> {
    use crate::ipc::protocol::{LX_PROC_KEYS_GROUPS_OFF, MSG_LX_PROC_KEYS};
    if !keys_forwarded() {
        return None;
    }
    if !svc::online(LXS_SEC) {
        return Some(alloc::string::String::new());
    }
    let (tid, tgid, euid, egid, caps) = crate::task::with_current_task_mut(|t| (t.id.0, t.tgid, t.euid, t.egid, if t.caps.in_userns { 0 } else { t.caps.effective }))?;
    let groups: alloc::vec::Vec<u32> = crate::compat::linux::proc::PROCS.lock().get(&tgid).map(|p| p.groups.clone()).unwrap_or_default();
    let msg = crate::ipc::Message::with_args(MSG_LX_PROC_KEYS, [tid, tgid, euid as u64 | (egid as u64) << 32, caps]);
    let text = window_text(LXS_SEC, msg, |win| {
        let n = groups.len().min(1000);
        win[LX_PROC_KEYS_GROUPS_OFF..LX_PROC_KEYS_GROUPS_OFF + 4].copy_from_slice(&(n as u32).to_le_bytes());
        for (i, g) in groups[..n].iter().enumerate() {
            let o = LX_PROC_KEYS_GROUPS_OFF + 4 + i * 4;
            win[o..o + 4].copy_from_slice(&g.to_le_bytes());
        }
    });
    Some(text.unwrap_or_default())
}

/// Group 13: `/proc/net/unix` from the IPC service when Unix sockets are its own (`None`:
/// the in-kernel table answers). A hand-off call, like `/proc/keys`.
pub fn proc_net_unix_text() -> Option<alloc::string::String> {
    use crate::ipc::protocol::MSG_LX_PROC_NET_UNIX;
    if !step4() {
        return None;
    }
    Some(window_text(LXS_IPC, crate::ipc::Message::with_args(MSG_LX_PROC_NET_UNIX, [0, 0, 0, 0]), |_| {}).unwrap_or_default())
}

// Host tests (test wave, Group 30): tests/host-t30 compiles this file with them
// wave9 G6b-2 begin: FUSE kernel calls to vfs-server, with lent kernel buffers
/// The buffers of the FUSE kernel calls in flight, by calling thread: `(in, out)`. The table
/// owns them (the caller copies in before and out after the call), so a caller torn down
/// while it waits leaves no pointer behind: a late copy by the service still lands in live
/// memory, and the entry goes with the thread's next call or a sweep of dead threads.
static FUSE_KBUFS: Mutex<alloc::collections::BTreeMap<u64, (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>)>> = Mutex::new(alloc::collections::BTreeMap::new());

/// FUSE kernel call `args` ([`LX_KCALL_FUSE`](crate::ipc::protocol::LX_KCALL_FUSE)) to
/// vfs-server for the current thread with input `kin` (the service reads it at
/// `FUSE_KBUF_IN`) and output into `kout` (it writes at `FUSE_KBUF_OUT`). `-ENOTCONN` when
/// vfs-server is not there.
pub fn call_vfs_fuse(args: [u64; 6], kin: &[u8], kout: &mut [u8]) -> i64 {
    use crate::ipc::protocol::{FUSE_KBUF_MAX, LXS_VFS, LX_KCALL_FUSE};
    const ENOTCONN: i64 = -107;
    let Some(x) = svc::host(svc::host_of(LXS_VFS)).filter(|x| host_usable(x)) else { return ENOTCONN };
    let Some(tid) = crate::task::with_current_task_mut(|t| t.id.0) else { return ENOTCONN };
    let bufs = (kin[..kin.len().min(FUSE_KBUF_MAX)].to_vec(), alloc::vec![0u8; kout.len().min(FUSE_KBUF_MAX)]);
    let sweep = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut m = FUSE_KBUFS.lock();
        m.insert(tid, bufs);
        (m.len() > 64).then(|| m.keys().copied().collect::<alloc::vec::Vec<u64>>())
    });
    // (entries of threads that died waiting: dropped now and then)
    if let Some(tids) = sweep {
        let dead: alloc::vec::Vec<u64> = {
            let sched = crate::task::SCHEDULER.lock();
            tids.into_iter().filter(|&t| t != tid && !sched.is_task_alive(TaskId(t))).collect()
        };
        x86_64::instructions::interrupts::without_interrupts(|| {
            let mut m = FUSE_KBUFS.lock();
            for t in dead {
                m.remove(&t);
            }
        });
    }
    let mut c = LxCall::EMPTY;
    c.nr = LX_KCALL_FUSE;
    c.args = args;
    c.svc = LXS_VFS as u32;
    let r = call_ident(x, c, false);
    let out = x86_64::instructions::interrupts::without_interrupts(|| FUSE_KBUFS.lock().remove(&tid));
    if let Some((_, out)) = out {
        let n = out.len().min(kout.len());
        kout[..n].copy_from_slice(&out[..n]);
    }
    r
}

/// [`client_mem`] at a FUSE kernel call's buffers: writes go to the out buffer, reads come
/// from the in buffer; only vfs-server, only for a call it is serving.
fn fuse_kbuf_mem(op: MemOp, id: u64, addr: u64, len: u64, buf: u64) -> i64 {
    use crate::ipc::protocol::{FUSE_KBUF_IN, FUSE_KBUF_OUT, LXS_VFS};
    if lx_req_svc(id) != svc::host_of(LXS_VFS) {
        return EFAULT;
    }
    let Some(client) = client_of(id) else { return ESRCH };
    let out = addr < FUSE_KBUF_IN;
    if out != (op == MemOp::Write) || op == MemOp::ReadStr {
        return EFAULT;
    }
    let off = (addr - if out { FUSE_KBUF_OUT } else { FUSE_KBUF_IN }) as usize;
    let n = len as usize;
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut l = FUSE_KBUFS.lock();
        let Some((kin, kout)) = l.get_mut(&client) else { return EFAULT };
        let cap = if out { kout.len() } else { kin.len() };
        if off.checked_add(n).is_none_or(|e| e > cap) {
            return EFAULT;
        }
        // SAFETY: the range lies in the table's own buffer, and the service's range was
        // faulted in (client_mem)
        unsafe {
            if out {
                core::ptr::copy_nonoverlapping(buf as *const u8, kout.as_mut_ptr().add(off), n);
            } else {
                core::ptr::copy_nonoverlapping(kin.as_ptr().add(off), buf as *mut u8, n);
            }
        }
        n as i64
    })
}

/// `open` of character device `rdev` served by service `s` (not by a major claim: `/dev/fuse`
/// is 10:229, and major 10 is shared): as [`dev_open`] once the service is chosen.
pub fn dev_open_to(s: SvcId, rdev: u64, flags: u32) -> Result<Arc<dyn crate::compat::linux::chardev::CharDevice>, i64> {
    let Some(x) = svc::host(svc::host_of(s)).filter(|x| host_usable(x)) else { return Err(-19) };
    let mut c = LxCall::EMPTY;
    c.nr = crate::ipc::protocol::LX_KCALL_DEVOPEN;
    c.args = [rdev, flags as u64, 0, 0, 0, 0];
    c.dev = rdev;
    c.svc = s as u32;
    let fd = call_ident(x, c, true);
    if fd < 0 {
        return Err(fd);
    }
    match crate::task::with_current_fds_mut(|t| t.set_fd(fd as usize, None)) {
        Some(crate::fs::FileDescriptor::Device(d)) if d.as_server().is_some() => Ok(d),
        _ => Err(EIO),
    }
}
// wave9 G6b-2 end

#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_mod.rs"]
pub(crate) mod tests;
