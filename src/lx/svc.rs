//! # The service registry (wave 6, Group 19)
//!
//! Since decision 9 the Linux layer is several ring-3 services, not one linux-server
//! (`docs/linux-services-design.md`, section 3). The kernel routes each forwarded call to the
//! service that owns it; this module says which process that is.
//!
//! - **A service id** ([`SvcId`], `LXS_*` in `ipc/protocol.rs`) names a Linux-facing service:
//!   keys and bpf ([`LXS_SEC`]), sockets ([`LXS_NET`]), pipes and Unix sockets ([`LXS_IPC`]),
//!   the test service ([`LXS_TEST`]), and so on. The forwarding table's entries name ids.
//! - **The registry** ([`SVC`]) gives each id its endpoint, its *host* and its mode. Several
//!   ids may name one endpoint: they are **co-located** in one process (today every split
//!   piece still lives in linux-server, endpoint 0x29). Splitting a piece out means giving
//!   its id another endpoint and starting a program there: the routing does not change.
//! - **A host** ([`Host`]) is the runtime state of one serving process: its request table,
//!   its workers, its notification ring, its object area. It is named by the id of the
//!   process's first service (linux-server: [`LXS_LINUX`]), allocated when its first worker
//!   attaches, and never freed (a restarted process gets the same one), so a `&'static Host`
//!   is always valid. Request ids carry the host (`id = host << 56 | sequence`).
//! - **Switching back** per service (decision 17): `lx.<name>=kernel` sends that service's
//!   calls back to the in-kernel code, `lx.<name>=linux` co-locates a split service back in
//!   linux-server; `lx=kernel` does it for every service.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering};
use spin::Mutex;

use crate::ipc::protocol::{
    LxCall, SvcId, ENDPOINT_DISPLAY_DEV, ENDPOINT_LINUX_SERVER, ENDPOINT_SVC_TEST, ENDPOINT_VFS_SERVER, LXS_DISPLAY, LXS_INPUT, LXS_IPC, LXS_LINUX, LXS_MAX, LXS_NAMES,
    LXS_NET, LXS_PROC, LXS_SEC, LXS_SOUND, LXS_TEST, LXS_TTY, LXS_VFS, LX_NOTE_EXEC, LX_NOTE_EXIT, LX_NOTE_FORK, LX_SVC_CLAIM_MAJOR, LX_SVC_SUBSCRIBE, LX_SVC_WHOAMI,
};
use crate::ipc::service::ContiguousFrames;

const EPERM: i64 = -1;
const EINVAL: i64 = -22;

/// Most worker threads of one host.
pub const MAX_WORKERS: usize = 16;
/// Calls in flight at once in one host (queued, served, or pending).
pub const MAX_REQS: usize = 128;
/// No request.
pub(super) const NONE: usize = usize::MAX;

/// How a service's calls are answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SvcMode {
    /// Forwarded to the service's host.
    Forward = 0,
    /// Answered by the in-kernel code (`lx.<name>=kernel`, or `lx=kernel` for all).
    Kernel = 1,
}

/// One registry entry.
pub struct SvcEntry {
    /// The endpoint of the process that serves the id (several ids may share one).
    endpoint: AtomicU32,
    /// The host serving it now (0: none online yet).
    host: AtomicU8,
    /// [`SvcMode`].
    mode: AtomicU8,
}

/// The registry, by service id.
pub static SVC: [SvcEntry; LXS_MAX] = [const { SvcEntry { endpoint: AtomicU32::new(0), host: AtomicU8::new(0), mode: AtomicU8::new(0) } }; LXS_MAX];

/// The endpoints the registry starts with: every piece still split out lives in
/// linux-server (co-located); vfs-server and the device services have endpoints of their
/// own (nothing serves them yet).
// wave6: a group that splits a piece out changes its line here (Group 24: LXS_SEC -> 0x31)
const DEFAULT_ENDPOINTS: [(SvcId, u32); 11] = [
    (LXS_LINUX, ENDPOINT_LINUX_SERVER),
    (LXS_VFS, ENDPOINT_VFS_SERVER),
    (LXS_NET, ENDPOINT_LINUX_SERVER),
    (LXS_IPC, ENDPOINT_LINUX_SERVER),
    (LXS_PROC, ENDPOINT_LINUX_SERVER),
    (LXS_DISPLAY, ENDPOINT_DISPLAY_DEV),
    (LXS_INPUT, 0x2A),
    (LXS_SOUND, 0x2B),
    (LXS_TTY, 0x2C),
    (LXS_SEC, ENDPOINT_LINUX_SERVER),
    (LXS_TEST, ENDPOINT_SVC_TEST),
];

/// Fills the registry (once, at boot, before the services start) and applies the boot words
/// `words` (`lx=kernel`, `lx.<name>=kernel`, `lx.<name>=linux`; separated by `+`, `,`, `;` or
/// blanks, the `lx.` prefix optional): returns whether `lx=kernel` (everything back) was given.
pub fn init(words: &[u8]) -> bool {
    for &(id, ep) in DEFAULT_ENDPOINTS.iter() {
        SVC[id as usize].endpoint.store(ep, Ordering::Release);
    }
    let mut all_kernel = false;
    for w in words.split(|c| matches!(c, b'+' | b',' | b';' | b' ' | b'\n' | b'\r' | b'\t' | 0)) {
        let w = w.strip_prefix(b"lx.").unwrap_or(w);
        let w = w.strip_prefix(b"lx=").map_or(w, |rest| if rest == b"kernel" { b"kernel".as_slice() } else { w });
        if w == b"kernel" {
            all_kernel = true;
            continue;
        }
        let Some(eq) = w.iter().position(|&c| c == b'=') else { continue };
        let (name, val) = (&w[..eq], &w[eq + 1..]);
        let Some(id) = LXS_NAMES.iter().position(|n| n.as_bytes() == name) else { continue };
        if id == 0 {
            continue;
        }
        match val {
            b"kernel" => SVC[id].mode.store(SvcMode::Kernel as u8, Ordering::Release),
            b"linux" => SVC[id].endpoint.store(ENDPOINT_LINUX_SERVER, Ordering::Release),
            _ => {}
        }
    }
    // Each id starts with the host its endpoint will have (the lowest id naming it)
    for id in 1..LXS_MAX {
        let ep = SVC[id].endpoint.load(Ordering::Acquire);
        SVC[id].host.store(if ep == 0 { 0 } else { home_of(ep) }, Ordering::Release);
    }
    all_kernel
}

/// The id whose host serves endpoint `ep`: the lowest id naming it (0: none).
fn home_of(ep: u32) -> SvcId {
    (1..LXS_MAX).find(|&i| SVC[i].endpoint.load(Ordering::Acquire) == ep).unwrap_or(0) as SvcId
}

/// The boot log: one line per service that has an endpoint.
pub fn log_lines(all_kernel: bool) {
    for id in 1..LXS_MAX {
        let ep = SVC[id].endpoint.load(Ordering::Acquire);
        if ep == 0 {
            continue;
        }
        let name = LXS_NAMES[id];
        let h = SVC[id].host.load(Ordering::Acquire);
        if all_kernel || mode(id as SvcId) == SvcMode::Kernel {
            crate::kprintln!("[lx] {}: in the kernel ({})", name, if all_kernel { "lx=kernel" } else { "lx.<name>=kernel" });
        } else if h as usize != id {
            crate::kprintln!("[lx] {}: {} (co-located, endpoint {:#x})", name, LXS_NAMES[h as usize], ep);
        } else {
            crate::kprintln!("[lx] {}: its own process (endpoint {:#x}, when started)", name, ep);
        }
    }
}

/// Service `svc`'s mode.
#[inline]
pub fn mode(svc: SvcId) -> SvcMode {
    if (svc as usize) < LXS_MAX && SVC[svc as usize].mode.load(Ordering::Relaxed) == SvcMode::Kernel as u8 {
        SvcMode::Kernel
    } else {
        SvcMode::Forward
    }
}

/// The host that serves service `svc` (0: none).
#[inline]
pub fn host_of(svc: SvcId) -> SvcId {
    if (svc as usize) < LXS_MAX {
        SVC[svc as usize].host.load(Ordering::Relaxed)
    } else {
        0
    }
}

/// The endpoint of service `svc`'s process (0: none).
pub fn endpoint_of(svc: SvcId) -> u32 {
    if (svc as usize) < LXS_MAX {
        SVC[svc as usize].endpoint.load(Ordering::Acquire)
    } else {
        0
    }
}

/// The host id of the process serving endpoint `ep` (`None`: no service there).
pub fn host_by_endpoint(ep: u32) -> Option<SvcId> {
    let h = home_of(ep);
    (h != 0).then_some(h)
}

/// Whether service `svc` is served now (its host's workers are online).
#[inline]
pub fn online(svc: SvcId) -> bool {
    host(host_of(svc)).is_some_and(|h| h.online.load(Ordering::Acquire))
}

// ----------------------------------------------------------------------
// Hosts
// ----------------------------------------------------------------------

/// Where a request is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum RState {
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
pub(super) struct Req {
    pub state: RState,
    pub id: u64,
    /// The calling thread.
    pub client: u64,
    /// Where the caller is in the scheduler's task table (a hint).
    pub client_idx: usize,
    pub result: i64,
    /// A signal arrived for the caller while the call was in the server.
    pub interrupted: bool,
    /// The call has copies ([`super::copy::describe`]): its header (and, while queued, its
    /// bytes) are in the host's copy buffer at the same index.
    pub has_copy: bool,
    /// Group 12: `SYS_LX_COMPLETE` came while the call was still being served (the server
    /// kept it as waiting and another of its threads finished it before the worker's
    /// "pending" answer reached the kernel): `result` holds the answer, and the "pending"
    /// answer turns into it.
    pub early: bool,
    /// Group 19: the answer was a redirect: `(result word, object)`.
    pub redir: (u64, u64),
}

impl Req {
    pub const FREE: Self = Self { state: RState::Free, id: 0, client: 0, client_idx: 0, result: 0, interrupted: false, has_copy: false, early: false, redir: (0, 0) };
}

/// A worker thread of a host.
pub(super) struct Worker {
    pub task: u64,
    /// Its syscall page.
    pub page: Arc<ContiguousFrames>,
    /// Waiting in `SYS_LX_REPLY_RECV` for a call (blocked).
    pub idle: bool,
    /// The request it serves (an index into `reqs`; [`NONE`]).
    pub req: usize,
    /// Where it is in the scheduler's task table (a hint).
    pub idx: usize,
}

impl Worker {
    /// Its syscall page, through the kernel's direct map.
    pub fn call_mut(&self) -> *mut LxCall {
        crate::memory::frame_allocator::phys_to_virt(self.page.base) as *mut LxCall
    }
}

/// A host's request table (under [`Host::table`]).
pub(super) struct Lx {
    /// The server process the workers belong to (0: none).
    pub server_tgid: u64,
    pub workers: Vec<Worker>,
    pub reqs: Vec<Req>,
    /// The calls of queued requests (same index).
    pub calls: Vec<LxCall>,
    /// The next request's sequence number (the host id goes in the top byte).
    pub next_id: u64,
}

/// The copies of each request slot (the copy-in/copy-out table, [`super::copy`]): the header
/// always, the copied-in bytes while the call is queued, the output after the answer. A
/// slot's buffer belongs to whoever holds the request: written under the request table's
/// lock while the call is placed, delivered or answered, read by the caller alone once it
/// saw the answer (the slot is freed after that). Kernel memory, so a caller that dies with
/// its call in the server leaves nothing dangling.
pub(super) struct CopyBufs(pub Box<[UnsafeCell<super::copy::CopyBuf>]>);
// SAFETY: see the type: every access is ordered by the request table's lock
unsafe impl Sync for CopyBufs {}

/// The runtime state of one serving process (see the module documentation).
pub struct Host {
    /// Its id (the first service its process serves).
    pub id: SvcId,
    /// Its endpoint.
    pub endpoint: AtomicU32,
    pub(super) table: Mutex<Lx>,
    pub(super) bufs: CopyBufs,
    /// The server's workers are attached and its endpoint registered: calls are forwarded.
    pub(super) online: AtomicBool,
    /// Per request slot: the call was answered (or failed) (Group 10's rule).
    pub(super) req_done: [AtomicBool; MAX_REQS],
    /// Per worker: a call was delivered to it that it has not taken yet.
    pub(super) has_work: [AtomicBool; MAX_WORKERS],
    /// The worker thread IDs (0: none).
    pub(super) worker_tids: [AtomicU64; MAX_WORKERS],
    /// Kernel address of the notification ring's header in the host's window (0: offline).
    pub(super) notes: AtomicU64,
    /// Posting is serialized.
    pub(super) notes_lock: Mutex<()>,
    /// A copy of the ring's head (a forwarded call reads it without touching the window).
    pub(super) notes_head: AtomicU64,
    /// The process events it wants (bit k: notification kind k).
    pub subs: AtomicU64,
    /// Its server objects.
    pub(super) objs: super::obj::HostObjs,
    /// A recovery after a crash is in progress (EndLinux).
    pub(super) recovering: AtomicBool,
    /// Calls handed to a worker directly, queued, failed.
    pub direct: AtomicU64,
    /// See [`Host::direct`].
    pub queued: AtomicU64,
    /// See [`Host::direct`].
    pub failed: AtomicU64,
}

/// The hosts, by id (null: none yet).
static HOSTS: [AtomicPtr<Host>; LXS_MAX] = [const { AtomicPtr::new(core::ptr::null_mut()) }; LXS_MAX];
/// Serializes making hosts.
static MAKING: Mutex<()> = Mutex::new(());

/// Host `h` (`None`: none was made).
#[inline]
pub fn host(h: SvcId) -> Option<&'static Host> {
    if h as usize >= LXS_MAX {
        return None;
    }
    let p = HOSTS[h as usize].load(Ordering::Acquire);
    // SAFETY: hosts are leaked boxes, never freed
    (!p.is_null()).then(|| unsafe { &*p })
}

/// Every host made so far.
pub fn hosts() -> impl Iterator<Item = &'static Host> {
    (0..LXS_MAX as SvcId).filter_map(host)
}

/// Host `h`, made now if it does not exist yet (its process attaches its first worker).
pub(super) fn host_or_make(h: SvcId, ep: u32) -> &'static Host {
    if let Some(x) = host(h) {
        return x;
    }
    let _g = MAKING.lock();
    if let Some(x) = host(h) {
        return x;
    }
    let mut reqs = Vec::with_capacity(MAX_REQS);
    reqs.resize(MAX_REQS, Req::FREE);
    let mut calls = Vec::with_capacity(MAX_REQS);
    calls.resize(MAX_REQS, LxCall::EMPTY);
    let bufs: Box<[UnsafeCell<super::copy::CopyBuf>]> = (0..MAX_REQS).map(|_| UnsafeCell::new(super::copy::CopyBuf::EMPTY)).collect::<Vec<_>>().into_boxed_slice();
    let x = Box::new(Host {
        id: h,
        endpoint: AtomicU32::new(ep),
        table: Mutex::new(Lx { server_tgid: 0, workers: Vec::new(), reqs, calls, next_id: 1 }),
        bufs: CopyBufs(bufs),
        online: AtomicBool::new(false),
        req_done: [const { AtomicBool::new(false) }; MAX_REQS],
        has_work: [const { AtomicBool::new(false) }; MAX_WORKERS],
        worker_tids: [const { AtomicU64::new(0) }; MAX_WORKERS],
        notes: AtomicU64::new(0),
        notes_lock: Mutex::new(()),
        notes_head: AtomicU64::new(0),
        // linux-server hosts every piece that wants process events
        subs: AtomicU64::new(if h == LXS_LINUX { 1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT } else { 0 }),
        objs: super::obj::HostObjs::new(),
        recovering: AtomicBool::new(false),
        direct: AtomicU64::new(0),
        queued: AtomicU64::new(0),
        failed: AtomicU64::new(0),
    });
    let p = Box::into_raw(x);
    HOSTS[h as usize].store(p, Ordering::Release);
    // SAFETY: just made, never freed
    unsafe { &*p }
}

impl Host {
    /// Request slot `slot`'s copy buffer (see [`CopyBufs`] for who may use it when).
    #[allow(clippy::mut_from_ref)]
    pub(super) fn buf(&self, slot: usize) -> &mut super::copy::CopyBuf {
        // SAFETY: see CopyBufs
        unsafe { &mut *self.bufs.0[slot].get() }
    }

    /// Runs `f` on the request table with interrupts off (serving TLB flush requests while
    /// waiting for the lock: the lock-free path takes it without the kernel lock).
    #[inline]
    pub(super) fn lx<R>(&self, f: impl FnOnce(&mut Lx) -> R) -> R {
        x86_64::instructions::interrupts::without_interrupts(|| f(&mut super::copy::lock_serving(&self.table)))
    }

    /// Whether its workers are serving calls.
    #[inline]
    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// The ring position: what has been posted so far.
    #[inline]
    pub(super) fn notes_head(&self) -> u64 {
        self.notes_head.load(Ordering::Acquire)
    }

    /// The services this host serves now (ids whose host it is), as a bit set.
    pub fn serves(&self) -> u32 {
        (1..LXS_MAX).filter(|&i| host_of(i as SvcId) == self.id).fold(0, |m, i| m | 1 << i)
    }
}

// ----------------------------------------------------------------------
// Workers, across hosts (the system call entry must tell a worker's call 52 from a Linux
// `getpeername` without any lock)
// ----------------------------------------------------------------------

/// Every attached worker of every host: `tid << 8 | host` (0: free).
static ALL_WORKERS: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// Entries of [`ALL_WORKERS`] ever used (the scan stops there).
static ALL_USED: AtomicU64 = AtomicU64::new(0);

/// The host whose worker thread `tid` is (`None`: not a worker).
#[inline]
pub(super) fn worker_host(tid: u64) -> Option<SvcId> {
    if tid == 0 {
        return None;
    }
    let n = ALL_USED.load(Ordering::Acquire) as usize;
    ALL_WORKERS[..n.min(64)].iter().map(|w| w.load(Ordering::Relaxed)).find(|w| w >> 8 == tid).map(|w| w as SvcId)
}

/// Records worker `tid` of host `h`.
pub(super) fn add_worker(tid: u64, h: SvcId) {
    let v = tid << 8 | h as u64;
    for (i, w) in ALL_WORKERS.iter().enumerate() {
        if w.compare_exchange(0, v, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            ALL_USED.fetch_max(i as u64 + 1, Ordering::AcqRel);
            return;
        }
    }
}

/// Forgets every worker of host `h`.
pub(super) fn drop_workers(h: SvcId) {
    for w in ALL_WORKERS.iter() {
        let v = w.load(Ordering::Acquire);
        if v != 0 && v as u8 == h {
            let _ = w.compare_exchange(v, 0, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

/// The process serving `ep` attached: it is now the host of every id that names `ep`.
pub(super) fn take_ids(h: SvcId, ep: u32) {
    for id in 1..LXS_MAX {
        if SVC[id].endpoint.load(Ordering::Acquire) == ep {
            SVC[id].host.store(h, Ordering::Release);
        }
    }
}

// ----------------------------------------------------------------------
// Device majors
// ----------------------------------------------------------------------

/// Per character major: the service whose `open` it is (0: the kernel's own drivers).
pub static MAJOR_SVC: [AtomicU8; 256] = [const { AtomicU8::new(0) }; 256];

/// The service that claimed character major `major` and is online (0: none).
pub fn major_svc(major: u64) -> SvcId {
    if major >= 256 {
        return 0;
    }
    let s = MAJOR_SVC[major as usize].load(Ordering::Acquire);
    if s != 0 && mode(s) == SvcMode::Forward && online(s) && !super::all_kernel() {
        s
    } else {
        0
    }
}

// ----------------------------------------------------------------------
// SYS_LX_SVC (native 72)
// ----------------------------------------------------------------------

/// `SYS_LX_SVC(op, a, b, c)`: a service's registry operations (`LX_SVC_*`).
pub fn svc_ctl(op: u64, a: u64, b: u64, _c: u64) -> i64 {
    let h = match super::server_caller() {
        Ok((_, _, h)) => h,
        Err(e) => return e,
    };
    match op {
        LX_SVC_SUBSCRIBE => {
            let Some(x) = host(h) else { return EINVAL };
            x.subs.store(a & (1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT), Ordering::Release);
            0
        }
        LX_SVC_CLAIM_MAJOR => {
            let svc = if b == 0 { h } else { b as SvcId };
            if a >= 256 || svc as usize >= LXS_MAX || host_of(svc) != h {
                return EINVAL;
            }
            let cur = MAJOR_SVC[a as usize].load(Ordering::Acquire);
            if cur != 0 && cur != svc && online(cur) {
                return EPERM;
            }
            MAJOR_SVC[a as usize].store(svc, Ordering::Release);
            0
        }
        LX_SVC_WHOAMI => h as i64,
        // wave6 G20 begin: ops 3-7
        // wave6 G20 end
        // wave6 G21 begin: ops 16-23
        16..=23 => super::restart::svc_op(h, op, a, b, _c),
        // wave6 G21 end
        _ => EINVAL,
    }
}
