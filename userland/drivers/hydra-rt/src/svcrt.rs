//! # The service runtime (wave 6, Group 19)
//!
//! Every Linux-facing service (linux-server, the test service, later lx-sec, vfs-server,
//! ...) runs the same machinery, which this module holds once
//! (`docs/linux-services-design.md`, section 3):
//!
//! - **Workers** ([`start`]): `N` threads, each attaching a syscall page (`SYS_LX_CTL`) and
//!   looping in `SYS_LX_REPLY_RECV`: the kernel puts a forwarded call in the page (an
//!   [`LxCall`]) and hands the CPU straight to the worker; the worker serves it with the
//!   service's `serve` function and answers, which hands the CPU straight back to the
//!   caller and waits for the next call.
//! - **The main thread** ([`Service`]): registers the endpoint, maps the object area, goes
//!   online, then serves the endpoint: supervisor heartbeats, kernel requests, notifications.
//! - **The call being served** ([`Cx`]): the caller's identity and memory (the copy-in /
//!   copy-out table in the page, or the client memory primitives).
//! - **Objects** ([`objs`]): server-object slots, readiness words and the doorbell, for a
//!   small service (linux-server keeps its own, richer allocator on the same area).
//! - **Notifications** ([`notes`]): the ring in the window, read in order.
//! - **Redirects** ([`redirect`]): "this call is another service's".

use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::protocol::{
    LxCall, LxCopy, LxObjDesc, SvcId, LX_COPY_OFF, LX_CTL_ATTACH, LX_CTL_OBJAREA, LX_CTL_ONLINE, LX_DATA_OFF, LX_GROUPS, LX_OBJ_CHANGED_OFF, LX_OBJ_INSTALL, LX_OBJ_NAME_MAX,
    LX_OBJ_OFF, LX_OBJ_SLOTS, LX_OBJ_WATCHED_OFF, LX_PAGE_SIZE, LX_REPLY_NONE, LX_REPLY_REDIRECT, LX_SIGNAL_OBJS, LX_SVC_SUBSCRIBE, MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG,
};
use crate::{println, sys, Message, Server};

const EFAULT: i64 = -14;
const ENFILE: i64 = -23;
const ENAMETOOLONG: i64 = -36;

/// Stack of each worker thread.
const WORKER_STACK: usize = 256 * 1024;
/// Most workers of one service (the kernel's `svc::MAX_WORKERS`).
pub const MAX_WORKERS: usize = 16;

/// A forwarded call's answer: `(result, SYS_LX_REPLY_RECV flags)`.
pub type Answer = (i64, u64);
/// A service's call handler: the call, and the worker's syscall page.
pub type ServeFn = fn(&LxCall, *mut u8) -> Answer;

/// How a service starts.
pub struct Config {
    /// Its name (in log lines).
    pub name: &'static str,
    /// Its endpoint.
    pub endpoint: u32,
    /// Worker threads.
    pub workers: usize,
    /// The process events it wants in its ring (`LX_SVC_SUBSCRIBE`: bit k = kind k), if any.
    pub subscribe: Option<u64>,
}

/// The `workers=N` argument, or `default` (1..=[`MAX_WORKERS`]).
pub fn workers_arg(args: &[&str], default: usize) -> usize {
    args.iter().find_map(|a| a.strip_prefix("workers=")).and_then(|n| n.parse::<usize>().ok()).unwrap_or(default).clamp(1, MAX_WORKERS)
}

/// The service's handler (a `ServeFn` as an address: set once by [`start`]).
static SERVE: AtomicUsize = AtomicUsize::new(0);
/// Workers that attached their syscall page.
static ATTACHED: AtomicUsize = AtomicUsize::new(0);
/// The service's name, for the workers' log lines.
static NAME: spin::Mutex<&'static str> = spin::Mutex::new("service");

/// A started service (its main thread's side).
pub struct Service {
    /// The endpoint's server (window, receive, reply).
    pub srv: Server,
    /// The object area (readiness slots and bitmaps, [`LX_OBJ_OFF`]).
    pub area: *mut u8,
}

/// Starts service `cfg`: its workers (each serving calls with `serve`), waits for them to
/// attach, registers the endpoint, maps the object area and subscribes to process events.
/// The caller then sets up what it keeps in the window and calls [`Service::online`].
///
/// # Errors
/// The kernel's error when it refuses the endpoint or the object area; `-EAGAIN` when the
/// workers did not attach within 5 s.
pub fn start(cfg: &Config, serve: ServeFn) -> Result<Service, i64> {
    *NAME.lock() = cfg.name;
    SERVE.store(serve as usize, Ordering::Release);
    for i in 0..cfg.workers {
        let stack = sys::map_anon(WORKER_STACK)?;
        // 16-byte aligned, minus the return address a call would have pushed
        let top = stack + WORKER_STACK as u64 - 8;
        // SAFETY: a fresh stack of its own
        unsafe { sys::thread_create(worker, top, i as u64) }?;
    }
    // Every worker attached before the endpoint is registered (the supervisor waits for
    // the registration; calls are forwarded from LX_CTL_ONLINE on)
    let deadline = sys::uptime_ticks() + 500;
    while ATTACHED.load(Ordering::Acquire) < cfg.workers {
        if sys::uptime_ticks() > deadline {
            println!("[{}] only {} of {} workers attached", cfg.name, ATTACHED.load(Ordering::Acquire), cfg.workers);
            return Err(-11);
        }
        // (wave6 G25: a sleep, not a yield: on one CPU a yield back to this thread never lets
        // the workers it waits for run)
        sys::sleep_ms(1);
    }
    let srv = Server::register(cfg.endpoint)?;
    let area = sys::lx_ctl(LX_CTL_OBJAREA)? as *mut u8;
    if let Some(mask) = cfg.subscribe {
        sys::lx_svc(LX_SVC_SUBSCRIBE, mask, 0, 0)?;
    }
    Ok(Service { srv, area })
}

/// What the main thread received.
pub enum Event {
    /// A request on the endpoint (`id`, message): answer it with [`Service::reply`].
    Request(u64, Message),
    /// Notification bits (`MSG_SVC_NOTIFY`: the ring has entries, ...).
    Notify(u64),
    /// Nothing within the timeout.
    Idle,
}

impl Service {
    /// Starts forwarding (the kernel empties the ring and the readiness slots first).
    ///
    /// # Errors
    /// The kernel's error.
    pub fn online(&self) -> Result<(), i64> {
        sys::lx_ctl(LX_CTL_ONLINE).map(|_| ())
    }

    /// The window shared with the kernel (the notification ring, text areas).
    pub fn window(&mut self) -> &mut [u8] {
        self.srv.window()
    }

    /// Waits up to `timeout` ticks (0: forever) for a request or a notification; answers
    /// supervisor heartbeats itself.
    pub fn recv(&mut self, timeout: u64) -> Event {
        match sys::svc_recv_notify(self.srv.endpoint, timeout) {
            Ok((0, m)) if m.args[0] != 0 => Event::Notify(m.args[0]),
            Ok((0, _)) | Err(_) => Event::Idle,
            Ok((id, req)) => {
                if req.label == MSG_SUPERVISOR_PING as u64 {
                    let _ = sys::svc_reply(self.srv.endpoint, id, &Message::new(MSG_SUPERVISOR_PONG as u64, [req.args[0], 1, 0, 0]));
                    return Event::Idle;
                }
                Event::Request(id, req)
            }
        }
    }

    /// Answers request `id`.
    pub fn reply(&mut self, id: u64, msg: &Message) {
        let _ = sys::svc_reply(self.srv.endpoint, id, msg);
    }
}

/// A worker thread: attaches its syscall page and serves forwarded calls forever.
extern "C" fn worker(_index: u64) -> ! {
    let name = *NAME.lock();
    let page = match sys::lx_ctl(LX_CTL_ATTACH) {
        Ok(p) => p,
        Err(e) => {
            println!("[{}] worker cannot attach: {}", name, e);
            sys::exit_group(1);
        }
    };
    ATTACHED.fetch_add(1, Ordering::AcqRel);
    // SAFETY: set by `start` before any worker started, to a `ServeFn`
    let serve: ServeFn = unsafe { core::mem::transmute::<usize, ServeFn>(SERVE.load(Ordering::Acquire)) };
    let call = page as *const LxCall;
    let mut answer = (0i64, LX_REPLY_NONE);
    loop {
        match sys::lx_reply_recv(answer.0, answer.1) {
            Ok(()) => {
                // SAFETY: the kernel filled the page before returning; it is ours alone
                let c = unsafe { core::ptr::read_volatile(call) };
                answer = serve(&c, page as *mut u8);
            }
            Err(e) => {
                // The kernel no longer knows this worker (the service is being replaced)
                println!("[{}] worker: reply_recv failed: {}", name, e);
                sys::exit_group(1);
            }
        }
    }
}

/// The answer that sends the call being served (in syscall page `page`) on to service
/// `svc`, naming object `obj` and the path position `tail` there (Group 16's lookups).
pub fn redirect(page: *mut u8, svc: SvcId, obj: u64, tail: u32) -> Answer {
    // SAFETY: the worker's own page; the kernel reads `redir_obj` when it takes the answer
    unsafe { core::ptr::write_volatile(&mut (*(page as *mut LxCall)).redir_obj, obj) };
    (svc as i64 | (tail as i64) << 32, LX_REPLY_REDIRECT)
}

// ----------------------------------------------------------------------
// The call being served (moved from linux-server's client.rs)
// ----------------------------------------------------------------------

/// `CAP_SYS_ADMIN`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// The caller's identity as a service checks it: thread, process, effective user and group
/// (the file system IDs Linux uses equal them here), `CAP_SYS_ADMIN`, and the
/// supplementary groups.
#[derive(Clone, Copy)]
pub struct Caller {
    /// Thread ID.
    pub tid: u64,
    /// Process ID.
    pub tgid: u64,
    /// Effective user ID.
    pub uid: u32,
    /// Effective group ID.
    pub gid: u32,
    /// Holds `CAP_SYS_ADMIN`.
    pub admin: bool,
    ngroups: usize,
    groups: [u32; LX_GROUPS],
}

impl Caller {
    /// A caller described by the kernel's words (`MSG_LX_PROC_KEYS`).
    pub fn new(tid: u64, tgid: u64, uid: u32, gid: u32, caps: u64, groups: &[u32]) -> Self {
        let mut g = [0u32; LX_GROUPS];
        let n = groups.len().min(LX_GROUPS);
        g[..n].copy_from_slice(&groups[..n]);
        Self { tid, tgid, uid, gid, admin: caps & CAP_SYS_ADMIN != 0, ngroups: n, groups: g }
    }

    /// Whether `gid` is one of the supplementary groups.
    pub fn in_groups(&self, gid: u32) -> bool {
        self.groups[..self.ngroups].contains(&gid)
    }
}

/// A forwarded call being served. Pointer arguments the kernel's copy-in table describes
/// are already in the syscall page (`LxCopy`, wave 4); the rest go through the kernel's
/// client memory primitives, `SYS_LX_READ` / `SYS_LX_WRITE` / `SYS_LX_READ_STR`.
/// [`Cx::copy_in`], [`Cx::user_cstr`] and [`Cx::copy_out`] pick the page when they can and
/// fall back by themselves, so code serving a call never needs to know.
///
/// Output written to the page is copied to the caller by the kernel after the answer: only
/// for an immediate answer (a call answered `LX_REPLY_PENDING` must write its output with
/// `SYS_LX_WRITE`, as [`Cx::copy_out_direct`] does, since the page is reused meanwhile).
pub struct Cx {
    /// The request's ID (it names the caller to the client memory primitives).
    pub id: u64,
    /// Linux system call number.
    pub nr: u64,
    /// Its arguments.
    pub args: [u64; 6],
    /// The whole call as the kernel gave it (identity, server object, IPC namespace).
    pub c: LxCall,
    caller: Caller,
    /// The worker's syscall page (null: none, e.g. a kernel request), and its copy header.
    page: *mut u8,
    copy: LxCopy,
    /// Output lengths written to the page so far (the kernel reads them after the answer).
    out_len: [Cell<u16>; 6],
}

impl Cx {
    /// The call in a worker's syscall page `page` (`c` is the `LxCall` read from it).
    pub fn from_call(c: &LxCall, page: *mut u8) -> Self {
        let n = (c.ngroups as usize).min(LX_GROUPS);
        // SAFETY: the page is the worker's own; the kernel wrote the header before the
        // worker's SYS_LX_REPLY_RECV returned
        let copy = if page.is_null() { LxCopy::EMPTY } else { unsafe { core::ptr::read_volatile(page.add(LX_COPY_OFF) as *const LxCopy) } };
        let out_len = [const { Cell::new(0) }; 6];
        if !page.is_null() {
            // No output unless this call writes some
            // SAFETY: as above
            unsafe { core::ptr::write_volatile(&mut (*(page.add(LX_COPY_OFF) as *mut LxCopy)).out_len, [0; 6]) };
        }
        Self { id: c.id, nr: c.nr, args: c.args, c: *c, caller: Caller::new(c.tid, c.tgid, c.euid, c.egid, c.caps, &c.groups[..n]), page, copy, out_len }
    }

    /// The worker's syscall page (for [`redirect`]).
    pub fn page(&self) -> *mut u8 {
        self.page
    }

    /// The bytes the kernel copied in for pointer `ptr`, if it is one of the arguments and
    /// was copied.
    fn copied(&self, ptr: u64) -> Option<&[u8]> {
        if self.page.is_null() || ptr == 0 {
            return None;
        }
        let i = (0..6).find(|&i| self.args[i] == ptr && self.copy.in_off[i] != 0)?;
        let (off, len) = (self.copy.in_off[i] as usize, self.copy.in_len[i] as usize);
        if off < LX_DATA_OFF || off + len > LX_PAGE_SIZE {
            return None;
        }
        // SAFETY: within the worker's page, which stays ours until the answer
        Some(unsafe { core::slice::from_raw_parts(self.page.add(off), len) })
    }

    /// Writes `data` to pointer `ptr` of the caller without the page (`SYS_LX_WRITE`): for
    /// output written after the answer, as by a call answered later.
    pub fn copy_out_direct(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        sys::lx_write(self.id, ptr, data)
    }

    /// Whether the caller holds capability `cap` (a bit number).
    pub fn has_cap(&self, cap: u32) -> bool {
        self.c.caps & (1 << cap) != 0
    }

    /// Whether `gid` is the caller's effective group or one of its supplementary groups.
    pub fn in_group(&self, gid: u32) -> bool {
        self.c.egid == gid || self.caller.in_groups(gid)
    }

    /// The descriptor's `O_NONBLOCK` (calls on a server object).
    pub fn nonblock(&self) -> bool {
        self.c.obj_flags & 0o4000 != 0
    }

    /// A little-endian u64 at `off` of `b`.
    pub fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// Who made the call.
    pub fn caller(&self) -> Caller {
        self.caller
    }

    /// `len` bytes at `ptr` of the caller.
    pub fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        if let Some(b) = self.copied(ptr).filter(|b| b.len() >= len) {
            return Ok(b[..len].to_vec());
        }
        let mut v = alloc::vec![0u8; len];
        sys::lx_read(self.id, ptr, &mut v)?;
        Ok(v)
    }

    /// [`Cx::copy_in`], where an empty range needs no valid pointer.
    pub fn copy_in_any(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if len == 0 {
            return Ok(Vec::new());
        }
        self.copy_in(ptr, len)
    }

    /// [`Cx::copy_out`], where an empty range needs no valid pointer.
    pub fn copy_out_any(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if data.is_empty() {
            return Ok(());
        }
        self.copy_out(ptr, data)
    }

    /// Writes `data` to `ptr` of the caller: into the page when the kernel left room for
    /// output to that argument (copied after an immediate answer), otherwise at once.
    pub fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        if !self.page.is_null() {
            if let Some(i) = (0..6).find(|&i| self.args[i] == ptr && self.copy.out_off[i] != 0) {
                let (off, cap) = (self.copy.out_off[i] as usize, self.copy.out_cap[i] as usize);
                if data.len() <= cap && off >= LX_DATA_OFF && off + data.len() <= LX_PAGE_SIZE {
                    // SAFETY: within the worker's page; the header's out_len is ours to set
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), self.page.add(off), data.len());
                        self.out_len[i].set(data.len() as u16);
                        let mut lens = [0u16; 6];
                        for (k, l) in lens.iter_mut().enumerate() {
                            *l = self.out_len[k].get();
                        }
                        core::ptr::write_volatile(&mut (*(self.page.add(LX_COPY_OFF) as *mut LxCopy)).out_len, lens);
                    }
                    return Ok(());
                }
            }
        }
        sys::lx_write(self.id, ptr, data)
    }

    /// The NUL-terminated string at `ptr` of the caller (at most 4095 bytes, as the
    /// kernel's `user_cstr`: longer is `-ENAMETOOLONG`).
    pub fn user_cstr(&self, ptr: u64) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        // (the kernel copies a string only with its NUL found within its limit, which is
        // 4096 bytes at most for every string the table describes)
        if let Some(b) = self.copied(ptr).filter(|b| b.len() < 4096) {
            return Ok(b.to_vec());
        }
        let mut buf = alloc::vec![0u8; 4096];
        let n = sys::lx_read_str(self.id, ptr, &mut buf)?;
        if n >= 4096 {
            return Err(ENAMETOOLONG);
        }
        buf.truncate(n);
        Ok(buf)
    }
}

/// Milliseconds since boot (the kernel's 100 Hz tick).
pub fn now_ms() -> u64 {
    sys::uptime_ticks() * 10
}

// ----------------------------------------------------------------------
// Objects: slots, readiness words, the doorbell (for a small service)
// ----------------------------------------------------------------------

/// A small service's server objects, in its object area: slot allocation, readiness words
/// (`[u32 poll bits, u32 edge count, u64 size]` per slot), the changed/watched bitmaps and
/// the doorbell (`SYS_SVC_SIGNAL(endpoint, LX_SIGNAL_OBJS)`).
pub mod objs {
    use super::*;

    static AREA: AtomicU64 = AtomicU64::new(0);
    static ENDPOINT: AtomicU32 = AtomicU32::new(0);
    static DIRTY: AtomicBool = AtomicBool::new(false);
    /// Slots in use (bit per slot).
    static USED: [AtomicU64; LX_OBJ_SLOTS / 64] = [const { AtomicU64::new(0) }; LX_OBJ_SLOTS / 64];

    /// Sets the object area and the endpoint whose doorbell to ring.
    pub fn init(area: *mut u8, endpoint: u32) {
        AREA.store(area as u64, Ordering::Release);
        ENDPOINT.store(endpoint, Ordering::Release);
    }

    fn bitmap(off: usize) -> *const AtomicU64 {
        (AREA.load(Ordering::Acquire) + off as u64) as *const AtomicU64
    }

    fn word_ptr(slot: u32) -> *mut u32 {
        (AREA.load(Ordering::Acquire) + LX_OBJ_OFF as u64 + 16 * slot as u64) as *mut u32
    }

    /// A free slot, its readiness word cleared and nobody marked as waiting for it.
    pub fn alloc() -> Result<u32, i64> {
        for (w, word) in USED.iter().enumerate() {
            let mut v = word.load(Ordering::Acquire);
            while v != u64::MAX {
                let b = (!v).trailing_zeros() as u64;
                match word.compare_exchange(v, v | 1 << b, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => {
                        let slot = (w as u64 * 64 + b) as u32;
                        let p = word_ptr(slot);
                        // SAFETY: the slot and the bitmap lie in the mapped object area
                        unsafe {
                            core::ptr::write_volatile(p.add(2) as *mut u64, 0);
                            core::ptr::write_volatile(p.add(1), 0);
                            core::ptr::write_volatile(p, 0);
                            (*bitmap(LX_OBJ_WATCHED_OFF).add(w)).fetch_and(!(1 << b), Ordering::AcqRel);
                        }
                        return Ok(slot);
                    }
                    Err(now) => v = now,
                }
            }
        }
        Err(ENFILE)
    }

    /// Takes slot `slot` again (an object a restarted instance adopts): its readiness word
    /// stays. `false` if it is in use already.
    pub fn reserve(slot: u32) -> bool {
        if slot as usize >= LX_OBJ_SLOTS {
            return false;
        }
        let b = 1u64 << (slot % 64);
        USED[slot as usize / 64].fetch_or(b, Ordering::AcqRel) & b == 0
    }
    // wave6 G21 end

    /// Lets slot `slot` go.
    pub fn free(slot: u32) {
        if (slot as usize) < LX_OBJ_SLOTS {
            USED[slot as usize / 64].fetch_and(!(1 << (slot % 64)), Ordering::AcqRel);
        }
    }

    /// Slot `slot`'s poll bits.
    pub fn ready(slot: u32) -> u32 {
        if AREA.load(Ordering::Acquire) == 0 || slot as usize >= LX_OBJ_SLOTS {
            return 0;
        }
        // SAFETY: the slot lies in the mapped object area
        unsafe { core::ptr::read_volatile(word_ptr(slot)) }
    }

    /// Sets slot `slot`'s readiness (poll bits) and size; marks it for the next [`flush`] if
    /// someone waits for it. The edge count grows when bits are added.
    pub fn set(slot: u32, ready: u32, size: u64) {
        if AREA.load(Ordering::Acquire) == 0 || slot as usize >= LX_OBJ_SLOTS {
            return;
        }
        let p = word_ptr(slot);
        // SAFETY: the slot lies in the mapped object area; only this service writes it
        unsafe {
            let (old, edges) = (core::ptr::read_volatile(p), core::ptr::read_volatile(p.add(1)));
            let edges = if ready & !old != 0 { edges.wrapping_add(1) } else { edges };
            core::ptr::write_volatile(p.add(2) as *mut u64, size);
            core::ptr::write_volatile(p.add(1), edges);
            core::ptr::write_volatile(p, ready);
        }
        core::sync::atomic::fence(Ordering::SeqCst);
        let (w, b) = (slot as usize / 64, 1u64 << (slot % 64));
        // SAFETY: the bitmaps lie in the object area
        let watched = unsafe { (*bitmap(LX_OBJ_WATCHED_OFF).add(w)).load(Ordering::SeqCst) } & b != 0;
        if watched {
            // SAFETY: as above; the kernel takes the changed bits with atomic swaps
            unsafe { (*bitmap(LX_OBJ_CHANGED_OFF).add(w)).fetch_or(b, Ordering::AcqRel) };
            DIRTY.store(true, Ordering::Release);
        }
    }

    /// Rings the doorbell if words of watched slots changed since the last time.
    pub fn flush() {
        if DIRTY.swap(false, Ordering::AcqRel) {
            sys::svc_signal(ENDPOINT.load(Ordering::Acquire), LX_SIGNAL_OBJS);
        }
    }

    /// Installs a descriptor for the object in slot `slot` in the caller's table; returns it.
    #[allow(clippy::too_many_arguments)]
    pub fn install(cx: &Cx, slot: u32, kind: u32, flags: u32, mode: u32, name: &[u8], tag: u64) -> Result<i64, i64> {
        install_keyed(cx, slot, kind, flags, mode, name, tag, 0)
    }

    // wave6 G21 begin: restart support
    /// [`install`] with the service's key for the object (`LxObjDesc::key`: what a restarted
    /// instance gets back from `LX_SVC_LIST` to rebind it).
    #[allow(clippy::too_many_arguments)]
    pub fn install_keyed(cx: &Cx, slot: u32, kind: u32, flags: u32, mode: u32, name: &[u8], tag: u64, key: u64) -> Result<i64, i64> {
        let mut d = LxObjDesc { slot, kind, flags, mode, uid: cx.c.euid, gid: cx.c.egid, name_len: 0, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag, key };
        let n = name.len().min(LX_OBJ_NAME_MAX);
        d.name[..n].copy_from_slice(&name[..n]);
        d.name_len = n as u32;
        sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0).map(|fd| fd as i64)
    }
}

// ----------------------------------------------------------------------
// Notifications: the ring in the window
// ----------------------------------------------------------------------

/// The notification ring in the window (`LX_NOTES_OFF`): the kernel appends events and
/// advances the head; the service takes them in order and advances the tail. A call carries
/// the ring position at the time it was made ([`LxCall::note_seq`]): `drain_to` it first, and
/// the call never overtakes the events before it.
pub mod notes {
    use super::*;
    use crate::protocol::{LX_NOTES, LX_NOTES_ENTRY_OFF, LX_NOTES_OFF};

    /// What handles one entry: `(kind, a, b, c)`.
    pub type Handler = fn(u64, u64, u64, u64);

    static BASE: AtomicU64 = AtomicU64::new(0);
    static HANDLER: AtomicUsize = AtomicUsize::new(0);
    static TAKING: spin::Mutex<()> = spin::Mutex::new(());
    static DONE: AtomicU64 = AtomicU64::new(0);

    /// Sets the window and the handler (before going online).
    pub fn init(window: *mut u8, handler: Handler) {
        HANDLER.store(handler as usize, Ordering::Release);
        BASE.store(window as u64 + LX_NOTES_OFF as u64, Ordering::Release);
    }

    fn word(i: usize) -> *mut u64 {
        (BASE.load(Ordering::Acquire) as *mut u64).wrapping_add(i)
    }

    fn head() -> u64 {
        // SAFETY: the ring header in the mapped window
        unsafe { core::ptr::read_volatile(word(0)) }
    }

    fn tail() -> u64 {
        // SAFETY: as `head`
        unsafe { core::ptr::read_volatile(word(1)) }
    }

    /// Takes the entries posted before position `seq` (a call's `note_seq`).
    pub fn drain_to(seq: u64) {
        if DONE.load(Ordering::Acquire) >= seq || BASE.load(Ordering::Acquire) == 0 || tail() >= seq {
            return;
        }
        take(seq);
    }

    /// Takes every entry posted so far.
    pub fn drain_all() {
        if BASE.load(Ordering::Acquire) == 0 || tail() >= head() {
            return;
        }
        take(head());
    }

    fn take(seq: u64) {
        // wave10 GN: the holder may be waiting for another server (lx-net's main thread
        // closing sockets in net-server): spin a little, then give the CPU away, so that
        // server can run here meanwhile
        let _g = loop {
            if let Some(g) = TAKING.try_lock() {
                break g;
            }
            let mut spins = 0;
            while TAKING.is_locked() && spins < 64 {
                core::hint::spin_loop();
                spins += 1;
            }
            if TAKING.is_locked() {
                crate::sys::yield_now();
            }
        };
        let h = HANDLER.load(Ordering::Acquire);
        let end = seq.min(head());
        core::sync::atomic::fence(Ordering::Acquire);
        let mut t = tail();
        while t < end {
            let e = (BASE.load(Ordering::Acquire) - LX_NOTES_OFF as u64 + LX_NOTES_ENTRY_OFF as u64 + (t % LX_NOTES) * 32) as *const u64;
            // SAFETY: the entry lies in the mapped window
            let (kind, a, b, c) = unsafe { (core::ptr::read_volatile(e), core::ptr::read_volatile(e.add(1)), core::ptr::read_volatile(e.add(2)), core::ptr::read_volatile(e.add(3))) };
            if h != 0 {
                // SAFETY: set by `init` to a `Handler`
                let f: Handler = unsafe { core::mem::transmute::<usize, Handler>(h) };
                f(kind, a, b, c);
            }
            t += 1;
            // SAFETY: as `head`; only the service writes the tail
            unsafe { core::ptr::write_volatile(word(1), t) };
            DONE.store(t, Ordering::Release);
        }
    }
}
