//! Tests of `src/lx/mod.rs`: the forwarding table and routing, the per-host request tables
//! (place, deliver, take_queued, wait_for, complete, free_if; the pending, early, redirect,
//! interrupted and net-wait paths), the lock-free path, the crash policy.
//!
//! The harness here ([`start`]) starts a service the way the real one starts (workers attach
//! with `SYS_LX_CTL`, the main thread registers its endpoint and goes online) in the
//! simulated world (`crate::world`); its workers then serve forwarded calls with a test's
//! handler, through `SYS_LX_REPLY_RECV` (either path).

use super::*;
use crate::ipc::protocol::*;
use crate::world::{Ev, Sim, Task};
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::Arc as StdArc;
use std::sync::Mutex as StdMutex;

#[path = "lx_mod_calls.rs"]
mod calls;
#[path = "lx_mod_objs.rs"]
pub(crate) mod objs;
#[path = "lx_mod_server.rs"]
mod server;

// ----------------------------------------------------------------------
// The harness
// ----------------------------------------------------------------------

/// Every global of `src/lx` and `src/ipc` back to its boot state.
pub(crate) fn reset_all() {
    svc::tests::reset();
    restart::tests::reset();
    timer::tests::reset();
    mem::tests::reset();
    dcall::tests::reset();
    obj::tests::reset();
    fileh::tests::reset(); // wave7 G7-2
    crate::ipc::service::tests::reset();
    netwaits(|w| w.clear());
    RELAY_SERVER.store(false, Ordering::Release);
    WATCHED_NET.store(0, Ordering::Release);
    ALL_KERNEL.store(false, Ordering::Release);
    STEP4.store(false, Ordering::Release);
    KERNEL_BY_BOOT_OPTION.store(false, Ordering::Release);
    *BOOT_WORDS.lock() = ([0; 256], 0);
    FAMILIES.store(0, Ordering::Release);
    for f in FAMILY_SVC.iter() {
        f.store(0, Ordering::Release);
    }
    for t in TABLE.iter().chain(PRIV.iter()) {
        t.store(0, Ordering::Release);
    }
    for c in [&DIRECT_CALLS, &QUEUED_CALLS, &FAILED_CALLS, &REDIRECTS, &NET_RETRIES, &FAST_CALLS, &REPLY_DIRECT, &REPLY_WOKEN] {
        c.store(0, Ordering::Release);
    }
    for i in 0..crate::arch::smp::MAX_CPUS {
        // SAFETY: tests run one at a time (no CPU uses the caches meanwhile)
        unsafe {
            (*IDENT.0[i].get()).epoch = 0;
            (*IDENT.0[i].get()).tid = 0;
            *FDS.0[i].get() = (0, 0, alloc::sync::Weak::new(), 0);
        }
        IO_KERNEL[i].store(0, Ordering::Release);
    }
}

/// A world whose running task is Linux thread 100 (process 100, groups 1000 and 27), with
/// the registry filled and the moved calls forwarded.
pub(crate) fn world() -> Sim {
    let sim = Sim::new(Task::linux(100, 100));
    reset_all();
    svc::init(b"");
    set_forwarding(true);
    let mut p = crate::compat::linux::proc::Process::default();
    p.groups = vec![1000, 27];
    p.pgid = 100;
    p.sid = 99;
    p.ns.ipc = 7;
    crate::compat::linux::proc::PROCS.lock().insert(100, p);
    sim
}

/// What a worker serves: the call in its page, the page itself, the worker's thread.
pub(crate) struct Served {
    pub call: LxCall,
    pub page: *mut u8,
    pub tid: u64,
}

impl Served {
    /// The page's copy header.
    pub fn hdr(&self) -> LxCopy {
        // SAFETY: the worker's syscall page
        unsafe { core::ptr::read_volatile(self.page.add(LX_COPY_OFF) as *const LxCopy) }
    }
    /// The page's copy area.
    pub fn data(&self) -> &'static mut [u8] {
        // SAFETY: the worker's syscall page
        unsafe { core::slice::from_raw_parts_mut(self.page.add(LX_DATA_OFF), LX_DATA_SIZE) }
    }
    /// Input `i` as the kernel copied it (`None`: not copied).
    pub fn input(&self, i: usize) -> Option<Vec<u8>> {
        let h = self.hdr();
        if h.in_off[i] == 0 {
            return None;
        }
        let o = h.in_off[i] as usize - LX_DATA_OFF;
        Some(self.data()[o..o + h.in_len[i] as usize].to_vec())
    }
    /// Writes output `i` (into the page's room for it) and says how long it is.
    pub fn output(&self, i: usize, bytes: &[u8]) {
        let mut h = self.hdr();
        let o = h.out_off[i] as usize - LX_DATA_OFF;
        self.data()[o..o + bytes.len()].copy_from_slice(bytes);
        h.out_len[i] = bytes.len() as u16;
        // SAFETY: the worker's syscall page
        unsafe { core::ptr::write_volatile(self.page.add(LX_COPY_OFF) as *mut LxCopy, h) };
    }
    /// The call's flags as the page holds them now (`LX_CALL_INTERRUPTED` arrives late).
    pub fn flags(&self) -> u64 {
        // SAFETY: the worker's syscall page
        unsafe { core::ptr::read_volatile(&(*(self.page as *const LxCall)).flags) }
    }
    /// Sets the page's redirect object (read with a redirect answer).
    pub fn set_redir_obj(&self, v: u64) {
        // SAFETY: the worker's syscall page
        unsafe { core::ptr::write_volatile(&mut (*(self.page as *mut LxCall)).redir_obj, v) };
    }
}

// SAFETY: a page pointer used by one task at a time
unsafe impl Send for Served {}

/// A worker's answer to one call: `(result, SYS_LX_REPLY_RECV flags)`.
pub(crate) type Handler = StdArc<dyn Fn(&mut Served) -> (i64, u64) + Send + Sync>;

/// A handler from a closure.
pub(crate) fn handler(f: impl Fn(&mut Served) -> (i64, u64) + Send + Sync + 'static) -> Handler {
    StdArc::new(f)
}

/// The kernel address of user address `addr` of the current task (a mapping its fake
/// address space recorded).
pub(crate) fn user_page(addr: u64) -> *mut u8 {
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().expect("an address space");
    let m = mm.lock();
    let map = m.maps.iter().find(|m| addr >= m.addr && addr < m.addr + m.len).expect("a mapping");
    let off = addr - map.addr;
    let f = map.obj.get_page(map.pgoff + off / 4096).expect("a page");
    (f.start_address().as_u64() + off % 4096) as *mut u8
}

/// A syscall frame for call `nr` with `args`.
pub(crate) fn frame(nr: u64, a: [u64; 6]) -> crate::arch::syscall::SyscallFrame {
    crate::arch::syscall::SyscallFrame { rax: nr, rdi: a[0], rsi: a[1], rdx: a[2], r10: a[3], r8: a[4], r9: a[5], ..Default::default() }
}

/// A started service.
pub(crate) struct Svc {
    pub x: &'static Host,
    pub ep: u32,
    pub tgid: u64,
    pub workers: Vec<u64>,
}

/// A worker's loop: attach, then serve calls with `h` until `SYS_LX_REPLY_RECV` fails
/// (`fast`: through the lock-free entry, as real workers do).
fn worker_loop(fast: bool, h: Handler) {
    let addr = ctl(LX_CTL_ATTACH);
    assert!(addr > 0, "attach: {addr}");
    let page = user_page(addr as u64);
    let tid = crate::task::CURRENT_TID.load(Ordering::Acquire);
    let (mut r, mut f) = (0i64, LX_REPLY_NONE);
    loop {
        let rc = if fast {
            match fast_entry(&frame(crate::arch::syscall::SYS_LX_REPLY_RECV, [r as u64, f, 0, 0, 0, 0])) {
                Some(Fast::Reply(v)) => v,
                // Not a worker any more (its service went away): the ordinary path
                None => reply_recv(r, f),
                Some(Fast::Call(_)) => panic!("a worker's reply taken for a call"),
            }
        } else {
            reply_recv(r, f)
        };
        if rc != 0 {
            return;
        }
        // SAFETY: the worker's syscall page
        let call = unsafe { core::ptr::read_volatile(page as *const LxCall) };
        let mut s = Served { call, page, tid };
        (r, f) = h(&mut s);
    }
}

/// Starts host `h`'s service (process `tgid`, workers `tgid + 1..`) with `n` workers serving
/// with `hd`, and runs it until it is online.
pub(crate) fn start(sim: &Sim, h: SvcId, tgid: u64, n: usize, fast: bool, hd: Handler) -> Svc {
    let ep = svc::endpoint_of(h);
    let x = svc::host_or_make(h, ep);
    let mut workers = Vec::new();
    for k in 0..n {
        let tid = tgid + 1 + k as u64;
        let mut t = Task::server(tid, tgid, ep);
        t.mm = Some(crate::memory::vm::Mm::shared());
        let hd = hd.clone();
        sim.spawn(t, move || worker_loop(fast, hd));
        workers.push(tid);
    }
    let mut t = Task::server(tgid, tgid, ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    sim.spawn(t, move || {
        crate::ipc::service::register(ep).expect("register");
        while x.lx(|s| s.workers.len()) < n {
            crate::task::yield_now();
        }
        assert_eq!(ctl(LX_CTL_ONLINE), 0);
    });
    for _ in 0..10 {
        if x.is_online() {
            break;
        }
        sim.run_others();
    }
    assert!(x.is_online(), "the service went online");
    assert_eq!(x.lx(|s| s.workers.iter().filter(|w| w.idle).count()), n, "every worker idle");
    Svc { x, ep, tgid, workers }
}

/// The entries of host `x`'s notification ring: `[kind, a, b, c]`.
pub(crate) fn notes(x: &Host) -> Vec<[u64; 4]> {
    let base = x.notes.load(Ordering::Acquire);
    if base == 0 {
        return Vec::new();
    }
    let w = base as *const u64;
    // SAFETY: the ring lies in the host's window
    unsafe {
        let head = *w;
        let tail = *w.add(1);
        (tail..head)
            .map(|i| {
                let e = (base + (LX_NOTES_ENTRY_OFF - LX_NOTES_OFF) as u64 + (i % LX_NOTES) * 32) as *const u64;
                [*e, *e.add(1), *e.add(2), *e.add(3)]
            })
            .collect()
    }
}

/// The test call `LX_TEST_NR(op, a1, a2)` forwarded by the running task (the path under the
/// kernel lock: the kernel lock is taken first, as the ordinary system call path holds it).
pub(crate) fn test_call(op: u64, a1: u64, a2: u64) -> i64 {
    crate::world::bkl_enter();
    forward(&frame(LX_TEST_NR, [op, a1, a2, 0, 0, 0])).expect("forwarded")
}

/// Calls a handler saw.
pub(crate) type Seen = StdArc<StdMutex<Vec<LxCall>>>;

pub(crate) fn seen() -> Seen {
    StdArc::new(StdMutex::new(Vec::new()))
}

// ----------------------------------------------------------------------
// The forwarding table and routing
// ----------------------------------------------------------------------

#[test]
fn set_forwarding_routes_the_moved_calls() {
    let _sim = world();
    // Number-routed calls carry their service
    let e = entry(250);
    assert_ne!(e & T_SERVER, 0);
    assert_eq!(entry_svc(e), LXS_SEC);
    assert_eq!(entry_svc(entry(240)), LXS_IPC);
    assert_eq!(entry(240) & (T_IPC | T_UMASK), T_IPC | T_UMASK);
    assert_eq!(entry(242) & T_FD0, T_FD0);
    assert_eq!(entry(321) & T_FDAT1, T_FDAT1);
    assert_eq!(entry_svc(entry(LX_NULL_NR)), LXS_LINUX);
    assert_eq!(entry_svc(entry(LX_TEST_NR)), LXS_TEST);
    assert_ne!(entry(LX_TEST_CTX_NR) & T_FSCTX, 0);
    // Sockets by family and by descriptor; read/write by descriptor
    assert_eq!(entry(41), T_SERVER | T_FAMILY);
    assert_eq!(entry(44), T_SERVER | T_BYFD);
    assert_eq!(entry(0), T_SERVER | T_BYFD);
    assert!(family_moved(2) && family_moved(10) && family_moved(16) && family_moved(1));
    assert!(!family_moved(17));
    assert!(!family_moved(64));
    assert_eq!(family_svc(2), LXS_NET);
    assert_eq!(family_svc(1), LXS_IPC);
    assert_eq!(family_svc(17), 0);
    assert!(STEP4.load(Ordering::Relaxed));
    assert_eq!(route(250), Route::Server);
    assert_eq!(route(39), Route::Kernel);
    assert!(keys_forwarded());
    // Numbers outside both tables
    assert_eq!(entry(600), 0);
    assert_eq!(entry(PRIV_BASE + 200), 0);
    assert_eq!(entry(u64::MAX), 0);
    // Off: everything back to the kernel
    set_forwarding(false);
    assert_eq!(entry(250), 0);
    assert_eq!(entry(41), 0);
    assert_eq!(entry(0), 0);
    assert_eq!(entry(LX_TEST_NR), 0);
    assert!(!family_moved(2));
    assert!(!STEP4.load(Ordering::Relaxed));
    assert!(!keys_forwarded());
}

#[test]
fn a_service_switched_back_stays_in_the_kernel() {
    let _sim = world();
    svc::tests::reset();
    svc::init(b"lx.ipc=kernel lx.net=kernel");
    set_forwarding(true);
    assert_eq!(entry(240), 0);
    assert_ne!(entry(250), 0);
    // Both socket services switched back: no family moved, no socket call routed
    assert!(!family_moved(1));
    assert!(!family_moved(2));
    assert_eq!(entry(41), 0);
    assert_eq!(entry(44), 0);
    assert!(!STEP4.load(Ordering::Relaxed));
    assert!(!step4());
}

#[test]
fn by_args_and_route_query() {
    let _sim = world();
    // By number: the service and its host (co-located in linux-server)
    assert_eq!(by_args(240, &[0; 6]), Some(Target { svc: LXS_IPC, host: LXS_LINUX }));
    // By family
    assert_eq!(by_args(41, &[2, 1, 0, 0, 0, 0]), Some(Target { svc: LXS_NET, host: LXS_LINUX }));
    assert_eq!(by_args(41, &[17, 1, 0, 0, 0, 0]), None);
    // By descriptor, or the kernel's
    assert_eq!(by_args(44, &[3; 6]), None);
    assert_eq!(by_args(39, &[0; 6]), None);
    // A service without a host
    svc::tests::set_host(LXS_SEC, 0);
    assert_eq!(by_args(250, &[0; 6]), None);
    // The routing query answers only for online services
    assert_eq!(route_query(240, 0), 0);
    let l = svc::host_or_make(LXS_LINUX, ENDPOINT_LINUX_SERVER);
    l.online.store(true, Ordering::Release);
    assert_eq!(route_query(240, 0), LXS_IPC as i64);
    assert_eq!(route_query(41, 1), LXS_IPC as i64);
    assert_eq!(route_query(41, 2), LXS_NET as i64);
    assert_eq!(route_query(41, 17), 0);
    assert_eq!(route_query(44, 0), 0);
    assert_eq!(route_query(39, 0), 0);
    // ... through the trap: LX_ROUTE_NR is answered by the kernel itself
    assert_eq!(forward(&frame(LX_ROUTE_NR, [240, 0, 0, 0, 0, 0])), Some(LXS_IPC as i64));
    l.online.store(false, Ordering::Release);
}

#[test]
fn boot_words_and_init() {
    let _sim = world();
    set_boot_words(b"quiet lx.ipc=kernel splash lx=kernel");
    {
        let b = BOOT_WORDS.lock();
        assert_eq!(&b.0[..b.1], b"lx.ipc=kernel lx=kernel ");
    }
    svc::tests::reset();
    init();
    assert!(all_kernel());
    assert_eq!(entry(250), 0);
    assert!(crate::fake::logged("in the kernel (switched back: lx=kernel)"));
    // fw_cfg words come first; the boot entry's words after them
    reset_all();
    crate::fake::rec(|r| r.fwcfg.insert("opt/hydra/lx".into(), b"lx.net=kernel".to_vec()));
    init();
    assert!(!all_kernel());
    assert_eq!(svc::mode(LXS_NET), svc::SvcMode::Kernel);
    assert_ne!(entry(250), 0);
    assert!(crate::fake::logged("forwarded to their services"));
    // The boot option alone
    reset_all();
    crate::fake::rec(|r| r.fwcfg.clear());
    KERNEL_BY_BOOT_OPTION.store(true, Ordering::Release);
    init();
    assert!(all_kernel());
    // Words that would overflow the buffer are dropped
    reset_all();
    let long = [b'l'; 300];
    set_boot_words(&long);
    assert_eq!(BOOT_WORDS.lock().1, 0);
}

#[test]
fn forward_answers_the_null_call_and_unrouted_calls() {
    let _sim = world();
    set_forwarding(false);
    assert_eq!(forward(&frame(LX_NULL_NR, [0; 6])), Some(0));
    assert_eq!(forward(&frame(39, [0; 6])), None);
    set_forwarding(true);
    // linux-server is not running: its calls are not implemented
    assert_eq!(forward(&frame(LX_NULL_NR, [0; 6])), Some(ENOSYS));
    // ... and fail with EIO once the ladder gave it up
    restart::tests::set_down(LXS_LINUX, true);
    assert_eq!(forward(&frame(LX_NULL_NR, [0; 6])), Some(EIO));
    restart::tests::set_down(LXS_LINUX, false);
    // A family whose service is not online goes to the kernel
    assert_eq!(forward(&frame(41, [2, 1, 0, 0, 0, 0])), None);
    assert_eq!(forward(&frame(41, [17, 1, 0, 0, 0, 0])), None);
    // A by-descriptor call on a descriptor holding no server object
    assert_eq!(forward(&frame(44, [3, 0, 0, 0, 0, 0])), None);
    assert_eq!(forward(&frame(0, [3, 0, 0, 0, 0, 0])), None);
}

// ----------------------------------------------------------------------
// Forwarded calls through workers
// ----------------------------------------------------------------------

#[test]
fn a_call_switches_straight_to_an_idle_worker_and_back() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        (s.call.args[1] as i64 + 1, 0)
    }));
    sim.clear_log();
    assert_eq!(test_call(LX_TEST_NULL, 41, 0), 42);
    let log = sim.log();
    let w = s.workers[0];
    assert!(log.contains(&Ev::Direct(100, w)), "{log:?}");
    assert!(log.contains(&Ev::Direct(w, 100)), "{log:?}");
    assert_eq!(DIRECT_CALLS.load(Ordering::Relaxed), 1);
    // (the worker counts its direct answer when it runs again: not yet)
    assert_eq!(REPLY_DIRECT.load(Ordering::Relaxed), 0);
    assert_eq!(REPLY_WOKEN.load(Ordering::Relaxed), 0);
    assert_eq!(s.x.direct.load(Ordering::Relaxed), 1);
    // The call carried the caller's identity, groups and its host's id
    let c = calls.lock().unwrap()[0];
    assert_eq!((c.tid, c.tgid, c.uid, c.euid, c.gid), (100, 100, 1000, 1000, 1000));
    assert_eq!(c.ngroups, 2);
    assert_eq!(&c.groups[..2], &[1000, 27]);
    assert_eq!(c.svc, LXS_TEST as u32);
    assert_eq!(lx_req_svc(c.id), LXS_TEST);
    // The request is free again; the worker idle
    s.x.lx(|t| {
        assert!(t.reqs.iter().all(|r| r.state == RState::Free));
        assert!(t.workers[0].idle);
        assert_eq!(t.workers[0].req, NONE);
    });
    // A second call: the worker ran again, so the first answer is counted
    assert_eq!(test_call(LX_TEST_NULL, 1, 0), 2);
    assert_eq!(REPLY_DIRECT.load(Ordering::Relaxed), 1);
    assert!(summary().contains("2 calls forwarded"), "{}", summary());
    assert!(summary().contains("test: 2 direct, 0 queued, 0 failed"), "{}", summary());
}

#[test]
fn a_worker_blocked_under_the_kernel_lock_is_woken_not_switched_to() {
    let sim = world();
    // Workers on the ordinary path block under the kernel lock; a caller without it may
    // not switch to them (only a CPU holding the lock may resume them)
    let s = start(&sim, LXS_TEST, 300, 1, false, handler(|s| (7 + s.call.args[0] as i64, 0)));
    sim.clear_log();
    crate::world::bkl_exit();
    assert_eq!(forward(&frame(LX_TEST_NR, [1, 0, 0, 0, 0, 0])), Some(8));
    let log = sim.log();
    assert!(log.contains(&Ev::DirectFail(100, "blocked under the kernel lock")), "{log:?}");
    assert!(log.contains(&Ev::Unblock(s.workers[0])), "{log:?}");
    // The caller took the kernel lock again before returning (`call_ident`)
    assert!(crate::world::bkl_held());
}

#[test]
fn calls_queue_when_every_worker_is_busy() {
    let sim = world();
    let order = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = order.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        o2.lock().unwrap().push(s.call.args[1]);
        // The first call takes a while: others run meanwhile
        if s.call.args[1] == 1 {
            crate::task::yield_now();
        }
        (s.call.args[1] as i64 * 10, 0)
    }));
    let got = StdArc::new(StdAtomicU64::new(0));
    let g2 = got.clone();
    sim.spawn(Task::linux(101, 100), move || {
        crate::world::bkl_enter();
        g2.store(forward(&frame(LX_TEST_NR, [0, 2, 0, 0, 0, 0])).unwrap() as u64, Ordering::Release);
    });
    assert_eq!(test_call(LX_TEST_NULL, 1, 0), 10);
    // Thread 101's call waited in the queue and was served next
    sim.run_others();
    assert_eq!(got.load(Ordering::Acquire), 20);
    assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    assert_eq!(QUEUED_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(s.x.queued.load(Ordering::Relaxed), 1);
    // The first answer could not switch back (a call was delivered to the worker meanwhile)
    assert!(REPLY_WOKEN.load(Ordering::Relaxed) >= 1);
    s.x.lx(|t| assert!(t.reqs.iter().all(|r| r.state == RState::Free)));
}
