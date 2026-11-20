//! Tests of `src/lx/svc.rs`: the service registry, hosts, the cross-host worker list,
//! device majors and `SYS_LX_SVC`.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::copy::CopyBuf;
use crate::world::{Sim, Task};

/// Puts the registry, the worker list, the majors and every host back to their boot state
/// (hosts are never freed: they are emptied in place).
pub(crate) fn reset() {
    for e in SVC.iter() {
        e.endpoint.store(0, Ordering::Release);
        e.host.store(0, Ordering::Release);
        e.mode.store(0, Ordering::Release);
    }
    for w in ALL_WORKERS.iter() {
        w.store(0, Ordering::Release);
    }
    ALL_USED.store(0, Ordering::Release);
    for m in MAJOR_SVC.iter() {
        m.store(0, Ordering::Release);
    }
    for x in hosts() {
        reset_host(x);
    }
}

/// Empties host `x` (requests, workers, flags, ring, objects, counters).
pub(crate) fn reset_host(x: &Host) {
    x.lx(|s| {
        s.server_tgid = 0;
        s.workers.clear();
        for r in s.reqs.iter_mut() {
            *r = Req::FREE;
        }
        for c in s.calls.iter_mut() {
            *c = LxCall::EMPTY;
        }
        s.next_id = 1;
    });
    for i in 0..MAX_REQS {
        x.req_done[i].store(false, Ordering::Release);
        *x.buf(i) = CopyBuf::EMPTY;
    }
    for i in 0..MAX_WORKERS {
        x.has_work[i].store(false, Ordering::Release);
        x.worker_tids[i].store(0, Ordering::Release);
    }
    x.online.store(false, Ordering::Release);
    x.notes.store(0, Ordering::Release);
    x.notes_head.store(0, Ordering::Release);
    x.subs.store(if x.id == LXS_LINUX { 1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT } else { 0 }, Ordering::Release);
    x.recovering.store(false, Ordering::Release);
    x.direct.store(0, Ordering::Release);
    x.queued.store(0, Ordering::Release);
    x.failed.store(0, Ordering::Release);
    crate::lx::obj::tests::reset_objs(x);
}

#[test]
fn init_fills_the_default_registry() {
    let _g = crate::world::serial();
    reset();
    assert!(!init(b""));
    assert_eq!(endpoint_of(LXS_LINUX), ENDPOINT_LINUX_SERVER);
    assert_eq!(endpoint_of(LXS_SEC), ENDPOINT_LX_SEC);
    assert_eq!(endpoint_of(LXS_TEST), ENDPOINT_SVC_TEST);
    assert_eq!(endpoint_of(LXS_VFS), ENDPOINT_VFS_SERVER);
    // Co-located pieces are hosted by linux-server, the lowest id naming its endpoint
    assert_eq!(host_of(LXS_NET), LXS_LINUX);
    assert_eq!(host_of(LXS_IPC), LXS_LINUX);
    assert_eq!(host_of(LXS_PROC), LXS_LINUX);
    assert_eq!(host_of(LXS_SEC), LXS_SEC);
    assert_eq!(host_of(LXS_TEST), LXS_TEST);
    // Ids without an endpoint have no host
    assert_eq!(host_of(12), 0);
    assert_eq!(mode(LXS_NET), SvcMode::Forward);
    // Out of range ids
    assert_eq!(host_of(200), 0);
    assert_eq!(endpoint_of(200), 0);
    assert_eq!(mode(200), SvcMode::Forward);
    assert_eq!(host_by_endpoint(ENDPOINT_LINUX_SERVER), Some(LXS_LINUX));
    assert_eq!(host_by_endpoint(0x7777), None);
}

#[test]
fn init_applies_the_switch_back_words() {
    let _g = crate::world::serial();
    reset();
    // lx.<name>=kernel, lx.<name>=linux, the `lx.` prefix optional, several separators,
    // unknown names and values ignored
    assert!(!init(b"lx.net=kernel+sec=linux,lx.bogus=kernel;lx.ipc=what\tkernel=linux test"));
    assert_eq!(mode(LXS_NET), SvcMode::Kernel);
    assert_eq!(mode(LXS_IPC), SvcMode::Forward);
    assert_eq!(endpoint_of(LXS_SEC), ENDPOINT_LINUX_SERVER);
    assert_eq!(host_of(LXS_SEC), LXS_LINUX);
    // The kernel's own id (0) cannot be switched
    assert_eq!(endpoint_of(0), 0);
    reset();
    assert!(init(b"lx=kernel"));
    reset();
    assert!(init(b"kernel"));
    reset();
    // `lx=linux` is not a word of the registry
    assert!(!init(b"lx=linux"));
    reset();
}

#[test]
fn log_lines_names_each_service_with_an_endpoint() {
    let _g = crate::world::serial();
    crate::fake::reset();
    reset();
    init(b"lx.ipc=kernel");
    log_lines(false);
    assert!(crate::fake::logged("[lx] net: linux (co-located, endpoint 0x29)"));
    assert!(crate::fake::logged("[lx] ipc: in the kernel (lx.<name>=kernel)"));
    assert!(crate::fake::logged("[lx] sec: its own process (endpoint 0x31, when started)"));
    log_lines(true);
    assert!(crate::fake::logged("[lx] test: in the kernel (lx=kernel)"));
    reset();
}

#[test]
fn hosts_are_made_once_and_named_by_id() {
    let _g = crate::world::serial();
    reset();
    init(b"");
    assert!(host(LXS_MAX as SvcId).is_none());
    let a = host_or_make(LXS_TEST, ENDPOINT_SVC_TEST);
    let b = host_or_make(LXS_TEST, 0x1234);
    assert!(core::ptr::eq(a, b));
    assert_eq!(a.endpoint.load(Ordering::Relaxed), ENDPOINT_SVC_TEST);
    assert!(hosts().any(|x| x.id == LXS_TEST));
    assert!(!a.is_online());
    assert!(!online(LXS_TEST));
    a.online.store(true, Ordering::Release);
    assert!(online(LXS_TEST));
    // The services it serves: the ids whose host it is
    assert_eq!(a.serves(), 1 << LXS_TEST);
    let l = host_or_make(LXS_LINUX, ENDPOINT_LINUX_SERVER);
    let want = 1 << LXS_NET | 1 << LXS_IPC | 1 << LXS_PROC;
    assert_eq!(l.serves() & want, want);
    // linux-server subscribes to the process events from the start
    assert_eq!(l.subs.load(Ordering::Relaxed), 1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT);
    assert_eq!(a.subs.load(Ordering::Relaxed), 0);
    // A fresh table: every request free, ids from 1
    a.lx(|s| {
        assert_eq!(s.reqs.len(), MAX_REQS);
        assert!(s.reqs.iter().all(|r| r.state == RState::Free));
        assert_eq!(s.next_id, 1);
    });
    assert_eq!(a.notes_head(), 0);
    reset();
}

#[test]
fn worker_list_spans_hosts() {
    let _g = crate::world::serial();
    reset();
    assert_eq!(worker_host(0), None);
    assert_eq!(worker_host(77), None);
    add_worker(77, LXS_TEST);
    add_worker(78, LXS_LINUX);
    add_worker(79, LXS_TEST);
    assert_eq!(worker_host(77), Some(LXS_TEST));
    assert_eq!(worker_host(78), Some(LXS_LINUX));
    drop_workers(LXS_TEST);
    assert_eq!(worker_host(77), None);
    assert_eq!(worker_host(79), None);
    assert_eq!(worker_host(78), Some(LXS_LINUX));
    // A freed entry is used again
    add_worker(80, LXS_SEC);
    assert_eq!(worker_host(80), Some(LXS_SEC));
    // Full: the 65th worker is not recorded
    reset();
    for t in 1..=64 {
        add_worker(t, LXS_TEST);
    }
    add_worker(1000, LXS_TEST);
    assert_eq!(worker_host(64), Some(LXS_TEST));
    assert_eq!(worker_host(1000), None);
    reset();
}

#[test]
fn take_ids_moves_every_id_of_an_endpoint() {
    let _g = crate::world::serial();
    reset();
    init(b"lx.sec=linux");
    SVC[LXS_SEC as usize].host.store(0, Ordering::Release);
    SVC[LXS_NET as usize].host.store(0, Ordering::Release);
    take_ids(LXS_LINUX, ENDPOINT_LINUX_SERVER);
    assert_eq!(host_of(LXS_SEC), LXS_LINUX);
    assert_eq!(host_of(LXS_NET), LXS_LINUX);
    assert_eq!(host_of(LXS_TEST), LXS_TEST);
    reset();
}

#[test]
fn major_svc_needs_a_forwarded_online_service() {
    let _g = crate::world::serial();
    reset();
    init(b"");
    assert_eq!(major_svc(300), 0);
    assert_eq!(major_svc(240), 0);
    MAJOR_SVC[240].store(LXS_TEST, Ordering::Release);
    let x = host_or_make(LXS_TEST, ENDPOINT_SVC_TEST);
    // Not online yet
    assert_eq!(major_svc(240), 0);
    x.online.store(true, Ordering::Release);
    assert_eq!(major_svc(240), LXS_TEST);
    // Switched back to the kernel
    SVC[LXS_TEST as usize].mode.store(SvcMode::Kernel as u8, Ordering::Release);
    assert_eq!(major_svc(240), 0);
    SVC[LXS_TEST as usize].mode.store(SvcMode::Forward as u8, Ordering::Release);
    crate::lx::ALL_KERNEL.store(true, Ordering::Release);
    assert_eq!(major_svc(240), 0);
    crate::lx::ALL_KERNEL.store(false, Ordering::Release);
    reset();
}

#[test]
fn worker_pages_hold_the_call_and_the_copy_area() {
    let _g = crate::world::serial();
    let page = crate::ipc::service::ContiguousFrames::allocate(1).unwrap();
    let base = page.base;
    let w = Worker { task: 5, page, idle: true, req: NONE, idx: 0 };
    assert_eq!(w.call_mut() as u64, base);
    assert_eq!(w.data_mut().as_ptr() as u64, base + LX_DATA_OFF as u64);
    assert_eq!(w.data_mut().len(), LX_DATA_SIZE);
}

/// A world whose running task is a thread of the test service's process.
fn as_test_service() -> Sim {
    let mut t = Task::server(300, 300, ENDPOINT_SVC_TEST);
    t.mm = Some(crate::memory::vm::Mm::shared());
    let sim = Sim::new(t);
    crate::lx::tests::reset_all();
    init(b"");
    host_or_make(LXS_TEST, ENDPOINT_SVC_TEST);
    sim
}

#[test]
fn svc_ctl_subscribe_and_whoami() {
    let _sim = as_test_service();
    assert_eq!(svc_ctl(LX_SVC_WHOAMI, 0, 0, 0), LXS_TEST as i64);
    // Only the three process events are kept
    assert_eq!(svc_ctl(LX_SVC_SUBSCRIBE, u64::MAX, 0, 0), 0);
    assert_eq!(host(LXS_TEST).unwrap().subs.load(Ordering::Relaxed), 1 << LX_NOTE_FORK | 1 << LX_NOTE_EXEC | 1 << LX_NOTE_EXIT);
    assert_eq!(svc_ctl(99, 0, 0, 0), EINVAL);
    // Group 20's and Group 21's ranges reach their modules
    assert_eq!(svc_ctl(3, 0, 0, 0), EPERM);
    assert_eq!(svc_ctl(23, 0, 0, 0), EINVAL);
}

#[test]
fn svc_ctl_claim_major() {
    let _sim = as_test_service();
    // Its own id (0) or one it hosts; a major in range
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 240, 0, 0), 0);
    assert_eq!(MAJOR_SVC[240].load(Ordering::Relaxed), LXS_TEST);
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 256, 0, 0), EINVAL);
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 241, LXS_MAX as u64, 0), EINVAL);
    // A service it does not host
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 241, LXS_NET as u64, 0), EINVAL);
    // A major an online service holds
    MAJOR_SVC[242].store(LXS_LINUX, Ordering::Release);
    let l = host_or_make(LXS_LINUX, ENDPOINT_LINUX_SERVER);
    l.online.store(true, Ordering::Release);
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 242, 0, 0), EPERM);
    // ... is free again once that service is offline
    l.online.store(false, Ordering::Release);
    assert_eq!(svc_ctl(LX_SVC_CLAIM_MAJOR, 242, 0, 0), 0);
    assert_eq!(MAJOR_SVC[242].load(Ordering::Relaxed), LXS_TEST);
}

#[test]
fn svc_ctl_refuses_a_program() {
    let _sim = Sim::new(Task::linux(100, 100));
    crate::lx::tests::reset_all();
    init(b"");
    assert_eq!(svc_ctl(LX_SVC_WHOAMI, 0, 0, 0), EPERM);
}

/// Sets service `id`'s host.
pub(crate) fn set_host(id: SvcId, h: SvcId) {
    SVC[id as usize].host.store(h, Ordering::Release);
}

/// Sets service `id`'s mode.
pub(crate) fn set_mode(id: SvcId, m: SvcMode) {
    SVC[id as usize].mode.store(m as u8, Ordering::Release);
}
