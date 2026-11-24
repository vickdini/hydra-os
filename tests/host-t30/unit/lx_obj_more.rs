//! `src/lx/obj.rs` through a running test service: readiness words, close notes, installs,
//! waiters and the doorbell, kernel reads and writes, `SYS_LX_OBJ`'s operations, descriptor
//! passing, signals, restart support, later writes.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::objs::{dev_at, install, new_obj, obj_handler, test_call_args};
use crate::lx::tests::{handler, notes, start, world, Served};
use crate::world::Task;
use std::sync::atomic::AtomicU64 as StdAtomicU64;
use std::sync::Arc as StdArc;
use std::sync::Mutex as StdMutex;

const EPERM: i64 = -1;

/// Sets slot `slot`'s readiness word in host `x`'s object area.
fn set_word(x: &Host, slot: u32, ready: u32, edges: u32, size: u64) {
    let base = x.objs.area.load(Ordering::Acquire);
    let p = (base + LX_OBJ_OFF as u64 + 16 * slot as u64) as *mut u32;
    // SAFETY: the slot lies in the object area
    unsafe {
        *p = ready;
        *p.add(1) = edges;
        *(p.add(2) as *mut u64) = size;
    }
}

/// Marks slot `slot` changed (the service's doorbell bitmap).
fn mark_changed(x: &Host, slot: u32) {
    let base = x.objs.area.load(Ordering::Acquire);
    let w = (base + LX_OBJ_CHANGED_OFF as u64) as *const AtomicU64;
    // SAFETY: the bitmap lies in the object area
    unsafe { (*w.add(slot as usize / 64)).fetch_or(1 << (slot % 64), Ordering::SeqCst) };
}

/// Results a handler pushed.
type Out = StdArc<StdMutex<Vec<i64>>>;

/// A test-service handler: `LX_TEST_NR` op 50 runs `f` (with the call), anything else is
/// `obj_handler`'s.
fn ops(f: impl Fn(&Served) -> i64 + Send + Sync + 'static) -> crate::lx::tests::Handler {
    let inner = obj_handler();
    handler(move |s| if s.call.nr == LX_TEST_NR && s.call.args[0] == 50 { (f(s), 0) } else { inner(s) })
}

/// `LX_TEST_NR(50, a1, a2)`: runs the test's operations in the service.
fn run_ops(a1: u64, a2: u64) -> i64 {
    crate::lx::tests::test_call(50, a1, a2)
}

/// A thread of service process `tgid` with an address space.
fn svc_task(tid: u64, tgid: u64, ep: u32) -> Task {
    let mut t = Task::server(tid, tgid, ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    t
}

#[test]
fn an_object_reads_its_readiness_word() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(5, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    set_word(s.x, 5, 0x0001, 3, 77);
    assert_eq!(d.poll_events(), 0x0001);
    assert_eq!(d.edges(), Some(3));
    let st = d.stat();
    assert_eq!((st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_blksize), (0o600, 1000, 1000, 1, 77, 4096));
    let gen = s.x.objs.gen.load(Ordering::Relaxed);
    assert_eq!(st.st_ino, 0x2_0000_0000 | (gen & 0xFFFF) << 16 | 5);
    assert_eq!(d.path(), "svc-test");
    assert_eq!(d.rdev(), 0);
    let o = d.as_server().unwrap();
    assert_eq!((o.kind(), o.tag(), o.flags()), (LX_OBJ_KIND_SVCTEST, 0, 0));
    // A pipe end reports the server's inode number; a pidfd and a bpf map do not
    let p = dev_at(test_call_args(LX_TEST_OBJ, [6, LX_OBJ_KIND_PIPE_R as u64, 0, 4242, 0]));
    assert_eq!(p.stat().st_ino, 4242);
    let m = dev_at(test_call_args(LX_TEST_OBJ, [7, LX_OBJ_KIND_BPF_MAP as u64, 0, 4 | 8 << 32, 0]));
    assert_eq!(m.stat().st_ino >> 32, 2);
    let q = dev_at(test_call_args(LX_TEST_OBJ, [8, LX_OBJ_KIND_PIDFD as u64, 0, 100, 0]));
    assert_eq!(q.stat().st_ino >> 32, 2);
    // Its service goes: the object is stale
    offline(s.x);
    assert_eq!(d.poll_events(), STALE);
    assert_eq!(d.edges(), Some(u64::MAX - 1));
    assert_eq!(d.stat().st_size, 0);
    assert_eq!(o.slot(), None);
}

#[test]
fn the_last_reference_tells_the_service_once() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(8, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    assert!(reg(s.x, |r| r[8].is_some()));
    // dup: two references; closing one says nothing
    let d2 = d.clone();
    crate::task::with_current_fds_mut(|t| t.set_fd(fd as usize, None));
    drop(d);
    assert!(notes(s.x).iter().all(|e| e[0] != LX_NOTE_CLOSE));
    drop(d2);
    let n: Vec<_> = notes(s.x).into_iter().filter(|e| e[0] == LX_NOTE_CLOSE).collect();
    assert_eq!(n, vec![[LX_NOTE_CLOSE, 8, LX_OBJ_KIND_SVCTEST as u64, 0]]);
    assert!(reg(s.x, |r| r[8].is_none()));
    // An object of an older generation (its service restarted) is not told about
    let fd = new_obj(9, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    crate::task::with_current_fds_mut(|t| t.set_fd(fd as usize, None));
    offline(s.x);
    online(s.x);
    drop(d);
    assert_eq!(notes(s.x).iter().filter(|e| e[0] == LX_NOTE_CLOSE).count(), 1);
}

#[test]
fn an_install_that_finds_no_descriptor_is_quiet() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    sim.with_task(100, |t| t.fds.lock().max = 0);
    assert_eq!(new_obj(10, LX_OBJ_KIND_SVCTEST), EMFILE);
    // The slot is free again and the service was not told (it frees the slot itself)
    assert!(reg(s.x, |r| r[10].is_none()));
    assert!(notes(s.x).iter().all(|e| e[0] != LX_NOTE_CLOSE));
    sim.with_task(100, |t| t.fds.lock().max = 1024);
}

#[test]
fn install_checks_its_description() {
    let sim = world();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let push = |v: i64| o2.lock().unwrap().push(v);
        // A bad pointer, a slot out of range, a name too long
        push(obj_ctl(LX_OBJ_INSTALL, id, 0, 0));
        push(install(s, LX_OBJ_SLOTS as u32, 1, 0, 0));
        let mut d = LxObjDesc { slot: 1, kind: 1, flags: 0, mode: 0, uid: 0, gid: 0, name_len: LX_OBJ_NAME_MAX as u32 + 1, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag: 0, key: 0 };
        push(obj_ctl(LX_OBJ_INSTALL, id, &d as *const LxObjDesc as u64, 0));
        // The slot is taken
        d.name_len = 0;
        push((obj_ctl(LX_OBJ_INSTALL, id, &d as *const LxObjDesc as u64, 0) >= 0) as i64);
        push(obj_ctl(LX_OBJ_INSTALL, id, &d as *const LxObjDesc as u64, 0));
        // A request of another host
        push(obj_ctl(LX_OBJ_INSTALL, id ^ (3 << 56), &d as *const LxObjDesc as u64, 0));
        // O_CLOEXEC and O_NONBLOCK come with the descriptor
        d.slot = 2;
        d.flags = O_CLOEXEC | O_NONBLOCK;
        let fd = obj_ctl(LX_OBJ_INSTALL, id, &d as *const LxObjDesc as u64, 0);
        push(fd);
        0
    }));
    assert_eq!(run_ops(0, 0), 0);
    let o = out.lock().unwrap().clone();
    assert_eq!(&o[..6], &[EFAULT, EINVAL, EINVAL, 1, EBUSY, ESRCH]);
    let fd = o[6] as usize;
    assert!(crate::task::with_current_fds_mut(|t| t.cloexec.contains(&fd)));
    assert!(dev_at(fd as i64).nonblock());
    // The service's area gone: nothing can be installed
    s.x.objs.area.store(0, Ordering::Release);
    assert_eq!(new_obj(30, 1), EINVAL);
}

#[test]
fn waiters_mark_the_slot_watched_and_internet_sockets_need_the_relay() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let d = dev_at(new_obj(64 + 3, LX_OBJ_KIND_INET));
    let mut w = WaitSet::new();
    d.add_wait_queues(&mut w);
    d.add_wait_queues(&mut w);
    let base = s.x.objs.area.load(Ordering::Acquire);
    // SAFETY: the watched bitmap in the object area
    let bits = unsafe { *((base + LX_OBJ_WATCHED_OFF as u64 + 8) as *const u64) };
    assert_eq!(bits, 1 << 3);
    // Counted once; the network service's main thread was told to relay
    assert_eq!(crate::lx::WATCHED_NET.load(Ordering::Relaxed), 1);
    assert_ne!(crate::ipc::service::tests::pending_bits(crate::lx::svc::endpoint_of(LXS_NET)) & NOTIFY_LX_NET, 0);
    assert_eq!(w.queues.len(), 2);
    drop(w);
    crate::task::with_current_fds_mut(|t| t.fds.clear());
    drop(d);
    assert_eq!(crate::lx::WATCHED_NET.load(Ordering::Relaxed), 0);
    // A stale object only adds its queue
    let d = dev_at(new_obj(4, LX_OBJ_KIND_SVCTEST));
    offline(s.x);
    let mut w = WaitSet::new();
    d.add_wait_queues(&mut w);
    assert_eq!(w.queues.len(), 1);
}

#[test]
fn the_doorbell_wakes_the_waiters_of_changed_slots() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let a = dev_at(new_obj(70, LX_OBJ_KIND_SVCTEST));
    let b = dev_at(new_obj(71, LX_OBJ_KIND_SVCTEST));
    let qa = reg(s.x, |r| r[70].clone().unwrap().wq.clone());
    let qb = reg(s.x, |r| r[71].clone().unwrap().wq.clone());
    mark_changed(s.x, 70);
    mark_changed(s.x, 200);
    on_doorbell(s.x);
    assert_eq!((qa.wakes(), qb.wakes()), (1, 0));
    // The bits were taken
    on_doorbell(s.x);
    assert_eq!(qa.wakes(), 1);
    // Offline: nothing to do
    offline(s.x);
    on_doorbell(s.x);
    drop((a, b));
}

#[test]
fn kernel_reads_and_writes_wait_on_readiness() {
    let sim = world();
    let calls = StdArc::new(StdAtomicU64::new(0));
    let c2 = calls.clone();
    let inner = obj_handler();
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.obj_flags & LX_OBJ_FLAGS_KBUF == 0 {
            return inner(s);
        }
        let n = c2.fetch_add(1, Ordering::AcqRel);
        match s.call.nr {
            // Reads: not ready the first time
            0 if n == 0 => (-11, 0),
            0 => {
                s.output(1, b"ok");
                (2, 0)
            }
            // Writes: all of it, unless the counter says "fail"
            _ if n < 5 => (s.call.args[2] as i64, 0),
            _ if n == 5 => (s.call.args[2] as i64, 0),
            _ => (-32, 0),
        }
    }));
    let x = s.x;
    let fd = new_obj(12, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    // Not ready: the reader waits; the service marks the slot ready and rings
    sim.spawn(svc_task(310, 300, s.ep), move || {
        set_word(x, 12, 0x0001, 1, 0);
        mark_changed(x, 12);
        on_doorbell(x);
    });
    let mut buf = [0u8; 8];
    crate::world::bkl_enter();
    assert_eq!(d.read(&mut buf), 2);
    assert_eq!(&buf[..2], b"ok");
    // Non-blocking: EAGAIN at once
    calls.store(0, Ordering::Release);
    d.set_nonblock(true);
    assert_eq!(d.read(&mut buf), -11);
    // A signal ends a blocking wait
    d.set_nonblock(false);
    calls.store(0, Ordering::Release);
    set_word(x, 12, 0, 1, 0);
    crate::fake::set_signal(100, true);
    assert_eq!(d.read(&mut buf), crate::compat::linux::proc::ERESTARTSYS);
    crate::fake::set_signal(100, false);
    // Ready: a retry at once (no wait)
    calls.store(0, Ordering::Release);
    set_word(x, 12, 0x0001, 1, 0);
    assert_eq!(d.read(&mut buf), 2);
    // Writes go in pieces of the copy area; an error after a piece: what was written
    calls.store(5, Ordering::Release);
    let big = vec![7u8; LX_DATA_SIZE + 100];
    assert_eq!(d.write(&big), LX_DATA_SIZE as i64);
    calls.store(0, Ordering::Release);
    assert_eq!(d.write(&big[..10]), 10);
    calls.store(6, Ordering::Release);
    assert_eq!(d.write(&big[..10]), -32);
    // An empty write is one call
    calls.store(0, Ordering::Release);
    assert_eq!(d.write(&[]), 0);
}

#[test]
fn kernel_io_on_an_object_whose_last_reference_went() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let d = dev_at(new_obj(13, LX_OBJ_KIND_SVCTEST));
    let o = d.as_server().unwrap();
    *o.shared.me.lock() = alloc::sync::Weak::new();
    let mut b = [0u8; 4];
    assert_eq!(d.read(&mut b), EBADF);
    assert!(!d.deliver_notification(b"x"));
    assert_eq!(d.socket_call(42, [0; 6]), None);
    let _ = s;
}

#[test]
fn signalfd_objects_poll_the_processs_signals() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, ops(|s| obj_ctl(LX_OBJ_SIGMASK, s.call.args[1], s.call.args[2], 0)));
    let d = dev_at(test_call_args(LX_TEST_OBJ, [13, LX_OBJ_KIND_SIGNALFD as u64, 0, 100, 0]));
    assert_eq!(run_ops(13, 1 << 9), 0);
    assert_eq!(d.poll_events(), 0);
    crate::compat::linux::proc::PROCS.lock().get_mut(&100).unwrap().pending = 1 << 9;
    assert_eq!(d.poll_events(), 0x0001);
    assert_eq!(d.edges(), None);
    // Slots out of range or empty
    assert_eq!(run_ops(LX_OBJ_SLOTS as u64, 0), EINVAL);
    assert_eq!(run_ops(99, 0), EBADF);
}

#[test]
fn netlink_objects_take_notifications_and_unix_sockets_their_socket_calls() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    let inner = obj_handler();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.nr == LX_KCALL_NLDELIVER {
            g2.lock().unwrap().push(s.input(1).unwrap());
            return (0, 0);
        }
        inner(s)
    }));
    let nl = dev_at(new_obj(14, LX_OBJ_KIND_NETLINK));
    crate::world::bkl_enter();
    assert!(nl.deliver_notification(b"cookie"));
    assert_eq!(*got.lock().unwrap(), vec![b"cookie".to_vec()]);
    let other = dev_at(new_obj(15, LX_OBJ_KIND_SVCTEST));
    assert!(!other.deliver_notification(b"x"));
    crate::fake::rec(|r| r.unix_answer = 17);
    assert_eq!(other.socket_call(42, [1, 2, 3, 4, 5, 6]), Some(17));
    assert_eq!(crate::fake::rec(|r| r.unix_calls.clone()), vec![(42, [1, 2, 3, 4, 5, 6])]);
}

#[test]
fn obj_fd_names_the_callers_objects() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(|s| obj_ctl(LX_OBJ_FD, s.call.id, s.call.args[1], 0)));
    let fd = new_obj(16, LX_OBJ_KIND_SVCTEST);
    dev_at(fd).set_nonblock(true);
    assert_eq!(run_ops(fd as u64, 0), (16 | (LX_OBJ_KIND_SVCTEST as u64) << 32 | 1 << 62) as i64);
    // Not a device; no descriptor
    let kfd = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::File { path: "/x".into(), readable: true, writable: true })).unwrap();
    assert_eq!(run_ops(kfd as u64, 0), EINVAL);
    assert_eq!(run_ops(500, 0), EBADF);
    // A kernel device
    let p = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::Device(StdArc::new(Plain)))).unwrap();
    assert_eq!(run_ops(p as u64, 0), EINVAL);
    // An object of the service's previous instance
    let gen = s.x.objs.gen.load(Ordering::Relaxed);
    s.x.objs.gen.store(gen + 1000, Ordering::Release);
    assert_eq!(run_ops(fd as u64, 0), crate::lx::restart_policy::stale_errno(LX_OBJ_KIND_SVCTEST));
}

#[test]
fn obj_ctl_small_operations() {
    let sim = world();
    let mut p = crate::compat::linux::proc::Process::default();
    p.exited = true;
    crate::compat::linux::proc::PROCS.lock().insert(555, p);
    crate::fake::rec(|r| r.proc_files.insert("100/comm".into(), b"a-very-long-command-name\n".to_vec()));
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let push = |v: i64| o2.lock().unwrap().push(v);
        // Signals for the caller's thread
        push(obj_ctl(LX_OBJ_SIGTHREAD, id, 10, 0));
        push(obj_ctl(LX_OBJ_SIGTHREAD, id, 0, 0));
        push(obj_ctl(LX_OBJ_SIGTHREAD, id, 65, 0));
        // Its command name (15 bytes at most, up to the newline)
        let mut comm = [0xFFu8; 16];
        push(obj_ctl(LX_OBJ_COMM, id, comm.as_mut_ptr() as u64, 16));
        push((&comm[..15] == b"a-very-long-com" && comm[15] == 0) as i64);
        // A process: running, exited, missing
        push(obj_ctl(LX_OBJ_PROC, 100, 0, 0));
        push(obj_ctl(LX_OBJ_PROC, 555, 0, 0));
        push(obj_ctl(LX_OBJ_PROC, 556, 0, 0));
        // Landlock's port check
        push(obj_ctl(LX_OBJ_NETCHECK, id, 80, 1));
        crate::fake::rec(|r| r.landlock = Some(-13));
        push(obj_ctl(LX_OBJ_NETCHECK, id, 80, 1));
        // The relay, net waits
        push(obj_ctl(LX_OBJ_RELAY, 1, 0, 0));
        push(obj_ctl(LX_OBJ_NETWAIT, id, 3, 0));
        push(obj_ctl(LX_OBJ_NETCANCEL, id, 0, 0));
        // bpf device programs: in, too long, a bad pointer
        let prog = [1u8, 2, 3];
        push(obj_ctl(LX_OBJ_BPF_DEVICE, prog.as_ptr() as u64, 3, 0));
        push(obj_ctl(LX_OBJ_BPF_DEVICE, prog.as_ptr() as u64, (1 << 20) + 1, 0));
        push(obj_ctl(LX_OBJ_BPF_DEVICE, 0, 3, 0));
        // Unknown operation; a request id of another host
        push(obj_ctl(99, 0, 0, 0));
        push(obj_ctl(LX_OBJ_COMM, id ^ (2 << 56), 0, 0));
        0
    }));
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![0, EINVAL, EINVAL, 0, 1, 1, 2, ESRCH, 0, -13, 0, 0, 1, 3, EINVAL, EFAULT, EINVAL, ESRCH]);
    assert_eq!(crate::fake::rec(|r| r.posted.clone()), vec![(100, 100, 10, 0, 0, 0, 0)]);
    assert_eq!(crate::fake::rec(|r| r.bpf_programs.clone()), vec![vec![1, 2, 3]]);
    // A program may not use it
    assert_eq!(obj_ctl(LX_OBJ_PROC, 100, 0, 0), EPERM);
}

#[test]
fn obj_ctl_for_a_request_nobody_serves() {
    let sim = world();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        // A request id of this host that is not in the table
        let id = s.call.id + 77;
        let mut b = [0u8; 16];
        for op in [LX_OBJ_FD, LX_OBJ_NETCHECK, LX_OBJ_SIGTHREAD, LX_OBJ_COMM, LX_OBJ_FDPATH, LX_OBJ_PIN] {
            o2.lock().unwrap().push(obj_ctl(op, id, 1, b.as_mut_ptr() as u64));
        }
        o2.lock().unwrap().push(sig_take(id, 1, b.as_mut_ptr() as u64, 0));
        0
    }));
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![ESRCH; 7]);
}

#[test]
fn fdpath_setfl_refs_pin_and_notify() {
    let sim = world();
    let vn = crate::fs::FileDescriptor::Vnode(StdArc::new(spin::Mutex::new(crate::fs::Vnode { path: "/home/u/f".into(), ..Default::default() })));
    let file = crate::fs::FileDescriptor::File { path: "/etc/hosts".into(), readable: true, writable: false };
    let (vfd, ffd) = crate::task::with_current_fds_mut(|t| (t.alloc_fd(vn).unwrap(), t.alloc_fd(file).unwrap()));
    let plain = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::Device(StdArc::new(Plain)))).unwrap();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let push = |v: i64| o2.lock().unwrap().push(v);
        let mut b = [0u8; 64];
        push(obj_ctl(LX_OBJ_FDPATH, id, vfd as u64, b.as_mut_ptr() as u64));
        push((&b[..9] == b"/home/u/f") as i64);
        push(obj_ctl(LX_OBJ_FDPATH, id, ffd as u64, b.as_mut_ptr() as u64));
        push(obj_ctl(LX_OBJ_FDPATH, id, plain as u64, b.as_mut_ptr() as u64));
        push(obj_ctl(LX_OBJ_FDPATH, id, 77, b.as_mut_ptr() as u64));
        // Pins: a kernel descriptor is kept for the service; nothing at 77
        let t = obj_ctl(LX_OBJ_PIN, id, plain as u64, 0);
        push((t > 0) as i64);
        push(obj_ctl(LX_OBJ_PIN, id, 77, 0));
        // Notify the pinned device (the plain device takes none: still 0)
        let data = *b"hi";
        push(obj_ctl(LX_OBJ_NOTIFY, t as u64, data.as_ptr() as u64, 2));
        push(obj_ctl(LX_OBJ_NOTIFY, t as u64, data.as_ptr() as u64, 5000));
        push(obj_ctl(LX_OBJ_NOTIFY, 9999, data.as_ptr() as u64, 2));
        push(obj_ctl(LX_OBJ_NOTIFY, t as u64, 0, 2));
        push(obj_ctl(LX_OBJ_UNPIN, t as u64, 0, 0));
        push(obj_ctl(LX_OBJ_UNPIN, t as u64, 0, 0));
        0
    }));
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![9, 1, 10, EINVAL, EBADF, 1, EBADF, 0, EINVAL, EINVAL, EFAULT, 0, EINVAL]);
    // SETFL and REFS on an object's slot
    let fd = new_obj(17, LX_OBJ_KIND_SVCTEST);
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(320, 300, s.ep), move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        push(obj_ctl(LX_OBJ_SETFL, 17, O_NONBLOCK as u64, 0));
        push(obj_ctl(LX_OBJ_SETFL, 18, 0, 0));
        push(obj_ctl(LX_OBJ_SETFL, LX_OBJ_SLOTS as u64, 0, 0));
        push(obj_ctl(LX_OBJ_REFS, 17, 0, 0));
        push(obj_ctl(LX_OBJ_REFS, 18, 0, 0));
        push(obj_ctl(LX_OBJ_REFS, LX_OBJ_SLOTS as u64, 0, 0));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![0, EBADF, EINVAL, 1, 0, EINVAL]);
    assert!(dev_at(fd).nonblock());
}

#[test]
fn descriptors_travel_through_the_service_by_token() {
    let sim = world();
    let pipe = StdArc::new(spin::Mutex::new(crate::fs::Pipe { readers: 1, writers: 1 }));
    let rfd = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::PipeRead(pipe.clone()))).unwrap();
    let wfd = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::PipeWrite(pipe.clone()))).unwrap();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let push = |v: i64| o2.lock().unwrap().push(v);
        let ofd = s.call.args[1];
        // Take three: a pipe's two ends and one of this service's objects
        let mut e = vec![0u8; 72];
        for (i, fd) in [rfd as u64, wfd as u64, ofd].iter().enumerate() {
            e[i * 24..i * 24 + 8].copy_from_slice(&fd.to_le_bytes());
        }
        push(obj_ctl(LX_OBJ_TAKE, id, e.as_ptr() as u64, 3));
        let tok = |i: usize| u64::from_le_bytes(e[i * 24 + 8..i * 24 + 16].try_into().unwrap());
        let what = |i: usize| u64::from_le_bytes(e[i * 24 + 16..i * 24 + 24].try_into().unwrap());
        push((what(0) == 0 && what(2) == 18 | (LX_OBJ_KIND_SVCTEST as u64) << 32 | 1 << 63) as i64);
        // Bad counts and descriptors
        push(obj_ctl(LX_OBJ_TAKE, id, e.as_ptr() as u64, 0));
        push(obj_ctl(LX_OBJ_TAKE, id, e.as_ptr() as u64, 513));
        let mut bad = vec![0u8; 24];
        bad[..8].copy_from_slice(&(-1i64).to_le_bytes());
        push(obj_ctl(LX_OBJ_TAKE, id, bad.as_ptr() as u64, 1));
        push(obj_ctl(LX_OBJ_TAKE, id, 0, 1));
        // Give the first back (close-on-exec), an unknown token fails the rest
        let mut g = vec![0u8; 32];
        g[..8].copy_from_slice(&tok(0).to_le_bytes());
        g[16..24].copy_from_slice(&12345u64.to_le_bytes());
        push(obj_ctl(LX_OBJ_GIVE, id, g.as_ptr() as u64, 2 | (O_CLOEXEC as u64) << 32));
        let newfd = u64::from_le_bytes(g[8..16].try_into().unwrap());
        push((u64::from_le_bytes(g[24..32].try_into().unwrap()) == u64::MAX) as i64);
        push(newfd as i64);
        push(obj_ctl(LX_OBJ_GIVE, id, g.as_ptr() as u64, 0));
        push(obj_ctl(LX_OBJ_GIVE, id, 0, 1));
        // Drop the second (a message dropped unread)
        let d = tok(1).to_le_bytes();
        push(obj_ctl(LX_OBJ_DROP, d.as_ptr() as u64, 1, 0));
        push(obj_ctl(LX_OBJ_DROP, d.as_ptr() as u64, 1, 1));
        push(obj_ctl(LX_OBJ_DROP, 0, 1, 0));
        0
    }));
    let ofd = new_obj(18, LX_OBJ_KIND_SVCTEST);
    assert_eq!(run_ops(ofd as u64, 0), 0);
    let o = out.lock().unwrap().clone();
    assert_eq!(&o[..6], &[0, 1, EINVAL, EINVAL, EBADF, EFAULT]);
    assert_eq!(&o[6..8], &[EINVAL, 1]);
    let newfd = o[8];
    assert_eq!(&o[9..], &[EINVAL, EFAULT, 0, EINVAL, EFAULT]);
    // The given descriptor is a new reader of the pipe; the dropped writer let go
    assert!(matches!(crate::task::with_current_fds_mut(|t| t.get(newfd as usize).cloned()), Some(crate::fs::FileDescriptor::PipeRead(_))));
    assert!(crate::task::with_current_fds_mut(|t| t.cloexec.contains(&(newfd as usize))));
    let (r, w) = { let p = pipe.lock(); (p.readers, p.writers) };
    assert_eq!((r, w), (2, 1));
    // The object is still kept (it counts as a reference): its service going lets it go
    assert_eq!(s.x.objs.kept.lock().len(), 1);
    offline(s.x);
    assert!(s.x.objs.kept.lock().is_empty());
}

#[test]
fn a_full_table_keeps_a_given_descriptor_kept() {
    let sim = world();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let mut e = vec![0u8; 24];
        e[..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(obj_ctl(LX_OBJ_TAKE, id, e.as_ptr() as u64, 1), 0);
        let mut g = vec![0u8; 16];
        g[..8].copy_from_slice(&e[8..16]);
        crate::task::SCHEDULER.lock().with_task_mut(crate::task::TaskId(100), |t| t.fds.lock().max = 1);
        o2.lock().unwrap().push(obj_ctl(LX_OBJ_GIVE, id, g.as_ptr() as u64, 1));
        0
    }));
    crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::File { path: "/a".into(), readable: true, writable: true })).unwrap();
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![EMFILE]);
    assert_eq!(s.x.objs.kept.lock().len(), 1);
    s.x.objs.kept.lock().clear();
    sim.with_task(100, |t| t.fds.lock().max = 1024);
}

#[test]
fn too_many_descriptors_in_flight() {
    let sim = world();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let e = vec![0u8; 24];
        o2.lock().unwrap().push(obj_ctl(LX_OBJ_TAKE, s.call.id, e.as_ptr() as u64, 1));
        0
    }));
    crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::File { path: "/a".into(), readable: true, writable: true })).unwrap();
    {
        let mut k = s.x.objs.kept.lock();
        for i in 0..MAX_KEPT as u64 {
            k.insert(1_000_000 + i, crate::fs::FileDescriptor::File { path: String::new(), readable: false, writable: false });
        }
    }
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![-109]);
    s.x.objs.kept.lock().clear();
}

#[test]
fn sig_post_and_sig_take() {
    let sim = world();
    let mut p = crate::compat::linux::proc::Process::default();
    p.pending = 1 << (crate::compat::linux::proc::SIGCHLD - 1) | 1 << 9;
    crate::compat::linux::proc::PROCS.lock().insert(100, p);
    let recs = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = recs.clone();
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let id = s.call.id;
        let push = |v: i64| o2.lock().unwrap().push(v);
        push(sig_post(100, 14, (-3i64) as u64, 7 | 8 << 32, 99));
        push(sig_post(100, 0, 0, 0, 0));
        push(sig_post(100, 65, 0, 0, 0));
        push(sig_post(7777, 1, 0, 0, 0));
        // SIGKILL and SIGSTOP are never taken; the lowest pending in the mask is
        let mut b = [0u8; 128];
        push(sig_take(id, 1 << 9 | 1 << 8, b.as_mut_ptr() as u64, 0));
        r2.lock().unwrap().push(b);
        push(sig_take(id, 1 << 16, b.as_mut_ptr() as u64, 0));
        r2.lock().unwrap().push(b);
        push(sig_take(id, 1 << 16, b.as_mut_ptr() as u64, 0));
        push(sig_take(id, u64::MAX, 0, 0));
        0
    }));
    assert_eq!(run_ops(0, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![0, EINVAL, EINVAL, ESRCH, 128, 128, 0, 0]);
    assert_eq!(crate::fake::rec(|r| r.posted.clone()), vec![(100, 0, 14, -3, 7, 8, 99)]);
    let r = recs.lock().unwrap().clone();
    // signal 10 (bit 9): its number, code, pid, value
    assert_eq!(u32::from_le_bytes(r[0][0..4].try_into().unwrap()), 10);
    assert_eq!(i32::from_le_bytes(r[0][8..12].try_into().unwrap()), -1);
    assert_eq!(u32::from_le_bytes(r[0][12..16].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(r[0][48..56].try_into().unwrap()), 0x1122_3344_5566_7788);
    // SIGCHLD: the child's details
    assert_eq!(u32::from_le_bytes(r[1][0..4].try_into().unwrap()), 17);
    assert_eq!(i32::from_le_bytes(r[1][8..12].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(r[1][12..16].try_into().unwrap()), 4242);
    assert_eq!(i32::from_le_bytes(r[1][40..44].try_into().unwrap()), 9);
    // Programs may not
    assert_eq!(sig_post(100, 1, 0, 0, 0), EPERM);
    assert_eq!(sig_take(1, 1, 0, 0), EPERM);
}

#[test]
fn restart_support_adopt_dead_and_list() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let a = dev_at(new_obj(20, LX_OBJ_KIND_SVCTEST));
    let b = dev_at(new_obj(21, LX_OBJ_KIND_MQ));
    let mut l = Vec::new();
    list_live(s.x, 0, 10, &mut l);
    assert_eq!(l.iter().map(|o| (o.slot, o.kind, o.key)).collect::<Vec<_>>(), vec![(20, LX_OBJ_KIND_SVCTEST, 0xC0DE + 20), (21, LX_OBJ_KIND_MQ, 0xC0DE + 21)]);
    let mut l2 = Vec::new();
    list_live(s.x, 21, 10, &mut l2);
    assert_eq!(l2.len(), 1);
    let mut l3 = Vec::new();
    list_live(s.x, 0, 1, &mut l3);
    assert_eq!(l3.len(), 1);
    // The new instance cannot rebind slot 21: stale from now on, its end not told
    let q = reg(s.x, |r| r[21].clone().unwrap().wq.clone());
    mark_dead(s.x, 21);
    mark_dead(s.x, 22);
    assert_eq!(q.wakes(), 1);
    assert_eq!(b.as_server().unwrap().slot(), None);
    assert_eq!(b.poll_events(), STALE);
    assert_eq!(stale_errno(b.as_server().unwrap()), crate::lx::restart_policy::stale_errno(LX_OBJ_KIND_MQ));
    crate::task::with_current_fds_mut(|t| t.fds.clear());
    drop(b);
    assert!(notes(s.x).iter().all(|e| e[0] != LX_NOTE_CLOSE));
    // Adopted: the objects keep their generation; waiters wake to read the words again
    let gen = s.x.objs.gen.load(Ordering::Relaxed);
    let qa = reg(s.x, |r| r[20].clone().unwrap().wq.clone());
    s.x.objs.area.store(0, Ordering::Release);
    assert_eq!(online_adopt(s.x), 0);
    assert_eq!(s.x.objs.gen.load(Ordering::Relaxed), gen);
    assert_eq!(a.as_server().unwrap().slot(), Some(20));
    assert_eq!(qa.wakes(), 1);
    // A list taken while an object's last reference is going skips it
    let shared = reg(s.x, |r| r[20].clone().unwrap());
    *shared.me.lock() = alloc::sync::Weak::new();
    let mut l4 = Vec::new();
    list_live(s.x, 0, 10, &mut l4);
    assert!(l4.is_empty());
    drop(a);
}

#[test]
fn offline_lets_pins_go_and_keeps_bpf_device_programs() {
    let sim = world();
    let s = start(&sim, LXS_SEC, 500, 1, true, obj_handler());
    s.x.objs.pins.lock().insert(1, StdArc::new(Plain));
    offline(s.x);
    assert!(s.x.objs.pins.lock().is_empty());
    // (wave10 G10-C: the device programs stay; only a service given up drops them)
    assert!(crate::fake::rec(|r| r.bpf_programs.is_empty()));
    // The area is made once and kept across restarts
    assert_eq!(s.x.objs.area.load(Ordering::Relaxed), 0);
    assert_eq!(online(s.x), 0);
    let f = s.x.objs.frames.lock().as_ref().unwrap().base;
    assert_eq!(s.x.objs.area.load(Ordering::Relaxed), f);
    // map_area maps it into the calling service
    let r = StdArc::new(StdAtomicU64::new(0));
    let r2 = r.clone();
    let x = s.x;
    sim.spawn(svc_task(510, 500, s.ep), move || r2.store(map_area(x) as u64, Ordering::Release));
    sim.run_others();
    assert!(r.load(Ordering::Acquire) > 0);
    // Without an address space it cannot be mapped; without memory it cannot be made
    let r3 = r.clone();
    sim.spawn(Task::server(511, 500, s.ep), move || r3.store(map_area(x) as u64, Ordering::Release));
    sim.run_others();
    assert_eq!(r.load(Ordering::Acquire) as i64, -14);
    drop_area(s.x);
    crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
    assert_eq!(online(s.x), -12);
    crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
    assert_eq!(online_adopt(s.x), -12);
    crate::fake::ALLOC_FAIL.store(1, Ordering::Release);
    assert_eq!(map_area(s.x), -12);
}

#[test]
fn current_fd_and_object_in() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(25, LX_OBJ_KIND_SVCTEST);
    let (d, slot, flags, svc) = current_fd(fd as u64).unwrap();
    assert_eq!((slot, flags, svc), (25, 0, LXS_TEST));
    assert!(d.as_server().is_some());
    assert!(current_fd(999).is_none());
    // A descriptor whose object is stale: none
    offline(s.x);
    assert!(current_fd(fd as u64).is_none());
    // client_fds: unknown request
    assert_eq!(client_fds(1).err(), Some(ESRCH));
}

#[test]
fn writes_later_go_through_a_kernel_task() {
    let sim = world();
    let got = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    let inner = obj_handler();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.nr == 1 && s.call.obj_flags & LX_OBJ_FLAGS_KBUF != 0 {
            g2.lock().unwrap().push(s.input(1).unwrap());
            return (8, 0);
        }
        inner(s)
    }));
    let d = dev_at(new_obj(26, LX_OBJ_KIND_EVENTFD));
    write_later(d.clone(), 5);
    assert_eq!(sim.spawned(), vec!["lx-later"]);
    // Only one task, however many writes
    write_later(d.clone(), 6);
    assert_eq!(sim.spawned().len(), 1);
    // The task (run here as a kernel thread of its own)
    let mut t = Task::linux(400, 400);
    t.personality = crate::task::TaskPersonality::Hydra;
    sim.spawn(t, || {
        crate::world::bkl_enter();
        later_task()
    });
    sim.settle();
    assert_eq!(*got.lock().unwrap(), vec![5u64.to_ne_bytes().to_vec(), 6u64.to_ne_bytes().to_vec()]);
    // More work later: the task wakes for it
    write_later(d, 7);
    sim.settle();
    assert_eq!(got.lock().unwrap().len(), 3);
}

// wave8 GX2 begin
/// lx-ipc's message queues keep lx-net's netlink socket for glibc's `SIGEV_THREAD`: a service
/// may pin another service's object (never its own: it keeps those itself), and a
/// notification through the pin goes to the object's owner as `LX_KCALL_NLDELIVER`.
#[test]
fn a_service_pins_another_services_object() {
    let sim = world();
    // The network service (co-located in linux-server in this world) installs a netlink
    // socket at `socket(AF_NETLINK, ..)`, and takes deliveries
    let got: StdArc<StdMutex<Vec<(u64, u64)>>> = StdArc::new(StdMutex::new(Vec::new()));
    let g2 = got.clone();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| match s.call.nr {
        41 => (install(s, 33, LX_OBJ_KIND_NETLINK, 0, 0), 0),
        n => {
            g2.lock().unwrap().push((n, s.call.obj));
            (0, 0)
        }
    }));
    crate::world::bkl_enter();
    let nl = crate::lx::forward(&crate::lx::tests::frame(41, [16, 3, 0, 0, 0, 0])).unwrap();
    assert!(nl >= 0, "{nl}");
    let out: Out = StdArc::new(StdMutex::new(Vec::new()));
    let o2 = out.clone();
    start(&sim, LXS_TEST, 300, 1, true, ops(move |s| {
        let push = |v: i64| o2.lock().unwrap().push(v);
        // linux-server's object: pinned; the test service's own (slot 5): refused
        let t = obj_ctl(LX_OBJ_PIN, s.call.id, nl as u64, 0);
        push((t > 0) as i64);
        push(obj_ctl(LX_OBJ_PIN, s.call.id, s.call.args[1], 0));
        let data = *b"cookie";
        push(obj_ctl(LX_OBJ_NOTIFY, t as u64, data.as_ptr() as u64, 6));
        push(obj_ctl(LX_OBJ_UNPIN, t as u64, 0, 0));
        0
    }));
    let own = new_obj(5, LX_OBJ_KIND_SVCTEST);
    assert!(own >= 0);
    assert_eq!(run_ops(own as u64, 0), 0);
    assert_eq!(*out.lock().unwrap(), vec![1, EBADF, 0, 0]);
    assert_eq!(*got.lock().unwrap(), vec![(LX_KCALL_NLDELIVER, 33)]);
}
// wave8 GX2 end
