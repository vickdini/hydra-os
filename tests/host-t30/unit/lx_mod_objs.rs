//! `src/lx/mod.rs` with server objects: calls routed by descriptor (both entry paths, the
//! descriptor-table caches), the extra words of Group 9's calls, `call_obj*`, `call_plain`,
//! `dev_open`, client memory, process info.

use super::*;
use calls::server_task;

/// Installs a server object for the caller of the call `s` serves (`LX_OBJ_INSTALL`): its
/// descriptor, or the error.
pub(crate) fn install(s: &Served, slot: u32, kind: u32, flags: u32, tag: u64) -> i64 {
    let mut d = LxObjDesc { slot, kind, flags, mode: 0o600, uid: 1000, gid: 1000, name_len: 8, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag, key: 0xC0DE + slot as u64 };
    d.name[..8].copy_from_slice(b"svc-test");
    obj::obj_ctl(LX_OBJ_INSTALL, s.call.id, &d as *const LxObjDesc as u64, 0)
}

/// A service handler for objects: `LX_TEST_OBJ(slot, kind)` installs one; `read` answers
/// "data" (or what `LX_OBJ` says), `write` the bytes it got; any other call answers its
/// object slot and flags (`obj | obj_flags`, in a word).
pub(crate) fn obj_handler() -> Handler {
    handler(|s| match s.call.nr {
        LX_TEST_NR if s.call.args[0] == LX_TEST_OBJ => (install(s, s.call.args[1] as u32, s.call.args[2] as u32, s.call.args[3] as u32, s.call.args[4]), 0),
        0 => {
            s.output(1, b"data");
            (4, 0)
        }
        1 => (s.input(1).map_or(-1, |b| b.len() as i64), 0),
        _ => ((s.call.obj as i64) | (s.call.obj_flags >> 32 << 40) as i64, 0),
    })
}

/// A test object for the running task, through the service: its descriptor.
pub(crate) fn new_obj(slot: u64, kind: u32) -> i64 {
    test_call_args(LX_TEST_OBJ, [slot, kind as u64, 0, 0, 0])
}

/// `LX_TEST_NR(op, a..)` with five more words.
pub(crate) fn test_call_args(op: u64, a: [u64; 5]) -> i64 {
    crate::world::bkl_enter();
    forward(&frame(LX_TEST_NR, [op, a[0], a[1], a[2], a[3], a[4]])).expect("forwarded")
}

/// The device at descriptor `fd` of the running task.
pub(crate) fn dev_at(fd: i64) -> Arc<dyn crate::compat::linux::chardev::CharDevice> {
    match crate::task::with_current_fds_mut(|t| t.get(fd as usize).cloned()) {
        Some(crate::fs::FileDescriptor::Device(d)) => d,
        _ => panic!("no device at {fd}"),
    }
}

#[test]
fn reads_and_writes_on_a_server_object_go_to_its_service() {
    let sim = world();
    crate::fake::user_space_on();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(5, LX_OBJ_KIND_SVCTEST);
    assert!(fd >= 0, "{fd}");
    // The descriptor holds a server object of the test service, slot 5
    let d = dev_at(fd);
    let o = d.as_server().unwrap();
    assert_eq!((o.slot(), o.svc(), o.kind()), (Some(5), LXS_TEST, LX_OBJ_KIND_SVCTEST));
    // read(fd): the ordinary path (the kernel lock held)
    let mut buf = [0u8; 8];
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(0, [fd as u64, buf.as_mut_ptr() as u64, 8, 0, 0, 0])), Some(4));
    assert_eq!(&buf[..4], b"data");
    // write(fd): the lock-free path
    let msg = *b"hello";
    match fast_entry(&frame(1, [fd as u64, msg.as_ptr() as u64, 5, 0, 0, 0])) {
        Some(Fast::Call(r)) => assert_eq!(r, 5),
        _ => panic!("not forwarded on the lock-free path"),
    }
    assert!(FAST_CALLS.load(Ordering::Relaxed) >= 1);
    // read and write of a kernel descriptor: the kernel's (decided once, cheaply)
    let kfd = crate::task::with_current_fds_mut(|t| t.alloc_fd(crate::fs::FileDescriptor::File { path: "/etc/passwd".into(), readable: true, writable: false })).unwrap();
    assert!(fast_entry(&frame(0, [kfd as u64, buf.as_mut_ptr() as u64, 8, 0, 0, 0])).is_none());
    // `forward` takes the lock-free entry's word for it
    assert_eq!(IO_KERNEL[0].load(Ordering::Relaxed), 100);
    assert!(forward(&frame(0, [kfd as u64, buf.as_mut_ptr() as u64, 8, 0, 0, 0])).is_none());
    assert_eq!(IO_KERNEL[0].load(Ordering::Relaxed), 0);
    // ... and without the mark, by the descriptor test
    assert!(forward(&frame(0, [kfd as u64, buf.as_mut_ptr() as u64, 8, 0, 0, 0])).is_none());
    // A socket call on the object: by descriptor (its owner answers with the slot)
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(51, [fd as u64, 0, 0, 0, 0, 0])), Some(5));
    // The object's flags travel with the call (O_NONBLOCK)
    d.set_nonblock(true);
    assert_eq!(o.flags(), 0o4000);
    assert_eq!(s.x.lx(|t| t.reqs.iter().filter(|r| r.state != RState::Free).count()), 0);
}

#[test]
fn bind_and_connect_on_a_unix_socket_go_to_the_kernel_first() {
    let sim = world();
    start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(6, LX_OBJ_KIND_UNIX);
    let d = dev_at(fd);
    assert!(kernel_first(42, &d));
    assert!(kernel_first(49, &d));
    assert!(!kernel_first(43, &d));
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(42, [fd as u64, 0, 0, 0, 0, 0])), None);
    assert!(fast_entry(&frame(49, [fd as u64, 0, 0, 0, 0, 0])).is_none());
    // Another kind is forwarded
    let fd2 = new_obj(7, LX_OBJ_KIND_SVCTEST);
    assert!(!kernel_first(42, &dev_at(fd2)));
}

#[test]
fn group9_calls_carry_object_namespace_umask_and_context() {
    let sim = world();
    crate::fake::user_space_on();
    crate::fake::IPC_NS.store(33, Ordering::Release);
    let calls = seen();
    let c2 = calls.clone();
    let inner = obj_handler();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        if s.call.nr == LX_TEST_NR {
            return inner(s);
        }
        (0, 0)
    }));
    // A queue descriptor of linux-server (the IPC service is co-located there)
    PRIV[(LX_TEST_NR - PRIV_BASE) as usize].store(T_SERVER | (LXS_LINUX as u32) << T_SVC_SHIFT, Ordering::Release);
    let fd = new_obj(9, LX_OBJ_KIND_MQ);
    assert!(fd >= 0);
    crate::world::bkl_enter();
    // mq_timedsend(fd, msg, len, prio, timeout): T_FD0
    let msg = *b"m";
    assert_eq!(forward(&frame(242, [fd as u64, msg.as_ptr() as u64, 1, 0, 0, 0])), Some(0));
    // mq_open(name, flags, mode, attr): T_IPC | T_UMASK
    assert_eq!(forward(&frame(240, [0, 0, 0, 0, 0, 0])), Some(0));
    let c = calls.lock().unwrap().clone();
    let send = c.iter().find(|c| c.nr == 242).unwrap();
    assert_eq!(send.obj, 9);
    let open = c.iter().find(|c| c.nr == 240).unwrap();
    assert_eq!(open.ipc_ns, 33);
    assert_eq!(open.umask, 0o022);
    assert_eq!(open.obj, LX_OBJ_NONE);
    // A descriptor that is not a server object: no slot
    calls.lock().unwrap().clear();
    assert_eq!(forward(&frame(243, [77, 0, 0, 0, 0, 0])), Some(0));
    assert_eq!(calls.lock().unwrap()[0].obj, LX_OBJ_NONE);
}

#[test]
fn the_context_call_carries_process_group_session_and_namespaces() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        ((s.call.pgid as u64 | (s.call.sid as u64) << 32) as i64, 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(LX_TEST_CTX_NR, [0; 6])), Some((100u64 | 99u64 << 32) as i64));
    // The lock-free path too
    match fast_entry(&frame(LX_TEST_CTX_NR, [0; 6])) {
        Some(Fast::Call(r)) => assert_eq!(r, (100u64 | 99u64 << 32) as i64),
        _ => panic!("not on the lock-free path"),
    }
    // The process table busy: the lock-free path gives up (the ordinary path waits)
    let g = crate::compat::linux::proc::PROCS.lock();
    assert!(fast_entry(&frame(LX_TEST_CTX_NR, [0; 6])).is_none());
    drop(g);
    let c = calls.lock().unwrap()[0];
    assert_eq!(c.user_ns, 0);
}

#[test]
fn socket_calls_in_a_network_namespace_are_marked() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        (3, 0)
    }));
    crate::fake::NET_ISOLATED.store(true, Ordering::Release);
    crate::world::bkl_enter();
    // socket(AF_INET, ..) by family: the network service (co-located in linux-server)
    assert_eq!(forward(&frame(41, [2, 1, 0, 0, 0, 0])), Some(3));
    let c = calls.lock().unwrap()[0];
    assert_eq!(c.svc, LXS_NET as u32);
    assert_ne!(c.obj_flags & LX_OBJ_FLAGS_NETNS, 0);
    // The lock-free path: by family, marked from the cached identity (no namespace of its
    // own in the process table: not marked)
    match fast_entry(&frame(41, [1, 1, 0, 0, 0, 0])) {
        Some(Fast::Call(r)) => assert_eq!(r, 3),
        _ => panic!("not on the lock-free path"),
    }
    assert_eq!(calls.lock().unwrap()[1].svc, LXS_IPC as u32);
    // A family no service has: the kernel's
    assert!(fast_entry(&frame(41, [17, 1, 0, 0, 0, 0])).is_none());
}

#[test]
fn bpf_map_calls_carry_the_map_and_its_element_pointers() {
    let sim = world();
    crate::fake::user_space_on();
    let calls = seen();
    let c2 = calls.clone();
    let inner = obj_handler();
    start(&sim, LXS_SEC, 500, 1, true, handler(move |s| {
        if s.call.nr == LX_TEST_NR {
            return inner(s);
        }
        c2.lock().unwrap().push(s.call);
        // A lookup: the key came in, the value goes out
        if s.call.args[0] == 1 && s.call.obj != LX_OBJ_NONE {
            assert_eq!(s.input(3).as_deref(), Some(&[1u8, 2, 3, 4][..]));
            s.output(4, &[9; 8]);
        }
        (0, 0)
    }));
    PRIV[(LX_TEST_NR - PRIV_BASE) as usize].store(T_SERVER | (LXS_SEC as u32) << T_SVC_SHIFT, Ordering::Release);
    // A map whose tag is its key and value sizes (4, 8)
    let fd = test_call_args(LX_TEST_OBJ, [11, LX_OBJ_KIND_BPF_MAP as u64, 0, 4 | 8 << 32, 0]);
    assert!(fd >= 0, "{fd}");
    let key = [1u8, 2, 3, 4];
    let mut val = [0u8; 8];
    let mut attr = [0u8; 24];
    attr[0..4].copy_from_slice(&(fd as u32).to_le_bytes());
    attr[8..16].copy_from_slice(&(key.as_ptr() as u64).to_le_bytes());
    attr[16..24].copy_from_slice(&(val.as_mut_ptr() as u64).to_le_bytes());
    // bpf(MAP_LOOKUP_ELEM, attr, 24), stale words in args[3..6] cleared: the ordinary path
    crate::world::bkl_enter();
    assert_eq!(forward(&frame(321, [1, attr.as_ptr() as u64, 24, 0xdead, 0xbeef, 0xf00d])), Some(0));
    assert_eq!(val, [9; 8]);
    let c = calls.lock().unwrap()[0];
    assert_eq!(c.obj, 11);
    assert_ne!(c.obj_flags & LX_OBJ_FLAGS_AT1, 0);
    assert_eq!(c.obj_flags >> 32 & 0x3FFF_FFFF, fd as u64);
    assert_eq!(c.args[3], key.as_ptr() as u64);
    // ... and the lock-free path (bpf alone: the cached descriptor table)
    val = [0; 8];
    match fast_entry(&frame(321, [1, attr.as_ptr() as u64, 24, 0, 0, 0])) {
        Some(Fast::Call(r)) => assert_eq!(r, 0),
        _ => panic!("not on the lock-free path"),
    }
    assert_eq!(val, [9; 8]);
    // A command naming a descriptor that is no map of this service: no object
    attr[0..4].copy_from_slice(&999u32.to_le_bytes());
    assert_eq!(forward(&frame(321, [1, attr.as_ptr() as u64, 24, 0, 0, 0])), Some(0));
    assert_eq!(calls.lock().unwrap().last().unwrap().obj, LX_OBJ_NONE);
}

#[test]
fn call_obj_and_kernel_buffers() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    let inner = obj_handler();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        match s.call.nr {
            LX_TEST_NR => inner(s),
            // A kernel-buffer read: the bytes for args[1]; a write: how many it got
            0 if s.call.obj_flags & LX_OBJ_FLAGS_KBUF != 0 => {
                s.output(1, b"kbuf");
                (4, 0)
            }
            1 if s.call.obj_flags & LX_OBJ_FLAGS_KBUF != 0 => (s.input(1).map_or(-1, |b| b.len() as i64), 0),
            LX_KCALL_NLDELIVER => (s.input(1).map_or(-1, |b| b.len() as i64), 0),
            16 => (s.call.args[1] as i64, 0),
            _ => (-99, 0),
        }
    }));
    let fd = new_obj(12, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    crate::world::bkl_enter();
    // ioctl through call_obj
    assert_eq!(call_obj(16, [fd as u64, 0x5401, 0, 0, 0, 0], &d), 0x5401);
    assert_eq!(calls.lock().unwrap().last().unwrap().obj, 12);
    // call_obj_ino: the socket node goes along
    call_obj_ino(16, [fd as u64, 1, 0, 0, 0, 0], &d, 4242);
    assert_eq!(calls.lock().unwrap().last().unwrap().ino, 4242);
    // Kernel buffers both ways
    let mut out = [0u8; 16];
    assert_eq!(call_obj_kbuf(&d, false, &[], &mut out), 4);
    assert_eq!(&out[..4], b"kbuf");
    assert_eq!(call_obj_kbuf(&d, true, b"12345", &mut []), 5);
    let c = *calls.lock().unwrap().last().unwrap();
    assert_eq!(c.args[0], u64::MAX);
    assert_eq!(c.args[1], LX_KBUF_ADDR);
    assert_ne!(c.obj_flags & 0o4000, 0);
    assert_eq!(call_obj_deliver(&d, b"abc"), 3);
    // Not a server object
    let k: Arc<dyn crate::compat::linux::chardev::CharDevice> = Arc::new(crate::lx::obj::tests::Plain);
    assert_eq!(call_obj(16, [0; 6], &k), EBADF);
    assert_eq!(call_obj_kbuf(&k, false, &[], &mut out), EBADF);
}

#[test]
fn calls_on_a_stale_object_fail() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let fd = new_obj(13, LX_OBJ_KIND_SVCTEST);
    let d = dev_at(fd);
    // Its service went offline: the object's generation is gone
    obj::offline(s.x);
    assert_eq!(d.as_server().unwrap().slot(), None);
    let mut out = [0u8; 4];
    let want = crate::lx::restart_policy::stale_errno(LX_OBJ_KIND_SVCTEST);
    assert_eq!(call_obj(16, [fd as u64, 0, 0, 0, 0, 0], &d), want);
    assert_eq!(call_obj_kbuf(&d, false, &[], &mut out), want);
    // The service not usable (offline, not restarting) but the object live
    obj::online(s.x);
    let fd2 = new_obj(14, LX_OBJ_KIND_SVCTEST);
    let d2 = dev_at(fd2);
    s.x.online.store(false, Ordering::Release);
    assert_eq!(call_obj(16, [fd2 as u64, 0, 0, 0, 0, 0], &d2), EBADF);
    assert_eq!(call_obj_kbuf(&d2, true, b"x", &mut []), EBADF);
    s.x.online.store(true, Ordering::Release);
}

#[test]
fn call_plain_routes_by_family_and_kernel_call() {
    let sim = world();
    let calls = seen();
    let c2 = calls.clone();
    start(&sim, LXS_LINUX, 200, 1, true, handler(move |s| {
        c2.lock().unwrap().push(s.call);
        (s.call.svc as i64, 0)
    }));
    crate::world::bkl_enter();
    assert_eq!(call_plain(41, [1, 1, 0, 0, 0, 0]), LXS_IPC as i64);
    assert_eq!(call_plain(53, [2, 1, 0, 0, 0, 0]), LXS_NET as i64);
    assert_eq!(call_plain(LX_KCALL_PIDFD, [5, 0, 0, 0, 0, 0]), LXS_IPC as i64);
    assert_eq!(call_plain(LX_KCALL_FIFO, [0; 6]), LXS_IPC as i64);
    assert_eq!(call_plain(22, [0; 6]), LXS_IPC as i64);
    // Kernel-made calls carry no groups
    assert_eq!(calls.lock().unwrap()[0].ngroups, 0);
    // A service with no host running: not implemented
    assert_eq!(call_plain(250, [0; 6]), ENOSYS);
    assert_eq!(plain_svc(LX_KCALL_REOPEN, &[0; 6]), LXS_IPC);
    assert_eq!(plain_svc(LX_KCALL_FCNTL, &[0; 6]), LXS_IPC);
}

#[test]
fn dev_open_takes_the_object_the_service_installed() {
    let sim = world();
    let inner = obj_handler();
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        if s.call.nr == LX_KCALL_DEVOPEN {
            assert_eq!(s.call.dev, (240 << 8) | 3);
            return match s.call.args[1] {
                // A failing open
                1 => (-6, 0),
                // A descriptor that is not one of its objects
                2 => (0, 0),
                _ => (install(s, 20, LX_OBJ_KIND_SVCTEST, 0, 0), 0),
            };
        }
        inner(s)
    }));
    // No service claims major 240 yet
    assert!(dev_open((240 << 8) | 3, 0).is_none());
    svc::MAJOR_SVC[240].store(LXS_TEST, Ordering::Release);
    crate::world::bkl_enter();
    let d = dev_open((240 << 8) | 3, 0).unwrap().unwrap();
    assert_eq!(d.as_server().unwrap().slot(), Some(20));
    // The service's descriptor was taken out of the table (the caller installs it again)
    assert!(crate::task::with_current_fds_mut(|t| t.get(0).is_none()));
    assert_eq!(dev_open((240 << 8) | 3, 1).unwrap().err(), Some(-6));
    // fd 0 holds no object: EIO
    assert_eq!(dev_open((240 << 8) | 3, 2).unwrap().err(), Some(EIO));
    // A kernel descriptor at the number answered: EIO too
    crate::task::with_current_fds_mut(|t| t.set_fd(0, Some(crate::fs::FileDescriptor::File { path: "x".into(), readable: true, writable: true })));
    assert_eq!(dev_open((240 << 8) | 3, 2).unwrap().err(), Some(EIO));
}

#[test]
fn client_memory_reaches_the_callers_address_space() {
    let sim = world();
    sim.with_task(100, |t| t.mm = Some(crate::memory::vm::Mm::shared()));
    let mine = StdArc::new(StdMutex::new(vec![10u8, 20, 30, 40]));
    let text = b"path/to\0rest".to_vec();
    let tp = text.as_ptr() as u64;
    let m2 = mine.clone();
    let mp = mine.lock().unwrap().as_ptr() as u64;
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        let id = s.call.id;
        let mut buf = vec![0u8; 16];
        let b = buf.as_mut_ptr() as u64;
        // Read the caller's bytes, add one, write them back (LX_TEST_COPY's work)
        assert_eq!(client_mem(MemOp::Read, id, mp, 4, b), 4);
        for x in &mut buf[..4] {
            *x += 1;
        }
        assert_eq!(client_mem(MemOp::Write, id, mp, 4, b), 4);
        // A string: its length without the NUL
        assert_eq!(client_mem(MemOp::ReadStr, id, tp, 16, b), 7);
        assert_eq!(&buf[..7], b"path/to");
        // No NUL within the limit
        assert_eq!(client_mem(MemOp::ReadStr, id, tp, 4, b), ENAMETOOLONG);
        // Limits and bad addresses
        assert_eq!(client_mem(MemOp::Read, id, mp, (1 << 20) + 1, b), EINVAL);
        assert_eq!(client_mem(MemOp::Read, id, mp, 0, b), 0);
        assert_eq!(client_mem(MemOp::Read, id, mp, 4, 0), EFAULT);
        assert_eq!(client_mem(MemOp::Read, id, 0, 4, b), EFAULT);
        assert_eq!(client_mem(MemOp::Read, id, u64::MAX - 1, 4, b), EFAULT);
        // Not a request of this service
        assert_eq!(client_mem(MemOp::Read, id ^ (1 << 56), mp, 4, b), ESRCH);
        drop(m2.lock());
        (0, 0)
    }));
    assert_eq!(test_call(LX_TEST_COPY, 0, 0), 0);
    assert_eq!(*mine.lock().unwrap(), vec![11, 21, 31, 41]);
    drop(text);
}

#[test]
fn client_memory_waits_for_a_userfaultfd_page() {
    let sim = world();
    let mm = crate::memory::vm::Mm::shared();
    let data = vec![5u8; 8];
    let dp = data.as_ptr() as u64;
    // A page a userfaultfd handler must supply: woken once ("again"), then it proceeds
    mm.lock().uffd.push((dp & !0xFFF, 1));
    mm.lock().uffd.push((dp & !0xFFF, 2));
    sim.with_task(100, |t| t.mm = Some(mm.clone()));
    crate::fake::UFFD.store(true, Ordering::Release);
    start(&sim, LXS_TEST, 300, 1, true, handler(move |s| {
        let mut b = [0u8; 8];
        let r = client_mem(MemOp::Read, s.call.id, dp, 8, b.as_mut_ptr() as u64);
        if s.call.args[1] == 0 {
            assert_eq!(r, 8);
            assert_eq!(b, [5; 8]);
        } else {
            // A handler that refuses kernel accesses (UFFD_USER_MODE_ONLY)
            assert_eq!(r, EFAULT);
        }
        (0, 0)
    }));
    assert_eq!(test_call(LX_TEST_NULL, 0, 0), 0);
    assert!(mm.lock().uffd.is_empty());
    mm.lock().uffd.push((dp & !0xFFF, 3));
    assert_eq!(test_call(LX_TEST_NULL, 1, 0), 0);
    drop(data);
}

#[test]
fn proc_info_gives_parent_and_credentials() {
    let mut t = calls::server_task(300, 300, ENDPOINT_SVC_TEST);
    t.service = Some(ENDPOINT_SVC_TEST);
    let sim = world();
    let mut p = crate::compat::linux::proc::Process::default();
    p.ppid = 1;
    crate::compat::linux::proc::PROCS.lock().insert(100, p.clone());
    let out = StdArc::new(StdMutex::new([0u64; 7]));
    let o2 = out.clone();
    sim.spawn(t, move || {
        let mut w = [0u64; 7];
        assert_eq!(proc_info(100, w.as_mut_ptr() as u64), 0);
        *o2.lock().unwrap() = w;
        assert_eq!(proc_info(555, w.as_mut_ptr() as u64), ESRCH);
        assert_eq!(proc_info(100, 0), EFAULT);
    });
    sim.run_others();
    assert_eq!(*out.lock().unwrap(), [1, 1000, 1000, 1000, 1000, 1000, 1000]);
    // A program may not ask
    assert_eq!(proc_info(100, 8), EPERM);
}
