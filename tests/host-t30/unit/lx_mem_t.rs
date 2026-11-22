//! `src/lx/mem.rs`: handles, sharing, kept objects, DMA objects, mappings, a service's
//! `mmap` answer.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::objs::{dev_at, new_obj};
use crate::lx::tests::{handler, start, world};
use crate::world::Task;
use std::sync::{Arc as StdArc, Mutex as StdMutex};

fn svc_task(tid: u64, ep: u32) -> Task {
    let mut t = Task::server(tid, tid, ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    t
}

const EP: u32 = ENDPOINT_SVC_TEST;

#[test]
fn handles_share_info_close() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(300, EP), move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        let h = sys_mem(LX_MEM_ANON, 5000, 0, 0, 0);
        push(h);
        push(sys_mem(LX_MEM_INFO, h as u64, 0, 0, 0));
        push(sys_mem(LX_MEM_ANON, 0, 0, 0, 0));
        push(sys_mem(LX_MEM_ANON, LX_MEM_MAX + 1, 0, 0, 0));
        // Mapped into the service, shared with net-server
        let a = sys_mem(LX_MEM_MAP, h as u64, 0, 8192, 3);
        push((a > 0) as i64);
        push(sys_mem(LX_MEM_MAP, h as u64, 4096, 8192, 3));
        push(sys_mem(LX_MEM_MAP, h as u64, 1, 4096, 3));
        push(sys_mem(LX_MEM_MAP, 99, 0, 4096, 3));
        let peer = sys_mem(LX_MEM_SHARE, h as u64, ENDPOINT_NET_SERVER as u64, 0, 0);
        push(peer);
        push(sys_mem(LX_MEM_SHARE, h as u64, 0x7777, 0, 0));
        push(sys_mem(LX_MEM_SHARE, 99, ENDPOINT_NET_SERVER as u64, 0, 0));
        push(sys_mem(LX_MEM_UNMAP, a as u64, 8192, 0, 0));
        push(sys_mem(LX_MEM_CLOSE, h as u64, 0, 0, 0));
        push(sys_mem(LX_MEM_CLOSE, h as u64, 0, 0, 0));
        push(sys_mem(LX_MEM_CLOSE, 0, 0, 0, 0));
        push(sys_mem(LX_MEM_INFO, h as u64, 0, 0, 0));
        // A freed handle is used again
        push(sys_mem(LX_MEM_ANON, 1, 0, 0, 0));
        push(sys_mem(99, 0, 0, 0, 0));
    });
    sim.run_others();
    let v = r.lock().unwrap().clone();
    assert_eq!(v, vec![1, 2, EINVAL, EINVAL, 1, EINVAL, EINVAL, EBADF, 1, EINVAL, EBADF, 0, 0, EBADF, EBADF, EBADF, 1, EINVAL]);
    assert_eq!(crate::fake::rec(|r| r.munmaps.clone()).len(), 1);
    // The peer's handle reaches the same object
    assert_eq!(get(ENDPOINT_NET_SERVER, 1).unwrap().pages(), 2);
    assert!(get(ENDPOINT_NET_SERVER, 0).is_none());
    assert!(summary().contains("0x28: 1 handles"));
    // Programs may not
    assert_eq!(sys_mem(LX_MEM_ANON, 1, 0, 0, 0), EPERM);
    // The service goes: its handles go
    service_gone(EP);
    service_gone(ENDPOINT_NET_SERVER);
    assert!(crate::fake::logged("handles dropped"));
    service_gone(0x7777);
    assert!(get(ENDPOINT_NET_SERVER, 1).is_none());
}

#[test]
fn kept_objects_survive_their_service() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(300, EP), move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        push(sys_mem(LX_MEM_ANON, 4096, LX_MEM_KEPT, 7, 0));
        push(sys_mem(LX_MEM_ANON, 4096, LX_MEM_KEPT, 0, 0));
        // The same key again: the old pages
        push(sys_mem(LX_MEM_ANON, 4096, LX_MEM_KEPT, 7, 0));
        push(sys_mem(LX_MEM_INFO, 1, 0, 0, 0) >> 48);
        push(sys_mem(LX_MEM_UNKEEP, 7, 0, 0, 0));
        push(sys_mem(LX_MEM_UNKEEP, 7, 0, 0, 0));
        push(sys_mem(LX_MEM_ANON, 0, LX_MEM_KEPT, 7, 0));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![1, EINVAL, 2 | LX_MEM_EXISTED, 1, 0, EINVAL, EINVAL]);
    // Kept objects by service, the ladder's reset
    let (o, new) = kept_get_or_create(LXS_TEST, 3, 8192).unwrap();
    assert!(new);
    assert_eq!(kept_list(LXS_TEST), vec![(3, 2, 0)]);
    let (o2, new2) = kept_get_or_create(LXS_TEST, 3, 8192).unwrap();
    assert!(!new2 && StdArc::ptr_eq(&o, &o2));
    for k in 10..10 + KEPT_MAX as u64 - 1 {
        kept_get_or_create(LXS_TEST, k, 4096).unwrap();
    }
    assert_eq!(kept_get_or_create(LXS_TEST, 1 << 40, 4096).err(), Some(ENOMEM));
    drop_kept(LXS_TEST);
    assert!(kept_list(LXS_TEST).is_empty());
    drop_kept(LXS_TEST);
    // A service without a host id may not keep
    let r3 = r.clone();
    sim.spawn(svc_task(310, ENDPOINT_NET_DEV), move || {
        r3.lock().unwrap().push(sys_mem(LX_MEM_ANON, 4096, LX_MEM_KEPT, 1, 0));
        r3.lock().unwrap().push(sys_mem(LX_MEM_UNKEEP, 1, 0, 0, 0));
    });
    sim.run_others();
    assert_eq!(&r.lock().unwrap()[7..], &[EPERM, EPERM]);
}

// wave7 G7-6: thousands of kept objects per service (vfs-server's tmpfs files), counted
// per service, dropped per service, keys far apart
#[test]
fn kept_objects_are_counted_and_dropped_per_service() {
    let _sim = world();
    assert!(KEPT_MAX >= LX_MEM_HANDLES);
    for k in 0..KEPT_MAX as u64 {
        kept_get_or_create(LXS_TEST, (1 << 32) + k, 4096).unwrap();
    }
    assert_eq!(kept_get_or_create(LXS_TEST, 5, 4096).err(), Some(ENOMEM));
    // Another service is not limited by the first one's objects
    let (_, new) = kept_get_or_create(LXS_SEC, u64::MAX, 4096).unwrap();
    assert!(new);
    let (_, new) = kept_get_or_create(LXS_SEC, 0, 4096).unwrap();
    assert!(new);
    // An existing key is found (no new object, even at the limit)
    let (_, new) = kept_get_or_create(LXS_TEST, 1 << 32, 4096).unwrap();
    assert!(!new);
    assert_eq!(kept_list(LXS_TEST).len(), KEPT_MAX);
    drop_kept(LXS_TEST);
    assert!(kept_list(LXS_TEST).is_empty());
    assert_eq!(kept_list(LXS_SEC).iter().map(|k| k.0).collect::<Vec<_>>(), vec![0, u64::MAX]);
    drop_kept(LXS_SEC);
}

// wave7 G7-6: a restarted service lists its kept keys to free the ones its state does not name
#[test]
fn a_service_lists_its_kept_keys() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(320, EP), move || {
        for k in [5u64, 1 << 32, (1 << 32) + 9, u64::MAX] {
            sys_mem(LX_MEM_ANON, 4096, LX_MEM_KEPT, k, 0);
        }
        let mut buf = [0u64; 8];
        let n = sys_mem(LX_MEM_KEPTKEYS, buf.as_mut_ptr() as u64, 8, 0, 0);
        r2.lock().unwrap().push((n, buf.to_vec()));
        // From a key on, and fewer than asked: the first page
        let mut two = [0u64; 2];
        let n = sys_mem(LX_MEM_KEPTKEYS, two.as_mut_ptr() as u64, 2, 6, 0);
        r2.lock().unwrap().push((n, two.to_vec()));
        let n = sys_mem(LX_MEM_KEPTKEYS, 8, 4, 0, 0);
        r2.lock().unwrap().push((n, vec![]));
        let n = sys_mem(LX_MEM_KEPTKEYS, buf.as_mut_ptr() as u64, 8, u64::MAX, 0);
        r2.lock().unwrap().push((n, buf[..1].to_vec()));
    });
    sim.run_others();
    let v = r.lock().unwrap().clone();
    assert_eq!(v[0].0, 4);
    assert_eq!(&v[0].1[..4], &[5, 1 << 32, (1 << 32) + 9, u64::MAX]);
    assert_eq!(v[1], (2, vec![1 << 32, (1 << 32) + 9]));
    assert_eq!(v[2].0, EFAULT);
    assert_eq!(v[3], (1, vec![u64::MAX]));
    // Another service sees none of them; one without a host id may not ask
    let r3 = r.clone();
    sim.spawn(svc_task(330, ENDPOINT_NET_DEV), move || {
        let mut buf = [0u64; 2];
        r3.lock().unwrap().push((sys_mem(LX_MEM_KEPTKEYS, buf.as_mut_ptr() as u64, 2, 0, 0), vec![]));
    });
    sim.run_others();
    assert_eq!(r.lock().unwrap()[4].0, EPERM);
    drop_kept(LXS_TEST);
}

#[test]
fn dma_objects_are_contiguous_and_in_the_drivers_domain() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(300, EP), move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        let mut phys = 0u64;
        let h = sys_mem(LX_MEM_DMA, 6000, &mut phys as *mut u64 as u64, 0, 0);
        push(h);
        push((phys != 0 && get(EP, h as u32).unwrap().phys_base() == Some(phys)) as i64);
        push(sys_mem(LX_MEM_INFO, h as u64, 0, 0, 0) >> 49);
        push(sys_mem(LX_MEM_DMA, 0, 0, 0, 0));
        push(sys_mem(LX_MEM_DMA, DMA_MAX + 1, 0, 0, 0));
        push(sys_mem(LX_MEM_DMA, 4096, 8, 0, 0));
        crate::fake::ALLOC_FAIL.store(1, core::sync::atomic::Ordering::Release);
        push(sys_mem(LX_MEM_DMA, 4096, 0, 0, 0));
        crate::fake::rec(|r| r.dma_fail = 1);
        push(sys_mem(LX_MEM_DMA, 4096, 0, 0, 0));
        // Closing the handle frees it and takes it out of the domain
        push(sys_mem(LX_MEM_CLOSE, h as u64, 0, 0, 0));
    });
    sim.run_others();
    assert_eq!(*r.lock().unwrap(), vec![1, 1, 1, EINVAL, EINVAL, EFAULT, ENOMEM, ENOMEM, 0]);
    let dma = crate::fake::rec(|r| r.dma.clone());
    assert!(dma.iter().any(|d| d.0 && d.3 == 8192));
    assert!(dma.iter().any(|d| !d.0 && d.3 == 8192));
    // A kernel object over frames
    let f = frames(0x10_0000, 4);
    assert_eq!((f.pages(), f.phys_base()), (4, Some(0x10_0000)));
}

#[test]
fn map_current_checks_and_names_the_mapping() {
    let sim = world();
    let o = anon(8192).unwrap();
    assert_eq!(map_current(o.clone(), 0, 4096, 3, None), Err(EFAULT));
    let mm = crate::memory::vm::Mm::shared();
    sim.with_task(100, |t| t.mm = Some(mm.clone()));
    let a = map_current(o.clone(), 4096, 4096, 7 | 8, Some(0x4000_0000)).unwrap();
    assert_eq!(a, 0x4000_0000);
    {
        let m = mm.lock();
        let map = m.maps.last().unwrap();
        assert_eq!((map.prot, map.fixed, map.shared, map.pgoff, map.name.as_deref()), (7, true, true, 1, Some("[hydra-mem]")));
    }
    assert_eq!(map_current(o.clone(), 0, 0, 3, None), Err(EINVAL));
    mm.lock().mmap_err = Some(-12);
    assert_eq!(map_current(o, 0, 4096, 3, None), Err(-12));
    // Too many handles
    for _ in 0..LX_MEM_HANDLES {
        give(0x99, anon(4096).unwrap()).unwrap();
    }
    assert_eq!(give(0x99, anon(4096).unwrap()), Err(EMFILE));
    service_gone(0x99);
}

#[test]
fn a_service_object_is_mapped_by_its_mmap_answer() {
    let sim = world();
    // The service answers mmap (nr 9) with a handle of its own
    let s = start(&sim, LXS_TEST, 300, 1, true, handler(|s| {
        match s.call.nr {
            9 => match s.call.args[1] {
                0 => (sys_mem(LX_MEM_ANON, 8192, 0, 0, 0), 0).0.max(0) as i64,
                1 => -6,
                2 => 0,
                3 => lx_mmap_answer(77, 0, false),
                _ => {
                    let h = sys_mem(LX_MEM_ANON, 8192, 0, 0, 0) as u32;
                    lx_mmap_answer(h, 1, true)
                }
            },
            _ => crate::lx::tests::objs::obj_handler()(s).0,
        }
        .into_tuple()
    }));
    let d = dev_at(new_obj(30, LX_OBJ_KIND_SVCTEST));
    crate::world::bkl_enter();
    let (obj, w, pg) = server_mmap(&d, [3, 4, 0, 0, 0, 0]).ok().unwrap();
    assert_eq!((w, pg), (EACCES, 1));
    assert!(obj.get_page(0).is_none());
    assert_eq!(server_mmap(&d, [3, 1, 0, 0, 0, 0]).err(), Some(-6));
    assert_eq!(server_mmap(&d, [3, 2, 0, 0, 0, 0]).err(), Some(ENODEV));
    assert_eq!(server_mmap(&d, [3, 3, 0, 0, 0, 0]).err(), Some(ENODEV));
    let _ = s;
    // A kernel device: no owner
    let k: StdArc<dyn crate::compat::linux::chardev::CharDevice> = StdArc::new(crate::lx::obj::tests::Plain);
    assert_eq!(owner_endpoint(&k), 0);
}

// wave8 GZ begin: zfs-server (a classic server) keeps its intent log across its restarts
#[test]
fn zfs_server_keeps_its_log_across_restarts() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    sim.spawn(svc_task(340, ENDPOINT_ZFS_SERVER), move || {
        r2.lock().unwrap().push(sys_mem(LX_MEM_ANON, 8192, LX_MEM_KEPT, 1, 0));
    });
    sim.run_others();
    service_gone(ENDPOINT_ZFS_SERVER);
    let r3 = r.clone();
    sim.spawn(svc_task(341, ENDPOINT_ZFS_SERVER), move || {
        r3.lock().unwrap().push(sys_mem(LX_MEM_ANON, 8192, LX_MEM_KEPT, 1, 0));
        let mut keys = [0u64; 4];
        r3.lock().unwrap().push(sys_mem(LX_MEM_KEPTKEYS, keys.as_mut_ptr() as u64, 4, 0, 0));
        r3.lock().unwrap().push(keys[0] as i64);
    });
    sim.run_others();
    // The second instance gets the first one's object back, under its kept-only id
    assert_eq!(*r.lock().unwrap(), vec![1, 1 | LX_MEM_EXISTED, 1, 1]);
    assert_eq!(kept_list(KEPT_ID_ZFS).iter().map(|k| k.0).collect::<Vec<_>>(), vec![1]);
    assert!((KEPT_ID_ZFS as usize) >= LXS_MAX);
    drop_kept(KEPT_ID_ZFS);
    service_gone(ENDPOINT_ZFS_SERVER);
}
// wave8 GZ end

trait IntoTuple {
    fn into_tuple(self) -> (i64, u64);
}
impl IntoTuple for i64 {
    fn into_tuple(self) -> (i64, u64) {
        (self, 0)
    }
}
