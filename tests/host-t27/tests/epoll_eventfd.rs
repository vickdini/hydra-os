//! epoll (`src/compat/linux/epoll.rs`) and eventfd (`src/compat/linux/eventfd.rs`):
//! interest lists, level, edge and one-shot reporting over real kernel objects, watches on
//! closed or replaced descriptors, and the eventfd counter in both modes.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::epoll::*;
use hydra_hosttests_t27::compat::linux::eventfd::{self, sys_eventfd2, EventFd, EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const ENOENT: i64 = -2;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOSYS: i64 = -38;

fn ev(events: u32, data: u64) -> Option<LinuxEpollEvent> {
    Some(LinuxEpollEvent { events, data })
}

fn eventfd_at(fd: usize, counter: u64) -> Arc<spin::Mutex<EventFd>> {
    let e = EventFd::new(0, 0);
    e.lock().counter = counter;
    fake::fd::install(fd, FileDescriptor::EventFd(e.clone()));
    e
}

fn collect(ep: &Arc<spin::Mutex<EpollInstance>>, max: usize) -> Vec<(u32, u64)> {
    epoll_collect_ready(ep, max).into_iter().map(|e| (e.events, e.data)).collect()
}

/// A device with an edge counter (a linux-server object's readiness word).
struct Edgy {
    ready: AtomicU64,
    edges: AtomicU64,
}
impl CharDevice for Edgy {
    fn read(&self, _b: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        self.ready.load(Ordering::Relaxed) as u32
    }
    fn add_wait_queues(&self, _w: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::new()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn edges(&self) -> Option<u64> {
        Some(self.edges.load(Ordering::Relaxed))
    }
}

// ------------------------------------------------------------------ epoll

#[test]
fn layouts_and_constants() {
    assert_eq!(std::mem::size_of::<LinuxEpollEvent>(), 12);
    assert_eq!(std::mem::size_of::<LinuxPollFd>(), 8);
    assert_eq!((EPOLLIN, EPOLLPRI, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLNVAL, EPOLLRDHUP), (1, 2, 4, 8, 0x10, 0x20, 0x2000));
    assert_eq!((EPOLLEXCLUSIVE, EPOLLWAKEUP, EPOLLONESHOT, EPOLLET), (1 << 28, 1 << 29, 1 << 30, 1 << 31));
    assert_eq!((EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD, EPOLL_CLOEXEC), (1, 2, 3, 0x80000));
}

#[test]
fn interest_list() {
    fake::reset();
    let ep = EpollInstance::new();
    let mut e = ep.lock();
    let w0 = e.changed.wakes();
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 1)), Ok(()));
    assert_eq!((e.generation, e.changed.wakes()), (1, w0 + 1), "a change wakes waiters");
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 1)), Err(EEXIST));
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 6, None), Err(EINVAL));
    assert_eq!(e.generation, 1, "failures change nothing");
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 5, ev(EPOLLOUT, 9)), Ok(()));
    assert_eq!((e.watches[&5].events, e.watches[&5].data, e.watches[&5].seen), (EPOLLOUT, 9, NOT_SEEN));
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 7, ev(EPOLLIN, 0)), Err(ENOENT));
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 5, None), Err(EINVAL));
    assert_eq!(e.ctl(EPOLL_CTL_DEL, 5, None), Ok(()));
    assert_eq!(e.ctl(EPOLL_CTL_DEL, 5, None), Err(ENOENT));
    assert_eq!(e.ctl(9, 5, ev(EPOLLIN, 0)), Err(EINVAL));
    e.ctl(EPOLL_CTL_ADD, 8, ev(EPOLLIN, 0)).unwrap();
    e.set_file(8, 1234);
    e.set_file(99, 1);
    assert_eq!(e.watches[&8].file, 1234);
}

#[test]
fn level_triggered_reports_while_ready() {
    fake::reset();
    let a = eventfd_at(5, 1);
    eventfd_at(6, 0);
    fake::fd::install(7, FileDescriptor::File { path: "/f".into(), readable: true, writable: true });
    let ep = EpollInstance::new();
    {
        let mut e = ep.lock();
        e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 50)).unwrap();
        e.ctl(EPOLL_CTL_ADD, 6, ev(EPOLLIN, 60)).unwrap();
        e.ctl(EPOLL_CTL_ADD, 7, ev(EPOLLIN | EPOLLOUT, 70)).unwrap();
    }
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 50), (EPOLLIN | EPOLLOUT, 70)]);
    assert_eq!(collect(&ep, 10).len(), 2, "again: still ready");
    assert_eq!(collect(&ep, 1), vec![(EPOLLIN, 50)], "maxevents");
    a.lock().counter = 0;
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN | EPOLLOUT, 70)]);
    // The wait set: the change queue and each watched descriptor's queue
    let w = epoll_wait_set(&ep);
    assert_eq!(w.queue_count(), 3, "changes + two eventfds (files have none)");
}

#[test]
fn edge_triggered_files_and_eventfds() {
    fake::reset();
    fake::fd::install(7, FileDescriptor::File { path: "/f".into(), readable: true, writable: true });
    let mfd = FileDescriptor::MemFd { memfd: Arc::new(spin::Mutex::new(hydra_hosttests_t27::fake::fd::MemFdStub)), flags: 0 };
    fake::fd::install(8, mfd);
    fake::fd::install(9, FileDescriptor::Vnode(Arc::new(spin::Mutex::new(hydra_hosttests_t27::fake::fd::Vnode))));
    let e = eventfd_at(5, 0);
    let ep = EpollInstance::new();
    {
        let mut x = ep.lock();
        for (fd, data) in [(7, 70), (8, 80), (9, 90), (5, 50)] {
            x.ctl(EPOLL_CTL_ADD, fd, ev(EPOLLIN | EPOLLET, data)).unwrap();
        }
    }
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 70), (EPOLLIN, 80), (EPOLLIN, 90)], "files: once");
    assert!(collect(&ep, 10).is_empty());
    // An eventfd: after each write (a wakeup of its queue)
    assert_eq!(eventfd::write(&e, &1u64.to_ne_bytes()), 8);
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 50)]);
    assert!(collect(&ep, 10).is_empty(), "no new edge");
    assert_eq!(eventfd::write(&e, &1u64.to_ne_bytes()), 8);
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 50)]);
    // MOD re-arms: reported again
    ep.lock().ctl(EPOLL_CTL_MOD, 7, ev(EPOLLIN | EPOLLET, 71)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 71)]);
}

#[test]
fn edge_counters_of_server_objects() {
    fake::reset();
    let d = Arc::new(Edgy { ready: AtomicU64::new(1), edges: AtomicU64::new(3) });
    fake::fd::install(5, FileDescriptor::Device(d.clone()));
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN | EPOLLET, 5)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 5)]);
    assert!(collect(&ep, 10).is_empty());
    d.edges.store(4, Ordering::Relaxed);
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 5)]);
    // Level-triggered on the same device: every time
    ep.lock().ctl(EPOLL_CTL_MOD, 5, ev(EPOLLIN, 6)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 6)]);
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 6)]);
    // Errors and hang-ups are reported whatever was asked
    d.ready.store((EPOLLERR | EPOLLHUP) as u64, Ordering::Relaxed);
    ep.lock().ctl(EPOLL_CTL_MOD, 5, ev(EPOLLOUT, 7)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLERR | EPOLLHUP, 7)]);
}

#[test]
fn one_shot_until_modified() {
    fake::reset();
    eventfd_at(5, 1);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN | EPOLLONESHOT, 5)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 5)]);
    assert_eq!(ep.lock().watches[&5].events, EPOLLONESHOT, "disabled");
    assert!(collect(&ep, 10).is_empty());
    ep.lock().ctl(EPOLL_CTL_MOD, 5, ev(EPOLLIN | EPOLLONESHOT, 6)).unwrap();
    assert_eq!(collect(&ep, 10), vec![(EPOLLIN, 6)]);
}

#[test]
fn closed_and_replaced_descriptors() {
    fake::reset();
    eventfd_at(5, 1);
    eventfd_at(6, 1);
    let ep = EpollInstance::new();
    {
        let mut e = ep.lock();
        e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 5)).unwrap();
        e.ctl(EPOLL_CTL_ADD, 6, ev(EPOLLIN, 6)).unwrap();
        e.ctl(EPOLL_CTL_ADD, 7, ev(EPOLLIN, 7)).unwrap(); // never open
    }
    assert_eq!(collect(&ep, 10).len(), 2);
    assert!(ep.lock().watches[&5].file != 0, "the open file was learnt");
    assert!(!ep.lock().watches.contains_key(&7), "a watch on nothing goes");
    // fd 5 closed: its watch goes; fd 6 now names another file: its watch goes too
    fake::fd::FDS.with_borrow_mut(|f| f.close(5).unwrap());
    eventfd_at(6, 1);
    assert!(collect(&ep, 10).is_empty());
    assert!(ep.lock().watches.is_empty());
    // A watch replaced by epoll_ctl meanwhile stays (only a watch on the gone file goes)
    let e = eventfd_at(8, 1);
    ep.lock().ctl(EPOLL_CTL_ADD, 8, ev(EPOLLIN, 8)).unwrap();
    assert_eq!(collect(&ep, 10).len(), 1);
    let _ = e;
}

// ------------------------------------------------------------------ eventfd

#[test]
fn eventfd2_flags() {
    fake::reset();
    assert_eq!(sys_eventfd2(0, !0), ENOSYS, "Chromium's probe");
    assert_eq!(sys_eventfd2(0, 0xffff_ffff), ENOSYS);
    assert_eq!(sys_eventfd2(0, 0x10), EINVAL);
    let fd = sys_eventfd2(7, (EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) as u64);
    assert!(fd >= 3);
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    match fake::fd::get(fd) {
        Some(FileDescriptor::EventFd(e)) => {
            let e = e.lock();
            assert_eq!((e.counter, e.semaphore, e.nonblocking), (7, true, true));
        }
        _ => panic!("not an eventfd"),
    }
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(sys_eventfd2(0, 0), EMFILE);
}

#[test]
fn counter_and_semaphore_modes() {
    fake::reset();
    let e = EventFd::new(3, EFD_NONBLOCK);
    let mut b = [0u8; 8];
    assert_eq!(eventfd::read(&e, &mut [0u8; 4]), EINVAL);
    assert_eq!(eventfd::read(&e, &mut b), 8);
    assert_eq!(u64::from_ne_bytes(b), 3, "the whole count");
    assert_eq!(eventfd::read(&e, &mut b), EAGAIN);
    let s = EventFd::new(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    assert_eq!(eventfd::read(&s, &mut b), 8);
    assert_eq!(u64::from_ne_bytes(b), 1, "one at a time");
    assert_eq!(s.lock().counter, 1);
    // Writes: overflow and the forbidden value
    assert_eq!(eventfd::write(&e, &[0u8; 4]), EINVAL);
    assert_eq!(eventfd::write(&e, &u64::MAX.to_ne_bytes()), EINVAL);
    assert_eq!(eventfd::write(&e, &(u64::MAX - 1).to_ne_bytes()), 8);
    assert_eq!(e.lock().poll_events(), 1, "full: readable, not writable");
    assert_eq!(eventfd::write(&e, &1u64.to_ne_bytes()), EAGAIN);
    assert_eq!(e.lock().poll_events() & 4, 0);
    // The object's own read/write (the native descriptor path)
    let mut o = e.lock();
    assert!(o.read(&mut [0u8; 4]).is_err());
    assert_eq!(o.read(&mut b), Ok(8));
    assert!(o.read(&mut b).is_err(), "empty");
    assert!(o.write(&[0u8; 4]).is_err());
    assert!(o.write(&u64::MAX.to_ne_bytes()).is_err());
    assert_eq!(o.write(&5u64.to_ne_bytes()), Ok(8));
    assert!(o.write(&(u64::MAX - 2).to_ne_bytes()).is_err(), "would overflow");
    assert_eq!(o.poll_events(), 5);
}

#[test]
fn blocking_reads_and_writes() {
    fake::reset();
    let e = EventFd::new(0, 0);
    let e2 = e.clone();
    fake::on_wait(move |_| e2.lock().counter = 4);
    let mut b = [0u8; 8];
    assert_eq!(eventfd::read(&e, &mut b), 8);
    assert_eq!(u64::from_ne_bytes(b), 4);
    fake::reset();
    let e = EventFd::new(0, 0);
    e.lock().counter = u64::MAX - 1;
    let e2 = e.clone();
    fake::on_wait(move |_| e2.lock().counter = 0);
    assert_eq!(eventfd::write(&e, &9u64.to_ne_bytes()), 8);
    assert_eq!(e.lock().counter, 9);
    // Signals restart; nothing to wake: blocks
    fake::reset();
    let e = EventFd::new(0, 0);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(eventfd::read(&e, &mut b), -512);
    e.lock().counter = u64::MAX - 1;
    assert_eq!(eventfd::write(&e, &1u64.to_ne_bytes()), -512);
    fake::SIGNAL_PENDING.set(false);
    assert!(blocks(|| eventfd::write(&e, &1u64.to_ne_bytes())));
    e.lock().counter = 0;
    assert!(blocks(|| eventfd::read(&e, &mut b)));
}
