//! Tests for epoll's interest list and readiness collection
//! (`src/compat/linux/epoll.rs`): EPOLL_CTL_ADD/MOD/DEL, level-triggered
//! reporting, EPOLLONESHOT, EPOLLET on regular files and eventfds, maxevents, and what
//! happens when a watched descriptor is closed.
//!
//! Readiness comes from real kernel objects (eventfd counters, message
//! queues) through the fake descriptor table's `readiness`.

use hydra_hosttests::compat::linux::epoll::*;
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

fn ev(events: u32, data: u64) -> Option<LinuxEpollEvent> {
    Some(LinuxEpollEvent { events, data })
}


fn file(fd: usize) {
    fake::FDS.with_borrow_mut(|f| f.install(fd, FileDescriptor::File { path: "/etc/hosts".into(), readable: true, writable: false }));
}

/// (events, data) pairs, as epoll_wait would return them.
fn collect(ep: &std::sync::Arc<spin::Mutex<EpollInstance>>, max: usize) -> Vec<(u32, u64)> {
    epoll_collect_ready(ep, max).into_iter().map(|e| (e.events, e.data)).collect()
}

// ------------------------------------------------------------------ ABI

#[test]
fn struct_layouts_match_linux() {
    assert_eq!(std::mem::size_of::<LinuxEpollEvent>(), 12, "packed on x86-64");
    assert_eq!(std::mem::size_of::<LinuxPollFd>(), 8);
    assert_eq!((EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLRDHUP), (1, 4, 8, 0x10, 0x2000));
    assert_eq!((EPOLLONESHOT, EPOLLET), (1 << 30, 1 << 31));
    assert_eq!((EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD), (1, 2, 3));
}

// ------------------------------------------------------------- epoll_ctl

#[test]
fn ctl_add_mod_del() {
    let ep = EpollInstance::new();
    let mut e = ep.lock();
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 1)), Ok(()));
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 5, ev(EPOLLIN, 1)), Err(EEXIST));
    assert_eq!(e.ctl(EPOLL_CTL_ADD, 6, None), Err(EINVAL), "ADD needs an event");
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 5, ev(EPOLLOUT, 9)), Ok(()));
    assert_eq!((e.watches[&5].events, e.watches[&5].data), (EPOLLOUT, 9));
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 7, ev(EPOLLIN, 0)), Err(ENOENT));
    assert_eq!(e.ctl(EPOLL_CTL_MOD, 5, None), Err(EINVAL));
    assert_eq!(e.ctl(EPOLL_CTL_DEL, 5, None), Ok(()), "DEL ignores the event");
    assert_eq!(e.ctl(EPOLL_CTL_DEL, 5, None), Err(ENOENT));
    assert_eq!(e.ctl(9, 5, ev(EPOLLIN, 0)), Err(EINVAL), "unknown op");
}

// ------------------------------------------------------------- readiness

#[test]
fn edge_triggered_regular_files_fire_once() {
    fake::reset();
    file(20);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 20, ev(EPOLLIN | EPOLLET, 3)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 3)]);
    assert!(collect(&ep, 8).is_empty(), "files never change readiness: one edge");
    ep.lock().ctl(EPOLL_CTL_MOD, 20, ev(EPOLLIN | EPOLLET, 4)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 4)], "MOD re-arms");

    let lt = EpollInstance::new();
    lt.lock().ctl(EPOLL_CTL_ADD, 20, ev(EPOLLIN, 5)).unwrap();
    assert_eq!(collect(&lt, 8).len(), 1);
    assert_eq!(collect(&lt, 8).len(), 1, "level-triggered files: always ready");
}
