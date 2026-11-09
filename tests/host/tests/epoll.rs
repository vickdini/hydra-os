//! Tests for epoll's interest list and readiness collection
//! (`src/compat/linux/epoll.rs`): EPOLL_CTL_ADD/MOD/DEL, level-triggered
//! reporting, EPOLLONESHOT, EPOLLET on regular files, maxevents, and what
//! happens when a watched descriptor is closed.
//!
//! Readiness comes from real kernel objects (eventfd counters, message
//! queues) through the fake descriptor table's `readiness`.

use hydra_hosttests::compat::linux::epoll::*;
use hydra_hosttests::compat::linux::eventfd::EventFd;
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const EEXIST: i64 = -17;
const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

fn ev(events: u32, data: u64) -> Option<LinuxEpollEvent> {
    Some(LinuxEpollEvent { events, data })
}

/// Install an eventfd with the given counter at `fd`.
fn eventfd(fd: usize, counter: u64) -> std::sync::Arc<spin::Mutex<EventFd>> {
    let e = EventFd::new(0, 0);
    e.lock().counter = counter;
    fake::FDS.with_borrow_mut(|f| f.install(fd, FileDescriptor::EventFd(e.clone())));
    e
}

fn file(fd: usize) {
    fake::FDS.with_borrow_mut(|f| f.install(fd, FileDescriptor::File { path: "/etc/hosts".into(), readable: true }));
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
fn level_triggered_reporting() {
    fake::reset();
    let efd = eventfd(10, 0);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN, 0xAA)).unwrap();
    assert!(collect(&ep, 8).is_empty(), "counter 0: not readable");
    efd.lock().counter = 3;
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 0xAA)]);
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 0xAA)], "level-triggered: reported until drained");
    efd.lock().counter = 0;
    assert!(collect(&ep, 8).is_empty());
}

#[test]
fn only_requested_events_plus_err_and_hup() {
    fake::reset();
    eventfd(10, 1); // readable and writable
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLOUT, 1)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLOUT, 1)], "EPOLLIN not requested, not reported");
    ep.lock().ctl(EPOLL_CTL_MOD, 10, ev(EPOLLIN | EPOLLOUT, 2)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN | EPOLLOUT, 2)]);
}

#[test]
fn maxevents_limits_the_batch() {
    fake::reset();
    let ep = EpollInstance::new();
    for fd in 10..15 {
        eventfd(fd, 1);
        ep.lock().ctl(EPOLL_CTL_ADD, fd as i32, ev(EPOLLIN, fd as u64)).unwrap();
    }
    assert_eq!(collect(&ep, 2), vec![(EPOLLIN, 10), (EPOLLIN, 11)]);
    assert_eq!(collect(&ep, 64).len(), 5);
}

#[test]
fn oneshot_fires_once_until_rearmed() {
    fake::reset();
    eventfd(10, 1);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN | EPOLLONESHOT, 7)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 7)]);
    assert!(collect(&ep, 8).is_empty(), "disabled after firing");
    assert!(ep.lock().watches.contains_key(&10), "but still registered (MOD re-arms, ADD gives EEXIST)");
    assert_eq!(ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN, 7)), Err(EEXIST));
    ep.lock().ctl(EPOLL_CTL_MOD, 10, ev(EPOLLIN | EPOLLONESHOT, 8)).unwrap();
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 8)]);
}

#[test]
fn oneshot_without_a_match_stays_armed() {
    fake::reset();
    let efd = eventfd(10, 0);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN | EPOLLONESHOT, 1)).unwrap();
    assert!(collect(&ep, 8).is_empty());
    efd.lock().counter = 1;
    assert_eq!(collect(&ep, 8), vec![(EPOLLIN, 1)], "fires on the first real event");
}

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

#[test]
fn edge_triggered_other_descriptors_behave_level_triggered() {
    // Documented approximation in epoll.rs: EPOLLET is only emulated for regular files.
    // Programs that read until EAGAIN (the usual EPOLLET pattern) are unaffected; they
    // just may be woken again while data remains.
    fake::reset();
    eventfd(10, 1);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN | EPOLLET, 1)).unwrap();
    assert_eq!(collect(&ep, 8).len(), 1);
    assert_eq!(collect(&ep, 8).len(), 1);
}

#[test]
fn wait_set_covers_watched_descriptors() {
    fake::reset();
    eventfd(10, 0);
    file(11);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN, 0)).unwrap();
    ep.lock().ctl(EPOLL_CTL_ADD, 11, ev(EPOLLIN, 0)).unwrap();
    ep.lock().ctl(EPOLL_CTL_ADD, 12, ev(EPOLLIN, 0)).unwrap(); // not open
    let _waits = epoll_wait_set(&ep); // registers queues of open descriptors only
}

#[test]
#[ignore = "BUG: closing a watched descriptor does not remove it from epoll interest lists \
            (watches are keyed by fd number only). The closed fd is then reported as \
            EPOLLHUP|EPOLLERR on every wait, forever, and if the number is reused the old watch \
            reports the new file's events with the old `data` (often a freed pointer in \
            libuv/tokio). Linux drops the watch when the file is closed \
            (src/compat/linux/epoll.rs, epoll_collect_ready; no cleanup on close in fs/fd.rs)"]
fn closing_a_descriptor_removes_its_watch() {
    fake::reset();
    eventfd(10, 0);
    let ep = EpollInstance::new();
    ep.lock().ctl(EPOLL_CTL_ADD, 10, ev(EPOLLIN, 0xDEAD)).unwrap();
    fake::FDS.with_borrow_mut(|f| f.close(10));
    assert!(collect(&ep, 8).is_empty(), "closed fd still reported: {:?}", collect(&ep, 8));
    eventfd(10, 1); // the number is reused by an unrelated, readable eventfd
    assert!(collect(&ep, 8).is_empty(), "new file reported under the old watch: {:?}", collect(&ep, 8));
}
