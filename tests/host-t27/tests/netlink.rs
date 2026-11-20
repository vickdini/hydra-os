//! Uevent netlink sockets (`src/compat/linux/netlink.rs`): what libudev's monitor does with
//! them (bind, address and option queries, filters) and that they never have a message.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::netlink::socket;
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::Arc;

const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EPROTONOSUPPORT: i64 = -93;
const EAFNOSUPPORT: i64 = -97;
const AF_NETLINK: u64 = 16;
const SOCK_RAW: u64 = 3;
const SOCK_DGRAM: u64 = 2;
const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;
const UEVENT: u64 = 15;

fn dev(fd: i64) -> Arc<dyn CharDevice> {
    match fake::fd::get(fd) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("not a device"),
    }
}

fn call(d: &Arc<dyn CharDevice>, num: u64, a: [u64; 6]) -> i64 {
    d.socket_call(num, a).expect("a socket call")
}

/// `getsockname`/`getpeername` into a `sockaddr_nl`.
fn name(d: &Arc<dyn CharDevice>, num: u64) -> ([u8; 12], u32) {
    let mut sa = [0u8; 12];
    let mut len = 12u32;
    assert_eq!(call(d, num, [0, mptr(&mut sa), mptr(&mut len), 0, 0, 0]), 0);
    (sa, len)
}

#[test]
fn socket_families_and_types() {
    fake::reset();
    assert_eq!(socket([1, SOCK_RAW, UEVENT, 0, 0, 0]), None, "not AF_NETLINK");
    assert_eq!(socket([AF_NETLINK, 1, UEVENT, 0, 0, 0]), Some(EPROTONOSUPPORT), "SOCK_STREAM");
    assert_eq!(socket([AF_NETLINK, SOCK_RAW, 4, 0, 0, 0]), Some(EAFNOSUPPORT), "another family");
    let route = socket([AF_NETLINK, SOCK_DGRAM, 0, 0, 0, 0]).unwrap();
    assert!(route >= 3, "NETLINK_ROUTE goes to rtnetlink");
    assert!(dev(route).path().starts_with("socket:["));
    let fd = socket([AF_NETLINK, SOCK_RAW | NONBLOCK | CLOEXEC, UEVENT, 0, 0, 0]).unwrap();
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    assert!(dev(fd).nonblock());
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(socket([AF_NETLINK, SOCK_RAW, UEVENT, 0, 0, 0]), Some(-24));
}

#[test]
fn bind_and_names() {
    fake::reset();
    fake::IDS.set((44, 40));
    let d = dev(socket([AF_NETLINK, SOCK_RAW, UEVENT, 0, 0, 0]).unwrap());
    // Port 0: the process ID is assigned; groups as asked
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&16u16.to_le_bytes());
    sa[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(call(&d, 49, [0, ptr(&sa), 12, 0, 0, 0]), 0);
    let (me, len) = name(&d, 51);
    assert_eq!(len, 12);
    assert_eq!(u16::from_le_bytes([me[0], me[1]]), 16);
    assert_eq!(u32::from_le_bytes(me[4..8].try_into().unwrap()), 40);
    assert_eq!(u32::from_le_bytes(me[8..12].try_into().unwrap()), 1);
    // An explicit port is kept
    sa[4..8].copy_from_slice(&777u32.to_le_bytes());
    assert_eq!(call(&d, 49, [0, ptr(&sa), 12, 0, 0, 0]), 0);
    assert_eq!(u32::from_le_bytes(name(&d, 51).0[4..8].try_into().unwrap()), 777);
    // The peer is the kernel: port 0
    let (peer, _) = name(&d, 52);
    assert_eq!(peer, { let mut k = [0u8; 12]; k[0] = 16; k });
    // A short buffer gets a prefix, and the full length
    let mut small = [0xffu8; 4];
    let mut len = 4u32;
    assert_eq!(call(&d, 51, [0, mptr(&mut small), mptr(&mut len), 0, 0, 0]), 0);
    assert_eq!((small, len), ([16, 0, 0, 0], 12));
    // No buffer: nothing to do
    assert_eq!(call(&d, 51, [0, 0, 0, 0, 0, 0]), 0);
    // Faults
    let mut bad_len = 12u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(&d, 51, [0, mptr(&mut small), mptr(&mut bad_len), 0, 0, 0]), EFAULT);
    let mut bad_sa = [0u8; 12];
    fake::bad_ptr(mptr(&mut bad_sa), 12);
    let mut len = 12u32;
    assert_eq!(call(&d, 51, [0, mptr(&mut bad_sa), mptr(&mut len), 0, 0, 0]), EFAULT);
    assert_eq!(call(&d, 49, [0, mptr(&mut bad_sa), 12, 0, 0, 0]), EFAULT);
}

#[test]
fn options() {
    fake::reset();
    let d = dev(socket([AF_NETLINK, SOCK_RAW, UEVENT, 0, 0, 0]).unwrap());
    assert_eq!(call(&d, 54, [0, 1, 7, 0, 4, 0]), 0, "setsockopt accepted");
    let get = |level: u64, opt: u64| {
        let mut v = 0xdeadu32;
        let mut len = 0u32;
        assert_eq!(call(&d, 55, [0, level, opt, mptr(&mut v), mptr(&mut len), 0]), 0);
        assert_eq!(len, 4);
        v
    };
    assert_eq!(get(1, 3), 3, "SO_TYPE");
    assert_eq!(get(1, 7), 212_992);
    assert_eq!(get(1, 8), 212_992);
    assert_eq!(get(1, 38), 15, "SO_PROTOCOL");
    assert_eq!(get(1, 39), 16, "SO_DOMAIN");
    assert_eq!(get(270, 1), 0, "anything else");
    let mut v = 0u32;
    fake::bad_ptr(mptr(&mut v), 4);
    let mut len = 4u32;
    assert_eq!(call(&d, 55, [0, 1, 3, mptr(&mut v), mptr(&mut len), 0]), EFAULT);
}

#[test]
fn sends_go_nowhere_and_receives_never_return() {
    fake::reset();
    let d = dev(socket([AF_NETLINK, SOCK_RAW | NONBLOCK, UEVENT, 0, 0, 0]).unwrap());
    assert_eq!(call(&d, 44, [0, 0, 123, 0, 0, 0]), 123, "sendto");
    assert_eq!(call(&d, 46, [0; 6]), 0, "sendmsg");
    assert_eq!(d.write(b"abc"), 3);
    for num in [45, 47, 299] {
        assert_eq!(call(&d, num, [0; 6]), EAGAIN, "call {num}");
    }
    let mut b = [0u8; 8];
    assert_eq!(d.read(&mut b), EAGAIN);
    assert_eq!(call(&d, 48, [0; 6]), 0, "shutdown");
    for num in [42, 43, 50, 288] {
        assert_eq!(call(&d, num, [0; 6]), EINVAL, "connect/accept/listen");
    }
    assert_eq!(d.socket_call(1, [0; 6]), None);
    assert_eq!(d.poll_events(), 4, "always writable, never readable");
    let mut w = WaitSet::new();
    d.add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 0);
    assert_eq!(d.rdev(), 0);
    assert!(d.path().starts_with("socket:["));
    // Blocking: only a signal ends the wait
    d.set_nonblock(false);
    assert!(!d.nonblock());
    assert!(blocks(|| d.read(&mut b)));
    fake::on_wait(|_| fake::SIGNAL_PENDING.set(true));
    assert_eq!(call(&d, 45, [0; 6]), -512);
}
