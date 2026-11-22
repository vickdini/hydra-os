//! Uevent netlink sockets (`src/compat/linux/netlink.rs`): what libudev's monitor does with
//! them (bind, address and option queries, filters), and the device announcements queued on
//! them (wave 8, Group H: `uevent_all`, group filter, sender address, credentials).

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::netlink::{socket, uevent_all};
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::{Arc, Mutex};

/// The announcement tests share the kernel's list of uevent sockets: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

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
fn sends_go_nowhere_and_empty_receives() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    let d = dev(socket([AF_NETLINK, SOCK_RAW | NONBLOCK, UEVENT, 0, 0, 0]).unwrap());
    assert_eq!(call(&d, 44, [0, 0, 123, 0, 0, 0]), 123, "sendto");
    assert_eq!(call(&d, 46, [0; 6]), 0, "sendmsg");
    assert_eq!(d.write(b"abc"), 3);
    assert_eq!(call(&d, 45, [0; 6]), EAGAIN, "recvfrom");
    // recvmsg / recvmmsg read their message header first
    assert_eq!(call(&d, 47, [0; 6]), EFAULT);
    assert_eq!(call(&d, 299, [0; 6]), EFAULT);
    let (mut msg, _iov, _buf, _name, _ctl) = msghdr(64);
    assert_eq!(call(&d, 47, [0, msg.as_mut_ptr() as u64, 0, 0, 0, 0]), EAGAIN);
    let mut b = [0u8; 8];
    assert_eq!(d.read(&mut b), EAGAIN);
    assert_eq!(call(&d, 48, [0; 6]), 0, "shutdown");
    for num in [42, 43, 50, 288] {
        assert_eq!(call(&d, num, [0; 6]), EINVAL, "connect/accept/listen");
    }
    assert_eq!(d.socket_call(1, [0; 6]), None);
    assert_eq!(d.poll_events(), 4, "writable, not readable while empty");
    let mut w = WaitSet::new();
    d.add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 1, "woken by announcements");
    assert_eq!(d.rdev(), 0);
    assert!(d.path().starts_with("socket:["));
    // Blocking: waits for a message or a signal
    d.set_nonblock(false);
    assert!(!d.nonblock());
    assert!(blocks(|| d.read(&mut b)));
    fake::on_wait(|_| fake::SIGNAL_PENDING.set(true));
    assert_eq!(call(&d, 45, [0; 6]), -512);
}

/// A `struct msghdr` with one iovec of `cap` bytes, a name and a 64-byte control buffer.
#[allow(clippy::type_complexity)]
fn msghdr(cap: usize) -> (Box<[u8; 56]>, Box<[u8; 16]>, Box<Vec<u8>>, Box<[u8; 12]>, Box<[u8; 64]>) {
    let mut buf = Box::new(vec![0u8; cap]);
    let mut iov = Box::new([0u8; 16]);
    iov[0..8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_le_bytes());
    iov[8..16].copy_from_slice(&(cap as u64).to_le_bytes());
    let mut name = Box::new([0u8; 12]);
    let mut ctl = Box::new([0u8; 64]);
    let mut msg = Box::new([0u8; 56]);
    msg[0..8].copy_from_slice(&(name.as_mut_ptr() as u64).to_le_bytes());
    msg[8..12].copy_from_slice(&12u32.to_le_bytes());
    msg[16..24].copy_from_slice(&(iov.as_mut_ptr() as u64).to_le_bytes());
    msg[24..32].copy_from_slice(&1u64.to_le_bytes());
    msg[32..40].copy_from_slice(&(ctl.as_mut_ptr() as u64).to_le_bytes());
    msg[40..48].copy_from_slice(&64u64.to_le_bytes());
    (msg, iov, buf, name, ctl)
}

fn bound(groups: u32) -> Arc<dyn CharDevice> {
    let d = dev(socket([AF_NETLINK, SOCK_RAW | NONBLOCK, UEVENT, 0, 0, 0]).unwrap());
    let mut sa = [0u8; 12];
    sa[0..2].copy_from_slice(&16u16.to_le_bytes());
    sa[8..12].copy_from_slice(&groups.to_le_bytes());
    assert_eq!(call(&d, 49, [0, ptr(&sa), 12, 0, 0, 0]), 0);
    d
}

#[test]
fn announcements_go_to_their_group() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    let k = bound(1);
    let u = bound(2);
    let none = bound(0);
    let both = bound(3);
    let msgs = vec![(1u32, b"add@/x ACTION=add ".to_vec()), (2u32, b"libudev udev".to_vec()), (0u32, b"never".to_vec()), (40u32, b"never".to_vec())];
    assert!(uevent_all(&msgs) >= 3, "the three bound sockets");
    assert_eq!(none.poll_events(), 4);
    assert_eq!(k.poll_events(), 5, "readable");
    // recvfrom: the kernel's message, sender = the kernel with nl_groups 1
    let mut b = [0u8; 64];
    let mut sa = [0u8; 12];
    let mut len = 12u32;
    let n = call(&k, 45, [0, mptr(&mut b), 64, 0, mptr(&mut sa), mptr(&mut len)]);
    assert_eq!(&b[..n as usize], b"add@/x ACTION=add ");
    assert_eq!(u32::from_le_bytes(sa[8..12].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(sa[4..8].try_into().unwrap()), 0, "port 0: the kernel");
    assert_eq!(call(&k, 45, [0, mptr(&mut b), 64, 0, 0, 0]), EAGAIN, "only group 1's");
    // recvmsg: udev's message with the group-2 address and SCM_CREDENTIALS uid 0
    let (mut msg, _iov, buf, name, ctl) = msghdr(64);
    let n = call(&u, 47, [0, msg.as_mut_ptr() as u64, 0, 0, 0, 0]);
    assert_eq!(&buf[..n as usize], b"libudev udev");
    assert_eq!(u32::from_le_bytes(name[8..12].try_into().unwrap()), 2);
    assert_eq!(u64::from_le_bytes(msg[40..48].try_into().unwrap()), 32, "controllen");
    assert_eq!(u64::from_le_bytes(ctl[0..8].try_into().unwrap()), 28);
    assert_eq!(i32::from_le_bytes(ctl[8..12].try_into().unwrap()), 1, "SOL_SOCKET");
    assert_eq!(i32::from_le_bytes(ctl[12..16].try_into().unwrap()), 2, "SCM_CREDENTIALS");
    assert_eq!(&ctl[16..28], &[0u8; 12], "pid, uid, gid 0");
    // both groups: two messages, in order; peek leaves one
    let n = call(&both, 45, [0, mptr(&mut b), 64, 2, 0, 0]);
    assert_eq!(n, 18, "MSG_PEEK");
    assert_eq!(call(&both, 45, [0, 0, 0, 2 | 0x20, 0, 0]), 18, "the size, no buffer (MSG_PEEK | MSG_TRUNC)");
    let mut r = [0u8; 4];
    assert_eq!(both.read(&mut r), 4, "read: truncated to the buffer");
    assert_eq!(call(&both, 45, [0, mptr(&mut b), 4, 0x20, 0, 0]), 12, "MSG_TRUNC: the real length");
    assert_eq!(both.poll_events(), 4);
}

#[test]
fn recvmmsg_and_short_control() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    let u = bound(2);
    uevent_all(&[(2, vec![7u8; 100])]);
    // recvmmsg: one message, its length after the header
    let mut mm = [0u8; 64];
    let (msg, _iov, buf, _name, _ctl) = msghdr(40);
    mm[..56].copy_from_slice(&msg[..]);
    assert_eq!(call(&u, 299, [0, mptr(&mut mm), 1, 0, 0, 0]), 1);
    assert_eq!(u32::from_le_bytes(mm[56..60].try_into().unwrap()), 40);
    assert_eq!(&buf[..], &[7u8; 40][..]);
    assert_eq!(u32::from_le_bytes(mm[48..52].try_into().unwrap()), 0x20, "MSG_TRUNC in msg_flags");
    // a control buffer too small for the credentials: none given
    uevent_all(&[(2, vec![1u8; 4])]);
    let (mut msg, _iov, _buf, _name, _ctl) = msghdr(8);
    msg[40..48].copy_from_slice(&16u64.to_le_bytes());
    assert_eq!(call(&u, 47, [0, msg.as_mut_ptr() as u64, 0, 0, 0, 0]), 4);
    assert_eq!(u64::from_le_bytes(msg[40..48].try_into().unwrap()), 0);
}

#[test]
fn queue_is_capped_and_closed_sockets_forgotten() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    let u = bound(2);
    let msgs: Vec<(u32, Vec<u8>)> = (0..300u32).map(|i| (2, i.to_le_bytes().to_vec())).collect();
    uevent_all(&msgs);
    let mut b = [0u8; 4];
    assert_eq!(u.read(&mut b), 4);
    assert_eq!(u32::from_le_bytes(b), 44, "the oldest 44 dropped (256 kept)");
    let mut n = 1;
    while u.read(&mut b) > 0 {
        n += 1;
    }
    assert_eq!(n, 256);
    drop(u);
    fake::reset();
    assert_eq!(uevent_all(&[(2, vec![1])]), 0, "no socket left");
}
