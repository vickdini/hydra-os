//! Unix domain sockets (`src/compat/linux/unix.rs`): socket pairs and named sockets
//! (abstract and file-system names), the stream and record queues with their buffer limit,
//! descriptor passing and credentials, shutdown and hang-up, options, ioctls, the kernel's
//! own listening sockets and the forwarding of linux-server's sockets.
//!
//! Names are global: each test uses its own. `/proc/net/unix` briefly holds every socket,
//! so the tests that read it and those that rely on a close taking effect at once hold
//! `serial()`.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::chardev::CharDevice;
use hydra_hosttests_t27::compat::linux::unix::{self, dispatch, UnixSocket};
use hydra_hosttests_t27::fake::vfs::{NO_ACCESS, PATHS, SOCKET_NODES, UNLINKED};
use hydra_hosttests_t27::fs::pipe::PipeBuffer;
use hydra_hosttests_t27::fs::FileDescriptor;
use hydra_hosttests_t27::lx::obj::ServerObject;
use hydra_hosttests_t27::task::wait::WaitSet;
use std::sync::Arc;

const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;
const EPIPE: i64 = -32;
const ENODATA: i64 = -61;
const EMSGSIZE: i64 = -90;
const EPROTOTYPE: i64 = -91;
const ENOPROTOOPT: i64 = -92;
const EPROTONOSUPPORT: i64 = -93;
const EOPNOTSUPP: i64 = -95;
const EADDRINUSE: i64 = -98;
const EISCONN: i64 = -106;
const ENOTCONN: i64 = -107;
const ETOOMANYREFS: i64 = -109;
const ECONNREFUSED: i64 = -111;
const ERESTARTSYS: i64 = -512;

const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const SEQPACKET: u64 = 5;
const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;
const MSG_PEEK: u64 = 2;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const MSG_CTRUNC: i32 = 8;
const MSG_TRUNC: i32 = 0x20;
const LIMIT: usize = 212_992;

fn call(num: u64, a: [u64; 6]) -> i64 {
    dispatch(num, a).expect("an AF_UNIX call")
}

fn socket(ty: u64) -> u64 {
    let fd = call(41, [1, ty, 0, 0, 0, 0]);
    assert!(fd >= 3, "socket: {fd}");
    fd as u64
}

fn pair(ty: u64) -> (u64, u64) {
    let mut sv = [0i32; 2];
    assert_eq!(call(53, [1, ty, 0, mptr(&mut sv), 0, 0]), 0);
    (sv[0] as u64, sv[1] as u64)
}

fn obj(fd: u64) -> Arc<UnixSocket> {
    match fake::fd::get(fd as i64) {
        Some(FileDescriptor::Unix(s)) => s,
        _ => panic!("not a unix socket"),
    }
}

fn close(fd: u64) {
    fake::fd::FDS.with_borrow_mut(|f| f.close(fd as usize).unwrap());
}

/// A `sockaddr_un` with a path.
fn path_addr(p: &str) -> Vec<u8> {
    let mut b = 1u16.to_le_bytes().to_vec();
    b.extend_from_slice(p.as_bytes());
    b.push(0);
    b
}

/// A `sockaddr_un` with an abstract name.
fn abs_addr(n: &str) -> Vec<u8> {
    let mut b = 1u16.to_le_bytes().to_vec();
    b.push(0);
    b.extend_from_slice(n.as_bytes());
    b
}

fn bind(fd: u64, sa: &[u8]) -> i64 {
    call(49, [fd, sa.as_ptr() as u64, sa.len() as u64, 0, 0, 0])
}

fn connect(fd: u64, sa: &[u8]) -> i64 {
    call(42, [fd, sa.as_ptr() as u64, sa.len() as u64, 0, 0, 0])
}

fn send(fd: u64, data: &[u8], flags: u64) -> i64 {
    call(44, [fd, data.as_ptr() as u64, data.len() as u64, flags, 0, 0])
}

fn recv(fd: u64, buf: &mut [u8], flags: u64) -> i64 {
    call(45, [fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags, 0, 0])
}

fn name(num: u64, fd: u64) -> Result<Vec<u8>, i64> {
    let mut sa = [0u8; 110];
    let mut len = 110u32;
    let r = call(num, [fd, mptr(&mut sa), mptr(&mut len), 0, 0, 0]);
    if r < 0 {
        Err(r)
    } else {
        Ok(sa[..len as usize].to_vec())
    }
}

fn getsockopt(fd: u64, level: u64, opt: u64) -> Result<Vec<u8>, i64> {
    let mut v = [0u8; 32];
    let mut len = 32u32;
    let r = call(55, [fd, level, opt, mptr(&mut v), mptr(&mut len), 0]);
    if r < 0 {
        Err(r)
    } else {
        Ok(v[..len as usize].to_vec())
    }
}

fn setsockopt(fd: u64, level: u64, opt: u64, val: &[u8]) -> i64 {
    call(54, [fd, level, opt, val.as_ptr() as u64, val.len() as u64, 0])
}

fn int(v: i32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

#[repr(C)]
#[derive(Default)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _pad: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad2: u32,
}

/// Sends `data` with descriptors `fds` attached (`SCM_RIGHTS`).
fn send_fds(fd: u64, data: &[u8], fds: &[i32], flags: u64) -> i64 {
    let iov = [(data.as_ptr() as u64, data.len() as u64)];
    let mut cm = Vec::new();
    if !fds.is_empty() {
        cm.extend_from_slice(&((16 + 4 * fds.len()) as u64).to_le_bytes());
        cm.extend_from_slice(&1i32.to_le_bytes());
        cm.extend_from_slice(&1i32.to_le_bytes());
        for f in fds {
            cm.extend_from_slice(&f.to_le_bytes());
        }
        cm.resize((cm.len() + 7) & !7, 0);
    }
    let msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: cm.as_ptr() as u64, controllen: cm.len() as u64, ..Default::default() };
    call(46, [fd, ptr(&msg), flags, 0, 0, 0])
}

/// Receives into `buf` with a control buffer of `cap` bytes: (result, control bytes, msg_flags).
fn recv_msg(fd: u64, buf: &mut [u8], cap: usize, flags: u64) -> (i64, Vec<u8>, i32) {
    let iov = [(buf.as_mut_ptr() as u64, buf.len() as u64)];
    let mut control = vec![0u8; cap];
    let mut msg = MsgHdr { namelen: 99, iov: ptr(&iov), iovlen: 1, control: control.as_mut_ptr() as u64, controllen: cap as u64, ..Default::default() };
    let r = call(47, [fd, mptr(&mut msg), flags, 0, 0, 0]);
    if r >= 0 {
        assert_eq!(msg.namelen, 0);
    }
    control.truncate(msg.controllen as usize);
    (r, control, msg.flags)
}

/// The control messages in `c`: (level, type, data).
fn cmsgs(c: &[u8]) -> Vec<(i32, i32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 16 <= c.len() {
        let len = u64::from_le_bytes(c[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(c[off + 8..off + 12].try_into().unwrap());
        let ty = i32::from_le_bytes(c[off + 12..off + 16].try_into().unwrap());
        out.push((level, ty, c[off + 16..off + len].to_vec()));
        off += (len + 7) & !7;
    }
    out
}

fn fds_in(data: &[u8]) -> Vec<i32> {
    data.chunks_exact(4).map(|c| i32::from_le_bytes(c.try_into().unwrap())).collect()
}

// ------------------------------------------------------------------ creation

#[test]
fn socket_and_socketpair() {
    fake::reset();
    assert_eq!(dispatch(41, [2, STREAM, 0, 0, 0, 0]), None, "AF_INET is not ours");
    assert_eq!(dispatch(53, [2, STREAM, 0, 0, 0, 0]), None);
    assert_eq!(dispatch(1, [3, 0, 0, 0, 0, 0]), None, "not a socket call");
    assert_eq!(dispatch(42, [3, 0, 0, 0, 0, 0]), None, "not a unix descriptor");
    assert_eq!(call(41, [1, STREAM, 2, 0, 0, 0]), EPROTONOSUPPORT);
    assert_eq!(call(41, [1, 3, 0, 0, 0, 0]), EPROTONOSUPPORT, "SOCK_RAW");
    let mut sv = [0i32; 2];
    assert_eq!(call(53, [1, 3, 0, mptr(&mut sv), 0, 0]), EPROTONOSUPPORT);
    for ty in [STREAM, DGRAM, SEQPACKET] {
        let fd = socket(ty);
        assert_eq!(getsockopt(fd, 1, 3).unwrap(), int(ty as i32), "SO_TYPE");
    }
    let fd = socket(STREAM | NONBLOCK | CLOEXEC);
    assert!(obj(fd).get_nonblock());
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(fd as usize)));
    assert!(obj(fd).ino() >= 0x5000_0000);
    let (a, b) = pair(STREAM | NONBLOCK | CLOEXEC);
    assert!(obj(a).get_nonblock() && obj(b).get_nonblock());
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(a as usize) && f.cloexec(b as usize)));
    // The two ends' credentials: ours
    fake::IDS.set((9, 8));
    fake::CREDS.set((1000, 100));
    let (c, _) = pair(STREAM);
    assert_eq!(getsockopt(c, 1, 17).unwrap(), [8u32, 1000, 100].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    // Faults and full tables
    let mut bad = [0i32; 2];
    fake::bad_ptr(mptr(&mut bad), 8);
    assert_eq!(call(53, [1, STREAM, 0, mptr(&mut bad), 0, 0]), EFAULT);
}

#[test]
fn full_descriptor_tables() {
    fake::reset();
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(call(41, [1, STREAM, 0, 0, 0, 0]), EMFILE);
    let mut sv = [0i32; 2];
    assert_eq!(call(53, [1, STREAM, 0, mptr(&mut sv), 0, 0]), EMFILE);
    fake::fd::FDS.with_borrow_mut(|f| f.limit = 4);
    assert_eq!(call(53, [1, STREAM, 0, mptr(&mut sv), 0, 0]), EMFILE, "room for one end only");
    assert!(fake::fd::get(3).is_none(), "the first end was closed again");
}

// ------------------------------------------------------------------ I/O

#[test]
fn stream_bytes_both_ways() {
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    assert_eq!(obj(a).poll_events(), 4, "writable");
    assert_eq!(send(a, b"hello ", 0), 6);
    assert_eq!(obj(a).write(b"world"), 5);
    assert_eq!(obj(b).poll_events(), 5);
    assert_eq!(obj(b).pending_bytes(), 11);
    let mut buf = [0u8; 8];
    assert_eq!(recv(b, &mut buf, MSG_PEEK), 8);
    assert_eq!(&buf, b"hello wo");
    assert_eq!(obj(b).pending_bytes(), 11, "a peek leaves them");
    // recvfrom: the address length is 0 (connected)
    let mut alen = 77u32;
    assert_eq!(call(45, [b, buf.as_mut_ptr() as u64, 3, 0, 0, mptr(&mut alen)]), 3);
    assert_eq!((&buf[..3], alen), (&b"hel"[..], 0));
    assert_eq!(obj(b).read(&mut buf), 8);
    assert_eq!(&buf, b"lo world");
    assert_eq!(recv(b, &mut buf, 0), EAGAIN);
    assert_eq!(obj(b).read(&mut buf), EAGAIN);
    assert_eq!(recv(a, &mut buf, MSG_DONTWAIT), EAGAIN);
    // Faults
    let mut bad = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad), 4);
    assert_eq!(send(a, &bad, 0), EFAULT);
    send(a, b"x", 0);
    assert_eq!(call(45, [b, mptr(&mut bad), 4, 0, 0, 0]), EFAULT);
    // An unconnected socket
    let u = socket(STREAM);
    assert_eq!(obj(u).poll_events(), 0x4 | 0x10);
    assert_eq!(obj(u).write(b"x"), ENOTCONN);
    assert_eq!(obj(u).read(&mut buf), ENOTCONN);
    assert_eq!(obj(u).pending_bytes(), 0);
    let mut w = WaitSet::new();
    obj(u).add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 1);
    let mut w = WaitSet::new();
    obj(a).add_wait_queues(&mut w);
    assert_eq!(w.queue_count(), 2, "its own queue and the connection's");
}

#[test]
fn records_keep_their_boundaries() {
    fake::reset();
    let (a, b) = pair(SEQPACKET | NONBLOCK);
    assert_eq!(send(a, b"first", 0), 5);
    assert_eq!(send(a, b"second!", 0), 7);
    assert_eq!(obj(b).pending_bytes(), 5, "the next record's size");
    let mut small = [0u8; 3];
    let (n, _, flags) = recv_msg(b, &mut small, 0, MSG_PEEK);
    assert_eq!((n, flags), (3, MSG_TRUNC));
    let (n, _, flags) = recv_msg(b, &mut small, 0, 0);
    assert_eq!((n, flags, &small), (3, MSG_TRUNC, b"fir"), "the rest of the record is gone");
    let mut buf = [0u8; 16];
    assert_eq!(recv(b, &mut buf, 0), 7);
    assert_eq!(&buf[..7], b"second!");
    // Too big for the buffer: EMSGSIZE
    let huge = vec![0u8; LIMIT + 1];
    assert_eq!(send(a, &huge, 0), EMSGSIZE);
    // A record that does not fit waits for room (an empty queue takes any record)
    let big = vec![1u8; LIMIT - 10];
    assert_eq!(send(a, &big, 0), (LIMIT - 10) as i64);
    assert_eq!(send(a, &[0u8; 20], 0), EAGAIN);
    assert_eq!(obj(a).poll_events() & 4, 4, "below the limit: still writable");
    // Datagram pairs are records too
    let (x, y) = pair(DGRAM | NONBLOCK);
    send(x, b"d1", 0);
    send(x, b"d22", 0);
    assert_eq!(recv(y, &mut buf, 0), 2);
    assert_eq!(recv(y, &mut buf, 0), 3);
}

#[test]
fn the_stream_buffer_limit() {
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    let big = vec![7u8; LIMIT + 100];
    assert_eq!(send(a, &big, 0), LIMIT as i64, "what fits");
    assert_eq!(obj(a).poll_events() & 4, 0, "full: not writable");
    assert_eq!(send(a, b"x", 0), EAGAIN);
    // SIOCOUTQ / FIONREAD
    let mut n = 0i32;
    assert_eq!(unix::ioctl(&obj(a), 0x5411, mptr(&mut n)), 0);
    assert_eq!(n, LIMIT as i32);
    assert_eq!(unix::ioctl(&obj(b), 0x541B, mptr(&mut n)), 0);
    assert_eq!(n, LIMIT as i32);
    // A blocking writer waits for the reader
    obj(a).set_nonblock(false);
    let rb = obj(b);
    fake::on_wait(move |_| {
        let mut sink = vec![0u8; 1000];
        rb.read(&mut sink);
    });
    assert_eq!(obj(a).write(&[1u8; 500]), 500);
    assert_eq!(fake::WAITS.get(), 1);
    // Interrupted: what was sent so far, or a restart
    fake::WAIT_HOOK.with_borrow_mut(|h| *h = None);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(obj(a).write(&[1u8; 600]), 500, "500 fitted before the signal");
    assert_eq!(obj(a).write(&[1u8; 10]), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    assert!(blocks(|| obj(a).write(&[1u8; 10])));
}

#[test]
fn a_peer_closing_during_a_send() {
    fake::reset();
    let (a, b) = pair(STREAM);
    let mut _peer = Some(obj(b));
    close(b);
    fake::on_wait(move |_| {
        _peer = None; // the reader goes away while the writer waits for room
    });
    let big = vec![3u8; LIMIT + 100];
    assert_eq!(obj(a).write(&big), LIMIT as i64, "what was queued before it went");
    assert!(obj(a).kernel_accept().is_none(), "not a listener");
}

#[test]
fn bad_addresses_and_short_data() {
    fake::reset();
    let s = socket(STREAM);
    assert_eq!(bind(s, &[1u8]), EINVAL, "too short to bind");
    assert_eq!(call(49, [s, 0, 10, 0, 0, 0]), EFAULT);
    let (a, b) = pair(STREAM | NONBLOCK);
    let mut sa = [0u8; 16];
    let mut bad_len = 16u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(52, [a, mptr(&mut sa), mptr(&mut bad_len), 0, 0, 0]), EFAULT);
    // Fewer bytes than the iovecs hold: the later ones stay untouched
    send(a, b"abc", 0);
    let (mut x, mut y, mut z) = ([0u8; 4], [9u8; 4], [9u8; 4]);
    let iov = [(mptr(&mut x), 4u64), (mptr(&mut y), 4u64), (mptr(&mut z), 4u64)];
    let mut msg = MsgHdr { iov: ptr(&iov), iovlen: 3, ..Default::default() };
    assert_eq!(call(47, [b, mptr(&mut msg), 0, 0, 0, 0]), 3);
    assert_eq!((&x[..3], y, z), (&b"abc"[..], [9; 4], [9; 4]));
}

#[test]
fn blocking_receive() {
    fake::reset();
    let (a, b) = pair(STREAM);
    let wa = obj(a);
    fake::on_wait(move |_| {
        wa.write(b"late");
    });
    let mut buf = [0u8; 8];
    assert_eq!(obj(b).read(&mut buf), 4);
    fake::reset();
    let (_a, b) = pair(STREAM);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(obj(b).read(&mut buf), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    assert!(blocks(|| obj(b).read(&mut buf)));
}

#[test]
fn closing_and_shutting_down() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    fake::IDS.set((4, 3));
    let (a, b) = pair(STREAM | NONBLOCK);
    send(a, b"bye", 0);
    close(a);
    let mut buf = [0u8; 8];
    assert_eq!(obj(b).poll_events(), 0x1 | 0x10 | 0x2000, "data, end of file, hang-up");
    assert_eq!(recv(b, &mut buf, 0), 3, "the data first");
    assert_eq!(recv(b, &mut buf, 0), 0, "then end of file");
    assert_eq!(send(b, b"x", 0), EPIPE);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.clone()), vec![(3, 4, 13)], "SIGPIPE");
    assert_eq!(send(b, b"x", MSG_NOSIGNAL), EPIPE);
    assert_eq!(fake::proc::POSTED.with_borrow(|p| p.len()), 1);
    // shutdown
    let u = socket(STREAM);
    assert_eq!(call(48, [u, 2, 0, 0, 0, 0]), ENOTCONN);
    let (c, d) = pair(STREAM | NONBLOCK);
    assert_eq!(call(48, [c, 3, 0, 0, 0, 0]), EINVAL);
    assert_eq!(call(48, [c, 1, 0, 0, 0, 0]), 0, "SHUT_WR");
    assert_eq!(recv(d, &mut buf, 0), 0, "the peer sees end of file");
    assert_eq!(obj(d).poll_events() & 0x2001, 0x2001);
    assert_eq!(send(c, b"x", MSG_NOSIGNAL), EPIPE);
    assert_eq!(send(d, b"to c", 0), 4, "the other direction still works");
    assert_eq!(call(48, [c, 0, 0, 0, 0, 0]), 0, "SHUT_RD");
    assert_eq!(recv(c, &mut buf, 0), 0, "reads end");
    assert_eq!(obj(c).poll_events() & 1, 1);
}

#[test]
fn ioctls() {
    fake::reset();
    let (a, _b) = pair(STREAM);
    let on = 1u32;
    assert_eq!(unix::ioctl(&obj(a), 0x5421, ptr(&on)), 0, "FIONBIO");
    assert!(obj(a).get_nonblock());
    let off = 0u32;
    assert_eq!(unix::ioctl(&obj(a), 0x5421, ptr(&off)), 0);
    assert!(!obj(a).get_nonblock());
    assert_eq!(unix::ioctl(&obj(a), 0x5401, 0), ENOTTY);
    assert_eq!(unix::ioctl(&obj(a), 0x8901, 0), EINVAL);
    let mut bad = 0u32;
    fake::bad_ptr(mptr(&mut bad), 4);
    for req in [0x5421, 0x541B, 0x5411] {
        assert_eq!(unix::ioctl(&obj(a), req, mptr(&mut bad)), EFAULT);
    }
    let u = socket(STREAM);
    let mut n = 5i32;
    assert_eq!(unix::ioctl(&obj(u), 0x5411, mptr(&mut n)), 0);
    assert_eq!(n, 0);
}

// ------------------------------------------------------------------ names

#[test]
fn abstract_names_listen_connect_accept() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    fake::IDS.set((21, 20));
    fake::CREDS.set((500, 50));
    let l = socket(STREAM);
    let name = abs_addr("t27-abs-main");
    assert_eq!(call(50, [l, 5, 0, 0, 0, 0]), EINVAL, "autobind is not supported");
    assert_eq!(bind(l, &name), 0);
    assert_eq!(bind(l, &abs_addr("t27-abs-other")), EINVAL, "already bound");
    let l2 = socket(STREAM);
    assert_eq!(bind(l2, &name), EADDRINUSE);
    assert_eq!(connect(l2, &name), ECONNREFUSED, "bound but not listening");
    assert_eq!(call(50, [l, 5, 0, 0, 0, 0]), 0);
    assert_eq!(call(50, [l, 9, 0, 0, 0, 0]), 0, "again: a new backlog");
    assert_eq!(getsockopt(l, 1, 30).unwrap(), int(1), "SO_ACCEPTCONN");
    assert_eq!(getsockopt(l, 1, 17).unwrap(), [20u32, 500, 50].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(), "a listener's SO_PEERCRED: its own");
    assert_eq!(name_of(l), name);
    obj(l).set_nonblock(true);
    assert_eq!(call(43, [l, 0, 0, 0, 0, 0]), EAGAIN);
    assert_eq!(obj(l).poll_events(), 0);
    // A client (bound itself, so the server sees its name)
    fake::IDS.set((31, 30));
    fake::CREDS.set((600, 60));
    let c = socket(STREAM);
    let cname = abs_addr("t27-abs-client");
    assert_eq!(bind(c, &cname), 0);
    assert_eq!(connect(c, &name), 0);
    assert_eq!(connect(c, &name), EISCONN);
    assert_eq!(call(50, [c, 1, 0, 0, 0, 0]), EINVAL, "connected");
    assert_eq!(obj(l).poll_events(), 1, "a connection waits");
    assert_eq!(getsockopt(c, 1, 17).unwrap(), [20u32, 500, 50].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(), "the listener's credentials");
    let mut sa = [0u8; 110];
    let mut len = 110u32;
    let s = call(288, [l, mptr(&mut sa), mptr(&mut len), NONBLOCK | CLOEXEC, 0, 0]);
    assert!(s >= 3);
    let s = s as u64;
    assert_eq!(&sa[..len as usize], &cname[..], "the client's name");
    assert!(obj(s).get_nonblock());
    assert!(fake::fd::FDS.with_borrow(|f| f.cloexec(s as usize)));
    assert_eq!(getsockopt(s, 1, 17).unwrap(), [30u32, 600, 60].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>(), "the client's credentials");
    assert_eq!(name_of(s), name, "the server end has the listener's name");
    assert_eq!(peer_of(s), Ok(cname.clone()));
    assert_eq!(peer_of(c), Ok(name.clone()));
    assert_eq!(peer_of(l), Err(ENOTCONN));
    // They talk
    assert_eq!(send(c, b"ping", 0), 4);
    let mut buf = [0u8; 4];
    assert_eq!(recv(s, &mut buf, 0), 4);
    // /proc/net/unix lists them
    let table = unix::proc_net_unix();
    assert!(table.starts_with("Num       RefCount Protocol Flags    Type St Inode Path\n"));
    assert!(table.lines().any(|r| r.contains(&format!("00010000 0001 01 {:5} @t27-abs-main", obj(l).ino()))), "{table}");
    assert!(table.lines().any(|r| r.contains(&format!("00000000 0001 03 {:5} @t27-abs-client", obj(c).ino()))));
}

fn name_of(fd: u64) -> Vec<u8> {
    name(51, fd).unwrap()
}

fn peer_of(fd: u64) -> Result<Vec<u8>, i64> {
    name(52, fd)
}

#[test]
fn connect_and_accept_errors() {
    fake::reset();
    let c = socket(STREAM);
    assert_eq!(connect(c, &abs_addr("t27-nobody")), ECONNREFUSED);
    for bad in [vec![1u8], vec![0u8; 111], { let mut v = abs_addr("x"); v[0] = 2; v }, 1u16.to_le_bytes().to_vec(), vec![1, 0, b'/'], ] {
        let r = connect(c, &bad);
        if bad.len() == 3 {
            assert_eq!(r, ENOENT, "a path that does not exist");
        } else {
            assert_eq!(r, EINVAL, "{bad:?}");
        }
    }
    assert_eq!(call(42, [c, 0, 10, 0, 0, 0]), EFAULT);
    // Type mismatch, datagram listeners
    let l = socket(SEQPACKET);
    bind(l, &abs_addr("t27-seq"));
    call(50, [l, 1, 0, 0, 0, 0]);
    assert_eq!(connect(c, &abs_addr("t27-seq")), EPROTOTYPE);
    let d = socket(DGRAM);
    assert_eq!(call(50, [d, 1, 0, 0, 0, 0]), EOPNOTSUPP);
    assert_eq!(bind(d, &abs_addr("t27-dgram")), 0);
    let d2 = socket(DGRAM);
    assert_eq!(connect(d2, &abs_addr("t27-dgram")), ECONNREFUSED, "unconnected datagram sockets are not supported");
    // accept on a socket that is not listening
    assert_eq!(call(43, [c, 0, 0, 0, 0, 0]), EINVAL);
    // A blocking accept waits for a connection
    let lfd = socket(STREAM);
    bind(lfd, &abs_addr("t27-wait"));
    call(50, [lfd, 4, 0, 0, 0, 0]);
    fake::on_wait(move |_| {
        let c = socket(STREAM);
        assert_eq!(connect(c, &abs_addr("t27-wait")), 0);
    });
    assert!(call(43, [lfd, 0, 0, 0, 0, 0]) >= 3);
    fake::WAIT_HOOK.with_borrow_mut(|h| *h = None);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(call(43, [lfd, 0, 0, 0, 0, 0]), ERESTARTSYS);
    fake::SIGNAL_PENDING.set(false);
    // The address cannot be written
    let c2 = socket(STREAM);
    connect(c2, &abs_addr("t27-wait"));
    let mut bad = [0u8; 16];
    fake::bad_ptr(mptr(&mut bad), 16);
    let mut len = 16u32;
    assert_eq!(call(43, [lfd, mptr(&mut bad), mptr(&mut len), 0, 0, 0]), EFAULT);
    let mut bad_len = 16u32;
    fake::bad_ptr(mptr(&mut bad_len), 4);
    assert_eq!(call(51, [lfd, mptr(&mut bad), mptr(&mut bad_len), 0, 0, 0]), EFAULT);
    assert_eq!(call(51, [lfd, 0, 0, 0, 0, 0]), 0, "nothing to write");
    let mut sa = [0u8; 4];
    let mut l4 = 4u32;
    assert_eq!(call(51, [lfd, mptr(&mut sa), mptr(&mut l4), 0, 0, 0]), 0);
    assert_eq!((sa, l4), ([1, 0, 0, b't'], 11), "truncated, with the full length");
}

#[test]
fn names_are_freed_with_their_sockets() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    let a = socket(STREAM);
    assert_eq!(bind(a, &abs_addr("t27-reuse")), 0);
    call(50, [a, 4, 0, 0, 0, 0]);
    // A pending connection is refused when the listener closes
    let c = socket(STREAM | NONBLOCK);
    assert_eq!(connect(c, &abs_addr("t27-reuse")), 0);
    close(a);
    let mut buf = [0u8; 4];
    assert_eq!(recv(c, &mut buf, 0), 0, "end of file");
    assert_eq!(send(c, b"x", MSG_NOSIGNAL), EPIPE);
    let b = socket(STREAM);
    assert_eq!(bind(b, &abs_addr("t27-reuse")), 0, "the name is free again");
}

#[test]
fn file_system_names() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    let l = socket(STREAM);
    assert_eq!(bind(l, &path_addr("/run/t27.sock")), 0);
    assert!(SOCKET_NODES.with_borrow(|m| m.contains_key(&b"/run/t27.sock"[..])), "a socket node was made");
    assert_eq!(call(50, [l, 4, 0, 0, 0, 0]), 0);
    assert_eq!(name_of(l), path_addr("/run/t27.sock"));
    let other = socket(STREAM);
    assert_eq!(bind(other, &path_addr("/run/t27.sock")), EADDRINUSE, "the path exists");
    // Connecting: through the node
    let c = socket(STREAM);
    assert_eq!(connect(c, &path_addr("/run/t27.sock")), 0);
    assert!(unix::proc_net_unix().contains(" /run/t27.sock"));
    // Not there / not a socket / no permission
    let c2 = socket(STREAM);
    assert_eq!(connect(c2, &path_addr("/run/none.sock")), ENOENT);
    PATHS.with_borrow_mut(|p| p.insert(b"/etc/passwd".to_vec()));
    assert_eq!(connect(c2, &path_addr("/etc/passwd")), ECONNREFUSED);
    NO_ACCESS.with_borrow_mut(|n| n.insert(b"/run/t27.sock".to_vec()));
    assert_eq!(connect(c2, &path_addr("/run/t27.sock")), EACCES);
    NO_ACCESS.with_borrow_mut(|n| n.clear());
    // A node left behind by a socket that is gone: connection refused
    close(l);
    assert_eq!(connect(c2, &path_addr("/run/t27.sock")), ECONNREFUSED);
    // Unlinked and bound again: the new socket gets the name
    SOCKET_NODES.with_borrow_mut(|m| m.clear());
    let l2 = socket(STREAM);
    assert_eq!(bind(l2, &path_addr("/run/t27.sock")), 0);
    call(50, [l2, 1, 0, 0, 0, 0]);
    assert_eq!(connect(c2, &path_addr("/run/t27.sock")), 0);
    // A name without its terminating NUL is fine too
    let l3 = socket(STREAM);
    let mut raw = 1u16.to_le_bytes().to_vec();
    raw.extend_from_slice(b"/tmp/t27-nonul");
    assert_eq!(bind(l3, &raw), 0);
    assert_eq!(name_of(l3), path_addr("/tmp/t27-nonul"));
}

// ------------------------------------------------------------------ descriptors and credentials

#[test]
fn descriptors_travel_with_their_bytes() {
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    let f = 50;
    fake::fd::install(f, FileDescriptor::File { path: "/passed".into(), readable: true, writable: false });
    assert_eq!(send(a, b"aa", 0), 2);
    assert_eq!(send_fds(a, b"BB", &[f as i32], 0), 2);
    assert_eq!(send(a, b"cc", 0), 2);
    // A read never merges across a message that carries descriptors
    let mut buf = [0u8; 16];
    let (n, c, _) = recv_msg(b, &mut buf, 64, 0);
    assert_eq!((n, c.len()), (2, 0), "the bytes before");
    let (n, c, flags) = recv_msg(b, &mut buf, 64, MSG_CMSG_CLOEXEC);
    assert_eq!((n, &buf[..2], flags), (2, &b"BB"[..], 0));
    let m = cmsgs(&c);
    assert_eq!((m[0].0, m[0].1), (1, 1));
    let got = fds_in(&m[0].2);
    assert_eq!(got.len(), 1);
    assert!(matches!(fake::fd::get(got[0] as i64), Some(FileDescriptor::File { ref path, .. }) if path == "/passed"));
    assert!(fake::fd::FDS.with_borrow(|t| t.cloexec(got[0] as usize)), "MSG_CMSG_CLOEXEC");
    assert_eq!(recv(b, &mut buf, 0), 2);
    // A partial read of a message with descriptors: they come with the first part
    send_fds(a, b"12345", &[f as i32], 0);
    let mut two = [0u8; 2];
    let (n, c, _) = recv_msg(b, &mut two, 64, 0);
    assert_eq!((n, cmsgs(&c).len()), (2, 1));
    let (n, c, _) = recv_msg(b, &mut buf, 64, 0);
    assert_eq!((n, c.len()), (3, 0));
    // A peek leaves the descriptors queued
    send_fds(a, b"pk", &[f as i32], 0);
    let (n, c, _) = recv_msg(b, &mut buf, 64, MSG_PEEK);
    assert_eq!((n, c.len()), (2, 0));
    let (_, c, _) = recv_msg(b, &mut buf, 64, 0);
    assert_eq!(cmsgs(&c).len(), 1);
}

#[test]
fn control_message_errors_and_truncation() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    assert_eq!(send_fds(a, b"x", &[77], 0), EBADF);
    let pipe = PipeBuffer::new();
    fake::fd::install(60, FileDescriptor::PipeWrite(pipe.clone()));
    fake::fd::install(61, FileDescriptor::PipeRead(pipe.clone()));
    // A failed send drops the references it took (it used to leak them: the reader of a
    // pipe sent this way never saw end of file)
    let many: Vec<i32> = vec![60; 254];
    assert_eq!(send_fds(a, b"x", &many, 0), EINVAL, "SCM_MAX_FD");
    assert_eq!(pipe.lock().writers_count(), 1, "the references taken were dropped again");
    assert_eq!(send_fds(a, b"x", &[60, 77], 0), EBADF, "the second is not open");
    assert_eq!(pipe.lock().writers_count(), 1);
    // A malformed header
    let iov = [(b"x".as_ptr() as u64, 1u64)];
    let mut cm = [0u8; 24];
    cm[0..8].copy_from_slice(&40u64.to_le_bytes());
    let msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: ptr(&cm), controllen: 24, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&msg), 0, 0, 0, 0]), EINVAL);
    // Other control messages (SCM_CREDENTIALS) are skipped; short control buffers ignored
    let mut cred = [0u8; 32];
    cred[0..8].copy_from_slice(&28u64.to_le_bytes());
    cred[8..12].copy_from_slice(&1i32.to_le_bytes());
    cred[12..16].copy_from_slice(&2i32.to_le_bytes());
    let msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: ptr(&cred), controllen: 32, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&msg), 0, 0, 0, 0]), 1);
    let msg = MsgHdr { iov: ptr(&iov), iovlen: 1, control: ptr(&cred), controllen: 8, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&msg), 0, 0, 0, 0]), 1);
    let mut buf = [0u8; 8];
    recv(b, &mut buf, 0);
    // Pipe ends in flight hold a reference; with no room they are closed
    assert_eq!(send_fds(a, b"p", &[60, 61], 0), 1);
    let counts = || {
        let p = pipe.lock();
        (p.writers_count(), p.readers_count())
    };
    assert_eq!(counts(), (2, 2));
    let (n, c, flags) = recv_msg(b, &mut buf, 20, 0);
    assert_eq!((n, flags), (1, MSG_CTRUNC));
    assert_eq!(fds_in(&cmsgs(&c)[0].2).len(), 1, "room for one");
    assert_eq!(pipe.lock().readers_count(), 1, "the other was closed");
    // Undelivered descriptors are closed with the socket
    assert_eq!(send_fds(a, b"q", &[60], 0), 1);
    assert_eq!(pipe.lock().writers_count(), 3);
    close(b);
    assert_eq!(pipe.lock().writers_count(), 2);
    // No room in the descriptor table: EMFILE, and what was not installed is released
    // (it used to leak too)
    let (c2, d2) = pair(STREAM | NONBLOCK);
    send_fds(c2, b"z", &[60, 60], 0);
    assert_eq!(pipe.lock().writers_count(), 4);
    // Exactly one free descriptor (the holes below the highest filled)
    fake::fd::FDS.with_borrow_mut(|f| {
        let max = *f.open.keys().max().unwrap();
        for n in 3..=max {
            if !f.open.contains_key(&n) {
                f.install(n, FileDescriptor::File { path: "/filler".into(), readable: true, writable: false });
            }
        }
        f.limit = max + 2;
    });
    assert_eq!(recv_msg(d2, &mut buf, 64, 0).0, EMFILE);
    assert_eq!(pipe.lock().writers_count(), 3, "one installed, one released");
}

#[test]
fn sockets_in_flight_cannot_form_cycles() {
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    let (c, _d) = pair(STREAM | NONBLOCK);
    // c's own queue (towards d)... b holds a in flight: sending b anywhere would make a cycle
    assert_eq!(send_fds(a, b"1", &[c as i32], 0), 1, "c now in flight towards b");
    assert_eq!(send_fds(c, b"2", &[b as i32], 0), ETOOMANYREFS, "b's queue holds a socket");
    // A listener whose pending connection holds one
    let l = socket(STREAM);
    bind(l, &abs_addr("t27-cycle"));
    call(50, [l, 4, 0, 0, 0, 0]);
    let x = socket(STREAM | NONBLOCK);
    connect(x, &abs_addr("t27-cycle"));
    assert_eq!(send_fds(x, b"3", &[a as i32], 0), 1);
    assert_eq!(send_fds(c, b"4", &[l as i32], 0), ETOOMANYREFS);
    let u = socket(STREAM);
    assert_eq!(send_fds(c, b"5", &[u as i32], 0), 1, "an unconnected one is fine");
}

#[test]
fn passcred_adds_credentials() {
    fake::reset();
    fake::IDS.set((41, 40));
    fake::CREDS.set((1234, 56));
    let (a, b) = pair(STREAM | NONBLOCK);
    assert_eq!(setsockopt(b, 0, 16, &int(1)), ENOPROTOOPT);
    assert_eq!(setsockopt(b, 1, 16, &[1, 0]), EINVAL);
    let mut bad = 0u32;
    fake::bad_ptr(mptr(&mut bad), 4);
    assert_eq!(call(54, [b, 1, 16, mptr(&mut bad), 4, 0]), EFAULT);
    assert_eq!(setsockopt(b, 1, 7, &int(4096)), 0, "buffer sizes: accepted, ignored");
    assert_eq!(setsockopt(b, 1, 16, &int(1)), 0);
    assert_eq!(getsockopt(b, 1, 16).unwrap(), int(1));
    send(a, b"c", 0);
    let mut buf = [0u8; 4];
    let (n, c, flags) = recv_msg(b, &mut buf, 64, 0);
    assert_eq!((n, flags), (1, 0));
    let m = cmsgs(&c);
    assert_eq!((m[0].0, m[0].1), (1, 2), "SCM_CREDENTIALS");
    assert_eq!(m[0].2, [40u32, 1234, 56].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    send(a, b"d", 0);
    let (_, c, flags) = recv_msg(b, &mut buf, 16, 0);
    assert_eq!((c.len(), flags), (0, MSG_CTRUNC), "no room for them");
    // Both descriptors and credentials
    fake::fd::install(50, FileDescriptor::File { path: "/f".into(), readable: true, writable: false });
    send_fds(a, b"e", &[50], 0);
    let (_, c, _) = recv_msg(b, &mut buf, 64, 0);
    assert_eq!(cmsgs(&c).iter().map(|m| m.1).collect::<Vec<_>>(), vec![1, 2]);
}

// ------------------------------------------------------------------ options

#[test]
fn socket_options() {
    fake::reset();
    let (a, _b) = pair(STREAM);
    assert_eq!(getsockopt(a, 6, 1), Err(ENOPROTOOPT));
    assert_eq!(getsockopt(a, 1, 4).unwrap(), int(0), "SO_ERROR");
    assert_eq!(getsockopt(a, 1, 7).unwrap(), int(LIMIT as i32));
    assert_eq!(getsockopt(a, 1, 8).unwrap(), int(LIMIT as i32));
    assert_eq!(getsockopt(a, 1, 16).unwrap(), int(0));
    assert_eq!(getsockopt(a, 1, 30).unwrap(), int(0));
    assert_eq!(getsockopt(a, 1, 38).unwrap(), int(0));
    assert_eq!(getsockopt(a, 1, 39).unwrap(), int(1));
    assert_eq!(getsockopt(a, 1, 20).unwrap(), vec![0; 16]);
    assert_eq!(getsockopt(a, 1, 21).unwrap(), vec![0; 16]);
    assert_eq!(getsockopt(a, 1, 99), Err(ENOPROTOOPT));
    let u = socket(STREAM);
    assert_eq!(getsockopt(u, 1, 17).unwrap(), [0u32, u32::MAX, u32::MAX].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    // At most *optlen bytes
    let mut v = [0xffu8; 4];
    let mut len = 2u32;
    assert_eq!(call(55, [a, 1, 3, mptr(&mut v), mptr(&mut len), 0]), 0);
    assert_eq!((len, v), (2, [1, 0, 0xff, 0xff]));
    let mut bad = 4u32;
    fake::bad_ptr(mptr(&mut bad), 4);
    assert_eq!(call(55, [a, 1, 3, mptr(&mut v), mptr(&mut bad), 0]), EFAULT);
}

#[test]
fn peer_pidfd() {
    fake::reset();
    fake::IDS.set((71, 70));
    let u = socket(STREAM);
    assert_eq!(getsockopt(u, 1, 77), Err(ENODATA), "no peer");
    let (a, _b) = pair(STREAM);
    assert_eq!(getsockopt(a, 1, 77), Err(ESRCH), "the peer process is not found");
    fake::task::PROCESSES.with_borrow_mut(|p| p.insert(70));
    let v = getsockopt(a, 1, 77).unwrap();
    let fd = i32::from_le_bytes(v[..4].try_into().unwrap());
    match fake::fd::get(fd as i64) {
        Some(FileDescriptor::PidFd(p)) => assert_eq!(p.pid, 70),
        _ => panic!("not a pidfd"),
    }
    let limit = fake::fd::FDS.with_borrow(|f| f.open.keys().max().copied().unwrap() + 1);
    fake::fd::FDS.with_borrow_mut(|f| f.limit = limit);
    assert_eq!(getsockopt(a, 1, 77), Err(EMFILE));
}

// ------------------------------------------------------------------ sendmsg family

#[test]
fn sendmsg_and_recvmsg_details() {
    fake::reset();
    let (a, b) = pair(STREAM | NONBLOCK);
    // Gather and scatter over several iovecs
    let (p1, p2) = (*b"abc", *b"defgh");
    let iov = [(ptr(&p1), 3u64), (ptr(&p2), 5u64)];
    let msg = MsgHdr { iov: ptr(&iov), iovlen: 2, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&msg), 0, 0, 0, 0]), 8);
    let (mut x, mut y) = ([0u8; 2], [0u8; 10]);
    let riov = [(mptr(&mut x), 2u64), (mptr(&mut y), 10u64)];
    let mut rmsg = MsgHdr { iov: ptr(&riov), iovlen: 2, ..Default::default() };
    assert_eq!(call(47, [b, mptr(&mut rmsg), 0, 0, 0, 0]), 8);
    assert_eq!((&x, &y[..6]), (b"ab", &b"cdefgh"[..]));
    // A destination on a connected socket is ignored; on others refused
    let dest = abs_addr("t27-x");
    let named = MsgHdr { name: dest.as_ptr() as u64, namelen: dest.len() as u32, iov: ptr(&iov), iovlen: 1, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&named), 0, 0, 0, 0]), 3);
    let s = socket(STREAM);
    assert_eq!(call(46, [s, ptr(&named), 0, 0, 0, 0]), EISCONN);
    let d = socket(DGRAM);
    assert_eq!(call(46, [d, ptr(&named), 0, 0, 0, 0]), EOPNOTSUPP);
    assert_eq!(call(44, [s, ptr(&p1), 3, 0, dest.as_ptr() as u64, 0]), ENOTCONN);
    assert_eq!(call(44, [d, ptr(&p1), 3, 0, dest.as_ptr() as u64, 0]), EOPNOTSUPP);
    assert_eq!(call(44, [a, ptr(&p1), 3, 0, dest.as_ptr() as u64, 0]), 3, "connected: to the peer");
    // Faults and limits
    let mut gone = [0u8; 56];
    fake::bad_ptr(mptr(&mut gone), 56);
    assert_eq!(call(46, [a, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    assert_eq!(call(47, [b, mptr(&mut gone), 0, 0, 0, 0]), EFAULT);
    let many = MsgHdr { iov: ptr(&iov), iovlen: 1025, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&many), 0, 0, 0, 0]), EINVAL);
    let mut bad = [0u8; 4];
    fake::bad_ptr(mptr(&mut bad), 4);
    let biov = [(mptr(&mut bad), 4u64)];
    let bmsg = MsgHdr { iov: ptr(&biov), iovlen: 1, ..Default::default() };
    assert_eq!(call(46, [a, ptr(&bmsg), 0, 0, 0, 0]), EFAULT);
    let mut bmsg2 = MsgHdr { iov: ptr(&biov), iovlen: 1, ..Default::default() };
    assert_eq!(call(47, [b, mptr(&mut bmsg2), 0, 0, 0, 0]), EFAULT, "scatter fault");
    // Empty sends and receives
    let empty = MsgHdr::default();
    assert_eq!(call(46, [a, ptr(&empty), 0, 0, 0, 0]), 0);
    // A control buffer that cannot be written
    fake::fd::install(50, FileDescriptor::File { path: "/f".into(), readable: true, writable: false });
    let mut buf = [0u8; 8];
    while recv(b, &mut buf, 0) > 0 {}
    send_fds(a, b"w", &[50], 0);
    let mut badc = [0u8; 64];
    fake::bad_ptr(mptr(&mut badc), 64);
    let iov3 = [(buf.as_mut_ptr() as u64, 8u64)];
    let mut m3 = MsgHdr { iov: ptr(&iov3), iovlen: 1, control: mptr(&mut badc), controllen: 64, ..Default::default() };
    assert_eq!(call(47, [b, mptr(&mut m3), 0, 0, 0, 0]), EFAULT);
}

#[test]
fn sendmmsg_and_recvmmsg() {
    fake::reset();
    let (a, b) = pair(SEQPACKET | NONBLOCK);
    #[repr(C)]
    #[derive(Default)]
    struct MMsg {
        hdr: MsgHdr,
        len: u32,
        _pad: u32,
    }
    let (p1, p2) = (*b"one", *b"three");
    let i1 = [(ptr(&p1), 3u64)];
    let i2 = [(ptr(&p2), 5u64)];
    let mut v = [MMsg { hdr: MsgHdr { iov: ptr(&i1), iovlen: 1, ..Default::default() }, ..Default::default() }, MMsg { hdr: MsgHdr { iov: ptr(&i2), iovlen: 1, ..Default::default() }, ..Default::default() }];
    assert_eq!(call(307, [a, mptr(&mut v[0]), 2, 0, 0, 0]), 2);
    assert_eq!((v[0].len, v[1].len), (3, 5));
    // recvmmsg returns what is there (one at a time here)
    let mut buf = [0u8; 8];
    let ri = [(buf.as_mut_ptr() as u64, 8u64)];
    let mut r = [MMsg { hdr: MsgHdr { iov: ptr(&ri), iovlen: 1, ..Default::default() }, ..Default::default() }, MMsg::default()];
    assert_eq!(call(299, [b, mptr(&mut r[0]), 2, 0, 0, 0]), 1);
    assert_eq!(r[0].len, 3);
    assert_eq!(call(299, [b, mptr(&mut r[0]), 2, 0, 0, 0]), 1);
    assert_eq!(call(299, [b, mptr(&mut r[0]), 2, 0, 0, 0]), EAGAIN, "the first fails: its error");
    // The second message fails: the count so far
    let bad = MMsg { hdr: MsgHdr { iov: ptr(&i1), iovlen: 2000, ..Default::default() }, ..Default::default() };
    let mut v2 = [MMsg { hdr: MsgHdr { iov: ptr(&i1), iovlen: 1, ..Default::default() }, ..Default::default() }, bad];
    assert_eq!(call(307, [a, mptr(&mut v2[0]), 2, 0, 0, 0]), 1);
    // msg_len cannot be written: stops there
    let mut v3 = Box::new([MMsg { hdr: MsgHdr { iov: ptr(&i1), iovlen: 1, ..Default::default() }, ..Default::default() }]);
    fake::bad_ptr(mptr(&mut v3[0].len), 4);
    assert_eq!(call(307, [a, mptr(&mut v3[0]), 1, 0, 0, 0]), 0);
}

// ------------------------------------------------------------------ the kernel's own sockets

#[test]
fn kernel_listening_sockets() {
    let _g = serial(); // /proc/net/unix holds sockets for a moment: closes must be final
    fake::reset();
    assert_eq!(unix::kernel_listen(1, "/run/t27-kernel", 0, 0).err(), Some(-5), "no pool: EIO");
    fake::ZFS_MKNOD.set(Some(88_001));
    let k = unix::kernel_listen(1, "/run/t27-kernel", 1000, 1000).unwrap();
    assert!(k.get_nonblock());
    assert!(k.kernel_accept().is_none(), "nobody yet");
    assert!(k.peer_cred().is_none());
    assert!(matches!(k.kernel_recv(&mut [0u8; 4]), Err(ENOTCONN)));
    // A program connects through the node
    SOCKET_NODES.with_borrow_mut(|m| m.insert(b"/run/t27-kernel".to_vec(), 88_001));
    fake::IDS.set((51, 50));
    fake::CREDS.set((1000, 1000));
    let c = socket(STREAM | NONBLOCK);
    assert_eq!(connect(c, &path_addr("/run/t27-kernel")), 0);
    assert_eq!(getsockopt(c, 1, 17).unwrap(), [0u32, 1000, 1000].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    let s = k.kernel_accept().expect("the connection");
    assert_eq!(s.peer_cred(), Some((50, 1000, 1000)));
    // Kernel-side I/O never blocks and never raises SIGPIPE
    let mut buf = [0u8; 16];
    assert!(matches!(s.kernel_recv(&mut buf), Ok(None)), "nothing yet");
    fake::fd::install(60, FileDescriptor::File { path: "/shm".into(), readable: true, writable: true });
    assert_eq!(send_fds(c, b"hello", &[60], 0), 5);
    match s.kernel_recv(&mut buf) {
        Ok(Some((5, fds))) => assert_eq!(fds.len(), 1),
        _ => panic!("five bytes and a descriptor expected"),
    }
    let shm = FileDescriptor::File { path: "/shm2".into(), readable: true, writable: true };
    assert_eq!(s.kernel_send(b"welcome", vec![shm]), 7);
    let (n, c2, _) = recv_msg(c, &mut buf, 64, 0);
    assert_eq!((n, cmsgs(&c2).len()), (7, 1));
    close(c);
    assert_eq!(s.kernel_send(b"x", Vec::new()), EPIPE);
    assert!(fake::proc::POSTED.with_borrow(|p| p.is_empty()), "MSG_NOSIGNAL");
    match s.kernel_recv(&mut buf) {
        Ok(Some((0, f))) => assert!(f.is_empty(), "end of file"),
        _ => panic!("end of file expected"),
    }
}

// ------------------------------------------------------------------ linux-server's sockets

struct ServerDev(ServerObject);
impl CharDevice for ServerDev {
    fn read(&self, _b: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
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
    fn as_server(&self) -> Option<&ServerObject> {
        Some(&self.0)
    }
}

#[test]
fn server_sockets_are_forwarded() {
    fake::reset();
    let kind = hydra_hosttests_t27::ipc::protocol::LX_OBJ_KIND_UNIX;
    let dev: Arc<dyn CharDevice> = Arc::new(ServerDev(ServerObject { kind, tag: 1 }));
    let other: Arc<dyn CharDevice> = Arc::new(ServerDev(ServerObject { kind: kind + 1, tag: 1 }));
    assert_eq!(unix::server_call(&other, 49, [0; 6]), -88, "ENOTSOCK");
    fake::LX_RESULT.set(5);
    assert_eq!(unix::server_call(&dev, 44, [3, 1, 2, 0, 0, 0]), 5, "other calls go to the server");
    assert_eq!(unix::server_call(&dev, 49, [3, 0, 1, 0, 0, 0]), EINVAL);
    assert_eq!(unix::server_call(&dev, 49, [3, 0, 111, 0, 0, 0]), EINVAL);
    assert_eq!(unix::server_call(&dev, 49, [3, 0, 10, 0, 0, 0]), EFAULT);
    let abs = abs_addr("srv");
    assert_eq!(unix::server_call(&dev, 49, [3, abs.as_ptr() as u64, abs.len() as u64, 0, 0, 0]), 5, "abstract: the server's");
    // bind with a path: the node is made here, its inode goes along
    fake::LX_RESULT.set(0);
    let p = path_addr("/run/t27-srv");
    assert_eq!(unix::server_call(&dev, 49, [3, p.as_ptr() as u64, p.len() as u64, 0, 0, 0]), 0);
    let ino = SOCKET_NODES.with_borrow(|m| m[&b"/run/t27-srv"[..]]);
    assert_eq!(fake::LX_CALLS.with_borrow(|v| v.last().unwrap().2), Some(ino));
    assert_eq!(unix::server_call(&dev, 49, [3, p.as_ptr() as u64, p.len() as u64, 0, 0, 0]), EADDRINUSE);
    // connect: through the node
    assert_eq!(unix::server_call(&dev, 42, [3, p.as_ptr() as u64, p.len() as u64, 0, 0, 0]), 0);
    assert_eq!(fake::LX_CALLS.with_borrow(|v| v.last().unwrap().2), Some(ino));
    let none = path_addr("/run/t27-none");
    assert_eq!(unix::server_call(&dev, 42, [3, none.as_ptr() as u64, none.len() as u64, 0, 0, 0]), ENOENT);
    // A failed bind removes the node again
    fake::LX_RESULT.set(-98);
    let q = path_addr("/run/t27-srv2");
    assert_eq!(unix::server_call(&dev, 49, [3, q.as_ptr() as u64, q.len() as u64, 0, 0, 0]), -98);
    assert_eq!(UNLINKED.with_borrow(|v| v.clone()), vec![b"/run/t27-srv2".to_vec()]);
}
