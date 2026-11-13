//! Tests for Unix domain sockets (`src/compat/linux/unix.rs`): connected pairs and
//! descriptor passing (`SCM_RIGHTS`), through `unix::dispatch` with the x86-64 syscall
//! numbers. D-Bus, Wayland and every KDE service talk over these.
//!
//! Descriptors live in the fake per-thread fd table; closing one drops it, as the
//! kernel's close does. File-system socket names are not available on the host.

use std::sync::mpsc;
use std::sync::{Arc, Weak};
use std::time::Duration;

use hydra_hosttests::compat::linux::unix::{dispatch, UnixSocket};
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const SENDMSG: u64 = 46;
const RECVMSG: u64 = 47;
const SOCKETPAIR: u64 = 53;

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

const EAGAIN: i64 = -11;
const ETOOMANYREFS: i64 = -109;

/// `struct msghdr`.
#[repr(C)]
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

/// `struct iovec`.
#[repr(C)]
struct Iovec {
    base: u64,
    len: u64,
}

/// A control buffer with room for one descriptor (`CMSG_SPACE(sizeof(int))`).
#[repr(C, align(8))]
struct OneFd {
    len: u64,
    level: i32,
    ty: i32,
    fd: i32,
    _pad: u32,
}

/// A non-blocking connected stream pair.
fn socketpair() -> (i32, i32) {
    let mut sv = [0i32; 2];
    let r = dispatch(SOCKETPAIR, [AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv.as_mut_ptr() as u64, 0, 0]).unwrap();
    assert_eq!(r, 0, "socketpair");
    (sv[0], sv[1])
}

/// Sends one byte with descriptor `fd` attached over socket `via`.
fn send_fd(via: i32, fd: i32) -> i64 {
    let byte = b'x';
    let iov = Iovec { base: &byte as *const u8 as u64, len: 1 };
    let cm = OneFd { len: 20, level: SOL_SOCKET, ty: SCM_RIGHTS, fd, _pad: 0 };
    let msg = MsgHdr {
        name: 0,
        namelen: 0,
        _pad: 0,
        iov: &iov as *const Iovec as u64,
        iovlen: 1,
        control: &cm as *const OneFd as u64,
        controllen: core::mem::size_of::<OneFd>() as u64,
        flags: 0,
        _pad2: 0,
    };
    dispatch(SENDMSG, [via as u64, &msg as *const MsgHdr as u64, 0, 0, 0, 0]).unwrap()
}

/// Receives one byte and the descriptor that came with it (or the error).
fn recv_fd(via: i32) -> Result<i32, i64> {
    let mut byte = 0u8;
    let iov = Iovec { base: &mut byte as *mut u8 as u64, len: 1 };
    let mut cm = OneFd { len: 0, level: 0, ty: 0, fd: -1, _pad: 0 };
    let mut msg = MsgHdr {
        name: 0,
        namelen: 0,
        _pad: 0,
        iov: &iov as *const Iovec as u64,
        iovlen: 1,
        control: &mut cm as *mut OneFd as u64,
        controllen: core::mem::size_of::<OneFd>() as u64,
        flags: 0,
        _pad2: 0,
    };
    let r = dispatch(RECVMSG, [via as u64, &mut msg as *mut MsgHdr as u64, 0, 0, 0, 0]).unwrap();
    if r < 0 {
        return Err(r);
    }
    assert_eq!(r, 1);
    assert_eq!((cm.level, cm.ty), (SOL_SOCKET, SCM_RIGHTS), "a descriptor came with the byte");
    Ok(cm.fd)
}

fn write(fd: i32, data: &[u8]) -> i64 {
    let iov = Iovec { base: data.as_ptr() as u64, len: data.len() as u64 };
    let msg = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: &iov as *const Iovec as u64, iovlen: 1, control: 0, controllen: 0, flags: 0, _pad2: 0 };
    dispatch(SENDMSG, [fd as u64, &msg as *const MsgHdr as u64, 0, 0, 0, 0]).unwrap()
}

fn read(fd: i32, buf: &mut [u8]) -> i64 {
    let iov = Iovec { base: buf.as_mut_ptr() as u64, len: buf.len() as u64 };
    let mut msg = MsgHdr { name: 0, namelen: 0, _pad: 0, iov: &iov as *const Iovec as u64, iovlen: 1, control: 0, controllen: 0, flags: 0, _pad2: 0 };
    dispatch(RECVMSG, [fd as u64, &mut msg as *mut MsgHdr as u64, 0, 0, 0, 0]).unwrap()
}

fn close(fd: i32) {
    fake::FDS.with_borrow_mut(|t| t.close(fd as usize)).expect("close an open descriptor");
}

/// The socket behind descriptor `fd`, without keeping it alive.
fn watch(fd: i32) -> Weak<UnixSocket> {
    fake::FDS.with_borrow(|t| match t.get(fd as usize) {
        Some(FileDescriptor::Unix(s)) => Arc::downgrade(s),
        _ => panic!("descriptor {} is not a Unix socket", fd),
    })
}

/// Runs `f` on its own thread (with its own fake fd table) and fails if it has not
/// finished within a few seconds: a kernel spin lock taken twice never returns.
fn completes(what: &str, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("{} did not finish (deadlock)", what),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{} panicked", what),
    }
}

#[test]
fn a_pair_carries_bytes_both_ways() {
    let (a, b) = socketpair();
    assert_eq!(write(a, b"ping"), 4);
    let mut buf = [0u8; 8];
    assert_eq!(read(b, &mut buf), 4);
    assert_eq!(&buf[..4], b"ping");
    assert_eq!(write(b, b"pong"), 4);
    assert_eq!(read(a, &mut buf), 4);
    assert_eq!(&buf[..4], b"pong");
    assert_eq!(read(a, &mut buf), EAGAIN, "nothing more to read");
    close(a);
    close(b);
}

#[test]
fn a_socket_with_an_empty_queue_can_be_sent() {
    let (a, b) = socketpair();
    let (x, y) = socketpair();
    assert_eq!(send_fd(a, x), 1);
    let got = recv_fd(b).expect("the socket arrives");
    assert_ne!(got, x, "the receiver gets a new descriptor");
    assert_eq!(write(got, b"hi"), 2, "the received socket works");
    let mut buf = [0u8; 2];
    assert_eq!(read(y, &mut buf), 2);
    assert_eq!(&buf, b"hi");
    for fd in [got, x, y, a, b] {
        close(fd);
    }
}

/// Bug 40: closing a socket whose own queue holds the last reference to its peer used to
/// lock the queue twice (the peer's Drop closes the queue's descriptors under the lock).
#[test]
fn closing_a_socket_sent_over_itself_completes() {
    completes("closing a pair with a socket in flight over itself", || {
        let (a, b) = socketpair();
        let (wa, wb) = (watch(a), watch(b));
        assert_eq!(send_fd(a, a), 1, "a waits in b's queue");
        close(a);
        close(b);
        assert!(wa.upgrade().is_none() && wb.upgrade().is_none(), "both sockets are gone");
    });
}

/// Finding 35: two sockets each waiting in the other's queue keep each other alive once
/// closed. Linux collects such cycles (unix_gc); Hydra refuses the send that closes one.
#[test]
fn the_send_that_closes_a_cycle_is_refused() {
    completes("the crossed sends", || {
        let (a, b) = socketpair();
        let (wa, wb) = (watch(a), watch(b));
        assert_eq!(send_fd(a, a), 1, "a waits in b's queue");
        assert_eq!(send_fd(b, b), ETOOMANYREFS, "b into a's queue would close the cycle");
        close(a);
        close(b);
        assert!(wa.upgrade().is_none() && wb.upgrade().is_none(), "no cycle keeps them alive");
    });
}

/// Descriptors still queued when a socket closes are closed with it: a pipe's write end
/// sent and never received no longer counts as a writer (its reader sees end-of-file).
#[test]
fn undelivered_descriptors_are_closed_with_the_socket() {
    let pipe = hydra_hosttests::fs::pipe::PipeBuffer::new();
    let w = fake::FDS.with_borrow_mut(|t| t.alloc_fd(FileDescriptor::PipeWrite(pipe.clone()))).unwrap() as i32;
    let (a, b) = socketpair();
    assert_eq!(send_fd(a, w), 1);
    assert_eq!(pipe.lock().writers_count(), 2, "the end in flight counts as a writer");
    close(w);
    pipe.lock().drop_writer(); // what the kernel's close does for a pipe end
    assert_eq!(pipe.lock().writers_count(), 1);
    close(a);
    close(b);
    assert_eq!(pipe.lock().writers_count(), 0, "the undelivered end was closed");
}
