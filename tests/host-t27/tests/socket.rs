//! The legacy Hydra-native Unix socket (`src/compat/linux/socket.rs`): the registry of bound
//! names, the bind/listen/connect/accept state machine, socket pairs and their byte and
//! descriptor channels.
//!
//! The registry is global: every test uses its own paths.

mod common;
use common::*;

use hydra_hosttests_t27::compat::linux::socket::*;
use hydra_hosttests_t27::compat::linux::types::{EADDRINUSE, EAGAIN, ECONNREFUSED, EINVAL};
use hydra_hosttests_t27::fs::FileDescriptor;

fn listener(path: &str, backlog: usize) -> std::sync::Arc<spin::Mutex<UnixSocket>> {
    let s = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    UnixSocket::bind(&s, path).unwrap();
    s.lock().listen(backlog).unwrap();
    s
}

#[test]
fn constants_match_linux() {
    assert_eq!((AF_UNIX, AF_LOCAL, AF_INET), (1, 1, 2));
    assert_eq!((SOCK_STREAM, SOCK_DGRAM, SOCK_RAW), (1, 2, 3));
    assert_eq!((SOCK_NONBLOCK, SOCK_CLOEXEC), (0o4000, 0o2000000));
    assert_eq!((SHUT_RD, SHUT_WR, SHUT_RDWR), (0, 1, 2));
    let sa = LinuxSockaddrUn::default();
    assert_eq!(sa.sun_family, 1);
    assert_eq!(std::mem::size_of::<LinuxSockaddrUn>(), 110);
}

#[test]
fn new_masks_the_type_flags() {
    let s = UnixSocket::new(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, true);
    let s = s.lock();
    assert_eq!(s.sock_type, SOCK_STREAM);
    assert!(s.nonblocking);
    assert!(matches!(s.role, UnixSocketRole::Unbound));
    assert_eq!(s.poll_events(), 0, "nothing to report while unbound");
}

#[test]
fn bind_registers_the_name_once() {
    let a = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(UnixSocket::bind(&a, "/t/sock-bind"), Ok(()));
    assert!(matches!(&a.lock().role, UnixSocketRole::Bound(p) if p == "/t/sock-bind"));
    assert_eq!(UnixSocket::bind(&a, "/t/sock-bind2"), Err(-EINVAL), "already bound");
    let b = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(UnixSocket::bind(&b, "/t/sock-bind"), Err(-EADDRINUSE));
    unregister_socket("/t/sock-bind");
    assert_eq!(UnixSocket::bind(&b, "/t/sock-bind"), Ok(()), "free again");
    unregister_socket("/t/sock-bind");
}

#[test]
fn listen_needs_a_name() {
    let s = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(s.lock().listen(5), Err(-EINVAL));
    UnixSocket::bind(&s, "/t/sock-listen").unwrap();
    assert_eq!(s.lock().listen(0), Ok(()));
    assert!(matches!(&s.lock().role, UnixSocketRole::Listening { backlog: 16, .. }), "0: the default backlog");
    assert_eq!(s.lock().listen(3), Ok(()), "listening again is fine");
    unregister_socket("/t/sock-listen");
}

#[test]
fn connect_and_accept() {
    let l = listener("/t/sock-conn", 2);
    let c = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(l.lock().poll_events(), 0);
    assert_eq!(c.lock().connect("/t/sock-conn"), Ok(()));
    assert_eq!(l.lock().poll_events(), 1, "a connection to accept");
    assert!(matches!(&c.lock().role, UnixSocketRole::Connected { peer_path, .. } if peer_path == "/t/sock-conn"));
    assert_eq!(c.lock().connect("/t/sock-conn"), Err(-EINVAL), "already connected");
    let srv = l.lock().accept(false).unwrap();
    // Bytes both ways
    assert_eq!(c.lock().write(b"ping"), Ok(4));
    assert_eq!(srv.lock().poll_events() & 1, 1);
    let mut b = [0u8; 8];
    assert_eq!(srv.lock().read(&mut b), Ok(4));
    assert_eq!(&b[..4], b"ping");
    assert_eq!(srv.lock().write(b"pong!"), Ok(5));
    assert_eq!(c.lock().read(&mut b), Ok(5));
    assert_eq!(&b[..5], b"pong!");
    assert_eq!(c.lock().poll_events(), 4, "writable, nothing to read");
    unregister_socket("/t/sock-conn");
}

#[test]
fn connect_errors() {
    let c = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(c.lock().connect("/t/nobody-here"), Err(-ECONNREFUSED));
    let bound = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    UnixSocket::bind(&bound, "/t/sock-notlistening").unwrap();
    assert_eq!(c.lock().connect("/t/sock-notlistening"), Err(-ECONNREFUSED));
    let l = listener("/t/sock-full", 1);
    let c1 = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(c1.lock().connect("/t/sock-full"), Ok(()));
    let c2 = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert_eq!(c2.lock().connect("/t/sock-full"), Err(-EAGAIN), "backlog full");
    drop(l);
    unregister_socket("/t/sock-full");
    unregister_socket("/t/sock-notlistening");
}

#[test]
fn accept_waits_cooperatively() {
    fake::reset();
    let l = listener("/t/sock-accept", 4);
    assert_eq!(l.lock().accept(true).err(), Some(-EAGAIN), "non-blocking");
    let c = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    assert!(UnixSocket::new(AF_UNIX, SOCK_STREAM, false).lock().accept(true).is_err());
    assert_eq!(c.lock().accept(false).err(), Some(-EINVAL), "not listening");
    // Blocking: gives up after 100 yields
    assert_eq!(l.lock().accept(false).err(), Some(-EAGAIN));
    assert_eq!(fake::task::YIELDS.get(), 100);
    // A non-blocking socket never waits
    l.lock().nonblocking = true;
    assert_eq!(l.lock().accept(false).err(), Some(-EAGAIN));
    unregister_socket("/t/sock-accept");
}

#[test]
fn pairs_carry_bytes_and_descriptors() {
    let (a, b) = UnixSocket::pair(SOCK_STREAM | SOCK_CLOEXEC, true);
    assert_eq!(a.lock().sock_type, SOCK_STREAM);
    assert!(a.lock().nonblocking && b.lock().nonblocking);
    assert!(matches!(&a.lock().role, UnixSocketRole::Connected { peer_path, .. } if peer_path == "[socketpair]"));
    assert_eq!(a.lock().write(b"hello"), Ok(5));
    let mut buf = [0u8; 16];
    assert_eq!(b.lock().read(&mut buf), Ok(5));
    assert_eq!(b.lock().write(b"x"), Ok(1));
    assert_eq!(a.lock().read(&mut buf), Ok(1));
    // SCM_RIGHTS queues
    let f = FileDescriptor::File { path: "/passed".into(), readable: true, writable: false };
    assert!(a.lock().push_ancillary_fd(f).is_ok());
    assert!(a.lock().pop_ancillary_fd().is_none(), "the sender's own queue is the other one");
    match b.lock().pop_ancillary_fd() {
        Some(FileDescriptor::File { path, .. }) => assert_eq!(path, "/passed"),
        _ => panic!("descriptor not delivered"),
    }
    assert!(b.lock().pop_ancillary_fd().is_none());
}

#[test]
fn unconnected_and_closed_sockets() {
    let s = UnixSocket::new(AF_UNIX, SOCK_STREAM, false);
    let mut buf = [0u8; 4];
    assert_eq!(s.lock().read(&mut buf), Err("Socket not connected"));
    assert_eq!(s.lock().write(b"x"), Err("Socket not connected"));
    let f = FileDescriptor::File { path: "/x".into(), readable: true, writable: false };
    assert_eq!(s.lock().push_ancillary_fd(f).err(), Some("Socket not connected"));
    assert!(s.lock().pop_ancillary_fd().is_none());
    assert_eq!(s.lock().shutdown(7), Err(-EINVAL));
    let (a, _b) = UnixSocket::pair(SOCK_STREAM, false);
    for how in [SHUT_RD, SHUT_WR, SHUT_RDWR] {
        assert_eq!(a.lock().shutdown(how), Ok(()));
    }
    assert!(matches!(a.lock().role, UnixSocketRole::Closed));
    assert_eq!(a.lock().read(&mut buf), Ok(0), "end of file");
    assert_eq!(a.lock().write(b"x"), Err("Broken pipe (EPIPE)"));
    assert_eq!(a.lock().poll_events(), 0x10, "POLLHUP");
    assert_eq!(a.lock().connect("/x"), Err(-EINVAL));
}
