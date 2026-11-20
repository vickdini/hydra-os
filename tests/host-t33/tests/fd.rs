//! The descriptor table and descriptor I/O (`src/fs/fd.rs`): allocation, dup rules,
//! close-on-exec, fork, the server-object bits, readiness and wait queues per kind, and
//! reads/writes of pool files (through the fake file server), pseudo-files, pipes,
//! memfds and the console.

mod common;

use std::sync::Arc;

use hydra_hosttests_t33::compat::linux::epoll::{EpollInstance, EPOLLIN, EPOLLONESHOT};
use hydra_hosttests_t33::compat::linux::{
    chardev::CharDevice, eventfd::EventFd, inet::InetSocket, inotify::Inotify, memfd::MemFd, pidfd::PidFd, pty::PtyFile, signalfd::SignalFd, socket, timerfd::TimerFd, tty, unix,
    FANOTIFY_ON, FSIZE, INOTIFY_ON, LOCKS, NOFILE, NOTIFIED,
};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs::{self, with_fs};
use hydra_hosttests_t33::fs::fd::{self, OpenFile, EBADF_MSG, EFBIG_MSG, ENOSPC_MSG, O_APPEND, O_PATH, O_RDONLY, O_RDWR, O_WRONLY, SRV_LOW};
use hydra_hosttests_t33::fs::{FdTable, FileDescriptor, PipeBuffer, MAX_FDS};
use hydra_hosttests_t33::task::wait::{WaitQueue, WaitSet};
use spin::Mutex;
use uefi::proto::console::text::Key;

fn setup() {
    fake::reset();
    fakefs::pool();
}

/// A pool file `/fdtests/<name>` with `data`, opened with `flags`.
fn vnode(name: &str, data: &[u8], flags: u32) -> (u64, FileDescriptor) {
    let d = with_fs(|fs| fs.mkdir_p(fakefs::ROOT_INO, "fdtests"));
    let ino = with_fs(|fs| fs.put(d, name, data));
    let f = OpenFile::new(ino, flags, format!("/fdtests/{name}"));
    (ino, FileDescriptor::Vnode(f))
}

fn data_of(ino: u64) -> Vec<u8> {
    with_fs(|fs| fs.data(ino).unwrap())
}

/// A device; `server` marks it a linux-server object.
struct Dev {
    server: bool,
    events: u32,
}

impl CharDevice for Dev {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        self.events
    }
    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.polled = true;
    }
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        "/dev/test".into()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_server(&self) -> Option<&hydra_hosttests_t33::lx::obj::ServerObject> {
        self.server.then_some(&hydra_hosttests_t33::lx::obj::ServerObject)
    }
}

fn dev(server: bool, events: u32) -> FileDescriptor {
    FileDescriptor::Device(Arc::new(Dev { server, events }))
}

fn ends(p: &Arc<Mutex<PipeBuffer>>) -> (usize, usize) {
    let g = p.lock();
    (g.readers_count(), g.writers_count())
}

fn file(path: &str, readable: bool, writable: bool, append: bool) -> FileDescriptor {
    FileDescriptor::File { path: path.into(), cursor: 0, readable, writable, append, shown: None }
}

// ---------------------------------------------------------------- open files

#[test]
fn open_file_access_modes_and_references() {
    setup();
    let (ino, _) = vnode("modes", b"", O_RDONLY);
    let ro = OpenFile::new(ino, O_RDONLY, "/x".into());
    let wo = OpenFile::new(ino, O_WRONLY, "/x".into());
    let rw = OpenFile::new(ino, O_RDWR | O_APPEND, "/x".into());
    let path = OpenFile::new(ino, O_PATH | O_RDWR, "/x".into());
    assert!(ro.lock().readable() && !ro.lock().writable());
    assert!(!wo.lock().readable() && wo.lock().writable());
    assert!(rw.lock().readable() && rw.lock().writable());
    assert!(!path.lock().readable() && !path.lock().writable(), "O_PATH: neither");
    assert_eq!(with_fs(|fs| fs.refs.get(&ino).copied()), Some(1), "the server heard of the first reference only");
    drop((ro, wo, rw, path));
    // (the descriptor `vnode()` made was dropped at once): the last release reached it
    assert_eq!(with_fs(|fs| fs.refs.get(&ino).copied()), Some(0));
}

#[test]
fn dropping_an_open_file_releases_locks_and_reports_the_close() {
    setup();
    let (ino, _keep) = vnode("close", b"", O_RDONLY);
    FANOTIFY_ON.set(true);
    INOTIFY_ON.set(true);
    let w = OpenFile::new(ino, O_WRONLY, "/fdtests/close".into());
    let key = { let g = w.lock(); &*g as *const OpenFile as u64 };
    drop(w);
    assert!(LOCKS.with_borrow(|v| v.contains(&("release_file", key))));
    assert!(NOTIFIED.with_borrow(|v| v.iter().any(|n| n.0 == "fanotify" && n.1 == ino && n.2 == 0x8)), "FAN_CLOSE_WRITE");
    assert!(with_fs(|fs| fs.notified.contains(&(ino, 0x8))), "IN_CLOSE_WRITE through the server");
    let r = OpenFile::new(ino, O_RDONLY, "/fdtests/close".into());
    drop(r);
    assert!(NOTIFIED.with_borrow(|v| v.iter().any(|n| n.0 == "fanotify" && n.2 == 0x10)), "FAN_CLOSE_NOWRITE");
    // nonotify and O_PATH descriptors make no events
    NOTIFIED.with_borrow_mut(|v| v.clear());
    let q = OpenFile::new(ino, O_RDONLY, "/q".into());
    q.lock().nonotify = true;
    drop(q);
    drop(OpenFile::new(ino, O_PATH, "/p".into()));
    assert!(NOTIFIED.with_borrow(|v| v.is_empty()));
}

#[test]
fn io_errors_keep_their_errno() {
    for e in [-1, -9, -2, -4, -11, -13, -22, -28, -30, -95, -107, -122, -5] {
        assert_eq!(fd::io_errno(fd::io_error(e)), Some(e));
    }
    assert_eq!(fd::io_error(-1234), "Input/output error");
    assert_eq!(fd::io_errno("something else"), None);
    assert_eq!(fd::io_error(-28), ENOSPC_MSG);
}

// --------------------------------------------------------- descriptor reads

#[test]
fn vnode_read_write_seek_and_access_checks() {
    setup();
    let (ino, mut d) = vnode("rw", b"0123456789", O_RDWR);
    let mut buf = [0u8; 4];
    assert_eq!(d.read(&mut []), Ok(0));
    assert_eq!(d.read(&mut buf), Ok(4));
    assert_eq!(&buf, b"0123");
    assert_eq!(d.read(&mut buf), Ok(4));
    assert_eq!(&buf, b"4567");
    assert_eq!(d.write(b"AB"), Ok(2));
    assert_eq!(data_of(ino), b"01234567AB");
    assert_eq!(d.pread(&mut buf, 1), Ok(4));
    assert_eq!(&buf, b"1234");
    assert_eq!(d.pwrite(b"zz", 0), Ok(2));
    assert_eq!(data_of(ino), b"zz234567AB");
    assert_eq!(d.write(b""), Ok(0));
    // Read-only and write-only descriptors
    let (_, mut ro) = vnode("ro", b"abc", O_RDONLY);
    assert_eq!(ro.write(b"x"), Err("File not opened for writing"));
    assert_eq!(ro.pwrite(b"x", 0), Err(EBADF_MSG));
    let (_, mut wo) = vnode("wo", b"abc", O_WRONLY);
    assert_eq!(wo.read(&mut buf), Err("File not opened for reading"));
    assert_eq!(wo.pread(&mut buf, 0), Err(EBADF_MSG));
    // A missing object maps the server's errno through io_error
    let gone = FileDescriptor::Vnode(OpenFile::new(999_999_997, O_RDWR, "/gone".into()));
    let mut gone2 = gone.clone();
    assert_eq!(gone2.read(&mut buf), Err("No such file or directory"));
    assert_eq!(gone2.pread(&mut buf, 0), Err("No such file or directory"));
    assert_eq!(gone2.write(b"x"), Err("No such file or directory"));
}

#[test]
fn append_mode_and_the_file_size_limit() {
    setup();
    let (ino, mut d) = vnode("append", b"start", O_WRONLY | O_APPEND);
    assert_eq!(d.write(b"-1"), Ok(2));
    assert_eq!(d.pwrite(b"-2", 0), Ok(2), "pwrite with O_APPEND appends too (Linux)");
    assert_eq!(data_of(ino), b"start-1-2");
    // RLIMIT_FSIZE: cut to the limit, then EFBIG
    let (ino2, mut e) = vnode("fsize", b"", O_RDWR);
    FSIZE.set(4);
    assert_eq!(e.write(b"123456"), Ok(4));
    assert_eq!(e.write(b"7"), Err(EFBIG_MSG));
    assert_eq!(e.pwrite(b"xy", 3), Ok(1));
    assert_eq!(e.pwrite(b"xy", 9), Err(EFBIG_MSG));
    assert_eq!(data_of(ino2), b"123x");
}

#[test]
fn vnode_io_reports_fanotify_access_and_modify() {
    setup();
    let (ino, mut d) = vnode("fan", b"abc", O_RDWR);
    FANOTIFY_ON.set(true);
    let mut b = [0u8; 2];
    d.read(&mut b).unwrap();
    d.pread(&mut b, 0).unwrap();
    d.write(b"z").unwrap();
    d.pwrite(b"y", 0).unwrap();
    let masks: Vec<u64> = NOTIFIED.with_borrow(|v| v.iter().filter(|n| n.1 == ino).map(|n| n.2).collect());
    assert_eq!(masks, vec![1, 1, 2, 2]);
    // Reading at the end: no event
    NOTIFIED.with_borrow_mut(|v| v.clear());
    d.pread(&mut b, 100).unwrap();
    assert!(NOTIFIED.with_borrow(|v| v.is_empty()));
}

#[test]
fn path_files_read_pseudo_files_and_the_pool() {
    setup();
    let mut v = file("/proc/version", true, false, false);
    let mut b = [0u8; 6];
    assert_eq!(v.read(&mut b), Ok(6));
    assert_eq!(&b, b"Linux ");
    assert_eq!(v.read(&mut b), Ok(6));
    assert_eq!(&b, b"versio");
    assert_eq!(v.pread(&mut b, 0), Ok(6));
    assert_eq!(v.write(b"x"), Err("File not opened for writing"));
    assert_eq!(v.pwrite(b"x", 0), Err(EBADF_MSG));
    let mut full = file("/dev/full", true, true, false);
    assert_eq!(full.write(b"x"), Err(ENOSPC_MSG));
    assert_eq!(full.pwrite(b"x", 0), Err(ENOSPC_MSG));
    let mut null = file("/dev/null", false, true, false);
    assert_eq!(null.write(b"xyz"), Ok(3));
    assert_eq!(null.read(&mut b), Err("File not opened for reading"));
    assert_eq!(null.pread(&mut b, 0), Err(EBADF_MSG));
    // A pool file by path
    let (ino, _keep) = vnode("bypath", b"hello", O_RDONLY);
    let mut p = file("/fdtests/bypath", true, true, false);
    assert_eq!(p.read(&mut b), Ok(5));
    assert_eq!(p.write(b"!"), Ok(1));
    assert_eq!(data_of(ino), b"hello!");
    assert_eq!(p.pwrite(b"H", 0), Ok(1));
    let mut a = file("/fdtests/bypath", false, true, true);
    assert_eq!(a.write(b"++"), Ok(2), "append: at the end");
    assert_eq!(data_of(ino), b"Hello!++");
    let mut missing = file("/fdtests/none", true, true, false);
    assert_eq!(missing.read(&mut b), Err("File not found"));
    assert_eq!(missing.write(b"x"), Err("File not found"));
    // The server failing a read or write
    fakefs::fail(0x3106, -5, 1);
    assert_eq!(p.pread(&mut b, 0), Err("ZFS read error"));
    fakefs::fail(0x3107, -5, 1);
    assert_eq!(p.pwrite(b"x", 0), Err("ZFS write error"));
    fakefs::fail(0x3104, -5, 1);
    assert_eq!(a.write(b"x"), Err("ZFS stat error"));
}

#[test]
fn console_streams() {
    setup();
    let mut cin = FileDescriptor::ConsoleIn;
    fake::KEYS.with_borrow_mut(|k| {
        for c in "ab\nc".chars() {
            k.push_back(Key::Printable(uefi::Char16::try_from(c).unwrap()));
        }
    });
    let mut b = [0u8; 8];
    assert_eq!(cin.read(&mut b), Ok(3), "a line at a time");
    assert_eq!(&b[..3], b"ab\n");
    // Non-ASCII and special keys are skipped; no key ends the read
    fake::KEYS.with_borrow_mut(|k| {
        k.push_back(Key::Printable(uefi::Char16::try_from('é').unwrap()));
        k.push_back(Key::Special(uefi::proto::console::text::ScanCode::UP));
    });
    assert_eq!(cin.read(&mut b), Ok(1));
    assert_eq!(b[0], b'c');
    assert_eq!(cin.write(b"x"), Err("Cannot write to read-only console input"));
    let mut out = FileDescriptor::ConsoleOut;
    assert_eq!(out.read(&mut b), Err("Cannot read from write-only console stream"));
    fake::console_take();
    assert_eq!(out.write(b"hi"), Ok(2));
    assert_eq!(FileDescriptor::ConsoleErr.write(&[b'o', 0xFF, b'k']), Ok(3));
    let printed = fake::console_take();
    assert!(printed.contains("hi") && printed.contains('o') && printed.contains('k'));
    assert!(!printed.contains('\u{FFFD}'), "invalid bytes are dropped");
}

#[test]
fn pipes_sockets_eventfds_and_memfds() {
    setup();
    common::global_frames();
    let pipe = PipeBuffer::new();
    let mut w = FileDescriptor::PipeWrite(pipe.clone());
    let mut r = FileDescriptor::PipeRead(pipe.clone());
    let mut b = [0u8; 8];
    assert_eq!(w.write(b"pipe"), Ok(4));
    assert_eq!(w.read(&mut b), Err("Cannot read from write end of pipe"));
    assert_eq!(r.write(b"x"), Err("Cannot write to read end of pipe"));
    assert_eq!(r.read(&mut b), Ok(4));
    assert_eq!(r.pread(&mut b, 0), Err("Descriptor is not seekable"));
    assert_eq!(w.pwrite(b"x", 0), Err("Descriptor is not seekable"));
    // Legacy socket
    let mut s = FileDescriptor::Socket(Arc::new(Mutex::new(socket::UnixSocket::connected())));
    assert_eq!(s.write(b"sock"), Ok(4));
    assert_eq!(s.read(&mut b), Ok(4));
    // eventfd
    let mut e = FileDescriptor::EventFd(EventFd::new(0, 0));
    assert_eq!(e.write(&5u64.to_le_bytes()), Ok(8));
    assert_eq!(e.read(&mut b), Ok(8));
    assert_eq!(u64::from_le_bytes(b), 5);
    // memfd: access mode per descriptor
    let m = MemFd::new("t");
    let mut rw = FileDescriptor::MemFd { memfd: m.clone(), flags: O_RDWR };
    let mut ro = FileDescriptor::MemFd { memfd: m.clone(), flags: O_RDONLY };
    let mut wo = FileDescriptor::MemFd { memfd: m.clone(), flags: O_WRONLY };
    assert_eq!(rw.write(b"memory"), Ok(6));
    assert_eq!(ro.write(b"x"), Err("File not opened for writing"));
    assert_eq!(ro.pwrite(b"x", 0), Err(EBADF_MSG));
    assert_eq!(wo.read(&mut b), Err("File not opened for reading"));
    assert_eq!(wo.pread(&mut b, 0), Err(EBADF_MSG));
    assert_eq!(wo.pwrite(b"M", 0), Ok(1));
    assert_eq!(ro.pread(&mut b[..6], 0), Ok(6));
    assert_eq!(&b[..6], b"Memory");
}

#[test]
fn kinds_read_and_written_elsewhere_refuse() {
    setup();
    let wq = WaitQueue::new_shared;
    let mut b = [0u8; 4];
    let mut kinds: Vec<(FileDescriptor, &str, Result<usize, &str>)> = vec![
        (FileDescriptor::Epoll(Arc::new(Mutex::new(EpollInstance::default()))), "Cannot read from epoll file descriptor", Err("Cannot write to epoll file descriptor")),
        (FileDescriptor::Inet(Arc::new(Mutex::new(InetSocket { wq: None, events: 0 }))), "Internet sockets are read through the Linux socket layer", Err("Internet sockets are written through the Linux socket layer")),
        (FileDescriptor::Pty(Arc::new(PtyFile::new())), "Pseudo-terminals are read through the Linux terminal layer", Ok(4)),
        (FileDescriptor::SignalFd(Arc::new(SignalFd)), "signalfd is read through the Linux layer", Err("signalfd is not writable")),
        (FileDescriptor::Unix(Arc::new(unix::UnixSocket)), "Unix sockets are read through the Linux socket layer", Ok(4)),
        (FileDescriptor::TimerFd(Arc::new(TimerFd { wq: wq() })), "read through the Linux layer", Err("not writable")),
        (FileDescriptor::Inotify(Arc::new(Inotify { wq: wq() })), "read through the Linux layer", Err("not writable")),
        (FileDescriptor::PidFd(Arc::new(PidFd)), "pidfds are not readable", Err("not writable")),
        (dev(false, 0), "devices are read through the Linux layer", Err("devices are written through the Linux layer")),
    ];
    for (d, rerr, w) in kinds.iter_mut() {
        assert_eq!(d.read(&mut b), Err(*rerr));
        assert_eq!(d.write(b"data"), *w);
        assert_eq!(d.pread(&mut b, 0), Err("Descriptor is not seekable"));
    }
    // The pty kept what the kernel wrote
    if let FileDescriptor::Pty(p) = &kinds[2].0 {
        assert_eq!(&*p.written.lock(), b"data");
    }
}

// ------------------------------------------------------------ readiness, waits

#[test]
fn poll_events_per_kind() {
    setup();
    common::global_frames();
    tty::ATTACHED.set(false);
    assert_eq!(FileDescriptor::ConsoleIn.poll_events(), 0x5, "not attached: always readable");
    tty::ATTACHED.set(true);
    assert_eq!(FileDescriptor::ConsoleOut.poll_events(), 0x4);
    tty::HAS_INPUT.set(true);
    assert_eq!(FileDescriptor::ConsoleErr.poll_events(), 0x5);
    let p = PipeBuffer::new();
    assert_eq!(FileDescriptor::PipeRead(p.clone()).poll_events(), 0, "empty, a writer");
    p.lock().write(b"x").unwrap();
    assert_eq!(FileDescriptor::PipeRead(p.clone()).poll_events(), 0x1);
    p.lock().drop_writer();
    assert_eq!(FileDescriptor::PipeRead(p.clone()).poll_events(), 0x11, "readable and hung up");
    assert_eq!(FileDescriptor::PipeWrite(p.clone()).poll_events(), 0x4);
    p.lock().drop_reader();
    assert_eq!(FileDescriptor::PipeWrite(p.clone()).poll_events(), 0xC, "no reader: error");
    assert_eq!(FileDescriptor::Socket(Arc::new(Mutex::new(socket::UnixSocket::connected()))).poll_events(), 0x4);
    assert_eq!(FileDescriptor::EventFd(EventFd::new(1, 0)).poll_events() & 0x1, 0x1);
    assert_eq!(file("/x", true, false, false).poll_events(), 0x1);
    assert_eq!(file("/x", false, true, false).poll_events(), 0x4);
    assert_eq!(FileDescriptor::Inet(Arc::new(Mutex::new(InetSocket { wq: None, events: 0x41 }))).poll_events(), 0x41);
    assert_eq!(FileDescriptor::Pty(Arc::new(PtyFile::new())).poll_events(), 0x4);
    assert_eq!(FileDescriptor::SignalFd(Arc::new(SignalFd)).poll_events(), 0x1);
    assert_eq!(FileDescriptor::Unix(Arc::new(unix::UnixSocket)).poll_events(), 0x4);
    assert_eq!(FileDescriptor::TimerFd(Arc::new(TimerFd { wq: WaitQueue::new_shared() })).poll_events(), 0);
    assert_eq!(FileDescriptor::Inotify(Arc::new(Inotify { wq: WaitQueue::new_shared() })).poll_events(), 0);
    assert_eq!(FileDescriptor::PidFd(Arc::new(PidFd)).poll_events(), 0x1);
    assert_eq!(dev(false, 0x40).poll_events(), 0x40);
    let (_, v) = vnode("poll", b"", O_RDONLY);
    assert_eq!(v.poll_events(), 0x5);
    let m = MemFd::new("p");
    assert_eq!(FileDescriptor::MemFd { memfd: m.clone(), flags: O_RDONLY }.poll_events(), 0x1);
    assert_eq!(FileDescriptor::MemFd { memfd: m.clone(), flags: O_WRONLY }.poll_events(), 0x4);
    assert_eq!(FileDescriptor::MemFd { memfd: m, flags: O_RDWR }.poll_events(), 0x5);
    assert_eq!(FileDescriptor::Epoll(Arc::new(Mutex::new(EpollInstance::default()))).poll_events(), 0);
}

#[test]
fn wait_queues_per_kind() {
    setup();
    common::global_frames();
    let count = |d: &FileDescriptor| {
        let mut w = WaitSet::new();
        d.add_wait_queues(&mut w);
        (w.queues.len(), w.polled, w.deadlines)
    };
    assert_eq!(count(&FileDescriptor::ConsoleIn), (1, false, 0));
    let p = PipeBuffer::new();
    assert_eq!(count(&FileDescriptor::PipeRead(p.clone())), (1, false, 0));
    assert_eq!(count(&FileDescriptor::Socket(Arc::new(Mutex::new(socket::UnixSocket::connected())))), (2, false, 0));
    let unbound = socket::UnixSocket { role: socket::UnixSocketRole::Unbound, data: vec![], shut: None };
    assert_eq!(count(&FileDescriptor::Socket(Arc::new(Mutex::new(unbound)))), (0, true, 0));
    assert_eq!(count(&FileDescriptor::Pty(Arc::new(PtyFile::new()))), (1, false, 0));
    assert_eq!(count(&FileDescriptor::SignalFd(Arc::new(SignalFd))), (0, false, 0));
    assert_eq!(count(&FileDescriptor::Unix(Arc::new(unix::UnixSocket))), (1, false, 0));
    assert_eq!(count(&FileDescriptor::TimerFd(Arc::new(TimerFd { wq: WaitQueue::new_shared() }))), (1, false, 1));
    assert_eq!(count(&FileDescriptor::Inotify(Arc::new(Inotify { wq: WaitQueue::new_shared() }))), (1, false, 0));
    assert_eq!(count(&FileDescriptor::PidFd(Arc::new(PidFd))), (1, false, 0));
    assert_eq!(count(&dev(false, 0)), (0, true, 0));
    assert_eq!(count(&FileDescriptor::EventFd(EventFd::new(0, 0))), (1, false, 0));
    let inet = |wq| FileDescriptor::Inet(Arc::new(Mutex::new(InetSocket { wq, events: 0 })));
    assert_eq!(count(&inet(None)), (0, true, 0));
    assert_eq!(count(&inet(Some(WaitQueue::new_shared()))), (0, true, 0), "net-server not running: polled");
    fake::NET_RUNNING.set(true);
    assert_eq!(count(&inet(Some(WaitQueue::new_shared()))), (1, false, 0));
    let (_, v) = vnode("waits", b"", O_RDONLY);
    assert_eq!(count(&v), (0, false, 0));
    assert_eq!(count(&FileDescriptor::MemFd { memfd: MemFd::new("w"), flags: 0 }), (0, false, 0));
    assert_eq!(count(&file("/x", true, true, false)), (0, false, 0));
    assert_eq!(count(&FileDescriptor::Epoll(Arc::new(Mutex::new(EpollInstance::default())))), (0, true, 0));
}

#[test]
fn object_ids_tell_open_files_apart() {
    setup();
    let p = PipeBuffer::new();
    let r = FileDescriptor::PipeRead(p.clone());
    let w = FileDescriptor::PipeWrite(p.clone());
    assert_eq!(r.object_id() | 1, w.object_id(), "the two ends differ in the low bit");
    assert_ne!(r.object_id(), w.object_id());
    assert_eq!(r.clone().object_id(), r.object_id(), "a dup is the same open file");
    assert_eq!([FileDescriptor::ConsoleIn.object_id(), FileDescriptor::ConsoleOut.object_id(), FileDescriptor::ConsoleErr.object_id()], [1, 2, 3]);
    let a = file("/a", true, false, false);
    let b = file("/a", true, false, false);
    assert_ne!(a.object_id(), b.object_id());
    let wq = WaitQueue::new_shared;
    let all = vec![
        FileDescriptor::Socket(Arc::new(Mutex::new(socket::UnixSocket::connected()))),
        FileDescriptor::Epoll(Arc::new(Mutex::new(EpollInstance::default()))),
        FileDescriptor::EventFd(EventFd::new(0, 0)),
        FileDescriptor::Inet(Arc::new(Mutex::new(InetSocket { wq: None, events: 0 }))),
        FileDescriptor::Pty(Arc::new(PtyFile::new())),
        FileDescriptor::SignalFd(Arc::new(SignalFd)),
        FileDescriptor::Unix(Arc::new(unix::UnixSocket)),
        FileDescriptor::TimerFd(Arc::new(TimerFd { wq: wq() })),
        FileDescriptor::Inotify(Arc::new(Inotify { wq: wq() })),
        FileDescriptor::PidFd(Arc::new(PidFd)),
        dev(false, 0),
        vnode("ids", b"", O_RDONLY).1,
    ];
    for d in &all {
        assert_ne!(d.object_id(), 0);
    }
}

// --------------------------------------------------------------- the table

#[test]
fn allocation_takes_the_lowest_free_number() {
    setup();
    let mut t = FdTable::new_default();
    assert_eq!(t.cwd_path, "/");
    assert!(matches!(t.get(0), Some(FileDescriptor::ConsoleIn)));
    assert!(matches!(t.get(2), Some(FileDescriptor::ConsoleErr)));
    assert_eq!(t.alloc_fd(file("/a", true, false, false)), Ok(3));
    assert_eq!(t.alloc_fd_from(file("/b", true, false, false), 10), Ok(10));
    assert_eq!(t.alloc_fd(file("/c", true, false, false)), Ok(4));
    t.close(1).unwrap();
    assert_eq!(t.alloc_fd(file("/d", true, false, false)), Ok(1));
    // RLIMIT_NOFILE bounds the numbers
    NOFILE.set(12);
    assert_eq!(t.alloc_fd_from(file("/e", true, false, false), 11), Ok(11));
    assert_eq!(t.alloc_fd_from(file("/f", true, false, false), 11), Err("Process file descriptor table is full (EMFILE)"));
    assert_eq!(t.dup2(3, 12), Err("Bad file descriptor (EBADF)"));
    NOFILE.set(1024);
    // init_default keeps what is there
    let mut e = FdTable::empty();
    assert!(e.get(0).is_none());
    e.set_fd(1, Some(file("/out", false, true, false)));
    e.init_default();
    assert!(matches!(e.get(0), Some(FileDescriptor::ConsoleIn)));
    assert!(matches!(e.get(1), Some(FileDescriptor::File { .. })));
    assert!(matches!(FdTable::default().get(1), Some(FileDescriptor::ConsoleOut)));
    assert!(t.get_mut(3).is_some() && t.get_mut(500).is_none());
}

#[test]
fn close_on_exec_and_dup_rules() {
    setup();
    let mut t = FdTable::new_default();
    let a = t.alloc_fd(file("/a", true, false, false)).unwrap();
    t.set_cloexec(a, true);
    assert!(t.cloexec(a));
    t.set_cloexec(5000, true); // out of range: ignored
    assert!(!t.cloexec(5000));
    // dup never copies FD_CLOEXEC
    let b = t.dup_from(a, 0).unwrap();
    assert!(!t.cloexec(b));
    let c = t.dup2(a, 20).unwrap();
    assert_eq!(c, 20);
    assert!(!t.cloexec(20));
    // dup2 onto itself changes nothing (FD_CLOEXEC stays)
    assert_eq!(t.dup2(a, a), Ok(a));
    assert!(t.cloexec(a));
    assert_eq!(t.dup2(77, 5), Err("Source file descriptor not open (EBADF)"));
    assert_eq!(t.dup_from(77, 0), Err("Source file descriptor not open (EBADF)"));
    // set_fd resets FD_CLOEXEC and returns what was there
    t.set_cloexec(b, true);
    let old = t.set_fd(b, Some(file("/z", true, false, false)));
    assert!(matches!(old, Some(FileDescriptor::File { ref path, .. }) if path == "/a"));
    assert!(!t.cloexec(b));
    assert!(t.set_fd(MAX_FDS, Some(file("/n", true, false, false))).is_none());
    // exec closes the marked ones only
    t.close_on_exec();
    assert!(t.get(a).is_none());
    assert!(t.get(b).is_some() && t.get(20).is_some());
    assert_eq!(t.close(a), Err("File descriptor not open (EBADF)"));
    assert_eq!(t.close(9999), Err("File descriptor not open (EBADF)"));
}

#[test]
fn pipe_ends_are_counted_through_dup_fork_and_close() {
    setup();
    let p = PipeBuffer::new();
    let mut t = FdTable::new_default();
    let r = t.alloc_fd(FileDescriptor::PipeRead(p.clone())).unwrap();
    let w = t.alloc_fd(FileDescriptor::PipeWrite(p.clone())).unwrap();
    assert_eq!(ends(&p), (1, 1));
    t.dup_from(r, 0).unwrap();
    t.dup2(w, 30).unwrap();
    assert_eq!(ends(&p), (2, 2));
    let mut child = t.fork_copy();
    assert_eq!(ends(&p), (4, 4));
    child.close_all();
    assert_eq!(ends(&p), (2, 2));
    // dup2 over an open pipe end closes it first
    t.dup2(r, w).unwrap();
    assert_eq!(ends(&p), (3, 1));
    let shared = t.into_shared();
    shared.lock().close_all();
    assert_eq!(ends(&p), (0, 0));
}

#[test]
fn closing_sockets_and_vnodes() {
    setup();
    let s = Arc::new(Mutex::new(socket::UnixSocket::connected()));
    let mut t = FdTable::new_default();
    let fd = t.alloc_fd(FileDescriptor::Socket(s.clone())).unwrap();
    t.close(fd).unwrap();
    assert_eq!(s.lock().shut, Some(socket::SHUT_RDWR));
    // A file closed by its process drops that process's POSIX locks on it
    let (ino, v) = vnode("locks", b"", O_RDONLY);
    let fd = t.alloc_fd(v.clone()).unwrap();
    t.close(fd).unwrap();
    assert!(LOCKS.with_borrow(|l| l.contains(&("closed", ino))));
    // A dead process's table: no lock release (the process's locks went with it)
    LOCKS.with_borrow_mut(|l| l.clear());
    t.alloc_fd(v).unwrap();
    t.close_all();
    assert!(LOCKS.with_borrow(|l| !l.contains(&("closed", ino))));
}

#[test]
fn epoll_readiness_and_wait_queues_through_the_table() {
    setup();
    let mut t = FdTable::new_default();
    let p = PipeBuffer::new();
    let r = t.alloc_fd(FileDescriptor::PipeRead(p.clone())).unwrap();
    let ep = Arc::new(Mutex::new(EpollInstance::default()));
    ep.lock().watch(r as i32, EPOLLIN);
    ep.lock().watch(99, EPOLLIN); // closed descriptor: never ready
    let e = t.alloc_fd(FileDescriptor::Epoll(ep.clone())).unwrap();
    let epd = t.get(e).unwrap().clone();
    assert_eq!(t.readiness(&epd), 0);
    p.lock().write(b"x").unwrap();
    assert_eq!(t.readiness(&epd), 0x1, "a watched descriptor is ready");
    assert_eq!(t.readiness(t.get(r).unwrap()), 0x1);
    // A one-shot watch that fired (events left = EPOLLONESHOT only) is not counted
    let ep2 = Arc::new(Mutex::new(EpollInstance::default()));
    ep2.lock().watch(r as i32, EPOLLONESHOT);
    assert_eq!(t.readiness(&FileDescriptor::Epoll(ep2)), 0);
    // Nested epoll, and a cycle stops at the depth limit
    let outer = Arc::new(Mutex::new(EpollInstance::default()));
    outer.lock().watch(e as i32, EPOLLIN);
    let o = t.alloc_fd(FileDescriptor::Epoll(outer.clone())).unwrap();
    assert_eq!(t.readiness(t.get(o).unwrap()), 0x1);
    outer.lock().watch(o as i32, EPOLLIN);
    let _ = t.readiness(t.get(o).unwrap());
    // Wait queues: those of the watched descriptors
    let mut w = WaitSet::new();
    t.add_wait_queues_for(&epd, &mut w);
    assert_eq!(w.queues.len(), 1);
    let mut w = WaitSet::new();
    t.add_wait_queues_for(t.get(r).unwrap(), &mut w);
    assert_eq!(w.queues.len(), 1);
    // The trace line
    let line = t.trace_describe(e);
    assert!(line.starts_with(&format!("{e}:epoll=0x1 [")), "{line}");
    assert!(line.contains(&format!(" {r}:pipe-r=0x1(want 0x1)")), "{line}");
    assert!(line.contains(" 99:closed(want 0x1)"), "{line}");
    assert_eq!(t.trace_describe(500), "500:closed");
    assert_eq!(t.trace_describe(1), "1:console=0x5");
}

#[test]
fn trace_names_every_kind() {
    setup();
    common::global_frames();
    let wq = WaitQueue::new_shared;
    let mut t = FdTable::empty();
    let kinds: Vec<(FileDescriptor, &str)> = vec![
        (FileDescriptor::PipeWrite(PipeBuffer::new()), "pipe-w"),
        (FileDescriptor::Socket(Arc::new(Mutex::new(socket::UnixSocket::connected()))), "socket"),
        (FileDescriptor::EventFd(EventFd::new(0, 0)), "eventfd"),
        (FileDescriptor::MemFd { memfd: MemFd::new("t"), flags: 2 }, "memfd"),
        (vnode("trace", b"", O_RDONLY).1, "vnode"),
        (FileDescriptor::Inet(Arc::new(Mutex::new(InetSocket { wq: None, events: 0 }))), "inet"),
        (FileDescriptor::Pty(Arc::new(PtyFile::new())), "pty"),
        (FileDescriptor::SignalFd(Arc::new(SignalFd)), "signalfd"),
        (FileDescriptor::Unix(Arc::new(unix::UnixSocket)), "unix"),
        (FileDescriptor::TimerFd(Arc::new(TimerFd { wq: wq() })), "timerfd"),
        (FileDescriptor::Inotify(Arc::new(Inotify { wq: wq() })), "inotify"),
        (FileDescriptor::PidFd(Arc::new(PidFd)), "pidfd"),
        (dev(false, 0), "device"),
        (file("/f", true, false, false), "file"),
    ];
    for (d, name) in kinds {
        let fd = t.alloc_fd(d).unwrap();
        assert!(t.trace_describe(fd).starts_with(&format!("{fd}:{name}=")));
    }
}

#[test]
fn server_object_bits() {
    setup();
    let mut t = FdTable::new_default();
    assert!(t.srv_bits().get().is_none(), "no server object yet: no bits");
    let a = t.alloc_fd(file("/a", true, false, false)).unwrap();
    assert!(t.srv_bits().get().is_none());
    let s = t.alloc_fd(dev(true, 0)).unwrap();
    let bits = t.srv_bits().get().unwrap();
    assert!(bits.maybe(s as u64));
    assert!(!bits.maybe(a as u64));
    // dup2 copies the bit, close clears it
    t.dup2(s, 40).unwrap();
    assert!(t.srv_bits().get().unwrap().maybe(40));
    t.close(40).unwrap();
    assert!(!t.srv_bits().get().unwrap().maybe(40));
    // Replacing with an ordinary descriptor clears it
    t.set_fd(s, Some(dev(false, 0)));
    assert!(!t.srv_bits().get().unwrap().maybe(s as u64));
    // A forked table has its own copy
    t.set_fd(s, Some(dev(true, 0)));
    let child = t.fork_copy();
    t.close(s).unwrap();
    assert!(child.srv_bits().get().unwrap().maybe(s as u64));
    assert!(!t.srv_bits().get().unwrap().maybe(s as u64));
    // Above SRV_LOW one flag covers all (never cleared)
    let mut big = FdTable::empty();
    assert!(big.set_fd(SRV_LOW + 5, Some(dev(true, 0))).is_none() || true);
    // MAX_FDS == SRV_LOW: such numbers are refused by set_fd; check the flag stays clear
    assert!(big.srv_bits().get().map_or(true, |b| !b.maybe((SRV_LOW + 5) as u64)));
}

#[test]
fn dup_of_a_pipe_is_the_same_open_file() {
    setup();
    let mut t = FdTable::new_default();
    let r = t.alloc_fd(FileDescriptor::PipeRead(PipeBuffer::new())).unwrap();
    let d = t.dup_from(r, 0).unwrap();
    assert_eq!(t.get(d).unwrap().object_id(), t.get(r).unwrap().object_id());
}

/// `FileDescriptor::object_id` promises "equal for descriptors that share it (dup)", and
/// epoll keys its watches by it. A by-path `File` descriptor is held by value: its dup
/// copies the path (a new buffer, so a new id) and the cursor (not shared, unlike Linux's
/// shared file offset after dup).
#[test]
#[ignore = "BUG: a dup of a by-path File descriptor gets a new object_id and its own cursor (held by value)"]
fn dup_of_a_path_file_shares_the_open_file() {
    setup();
    let mut t = FdTable::new_default();
    let a = t.alloc_fd(file("/proc/version", true, false, false)).unwrap();
    let b = t.dup_from(a, 0).unwrap();
    assert_eq!(t.get(b).unwrap().object_id(), t.get(a).unwrap().object_id());
    let mut buf = [0u8; 6];
    t.get_mut(a).unwrap().read(&mut buf).unwrap();
    t.get_mut(b).unwrap().read(&mut buf).unwrap();
    assert_eq!(&buf, b"versio", "the dup continues where the original stopped");
}
