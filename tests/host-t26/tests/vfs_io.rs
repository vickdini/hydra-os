//! vfs.rs: stream I/O (pipes, terminals, devices, sockets), ioctl and extended attributes.
mod common;
use common::*;
use hydra_hosttests_t26::fs::pipe::PipeBuffer;
use std::sync::Arc;

fn rd(fd: i64, n: usize) -> (i64, Vec<u8>) {
    let b = buf(n);
    let r = sys(0, &[fd as u64, b, n as u64]);
    (r, if r > 0 { read(b, r as usize) } else { Vec::new() })
}

fn wr(fd: i64, data: &[u8]) -> i64 {
    let b = hydra_hosttests_t26::fake::leak(data.to_vec());
    sys(1, &[fd as u64, b, data.len() as u64])
}

#[test]
fn pipe_read_and_write() {
    let _e = setup();
    let p = PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(p.clone()));
    let w = install(FileDescriptor::PipeWrite(p.clone()));
    assert_eq!(wr(w, b"hello"), 5);
    assert_eq!(rd(r, 3), (3, b"hel".to_vec()));
    assert_eq!(rd(r, 10), (2, b"lo".to_vec()));
    // Wrong ends
    assert_eq!(rd(w, 1).0, EBADF);
    assert_eq!(wr(r, b"x"), EBADF);
    // Empty and non-blocking: EAGAIN; a signal: ERESTARTSYS
    p.lock().read_nonblock = true;
    assert_eq!(rd(r, 1).0, EAGAIN);
    p.lock().read_nonblock = false;
    lx::proc::SIGNAL.set(true);
    assert_eq!(rd(r, 1).0, -512);
    lx::proc::SIGNAL.set(false);
    // A blocking read waits for a writer (another thread writes during the wait)
    let p2 = p.clone();
    task::wait::on_wait(move || {
        p2.lock().write(b"late").unwrap();
    });
    assert_eq!(rd(r, 8), (4, b"late".to_vec()));
    task::wait::clear_on_wait();
    // All writers gone: end of file
    p.lock().drop_writer();
    assert_eq!(rd(r, 4).0, 0);
}

#[test]
fn pipe_write_without_readers_and_when_full() {
    let _e = setup();
    let p = PipeBuffer::new();
    let w = install(FileDescriptor::PipeWrite(p.clone()));
    p.lock().drop_reader();
    assert_eq!(wr(w, b"x"), -32);
    assert_eq!(lx::proc::POSTED.with_borrow(|v| v.clone()), vec![(task::SELF_PID, task::SELF_PID, 13)]);
    // Full pipe: non-blocking EAGAIN, partial writes count
    let p = PipeBuffer::new();
    let w = install(FileDescriptor::PipeWrite(p.clone()));
    let cap = p.lock().available_write();
    let big = vec![7u8; cap + 10];
    p.lock().write_nonblock = true;
    assert_eq!(wr(w, &big), cap as i64);
    assert_eq!(wr(w, b"y"), EAGAIN);
    p.lock().write_nonblock = false;
    lx::proc::SIGNAL.set(true);
    assert_eq!(wr(w, b"y"), -512);
    lx::proc::SIGNAL.set(false);
    // A blocking writer waits for room (a reader drains during the wait)
    let p2 = p.clone();
    task::wait::on_wait(move || {
        let mut b = vec![0u8; 4096];
        p2.lock().read(&mut b);
    });
    assert_eq!(wr(w, b"after"), 5);
}

#[test]
fn vectored_stream_io() {
    let _e = setup();
    let p = PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(p.clone()));
    let w = install(FileDescriptor::PipeWrite(p.clone()));
    let a = hydra_hosttests_t26::fake::leak(b"ab".to_vec());
    let b = hydra_hosttests_t26::fake::leak(b"cde".to_vec());
    let iov = buf(48);
    write(iov, &[a.to_le_bytes(), 2u64.to_le_bytes(), b.to_le_bytes(), 3u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes()].concat());
    assert_eq!(sys(20, &[w as u64, iov, 3]), 5);
    let o1 = buf(3);
    let o2 = buf(8);
    write(iov, &[o1.to_le_bytes(), 3u64.to_le_bytes(), o2.to_le_bytes(), 8u64.to_le_bytes()].concat());
    assert_eq!(sys(19, &[r as u64, iov, 2]), 5);
    assert_eq!(read(o1, 3), b"abc");
    assert_eq!(read(o2, 2), b"de");
    // A bad iovec array; a bad buffer in it
    assert_eq!(sys(19, &[r as u64, 16, 2]), EFAULT);
    write(iov, &[16u64.to_le_bytes(), 3u64.to_le_bytes()].concat());
    assert_eq!(sys(20, &[w as u64, iov, 1]), EFAULT);
    // Partial success is reported
    write(iov, &[a.to_le_bytes(), 2u64.to_le_bytes(), 16u64.to_le_bytes(), 3u64.to_le_bytes()].concat());
    assert_eq!(sys(20, &[w as u64, iov, 2]), 2);
}

#[test]
fn terminal_and_other_streams() {
    let _e = setup();
    let c = install(FileDescriptor::ConsoleOut);
    assert_eq!(wr(c, b"hi"), 2);
    assert_eq!(lx::tty::OUT.with_borrow(|o| o.clone()), b"hi");
    let ci = install(FileDescriptor::ConsoleIn);
    assert_eq!(rd(ci, 4), (1, b"\n".to_vec()));
    lx::tty::set_nonblock(true);
    assert_eq!(rd(ci, 4).0, EAGAIN);
    // Pty, Unix socket, internet socket, eventfd, timerfd, signalfd
    let pty = lx::pty::PtyFile::named("/dev/pts/0", false);
    let pf = install(FileDescriptor::Pty(pty.clone()));
    assert_eq!(wr(pf, b"ls\n"), 3);
    assert_eq!(*pty.written.lock(), b"ls\n");
    assert_eq!(rd(pf, 4), (1, b"p".to_vec()));
    let u = install(FileDescriptor::Unix(lx::unix::UnixSocket::new(1)));
    assert_eq!(rd(u, 8).0, 2);
    assert_eq!(wr(u, b"abc"), 3);
    let s = install(FileDescriptor::Inet(Arc::new(spin::Mutex::new(Default::default()))));
    assert_eq!(rd(s, 8).0, 3);
    assert_eq!(wr(s, b"abcd"), 4);
    let e = lx::eventfd::EventFd::new(0);
    let ef = install(FileDescriptor::EventFd(e.clone()));
    assert_eq!(wr(ef, &5u64.to_le_bytes()), 8);
    assert_eq!(rd(ef, 8), (8, 5u64.to_le_bytes().to_vec()));
    let t = install(FileDescriptor::TimerFd(Arc::new(Default::default())));
    assert_eq!(rd(t, 8).0, 8);
    assert_eq!(wr(t, b"12345678"), EINVAL);
    let sg = install(FileDescriptor::SignalFd(Arc::new(Default::default())));
    assert_eq!(rd(sg, 128).0, EAGAIN);
    assert_eq!(wr(sg, b"x"), EINVAL);
    // Not streams: pool files are not ours
    memfs::mkfile("/f", b"abc");
    let f = open("/f", O_RDONLY);
    assert_eq!(sys_opt(0, &[f as u64, buf(4), 4]), None);
    assert_eq!(sys_opt(0, &[777, buf(4), 4]), None);
}

#[test]
fn device_streams() {
    let _e = setup();
    let dev = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    dev.input.lock().extend(b"input");
    let d: Arc<dyn lx::chardev::CharDevice> = dev.clone();
    let fd = install(FileDescriptor::Device(d));
    assert_eq!(rd(fd, 3), (3, b"inp".to_vec()));
    assert_eq!(wr(fd, b"out"), 3);
    // writev to a device is one write (a FUSE reply: header and data together)
    let a = hydra_hosttests_t26::fake::leak(b"head".to_vec());
    let b = hydra_hosttests_t26::fake::leak(b"body".to_vec());
    let iov = buf(32);
    write(iov, &[a.to_le_bytes(), 4u64.to_le_bytes(), b.to_le_bytes(), 4u64.to_le_bytes()].concat());
    assert_eq!(sys(20, &[fd as u64, iov, 2]), 8);
    assert_eq!(*dev.output.lock(), b"outheadbody");
    write(iov, &[a.to_le_bytes(), 4u64.to_le_bytes(), 16u64.to_le_bytes(), 4u64.to_le_bytes()].concat());
    assert_eq!(sys(20, &[fd as u64, iov, 2]), EFAULT);
    // A linux-server object: the call is forwarded as it is
    let s: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::server(16, None));
    let sfd = install(FileDescriptor::Device(s));
    hydra_hosttests_t26::fake::lx::ANSWER.set(12);
    assert_eq!(sys(0, &[sfd as u64, 1, 2]), 12);
    assert_eq!(hydra_hosttests_t26::fake::lx::calls()[0].0, 0);
}

#[test]
fn notify_calls_reaching_the_kernel_are_refused() {
    // wave9 G9-C: inotify instances and fanotify groups are vfs-server's; what reaches the
    // kernel: init with vfs-server down (ENOSYS), a descriptor that is no instance
    let _e = setup();
    assert_eq!(lx::inotify::sys_init1(0), -38);
    assert_eq!(lx::inotify::sys_add_watch(700, 0, 2), EBADF);
    assert_eq!(lx::inotify::sys_rm_watch(700, 1), EBADF);
    memfs::mkfile("/f", b"");
    let f = open("/f", O_RDONLY);
    assert_eq!(lx::inotify::sys_add_watch(f as u64, 0, 2), EINVAL);
    assert_eq!(lx::inotify::sys_rm_watch(f as u64, 1), EINVAL);
    assert_eq!(lx::fanotify::dispatch(300, [0; 6]), -38);
    assert_eq!(lx::fanotify::dispatch(301, [700, 0, 0, 0, 0, 0]), EBADF);
    assert_eq!(lx::fanotify::dispatch(301, [f as u64, 0, 0, 0, 0, 0]), EINVAL);
}

#[test]
fn ioctl_requests() {
    let _e = setup();
    let ioctl = |fd: i64, req: u64, arg: u64| sys(16, &[fd as u64, req, arg]);
    memfs::mkfile("/f", b"0123456789");
    let f = open("/f", O_RDONLY);
    // FIOCLEX / FIONCLEX on anything
    assert_eq!(ioctl(f, 0x5451, 0), 0);
    assert!(task::with_current_fds_mut(|t| t.cloexec(f as usize)));
    assert_eq!(ioctl(f, 0x5450, 0), 0);
    assert!(!task::with_current_fds_mut(|t| t.cloexec(f as usize)));
    // FIONREAD on a regular file: bytes left; FIONBIO; FIOASYNC; others ENOTTY
    sys(8, &[f as u64, 4, 0]);
    let n = buf(4);
    assert_eq!(ioctl(f, 0x541B, n), 0);
    assert_eq!(read_i32(n), 6);
    let on = hydra_hosttests_t26::fake::leak(1u32.to_le_bytes().to_vec());
    let off = hydra_hosttests_t26::fake::leak(0u32.to_le_bytes().to_vec());
    assert_eq!(ioctl(f, 0x5421, on), 0);
    assert_eq!(vnode(f).lock().flags & O_NONBLOCK as u32, O_NONBLOCK as u32);
    assert_eq!(ioctl(f, 0x5421, off), 0);
    assert_eq!(vnode(f).lock().flags & O_NONBLOCK as u32, 0);
    assert_eq!(ioctl(f, 0x5421, 16), EFAULT);
    assert_eq!(ioctl(f, 0x5452, 0), 0);
    assert_eq!(ioctl(f, 0x5401, 0), -25);
    memfs::mkdir_p("/d");
    let d = open("/d", O_RDONLY);
    assert_eq!(ioctl(d, 0x541B, n), -25);
    // Other requests on a pool file are not ours
    assert_eq!(sys_opt(16, &[f as u64, 0x1234, 0]), None);
    assert_eq!(ioctl(999, 0x5401, 0), EBADF);
    // The console's requests go to the terminal
    let c = install(FileDescriptor::ConsoleOut);
    assert_eq!(ioctl(c, 0x5413, 0), 0);
    assert_eq!(lx::tty::IOCTLS.with_borrow(|v| v.clone()), vec![(0x5413, 0)]);
    // A Unix socket
    let u = install(FileDescriptor::Unix(lx::unix::UnixSocket::new(1)));
    assert_eq!(ioctl(u, 0x541B, n), 0);
    assert_eq!(ioctl(u, 0x5401, n), -25);
    // A device: FIONBIO, its own requests, a server object's
    let dev = Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let dd: Arc<dyn lx::chardev::CharDevice> = dev.clone();
    let dfd = install(FileDescriptor::Device(dd));
    assert_eq!(ioctl(dfd, 0x5421, on), 0);
    assert!(dev.nb.load(std::sync::atomic::Ordering::Relaxed));
    assert_eq!(ioctl(dfd, 0x5421, 16), EFAULT);
    assert_eq!(ioctl(dfd, 0xC0DE, 5), 0);
    assert_eq!(*dev.ioctls.lock(), vec![(0xC0DE, 5)]);
    let s: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::server(30, None));
    let sfd = install(FileDescriptor::Device(s));
    hydra_hosttests_t26::fake::lx::ANSWER.set(3);
    assert_eq!(ioctl(sfd, 0x1234, 0), 3);
    // A pty: FIONBIO, its own requests (TIOCGPTPEER opens the peer)
    let p = lx::pty::PtyFile::named("/dev/ptmx", false);
    let pfd = install(FileDescriptor::Pty(p.clone()));
    assert_eq!(ioctl(pfd, 0x5421, on), 0);
    assert!(p.get_nonblock());
    assert_eq!(ioctl(pfd, 0x5421, 16), EFAULT);
    let peer = ioctl(pfd, 0x5441, O_CLOEXEC);
    assert!(peer > pfd);
    assert!(matches!(desc(peer), Some(FileDescriptor::Pty(_))));
    assert!(task::with_current_fds_mut(|t| t.cloexec(peer as usize)));
    // An internet socket
    let sock = Arc::new(spin::Mutex::new(lx::inet::InetSocket { nonblock: false, pending: 9 }));
    let ifd2 = install(FileDescriptor::Inet(sock.clone()));
    assert_eq!(ioctl(ifd2, 0x5421, on), 0);
    assert!(sock.lock().nonblock);
    assert_eq!(ioctl(ifd2, 0x5421, 16), EFAULT);
    assert_eq!(ioctl(ifd2, 0x541B, n), 0);
    assert_eq!(read_i32(n), 9);
    assert_eq!(ioctl(ifd2, 0x541B, 16), EFAULT);
    assert_eq!(ioctl(ifd2, 0x8907, 0), 0);
    assert_eq!(ioctl(ifd2, 0x5401, 0), -25);
    assert_eq!(ioctl(ifd2, 0x8000, 0), EINVAL);
    // Pipes
    let pipe = PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(pipe.clone()));
    let w = install(FileDescriptor::PipeWrite(pipe.clone()));
    pipe.lock().write(b"abc").unwrap();
    assert_eq!(ioctl(r, 0x541B, n), 0);
    assert_eq!(read_i32(n), 3);
    assert_eq!(ioctl(r, 0x5421, on), 0);
    assert!(pipe.lock().read_nonblock);
    assert_eq!(ioctl(w, 0x5421, on), 0);
    assert!(pipe.lock().write_nonblock);
    assert_eq!(ioctl(w, 0x5421, 16), EFAULT);
    assert_eq!(ioctl(w, 0x5452, 0), 0);
    assert_eq!(ioctl(w, 0x5401, 0), -25);
    assert_eq!(sys_opt(16, &[w as u64, 0x1234, 0]), None);
}

fn setx(path: &str, name: &str, value: &[u8], flags: u64) -> i64 {
    let v = hydra_hosttests_t26::fake::leak(value.to_vec());
    sys(188, &[cstr(path), cstr(name), v, value.len() as u64, flags])
}

fn getx(path: &str, name: &str, size: u64) -> (i64, Vec<u8>) {
    let b = buf(size.max(1) as usize);
    let r = sys(191, &[cstr(path), cstr(name), b, size]);
    (r, if r > 0 && size > 0 { read(b, r as usize) } else { Vec::new() })
}

#[test]
fn user_xattrs() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    assert_eq!(setx("/f", "user.comment", b"hello", 0), 0);
    assert_eq!(memfs::xattr(f, b"user.comment").unwrap(), b"hello");
    assert_eq!(getx("/f", "user.comment", 64), (5, b"hello".to_vec()));
    assert_eq!(getx("/f", "user.comment", 0).0, 5);
    assert_eq!(getx("/f", "user.comment", 2).0, ERANGE);
    assert_eq!(getx("/f", "user.none", 64).0, ENODATA);
    // XATTR_CREATE / XATTR_REPLACE
    assert_eq!(setx("/f", "user.comment", b"x", 1), EEXIST);
    assert_eq!(setx("/f", "user.other", b"x", 2), ENODATA);
    assert_eq!(setx("/f", "user.comment", b"x", 8), EINVAL);
    // list and remove
    let b = buf(128);
    let n = sys(194, &[cstr("/f"), b, 128]);
    assert_eq!(read(b, n as usize), b"user.comment\0");
    assert_eq!(sys(194, &[cstr("/f"), b, 0]), n);
    assert_eq!(sys(194, &[cstr("/f"), b, 3]), ERANGE);
    assert_eq!(sys(197, &[cstr("/f"), cstr("user.comment")]), 0);
    assert_eq!(sys(197, &[cstr("/f"), cstr("user.comment")]), ENODATA);
    // Names: empty, too long, unknown namespace, bare namespace
    assert_eq!(setx("/f", "", b"x", 0), ERANGE);
    assert_eq!(setx("/f", &format!("user.{}", "n".repeat(260)), b"x", 0), ERANGE);
    assert_eq!(setx("/f", "other.x", b"x", 0), EOPNOTSUPP);
    assert_eq!(setx("/f", "user.", b"x", 0), EINVAL);
    // Empty value; too large a value; bad pointers
    assert_eq!(setx("/f", "user.empty", b"", 0), 0);
    let v = buf(8);
    assert_eq!(sys(188, &[cstr("/f"), cstr("user.big"), v, 70000, 0]), -7);
    assert_eq!(sys(188, &[cstr("/f"), cstr("user.bad"), 16, 4, 0]), EFAULT);
    assert_eq!(sys(188, &[cstr("/f"), 16, v, 4, 0]), EFAULT);
    assert_eq!(sys(191, &[cstr("/f"), cstr("user.empty"), 16, 4]), 0);
    setx("/f", "user.z", b"zz", 0);
    assert_eq!(sys(191, &[cstr("/f"), cstr("user.z"), 16, 4]), EFAULT);
    // Missing file
    assert_eq!(setx("/none", "user.a", b"x", 0), ENOENT);
}

#[test]
fn xattr_namespaces_and_permissions() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chmod(f, 0o644);
    let l = memfs::mklink("/l", "/f");
    // user.* only on files and directories
    assert_eq!(sys(189, &[cstr("/l"), cstr("user.x"), cstr("v"), 1, 0]), EPERM);
    assert_eq!(sys(192, &[cstr("/l"), cstr("user.x"), buf(8), 8]), ENODATA);
    let _ = l;
    // trusted.*: CAP_SYS_ADMIN only; hidden from lists without it
    assert_eq!(setx("/f", "trusted.t", b"1", 0), 0);
    assert_eq!(setx("/f", "user.u", b"1", 0), 0);
    become_user(1000);
    assert_eq!(setx("/f", "trusted.t", b"1", 0), EPERM);
    assert_eq!(getx("/f", "trusted.t", 8).0, ENODATA);
    let b = buf(128);
    let n = sys(194, &[cstr("/f"), b, 128]);
    assert_eq!(read(b, n as usize), b"user.u\0");
    // user.* needs write permission to set, read to get
    assert_eq!(setx("/f", "user.u", b"2", 0), EACCES);
    assert_eq!(getx("/f", "user.u", 8), (1, b"1".to_vec()));
    memfs::chmod(f, 0o600);
    assert_eq!(getx("/f", "user.u", 8).0, EACCES);
    // security.*: anyone reads; writing needs CAP_SYS_ADMIN (CAP_SETFCAP for capability)
    memfs::chmod(f, 0o644);
    assert_eq!(setx("/f", "security.selinux", b"x", 0), EPERM);
    task::set_caps(1 << 21);
    assert_eq!(setx("/f", "security.selinux", b"x", 0), 0);
    assert_eq!(getx("/f", "security.selinux", 8).0, 1);
    let mut cap = 0x0200_0000u32.to_le_bytes().to_vec();
    cap.extend_from_slice(&[0u8; 16]);
    assert_eq!(setx("/f", "security.capability", &cap, 0), EPERM);
    task::set_caps(1 << 31);
    assert_eq!(setx("/f", "security.capability", &cap, 0), 0);
    assert_eq!(setx("/f", "security.capability", b"short", 0), EINVAL);
    let mut bad = 0x0200_0002u32.to_le_bytes().to_vec();
    bad.extend_from_slice(&[0u8; 16]);
    assert_eq!(setx("/f", "security.capability", &bad, 0), EINVAL);
    let mut v3 = 0x0300_0000u32.to_le_bytes().to_vec();
    v3.extend_from_slice(&[0u8; 20]);
    assert_eq!(setx("/f", "security.capability", &v3, 0), 0);
    // system.* other than ACLs
    assert_eq!(setx("/f", "system.other", b"x", 0), EOPNOTSUPP);
    assert_eq!(getx("/f", "system.other", 8).0, ENODATA);
    assert_eq!(sys(197, &[cstr("/f"), cstr("system.other")]), ENODATA);
}

#[test]
fn access_labels_attribute() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    task::set_caps(1 << 21);
    assert_eq!(setx("/f", "security.hydra.labels", b"secret", 0), 0);
    assert_eq!(hydra_hosttests_t26::fake::counter("labels_changed"), 1);
    assert_eq!(sys(197, &[cstr("/f"), cstr("security.hydra.labels")]), 0);
    assert_eq!(hydra_hosttests_t26::fake::counter("labels_changed"), 2);
    let _ = f;
}

#[test]
fn xattr_by_descriptor_and_at_calls() {
    let _e = setup();
    let f = memfs::mkfile("/d/f", b"");
    let fd = open("/d/f", O_RDONLY);
    let v = hydra_hosttests_t26::fake::leak(b"val".to_vec());
    assert_eq!(sys(190, &[fd as u64, cstr("user.a"), v, 3, 0]), 0);
    assert_eq!(memfs::xattr(f, b"user.a").unwrap(), b"val");
    let b = buf(16);
    assert_eq!(sys(193, &[fd as u64, cstr("user.a"), b, 16]), 3);
    assert_eq!(sys(196, &[fd as u64, b, 16]), 7);
    assert_eq!(sys(199, &[fd as u64, cstr("user.a")]), 0);
    // An O_PATH descriptor; not a pool file; no descriptor
    let p = open("/d/f", O_PATH);
    assert_eq!(sys(193, &[p as u64, cstr("user.a"), b, 16]), EBADF);
    let c = install(FileDescriptor::ConsoleIn);
    assert_eq!(sys(193, &[c as u64, cstr("user.a"), b, 16]), EOPNOTSUPP);
    assert_eq!(sys(193, &[999, cstr("user.a"), b, 16]), EBADF);
    // setxattrat / getxattrat with struct xattr_args { value, size, flags }
    let args = buf(16);
    write(args, &[v.to_le_bytes().to_vec(), 3u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec()].concat());
    assert_eq!(sys(463, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b"), args, 16]), 0);
    assert_eq!(memfs::xattr(f, b"user.b").unwrap(), b"val");
    let out = buf(16);
    write(args, &[out.to_le_bytes().to_vec(), 16u32.to_le_bytes().to_vec(), 0u32.to_le_bytes().to_vec()].concat());
    assert_eq!(sys(464, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b"), args, 16]), 3);
    assert_eq!(read(out, 3), b"val");
    // getxattrat with flags: EINVAL; a short args struct; bad at-flags
    write(args, &[out.to_le_bytes().to_vec(), 16u32.to_le_bytes().to_vec(), 1u32.to_le_bytes().to_vec()].concat());
    assert_eq!(sys(464, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b"), args, 16]), EINVAL);
    assert_eq!(sys(464, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b"), args, 8]), EINVAL);
    assert_eq!(sys(464, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b"), 16, 16]), EFAULT);
    assert_eq!(sys(465, &[AT_FDCWD, cstr("/d/f"), 0x4, b, 16]), EINVAL);
    // listxattrat, removexattrat; by descriptor with AT_EMPTY_PATH
    assert_eq!(sys(465, &[AT_FDCWD, cstr("/d/f"), 0, b, 16]), 7);
    assert_eq!(sys(465, &[fd as u64, 0, 0x1000, b, 16]), 7);
    assert_eq!(sys(465, &[fd as u64, 0, 0, b, 16]), ENOENT);
    assert_eq!(sys(465, &[999, 0, 0x1000, b, 16]), EBADF);
    assert_eq!(sys(466, &[AT_FDCWD, cstr("/d/f"), 0, cstr("user.b")]), 0);
    // The working directory with an empty path
    task::with_current_fds_mut(|t| t.cwd_ino = memfs::lookup("/d").unwrap());
    assert_eq!(sys(465, &[AT_FDCWD, 0, 0x1000, b, 16]), 0);
    // A missing path; a bad path pointer
    assert_eq!(sys(465, &[AT_FDCWD, cstr("/none"), 0, b, 16]), ENOENT);
    assert_eq!(sys(465, &[AT_FDCWD, 16, 0, b, 16]), EFAULT);
    // Symlinks: followed unless AT_SYMLINK_NOFOLLOW
    memfs::mklink("/d/l", "f");
    assert_eq!(sys(466, &[AT_FDCWD, cstr("/d/l"), 0x100, cstr("user.zz")]), EPERM);
}

#[test]
fn acl_attributes_go_to_acl() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    // An access ACL with a named user and a mask
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [(1u16, 6u16, 0u32), (2, 6, 1000), (4, 4, 0), (0x10, 6, 0), (0x20, 4, 0)] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&perm.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    assert_eq!(setx("/f", "system.posix_acl_access", &acl, 0), 0);
    assert_eq!(memfs::attr(f).mode, 0o100664);
    assert!(memfs::xattr(f, b"system.posix_acl_access").is_some());
    assert_eq!(getx("/f", "system.posix_acl_access", 64).0, acl.len() as i64);
    assert_eq!(sys(197, &[cstr("/f"), cstr("system.posix_acl_access")]), 0);
    assert!(memfs::xattr(f, b"system.posix_acl_access").is_none());
    // A default ACL on a file
    assert_eq!(setx("/f", "system.posix_acl_default", &acl, 0), EACCES);
}
