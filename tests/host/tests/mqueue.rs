//! Tests for POSIX message queues (`src/compat/linux/mqueue.rs`), driven
//! through `mqueue::dispatch` with the x86-64 syscall numbers (mq_open 240 …
//! mq_getsetattr 245). Queue names, attributes and messages are passed as
//! host pointers, as `copy_in`/`copy_out` allow with no current `Mm`.
//!
//! Queues live in one global table keyed by IPC namespace, so each test
//! runs in its own namespace. This binary counts peak heap use to catch
//! oversized kernel copies.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::sync::atomic::{AtomicIsize, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use hydra_hosttests::compat::linux::chardev::CharDevice;
use hydra_hosttests::compat::linux::mqueue::dispatch;
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const MQ_OPEN: u64 = 240;
const MQ_UNLINK: u64 = 241;
const MQ_SEND: u64 = 242;
const MQ_RECV: u64 = 243;
const MQ_NOTIFY: u64 = 244;
const MQ_GETSETATTR: u64 = 245;

const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const ENAMETOOLONG: i64 = -36;
const EMSGSIZE: i64 = -90;
const ETIMEDOUT: i64 = -110;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;
const SI_MESGQ: i32 = -3;
const CAP_DAC_OVERRIDE: u64 = 1 << 1;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

// ------------------------------------------------------- heap accounting

struct Counting;
static HEAP: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = HEAP.fetch_add(l.size() as isize, Ordering::Relaxed) + l.size() as isize;
        PEAK.fetch_max(now, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        HEAP.fetch_sub(l.size() as isize, Ordering::Relaxed);
        System.dealloc(p, l)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

// --------------------------------------------------------------- helpers

static NEXT: AtomicU64 = AtomicU64::new(5000);

/// Fresh fakes, own IPC namespace and pid, uid/gid 1000; returns the pid.
fn setup() -> u64 {
    fake::reset();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    fake::IPC_NS.set(n);
    fake::IDS.set((n, n));
    fake::CREDS.set((1000, 1000));
    fake::UID.set(1000);
    n
}

fn sys(num: u64, a: [u64; 6]) -> i64 {
    dispatch(num, a).expect("an mqueue syscall")
}

fn open_attr(name: &str, oflag: u64, mode: u64, attr: Option<(i64, i64)>) -> i64 {
    let c = CString::new(name).unwrap();
    let mut a = attr.map(|(m, s)| [0i64, m, s, 0, 0, 0, 0, 0]);
    let ap = a.as_mut().map_or(0, |a| a.as_mut_ptr() as u64);
    sys(MQ_OPEN, [c.as_ptr() as u64, oflag, mode, ap, 0, 0])
}

fn open(name: &str, oflag: u64) -> i64 {
    open_attr(name, oflag, 0o600, None)
}

fn unlink(name: &str) -> i64 {
    let c = CString::new(name).unwrap();
    sys(MQ_UNLINK, [c.as_ptr() as u64, 0, 0, 0, 0, 0])
}

fn send_t(fd: i64, data: &[u8], prio: u64, timeout: Option<[i64; 2]>) -> i64 {
    let mut ts = timeout;
    let tp = ts.as_mut().map_or(0, |t| t.as_mut_ptr() as u64);
    sys(MQ_SEND, [fd as u64, data.as_ptr() as u64, data.len() as u64, prio, tp, 0])
}

fn send(fd: i64, data: &[u8], prio: u64) -> i64 {
    send_t(fd, data, prio, None)
}

/// Returns (result, data, priority).
fn recv_t(fd: i64, len: usize, timeout: Option<[i64; 2]>) -> (i64, Vec<u8>, u32) {
    let mut buf = vec![0u8; len];
    let mut prio = [0u8; 4];
    let mut ts = timeout;
    let tp = ts.as_mut().map_or(0, |t| t.as_mut_ptr() as u64);
    let r = sys(MQ_RECV, [fd as u64, buf.as_mut_ptr() as u64, len as u64, prio.as_mut_ptr() as u64, tp, 0]);
    buf.truncate(r.max(0) as usize);
    (r, buf, u32::from_le_bytes(prio))
}

fn recv(fd: i64) -> (i64, Vec<u8>, u32) {
    recv_t(fd, 8192, None)
}

/// mq_getsetattr: returns (flags, maxmsg, msgsize, curmsgs).
fn attrs(fd: i64) -> (i64, i64, i64, i64) {
    let mut old = [0i64; 8];
    assert_eq!(sys(MQ_GETSETATTR, [fd as u64, 0, old.as_mut_ptr() as u64, 0, 0, 0]), 0);
    (old[0], old[1], old[2], old[3])
}

fn set_flags(fd: i64, flags: u64) -> i64 {
    let mut new = [flags as i64, 0, 0, 0, 0, 0, 0, 0];
    sys(MQ_GETSETATTR, [fd as u64, new.as_mut_ptr() as u64, 0, 0, 0, 0])
}

fn handle(fd: i64) -> Arc<dyn CharDevice> {
    fake::FDS.with_borrow(|f| match f.get(fd as usize) {
        Some(FileDescriptor::Device(d)) => d.clone(),
        _ => panic!("fd {fd} is not a device"),
    })
}

/// struct sigevent: value, signo, notify.
fn notify(fd: i64, how: i32, signo: i32, value: u64) -> i64 {
    let mut ev = [0u8; 64];
    ev[0..8].copy_from_slice(&value.to_le_bytes());
    ev[8..12].copy_from_slice(&signo.to_le_bytes());
    ev[12..16].copy_from_slice(&how.to_le_bytes());
    sys(MQ_NOTIFY, [fd as u64, ev.as_mut_ptr() as u64, 0, 0, 0, 0])
}

fn far_future() -> [i64; 2] {
    [4_000_000_000, 0]
}

// ------------------------------------------------------------- mq_open

#[test]
fn names_are_validated() {
    setup();
    assert_eq!(open("", O_RDWR | O_CREAT), ENOENT);
    assert_eq!(open("a/b", O_RDWR | O_CREAT), EINVAL, "glibc strips the leading slash");
    assert_eq!(open(".", O_RDWR | O_CREAT), EINVAL);
    assert_eq!(open("..", O_RDWR | O_CREAT), EINVAL);
    assert_eq!(open(&"q".repeat(256), O_RDWR | O_CREAT), ENAMETOOLONG);
    assert!(open(&"q".repeat(255), O_RDWR | O_CREAT) >= 0);
    assert_eq!(sys(MQ_OPEN, [0, O_RDWR | O_CREAT, 0o600, 0, 0, 0]), EFAULT);
}

#[test]
fn open_create_exclusive_and_modes() {
    setup();
    assert_eq!(open("q", O_RDWR), ENOENT);
    let fd = open_attr("q", O_RDWR | O_CREAT | O_CLOEXEC, 0o666, None);
    assert!(fd >= 0);
    assert_eq!(open("q", O_RDWR | O_CREAT | O_EXCL), EEXIST);
    assert!(open("q", O_RDONLY) >= 0, "existing queue opens without O_CREAT");
    assert_eq!(open("q", 3), EINVAL, "O_ACCMODE 3");
    let h = handle(fd);
    assert_eq!(h.path(), "/q");
    let st = h.stat();
    assert_eq!(st.st_mode, 0o100644, "regular-file type, umask 022 applied");
    assert_eq!((st.st_uid, st.st_gid), (1000, 1000));
    fake::FDS.with_borrow(|f| assert!(f.open[&(fd as usize)].1, "O_CLOEXEC"));
}

#[test]
fn default_and_custom_attributes() {
    setup();
    let fd = open("d", O_RDWR | O_CREAT);
    assert_eq!(attrs(fd), (0, 10, 8192, 0), "Linux defaults");
    let fd = open_attr("c", O_RDWR | O_CREAT | O_NONBLOCK, 0o600, Some((3, 64)));
    assert_eq!(attrs(fd), (O_NONBLOCK as i64, 3, 64, 0));
    for bad in [(0, 64), (3, 0), (-1, 64), (11, 64), (3, 8193)] {
        assert_eq!(open_attr("x", O_RDWR | O_CREAT, 0o600, Some(bad)), EINVAL, "{bad:?}");
    }
    fake::CAPS.set(Some(CAP_SYS_RESOURCE));
    assert!(open_attr("big", O_RDWR | O_CREAT, 0o600, Some((1000, 1 << 20))) >= 0, "raised limits");
    assert_eq!(open_attr("huge", O_RDWR | O_CREAT, 0o600, Some((65537, 64))), EINVAL, "hard limit");
}

#[test]
fn permissions_on_open() {
    let pid = setup();
    open_attr("p", O_RDWR | O_CREAT, 0o640, None);
    fake::CREDS.set((2000, 2000));
    assert_eq!(open("p", O_RDONLY), EACCES, "others: ---");
    fake::CREDS.set((2000, 1000));
    assert!(open("p", O_RDONLY) >= 0, "group may read");
    assert_eq!(open("p", O_WRONLY), EACCES, "but not write");
    fake::CREDS.set((2000, 2000));
    fake::PROCS.lock().insert(pid, fake::Process { groups: vec![1000], ..Default::default() });
    assert!(open("p", O_RDONLY) >= 0, "supplementary group");
    fake::PROCS.lock().remove(&pid);
    fake::CAPS.set(Some(CAP_DAC_OVERRIDE));
    assert!(open("p", O_RDWR) >= 0, "CAP_DAC_OVERRIDE");
}

#[test]
fn queue_limit_per_namespace() {
    setup();
    for i in 0..256 {
        assert!(open(&format!("q{i}"), O_RDWR | O_CREAT) >= 0, "queue {i}");
    }
    assert_eq!(open("one-more", O_RDWR | O_CREAT), ENOSPC);
    assert!(open("q7", O_RDWR) >= 0, "existing queues still open");
    fake::CAPS.set(Some(CAP_SYS_RESOURCE));
    assert!(open("one-more", O_RDWR | O_CREAT) >= 0);
}

#[test]
fn namespaces_are_isolated() {
    setup();
    let fd = open("shared-name", O_RDWR | O_CREAT);
    send(fd, b"hi", 0);
    fake::IPC_NS.set(NEXT.fetch_add(1, Ordering::Relaxed));
    assert_eq!(open("shared-name", O_RDWR), ENOENT);
    let other = open("shared-name", O_RDWR | O_CREAT | O_NONBLOCK);
    assert_eq!(recv(other).0, EAGAIN, "a different queue");
}

// ----------------------------------------------------------- mq_unlink

#[test]
fn unlink_rules() {
    setup();
    let fd = open("u", O_RDWR | O_CREAT);
    send(fd, b"still here", 0);
    fake::CREDS.set((2000, 2000));
    assert_eq!(unlink("u"), EACCES, "only the owner");
    fake::CREDS.set((1000, 1000));
    assert_eq!(unlink("u"), 0);
    assert_eq!(unlink("u"), ENOENT);
    assert_eq!(open("u", O_RDWR), ENOENT, "name is gone");
    assert_eq!(recv(fd).1, b"still here", "open descriptors keep the queue");
    open("r", O_RDWR | O_CREAT);
    fake::CREDS.set((0, 0));
    assert_eq!(unlink("r"), 0, "root may unlink any queue");
}

// ----------------------------------------------------- send / receive

#[test]
fn messages_come_out_by_priority_then_fifo() {
    setup();
    let fd = open("prio", O_RDWR | O_CREAT);
    for (d, p) in [("a", 1), ("b", 5), ("c", 1), ("d", 5), ("e", 0)] {
        assert_eq!(send(fd, d.as_bytes(), p), 0);
    }
    let order: Vec<(Vec<u8>, u32)> = (0..5).map(|_| recv(fd)).map(|(_, d, p)| (d, p)).collect();
    let expected = [("b", 5), ("d", 5), ("a", 1), ("c", 1), ("e", 0)];
    assert_eq!(order, expected.map(|(d, p)| (d.as_bytes().to_vec(), p)).to_vec());
}

#[test]
fn size_and_priority_limits() {
    setup();
    let fd = open_attr("s", O_RDWR | O_CREAT, 0o600, Some((2, 16)));
    assert_eq!(send(fd, &[0; 17], 0), EMSGSIZE);
    assert_eq!(send(fd, &[0; 16], 32768), EINVAL, "MQ_PRIO_MAX");
    assert_eq!(send(fd, b"", 32767), 0, "empty messages are fine");
    assert_eq!(recv_t(fd, 15, None).0, EMSGSIZE, "buffer must hold mq_msgsize");
    assert_eq!(recv_t(fd, 16, None), (0, vec![], 32767));
    assert_eq!(sys(MQ_SEND, [fd as u64, 0, 4, 0, 0, 0]), EFAULT);
}

#[test]
fn full_queue_behaviour() {
    setup();
    let fd = open_attr("full", O_RDWR | O_CREAT | O_NONBLOCK, 0o600, Some((2, 8)));
    send(fd, b"1", 0);
    send(fd, b"2", 0);
    assert_eq!(send(fd, b"3", 0), EAGAIN, "maxmsg reached");
    assert_eq!(attrs(fd).3, 2, "mq_curmsgs");
    set_flags(fd, 0);
    assert_eq!(send_t(fd, b"3", 0, Some([0, 0])), ETIMEDOUT, "absolute time in the past");
    assert_eq!(send_t(fd, b"3", 0, Some([0, 1_000_000_000])), EINVAL, "bad tv_nsec");
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(send_t(fd, b"3", 0, Some(far_future())), EINTR);
    fake::SIGNAL_PENDING.set(false);
    assert!(std::panic::catch_unwind(|| send(fd, b"3", 0)).is_err(), "blocking send sleeps");
}

#[test]
fn empty_queue_behaviour() {
    setup();
    let fd = open("empty", O_RDWR | O_CREAT | O_NONBLOCK);
    assert_eq!(recv(fd).0, EAGAIN);
    set_flags(fd, 0);
    assert_eq!(recv_t(fd, 8192, Some([0, 0])).0, ETIMEDOUT);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(recv(fd).0, EINTR);
    fake::SIGNAL_PENDING.set(false);
    assert!(std::panic::catch_unwind(|| recv(fd)).is_err(), "blocking receive sleeps");
}

#[test]
fn access_modes_and_bad_descriptors() {
    setup();
    let w = open("am", O_WRONLY | O_CREAT);
    let r = open("am", O_RDONLY | O_NONBLOCK);
    assert_eq!(recv(w).0, EBADF, "write-only handle");
    assert_eq!(send(r, b"x", 0), EBADF, "read-only handle");
    assert_eq!(send(w, b"x", 0), 0);
    assert_eq!(recv(r).1, b"x");
    assert_eq!(send(99, b"x", 0), EBADF, "not open");
    let efd = hydra_hosttests::compat::linux::eventfd::EventFd::new(0, 0);
    fake::FDS.with_borrow_mut(|f| f.install(50, FileDescriptor::EventFd(efd)));
    assert_eq!(send(50, b"x", 0), EBADF, "not a message queue");
    assert_eq!(handle(w).poll_events(), 0x104, "write side: POLLOUT only");
    assert_eq!(handle(r).poll_events(), 0, "read side, empty");
    send(w, b"y", 0);
    assert_eq!(handle(r).poll_events(), 0x41, "POLLIN");
}

#[test]
fn getsetattr_only_changes_o_nonblock() {
    setup();
    let fd = open("ga", O_RDWR | O_CREAT);
    assert_eq!(set_flags(fd, O_NONBLOCK), 0);
    assert_eq!(attrs(fd).0, O_NONBLOCK as i64);
    assert_eq!(set_flags(fd, O_NONBLOCK | 1), EINVAL);
}

// ----------------------------------------------------------- mq_notify

#[test]
fn signal_notification_fires_once_on_empty_to_nonempty() {
    let pid = setup();
    fake::PROCS.lock().insert(pid, fake::Process { groups: vec![], ..Default::default() });
    let fd = open("n", O_RDWR | O_CREAT | O_NONBLOCK);
    assert_eq!(notify(fd, SIGEV_SIGNAL, 10, 0xABCD), 0);
    send(fd, b"first", 0);
    send(fd, b"second", 0); // queue no longer empty: no notification
    let posted = fake::POSTED.with_borrow(|v| v.clone());
    assert_eq!(posted, vec![(pid, 10, SI_MESGQ, pid as u32, 1000, 0xABCD)]);
    recv(fd);
    recv(fd);
    send(fd, b"third", 0);
    assert_eq!(fake::POSTED.with_borrow(|v| v.len()), 1, "registration is one-shot");
    fake::PROCS.lock().remove(&pid);
}

#[test]
fn notification_registration_rules() {
    let pid = setup();
    let fd = open("nr", O_RDWR | O_CREAT);
    assert_eq!(notify(fd, SIGEV_SIGNAL, 0, 0), EINVAL);
    assert_eq!(notify(fd, SIGEV_SIGNAL, 65, 0), EINVAL);
    assert_eq!(notify(fd, 7, 10, 0), EINVAL, "unknown sigev_notify");
    assert_eq!(notify(fd, SIGEV_NONE, 0, 0), 0);
    fake::PROCS.lock().insert(pid, fake::Process { groups: vec![], ..Default::default() });
    let other = pid + 1_000_000;
    fake::IDS.set((other, other));
    assert_eq!(notify(fd, SIGEV_SIGNAL, 10, 0), EBUSY, "registered by a live process");
    assert_eq!(sys(MQ_NOTIFY, [fd as u64, 0, 0, 0, 0, 0]), 0, "unregistering someone else's is a no-op");
    fake::IDS.set((pid, pid));
    assert_eq!(sys(MQ_NOTIFY, [fd as u64, 0, 0, 0, 0, 0]), 0);
    fake::IDS.set((other, other));
    assert_eq!(notify(fd, SIGEV_SIGNAL, 10, 0), 0, "free again");
    fake::PROCS.lock().remove(&pid);
    fake::IDS.set((pid, pid));
    assert_eq!(notify(fd, SIGEV_SIGNAL, 12, 0), 0, "the old registrant exited: taken over");
}

/// glibc's SIGEV_THREAD helper receives a cookie on a netlink socket.
struct Sink(StdMutex<Vec<Vec<u8>>>);

impl CharDevice for Sink {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _w: &mut hydra_hosttests::task::wait::WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        "socket:[netlink]".into()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn deliver_notification(&self, data: &[u8]) -> bool {
        self.0.lock().unwrap().push(data.to_vec());
        true
    }
}

#[test]
fn thread_notification_sends_the_cookie() {
    setup();
    let fd = open("t", O_RDWR | O_CREAT | O_NONBLOCK);
    let sink = Arc::new(Sink(StdMutex::new(Vec::new())));
    fake::FDS.with_borrow_mut(|f| f.install(60, FileDescriptor::Device(sink.clone())));
    let mut cookie = [7u8; 32];
    assert_eq!(notify(fd, SIGEV_THREAD, 61, cookie.as_mut_ptr() as u64), EBADF, "sink fd not open");
    assert_eq!(notify(fd, SIGEV_THREAD, 60, cookie.as_mut_ptr() as u64), 0);
    send(fd, b"x", 0);
    let got = sink.0.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert_eq!(&got[0][..31], &[7u8; 31]);
    assert_eq!(got[0][31], 1, "NOTIFY_WOKENUP in the last byte");
}

#[test]
fn reading_the_descriptor_gives_the_status_line() {
    let pid = setup();
    let fd = open("st", O_RDWR | O_CREAT);
    notify(fd, SIGEV_SIGNAL, 10, 0);
    let mut buf = [0u8; 128];
    let n = handle(fd).read(&mut buf) as usize;
    let line = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert_eq!(line, format!("QSIZE:{:<10} NOTIFY:{:<5} SIGNO:{:<5} NOTIFY_PID:{:<6}\n", 0, 0, 10, pid));
    send(fd, b"12345", 0);
    let n = handle(fd).read(&mut buf) as usize;
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("QSIZE:5 "), "QSIZE counts message bytes");
    assert_eq!(handle(fd).stat().st_size, 5);
}

// ------------------------------------------------------------------ bugs

#[test]
#[ignore = "BUG: mq_timedsend copies the whole message into the kernel (copy_in of `len` bytes, \
            faulting in the user pages) before checking len against mq_msgsize, so a process can \
            make the kernel allocate any amount of memory with one call; Linux checks the size \
            first (src/compat/linux/mqueue.rs, mq_timedsend)"]
fn oversized_send_is_rejected_before_copying() {
    setup();
    let fd = open("big", O_RDWR | O_CREAT);
    let msg = vec![0u8; 16 << 20];
    let base = HEAP.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    assert_eq!(send(fd, &msg, 0), EMSGSIZE);
    let extra = PEAK.load(Ordering::Relaxed) - base;
    assert!(extra < 4 << 20, "rejecting a 16 MiB message took {} MiB of kernel heap", extra >> 20);
}
