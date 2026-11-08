//! Tests for `userfaultfd` (`src/compat/linux/userfaultfd.rs`): creation
//! and privilege rules, the UFFDIO_API handshake, registering ranges of the
//! caller's address space, fault delivery through `read()`, and resolving
//! faults with UFFDIO_COPY / UFFDIO_ZEROPAGE. QEMU live migration, CRIU and
//! some garbage collectors use this interface.
//!
//! The descriptor works on the real `Mm` (tests/vm.rs). A faulting thread
//! would sleep in `wait_fault`; here that sleep is the fake wait queue's
//! "would block" panic, caught by `catch_unwind`, after which the queued
//! fault can be read like a monitor thread would.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use hydra_hosttests::compat::linux::chardev::CharDevice;
use hydra_hosttests::compat::linux::userfaultfd::{active, sys_userfaultfd, wait_fault, Waited};
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;
use hydra_hosttests::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests::memory::vm::{Backing, BufferObject, Mm, PROT_READ, PROT_WRITE, USER_SPACE_START};
use spin::Mutex;

const UFFD_API: u64 = 0xAA;
const UFFD_USER_MODE_ONLY: u64 = 1;
const UFFD_FEATURE_THREAD_ID: u64 = 1 << 8;
const UFFDIO_API: u64 = 0xc018_aa3f;
const UFFDIO_REGISTER: u64 = 0xc020_aa00;
const UFFDIO_UNREGISTER: u64 = 0x8010_aa01;
const UFFDIO_WAKE: u64 = 0x8010_aa02;
const UFFDIO_COPY: u64 = 0xc028_aa03;
const UFFDIO_ZEROPAGE: u64 = 0xc020_aa04;
const MODE_MISSING: u64 = 1;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const CAP_SYS_PTRACE: u64 = 1 << 19;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EAGAIN: i64 = -11;
const EEXIST: i64 = -17;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOTTY: i64 = -25;

const P: u64 = 4096;
const RW: u32 = PROT_READ | PROT_WRITE;
const A: u64 = USER_SPACE_START + 0x4000_0000;

fn words(v: &[u64]) -> Vec<u8> {
    v.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn word(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap())
}

/// ioctl with an in/out argument block; returns (result, block afterwards).
fn ioctl(dev: &Arc<dyn CharDevice>, cmd: u64, arg: &[u64]) -> (i64, Vec<u8>) {
    let mut b = words(arg);
    let r = dev.ioctl(cmd, b.as_mut_ptr() as u64);
    (r, b)
}

fn device(fd: i64) -> Arc<dyn CharDevice> {
    fake::FDS.with_borrow(|f| match f.get(fd as usize) {
        Some(FileDescriptor::Device(d)) => d.clone(),
        _ => panic!("fd {fd} is not a device"),
    })
}

/// A user-mode-only descriptor with the API handshake done.
fn open(features: u64) -> Arc<dyn CharDevice> {
    let fd = sys_userfaultfd(UFFD_USER_MODE_ONLY | O_NONBLOCK);
    assert!(fd >= 0);
    let dev = device(fd);
    let (r, _) = ioctl(&dev, UFFDIO_API, &[UFFD_API, features, 0]);
    assert_eq!(r, 0);
    dev
}

/// Exclusive frame pool, an address space with `pages` anonymous pages at A,
/// installed as the current task's; leak check afterwards.
fn with_space(pages: u64, f: impl FnOnce(&Arc<Mutex<Mm>>)) {
    let _g = common::serial();
    common::global_frames();
    fake::reset();
    let before = FRAME_ALLOCATOR.lock().allocated_memory();
    {
        let mm = Arc::new(Mutex::new(Mm::new().unwrap()));
        mm.lock().mmap(A, pages * P, RW, false, true, false, Backing::Anon).unwrap();
        fake::TASK_MM.with_borrow_mut(|m| *m = Some(mm.clone()));
        f(&mm);
        fake::TASK_MM.with_borrow_mut(|m| *m = None);
        fake::FDS.with_borrow_mut(|f| f.open.clear());
    }
    assert_eq!(FRAME_ALLOCATOR.lock().allocated_memory(), before, "frames leaked");
}

fn register(dev: &Arc<dyn CharDevice>, start: u64, len: u64) -> (i64, Vec<u8>) {
    ioctl(dev, UFFDIO_REGISTER, &[start, len, MODE_MISSING, 0])
}

/// A faulting thread's view: enqueue the fault and go to sleep.
fn fault(id: u64, page: u64, write: bool) -> bool {
    matches!(catch_unwind(AssertUnwindSafe(|| wait_fault(id, page, write, false))), Err(_))
}

fn uffd_id(mm: &Arc<Mutex<Mm>>, addr: u64) -> u64 {
    mm.lock().find_vma(addr).unwrap().uffd
}

// ------------------------------------------------------------- creation

#[test]
fn creation_flags_and_privilege() {
    fake::reset();
    assert_eq!(sys_userfaultfd(0x10), EINVAL, "unknown flag");
    assert_eq!(sys_userfaultfd(0), EPERM, "kernel faults need CAP_SYS_PTRACE");
    fake::CAPS.set(Some(CAP_SYS_PTRACE));
    fake::IN_USERNS.set(true);
    assert_eq!(sys_userfaultfd(0), EPERM, "a user-namespace capability is not enough");
    fake::IN_USERNS.set(false);
    let fd = sys_userfaultfd(O_CLOEXEC);
    assert!(fd >= 0);
    fake::CAPS.set(Some(0));
    let user = sys_userfaultfd(UFFD_USER_MODE_ONLY);
    assert!(user >= 0, "UFFD_USER_MODE_ONLY needs no privilege");
    fake::FDS.with_borrow(|f| {
        assert!(f.open[&(fd as usize)].1, "O_CLOEXEC");
        assert!(!f.open[&(user as usize)].1);
    });
    assert_eq!(device(fd).path(), "anon_inode:[userfaultfd]");
    assert!(active(), "the fault path now checks for registered ranges");
    fake::FDS.with_borrow_mut(|f| f.limit = 0);
    assert_eq!(sys_userfaultfd(UFFD_USER_MODE_ONLY), EMFILE);
    fake::FDS.with_borrow_mut(|f| f.open.clear());
}

// ------------------------------------------------------------ handshake

#[test]
fn api_handshake() {
    fake::reset();
    let dev = device(sys_userfaultfd(UFFD_USER_MODE_ONLY));
    assert_eq!(ioctl(&dev, UFFDIO_REGISTER, &[A, P, MODE_MISSING, 0]).0, EINVAL, "API first");
    let (r, out) = ioctl(&dev, UFFDIO_API, &[0xAB, 0, 0]);
    assert_eq!(r, EINVAL, "wrong API version");
    assert_eq!(word(&out, 1), 0, "features cleared on failure");
    assert_eq!(ioctl(&dev, UFFDIO_API, &[UFFD_API, 1 << 3, 0]).0, EINVAL, "unsupported feature");
    let (r, out) = ioctl(&dev, UFFDIO_API, &[UFFD_API, UFFD_FEATURE_THREAD_ID, 0]);
    assert_eq!(r, 0);
    assert_eq!((word(&out, 0), word(&out, 1)), (UFFD_API, UFFD_FEATURE_THREAD_ID));
    assert_eq!(word(&out, 2), (1 << 0x00) | (1 << 0x01) | (1 << 0x3f), "REGISTER, UNREGISTER, API");
    assert_eq!(ioctl(&dev, UFFDIO_API, &[UFFD_API, 0, 0]).0, EINVAL, "only once");
    assert_eq!(dev.ioctl(0x1234, 0), ENOTTY);
    assert_eq!(dev.ioctl(UFFDIO_API, 0), -14, "EFAULT on a null argument");
    fake::FDS.with_borrow_mut(|f| f.open.clear());
}

// ------------------------------------------------------------- register

#[test]
fn register_marks_the_range() {
    with_space(4, |mm| {
        let dev = open(0);
        let (r, out) = register(&dev, A + P, 2 * P);
        assert_eq!(r, 0);
        assert_eq!(word(&out, 3), (1 << 2) | (1 << 3) | (1 << 4), "WAKE, COPY, ZEROPAGE available");
        let id = uffd_id(mm, A + P);
        assert_ne!(id, 0);
        assert_eq!(uffd_id(mm, A), 0, "outside the range untouched");
        assert_eq!(mm.lock().uffd_missing(A + P), Some(id));

        let (r, _) = ioctl(&dev, UFFDIO_UNREGISTER, &[A + P, 2 * P]);
        assert_eq!(r, 0);
        assert_eq!(uffd_id(mm, A + P), 0);
    });
}

#[test]
fn register_validation() {
    with_space(2, |mm| {
        let dev = open(0);
        assert_eq!(register(&dev, A + 1, P).0, EINVAL, "unaligned start");
        assert_eq!(register(&dev, A, 100).0, EINVAL, "unaligned length");
        assert_eq!(register(&dev, A, 0).0, EINVAL, "empty");
        assert_eq!(register(&dev, 0x7FFF_FFFF_F000, 2 * P).0, EINVAL, "past the user address space");
        assert_eq!(ioctl(&dev, UFFDIO_REGISTER, &[A, P, 2 /* WP */, 0]).0, EINVAL, "write-protect mode not offered");
        assert_eq!(register(&dev, A, 3 * P).0, EINVAL, "range must be fully mapped");

        mm.lock().mmap(A + 8 * P, P, RW, false, true, false, Backing::Object { obj: BufferObject::new(vec![0; 10].into_boxed_slice()), pgoff: 0 }).unwrap();
        assert_eq!(register(&dev, A + 8 * P, P).0, EINVAL, "anonymous memory only");

        let other = open(0);
        assert_eq!(register(&dev, A, P).0, 0);
        assert_eq!(register(&other, A, P).0, EBUSY, "already taken by another descriptor");

        fake::TASK_MM.with_borrow_mut(|m| *m = None);
        assert_eq!(register(&other, A + P, P).0, EINVAL, "no address space");
    });
}

#[test]
fn closing_the_descriptor_unregisters() {
    with_space(2, |mm| {
        let dev = open(0);
        register(&dev, A, 2 * P);
        let id = uffd_id(mm, A);
        fake::FDS.with_borrow_mut(|f| f.open.clear());
        drop(dev);
        assert_eq!(uffd_id(mm, A), 0, "ranges released on close");
        assert!(matches!(wait_fault(id, A, false, false), Waited::Proceed), "faults no longer wait");
    });
}

// ------------------------------------------------------- fault delivery

#[test]
fn faults_are_queued_and_read_as_uffd_msg() {
    with_space(2, |mm| {
        fake::IDS.set((4242, 4242));
        let dev = open(UFFD_FEATURE_THREAD_ID);
        register(&dev, A, 2 * P);
        let id = uffd_id(mm, A);
        let mut buf = [0u8; 64];
        assert_eq!(dev.read(&mut buf), EAGAIN, "nothing yet (nonblocking)");
        assert_eq!(dev.poll_events(), 0);

        assert!(fault(id, A + P, true), "the faulting thread sleeps");
        assert!(fault(id, A + P, false), "a second fault on the same page...");
        assert_eq!(dev.poll_events(), 0x41, "POLLIN | POLLRDNORM");
        assert_eq!(dev.read(&mut buf), 32, "...is reported once");
        assert_eq!(buf[0], 0x12, "UFFD_EVENT_PAGEFAULT");
        assert_eq!(word(&buf, 1), 1, "UFFD_PAGEFAULT_FLAG_WRITE");
        assert_eq!(word(&buf, 2), A + P, "fault address");
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 4242, "thread id (FEATURE_THREAD_ID)");
    });
}

#[test]
fn read_rules() {
    with_space(1, |mm| {
        let fd = sys_userfaultfd(UFFD_USER_MODE_ONLY);
        let dev = device(fd);
        assert_eq!(dev.read(&mut [0u8; 32]), EINVAL, "before UFFDIO_API");
        ioctl(&dev, UFFDIO_API, &[UFFD_API, 0, 0]);
        assert_eq!(dev.read(&mut [0u8; 31]), EINVAL, "buffer smaller than one message");
        assert!(catch_unwind(AssertUnwindSafe(|| dev.read(&mut [0u8; 32]))).is_err(), "blocking read sleeps");
        fake::SIGNAL_PENDING.set(true);
        assert_eq!(dev.read(&mut [0u8; 32]), EINTR);
        fake::SIGNAL_PENDING.set(false);
        register(&dev, A, P);
        fault(uffd_id(mm, A), A, false);
        let mut two = [0u8; 70];
        assert_eq!(dev.read(&mut two), 32, "only whole messages");
        assert_eq!(word(&two, 1), 0, "read fault");
        assert_eq!(&two[24..28], &[0; 4], "no thread id without the feature");
    });
}

#[test]
fn kernel_accesses_and_unknown_ids() {
    with_space(1, |mm| {
        let dev = open(0); // user-mode only
        register(&dev, A, P);
        let id = uffd_id(mm, A);
        assert!(matches!(wait_fault(id, A, false, true), Waited::Refuse), "kernel access refused (EFAULT)");
        assert!(matches!(wait_fault(987_654_321, A, false, false), Waited::Proceed));
        fake::SIGKILL_PENDING.set(true);
        assert!(matches!(wait_fault(id, A, false, false), Waited::Proceed), "a dying process does not wait");
    });
}

// ---------------------------------------------------------- resolution

#[test]
fn uffdio_copy_fills_missing_pages() {
    with_space(3, |mm| {
        let dev = open(0);
        register(&dev, A, 3 * P);
        let src: Vec<u8> = (0..2 * P).map(|i| (i % 251) as u8).collect();
        let (r, out) = ioctl(&dev, UFFDIO_COPY, &[A, src.as_ptr() as u64, 2 * P, 0, 0]);
        assert_eq!(r, 0);
        assert_eq!(word(&out, 4) as i64, (2 * P) as i64, "copy field: bytes copied");
        let mut m = mm.lock();
        let got = unsafe { std::slice::from_raw_parts(m.translate(A + P).unwrap().as_u64() as *const u8, P as usize) };
        assert_eq!(got, &src[P as usize..]);
        assert_eq!(m.uffd_missing(A), None);
        assert_eq!(m.uffd_missing(A + 2 * P), Some(m.find_vma(A).unwrap().uffd));
    });
}

#[test]
fn uffdio_copy_errors_and_partial_success() {
    with_space(2, |_| {
        let dev = open(0);
        register(&dev, A, 2 * P);
        let src = vec![1u8; 3 * P as usize];
        let s = src.as_ptr() as u64;
        assert_eq!(ioctl(&dev, UFFDIO_COPY, &[A + 1, s, P, 0, 0]).0, EINVAL, "unaligned dst");
        assert_eq!(ioctl(&dev, UFFDIO_COPY, &[A, s, 0, 0, 0]).0, EINVAL, "zero length");
        assert_eq!(ioctl(&dev, UFFDIO_COPY, &[A, s, P, 2, 0]).0, EINVAL, "unknown mode bit");
        assert_eq!(ioctl(&dev, UFFDIO_COPY, &[A, s, P, 0, 0]).0, 0);
        let (r, out) = ioctl(&dev, UFFDIO_COPY, &[A, s, P, 0, 0]);
        assert_eq!((r, word(&out, 4) as i64), (EEXIST, EEXIST), "page already present");
        let (r, out) = ioctl(&dev, UFFDIO_COPY, &[A + P, s, 2 * P, 0, 0]);
        assert_eq!((r, word(&out, 4)), (EAGAIN, P), "first page copied, then ran off the range");
        assert_eq!(ioctl(&dev, UFFDIO_COPY, &[A + 16 * P, s, P, 0, 0]).0, ENOENT, "not registered here");
    });
}

#[test]
fn uffdio_zeropage_and_wake() {
    with_space(1, |mm| {
        let dev = open(0);
        register(&dev, A, P);
        let (r, out) = ioctl(&dev, UFFDIO_ZEROPAGE, &[A, P, 0, 0]);
        assert_eq!((r, word(&out, 3)), (0, P));
        let mut m = mm.lock();
        let page = unsafe { std::slice::from_raw_parts(m.translate(A).unwrap().as_u64() as *const u8, P as usize) };
        assert!(page.iter().all(|&b| b == 0));
        drop(m);
        assert_eq!(ioctl(&dev, UFFDIO_WAKE, &[A, P]).0, 0);
        assert_eq!(ioctl(&dev, UFFDIO_WAKE, &[A + 1, P]).0, EINVAL);
    });
}

#[test]
fn unregister_needs_a_registered_address_space() {
    fake::reset();
    let dev = open(0);
    assert_eq!(ioctl(&dev, UFFDIO_UNREGISTER, &[A, P]).0, EINVAL);
    fake::FDS.with_borrow_mut(|f| f.open.clear());
}
