//! Tests for the anonymous pipe ring buffer (`src/fs/pipe.rs`) and Linux
//! `eventfd` (`src/compat/linux/eventfd.rs`).
//!
//! Wait queues are faked: wake-ups are counted in `fake::WAKES`, and any path
//! that would put the caller to sleep panics with `fake::wait::WOULD_BLOCK`,
//! which [`blocks`] turns into a boolean.

use std::panic::{catch_unwind, AssertUnwindSafe};

use hydra_hosttests::compat::linux::eventfd::{self, EventFd, EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};
use hydra_hosttests::fake;
use hydra_hosttests::fs::pipe::{PipeBuffer, PIPE_BUFFER_SIZE};

const EAGAIN: i64 = -11;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOSYS: i64 = -38;
const ERESTARTSYS: i64 = -512;
const EPOLLIN: u32 = 0x1;
const EPOLLOUT: u32 = 0x4;

fn wakes() -> usize {
    fake::WAKES.get()
}

/// True if `f` tried to sleep on a wait queue.
fn blocks<R>(f: impl FnOnce() -> R) -> bool {
    // The panic message goes to this test's captured output, not the console.
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => false,
        Err(e) => {
            let msg = e.downcast_ref::<String>().cloned().unwrap_or_default();
            assert_eq!(msg, fake::wait::WOULD_BLOCK, "unexpected panic");
            true
        }
    }
}

fn u64_bytes(v: u64) -> [u8; 8] {
    v.to_ne_bytes()
}

// -------------------------------------------------------------------- pipe

#[test]
fn new_pipe_has_one_reader_and_writer() {
    let p = PipeBuffer::new();
    let p = p.lock();
    assert!(p.is_empty() && !p.is_full());
    assert_eq!((p.readers_count(), p.writers_count()), (1, 1));
    assert_eq!((p.available_read(), p.available_write()), (0, PIPE_BUFFER_SIZE));
    assert!(!p.read_nonblock && !p.write_nonblock);
}

#[test]
fn write_then_read_preserves_bytes() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    assert_eq!(p.write(b"hello, "), Ok(7));
    assert_eq!(p.write(b"pipe"), Ok(4));
    assert_eq!(p.available_read(), 11);
    let mut out = [0u8; 32];
    assert_eq!(p.read(&mut out), 11);
    assert_eq!(&out[..11], b"hello, pipe");
    assert!(p.is_empty());
}

#[test]
fn partial_reads_consume_in_order() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    p.write(b"abcdef").unwrap();
    let mut two = [0u8; 2];
    assert_eq!(p.read(&mut two), 2);
    assert_eq!(&two, b"ab");
    assert_eq!(p.read(&mut two), 2);
    assert_eq!(&two, b"cd");
    assert_eq!(p.available_read(), 2);
}

#[test]
fn read_from_empty_pipe_returns_zero_without_waking() {
    fake::reset();
    let p = PipeBuffer::new();
    let mut p = p.lock();
    let mut out = [0u8; 4];
    assert_eq!(p.read(&mut out), 0);
    assert_eq!(wakes(), 0);
}

#[test]
fn peek_does_not_consume() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    p.write(b"xyz").unwrap();
    let mut out = [0u8; 8];
    assert_eq!(p.peek(&mut out), 3);
    assert_eq!(&out[..3], b"xyz");
    assert_eq!(p.peek(&mut out[..1]), 1);
    assert_eq!(p.available_read(), 3);
    assert_eq!(p.read(&mut out), 3);
    assert_eq!(&out[..3], b"xyz");
}

#[test]
fn write_is_partial_when_nearly_full() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    let big = vec![7u8; PIPE_BUFFER_SIZE - 10];
    assert_eq!(p.write(&big), Ok(PIPE_BUFFER_SIZE - 10));
    assert_eq!(p.write(&[1u8; 25]), Ok(10), "only the free space is written");
    assert!(p.is_full());
    assert_eq!(p.available_write(), 0);
    assert_eq!(p.write(b"more"), Ok(0), "full pipe accepts nothing");
}

#[test]
fn ring_buffer_wraps_around_correctly() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    let mut sink = vec![0u8; PIPE_BUFFER_SIZE];
    // Move head/tail close to the end of the ring.
    p.write(&vec![0u8; PIPE_BUFFER_SIZE - 3]).unwrap();
    p.read(&mut sink);
    // This write straddles the wrap point.
    let data: Vec<u8> = (0..100u8).collect();
    assert_eq!(p.write(&data), Ok(100));
    let mut peeked = [0u8; 100];
    assert_eq!(p.peek(&mut peeked), 100);
    assert_eq!(peeked.to_vec(), data, "peek across the wrap");
    let mut out = [0u8; 100];
    assert_eq!(p.read(&mut out), 100);
    assert_eq!(out.to_vec(), data, "read across the wrap");
}

#[test]
fn streaming_many_chunks_through_the_ring() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    let mut written = Vec::new();
    let mut read = Vec::new();
    let mut buf = vec![0u8; 7_919];
    for i in 0..200u32 {
        let chunk: Vec<u8> = (0..5_003u32).map(|j| (i.wrapping_mul(31) ^ j) as u8).collect();
        let n = p.write(&chunk).unwrap();
        written.extend_from_slice(&chunk[..n]);
        let r = p.read(&mut buf);
        read.extend_from_slice(&buf[..r]);
    }
    while !p.is_empty() {
        let r = p.read(&mut buf);
        read.extend_from_slice(&buf[..r]);
    }
    assert_eq!(read, written);
}

#[test]
fn write_without_readers_is_broken_pipe() {
    let p = PipeBuffer::new();
    let mut p = p.lock();
    p.drop_reader();
    assert!(p.write(b"x").is_err());
    p.add_reader();
    assert_eq!(p.write(b"x"), Ok(1));
}

#[test]
fn closing_the_last_end_wakes_waiters() {
    fake::reset();
    let p = PipeBuffer::new();
    let mut p = p.lock();
    p.add_writer();
    p.drop_writer();
    assert_eq!(wakes(), 0, "one writer left: nobody to wake");
    p.drop_writer();
    assert_eq!(wakes(), 1, "readers must see EOF");
    p.drop_reader();
    assert_eq!(wakes(), 2, "writers must see EPIPE");
    p.drop_reader();
    assert_eq!(p.readers_count(), 0, "count does not underflow");
}

#[test]
fn data_transfer_wakes_the_other_side() {
    fake::reset();
    let p = PipeBuffer::new();
    let mut p = p.lock();
    p.write(b"a").unwrap();
    assert_eq!(wakes(), 1);
    p.read(&mut [0u8; 1]);
    assert_eq!(wakes(), 2);
    p.write(b"").unwrap();
    assert_eq!(wakes(), 2, "empty write wakes nobody");
}

// ---------------------------------------------------------- EventFd methods

#[test]
fn eventfd_counter_mode_reads_and_resets() {
    let e = EventFd::new(5, 0);
    let mut e = e.lock();
    e.write(&u64_bytes(10)).unwrap();
    let mut out = [0u8; 8];
    assert_eq!(e.read(&mut out), Ok(8));
    assert_eq!(u64::from_ne_bytes(out), 15);
    assert!(e.read(&mut out).is_err(), "counter is now 0: EAGAIN");
}

#[test]
fn eventfd_semaphore_mode_reads_one_at_a_time() {
    let e = EventFd::new(3, EFD_SEMAPHORE);
    let mut e = e.lock();
    let mut out = [0u8; 8];
    for left in [2, 1, 0] {
        e.read(&mut out).unwrap();
        assert_eq!(u64::from_ne_bytes(out), 1);
        assert_eq!(e.counter, left);
    }
    assert!(e.read(&mut out).is_err());
}

#[test]
fn eventfd_rejects_short_buffers_and_max_value() {
    let e = EventFd::new(1, 0);
    let mut e = e.lock();
    assert!(e.read(&mut [0u8; 7]).is_err());
    assert!(e.write(&[0u8; 7]).is_err());
    assert!(e.write(&u64_bytes(u64::MAX)).is_err(), "0xffffffffffffffff is reserved");
    assert_eq!(e.counter, 1);
}

#[test]
fn eventfd_counter_cannot_exceed_max_minus_one() {
    let e = EventFd::new(0, 0);
    let mut e = e.lock();
    e.write(&u64_bytes(u64::MAX - 1)).unwrap();
    assert!(e.write(&u64_bytes(1)).is_err(), "would overflow: EAGAIN");
    assert_eq!(e.counter, u64::MAX - 1);
    assert_eq!(e.write(&u64_bytes(0)), Ok(8), "adding zero always fits");
}

#[test]
fn eventfd_poll_events() {
    let e = EventFd::new(0, 0);
    assert_eq!(e.lock().poll_events(), EPOLLOUT);
    e.lock().counter = 1;
    assert_eq!(e.lock().poll_events(), EPOLLIN | EPOLLOUT);
    e.lock().counter = u64::MAX - 1;
    assert_eq!(e.lock().poll_events(), EPOLLIN, "full counter is not writable");
}

#[test]
fn eventfd_flags_are_decoded() {
    let e = EventFd::new(7, EFD_SEMAPHORE | EFD_NONBLOCK);
    let e = e.lock();
    assert!(e.semaphore && e.nonblocking);
    assert_eq!(e.counter, 7);
}

// --------------------------------------------------- eventfd syscall paths

#[test]
fn eventfd_read_syscall() {
    fake::reset();
    let e = EventFd::new(9, EFD_NONBLOCK);
    let mut buf = [0u8; 8];
    assert_eq!(eventfd::read(&e, &mut buf), 8);
    assert_eq!(u64::from_ne_bytes(buf), 9);
    assert_eq!(eventfd::read(&e, &mut buf), EAGAIN);
    assert_eq!(eventfd::read(&e, &mut [0u8; 4]), EINVAL);
    assert!(wakes() >= 1, "a successful read wakes blocked writers");
}

#[test]
fn eventfd_blocking_read_sleeps_until_signal_or_data() {
    fake::reset();
    let e = EventFd::new(0, 0);
    assert!(blocks(|| eventfd::read(&e, &mut [0u8; 8])), "empty blocking eventfd must sleep");

    fake::SIGNAL_PENDING.set(true);
    assert_eq!(eventfd::read(&e, &mut [0u8; 8]), ERESTARTSYS, "a pending signal interrupts the wait");
}

#[test]
fn eventfd_write_syscall() {
    fake::reset();
    let e = EventFd::new(0, EFD_NONBLOCK);
    assert_eq!(eventfd::write(&e, &u64_bytes(4)), 8);
    assert_eq!(e.lock().counter, 4);
    assert_eq!(eventfd::write(&e, &u64_bytes(u64::MAX)), EINVAL);
    assert_eq!(eventfd::write(&e, &[1, 2, 3]), EINVAL);
    assert_eq!(eventfd::write(&e, &u64_bytes(u64::MAX - 2)), EAGAIN, "would overflow");
    assert_eq!(e.lock().counter, 4);
}

#[test]
fn eventfd_blocking_write_sleeps_when_counter_is_full() {
    fake::reset();
    let e = EventFd::new(0, 0);
    e.lock().counter = u64::MAX - 1;
    assert!(blocks(|| eventfd::write(&e, &u64_bytes(1))));
    assert!(!blocks(|| eventfd::write(&e, &u64_bytes(0))));
}

#[test]
fn eventfd2_allocates_a_descriptor() {
    fake::reset();
    let fd = eventfd::sys_eventfd2(42, (EFD_CLOEXEC | EFD_SEMAPHORE) as u64);
    assert_eq!(fd, 3);
    fake::FDS.with_borrow(|f| {
        let (desc, cloexec) = &f.open[&3];
        assert!(*cloexec);
        let hydra_hosttests::fs::FileDescriptor::EventFd(e) = desc else { panic!("not an eventfd") };
        let e = e.lock();
        assert_eq!(e.counter, 42);
        assert!(e.semaphore && !e.nonblocking);
    });
    assert_eq!(eventfd::sys_eventfd2(0, 0), 4);
    fake::FDS.with_borrow(|f| assert!(!f.open[&4].1, "no CLOEXEC requested"));
}

#[test]
fn eventfd2_flag_validation() {
    fake::reset();
    assert_eq!(eventfd::sys_eventfd2(0, 0x1), 3);
    assert_eq!(eventfd::sys_eventfd2(0, 0x2), EINVAL, "unknown flag");
    assert_eq!(eventfd::sys_eventfd2(0, !0), ENOSYS, "Chromium's feature probe");
    assert_eq!(eventfd::sys_eventfd2(0, 0xFFFF_FFFF), ENOSYS);
}

#[test]
fn eventfd2_reports_emfile_when_table_is_full() {
    fake::reset();
    fake::FDS.with_borrow_mut(|f| f.limit = 3);
    assert_eq!(eventfd::sys_eventfd2(0, 0), EMFILE);
}

#[test]
fn eventfd2_truncates_initval_to_32_bits() {
    // Linux takes `unsigned int initval`.
    fake::reset();
    let fd = eventfd::sys_eventfd2(0x1_0000_0005, 0) as usize;
    fake::FDS.with_borrow(|f| {
        let hydra_hosttests::fs::FileDescriptor::EventFd(e) = &f.open[&fd].0 else { panic!("not an eventfd") };
        assert_eq!(e.lock().counter, 5);
    });
}
