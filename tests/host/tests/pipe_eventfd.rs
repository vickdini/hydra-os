//! Tests for the anonymous pipe ring buffer (`src/fs/pipe.rs`) and Linux
//! `eventfd` (`src/compat/linux/eventfd.rs`).
//!
//! Wait queues are faked: wake-ups are counted in `fake::WAKES`, and any path
//! that would put the caller to sleep panics with `fake::wait::WOULD_BLOCK`,
//! which [`blocks`] turns into a boolean.


use hydra_hosttests::fake;
use hydra_hosttests::fs::pipe::{PipeBuffer, PIPE_BUFFER_SIZE};


fn wakes() -> usize {
    fake::WAKES.get()
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

// --------------------------------------------------- eventfd syscall paths
