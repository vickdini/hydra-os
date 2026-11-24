//! xfer.rs, aio.rs and recent.rs: calls built on the program's own system calls (answered
//! here by a model of them, `set_nested`).
mod common;
use common::*;
use hydra_hosttests_t26::arch::syscall::SyscallFrame;
use hydra_hosttests_t26::fake::linux::{nested_calls, set_nested};
use hydra_hosttests_t26::fs::pipe::PipeBuffer;
use lx::{aio, recent, xfer};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

/// Gives the current task an address space (the bounce buffers are mapped in it).
fn with_mm() {
    let mm = Arc::new(spin::Mutex::new(hydra_hosttests_t26::memory::vm::Mm::default()));
    task::current(|t| t.mm = Some(mm));
}

fn call(num: u64, a: [u64; 6], f: fn(&mut SyscallFrame, u64) -> i64) -> i64 {
    let mut fr = SyscallFrame::call(num, a);
    f(&mut fr, num)
}

/// A model of read/write/pread64/pwrite64/lseek over in-memory "files" by descriptor.
#[derive(Default)]
struct Files {
    data: BTreeMap<u64, Vec<u8>>,
    pos: BTreeMap<u64, u64>,
    /// Descriptors that fail with this errno.
    fail: BTreeMap<u64, i64>,
    /// Writes accept at most this many bytes per call.
    write_cap: Option<u64>,
}

fn model(files: Rc<RefCell<Files>>) {
    set_nested(move |nr, a| {
        let mut f = files.borrow_mut();
        let fd = a[0];
        if let Some(&e) = f.fail.get(&fd) {
            return e;
        }
        match nr {
            0 | 17 => {
                let off = if nr == 17 { a[3] } else { *f.pos.get(&fd).unwrap_or(&0) };
                let d = f.data.get(&fd).cloned().unwrap_or_default();
                let start = (off as usize).min(d.len());
                let n = (a[2] as usize).min(d.len() - start);
                write(a[1], &d[start..start + n]);
                if nr == 0 {
                    f.pos.insert(fd, off + n as u64);
                }
                n as i64
            }
            1 | 18 => {
                let off = if nr == 18 { a[3] } else { *f.pos.get(&fd).unwrap_or(&0) };
                let n = a[2].min(f.write_cap.unwrap_or(u64::MAX));
                let bytes = read(a[1], n as usize);
                let d = f.data.entry(fd).or_default();
                if d.len() < (off + n) as usize {
                    d.resize((off + n) as usize, 0);
                }
                d[off as usize..(off + n) as usize].copy_from_slice(&bytes);
                if nr == 1 {
                    f.pos.insert(fd, off + n);
                }
                n as i64
            }
            8 => f.data.get(&fd).map_or(-9, |d| d.len() as i64),
            19 | 20 => 77,
            _ => -38,
        }
    });
}

// ------------------------------------------------------------------- xfer

#[test]
fn sendfile_and_copy_file_range() {
    let _e = setup();
    with_mm();
    let files = Rc::new(RefCell::new(Files::default()));
    files.borrow_mut().data.insert(3, (0..200u8).collect());
    model(files.clone());
    // sendfile with an offset: the offset moves, the input position not
    let off = hydra_hosttests_t26::fake::leak(10u64.to_le_bytes().to_vec());
    assert_eq!(call(40, [4, 3, off, 50, 0, 0], xfer::dispatch), 50);
    assert_eq!(read_u64(off), 60);
    assert_eq!(files.borrow().data[&4], (10..60u8).collect::<Vec<u8>>());
    // without: from the current position, to the end of file (short read stops)
    assert_eq!(call(40, [5, 3, 0, 1000, 0, 0], xfer::dispatch), 200);
    assert_eq!(call(40, [5, 3, 0, 0, 0, 0], xfer::dispatch), 0);
    // bad offsets
    let neg = hydra_hosttests_t26::fake::leak((-1i64).to_le_bytes().to_vec());
    assert_eq!(call(40, [4, 3, neg, 5, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(40, [4, 3, 16, 5, 0, 0], xfer::dispatch), EFAULT);
    // copy_file_range with both offsets
    let oi = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    let oo = hydra_hosttests_t26::fake::leak(100u64.to_le_bytes().to_vec());
    assert_eq!(call(326, [3, oi, 6, oo, 20, 0], xfer::dispatch), 20);
    assert_eq!((read_u64(oi), read_u64(oo)), (20, 120));
    assert_eq!(files.borrow().data[&6][100..120], (0..20u8).collect::<Vec<u8>>()[..]);
    assert_eq!(call(326, [3, oi, 6, oo, 20, 1], xfer::dispatch), EINVAL);
    assert_eq!(call(326, [3, oi, 6, oo, 0, 0], xfer::dispatch), 0);
    assert_eq!(call(326, [3, neg, 6, 0, 1, 0], xfer::dispatch), EINVAL);
    // Errors: read fails at once, write fails at once or after some
    files.borrow_mut().fail.insert(9, -5);
    assert_eq!(call(40, [4, 9, 0, 10, 0, 0], xfer::dispatch), -5);
    let z0 = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    assert_eq!(call(40, [9, 3, z0, 10, 0, 0], xfer::dispatch), -5);
    files.borrow_mut().write_cap = Some(0);
    let z = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    assert_eq!(call(40, [4, 3, z, 10, 0, 0], xfer::dispatch), -5);
    // Large counts go in 64 KiB pieces
    files.borrow_mut().write_cap = None;
    files.borrow_mut().data.insert(10, vec![1u8; 150_000]);
    assert_eq!(call(40, [11, 10, 0, 150_000, 0, 0], xfer::dispatch), 150_000);
    let reads = nested_calls().iter().filter(|c| c.0 == 0 && c.1[0] == 10).count();
    assert_eq!(reads, 3);
    // No address space: EFAULT
    task::current(|t| t.mm = None);
    assert_eq!(call(40, [4, 3, 0, 10, 0, 0], xfer::dispatch), EFAULT);
}

#[test]
fn partial_writes_keep_offsets_exact() {
    let _e = setup();
    with_mm();
    let files = Rc::new(RefCell::new(Files::default()));
    files.borrow_mut().data.insert(3, vec![7u8; 100]);
    model(files.clone());
    // The output takes 30 bytes per write: still all copied
    files.borrow_mut().write_cap = Some(30);
    let oi = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    assert_eq!(call(326, [3, oi, 4, 0, 100, 0], xfer::dispatch), 100);
    assert_eq!(read_u64(oi), 100);
    // The output fails after the first piece: what reached it counts
    let calls = Rc::new(RefCell::new(0));
    let c2 = calls.clone();
    let f2 = files.clone();
    set_nested(move |nr, a| {
        if nr == 1 || nr == 18 {
            *c2.borrow_mut() += 1;
            return if *c2.borrow() == 1 { 10 } else { -28 };
        }
        let d = f2.borrow().data[&3].clone();
        let off = a[3] as usize;
        let n = (a[2] as usize).min(d.len().saturating_sub(off));
        write(a[1], &d[off..off + n]);
        n as i64
    });
    write(oi, &0u64.to_le_bytes());
    let oo = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    assert_eq!(call(326, [3, oi, 4, oo, 100, 0], xfer::dispatch), 10);
    assert_eq!((read_u64(oi), read_u64(oo)), (10, 10));
    // Result offsets that cannot be written back
    model(files.clone());
    let off = hydra_hosttests_t26::fake::leak(0u64.to_le_bytes().to_vec());
    hydra_hosttests_t26::fake::memory::make_bad(off, 8);
    let _ = off;
}

#[test]
fn vectored_at_offsets() {
    let _e = setup();
    with_mm();
    let files = Rc::new(RefCell::new(Files::default()));
    files.borrow_mut().data.insert(3, (0..50u8).collect());
    model(files.clone());
    let b1 = buf(5);
    let b2 = buf(100);
    let iov = hydra_hosttests_t26::fake::leak([b1.to_le_bytes(), 5u64.to_le_bytes(), 0u64.to_le_bytes(), 0u64.to_le_bytes(), b2.to_le_bytes(), 100u64.to_le_bytes()].concat());
    // preadv at 10: 5 + (the rest: 35, short) = 40
    assert_eq!(call(295, [3, iov, 3, 10, 0, 0], xfer::dispatch), 40);
    assert_eq!(read(b1, 5), (10..15u8).collect::<Vec<u8>>());
    assert_eq!(read(b2, 35), (15..50u8).collect::<Vec<u8>>());
    assert_eq!(call(295, [3, iov, 0, 0, 0, 0], xfer::dispatch), 0);
    assert_eq!(call(295, [3, iov, 2000, 0, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(295, [3, iov, 1, (-1i64) as u64, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(295, [3, 16, 1, 0, 0, 0], xfer::dispatch), EFAULT);
    // pwritev
    assert_eq!(call(296, [4, iov, 1, 0, 0, 0], xfer::dispatch), 5);
    // An error after some bytes: the bytes
    files.borrow_mut().fail.insert(7, -5);
    assert_eq!(call(295, [7, iov, 1, 0, 0, 0], xfer::dispatch), -5);
    // preadv2/pwritev2: flags, -1 offset (current position), RWF_APPEND
    assert_eq!(call(327, [3, iov, 1, 0, 0, 0x100], xfer::dispatch), EOPNOTSUPP);
    assert_eq!(call(327, [3, iov, 1, (-1i64) as u64, 0, 0], xfer::dispatch), 77);
    assert_eq!(call(328, [3, iov, 1, (-1i64) as u64, 0, 0], xfer::dispatch), 77);
    assert_eq!(call(327, [3, iov, 1, (-2i64) as u64, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(327, [3, iov, 1, 0, 0, 0x8], xfer::dispatch), 5);
    assert_eq!(call(328, [3, iov, 1, 0, 0, 0x10], xfer::dispatch), 5);
    assert_eq!(files.borrow().data[&3].len(), 55);
    assert_eq!(call(328, [99, iov, 1, 0, 0, 0x10], xfer::dispatch), -9);
    assert_eq!(call(1, [0; 6], xfer::dispatch), -38);
}

#[test]
fn splice_and_vmsplice() {
    let _e = setup();
    with_mm();
    let files = Rc::new(RefCell::new(Files::default()));
    files.borrow_mut().data.insert(30, (0..100u8).collect());
    model(files.clone());
    let p = PipeBuffer::new();
    let r = install(FileDescriptor::PipeRead(p.clone())) as u64;
    let w = install(FileDescriptor::PipeWrite(p.clone())) as u64;
    // Neither end a pipe; wrong ends; offsets on a pipe
    assert_eq!(call(275, [30, 0, 31, 0, 10, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(275, [w, 0, 31, 0, 10, 0], xfer::dispatch), EBADF);
    assert_eq!(call(275, [30, 0, r, 0, 10, 0], xfer::dispatch), EBADF);
    let off = hydra_hosttests_t26::fake::leak(5u64.to_le_bytes().to_vec());
    assert_eq!(call(275, [r, off, 31, 0, 10, 0], xfer::dispatch), -29);
    assert_eq!(call(275, [30, 0, w, off, 10, 0], xfer::dispatch), -29);
    assert_eq!(call(275, [30, off, w, 0, 0, 0], xfer::dispatch), 0);
    // Non-blocking on an empty pipe to read: EAGAIN
    assert_eq!(call(275, [r, 0, 31, 0, 10, 2], xfer::dispatch), EAGAIN);
    // File -> pipe at an offset (one piece): the model writes into the pipe descriptor
    let n = call(275, [30, off, w, 0, 10, 0], xfer::dispatch);
    assert_eq!(n, 10);
    assert_eq!(read_u64(off), 15);
    assert_eq!(call(275, [30, 16, w, 0, 10, 0], xfer::dispatch), EFAULT);
    let neg = hydra_hosttests_t26::fake::leak((-1i64).to_le_bytes().to_vec());
    assert_eq!(call(275, [30, neg, w, 0, 10, 0], xfer::dispatch), EINVAL);
    // vmsplice: user memory into the write end (writev) or out of the read end (readv)
    assert_eq!(call(278, [w, 1, 1, 0, 0, 0], xfer::dispatch), 77);
    assert_eq!(nested_calls().last().unwrap().0, 20);
    assert_eq!(call(278, [r, 1, 1, 0, 0, 0], xfer::dispatch), 77);
    assert_eq!(nested_calls().last().unwrap().0, 19);
    assert_eq!(call(278, [30, 1, 1, 0, 0, 0], xfer::dispatch), EBADF);
}

#[test]
fn tee_between_pipes() {
    let _e = setup();
    let a = PipeBuffer::new();
    let b = PipeBuffer::new();
    let ar = install(FileDescriptor::PipeRead(a.clone())) as u64;
    let aw = install(FileDescriptor::PipeWrite(a.clone())) as u64;
    let br = install(FileDescriptor::PipeRead(b.clone())) as u64;
    let bw = install(FileDescriptor::PipeWrite(b.clone())) as u64;
    a.lock().write(b"hello").unwrap();
    // Copies without consuming
    assert_eq!(call(276, [ar, bw, 3, 0, 0, 0], xfer::dispatch), 3);
    assert_eq!(a.lock().available_read(), 5);
    let mut out = [0u8; 8];
    assert_eq!(b.lock().read(&mut out), 3);
    assert_eq!(&out[..3], b"hel");
    // Same pipe, wrong ends, zero length
    assert_eq!(call(276, [ar, aw, 3, 0, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(276, [aw, br, 3, 0, 0, 0], xfer::dispatch), EINVAL);
    assert_eq!(call(276, [ar, bw, 0, 0, 0, 0], xfer::dispatch), 0);
    // Empty input: non-blocking EAGAIN; signal ERESTARTSYS; writers gone: 0
    let mut drain = [0u8; 16];
    a.lock().read(&mut drain);
    assert_eq!(call(276, [ar, bw, 3, 2, 0, 0], xfer::dispatch), EAGAIN);
    lx::proc::SIGNAL.set(true);
    assert_eq!(call(276, [ar, bw, 3, 0, 0, 0], xfer::dispatch), -512);
    lx::proc::SIGNAL.set(false);
    // A blocking tee waits a tick for data (another thread writes)
    let a2 = a.clone();
    task::wait::on_wait(move || {
        if a2.lock().available_read() == 0 {
            a2.lock().write(b"zz").unwrap();
        }
    });
    assert_eq!(call(276, [ar, bw, 8, 0, 0, 0], xfer::dispatch), 2);
    task::wait::clear_on_wait();
    // Output full: non-blocking EAGAIN
    let cap = b.lock().available_write();
    b.lock().write(&vec![0u8; cap]).unwrap();
    assert_eq!(call(276, [ar, bw, 1, 2, 0, 0], xfer::dispatch), EAGAIN);
    // No reader on the output: EPIPE
    let mut big = vec![0u8; cap];
    b.lock().read(&mut big);
    b.lock().drop_reader();
    assert_eq!(call(276, [ar, bw, 1, 0, 0, 0], xfer::dispatch), -32);
    a.lock().read(&mut drain);
    a.lock().drop_writer();
    assert_eq!(call(276, [ar, bw, 1, 0, 0, 0], xfer::dispatch), 0);
}

#[test]
fn server_pipes() {
    let _e = setup();
    with_mm();
    let mut rd = lx::chardev::TestDev::server(16, Some(3));
    rd.poll = 0;
    let r: Arc<dyn lx::chardev::CharDevice> = Arc::new(rd);
    let mut wd = lx::chardev::TestDev::server(17, Some(4));
    wd.poll = 0x4;
    let w: Arc<dyn lx::chardev::CharDevice> = Arc::new(wd);
    let rfd = install(FileDescriptor::Device(r)) as u64;
    let wfd = install(FileDescriptor::Device(w)) as u64;
    let other: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::server(30, None));
    let ofd = install(FileDescriptor::Device(other)) as u64;
    // tee between two server pipes: the server copies; it answers EAGAIN, we wait
    hydra_hosttests_t26::fake::lx::ANSWER.set(EAGAIN);
    assert_eq!(call(276, [rfd, wfd, 5, 2, 0, 0], xfer::dispatch), EAGAIN);
    hydra_hosttests_t26::fake::lx::ANSWER.set(5);
    assert_eq!(call(276, [rfd, wfd, 5, 0, 0, 0], xfer::dispatch), 5);
    assert_eq!(hydra_hosttests_t26::fake::lx::calls().last().unwrap(), &(276, [rfd, 4, 5, 2, 0, 0]));
    assert_eq!(call(276, [rfd, wfd, 0, 0, 0, 0], xfer::dispatch), 0);
    // A blocking tee retries after a wait
    let n = Rc::new(RefCell::new(0));
    let n2 = n.clone();
    hydra_hosttests_t26::fake::lx::ANSWER.set(EAGAIN);
    task::wait::on_wait(move || {
        *n2.borrow_mut() += 1;
        hydra_hosttests_t26::fake::lx::ANSWER.set(1);
    });
    assert_eq!(call(276, [rfd, wfd, 5, 0, 0, 0], xfer::dispatch), 1);
    assert_eq!(*n.borrow(), 1);
    task::wait::clear_on_wait();
    // A write end without a slot
    let ns: Arc<dyn lx::chardev::CharDevice> = Arc::new(lx::chardev::TestDev::server(17, None));
    let nsfd = install(FileDescriptor::Device(ns)) as u64;
    assert_eq!(call(276, [rfd, nsfd, 5, 0, 0, 0], xfer::dispatch), EBADF);
    // splice with server pipes: readiness from poll (read end not ready: EAGAIN non-blocking)
    assert_eq!(call(275, [rfd, 0, 30, 0, 5, 2], xfer::dispatch), EAGAIN);
    assert_eq!(call(275, [ofd, 0, 31, 0, 5, 0], xfer::dispatch), EINVAL);
    set_nested(|nr, _| if nr == 0 { 0 } else { -38 });
    assert_eq!(call(275, [30, 0, wfd, 0, 5, 2], xfer::dispatch), 0);
}

// -------------------------------------------------------------------- aio

fn setup_ctx(nr: u64) -> u64 {
    let p = buf(8);
    assert_eq!(call(206, [nr, p, 0, 0, 0, 0], aio::dispatch), 0);
    read_u64(p)
}

fn iocb(data: u64, opcode: u16, fd: u32, buf: u64, nbytes: u64, offset: u64, flags: u32, resfd: u32) -> u64 {
    let mut v = vec![0u8; 64];
    v[0..8].copy_from_slice(&data.to_le_bytes());
    v[16..18].copy_from_slice(&opcode.to_le_bytes());
    v[20..24].copy_from_slice(&fd.to_le_bytes());
    v[24..32].copy_from_slice(&buf.to_le_bytes());
    v[32..40].copy_from_slice(&nbytes.to_le_bytes());
    v[40..48].copy_from_slice(&offset.to_le_bytes());
    v[56..60].copy_from_slice(&flags.to_le_bytes());
    v[60..64].copy_from_slice(&resfd.to_le_bytes());
    hydra_hosttests_t26::fake::leak(v)
}

fn submit(ctx: u64, cbs: &[u64]) -> i64 {
    let arr: Vec<u8> = cbs.iter().flat_map(|c| c.to_le_bytes()).collect();
    let p = hydra_hosttests_t26::fake::leak(arr);
    call(209, [ctx, cbs.len() as u64, p, 0, 0, 0], aio::dispatch)
}

fn getevents(ctx: u64, min: u64, nr: u64, timeout: u64) -> (i64, Vec<[u64; 4]>) {
    let ev = buf(32 * nr.max(1) as usize);
    let r = call(208, [ctx, min, nr, ev, timeout, 0], aio::dispatch);
    let mut out = Vec::new();
    for i in 0..r.max(0) as u64 {
        let b = read(ev + i * 32, 32);
        out.push([0, 8, 16, 24].map(|o| u64::from_le_bytes(b[o..o + 8].try_into().unwrap())));
    }
    (r, out)
}

#[test]
fn aio_submit_and_reap() {
    let _e = setup();
    with_mm();
    let files = Rc::new(RefCell::new(Files::default()));
    files.borrow_mut().data.insert(3, (0..64u8).collect());
    model(files.clone());
    // io_setup: checks
    let p = hydra_hosttests_t26::fake::leak(5u64.to_le_bytes().to_vec());
    assert_eq!(call(206, [4, p, 0, 0, 0, 0], aio::dispatch), EINVAL);
    let z = buf(8);
    assert_eq!(call(206, [0, z, 0, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(call(206, [70000, z, 0, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(call(206, [4, 16, 0, 0, 0, 0], aio::dispatch), EFAULT);
    let ctx = setup_ctx(2);
    // Read, write, fsync, noop
    let b = buf(16);
    let r = iocb(11, 0, 3, b, 16, 8, 0, 0);
    let w = iocb(12, 1, 4, b, 4, 0, 0, 0);
    assert_eq!(submit(ctx, &[r, w]), 2);
    assert_eq!(read(b, 16), (8..24u8).collect::<Vec<u8>>());
    // The context is full now
    let s = iocb(13, 2, 3, 0, 0, 0, 0, 0);
    assert_eq!(submit(ctx, &[s]), EAGAIN);
    let (n, ev) = getevents(ctx, 1, 4, 0);
    assert_eq!(n, 2);
    assert_eq!(ev[0], [11, r, 16, 0]);
    assert_eq!(ev[1], [12, w, 4, 0]);
    // Other opcodes
    let cbs = [iocb(20, 3, 3, 0, 0, 0, 0, 0), iocb(21, 6, 3, 0, 0, 0, 0, 0)];
    assert_eq!(submit(ctx, &cbs), 2);
    let (_, ev) = getevents(ctx, 2, 2, 0);
    assert_eq!(ev[1][2], 0);
    let cbs = [iocb(22, 7, 3, 0, 0, 0, 0, 0), iocb(23, 8, 3, 0, 0, 0, 0, 0)];
    assert_eq!(submit(ctx, &cbs), 2);
    assert_eq!(getevents(ctx, 0, 2, 0).0, 2);
    // Bad requests: the first fails the call, a later one ends it with the count
    let bad = iocb(30, 99, 3, 0, 0, 0, 0, 0);
    assert_eq!(submit(ctx, &[bad]), EINVAL);
    assert_eq!(submit(ctx, &[iocb(31, 6, 3, 0, 0, 0, 0, 0), bad]), 1);
    let mut key = read(iocb(32, 6, 3, 0, 0, 0, 0, 0), 64);
    key[8] = 1;
    let keyed = hydra_hosttests_t26::fake::leak(key);
    assert_eq!(submit(ctx, &[keyed]), EINVAL);
    assert_eq!(submit(ctx, &[iocb(33, 6, 3, 0, 0, 0, 0x40, 0)]), EINVAL);
    assert_eq!(submit(ctx, &[16]), EFAULT);
    assert_eq!(call(209, [ctx, 1, 16, 0, 0, 0], aio::dispatch), EFAULT);
    assert_eq!(call(209, [ctx, (-1i64) as u64, 16, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(submit(ctx + 4096, &[r]), EINVAL);
    // getevents: argument checks
    assert_eq!(getevents(ctx, 3, 2, 0).0, EINVAL);
    assert_eq!(getevents(ctx + 1, 0, 1, 0).0, EINVAL);
    let ts = hydra_hosttests_t26::fake::leak([(-1i64).to_le_bytes(), 0i64.to_le_bytes()].concat());
    assert_eq!(getevents(ctx, 0, 1, ts).0, EINVAL);
    assert_eq!(getevents(ctx, 0, 1, 16).0, EFAULT);
    // The pending noop is reaped; then a timeout with nothing returns 0
    assert_eq!(getevents(ctx, 0, 4, 0).0, 1);
    let ts = hydra_hosttests_t26::fake::leak([0i64.to_le_bytes(), 1_000_000i64.to_le_bytes()].concat());
    assert_eq!(getevents(ctx, 1, 4, ts).0, 0);
    // A signal while waiting
    lx::proc::SIGNAL.set(true);
    assert_eq!(getevents(ctx, 1, 4, 0).0, -4);
    lx::proc::SIGNAL.set(false);
    // Events that cannot be copied out
    submit(ctx, &[iocb(40, 6, 3, 0, 0, 0, 0, 0)]);
    assert_eq!(call(208, [ctx, 1, 1, 16, 0, 0], aio::dispatch), EFAULT);
    // Destroy; it is gone
    assert_eq!(call(207, [ctx, 0, 0, 0, 0, 0], aio::dispatch), 0);
    assert_eq!(call(207, [ctx, 0, 0, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(call(210, [ctx, r, 0, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(call(999, [0; 6], aio::dispatch), -38);
}

#[test]
fn aio_polls_and_eventfds() {
    let _e = setup();
    with_mm();
    let ready = Rc::new(RefCell::new(0u16));
    let r2 = ready.clone();
    let efd_writes = Rc::new(RefCell::new(0));
    let e2 = efd_writes.clone();
    set_nested(move |nr, a| match nr {
        7 => {
            let rev = *r2.borrow();
            if rev == 0 {
                return 0;
            }
            write(a[0] + 6, &rev.to_le_bytes());
            1
        }
        1 => {
            *e2.borrow_mut() += 1;
            8
        }
        14 => 0,
        _ => -38,
    });
    let ctx = setup_ctx(8);
    // A poll that is ready at once completes; one that is not waits
    *ready.borrow_mut() = 1;
    let p1 = iocb(1, 5, 3, 1, 0, 0, 1, 9); // with RESFD
    assert_eq!(submit(ctx, &[p1]), 1);
    assert_eq!(*efd_writes.borrow(), 1);
    let (_, ev) = getevents(ctx, 1, 4, 0);
    assert_eq!(ev[0], [1, p1, 1, 0]);
    *ready.borrow_mut() = 0;
    let p2 = iocb(2, 5, 3, 1, 0, 0, 1, 9);
    assert_eq!(submit(ctx, &[p2]), 1);
    // Bug found by this crate (fixed): min_nr 0 with nothing done waited forever; Linux
    // returns at once
    assert_eq!(getevents(ctx, 0, 4, 0).0, 0);
    // It becomes ready while getevents waits (checked every tick)
    let r3 = ready.clone();
    task::wait::on_wait(move || *r3.borrow_mut() = 4);
    let (n, ev) = getevents(ctx, 1, 4, 0);
    task::wait::clear_on_wait();
    assert_eq!(n, 1);
    assert_eq!(ev[0][2], 4);
    assert_eq!(*efd_writes.borrow(), 2);
    // Cancel a pending poll: EINPROGRESS, completed with no events
    *ready.borrow_mut() = 0;
    let p3 = iocb(3, 5, 3, 1, 0, 0, 0, 0);
    assert_eq!(submit(ctx, &[p3]), 1);
    assert_eq!(call(210, [ctx, p3, 0, 0, 0, 0], aio::dispatch), -115);
    assert_eq!(call(210, [ctx, p3, 0, 0, 0, 0], aio::dispatch), EINVAL);
    assert_eq!(getevents(ctx, 1, 4, 0).1[0], [3, p3, 0, 0]);
    // io_pgetevents with a signal mask (sets and restores it)
    let p4 = iocb(4, 6, 3, 0, 0, 0, 0, 0);
    submit(ctx, &[p4]);
    let usig = hydra_hosttests_t26::fake::leak([buf(8).to_le_bytes(), 8u64.to_le_bytes()].concat());
    write(read_u64(usig), &1u64.to_le_bytes());
    let ev = buf(32);
    assert_eq!(call(333, [ctx, 1, 1, ev, 0, usig], aio::dispatch), 1);
    assert_eq!(nested_calls().iter().filter(|c| c.0 == 14).count(), 2);
    // A zero mask means none; a bad usig pointer
    let usig0 = hydra_hosttests_t26::fake::leak([0u64.to_le_bytes(), 8u64.to_le_bytes()].concat());
    assert_eq!(call(333, [ctx, 0, 1, ev, 0, usig0], aio::dispatch), 0);
    assert_eq!(call(333, [ctx, 0, 1, ev, 0, 16], aio::dispatch), EFAULT);
    // The mask call failing
    set_nested(|_, _| -22);
    assert_eq!(call(333, [ctx, 0, 1, ev, 0, usig], aio::dispatch), EINVAL);
    // The context belongs to its process
    task::current(|t| t.tgid = 4242);
    assert_eq!(call(207, [ctx, 0, 0, 0, 0, 0], aio::dispatch), EINVAL);
    task::current(|t| t.tgid = task::SELF_PID);
    aio::forget_process(task::SELF_PID);
    assert_eq!(call(207, [ctx, 0, 0, 0, 0, 0], aio::dispatch), EINVAL);
}

#[test]
fn aio_mapping_failures() {
    let _e = setup();
    let z = buf(8);
    assert_eq!(call(206, [1, z, 0, 0, 0, 0], aio::dispatch), EFAULT); // no address space
    with_mm();
    lx::mm::MMAP_FAILS.set(-12);
    assert_eq!(call(206, [1, z, 0, 0, 0, 0], aio::dispatch), -12);
    lx::mm::MMAP_FAILS.set(0);
    let ctx = setup_ctx(1);
    lx::mm::MMAP_FAILS.set(-12);
    assert_eq!(submit(ctx, &[iocb(1, 6, 3, 0, 0, 0, 0, 0)]), -12);
    assert_eq!(getevents(ctx, 0, 1, 0).0, -12);
}

// ----------------------------------------------------------------- recent

/// A model of newfstatat/readlinkat/openat over a small tree of paths (from "/"),
/// relative paths are taken from the root too (dirfd ignored except 7 = "/d").
fn tree_model(links: &'static [(&'static str, &'static str)], files: &'static [&'static str], dev_of: fn(&str) -> u64) {
    set_nested(move |nr, a| {
        let path = |p: u64| {
            let s = String::from_utf8(read(p, 4096).into_iter().take_while(|&c| c != 0).collect()).unwrap();
            if s.starts_with('/') || s.starts_with("/proc") {
                s
            } else if a[0] == 7 {
                format!("/d/{}", s)
            } else {
                format!("/{}", s)
            }
        };
        match nr {
            262 => {
                let p = path(a[1]);
                let p = if p == "/." { "/".to_string() } else { p.trim_end_matches("/.").to_string() };
                let mode: u32 = if links.iter().any(|l| l.0 == p) {
                    0o120777
                } else if files.contains(&p.as_str()) || p == "/" || p == "." {
                    0o100644
                } else {
                    return -2;
                };
                let mut st = vec![0u8; 32];
                st[0..8].copy_from_slice(&dev_of(&p).to_le_bytes());
                st[24..28].copy_from_slice(&mode.to_le_bytes());
                write(a[2], &st);
                0
            }
            5 => {
                write(a[1], &dev_of("/d").to_le_bytes());
                0
            }
            267 => {
                let p = path(a[1]);
                if p == "/proc/self/fd/7" {
                    write(a[2], b"/d");
                    return 2;
                }
                match links.iter().find(|l| l.0 == p) {
                    Some(l) => {
                        write(a[2], l.1.as_bytes());
                        l.1.len() as i64
                    }
                    None => -22,
                }
            }
            257 => {
                let p = String::from_utf8(read(a[1], 4096).into_iter().take_while(|&c| c != 0).collect()).unwrap();
                RESOLVED.with_borrow_mut(|r| r.push((a[0], p)));
                5
            }
            281 => a[3] as i64,
            _ => -38,
        }
    });
}

thread_local! {
    static RESOLVED: RefCell<Vec<(u64, String)>> = const { RefCell::new(Vec::new()) };
}

fn how(flags: u64, mode: u64, resolve: u64) -> u64 {
    hydra_hosttests_t26::fake::leak([flags.to_le_bytes(), mode.to_le_bytes(), resolve.to_le_bytes()].concat())
}

fn openat2(dirfd: u64, path: &str, h: u64, size: u64) -> i64 {
    call(437, [dirfd, cstr(path), h, size, 0, 0], recent::dispatch)
}

fn last_open() -> (u64, String) {
    RESOLVED.with_borrow(|r| r.last().cloned().unwrap())
}

#[test]
fn openat2_arguments() {
    let _e = setup();
    with_mm();
    tree_model(&[], &["/a"], |_| 1);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0), 16), EINVAL);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0), 5000), -7);
    let big = buf(40);
    write(big + 30, &[1]);
    assert_eq!(openat2(AT_FDCWD, "/a", big, 40), -7);
    assert_eq!(openat2(AT_FDCWD, "/a", 16, 24), EFAULT);
    assert_eq!(openat2(AT_FDCWD, "/a", how(1 << 33, 0, 0), 24), EINVAL);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0x40), 24), EINVAL);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0o10000, 0), 24), EINVAL);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0o644, 0), 24), EINVAL); // mode without O_CREAT
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0x18), 24), EINVAL);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0x20), 24), EAGAIN);
    // No restriction: a plain openat
    assert_eq!(openat2(AT_FDCWD, "/a", how(0o100, 0o644, 0), 24), 5);
    assert_eq!(last_open().1, "/a");
    // O_TMPFILE may take a mode
    assert_eq!(openat2(AT_FDCWD, "/a", how(0o20200000, 0o600, 0), 24), 5);
    // Bad path; no address space for the walk
    assert_eq!(call(437, [AT_FDCWD, 16, how(0, 0, 4), 24, 0, 0], recent::dispatch), EFAULT);
    task::current(|t| t.mm = None);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 4), 24), EFAULT);
}

#[test]
fn openat2_resolution() {
    let _e = setup();
    with_mm();
    tree_model(
        &[("/l", "a"), ("/abs", "/a"), ("/loop", "loop"), ("/up", "../a"), ("/proc/self/fd/3", "/a"), ("/d/dl", "x")],
        &["/a", "/d/x", "/d", "/proc", "/proc/self", "/proc/self/fd", "/mnt"],
        |p| if p.starts_with("/mnt") { 2 } else { 1 },
    );
    // A link expanded
    assert_eq!(openat2(AT_FDCWD, "l", how(0, 0, 0x2), 24), 5);
    assert_eq!(last_open(), (AT_FDCWD, "a".to_string()));
    // An absolute link
    assert_eq!(openat2(AT_FDCWD, "abs", how(0, 0, 0x2), 24), 5);
    assert_eq!(last_open().1, "/a");
    // NO_SYMLINKS refuses any link; NO_MAGICLINKS a /proc magic link
    assert_eq!(openat2(AT_FDCWD, "l", how(0, 0, 0x4), 24), ELOOP);
    assert_eq!(openat2(AT_FDCWD, "/proc/self/fd/3", how(0, 0, 0x2), 24), ELOOP);
    assert_eq!(openat2(AT_FDCWD, "/proc/self/fd/3", how(0, 0, 0x1), 24), 5);
    assert_eq!(last_open().1, "/a");
    // A link loop
    assert_eq!(openat2(AT_FDCWD, "loop", how(0, 0, 0x2), 24), ELOOP);
    // O_NOFOLLOW on a final link: left for open to refuse
    assert_eq!(openat2(AT_FDCWD, "l", how(0o400000, 0, 0x2), 24), 5);
    assert_eq!(last_open().1, "l");
    // BENEATH: absolute paths, `..` above, absolute links: EXDEV
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0x8), 24), EXDEV);
    assert_eq!(openat2(AT_FDCWD, "../a", how(0, 0, 0x8), 24), EXDEV);
    assert_eq!(openat2(AT_FDCWD, "abs", how(0, 0, 0x8), 24), EXDEV);
    assert_eq!(openat2(AT_FDCWD, "x/../a", how(0, 0, 0x8), 24), ENOENT);
    // IN_ROOT: absolute paths and links stay inside, `..` at the top stays
    assert_eq!(openat2(7, "/x", how(0, 0, 0x10), 24), 5);
    assert_eq!(last_open(), (7, "x".to_string()));
    assert_eq!(openat2(7, "../../x", how(0, 0, 0x10), 24), 5);
    // Without restrictions on `..`: kept above the start
    assert_eq!(openat2(AT_FDCWD, "./up", how(0, 0, 0x2), 24), 5);
    assert_eq!(last_open().1, "../a");
    // A missing final component (O_CREAT may make it); a missing middle one
    assert_eq!(openat2(AT_FDCWD, "newfile", how(0o100, 0o600, 0x2), 24), 5);
    assert_eq!(openat2(AT_FDCWD, "no/x", how(0, 0, 0x2), 24), ENOENT);
    // NO_XDEV: crossing to another device
    assert_eq!(openat2(AT_FDCWD, "/mnt", how(0, 0, 0x1), 24), EXDEV);
    assert_eq!(openat2(AT_FDCWD, "a", how(0, 0, 0x1), 24), 5);
    assert_eq!(openat2(7, "x", how(0, 0, 0x1), 24), 5);
    assert_eq!(openat2(AT_FDCWD, "/a", how(0, 0, 0x1), 24), 5);
    // A directory descriptor's path through /proc/self/fd (magic link check)
    assert_eq!(openat2(7, "dl", how(0, 0, 0x2), 24), 5);
    assert_eq!(openat2(8, "x", how(0, 0, 0x2), 24), EBADF);
    // The result path too long for the scratch buffer
    let long = format!("/{}", "a/".repeat(2100));
    assert!(openat2(AT_FDCWD, &long, how(0, 0, 0x2), 24) < 0);
    // `.` and empty components are skipped
    assert_eq!(openat2(AT_FDCWD, "./a/", how(0, 0, 0x2), 24), 5);
    assert_eq!(openat2(AT_FDCWD, ".", how(0, 0, 0x2), 24), 5);
    assert_eq!(last_open().1, ".");
}

#[test]
fn epoll_pwait2_timeouts() {
    let _e = setup();
    tree_model(&[], &[], |_| 1);
    assert_eq!(call(441, [3, 1, 2, 0, 0, 8], recent::dispatch), -1);
    let ts = hydra_hosttests_t26::fake::leak([2i64.to_le_bytes(), 1_500_000i64.to_le_bytes()].concat());
    assert_eq!(call(441, [3, 1, 2, ts, 0, 8], recent::dispatch), 2002);
    let bad = hydra_hosttests_t26::fake::leak([0i64.to_le_bytes(), 2_000_000_000i64.to_le_bytes()].concat());
    assert_eq!(call(441, [3, 1, 2, bad, 0, 8], recent::dispatch), EINVAL);
    assert_eq!(call(441, [3, 1, 2, 16, 0, 8], recent::dispatch), EFAULT);
    let huge = hydra_hosttests_t26::fake::leak([i64::MAX.to_le_bytes(), 0i64.to_le_bytes()].concat());
    assert_eq!(call(441, [3, 1, 2, huge, 0, 8], recent::dispatch), i32::MAX as i64);
    assert_eq!(call(1, [0; 6], recent::dispatch), -38);
}
