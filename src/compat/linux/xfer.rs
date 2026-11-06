//! # Data transfer system calls
//!
//! `preadv`, `pwritev`, `preadv2`, `pwritev2`, `sendfile`, `copy_file_range`, `splice`,
//! `tee` and `vmsplice`. They are built on the program's own `read`/`write`/`pread64`/
//! `pwrite64`/`readv`/`writev` calls ([`super::nested`]), so every kind of descriptor
//! behaves exactly as it does for those (blocking, `O_NONBLOCK`, end of file, sockets).
//! Data that moves between two descriptors passes through a temporary anonymous mapping
//! in the caller's address space; Hydra has no page cache to move pages through, so these
//! calls copy (as Linux does too when it cannot splice pages).

use alloc::sync::Arc;
use spin::Mutex;

use super::vfs::{copy_in, copy_out};
use crate::arch::syscall::SyscallFrame;
use crate::fs::pipe::PipeBuffer;
use crate::fs::FileDescriptor;

const NR_READ: u64 = 0;
const NR_WRITE: u64 = 1;
const NR_LSEEK: u64 = 8;
const NR_PREAD64: u64 = 17;
const NR_PWRITE64: u64 = 18;
const NR_READV: u64 = 19;
const NR_WRITEV: u64 = 20;

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const EOPNOTSUPP: i64 = -95;

/// Bytes moved per step between two descriptors.
const CHUNK: u64 = 64 * 1024;
/// Largest `iovec` count (`UIO_MAXIOV`).
const IOV_MAX: u64 = 1024;
/// `SPLICE_F_NONBLOCK`: do not wait on the pipe.
const SPLICE_F_NONBLOCK: u64 = 2;
/// `RWF_*` flags `preadv2`/`pwritev2` accept (HIPRI, DSYNC, SYNC, NOWAIT, APPEND).
const RWF_SUPPORTED: u64 = 0x1f;
/// `RWF_APPEND`: write at the end of the file.
const RWF_APPEND: u64 = 0x10;

/// A temporary anonymous mapping in the caller's address space, unmapped on drop.
pub(crate) struct Bounce {
    pub(crate) addr: u64,
    len: u64,
}

impl Bounce {
    /// Maps `len` bytes of read-write anonymous memory.
    pub(crate) fn new(len: u64) -> Result<Self, i64> {
        let mm = super::mm::current_mm().ok_or(EFAULT)?;
        // PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS
        let addr = super::mm::sys_mmap(&mm, 0, len, 3, 0x22, -1, 0);
        if addr < 0 {
            return Err(addr);
        }
        Ok(Self { addr: addr as u64, len })
    }
}

impl Drop for Bounce {
    fn drop(&mut self) {
        if let Some(mm) = super::mm::current_mm() {
            super::mm::sys_munmap(&mm, self.addr, self.len);
        }
    }
}

/// The pipe behind descriptor `fd`, and whether `fd` is its write end.
fn pipe_of(fd: u64) -> Option<(Arc<Mutex<PipeBuffer>>, bool)> {
    crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
        Some(FileDescriptor::PipeRead(p)) => Some((p.clone(), false)),
        Some(FileDescriptor::PipeWrite(p)) => Some((p.clone(), true)),
        _ => None,
    })
}

/// Reads a user `loff_t`.
fn read_off(ptr: u64) -> Result<u64, i64> {
    let raw = copy_in(ptr, 8)?;
    let v = i64::from_le_bytes(raw[..8].try_into().unwrap());
    if v < 0 {
        return Err(EINVAL);
    }
    Ok(v as u64)
}

/// Moves up to `count` bytes from `inp` to `out`: reads at `in_off` (or the current
/// position), writes all of each piece at `out_off` (or the current position). Stops after
/// one piece with `once`, or when a read comes back short (end of file, nothing more
/// available yet).
///
/// # Returns
/// Bytes moved, or a negative errno if nothing moved.
fn copy(frame: &SyscallFrame, inp: u64, in_off: &mut Option<u64>, out: u64, out_off: &mut Option<u64>, count: u64, once: bool) -> i64 {
    let buf = match Bounce::new(CHUNK) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut total: u64 = 0;
    while total < count {
        let want = (count - total).min(CHUNK);
        let r = match *in_off {
            Some(o) => super::nested(frame, NR_PREAD64, [inp, buf.addr, want, o, 0, 0]),
            None => super::nested(frame, NR_READ, [inp, buf.addr, want, 0, 0, 0]),
        };
        if r <= 0 {
            return if total > 0 { total as i64 } else { r };
        }
        let r = r as u64;
        let mut done = 0;
        while done < r {
            let w = match *out_off {
                Some(o) => super::nested(frame, NR_PWRITE64, [out, buf.addr + done, r - done, o + done, 0, 0]),
                None => super::nested(frame, NR_WRITE, [out, buf.addr + done, r - done, 0, 0, 0]),
            };
            if w <= 0 {
                // What was read but not written is lost for a stream; offsets move only by
                // what reached the output
                if let Some(o) = in_off.as_mut() {
                    *o += done;
                }
                if let Some(o) = out_off.as_mut() {
                    *o += done;
                }
                total += done;
                return if total > 0 { total as i64 } else if w == 0 { -5 } else { w };
            }
            done += w as u64;
        }
        if let Some(o) = in_off.as_mut() {
            *o += r;
        }
        if let Some(o) = out_off.as_mut() {
            *o += r;
        }
        total += r;
        if once || r < want {
            break;
        }
    }
    total as i64
}

/// `preadv`/`pwritev` at `offset`: one `pread64`/`pwrite64` per buffer, stopping at the
/// first short transfer.
fn vectored_at(frame: &SyscallFrame, fd: u64, iov: u64, cnt: u64, mut offset: u64, write: bool) -> i64 {
    if cnt > IOV_MAX {
        return EINVAL;
    }
    if cnt == 0 {
        return 0;
    }
    let raw = match copy_in(iov, cnt as usize * 16) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for c in raw.chunks(16) {
        let base = u64::from_le_bytes(c[0..8].try_into().unwrap());
        let len = u64::from_le_bytes(c[8..16].try_into().unwrap());
        if len == 0 {
            continue;
        }
        let r = super::nested(frame, if write { NR_PWRITE64 } else { NR_PREAD64 }, [fd, base, len, offset, 0, 0]);
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        total += r;
        offset += r as u64;
        if (r as u64) < len {
            break;
        }
    }
    total
}

/// Waits a tick for a pipe to change, or reports why not to.
fn pipe_wait(nonblock: bool) -> Result<(), i64> {
    if nonblock {
        return Err(EAGAIN);
    }
    if super::proc::signal_pending() {
        return Err(super::proc::ERESTARTSYS);
    }
    crate::task::sleep_ticks(1);
    Ok(())
}

/// `tee(2)`: copies up to `len` bytes from pipe `inp` to pipe `out` without consuming them.
fn tee(inp: u64, out: u64, len: u64, flags: u64) -> i64 {
    let (Some((src, false)), Some((dst, true))) = (pipe_of(inp), pipe_of(out)) else { return EINVAL };
    if Arc::ptr_eq(&src, &dst) {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    loop {
        let (avail, writers) = {
            let s = src.lock();
            (s.available_read(), s.writers_count())
        };
        if avail == 0 {
            if writers == 0 {
                return 0;
            }
            if let Err(e) = pipe_wait(nonblock) {
                return e;
            }
            continue;
        }
        let room = dst.lock().available_write();
        if room == 0 {
            if let Err(e) = pipe_wait(nonblock) {
                return e;
            }
            continue;
        }
        let mut data = alloc::vec![0u8; avail.min(room).min(len as usize)];
        let n = src.lock().peek(&mut data);
        return match dst.lock().write(&data[..n]) {
            Ok(w) => w as i64,
            Err(_) => -32, // EPIPE: no reader
        };
    }
}

/// Handles the data transfer calls (see the module documentation).
///
/// # Arguments
/// * `frame` - The caller's registers (call number and arguments).
/// * `num` - System call number.
///
/// # Returns
/// The call's result or a negative errno.
pub fn dispatch(frame: &mut SyscallFrame, num: u64) -> i64 {
    let a = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    match num {
        // preadv / pwritev (fd, iov, iovcnt, pos_l, pos_h): pos_l is the whole offset
        295 | 296 => {
            if (a[3] as i64) < 0 {
                return EINVAL;
            }
            vectored_at(frame, a[0], a[1], a[2], a[3], num == 296)
        }
        // preadv2 / pwritev2 (..., flags): offset -1 means the current position
        327 | 328 => {
            let write = num == 328;
            if a[5] & !RWF_SUPPORTED != 0 {
                return EOPNOTSUPP;
            }
            if write && a[5] & RWF_APPEND != 0 {
                let end = super::nested(frame, NR_LSEEK, [a[0], 0, 2, 0, 0, 0]);
                if end < 0 {
                    return end;
                }
                return vectored_at(frame, a[0], a[1], a[2], end as u64, true);
            }
            if a[3] as i64 == -1 {
                return super::nested(frame, if write { NR_WRITEV } else { NR_READV }, [a[0], a[1], a[2], 0, 0, 0]);
            }
            if (a[3] as i64) < 0 {
                return EINVAL;
            }
            vectored_at(frame, a[0], a[1], a[2], a[3], write)
        }
        // sendfile(out_fd, in_fd, offset*, count)
        40 => {
            let mut in_off = if a[2] != 0 {
                match read_off(a[2]) {
                    Ok(o) => Some(o),
                    Err(e) => return e,
                }
            } else {
                None
            };
            if a[3] == 0 {
                return 0;
            }
            let r = copy(frame, a[1], &mut in_off, a[0], &mut None, a[3], false);
            if let Some(o) = in_off {
                if copy_out(a[2], &o.to_le_bytes()).is_err() {
                    return EFAULT;
                }
            }
            r
        }
        // copy_file_range(fd_in, off_in*, fd_out, off_out*, len, flags)
        326 => {
            if a[5] != 0 {
                return EINVAL;
            }
            let mut offs = [None, None];
            for (i, p) in [a[1], a[3]].into_iter().enumerate() {
                if p != 0 {
                    match read_off(p) {
                        Ok(o) => offs[i] = Some(o),
                        Err(e) => return e,
                    }
                }
            }
            if a[4] == 0 {
                return 0;
            }
            let [mut in_off, mut out_off] = offs;
            let r = copy(frame, a[0], &mut in_off, a[2], &mut out_off, a[4], false);
            for (p, o) in [(a[1], in_off), (a[3], out_off)] {
                if let (true, Some(o)) = (p != 0, o) {
                    if copy_out(p, &o.to_le_bytes()).is_err() {
                        return EFAULT;
                    }
                }
            }
            r
        }
        // splice(fd_in, off_in*, fd_out, off_out*, len, flags): one end is a pipe
        275 => {
            let in_pipe = pipe_of(a[0]);
            let out_pipe = pipe_of(a[2]);
            if in_pipe.is_none() && out_pipe.is_none() {
                return EINVAL;
            }
            if matches!(in_pipe, Some((_, true))) || matches!(out_pipe, Some((_, false))) {
                return EBADF;
            }
            if (in_pipe.is_some() && a[1] != 0) || (out_pipe.is_some() && a[3] != 0) {
                return ESPIPE;
            }
            if a[4] == 0 {
                return 0;
            }
            let nonblock = a[5] & SPLICE_F_NONBLOCK != 0;
            if nonblock {
                if let Some((p, _)) = &in_pipe {
                    let p = p.lock();
                    if p.available_read() == 0 && p.writers_count() > 0 {
                        return EAGAIN;
                    }
                }
                if let Some((p, _)) = &out_pipe {
                    if p.lock().available_write() == 0 {
                        return EAGAIN;
                    }
                }
            }
            let mut offs = [None, None];
            for (i, p) in [a[1], a[3]].into_iter().enumerate() {
                if p != 0 {
                    match read_off(p) {
                        Ok(o) => offs[i] = Some(o),
                        Err(e) => return e,
                    }
                }
            }
            let [mut in_off, mut out_off] = offs;
            let r = copy(frame, a[0], &mut in_off, a[2], &mut out_off, a[4], true);
            for (p, o) in [(a[1], in_off), (a[3], out_off)] {
                if let (true, Some(o)) = (p != 0, o) {
                    if copy_out(p, &o.to_le_bytes()).is_err() {
                        return EFAULT;
                    }
                }
            }
            r
        }
        // tee(fd_in, fd_out, len, flags)
        276 => tee(a[0], a[1], a[2], a[3]),
        // vmsplice(fd, iov, nr_segs, flags): user memory into a pipe, or out of one
        278 => match pipe_of(a[0]) {
            Some((_, true)) => super::nested(frame, NR_WRITEV, [a[0], a[1], a[2], 0, 0, 0]),
            Some((_, false)) => super::nested(frame, NR_READV, [a[0], a[1], a[2], 0, 0, 0]),
            None => EBADF,
        },
        _ => -38,
    }
}
