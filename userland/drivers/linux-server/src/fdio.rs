//! Byte transfers of calls on descriptors (Group 13, wave 5): `read`/`readv`/`write`/
//! `writev` and the socket calls' buffers, as `(address, length)` pieces of the caller's
//! memory. Served at once they go through the call's page when the kernel copied them
//! ([`Cx::copy_in`] / [`Cx::copy_out`]); for a call left pending they go through the client
//! memory primitives by request ID (the page is reused meanwhile).

use alloc::vec::Vec;

use hydra_rt::protocol::{LX_KBUF_ADDR, LX_OBJ_FLAGS_KBUF};
use hydra_rt::sys;

use crate::client::Cx;

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

/// Most pieces of one vector (`UIO_MAXIOV`).
const MAX_IOV: u64 = 1024;

/// The caller's buffers of one call.
#[derive(Clone, Default)]
pub struct Iov(pub Vec<(u64, u64)>);

impl Iov {
    /// One buffer.
    pub fn one(ptr: u64, len: u64) -> Self {
        Self(alloc::vec![(ptr, len)])
    }

    /// An iovec array of `count` entries at `ptr` of the caller.
    pub fn array(cx: &Cx, ptr: u64, count: u64) -> Result<Self, i64> {
        if count > MAX_IOV {
            return Err(EINVAL);
        }
        let raw = cx.copy_in_any(ptr, count as usize * 16)?;
        let mut v = Vec::with_capacity(count as usize);
        let mut total: u64 = 0;
        for c in raw.chunks_exact(16) {
            let (p, l) = (Cx::u64_at(c, 0), Cx::u64_at(c, 8));
            if (l as i64) < 0 {
                return Err(EINVAL);
            }
            total = total.checked_add(l).ok_or(EINVAL)?;
            if l > 0 {
                v.push((p, l));
            }
        }
        if total > i64::MAX as u64 {
            return Err(EINVAL);
        }
        Ok(Self(v))
    }

    /// The buffers of `read`/`write` (0, 1) or `readv`/`writev` (19, 20) in `cx`.
    pub fn of_call(cx: &Cx) -> Result<Self, i64> {
        match cx.nr {
            19 | 20 => Self::array(cx, cx.args[1], cx.args[2]),
            _ => Ok(Self::one(cx.args[1], cx.args[2])),
        }
    }

    /// Bytes in all pieces.
    pub fn total(&self) -> usize {
        self.0.iter().map(|&(_, l)| l as usize).sum()
    }

    /// Up to `max` bytes from the caller, starting `skip` bytes in, at once.
    pub fn gather(&self, cx: &Cx, skip: usize, max: usize) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        self.walk(skip, max, |p, n| {
            out.extend_from_slice(&cx.copy_in(p, n)?);
            Ok(())
        })?;
        Ok(out)
    }

    /// Up to `max` bytes from the caller of pending call `id`, starting `skip` bytes in.
    pub fn gather_later(&self, id: u64, skip: usize, max: usize) -> Result<Vec<u8>, i64> {
        let mut out = Vec::new();
        self.walk(skip, max, |p, n| {
            let at = out.len();
            out.resize(at + n, 0);
            sys::lx_read(id, p, &mut out[at..])
        })?;
        Ok(out)
    }

    /// Writes `data` into the caller's pieces (from the start), at once.
    pub fn scatter(&self, cx: &Cx, data: &[u8]) -> Result<(), i64> {
        let mut o = 0;
        self.walk(0, data.len(), |p, n| {
            cx.copy_out(p, &data[o..o + n])?;
            o += n;
            Ok(())
        })
    }

    /// Writes `data` into the pieces of pending call `id`'s caller.
    pub fn scatter_later(&self, id: u64, data: &[u8]) -> Result<(), i64> {
        let mut o = 0;
        self.walk(0, data.len(), |p, n| {
            sys::lx_write(id, p, &data[o..o + n])?;
            o += n;
            Ok(())
        })
    }

    /// Calls `f(address, length)` for the bytes `skip..skip + max` of the pieces.
    fn walk(&self, mut skip: usize, max: usize, mut f: impl FnMut(u64, usize) -> Result<(), i64>) -> Result<(), i64> {
        let mut left = max;
        for &(p, l) in &self.0 {
            if left == 0 {
                break;
            }
            let l = l as usize;
            if skip >= l {
                skip -= l;
                continue;
            }
            let n = (l - skip).min(left);
            if p == 0 {
                return Err(EFAULT);
            }
            f(p + skip as u64, n)?;
            left -= n;
            skip = 0;
        }
        Ok(())
    }
}

/// Whether the call is a kernel-buffer transfer (`splice`, io_uring, ...): it must not wait
/// and posts no `SIGPIPE`.
pub fn kbuf(cx: &Cx) -> bool {
    cx.c.obj_flags & LX_OBJ_FLAGS_KBUF != 0 && cx.args[1] == LX_KBUF_ADDR
}

/// Posts `SIGPIPE` to the process of the call (a write to a pipe or socket nobody reads).
pub fn sigpipe(tgid: u64, tid: u64) {
    let _ = tid;
    let _ = sys::lx_sig(tgid, 13, 0, 0, 0, 0);
}
