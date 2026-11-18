//! The call being served: who made it, and its memory. Pointer arguments the kernel's
//! copy-in table describes are already in the syscall page (`LxCopy`, wave 4); the rest go
//! through the kernel's client memory primitives, `SYS_LX_READ` / `SYS_LX_WRITE` /
//! `SYS_LX_READ_STR`. [`Cx::copy_in`], [`Cx::user_cstr`] and [`Cx::copy_out`] pick the page
//! when they can and fall back by themselves, so code serving a call never needs to know.
//!
//! Output written to the page is copied to the caller by the kernel after the answer: only
//! for an immediate answer (a call answered `LX_REPLY_PENDING` must write its output with
//! `SYS_LX_WRITE`, as [`Cx::copy_out_direct`] does, since the page is reused meanwhile).

use alloc::vec::Vec;
use core::cell::Cell;

use hydra_rt::protocol::{LxCall, LxCopy, LX_COPY_OFF, LX_DATA_OFF, LX_GROUPS, LX_PAGE_SIZE};
use hydra_rt::sys;

const EFAULT: i64 = -14;
const ENAMETOOLONG: i64 = -36;

/// `CAP_SYS_ADMIN`.
const CAP_SYS_ADMIN: u64 = 1 << 21;

/// The caller's identity as the key service checks it: thread, process, effective user
/// and group (the file system IDs Linux uses equal them here), `CAP_SYS_ADMIN`, and the
/// supplementary groups.
#[derive(Clone, Copy)]
pub struct Caller {
    /// Thread ID.
    pub tid: u64,
    /// Process ID.
    pub tgid: u64,
    /// Effective user ID.
    pub uid: u32,
    /// Effective group ID.
    pub gid: u32,
    /// Holds `CAP_SYS_ADMIN`.
    pub admin: bool,
    ngroups: usize,
    groups: [u32; LX_GROUPS],
}

impl Caller {
    /// A caller described by the kernel's words (`MSG_LX_PROC_KEYS`).
    pub fn new(tid: u64, tgid: u64, uid: u32, gid: u32, caps: u64, groups: &[u32]) -> Self {
        let mut g = [0u32; LX_GROUPS];
        let n = groups.len().min(LX_GROUPS);
        g[..n].copy_from_slice(&groups[..n]);
        Self { tid, tgid, uid, gid, admin: caps & CAP_SYS_ADMIN != 0, ngroups: n, groups: g }
    }

    /// Whether `gid` is one of the supplementary groups.
    pub fn in_groups(&self, gid: u32) -> bool {
        self.groups[..self.ngroups].contains(&gid)
    }
}

/// A forwarded call being served.
pub struct Cx {
    /// The request's ID (it names the caller to the client memory primitives).
    pub id: u64,
    /// Linux system call number.
    pub nr: u64,
    /// Its arguments.
    pub args: [u64; 6],
    /// The whole call as the kernel gave it (identity, server object, IPC namespace).
    pub c: LxCall,
    caller: Caller,
    /// The worker's syscall page (null: none, e.g. a kernel request), and its copy header.
    page: *mut u8,
    copy: LxCopy,
    /// Output lengths written to the page so far (the kernel reads them after the answer).
    out_len: [Cell<u16>; 6],
}

impl Cx {
    /// The call in a worker's syscall page `page` (`c` is the `LxCall` read from it).
    pub fn from_call(c: &LxCall, page: *mut u8) -> Self {
        let n = (c.ngroups as usize).min(LX_GROUPS);
        // SAFETY: the page is the worker's own; the kernel wrote the header before the
        // worker's SYS_LX_REPLY_RECV returned
        let copy = if page.is_null() { LxCopy::EMPTY } else { unsafe { core::ptr::read_volatile(page.add(LX_COPY_OFF) as *const LxCopy) } };
        let out_len = [const { Cell::new(0) }; 6];
        if !page.is_null() {
            // No output unless this call writes some
            // SAFETY: as above
            unsafe { core::ptr::write_volatile(&mut (*(page.add(LX_COPY_OFF) as *mut LxCopy)).out_len, [0; 6]) };
        }
        Self { id: c.id, nr: c.nr, args: c.args, c: *c, caller: Caller::new(c.tid, c.tgid, c.euid, c.egid, c.caps, &c.groups[..n]), page, copy, out_len }
    }

    /// The bytes the kernel copied in for pointer `ptr`, if it is one of the arguments and
    /// was copied.
    fn copied(&self, ptr: u64) -> Option<&[u8]> {
        if self.page.is_null() || ptr == 0 {
            return None;
        }
        let i = (0..6).find(|&i| self.args[i] == ptr && self.copy.in_off[i] != 0)?;
        let (off, len) = (self.copy.in_off[i] as usize, self.copy.in_len[i] as usize);
        if off < LX_DATA_OFF || off + len > LX_PAGE_SIZE {
            return None;
        }
        // SAFETY: within the worker's page, which stays ours until the answer
        Some(unsafe { core::slice::from_raw_parts(self.page.add(off), len) })
    }

    /// Writes `data` to pointer `ptr` of the caller without the page (`SYS_LX_WRITE`): for
    /// output written after the answer, as by a call answered later.
    #[allow(dead_code)] // for the blocking calls of step 2 (Group 9)
    pub fn copy_out_direct(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        sys::lx_write(self.id, ptr, data)
    }

    /// Whether the caller holds capability `cap` (a bit number).
    pub fn has_cap(&self, cap: u32) -> bool {
        self.c.caps & (1 << cap) != 0
    }

    /// Whether `gid` is the caller's effective group or one of its supplementary groups.
    pub fn in_group(&self, gid: u32) -> bool {
        self.c.egid == gid || self.caller.in_groups(gid)
    }

    /// The descriptor's `O_NONBLOCK` (calls on a server object).
    pub fn nonblock(&self) -> bool {
        self.c.obj_flags & 0o4000 != 0
    }

    /// A little-endian u64 at `off` of `b`.
    pub fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// Who made the call.
    pub fn caller(&self) -> Caller {
        self.caller
    }

    /// `len` bytes at `ptr` of the caller.
    pub fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        if let Some(b) = self.copied(ptr).filter(|b| b.len() >= len) {
            return Ok(b[..len].to_vec());
        }
        let mut v = alloc::vec![0u8; len];
        sys::lx_read(self.id, ptr, &mut v)?;
        Ok(v)
    }

    /// [`Cx::copy_in`], where an empty range needs no valid pointer.
    pub fn copy_in_any(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if len == 0 {
            return Ok(Vec::new());
        }
        self.copy_in(ptr, len)
    }

    /// [`Cx::copy_out`], where an empty range needs no valid pointer.
    pub fn copy_out_any(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if data.is_empty() {
            return Ok(());
        }
        self.copy_out(ptr, data)
    }

    /// Writes `data` to `ptr` of the caller: into the page when the kernel left room for
    /// output to that argument (copied after an immediate answer), otherwise at once.
    pub fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        if !self.page.is_null() {
            if let Some(i) = (0..6).find(|&i| self.args[i] == ptr && self.copy.out_off[i] != 0) {
                let (off, cap) = (self.copy.out_off[i] as usize, self.copy.out_cap[i] as usize);
                if data.len() <= cap && off >= LX_DATA_OFF && off + data.len() <= LX_PAGE_SIZE {
                    // SAFETY: within the worker's page; the header's out_len is ours to set
                    unsafe {
                        core::ptr::copy_nonoverlapping(data.as_ptr(), self.page.add(off), data.len());
                        self.out_len[i].set(data.len() as u16);
                        let mut lens = [0u16; 6];
                        for (k, l) in lens.iter_mut().enumerate() {
                            *l = self.out_len[k].get();
                        }
                        core::ptr::write_volatile(&mut (*(self.page.add(LX_COPY_OFF) as *mut LxCopy)).out_len, lens);
                    }
                    return Ok(());
                }
            }
        }
        sys::lx_write(self.id, ptr, data)
    }

    /// The NUL-terminated string at `ptr` of the caller (at most 4095 bytes, as the
    /// kernel's `user_cstr`: longer is `-ENAMETOOLONG`).
    pub fn user_cstr(&self, ptr: u64) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        // (the kernel copies a string only with its NUL found within its limit, which is
        // 4096 bytes at most for every string the table describes)
        if let Some(b) = self.copied(ptr).filter(|b| b.len() < 4096) {
            return Ok(b.to_vec());
        }
        let mut buf = alloc::vec![0u8; 4096];
        let n = sys::lx_read_str(self.id, ptr, &mut buf)?;
        if n >= 4096 {
            return Err(ENAMETOOLONG);
        }
        buf.truncate(n);
        Ok(buf)
    }
}

/// Milliseconds since boot (the kernel's 100 Hz tick).
pub fn now_ms() -> u64 {
    sys::uptime_ticks() * 10
}
