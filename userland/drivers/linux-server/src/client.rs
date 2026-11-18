//! The call being served: who made it, and its memory (through the kernel's client memory
//! primitives, `SYS_LX_READ` / `SYS_LX_WRITE` / `SYS_LX_READ_STR`).

use alloc::vec::Vec;

use hydra_rt::protocol::{LxCall, LX_GROUPS};
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
}

impl Cx {
    /// The call in a worker's syscall page.
    pub fn from_call(c: &LxCall) -> Self {
        let n = (c.ngroups as usize).min(LX_GROUPS);
        Self { id: c.id, nr: c.nr, args: c.args, c: *c, caller: Caller::new(c.tid, c.tgid, c.euid, c.egid, c.caps, &c.groups[..n]) }
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

    /// Writes `data` to `ptr` of the caller.
    pub fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        sys::lx_write(self.id, ptr, data)
    }

    /// The NUL-terminated string at `ptr` of the caller (at most 4095 bytes, as the
    /// kernel's `user_cstr`: longer is `-ENAMETOOLONG`).
    pub fn user_cstr(&self, ptr: u64) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(EFAULT);
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
