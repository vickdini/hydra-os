//! # `execve`'s front half and socket files by the services (wave 7, Group 7-5)
//!
//! `docs/vfs-design.md` 12.2 (7-5) and B.4.4: path lookups leave the kernel.
//!
//! - **`execve`/`execveat`** stay routed to the kernel by number (the new image is built and
//!   committed in the caller's trap, with its frame), but [`front`] first asks linux-server
//!   for the front half (`LX_KCALL_EXEC`): linux-server resolves the program, the
//!   interpreters of `#!` scripts and the ELF interpreter with direct calls to vfs-server,
//!   which checks exec permission in the caller's context, and answers with an
//!   [`ExecPlan`]. `compat::linux::execve` then runs the same checks on the program the
//!   kernel's own lookup would run (set-ID, file capabilities, `nosuid`, tracing,
//!   `no_new_privs`), loads it and commits.
//! - **Unix socket path names** (`bind`, `connect` on a socket of linux-server): instead of
//!   resolving the node in the kernel first (Group 13's temporary `vfs_resolve`),
//!   [`sock_call`] forwards the call with the caller's file context
//!   (`LX_OBJ_FLAGS_VFSCTX`), and linux-server asks vfs-server for the node.
//!
//! Both fall back to the kernel's own code whenever the file service cannot answer for the
//! caller: `lx=kernel`, `lx.vfs=kernel`, vfs-server or linux-server not online, and callers
//! whose state only the kernel sees (`fileh::kernel_mask`: foreign roots, mount namespaces,
//! Landlock, fanotify, ABAC; inotify for `bind`, which makes a node). A service answers
//! "kernel" (`LX_EXEC_KERNEL`, a redirect to the kernel) before anything changed.

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

use super::fileh::{self, Shape};
use super::svc::{self, Host};
use super::{copy, HeldObj, SyscallFrame};
use crate::ipc::protocol::{
    LxCall, LXS_LINUX, LXS_VFS, LX_DATA_OFF, LX_DATA_SIZE, LX_EXEC_KERNEL, LX_FS_ABAC, LX_FS_FANOTIFY, LX_FS_FOREIGN, LX_FS_INOTIFY, LX_FS_LANDLOCK, LX_FS_MOUNTS, LX_GROUPS,
    LX_KBUF_ADDR, LX_KBUF_ADDR_IN, LX_KCALL_EXEC, LX_OBJ_FLAGS_VFSCTX,
};

/// Front halves made by the services, handed back to the kernel, and failed by them (since
/// boot); socket calls sent with the file context.
pub static EXEC_PLANS: AtomicU64 = AtomicU64::new(0);
/// See [`EXEC_PLANS`].
pub static EXEC_KERNEL: AtomicU64 = AtomicU64::new(0);
/// See [`EXEC_PLANS`].
pub static EXEC_FAILED: AtomicU64 = AtomicU64::new(0);
/// See [`EXEC_PLANS`].
pub static SOCK_CALLS: AtomicU64 = AtomicU64::new(0);

pub use super::xplan::{decode_plan, ExecPlan};

/// The host of `s` when it is online.
fn online(s: crate::ipc::protocol::SvcId) -> Option<&'static Host> {
    svc::host(svc::host_of(s)).filter(|x| x.is_online())
}

/// Whether the caller's context in `c` lets the file service answer (none of the
/// `LX_FS_*` bits in `mask`, no root or working directory in a mount).
fn servable(c: &LxCall, mask: u32) -> bool {
    c.fs_flags & mask == 0 && c.root_mnt == 0 && c.cwd_mnt == 0
}

/// The fixed context of a call to the file service's partners: identity, namespaces, the
/// file context of the descriptor table (`sh` says where the directory descriptor is), and
/// what `more` reads from the same table under the same lock (the paths that go with it).
fn context<R>(c: &mut LxCall, sh: Shape, more: impl FnOnce(&crate::fs::FdTable) -> Option<R>) -> Option<(fileh::Held, R)> {
    c.tgid = crate::task::with_current_task_mut(|t| t.tgid).unwrap_or(0);
    super::fill_ctx(c, true);
    let (held, r) = crate::task::with_current_fds_mut(|t| {
        let h = fileh::fill(c, t, sh, true).ok()??;
        Some((h, more(t)?))
    })?;
    let f = fileh::fs_flags_global(c); // (wave7 G7-7: it also sets `mnt_gen`)
    c.fs_flags |= f;
    Some((held, r))
}

/// Whether the caller's supplementary groups all fit a call (else the kernel checks with all
/// of them itself).
fn groups_fit(tgid: u64) -> bool {
    crate::compat::linux::proc::PROCS.lock().get(&tgid).is_none_or(|p| p.groups.len() <= LX_GROUPS)
}

/// `execve`'s front half by linux-server and vfs-server for the current thread: `dirfd`,
/// the path (the kernel's copy), the `execveat` flags. `None`: the kernel makes it
/// itself; `Some(Err(e))`: `execve` fails with `e`.
pub fn front(dirfd: i64, path: &[u8], flags: u64) -> Option<Result<ExecPlan, i64>> {
    const AT_EMPTY_PATH: u64 = 0x1000;
    if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        return None;
    }
    online(LXS_VFS)?;
    let x = online(LXS_LINUX)?;
    let mut c = LxCall::EMPTY;
    c.nr = LX_KCALL_EXEC;
    c.svc = LXS_LINUX as u32;
    // (the path goes in the kernel buffer: linux-server never reads the caller's memory)
    c.args = [dirfd as u64, LX_KBUF_ADDR, 0, flags, LX_KBUF_ADDR_IN, 0];
    // The bases, from the same table and under the same lock as the context: the directory a
    // relative path starts at, and the working directory (for interpreters), as shown
    let (held, (base, cwd)) = context(&mut c, Shape::At0, |t| {
        let base = if path.first() == Some(&b'/') {
            String::from("/")
        } else if dirfd as i32 == -100 {
            t.cwd_path.clone()
        } else {
            // (a handle on the pool: its shown path; anything else is the kernel's)
            match t.get(dirfd as i32 as usize) {
                Some(crate::fs::FileDescriptor::Vnode(f)) if dirfd as i32 >= 0 => f.try_lock().filter(|f| f.foreign.is_none()).map(|f| f.path.clone())?,
                _ => return None,
            }
        };
        Some((base, t.cwd_path.clone()))
    })?;
    if !servable(&c, LX_FS_FOREIGN | LX_FS_MOUNTS | LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC) {
        return None;
    }
    // In: "base\0cwd\0path\0" (the path the kernel read, never fetched again); out: the
    // rest of the copy area
    let n = base.len() + cwd.len() + path.len() + 3;
    if n + 1024 > LX_DATA_SIZE {
        return None;
    }
    let mut buf = copy::CopyBuf::EMPTY;
    buf.data[..base.len()].copy_from_slice(base.as_bytes());
    buf.data[base.len() + 1..base.len() + 1 + cwd.len()].copy_from_slice(cwd.as_bytes());
    let po = base.len() + cwd.len() + 2;
    buf.data[po..po + path.len()].copy_from_slice(path);
    buf.used = LX_DATA_SIZE;
    buf.hdr.in_off[4] = LX_DATA_OFF as u16;
    buf.hdr.in_len[4] = n as u16;
    buf.hdr.out_off[1] = (LX_DATA_OFF + n) as u16;
    buf.hdr.out_cap[1] = (LX_DATA_SIZE - n) as u16;
    c.args[5] = n as u64;
    let mut out = alloc::vec![0u8; LX_DATA_SIZE - n];
    let r = kcall(x, c, &buf, &mut out);
    drop(held);
    match r {
        0 => match decode_plan(&out) {
            Some(p) => {
                EXEC_PLANS.fetch_add(1, Ordering::Relaxed);
                Some(Ok(p))
            }
            None => {
                EXEC_KERNEL.fetch_add(1, Ordering::Relaxed);
                None
            }
        },
        // (the service's own "kernel", and every failure of the call itself: the service
        // went away or restarts, a signal, too many calls in flight)
        LX_EXEC_KERNEL | super::EIO | super::ENOSYS | super::EINTR | super::EAGAIN | super::EFAULT => {
            EXEC_KERNEL.fetch_add(1, Ordering::Relaxed);
            None
        }
        r if r < 0 && r > -4096 => {
            EXEC_FAILED.fetch_add(1, Ordering::Relaxed);
            Some(Err(r))
        }
        _ => {
            EXEC_KERNEL.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

/// Makes kernel call `c` (its context filled) to host `x` with the copies of `buf`; the
/// output for `args[1]` lands in `out`. Never redirected (an answer 0 or negative, or the
/// service's own codes).
fn kcall(x: &'static Host, mut c: LxCall, buf: &copy::CopyBuf, out: &mut [u8]) -> i64 {
    let mut sched = crate::task::SCHEDULER.lock();
    let my_idx = sched.current_index();
    let me = sched.current_task_mut(|t| {
        c.tid = t.id.0;
        c.uid = t.uid;
        c.euid = t.euid;
        c.suid = t.suid;
        c.gid = t.gid;
        c.egid = t.egid;
        c.sgid = t.sgid;
        c.caps = if t.caps.in_userns { 0 } else { t.caps.effective };
        t.id.0
    });
    drop(sched);
    let Some(me) = me else { return super::ENOSYS };
    if let Some(p) = crate::compat::linux::proc::PROCS.lock().get(&c.tgid) {
        // (more groups than a call carries: the kernel checks with all of them itself)
        if p.groups.len() > LX_GROUPS {
            return LX_EXEC_KERNEL;
        }
        let n = p.groups.len();
        c.groups[..n].copy_from_slice(&p.groups[..n]);
        c.ngroups = n as u64;
    }
    c.note_seq = x.notes_head();
    let mut redir = (0, 0);
    let r = x86_64::instructions::interrupts::without_interrupts(|| super::call_and_wait(x, me, my_idx, c, copy::Src::Kernel(buf), true, Some(out), &mut redir));
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    if r == super::LX_REDIRECTED {
        return LX_EXEC_KERNEL;
    }
    r
}

/// `bind` (49) or `connect` (42) on Unix socket `o` of linux-server, the ordinary path:
/// forwarded with the caller's file context when vfs-server can make or check the node for
/// this caller (`None`: the kernel's dispatcher answers, resolving the node itself as
/// before).
pub(super) fn sock_call(frame: &SyscallFrame, o: HeldObj) -> Option<i64> {
    if !matches!(frame.rax, 42 | 49) {
        return None;
    }
    online(LXS_VFS)?;
    let (dev, slot, flags, h) = o;
    let x = svc::host(h).filter(|x| x.is_online())?;
    let mut c = LxCall::EMPTY;
    c.nr = frame.rax;
    c.args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    c.svc = x.id as u32;
    c.obj = slot;
    c.obj_flags = flags | LX_OBJ_FLAGS_VFSCTX;
    let (held, ()) = context(&mut c, Shape::Path, |_| Some(()))?;
    if !groups_fit(c.tgid) {
        return None;
    }
    let mask = if c.nr == 49 { LX_FS_FOREIGN | LX_FS_MOUNTS | LX_FS_LANDLOCK | LX_FS_FANOTIFY | LX_FS_ABAC | LX_FS_INOTIFY } else { LX_FS_FOREIGN | LX_FS_MOUNTS | LX_FS_LANDLOCK | LX_FS_ABAC };
    if !servable(&c, mask) {
        return None;
    }
    SOCK_CALLS.fetch_add(1, Ordering::Relaxed);
    let r = super::call_ident_raw(x, c, true);
    drop(held);
    drop(dev);
    if r == fileh::LX_TO_KERNEL {
        return None;
    }
    Some(r)
}

/// `LX_FH_READ(ino, buf, off << 16 | len)` of service host `h`: bytes of pool object `ino`
/// through the page cache into the caller's (vfs-server's) buffer.
pub(super) fn read(h: crate::ipc::protocol::SvcId, ino: u64, buf: u64, c: u64) -> i64 {
    if svc::host_of(LXS_VFS) != h {
        return super::EPERM;
    }
    if ino == 0 || !fileh::plain_ino(ino) {
        return super::EINVAL;
    }
    let (off, len) = (c >> 16, (c & 0xFFFF) as usize);
    let mut v = alloc::vec![0u8; len];
    match crate::compat::linux::mm::cached_read(ino, off, &mut v) {
        Ok(n) => match crate::compat::linux::vfs::copy_out(buf, &v[..n.min(len)]) {
            Ok(()) => n.min(len) as i64,
            Err(e) => e,
        },
        Err(e) => e,
    }
}

/// One line for `lx` statistics.
pub fn summary() -> String {
    alloc::format!(
        "execve front halves: {} by the services, {} by the kernel, {} failed there; Unix socket names by vfs-server: {} calls",
        EXEC_PLANS.load(Ordering::Relaxed),
        EXEC_KERNEL.load(Ordering::Relaxed),
        EXEC_FAILED.load(Ordering::Relaxed),
        SOCK_CALLS.load(Ordering::Relaxed)
    )
}
