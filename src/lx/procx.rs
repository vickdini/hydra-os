//! # More `/proc` facts for lx-proc (wave 11, Group P): `LX_INFO_PROCX` (op 82)
//!
//! lx-proc serves all of `/proc` (`docs/src/linux-server.md`, "lx-proc"). What only the
//! kernel knows about a process beyond 7-4's and 7b-2's info primitives (`lx::info`) comes
//! from this operation: its open descriptors and what they link to, a descriptor's
//! `fdinfo` fields, the `exe`/`cwd`/`root` links, the auxiliary vector, the control group,
//! the namespace inode numbers, the thread list, the processes a caller sees, the user
//! namespace maps, the OOM numbers, and tables other parts keep (`filesystems`, `swaps`,
//! `locks`, `mountinfo`, `mounts`, `asound`), relayed as their owners write them.
//!
//! `SYS_LX_OBJ(LX_INFO_PROCX, req, what, *LxProcxIo)` from lx-proc's host only, for one of
//! its own requests: the request's caller (in a remake, the process that opened the file)
//! names the process (`pid`, 0: itself) in its own PID namespace; IDs come back as it sees
//! them. The descriptors, links and the auxiliary vector are under the `ptrace` read rule
//! (`lx::info::may_read`: Linux's `PTRACE_MODE_READ_FSCREDS`), `EACCES` otherwise. The
//! kernel formats nothing: lx-proc makes the text.

use crate::ipc::protocol::{LX_PX_AUXV, LX_PX_CGROUP, LX_PX_FDINFO, LX_PX_FDLINK, LX_PX_FDS, LX_PX_IDMAP, LX_PX_LINK, LX_PX_NSINO, LX_PX_OOM, LX_PX_TASKS};

const ENOENT: i64 = -2;
const EINVAL: i64 = -22;

/// Whether operation `what` reads what the `ptrace` read rule guards (Linux: `fd/`,
/// `fdinfo/`, `exe`, `cwd`, `root`, `auxv` need `PTRACE_MODE_READ_FSCREDS`).
pub fn guarded(what: u64) -> bool {
    matches!(what, LX_PX_FDS | LX_PX_FDLINK | LX_PX_FDINFO | LX_PX_LINK | LX_PX_AUXV)
}

/// Whether operation `what` is about one process (`pid`), not the whole system.
pub fn per_process(what: u64) -> bool {
    matches!(what, LX_PX_FDS | LX_PX_FDLINK | LX_PX_FDINFO | LX_PX_LINK | LX_PX_AUXV | LX_PX_CGROUP | LX_PX_NSINO | LX_PX_TASKS | LX_PX_IDMAP | LX_PX_OOM)
}

/// The `flags:` field of `fdinfo` (octal in the text): the open's flags without
/// `O_CLOEXEC`, with it when the descriptor has it.
pub fn fdinfo_flags(open_flags: u32, cloexec: bool) -> u32 {
    const O_CLOEXEC: u32 = 0o2000000;
    (open_flags & !O_CLOEXEC) | if cloexec { O_CLOEXEC } else { 0 }
}

/// The kernel's side.
#[cfg(target_os = "uefi")]
mod glue {
    use super::*;
    use alloc::vec::Vec;
    use crate::compat::linux as lx;
    use crate::ipc::protocol::{LX_PX_PIDS, LX_PX_TEXT};
    use crate::fs::FileDescriptor;
    use crate::ipc::protocol::{
        LxProcxIo, LX_PX_NS_NAMES, LX_PX_T_ASOUND, LX_PX_T_BOOTID, LX_PX_T_FILESYSTEMS, LX_PX_T_LOCKS, LX_PX_T_MOUNTINFO, LX_PX_T_MOUNTS, LX_PX_T_SWAPS, LX_PX_T_UUID,
    };
    use crate::lx::info::glue::{caller, is_service, out_bytes, target_caps, visible, Caller};
    use crate::lx::info::{may_read, resolve_pid, to_caller, u32_list};

    const ESRCH: i64 = -3;
    const EFAULT: i64 = -14;
    const EACCES: i64 = -13;

    /// `SYS_LX_OBJ(LX_INFO_PROCX, req, what, io)` (lx-proc's host already checked).
    pub fn ctl(req: u64, what: u64, io: u64) -> i64 {
        let mut x = LxProcxIo::default();
        // SAFETY: a plain repr(C) struct of integers: any bytes are a valid value
        let raw = unsafe { core::slice::from_raw_parts_mut(&mut x as *mut LxProcxIo as *mut u8, core::mem::size_of::<LxProcxIo>()) };
        if crate::lx::copy::read_user(io, raw).is_err() {
            return EFAULT;
        }
        let c = match caller(req) {
            Ok(c) => c,
            Err(e) => return e,
        };
        let r = run(&c, what, &mut x);
        // (the words out, whatever the answer)
        // SAFETY: as above
        let raw = unsafe { core::slice::from_raw_parts(&x as *const LxProcxIo as *const u8, core::mem::size_of::<LxProcxIo>()) };
        if lx::vfs::copy_out(io, raw).is_err() {
            return EFAULT;
        }
        r
    }

    /// Process `pid` (system-wide) may be read by `c` under the `ptrace` read rule.
    fn readable(c: &Caller, pid: u64) -> Result<(), i64> {
        let (uids, gids, service, perm) = crate::task::SCHEDULER
            .lock()
            .with_process(pid, |t| ((t.uid, t.euid, t.suid), (t.gid, t.egid, t.sgid), t.service.is_some(), t.caps.permitted))
            .ok_or(ESRCH)?;
        let dumpable = crate::lx::proc::proc_attrs(pid).dumpable == 1;
        if may_read(pid == c.tgid, service, (c.euid, c.egid), c.caps, uids, gids, dumpable, target_caps(pid, c.tgid, c.euid, perm)) {
            Ok(())
        } else {
            Err(EACCES)
        }
    }

    fn run(c: &Caller, what: u64, x: &mut LxProcxIo) -> i64 {
        let pid = resolve_pid(x.pid, c.tgid, c.init);
        if per_process(what) {
            if pid > u32::MAX as u64 || is_service(pid) != Some(false) || !visible(pid, c.init, x.pid) {
                return ESRCH;
            }
            if guarded(what) {
                if let Err(e) = readable(c, pid) {
                    return e;
                }
            }
        }
        let (buf, cap) = (x.buf, x.cap);
        match what {
            LX_PX_FDS => {
                let Some(fds) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()) else { return ESRCH };
                let list: Vec<u64> = {
                    let t = fds.lock();
                    (0..crate::fs::MAX_FDS).filter(|&i| t.get(i).is_some()).map(|i| i as u64).collect()
                };
                out_bytes(buf, cap, &u32_list(&list))
            }
            LX_PX_FDLINK | LX_PX_FDINFO => {
                let fd = x.arg as usize;
                let Some(fds) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()) else { return ESRCH };
                let (desc, cloexec) = {
                    let t = fds.lock();
                    match t.get(fd) {
                        Some(d) => (d.clone(), t.cloexec(fd)),
                        None => return ENOENT,
                    }
                };
                if what == LX_PX_FDLINK {
                    return out_bytes(buf, cap, lx::vfs::desc_link(pid, fd, desc).as_bytes());
                }
                // (pos, flags, mnt_id, inode, a pidfd's process)
                let (pos, flags, ino) = match &desc {
                    FileDescriptor::Vnode(f) => {
                        let f = f.lock();
                        (f.offset, f.flags, f.ino)
                    }
                    FileDescriptor::File { cursor, .. } => (cursor.get() as u64, 0o2, 0),
                    _ => (0, 0o2, 0),
                };
                let pidfd = match &desc {
                    FileDescriptor::Device(d) => d.as_server().filter(|o| o.kind() == crate::ipc::protocol::LX_OBJ_KIND_PIDFD).map(|o| o.tag()),
                    _ => None,
                };
                x.out[0] = pos;
                x.out[1] = fdinfo_flags(flags, cloexec) as u64;
                x.out[2] = 2069;
                x.out[3] = ino;
                x.out[4] = match pidfd {
                    // (-1 once the process has exited, as Linux reports it)
                    Some(p) if crate::task::SCHEDULER.lock().with_process(p, |_| ()).is_some() => to_caller(p, c.init) + 1,
                    Some(_) => u64::MAX,
                    None => 0,
                };
                0
            }
            LX_PX_LINK => {
                let text = match x.arg {
                    0 => crate::task::SCHEDULER.lock().exe_of(pid),
                    1 => crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()).map(|f| f.lock().cwd_path.clone()),
                    // (every Linux process shares the caller's root: "/" as the caller sees it)
                    2 => Some(alloc::string::String::from("/")),
                    _ => return EINVAL,
                };
                match text {
                    Some(t) => out_bytes(buf, cap, t.as_bytes()),
                    None => ENOENT,
                }
            }
            LX_PX_AUXV => {
                let Some(mm) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.mm.clone()).flatten() else { return out_bytes(buf, cap, &[]) };
                let auxv = mm.lock().auxv.clone();
                out_bytes(buf, cap, &auxv)
            }
            LX_PX_CGROUP => {
                let group = lx::proc::PROCS.lock().get(&pid).map(|p| p.cgroup.clone());
                match group {
                    Some(g) => out_bytes(buf, cap, g.as_deref().unwrap_or("/").as_bytes()),
                    None => ESRCH,
                }
            }
            LX_PX_NSINO => {
                for (k, name) in LX_PX_NS_NAMES.iter().enumerate() {
                    x.out[k] = lx::ns::ns_ino_of(pid, name).unwrap_or(0);
                }
                if lx::proc::PROCS.lock().get(&pid).is_none() {
                    return ESRCH;
                }
                0
            }
            LX_PX_TASKS => {
                let list: Vec<u64> = lx::proc::thread_ids_of(pid).into_iter().map(|t| to_caller(t, c.init)).collect();
                if list.is_empty() {
                    return ESRCH;
                }
                out_bytes(buf, cap, &u32_list(&list))
            }
            LX_PX_PIDS => {
                // (the processes of the caller's PID namespace, zombies too, by its IDs)
                let mut list: Vec<u64> = {
                    let procs = lx::proc::PROCS.lock();
                    procs
                        .values()
                        .filter(|p| match c.init {
                            None => true,
                            Some(i) => p.pid == i || p.ns.pid_inits.contains(&i),
                        })
                        .map(|p| to_caller(p.pid, c.init))
                        .collect()
                };
                list.sort_unstable();
                out_bytes(buf, cap, &u32_list(&list))
            }
            LX_PX_IDMAP => {
                let file = match x.arg {
                    0 => "uid_map",
                    1 => "gid_map",
                    2 => "setgroups",
                    _ => return EINVAL,
                };
                out_bytes(buf, cap, lx::ns::read_file_of(pid, file).as_bytes())
            }
            LX_PX_OOM => {
                let num = |f: &str| lx::proc::oom_file_text(pid, f).and_then(|t| t.trim().parse::<i64>().ok());
                match (num("oom_score_adj"), num("oom_score")) {
                    (Some(a), Some(s)) => {
                        x.out[0] = a as u64;
                        x.out[1] = s as u64;
                        0
                    }
                    _ => ESRCH,
                }
            }
            LX_PX_TEXT => {
                let text = match x.arg {
                    LX_PX_T_FILESYSTEMS => lx::admin::filesystems_text(),
                    LX_PX_T_SWAPS => lx::admin::swaps_text(),
                    LX_PX_T_LOCKS => lx::locks::proc_locks(),
                    LX_PX_T_BOOTID => lx::fs::uuid_text(true),
                    LX_PX_T_UUID => lx::fs::uuid_text(false),
                    LX_PX_T_MOUNTINFO | LX_PX_T_MOUNTS => {
                        if pid > u32::MAX as u64 || is_service(pid) != Some(false) || !visible(pid, c.init, x.pid) {
                            return ESRCH;
                        }
                        if x.arg == LX_PX_T_MOUNTINFO {
                            lx::fs::mountinfo_for(pid)
                        } else {
                            lx::fs::mounts_for(pid)
                        }
                    }
                    LX_PX_T_ASOUND => {
                        // (the path below /proc/asound/, NUL-ended, in the buffer)
                        let n = (cap as usize).min(256);
                        let Ok(raw) = lx::vfs::copy_in(buf, n) else { return EFAULT };
                        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                        let Ok(p) = core::str::from_utf8(&raw[..end]) else { return EINVAL };
                        match lx::snd::proc_text(p) {
                            Some(t) => t,
                            None => return ENOENT,
                        }
                    }
                    _ => return EINVAL,
                };
                out_bytes(buf, cap, text.as_bytes())
            }
            _ => EINVAL,
        }
    }
}

#[cfg(target_os = "uefi")]
pub use glue::ctl;
