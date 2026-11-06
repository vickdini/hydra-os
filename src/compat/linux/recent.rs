//! # System calls added in Linux 5.x and 6.x
//!
//! - `openat2`: `openat` with resolution restrictions (`RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`,
//!   `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`). The path is walked
//!   one component at a time with the program's own `newfstatat` and `readlinkat`
//!   ([`super::nested`]), symbolic links are expanded as they are met, and the result is
//!   opened relative to the starting directory.
//! - `epoll_pwait2`: `epoll_pwait` with a `timespec` timeout.
//! - `pidfd_getfd`: duplicates another process's descriptor (the caller must be allowed
//!   to signal-and-trace it: same user, or `CAP_SYS_PTRACE`).
//! - `process_madvise`, `process_mrelease`: memory hints for another process. Hydra has no
//!   swap or page reclaim, so hints are checked and accepted without effect.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use super::vfs::{copy_in, copy_out};
use crate::arch::syscall::SyscallFrame;
use crate::fs::FileDescriptor;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EFAULT: i64 = -14;
const EXDEV: i64 = -18;
const EINVAL: i64 = -22;
const E2BIG: i64 = -7;
const ELOOP: i64 = -40;

const AT_FDCWD: u64 = -100i64 as u64;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const O_CREAT: u64 = 0o100;
const O_NOFOLLOW: u64 = 0o400000;
const O_TMPFILE: u64 = 0o20200000;

const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;
const RESOLVE_ALL: u64 = 0x3f;
/// Most symbolic links followed in one lookup (`MAXSYMLINKS`).
const MAX_LINKS: u32 = 40;

const NR_OPENAT: u64 = 257;
const NR_NEWFSTATAT: u64 = 262;
const NR_READLINKAT: u64 = 267;
const NR_EPOLL_PWAIT: u64 = 281;
const NR_FSTAT: u64 = 5;

/// Whether an absolute path names one of `/proc`'s magic links (`fd/N`, `exe`, `cwd`,
/// `root`, `ns/*`, `map_files/*`), which do not point at a path but at an object.
fn is_magic(abs: &str) -> bool {
    let Some(rest) = abs.strip_prefix("/proc/") else { return false };
    let Some((_, entry)) = rest.split_once('/') else { return false };
    matches!(entry, "exe" | "cwd" | "root") || entry.starts_with("fd/") || entry.starts_with("ns/") || entry.starts_with("map_files/")
}

/// Scratch user memory for `openat2`'s nested calls: a path, a `struct stat`, a link target.
struct Scratch {
    buf: super::xfer::Bounce,
}

impl Scratch {
    const PATH: u64 = 0;
    const STAT: u64 = 4096;
    const LINK: u64 = 4096 + 256;

    fn path(&self, p: &str) -> Result<u64, i64> {
        let mut b = p.as_bytes().to_vec();
        b.push(0);
        if b.len() > 4096 {
            return Err(-36); // ENAMETOOLONG
        }
        copy_out(self.buf.addr + Self::PATH, &b)?;
        Ok(self.buf.addr + Self::PATH)
    }
}

/// `openat2(2)`.
fn openat2(frame: &SyscallFrame, dirfd: u64, path_ptr: u64, how: u64, size: u64) -> i64 {
    if size < 24 {
        return EINVAL;
    }
    if size > 4096 {
        return E2BIG;
    }
    let raw = match copy_in(how, size as usize) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if raw[24..].iter().any(|&b| b != 0) {
        return E2BIG;
    }
    let field = |o: usize| u64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
    let (flags, mode, resolve) = (field(0), field(8), field(16));
    if flags >> 32 != 0 || resolve & !RESOLVE_ALL != 0 || mode & !0o7777 != 0 {
        return EINVAL;
    }
    if mode != 0 && flags & O_CREAT == 0 && flags & O_TMPFILE != O_TMPFILE {
        return EINVAL;
    }
    if resolve & RESOLVE_BENEATH != 0 && resolve & RESOLVE_IN_ROOT != 0 {
        return EINVAL;
    }
    if resolve & RESOLVE_CACHED != 0 {
        // Hydra cannot promise a lookup from cached state only; callers retry without
        return EAGAIN;
    }
    if resolve == 0 {
        return super::nested(frame, NR_OPENAT, [dirfd, path_ptr, flags, mode, 0, 0]);
    }
    let path = match super::vfs::user_path(path_ptr) {
        Ok(p) => String::from_utf8_lossy(&p).into_owned(),
        Err(e) => return e,
    };
    let scratch = match super::xfer::Bounce::new(8192) {
        Ok(b) => Scratch { buf: b },
        Err(e) => return e,
    };
    match walk(frame, &scratch, dirfd, &path, flags, resolve) {
        Ok((base, resolved)) => {
            let p = match scratch.path(&resolved) {
                Ok(p) => p,
                Err(e) => return e,
            };
            super::nested(frame, NR_OPENAT, [base, p, flags, mode, 0, 0])
        }
        Err(e) => e,
    }
}

/// Walks `path` from `dirfd` under the `resolve` restrictions, expanding symbolic links.
///
/// # Returns
/// The descriptor to open relative to and the resolved path (no symbolic links left except
/// a final one with `O_NOFOLLOW`, or a final component that does not exist yet).
fn walk(frame: &SyscallFrame, s: &Scratch, dirfd: u64, path: &str, flags: u64, resolve: u64) -> Result<(u64, String), i64> {
    let beneath = resolve & RESOLVE_BENEATH != 0;
    let in_root = resolve & RESOLVE_IN_ROOT != 0;
    let stat_at = |base: u64, p: &str| -> Result<(u64, u32), i64> {
        let pp = s.path(p)?;
        let r = super::nested(frame, NR_NEWFSTATAT, [base, pp, s.buf.addr + Scratch::STAT, AT_SYMLINK_NOFOLLOW, 0, 0]);
        if r < 0 {
            return Err(r);
        }
        let st = copy_in(s.buf.addr + Scratch::STAT, 32)?;
        Ok((u64::from_le_bytes(st[0..8].try_into().unwrap()), u32::from_le_bytes(st[24..28].try_into().unwrap())))
    };
    // Absolute paths: outside the starting directory (BENEATH), inside it (IN_ROOT), or
    // from the process root
    let mut absolute = path.starts_with('/') && !in_root;
    if path.starts_with('/') && beneath {
        return Err(EXDEV);
    }
    let base_of = |absolute: bool| if absolute { AT_FDCWD } else { dirfd };
    let join = |stack: &[String], absolute: bool| -> String {
        if stack.is_empty() {
            String::from(if absolute { "/" } else { "." })
        } else if absolute {
            alloc::format!("/{}", stack.join("/"))
        } else {
            stack.join("/")
        }
    };
    // The starting directory's device, for NO_XDEV, and its absolute path, for NO_MAGICLINKS
    let start_dev = if resolve & RESOLVE_NO_XDEV != 0 {
        if absolute {
            Some(stat_at(AT_FDCWD, "/")?.0)
        } else if dirfd == AT_FDCWD {
            Some(stat_at(AT_FDCWD, ".")?.0)
        } else {
            let r = super::nested(frame, NR_FSTAT, [dirfd, s.buf.addr + Scratch::STAT, 0, 0, 0, 0]);
            if r < 0 {
                return Err(r);
            }
            Some(u64::from_le_bytes(copy_in(s.buf.addr + Scratch::STAT, 8)?[..8].try_into().unwrap()))
        }
    } else {
        None
    };
    let dir_abs = if dirfd == AT_FDCWD {
        String::from(".")
    } else {
        let link = alloc::format!("/proc/self/fd/{}", dirfd as i32);
        let pp = s.path(&link)?;
        let n = super::nested(frame, NR_READLINKAT, [AT_FDCWD, pp, s.buf.addr + Scratch::LINK, 3800, 0, 0]);
        if n < 0 {
            return Err(EBADF);
        }
        String::from_utf8_lossy(&copy_in(s.buf.addr + Scratch::LINK, n as usize)?).into_owned()
    };
    let mut rest: VecDeque<String> = path.split('/').map(String::from).collect();
    let mut stack: Vec<String> = Vec::new();
    let mut links = 0;
    while let Some(c) = rest.pop_front() {
        if c.is_empty() || c == "." {
            continue;
        }
        if c == ".." {
            if stack.is_empty() || stack.last().is_some_and(|l| l == "..") {
                if beneath {
                    return Err(EXDEV);
                }
                if in_root || absolute {
                    continue; // the root's parent is the root
                }
                stack.push(c); // above the starting directory, allowed without a restriction
            } else {
                stack.pop();
            }
            continue;
        }
        stack.push(c);
        let cur = join(&stack, absolute);
        let last = rest.iter().all(|r| r.is_empty() || r == ".");
        let (dev, mode) = match stat_at(base_of(absolute), &cur) {
            Ok(v) => v,
            Err(ENOENT) if last => break, // O_CREAT may create it
            Err(e) => return Err(e),
        };
        if start_dev.is_some_and(|d| d != dev) {
            return Err(EXDEV);
        }
        if mode & 0o170000 != 0o120000 {
            continue;
        }
        // A symbolic link
        if last && flags & O_NOFOLLOW != 0 {
            break; // open fails with ELOOP itself
        }
        let abs_cur = if absolute { cur.clone() } else { alloc::format!("{}/{}", dir_abs, cur) };
        if resolve & RESOLVE_NO_SYMLINKS != 0 || (resolve & RESOLVE_NO_MAGICLINKS != 0 && is_magic(&abs_cur)) {
            return Err(ELOOP);
        }
        links += 1;
        if links > MAX_LINKS {
            return Err(ELOOP);
        }
        let pp = s.path(&cur)?;
        let n = super::nested(frame, NR_READLINKAT, [base_of(absolute), pp, s.buf.addr + Scratch::LINK, 3800, 0, 0]);
        if n < 0 {
            return Err(n);
        }
        let target = String::from_utf8_lossy(&copy_in(s.buf.addr + Scratch::LINK, n as usize)?).into_owned();
        stack.pop();
        if target.starts_with('/') {
            if beneath {
                return Err(EXDEV);
            }
            stack.clear();
            if !in_root {
                absolute = true;
            }
        }
        for (i, part) in target.split('/').enumerate() {
            rest.insert(i, String::from(part));
        }
    }
    Ok((base_of(absolute), join(&stack, absolute)))
}

/// The process behind pidfd `fd`, if the caller may reach into it (same real user as the
/// target's real, effective and saved user, or `CAP_SYS_PTRACE`).
fn ptrace_target(fd: u64) -> Result<u64, i64> {
    let pid = super::pidfd::pid_of(fd)?;
    let target = crate::task::SCHEDULER.lock().with_process(pid, |t| (t.uid, t.euid, t.suid, t.service.is_some()));
    let Some((uid, euid, suid, service)) = target else { return Err(ESRCH) };
    if service {
        return Err(EPERM);
    }
    let (me, cap) = crate::task::with_current_task_mut(|t| (t.uid, t.caps.has(1 << 19))).unwrap_or((u32::MAX, false));
    if !cap && !(me == uid && me == euid && me == suid) {
        return Err(EPERM);
    }
    Ok(pid)
}

/// `pidfd_getfd(2)`: a copy (close-on-exec) of descriptor `target` of the pidfd's process.
fn pidfd_getfd(pidfd: u64, target: u64, flags: u64) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    let pid = match ptrace_target(pidfd) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let Some(fds) = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone()) else { return ESRCH };
    let desc = fds.lock().get(target as usize).cloned();
    let Some(desc) = desc else { return EBADF };
    match &desc {
        FileDescriptor::PipeRead(p) => p.lock().add_reader(),
        FileDescriptor::PipeWrite(p) => p.lock().add_writer(),
        _ => {}
    }
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(desc) {
        Ok(fd) => {
            fds.set_cloexec(fd, true);
            fd as i64
        }
        Err(_) => -24, // EMFILE
    })
}

/// `process_madvise(2)`: hints are checked (ptrace access and `CAP_SYS_NICE`, as Linux) and
/// accepted; Hydra keeps every page resident.
fn process_madvise(pidfd: u64, iov: u64, vlen: u64, advice: u64, flags: u64) -> i64 {
    // MADV_WILLNEED, MADV_COLD, MADV_PAGEOUT, MADV_COLLAPSE
    if flags != 0 || !matches!(advice, 3 | 20 | 21 | 25) || vlen > 1024 {
        return EINVAL;
    }
    if let Err(e) = ptrace_target(pidfd) {
        return e;
    }
    // Since Linux 5.12 the hints also take CAP_SYS_NICE
    if !crate::task::with_current_task_mut(|t| t.caps.has(1 << 23)).unwrap_or(false) {
        return EPERM;
    }
    let raw = match copy_in(iov, vlen as usize * 16) {
        Ok(r) => r,
        Err(e) => return e,
    };
    raw.chunks(16).map(|c| u64::from_le_bytes(c[8..16].try_into().unwrap())).sum::<u64>() as i64
}

/// `process_mrelease(2)`: frees a dying process's memory early. Hydra frees it when the
/// process is reaped; the call only checks the process is indeed exiting.
fn process_mrelease(pidfd: u64, flags: u64) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    let pid = match super::pidfd::pid_of(pidfd) {
        Ok(p) => p,
        Err(e) => return e,
    };
    if super::proc::has_exited(pid) { 0 } else { EINVAL }
}

/// Handles the calls of this module.
///
/// # Arguments
/// * `frame` - The caller's registers.
/// * `num` - System call number.
///
/// # Returns
/// The call's result or a negative errno.
pub fn dispatch(frame: &mut SyscallFrame, num: u64) -> i64 {
    let a = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    // Descriptor arguments are C ints: only the low 32 bits of the register count
    let fd = |v: u64| v as i32 as i64 as u64;
    match num {
        437 => openat2(frame, fd(a[0]), a[1], a[2], a[3]),
        // epoll_pwait2(epfd, events, maxevents, timeout*, sigmask, sigsetsize)
        441 => {
            let ms = if a[3] == 0 {
                -1i64 as u64
            } else {
                let t = match copy_in(a[3], 16) {
                    Ok(t) => t,
                    Err(_) => return EFAULT,
                };
                let (s, ns) = (i64::from_le_bytes(t[0..8].try_into().unwrap()), i64::from_le_bytes(t[8..16].try_into().unwrap()));
                if s < 0 || !(0..1_000_000_000).contains(&ns) {
                    return EINVAL;
                }
                ((s as u128 * 1000 + (ns as u128).div_ceil(1_000_000)).min(i32::MAX as u128)) as u64
            };
            super::nested(frame, NR_EPOLL_PWAIT, [fd(a[0]), a[1], a[2], ms, a[4], a[5]])
        }
        438 => pidfd_getfd(fd(a[0]), fd(a[1]), a[2]),
        440 => process_madvise(fd(a[0]), a[1], a[2], a[3], a[4]),
        448 => process_mrelease(fd(a[0]), a[1]),
        _ => -38,
    }
}
