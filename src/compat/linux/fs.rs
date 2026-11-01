//! # Linux Compatibility: Pseudo-Filesystem Emulation (`/dev` & `/proc`)
//!
//! Provides synthetic in-memory emulation for essential Linux virtual filesystems
//! (`/dev/null`, `/dev/zero`, `/dev/urandom`, and `/proc/*` informational nodes).
//!
//! ## Architectural Role & Design Rationale
//! Standard C libraries (`musl`, `glibc`), dynamic linkers, and system utilities query
//! `/dev` and `/proc` during startup to seed random number generators, discover memory
//! and CPU topology, and inspect the current process's executable path or auxiliary vector.
//! This module synthesizes these files on-the-fly from live kernel state without requiring
//! backing storage on the ZFS pool.
//!
//! ## Key Types & Interfaces
//! - [`PseudoFile`]: Enumeration of supported virtual device and `/proc` nodes.
//! - [`match_pseudo_path()`]: Resolves a canonical path string to a [`PseudoFile`] variant.
//! - [`proc_link()`]: Resolves dynamic `/proc/self/cwd`, `/proc/self/exe`, `/proc/<pid>/root` and `/proc/<pid>/exe` symbolic links.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reads PIT tick counter ([`crate::arch::pit::ticks`]) to seed PRNG
//!   for `/dev/urandom`.
//! - Concurrency: Stateless enum variants reading atomic/spinlock-guarded kernel metrics.

use crate::compat::linux::types::*;

/// Identifies an emulated Linux virtual file under `/dev` or `/proc`.
pub enum PseudoFile {
    /// `/dev/null`: discards all writes and immediately returns EOF (`0` bytes) on read.
    DevNull,
    /// `/dev/zero`: discards all writes and fills read buffers with zero bytes (`0x00`).
    DevZero,
    /// `/dev/urandom` and `/dev/random`: generates pseudo-random bytes on read.
    DevUrandom,
    /// `/proc/version`: reports the kernel release and compiler version banner.
    ProcVersion,
    /// `/proc/meminfo`: reports total and free kernel heap memory in `kB`.
    ProcMeminfo,
    /// `/proc/cpuinfo`: reports `x86_64` processor identification and feature flags.
    ProcCpuinfo,
    /// `/proc/self/maps`: reports the virtual memory regions of the calling process.
    ProcSelfMaps,
    /// `/proc/self/auxv`: exposes the raw ELF auxiliary vector of the calling process.
    ProcSelfAuxv,
    /// `/proc/self/mountinfo` (and `/proc/<pid>/mountinfo`): the mount table, detailed.
    ProcMountinfo,
    /// `/proc/mounts` (`/proc/self/mounts`): the mount table in `fstab` format.
    ProcMounts,
    /// `/proc/<pid>/cmdline`, `comm` and `fdinfo/<fd>` (the path after `/proc/`). Their
    /// text is captured when opened ([`proc_pid_file_text`]); reads through the path see EOF.
    ProcPidFile(alloc::string::String),
}

/// The mounts a Linux system has, as Hydra presents them: the pool at `/` (device 8:1,
/// mount id 2069 = what `statx` reports for its files), and the pseudo file systems.
const MOUNTINFO: &str = "2069 1 8:1 / / rw,relatime shared:1 - zfs hydrapool/root rw,xattr
22 2069 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw
23 2069 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:3 - sysfs sysfs rw
24 2069 0:6 / /dev rw,nosuid,relatime shared:4 - devtmpfs udev rw,mode=755
25 24 0:25 / /dev/pts rw,nosuid,noexec,relatime shared:5 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
26 2069 0:26 / /run rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,mode=755
";

const MOUNTS: &str = "hydrapool/root / zfs rw,relatime,xattr 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
";

/// Matches a normalized filesystem path against known `/dev` and `/proc` pseudo-files.
///
/// # Arguments
/// * `path` - Absolute path string to inspect.
///
/// # Returns
/// * `Some(PseudoFile)` if `path` names a recognized virtual device or `/proc` entry.
/// * `None` if `path` should be resolved against the real ZFS filesystem.
pub fn match_pseudo_path(path: &str) -> Option<PseudoFile> {
    match path {
        "/dev/null" => Some(PseudoFile::DevNull),
        "/dev/zero" => Some(PseudoFile::DevZero),
        "/dev/urandom" | "/dev/random" => Some(PseudoFile::DevUrandom),
        "/proc/version" => Some(PseudoFile::ProcVersion),
        "/proc/meminfo" => Some(PseudoFile::ProcMeminfo),
        "/proc/cpuinfo" => Some(PseudoFile::ProcCpuinfo),
        "/proc/self/maps" => Some(PseudoFile::ProcSelfMaps),
        "/proc/self/auxv" => Some(PseudoFile::ProcSelfAuxv),
        "/proc/self/mountinfo" | "/proc/thread-self/mountinfo" => Some(PseudoFile::ProcMountinfo),
        "/proc/mounts" | "/proc/self/mounts" | "/proc/thread-self/mounts" => Some(PseudoFile::ProcMounts),
        p if p.starts_with("/proc/") && p.ends_with("/mountinfo") && p[6..p.len() - 10].bytes().all(|b| b.is_ascii_digit()) => {
            Some(PseudoFile::ProcMountinfo)
        }
        p if p.starts_with("/proc/") && is_proc_pid_file(&p[6..]) => Some(PseudoFile::ProcPidFile(alloc::string::String::from(&p[6..]))),
        _ => None,
    }
}

/// Whether `rest` (a path after `/proc/`) names `<pid>/cmdline`, `<pid>/comm` or
/// `<pid>/fdinfo/<fd>`, with `<pid>` also `self` or `thread-self`. Takes no locks: path
/// lookups run under the scheduler lock.
fn is_proc_pid_file(rest: &str) -> bool {
    let Some((who, file)) = rest.split_once('/') else { return false };
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    (who == "self" || who == "thread-self" || numeric(who))
        && (file == "cmdline" || file == "comm" || file.strip_prefix("fdinfo/").is_some_and(numeric))
}

/// Text of `/proc/<pid>/cmdline`, `comm` or `fdinfo/<fd>` (`rest` is the path after
/// `/proc/`), or `None` if the process or descriptor does not exist.
///
/// D-Bus needs these to identify its peers: it reads the `Pid:` line of a pidfd's `fdinfo`
/// (without it the peer's pid is unknown, logged as `pid=18446744073709551615`) and names
/// the peer by its `cmdline`.
///
/// Takes the scheduler lock and the process's descriptor table lock, so it must be called
/// with neither held (when the file is opened, not when it is read).
pub fn proc_pid_file_text(rest: &str) -> Option<alloc::vec::Vec<u8>> {
    let (who, file) = rest.split_once('/')?;
    let pid = match who {
        "self" | "thread-self" => super::proc::current_ids().1,
        n => n.parse().ok()?,
    };
    // The descriptor table has its own lock, taken after the scheduler's is released
    let (exe, cmdline, fds) = crate::task::SCHEDULER
        .lock()
        .with_process(pid, |t| (alloc::string::String::from(t.exe_path()), t.cmdline.clone(), t.fds.clone()))?;
    match file {
        "cmdline" => Some(cmdline.map(|c| c.to_vec()).unwrap_or_default()),
        "comm" => {
            // The executable's file name, truncated to TASK_COMM_LEN - 1 bytes
            let mut comm: alloc::vec::Vec<u8> = exe.rsplit('/').next().unwrap_or("").bytes().take(15).collect();
            comm.push(b'\n');
            Some(comm)
        }
        f => {
            let fd: usize = f.strip_prefix("fdinfo/")?.parse().ok()?;
            let (pos, cloexec, pidfd) = {
                let table = fds.lock();
                let desc = table.get(fd)?;
                let pos = match desc {
                    crate::fs::FileDescriptor::File { cursor, .. } => *cursor as u64,
                    _ => 0,
                };
                let pidfd = match desc {
                    crate::fs::FileDescriptor::PidFd(p) => Some(p.pid),
                    _ => None,
                };
                (pos, table.cloexec(fd), pidfd)
            };
            let flags = 0o2 | if cloexec { 0o2000000 } else { 0 };
            let mut text = alloc::format!("pos:\t{}\nflags:\t0{:o}\nmnt_id:\t2069\n", pos, flags);
            if let Some(p) = pidfd {
                // -1 once the process has exited, as Linux reports it
                let alive = crate::task::SCHEDULER.lock().with_process(p, |_| ()).is_some();
                let shown = if alive { p as i64 } else { -1 };
                text.push_str(&alloc::format!("Pid:\t{}\nNSpid:\t{}\n", shown, shown));
            }
            Some(text.into_bytes())
        }
    }
}

impl PseudoFile {
    /// Synthesizes data for a read operation on this pseudo-file starting at `cursor`.
    ///
    /// # Arguments
    /// * `cursor` - Current byte offset within the open file description.
    /// * `buf` - Destination slice to fill with synthesized bytes.
    ///
    /// # Returns
    /// Number of bytes written into `buf` (`0` indicates end-of-file).
    pub fn read(&self, cursor: usize, buf: &mut [u8]) -> usize {
        match self {
            PseudoFile::DevNull => 0,
            PseudoFile::DevZero => {
                buf.fill(0);
                buf.len()
            }
            PseudoFile::DevUrandom => {
                // Generate pseudo-random bytes using PIT ticks and linear-feedback PRNG
                let mut seed = crate::arch::pit::ticks().wrapping_mul(0x5DEECE66D).wrapping_add(11);
                for byte in buf.iter_mut() {
                    seed = seed.wrapping_mul(0x5DEECE66D).wrapping_add(11);
                    *byte = (seed >> 16) as u8;
                }
                buf.len()
            }
            PseudoFile::ProcVersion => {
                let content = b"Linux version 6.8.0-hydra (gcc-13 / rustc-1.80) #1 SMP PREEMPT Hydra Microkernel\n";
                read_slice(content, cursor, buf)
            }
            PseudoFile::ProcMeminfo => {
                // Physical memory (as sysinfo reports it); no swap. System monitors read
                // the swap and cache lines too and show garbage when they are missing.
                let fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
                let (total, free) = (fa.total_usable_memory() / 1024, fa.free_memory() / 1024);
                drop(fa);
                let mut text = alloc::format!("MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\n", total, free, free);
                for field in ["Buffers", "Cached", "SwapCached", "SwapTotal", "SwapFree", "Shmem", "SReclaimable", "SUnreclaim"] {
                    text.push_str(&alloc::format!("{:<16}{:8} kB\n", alloc::format!("{}:", field), 0));
                }
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcCpuinfo => {
                let text = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 1\nmodel name\t: x86_64 Hydra Virtual CPU\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx lm\n\n";
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcSelfAuxv => {
                let auxv = super::process::current_auxv();
                read_slice(&auxv, cursor, buf)
            }
            PseudoFile::ProcMountinfo => read_slice(MOUNTINFO.as_bytes(), cursor, buf),
            PseudoFile::ProcMounts => read_slice(MOUNTS.as_bytes(), cursor, buf),
            PseudoFile::ProcPidFile(_) => 0,
            PseudoFile::ProcSelfMaps => {
                let text = "00400000-00452000 r-xp 00000000 00:00 0 /bin/app\n00652000-00653000 rw-p 00052000 00:00 0 /bin/app\n7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n";
                read_slice(text.as_bytes(), cursor, buf)
            }
        }
    }

    /// Handles a write operation on this pseudo-file.
    ///
    /// Character devices (`/dev/null`, `/dev/zero`, `/dev/urandom`) absorb all bytes;
    /// `/proc` entries are read-only and return `0`.
    ///
    /// # Arguments
    /// * `buf` - Slice of bytes written by the caller.
    ///
    /// # Returns
    /// Number of bytes consumed (`buf.len()` for `/dev/*`, `0` for `/proc/*`).
    pub fn write(&self, buf: &[u8]) -> usize {
        match self {
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevUrandom => buf.len(),
            _ => 0, // /proc is read-only
        }
    }

    /// Populates a [`LinuxStat`] buffer with synthetic inode metadata for this pseudo-file.
    ///
    /// # Arguments
    /// * `statbuf` - Mutable [`LinuxStat`] structure to fill.
    pub fn stat(&self, statbuf: &mut LinuxStat) {
        statbuf.st_dev = 1;
        statbuf.st_ino = 1;
        statbuf.st_nlink = 1;
        statbuf.st_uid = 0;
        statbuf.st_gid = 0;
        statbuf.st_blksize = 4096;

        match self {
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevUrandom => {
                statbuf.st_mode = S_IFCHR | 0o666;
                statbuf.st_size = 0;
            }
            _ => {
                statbuf.st_mode = S_IFREG | 0o444;
                statbuf.st_size = 512;
            }
        }
    }
}

/// Copies a window of `data` starting at `cursor` into `buf`.
fn read_slice(data: &[u8], cursor: usize, buf: &mut [u8]) -> usize {
    if cursor >= data.len() {
        return 0;
    }
    let available = &data[cursor..];
    let to_copy = available.len().min(buf.len());
    buf[..to_copy].copy_from_slice(&available[..to_copy]);
    to_copy
}

/// Resolves the target of a `/proc/self/*` symbolic link (`/proc/self/exe`, `/proc/self/cwd`).
///
/// # Arguments
/// * `path` - Absolute `/proc` path to inspect.
///
/// # Returns
/// * `Some(String)` containing the target path if `path` is a known `/proc/self` symlink.
/// * `None` if `path` is not a dynamic `/proc` symlink.
pub fn proc_link(path: &str) -> Option<alloc::string::String> {
    match path {
        "/proc/self/cwd" => Some(crate::task::with_current_fds_mut(|fds| fds.cwd_path.clone())),
        "/proc/self/exe" => crate::task::with_current_task_mut(|t| alloc::string::String::from(t.exe_path())),
        // A process's root directory. Every Linux process shares the caller's root, so it
        // is "/" as the caller sees it. PipeWire opens it to tell host clients from
        // Flatpak sandboxes (".flatpak-info" in the client's root); a failure makes it
        // treat every client, the session manager included, as sandboxed.
        "/proc/self/root" => Some(alloc::string::String::from("/")),
        _ => {
            // /proc/<pid>/root and /proc/<pid>/exe of another process (KWin reads the exe
            // link of a Wayland client to decide which privileged protocols it may bind)
            let (pid, entry) = path.strip_prefix("/proc/")?.split_once('/')?;
            let pid: u64 = pid.parse().ok()?;
            match entry {
                "root" => {
                    let alive = super::proc::PROCS.lock().get(&pid).map_or(false, |p| !p.zombie);
                    alive.then(|| alloc::string::String::from("/"))
                }
                "exe" => crate::task::SCHEDULER.lock().exe_of(pid),
                _ => None,
            }
        }
    }
}

