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
    /// `/dev/full`: reads zeros; every write fails with `ENOSPC`.
    DevFull,
    /// `/dev/urandom` and `/dev/random`: generates pseudo-random bytes on read.
    DevUrandom,
    /// `/proc/version`: reports the kernel release and compiler version banner.
    ProcVersion,
    /// `/proc/meminfo`: reports total and free kernel heap memory in `kB`.
    ProcMeminfo,
    /// `/proc/swaps`: the active swap areas.
    ProcSwaps,
    /// `/proc/locks`: the file locks held.
    ProcLocks,
    /// `/proc/net/{tcp,udp,tcp6,udp6,dev,unix}`: sockets and interfaces (index into
    /// [`PROC_NET`]).
    ProcNet(u8),
    /// `/proc/filesystems`: the file system types.
    ProcFilesystems,
    /// `/proc/cpuinfo`: reports `x86_64` processor identification and feature flags.
    ProcCpuinfo,
    /// `/sys/devices/system/cpu/{online,possible,present}`: the CPUs ("0-3").
    CpuRange,
    /// `/proc/stat`: CPU time per CPU (user, system, idle), boot time, process counts.
    ProcStat,
    /// `/proc/uptime`: seconds since boot, and idle seconds summed over the CPUs.
    ProcUptime,
    /// `/proc/loadavg`: load averages, running and total tasks, the last process ID.
    ProcLoadavg,
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
    /// Static read-only byte slice pseudo-file (e.g. `/proc/sys/fs/inotify/max_user_watches`).
    ProcStatic(&'static [u8]),
    /// `/proc/sys/kernel/random/boot_id` (`true`: one UUID per boot) and `uuid` (`false`: a
    /// new random UUID on every read).
    ProcUuid(bool),
    /// `/proc/keys`: the keys the caller may view
    ProcKeys,
    /// Virtual directory under `/proc` (e.g. `/proc/self/task`, `/proc/self/fd`, `/proc/<pid>/task`).
    ProcDir(alloc::string::String),
    /// `/sys/fs/cgroup<group>/cgroup.procs`: the processes in a control group (`group` is
    /// empty for the root). Writing a process ID moves the process there.
    CgroupProcs(alloc::string::String),
    /// `/proc/<pid>/uid_map`, `gid_map`, `setgroups` and `ns/<kind>` (the path after
    /// `/proc/`): read and written through [`super::ns`].
    ProcNs(alloc::string::String),
    /// `/proc/sys/user/max_user_namespaces` (per user namespace, writable there).
    MaxUserNs,
    /// `/proc/<pid>/oom_score_adj` and `oom_score` (the path after `/proc/`).
    ProcOom(alloc::string::String),
}

/// Where the cgroup v2 hierarchy is mounted.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The mounts a Linux system has, as Hydra presents them: the pool at `/` (device 8:1,
/// mount id 2069 = what `statx` reports for its files), and the pseudo file systems.
const MOUNTINFO: &str = "2069 1 8:1 / / rw,relatime shared:1 - zfs hydrapool/root rw,xattr
22 2069 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw
23 2069 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:3 - sysfs sysfs rw
27 23 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
24 2069 0:6 / /dev rw,nosuid,relatime shared:4 - devtmpfs udev rw,mode=755
25 24 0:25 / /dev/pts rw,nosuid,noexec,relatime shared:5 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
26 2069 0:26 / /run rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,mode=755
";

/// What `/proc/self/mountinfo` shows the caller (its mount namespace's table, or Hydra's
/// fixed layout).
pub fn mountinfo_text() -> alloc::string::String {
    super::mount::mountinfo(super::proc::current_ids().1).unwrap_or_else(|| alloc::format!("{}{}", MOUNTINFO, super::fuse::ns0_mountinfo_text()))
}

const MOUNTS: &str = "hydrapool/root / zfs rw,relatime,xattr 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot 0 0
udev /dev devtmpfs rw,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755 0 0
";

/// The socket tables under `/proc/net`.
const PROC_NET: [&str; 6] = ["tcp", "udp", "tcp6", "udp6", "dev", "unix"];

/// `/proc/net/<table>`, `/proc/self/net/<table>` or `/proc/<pid>/net/<table>` (one network
/// namespace view per caller, as `/proc/net` links to `self/net`).
fn proc_net_index(path: &str) -> Option<u8> {
    let rest = path.strip_prefix("/proc/")?;
    let table = match rest.strip_prefix("net/") {
        Some(t) => t,
        None => {
            let (who, t) = rest.split_once("/net/")?;
            if who != "self" && !who.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            t
        }
    };
    PROC_NET.iter().position(|&n| n == table).map(|i| i as u8)
}

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
        "/dev/full" => Some(PseudoFile::DevFull),
        "/dev/urandom" | "/dev/random" => Some(PseudoFile::DevUrandom),
        "/proc/version" => Some(PseudoFile::ProcVersion),
        "/proc/meminfo" => Some(PseudoFile::ProcMeminfo),
        "/proc/swaps" => Some(PseudoFile::ProcSwaps),
        "/proc/locks" => Some(PseudoFile::ProcLocks),
        p if proc_net_index(p).is_some() => proc_net_index(p).map(PseudoFile::ProcNet),
        "/proc/filesystems" => Some(PseudoFile::ProcFilesystems),
        "/proc/sys/kernel/dmesg_restrict" => Some(PseudoFile::ProcStatic(b"1\n")),
        "/proc/cpuinfo" => Some(PseudoFile::ProcCpuinfo),
        "/proc/stat" => Some(PseudoFile::ProcStat),
        "/proc/uptime" => Some(PseudoFile::ProcUptime),
        "/proc/loadavg" => Some(PseudoFile::ProcLoadavg),
        "/sys/devices/system/cpu/online" | "/sys/devices/system/cpu/possible" | "/sys/devices/system/cpu/present" => Some(PseudoFile::CpuRange),
        "/proc/self/maps" => Some(PseudoFile::ProcSelfMaps),
        "/proc/self/auxv" => Some(PseudoFile::ProcSelfAuxv),
        "/proc/self/mountinfo" | "/proc/thread-self/mountinfo" => Some(PseudoFile::ProcMountinfo),
        "/proc/mounts" | "/proc/self/mounts" | "/proc/thread-self/mounts" => Some(PseudoFile::ProcMounts),
        "/proc/sys/fs/inotify/max_user_watches" => Some(PseudoFile::ProcStatic(b"1048576\n")),
        "/proc/sys/fs/inotify/max_user_instances" => Some(PseudoFile::ProcStatic(b"1024\n")),
        "/proc/sys/fs/inotify/max_queued_events" => Some(PseudoFile::ProcStatic(b"16384\n")),
        // The IDs unmapped users and groups show as in a user namespace (see super::ns)
        "/proc/sys/kernel/overflowuid" | "/proc/sys/kernel/overflowgid" | "/proc/sys/fs/overflowuid" | "/proc/sys/fs/overflowgid" => {
            Some(PseudoFile::ProcStatic(b"65534\n"))
        }
        "/proc/sys/user/max_user_namespaces" => Some(PseudoFile::MaxUserNs),
        "/proc/sys/kernel/random/boot_id" => Some(PseudoFile::ProcUuid(true)),
        "/proc/sys/kernel/random/uuid" => Some(PseudoFile::ProcUuid(false)),
        "/proc/keys" => Some(PseudoFile::ProcKeys),
        "/proc/sys/kernel/random/entropy_avail" | "/proc/sys/kernel/random/poolsize" => Some(PseudoFile::ProcStatic(b"256\n")),
        // POSIX message queue limits (see super::mqueue)
        "/proc/sys/fs/mqueue/msg_max" | "/proc/sys/fs/mqueue/msg_default" => Some(PseudoFile::ProcStatic(b"10\n")),
        "/proc/sys/fs/mqueue/msgsize_max" | "/proc/sys/fs/mqueue/msgsize_default" => Some(PseudoFile::ProcStatic(b"8192\n")),
        "/proc/sys/fs/mqueue/queues_max" => Some(PseudoFile::ProcStatic(b"256\n")),
        // System V IPC limits (see super::sysv)
        "/proc/sys/kernel/shmmax" => Some(PseudoFile::ProcStatic(b"1099511627776\n")),
        "/proc/sys/kernel/shmall" => Some(PseudoFile::ProcStatic(b"268435456\n")),
        "/proc/sys/kernel/shmmni" => Some(PseudoFile::ProcStatic(b"4096\n")),
        "/proc/sys/kernel/sem" => Some(PseudoFile::ProcStatic(b"32000\t1024000000\t500\t32000\n")),
        "/proc/sys/kernel/msgmax" => Some(PseudoFile::ProcStatic(b"8192\n")),
        "/proc/sys/kernel/msgmnb" => Some(PseudoFile::ProcStatic(b"16384\n")),
        "/proc/sys/kernel/msgmni" => Some(PseudoFile::ProcStatic(b"32000\n")),
        // Yama mode 3 ("no attach"): true of Hydra, which has no ptrace at all
        "/proc/sys/kernel/yama/ptrace_scope" => Some(PseudoFile::ProcStatic(b"3\n")),
        "/proc/sys/kernel/perf_event_paranoid" => Some(PseudoFile::ProcStatic(b"2\n")),
        // /proc/<pid>/oom_score_adj and oom_score
        p if OOM_FILES && p.starts_with("/proc/") && is_oom_file(&p[6..]) => Some(PseudoFile::ProcOom(alloc::string::String::from(&p[6..]))),
        p if is_proc_dir(p) => Some(PseudoFile::ProcDir(alloc::string::String::from(p))),
        p if p.starts_with("/proc/") && p.ends_with("/mountinfo") && p[6..p.len() - 10].bytes().all(|b| b.is_ascii_digit()) => {
            Some(PseudoFile::ProcMountinfo)
        }
        p if p.starts_with("/proc/") && super::ns::is_ns_file(&p[6..]) => Some(PseudoFile::ProcNs(alloc::string::String::from(&p[6..]))),
        p if p.starts_with("/proc/") && is_proc_pid_file(&p[6..]) => Some(PseudoFile::ProcPidFile(alloc::string::String::from(&p[6..]))),
        p => {
            let group = p.strip_prefix(CGROUP_ROOT)?.strip_suffix("/cgroup.procs")?;
            (group.is_empty() || group.starts_with('/')).then(|| PseudoFile::CgroupProcs(alloc::string::String::from(group)))
        }
    }
}

/// Whether `path` names a dynamic `/proc` directory like `/proc/self/task`,
/// `/proc/self/fd`, `/proc/<pid>/task`, `/proc/<pid>/fd`.
pub fn is_proc_dir(path: &str) -> bool {
    let clean = path.trim_end_matches('/');
    let Some(rest) = clean.strip_prefix("/proc/") else { return false };
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    // /proc/<pid> itself (and /proc/self, /proc/thread-self followed)
    let Some((who, dir)) = rest.split_once('/') else { return rest == "self" || rest == "thread-self" || numeric(rest) };
    (who == "self" || who == "thread-self" || numeric(who)) && (dir == "task" || dir == "fd" || dir == "ns")
}

/// Whether `rest` (a path after `/proc/`) names `<pid>/cmdline`, `<pid>/comm` or
/// `<pid>/fdinfo/<fd>`, with `<pid>` also `self` or `thread-self`. Takes no locks: path
/// lookups run under the scheduler lock.
///
/// # Arguments
///
/// * `rest` - Path suffix following `/proc/`.
///
/// # Returns
///
/// `true` if the path matches a known process-specific `/proc` virtual file.
fn is_proc_pid_file(rest: &str) -> bool {
    let Some((who, file)) = rest.split_once('/') else { return false };
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    (who == "self" || who == "thread-self" || numeric(who))
        && (matches!(file, "cmdline" | "comm" | "status" | "stat" | "cgroup" | "auxv" | "maps" | "limits")
            || file.strip_prefix("fdinfo/").is_some_and(numeric)
            || file.strip_prefix("task/").and_then(|r| r.split_once('/')).is_some_and(|(t, f)| numeric(t) && matches!(f, "status" | "stat" | "comm")))
}

/// Serve `/proc/<pid>/oom_score_adj` and `oom_score` (see [`match_pseudo_path`]).
const OOM_FILES: bool = true;

/// Whether `rest` (a path after `/proc/`) is `<pid>/oom_score_adj` or `<pid>/oom_score`.
fn is_oom_file(rest: &str) -> bool {
    let Some((who, file)) = rest.split_once('/') else { return false };
    (who == "self" || (!who.is_empty() && who.bytes().all(|b| b.is_ascii_digit()))) && matches!(file, "oom_score_adj" | "oom_score")
}

/// Process ID and file name of a `/proc/<pid>/<file>` path (after `/proc/`).
fn pid_and_file(rest: &str) -> Option<(u64, &str)> {
    let (who, file) = rest.split_once('/')?;
    let pid = match who {
        "self" | "thread-self" => super::proc::current_ids().1,
        n => super::ns::pid_from_caller(n.parse().ok()?),
    };
    Some((pid, file))
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
///
/// # Arguments
///
/// * `rest` - Path suffix following `/proc/`.
///
/// # Returns
///
/// Generated byte contents of the target `/proc` file, or `None` if process or entry not found.
pub fn proc_pid_file_text(rest: &str) -> Option<alloc::vec::Vec<u8>> {
    let (who, file) = rest.split_once('/')?;
    let pid = match who {
        "self" | "thread-self" => super::proc::current_ids().1,
        n => super::ns::pid_from_caller(n.parse().ok()?),
    };
    // task/<tid>/<file>: a thread's own status, stat or comm
    let (file, tid) = match file.strip_prefix("task/") {
        Some(r) => {
            let (t, f) = r.split_once('/')?;
            let t: u64 = t.parse().ok()?;
            if !super::proc::thread_ids_of(pid).contains(&t) {
                return None;
            }
            (f, t)
        }
        None => (file, pid),
    };
    if file == "maps" {
        // Another process's mappings (debuggers, profilers)
        super::extra::may_access(pid).ok()?;
        let mm = crate::task::SCHEDULER.lock().with_process(pid, |t| t.mm.clone()).flatten()?;
        let text = mm.lock().maps_text();
        return Some(text.into_bytes());
    }
    if file == "limits" {
        return Some(super::limits::limits_text(pid).into_bytes());
    }
    if file == "auxv" {
        // Another process's auxiliary vector (debuggers find where a program was loaded)
        super::extra::may_access(pid).ok()?;
        let mm = crate::task::SCHEDULER.lock().with_process(pid, |t| t.mm.clone()).flatten()?;
        let auxv = mm.lock().auxv.clone();
        return Some(auxv);
    }
    if file == "cgroup" {
        // cgroup v2 only. libsystemd finds the hierarchy's root from pid 1's group (the
        // init process Hydra does not have: it is the kernel's)
        let group = super::proc::PROCS.lock().get(&pid).map(|p| p.cgroup.clone());
        let path = match (group, pid) {
            (Some(g), _) => alloc::string::String::from(g.as_deref().unwrap_or("/")),
            (None, 1) => alloc::string::String::from("/init.scope"),
            (None, _) => return None,
        };
        return Some(alloc::format!("0::{}\n", path).into_bytes());
    }
    // The descriptor table has its own lock, taken after the scheduler's is released
    let (exe, cmdline, ids) = crate::task::SCHEDULER
        .lock()
        .with_process(pid, |t| (alloc::string::String::from(t.exe_path()), t.cmdline.clone(), [t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid]))?;
    match file {
        "status" => {
            // The fields tools read: name, ids, parent (login managers walk it to a session)
            let (ppid, inits) = super::proc::PROCS.lock().get(&pid).map_or((0, alloc::vec::Vec::new()), |p| (p.ppid, p.ns.pid_inits.clone()));
            let (nnp, seccomp_mode) = super::seccomp::status_of(pid);
            // NStgid/NSpid: the ID in each PID namespace the process is in, outermost first
            // (only the init of a namespace is renumbered, to 1)
            let ns_ids = |id: u64| {
                let mut s = alloc::format!("{}", id);
                for init in &inits {
                    s.push_str(&alloc::format!("\t{}", if *init == id { 1 } else { id }));
                }
                s
            };
            let (nstgid, nspid) = (ns_ids(pid), ns_ids(tid));
            let tracer = match super::ptrace::tracer_of(pid) {
                0 => 0,
                t => super::ns::pid_to_caller(t),
            };
            let name: alloc::string::String = exe.rsplit('/').next().unwrap_or("").chars().take(15).collect();
            Some(
                alloc::format!(
                    "Name:	{}
State:	R (running)
Tgid:	{}
Pid:	{}
PPid:	{}
TracerPid:	{}
Uid:	{}	{}	{}	{}
Gid:	{}	{}	{}	{}
NStgid:	{}
NSpid:	{}
VmLck:	{} kB
NoNewPrivs:	{}
Seccomp:	{}
",
                    name, pid, tid, ppid, tracer, ids[0], ids[1], ids[2], ids[1], ids[3], ids[4], ids[5], ids[4], nstgid, nspid,
                    super::limits::locked_kib(pid), nnp as u8, seccomp_mode
                )
                .into_bytes(),
            )
        }
        "stat" => {
            // The 52 fields of proc(5); those Hydra does not keep (fault counts, memory
            // addresses) are 0
            let (ppid, pgid, sid, threads, start, zombie) = super::proc::PROCS
                .lock()
                .get(&pid)
                .map_or((0, pid, pid, 1, 0, false), |p| (p.ppid, p.pgid, p.sid, p.threads_alive().max(1), p.start_time, p.zombie));
            let comm: alloc::string::String = exe.rsplit('/').next().unwrap_or("").chars().take(15).collect();
            // CPU time (user, system, waited-for children's), in clock ticks
            let cpu = super::proc::cpu_times(pid);
            let ct = super::proc::to_clock_ticks;
            let cpu = (ct(cpu.0), ct(cpu.1), ct(cpu.2), ct(cpu.3));
            let mut text = alloc::format!(
                "{} ({}) {} {} {} {} 0 -1 4194304 0 0 0 0 {} {} {} {} {} {} {} 0 {}",
                pid,
                comm,
                if zombie { 'Z' } else { 'S' },
                ppid,
                pgid,
                sid,
                cpu.0,
                cpu.1,
                cpu.2,
                cpu.3,
                20 + super::extra::sched_of(tid).1,
                super::extra::sched_of(tid).1,
                threads,
                start
            );
            for _ in 23..=52 {
                text.push_str(" 0");
            }
            text.push('\n');
            Some(text.into_bytes())
        }
        "cmdline" => Some(cmdline.map(|c| c.to_vec()).unwrap_or_default()),
        "comm" => {
            // The executable's file name, truncated to TASK_COMM_LEN - 1 bytes
            let mut comm: alloc::vec::Vec<u8> = exe.rsplit('/').next().unwrap_or("").bytes().take(15).collect();
            comm.push(b'\n');
            Some(comm)
        }
        f => {
            let fd: usize = f.strip_prefix("fdinfo/")?.parse().ok()?;
            // Only fdinfo needs the table: holding a reference to another process's table
            // can make this caller the one that closes its files when that process exits
            let fds = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone())?;
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
            PseudoFile::DevZero | PseudoFile::DevFull => {
                buf.fill(0);
                buf.len()
            }
            PseudoFile::DevUrandom => {
                crate::arch::random::fill(buf);
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
                let (swap_total, swap_free) = super::admin::swap_kib();
                for field in ["Buffers", "Cached", "SwapCached", "SwapTotal", "SwapFree", "Shmem", "SReclaimable", "SUnreclaim"] {
                    let v = match field {
                        "SwapTotal" => swap_total,
                        "SwapFree" => swap_free,
                        _ => 0,
                    };
                    text.push_str(&alloc::format!("{:<16}{:8} kB\n", alloc::format!("{}:", field), v));
                }
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcSwaps => read_slice(super::admin::swaps_text().as_bytes(), cursor, buf),
            PseudoFile::ProcLocks => read_slice(super::locks::proc_locks().as_bytes(), cursor, buf),
            PseudoFile::ProcNet(i) => {
                let text = match PROC_NET[*i as usize] {
                    "unix" => super::unix::proc_net_unix(),
                    t => super::inet::proc_net(t).unwrap_or_default(),
                };
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcFilesystems => read_slice(super::admin::filesystems_text().as_bytes(), cursor, buf),
            PseudoFile::ProcStat => read_slice(proc_stat_text().as_bytes(), cursor, buf),
            PseudoFile::ProcUptime => {
                let up = crate::arch::pit::now_ns() / 10_000_000; // hundredths of a second
                let n = crate::arch::smp::online().max(1);
                let idle: u64 = (0..n).map(|c| super::proc::to_clock_ticks(cpu_ticks(c)[crate::task::scheduler::CPU_IDLE])).sum();
                let text = alloc::format!("{}.{:02} {}.{:02}
", up / 100, up % 100, idle / 100, idle % 100);
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcLoadavg => {
                let l = |i: usize| crate::task::scheduler::LOAD_AVG[i].load(core::sync::atomic::Ordering::Relaxed);
                let f = |v: u64| alloc::format!("{}.{:02}", v >> 11, ((v & 2047) * 100) >> 11);
                let (running, total) = crate::task::SCHEDULER.lock().task_counts();
                let last = super::proc::PROCS.lock().keys().next_back().copied().unwrap_or(0);
                let text = alloc::format!("{} {} {} {}/{} {}
", f(l(0)), f(l(1)), f(l(2)), running, total, last);
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcCpuinfo => {
                // One entry per CPU online
                let n = crate::arch::smp::online();
                let mut text = alloc::string::String::new();
                for i in 0..n {
                    text.push_str(&alloc::format!(
                        "processor\t: {i}\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 1\nmodel name\t: x86_64 Hydra Virtual CPU\nphysical id\t: 0\nsiblings\t: {n}\ncore id\t\t: {i}\ncpu cores\t: {n}\napicid\t\t: {i}\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx lm\n\n"
                    ));
                }
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::CpuRange => {
                let n = crate::arch::smp::online();
                let text = if n > 1 { alloc::format!("0-{}\n", n - 1) } else { alloc::string::String::from("0\n") };
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcSelfAuxv => {
                let auxv = super::process::current_auxv();
                read_slice(&auxv, cursor, buf)
            }
            // A mount namespace of its own lists its own table
            PseudoFile::ProcMountinfo => match super::mount::mountinfo(super::proc::current_ids().1) {
                Some(t) => read_slice(t.as_bytes(), cursor, buf),
                None => read_slice(alloc::format!("{}{}", MOUNTINFO, super::fuse::ns0_mountinfo_text()).as_bytes(), cursor, buf),
            },
            PseudoFile::ProcMounts => match super::mount::mounts(super::proc::current_ids().1) {
                Some(t) => read_slice(t.as_bytes(), cursor, buf),
                None => read_slice(alloc::format!("{}{}", MOUNTS, super::fuse::ns0_mounts_text()).as_bytes(), cursor, buf),
            },
            PseudoFile::ProcPidFile(_) => 0,
            PseudoFile::ProcOom(rest) => match pid_and_file(rest).and_then(|(pid, f)| super::proc::oom_file_text(pid, f)) {
                Some(text) => read_slice(text.as_bytes(), cursor, buf),
                None => 0,
            },
            PseudoFile::MaxUserNs => read_slice(super::ns::max_user_namespaces_text().as_bytes(), cursor, buf),
            PseudoFile::ProcNs(rest) if rest.contains("/ns/") => 0,
            PseudoFile::ProcNs(rest) => read_slice(super::ns::read_file(rest).as_bytes(), cursor, buf),
            PseudoFile::CgroupProcs(group) => {
                let mut text = alloc::string::String::new();
                for p in super::proc::PROCS.lock().values().filter(|p| !p.zombie && p.cgroup.as_deref().unwrap_or("") == group.as_str()) {
                    text.push_str(&alloc::format!("{}\n", p.pid));
                }
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcStatic(content) => read_slice(content, cursor, buf),
            PseudoFile::ProcUuid(boot) => read_slice(uuid_text(*boot).as_bytes(), cursor, buf),
            PseudoFile::ProcKeys => read_slice(super::keys::proc_keys().as_bytes(), cursor, buf),
            PseudoFile::ProcDir(_) => 0,
            PseudoFile::ProcSelfMaps => {
                let text = super::mm::current_mm().map(|m| m.lock().maps_text()).unwrap_or_default();
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
            PseudoFile::CgroupProcs(group) => {
                // A process ID ("0": the writer) moves that whole process into the group
                let text = core::str::from_utf8(buf).unwrap_or("");
                let Ok(mut pid) = text.trim().parse::<u64>() else { return 0 };
                if pid == 0 {
                    pid = super::proc::current_ids().1;
                }
                match super::proc::PROCS.lock().get_mut(&pid) {
                    Some(p) => {
                        p.cgroup = if group.is_empty() { None } else { Some(alloc::sync::Arc::from(group.as_str())) };
                        buf.len()
                    }
                    None => 0,
                }
            }
            PseudoFile::ProcNs(rest) => super::ns::write_file(rest, buf).max(0) as usize,
            PseudoFile::MaxUserNs => super::ns::set_max_user_namespaces(buf).max(0) as usize,
            PseudoFile::ProcOom(rest) => match pid_and_file(rest) {
                Some((pid, "oom_score_adj")) => super::proc::write_oom_score_adj(pid, buf).max(0) as usize,
                _ => 0,
            },
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
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevFull | PseudoFile::DevUrandom => {
                statbuf.st_mode = S_IFCHR | 0o666;
                statbuf.st_size = 0;
            }
            PseudoFile::CgroupProcs(_) => {
                statbuf.st_mode = S_IFREG | 0o644;
                statbuf.st_size = 0;
            }
            PseudoFile::ProcOom(rest) => {
                statbuf.st_mode = S_IFREG | if rest.ends_with("_adj") { 0o644 } else { 0o444 };
                statbuf.st_size = 0;
            }
            PseudoFile::ProcNs(rest) => {
                // ns/<kind> stats as the namespace (nsfs inodes are regular files, 0444)
                statbuf.st_mode = S_IFREG | if rest.contains("/ns/") { 0o444 } else { 0o644 };
                statbuf.st_size = 0;
            }
            PseudoFile::ProcDir(path) => {
                statbuf.st_mode = S_IFDIR | 0o555;
                statbuf.st_size = 4096;
                // A directory links "." and ".." plus one per subdirectory: for task/ that is
                // one per thread (Chromium counts threads this way and checks it is above 2)
                statbuf.st_nlink = 2;
                if let Some(rest) = path.trim_end_matches('/').strip_prefix("/proc/").and_then(|r| r.strip_suffix("/task")) {
                    let pid = if rest == "self" || rest == "thread-self" { super::proc::current_ids().1 } else { rest.parse().unwrap_or(0) };
                    statbuf.st_nlink += super::proc::thread_ids_of(pid).len() as u64;
                }
            }
            PseudoFile::ProcStatic(content) => {
                statbuf.st_mode = S_IFREG | 0o444;
                statbuf.st_size = content.len() as i64;
            }
            _ => {
                statbuf.st_mode = S_IFREG | 0o444;
                statbuf.st_size = 512;
            }
        }
    }
}

/// This boot's ID (`/proc/sys/kernel/random/boot_id`), drawn on first use.
static BOOT_ID: spin::Mutex<Option<[u8; 16]>> = spin::Mutex::new(None);

/// A random (version 4) UUID as text with a newline: this boot's ID (`boot`), or a new one.
fn uuid_text(boot: bool) -> alloc::string::String {
    let mut b = [0u8; 16];
    if boot {
        let mut id = BOOT_ID.lock();
        b = *id.get_or_insert_with(|| {
            let mut n = [0u8; 16];
            crate::arch::random::fill(&mut n);
            n
        });
    } else {
        crate::arch::random::fill(&mut b);
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = |r: core::ops::Range<usize>| b[r].iter().map(|x| alloc::format!("{:02x}", x)).collect::<alloc::string::String>();
    alloc::format!("{}-{}-{}-{}-{}\n", h(0..4), h(4..6), h(6..8), h(8..10), h(10..16))
}

/// Copies a window of `data` starting at `cursor` into `buf`.
///
/// # Arguments
///
/// * `data` - Source byte slice.
/// * `cursor` - Starting offset within `data`.
/// * `buf` - Destination buffer slice.
///
/// # Returns
///
/// Number of bytes copied into `buf`.
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
    if let Some(rest) = path.strip_prefix("/proc/").filter(|r| r.contains("/ns/")) {
        return super::ns::ns_link(rest);
    }
    match path {
        // /proc/self and /proc/thread-self link to the caller's own entries
        "/proc/self" => {
            let (_, pid) = super::proc::current_ids();
            Some(alloc::format!("{}", super::ns::pid_to_caller(pid)))
        }
        "/proc/thread-self" => {
            let (tid, pid) = super::proc::current_ids();
            Some(alloc::format!("{}/task/{}", super::ns::pid_to_caller(pid), super::ns::pid_to_caller(tid)))
        }
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
            let pid: u64 = super::ns::pid_from_caller(pid.parse().ok()?);
            match entry {
                // Opened and walked through in that process's root (see vfs::resolve);
                // readlink shows "/" (readlink_at)
                "root" => None,
                "exe" => crate::task::SCHEDULER.lock().exe_of(pid),
                _ => None,
            }
        }
    }
}

/// The timer ticks CPU `cpu` spent in user mode, kernel mode and idle.
fn cpu_ticks(cpu: usize) -> [u64; 3] {
    let t = &crate::task::scheduler::CPU_TIMES[cpu.min(crate::arch::smp::MAX_CPUS - 1)];
    [0, 1, 2].map(|k| t[k].load(core::sync::atomic::Ordering::Relaxed))
}

/// The text of `/proc/stat`: per CPU (and summed) user, nice, system, idle, iowait, irq,
/// softirq, steal, guest and guest_nice times in clock ticks; then the boot time and the
/// process counts (as `top`, `vmstat` and system monitors read them).
fn proc_stat_text() -> alloc::string::String {
    let n = crate::arch::smp::online().max(1);
    let ct = super::proc::to_clock_ticks;
    let per: alloc::vec::Vec<[u64; 3]> = (0..n).map(|c| cpu_ticks(c).map(ct)).collect();
    let line = |name: &str, t: [u64; 3]| alloc::format!("{} {} 0 {} {} 0 0 0 0 0 0
", name, t[0], t[1], t[2]);
    let total = per.iter().fold([0u64; 3], |a, t| [a[0] + t[0], a[1] + t[1], a[2] + t[2]]);
    let mut text = line("cpu ", total);
    for (i, t) in per.iter().enumerate() {
        text.push_str(&line(&alloc::format!("cpu{}", i), *t));
    }
    let boot = crate::arch::rtc::now().0.saturating_sub(crate::arch::pit::now_ns() / 1_000_000_000);
    let (running, _) = crate::task::SCHEDULER.lock().task_counts();
    let procs = super::proc::PROCS.lock().len();
    text.push_str(&alloc::format!(
        "intr 0
ctxt 0
btime {}
processes {}
procs_running {}
procs_blocked 0
",
        boot, procs, running.max(1)
    ));
    text
}
