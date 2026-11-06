//! # Linux Compatibility: Processes, Thread Groups, and POSIX Signals
//!
//! Manages the Linux process table (parent/child relationships, process groups, sessions,
//! exit status, and zombies), POSIX signal state (dispositions, masks, pending bitmasks,
//! signal frame delivery, and `rt_sigreturn`), and the `wait4`/`waitid`/`kill` system call family.
//!
//! ## Architectural Role & Design Rationale
//! A Linux process is a thread group (`tgid`). Signal dispositions (`struct sigaction`) and
//! process-directed pending signals belong to the [`Process`], whereas each thread maintains
//! its own blocked signal mask, thread-directed pending set, and alternate signal stack.
//! Signals are delivered when a thread returns to user mode, either from a system call
//! ([`deliver_on_syscall_return`]) or from an interrupt or exception ([`deliver_on_trap_return`]).
//! The signal frame constructed on the user stack matches Linux's x86_64 `rt_sigframe` layout
//! byte-for-byte, allowing standard C library (`glibc`/`musl`) `sa_restorer` trampolines and
//! `ucontext_t` accessors to operate without modification.
//!
//! Blocking system calls poll for completion and return [`ERESTARTSYS`] when a signal arrives;
//! delivery converts that into either a transparent syscall restart (`SA_RESTART` or an ignored
//! signal) or `-EINTR`.
//!
//! Lock ordering invariant: the scheduler lock may be held while acquiring [`PROCS`], never the reverse.
//!
//! ## Key Types & Interfaces
//! - [`Process`] & [`PROCS`]: Thread-group state and the global process table.
//! - [`SigAction`]: Kernel representation of x86_64 `struct sigaction`.
//! - [`UserRegs`]: Complete user-mode general-purpose register snapshot saved/restored across signals.
//! - [`deliver_on_syscall_return`] & [`deliver_on_trap_return`]: User-return signal delivery hooks.
//! - [`sys_rt_sigreturn`] & [`return_to_user`]: Signal frame restoration and `iretq` user-mode transition.
//! - [`sys_wait4`], [`sys_waitid`], [`sys_kill`], [`sys_tgkill`], [`sys_tkill`]: Process lifecycle and signaling syscalls.
//!
//! ## Hardware & Dependency Context
//! - **Architecture**: x86_64 (`FXSAVE64`/`FXRSTOR64` 512-byte FPU frame, 128-byte ABI red zone, `iretq` ring-3 return).
//! - **Dependencies**: Coordinates with [`crate::task`] for thread scheduling and wakeups,
//!   [`crate::memory::vm::prefault_current`] for safe user stack access, and [`super::pidfd`] for exit notifications.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::arch::idt::{ExceptionContext, FpuState};
use crate::arch::syscall::SyscallFrame;
use crate::memory::vm::prefault_current;

/// Total number of supported POSIX and real-time signals (`1..=64`).
pub const NSIG: usize = 64;

/// Hangup detected on controlling terminal or death of controlling process (`SIGHUP`).
pub const SIGHUP: u32 = 1;
/// Interactive attention / interrupt signal from keyboard (`SIGINT`).
pub const SIGINT: u32 = 2;
/// Quit from keyboard with core dump (`SIGQUIT`).
pub const SIGQUIT: u32 = 3;
/// Illegal instruction fault (`SIGILL`).
pub const SIGILL: u32 = 4;
/// Trace/breakpoint trap (`SIGTRAP`).
pub const SIGTRAP: u32 = 5;
/// Abnormal termination / abort signal (`SIGABRT`).
pub const SIGABRT: u32 = 6;
/// Bus error / misaligned memory access (`SIGBUS`).
pub const SIGBUS: u32 = 7;
/// Floating-point / arithmetic exception (`SIGFPE`).
pub const SIGFPE: u32 = 8;
/// Unblockable, uncatchable immediate process termination signal (`SIGKILL`).
pub const SIGKILL: u32 = 9;
/// Invalid memory reference / segmentation fault (`SIGSEGV`).
pub const SIGSEGV: u32 = 11;
/// Write on a pipe or socket with no readers (`SIGPIPE`).
pub const SIGPIPE: u32 = 13;
/// Timer clock alarm (`SIGALRM`).
pub const SIGALRM: u32 = 14;
/// Software termination request signal (`SIGTERM`).
pub const SIGTERM: u32 = 15;
/// Child process stopped, continued, or terminated (`SIGCHLD`).
pub const SIGCHLD: u32 = 17;
/// Continue executing if stopped (`SIGCONT`).
pub const SIGCONT: u32 = 18;
/// Unblockable, uncatchable stop execution signal (`SIGSTOP`).
pub const SIGSTOP: u32 = 19;
/// Stop typed at terminal (`SIGTSTP`).
pub const SIGTSTP: u32 = 20;
/// Background process attempting terminal read (`SIGTTIN`).
pub const SIGTTIN: u32 = 21;
/// Background process attempting terminal write (`SIGTTOU`).
pub const SIGTTOU: u32 = 22;
/// Urgent condition on socket (`SIGURG`).
pub const SIGURG: u32 = 23;
/// Virtual timer alarm expired (`SIGVTALRM`).
pub const SIGVTALRM: u32 = 26;
/// Profiling timer clock expired (`SIGPROF`).
pub const SIGPROF: u32 = 27;
/// Terminal window size change (`SIGWINCH`).
pub const SIGWINCH: u32 = 28;
/// Bad system call (raised by a seccomp `TRAP` filter).
pub const SIGSYS: u32 = 31;

/// Default signal disposition constant (`SIG_DFL`).
const SIG_DFL: u64 = 0;
/// Ignore signal disposition constant (`SIG_IGN`).
const SIG_IGN: u64 = 1;

/// `sigaction` flag: deliver signal on the alternate signal stack configured by `sigaltstack`.
const SA_ONSTACK: u64 = 0x0800_0000;
/// `sigaction` flag: automatically restart interrupted system calls instead of failing with `EINTR`.
const SA_RESTART: u64 = 0x1000_0000;
/// `sigaction` flag: do not automatically block the signal while its handler is executing.
const SA_NODEFER: u64 = 0x4000_0000;
/// `sigaction` flag: reset disposition to `SIG_DFL` upon entry to the signal handler.
const SA_RESETHAND: u64 = 0x8000_0000;

/// `sigaltstack` flag indicating the thread is currently executing on the alternate stack.
const SS_ONSTACK: u32 = 1;
/// `sigaltstack` flag to disable the alternate signal stack.
const SS_DISABLE: u32 = 2;

/// Internal return value of interrupted blocking system calls (never seen by user code).
pub const ERESTARTSYS: i64 = -512;
/// Like [`ERESTARTSYS`], but the call resumes from saved state (its restart block) and a
/// signal handler always turns it into `EINTR`, even with `SA_RESTART` (sleeps).
pub const ERESTART_RESTARTBLOCK: i64 = -516;

/// Threads whose interrupted system call is being restarted transparently.
static RESTARTING: Mutex<BTreeMap<u64, ()>> = Mutex::new(BTreeMap::new());

/// Returns `true` (once) if the calling thread's current system call is a transparent restart.
///
/// # Returns
/// `true` if this syscall was marked for transparent restart, `false` otherwise.
pub fn take_restart_flag() -> bool {
    let (tid, _) = current_ids();
    RESTARTING.lock().remove(&tid).is_some()
}

/// Records that system call `nr` is being restarted (only sleeps keep restart state).
///
/// # Arguments
/// * `nr` - System call number being restarted.
fn mark_restart(nr: u64) {
    if nr == 35 || nr == 230 {
        let (tid, _) = current_ids();
        RESTARTING.lock().insert(tid, ());
    }
}
/// Negative `EPERM` error constant (`-1`).
const EPERM: i64 = -1;
/// Negative `ESRCH` error constant (`-3`).
const ESRCH: i64 = -3;
/// Negative `EINTR` error constant (`-4`).
const EINTR: i64 = -4;
/// Negative `ECHILD` error constant (`-10`).
const ECHILD: i64 = -10;
/// Negative `EFAULT` error constant (`-14`).
const EFAULT: i64 = -14;
/// Permission denied.
const EACCES: i64 = -13;
/// Negative `EINVAL` error constant (`-22`).
const EINVAL: i64 = -22;

/// Kernel `struct sigaction` for x86_64.
#[derive(Clone, Copy, Default)]
pub struct SigAction {
    /// User-space virtual address of the signal handler function (or `SIG_DFL`/`SIG_IGN`).
    pub handler: u64,
    /// Action flags (`SA_RESTART`, `SA_ONSTACK`, `SA_NODEFER`, `SA_RESETHAND`, `SA_NOCLDSTOP`).
    pub flags: u64,
    /// User-space address of the `sa_restorer` trampoline that invokes `rt_sigreturn`.
    pub restorer: u64,
    /// Bitmask of additional signals to block while the handler is executing.
    pub mask: u64,
}

/// Per-thread signal mask, pending signal bitmask, and alternate signal stack state.
#[derive(Clone, Copy)]
struct ThreadSig {
    /// Bitmask of signals currently blocked by this thread.
    mask: u64,
    /// Bitmask of pending signals directed specifically at this thread (`tkill`/`tgkill`).
    pending: u64,
    /// Base user virtual address of the alternate signal stack (`ss_sp`).
    alt_sp: u64,
    /// Size in bytes of the alternate signal stack (`ss_size`).
    alt_size: u64,
    /// Alternate stack flags (`SS_DISABLE`, `SS_ONSTACK`).
    alt_flags: u32,
    /// Senders of the signals pending for this thread (`tkill`/`tgkill`), by number.
    senders: [SigSender; NSIG + 1],
    /// Signals a tracer let through after a signal-delivery stop: acted on without another.
    injected: u64,
}

impl Default for ThreadSig {
    fn default() -> Self {
        ThreadSig { mask: 0, pending: 0, alt_sp: 0, alt_size: 0, alt_flags: 0, senders: [SigSender::default(); NSIG + 1], injected: 0 }
    }
}

/// The sender of a signal, as its handler's `siginfo` reports it.
#[derive(Clone, Copy, Default)]
struct SigSender {
    /// `si_code`: `SI_USER` (`kill`), `SI_TKILL` (`tkill`/`tgkill`); 0 also for the kernel's.
    code: i32,
    /// `si_pid`: the sending process.
    pid: u32,
    /// `si_uid`: its real user ID.
    uid: u32,
    /// `SIGSYS` from seccomp: `si_call_addr`, the address after the `syscall` instruction.
    call_addr: u64,
    /// `SIGSYS` from seccomp: `si_syscall`, the call number.
    syscall: i32,
    /// `SIGSYS` from seccomp: `si_errno`, the filter's return data.
    errno: i32,
    /// `si_value` of a signal queued with `rt_sigqueueinfo` (`sigqueue`).
    value: u64,
}

/// `si_code` of a signal sent by `kill`.
const SI_USER: i32 = 0;
/// `si_code` of a signal sent by `tkill` or `tgkill`.
const SI_TKILL: i32 = -6;
/// `si_code` of a `SIGSYS` raised by a seccomp filter.
const SYS_SECCOMP: i32 = 1;

/// One process (thread group).
pub struct Process {
    /// Process ID / thread group ID (`tgid`).
    pub pid: u64,
    /// Parent process ID (`ppid`).
    pub ppid: u64,
    /// Process group ID (`pgid`).
    pub pgid: u64,
    /// Session ID (`sid`).
    pub sid: u64,
    /// Signal dispositions indexed by 1-based signal number (`1..=NSIG`).
    pub actions: [SigAction; NSIG + 1],
    /// Bitmask of pending signals directed at the process as a whole.
    pub pending: u64,
    /// Per-thread signal state keyed by thread ID (`tid`).
    threads: BTreeMap<u64, ThreadSig>,
    /// Exit status in `wait` encoding, set by `exit_group` or a fatal signal.
    pub exit_status: Option<i32>,
    /// Set once every thread has exited (zombie until reaped).
    pub zombie: bool,
    /// `vfork` parent waits until this child execs or exits.
    pub vfork_released: bool,
    /// Job control: stopped by `stop_sig`; the parent learns about the stop and the later
    /// continue through `wait` (WUNTRACED / WCONTINUED), each reported once.
    pub stopped: bool,
    /// Signal number that caused this process to stop.
    pub stop_sig: u32,
    /// Supplementary group IDs (`getgroups`/`setgroups`).
    pub groups: Vec<u32>,
    /// Whether the current job-control stop state has already been reported to `wait`.
    stop_reported: bool,
    /// Whether a `SIGCONT` continuation is awaiting reporting via `wait` (`WCONTINUED`).
    continued: bool,
    /// Control group (cgroup v2 path, e.g. `/user.slice/user-1000.slice/session-2.scope`);
    /// `None` is the root group. Login managers place sessions in groups with `cgroup.procs`.
    pub cgroup: Option<alloc::sync::Arc<str>>,
    /// Who sent each signal pending for the process as a whole (`kill`), by number.
    senders: [SigSender; NSIG + 1],
    /// When the process started, in clock ticks (`USER_HZ`, 100 per second) since boot
    /// (`/proc/<pid>/stat`; polkit tells processes apart by pid and start time).
    pub start_time: u64,
    /// Namespaces the process is in.
    pub ns: super::ns::Ns,
    /// `/proc/<pid>/oom_score_adj` (-1000..=1000). Hydra has no OOM killer: it is kept
    /// for the programs that set and read it.
    pub oom_score_adj: i32,
    /// Execution domain (`personality(2)`); inherited by children and kept across `execve`.
    pub personality: u32,
    /// Process sharing this one's root and working directory (`clone` with `CLONE_FS`
    /// only: they live in the descriptor table, which is not shared), or 0.
    pub fs_peer: u64,
}

/// All Linux processes, including zombies not yet reaped.
pub static PROCS: Mutex<BTreeMap<u64, Process>> = Mutex::new(BTreeMap::new());

/// Converts a 1-based signal number (`1..=64`) into its corresponding 64-bit mask bit.
///
/// # Arguments
/// * `sig` - 1-based signal number.
///
/// # Returns
/// Single-bit mask corresponding to the signal number.
fn bit(sig: u32) -> u64 {
    1u64 << (sig - 1)
}

/// Bitmask of signals that cannot be blocked or ignored (`SIGKILL` and `SIGSTOP`).
const UNBLOCKABLE: u64 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

/// Returns the calling thread's `(tid, pid)` pair.
///
/// # Returns
/// A tuple containing `(thread_id, process_id)`.
pub fn current_ids() -> (u64, u64) {
    crate::task::with_current_task_mut(|t| (t.id.0, t.tgid)).unwrap_or((0, 0))
}

// ----------------------------------------------------------------------
// Process table
// ----------------------------------------------------------------------

/// Registers a new process with a single thread. A child inherits its parent's process
/// group, session and signal dispositions (`fork`); otherwise it starts its own session.
///
/// # Arguments
/// * `pid` - New process ID.
/// * `ppid` - Parent process ID.
/// * `tid` - Initial thread ID.
/// * `inherit_from` - Optional parent process ID to inherit signal dispositions and IDs from.
pub fn register_process(pid: u64, ppid: u64, tid: u64, inherit_from: Option<u64>) {
    let mut procs = PROCS.lock();
    let (pgid, sid, actions, mask, groups, cgroup, ns, oom_score_adj) = match inherit_from.and_then(|p| procs.get(&p)) {
        Some(parent) => {
            let mask = parent.threads.values().next().map(|t| t.mask).unwrap_or(0);
            (parent.pgid, parent.sid, parent.actions, mask, parent.groups.clone(), parent.cgroup.clone(), parent.ns.for_child(pid), (parent.oom_score_adj, parent.personality))
        }
        None => (pid, pid, [SigAction::default(); NSIG + 1], 0, Vec::new(), None, super::ns::Ns::default(), (0, 0)),
    };
    let (oom_score_adj, personality) = oom_score_adj;
    let mut threads = BTreeMap::new();
    threads.insert(tid, ThreadSig { mask, ..ThreadSig::default() });
    procs.insert(
        pid,
        Process {
            pid,
            ppid,
            pgid,
            sid,
            actions,
            pending: 0,
            threads,
            exit_status: None,
            zombie: false,
            vfork_released: false,
            stopped: false,
            stop_sig: 0,
            groups,
            stop_reported: false,
            continued: false,
            cgroup,
            senders: [SigSender::default(); NSIG + 1],
            start_time: crate::arch::pit::ticks() * 100 / crate::arch::pit::frequency_hz().max(1),
            ns,
            oom_score_adj,
            personality,
            fs_peer: 0,
        },
    );
}

/// Records that process `pid` shares process `peer`'s root and working directory.
///
/// # Arguments
/// * `pid` - Process created with `CLONE_FS`.
/// * `peer` - Its creator.
pub fn set_fs_peer(pid: u64, peer: u64) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        p.fs_peer = peer;
    }
}

/// Adds a thread to an existing process (inherits the creating thread's mask).
///
/// # Arguments
/// * `pid` - Process ID to add the thread to.
/// * `tid` - New thread ID.
/// * `creator` - Thread ID of the creating thread to inherit mask from.
pub fn register_thread(pid: u64, tid: u64, creator: u64) {
    let mut procs = PROCS.lock();
    if let Some(p) = procs.get_mut(&pid) {
        let mask = p.threads.get(&creator).map(|t| t.mask).unwrap_or(0);
        p.threads.insert(tid, ThreadSig { mask, ..ThreadSig::default() });
    }
}

/// Records the exit status for a whole process (`exit_group`, fatal signal).
///
/// # Arguments
/// * `pid` - Process ID exiting.
/// * `status` - Encoded exit status.
pub fn set_exit_status(pid: u64, status: i32) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        if p.exit_status.is_none() {
            p.exit_status = Some(status);
        }
    }
}

/// Called by the scheduler when thread `tid` of process `pid` dies. When the last thread
/// is gone the process becomes a zombie, its children are re-parented, and its parent
/// receives `SIGCHLD` (or the zombie is discarded if no Linux parent will wait for it).
///
/// # Arguments
/// * `pid` - Process ID of the exiting thread.
/// * `tid` - Thread ID that exited.
pub fn thread_exited(pid: u64, tid: u64) {
    super::mount::forget_thread(tid);
    let mut procs = PROCS.lock();
    let (ppid, now_zombie) = match procs.get_mut(&pid) {
        Some(p) => {
            p.threads.remove(&tid);
            if p.threads.is_empty() && !p.zombie {
                p.zombie = true;
                p.vfork_released = true;
                super::pidfd::EXIT_WQ.wake_all();
                if p.exit_status.is_none() {
                    p.exit_status = Some(0);
                }
                (p.ppid, true)
            } else {
                (p.ppid, false)
            }
        }
        None => return,
    };
    let status = procs.get(&pid).and_then(|p| p.exit_status).unwrap_or(0);
    if let Some(tracer) = super::ptrace::on_thread_exit(pid, tid, status, ppid) {
        if let Some(t) = procs.get_mut(&tracer) {
            t.pending |= bit(SIGCHLD);
        }
        crate::task::wait::wake_process_deferred(tracer);
        super::pidfd::EXIT_WQ.wake_all();
    }
    if !now_zombie {
        return;
    }
    for (tgid, t) in super::ptrace::on_tracer_exit(pid) {
        if let Some(th) = procs.get_mut(&tgid).and_then(|q| q.threads.get_mut(&t)) {
            th.pending |= bit(SIGKILL);
        }
        crate::task::wait::wake_process_deferred(tgid);
    }
    super::misc::forget_process(pid);
    super::ptimer::forget_process(pid);
    super::aio::forget_process(pid);
    super::sysv::forget_process(pid, true);
    // The init of a PID namespace takes the namespace with it
    if procs.get(&pid).is_some_and(|p| p.ns.pid_inits.last() == Some(&pid)) {
        let members: Vec<u64> = procs.values().filter(|q| q.pid != pid && !q.zombie && q.ns.pid_inits.contains(&pid)).map(|q| q.pid).collect();
        for m in members {
            if let Some(q) = procs.get_mut(&m) {
                q.pending |= bit(SIGKILL);
            }
            crate::task::wait::wake_process_deferred(m);
        }
    }
    // Orphans are adopted by "init" (pid 1); zombies of init are reaped at once
    let orphans: Vec<u64> = procs.values().filter(|c| c.ppid == pid).map(|c| c.pid).collect();
    for c in orphans {
        let reap = procs.get(&c).map_or(false, |c| c.zombie);
        if reap {
            procs.remove(&c);
        } else if let Some(child) = procs.get_mut(&c) {
            child.ppid = 1;
        }
    }
    match procs.get_mut(&ppid) {
        Some(parent) if !parent.zombie => {
            let ign = parent.actions[SIGCHLD as usize].handler == SIG_IGN;
            if ign {
                procs.remove(&pid);
            } else {
                parent.pending |= bit(SIGCHLD);
                // This runs under the scheduler lock (task exit): wake the parent later
                crate::task::wait::wake_process_deferred(ppid);
            }
        }
        // Parent 0 is the Hydra shell, which reads the status itself (see `take_status`)
        _ if ppid == 0 => {}
        _ => {
            procs.remove(&pid);
        }
    }
}

/// Reaps a zombie started from the Hydra shell, returning its `wait` status.
///
/// # Arguments
/// * `pid` - Target process ID to reap.
///
/// # Returns
/// `Some(status)` if the process was a zombie and was reaped, or `None`.
pub fn take_status(pid: u64) -> Option<i32> {
    let mut procs = PROCS.lock();
    match procs.get(&pid) {
        Some(p) if p.zombie => procs.remove(&pid).and_then(|p| p.exit_status),
        _ => None,
    }
}

impl Process {
    /// Returns the number of threads of this process still running.
    ///
    /// # Returns
    /// Count of currently active threads in this process.
    pub fn threads_alive(&self) -> usize {
        self.threads.len()
    }

    /// Returns the IDs of this process's running threads, in ascending order.
    ///
    /// # Returns
    /// Thread IDs (`tid`) of every live thread.
    pub fn thread_ids(&self) -> Vec<u64> {
        self.threads.keys().copied().collect()
    }
}

/// Retrieves the list of supplementary group IDs for the calling process.
///
/// # Arguments
/// * `size` - Maximum number of group IDs that can be stored in `list`. If 0, returns the count.
/// * `list` - User pointer to array of `gid_t` (`u32`).
///
/// # Returns
/// Number of group IDs on success, or a negative Linux error code on failure.
pub fn sys_getgroups(size: u64, list: u64) -> i64 {
    let (_, pid) = current_ids();
    let groups = PROCS.lock().get(&pid).map(|p| p.groups.clone()).unwrap_or_default();
    if size == 0 {
        return groups.len() as i64;
    }
    if (size as usize) < groups.len() {
        return EINVAL;
    }
    let bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_le_bytes()).collect();
    if !bytes.is_empty() && !write_bytes(list, &bytes) {
        return EFAULT;
    }
    groups.len() as i64
}

/// Replaces the supplementary group IDs for the calling process (privileged only).
///
/// # Arguments
/// * `size` - Number of group IDs in the array.
/// * `list` - User pointer to array of `gid_t` (`u32`).
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_setgroups(size: u64, list: u64) -> i64 {
    if size > 65536 {
        return EINVAL;
    }
    let privileged = crate::task::with_current_task_mut(|t| t.caps.has(crate::task::tcb::Caps::SETGID)).unwrap_or(false);
    if !privileged {
        return EPERM;
    }
    let mut groups = Vec::with_capacity(size as usize);
    if size > 0 {
        if !prefault_current(list, size * 4, false) {
            return EFAULT;
        }
        for i in 0..size {
            groups.push(unsafe { *((list + i * 4) as *const u32) });
        }
    }
    let (_, pid) = current_ids();
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        p.groups = groups;
    }
    0
}

/// Checks whether `gid` is present in the calling process's supplementary groups.
///
/// # Arguments
/// * `gid` - Group ID to check.
///
/// # Returns
/// `true` if `gid` is in supplementary groups, `false` otherwise.
pub fn in_supplementary_groups(gid: u32) -> bool {
    let (_, pid) = current_ids();
    PROCS.lock().get(&pid).map_or(false, |p| p.groups.contains(&gid))
}

/// Number of Linux processes (live and zombie), for `sysinfo`.
///
/// # Returns
/// Total count of registered Linux processes.
pub fn process_count() -> usize {
    PROCS.lock().len()
}

/// Returns the parent process ID of the calling process.
///
/// # Returns
/// Parent process ID as `i64`.
pub fn getppid() -> i64 {
    let (_, pid) = current_ids();
    let ppid = {
        let procs = PROCS.lock();
        let Some(me) = procs.get(&pid) else { return 1 };
        let mine = &me.ns.pid_inits;
        // A parent outside the caller's PID namespace (the init's, or one left behind by
        // setns or unshare) is not visible in it
        let visible = mine.last() != Some(&pid)
            && procs.get(&me.ppid).map_or(mine.is_empty(), |p| p.ns.pid_inits.starts_with(mine));
        if !visible {
            return 0;
        }
        me.ppid
    };
    super::ns::pid_to_caller(ppid) as i64
}

/// Returns the process group ID of `target` (or the caller when `target == 0`).
///
/// # Arguments
/// * `target` - Process ID to query, or `0` for the calling process.
///
/// # Returns
/// Process group ID on success, or negative error code (`-ESRCH`).
pub fn getpgid(target: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    PROCS.lock().get(&target).map_or(ESRCH, |p| p.pgid as i64)
}

/// Returns the session ID of `target` (or the caller when `target == 0`).
///
/// # Arguments
/// * `target` - Process ID to query, or `0` for the calling process.
///
/// # Returns
/// Session ID on success, or negative error code (`-ESRCH`).
pub fn getsid(target: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    PROCS.lock().get(&target).map_or(ESRCH, |p| p.sid as i64)
}

/// Sets the process group ID of `target` to `pgid`.
///
/// # Arguments
/// * `target` - Target process ID, or `0` for the caller.
/// * `pgid` - New process group ID, or `0` to use `target`.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn setpgid(target: u64, pgid: u64) -> i64 {
    let (_, pid) = current_ids();
    let target = if target == 0 { pid } else { target };
    let pgid = if pgid == 0 { target } else { pgid };
    let mut procs = PROCS.lock();
    let allowed = procs.get(&target).map_or(false, |p| p.pid == pid || p.ppid == pid);
    if !allowed {
        return ESRCH;
    }
    let p = procs.get_mut(&target).unwrap();
    if p.sid == p.pid {
        return EPERM; // a session leader cannot change its group
    }
    p.pgid = pgid;
    0
}

/// Creates a new session if the calling process is not a process group leader.
///
/// # Returns
/// The new session ID on success, or a negative Linux error code on failure.
pub fn setsid() -> i64 {
    let (_, pid) = current_ids();
    let mut procs = PROCS.lock();
    if procs.values().any(|p| p.pgid == pid && p.pid != pid) {
        return EPERM;
    }
    match procs.get_mut(&pid) {
        Some(p) if p.pgid != pid => {
            p.pgid = pid;
            p.sid = pid;
            pid as i64
        }
        Some(_) => EPERM,
        None => ESRCH,
    }
}

/// Thread IDs of process `pid` (just `pid` itself if the process has no thread records).
///
/// # Arguments
/// * `pid` - Process ID.
///
/// # Returns
/// Thread IDs in ascending order.
pub fn thread_ids_of(pid: u64) -> Vec<u64> {
    let ids = PROCS.lock().get(&pid).map(|p| p.thread_ids()).unwrap_or_default();
    if ids.is_empty() { alloc::vec![pid] } else { ids }
}

/// Returns `true` if process `pid` is in the process table (alive or a zombie).
///
/// # Arguments
/// * `pid` - Process ID to query.
///
/// # Returns
/// `true` if the process exists in the table, `false` otherwise.
pub fn process_exists(pid: u64) -> bool {
    PROCS.lock().contains_key(&pid)
}

/// Returns `true` if process `pid` has exited (a zombie, or already reaped). Never blocks: reports
/// `false` while the table is busy (callers re-check after the next wakeup).
///
/// # Arguments
/// * `pid` - Process ID to query.
///
/// # Returns
/// `true` if the process has exited or does not exist, `false` if running or table busy.
pub fn has_exited(pid: u64) -> bool {
    match PROCS.try_lock() {
        Some(p) => p.get(&pid).map_or(true, |p| p.zombie),
        None => false,
    }
}

/// Returns the `(sid, pgid)` session and process group of `pid`.
///
/// # Arguments
/// * `pid` - Process ID to query.
///
/// # Returns
/// `Some((sid, pgid))` if found, or `None`.
pub fn session_of(pid: u64) -> Option<(u64, u64)> {
    PROCS.lock().get(&pid).map(|p| (p.sid, p.pgid))
}

/// Resets handled signals of `pid` to their default action (ignored ones stay ignored).
///
/// # Arguments
/// * `pid` - Process ID whose handlers are being reset.
pub fn reset_handlers(pid: u64) {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        for a in p.actions.iter_mut() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
    }
}

/// Resets signal dispositions across `execve` (handled signals return to default).
///
/// # Arguments
/// * `pid` - Process ID undergoing execution reset.
pub fn exec_reset(pid: u64) {
    super::misc::forget_process(pid);
    super::ptimer::forget_process(pid);
    super::sysv::forget_process(pid, false);
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        for a in p.actions.iter_mut() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
        }
        p.vfork_released = true;
        for t in p.threads.values_mut() {
            t.alt_flags = SS_DISABLE;
            t.alt_sp = 0;
            t.alt_size = 0;
        }
    }
}

/// Returns `true` when a `vfork` parent may continue (the child has `exec`'ed or exited).
///
/// # Arguments
/// * `child` - Child process ID.
///
/// # Returns
/// `true` if vfork parent is released, `false` otherwise.
pub fn vfork_released(child: u64) -> bool {
    PROCS.lock().get(&child).map_or(true, |p| p.vfork_released)
}

// ----------------------------------------------------------------------
// Sending signals
// ----------------------------------------------------------------------

/// Returns `true` if `sig`'s default disposition (`SIG_DFL`) is to be ignored.
///
/// # Arguments
/// * `sig` - Signal number.
///
/// # Returns
/// `true` if default action is ignore, `false` otherwise.
fn default_ignored(sig: u32) -> bool {
    matches!(sig, SIGCHLD | SIGURG | SIGWINCH | SIGCONT)
}

/// Returns `true` if `sig` is a job-control stop signal (`SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`).
///
/// # Arguments
/// * `sig` - Signal number.
///
/// # Returns
/// `true` if signal causes job control stop, `false` otherwise.
fn is_stop_signal(sig: u32) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// Bitmask of all job-control stop signals.
const STOP_MASK: u64 = (1 << (SIGSTOP - 1)) | (1 << (SIGTSTP - 1)) | (1 << (SIGTTIN - 1)) | (1 << (SIGTTOU - 1));
/// `sigaction` flag for `SIGCHLD`: do not generate `SIGCHLD` when children stop or continue.
const SA_NOCLDSTOP: u64 = 1;

/// Tells the parent of `child` about a job-control state change (unless it asked not to be).
///
/// # Arguments
/// * `procs` - Mutable reference to the process map.
/// * `ppid` - Parent process ID to notify.
fn notify_parent_stop(procs: &mut BTreeMap<u64, Process>, ppid: u64) {
    if let Some(parent) = procs.get_mut(&ppid) {
        if parent.actions[SIGCHLD as usize].flags & SA_NOCLDSTOP == 0 {
            parent.pending |= bit(SIGCHLD);
            crate::task::wait::wake_process_deferred(ppid);
        }
    }
}

/// Unblocks all sleeping threads belonging to process `pid`.
///
/// # Arguments
/// * `pid` - Process ID whose threads should be woken.
fn wake_process(pid: u64) {
    let mut sched = crate::task::SCHEDULER.lock();
    sched.unblock_group(pid);
}

/// Posts `sig` to process `pid` (process-directed).
///
/// # Arguments
/// * `pid` - Destination process ID.
/// * `sig` - Signal number to post.
///
/// # Returns
/// `true` if signal was posted, `false` if process does not exist or has terminated.
pub fn post_process(pid: u64, sig: u32) -> bool {
    {
        let mut procs = PROCS.lock();
        let mut resumed_ppid = None;
        match procs.get_mut(&pid) {
            Some(p) if !p.zombie => {
                if sig == SIGCONT {
                    p.pending &= !STOP_MASK;
                    for t in p.threads.values_mut() {
                        t.pending &= !STOP_MASK;
                    }
                    if p.stopped {
                        p.stopped = false;
                        p.continued = true;
                        resumed_ppid = Some(p.ppid);
                        super::pidfd::EXIT_WQ.wake_all(); // WCONTINUED waiters
                    }
                } else if is_stop_signal(sig) {
                    p.pending &= !bit(SIGCONT);
                }
                if sig != 0 {
                    p.pending |= bit(sig);
                }
            }
            _ => return false,
        }
        if let Some(ppid) = resumed_ppid {
            notify_parent_stop(&mut procs, ppid);
        }
    }
    if sig == SIGCONT {
        super::ptrace::on_sigcont(pid);
    }
    wake_process(pid);
    true
}

/// Returns `true` if the calling thread ignores or blocks `sig`.
///
/// # Arguments
/// * `sig` - Signal number.
///
/// # Returns
/// `true` if signal is blocked or ignored, `false` otherwise.
pub fn ignores_or_blocks(sig: u32) -> bool {
    let (tid, pid) = current_ids();
    PROCS.lock().get(&pid).map_or(true, |p| {
        let blocked = p.threads.get(&tid).map_or(0, |t| t.mask) & bit(sig) != 0;
        blocked || p.actions[sig as usize].handler == SIG_IGN
    })
}

/// Returns `true` if process `pid` is stopped by job control.
///
/// # Arguments
/// * `pid` - Process ID to query.
///
/// # Returns
/// `true` if stopped by job control, `false` otherwise.
pub fn is_stopped(pid: u64) -> bool {
    PROCS.lock().get(&pid).map_or(false, |p| p.stopped)
}

/// Stops the calling process (default action of a stop signal) and waits until it is
/// continued or killed.
///
/// # Arguments
/// * `sig` - Signal number causing the stop.
fn stop_current(sig: u32) {
    if super::TRACE_SYSCALLS.load(core::sync::atomic::Ordering::Relaxed) {
        crate::kprintln!("[signal] pid {} stopped by signal {}", current_ids().1, sig);
    }
    let (_, pid) = current_ids();
    {
        let mut procs = PROCS.lock();
        let ppid = match procs.get_mut(&pid) {
            Some(p) => {
                p.stopped = true;
                p.stop_sig = sig;
                p.stop_reported = false;
                p.continued = false;
                super::pidfd::EXIT_WQ.wake_all(); // WUNTRACED waiters
                p.ppid
            }
            None => return,
        };
        notify_parent_stop(&mut procs, ppid);
    }
    wait_while_stopped();
}

/// Blocks the calling thread while its process is stopped (until `SIGCONT` or `SIGKILL`).
fn wait_while_stopped() {
    let (tid, pid) = current_ids();
    loop {
        let (stopped, killed) = match PROCS.lock().get(&pid) {
            Some(p) => {
                let t = p.threads.get(&tid).map_or(0, |t| t.pending);
                (p.stopped, (p.pending | t) & bit(SIGKILL) != 0)
            }
            None => (false, false),
        };
        if !stopped || killed {
            return;
        }
        crate::task::sleep_ticks(1);
    }
}

/// Posts `sig` to one specific thread `tid` within process `pid`.
///
/// # Arguments
/// * `pid` - Process ID containing the target thread.
/// * `tid` - Target thread ID.
/// * `sig` - Signal number to post.
///
/// # Returns
/// `true` if signal was posted, `false` if thread was not found.
pub fn post_thread(pid: u64, tid: u64, sig: u32) -> bool {
    {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => {
                if sig != 0 {
                    t.pending |= bit(sig);
                }
            }
            None => return false,
        }
    }
    wake_process(pid);
    true
}

/// Records the calling process as the sender of `sig` to process `pid`, or to its thread
/// `tid` (`Some`), with `code`, for the `siginfo` its handler receives. glibc's handler for
/// the signal it uses to apply `setuid` to every thread ignores a signal not sent by its
/// own process with `tgkill`.
///
/// # Arguments
/// * `pid` - Receiving process ID.
/// * `tid` - Receiving thread, for a signal directed at one thread.
/// * `sig` - Signal number.
/// * `code` - `si_code` to report.
fn record_sender(pid: u64, tid: Option<u64>, sig: u32, code: i32) {
    if sig == 0 || sig as usize > NSIG {
        return;
    }
    let (_, me) = current_ids();
    let uid = crate::task::with_current_task_mut(|t| t.uid).unwrap_or(0);
    let sender = SigSender { code, pid: me as u32, uid, ..Default::default() };
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        match tid {
            Some(tid) => {
                if let Some(t) = p.threads.get_mut(&tid) {
                    t.senders[sig as usize] = sender;
                }
            }
            None => p.senders[sig as usize] = sender,
        }
    }
}

/// Whether `pid` is one of the system's driver processes (started by the supervisor to
/// serve a driver endpoint), which Linux signals never reach.
fn is_system_service(pid: u64) -> bool {
    crate::task::SCHEDULER.lock().with_process(pid, |t| t.service.is_some()).unwrap_or(false)
}

/// Posts `sig` to every process in process group `pgid`.
///
/// # Arguments
/// * `pgid` - Target process group ID.
/// * `sig` - Signal number to post.
///
/// # Returns
/// Number of processes to which the signal was delivered.
pub fn post_group(pgid: u64, sig: u32) -> usize {
    let members: Vec<u64> = PROCS.lock().values().filter(|p| p.pgid == pgid && !p.zombie).map(|p| p.pid).collect();
    for &pid in &members {
        post_process(pid, sig);
    }
    members.len()
}

/// Sends signal `sig` to a process or process group selected by `pid`.
///
/// # Arguments
/// * `pid` - Destination selector (>0: pid, 0: own group, -1: all processes, <-1: pgid).
/// * `sig` - Signal number to send.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_kill(pid: i64, sig: u64) -> i64 {
    if sig as usize > NSIG {
        return EINVAL;
    }
    let sig = sig as u32;
    let (_, me) = current_ids();
    let targets: Vec<u64> = {
        let procs = PROCS.lock();
        match pid {
            p if p > 0 => alloc::vec![p as u64],
            0 => {
                let pgid = procs.get(&me).map_or(me, |p| p.pgid);
                procs.values().filter(|p| p.pgid == pgid && !p.zombie).map(|p| p.pid).collect()
            }
            -1 => procs.keys().copied().filter(|&p| p != me).collect(),
            p => procs.values().filter(|q| q.pgid == (-p) as u64 && !q.zombie).map(|q| q.pid).collect(),
        }
    };
    // The system's driver processes are not Linux processes to signal (as kernel threads
    // are not on Linux): kill(-1) passes over them, and signalling one is refused
    let targets: Vec<u64> = targets.into_iter().filter(|&t| !is_system_service(t)).collect();
    if pid > 0 && targets.is_empty() && is_system_service(pid as u64) {
        return EPERM;
    }
    for &t in &targets {
        record_sender(t, None, sig, SI_USER);
    }
    let n = targets.iter().filter(|&&t| post_process(t, sig)).count();
    if n == 0 {
        ESRCH
    } else {
        0
    }
}

/// Sends signal `sig` to thread `tid` in thread group `pid`.
///
/// # Arguments
/// * `pid` - Target process (thread group) ID.
/// * `tid` - Target thread ID.
/// * `sig` - Signal number to send.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_tgkill(pid: u64, tid: u64, sig: u64) -> i64 {
    if sig as usize > NSIG {
        return EINVAL;
    }
    if is_system_service(pid) {
        return EPERM;
    }
    record_sender(pid, Some(tid), sig as u32, SI_TKILL);
    if post_thread(pid, tid, sig as u32) {
        0
    } else {
        ESRCH
    }
}

/// Sends signal `sig` to thread `tid`.
///
/// # Arguments
/// * `tid` - Target thread ID.
/// * `sig` - Signal number to send.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_tkill(tid: u64, sig: u64) -> i64 {
    let pid = PROCS.lock().values().find(|p| p.threads.contains_key(&tid)).map(|p| p.pid);
    match pid {
        Some(pid) => sys_tgkill(pid, tid, sig),
        None => ESRCH,
    }
}

// ----------------------------------------------------------------------
// Dispositions and masks
// ----------------------------------------------------------------------

/// Safely prefaults and reads `N` consecutive 64-bit values from user address `ptr`.
///
/// # Arguments
/// * `ptr` - User virtual address to read from.
///
/// # Returns
/// `Some([u64; N])` on success, or `None` on fault.
fn read_u64s<const N: usize>(ptr: u64) -> Option<[u64; N]> {
    if !prefault_current(ptr, (N * 8) as u64, false) {
        return None;
    }
    let mut out = [0u64; N];
    for (i, v) in out.iter_mut().enumerate() {
        *v = unsafe { *((ptr + i as u64 * 8) as *const u64) };
    }
    Some(out)
}

/// Safely prefaults and writes `data` into user memory at `ptr`.
///
/// # Arguments
/// * `ptr` - User virtual address to write to.
/// * `data` - Byte slice to copy into user space.
///
/// # Returns
/// `true` on successful write, `false` on fault.
fn write_bytes(ptr: u64, data: &[u8]) -> bool {
    if !prefault_current(ptr, data.len() as u64, true) {
        return false;
    }
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
    true
}

/// Inspects and/or updates the disposition for signal `sig`.
///
/// # Arguments
/// * `sig` - Signal number.
/// * `act` - User pointer to new `sigaction` struct, or `0`.
/// * `oact` - User pointer to store previous `sigaction` struct, or `0`.
/// * `size` - Size of the signal set (must be 8).
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_rt_sigaction(sig: u64, act: u64, oact: u64, size: u64) -> i64 {
    if size != 8 || sig == 0 || sig as usize > NSIG {
        return EINVAL;
    }
    let sig = sig as u32;
    let new = if act != 0 {
        if sig == SIGKILL || sig == SIGSTOP {
            return EINVAL;
        }
        match read_u64s::<4>(act) {
            Some([handler, flags, restorer, mask]) => Some(SigAction { handler, flags, restorer, mask }),
            None => return EFAULT,
        }
    } else {
        None
    };
    let (_, pid) = current_ids();
    let old = {
        let mut procs = PROCS.lock();
        let p = match procs.get_mut(&pid) {
            Some(p) => p,
            None => return ESRCH,
        };
        let old = p.actions[sig as usize];
        if let Some(a) = new {
            p.actions[sig as usize] = a;
            if a.handler == SIG_IGN || (a.handler == SIG_DFL && default_ignored(sig)) {
                // Setting a signal to ignored discards it if pending
                p.pending &= !bit(sig);
                for t in p.threads.values_mut() {
                    t.pending &= !bit(sig);
                }
            }
        }
        old
    };
    if oact != 0 {
        let mut b = [0u8; 32];
        for (i, v) in [old.handler, old.flags, old.restorer, old.mask].iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        if !write_bytes(oact, &b) {
            return EFAULT;
        }
    }
    0
}

/// Inspects and/or updates the calling thread's blocked signal mask.
///
/// # Arguments
/// * `how` - Operation mode (`SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`).
/// * `set` - User pointer to new signal mask, or `0`.
/// * `oset` - User pointer to store previous signal mask, or `0`.
/// * `size` - Size of the signal set (must be 8).
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_rt_sigprocmask(how: u64, set: u64, oset: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let new = if set != 0 {
        match read_u64s::<1>(set) {
            Some([v]) => Some(v),
            None => return EFAULT,
        }
    } else {
        None
    };
    let (tid, pid) = current_ids();
    let old = {
        let mut procs = PROCS.lock();
        let t = match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => t,
            None => return 0,
        };
        let old = t.mask;
        if let Some(v) = new {
            t.mask = match how {
                0 => t.mask | v,  // SIG_BLOCK
                1 => t.mask & !v, // SIG_UNBLOCK
                2 => v,           // SIG_SETMASK
                _ => return EINVAL,
            } & !UNBLOCKABLE;
        }
        old
    };
    if oset != 0 && !write_bytes(oset, &old.to_le_bytes()) {
        return EFAULT;
    }
    0
}

/// Configures and/or queries the calling thread's alternate signal stack.
///
/// # Arguments
/// * `ss` - User pointer to new `stack_t`, or `0`.
/// * `old` - User pointer to store previous `stack_t`, or `0`.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_sigaltstack(ss: u64, old: u64) -> i64 {
    let (tid, pid) = current_ids();
    let mut procs = PROCS.lock();
    let t = match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
        Some(t) => *t,
        None => return EINVAL,
    };
    drop(procs);
    if old != 0 {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&t.alt_sp.to_le_bytes());
        let flags = if t.alt_size == 0 { SS_DISABLE } else { t.alt_flags };
        b[8..12].copy_from_slice(&flags.to_le_bytes());
        b[16..24].copy_from_slice(&t.alt_size.to_le_bytes());
        if !write_bytes(old, &b) {
            return EFAULT;
        }
    }
    if ss != 0 {
        let [sp, flags, size] = match read_u64s::<3>(ss) {
            Some(v) => v,
            None => return EFAULT,
        };
        let flags = flags as u32;
        let mut procs = PROCS.lock();
        if let Some(t) = procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            if flags & SS_DISABLE != 0 {
                t.alt_sp = 0;
                t.alt_size = 0;
                t.alt_flags = SS_DISABLE;
            } else {
                t.alt_sp = sp;
                t.alt_size = size;
                t.alt_flags = 0;
            }
        }
    }
    0
}

/// Writes the bitmask of signals pending for the calling thread/process to `set`.
///
/// # Arguments
/// * `set` - User pointer to store pending signal mask.
/// * `size` - Size of the signal set (must be 8).
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_rt_sigpending(set: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let (tid, pid) = current_ids();
    let pending = PROCS
        .lock()
        .get(&pid)
        .map(|p| p.pending | p.threads.get(&tid).map_or(0, |t| t.pending))
        .unwrap_or(0);
    if write_bytes(set, &pending.to_le_bytes()) {
        0
    } else {
        EFAULT
    }
}

/// Waits with a temporary mask until an unblocked signal is delivered.
///
/// # Arguments
/// * `mask_ptr` - User pointer to temporary signal mask.
/// * `size` - Size of the signal set (must be 8).
///
/// # Returns
/// Always returns `-EINTR` (or negative error code).
pub fn sys_rt_sigsuspend(mask_ptr: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let mask = match read_u64s::<1>(mask_ptr) {
        Some([m]) => m,
        None => return EFAULT,
    };
    let (tid, pid) = current_ids();
    let saved = {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
            Some(t) => {
                let saved = t.mask;
                t.mask = mask & !UNBLOCKABLE;
                saved
            }
            None => return EINTR,
        }
    };
    while !signal_pending() {
        crate::task::sleep_ticks(1);
    }
    // The original mask is restored after the handler runs (stored for delivery)
    SUSPEND_RESTORE.lock().insert(tid, saved);
    EINTR
}

/// `rt_sigtimedwait(2)`: waits for a signal from `set`, takes it without running its
/// handler, and returns its number.
///
/// # Arguments
/// * `set_ptr` - User pointer to the signal set.
/// * `info_ptr` - User pointer to a `siginfo_t` to fill, or 0.
/// * `ts_ptr` - User pointer to the timeout (`struct timespec`), or 0 to wait forever.
/// * `size` - Size of the signal set (8).
///
/// # Returns
/// The signal number, `-EAGAIN` on timeout, `-EINTR` if another signal arrived.
pub fn sys_rt_sigtimedwait(set_ptr: u64, info_ptr: u64, ts_ptr: u64, size: u64) -> i64 {
    if size != 8 {
        return EINVAL;
    }
    let Some([set]) = read_u64s::<1>(set_ptr) else { return EFAULT };
    let mask = set & !(bit(SIGKILL) | bit(SIGSTOP));
    let hz = crate::arch::pit::frequency_hz().max(1);
    let deadline = if ts_ptr != 0 {
        let Some([sec, nsec]) = read_u64s::<2>(ts_ptr) else { return EFAULT };
        if (sec as i64) < 0 || nsec >= 1_000_000_000 {
            return EINVAL;
        }
        Some(crate::arch::pit::ticks() + sec * hz + (nsec * hz).div_ceil(1_000_000_000))
    } else {
        None
    };
    loop {
        if let Some(sig) = take_signal(mask) {
            if info_ptr != 0 {
                let (tid, pid) = current_ids();
                let sender = {
                    let mut procs = PROCS.lock();
                    procs
                        .get_mut(&pid)
                        .map(|p| match p.threads.get_mut(&tid).map(|t| core::mem::take(&mut t.senders[sig as usize])) {
                            Some(s) if s.pid != 0 => s,
                            _ => core::mem::take(&mut p.senders[sig as usize]),
                        })
                        .unwrap_or_default()
                };
                let mut info = [0u8; 128];
                info[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
                info[8..12].copy_from_slice(&sender.code.to_le_bytes());
                info[16..20].copy_from_slice(&sender.pid.to_le_bytes());
                info[20..24].copy_from_slice(&sender.uid.to_le_bytes());
                info[24..32].copy_from_slice(&sender.value.to_le_bytes());
                if !write_bytes(info_ptr, &info) {
                    return EFAULT;
                }
            }
            return sig as i64;
        }
        if signal_pending() {
            return EINTR;
        }
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            return -11; // EAGAIN
        }
        crate::task::sleep_ticks(1);
    }
}

/// Text of `/proc/<pid>/oom_score_adj` or `oom_score` (`file`), or `None` if there is no
/// such process.
///
/// # Arguments
/// * `pid` - Process ID.
/// * `file` - `oom_score_adj` or `oom_score`.
pub fn oom_file_text(pid: u64, file: &str) -> Option<alloc::string::String> {
    let adj = PROCS.lock().get(&pid).filter(|p| !p.zombie).map(|p| p.oom_score_adj)?;
    // oom_score: Linux's badness, 0..=2000; without memory accounting, the adjustment
    Some(alloc::format!("{}
", if file == "oom_score" { adj.max(0) } else { adj }))
}

/// Writes `/proc/<pid>/oom_score_adj`: the owner (or root) may set it; going below 0 takes
/// `CAP_SYS_RESOURCE`.
///
/// # Arguments
/// * `pid` - Process ID.
/// * `buf` - Bytes written (a decimal number).
///
/// # Returns
/// Bytes accepted, or a negative errno.
pub fn write_oom_score_adj(pid: u64, buf: &[u8]) -> i64 {
    let Ok(value) = core::str::from_utf8(buf).unwrap_or("").trim().parse::<i32>() else { return EINVAL };
    if !(-1000..=1000).contains(&value) {
        return EINVAL;
    }
    let owner = crate::task::SCHEDULER.lock().with_process(pid, |t| t.uid);
    let (euid, resource) = crate::task::with_current_task_mut(|t| (t.euid, t.caps.has(1 << 24))).unwrap_or((u32::MAX, false));
    let Some(owner) = owner else { return ESRCH };
    if euid != 0 && euid != owner {
        return EPERM;
    }
    match PROCS.lock().get_mut(&pid) {
        Some(p) => {
            // Linux's floor for unprivileged writers (oom_score_adj_min) starts at 0
            if value < 0 && value < p.oom_score_adj && !resource {
                return EACCES;
            }
            p.oom_score_adj = value;
            buf.len() as i64
        }
        None => ESRCH,
    }
}

/// `rt_sigqueueinfo(2)` (`tid == None`) and `rt_tgsigqueueinfo(2)`: sends `sig` with the
/// caller's `siginfo` (`sigqueue` passes a value this way). Only a process signalling itself
/// may claim a kernel or `kill` origin (`si_code >= 0`, or `SI_TKILL`).
///
/// # Arguments
/// * `pid` - Target process (in the caller's PID namespace).
/// * `tid` - Target thread, for `rt_tgsigqueueinfo`.
/// * `sig` - Signal number (0 only checks the target exists).
/// * `info_ptr` - User pointer to the `siginfo_t`.
///
/// # Returns
/// `0` on success, or a negative errno.
pub fn sys_rt_sigqueueinfo(pid: u64, tid: Option<u64>, sig: u64, info_ptr: u64) -> i64 {
    if sig as usize > NSIG {
        return EINVAL;
    }
    let pid = super::ns::pid_from_caller(pid);
    let tid = tid.map(super::ns::pid_from_caller);
    let Some(raw) = read_u64s::<4>(info_ptr) else { return EFAULT };
    let code = (raw[1] & 0xffff_ffff) as u32 as i32;
    let (_, me) = current_ids();
    if (code >= 0 || code == SI_TKILL) && pid != me {
        return EPERM;
    }
    if !process_exists(pid) || is_system_service(pid) {
        return ESRCH;
    }
    if sig == 0 {
        return 0;
    }
    let sender = SigSender { code, pid: raw[2] as u32, uid: (raw[2] >> 32) as u32, value: raw[3], ..Default::default() };
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        match tid {
            Some(t) => {
                if let Some(t) = p.threads.get_mut(&t) {
                    t.senders[sig as usize] = sender;
                }
            }
            None => p.senders[sig as usize] = sender,
        }
    }
    let posted = match tid {
        Some(t) => post_thread(pid, t, sig as u32),
        None => post_process(pid, sig as u32),
    };
    if posted { 0 } else { ESRCH }
}

/// Whether `sig` is still pending for process `pid` (or its thread `tid`): a POSIX timer
/// counts an expiry as an overrun instead of sending the signal again.
///
/// # Arguments
/// * `pid` - Process ID.
/// * `tid` - Thread the signal was sent to, if any.
/// * `sig` - Signal number.
pub fn signal_queued(pid: u64, tid: Option<u64>, sig: u32) -> bool {
    let procs = PROCS.lock();
    let Some(p) = procs.get(&pid) else { return false };
    match tid {
        Some(t) => p.threads.get(&t).is_some_and(|t| t.pending & bit(sig) != 0),
        None => p.pending & bit(sig) != 0,
    }
}

/// Sends a POSIX timer's signal: `si_code` `SI_TIMER`, with the timer ID, overrun count
/// and value its handler reads.
///
/// # Arguments
/// * `pid` - Process owning the timer.
/// * `tid` - Thread to signal (`SIGEV_THREAD_ID`), or the process.
/// * `sig` - Signal number.
/// * `timer` - Timer ID (`si_timerid`).
/// * `overrun` - Expiries not signalled (`si_overrun`).
/// * `value` - The creator's value (`si_value`).
///
/// # Returns
/// `false` if the process or thread no longer exists.
pub fn post_timer_signal(pid: u64, tid: Option<u64>, sig: u32, timer: i32, overrun: u32, value: u64) -> bool {
    // si_timerid and si_overrun sit where si_pid and si_uid do for other signals
    let sender = SigSender { code: super::ptimer::SI_TIMER, pid: timer as u32, uid: overrun, value, ..Default::default() };
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        match tid {
            Some(t) => {
                if let Some(t) = p.threads.get_mut(&t) {
                    t.senders[sig as usize] = sender;
                }
            }
            None => p.senders[sig as usize] = sender,
        }
    }
    match tid {
        Some(t) => post_thread(pid, t, sig),
        None => post_process(pid, sig),
    }
}

/// Sends `sig` to process `pid` with the given `siginfo` origin (`si_code`, `si_pid`,
/// `si_uid`, `si_value`), for kernel-generated notifications such as a POSIX message
/// queue's.
///
/// # Returns
/// `false` if the process no longer exists.
pub fn post_with_info(pid: u64, sig: u32, code: i32, spid: u32, suid: u32, value: u64) -> bool {
    if let Some(p) = PROCS.lock().get_mut(&pid) {
        p.senders[sig as usize] = SigSender { code, pid: spid, uid: suid, value, ..Default::default() };
    }
    post_process(pid, sig)
}

/// Updates the overrun count (`si_overrun`) of a POSIX timer signal still queued.
///
/// # Arguments
/// * `pid` - Process ID.
/// * `tid` - Thread the signal was sent to, if any.
/// * `sig` - Signal number.
/// * `overrun` - Expiries counted while it was pending.
pub fn set_timer_overrun(pid: u64, tid: Option<u64>, sig: u32, overrun: u32) {
    let mut procs = PROCS.lock();
    let Some(p) = procs.get_mut(&pid) else { return };
    let sender = match tid {
        Some(t) => p.threads.get_mut(&t).map(|t| &mut t.senders[sig as usize]),
        None => Some(&mut p.senders[sig as usize]),
    };
    if let Some(s) = sender.filter(|s| s.code == super::ptimer::SI_TIMER) {
        s.uid = overrun;
    }
}

/// Masks to restore after a signal interrupted `rt_sigsuspend`, by thread.
static SUSPEND_RESTORE: Mutex<BTreeMap<u64, u64>> = Mutex::new(BTreeMap::new());

/// Returns `true` if process `pid` (or one of its threads) has a signal from `mask` pending
/// (`signalfd` readiness). Never blocks.
///
/// # Arguments
/// * `pid` - Target process ID.
/// * `mask` - Signal mask to test against.
///
/// # Returns
/// `true` if any matching signal is pending, `false` otherwise.
pub fn pending_for(pid: u64, mask: u64) -> bool {
    let procs = match PROCS.try_lock() {
        Some(p) => p,
        None => return false,
    };
    procs.get(&pid).map_or(false, |p| {
        let threads = p.threads.values().fold(0, |acc, t| acc | t.pending);
        (p.pending | threads) & mask != 0
    })
}

/// Returns `(si_code, child_pid, si_status)` for a `SIGCHLD` received by `parent`, derived
/// from its children's state (the process table does not queue per-signal details):
/// an unreaped zombie gives `CLD_EXITED`/`CLD_KILLED`/`CLD_DUMPED`, else a stopped or continued child.
///
/// # Arguments
/// * `parent` - Parent process ID.
///
/// # Returns
/// Tuple containing `(si_code, child_pid, si_status)`.
pub fn sigchld_details(parent: u64) -> (i32, u64, i32) {
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    const CLD_STOPPED: i32 = 5;
    const CLD_CONTINUED: i32 = 6;
    let procs = PROCS.lock();
    let children = || procs.values().filter(move |c| c.ppid == parent);
    if let Some(c) = children().find(|c| c.zombie) {
        let st = c.exit_status.unwrap_or(0);
        return match st & 0x7f {
            0 => (CLD_EXITED, c.pid, (st >> 8) & 0xff),
            sig if st & 0x80 != 0 => (CLD_DUMPED, c.pid, sig),
            sig => (CLD_KILLED, c.pid, sig),
        };
    }
    if let Some(c) = children().find(|c| c.stopped) {
        return (CLD_STOPPED, c.pid, c.stop_sig as i32);
    }
    if let Some(c) = children().find(|c| c.continued) {
        return (CLD_CONTINUED, c.pid, SIGCONT as i32);
    }
    (0, 0, 0)
}

/// Takes the lowest pending signal in `mask` for the calling thread (its own pending set
/// first, then the process's) without delivering it (`signalfd` reads).
///
/// # Arguments
/// * `mask` - Mask of signals eligible to be taken.
///
/// # Returns
/// `Some(signal_number)` if a pending signal was found and dequeued, or `None`.
pub fn take_signal(mask: u64) -> Option<u32> {
    let (tid, pid) = current_ids();
    let mut procs = PROCS.lock();
    let p = procs.get_mut(&pid)?;
    let t = p.threads.entry(tid).or_default();
    if t.pending & mask != 0 {
        let sig = (t.pending & mask).trailing_zeros() + 1;
        t.pending &= !bit(sig);
        return Some(sig);
    }
    if p.pending & mask != 0 {
        let sig = (p.pending & mask).trailing_zeros() + 1;
        p.pending &= !bit(sig);
        return Some(sig);
    }
    None
}

/// Whether `sig` is one the CPU raises (its `siginfo` carries `si_addr`).
fn is_fault_signal(sig: u32) -> bool {
    matches!(sig, SIGSEGV | SIGBUS | SIGILL | SIGFPE | SIGTRAP)
}

/// `si_code` and `si_addr` of a fault signal raised by exception `ctx`.
fn fault_sender(ctx: &ExceptionContext, sig: u32) -> SigSender {
    let (code, addr) = match (sig, ctx.vector) {
        // int3: SI_KERNEL; a single step: TRAP_TRACE (debuggers tell them apart)
        // #DB: a hardware breakpoint or watchpoint (TRAP_HWBKPT, at its address; DR6 is in
        // error_code) or a single step (TRAP_TRACE)
        (SIGTRAP, 1) if ctx.error_code & 0xf != 0 => {
            let n = (ctx.error_code & 0xf).trailing_zeros() as usize;
            (4, crate::task::with_current_task_mut(|t| t.debugregs[n]).unwrap_or(0))
        }
        (SIGTRAP, 1) => (2, 0),
        (SIGTRAP, _) => (0x80, 0),
        // Page faults: SEGV_MAPERR (nothing mapped) or SEGV_ACCERR (not allowed); BUS_ADRERR
        (SIGSEGV, 14) => (if ctx.error_code & 1 != 0 { 2 } else { 1 }, x86_64::registers::control::Cr2::read_raw()),
        (SIGBUS, 14) => (2, x86_64::registers::control::Cr2::read_raw()),
        // Invalid opcode: ILL_ILLOPN at the instruction; divide error: FPE_INTDIV
        (SIGILL, _) => (2, ctx.rip),
        (SIGFPE, 0) => (1, ctx.rip),
        _ => (0x80, 0),
    };
    SigSender { code, call_addr: addr, ..SigSender::default() }
}

/// `siginfo` for `sig` from `s`, as a handler (or a tracer's `PTRACE_GETSIGINFO`) sees it.
fn siginfo_of(sig: u32, s: &SigSender) -> [u8; 128] {
    let mut f = [0u8; 128];
    f[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
    f[8..12].copy_from_slice(&s.code.to_le_bytes());
    f[16..20].copy_from_slice(&s.pid.to_le_bytes());
    f[20..24].copy_from_slice(&s.uid.to_le_bytes());
    f[24..32].copy_from_slice(&s.value.to_le_bytes());
    if is_fault_signal(sig) && s.pid == 0 {
        f[16..24].copy_from_slice(&s.call_addr.to_le_bytes());
    }
    if sig == SIGSYS && s.code == SYS_SECCOMP {
        f[4..8].copy_from_slice(&s.errno.to_le_bytes());
        f[16..24].copy_from_slice(&s.call_addr.to_le_bytes());
        f[24..28].copy_from_slice(&s.syscall.to_le_bytes());
        f[28..32].copy_from_slice(&super::seccomp::AUDIT_ARCH_X86_64.to_le_bytes());
    }
    f
}

/// Queues `sig` for the calling thread as let through by its tracer.
fn inject(sig: u32) {
    let (tid, pid) = current_ids();
    if sig == 0 || sig as usize > NSIG {
        return;
    }
    if let Some(t) = PROCS.lock().get_mut(&pid).map(|p| p.threads.entry(tid).or_default()) {
        t.pending |= bit(sig);
        t.injected |= bit(sig);
    }
}

/// Tells tracer `pid` that a tracee stopped (`SIGCHLD`, unless it asked not to).
pub fn notify_tracer(pid: u64) {
    let mut procs = PROCS.lock();
    notify_parent_stop(&mut procs, pid);
}

/// Whether `SIGKILL` is pending for the calling thread.
pub fn sigkill_pending() -> bool {
    let (tid, pid) = current_ids();
    PROCS.lock().get(&pid).map_or(false, |p| (p.pending | p.threads.get(&tid).map_or(0, |t| t.pending)) & bit(SIGKILL) != 0)
}

/// Parent of process `pid` (0 if unknown).
pub fn parent_of(pid: u64) -> u64 {
    PROCS.lock().get(&pid).map_or(0, |p| p.ppid)
}

/// The process thread `tid` belongs to.
pub fn tgid_of(tid: u64) -> Option<u64> {
    PROCS.lock().values().find(|p| !p.zombie && p.threads.contains_key(&tid)).map(|p| p.pid)
}

/// Returns `true` if the calling thread has an unblocked pending signal (blocking syscalls poll this).
///
/// # Returns
/// `true` if an unblocked signal is pending for the calling thread, `false` otherwise.
pub fn signal_pending() -> bool {
    let (tid, pid) = current_ids();
    let procs = match PROCS.try_lock() {
        Some(p) => p,
        None => return false,
    };
    match procs.get(&pid) {
        Some(p) => {
            let t = p.threads.get(&tid).copied().unwrap_or_default();
            (p.pending | t.pending) & !(t.mask & !UNBLOCKABLE) != 0
        }
        None => false,
    }
}

// ----------------------------------------------------------------------
// Delivery
// ----------------------------------------------------------------------

/// Complete user register state of an interrupted context.
#[derive(Clone, Copy, Default)]
pub struct UserRegs {
    /// General-purpose register `r8`.
    pub r8: u64,
    /// General-purpose register `r9`.
    pub r9: u64,
    /// General-purpose register `r10`.
    pub r10: u64,
    /// General-purpose register `r11`.
    pub r11: u64,
    /// General-purpose register `r12`.
    pub r12: u64,
    /// General-purpose register `r13`.
    pub r13: u64,
    /// General-purpose register `r14`.
    pub r14: u64,
    /// General-purpose register `r15`.
    pub r15: u64,
    /// General-purpose register `rdi` (first argument).
    pub rdi: u64,
    /// General-purpose register `rsi` (second argument).
    pub rsi: u64,
    /// Base pointer register `rbp`.
    pub rbp: u64,
    /// General-purpose register `rbx`.
    pub rbx: u64,
    /// General-purpose register `rdx` (third argument).
    pub rdx: u64,
    /// Accumulator / return value register `rax`.
    pub rax: u64,
    /// General-purpose register `rcx`.
    pub rcx: u64,
    /// User stack pointer register `rsp`.
    pub rsp: u64,
    /// Instruction pointer register `rip`.
    pub rip: u64,
    /// CPU status flags register `rflags`.
    pub rflags: u64,
}

/// Internal decision produced when dequeuing a pending signal for delivery.
enum Action {
    /// No deliverable unblocked signal remains.
    None,
    /// Invoke user handler `(sig, sigaction, saved_mask)`.
    Handler(u32, SigAction, u64),
    /// Terminate the process due to `sig`.
    Terminate(u32),
    /// Stop the process due to job-control signal `sig`.
    Stop(u32),
    /// A traced thread's signal-delivery stop for `sig` (sent by the sender given).
    Trace(u32, SigSender),
}

/// Takes the next deliverable signal for the calling thread and decides what to do.
///
/// # Returns
/// The [`Action`] to take for the dequeued signal.
fn dequeue() -> Action {
    let (tid, pid) = current_ids();
    let mut procs = match PROCS.try_lock() {
        Some(p) => p,
        None => return Action::None,
    };
    let p = match procs.get_mut(&pid) {
        Some(p) => p,
        None => return Action::None,
    };
    loop {
        let t = p.threads.entry(tid).or_default();
        let ready = (p.pending | t.pending) & !(t.mask & !UNBLOCKABLE);
        if ready == 0 {
            return Action::None;
        }
        let sig = ready.trailing_zeros() + 1;
        if t.pending & bit(sig) != 0 {
            t.pending &= !bit(sig);
        } else {
            p.pending &= !bit(sig);
        }
        // A traced thread stops for every signal but SIGKILL before acting on it; one its
        // tracer let through is acted on
        if t.injected & bit(sig) != 0 {
            t.injected &= !bit(sig);
        } else if sig != SIGKILL && super::ptrace::is_traced(tid) {
            let ts = t.senders[sig as usize];
            let sender = if ts.pid != 0 || ts.code != 0 { ts } else { p.senders[sig as usize] };
            return Action::Trace(sig, sender);
        }
        let mask = t.mask;
        let act = p.actions[sig as usize];
        match act.handler {
            SIG_IGN if sig != SIGKILL => continue,
            SIG_DFL => {
                if default_ignored(sig) {
                    continue;
                }
                if is_stop_signal(sig) {
                    return Action::Stop(sig);
                }
                return Action::Terminate(sig);
            }
            _ if sig == SIGSTOP => return Action::Stop(sig),
            _ if sig == SIGKILL => return Action::Terminate(sig),
            _ => {
                if act.flags & SA_RESETHAND != 0 {
                    p.actions[sig as usize] = SigAction::default();
                }
                let t = p.threads.get_mut(&tid).unwrap();
                let restore = SUSPEND_RESTORE.lock().remove(&tid).unwrap_or(mask);
                t.mask |= act.mask & !UNBLOCKABLE;
                if act.flags & SA_NODEFER == 0 {
                    t.mask |= bit(sig);
                }
                return Action::Handler(sig, act, restore);
            }
        }
    }
}

/// Terminates the calling process because of `sig` (default action).
///
/// # Arguments
/// * `sig` - Signal number causing termination.
///
/// # Returns
/// Does not return (`!`).
fn die(sig: u32) -> ! {
    let (_, pid) = current_ids();
    let core = matches!(sig, SIGQUIT | SIGILL | SIGTRAP | SIGABRT | SIGBUS | SIGFPE | SIGSEGV | SIGSYS);
    if sig != SIGPIPE && sig != SIGTERM && sig != SIGINT && sig != SIGKILL {
        crate::kprintln!("[linux] pid {} killed by signal {}{}", pid, sig, if core { " (core dumped)" } else { "" });
    }
    set_exit_status(pid, (sig as i32) | if core { 0x80 } else { 0 });
    crate::task::exit_group();
}

/// Terminates the calling process as if killed by `sig` (seccomp `KILL` actions).
///
/// # Arguments
/// * `sig` - Signal number reported as the cause.
///
/// # Returns
/// Does not return (`!`).
pub fn die_by_signal(sig: u32) -> ! {
    die(sig)
}

/// Raises `SIGSYS` for a call a seccomp filter trapped, the way the kernel forces it: the
/// signal is unblocked and an ignored disposition is reset, and its `siginfo` names the
/// call. It is delivered as the skipped call returns.
///
/// # Arguments
/// * `nr` - Trapped system call number.
/// * `ip` - Address after the `syscall` instruction.
/// * `errno` - Filter return data, reported as `si_errno`.
pub fn force_seccomp_sigsys(nr: i32, ip: u64, errno: i32) {
    let (tid, pid) = current_ids();
    let mut procs = PROCS.lock();
    if let Some(p) = procs.get_mut(&pid) {
        if p.actions[SIGSYS as usize].handler == SIG_IGN {
            p.actions[SIGSYS as usize] = SigAction::default();
        }
        let t = p.threads.entry(tid).or_default();
        t.mask &= !bit(SIGSYS);
        t.pending |= bit(SIGSYS);
        t.senders[SIGSYS as usize] = SigSender { code: SYS_SECCOMP, call_addr: ip, syscall: nr, errno, ..Default::default() };
    }
}

/// Writes an `rt_sigframe` for `sig` onto the user stack and redirects `regs` to the
/// handler. Returns `false` if the stack is unusable.
///
/// # Arguments
/// * `regs` - User register context to modify for handler execution.
/// * `fpu` - Floating-point state to save in frame.
/// * `sig` - Signal number being delivered.
/// * `act` - Signal action configuring the handler.
/// * `old_mask` - Blocked signal mask prior to handler entry.
///
/// # Returns
/// `true` on successful frame creation, `false` if stack memory could not be written.
fn build_frame(regs: &mut UserRegs, fpu: &FpuState, sig: u32, act: &SigAction, old_mask: u64) -> bool {
    let (tid, pid) = current_ids();
    let alt = PROCS.lock().get(&pid).and_then(|p| p.threads.get(&tid).copied()).unwrap_or_default();
    let on_alt = alt.alt_size != 0 && regs.rsp > alt.alt_sp && regs.rsp <= alt.alt_sp + alt.alt_size;
    let mut sp = if act.flags & SA_ONSTACK != 0 && alt.alt_size != 0 && !on_alt {
        alt.alt_sp + alt.alt_size
    } else {
        regs.rsp - 128 // skip the red zone
    };

    // FXSAVE area, then the frame: pretcode (8) + ucontext (304) + siginfo (128)
    sp = (sp - 512) & !63;
    let fp_addr = sp;
    let frame = ((sp - 440) & !15) - 8;
    let uc = frame + 8;
    let info = uc + 304;

    let mut f = [0u8; 440];
    let put = |f: &mut [u8; 440], off: usize, v: u64| f[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut f, 0, act.restorer);
    // ucontext: uc_flags, uc_link, uc_stack
    put(&mut f, 8 + 16, alt.alt_sp);
    f[8 + 24..8 + 28].copy_from_slice(&(if on_alt { SS_ONSTACK } else if alt.alt_size == 0 { SS_DISABLE } else { 0 }).to_le_bytes());
    put(&mut f, 8 + 32, alt.alt_size);
    // sigcontext (uc + 40)
    let mc = 8 + 40;
    let gprs = [
        regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rdi, regs.rsi, regs.rbp, regs.rbx,
        regs.rdx, regs.rax, regs.rcx, regs.rsp, regs.rip, regs.rflags,
    ];
    for (i, v) in gprs.iter().enumerate() {
        put(&mut f, mc + i * 8, *v);
    }
    f[mc + 144..mc + 146].copy_from_slice(&0x23u16.to_le_bytes()); // cs
    f[mc + 150..mc + 152].copy_from_slice(&0x1bu16.to_le_bytes()); // ss
    put(&mut f, mc + 160, 0); // err
    put(&mut f, mc + 168, 0); // trapno
    put(&mut f, mc + 176, old_mask);
    put(&mut f, mc + 192, fp_addr);
    // uc_sigmask
    put(&mut f, 8 + 296, old_mask);
    // siginfo: si_signo, si_errno, si_code, then si_pid and si_uid (for kill/tkill/tgkill)
    let sender = {
        let mut procs = PROCS.lock();
        // The thread's own record (tgkill) first, then the process's (kill)
        procs
            .get_mut(&pid)
            .map(|p| match p.threads.get_mut(&tid).map(|t| core::mem::take(&mut t.senders[sig as usize])) {
                Some(s) if s.pid != 0 || s.code != 0 => s,
                _ => core::mem::take(&mut p.senders[sig as usize]),
            })
            .unwrap_or_default()
    };
    f[312..316].copy_from_slice(&(sig as i32).to_le_bytes());
    f[320..324].copy_from_slice(&sender.code.to_le_bytes());
    f[328..332].copy_from_slice(&sender.pid.to_le_bytes());
    f[332..336].copy_from_slice(&sender.uid.to_le_bytes());
    put(&mut f, 336, sender.value); // si_value
    if is_fault_signal(sig) && sender.pid == 0 {
        put(&mut f, 328, sender.call_addr); // si_addr
    }
    if sig == SIGSYS && sender.code == SYS_SECCOMP {
        // _sigsys: si_call_addr, si_syscall, si_arch (in place of si_pid/si_uid)
        f[316..320].copy_from_slice(&sender.errno.to_le_bytes());
        put(&mut f, 328, sender.call_addr);
        f[336..340].copy_from_slice(&sender.syscall.to_le_bytes());
        f[340..344].copy_from_slice(&super::seccomp::AUDIT_ARCH_X86_64.to_le_bytes());
    }

    if !write_bytes(fp_addr, &fpu.0) || !write_bytes(frame, &f) {
        return false;
    }

    regs.rsp = frame;
    regs.rip = act.handler;
    regs.rdi = sig as u64;
    regs.rsi = info;
    regs.rdx = uc;
    regs.rax = 0;
    regs.rflags &= !0x400; // clear DF
    true
}

/// Delivers pending signals before returning from a system call. `orig_nr` is the system
/// call number (for restarts); the result is already in `frame.rax`.
///
/// # Arguments
/// * `frame` - Syscall register frame.
/// * `fpu` - Pointer to thread's saved FPU state.
/// * `orig_nr` - Original syscall number invoked.
pub fn deliver_on_syscall_return(frame: &mut SyscallFrame, fpu: *mut FpuState, orig_nr: u64) {
    let result = frame.rax as i64;
    let (_, pid) = current_ids();
    let action = loop {
        if is_stopped(pid) {
            wait_while_stopped();
        }
        if super::ptrace::interrupt_pending() {
            super::ptrace::interrupt_stop(frame, fpu, orig_nr);
        }
        match dequeue() {
            Action::Stop(sig) if super::ptrace::is_traced(current_ids().0) => super::ptrace::group_stop(frame, fpu, orig_nr, sig),
            Action::Stop(sig) => stop_current(sig),
            Action::Trace(sig, s) => {
                let new = super::ptrace::signal_stop(frame, fpu, orig_nr, sig, &siginfo_of(sig, &s));
                if new != 0 {
                    inject(new);
                }
            }
            a => break a,
        }
    };
    match action {
        Action::Stop(_) | Action::Trace(..) => unreachable!(),
        Action::None => {
            if result == ERESTARTSYS || result == ERESTART_RESTARTBLOCK {
                // Interrupted by a signal that turned out to be ignored (or a stop): restart
                frame.rip -= 2;
                frame.rax = orig_nr;
                mark_restart(orig_nr);
            }
        }
        Action::Terminate(sig) => die(sig),
        Action::Handler(sig, act, old_mask) => {
            if result == ERESTARTSYS && act.flags & SA_RESTART != 0 {
                frame.rip -= 2;
                frame.rax = orig_nr;
                mark_restart(orig_nr);
            } else if result == ERESTARTSYS || result == ERESTART_RESTARTBLOCK {
                frame.rax = EINTR as u64;
            }
            let mut regs = UserRegs {
                r8: frame.r8,
                r9: frame.r9,
                r10: frame.r10,
                r11: frame.rflags,
                r12: frame.r12,
                r13: frame.r13,
                r14: frame.r14,
                r15: frame.r15,
                rdi: frame.rdi,
                rsi: frame.rsi,
                rbp: frame.rbp,
                rbx: frame.rbx,
                rdx: frame.rdx,
                rax: frame.rax,
                rcx: frame.rip,
                rsp: frame.rsp,
                rip: frame.rip,
                rflags: frame.rflags,
            };
            let fpu_ref = unsafe { &*fpu };
            if !build_frame(&mut regs, fpu_ref, sig, &act, old_mask) {
                die(SIGSEGV);
            }
            frame.rip = regs.rip;
            frame.rsp = regs.rsp;
            frame.rdi = regs.rdi;
            frame.rsi = regs.rsi;
            frame.rdx = regs.rdx;
            frame.rax = regs.rax;
            frame.rflags = regs.rflags;
        }
    }
}

/// Delivers pending signals to a thread about to return to user mode from an interrupt
/// or exception.
///
/// # Arguments
/// * `ctx` - Exception register context.
/// * `fpu` - Pointer to thread's saved FPU state.
pub fn deliver_on_trap_return(ctx: &mut ExceptionContext, fpu: *mut FpuState) {
    if (ctx.cs & 3) != 3 || fpu.is_null() {
        return;
    }
    let (_, pid) = current_ids();
    let stopped = PROCS.try_lock().map_or(false, |p| p.get(&pid).map_or(false, |p| p.stopped));
    if !stopped && !signal_pending() && !super::ptrace::interrupt_pending() {
        return;
    }
    let action = loop {
        if is_stopped(pid) {
            wait_while_stopped();
        }
        if super::ptrace::interrupt_pending() {
            super::ptrace::interrupt_stop(ctx, fpu, u64::MAX);
        }
        match dequeue() {
            Action::Stop(sig) if super::ptrace::is_traced(current_ids().0) => super::ptrace::group_stop(ctx, fpu, u64::MAX, sig),
            Action::Stop(sig) => stop_current(sig),
            Action::Trace(sig, s) => {
                let new = super::ptrace::signal_stop(ctx, fpu, u64::MAX, sig, &siginfo_of(sig, &s));
                if new != 0 {
                    inject(new);
                }
            }
            a => break a,
        }
    };
    match action {
        Action::Stop(_) | Action::Trace(..) => unreachable!(),
        Action::None => {}
        Action::Terminate(sig) => die(sig),
        Action::Handler(sig, act, old_mask) => {
            let mut regs = UserRegs {
                r8: ctx.r8,
                r9: ctx.r9,
                r10: ctx.r10,
                r11: ctx.r11,
                r12: ctx.r12,
                r13: ctx.r13,
                r14: ctx.r14,
                r15: ctx.r15,
                rdi: ctx.rdi,
                rsi: ctx.rsi,
                rbp: ctx.rbp,
                rbx: ctx.rbx,
                rdx: ctx.rdx,
                rax: ctx.rax,
                rcx: ctx.rcx,
                rsp: ctx.rsp,
                rip: ctx.rip,
                rflags: ctx.rflags,
            };
            let fpu_ref = unsafe { &*fpu };
            if !build_frame(&mut regs, fpu_ref, sig, &act, old_mask) {
                die(SIGSEGV);
            }
            ctx.rip = regs.rip;
            ctx.rsp = regs.rsp;
            ctx.rdi = regs.rdi;
            ctx.rsi = regs.rsi;
            ctx.rdx = regs.rdx;
            ctx.rax = regs.rax;
            ctx.rflags = regs.rflags;
        }
    }
}

/// Raises a synchronous fault signal (`SIGSEGV`, `SIGILL`, `SIGFPE`, `SIGBUS`) in the
/// current thread. If the signal is blocked or has no handler, the process dies.
///
/// # Arguments
/// * `ctx` - Exception register context.
/// * `fpu` - Pointer to thread's saved FPU state.
/// * `sig` - Synchronous signal to force.
pub fn force_fault_signal(ctx: &mut ExceptionContext, fpu: *mut FpuState, sig: u32) {
    let (tid, pid) = current_ids();
    // A tracer sees the fault first, whatever the disposition
    let traced = super::ptrace::is_traced(tid);
    let handled = {
        let mut procs = PROCS.lock();
        match procs.get_mut(&pid) {
            Some(p) => {
                let act = p.actions[sig as usize];
                let t = p.threads.entry(tid).or_default();
                let usable = traced || (act.handler > SIG_IGN && t.mask & bit(sig) == 0);
                if usable {
                    t.pending |= bit(sig);
                    t.mask &= !bit(sig);
                    t.senders[sig as usize] = fault_sender(ctx, sig);
                }
                usable
            }
            None => false,
        }
    };
    if !handled {
        die(sig);
    }
    deliver_on_trap_return(ctx, fpu);
}

/// Restores the context saved in the signal frame and returns to it.
///
/// # Arguments
/// * `frame` - Syscall frame from which `rsp` is retrieved.
///
/// # Returns
/// Does not return (`!`).
pub fn sys_rt_sigreturn(frame: &SyscallFrame) -> ! {
    let uc = frame.rsp; // the handler's `ret` popped pretcode, so rsp points at the ucontext
    let mut raw = [0u8; 304];
    if !prefault_current(uc, 304, false) {
        die(SIGSEGV);
    }
    unsafe { core::ptr::copy_nonoverlapping(uc as *const u8, raw.as_mut_ptr(), 304) };
    let get = |off: usize| u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
    let mc = 40;
    let g = |i: usize| get(mc + i * 8);
    let mut regs = UserRegs {
        r8: g(0),
        r9: g(1),
        r10: g(2),
        r11: g(3),
        r12: g(4),
        r13: g(5),
        r14: g(6),
        r15: g(7),
        rdi: g(8),
        rsi: g(9),
        rbp: g(10),
        rbx: g(11),
        rdx: g(12),
        rax: g(13),
        rcx: g(14),
        rsp: g(15),
        rip: g(16),
        // User code may only change the arithmetic flags, DF, TF... keep IF set
        rflags: (g(17) & 0x0000_0000_0025_4DD5) | 0x202,
    };
    let fp_addr = get(mc + 192);
    let mask = get(296);

    let (tid, pid) = current_ids();
    if let Some(t) = PROCS.lock().get_mut(&pid).and_then(|p| p.threads.get_mut(&tid)) {
        t.mask = mask & !UNBLOCKABLE;
    }

    let mut fpu = FpuState::new();
    if fp_addr != 0 && prefault_current(fp_addr, 512, false) {
        unsafe { core::ptr::copy_nonoverlapping(fp_addr as *const u8, fpu.0.as_mut_ptr(), 512) };
        // Keep MXCSR's reserved bits clear or FXRSTOR faults
        let mxcsr = u32::from_le_bytes(fpu.0[24..28].try_into().unwrap()) & 0xFFFF;
        fpu.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
    }
    // A tracer's exit stop for rt_sigreturn (it does not return through the dispatcher)
    if super::ptrace::is_traced(current_ids().0) {
        super::ptrace::sigreturn_exit(&mut regs, &mut fpu);
    }
    if regs.rip >= crate::memory::vm::USER_SPACE_END || regs.rsp >= crate::memory::vm::USER_SPACE_END {
        die(SIGSEGV);
    }
    unsafe { return_to_user(&regs, &fpu) }
}

/// Returns to user mode with every register (including `rcx`/`r11`) taken from `regs`
/// and the FPU state from `fpu`, via `iretq`. Used where `sysret` cannot restore the
/// full context.
///
/// # Arguments
/// * `regs` - Complete user-mode register state to restore.
/// * `fpu` - Floating-point state image to restore.
///
/// # Returns
/// Does not return (`!`).
///
/// # Safety
/// - `regs.rip` and `regs.rsp` must point to valid user-space addresses mapped in the active page table.
/// - `regs.rflags` must have `IF` (`0x200`) set and privileged flags masked properly for Ring 3 execution.
/// - `fpu` must contain a valid 64-byte-aligned 512-byte `FXRSTOR64` image with reserved `MXCSR` bits cleared.
pub unsafe fn return_to_user(regs: &UserRegs, fpu: &FpuState) -> ! {
    let regs = *regs;
    core::arch::asm!(
        "fxrstor64 [{fpu}]",
        "push 0x1b",          // SS
        "push qword ptr [rax + 15*8]", // RSP
        "push qword ptr [rax + 17*8]", // RFLAGS
        "push 0x23",          // CS
        "push qword ptr [rax + 16*8]", // RIP
        "mov r8,  [rax + 0*8]",
        "mov r9,  [rax + 1*8]",
        "mov r10, [rax + 2*8]",
        "mov r11, [rax + 3*8]",
        "mov r12, [rax + 4*8]",
        "mov r13, [rax + 5*8]",
        "mov r14, [rax + 6*8]",
        "mov r15, [rax + 7*8]",
        "mov rdi, [rax + 8*8]",
        "mov rsi, [rax + 9*8]",
        "mov rbp, [rax + 10*8]",
        "mov rbx, [rax + 11*8]",
        "mov rdx, [rax + 12*8]",
        "mov rcx, [rax + 14*8]",
        "mov rax, [rax + 13*8]",
        "iretq",
        // The pointer must sit in the register loaded last: any other could be overwritten
        // by the loads before it is done with
        fpu = in(reg) fpu as *const FpuState,
        in("rax") &regs as *const UserRegs,
        options(noreturn)
    );
}

// ----------------------------------------------------------------------
// wait4 / waitid
// ----------------------------------------------------------------------

/// `wait4` / `waitid` option flag: return immediately if no child has changed state (`WNOHANG`).
const WNOHANG: u64 = 1;
/// `wait4` / `waitid` option flag: also report stopped children (`WUNTRACED` / `WSTOPPED`).
const WUNTRACED: u64 = 2;
/// `wait4` / `waitid` option flag: also report continued children (`WCONTINUED`).
const WCONTINUED: u64 = 8;
/// `waitid` option flag: leave the child in a waitable state without reaping it (`WNOWAIT`).
const WNOWAIT: u64 = 0x0100_0000;

/// Status values `wait` reports for job-control state changes.
const WAIT_CONTINUED: i32 = 0xffff;
/// Encodes a stop signal `sig` into the 16-bit status word reported by `wait4`.
///
/// # Arguments
/// * `sig` - Signal number causing the stop.
///
/// # Returns
/// Encoded wait status word.
fn wait_status_stopped(sig: u32) -> i32 {
    0x7f | ((sig as i32) << 8)
}

/// Returns `true` if `child` is a direct child of `me` matching the `wait` selector `sel`.
///
/// # Arguments
/// * `child` - Child process candidate.
/// * `me` - Parent process ID.
/// * `my_pgid` - Parent's process group ID.
/// * `sel` - Wait selector (< -1 for pgid, -1 for any, 0 for pgid, >0 for pid).
///
/// # Returns
/// `true` if the child matches the selection criteria, `false` otherwise.
fn matches(child: &Process, me: u64, my_pgid: u64, sel: i64) -> bool {
    child.ppid == me
        && match sel {
            -1 => true,
            0 => child.pgid == my_pgid,
            s if s > 0 => child.pid == s as u64,
            s => child.pgid == (-s) as u64,
        }
}

/// Finds (and unless `keep`, reaps) a zombie child matching `sel`.
///
/// # Arguments
/// * `sel` - Wait selector.
/// * `options` - Wait option flags (`WNOHANG`, `WUNTRACED`, `WCONTINUED`, `WNOWAIT`).
///
/// # Returns
/// `Ok(Some((pid, status)))` if child found, `Ok(None)` if matching children exist but none exited,
/// or `Err(-ECHILD)` if no matching children exist.
fn reap(sel: i64, options: u64) -> Result<Option<(u64, i32)>, i64> {
    let keep = options & WNOWAIT != 0;
    let (_, me) = current_ids();
    let mut procs = PROCS.lock();
    let my_pgid = procs.get(&me).map_or(me, |p| p.pgid);
    let mut any = false;
    // Stops and exits of threads the caller traces
    if let Some(r) = super::ptrace::wait_report(me, sel, keep) {
        return Ok(Some(r));
    }
    // (pid, status, kind): 0 = exited (reap), 1 = stopped, 2 = continued
    let mut found = None;
    for c in procs.values() {
        if matches(c, me, my_pgid, sel) {
            any = true;
            if c.zombie {
                found = Some((c.pid, c.exit_status.unwrap_or(0), 0));
                break;
            }
            if options & WUNTRACED != 0 && c.stopped && !c.stop_reported {
                found = Some((c.pid, wait_status_stopped(c.stop_sig), 1));
                break;
            }
            if options & WCONTINUED != 0 && c.continued {
                found = Some((c.pid, WAIT_CONTINUED, 2));
                break;
            }
        }
    }
    if !any && !super::ptrace::has_tracee(me, sel) {
        return Err(ECHILD);
    }
    if let Some((pid, _, kind)) = found {
        if !keep {
            match kind {
                0 => {
                    procs.remove(&pid);
                }
                1 => procs.get_mut(&pid).unwrap().stop_reported = true,
                _ => procs.get_mut(&pid).unwrap().continued = false,
            }
        }
    }
    Ok(found.map(|(pid, status, _)| (pid, status)))
}

/// Encodes an exit status the way `wait` reports it.
///
/// # Arguments
/// * `code` - Process exit code.
///
/// # Returns
/// Encoded 16-bit status integer.
pub fn wait_status_exit(code: i32) -> i32 {
    (code & 0xff) << 8
}

/// Waits until a matching child changes state (exit, stop, continue: all wake
/// [`super::pidfd::EXIT_WQ`]), `WNOHANG` applies, or a signal interrupts the wait.
///
/// # Arguments
/// * `sel` - Wait selector.
/// * `options` - Wait option flags.
///
/// # Returns
/// `Ok(Some((pid, status)))` on state change, `Ok(None)` for non-blocking wait without change,
/// or `Err(code)` on signal or failure.
fn wait_loop(sel: i64, options: u64) -> Result<Option<(u64, i32)>, i64> {
    let mut waits = crate::task::wait::WaitSet::new();
    waits.add(crate::task::wait::QueueRef::Static(&super::pidfd::EXIT_WQ));
    loop {
        waits.register();
        match reap(sel, options)? {
            Some(r) => return Ok(Some(r)),
            None if options & WNOHANG != 0 => return Ok(None),
            None => {}
        }
        if signal_pending() {
            return Err(ERESTARTSYS);
        }
        waits.wait(None);
    }
}

/// Waits for a child process to change state.
///
/// # Arguments
/// * `pid` - Child selector (< -1 for pgid, -1 for any, 0 for caller pgid, >0 for pid).
/// * `status_ptr` - User pointer to store exit status integer, or `0`.
/// * `options` - Wait options (`WNOHANG`, `WUNTRACED`, `WCONTINUED`).
/// * `_rusage` - Pointer to `rusage` structure (ignored).
///
/// # Returns
/// Process ID of the child on success, `0` if `WNOHANG` and no change, or a negative Linux error code.
pub fn sys_wait4(pid: i64, status_ptr: u64, options: u64, _rusage: u64) -> i64 {
    match wait_loop(pid, options) {
        Ok(Some((pid, status))) => {
            if status_ptr != 0 && !write_bytes(status_ptr, &status.to_le_bytes()) {
                return EFAULT;
            }
            pid as i64
        }
        Ok(None) => 0,
        Err(e) => e,
    }
}

/// Waits for a child process state change and populates a `siginfo_t`.
///
/// # Arguments
/// * `idtype` - Target type (`P_ALL`, `P_PID`, `P_PGID`, `P_PIDFD`).
/// * `id` - Target identifier corresponding to `idtype`.
/// * `infop` - User pointer to `siginfo_t` structure.
/// * `options` - Wait options.
///
/// # Returns
/// `0` on success, or a negative Linux error code on failure.
pub fn sys_waitid(idtype: u64, id: u64, infop: u64, options: u64) -> i64 {
    let sel = match idtype {
        0 => -1,               // P_ALL
        1 => id as i64,        // P_PID
        2 => -(id as i64),     // P_PGID
        3 => match super::pidfd::pid_of(id) {
            // P_PIDFD
            Ok(pid) => pid as i64,
            Err(e) => return e,
        },
        _ => return EINVAL,
    };
    if options & (4 | WUNTRACED | WCONTINUED) == 0 {
        return EINVAL; // need at least one of WEXITED, WSTOPPED, WCONTINUED
    }
    match wait_loop(sel, options) {
        Ok(Some((pid, status))) => {
            if infop != 0 {
                let mut info = [0u8; 128];
                info[0..4].copy_from_slice(&(SIGCHLD as i32).to_le_bytes());
                // CLD_EXITED 1, CLD_KILLED 2, CLD_STOPPED 5, CLD_CONTINUED 6
                let (code, value) = if status == WAIT_CONTINUED {
                    (6, SIGCONT as i32)
                } else if status & 0xff == 0x7f {
                    (5, (status >> 8) & 0xff)
                } else if status & 0x7f == 0 {
                    (1, (status >> 8) & 0xff)
                } else {
                    (2, status & 0x7f)
                };
                info[8..12].copy_from_slice(&(code as i32).to_le_bytes());
                info[16..20].copy_from_slice(&(pid as i32).to_le_bytes());
                info[24..28].copy_from_slice(&value.to_le_bytes());
                if !write_bytes(infop, &info) {
                    return EFAULT;
                }
            }
            0
        }
        Ok(None) => {
            if infop != 0 {
                write_bytes(infop, &[0u8; 128]);
            }
            0
        }
        Err(e) => e,
    }
}
