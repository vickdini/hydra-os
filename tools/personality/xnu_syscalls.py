"""macOS (XNU) BSD system calls against the FreeBSD front end / BSD core (Group 11, step 0).

    python3 -I xnu_syscalls.py XNU_SYSCALLS_MASTER [DARLING_BSD_SYSCALL_TABLE_C] > table.md

Reads XNU's bsd/kern/syscalls.master (macOS 26, xnu-12377.121.6), classifies every live
call, and, when Darling's bsd_syscall_table.c is given, marks which ones Darling implements
(a measure of what real macOS programs need). Only reads files; run with python3 -I.

Classes (docs/personality-design.md section 5):
  F  same operation as the FreeBSD front end (shared BSD-core path; only the number differs)
  T  same operation, but macOS layouts or constants differ from FreeBSD's (stat64, dirent64,
     kevent, 32-bit sigset_t, open flags, AF_INET6 30, errno above 81, sysctl tree)
  N  macOS-only; new code in the macOS front end or the BSD core
  M  goes to mach-server (Mach semantics: psynch, semaphores, thread ports, workqueues)
  S  safe to stub at first
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syscalls_master as sm  # noqa: E402

C = {}
def cls(c, names, note=""):
    for n in names.split():
        C[n] = (c, note)

cls("F", "exit fork read write close wait4 link unlink chdir fchdir mknod chmod chown getpid setuid "
         "getuid geteuid recvmsg sendmsg recvfrom accept getpeername getsockname access kill getppid "
         "dup getegid getgid getlogin setlogin acct readlink symlink umask chroot msync vfork munmap "
         "mprotect madvise mincore getgroups setgroups getpgrp setpgid setitimer getitimer getdtablesize "
         "dup2 select fsync setpriority socket connect getpriority bind setsockopt listen gettimeofday "
         "getrusage getsockopt readv writev settimeofday fchown fchmod setreuid setregid rename flock "
         "mkfifo sendto shutdown socketpair mkdir rmdir utimes futimes adjtime setsid getpgid pread pwrite "
         "setgid setegid seteuid fdatasync pathconf fpathconf getrlimit setrlimit mmap lseek truncate "
         "ftruncate mlock munlock poll semget semop msgget msgsnd msgrcv shmat shmdt shmget semctl msgctl "
         "shmctl shm_unlink getsid mlockall munlockall issetugid lchown pselect openat renameat faccessat "
         "fchmodat fchownat linkat unlinkat readlinkat symlinkat mkdirat mkfifoat mknodat preadv pwritev "
         "aio_fsync aio_return aio_suspend aio_cancel aio_error aio_read aio_write lio_listio sync "
         "minherit sigaltstack waitid execve",
    "")
cls("T", "open open_dprotected_np openat_dprotected_np", "O_CLOEXEC 0x1000000, O_DIRECTORY 0x100000 (FreeBSD 0x100000 / 0x20000)")
cls("T", "fcntl", "F_* numbers (F_GETPATH 50, F_FULLFSYNC 51, F_NOCACHE, F_SETNOSIGPIPE...)")
cls("T", "ioctl", "termios is FreeBSD-like but with 64-bit tcflag_t/speed_t; FIO*/TIOC* numbers")
cls("T", "stat fstat lstat stat64 fstat64 lstat64 fstatat fstatat64", "struct stat64 ($INODE64: st_birthtimespec, 64-bit ino, st_flags, st_gen)")
cls("T", "statfs fstatfs getfsstat statfs64 fstatfs64 getfsstat64", "struct statfs64 (f_fstypename, f_mntonname[1024])")
cls("T", "getdirentries getdirentries64", "struct dirent64 (d_seekoff, d_namlen, d_name[1024])")
cls("T", "sigaction sigprocmask sigpending sigsuspend sigreturn __pthread_sigmask __sigwait",
    "32-bit sigset_t; sigaction with sa_tramp (libc's _sigtramp passed in); sigreturn(uctx, infostyle, token)")
cls("T", "sysctl sysctlbyname", "same engine as FreeBSD, macOS tree (hw.memsize, hw.optional.*, machdep.cpu.*, kern.osversion, kern.osproductversion)")
cls("T", "kqueue kevent", "32-byte kevent (no ext[]), EVFILT_MACHPORT -8, EVFILT_VM, EVFILT_EXCEPT; same core as FreeBSD")
cls("T", "kevent64 kevent_qos kevent_id", "kevent64_s / kevent_qos_s; kevent_qos also serves libdispatch workloops (with workq)")
cls("T", "pipe", "returns both descriptors in rax/rdx")
cls("T", "sendfile", "(fd, s, offset, *len, hdtr, flags)")
cls("T", "getxattr fgetxattr setxattr fsetxattr removexattr fremovexattr listxattr flistxattr",
    "onto the core's xattrs with position/options arguments (resource forks: com.apple.ResourceFork)")
cls("T", "chflags fchflags", "UF_HIDDEN etc.: kept as an xattr or ignored")
cls("T", "gettid", "macOS gettid returns the per-thread uid/gid (not a thread id)")
cls("T", "thread_selfid", "the thread id (Hydra's tid)")
cls("T", "__pthread_kill", "thread port -> tid, then the core's tgkill")
cls("T", "__pthread_chdir __pthread_fchdir", "per-thread working directory (core: a thread-private cwd)")
cls("T", "getentropy", "onto getrandom")
cls("T", "renameatx_np", "RENAME_SWAP/EXCL onto renameat2")
cls("T", "ntp_adjtime ntp_gettime", "struct timex/ntptimeval")
cls("T", "initgroups", "setgroups + login name")
cls("T", "gethostuuid", "a stable host UUID (machine id)")
cls("T", "fsgetpath fsgetpath_ext", "path of (fsid, objid): the core's inode -> path")
cls("T", "freadlink", "readlink of a descriptor")
cls("T", "posix_spawn", "fork+exec in one call with file actions and attributes; the core's spawn")
cls("N", "getattrlist setattrlist fgetattrlist fsetattrlist getattrlistat setattrlistat getdirentriesattr getattrlistbulk",
    "attribute lists (Finder info, sizes, dates in one call); Foundation and CoreServices use them")
cls("N", "exchangedata searchfs delete copyfile clonefileat fclonefileat fs_snapshot fsctl ffsctl",
    "APFS/HFS operations: clonefile onto a ZFS block clone or a copy; the rest ENOTSUP")
cls("N", "proc_info proc_info_extended_id", "libproc: process lists, fd info, paths (Activity Monitor, ps, lsof)")
cls("N", "csops csops_audittoken", "code signing status: answer 'valid, not restricted' (darlingserver does)")
cls("N", "shared_region_check_np shared_region_map_and_slide_2_np", "dyld shared cache: answer 'no shared region' (Darling does)")
cls("N", "guarded_open_np guarded_close_np guarded_kqueue_np change_fdguard_np guarded_open_dprotected_np "
         "guarded_write_np guarded_pwrite_np guarded_writev_np",
    "guarded descriptors: a guard value per descriptor, checked on close/dup (libdispatch, libxpc)")
cls("N", "sys_ulock_wait sys_ulock_wake sys_ulock_wait2 ulock_wait ulock_wake ulock_wait2",
    "os_unfair_lock and friends: onto the kernel futex (owner tid in the word)")
cls("N", "open_extended umask_extended stat_extended lstat_extended fstat_extended chmod_extended "
         "fchmod_extended access_extended mkfifo_extended mkdir_extended stat64_extended "
         "lstat64_extended fstat64_extended", "the *_extended forms carry a kauth ACL: ignore the ACL")
cls("N", "openbyid_np", "open by (fsid, objid)")
cls("N", "memorystatus_control memorystatus_get_level memorystatus_available_memory",
    "jetsam: answer plausibly (no memory pressure)")
cls("N", "terminate_with_payload abort_with_payload os_fault_with_payload", "crash reasons: log, then SIGABRT/exit")
cls("N", "fileport_makeport fileport_makefd", "descriptor <-> Mach port: needs mach-server (send a descriptor as a port right)")
cls("N", "socket_delegate connectx disconnectx peeloff recvmsg_x sendmsg_x", "multipath and batch socket calls (sendmsg_x: loop)")
cls("N", "iopolicysys process_policy", "I/O and process policy: accept and ignore")
cls("N", "persona", "ENOTSUP")
cls("M", "bsdthread_create bsdthread_terminate bsdthread_register bsdthread_ctl",
    "pthread start-up: task_clone + a thread port from mach-server; bsdthread_terminate also frees the stack and a semaphore")
cls("M", "workq_open workq_kernreturn kqueue_workloop_ctl work_interval_ctl",
    "libdispatch's kernel-managed thread pool: in mach-server (or a user-space pool, Darling-style)")
cls("M", "psynch_mutexwait psynch_mutexdrop psynch_cvbroad psynch_cvsignal psynch_cvwait psynch_rw_rdlock "
         "psynch_rw_wrlock psynch_rw_unlock psynch_rw_unlock2 psynch_cvclrprepost psynch_rw_longrdlock "
         "psynch_rw_yieldwrlock psynch_rw_downgrade psynch_rw_upgrade",
    "libpthread's kernel side (generation counters); darlingserver runs XNU's own code for it")
cls("M", "__semwait_signal __disable_threadsignal __pthread_markcancel __pthread_canceled",
    "cancellation and sleep through Mach semaphores")
cls("M", "mach_eventlink_signal mach_eventlink_wait_until mach_eventlink_signal_wait_until", "Mach eventlinks")
cls("M", "audit_session_self audit_session_join audit_session_port", "Mach ports for the audit session: a dummy port")
cls("M", "task_inspect_for_pid task_read_for_pid", "Mach task ports by pid")
cls("S", "nfssvc getfh fhopen quotactl mount unmount funmount fmount __mac_mount __mac_get_mount __mac_getfsstat "
         "reboot swapon revoke undelete vfs_purge graftdmg ungraftdmg pivot_root", "EPERM/ENOTSUP")
cls("S", "ptrace", "PT_DENY_ATTACH (anti-debugging, common in apps): accept; the rest later")
cls("S", "setprivexec settid settid_with_pid setsgroups getsgroups setwgroups getwgroups identitysvc", "ENOTSUP")
cls("S", "kdebug_typefilter kdebug_trace_string kdebug_trace64 kdebug_trace", "tracing: accept and drop")
cls("S", "panic_with_data thread_selfcounts thread_selfusage oslog_coproc_reg oslog_coproc crossarch_trap",
    "ENOTSUP")
cls("S", "audit auditon getauid setauid getaudit_addr setaudit_addr auditctl", "ENOSYS (BSM audit)")
cls("S", "__mac_execve __mac_syscall __mac_get_file __mac_set_file __mac_get_link __mac_set_link "
         "__mac_get_proc __mac_set_proc __mac_get_fd __mac_set_fd __mac_get_pid",
    "sandbox (MACF): __mac_syscall(\"Sandbox\", ...) succeeds without enforcing")
cls("S", "semsys msgsys shmsys", "old multiplexers, not used by libc")
cls("T", "sem_open sem_close sem_unlink sem_wait sem_trywait sem_post shm_open",
    "named POSIX semaphores and shared memory are system calls on macOS: the core's named objects")
cls("S", "pid_suspend pid_resume pid_hibernate pid_shutdown_sockets kas_info usrctl proc_rlimit_control "
         "telemetry proc_uuid_policy system_override sfi_ctl sfi_pidctl coalition coalition_info "
         "coalition_ledger necp_match_policy necp_open necp_client_action necp_session_open "
         "necp_session_action netagent_trigger net_qos_guideline proc_trace_log csrctl mremap_encrypted "
         "stack_snapshot_with_config microstackshot grab_pgo_data __nexus_open __nexus_register "
         "__nexus_deregister __nexus_create __nexus_destroy __nexus_get_opt __nexus_set_opt __channel_open "
         "__channel_get_info __channel_sync __channel_get_opt __channel_set_opt log_data "
         "__mach_bridge_remote_time objc_bp_assist_cfg_np tracker_action debug_syscall_reject "
         "debug_syscall_reject_config record_system_event coalition_policy_set coalition_policy_get ledger "
         "vm_pressure_monitor map_with_linking_np",
    "Apple-internal or policy calls: ENOTSUP or a harmless answer")


def darling_set(path):
    nums = set()
    for m in re.finditer(r"\[(\d+)\]\s*=\s*(\w+)", open(path, encoding="utf-8", errors="replace").read()):
        nums.add(int(m.group(1)))
    return nums


def norm(name):
    n = name
    if n.startswith("sys_"):
        n = n[4:]
    if n.endswith("_nocancel"):
        n = n[: -len("_nocancel")]
    return n


def main():
    ents = [e for e in sm.parse(sys.argv[1]) if e[3] not in ("nosys", "enosys")]
    dar = darling_set(sys.argv[2]) if len(sys.argv) > 2 else None
    tot, tot_d, missing = {}, {}, []
    print("| # | Call | Class | Darling | Note |")
    print("|---:|---|:-:|:-:|---|")
    for num, _, _, name, _ in ents:
        n = norm(name)
        c, note = C.get(n, C.get(name, ("?", "")))
        if c == "?":
            missing.append(name)
        if name.endswith("_nocancel"):
            note = "as `%s` (no cancellation point)" % n
        tot[c] = tot.get(c, 0) + 1
        d = ""
        if dar is not None:
            d = "yes" if num in dar else ""
            if num in dar:
                tot_d[c] = tot_d.get(c, 0) + 1
        print("| %d | `%s` | %s | %s | %s |" % (num, name, c, d, note))
    print()
    print("Totals: " + ", ".join("%s %d" % (k, v) for k, v in sorted(tot.items())) + ", all %d" % len(ents))
    if dar is not None:
        print("Implemented by Darling, per class: " + ", ".join("%s %d" % (k, v) for k, v in sorted(tot_d.items()))
              + ", all %d" % sum(tot_d.values()))
    if missing:
        print("UNCLASSIFIED: " + " ".join(missing), file=sys.stderr)


if __name__ == "__main__":
    main()
