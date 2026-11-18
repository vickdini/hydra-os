"""FreeBSD/amd64 system calls against Hydra's Linux layer (Group 11, step 0).

    python3 -I fbsd_syscalls.py SYSCALLS_MASTER [FREEBSD_ROOT] > table.md

Reads FreeBSD's sys/kern/syscalls.master, classifies every live (STD/NOSTD) call with the
hand-made table below, and, when FREEBSD_ROOT (an extracted base.txz) is given, counts how many
ELF files of the base system import each call's libc/libsys symbol (readelf --dyn-syms), as a
rough measure of how much it matters. Only reads files; never runs anything from the root
except readelf on it.

Classes (see docs/personality-design.md section 4):
  D  direct: maps onto an existing Linux-layer operation as is (errno translation only)
  T  translate: same operation, but a layout, flag or constant translation is needed
  N  new: no Linux-layer equivalent; new code in the BSD core or the FreeBSD front end
  S  safe to stub (ENOSYS, EPERM, or a harmless constant answer), at least at first
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syscalls_master as sm  # noqa: E402

C = {}
def cls(c, names, note=""):
    for n in names.split():
        C[n] = (c, note)

# --- D: direct --------------------------------------------------------------------------
cls("D", "_exit fork read write close wait4 link unlink chdir fchdir chmod chown break getpid "
         "getuid geteuid getppid dup getegid getgid dup2 select fsync setpriority getpriority "
         "listen gettimeofday getrusage readv writev settimeofday fchown fchmod setreuid "
         "setregid rename flock mkfifo shutdown mkdir rmdir utimes setsid getpgid lchown "
         "setuid setgid setegid seteuid getpgrp setpgid setitimer getitimer getdtablesize "
         "munmap mprotect mincore mlock munlock mlockall munlockall symlink readlink umask "
         "chroot sync acct vfork poll nanosleep getsid setresuid setresgid getresuid getresgid "
         "yield sched_yield sched_rr_get_interval __getcwd futimes futimesat pread pwrite "
         "preadv pwritev lseek truncate ftruncate readlinkat symlinkat mkdirat renameat "
         "mkfifoat posix_fallocate posix_fadvise futimens fdatasync getrandom copy_file_range "
         "close_range sched_getcpu membarrier timerfd_gettime timerfd_settime inotify_rm_watch "
         "getgroups setgroups clock_settime eaccess kmq_open kmq_setattr kmq_timedreceive "
         "kmq_timedsend kmq_unlink semget semop msgget msgsnd msgrcv shmat shmdt shmget "
         "execve shm_unlink access",
    "")
# --- T: translate -----------------------------------------------------------------------
cls("T", "open openat", "O_* flag values differ (O_CREAT 0x200, O_CLOEXEC 0x100000, ...)")
cls("T", "fstat fstatat", "struct stat layout (st_birthtim, st_flags, st_gen, 64-bit dev_t encoding)")
cls("T", "statfs fstatfs getfsstat", "struct statfs (f_mntonname/f_mntfromname, f_fstypename); getfsstat lists the mount table")
cls("T", "getdirentries", "struct dirent (d_off, d_namlen, d_type) and the base pointer")
cls("T", "fcntl", "F_* command numbers, struct flock layout (l_sysid), F_DUPFD_CLOEXEC, F_ISUNIONSTACK")
cls("T", "ioctl", "termios ioctls (TIOCGETA/TIOCSETA, struct termios differs), FIO*, sockets; per device")
cls("T", "mmap", "MAP_ANON 0x1000, MAP_EXCL, MAP_ALIGNED(n), MAP_GUARD, MAP_STACK semantics")
cls("T", "madvise msync minherit", "advice and flag values; minherit(INHERIT_ZERO) onto MADV_WIPEONFORK (arc4random)")
cls("T", "kill thr_kill thr_kill2 sigqueue", "signal numbers differ above 15 (SIGCHLD 20, SIGUSR1 30, ...)")
cls("T", "sigaction sigprocmask sigsuspend sigpending sigtimedwait sigwaitinfo sigwait sigreturn",
    "128-bit sigset_t, struct sigaction and siginfo layouts; sigreturn takes a FreeBSD ucontext")
cls("T", "sigaltstack", "stack_t field order differs (ss_size before ss_flags)")
cls("T", "getcontext setcontext swapcontext", "FreeBSD ucontext_t/mcontext_t (kernel side, with the signal frame)")
cls("T", "socket socketpair", "SOCK_CLOEXEC/SOCK_NONBLOCK values, AF_INET6 28, AF_LOCAL 1")
cls("T", "connect bind accept accept4 getpeername getsockname sendto recvfrom",
    "sockaddr with sa_len, family numbers")
cls("T", "sendmsg recvmsg", "struct msghdr (int msg_iovlen, socklen_t msg_controllen), cmsghdr, SCM_CREDS")
cls("T", "setsockopt getsockopt", "SOL_SOCKET 0xffff, SO_* and IP*/TCP_* option numbers")
cls("T", "sendfile", "different signature (fd, s, offset, nbytes, hdtr, *sbytes, flags)")
cls("T", "getrlimit setrlimit", "RLIMIT_* numbers differ (NOFILE 8, NPROC 7, MEMLOCK 6, AS 10)")
cls("T", "clock_gettime clock_getres clock_nanosleep timerfd_create",
    "clock ids differ (MONOTONIC 4, UPTIME 5, PROF 2, VIRTUAL 1, *_FAST/_PRECISE, THREAD 14, PROCESS 15)")
cls("T", "clock_getcpuclockid2", "onto Linux's encoded per-process/thread CPU clock ids")
cls("T", "ktimer_create ktimer_delete ktimer_settime ktimer_gettime ktimer_getoverrun",
    "POSIX timers; struct sigevent layout and clock ids")
cls("T", "kmq_notify", "struct sigevent")
cls("T", "__semctl msgctl shmctl", "ipc_perm, semid_ds, msqid_ds, shmid_ds layouts")
cls("T", "faccessat fchmodat fchownat linkat unlinkat utimensat lutimes funlinkat renameat2 lchmod",
    "AT_* flag values differ (AT_SYMLINK_NOFOLLOW 0x200, AT_REMOVEDIR 0x800, AT_EACCESS 0x100)")
cls("T", "mknodat", "64-bit dev_t encoding")
cls("T", "pipe2", "O_CLOEXEC value; FreeBSD pipes are bidirectional (both ends readable and writable)")
cls("T", "ppoll pselect", "128-bit sigset_t")
cls("T", "wait6", "onto waitid + rusage: idtype_t values, struct __wrusage, siginfo")
cls("T", "rfork", "RF* flags onto clone flags (RFPROC, RFMEM, RFFDG, RFCFDG, RFNOWAIT)")
cls("T", "pdfork pdrfork pdkill pdgetpid pdwait", "process descriptors onto pidfd")
cls("T", "posix_openpt", "O_* flags; onto /dev/ptmx")
cls("T", "bindat connectat", "Unix-socket path relative to a directory descriptor (core: resolve, then bind/connect)")
cls("T", "fexecve", "onto execveat(fd, \"\", AT_EMPTY_PATH)")
cls("T", "extattr_set_file extattr_get_file extattr_delete_file extattr_set_fd extattr_get_fd "
         "extattr_delete_fd extattr_set_link extattr_get_link extattr_delete_link extattr_list_fd "
         "extattr_list_file extattr_list_link",
    "onto xattrs: namespace USER -> \"user.\", SYSTEM -> \"system.\"; list format (length-prefixed)")
cls("T", "inotify_add_watch_at", "onto inotify with a directory descriptor")
cls("T", "kcmp", "type numbers")
cls("T", "fchroot", "fchdir + chroot")
cls("T", "setcred", "setresuid + setresgid + setgroups in one step")
cls("T", "thr_set_name", "per-thread comm (Linux: /proc/self/task/T/comm, PR_SET_NAME)")
cls("T", "abort2", "log the message, then SIGABRT to self")
cls("T", "sched_setparam sched_getparam sched_setscheduler sched_getscheduler "
         "sched_get_priority_max sched_get_priority_min",
    "policy numbers differ (SCHED_FIFO 1, SCHED_OTHER 2, SCHED_RR 3)")
cls("T", "cpuset_getaffinity cpuset_setaffinity", "onto sched_get/setaffinity; level/which/id, 1024-bit cpuset_t")
cls("T", "shm_open2 shm_rename", "SHM_ANON onto memfd; named objects in a hidden directory of the core")
cls("T", "__specialfd", "SPECIALFD_EVENTFD onto eventfd, SPECIALFD_INOTIFY onto inotify_init1")
cls("T", "fspacectl", "SPACECTL_DEALLOC onto fallocate(PUNCH_HOLE)")
cls("T", "ntp_gettime", "struct ntptimeval")
# --- N: new -----------------------------------------------------------------------------
cls("N", "kqueue kqueuex kevent", "kqueue: the core's readiness words, plus process, signal, timer and vnode filters")
cls("N", "__sysctl __sysctlbyname", "sysctl MIB tree (section 4.4)")
cls("N", "thr_new thr_exit thr_self", "threads onto task_clone; thr_exit stores *state and wakes it (umtx)")
cls("N", "_umtx_op", "libthr's locks, condition variables, semaphores: mostly onto futex, robust lists differ")
cls("N", "sysarch", "AMD64_SET_FSBASE/GET_FSBASE/SET_GSBASE/GET_GSBASE: thin, kernel-local, like arch_prctl")
cls("N", "issetugid", "a per-process flag set at exec of set-id programs (Linux: AT_SECURE)")
cls("N", "getlogin setlogin", "the session's login name, kept with the session")
cls("N", "pathconf fpathconf lpathconf", "answered from the file system (NAME_MAX, PIPE_BUF, _PC_ACL_*)")
cls("N", "__realpathat", "canonical path from the VFS (libc's realpath(3) uses it first)")
cls("N", "uuidgen", "random version-4 UUIDs")
cls("N", "procctl", "PROC_REAP_* (subreaper), PDEATHSIG, TRACE_CTL, ASLR/STACKGAP/WXMAP status, NO_NEW_PRIVS")
cls("N", "aio_read aio_write lio_listio aio_return aio_suspend aio_cancel aio_error "
         "aio_waitcomplete aio_fsync aio_readv aio_writev", "POSIX AIO in the core (struct aiocb), later")
cls("N", "cap_enter cap_getmode __cap_rights_get cap_rights_limit cap_ioctls_limit cap_ioctls_get "
         "cap_fcntls_limit cap_fcntls_get",
    "Capsicum: stub ENOSYS first (capsicum_helpers treat it as 'no Capsicum'), later per-descriptor rights")
cls("N", "jail jail_attach jail_get jail_set jail_remove jail_attach_jd jail_remove_jd",
    "jails: jail_get ENOENT / jail_set EPERM first, later onto Hydra namespaces and ABAC")
cls("N", "ptrace", "FreeBSD ptrace API (PT_*, struct reg, PT_LWPINFO): after the Linux ptrace policy moves")
# --- S: stub ----------------------------------------------------------------------------
cls("S", "mount unmount nmount reboot swapon swapoff quotactl", "EPERM (Hydra's admin interface owns these)")
cls("S", "kldload kldunload kldunloadf kldfind kldnext kldstat kldfirstmod kldsym modnext modstat "
         "modfnext modfind", "no kernel modules: kldfind/modfind ENOENT, kldload EPERM")
cls("S", "ktrace utrace profil", "ENOSYS")
cls("S", "nlm_syscall nfssvc lgetfh getfh fhopen fhstat fhstatfs getfhat fhlink fhlinkat fhreadlink",
    "NFS and file handles: ENOSYS/EOPNOTSUPP")
cls("S", "semsys msgsys shmsys", "old multiplexers, not used by libc")
cls("S", "rtprio rtprio_thread setfib adjtime ntp_adjtime ffclock_getcounter ffclock_setestimate "
         "ffclock_getestimate", "EPERM/ENOSYS")
cls("S", "undelete revoke", "EOPNOTSUPP")
cls("S", "chflags fchflags lchflags chflagsat", "0 for flags 0, EOPNOTSUPP otherwise (no BSD file flags on Hydra ZFS)")
cls("S", "__setugid", "test-only")
cls("S", "nnpfs_syscall afs3_syscall sctp_peeloff sctp_generic_sendmsg sctp_generic_sendmsg_iov "
         "sctp_generic_recvmsg rpctls_syscall", "ENOSYS")
cls("S", "__acl_get_file __acl_set_file __acl_get_fd __acl_set_fd __acl_delete_file __acl_delete_fd "
         "__acl_aclcheck_file __acl_aclcheck_fd __acl_get_link __acl_set_link __acl_delete_link "
         "__acl_aclcheck_link", "EOPNOTSUPP first; later onto the core's POSIX ACLs (NFSv4 ACLs differ)")
cls("S", "extattrctl", "EOPNOTSUPP")
cls("S", "__mac_get_proc __mac_set_proc __mac_get_fd __mac_get_file __mac_set_fd __mac_set_file "
         "__mac_get_pid __mac_get_link __mac_set_link __mac_execve mac_syscall", "ENOSYS (no MAC framework)")
cls("S", "kenv", "ENOENT for every variable")
cls("S", "ksem_close ksem_post ksem_wait ksem_trywait ksem_init ksem_open ksem_unlink ksem_getvalue "
         "ksem_destroy ksem_timedwait", "old kernel semaphores; libc's sem_* use _umtx_op")
cls("S", "thr_create thr_suspend thr_wake", "not used by libthr")
cls("S", "audit auditon getauid setauid getaudit setaudit getaudit_addr setaudit_addr auditctl", "ENOSYS")
cls("S", "cpuset cpuset_setid cpuset_getid cpuset_getdomain cpuset_setdomain", "one root cpuset, id 1")
cls("S", "getloginclass setloginclass", "\"default\"")
cls("S", "rctl_get_racct rctl_get_rules rctl_get_limits rctl_add_rule rctl_remove_rule", "ENOSYS")
cls("S", "aio_mlock", "EOPNOTSUPP")
cls("S", "sigfastblock", "not advertised (AT_BSDFLAGS without ELF_BSDF_SIGFASTBLK): rtld and libthr then never call it")
cls("S", "getrlimitusage", "ENOSYS")
cls("S", "exterrctl", "ENOSYS: libc then shows plain errno strings")


def imports(root):
    """{symbol: number of ELF files importing it} over the root (dynamic symbols, UND)."""
    counts = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            if f.startswith("libsys.so"):
                continue
            r = subprocess.run(["readelf", "--dyn-syms", "-W", p], capture_output=True, text=True)
            seen = set()
            for ln in r.stdout.splitlines():
                parts = ln.split()
                if len(parts) >= 8 and parts[6] == "UND":
                    s = parts[7].split("@")[0]
                    seen.add(s)
            for s in seen:
                counts[s] = counts.get(s, 0) + 1
    return counts


def users(counts, name):
    # libc's public names for some calls differ from syscalls.master's.
    alias = {"__sysctl": ["sysctl", "sysctlnametomib", "__sysctl"], "__sysctlbyname": ["sysctlbyname"],
             "break": ["brk", "sbrk"], "__getcwd": ["getcwd"], "_umtx_op": ["_umtx_op"],
             "__realpathat": ["realpath"], "__specialfd": ["eventfd", "inotify_init", "inotify_init1"],
             "ktimer_create": ["timer_create"], "ktimer_settime": ["timer_settime"],
             "ktimer_gettime": ["timer_gettime"], "ktimer_delete": ["timer_delete"],
             "ktimer_getoverrun": ["timer_getoverrun"], "kmq_open": ["mq_open"],
             "kmq_timedsend": ["mq_send", "mq_timedsend"], "kmq_timedreceive": ["mq_receive", "mq_timedreceive"],
             "kmq_unlink": ["mq_unlink"], "kmq_notify": ["mq_notify"], "kmq_setattr": ["mq_setattr", "mq_getattr"],
             "__semctl": ["semctl"], "_exit": ["_exit", "exit"], "shm_open2": ["shm_open", "memfd_create"],
             "__cap_rights_get": ["__cap_rights_get", "cap_rights_get"], "sigreturn": ["sigreturn"],
             "inotify_add_watch_at": ["inotify_add_watch", "inotify_add_watch_at"]}
    n = 0
    for s in alias.get(name, [name]):
        n = max(n, counts.get(s, 0), counts.get("_" + s, 0), counts.get("__sys_" + s, 0))
    return n


def main():
    ents = [e for e in sm.parse(sys.argv[1]) if e[2].split("|")[0] in ("STD", "NOSTD")]
    counts = imports(sys.argv[2]) if len(sys.argv) > 2 else {}
    tot = {}
    rows = []
    missing = []
    for num, _, _, name, _ in ents:
        c, note = C.get(name, ("?", ""))
        if c == "?":
            missing.append(name)
        tot[c] = tot.get(c, 0) + 1
        rows.append((num, name, c, users(counts, name) if counts else "", note))
    print("| # | Call | Class | Users | Note |")
    print("|---:|---|:-:|---:|---|")
    for r in rows:
        print("| %d | `%s` | %s | %s | %s |" % r)
    print()
    print("Totals: " + ", ".join("%s %d" % (k, v) for k, v in sorted(tot.items())) + ", all %d" % len(rows))
    if missing:
        print("UNCLASSIFIED: " + " ".join(missing), file=sys.stderr)


if __name__ == "__main__":
    main()
