// ptperm: who may trace and observe whom (wave 10, Group 8-1: the ptrace / perf policy in
// lx-proc). Run as root; each case runs in a child that drops to the ids it needs.
//
//   ptperm            permission matrix (ptrace attach/seize/traceme, process_vm_readv,
//                     kcmp, pidfd_getfd, perf_event_open) and the dumpable rules
//   ptperm bench N    timings: PTRACE_ATTACH, PTRACE_DETACH, PEEKDATA, GETREGS,
//                     perf_event_open+close (microseconds per call, medians of 5 rounds)
//   ptperm crash      dereferences NULL (for gdb -batch -ex run -ex bt)
//   ptperm step S     attach to a child and single-step it for S seconds (kill tests):
//                     prints steps every second, "STEP FAIL" on any error, "STEP PASS" at end
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef PTRACE_O_SUSPEND_SECCOMP
#define PTRACE_O_SUSPEND_SECCOMP (1 << 21)
#endif

static int fails;
#define CHECK(c, ...)                                                       \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("     FAIL: ");                                          \
            printf(__VA_ARGS__);                                            \
            printf(" (line %d)\n", __LINE__);                               \
            fails++;                                                        \
        }                                                                   \
    } while (0)

static volatile uint64_t magic = 0x5eed1234abcd5678ull;

static void in_child(const char *name, void (*f)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        fails = 0;
        f();
        fflush(stdout);
        _exit(fails ? 1 : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAIL %s (status %#x)\n", name, st);
        fails++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void become(uid_t u) {
    if (setresgid(u, u, u) || setresuid(u, u, u)) {
        printf("     cannot become %u: %s\n", u, strerror(errno));
        _exit(3);
    }
}

// A target: a child of the caller with ids `uid` (-1: keep), dumpable set to `dump` after
// that (-1: leave it), waiting until `release`.
struct target {
    pid_t pid;
    int hold;
    int dump_after_ids; // PR_GET_DUMPABLE right after the id change
};

static struct target spawn(int uid, int dump) {
    int ready[2], hold[2];
    struct target t = {0};
    if (pipe(ready) || pipe(hold)) exit(4);
    t.pid = fork();
    if (t.pid == 0) {
        close(ready[0]);
        close(hold[1]);
        int d = prctl(PR_GET_DUMPABLE);
        if (uid >= 0) {
            become(uid);
            d = prctl(PR_GET_DUMPABLE);
        }
        if (dump >= 0) prctl(PR_SET_DUMPABLE, dump);
        char c = (char)d;
        if (write(ready[1], &c, 1) != 1) _exit(5);
        while (read(hold[0], &c, 1) > 0) {
        }
        _exit(0);
    }
    close(ready[1]);
    close(hold[0]);
    char c = 0;
    if (read(ready[0], &c, 1) != 1) exit(6);
    close(ready[0]);
    t.hold = hold[1];
    t.dump_after_ids = c;
    return t;
}

static void release(struct target *t) {
    close(t->hold);
    kill(t->pid, SIGKILL); // (allowed only when we may; waitpid reaps in any case)
    waitpid(t->pid, NULL, __WALL);
}

// ptrace(ATTACH): 0 and a PEEKDATA that reads `magic`, or -errno
static int try_attach(pid_t p) {
    if (ptrace(PTRACE_ATTACH, p, 0, 0) != 0) return -errno;
    int st = 0;
    waitpid(p, &st, __WALL);
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, p, (void *)&magic, 0);
    int ok = errno == 0 && (uint64_t)v == (uint64_t)magic;
    struct user_regs_struct r;
    int regs = ptrace(PTRACE_GETREGS, p, 0, &r) == 0;
    ptrace(PTRACE_DETACH, p, 0, 0);
    return ok && regs ? 0 : -1000;
}

static int try_vm(pid_t p) {
    uint64_t v = 0;
    struct iovec l = {&v, 8}, r = {(void *)&magic, 8};
    long n = syscall(SYS_process_vm_readv, p, &l, 1, &r, 1, 0);
    if (n < 0) return -errno;
    return v == magic ? 0 : -1000;
}

static int try_kcmp(pid_t p) {
    long r = syscall(SYS_kcmp, getpid(), p, KCMP_VM, 0, 0);
    return r < 0 ? -errno : 0;
}

static int try_getfd(pid_t p) {
    int pfd = syscall(SYS_pidfd_open, p, 0);
    if (pfd < 0) return -1000 - errno;
    int fd = syscall(SYS_pidfd_getfd, pfd, 0, 0);
    int e = errno;
    close(pfd);
    if (fd < 0) return -e;
    close(fd);
    return 0;
}

static int perf_open(pid_t p, int cpu, int kernel) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.type = PERF_TYPE_SOFTWARE;
    a.config = PERF_COUNT_SW_TASK_CLOCK;
    a.disabled = 1;
    a.exclude_kernel = !kernel;
    a.exclude_hv = 1;
    int fd = syscall(SYS_perf_event_open, &a, p, cpu, -1, 0);
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

// /proc/<pid>/<file> read: 0 when some bytes came, else -errno (EOF: -1000)
static int try_proc(pid_t p, const char *file) {
    char path[64], buf[256];
    snprintf(path, sizeof path, "/proc/%d/%s", p, file);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    long n = read(fd, buf, sizeof buf);
    int e = errno;
    close(fd);
    return n > 0 ? 0 : n == 0 ? -1000 : -e;
}

static int try_perf(pid_t p) {
    return perf_open(p, -1, 0);
}

// ---- cases ----

static void t_same_user(void) {
    struct target t = spawn(1000, 1);
    CHECK(t.dump_after_ids == 0, "dumpable after setresuid(1000): %d (want 0)", t.dump_after_ids);
    become(1000);
    CHECK(try_attach(t.pid) == 0, "attach to own uid: %d", try_attach(t.pid));
    CHECK(try_vm(t.pid) == 0, "process_vm_readv own uid: %d", try_vm(t.pid));
    CHECK(try_kcmp(t.pid) == 0, "kcmp own uid: %d", try_kcmp(t.pid));
    CHECK(try_getfd(t.pid) == 0, "pidfd_getfd own uid: %d", try_getfd(t.pid));
    CHECK(try_perf(t.pid) == 0, "perf_event_open own uid: %d", try_perf(t.pid));
    CHECK(try_proc(t.pid, "maps") == 0, "/proc maps own uid: %d", try_proc(t.pid, "maps"));
    // (environ: ENOENT where /proc does not serve it yet: before 7b-2)
    CHECK(try_proc(t.pid, "environ") == 0 || try_proc(t.pid, "environ") == -1000 || try_proc(t.pid, "environ") == -ENOENT, "/proc environ own uid: %d", try_proc(t.pid, "environ"));
    release(&t);
}

static void t_other_user(void) {
    struct target t = spawn(1001, 1);
    become(1000);
    CHECK(try_attach(t.pid) == -EPERM, "attach to another user: %d", try_attach(t.pid));
    CHECK(try_vm(t.pid) == -EPERM, "process_vm_readv another user: %d", try_vm(t.pid));
    CHECK(try_kcmp(t.pid) == -EPERM, "kcmp another user: %d", try_kcmp(t.pid));
    CHECK(try_getfd(t.pid) == -EPERM, "pidfd_getfd another user: %d", try_getfd(t.pid));
    CHECK(try_perf(t.pid) == -EACCES, "perf_event_open another user: %d", try_perf(t.pid));
    release(&t);
}

static void t_not_dumpable(void) {
    struct target t = spawn(1000, 0);
    become(1000);
    CHECK(try_attach(t.pid) == -EPERM, "attach to a non-dumpable process: %d", try_attach(t.pid));
    CHECK(try_vm(t.pid) == -EPERM, "process_vm_readv non-dumpable: %d", try_vm(t.pid));
    CHECK(try_getfd(t.pid) == -EPERM, "pidfd_getfd non-dumpable: %d", try_getfd(t.pid));
    CHECK(try_perf(t.pid) == -EACCES, "perf_event_open non-dumpable: %d", try_perf(t.pid));
    release(&t);
}

static void t_setuid_running(void) {
    // A process that changed its ids (no PR_SET_DUMPABLE after): not dumpable, so its new
    // user cannot attach (Linux's commit_creds)
    struct target t = spawn(1000, -1);
    CHECK(t.dump_after_ids == 0, "dumpable after setresuid: %d", t.dump_after_ids);
    become(1000);
    CHECK(try_attach(t.pid) == -EPERM, "attach after the target's setuid: %d", try_attach(t.pid));
    release(&t);
}

static void t_setuid_same(void) {
    // seteuid alone clears it too; setting the same ids again changes nothing (run as root)
    pid_t p = fork();
    if (p == 0) {
        int a = prctl(PR_GET_DUMPABLE);
        setresuid(0, 0, 0);
        int b = prctl(PR_GET_DUMPABLE);
        if (seteuid(1000)) _exit(9);
        int c = prctl(PR_GET_DUMPABLE);
        _exit((a == 1 && b == 1 && c == 0) ? 0 : 10 + a * 4 + b * 2 + c);
    }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "dumpable over setresuid(same)/seteuid: status %#x", st);
}

static void t_root(void) {
    struct target t = spawn(1001, 0);
    CHECK(try_attach(t.pid) == 0, "root attaches to another user's non-dumpable process: %d", try_attach(t.pid));
    CHECK(try_vm(t.pid) == 0, "root process_vm_readv: %d", try_vm(t.pid));
    CHECK(try_kcmp(t.pid) == 0, "root kcmp: %d", try_kcmp(t.pid));
    CHECK(try_getfd(t.pid) == 0, "root pidfd_getfd: %d", try_getfd(t.pid));
    CHECK(try_perf(t.pid) == 0, "root perf_event_open: %d", try_perf(t.pid));
    release(&t);
}

static const char *self_path;

static void t_setuid_exec(void) {
    // A copy of this program, set-user-ID root; run by user 1000 it reports its euid and
    // dumpable flag and waits: user 1000 must not attach to it
    const char *suid = "/tmp/ptperm_suid";
    char cmd[512];
    snprintf(cmd, sizeof cmd, "cp %s %s && chown 0:0 %s && chmod 4755 %s", self_path, suid, suid, suid);
    CHECK(system(cmd) == 0, "set up %s", suid);
    int ready[2], hold[2];
    if (pipe(ready) || pipe(hold)) exit(4);
    pid_t p = fork();
    if (p == 0) {
        become(1000);
        dup2(ready[1], 10);
        dup2(hold[0], 11);
        close(ready[0]);
        close(ready[1]);
        close(hold[0]);
        close(hold[1]);
        execl(suid, suid, "suidwait", NULL);
        _exit(7);
    }
    close(ready[1]);
    close(hold[0]);
    int euid = -1;
    if (read(ready[0], &euid, sizeof euid) != sizeof euid) euid = -2;
    CHECK(euid == 0 || euid == 1000, "set-user-ID program: euid %d (101: still dumpable)", euid);
    if (euid == 1000) {
        printf("     (set-ID bit not honoured here; case skipped)\n");
    } else if (euid == 0) {
        pid_t q = fork();
        if (q == 0) {
            become(1000);
            int r = try_attach(p);
            _exit(r == -EPERM ? 0 : 1);
        }
        int st = 0;
        waitpid(q, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "user attached to its set-user-ID program (status %#x)", st);
    }
    close(hold[1]);
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    unlink(suid);
}

static int suidwait(void) {
    int e = geteuid();
    int d = prctl(PR_GET_DUMPABLE);
    if (e == 0 && d != 0) e = 100 + d; // (reported as a failure: a set-ID exec must clear it)
    if (write(10, &e, sizeof e) != sizeof e) return 1;
    char c;
    while (read(11, &c, 1) > 0) {
    }
    return 0;
}

// Review 10-81 finding 1: a sandbox in a child user namespace (same kuid) may not attach to
// or write into its parent; the parent's process is in another user namespace
static void t_userns_sandbox(void) {
    become(1000);
    prctl(PR_SET_DUMPABLE, 1);
    pid_t parent = getpid();
    pid_t p = fork();
    if (p == 0) {
        if (unshare(CLONE_NEWUSER) != 0) {
            printf("     (unshare(CLONE_NEWUSER): %s; case skipped)\n", strerror(errno));
            _exit(0);
        }
        int a = try_attach(parent);
        uint64_t v = magic;
        struct iovec l = {&v, 8}, r = {(void *)&magic, 8};
        long n = syscall(SYS_process_vm_writev, parent, &l, 1, &r, 1, 0);
        int w = n < 0 ? -errno : 0;
        int m = try_proc(parent, "maps"), e = try_proc(parent, "environ");
        _exit((a == -EPERM ? 0 : 1) | (w == -EPERM ? 0 : 2) | (m != 0 ? 0 : 4) | (e != 0 ? 0 : 8));
    }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "sandbox in a child user namespace reached its parent (attach bit 1, process_vm_writev bit 2, maps 4, environ 8: status %#x)", st);
}

// Review 10-81 finding 1: a same-uid process holding file capabilities (dumpable again) is
// not attachable by one without them
static void t_file_caps(void) {
    const char *capf = "/tmp/ptperm_cap";
    char cmd[512];
    snprintf(cmd, sizeof cmd, "cp %s %s && chown 0:0 %s && chmod 755 %s", self_path, capf, capf, capf);
    CHECK(system(cmd) == 0, "set up %s", capf);
    // security.capability v2: effective, permitted CAP_NET_RAW (13)
    uint32_t xc[5] = {0x02000001, 1u << 13, 0, 0, 0};
    if (setxattr(capf, "security.capability", xc, sizeof xc, 0) != 0) {
        printf("     (setxattr security.capability: %s; case skipped)\n", strerror(errno));
        unlink(capf);
        return;
    }
    int ready[2], hold[2];
    if (pipe(ready) || pipe(hold)) exit(4);
    pid_t p = fork();
    if (p == 0) {
        become(1000);
        dup2(ready[1], 10);
        dup2(hold[0], 11);
        close(ready[0]);
        close(ready[1]);
        close(hold[0]);
        close(hold[1]);
        execl(capf, capf, "capwait", NULL);
        _exit(7);
    }
    close(ready[1]);
    close(hold[0]);
    int prm = -1;
    if (read(ready[0], &prm, sizeof prm) != sizeof prm) prm = -2;
    if (prm == 0) {
        printf("     (file capabilities not granted here; case skipped)\n");
    } else {
        CHECK(prm > 0, "capability program: %d", prm);
        pid_t q = fork();
        if (q == 0) {
            become(1000);
            int r = try_attach(p);
            int v = try_vm(p);
            int m = try_proc(p, "maps"), e = try_proc(p, "environ");
            _exit((r == -EPERM ? 0 : 1) | (v == -EPERM ? 0 : 2) | (m != 0 ? 0 : 4) | (e != 0 ? 0 : 8));
        }
        int st = 0;
        waitpid(q, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a capability-less user reached its capable process (attach bit 1, process_vm_readv bit 2, maps 4, environ 8: status %#x)", st);
    }
    close(hold[1]);
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    unlink(capf);
}

static int capwait(void) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    memset(d, 0, sizeof d);
    int prm = syscall(SYS_capget, &h, d) == 0 ? (int)d[0].permitted : -3;
    // dumpable again, as a program may make itself
    prctl(PR_SET_DUMPABLE, 1);
    if (write(10, &prm, sizeof prm) != sizeof prm) return 1;
    char c;
    while (read(11, &c, 1) > 0) {
    }
    return 0;
}

static void t_perf_paranoid(void) {
    become(1000);
    CHECK(perf_open(0, -1, 0) == 0, "perf self, user only: %d", perf_open(0, -1, 0));
    CHECK(perf_open(0, -1, 1) == -EACCES, "perf self counting kernel mode unprivileged: %d", perf_open(0, -1, 1));
    CHECK(perf_open(-1, 0, 0) == -EACCES, "perf whole CPU unprivileged: %d", perf_open(-1, 0, 0));
    CHECK(perf_open(0, 5, 0) == -EINVAL, "perf cpu 5: %d", perf_open(0, 5, 0));
    CHECK(perf_open(-1, -1, 0) == -EINVAL, "perf pid -1 cpu -1: %d", perf_open(-1, -1, 0));
    CHECK(perf_open(999999, -1, 0) == -ESRCH, "perf no such pid: %d", perf_open(999999, -1, 0));
}

static void t_perf_root(void) {
    CHECK(perf_open(0, -1, 1) == 0, "root perf counting kernel mode: %d", perf_open(0, -1, 1));
    CHECK(perf_open(-1, 0, 0) == 0, "root perf whole CPU: %d", perf_open(-1, 0, 0));
}

static void seize_suspend(int expect) {
    struct target t = spawn(-1, -1);
    long r = ptrace(PTRACE_SEIZE, t.pid, 0, (void *)(long)PTRACE_O_SUSPEND_SECCOMP);
    int e = r < 0 ? -errno : 0;
    CHECK(e == expect, "SEIZE with O_SUSPEND_SECCOMP: %d (want %d)", e, expect);
    if (r == 0) {
        // (a seized tracee that never stopped: start over with a fresh one)
        release(&t);
        t = spawn(-1, -1);
    }
    // A plain attach, then SETOPTIONS asking for it
    if (ptrace(PTRACE_ATTACH, t.pid, 0, 0) == 0) {
        waitpid(t.pid, NULL, __WALL);
        r = ptrace(PTRACE_SETOPTIONS, t.pid, 0, (void *)(long)PTRACE_O_SUSPEND_SECCOMP);
        e = r < 0 ? -errno : 0;
        CHECK(e == expect, "SETOPTIONS O_SUSPEND_SECCOMP: %d (want %d)", e, expect);
        r = ptrace(PTRACE_SETOPTIONS, t.pid, 0, (void *)(long)PTRACE_O_TRACESYSGOOD);
        CHECK(r == 0, "SETOPTIONS TRACESYSGOOD: %s", strerror(errno));
        ptrace(PTRACE_DETACH, t.pid, 0, 0);
    } else {
        CHECK(0, "attach to own child: %s", strerror(errno));
    }
    release(&t);
}

static void t_suspend_user(void) {
    become(1000);
    prctl(PR_SET_DUMPABLE, 1);
    seize_suspend(-EPERM);
}

static void t_suspend_root(void) {
    seize_suspend(0);
}

static void t_traceme(void) {
    become(1000);
    prctl(PR_SET_DUMPABLE, 1);
    pid_t p = fork();
    if (p == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(20);
        raise(SIGSTOP);
        _exit(magic == 0x5eed1234abcd5678ull ? 0 : 21);
    }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK(WIFSTOPPED(st), "TRACEME child did not stop: %#x", st);
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, p, (void *)&magic, 0);
    CHECK(errno == 0 && (uint64_t)v == magic, "PEEKDATA of TRACEME child: %s", strerror(errno));
    ptrace(PTRACE_CONT, p, 0, 0);
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "TRACEME child exit %#x", st);
}

static void t_self(void) {
    // own process: attach refused (EPERM), the rest allowed
    CHECK(ptrace(PTRACE_ATTACH, getpid(), 0, 0) == -1 && errno == EPERM, "attach to self: %s", strerror(errno));
    CHECK(try_vm(getpid()) == 0, "process_vm_readv self");
    CHECK(syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0) == 0, "kcmp self");
}

// ---- timings ----

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

// Where a decided call's time goes: a cold or warm attach, a kcmp after an identity-epoch
// bump (any ptrace call), a kcmp after a pause (the service's worker gone idle)
static int probe(int n) {
    double a1 = 0, a2 = 0, k0 = 0, k1 = 0, k2 = 0, n0 = 0, n1 = 0;
    for (int i = 0; i < n; i++) {
        struct target t = spawn(-1, -1);
        double t0 = now_us();
        long r = ptrace(PTRACE_ATTACH, t.pid, 0, 0);
        a1 += now_us() - t0;
        if (r != 0) return 1;
        waitpid(t.pid, NULL, __WALL);
        ptrace(PTRACE_DETACH, t.pid, 0, 0);
        release(&t);
        t = spawn(-1, -1);
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0);
        t0 = now_us();
        r = ptrace(PTRACE_ATTACH, t.pid, 0, 0);
        a2 += now_us() - t0;
        if (r != 0) return 1;
        waitpid(t.pid, NULL, __WALL);
        ptrace(PTRACE_DETACH, t.pid, 0, 0);
        release(&t);
        // kcmp: hot, after an epoch bump, after a pause
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0);
        t0 = now_us();
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0);
        k0 += now_us() - t0;
        ptrace(PTRACE_PEEKDATA, 1, 0, 0);
        t0 = now_us();
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0);
        k1 += now_us() - t0;
        usleep(2000);
        t0 = now_us();
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_VM, 0, 0);
        k2 += now_us() - t0;
        // Hydra's null call to linux-server (0x6710): hot, and after a pause
        syscall(0x6710);
        t0 = now_us();
        syscall(0x6710);
        n0 += now_us() - t0;
        usleep(2000);
        t0 = now_us();
        syscall(0x6710);
        n1 += now_us() - t0;
    }
    printf("ptperm probe: attach %.2f attach-after-kcmp %.2f kcmp-hot %.2f kcmp-after-epoch %.2f kcmp-after-pause %.2f lx_null-hot %.2f lx_null-after-pause %.2f us\n", a1 / n, a2 / n, k0 / n, k1 / n, k2 / n, n0 / n, n1 / n);
    return 0;
}

static int bench(int n) {
    double att[5], det[5], peek[5], regs[5], perf[5], kc[5], vm[5];
    for (int round = 0; round < 5; round++) {
        double a = 0, d = 0;
        // A fresh target for every attach (one just detached is untraced only once it ran)
        for (int i = 0; i < n; i++) {
            struct target t = spawn(-1, -1);
            double t0 = now_us();
            long r = ptrace(PTRACE_ATTACH, t.pid, 0, 0);
            double t1 = now_us();
            if (r != 0) {
                printf("attach: %s\n", strerror(errno));
                return 1;
            }
            waitpid(t.pid, NULL, __WALL);
            double t2 = now_us();
            ptrace(PTRACE_DETACH, t.pid, 0, 0);
            double t3 = now_us();
            a += t1 - t0;
            d += t3 - t2;
            release(&t);
        }
        att[round] = a / n;
        det[round] = d / n;
        struct target t = spawn(-1, -1);
        if (ptrace(PTRACE_ATTACH, t.pid, 0, 0) != 0) {
            printf("attach: %s\n", strerror(errno));
            return 1;
        }
        waitpid(t.pid, NULL, __WALL);
        double t0 = now_us();
        for (int i = 0; i < n * 10; i++) ptrace(PTRACE_PEEKDATA, t.pid, (void *)&magic, 0);
        double t1 = now_us();
        struct user_regs_struct r;
        for (int i = 0; i < n * 10; i++) ptrace(PTRACE_GETREGS, t.pid, 0, &r);
        double t2 = now_us();
        ptrace(PTRACE_DETACH, t.pid, 0, 0);
        release(&t);
        peek[round] = (t1 - t0) / (n * 10);
        regs[round] = (t2 - t1) / (n * 10);
        t0 = now_us();
        for (int i = 0; i < n; i++) perf_open(0, -1, 0);
        perf[round] = (now_us() - t0) / n;
        // kcmp and process_vm_readv on a live child: the decision alone (no signals)
        struct target u = spawn(-1, -1);
        t0 = now_us();
        for (int i = 0; i < n * 10; i++) syscall(SYS_kcmp, getpid(), u.pid, KCMP_VM, 0, 0);
        t1 = now_us();
        for (int i = 0; i < n * 10; i++) try_vm(u.pid);
        t2 = now_us();
        kc[round] = (t1 - t0) / (n * 10);
        vm[round] = (t2 - t1) / (n * 10);
        release(&u);
    }
    qsort(att, 5, sizeof(double), cmp_d);
    qsort(det, 5, sizeof(double), cmp_d);
    qsort(peek, 5, sizeof(double), cmp_d);
    qsort(regs, 5, sizeof(double), cmp_d);
    qsort(perf, 5, sizeof(double), cmp_d);
    qsort(kc, 5, sizeof(double), cmp_d);
    qsort(vm, 5, sizeof(double), cmp_d);
    printf("ptperm bench: attach %.2f detach %.2f peekdata %.2f getregs %.2f perf_open+close %.2f kcmp %.2f process_vm_readv %.2f us\n", att[2], det[2], peek[2], regs[2], perf[2], kc[2], vm[2]);
    return 0;
}

// ---- stepping (kill tests) ----

static int step(int secs) {
    pid_t p = fork();
    if (p == 0) {
        volatile uint64_t x = 0;
        for (;;) x++;
    }
    if (ptrace(PTRACE_ATTACH, p, 0, 0) != 0) {
        printf("STEP FAIL attach: %s\n", strerror(errno));
        return 1;
    }
    waitpid(p, NULL, __WALL);
    long steps = 0, bad = 0;
    double end = now_us() + secs * 1e6, next = now_us() + 1e6;
    while (now_us() < end) {
        if (ptrace(PTRACE_SINGLESTEP, p, 0, 0) != 0) bad++;
        int st = 0;
        if (waitpid(p, &st, __WALL) != p || !WIFSTOPPED(st)) bad++;
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, p, 0, &r) != 0) bad++;
        errno = 0;
        ptrace(PTRACE_PEEKDATA, p, (void *)&magic, 0);
        if (errno) bad++;
        steps++;
        if (now_us() > next) {
            printf("steps %ld errors %ld\n", steps, bad);
            next += 1e6;
            // a fresh attach every second too (that decision goes to lx-proc)
            pid_t q = fork();
            if (q == 0) {
                pause();
                _exit(0);
            }
            if (ptrace(PTRACE_ATTACH, q, 0, 0) != 0) {
                printf("re-attach: %s\n", strerror(errno));
                bad++;
            } else {
                waitpid(q, NULL, __WALL);
                ptrace(PTRACE_DETACH, q, 0, 0);
            }
            kill(q, SIGKILL);
            waitpid(q, NULL, 0);
        }
    }
    ptrace(PTRACE_DETACH, p, 0, 0);
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
    printf(bad ? "STEP FAIL (%ld errors in %ld steps)\n" : "STEP PASS (%ld errors in %ld steps)\n", bad, steps);
    return bad != 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    self_path = argv[0][0] == '/' ? argv[0] : realpath(argv[0], NULL);
    if (argc > 1 && !strcmp(argv[1], "suidwait")) return suidwait();
    if (argc > 1 && !strcmp(argv[1], "capwait")) return capwait();
    if (argc > 1 && !strcmp(argv[1], "crash")) {
        // (for gdb -batch -ex run -ex bt)
        volatile int *p = (int *)(uintptr_t)(argc - 2);
        return *p;
    }
    if (argc > 2 && !strcmp(argv[1], "bench")) return bench(atoi(argv[2]));
    if (argc > 2 && !strcmp(argv[1], "probe")) return probe(atoi(argv[2]));
    if (argc > 2 && !strcmp(argv[1], "step")) return step(atoi(argv[2]));
    if (geteuid() != 0) {
        printf("ptperm: run as root\n");
        return 2;
    }
    alarm(240);
    in_child("same user", t_same_user);
    in_child("another user", t_other_user);
    in_child("not dumpable", t_not_dumpable);
    in_child("setuid while running", t_setuid_running);
    in_child("setuid to the same ids, seteuid", t_setuid_same);
    in_child("root", t_root);
    in_child("set-user-ID exec", t_setuid_exec);
    in_child("sandbox in a child user namespace", t_userns_sandbox);
    in_child("file capabilities", t_file_caps);
    in_child("perf paranoid (user)", t_perf_paranoid);
    in_child("perf (root)", t_perf_root);
    in_child("suspend seccomp (user)", t_suspend_user);
    in_child("suspend seccomp (root)", t_suspend_root);
    in_child("traceme", t_traceme);
    in_child("own process", t_self);
    printf(fails ? "ptperm FAIL (%d)\n" : "ptperm PASS\n", fails);
    return fails ? 1 : 0;
}

