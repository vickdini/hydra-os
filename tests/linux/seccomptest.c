// seccomp test: ERRNO / TRAP (SIGSYS siginfo + ucontext result) / argument matching /
// stacking / fork inheritance / TSYNC / strict mode / KILL_PROCESS / validation.
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); } while (0)

#define LD_NR BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define LD_ARCH BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch))
#define LD_ARG0 BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]))
#define RET(v) BPF_STMT(BPF_RET | BPF_K, (v))

static long install(struct sock_filter *f, unsigned short n, unsigned flags) {
    struct sock_fprog p = {n, f};
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &p);
}

static volatile int sig_nr, sig_code, sig_arch, sig_errno;
static void on_sigsys(int s, siginfo_t *si, void *ctx) {
    (void)s;
    sig_nr = si->si_syscall;
    sig_code = si->si_code;
    sig_arch = si->si_arch;
    sig_errno = si->si_errno;
    ((ucontext_t *)ctx)->uc_mcontext.gregs[REG_RAX] = 4242;
}

static volatile int go, thread_result;
static void *worker(void *a) {
    (void)a;
    while (!go) usleep(1000);
    long r = syscall(SYS_getpgrp);
    thread_result = r < 0 ? errno : 0;
    return 0;
}

static int child_sig(void (*fn)(void)) {
    pid_t c = fork();
    if (c == 0) { fn(); _exit(0); }
    int st = 0;
    waitpid(c, &st, 0);
    return WIFSIGNALED(st) ? WTERMSIG(st) : -WEXITSTATUS(st);
}
static void strict_child(void) {
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
    if (write(1, "", 0)) {}
    syscall(SYS_getpid);
}
static void kill_child(void) {
    struct sock_filter f[] = {LD_NR, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
                              RET(SECCOMP_RET_KILL_PROCESS), RET(SECCOMP_RET_ALLOW)};
    install(f, 4, 0);
    syscall(SYS_getpid);
}

int main(void) {
    CHECK(prctl(PR_GET_SECCOMP) == 0, "PR_GET_SECCOMP initially 0");
    CHECK(child_sig(strict_child) == SIGKILL, "strict mode kills on getpid");
    struct sock_filter allow[] = {RET(SECCOMP_RET_ALLOW)};
    errno = 0;
    if (getuid() != 0)
        CHECK(install(allow, 1, 0) == -1 && errno == EACCES, "filter without no_new_privs -> EACCES");
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "PR_SET_NO_NEW_PRIVS");
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "PR_GET_NO_NEW_PRIVS == 1");

    struct sock_filter bad[] = {BPF_JUMP(BPF_JMP | BPF_JA, 5, 0, 0), RET(SECCOMP_RET_ALLOW)};
    errno = 0;
    CHECK(install(bad, 2, 0) == -1 && errno == EINVAL, "out-of-range jump rejected");
    struct sock_filter misaligned[] = {BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 2), RET(SECCOMP_RET_ALLOW)};
    errno = 0;
    CHECK(install(misaligned, 2, 0) == -1 && errno == EINVAL, "misaligned load rejected");
    unsigned act = SECCOMP_RET_TRAP;
    CHECK(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &act) == 0, "TRAP action available");

    pthread_t th;
    pthread_create(&th, 0, worker, 0);

    struct sigaction sa = {0};
    sa.sa_sigaction = on_sigsys;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSYS, &sa, 0);

    struct sock_filter f1[] = {
        LD_ARCH,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        RET(SECCOMP_RET_KILL_PROCESS),
        LD_NR,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        RET(SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getuid, 0, 1),
        RET(SECCOMP_RET_TRAP | 0x42),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_dup, 0, 3),
        LD_ARG0,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 999, 0, 1),
        RET(SECCOMP_RET_ERRNO | 77),
        RET(SECCOMP_RET_ALLOW),
    };
    CHECK(install(f1, sizeof f1 / sizeof *f1, 0) == 0, "install filter");
    CHECK(prctl(PR_GET_SECCOMP) == 2, "PR_GET_SECCOMP == 2");

    errno = 0;
    CHECK(syscall(SYS_getppid) == -1 && errno == EPERM, "getppid -> EPERM (errno %d)", errno);
    long u = syscall(SYS_getuid);
    CHECK(u == 4242, "getuid trapped, handler result %ld", u);
    CHECK(sig_nr == SYS_getuid && sig_code == 1 && sig_arch == (int)AUDIT_ARCH_X86_64 && sig_errno == 0x42,
          "siginfo: syscall %d code %d arch %#x errno %#x", sig_nr, sig_code, sig_arch, sig_errno);
    errno = 0;
    CHECK(syscall(SYS_dup, 999) == -1 && errno == 77, "dup(999) -> errno 77 (%d)", errno);
    int d = dup(0);
    CHECK(d >= 0, "dup(0) allowed");
    close(d);

    struct sock_filter f2[] = {LD_NR, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
                               RET(SECCOMP_RET_ERRNO | EIO), RET(SECCOMP_RET_ALLOW)};
    CHECK(install(f2, 4, 0) == 0, "stack second filter");
    errno = 0;
    syscall(SYS_getppid);
    CHECK(errno == EIO, "newest filter wins ties (errno %d)", errno);

    pid_t c = fork();
    if (c == 0) {
        errno = 0;
        syscall(SYS_getppid);
        _exit(errno == EIO ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child inherits filters");

    struct sock_filter f3[] = {LD_NR, BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpgrp, 0, 1),
                               RET(SECCOMP_RET_ERRNO | EACCES), RET(SECCOMP_RET_ALLOW)};
    CHECK(install(f3, 4, SECCOMP_FILTER_FLAG_TSYNC) == 0, "TSYNC filter");
    go = 1;
    pthread_join(th, 0);
    CHECK(thread_result == EACCES, "other thread filtered by TSYNC (errno %d)", thread_result);

    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];
    int seen = 0;
    while (fp && fgets(line, sizeof line, fp))
        if (!strncmp(line, "Seccomp:", 8)) seen = atoi(line + 8);
    if (fp) fclose(fp);
    CHECK(seen == 2, "/proc/self/status Seccomp: %d", seen);

    CHECK(child_sig(kill_child) == SIGSYS, "KILL_PROCESS -> SIGSYS");

    printf(fails ? "SECCOMP TEST FAILED (%d)\n" : "SECCOMP TEST PASSED\n", fails);
    return fails != 0;
}
