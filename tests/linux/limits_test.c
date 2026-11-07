// Resource limits (get/set/prlimit, checks, inheritance across fork and exec, NOFILE,
// FSIZE, NPROC, MEMLOCK enforcement, /proc/self/limits), nice and scheduling policies,
// CPU affinity, I/O priorities, mlock. Run as an unprivileged user.
// Build: gcc -O1 -w -o limits limits_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int in_child(int (*f)(void)) {
    pid_t c = fork();
    if (c == 0) _exit(f());
    int st;
    waitpid(c, &st, 0);
    int r = WIFEXITED(st) ? WEXITSTATUS(st) : 255;
    if (r) printf("  (child status %d)\n", r);
    return r;
}

static long status_kb(const char *key) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = -1;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, key, strlen(key))) v = atol(line + strlen(key));
    if (f) fclose(f);
    return v;
}

static int child_nofile(void) {
    struct rlimit r = {16, 16};
    if (setrlimit(RLIMIT_NOFILE, &r)) return 1;
    int fd, last = -1;
    while ((fd = open("/dev/null", O_RDONLY)) >= 0) last = fd;
    if (errno != EMFILE || last != 15) return 2;
    errno = 0;
    if (dup2(0, 20) != -1 || errno != EBADF) return 3;
    // Inherited across exec
    for (int i = 3; i < 10; i++) close(i);  // popen needs descriptors
    FILE *p = popen("ulimit -n", "r");
    char out[32] = "";
    if (!p) return 4;
    fgets(out, sizeof out, p);
    pclose(p);
    return atoi(out) == 16 ? 0 : 5;
}

static volatile int xfsz;
static void on_xfsz(int s) { xfsz++; }

static int child_fsize(void) {
    signal(SIGXFSZ, on_xfsz);
    char path[64];
    snprintf(path, sizeof path, "/tmp/fsize.%d.%ld", getpid(), (long)time(NULL));
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    struct rlimit r = {100, 100};
    setrlimit(RLIMIT_FSIZE, &r);
    char buf[150];
    memset(buf, 'x', sizeof buf);
    ssize_t n = write(fd, buf, 150);
    errno = 0;
    ssize_t m = write(fd, buf, 10);
    int e = errno;
    ssize_t p = pwrite(fd, buf, 10, 50);
    unlink(path);
    if (n != 100) return 1;
    if (m != -1 || e != EFBIG) return 2;
    if (!xfsz) return 3;
    return p == 10 ? 0 : 4;
}

static int child_nproc(void) {
    struct rlimit r = {1, 1};
    if (setrlimit(RLIMIT_NPROC, &r)) return 1;
    errno = 0;
    pid_t c = fork();
    if (c == 0) _exit(0);
    if (c > 0) {
        waitpid(c, NULL, 0);
        return 2;
    }
    return errno == EAGAIN ? 0 : 3;
}

static int child_raise_nice(void) {
    if (setpriority(PRIO_PROCESS, 0, 5)) return 1;
    errno = 0;
    if (getpriority(PRIO_PROCESS, 0) != 5) return 2;
    // A child inherits it
    pid_t c = fork();
    if (c == 0) _exit(getpriority(PRIO_PROCESS, 0) == 5 ? 0 : 1);
    int st;
    waitpid(c, &st, 0);
    if (WEXITSTATUS(st)) return 3;
    // /proc/self/stat: priority 25, nice 5 (fields 18 and 19)
    FILE *f = fopen("/proc/self/stat", "r");
    char line[512];
    fgets(line, sizeof line, f);
    fclose(f);
    char *s = strrchr(line, ')') + 2;
    int field = 3, prio = 0, nice = 0;
    for (char *t = strtok(s, " "); t; t = strtok(NULL, " "), field++) {
        if (field == 18) prio = atoi(t);
        if (field == 19) nice = atoi(t);
    }
    if (prio != 25 || nice != 5) return 4;
    errno = 0;
    if (setpriority(PRIO_PROCESS, 0, 0) != -1 || errno != EACCES) return 5;
    return 0;
}

static int child_idle(void) {
    struct sched_param p = {0};
    if (sched_setscheduler(0, SCHED_IDLE, &p)) return 1;
    return sched_getscheduler(0) == SCHED_IDLE ? 0 : 2;
}

static int child_prlimit_parent(void) {
    struct rlimit r;
    if (prlimit(getppid(), RLIMIT_CORE, NULL, &r)) return 1;
    return r.rlim_cur == 4096 ? 0 : 2;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (geteuid() == 0) {
        printf("run as an unprivileged user\n");
        return 1;
    }
    struct rlimit r, o;

    // Limits
    check(getrlimit(RLIMIT_STACK, &r) == 0 && r.rlim_cur > 0, "getrlimit");
    getrlimit(RLIMIT_CORE, &o);
    r.rlim_cur = 4096;
    r.rlim_max = o.rlim_max;
    check(setrlimit(RLIMIT_CORE, &r) == 0 && getrlimit(RLIMIT_CORE, &r) == 0 && r.rlim_cur == 4096, "setrlimit is kept");
    struct rlimit bad = {200, 100};
    errno = 0;
    check(setrlimit(RLIMIT_CORE, &bad) == -1 && errno == EINVAL, "soft above hard: EINVAL");
    errno = 0;
    check(getrlimit(99, &r) == -1 && errno == EINVAL, "unknown resource: EINVAL");
    getrlimit(RLIMIT_MSGQUEUE, &o);
    struct rlimit lower = {o.rlim_cur / 2, o.rlim_cur / 2};
    check(setrlimit(RLIMIT_MSGQUEUE, &lower) == 0, "lowering a hard limit");
    errno = 0;
    check(setrlimit(RLIMIT_MSGQUEUE, &o) == -1 && errno == EPERM, "raising it again: EPERM");
    struct rlimit got;
    check(prlimit(0, RLIMIT_CORE, NULL, &got) == 0 && got.rlim_cur == 4096, "prlimit reads ours");
    check(in_child(child_prlimit_parent) == 0, "prlimit reads another process's");
    // prlimit sets a child's limit
    int pp[2];
    pipe(pp);
    pid_t c = fork();
    if (c == 0) {
        char x;
        read(pp[0], &x, 1);
        struct rlimit q;
        getrlimit(RLIMIT_CORE, &q);
        _exit(q.rlim_cur == 1234 ? 0 : 1);
    }
    struct rlimit nl = {1234, got.rlim_max}, old;
    check(prlimit(c, RLIMIT_CORE, &nl, &old) == 0 && old.rlim_cur == 4096, "prlimit sets a child's, returns the old");
    write(pp[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child sees it");
    errno = 0;
    int pr = prlimit(1, RLIMIT_CORE, &nl, NULL), pe = errno;
    // (Hydra's PID 1 is the kernel's idle task, not a Linux process: ESRCH there)
    int no_init = kill(1, 0) == -1 && errno == ESRCH;
    check(pr == -1 && (pe == EPERM || (no_init && pe == ESRCH)), "another user's process: EPERM");
    check(in_child(child_nofile) == 0, "RLIMIT_NOFILE: EMFILE at the limit, dup2 past it EBADF, kept across exec");
    check(in_child(child_fsize) == 0, "RLIMIT_FSIZE: write cut short, then EFBIG and SIGXFSZ");
    check(in_child(child_nproc) == 0, "RLIMIT_NPROC: fork fails with EAGAIN");
    FILE *f = fopen("/proc/self/limits", "r");
    char line[256];
    int seen = 0;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "Max core file size", 18) && strstr(line, "4096")) seen = 1;
    if (f) fclose(f);
    check(seen, "/proc/self/limits shows them");

    // Priorities and policies
    errno = 0;
    check(getpriority(PRIO_PROCESS, 0) == 0 && errno == 0, "getpriority: nice 0");
    check(in_child(child_raise_nice) == 0, "setpriority raises nice; inherited; in /proc/self/stat; lowering it: EACCES");
    struct sched_param sp = {0};
    check(sched_getscheduler(0) == SCHED_OTHER, "sched_getscheduler: SCHED_OTHER");
    check(sched_setscheduler(0, SCHED_BATCH, &sp) == 0 && sched_getscheduler(0) == SCHED_BATCH, "SCHED_BATCH is kept");
    check(sched_setscheduler(0, SCHED_OTHER, &sp) == 0, "back to SCHED_OTHER");
    sp.sched_priority = 10;
    errno = 0;
    check(sched_setscheduler(0, SCHED_FIFO, &sp) == -1 && errno == EPERM, "SCHED_FIFO unprivileged: EPERM");
    errno = 0;
    check(sched_setparam(0, &sp) == -1 && errno == EINVAL, "priority 10 for SCHED_OTHER: EINVAL");
    sp.sched_priority = 7;
    check(sched_getparam(0, &sp) == 0 && sp.sched_priority == 0, "sched_getparam: 0");
    check(in_child(child_idle) == 0, "SCHED_IDLE");

    // Affinity
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    check(sched_setaffinity(0, sizeof set, &set) == 0, "affinity to CPU 0");
    CPU_ZERO(&set);
    CPU_SET(1023, &set);
    errno = 0;
    check(sched_setaffinity(0, sizeof set, &set) == -1 && errno == EINVAL, "no available CPU: EINVAL");
    CPU_ZERO(&set);
    check(sched_getaffinity(0, sizeof set, &set) == 0 && CPU_ISSET(0, &set), "sched_getaffinity");

    // I/O priorities
    int be3 = (2 << 13) | 3;
    check(syscall(SYS_ioprio_set, 1, 0, be3) == 0 && syscall(SYS_ioprio_get, 1, 0) == be3, "ioprio best-effort 3 is kept");
    errno = 0;
    check(syscall(SYS_ioprio_set, 1, 0, (2 << 13) | 8) == -1 && errno == EINVAL, "level 8: EINVAL");
    errno = 0;
    check(syscall(SYS_ioprio_set, 1, 0, (1 << 13) | 0) == -1 && errno == EPERM, "real-time class unprivileged: EPERM");

    // mlock
    struct rlimit ml = {8192, 8192};
    setrlimit(RLIMIT_MEMLOCK, &ml);
    char *m = mmap(NULL, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(mlock(m, 4096) == 0 && status_kb("VmLck:") == 4, "mlock: VmLck 4 kB");
    errno = 0;
    check(mlock(m, 4 * 4096) == -1 && errno == ENOMEM, "past RLIMIT_MEMLOCK: ENOMEM");
    check(munlock(m, 4096) == 0 && status_kb("VmLck:") == 0, "munlock");
    munmap(m + 2 * 4096, 4096);
    errno = 0;
    check(mlock(m + 2 * 4096, 4096) == -1 && errno == ENOMEM, "an unmapped range: ENOMEM");
    errno = 0;
    check(mlockall(0) == -1 && errno == EINVAL, "mlockall(0): EINVAL");
    errno = 0;
    check(syscall(SYS_mlock2, m, 4096, 2) == -1 && errno == EINVAL, "mlock2 unknown flag: EINVAL");
    check(syscall(SYS_mlock2, m, 4096, 1) == 0 && munlockall() == 0 && status_kb("VmLck:") == 0, "mlock2 MLOCK_ONFAULT, munlockall");

    printf(fails ? "LIMITS TEST FAILED (%d)\n" : "LIMITS TEST PASSED\n", fails);
    return fails != 0;
}
