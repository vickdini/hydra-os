// Hydra conformance test: interval timers, pidfds, clone3, process-shared futexes.
// Build (WSL): gcc -static-pie -O1 -pthread -o esp/bin/gapstest.elf scratch/gapstest.c
// Run in Hydra: linux run gapstest.elf
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <poll.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif
#define CLONE_PIDFD_FLAG 0x1000

struct clone_args_v0 {
    uint64_t flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls;
};

static int failures;
static void check(const char *name, int ok) {
    printf("[gapstest] %-56s %s\n", name, ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) failures++;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static volatile sig_atomic_t alrm, prof;
static void on_alrm(int s) { (void)s; alrm++; }
static void on_prof(int s) { (void)s; prof++; }

static long futex(uint32_t *a, int op, uint32_t v) { return syscall(SYS_futex, a, op, v, NULL, NULL, 0); }

static void timer_tests(void) {
    signal(SIGALRM, on_alrm);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    check("alarm(1) returns 0 when none was pending", alarm(1) == 0);
    pause();
    long el = ms_since(&t0);
    check("SIGALRM arrives after about one second", alrm == 1 && el >= 900 && el < 3000);

    alarm(10);
    unsigned left = alarm(0);
    check("alarm returns the seconds left on the previous alarm", left >= 9 && left <= 10);

    alrm = 0;
    struct itimerval it = {{0, 100000}, {0, 100000}};
    check("setitimer(ITIMER_REAL) periodic 100 ms", setitimer(ITIMER_REAL, &it, NULL) == 0);
    struct itimerval cur;
    check("getitimer reports the interval", getitimer(ITIMER_REAL, &cur) == 0 && cur.it_interval.tv_usec == 100000);
    while (alrm < 3) pause();
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, NULL);
    check("periodic timer delivered repeated SIGALRMs", alrm >= 3);
    check("disarmed timer reads back as zero", getitimer(ITIMER_REAL, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_usec == 0);

    signal(SIGPROF, on_prof);
    struct itimerval p = {{0, 0}, {0, 200000}};
    setitimer(ITIMER_PROF, &p, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile unsigned long spin = 0;
    while (!prof && ms_since(&t0) < 5000) spin++;
    check("ITIMER_PROF fires after CPU time is used", prof == 1);

    pid_t c = fork();
    if (c == 0) {
        signal(SIGALRM, SIG_DFL);
        alarm(1);
        pause();
        _exit(0);
    }
    int st = 0;
    waitpid(c, &st, 0);
    check("an unhandled SIGALRM terminates the process", WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM);
}

static void pidfd_tests(void) {
    pid_t c = fork();
    if (c == 0) {
        usleep(300 * 1000);
        _exit(7);
    }
    int pfd = syscall(SYS_pidfd_open, c, 0);
    check("pidfd_open on a child", pfd >= 0);
    struct pollfd p = {pfd, POLLIN, 0};
    check("pidfd not readable while the child runs", poll(&p, 1, 0) == 0);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int r = poll(&p, 1, 5000);
    check("pidfd becomes readable when the child exits", r == 1 && (p.revents & POLLIN) && ms_since(&t0) >= 150);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    check("waitid(P_PIDFD) reaps the child", waitid(P_PIDFD, pfd, &si, WEXITED) == 0 && si.si_pid == c && si.si_status == 7);
    close(pfd);

    c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    pfd = syscall(SYS_pidfd_open, c, 0);
    check("pidfd_send_signal(SIGTERM)", syscall(SYS_pidfd_send_signal, pfd, SIGTERM, NULL, 0) == 0);
    int st = 0;
    waitpid(c, &st, 0);
    check("the signalled child was terminated", WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);
    check("pidfd_open of a missing process -> ESRCH", syscall(SYS_pidfd_open, 999999, 0) == -1 && errno == ESRCH);
    close(pfd);
}

static void clone3_test(void) {
    int pidfd = -1;
    struct clone_args_v0 ca;
    memset(&ca, 0, sizeof ca);
    ca.flags = CLONE_PIDFD_FLAG;
    ca.pidfd = (uint64_t)(uintptr_t)&pidfd;
    ca.exit_signal = SIGCHLD;
    long c = syscall(SYS_clone3, &ca, sizeof ca);
    if (c == 0) _exit(5);
    check("clone3 creates a process", c > 0);
    check("clone3 CLONE_PIDFD returns a pidfd", pidfd >= 0);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    check("child of clone3 exits with its status", waitid(P_PIDFD, pidfd, &si, WEXITED) == 0 && si.si_pid == c && si.si_status == 5);
    close(pidfd);
}

static void shared_futex_tests(void) {
    uint32_t *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *word = 0;
    pid_t c = fork();
    if (c == 0) {
        // Shared (non-private) wait: must be woken by the parent's wake
        while (__atomic_load_n(word, __ATOMIC_SEQ_CST) == 0) futex(word, FUTEX_WAIT, 0);
        _exit(0);
    }
    usleep(300 * 1000);
    __atomic_store_n(word, 1, __ATOMIC_SEQ_CST);
    long woke = futex(word, FUTEX_WAKE, 1);
    int st = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    waitpid(c, &st, 0);
    check("FUTEX_WAKE in a parent wakes the child in shared memory", woke == 1 && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // Process-shared semaphore (glibc uses shared futexes)
    sem_t *sem = (sem_t *)(word + 16);
    sem_init(sem, 1, 0);
    c = fork();
    if (c == 0) {
        _exit(sem_wait(sem) == 0 ? 0 : 1);
    }
    usleep(200 * 1000);
    sem_post(sem);
    waitpid(c, &st, 0);
    check("process-shared semaphore between parent and child", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    // Private futexes at the same address in two processes stay separate
    static uint32_t priv = 0;
    c = fork();
    if (c == 0) {
        struct timespec ts = {1, 0};
        long r = syscall(SYS_futex, &priv, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
        _exit(r == -1 && errno == ETIMEDOUT ? 0 : 1);
    }
    usleep(200 * 1000);
    long w = futex(&priv, FUTEX_WAKE_PRIVATE, 1);
    waitpid(c, &st, 0);
    check("a private wake does not reach another process", w == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    munmap(word, 4096);
}

int main(void) {
    timer_tests();
    pidfd_tests();
    clone3_test();
    shared_futex_tests();
    if (failures == 0)
        printf("[gapstest] ALL PASSED (0 failures)\n");
    else
        printf("[gapstest] %d FAILURES\n", failures);
    return failures != 0;
}
