// Clock resolution: CLOCK_MONOTONIC never goes backwards and has sub-millisecond
// resolution (many distinct values, small steps), CLOCK_REALTIME agrees with
// gettimeofday, clock_getres reports 1 ns for the high-resolution clocks (EINVAL for an
// unknown clock), short timeouts (nanosleep, poll, ppoll, select, epoll_wait, futex,
// timerfd, sigtimedwait) end within a few milliseconds of their deadline.
// Build: gcc -O1 -w -o clock clock_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <linux/futex.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long long ns(clockid_t c) {
    struct timespec t;
    clock_gettime(c, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return x < y ? -1 : x > y;
}

// Median and minimum duration (ns) of 15 runs of `op` asked to wait `want` ns
static void timed(const char *name, long long want, void (*op)(long long)) {
    long long d[15];
    for (int i = 0; i < 15; i++) {
        long long a = ns(CLOCK_MONOTONIC);
        op(want);
        d[i] = ns(CLOCK_MONOTONIC) - a;
    }
    qsort(d, 15, sizeof d[0], cmp);
    char what[160];
    printf("     %-13s %.2f ms: median %.3f ms, min %.3f ms\n", name, want / 1e6, d[7] / 1e6, d[0] / 1e6);
    snprintf(what, sizeof what, "%s(%.1f ms) waits at least that long, median within 3 ms", name, want / 1e6);
    check(d[0] >= want - 100000 && d[7] < want + 3000000, what);
}

static void op_nanosleep(long long w) {
    struct timespec t = {0, w};
    nanosleep(&t, NULL);
}
static void op_poll(long long w) { poll(NULL, 0, w / 1000000); }
static void op_ppoll(long long w) {
    struct timespec t = {0, w};
    int p[2];
    pipe(p);
    struct pollfd f = {p[0], POLLIN, 0};
    ppoll(&f, 1, &t, NULL);
    close(p[0]);
    close(p[1]);
}
static void op_select(long long w) {
    struct timeval t = {0, w / 1000};
    select(0, NULL, NULL, NULL, &t);
}
static int ep = -1;
static void op_epoll(long long w) {
    struct epoll_event e;
    epoll_wait(ep, &e, 1, w / 1000000);
}
static int fword;
static void op_futex(long long w) {
    struct timespec t = {0, w};
    syscall(SYS_futex, &fword, FUTEX_WAIT_PRIVATE, 0, &t, NULL, 0);
}
static void op_timerfd(long long w) {
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{0, 0}, {0, w}};
    timerfd_settime(t, 0, &its, NULL);
    unsigned long long x;
    read(t, &x, sizeof x);
    close(t);
}
static void op_sigtimedwait(long long w) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    struct timespec t = {0, w};
    sigtimedwait(&s, NULL, &t);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long long prev = ns(CLOCK_MONOTONIC), start = prev;
    int backwards = 0, distinct = 0, n = 0;
    while (ns(CLOCK_MONOTONIC) - start < 300000000LL && n < 200000) {
        long long t = ns(CLOCK_MONOTONIC);
        if (t < prev) backwards++;
        if (t != prev) distinct++;
        prev = t;
        n++;
    }
    check(backwards == 0, "CLOCK_MONOTONIC never goes backwards");
    printf("     %d reads, %d distinct values in %.0f ms\n", n, distinct, (prev - start) / 1e6);
    check(distinct > 100, "sub-tick resolution (more than 100 distinct values in 300 ms)");
    // Readings spread over the tick (not stuck at its end): under 20% in its last 0.1 ms
    int late = 0;
    for (int i = 0; i < 2000; i++) {
        long long t = ns(CLOCK_MONOTONIC) % 10000000;
        late += t >= 9900000;
        // A varying busy wait between samples
        volatile long long sink = 0;
        for (int k = 0; k < (i * 7919) % 3000; k++) sink += ns(CLOCK_MONOTONIC) & 1;
    }
    printf("     %d of 2000 readings in a tick's last 0.1 ms\n", late);
    check(late < 400, "readings spread over the tick");
    // Small steps: the time between two back-to-back reads is well under a millisecond
    int small = 0;
    for (int i = 0; i < 100; i++) {
        long long a = ns(CLOCK_MONOTONIC), b = ns(CLOCK_MONOTONIC);
        small += b - a < 1000000;
    }
    check(small >= 90, "back-to-back reads differ by less than 1 ms");
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long long rt = ns(CLOCK_REALTIME), gt = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000LL;
    check(rt - gt < 50000000LL && rt >= gt - 1000, "CLOCK_REALTIME agrees with gettimeofday");
    struct timespec r;
    check(clock_getres(CLOCK_MONOTONIC, &r) == 0 && r.tv_sec == 0 && r.tv_nsec == 1, "clock_getres(CLOCK_MONOTONIC) = 1 ns");
    check(clock_getres(CLOCK_REALTIME, &r) == 0 && r.tv_nsec == 1, "clock_getres(CLOCK_REALTIME) = 1 ns");
    check(clock_getres(CLOCK_MONOTONIC_COARSE, &r) == 0 && r.tv_nsec > 1, "the coarse clock reports the tick");
    errno = 0;
    check(clock_getres(42, &r) == -1 && errno == EINVAL, "an unknown clock: EINVAL");
    long long a = ns(CLOCK_MONOTONIC);
    struct timespec two = {0, 2000000};
    nanosleep(&two, NULL);
    long long slept = ns(CLOCK_MONOTONIC) - a;
    printf("     nanosleep(2 ms) took %.3f ms\n", slept / 1e6);
    check(slept >= 2000000, "nanosleep(2 ms) sleeps at least 2 ms");
    check(slept < 100000000, "nanosleep(2 ms) returns within 100 ms");
    // Short timeouts end close to their deadline, not at the next 10 ms tick
    sigset_t blk;
    sigemptyset(&blk);
    sigaddset(&blk, SIGUSR1);
    sigprocmask(SIG_BLOCK, &blk, NULL);
    ep = epoll_create1(0);
    timed("nanosleep", 2000000, op_nanosleep);
    timed("nanosleep", 500000, op_nanosleep);
    timed("poll", 3000000, op_poll);
    timed("ppoll", 1500000, op_ppoll);
    timed("select", 2000000, op_select);
    timed("epoll_wait", 4000000, op_epoll);
    timed("futex", 2000000, op_futex);
    timed("timerfd", 2500000, op_timerfd);
    timed("sigtimedwait", 2000000, op_sigtimedwait);
    printf(fails ? "CLOCK TEST FAILED (%d)\n" : "CLOCK TEST PASSED\n", fails);
    return fails != 0;
}
