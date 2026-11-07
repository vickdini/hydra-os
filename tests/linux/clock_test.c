// Clock resolution: CLOCK_MONOTONIC never goes backwards and has sub-millisecond
// resolution (many distinct values, small steps), CLOCK_REALTIME agrees with
// gettimeofday, clock_getres reports 1 ns for the high-resolution clocks (EINVAL for an
// unknown clock), nanosleep(2 ms) sleeps at least 2 ms and not wildly more.
// Build: gcc -O1 -w -o clock clock_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

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
    check(slept >= 2000000 && slept < 100000000, "nanosleep(2 ms) sleeps at least 2 ms");
    printf(fails ? "CLOCK TEST FAILED (%d)\n" : "CLOCK TEST PASSED\n", fails);
    return fails != 0;
}
