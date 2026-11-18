// timerfd latency probe (Group 13): 30 waits of 2.5 ms each way: a blocking read, poll then
// read, epoll then read, and nanosleep for comparison; prints sorted delays over 2.5 ms (us).
// Build: gcc -O1 -w -o tfdlat tfdlat.c
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static long long ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}
static int cmp(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return x < y ? -1 : x > y;
}
#define N 30
static void show(const char *name, long long *d) {
    qsort(d, N, sizeof *d, cmp);
    printf("%-10s late us: min %lld p25 %lld med %lld p75 %lld max %lld\n", name, d[0] / 1000, d[N / 4] / 1000, d[N / 2] / 1000, d[3 * N / 4] / 1000, d[N - 1] / 1000);
}
int main(void) {
    const long long w = 2500000;
    long long d[N];
    unsigned long long x;
    struct itimerspec its = {{0, 0}, {0, w}};
    for (int mode = 0; mode < 4; mode++) {
        for (int i = 0; i < N; i++) {
            int t = timerfd_create(CLOCK_MONOTONIC, 0);
            int ep = epoll_create1(0);
            struct epoll_event e = {.events = EPOLLIN};
            epoll_ctl(ep, EPOLL_CTL_ADD, t, &e);
            long long a = ns();
            if (mode == 3) {
                struct timespec s = {0, w};
                nanosleep(&s, 0);
            } else {
                timerfd_settime(t, 0, &its, 0);
                if (mode == 1) {
                    struct pollfd p = {t, POLLIN, 0};
                    poll(&p, 1, 1000);
                } else if (mode == 2) {
                    epoll_wait(ep, &e, 1, 1000);
                }
                read(t, &x, 8);
            }
            d[i] = ns() - a - w;
            close(ep);
            close(t);
        }
        show(mode == 0 ? "read" : mode == 1 ? "poll" : mode == 2 ? "epoll" : "nanosleep", d);
    }
    return 0;
}
