// Edge-triggered epoll watches on an eventfd report once per change, not whenever the
// eventfd holds a value: Firefox's event loops spun at thousands of epoll_wait calls a
// second when Hydra treated EPOLLET on an eventfd as level-triggered. A level-triggered
// watch still reports every time, and EPOLL_CTL_MOD re-arms an edge-triggered one.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static int wait_n(int ep, int timeout_ms) {
    struct epoll_event ev[4];
    return epoll_wait(ep, ev, 4, timeout_ms);
}

static void add(int efd, uint64_t n) {
    if (write(efd, &n, 8) != 8) perror("write");
}

static int efd_global;
static void *writer(void *arg) {
    (void)arg;
    usleep(200 * 1000);
    add(efd_global, 1);
    return NULL;
}

int main(void) {
    int efd = eventfd(0, EFD_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN | EPOLLET, .data.u64 = 1};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, efd, &e) == 0, "EPOLL_CTL_ADD edge-triggered");

    CHECK(wait_n(ep, 0) == 0, "empty eventfd: nothing");
    add(efd, 1);
    CHECK(wait_n(ep, 0) == 1, "a write: one event");
    CHECK(wait_n(ep, 0) == 0, "still readable, no new edge: nothing");
    CHECK(wait_n(ep, 0) == 0, "and again nothing");
    add(efd, 1);
    CHECK(wait_n(ep, 0) == 1, "another write: an event although it was already readable");

    // Draining and refilling between two waits is a new edge too (never lost)
    uint64_t v;
    CHECK(read(efd, &v, 8) == 8 && v == 2, "read drains the counter (%llu)", (unsigned long long)v);
    add(efd, 5);
    CHECK(wait_n(ep, 0) == 1, "drained and refilled between waits: an event");

    // EPOLL_CTL_MOD re-arms: a ready eventfd is reported again
    CHECK(wait_n(ep, 0) == 0, "no edge before MOD");
    e.data.u64 = 2;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, efd, &e) == 0, "EPOLL_CTL_MOD");
    CHECK(wait_n(ep, 0) == 1, "MOD re-arms a ready eventfd");

    // A blocking wait sleeps until the next write instead of returning at once
    efd_global = efd;
    pthread_t t;
    pthread_create(&t, NULL, writer, NULL);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    int n = wait_n(ep, 2000);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    pthread_join(t, NULL);
    CHECK(n == 1 && ms >= 150, "a blocking wait sleeps until the next write (%d after %ld ms)", n, ms);

    // Level-triggered: every wait while readable
    int ep2 = epoll_create1(0);
    struct epoll_event l = {.events = EPOLLIN, .data.u64 = 3};
    CHECK(epoll_ctl(ep2, EPOLL_CTL_ADD, efd, &l) == 0, "EPOLL_CTL_ADD level-triggered");
    CHECK(wait_n(ep2, 0) == 1 && wait_n(ep2, 0) == 1, "level-triggered: reported on every wait");

    printf("%s\n", fails ? "EPOLLET TEST FAILED" : "EPOLLET TEST PASSED");
    return fails != 0;
}
