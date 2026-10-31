// Hydra M3 event-descriptor conformance test: eventfd, timerfd, inotify, epoll one-shot.
// Build (WSL): gcc -static-pie -O1 -pthread -o esp/bin/m3test.elf scratch/m3test.c
// Run in Hydra: linux run m3test.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("[m3test] %-54s %s\n", name, ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) failures++;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000 + (t.tv_nsec - t0->tv_nsec) / 1000000;
}

static int efd_shared;
static void *poke_later(void *arg) {
    (void)arg;
    usleep(200 * 1000);
    uint64_t one = 1;
    write(efd_shared, &one, 8);
    return NULL;
}

static void eventfd_tests(void) {
    int e = eventfd(0, EFD_CLOEXEC);
    check("eventfd2 with EFD_CLOEXEC", e >= 0 && (fcntl(e, F_GETFD) & FD_CLOEXEC));
    uint64_t v = 5;
    write(e, &v, 8);
    v = 2;
    write(e, &v, 8);
    v = 0;
    check("eventfd read returns the sum and resets", read(e, &v, 8) == 8 && v == 7);

    efd_shared = e;
    pthread_t t;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_create(&t, NULL, poke_later, NULL);
    v = 0;
    int r = read(e, &v, 8); // blocks until the thread writes
    long el = ms_since(&t0);
    pthread_join(t, NULL);
    check("blocking eventfd read waits for a writer", r == 8 && v == 1 && el >= 150);

    int s = eventfd(3, EFD_SEMAPHORE | EFD_NONBLOCK);
    int ok = 1;
    for (int i = 0; i < 3; i++) ok &= read(s, &v, 8) == 8 && v == 1;
    check("EFD_SEMAPHORE counts down by one", ok);
    check("empty non-blocking eventfd -> EAGAIN", read(s, &v, 8) == -1 && errno == EAGAIN);

    struct pollfd p = {s, POLLIN, 0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    efd_shared = s;
    pthread_create(&t, NULL, poke_later, NULL);
    int pr = poll(&p, 1, 5000);
    el = ms_since(&t0);
    pthread_join(t, NULL);
    check("poll wakes when another thread writes the eventfd", pr == 1 && el >= 150 && el < 2000);
    close(e);
    close(s);
}

static void timerfd_tests(void) {
    int t = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    check("timerfd_create", t >= 0);
    struct itimerspec its = {{0, 0}, {0, 300 * 1000000}};
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    check("timerfd_settime one-shot 300 ms", timerfd_settime(t, 0, &its, NULL) == 0);
    struct itimerspec cur;
    check("timerfd_gettime shows it armed", timerfd_gettime(t, &cur) == 0 && (cur.it_value.tv_sec || cur.it_value.tv_nsec));
    uint64_t n = 0;
    int r = read(t, &n, 8);
    long el = ms_since(&t0);
    check("read blocks until expiry (one expiration)", r == 8 && n == 1 && el >= 250 && el < 1500);

    struct itimerspec per = {{0, 50 * 1000000}, {0, 50 * 1000000}};
    timerfd_settime(t, 0, &per, NULL);
    usleep(330 * 1000);
    r = read(t, &n, 8);
    check("periodic timer counts missed expirations", r == 8 && n >= 4 && n <= 8);

    // epoll wakes on expiry
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = {.events = EPOLLIN, .data.u32 = 42};
    epoll_ctl(ep, EPOLL_CTL_ADD, t, &ev);
    read(t, &n, 8);
    struct itimerspec once = {{0, 0}, {0, 200 * 1000000}};
    timerfd_settime(t, 0, &once, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    struct epoll_event out;
    int w = epoll_wait(ep, &out, 1, 5000);
    el = ms_since(&t0);
    check("epoll_wait wakes on timer expiry", w == 1 && out.data.u32 == 42 && el >= 150 && el < 1500);

    struct itimerspec off = {{0, 0}, {0, 0}};
    timerfd_settime(t, 0, &off, NULL);
    fcntl(t, F_SETFL, O_NONBLOCK);
    check("disarmed non-blocking read -> EAGAIN", read(t, &n, 8) == -1 && errno == EAGAIN);
    close(ep);
    close(t);
}

// Reads events into buf; returns bytes (waits up to 1 s).
static int read_events(int fd, char *buf, int cap) {
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, 1000) != 1) return 0;
    return read(fd, buf, cap);
}

static int has_event(char *buf, int n, uint32_t mask, const char *name) {
    for (int off = 0; off < n;) {
        struct inotify_event *e = (struct inotify_event *)(buf + off);
        if ((e->mask & mask) == mask && (!name || (e->len && strcmp(e->name, name) == 0))) return 1;
        off += sizeof *e + e->len;
    }
    return 0;
}

static void inotify_tests(void) {
    char dir[64];
    snprintf(dir, sizeof dir, "/tmp/m3test-%d", getpid());
    mkdir(dir, 0755);
    int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    check("inotify_init1", in >= 0);
    int wd = inotify_add_watch(in, dir, IN_ALL_EVENTS);
    check("inotify_add_watch on a directory", wd > 0);
    check("watching the same inode again returns the same wd", inotify_add_watch(in, dir, IN_ALL_EVENTS) == wd);
    char buf[4096];
    check("no events yet -> EAGAIN", read(in, buf, sizeof buf) == -1 && errno == EAGAIN);

    char path[128];
    snprintf(path, sizeof path, "%s/file", dir);
    int f = open(path, O_CREAT | O_WRONLY, 0644);
    int n = read_events(in, buf, sizeof buf);
    check("IN_CREATE with the entry name", has_event(buf, n, IN_CREATE, "file"));
    write(f, "data", 4);
    n = read_events(in, buf, sizeof buf);
    check("IN_MODIFY for a write to a file in the directory", has_event(buf, n, IN_MODIFY, "file"));
    close(f);
    n = read_events(in, buf, sizeof buf);
    check("IN_CLOSE_WRITE on close", has_event(buf, n, IN_CLOSE_WRITE, "file"));

    int qn = 0;
    ioctl(in, FIONREAD, &qn);
    chmod(path, 0600);
    ioctl(in, FIONREAD, &qn);
    check("FIONREAD counts queued bytes", qn > 0);
    n = read_events(in, buf, sizeof buf);
    check("IN_ATTRIB on chmod", has_event(buf, n, IN_ATTRIB, "file"));

    char path2[128];
    snprintf(path2, sizeof path2, "%s/renamed", dir);
    rename(path, path2);
    n = read_events(in, buf, sizeof buf);
    uint32_t c1 = 0, c2 = 0;
    for (int off = 0; off < n;) {
        struct inotify_event *e = (struct inotify_event *)(buf + off);
        if (e->mask & IN_MOVED_FROM) c1 = e->cookie;
        if (e->mask & IN_MOVED_TO) c2 = e->cookie;
        off += sizeof *e + e->len;
    }
    check("rename gives MOVED_FROM/MOVED_TO with one cookie", c1 && c1 == c2);

    int fw = inotify_add_watch(in, path2, IN_DELETE_SELF);
    unlink(path2);
    n = read_events(in, buf, sizeof buf);
    check("IN_DELETE in the directory", has_event(buf, n, IN_DELETE, "renamed"));
    int self = 0, ignored = 0;
    for (int off = 0; off < n;) {
        struct inotify_event *e = (struct inotify_event *)(buf + off);
        if (e->wd == fw && (e->mask & IN_DELETE_SELF)) self = 1;
        if (e->wd == fw && (e->mask & IN_IGNORED)) ignored = 1;
        off += sizeof *e + e->len;
    }
    check("IN_DELETE_SELF then IN_IGNORED on the file's watch", self && ignored);

    char sub[128];
    snprintf(sub, sizeof sub, "%s/sub", dir);
    mkdir(sub, 0755);
    n = read_events(in, buf, sizeof buf);
    check("mkdir gives IN_CREATE|IN_ISDIR", has_event(buf, n, IN_CREATE | IN_ISDIR, "sub"));
    rmdir(sub);
    read_events(in, buf, sizeof buf);
    check("inotify_rm_watch", inotify_rm_watch(in, wd) == 0);
    n = read_events(in, buf, sizeof buf);
    check("rm_watch queues IN_IGNORED", has_event(buf, n, IN_IGNORED, NULL));
    rmdir(dir);
    close(in);
}

static void epoll_oneshot_test(void) {
    int e = eventfd(1, EFD_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT, .data.u32 = 7};
    epoll_ctl(ep, EPOLL_CTL_ADD, e, &ev);
    struct epoll_event out;
    int a = epoll_wait(ep, &out, 1, 100);
    int b = epoll_wait(ep, &out, 1, 50);
    epoll_ctl(ep, EPOLL_CTL_MOD, e, &ev);
    int c = epoll_wait(ep, &out, 1, 100);
    check("EPOLLONESHOT reports once until re-armed", a == 1 && b == 0 && c == 1);
    close(ep);
    close(e);
}

int main(void) {
    eventfd_tests();
    timerfd_tests();
    inotify_tests();
    epoll_oneshot_test();
    if (failures == 0)
        printf("[m3test] ALL PASSED (0 failures)\n");
    else
        printf("[m3test] %d FAILURES\n", failures);
    return failures != 0;
}
