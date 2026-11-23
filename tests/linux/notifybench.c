// notifybench: the cost of changes in a watched directory (wave 9, Group 6b-1 budget).
//
// usage: notifybench DIR N WATCH
// N rounds of create+write+close, chmod, rename, unlink of one file in DIR; with WATCH=1
// an inotify watch (IN_ALL_EVENTS) is on DIR and the events are read as they come (every
// 32 rounds, and at the end). Prints "BENCH watch=W rounds=N us_per_round=X events=E".
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static long drain(int in) {
    char buf[16384] __attribute__((aligned(8)));
    long n = 0;
    for (;;) {
        ssize_t r = read(in, buf, sizeof buf);
        if (r <= 0)
            return n;
        for (ssize_t off = 0; off < r;) {
            struct inotify_event *e = (void *)(buf + off);
            n++;
            off += sizeof *e + e->len;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: notifybench DIR N WATCH\n");
        return 2;
    }
    const char *dir = argv[1];
    int n = atoi(argv[2]), watch = atoi(argv[3]);
    mkdir(dir, 0755);
    int in = -1;
    if (watch) {
        in = inotify_init1(IN_NONBLOCK);
        if (in < 0 || inotify_add_watch(in, dir, IN_ALL_EVENTS) < 0) {
            perror("inotify");
            return 1;
        }
    }
    char a[512], b[512];
    snprintf(a, sizeof a, "%s/f", dir);
    snprintf(b, sizeof b, "%s/g", dir);
    long events = 0;
    double t0 = now_us();
    for (int i = 0; i < n; i++) {
        int fd = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            perror("open");
            return 1;
        }
        write(fd, "x", 1);
        close(fd);
        chmod(a, 0600);
        rename(a, b);
        unlink(b);
        if (watch && i % 32 == 31)
            events += drain(in);
    }
    if (watch)
        events += drain(in);
    double t1 = now_us();
    printf("BENCH watch=%d rounds=%d us_per_round=%.1f events=%ld\n", watch, n, (t1 - t0) / n, events);
    return 0;
}
