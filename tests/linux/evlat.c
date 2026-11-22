/* evlat (wave 8, Group I): input latency from the interrupt to the read of /dev/input/event*.
 * Each event carries the kernel's CLOCK_MONOTONIC time of the interrupt that delivered it
 * (since wave 8; before, the 10 ms tick), so the time a read returns minus the first event's
 * time is the interrupt-to-read latency (display-input-design.md section 2.4, column 1).
 * Usage: evlat SECONDS [OUTFILE]  (as root; reads beside kwin, which keeps its own queues)
 * Prints per device: reads, average, p50, p90, max (ms).
 * Build: gcc -O1 -w -pthread -o evlat evlat.c */
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAXS 100000
static double lat[3][MAXS];
static int nl[3];

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 30;
    FILE *out = argc > 2 ? fopen(argv[2], "w") : stdout;
    if (!out) out = stdout;
    struct pollfd p[3];
    int dev[3], n = 0;
    for (int d = 0; d < 3; d++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/input/event%d", d);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;
        p[n].fd = fd;
        p[n].events = POLLIN;
        dev[n++] = d;
    }
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double el = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
        if (el >= secs) break;
        if (poll(p, n, 500) <= 0) continue;
        for (int i = 0; i < n; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            struct input_event ev[64];
            ssize_t r = read(p[i].fd, ev, sizeof ev);
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (r < (ssize_t)sizeof ev[0]) continue;
            double t = ev[0].time.tv_sec + ev[0].time.tv_usec / 1e6;
            double tn = now.tv_sec + now.tv_nsec / 1e9;
            int d = dev[i];
            if (nl[d] < MAXS) lat[d][nl[d]++] = (tn - t) * 1000.0;
        }
    }
    static const char *names[3] = {"keyboard", "mouse", "pointer"};
    for (int d = 0; d < 3; d++) {
        if (!nl[d]) {
            fprintf(out, "evlat %s: no events\n", names[d]);
            continue;
        }
        double sum = 0;
        for (int i = 0; i < nl[d]; i++) sum += lat[d][i];
        qsort(lat[d], nl[d], sizeof(double), cmp);
        fprintf(out, "evlat %s: reads %d avg %.3f p50 %.3f p90 %.3f max %.3f ms\n", names[d], nl[d], sum / nl[d], lat[d][nl[d] / 2], lat[d][nl[d] * 9 / 10], lat[d][nl[d] - 1]);
    }
    fprintf(out, "evlat done\n");
    return 0;
}
