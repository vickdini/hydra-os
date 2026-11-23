/* conntime: where a loopback TCP connect loop spends its time (wave 10, Group N).
 * Times each call of lxbench's tcp_connect loop (socket, connect, accept, close, close)
 * separately and prints the median and mean of each, in ns.
 *   conntime [ITERATIONS] [ROUNDS] [tight]
 * Also: "gap" rounds sleep 200 us after the closes, so the next socket() does not pay for
 * work left behind by them. */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int cmpu(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

#define PH 6
static const char *names[PH] = {"socket", "connect", "accept", "close_c", "close_s", "total"};

static void report(const char *tag, uint64_t *v[PH], long n) {
    for (int p = 0; p < PH; p++) {
        uint64_t sum = 0;
        for (long i = 0; i < n; i++) sum += v[p][i];
        qsort(v[p], n, sizeof(uint64_t), cmpu);
        printf("CONNT %-4s %-8s med %8lu mean %8lu p90 %8lu\n", tag, names[p], (unsigned long)v[p][n / 2],
               (unsigned long)(sum / n), (unsigned long)v[p][n * 9 / 10]);
    }
}

int main(int argc, char **argv) {
    long n = argc > 1 ? atol(argv[1]) : 1000;
    int rounds = argc > 2 ? atoi(argv[2]) : 2;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (l < 0 || bind(l, (void *)&a, sizeof a) || listen(l, 64)) return 1;
    socklen_t al = sizeof a;
    getsockname(l, (void *)&a, &al);
    uint64_t *v[PH];
    for (int p = 0; p < PH; p++) v[p] = malloc(n * sizeof(uint64_t));
    for (int r = 0; r < rounds * 2; r++) {
        int gap = r & 1;
        if (gap && argc > 3) continue; /* conntime N R tight: no gap rounds */
        for (long i = 0; i < n; i++) {
            uint64_t t[PH];
            t[0] = now();
            int c = socket(AF_INET, SOCK_STREAM, 0);
            t[1] = now();
            if (c < 0 || connect(c, (void *)&a, sizeof a)) { printf("CONNT connect failed\n"); return 1; }
            t[2] = now();
            int s = accept(l, 0, 0);
            if (s < 0) { printf("CONNT accept failed\n"); return 1; }
            t[3] = now();
            close(c);
            t[4] = now();
            close(s);
            uint64_t e = now();
            for (int p = 0; p < PH - 1; p++) v[p][i] = (p + 1 < PH - 1 ? t[p + 1] : e) - t[p];
            v[PH - 1][i] = e - t[0];
            if (gap) usleep(200);
        }
        report(gap ? "gap" : "tight", v, n);
    }
    printf("CONNT-DONE\n");
    return 0;
}
