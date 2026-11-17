// Network benchmark for Hydra (Group 2, wave 2): the same binary measures the kernel's
// network stack before (2c6bc80) and net-server after.
//
//   netbench dl HOST PORT PATH            HTTP/1.0 GET, body discarded: MB/s
//   netbench get HOST PORT PATH N         N sequential HTTP/1.0 GETs, a new TCP connection
//                                         each: average and median latency (us)
//   netbench udp HOST PORT N              N UDP echo round trips (a host echo server)
//   netbench lo MB                        TCP over 127.0.0.1 (fork: sender and receiver)
//   netbench lolat N                      N TCP round trips of 1 byte over 127.0.0.1
//
// Prints one line "NETBENCH <mode> ..." per run. Build: gcc -O1 -w -pthread.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static int tcp_connect(const char *host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return -1; }
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, host, &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); close(s); return -1; }
    return s;
}

// One GET; returns body+header bytes read, or -1.
static long http_get(const char *host, int port, const char *path) {
    int s = tcp_connect(host, port);
    if (s < 0) return -1;
    char req[512];
    int n = snprintf(req, sizeof req, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host);
    if (write(s, req, n) != n) { perror("write"); close(s); return -1; }
    static char buf[65536];
    long total = 0;
    for (;;) {
        ssize_t r = read(s, buf, sizeof buf);
        if (r < 0) { perror("read"); close(s); return -1; }
        if (r == 0) break;
        total += r;
    }
    close(s);
    return total;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: see source\n"); return 2; }
    const char *mode = argv[1];
    if (!strcmp(mode, "dl") && argc >= 5) {
        double t0 = now_us();
        long n = http_get(argv[2], atoi(argv[3]), argv[4]);
        double dt = (now_us() - t0) / 1e6;
        if (n < 0) { printf("NETBENCH dl FAILED\n"); return 1; }
        printf("NETBENCH dl bytes=%ld secs=%.3f MBps=%.2f\n", n, dt, n / dt / 1e6);
        return 0;
    }
    if (!strcmp(mode, "get") && argc >= 6) {
        int count = atoi(argv[5]);
        double *lat = calloc(count, sizeof(double));
        double t0 = now_us();
        for (int i = 0; i < count; i++) {
            double a = now_us();
            if (http_get(argv[2], atoi(argv[3]), argv[4]) < 0) { printf("NETBENCH get FAILED at %d\n", i); return 1; }
            lat[i] = now_us() - a;
        }
        double total = now_us() - t0;
        qsort(lat, count, sizeof(double), cmp);
        printf("NETBENCH get n=%d avg_us=%.0f median_us=%.0f p90_us=%.0f\n", count, total / count, lat[count / 2], lat[count * 9 / 10]);
        return 0;
    }
    if (!strcmp(mode, "udp") && argc >= 5) {
        int count = atoi(argv[4]);
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(atoi(argv[3]));
        inet_pton(AF_INET, argv[2], &a.sin_addr);
        connect(s, (struct sockaddr *)&a, sizeof a);
        struct timeval tv = {2, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        double *lat = calloc(count, sizeof(double));
        int lost = 0;
        char buf[64];
        double t0 = now_us();
        for (int i = 0; i < count; i++) {
            double t = now_us();
            send(s, "ping", 4, 0);
            if (recv(s, buf, sizeof buf, 0) <= 0) lost++;
            lat[i] = now_us() - t;
        }
        double total = now_us() - t0;
        qsort(lat, count, sizeof(double), cmp);
        printf("NETBENCH udp n=%d lost=%d avg_us=%.0f median_us=%.0f\n", count, lost, total / count, lat[count / 2]);
        return 0;
    }
    if (!strcmp(mode, "lo") && argc >= 3) {
        long mb = atol(argv[2]);
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(45678);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 1) < 0) { perror("bind/listen"); return 1; }
        pid_t p = fork();
        if (p == 0) {
            int c = tcp_connect("127.0.0.1", 45678);
            static char buf[65536];
            memset(buf, 'x', sizeof buf);
            long left = mb * 1000000;
            while (left > 0) {
                ssize_t w = write(c, buf, left < (long)sizeof buf ? left : (long)sizeof buf);
                if (w <= 0) { perror("write"); _exit(1); }
                left -= w;
            }
            close(c);
            _exit(0);
        }
        int c = accept(ls, 0, 0);
        static char buf[65536];
        long total = 0;
        double t0 = now_us();
        for (;;) {
            ssize_t r = read(c, buf, sizeof buf);
            if (r <= 0) break;
            total += r;
        }
        double dt = (now_us() - t0) / 1e6;
        waitpid(p, 0, 0);
        printf("NETBENCH lo bytes=%ld secs=%.3f MBps=%.2f\n", total, dt, total / dt / 1e6);
        return 0;
    }
    if (!strcmp(mode, "lolat") && argc >= 3) {
        int count = atoi(argv[2]);
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET;
        a.sin_port = htons(45679);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(ls, (struct sockaddr *)&a, sizeof a) < 0 || listen(ls, 1) < 0) { perror("bind/listen"); return 1; }
        pid_t p = fork();
        if (p == 0) {
            int c = accept(ls, 0, 0);
            char b;
            while (read(c, &b, 1) == 1) write(c, &b, 1);
            _exit(0);
        }
        int c = tcp_connect("127.0.0.1", 45679);
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        char b = 'x';
        double t0 = now_us();
        for (int i = 0; i < count; i++) {
            if (write(c, &b, 1) != 1 || read(c, &b, 1) != 1) { printf("NETBENCH lolat FAILED at %d\n", i); return 1; }
        }
        double dt = now_us() - t0;
        close(c);
        waitpid(p, 0, 0);
        printf("NETBENCH lolat n=%d avg_us=%.0f\n", count, dt / count);
        return 0;
    }
    fprintf(stderr, "bad arguments\n");
    return 2;
}
