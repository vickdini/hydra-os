// CPU time and memory accounting as system monitors read it:
// - a process that does user-mode work between frequent blocking system calls (a ping-pong
//   over pipes) is charged mostly user time, in getrusage and in /proc/stat (each tick to
//   the mode it interrupted, not system time for every tick a task switch crossed first);
// - /proc/meminfo shows the page cache: a file just read counts in Cached, and what only
//   the cache holds counts in MemAvailable (>= MemFree).
// Passes on Linux.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }

// About `us` microseconds of user-mode work
static volatile unsigned long sink;
static void work(int us) {
    double end = now() + us / 1e6;
    while (now() < end)
        for (int i = 0; i < 200; i++) sink += i;
}

static long meminfo(const char *key) {
    FILE *f = fopen("/proc/meminfo", "r");
    char line[256];
    long v = -1;
    size_t n = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, key, n) && line[n] == ':') v = atol(line + n + 1);
    if (f) fclose(f);
    return v;
}

static int stat_cpu(long long *user, long long *sys) {
    FILE *f = fopen("/proc/stat", "r");
    long long u, n, s;
    int ok = f && fscanf(f, "cpu %lld %lld %lld", &u, &n, &s) == 3;
    if (f) fclose(f);
    *user = u + n;
    *sys = s;
    return ok;
}

int main(void) {
    // 1. User work between blocking calls, in two processes
    int a[2], b[2];
    pipe(a); pipe(b);
    long long u0, s0, u1, s1;
    stat_cpu(&u0, &s0);
    struct rusage r0, r1;
    getrusage(RUSAGE_SELF, &r0);
    pid_t c = fork();
    char x = 0;
    if (c == 0) {
        close(a[1]);
        while (read(a[0], &x, 1) == 1) {
            work(200);
            write(b[1], &x, 1);
        }
        _exit(0);
    }
    double t0 = now();
    while (now() - t0 < 1.5) {
        write(a[1], &x, 1);
        read(b[0], &x, 1);
        work(200);
    }
    close(a[1]);
    waitpid(c, NULL, 0);
    getrusage(RUSAGE_SELF, &r1);
    stat_cpu(&u1, &s1);
    double ut = (r1.ru_utime.tv_sec - r0.ru_utime.tv_sec) + (r1.ru_utime.tv_usec - r0.ru_utime.tv_usec) / 1e6;
    double st = (r1.ru_stime.tv_sec - r0.ru_stime.tv_sec) + (r1.ru_stime.tv_usec - r0.ru_stime.tv_usec) / 1e6;
    printf("getrusage: user %.2f s, system %.2f s; /proc/stat: user %lld, system %lld ticks\n", ut, st, u1 - u0, s1 - s0);
    check(ut + st > 0.3 && ut > 0.4 * (ut + st), "user work between blocking calls is user time (getrusage)");
    check(u1 - u0 > 0 && (u1 - u0) > 0.4 * ((u1 - u0) + (s1 - s0)), "and in /proc/stat");

    // 2. The page cache in /proc/meminfo
    const char *path = "/tmp/acct_test.dat";
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    static char buf[1 << 20];
    memset(buf, 'a', sizeof buf);
    for (int i = 0; i < 8; i++) write(fd, buf, sizeof buf);
    fsync(fd);
    lseek(fd, 0, SEEK_SET);
    while (read(fd, buf, sizeof buf) > 0) {
    }
    long cached = meminfo("Cached"), avail = meminfo("MemAvailable"), freek = meminfo("MemFree"), buffers = meminfo("Buffers");
    printf("Cached %ld kB, MemAvailable %ld kB, MemFree %ld kB, Buffers %ld kB\n", cached, avail, freek, buffers);
    check(cached >= 8 * 1024, "a file just read counts in Cached");
    check(buffers >= 0, "Buffers is present");
    check(avail >= freek, "MemAvailable includes what only the cache holds");
    close(fd);
    unlink(path);
    printf(fails ? "ACCT TEST FAILED (%d)\n" : "ACCT TEST PASSED\n", fails);
    return fails != 0;
}
