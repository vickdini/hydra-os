/* zfsbench: write-heavy file system micro-benchmarks on the pool (wave 8, Group Z: the
 * intent log's cost). Each test runs a loop five times in a fresh directory and prints
 *   BENCH <name> min <ns> med <ns> max <ns> ns/op (<iterations per run>)
 * like tests/linux/lxbench.c. Optional arguments: the directory (default /tmp/zb), a divisor
 * of the iteration counts (default 1), then the tests to run (default: all).
 *
 * Build (WSL): gcc -O1 -w -pthread tests/linux/zfsbench.c -o esp/bin/zfsbench.elf
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define REPS 5

static char base[256];
static char d[300];
static char blk[65536];

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static void fresh(int rep) {
    char cmd[400];
    snprintf(d, sizeof d, "%s/r%d", base, rep);
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", d);
    system(cmd);
    mkdir(d, 0755);
}

static void name(char *p, const char *what, long i) { snprintf(p, 400, "%s/%s%ld", d, what, i); }

/* create + 4 KiB write + close (the files stay for the unlink test) */
static double b_create_4k(long n) {
    char p[400];
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        name(p, "f", i);
        int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0644);
        write(fd, blk, 4096);
        close(fd);
    }
    return (double)(now() - t0) / n;
}

static double b_create_unlink(long n) {
    char p[400];
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        name(p, "c", i);
        close(open(p, O_CREAT | O_EXCL | O_WRONLY, 0644));
        unlink(p);
    }
    return (double)(now() - t0) / n;
}

static double b_unlink(long n) {
    char p[400];
    for (long i = 0; i < n; i++) {
        name(p, "u", i);
        close(open(p, O_CREAT | O_WRONLY, 0644));
    }
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        name(p, "u", i);
        unlink(p);
    }
    return (double)(now() - t0) / n;
}

static double b_mkdir_rmdir(long n) {
    char p[400];
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        name(p, "d", i);
        mkdir(p, 0755);
        rmdir(p);
    }
    return (double)(now() - t0) / n;
}

static double b_rename(long n) {
    char a[400], b[400];
    name(a, "ra", 0);
    name(b, "rb", 0);
    close(open(a, O_CREAT | O_WRONLY, 0644));
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        if (i & 1) rename(b, a);
        else rename(a, b);
    }
    return (double)(now() - t0) / n;
}

static double b_chmod(long n) {
    char a[400];
    name(a, "m", 0);
    close(open(a, O_CREAT | O_WRONLY, 0644));
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) chmod(a, i & 1 ? 0600 : 0644);
    return (double)(now() - t0) / n;
}

static double b_append_64k(long n) {
    char a[400];
    name(a, "big", 0);
    int fd = open(a, O_CREAT | O_WRONLY | O_APPEND, 0644);
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) write(fd, blk, sizeof blk);
    double r = (double)(now() - t0) / n;
    close(fd);
    unlink(a);
    return r;
}

static double b_write_fsync_4k(long n) {
    char a[400];
    name(a, "sync", 0);
    int fd = open(a, O_CREAT | O_WRONLY, 0644);
    uint64_t t0 = now();
    for (long i = 0; i < n; i++) {
        pwrite(fd, blk, 4096, (i % 64) * 4096);
        fsync(fd);
    }
    double r = (double)(now() - t0) / n;
    close(fd);
    return r;
}

struct test {
    const char *name;
    double (*fn)(long);
    long iters;
};

static struct test tests[] = {
    {"create_4k", b_create_4k, 2000},
    {"create_unlink", b_create_unlink, 2000},
    {"unlink", b_unlink, 2000},
    {"mkdir_rmdir", b_mkdir_rmdir, 2000},
    {"rename", b_rename, 5000},
    {"chmod", b_chmod, 5000},
    {"append_64k", b_append_64k, 512},
    {"write_fsync_4k", b_write_fsync_4k, 100},
};

int main(int argc, char **argv) {
    snprintf(base, sizeof base, "%s", argc > 1 ? argv[1] : "/tmp/zb");
    mkdir(base, 0755);
    memset(blk, 'z', sizeof blk);
    long div = argc > 2 ? atol(argv[2]) : 1;
    if (div < 1) div = 1;
    for (unsigned k = 0; k < sizeof tests / sizeof tests[0]; k++) {
        struct test *t = &tests[k];
        int want = argc <= 3;
        for (int a = 3; a < argc; a++) want |= !strcmp(argv[a], t->name);
        if (!want) continue;
        double r[REPS];
        for (int rep = 0; rep < REPS; rep++) {
            fresh(rep);
            r[rep] = t->fn(t->iters / div > 0 ? t->iters / div : 1);
        }
        qsort(r, REPS, sizeof r[0], cmp);
        printf("BENCH %s min %.1f med %.1f max %.1f ns/op (%ld)\n", t->name, r[0], r[REPS / 2], r[REPS - 1], t->iters / div > 0 ? t->iters / div : 1);
        fflush(stdout);
    }
    // Only what this run made: its r0..r4 directories, then the directory itself if empty
    for (int rep = 0; rep < REPS; rep++) {
        char cmd[400];
        snprintf(cmd, sizeof cmd, "rm -rf '%s/r%d'", base, rep);
        system(cmd);
    }
    rmdir(base);
    printf("zfsbench: done\n");
    return 0;
}
