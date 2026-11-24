/* vfsbench: VFS-shaped system call micro-benchmarks for the VFS design (microkernel wave 5,
 * group 16, step 0 for wave 7; docs/vfs-design.md). Each test runs a loop five times and
 * prints
 *   BENCH <name> min <ns> med <ns> max <ns> ns/op (<iterations per run>)
 * like tests/linux/lxbench.c. Optional arguments name the tests to run (default: all).
 *
 * The "*_stub" tests call operations 0x1605..0x1607 of Hydra's test call (0x6710), which
 * only the group 16 prototype build answers (tools/vfsbench/prototype.patch): a stat, a
 * getdents64 and a read answered by linux-server, with the copy-in/copy-out table. On any
 * other kernel they are skipped.
 *
 * Build (WSL): gcc -O1 -w -pthread tests/linux/vfsbench.c -o esp/bin/vfsbench.elf
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define REPS 5
#define LX_NULL_NR 0x6710
#define OP_STAT 0x1605
#define OP_DENTS 0x1606
#define OP_READ 0x1607

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef double (*bench_fn)(long n);
static char buf[65536];
static int usrbin = -1, smalldir = -1, bashfd = -1;

#define LOOP(n, body) do { uint64_t t_ = now(); for (long i = 0; i < (n); i++) { body; } return (double)(now() - t_) / (n); } while (0)

/* --- baselines --- */
static double b_getpgrp(long n) { LOOP(n, syscall(SYS_getpgrp)); }
static double b_lx_null(long n) { LOOP(n, syscall(LX_NULL_NR, 0)); }

/* --- path calls --- */
static double b_stat_abs(long n) { struct stat st; LOOP(n, stat("/usr/bin/bash", &st)); }
static double b_lstat_abs(long n) { struct stat st; LOOP(n, lstat("/usr/bin/bash", &st)); }
static double b_fstatat_rel(long n) { struct stat st; LOOP(n, fstatat(usrbin, "bash", &st, AT_SYMLINK_NOFOLLOW)); }
static double b_stat_enoent(long n) { struct stat st; LOOP(n, stat("/usr/bin/no-such-file", &st)); }
static double b_statx_abs(long n) {
    char sx[256];
    LOOP(n, syscall(SYS_statx, AT_FDCWD, "/usr/bin/bash", 0, 0x7ff, sx));
}
static double b_access(long n) { LOOP(n, access("/usr/bin/bash", X_OK)); }
static double b_readlink(long n) { LOOP(n, readlink("/tmp/vfsb.link", buf, 4096)); }
static double b_open_close_rel(long n) { LOOP(n, close(openat(usrbin, "bash", O_RDONLY | O_CLOEXEC))); }
static double b_open_dir_close(long n) { /* what find does per directory, before reading it */
    LOOP(n, close(open("/usr/share", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)));
}
static double b_proc_stat_read(long n) { /* a pseudo file: open, read, close /proc/self/stat */
    LOOP(n, { int f = open("/proc/self/stat", O_RDONLY); read(f, buf, 4096); close(f); });
}
/* wave10 G7b-2: more /proc shapes (ps, top, free) */
static double b_proc_status_read(long n) { LOOP(n, { int f = open("/proc/self/status", O_RDONLY); read(f, buf, 4096); close(f); }); }
static double b_proc_meminfo_read(long n) { LOOP(n, { int f = open("/proc/meminfo", O_RDONLY); read(f, buf, 4096); close(f); }); }
static double b_proc_sysstat_read(long n) { LOOP(n, { int f = open("/proc/stat", O_RDONLY); read(f, buf, 4096); close(f); }); }
static double b_proc_cmdline_read(long n) { LOOP(n, { int f = open("/proc/self/cmdline", O_RDONLY); read(f, buf, 4096); close(f); }); }
static int procstat_fd = -1;
static double b_proc_stat_rewind(long n) { /* what top does with /proc/stat: rewind, read */
    LOOP(n, { lseek(procstat_fd, 0, SEEK_SET); read(procstat_fd, buf, 4096); });
}
static double b_proc_stat_pread0(long n) { LOOP(n, pread(procstat_fd, buf, 4096, 0)); }
static double b_proc_fd_read2(long n) { /* a read past the start of an open /proc file: no new text */
    LOOP(n, pread(procstat_fd, buf, 64, 8));
}

/* --- descriptor calls --- */
static double b_fstat(long n) { struct stat st; LOOP(n, fstat(bashfd, &st)); }
static double b_fcntl_getfd(long n) { LOOP(n, fcntl(bashfd, F_GETFD)); }
static double b_dup_close(long n) { LOOP(n, close(dup(bashfd))); }
static double b_lseek(long n) { LOOP(n, lseek(bashfd, 0, SEEK_SET)); }
static double b_pread_4k(long n) { LOOP(n, pread(bashfd, buf, 4096, 0)); }
static double b_pread_256(long n) { LOOP(n, pread(bashfd, buf, 256, 0)); }
static double b_getdents_20(long n) { /* list a 20-entry directory: lseek + getdents64 (all) + getdents64 (end) */
    LOOP(n, { lseek(smalldir, 0, SEEK_SET); syscall(SYS_getdents64, smalldir, buf, 32768); syscall(SYS_getdents64, smalldir, buf, 32768); });
}
static double b_getdents_one(long n) { /* one getdents64 that returns the 20 entries */
    uint64_t t = 0;
    for (long i = 0; i < n; i++) {
        lseek(smalldir, 0, SEEK_SET);
        uint64_t a = now();
        syscall(SYS_getdents64, smalldir, buf, 32768);
        t += now() - a;
    }
    return (double)t / n;
}

/* --- the prototype's stubs (linux-server answers; skipped elsewhere) --- */
static double b_stat_stub(long n) { char st[144]; LOOP(n, syscall(LX_NULL_NR, OP_STAT, "/usr/bin/bash", st)); }
static double b_dents_stub_1k(long n) { LOOP(n, syscall(LX_NULL_NR, OP_DENTS, buf, 1024, 600)); }
static double b_dents_stub_32k(long n) { LOOP(n, syscall(LX_NULL_NR, OP_DENTS, buf, 32768, 600)); }
static double b_read_stub_256(long n) { LOOP(n, syscall(LX_NULL_NR, OP_READ, buf, 256)); }
static double b_read_stub_4k(long n) { LOOP(n, syscall(LX_NULL_NR, OP_READ, buf, 4096)); }

struct test { const char *name; bench_fn fn; long iters; int stub; };
static struct test tests[] = {
    {"getpgrp", b_getpgrp, 200000, 0},
    {"lx_null", b_lx_null, 200000, 0},
    {"stat_abs", b_stat_abs, 50000, 0},
    {"lstat_abs", b_lstat_abs, 50000, 0},
    {"fstatat_rel", b_fstatat_rel, 50000, 0},
    {"stat_enoent", b_stat_enoent, 50000, 0},
    {"statx_abs", b_statx_abs, 50000, 0},
    {"access", b_access, 50000, 0},
    {"readlink", b_readlink, 50000, 0},
    {"open_close_rel", b_open_close_rel, 20000, 0},
    {"open_dir_close", b_open_dir_close, 20000, 0},
    {"proc_stat_read", b_proc_stat_read, 10000, 0},
    {"proc_status_read", b_proc_status_read, 10000, 0},
    {"proc_meminfo_read", b_proc_meminfo_read, 10000, 0},
    {"proc_sysstat_read", b_proc_sysstat_read, 10000, 0},
    {"proc_cmdline_read", b_proc_cmdline_read, 10000, 0},
    {"proc_stat_rewind", b_proc_stat_rewind, 10000, 0},
    {"proc_stat_pread0", b_proc_stat_pread0, 10000, 0},
    {"proc_fd_read2", b_proc_fd_read2, 100000, 0},
    {"fstat", b_fstat, 100000, 0},
    {"fcntl_getfd", b_fcntl_getfd, 200000, 0},
    {"dup_close", b_dup_close, 100000, 0},
    {"lseek", b_lseek, 200000, 0},
    {"pread_256", b_pread_256, 100000, 0},
    {"pread_4k", b_pread_4k, 50000, 0},
    {"getdents_20", b_getdents_20, 20000, 0},
    {"getdents_one", b_getdents_one, 20000, 0},
    {"stat_stub", b_stat_stub, 100000, 1},
    {"dents_stub_1k", b_dents_stub_1k, 100000, 1},
    {"dents_stub_32k", b_dents_stub_32k, 100000, 1},
    {"read_stub_256", b_read_stub_256, 100000, 1},
    {"read_stub_4k", b_read_stub_4k, 100000, 1},
};

static int stubs_ok(void) {
    char st[144];
    memset(st, 0, sizeof st);
    long r = syscall(LX_NULL_NR, OP_STAT, "/usr/bin/bash", st);
    long r2 = syscall(LX_NULL_NR, OP_DENTS, buf, 32768, 600);
    return r == 0 && st[24] == (char)0xa4 && r2 == 600;
}

int main(int argc, char **argv) {
    usrbin = open("/usr/bin", O_RDONLY | O_DIRECTORY);
    bashfd = open("/usr/bin/bash", O_RDONLY);
    procstat_fd = open("/proc/stat", O_RDONLY);
    mkdir("/tmp/vfsb.dir", 0755);
    for (int i = 0; i < 20; i++) {
        char p[64];
        snprintf(p, sizeof p, "/tmp/vfsb.dir/file-%02d", i);
        close(open(p, O_CREAT | O_WRONLY, 0644));
    }
    smalldir = open("/tmp/vfsb.dir", O_RDONLY | O_DIRECTORY);
    unlink("/tmp/vfsb.link");
    symlink("/usr/bin/bash", "/tmp/vfsb.link");
    if (usrbin < 0 || bashfd < 0 || smalldir < 0) {
        printf("vfsbench: setup failed (%d %d %d)\n", usrbin, bashfd, smalldir);
        return 1;
    }
    int stubs = stubs_ok();
    printf("vfsbench: prototype stubs %s\n", stubs ? "answered (group 16 prototype build)" : "not available: skipped");
    for (size_t k = 0; k < sizeof tests / sizeof tests[0]; k++) {
        struct test *t = &tests[k];
        if (argc > 1) {
            int want = 0;
            for (int a = 1; a < argc; a++) want |= !strcmp(argv[a], t->name);
            if (!want) continue;
        }
        if (t->stub && !stubs) continue;
        double r[REPS];
        t->fn(t->iters / 10); /* warm */
        for (int i = 0; i < REPS; i++) r[i] = t->fn(t->iters);
        qsort(r, REPS, sizeof r[0], cmp);
        printf("BENCH %s min %.1f med %.1f max %.1f ns/op (%ld)\n", t->name, r[0], r[REPS / 2], r[REPS - 1], t->iters);
        fflush(stdout);
    }
    printf("vfsbench: done\n");
    return 0;
}
