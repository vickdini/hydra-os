// pseudofs: /proc and /sys files served by linux-server (wave 7, Group 7-4).
//
// A path call under /proc or /sys that vfs-server serves is redirected to linux-server,
// which serves the files it knows (and sends the rest on to the kernel). This test reads
// each file two ways and compares them:
//   - by its path ("/proc/uptime"): vfs-server -> linux-server;
//   - relative to a descriptor of the /proc (or /sys/...) directory (openat(dirfd, "uptime")):
//     the directory is the kernel's, so the kernel's in-kernel copy answers.
// Fixed files must be equal byte for byte; changing ones (times, memory) must have the same
// shape. It also checks lseek/pread (a rewind reads fresh text), fstat, stat/lstat/statx,
// access, readlink of /proc/self, read-only opens, and files the kernel keeps (fd/, exe).
// With linux-server serving, fstat of a path-opened file shows st_dev 22 (proc's 0:22);
// "served=N" counts those (0 when everything goes to the kernel: lx.vfs=kernel, lx=kernel).
//
// gcc -O1 -w -pthread -o pseudofs pseudofs.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

static int fails, served;
#define CHECK(c, ...)                         \
    do {                                      \
        if (!(c)) {                           \
            printf("FAIL: " __VA_ARGS__);     \
            printf("\n");                     \
            fails++;                          \
        }                                     \
    } while (0)

static char a[1 << 18], b[1 << 18];

static int slurp(int fd, char *buf, int cap) {
    int n = 0, r;
    while (n < cap - 1 && (r = read(fd, buf + n, cap - 1 - n)) > 0) n += r;
    buf[n] = 0;
    return r < 0 ? -1 : n;
}

// Reads `name` by its path into a and relative to a descriptor of /proc (the kernel's: the
// in-kernel copy answers) into b; returns 0 when both worked. `dir` is under /proc.
static int both(const char *dir, const char *name, int *na, int *nb) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) == 0 && st.st_dev == 22) served++;
    *na = slurp(fd, a, sizeof a);
    close(fd);
    int d = open("/proc", O_RDONLY | O_DIRECTORY);
    if (d < 0) return -2;
    fd = openat(d, path + 6, O_RDONLY);
    close(d);
    if (fd < 0) return -3;
    *nb = slurp(fd, b, sizeof b);
    close(fd);
    return 0;
}

static void same(const char *dir, const char *name) {
    int na, nb;
    int r = both(dir, name, &na, &nb);
    CHECK(r == 0, "%s/%s: opened both ways (%d, errno %d)", dir, name, r, errno);
    if (r) return;
    CHECK(na >= 0 && nb >= 0, "%s/%s: read both ways (%d, %d)", dir, name, na, nb);
    if (na < 0 || nb < 0) return;
    CHECK(na == nb && memcmp(a, b, na) == 0, "%s/%s: same text (%d vs %d bytes)\n--- by path:\n%.300s\n--- by dirfd:\n%.300s", dir, name, na, nb, a, b);
}

static int lines(const char *s) {
    int n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

static int fields(const char *s) {
    int n = 0, in = 0;
    for (; *s && *s != '\n'; s++) {
        if (*s != ' ' && !in) n++;
        in = *s != ' ';
    }
    return n;
}

// The same lines, each starting with the same word (values may differ).
static void shape(const char *dir, const char *name) {
    int na, nb;
    int r = both(dir, name, &na, &nb);
    CHECK(r == 0, "%s/%s: opened both ways (%d)", dir, name, r);
    if (r) return;
    CHECK(na > 0 && nb > 0, "%s/%s: read both ways (%d, %d)", dir, name, na, nb);
    CHECK(lines(a) == lines(b), "%s/%s: %d lines vs %d", dir, name, lines(a), lines(b));
    char *p = a, *q = b;
    while (*p && *q) {
        size_t ka = strcspn(p, " :\t\n"), kb = strcspn(q, " :\t\n");
        CHECK(ka == kb && !strncmp(p, q, ka), "%s/%s: line starts '%.*s' vs '%.*s'", dir, name, (int)ka, p, (int)kb, q);
        CHECK(fields(p) == fields(q), "%s/%s: field count of '%.*s'", dir, name, (int)ka, p);
        p = strchr(p, '\n');
        q = strchr(q, '\n');
        if (!p || !q) break;
        p++, q++;
    }
}

static void *idle(void *x) {
    pause();
    return x;
}

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

// `pseudofs bench [N]`: median of 5 rounds of N calls, by path (linux-server when served)
// and through the kernel's /proc descriptor (the in-kernel copy), in microseconds per call.
static int bench(int n) {
    int d = open("/proc", O_RDONLY | O_DIRECTORY);
    struct stat st;
    char buf[4096];
    const char *names[] = {"stat /proc/self/stat", "stat /proc/uptime", "open+read+close /proc/self/stat", "open+read+close /proc/uptime", "stat /usr/bin/bash (pool)"};
    for (int k = 0; k < 5; k++) {
        double r[2][5];
        for (int round = 0; round < 5; round++) {
            for (int way = 0; way < 2; way++) {
                const char *path = k == 0 || k == 2 ? "/proc/self/stat" : k == 4 ? "/usr/bin/bash" : "/proc/uptime";
                double t0 = now_us();
                for (int i = 0; i < n; i++) {
                    if (k == 0 || k == 1 || k == 4) {
                        if (way == 0 || k == 4) stat(path, &st); else fstatat(d, path + 6, &st, 0);
                    } else {
                        int fd = way == 0 ? open(path, O_RDONLY) : openat(d, path + 6, O_RDONLY);
                        read(fd, buf, sizeof buf);
                        close(fd);
                    }
                }
                r[way][round] = (now_us() - t0) / n;
            }
        }
        for (int way = 0; way < 2; way++)
            for (int i = 0; i < 5; i++)
                for (int j = i + 1; j < 5; j++)
                    if (r[way][j] < r[way][i]) { double t = r[way][i]; r[way][i] = r[way][j]; r[way][j] = t; }
        printf("BENCH %-34s by path %7.2f us   via kernel dirfd %7.2f us\n", names[k], r[0][2], r[1][2]);
    }
    return 0;
}

// `pseudofs loop SECONDS`: opens, reads and stats served files for that long (for kill
// tests: `service kill vfs_server` meanwhile); prints the loops and the errors.
static int loop(int secs) {
    double end = now_us() + secs * 1e6;
    long loops = 0, errs = 0, lasterr = 0;
    struct stat st;
    char buf[4096];
    while (now_us() < end) {
        const char *p[] = {"/proc/self/stat", "/proc/uptime", "/proc/self/status", "/sys/devices/system/cpu/online"};
        for (int i = 0; i < 4; i++) {
            int fd = open(p[i], O_RDONLY);
            if (fd < 0 || read(fd, buf, sizeof buf) <= 0) errs++, lasterr = errno;
            if (fd >= 0) close(fd);
            if (stat(p[i], &st) != 0) errs++, lasterr = errno;
        }
        loops++;
    }
    printf("LOOP loops=%ld errors=%ld last_errno=%ld\n", loops, errs, lasterr);
    return errs != 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "bench")) return bench(argc > 2 ? atoi(argv[2]) : 2000);
    if (argc > 1 && !strcmp(argv[1], "loop")) return loop(argc > 2 ? atoi(argv[2]) : 30);
    char self[64];
    snprintf(self, sizeof self, "/proc/%d", getpid());
    pthread_t th;
    pthread_create(&th, 0, idle, 0);

    // ---- fixed text: byte for byte
    same("/proc", "version");
    same("/proc", "cpuinfo");
    same("/proc/sys/kernel", "shmmni");
    same("/proc/sys/kernel", "sem");
    same("/proc/sys/fs/inotify", "max_user_watches");
    same("/proc/sys/kernel/yama", "ptrace_scope");
    same("/proc/self", "comm");
    same("/proc/self", "cmdline");
    same(self, "comm");
    same(self, "cmdline");
    shape("/proc/self", "statm");
    // ---- changing text: the same shape
    shape("/proc", "uptime");
    shape("/proc", "loadavg");
    shape("/proc", "stat");
    shape("/proc", "meminfo");
    shape("/proc/self", "stat");
    shape("/proc/self", "status");
    shape("/proc/self", "maps");
    shape(self, "status");
    {
        char t[64];
        snprintf(t, sizeof t, "/proc/self/task/%ld", (long)syscall(SYS_gettid));
        shape(t, "stat");
        shape(t, "status");
        shape(t, "comm");
    }

    // ---- /sys/devices/system/cpu/{online,possible,present}: 0-(N-1), N = the processors
    {
        int fd = open("/proc/cpuinfo", O_RDONLY);
        slurp(fd, b, sizeof b);
        close(fd);
        int n = 0;
        for (char *p = b; (p = strstr(p, "processor\t:")); p++) n++;
        char want[32];
        if (n > 1) snprintf(want, sizeof want, "0-%d\n", n - 1); else snprintf(want, sizeof want, "0\n");
        const char *f[] = {"online", "possible", "present"};
        for (int i = 0; i < 3; i++) {
            char path[64];
            snprintf(path, sizeof path, "/sys/devices/system/cpu/%s", f[i]);
            fd = open(path, O_RDONLY);
            int k = slurp(fd, a, sizeof a);
            close(fd);
            CHECK(k > 0 && !strcmp(a, want), "%s: '%s' (want '%s')", path, a, want);
        }
    }

    // ---- /proc/self/stat: 52 fields, our pid and comm
    {
        int fd = open("/proc/self/stat", O_RDONLY);
        int n = slurp(fd, a, sizeof a);
        close(fd);
        char want[64];
        snprintf(want, sizeof want, "%d (pseudofs) ", getpid());
        CHECK(n > 0 && !strncmp(a, want, strlen(want)), "self/stat starts with '%s': %.60s", want, a);
        CHECK(fields(a) == 52, "self/stat has 52 fields (%d)", fields(a));
        fd = open("/proc/self/status", O_RDONLY);
        slurp(fd, a, sizeof a);
        close(fd);
        CHECK(strstr(a, "Name:\tpseudofs\n") != 0, "self/status Name (%.40s)", a);
        char tg[32];
        snprintf(tg, sizeof tg, "\nTgid:\t%d\n", getpid());
        CHECK(strstr(a, tg) != 0, "self/status Tgid");
    }

    // ---- reads in pieces, lseek, pread, a rewind reads fresh text
    {
        int fd = open("/proc/version", O_RDONLY);
        char x[8], y[300];
        CHECK(read(fd, x, 5) == 5 && !memcmp(x, "Linux", 5), "read in pieces");
        CHECK(read(fd, x, 1) == 1 && x[0] == ' ', "the next piece follows");
        CHECK(lseek(fd, 0, SEEK_CUR) == 6, "lseek(SEEK_CUR) = 6 (%ld, errno %d)", (long)lseek(fd, 0, SEEK_CUR), errno);
        CHECK(lseek(fd, 2, SEEK_SET) == 2, "lseek(SEEK_SET, 2) (errno %d)", errno);
        CHECK(read(fd, x, 3) == 3 && !memcmp(x, "nux", 3), "read after lseek");
        CHECK(pread(fd, x, 4, 6) == 4 && !memcmp(x, "vers", 4), "pread at 6 (errno %d)", errno);
        CHECK(read(fd, x, 1) == 1 && x[0] == ' ', "pread does not move the position");
        int n = pread(fd, y, sizeof y, 0);
        CHECK(n > 20 && y[n - 1] == '\n', "pread of all (%d)", n);
        CHECK(lseek(fd, -1, SEEK_SET) == -1 && errno == EINVAL, "lseek before the start: EINVAL");
        CHECK(lseek(fd, 1000, SEEK_SET) == 1000 && read(fd, x, 1) == 0, "read past the end: 0");
        CHECK(write(fd, "x", 1) == -1 && errno == EBADF, "write to a read-only /proc file: EBADF (errno %d)", errno);
        close(fd);
        fd = open("/proc/uptime", O_RDONLY);
        n = read(fd, y, sizeof y - 1);
        y[n > 0 ? n : 0] = 0;
        double u1 = atof(y);
        usleep(300000);
        n = read(fd, y, sizeof y - 1);
        CHECK(n == 0, "uptime: the text is made once, then EOF (%d)", n);
        CHECK(lseek(fd, 0, SEEK_SET) == 0, "rewind");
        n = read(fd, y, sizeof y - 1);
        y[n > 0 ? n : 0] = 0;
        double u2 = atof(y);
        CHECK(u2 >= u1 + 0.2, "a rewind reads fresh text (%.2f -> %.2f)", u1, u2);
        n = pread(fd, y, sizeof y - 1, 0);
        CHECK(n > 0, "pread at 0");
        close(fd);
    }

    // ---- fstat, stat, lstat, statx, access, readlink
    {
        struct stat s1, s2;
        int fd = open("/proc/loadavg", O_RDONLY);
        CHECK(fstat(fd, &s1) == 0 && S_ISREG(s1.st_mode) && (s1.st_mode & 0777) == 0444, "fstat: a read-only regular file (0%o)", s1.st_mode);
        CHECK(stat("/proc/loadavg", &s2) == 0 && S_ISREG(s2.st_mode), "stat");
        if (s1.st_dev == 22) {
            CHECK(s2.st_dev == s1.st_dev && s2.st_ino == s1.st_ino, "stat and fstat agree (dev %lu/%lu ino %lu/%lu)", s2.st_dev, s1.st_dev, s2.st_ino, s1.st_ino);
        }
        close(fd);
        CHECK(lstat("/proc/self", &s1) == 0 && S_ISLNK(s1.st_mode), "lstat(/proc/self) is a link");
        CHECK(stat("/proc/self", &s1) == 0 && S_ISDIR(s1.st_mode), "stat(/proc/self) is a directory");
        CHECK(fstatat(AT_FDCWD, "/proc/meminfo", &s1, 0) == 0 && S_ISREG(s1.st_mode), "newfstatat");
        struct statx sx;
        CHECK(statx(AT_FDCWD, "/proc/stat", 0, STATX_BASIC_STATS, &sx) == 0 && S_ISREG(sx.stx_mode), "statx");
        CHECK(access("/proc/self/status", R_OK) == 0, "access");
        CHECK(faccessat(AT_FDCWD, "/proc/uptime", F_OK, 0) == 0, "faccessat");
        char l[64], want[64];
        int n = readlink("/proc/self", l, sizeof l - 1);
        l[n > 0 ? n : 0] = 0;
        snprintf(want, sizeof want, "%d", getpid());
        CHECK(!strcmp(l, want), "readlink(/proc/self) = %s (%s)", l, want);
        n = readlinkat(AT_FDCWD, "/proc/thread-self", l, sizeof l - 1);
        l[n > 0 ? n : 0] = 0;
        snprintf(want, sizeof want, "%d/task/%ld", getpid(), (long)syscall(SYS_gettid));
        CHECK(!strcmp(l, want), "readlink(/proc/thread-self) = %s (%s)", l, want);
        CHECK(readlink("/proc/self", l, 0) == -1 && errno == EINVAL, "readlink with size 0: EINVAL");
        CHECK(readlink("/proc/self", l, 2) == (getpid() > 9 ? 2 : 1), "readlink cut to the buffer");
    }

    // ---- what the kernel keeps answering
    {
        char l[512];
        CHECK(readlink("/proc/self/exe", l, sizeof l) > 0, "readlink(/proc/self/exe)");
        int fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
        CHECK(fd >= 0, "open(/proc/self/fd) as a directory");
        close(fd);
        CHECK(open("/proc/999999/stat", O_RDONLY) == -1, "a process that does not exist");
        CHECK(open("/proc/self/../self/comm", O_RDONLY) >= 0, ".. inside /proc");
        struct stat st;
        CHECK(stat("/proc/mounts", &st) == 0, "stat(/proc/mounts)");
        fd = open("/proc/self/mountinfo", O_RDONLY);
        CHECK(fd >= 0 && slurp(fd, a, sizeof a) > 0, "read /proc/self/mountinfo");
        close(fd);
        fd = open("/dev/null", O_RDWR);
        CHECK(fd >= 0 && write(fd, "x", 1) == 1, "/dev/null");
        close(fd);
    }

    // ---- many opens and closes (slots are given back)
    for (int i = 0; i < 3000; i++) {
        int fd = open("/proc/self/stat", O_RDONLY);
        if (fd < 0) {
            CHECK(0, "open %d failed (errno %d)", i, errno);
            break;
        }
        close(fd);
    }

    printf("PSEUDOFS %s fails=%d served=%d\n", fails ? "FAIL" : "PASS", fails, served);
    return fails != 0;
}
