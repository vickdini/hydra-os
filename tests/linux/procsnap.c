/* procsnap: /proc files served by lx-proc as kernel-held snapshots (wave 10, Group 7b-2).
 *
 *   procsnap            the checks below; prints "PROCSNAP PASS" or "FAIL ..." lines
 *   procsnap hold SECS  keeps /proc/self/status and /proc/stat open and, every 50 ms,
 *                       reads them (pread past 0, a rewind + read) for SECS seconds while
 *                       lx-proc may be killed; prints counts and "HOLD PASS" when no call
 *                       failed except EIO/EINTR within a restart
 *   procsnap top SECS   what top does: /proc/stat and /proc/meminfo rewound and read, and
 *                       every /proc/<pid>/stat opened, read and closed, in a loop
 *
 * Build (WSL): gcc -O1 -w -pthread tests/linux/procsnap.c -o esp/bin/procsnap.elf
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); fails++; } } while (0)

static char buf[1 << 16], buf2[1 << 16];

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static long slurp(const char *p, char *b, size_t n) {
    int f = open(p, O_RDONLY | O_CLOEXEC);
    if (f < 0) return -errno;
    long t = 0, r;
    while ((r = read(f, b + t, n - 1 - t)) > 0) t += r;
    close(f);
    b[t] = 0;
    return t;
}

static void checks(void) {
    /* reads, positions, rewinds */
    int f = open("/proc/stat", O_RDONLY);
    CHECK(f >= 0, "open /proc/stat");
    long n = read(f, buf, 16);
    CHECK(n == 16 && !memcmp(buf, "cpu ", 4), "first read %ld", n);
    CHECK(lseek(f, 0, SEEK_CUR) == 16, "position after read");
    long m = read(f, buf + 16, sizeof buf - 17);
    CHECK(m > 0, "second read");
    buf[16 + m] = 0;
    CHECK(strstr(buf, "btime ") != NULL, "btime line");
    CHECK(read(f, buf2, 100) == 0, "read at the end");
    off_t end = lseek(f, 0, SEEK_END);
    CHECK(end == 16 + m, "SEEK_END %ld", (long)end);
    CHECK(lseek(f, -4, SEEK_END) == end - 4, "SEEK_END -4");
    CHECK(lseek(f, -1, SEEK_SET) == -1 && errno == EINVAL, "negative seek");
    CHECK(lseek(f, 0, SEEK_SET) == 0, "rewind");
    n = read(f, buf2, sizeof buf2 - 1);
    CHECK(n > 0 && !memcmp(buf2, "cpu ", 4), "read after rewind");
    CHECK(pread(f, buf2, 4, 0) == 4 && !memcmp(buf2, "cpu ", 4), "pread at 0");
    CHECK(pread(f, buf2, 4, 1) == 4 && !memcmp(buf2, "pu  ", 3), "pread at 1");
    CHECK(lseek(f, 0, SEEK_CUR) == n, "pread keeps the position");
    /* dup shares the position */
    int g = dup(f);
    CHECK(lseek(g, 5, SEEK_SET) == 5 && lseek(f, 0, SEEK_CUR) == 5, "dup shares the position");
    close(g);
    /* fstat, write, mmap, the fd link */
    struct stat st;
    CHECK(fstat(f, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0444, "fstat mode %o", st.st_mode);
    struct stat st2;
    CHECK(stat("/proc/stat", &st2) == 0 && st2.st_ino == st.st_ino && st2.st_dev == st.st_dev, "fstat matches stat");
    CHECK(write(f, "x", 1) == -1 && errno == EBADF, "write is EBADF");
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f, 0) == MAP_FAILED, "mmap fails");
    char link[256], want[64];
    snprintf(want, sizeof want, "/proc/self/fd/%d", f);
    ssize_t l = readlink(want, link, sizeof link - 1);
    CHECK(l > 0 && (link[l] = 0, !strcmp(link, "/proc/stat")), "fd link %s", l > 0 ? link : "?");
    close(f);
    /* opening for writing: refused for users (lx-proc: EACCES; the kernel's copy lets the
     * open through, but no write is taken) */
    g = open("/proc/stat", O_RDWR);
    if (geteuid() != 0) CHECK(g < 0 && errno == EACCES, "a user's open for writing: EACCES");
    else {
        /* root: the open works (as Linux), writes fail with EIO, reads work */
        CHECK(g >= 0, "root's open for writing");
        CHECK(write(g, "x", 1) == -1 && errno == EIO, "root's write: EIO");
        CHECK(read(g, buf2, 4) == 4, "read of a read-write open");
        close(g);
    }
    g = open("/proc/stat", O_WRONLY | O_TRUNC);
    if (geteuid() == 0 && g >= 0) {
        CHECK(read(g, buf2, 4) == -1 && errno == EBADF, "read of a write-only open: EBADF");
        close(g);
    }

    /* the caller's files: self is named by pid */
    f = open("/proc/self/status", O_RDONLY);
    snprintf(want, sizeof want, "/proc/self/fd/%d", f);
    l = readlink(want, link, sizeof link - 1);
    char pidpath[64];
    snprintf(pidpath, sizeof pidpath, "/proc/%d/status", getpid());
    CHECK(l > 0 && (link[l] = 0, !strcmp(link, pidpath)), "self named by pid: %s", l > 0 ? link : "?");
    n = read(f, buf, sizeof buf - 1);
    buf[n > 0 ? n : 0] = 0;
    CHECK(strstr(buf, "Name:\tprocsnap") != NULL || strstr(buf, "Name:\t") != NULL, "status Name");
    close(f);

    /* environ (0400, ours) and limits */
    setenv("PROCSNAP_MARK", "hello", 1);
    n = slurp("/proc/self/environ", buf, sizeof buf);
    CHECK(n > 0, "environ read %ld", n);
    int found = 0;
    for (long i = 0; i < n; i += strlen(buf + i) + 1)
        if (!strncmp(buf + i, "PATH=", 5) || !strncmp(buf + i, "HOME=", 5)) found = 1;
    CHECK(found, "environ has PATH or HOME");
    CHECK(stat("/proc/self/environ", &st) == 0 && (st.st_mode & 0777) == 0400, "environ mode %o", st.st_mode);
    n = slurp("/proc/self/limits", buf, sizeof buf);
    CHECK(n > 0 && strstr(buf, "Max open files") && !strncmp(buf, "Limit ", 6), "limits");
    n = slurp("/proc/1/environ", buf, sizeof buf);
    if (getuid() != 0) CHECK(n == -EACCES || n == -ENOENT, "another user's environ refused: %ld", n);

    /* a pinned process: its file fails with ESRCH on a rewind once it is gone */
    int pfd[2];
    pipe(pfd);
    pid_t c = fork();
    if (c == 0) {
        char x;
        read(pfd[0], &x, 1);
        _exit(0);
    }
    snprintf(pidpath, sizeof pidpath, "/proc/%d/stat", c);
    f = open(pidpath, O_RDONLY);
    CHECK(f >= 0, "open child stat");
    CHECK(read(f, buf, sizeof buf) > 0, "read child stat");
    CHECK(lseek(f, 0, SEEK_SET) == 0, "rewind while alive");
    write(pfd[1], "x", 1);
    waitpid(c, NULL, 0);
    CHECK(pread(f, buf, 16, 2) == 16, "old text still readable after exit");
    errno = 0;
    /* (lseek always works; the read after it makes the text again and reports ESRCH) */
    CHECK(lseek(f, 0, SEEK_SET) == 0, "rewind after exit works");
    errno = 0;
    CHECK(read(f, buf, 16) == -1 && errno == ESRCH, "read after the rewind is ESRCH");
    close(f);
    CHECK(open(pidpath, O_RDONLY) < 0, "open of a gone process fails");

    /* fork: the child reads the same open file */
    f = open("/proc/uptime", O_RDONLY);
    c = fork();
    if (c == 0) _exit(read(f, buf, 3) == 3 ? 0 : 1);
    int s;
    waitpid(c, &s, 0);
    CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0, "child reads");
    CHECK(lseek(f, 0, SEEK_CUR) == 3, "child moved the shared position");
    close(f);

    /* process directories: owned by the process's effective ids; task/ counts threads */
    snprintf(pidpath, sizeof pidpath, "/proc/%d", getpid());
    CHECK(stat(pidpath, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && st.st_gid == getegid(), "pid dir owner %u", st.st_uid);
    CHECK(stat("/proc/self", &st2) == 0 && S_ISDIR(st2.st_mode) && st2.st_uid == geteuid(), "/proc/self followed");
    CHECK(lstat("/proc/self", &st2) == 0 && S_ISLNK(st2.st_mode), "/proc/self is a link");
    CHECK(stat("/proc/self/task", &st2) == 0 && st2.st_nlink >= 3, "task nlink %lu", (unsigned long)st2.st_nlink);
    CHECK(access(pidpath, R_OK | X_OK) == 0, "pid dir access");
    CHECK(stat("/proc/999999999", &st2) == -1 && errno == ENOENT, "missing pid dir");

    /* a process that is not dumpable: its environ and maps are hidden from its user (not
     * from root, which holds CAP_SYS_PTRACE) */
    int p2[2], q2[2];
    pipe(p2);
    pipe(q2);
    c = fork();
    if (c == 0) {
        char x;
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        write(q2[1], "r", 1);
        read(p2[0], &x, 1);
        _exit(0);
    }
    {
        char x;
        read(q2[0], &x, 1);
    }
    snprintf(pidpath, sizeof pidpath, "/proc/%d/environ", c);
    long ne = slurp(pidpath, buf, sizeof buf);
    snprintf(pidpath, sizeof pidpath, "/proc/%d/maps", c);
    long nm = slurp(pidpath, buf, sizeof buf);
    if (geteuid() != 0) {
        CHECK(ne == -EACCES, "undumpable environ refused: %ld", ne);
        CHECK(nm == -EACCES || nm == -EPERM || nm == -ENOENT, "undumpable maps refused: %ld", nm);
    } else {
        CHECK(ne >= 0 && nm > 0, "root reads an undumpable process: %ld %ld", ne, nm);
    }
    write(p2[1], "x", 1);
    waitpid(c, NULL, 0);

    /* root only: rights are the opener's (a rewind after setuid keeps working), and another
     * user's access(R_OK) of root's environ is refused */
    if (geteuid() == 0) {
        pid_t me = getpid();
        c = fork();
        if (c == 0) {
            char pp[64];
            snprintf(pp, sizeof pp, "/proc/%d/environ", me);
            int e = open(pp, O_RDONLY);
            if (e < 0 || setgid(1000) || setuid(1000)) _exit(2);
            if (lseek(e, 0, SEEK_SET) != 0 || read(e, buf, sizeof buf) <= 0) _exit(3);
            if (pread(e, buf, 16, 0) <= 0) _exit(4);
            if (open(pp, O_RDONLY) >= 0 || errno != EACCES) _exit(5);
            if (access(pp, R_OK) == 0 || errno != EACCES) _exit(6);
            _exit(0);
        }
        waitpid(c, &s, 0);
        CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0, "opener's rights after setuid (child rc %d)", WIFEXITED(s) ? WEXITSTATUS(s) : -1);
    }

    /* the version file is fixed text */
    CHECK(slurp("/proc/version", buf, sizeof buf) > 0 && !strncmp(buf, "Linux version", 13), "version");
}

static int hold(int secs) {
    int st = open("/proc/self/status", O_RDONLY), ps = open("/proc/stat", O_RDONLY);
    if (st < 0 || ps < 0) { printf("FAIL open\n"); return 1; }
    long ok = 0, eio = 0, bad = 0;
    double end = now() + secs;
    while (now() < end) {
        long a = pread(st, buf, 64, 1);
        long b = lseek(ps, 0, SEEK_SET);
        long c = b == 0 ? read(ps, buf2, sizeof buf2) : -1;
        if (a > 0 && b == 0 && c > 0) ok++;
        else if (errno == EIO || errno == EINTR) eio++;
        else { bad++; printf("bad: pread %ld seek %ld read %ld errno %d\n", a, b, c, errno); }
        usleep(50000);
    }
    printf("hold: ok %ld eio %ld bad %ld\n", ok, eio, bad);
    if (!bad && ok > 0) printf("HOLD PASS\n");
    return bad != 0;
}

static int top(int secs) {
    int ps = open("/proc/stat", O_RDONLY), mi = open("/proc/meminfo", O_RDONLY);
    long rounds = 0, files = 0, errs = 0;
    double end = now() + secs;
    while (now() < end) {
        if (lseek(ps, 0, SEEK_SET) != 0 || read(ps, buf, sizeof buf) <= 0) errs++;
        if (lseek(mi, 0, SEEK_SET) != 0 || read(mi, buf, sizeof buf) <= 0) errs++;
        DIR *d = opendir("/proc");
        struct dirent *e;
        while (d && (e = readdir(d))) {
            if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
            char p[64];
            snprintf(p, sizeof p, "/proc/%s/stat", e->d_name);
            if (slurp(p, buf, sizeof buf) > 0) files++;
        }
        if (d) closedir(d);
        rounds++;
    }
    printf("top: rounds %ld files %ld errors %ld\n", rounds, files, errs);
    if (!errs && rounds > 0) printf("TOP PASS\n");
    return errs != 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && !strcmp(argv[1], "hold")) return hold(atoi(argv[2]));
    if (argc > 2 && !strcmp(argv[1], "top")) return top(atoi(argv[2]));
    /* the kernel's own copy of /proc (lx.proc=kernel, lx=kernel) keeps per-process files
     * as memfd copies and has no environ: only the basic reads are checked there */
    int f = open("/proc/self/status", O_RDONLY);
    char want[64], link[256];
    snprintf(want, sizeof want, "/proc/self/fd/%d", f);
    ssize_t l = readlink(want, link, sizeof link - 1);
    close(f);
    if (l <= 0 || (link[l] = 0, strncmp(link, "/proc/", 6))) {
        CHECK(slurp("/proc/stat", buf, sizeof buf) > 0 && !strncmp(buf, "cpu ", 4), "/proc/stat");
        CHECK(slurp("/proc/self/status", buf, sizeof buf) > 0 && strstr(buf, "Pid:"), "/proc/self/status");
        if (!fails) printf("PROCSNAP PASS (the kernel's /proc: basic checks only)\n");
        return fails != 0;
    }
    checks();
    if (!fails) printf("PROCSNAP PASS\n");
    return fails != 0;
}
