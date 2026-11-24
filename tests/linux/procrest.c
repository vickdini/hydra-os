/* procrest: the rest of /proc served by lx-proc (wave 11, Group P): directories, magic
 * links, fdinfo, auxv, cgroup, mountinfo, the namespace files, walks relative to a /proc
 * directory descriptor, and callers in a PID namespace of their own.
 *
 *   procrest            the checks below; prints "PROCREST PASS" or "FAIL ..." lines
 *   procrest bench N    timings (us per open+read+close, or per opendir+readdir+closedir)
 *   procrest hold SECS  lists /proc, /proc/self/fd, reads fdinfo and links in a loop for SECS
 *                       seconds (for kill tests: lx-proc may be killed meanwhile); prints the
 *                       counts and "HOLD PASS" when no call failed except EIO/EINTR
 *
 * Build (WSL): gcc -O1 -w -pthread tests/linux/procrest.c -o esp/bin/procrest.elf
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

static long slurp_at(int dir, const char *p, char *b, size_t n) {
    int f = openat(dir, p, O_RDONLY | O_CLOEXEC);
    if (f < 0) return -errno;
    long t = 0, r;
    while ((r = read(f, b + t, n - 1 - t)) > 0) t += r;
    close(f);
    b[t] = 0;
    return r < 0 ? -errno : t;
}
static long slurp(const char *p, char *b, size_t n) { return slurp_at(AT_FDCWD, p, b, n); }

/* whether directory p lists name */
static int lists(const char *p, const char *name) {
    DIR *d = opendir(p);
    if (!d) return -errno;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) if (!strcmp(e->d_name, name)) found = 1;
    closedir(d);
    return found;
}

static int count_entries(const char *p) {
    DIR *d = opendir(p);
    if (!d) return -errno;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static void checks(void) {
    char p[256], l[512];
    pid_t me = getpid();
    /* /proc itself */
    snprintf(p, sizeof p, "%d", me);
    CHECK(lists("/proc", p) == 1, "/proc lists my pid");
    CHECK(lists("/proc", "self") == 1, "/proc lists self");
    CHECK(lists("/proc", "meminfo") == 1, "/proc lists meminfo");
    CHECK(lists("/proc", ".") == 1, "/proc lists .");
    struct stat st;
    CHECK(stat("/proc", &st) == 0 && S_ISDIR(st.st_mode), "stat /proc");
    /* a process directory */
    CHECK(lists("/proc/self", "status") == 1, "/proc/self lists status");
    CHECK(lists("/proc/self", "fd") == 1, "/proc/self lists fd");
    CHECK(lists("/proc/self", "exe") == 1, "/proc/self lists exe");
    /* task/ */
    snprintf(p, sizeof p, "%ld", (long)syscall(SYS_gettid));
    CHECK(lists("/proc/self/task", p) == 1, "task lists my tid");
    /* fd/ and its links */
    int f = open("/proc/version", O_RDONLY);
    CHECK(f >= 0, "open version");
    snprintf(p, sizeof p, "%d", f);
    CHECK(lists("/proc/self/fd", p) == 1, "fd/ lists %d", f);
    CHECK(lists("/proc/self/fdinfo", p) == 1, "fdinfo/ lists %d", f);
    snprintf(p, sizeof p, "/proc/self/fd/%d", f);
    long n = readlink(p, l, sizeof l - 1);
    CHECK(n > 0, "readlink fd");
    if (n > 0) { l[n] = 0; CHECK(!strcmp(l, "/proc/version"), "fd link %s", l); }
    CHECK(lstat(p, &st) == 0 && S_ISLNK(st.st_mode), "lstat fd link");
    CHECK(stat(p, &st) == 0 && S_ISREG(st.st_mode), "stat follows fd link");
    int g = open(p, O_RDONLY); /* reopen through the link: the kernel's */
    CHECK(g >= 0 && read(g, buf, 5) == 5 && !memcmp(buf, "Linux", 5), "reopen via fd link");
    if (g >= 0) close(g);
    /* fdinfo */
    lseek(f, 3, SEEK_SET);
    snprintf(p, sizeof p, "/proc/self/fdinfo/%d", f);
    CHECK(slurp(p, buf, sizeof buf) > 0, "read fdinfo");
    CHECK(strstr(buf, "pos:") && strstr(buf, "flags:") && strstr(buf, "mnt_id:"), "fdinfo fields: %s", buf);
    { /* fstat's size of an open /proc file is its text's length (D-Bus reads up to it) */
        int q = open(p, O_RDONLY);
        struct stat qs;
        CHECK(q >= 0 && fstat(q, &qs) == 0 && qs.st_size == (long)strlen(buf), "fdinfo st_size %ld vs %zu", (long)qs.st_size, strlen(buf));
        if (q >= 0) close(q);
    }
    close(f);
    CHECK(slurp("/proc/self/fdinfo/987", buf, sizeof buf) == -ENOENT, "fdinfo of a closed fd");
    CHECK(readlink("/proc/self/fd/987", l, sizeof l) < 0 && errno == ENOENT, "readlink closed fd");
    /* exe, cwd, root */
    n = readlink("/proc/self/exe", l, sizeof l - 1);
    CHECK(n > 0 && strstr((l[n] = 0, l), "procrest"), "exe link %s", l);
    char cwd[512];
    CHECK(getcwd(cwd, sizeof cwd) != NULL, "getcwd");
    n = readlink("/proc/self/cwd", l, sizeof l - 1);
    CHECK(n > 0 && !strcmp((l[n] = 0, l), cwd), "cwd link %s vs %s", l, cwd);
    n = readlink("/proc/self/root", l, sizeof l - 1);
    CHECK(n == 1 && l[0] == '/', "root link");
    snprintf(p, sizeof p, "/proc/%d/exe", getppid());
    n = readlink(p, l, sizeof l - 1);
    CHECK(n > 0, "parent exe link");
    /* ns/ */
    CHECK(lists("/proc/self/ns", "mnt") == 1, "ns/ lists mnt");
    n = readlink("/proc/self/ns/net", l, sizeof l - 1);
    CHECK(n > 5 && !strncmp(l, "net:[", 5), "ns link %.*s", (int)(n > 0 ? n : 0), l);
    struct stat a, b;
    CHECK(stat("/proc/self/ns/pid", &a) == 0 && stat("/proc/1/ns/pid", &b) == 0 || stat("/proc/self/ns/pid", &a) == 0, "stat ns");
    int nsfd = open("/proc/self/ns/uts", O_RDONLY);
    CHECK(nsfd >= 0, "open ns file");
    if (nsfd >= 0) {
        struct stat c, d;
        CHECK(fstat(nsfd, &c) == 0 && stat("/proc/self/ns/uts", &d) == 0 && c.st_ino == d.st_ino && c.st_dev == d.st_dev, "ns fstat = stat (%lu/%lu %lu/%lu)", c.st_ino, d.st_ino, c.st_dev, d.st_dev);
        CHECK(setns(nsfd, CLONE_NEWUTS) == 0 || errno == EPERM, "setns own uts");
        close(nsfd);
    }
    /* auxv, cgroup, mountinfo, mounts, maps of ids, oom */
    n = slurp("/proc/self/auxv", buf, sizeof buf);
    CHECK(n >= 16 && n % 16 == 0, "auxv %ld", n);
    unsigned long *av = (unsigned long *)buf;
    int pg = 0;
    for (long i = 0; i + 1 < n / 8; i += 2) if (av[i] == AT_PAGESZ) pg = av[i + 1];
    CHECK(pg == 4096, "auxv AT_PAGESZ %d", pg);
    CHECK(slurp("/proc/self/cgroup", buf, sizeof buf) > 3 && !strncmp(buf, "0::/", 4), "cgroup %s", buf);
    CHECK(slurp("/proc/self/mountinfo", buf, sizeof buf) > 0 && strstr(buf, " / "), "mountinfo");
    CHECK(slurp("/proc/mounts", buf, sizeof buf) > 0 && strstr(buf, "proc"), "mounts");
    CHECK(slurp("/proc/self/uid_map", buf, sizeof buf) > 0, "uid_map");
    CHECK(slurp("/proc/self/setgroups", buf, sizeof buf) > 0, "setgroups");
    CHECK(slurp("/proc/self/oom_score_adj", buf, sizeof buf) > 0, "oom_score_adj");
    CHECK(slurp("/proc/filesystems", buf, sizeof buf) > 0 && strstr(buf, "proc"), "filesystems");
    CHECK(slurp("/proc/swaps", buf, sizeof buf) > 0 && strstr(buf, "Filename"), "swaps");
    CHECK(slurp("/proc/locks", buf, sizeof buf) >= 0, "locks");
    CHECK(slurp("/proc/sys/kernel/random/boot_id", buf, sizeof buf) == 37, "boot_id");
    CHECK(slurp("/proc/sys/kernel/random/boot_id", buf2, sizeof buf2) == 37 && !strcmp(buf, buf2), "boot_id stable");
    CHECK(slurp("/proc/sys/kernel/random/uuid", buf, sizeof buf) == 37, "uuid");
    CHECK(slurp("/proc/sys/kernel/random/uuid", buf2, sizeof buf2) == 37 && strcmp(buf, buf2), "uuid fresh");
    CHECK(lists("/proc/sys/kernel", "shmmax") == 1, "sys/kernel lists shmmax");
    CHECK(lists("/proc/sys", "fs") == 1, "sys lists fs");
    /* names that are not there */
    CHECK(slurp("/proc/self/nonesuch", buf, sizeof buf) == -ENOENT, "missing pid file");
    CHECK(slurp("/proc/pressure/cpu", buf, sizeof buf) == -ENOENT, "missing pressure");
    CHECK(stat("/proc/self/.directory", &st) < 0 && errno == ENOENT, "missing .directory");
    /* a directory descriptor: walks relative to it, rewind, positions */
    int pd = open("/proc", O_RDONLY | O_DIRECTORY);
    CHECK(pd >= 0, "open /proc dir");
    CHECK(read(pd, buf, 10) < 0 && errno == EISDIR, "read of a directory");
    snprintf(p, sizeof p, "%d/stat", me);
    CHECK(slurp_at(pd, p, buf, sizeof buf) > 0 && atoi(buf) == me, "openat(/proc, pid/stat)");
    CHECK(fstatat(pd, "self/status", &st, 0) == 0 && S_ISREG(st.st_mode), "fstatat(/proc, self/status)");
    CHECK(faccessat(pd, "meminfo", R_OK, 0) == 0, "faccessat(/proc, meminfo)");
    n = readlinkat(pd, "self", l, sizeof l - 1);
    CHECK(n > 0 && atoi((l[n] = 0, l)) == me, "readlinkat(/proc, self)");
    int sd = openat(pd, "self", O_RDONLY | O_DIRECTORY);
    CHECK(sd >= 0, "openat(/proc, self) dir");
    if (sd >= 0) {
        CHECK(slurp_at(sd, "comm", buf, sizeof buf) > 0 && strstr(buf, "procrest"), "openat(self, comm) %s", buf);
        int td = openat(sd, "task", O_RDONLY | O_DIRECTORY);
        CHECK(td >= 0, "openat(self, task)");
        if (td >= 0) close(td);
        CHECK(fstat(sd, &st) == 0 && S_ISDIR(st.st_mode), "fstat dir snapshot");
        close(sd);
    }
    DIR *d = fdopendir(pd);
    CHECK(d != NULL, "fdopendir");
    if (d) {
        int k = 0;
        while (readdir(d)) k++;
        rewinddir(d);
        int k2 = 0;
        while (readdir(d)) k2++;
        CHECK(k > 3 && k2 > 3 && abs(k - k2) < 20, "rewinddir %d %d", k, k2);
        closedir(d);
    }
    /* another process: its fd/ and links; gone: its files */
    int pp[2];
    CHECK(pipe(pp) == 0, "pipe");
    pid_t c = fork();
    if (c == 0) { close(pp[1]); read(pp[0], buf, 1); _exit(0); }
    snprintf(p, sizeof p, "/proc/%d/fd", c);
    CHECK(count_entries(p) >= 3, "child fd/ %d", count_entries(p));
    snprintf(p, sizeof p, "/proc/%d/fd/%d", c, pp[0]);
    n = readlink(p, l, sizeof l - 1);
    CHECK(n > 5 && !strncmp(l, "pipe:", 5), "child fd link %.*s", (int)(n > 0 ? n : 0), l);
    snprintf(p, sizeof p, "/proc/%d", c);
    int cd = open(p, O_RDONLY | O_DIRECTORY);
    CHECK(cd >= 0, "open child dir");
    close(pp[1]);
    waitpid(c, NULL, 0);
    if (cd >= 0) {
        CHECK(slurp_at(cd, "stat", buf, sizeof buf) < 0, "child gone: its stat");
        close(cd);
    }
    close(pp[0]);
}

/* in a PID namespace of its own: /proc mounted for it shows its view */
static void pidns_checks(void) {
    if (unshare(CLONE_NEWPID | CLONE_NEWNS) != 0) {
        printf("pidns: unshare %d (not root?): skipped\n", errno);
        return;
    }
    pid_t c = fork();
    if (c == 0) {
        int bad = 0;
        mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) printf("pidns: mount proc %d\n", errno);
        if (getpid() != 1) bad++;
        char l[64];
        long n = readlink("/proc/self", l, sizeof l - 1);
        if (n <= 0 || atoi((l[n] = 0, l)) != 1) { printf("FAIL pidns readlink self %s\n", n > 0 ? l : "?"); bad++; }
        if (slurp("/proc/self/stat", buf, sizeof buf) <= 0 || atoi(buf) != 1) { printf("FAIL pidns stat %s\n", buf); bad++; }
        if (lists("/proc", "1") != 1) { printf("FAIL pidns /proc lists 1\n"); bad++; }
        if (slurp("/proc/1/status", buf, sizeof buf) <= 0 || !strstr(buf, "Pid:\t1\n")) { printf("FAIL pidns status %s\n", buf); bad++; }
        _exit(bad);
    }
    int s = 0;
    waitpid(c, &s, 0);
    CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0, "pidns child %x", s);
}

static void bench(int n) {
    const char *files[] = {"/proc/self/fdinfo/0", "/proc/self/cgroup", "/proc/self/mountinfo", "/proc/self/auxv", "/proc/filesystems", "/proc/self/oom_score_adj"};
    for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
        double t = now();
        for (int k = 0; k < n; k++) slurp(files[i], buf, sizeof buf);
        printf("bench %-28s %.2f us\n", files[i], (now() - t) * 1e6 / n);
    }
    const char *dirs[] = {"/proc", "/proc/self/fd", "/proc/self/task", "/proc/self"};
    for (unsigned i = 0; i < sizeof dirs / sizeof *dirs; i++) {
        double t = now();
        for (int k = 0; k < n; k++) count_entries(dirs[i]);
        printf("bench list %-23s %.2f us\n", dirs[i], (now() - t) * 1e6 / n);
    }
    char l[256];
    double t = now();
    for (int k = 0; k < n; k++) readlink("/proc/self/exe", l, sizeof l);
    printf("bench readlink /proc/self/exe      %.2f us\n", (now() - t) * 1e6 / n);
    t = now();
    for (int k = 0; k < n; k++) readlink("/proc/self/fd/0", l, sizeof l);
    printf("bench readlink /proc/self/fd/0     %.2f us\n", (now() - t) * 1e6 / n);
    int pd = open("/proc", O_RDONLY | O_DIRECTORY);
    char p[64];
    snprintf(p, sizeof p, "%d/stat", getpid());
    t = now();
    for (int k = 0; k < n; k++) slurp_at(pd, p, buf, sizeof buf);
    printf("bench openat(/proc fd, pid/stat)   %.2f us\n", (now() - t) * 1e6 / n);
    close(pd);
}

static void hold(int secs) {
    double end = now() + secs;
    long rounds = 0, errs = 0, gaps = 0;
    int keep = open("/proc", O_RDONLY | O_DIRECTORY);
    while (now() < end) {
        int a = count_entries("/proc"), b = count_entries("/proc/self/fd");
        long c = slurp("/proc/self/fdinfo/0", buf, sizeof buf);
        char l[256];
        long r = readlink("/proc/self/exe", l, sizeof l);
        int e = errno;
        long s = slurp_at(keep, "self/stat", buf2, sizeof buf2);
        if (a < 0 || b < 0 || c < 0 || r < 0 || s < 0) {
            int err = a < 0 ? -a : b < 0 ? -b : c < 0 ? -c : r < 0 ? e : -s;
            if (err == EIO || err == EINTR) gaps++;
            else { errs++; if (errs < 5) printf("hold error %d (%d %d %ld %ld %ld)\n", err, a, b, c, r, s); }
        }
        rounds++;
        usleep(20000);
    }
    close(keep);
    printf("hold rounds %ld errors %ld restart-gaps %ld\n", rounds, errs, gaps);
    if (!errs) printf("HOLD PASS\n");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && !strcmp(argv[1], "bench")) { bench(atoi(argv[2])); return 0; }
    if (argc > 2 && !strcmp(argv[1], "hold")) { hold(atoi(argv[2])); return 0; }
    checks();
    if (geteuid() == 0) pidns_checks();
    else printf("pidns: not root: skipped\n");
    if (!fails) printf("PROCREST PASS\n");
    return fails != 0;
}
