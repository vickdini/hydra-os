// mntvfs: the mount calls vfs-server decides (wave 8, Group F).
//
//   mntvfs check        as root: a new mount namespace; tmpfs, binds, remount ro, move,
//                       propagation, umount (EBUSY, MNT_DETACH), pivot_root, statfs magic,
//                       /proc/self/mountinfo (the kernel's copy) after each change.
//   mntvfs user         the same in a new user + mount namespace (as an ordinary user).
//   mntvfs run SECS     kill test: one namespace with a tmpfs, a bind and a pivoted child;
//                       reads (must never fail) and mount/umount cycles (only EIO allowed)
//                       for SECS seconds while vfs_server is killed; the mounts must still
//                       be there at the end. Prints "MNTKILL PASS" or "MNTKILL FAIL".
//
// Build: gcc -O1 -w -pthread -o mntvfs.elf mntvfs.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails = 0;
#define CHECK(c, ...) do { if (c) { printf("  ok   "); printf(__VA_ARGS__); printf("\n"); } else { fails++; printf("  FAIL "); printf(__VA_ARGS__); printf(" (errno %d %s)\n", errno, strerror(errno)); } fflush(stdout); } while (0)

static int put(const char *p, const char *s) {
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    int n = write(fd, s, strlen(s));
    close(fd);
    return n == (int)strlen(s) ? 0 : -1;
}

static int get(const char *p, char *buf, int cap) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, cap - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = 0;
    return n;
}

// Whether /proc/self/mountinfo lists a mount at `path` (with fstype `fs`, or any if NULL).
static int listed(const char *path, const char *fs) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        char mp[512], rest[512];
        // id parent maj:min root mountpoint ...
        if (sscanf(line, "%*s %*s %*s %*s %511s %511[^\n]", mp, rest) != 2) continue;
        if (strcmp(mp, path) != 0) continue;
        if (!fs) { found = 1; continue; }
        char *dash = strstr(rest, " - ");
        if (dash && strncmp(dash + 3, fs, strlen(fs)) == 0 && dash[3 + strlen(fs)] == ' ') found = 1;
    }
    fclose(f);
    return found;
}

static void show_mountinfo(void) {
    char buf[8192];
    if (get("/proc/self/mountinfo", buf, sizeof buf) > 0) printf("%s", buf);
}

static int scenario(const char *base) {
    char a[256], b[256], c[256], d[256], f[256], buf[256];
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);
    snprintf(c, sizeof c, "%s/c", base);
    snprintf(d, sizeof d, "%s/d", base);
    mkdir(base, 0755); mkdir(a, 0755); mkdir(b, 0755); mkdir(c, 0755); mkdir(d, 0755);

    CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "make / private (propagation, recursive)");
    CHECK(mount("mytmp", a, "tmpfs", MS_NOSUID, "mode=0750") == 0, "mount tmpfs on %s", a);
    CHECK(listed(a, "tmpfs"), "mountinfo lists the tmpfs");
    struct stat st;
    CHECK(stat(a, &st) == 0 && (st.st_mode & 07777) == 0750, "tmpfs root mode 0750 (got %o)", st.st_mode & 07777);
    struct statfs sf;
    CHECK(statfs(a, &sf) == 0 && sf.f_type == 0x01021994, "statfs: TMPFS_MAGIC (got %lx)", (long)sf.f_type);
    snprintf(f, sizeof f, "%s/file", a);
    CHECK(put(f, "hello tmpfs") == 0, "write a file in the tmpfs");
    CHECK(get(f, buf, sizeof buf) > 0 && strcmp(buf, "hello tmpfs") == 0, "read it back");
    mkdir(f, 0); // (exists)
    char sub[256];
    snprintf(sub, sizeof sub, "%s/sub", a);
    CHECK(mkdir(sub, 0755) == 0, "mkdir inside the tmpfs");

    CHECK(mount(a, b, NULL, MS_BIND, NULL) == 0, "bind %s on %s", a, b);
    snprintf(f, sizeof f, "%s/file", b);
    CHECK(get(f, buf, sizeof buf) > 0 && strcmp(buf, "hello tmpfs") == 0, "the file through the bind");
    CHECK(listed(b, "tmpfs"), "mountinfo lists the bind (as tmpfs)");
    CHECK(mount(NULL, b, NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL) == 0, "remount the bind read-only");
    snprintf(f, sizeof f, "%s/new", b);
    errno = 0;
    CHECK(put(f, "x") < 0 && errno == EROFS, "write through the read-only bind: EROFS");
    snprintf(f, sizeof f, "%s/new", a);
    CHECK(put(f, "x") == 0, "write through the tmpfs itself still works");

    // a tmpfs on the sub directory, then umount of the parent: EBUSY
    CHECK(mount("t2", sub, "tmpfs", 0, NULL) == 0, "mount a tmpfs below (on %s)", sub);
    errno = 0;
    CHECK(umount2(a, 0) < 0 && errno == EBUSY, "umount of the parent with a mount below: EBUSY");

    // move
    CHECK(mount(sub, c, NULL, MS_MOVE, NULL) == 0, "move %s to %s", sub, c);
    CHECK(listed(c, "tmpfs") && !listed(sub, NULL), "mountinfo: moved");
    CHECK(umount2(c, 0) == 0, "umount the moved one");
    CHECK(!listed(c, NULL), "gone from mountinfo");

    // recursive bind
    CHECK(mount("t3", sub, "tmpfs", 0, NULL) == 0, "mount a tmpfs on %s again", sub);
    snprintf(f, sizeof f, "%s/inner", sub);
    CHECK(put(f, "inner") == 0, "a file in it");
    CHECK(mount(a, d, NULL, MS_BIND | MS_REC, NULL) == 0, "recursive bind %s on %s", a, d);
    snprintf(f, sizeof f, "%s/sub/inner", d);
    CHECK(get(f, buf, sizeof buf) > 0 && strcmp(buf, "inner") == 0, "the submount through the recursive bind");

    errno = 0;
    CHECK(umount2(d, 0) < 0 && errno == EBUSY, "umount of the recursive bind: EBUSY");
    CHECK(umount2(d, MNT_DETACH) == 0, "umount -l of the recursive bind");
    CHECK(!listed(d, NULL), "gone");
    CHECK(umount2(b, 0) == 0, "umount the bind");
    CHECK(umount2(a, MNT_DETACH) == 0, "umount -l the tmpfs and what is below it");
    CHECK(!listed(a, NULL), "the tmpfs is gone");
    snprintf(f, sizeof f, "%s/file", a);
    CHECK(access(f, F_OK) < 0 && errno == ENOENT, "its file is gone with it");

    // errors
    errno = 0;
    CHECK(mount("x", a, "nosuchfs", 0, NULL) < 0 && errno == ENODEV, "unknown type: ENODEV");
    errno = 0;
    CHECK(umount2(a, 0) < 0 && errno == EINVAL, "umount of a directory that is no mount: EINVAL");
    errno = 0;
    CHECK(umount2(a, 0x100) < 0 && errno == EINVAL, "umount2 with unknown flags: EINVAL");
    errno = 0;
    CHECK(mount("x", "/nonexistent/dir", "tmpfs", 0, NULL) < 0 && errno == ENOENT, "missing target: ENOENT");
    return 0;
}

// pivot_root into a fresh tmpfs, in the calling (new) namespace.
static int pivot_into(const char *base) {
    char nr[256], old[256], buf[64];
    snprintf(nr, sizeof nr, "%s/newroot", base);
    mkdir(base, 0755);
    mkdir(nr, 0755);
    if (mount("root", nr, "tmpfs", 0, NULL) != 0) return -1;
    snprintf(old, sizeof old, "%s/old", nr);
    int mk = mkdir(old, 0755);
    int mke = errno;
    struct stat so;
    int sr = stat(old, &so);
    if (mk != 0 || sr != 0) printf("pivot_into: mkdir %s = %d (%s), stat = %d (%s)\n", old, mk, strerror(mke), sr, strerror(errno));
    char f[256];
    snprintf(f, sizeof f, "%s/marker", nr);
    put(f, "pivoted");
    if (syscall(SYS_pivot_root, nr, old) != 0) return -2;
    if (chdir("/") != 0) return -3;
    if (get("/marker", buf, sizeof buf) <= 0 || strcmp(buf, "pivoted") != 0) return -4;
    return 0;
}

static int check_mode(int user) {
    if (user) {
        uid_t uid = getuid();
        gid_t gid = getgid();
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) { printf("unshare(user|mnt): %s\n", strerror(errno)); return 1; }
        char m[64];
        int fd = open("/proc/self/setgroups", O_WRONLY); if (fd >= 0) { write(fd, "deny", 4); close(fd); }
        snprintf(m, sizeof m, "0 %d 1", uid); fd = open("/proc/self/uid_map", O_WRONLY); if (fd >= 0) { write(fd, m, strlen(m)); close(fd); }
        snprintf(m, sizeof m, "0 %d 1", gid); fd = open("/proc/self/gid_map", O_WRONLY); if (fd >= 0) { write(fd, m, strlen(m)); close(fd); }
    } else if (unshare(CLONE_NEWNS) != 0) {
        printf("unshare(mnt): %s\n", strerror(errno));
        return 1;
    }
    char base[128];
    snprintf(base, sizeof base, "/tmp/mntvfs-%d", getpid());
    scenario(base);
    pid_t p = fork();
    if (p == 0) {
        int r = pivot_into(base);
        CHECK(r == 0, "pivot_root into a tmpfs (step %d)", r);
        if (r == 0) {
            CHECK(access("/old/etc/passwd", F_OK) == 0, "the old root under /old");
            CHECK(listed("/", "tmpfs") && listed("/old", NULL), "mountinfo after pivot_root");
            CHECK(umount2("/old", MNT_DETACH) == 0, "umount -l /old");
            CHECK(access("/old/etc/passwd", F_OK) < 0, "the old root is gone");
            show_mountinfo();
        }
        exit(fails ? 1 : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) fails++;
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", base);
    system(cmd);
    printf("MNTVFS %s %s (%d failures)\n", user ? "user" : "check", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// The kill test.
static int run_mode(int secs) {
    if (unshare(CLONE_NEWNS) != 0) { printf("unshare: %s\n", strerror(errno)); return 1; }
    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
    char base[128], t[200], b[200], x[200], f[256], buf[256];
    snprintf(base, sizeof base, "/tmp/mntkill-%d", getpid());
    snprintf(t, sizeof t, "%s/t", base);
    snprintf(b, sizeof b, "%s/b", base);
    snprintf(x, sizeof x, "%s/t/x", base);
    mkdir(base, 0755); mkdir(t, 0755); mkdir(b, 0755);
    if (mount("killtmp", t, "tmpfs", 0, NULL) != 0) { printf("MNTKILL FAIL: tmpfs %s\n", strerror(errno)); return 1; }
    snprintf(f, sizeof f, "%s/data", t);
    put(f, "kept across kills");
    mkdir(x, 0755);
    if (mount(t, b, NULL, MS_BIND, NULL) != 0) { printf("MNTKILL FAIL: bind %s\n", strerror(errno)); return 1; }
    // a pivoted child that reads its root's marker for the whole run
    int pfd[2];
    pipe(pfd);
    pid_t child = fork();
    if (child == 0) {
        close(pfd[0]);
        if (unshare(CLONE_NEWNS) != 0 || pivot_into(base) != 0) { write(pfd[1], "E", 1); exit(2); }
        umount2("/old", MNT_DETACH);
        long reads = 0, errs = 0;
        double end = now() + secs;
        while (now() < end) {
            char m[64];
            if (get("/marker", m, sizeof m) <= 0 || strcmp(m, "pivoted") != 0) errs++;
            reads++;
            usleep(2000);
        }
        char r[64];
        int n = snprintf(r, sizeof r, "%ld %ld", reads, errs);
        write(pfd[1], r, n);
        exit(0);
    }
    close(pfd[1]);
    long reads = 0, read_err = 0, cycles = 0, mnt_eio = 0, mnt_err = 0, listed_err = 0;
    double worst = 0;
    double end = now() + secs;
    int last_report = 0;
    while (now() < end) {
        // reads: through the tmpfs and through the bind
        if (get(f, buf, sizeof buf) <= 0 || strcmp(buf, "kept across kills") != 0) { read_err++; if (read_err < 5) printf("read error: %s\n", strerror(errno)); }
        char fb[256];
        snprintf(fb, sizeof fb, "%s/data", b);
        if (get(fb, buf, sizeof buf) <= 0 || strcmp(buf, "kept across kills") != 0) { read_err++; if (read_err < 5) printf("bind read error: %s\n", strerror(errno)); }
        reads += 2;
        // a mount change: tmpfs on x, then away
        double t0 = now();
        int r = mount("cyc", x, "tmpfs", 0, NULL);
        int e1 = errno;
        int u = r == 0 ? umount2(x, 0) : 0;
        int e2 = errno;
        double dt = now() - t0;
        if (dt > worst) worst = dt;
        if (r != 0 || u != 0) {
            int e = r != 0 ? e1 : e2;
            if (e == EIO) mnt_eio++; else { mnt_err++; if (mnt_err < 5) printf("mount cycle error: %s (mount %d umount %d)\n", strerror(e), r, u); }
            // (a mount left behind by a failed umount)
            if (r == 0) umount2(x, MNT_DETACH);
        }
        cycles++;
        if (cycles % 20 == 0 && (!listed(t, "tmpfs") || !listed(b, "tmpfs"))) { listed_err++; if (listed_err < 5) printf("mountinfo lost a mount\n"); }
        int el = (int)(now() - (end - secs));
        if (el / 10 != last_report) { last_report = el / 10; printf("progress %ds: reads %ld (errors %ld) cycles %ld (EIO %ld, other %ld) worst %.2fs\n", el, reads, read_err, cycles, mnt_eio, mnt_err, worst); fflush(stdout); }
        usleep(5000);
    }
    char r[64] = {0};
    int n = read(pfd[0], r, sizeof r - 1);
    int st = 0;
    waitpid(child, &st, 0);
    long creads = 0, cerrs = -1;
    if (n > 0) sscanf(r, "%ld %ld", &creads, &cerrs);
    int still = listed(t, "tmpfs") && listed(b, "tmpfs") && get(f, buf, sizeof buf) > 0;
    printf("reads %ld read_errors %ld cycles %ld mount_eio %ld mount_other %ld listed_errors %ld worst_change %.2fs pivoted_reads %ld pivoted_errors %ld mounts_kept %d\n",
           reads, read_err, cycles, mnt_eio, mnt_err, listed_err, worst, creads, cerrs, still);
    umount2(b, 0);
    umount2(t, MNT_DETACH);
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", base);
    system(cmd);
    int ok = read_err == 0 && mnt_err == 0 && listed_err == 0 && cerrs == 0 && still;
    printf("MNTKILL %s\n", ok ? "PASS" : "FAIL");
    return !ok;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 2 && strcmp(argv[1], "check") == 0) return check_mode(0);
    if (argc >= 2 && strcmp(argv[1], "user") == 0) return check_mode(1);
    if (argc >= 3 && strcmp(argv[1], "run") == 0) return run_mode(atoi(argv[2]));
    fprintf(stderr, "usage: mntvfs check | user | run SECS\n");
    return 2;
}
