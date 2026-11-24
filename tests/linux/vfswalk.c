// vfswalk: compares vfs-server's path walk (Hydra's test call LX_VFS_WALK_NR, wave 7 Group
// 7-1) with the kernel's stat/lstat for every path of the given trees, plus the walk's
// special cases (.., symbolic links, trailing slashes, errors, permissions, redirects of
// /proc, /sys and /dev), and times a cached walk against stat.
//
//   vfswalk [-q] [TREE...]     (default trees: /usr /etc /var /bin /lib /sbin)
//
// Prints "VFSWALK PASS ..." or "VFSWALK FAIL ..." at the end.
// Build: gcc -O1 -w -pthread tests/linux/vfswalk.c -o esp/bin/vfswalk.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_VFS_WALK_NR 0x6714
#define NOFOLLOW 1
#define NOREDIR 2
#define NOCACHE 4
#define LXS_LINUX 1
#define LXS_PROC 5

struct out {
    uint64_t ino, mnt, mode, nlink, uid, gid, rdev, size, redir_svc, redir_obj, redir_tail, zfs_requests;
};

static long walk(const char *p, int flags, struct out *o) {
    memset(o, 0, sizeof *o);
    long r = syscall(LX_VFS_WALK_NR, AT_FDCWD, p, flags, o);
    return r < 0 ? -errno : r;
}

static long paths, mism, specials, special_fail, redirected;
static int quiet;
static uint64_t zfs_reqs;

static void report(const char *what, const char *p, const char *detail) {
    mism++;
    if (mism <= 30)
        printf("MISMATCH %s %s: %s\n", what, p, detail);
}

// Compares one path: the kernel's (l)stat and the walk with or without following
static void compare(const char *p, int follow) {
    struct stat st;
    int kr = follow ? stat(p, &st) : lstat(p, &st);
    int ke = kr < 0 ? -errno : 0;
    struct out o;
    long vr = walk(p, follow ? 0 : NOFOLLOW, &o);
    zfs_reqs += o.zfs_requests;
    char d[256];
    if (vr == 0 && o.redir_svc == 0 && o.ino == 0 && ke == 0) {
        // (a redirect answered by linux-server: not comparable here)
    }
    if (vr > 0 && ke == 0) {
        // A symbolic link into /proc, /sys or /dev: vfs-server redirected the walk and
        // linux-server answered it (0x10000 * service + 0x100 * object + tail)
        redirected++;
        return;
    }
    if (ke != 0 || vr != 0) {
        if (ke != vr) {
            snprintf(d, sizeof d, "%s kernel %d vfs %ld", follow ? "stat" : "lstat", ke, vr);
            report("errno", p, d);
        }
        return;
    }
    if (o.ino != st.st_ino || o.mode != st.st_mode || o.nlink != st.st_nlink || o.uid != st.st_uid || o.gid != st.st_gid ||
        (!S_ISDIR(st.st_mode) && o.size != (uint64_t)st.st_size) || o.rdev != st.st_rdev) {
        snprintf(d, sizeof d, "%s kernel ino %lu mode %o nlink %lu uid %u gid %u size %ld rdev %lx / vfs ino %lu mode %lo nlink %lu uid %lu gid %lu size %lu rdev %lx",
                 follow ? "stat" : "lstat", (unsigned long)st.st_ino, st.st_mode, (unsigned long)st.st_nlink, st.st_uid, st.st_gid, (long)st.st_size,
                 (unsigned long)st.st_rdev, o.ino, o.mode, o.nlink, o.uid, o.gid, o.size, o.rdev);
        report("attr", p, d);
    }
}

static int visit(const char *p, const struct stat *sb, int type, struct FTW *f) {
    paths++;
    compare(p, 0);
    compare(p, 1);
    // The same path with a trailing slash (directories: found; others: ENOTDIR)
    if (strlen(p) < 4000 && type != FTW_SL) {
        char q[4100];
        snprintf(q, sizeof q, "%s/", p);
        compare(q, 1);
    }
    return 0;
}

static void expect(const char *name, long got, long want) {
    specials++;
    if (got != want) {
        special_fail++;
        printf("SPECIAL FAIL %s: got %ld (%#lx) want %ld (%#lx)\n", name, got, got, want, want);
    } else if (!quiet) {
        printf("special ok %s (%ld)\n", name, got);
    }
}

static void specials_run(void) {
    struct out o;
    // Redirects reported (NOREDIR): service, object, tail
    expect("proc noredir", walk("/proc/self/stat", NOREDIR, &o), 0);
    expect("proc svc", o.redir_svc, LXS_PROC);
    expect("proc obj", o.redir_obj, 1);
    expect("proc tail", o.redir_tail, 6);
    // (wave10 GV2: /sys and /dev are pool trees vfs-server walks; the names other services
    // serve in them are redirected at lookup: linux-server's cpu ranges, tty-server's /dev/pts)
    expect("sys walked", walk("/sys/class", NOREDIR, &o), 0);
    expect("sys walked svc", o.redir_svc, 0);
    expect("sys tail", (walk("/sys/devices/system/cpu/online", NOREDIR, &o), o.redir_tail), 5);
    expect("sys svc", o.redir_svc, LXS_LINUX);
    expect("dev walked", walk("/dev/null", NOREDIR, &o), 0);
    expect("dev node", o.rdev, 0x103);
    expect("pts obj", (walk("/dev/pts/0", NOREDIR, &o), o.redir_obj), 4);
    expect("pts svc", o.redir_svc, 9);
    expect("pts tail", o.redir_tail, 5);
    expect("proc itself", (walk("/proc", NOREDIR, &o), o.redir_tail), 5);
    expect("dotdot to proc", (walk("/usr/../proc/1", NOREDIR, &o), o.redir_tail), 13);
    // /etc/mtab -> ../proc/self/mounts: the rest is text (a ticket in the object, tail -1)
    if (readlink("/etc/mtab", (char[64]){0}, 64) > 0) {
        expect("mtab noredir", walk("/etc/mtab", NOREDIR, &o), 0);
        expect("mtab svc", o.redir_svc, LXS_PROC);
        expect("mtab tail", o.redir_tail, 0xFFFFFFFFul);
        expect("mtab obj", o.redir_obj & 0xFFFFFFFF, 1);
        expect("mtab ticket", (o.redir_obj >> 32) != 0, 1);
        expect("mtab nofollow", (walk("/etc/mtab", NOFOLLOW, &o), o.mode & S_IFMT), S_IFLNK);
    }
    // A redirect made: linux-server answers the redirected call (0x10000 * svc + 0x100 * obj + tail)
    expect("proc redirect", walk("/proc/self/stat", 0, &o), 0x10000 * LXS_PROC + 0x100 * 1 + 6);
    expect("sys redirect", walk("/sys/devices/system/cpu/online", 0, &o), 0x10000 * LXS_LINUX + 0x100 * 2 + 5);
    expect("pts redirect", walk("/dev/pts/0", 0, &o), 0x10000 * 9 + 0x100 * 4 + 5);
    // Errors
    expect("missing", walk("/nonexistent-vfswalk", 0, &o), -ENOENT);
    expect("empty", walk("", 0, &o), -ENOENT);
    expect("notdir", walk("/etc/passwd/x", 0, &o), -ENOTDIR);
    expect("notdir slash", walk("/etc/passwd/", 0, &o), -ENOTDIR);
    char longname[300];
    memset(longname, 'a', 299);
    longname[0] = '/';
    longname[299] = 0;
    expect("name too long", walk(longname, 0, &o), -ENAMETOOLONG);
    char *longpath = malloc(5000);
    for (int i = 0; i < 4998; i += 2) longpath[i] = '/', longpath[i + 1] = '.';
    longpath[4998] = 0;
    expect("path too long", walk(longpath, 0, &o), -ENAMETOOLONG);
    expect("bad dirfd", syscall(LX_VFS_WALK_NR, 3, "x", 0, &o) < 0 ? -errno : 0, -EINVAL);
    // The root: "/", "/..", "." and ".." from it
    struct stat rs;
    stat("/", &rs);
    expect("root", (walk("/", 0, &o), o.ino), rs.st_ino);
    expect("root dotdot", (walk("/../../..", 0, &o), o.ino), rs.st_ino);
    chdir("/usr");
    struct stat us;
    stat("/usr/bin", &us);
    expect("relative", (walk("bin", 0, &o), o.ino), us.st_ino);
    expect("relative dotdot", (walk("../usr/./bin/", 0, &o), o.ino), us.st_ino);
    chdir("/");
    // Symbolic links: a loop, a chain, a dangling one, an absolute and a relative one
    mkdir("/tmp/vfswalk.d", 0755);
    symlink("loop2", "/tmp/vfswalk.d/loop1");
    symlink("loop1", "/tmp/vfswalk.d/loop2");
    symlink("/usr/bin", "/tmp/vfswalk.d/abs");
    symlink("../vfswalk.d/abs", "/tmp/vfswalk.d/rel");
    symlink("nowhere", "/tmp/vfswalk.d/dangling");
    expect("loop", walk("/tmp/vfswalk.d/loop1", 0, &o), -ELOOP);
    expect("loop nofollow", walk("/tmp/vfswalk.d/loop1", NOFOLLOW, &o), 0);
    expect("chain", (walk("/tmp/vfswalk.d/rel/", NOFOLLOW, &o), o.ino), us.st_ino);
    expect("chain inside", (walk("/tmp/vfswalk.d/rel/../bin", 0, &o), o.ino), us.st_ino);
    expect("dangling", walk("/tmp/vfswalk.d/dangling", 0, &o), -ENOENT);
    expect("dangling nofollow", walk("/tmp/vfswalk.d/dangling", NOFOLLOW, &o), 0);
    // Search permission: a directory only its owner may search, walked as another user
    mkdir("/tmp/vfswalk.d/private", 0700);
    close(open("/tmp/vfswalk.d/private/f", O_CREAT | O_WRONLY, 0644));
    chmod("/tmp/vfswalk.d/private", 0700);
    // As the owner without x on its own directory (no capability): refused
    mkdir("/tmp/vfswalk.d/closed", 0755);
    close(open("/tmp/vfswalk.d/closed/f", O_CREAT | O_WRONLY, 0644));
    chmod("/tmp/vfswalk.d/closed", 0600);
    if (getuid() != 0)
        expect("search denied to the owner", walk("/tmp/vfswalk.d/closed/f", 0, &o), -EACCES);
    chmod("/tmp/vfswalk.d/closed", 0755);
    expect("search allowed again", walk("/tmp/vfswalk.d/closed/f", NOCACHE, &o), 0);
    if (getuid() != 0) {
        printf("vfswalk: not root: the other-user permission check is skipped\n");
    } else {
    pid_t pid = fork();
    if (pid == 0) {
        if (setgid(65534) || setuid(65534)) _exit(2);
        struct out q;
        long r1 = walk("/tmp/vfswalk.d/private/f", 0, &q);
        long r2 = walk("/tmp/vfswalk.d/private", 0, &q);
        _exit(r1 == -EACCES && r2 == 0 ? 0 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    expect("search denied as nobody", WIFEXITED(status) ? WEXITSTATUS(status) : 99, 0);
    expect("search as root", walk("/tmp/vfswalk.d/private/f", 0, &o), 0);
    }
    // Uncached walks agree with cached ones
    struct out a, b;
    walk("/usr/bin/bash", 0, &a);
    walk("/usr/bin/bash", NOCACHE, &b);
    expect("nocache same ino", a.ino == b.ino && a.mode == b.mode, 1);
    expect("nocache asks zfs", b.zfs_requests > 0, 1);
    walk("/usr/bin/bash", 0, &a);
    expect("cached asks nothing", a.zfs_requests, 0);
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void timing(void) {
    struct out o;
    struct stat st;
    const int n = 20000;
    double best_w = 1e9, best_s = 1e9;
    for (int k = 0; k < 5; k++) {
        double t0 = now();
        for (int i = 0; i < n; i++) walk("/usr/bin/bash", 0, &o);
        double t1 = now();
        for (int i = 0; i < n; i++) stat("/usr/bin/bash", &st);
        double t2 = now();
        if ((t1 - t0) < best_w) best_w = t1 - t0;
        if ((t2 - t1) < best_s) best_s = t2 - t1;
    }
    printf("VFSWALK TIMING walk(/usr/bin/bash) %.2f us, kernel stat %.2f us (best of 5 x %d)\n", best_w / n * 1e6, best_s / n * 1e6, n);
}

int main(int argc, char **argv) {
    int i = 1;
    if (i < argc && !strcmp(argv[i], "-q")) quiet = 1, i++;
    struct out o;
    long r = walk("/", 0, &o);
    if (r == -ENOSYS) {
        printf("VFSWALK SKIP: the walk call is not served (vfs-server off, lx.vfs=kernel or lx=kernel)\n");
        return 0;
    }
    specials_run();
    const char *def[] = {"/usr", "/etc", "/var", "/bin", "/lib", "/sbin", 0};
    double t0 = now();
    if (i < argc)
        for (; i < argc; i++) nftw(argv[i], visit, 64, FTW_PHYS);
    else
        for (int k = 0; def[k]; k++) nftw(def[k], visit, 64, FTW_PHYS);
    double t1 = now();
    printf("VFSWALK TREES %ld paths (%ld comparisons, %ld redirected) in %.1f s, %lu zfs-server requests from vfs-server\n", paths, paths * 3, redirected, t1 - t0, (unsigned long)zfs_reqs);
    timing();
    int ok = mism == 0 && special_fail == 0;
    printf("VFSWALK %s paths=%ld mismatches=%ld specials=%ld special_failures=%ld\n", ok ? "PASS" : "FAIL", paths, mism, specials, special_fail);
    return ok ? 0 : 1;
}
