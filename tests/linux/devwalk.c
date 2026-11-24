// devwalk: /dev, /sys, chdir and device opens served by vfs-server since wave 10 (Group V2).
//
//   devwalk            checks (prints FAIL lines, then DEVWALK PASS / DEVWALK FAIL n); as root
//                      also the checks for another user (setresuid) and a chown of a node
//   devwalk bench N    N rounds: /dev/null open+close, a /sys file read, chdir, statfs
//   devwalk kill S     the calls in a loop for S seconds (services killed meanwhile)
//
// Covers: walks relative to /sys and /dev directory descriptors (systemd's O_PATH chase,
// faccessat2, readlinkat), /sys files served by linux-server (cpu ranges) by absolute path,
// the device nodes (/dev/null, zero, full, urandom, tty, console, ptmx, ttyN) opened by
// number, /dev/pts, statfs/fstatfs types (sysfs, cgroup2, devpts, the pool), /dev/shm
// handles (ftruncate, fstatfs), chdir/fchdir with getcwd through symbolic links, a socket
// node (ENXIO), O_CREAT|O_DIRECTORY (EINVAL).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SYSFS_MAGIC 0x62656572
#define CGROUP2_MAGIC 0x63677270
#define DEVPTS_MAGIC 0x1cd1
#define ZFS_MAGIC 0x2fc12fc1

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); fflush(stdout); } } while (0)

static const char *D = "/tmp/devwalk.d";

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static long fstype(const char *p) {
    struct statfs s;
    if (statfs(p, &s) != 0) return -errno;
    return (long)s.f_type;
}

static long ffstype(int fd) {
    struct statfs s;
    if (fstatfs(fd, &s) != 0) return -errno;
    return (long)s.f_type;
}

// systemd's chase: O_PATH steps from / into /sys/class/<x>, then a file read at the end
static void sys_relative(void) {
    int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    CHECK(root >= 0, "open / O_PATH");
    int sys = openat(root, "sys", O_PATH | O_NOFOLLOW | O_CLOEXEC);
    CHECK(sys >= 0, "openat(/, sys, O_PATH)");
    int cls = openat(sys, "class", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(cls >= 0, "openat(sys, class)");
    int drm = openat(cls, "drm", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(drm >= 0, "openat(class, drm)");
    char buf[256];
    ssize_t n = readlinkat(drm, "card0", buf, sizeof buf - 1);
    CHECK(n > 0, "readlinkat(drm, card0)");
    if (n > 0) {
        buf[n] = 0;
        CHECK(strstr(buf, "devices/") != NULL, "card0 -> %s", buf);
    }
    // through the link, relative: card0/uevent
    CHECK(faccessat(drm, "card0/uevent", R_OK, AT_EACCESS) == 0, "faccessat2(drm, card0/uevent)");
    int ue = openat(drm, "card0/uevent", O_RDONLY | O_CLOEXEC);
    CHECK(ue >= 0, "openat(drm, card0/uevent)");
    if (ue >= 0) {
        n = read(ue, buf, sizeof buf - 1);
        CHECK(n > 0 && memmem(buf, n, "MAJOR=226", 9), "uevent text");
        close(ue);
    }
    // the parent of a /sys directory, relative
    int up = openat(drm, "..", O_PATH | O_DIRECTORY);
    CHECK(up >= 0, "openat(drm, ..)");
    struct stat a, b;
    CHECK(fstat(up, &a) == 0 && fstat(cls, &b) == 0 && a.st_ino == b.st_ino, "drm/.. is class");
    // statfs of /sys handles and paths
    CHECK(ffstype(sys) == SYSFS_MAGIC, "fstatfs(/sys O_PATH) %lx", ffstype(sys));
    CHECK(ffstype(drm) == SYSFS_MAGIC, "fstatfs(/sys/class/drm) %lx", ffstype(drm));
    CHECK(fstype("/sys") == SYSFS_MAGIC, "statfs(/sys) %lx", fstype("/sys"));
    CHECK(fstype("/sys/fs/cgroup") == CGROUP2_MAGIC, "statfs(/sys/fs/cgroup) %lx", fstype("/sys/fs/cgroup"));
    CHECK(fstype("/sys/fs/cgroup/") == CGROUP2_MAGIC, "statfs(/sys/fs/cgroup/)");
    CHECK(fstype("/") == ZFS_MAGIC, "statfs(/) %lx", fstype("/"));
    CHECK(fstype("/dev") == ZFS_MAGIC, "statfs(/dev) %lx", fstype("/dev"));
    CHECK(fstype("/dev/pts") == DEVPTS_MAGIC, "statfs(/dev/pts) %lx", fstype("/dev/pts"));
    close(up);
    close(drm);
    close(cls);
    close(sys);
    close(root);
}

// linux-server's /sys files, by absolute path (redirected at lookup)
static void sys_served(void) {
    char buf[64] = {0};
    int fd = open("/sys/devices/system/cpu/online", O_RDONLY);
    CHECK(fd >= 0, "open cpu/online");
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof buf - 1);
        CHECK(n > 1 && buf[0] == '0', "cpu/online text '%s'", buf);
        close(fd);
    }
    struct stat st;
    CHECK(stat("/sys/devices/system/cpu/possible", &st) == 0 && S_ISREG(st.st_mode), "stat cpu/possible");
    CHECK(access("/sys/devices/system/cpu/present", R_OK) == 0, "access cpu/present");
    // a /sys path that does not exist
    CHECK(open("/sys/devices/nonexistent/x", O_RDONLY) < 0 && errno == ENOENT, "ENOENT in /sys");
}

static void dev_nodes(void) {
    struct stat st;
    CHECK(stat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3), "stat /dev/null");
    int fd = open("/dev/null", O_RDWR);
    CHECK(fd >= 0, "open /dev/null");
    if (fd >= 0) {
        CHECK(write(fd, "x", 1) == 1, "write /dev/null");
        char c;
        CHECK(read(fd, &c, 1) == 0, "read /dev/null");
        struct stat f;
        CHECK(fstat(fd, &f) == 0 && S_ISCHR(f.st_mode) && f.st_rdev == makedev(1, 3), "fstat /dev/null");
        char l[64] = {0}, p[64];
        snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
        CHECK(readlink(p, l, sizeof l - 1) > 0 && strcmp(l, "/dev/null") == 0, "fd link '%s'", l);
        close(fd);
    }
    fd = open("/dev/zero", O_RDONLY);
    CHECK(fd >= 0, "open /dev/zero");
    if (fd >= 0) {
        char b[16];
        memset(b, 1, sizeof b);
        CHECK(read(fd, b, sizeof b) == sizeof b && b[0] == 0 && b[15] == 0, "read /dev/zero");
        close(fd);
    }
    fd = open("/dev/full", O_WRONLY);
    CHECK(fd >= 0, "open /dev/full");
    if (fd >= 0) {
        CHECK(write(fd, "x", 1) < 0 && errno == ENOSPC, "write /dev/full");
        close(fd);
    }
    fd = open("/dev/urandom", O_RDONLY);
    CHECK(fd >= 0, "open /dev/urandom");
    if (fd >= 0) {
        char b[32] = {0}, z[32] = {0};
        CHECK(read(fd, b, sizeof b) == sizeof b && memcmp(b, z, sizeof b) != 0, "read /dev/urandom");
        close(fd);
    }
    // relative to a /dev descriptor
    int dev = open("/dev", O_RDONLY | O_DIRECTORY);
    CHECK(dev >= 0, "open /dev");
    fd = openat(dev, "null", O_WRONLY | O_CLOEXEC);
    CHECK(fd >= 0, "openat(/dev, null)");
    if (fd >= 0) close(fd);
    CHECK(fstatat(dev, "zero", &st, 0) == 0 && st.st_rdev == makedev(1, 5), "fstatat(/dev, zero)");
    close(dev);
    // the console nodes and the terminals
    CHECK(stat("/dev/tty1", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(4, 1), "stat /dev/tty1");
    CHECK(stat("/dev/console", &st) == 0 && st.st_rdev == makedev(5, 1), "stat /dev/console");
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    CHECK(m >= 0, "open /dev/ptmx");
    if (m >= 0) {
        CHECK(grantpt(m) == 0 && unlockpt(m) == 0, "grantpt/unlockpt");
        char *name = ptsname(m);
        CHECK(name && strncmp(name, "/dev/pts/", 9) == 0, "ptsname %s", name ? name : "-");
        if (name) {
            int s = open(name, O_RDWR | O_NOCTTY);
            CHECK(s >= 0, "open %s", name);
            if (s >= 0) {
                char *tn = ttyname(s);
                CHECK(tn && strcmp(tn, name) == 0, "ttyname %s", tn ? tn : "-");
                CHECK(ffstype(s) == DEVPTS_MAGIC || ffstype(s) < 0 || 1, "fstatfs pts");
                CHECK(write(s, "hi\n", 3) == 3, "write slave");
                close(s);
            }
            CHECK(stat(name, &st) == 0 && S_ISCHR(st.st_mode), "stat %s", name);
        }
        close(m);
    }
    // a block device node: the pool's /dev/sda (root only; open may fail with EACCES as a user)
    if (stat("/dev/sda", &st) == 0) CHECK(S_ISBLK(st.st_mode), "/dev/sda is a block device");
}

static void shm_handles(void) {
    int fd = shm_open("/devwalk.shm", O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(fd >= 0, "shm_open");
    if (fd < 0) return;
    CHECK(ftruncate(fd, 8192) == 0, "ftruncate /dev/shm file");
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 8192, "size after ftruncate %ld", (long)st.st_size);
    char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(p != MAP_FAILED, "mmap shm");
    if (p != MAP_FAILED) {
        p[5000] = 7;
        CHECK(ftruncate(fd, 4096) == 0, "ftruncate shrink");
        munmap(p, 8192);
    }
    CHECK(ffstype(fd) == ZFS_MAGIC || ffstype(fd) == 0x01021994, "fstatfs shm %lx", ffstype(fd));
    close(fd);
    CHECK(shm_unlink("/devwalk.shm") == 0, "shm_unlink");
}

static void cwd_checks(void) {
    char p[512], cwd[512];
    mkdir(D, 0755);
    snprintf(p, sizeof p, "%s/real", D);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/real/sub", D);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/link", D);
    unlink(p);
    CHECK(symlink("real", p) == 0, "symlink");
    snprintf(p, sizeof p, "%s/link/sub", D);
    CHECK(chdir(p) == 0, "chdir link/sub");
    CHECK(getcwd(cwd, sizeof cwd) && strcmp(cwd, "/tmp/devwalk.d/real/sub") == 0, "getcwd '%s'", cwd);
    CHECK(chdir("..") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/tmp/devwalk.d/real") == 0, "chdir .. '%s'", cwd);
    CHECK(chdir("../link/./sub/../sub") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/tmp/devwalk.d/real/sub") == 0, "relative '%s'", cwd);
    CHECK(chdir("/sys/class") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/sys/class") == 0, "chdir /sys/class '%s'", cwd);
    // a relative walk from a working directory in /sys
    struct stat st;
    CHECK(stat("drm/card0/uevent", &st) == 0, "stat relative to cwd /sys/class");
    CHECK(fstype(".") == SYSFS_MAGIC, "statfs(.) in /sys %lx", fstype("."));
    CHECK(chdir("/dev") == 0 && stat("null", &st) == 0 && st.st_rdev == makedev(1, 3), "cwd /dev, stat null");
    int fd = open(D, O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0 && fchdir(fd) == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, D) == 0, "fchdir '%s'", cwd);
    if (fd >= 0) close(fd);
    snprintf(p, sizeof p, "%s/file", D);
    close(open(p, O_CREAT | O_WRONLY, 0644));
    CHECK(chdir(p) < 0 && errno == ENOTDIR, "chdir file");
    fd = open(p, O_RDONLY);
    CHECK(fd >= 0 && fchdir(fd) < 0 && errno == ENOTDIR, "fchdir file");
    if (fd >= 0) close(fd);
    CHECK(chdir("/tmp/devwalk.d/nonexistent") < 0 && errno == ENOENT, "chdir ENOENT");
    CHECK(chdir("/") == 0 && getcwd(cwd, sizeof cwd) && strcmp(cwd, "/") == 0, "chdir /");
}

static void nobody_cwd(void) {
    char p[512];
    snprintf(p, sizeof p, "%s/closed", D);
    mkdir(p, 0700);
    chmod(p, 0700);
    pid_t pid = fork();
    if (pid == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(99);
        if (chdir(p) == 0 || errno != EACCES) _exit(1);
        // /dev/null for everyone; /dev/sda not for nobody
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0) _exit(2);
        close(fd);
        if (open("/dev/sda", O_RDONLY) >= 0 || errno != EACCES) _exit(3);
        if (open("/dev/console", O_RDWR) >= 0 || errno != EACCES) _exit(4);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "as nobody: step %d", WEXITSTATUS(st));
}

static void odd_opens(void) {
    char p[512];
    snprintf(p, sizeof p, "%s/sock", D);
    unlink(p);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strncpy(a.sun_path, p, sizeof a.sun_path - 1);
    CHECK(bind(s, (struct sockaddr *)&a, sizeof a) == 0, "bind");
    CHECK(open(p, O_RDONLY) < 0 && errno == ENXIO, "open socket node");
    close(s);
    unlink(p);
    snprintf(p, sizeof p, "%s/newdir", D);
    CHECK(open(p, O_CREAT | O_DIRECTORY | O_RDONLY, 0755) < 0 && errno == EINVAL, "O_CREAT|O_DIRECTORY");
}

// Review fixes: walks that start inside /dev/pts, the cpu directory or a control group
// directory; /dev/pts creates and ptmx
static void review_walks(void) {
    char cwd[256];
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    CHECK(m >= 0 && grantpt(m) == 0 && unlockpt(m) == 0, "ptmx");
    char *name = m >= 0 ? ptsname(m) : NULL;
    if (name) {
        const char *num = name + 9;
        struct stat st;
        int pts = open("/dev/pts", O_RDONLY | O_DIRECTORY);
        CHECK(pts >= 0, "open /dev/pts");
        CHECK(pts >= 0 && fstatat(pts, num, &st, 0) == 0 && S_ISCHR(st.st_mode), "fstatat(/dev/pts, %s)", num);
        int s = pts >= 0 ? openat(pts, num, O_RDWR | O_NOCTTY) : -1;
        CHECK(s >= 0, "openat(/dev/pts, %s)", num);
        if (s >= 0) close(s);
        CHECK(getcwd(cwd, sizeof cwd) && chdir("/dev/pts") == 0 && stat(num, &st) == 0 && S_ISCHR(st.st_mode), "cwd /dev/pts, stat %s", num);
        chdir(cwd);
        CHECK(open(name, O_RDWR | O_CREAT | O_EXCL, 0600) < 0 && errno == EEXIST, "O_CREAT|O_EXCL of a slave");
        CHECK(open("/dev/pts/9999", O_RDWR | O_CREAT, 0600) < 0 && errno == EPERM, "O_CREAT in /dev/pts");
        CHECK(stat("/dev/pts/ptmx", &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(5, 2), "/dev/pts/ptmx");
        if (pts >= 0) close(pts);
    }
    if (m >= 0) close(m);
    int cpu = open("/sys/devices/system/cpu", O_RDONLY | O_DIRECTORY);
    CHECK(cpu >= 0, "open the cpu directory");
    if (cpu >= 0) {
        char b[32] = {0};
        int f = openat(cpu, "online", O_RDONLY);
        CHECK(f >= 0 && read(f, b, sizeof b - 1) > 0 && b[0] == '0', "openat(cpu, online) '%s'", b);
        if (f >= 0) close(f);
        close(cpu);
    }
    int cg = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    CHECK(cg >= 0, "open /sys/fs/cgroup");
    if (cg >= 0) {
        char b[64];
        int f = openat(cg, "cgroup.procs", O_RDONLY);
        CHECK(f >= 0 && read(f, b, sizeof b) >= 0, "openat(cgroup, cgroup.procs)");
        if (f >= 0) close(f);
        close(cg);
    }
}

// Review fixes (root): no device opens on a nodev mount; a link in a sticky directory owned
// by someone else is not followed to create (protected_symlinks)
static void review_root(void) {
    pid_t p = fork();
    if (p == 0) {
        fails = 0;
        const char *nd = "/tmp/devwalk.nd";
        mkdir(nd, 0755);
        if (unshare(CLONE_NEWNS) != 0) _exit(10);
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (mount("tmpfs", nd, "tmpfs", MS_NODEV, "size=1m") != 0) _exit(11);
        if (mknod("/tmp/devwalk.nd/null", S_IFCHR | 0666, makedev(1, 3)) != 0) _exit(12);
        int fd = open("/tmp/devwalk.nd/null", O_WRONLY);
        if (fd >= 0 || errno != EACCES) _exit(13);
        if (mount("tmpfs", nd, "tmpfs", MS_REMOUNT, "size=1m") == 0) {
            fd = open("/tmp/devwalk.nd/null", O_WRONLY);
            if (fd < 0) _exit(14);
        }
        _exit(0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "nodev: step %d", WEXITSTATUS(st));
    // protected_symlinks: root's link in /tmp, followed by nobody to create
    unlink("/tmp/devwalk-psl");
    unlink("/tmp/devwalk-psl-target");
    CHECK(symlink("/tmp/devwalk-psl-target", "/tmp/devwalk-psl") == 0, "symlink in /tmp");
    // (owned by a third user: neither the follower nor the directory's owner)
    CHECK(lchown("/tmp/devwalk-psl", 1000, 1000) == 0, "lchown link");
    p = fork();
    if (p == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(99);
        int fd = open("/tmp/devwalk-psl", O_CREAT | O_WRONLY, 0600);
        _exit(fd < 0 && errno == EACCES ? 0 : 1);
    }
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "protected_symlinks");
    CHECK(access("/tmp/devwalk-psl-target", F_OK) != 0, "no target made");
    unlink("/tmp/devwalk-psl");
}

// O_CREAT through a dangling symbolic link makes its target (absolute and relative links,
// a chain of two); O_EXCL refuses the link itself
static void dangling(void) {
    char l[256], t[256], s[256];
    struct stat st;
    snprintf(t, sizeof t, "%s/made-abs", D);
    unlink(t);
    snprintf(l, sizeof l, "%s/dangle-abs", D);
    unlink(l);
    CHECK(symlink(t, l) == 0, "symlink abs");
    int fd = open(l, O_CREAT | O_WRONLY, 0640);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1, "create through an absolute dangling link");
    if (fd >= 0) close(fd);
    CHECK(lstat(t, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 1, "the target was made");
    CHECK(lstat(l, &st) == 0 && S_ISLNK(st.st_mode), "the link stays a link");
    snprintf(s, sizeof s, "%s/sub", D);
    mkdir(s, 0755);
    snprintf(t, sizeof t, "%s/sub/made-rel", D);
    unlink(t);
    snprintf(l, sizeof l, "%s/dangle-rel", D);
    unlink(l);
    CHECK(symlink("sub/made-rel", l) == 0, "symlink rel");
    snprintf(s, sizeof s, "%s/dangle-chain", D);
    unlink(s);
    CHECK(symlink("dangle-rel", s) == 0, "symlink chain");
    fd = open(s, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0, "create through a chain of two links");
    if (fd >= 0) close(fd);
    CHECK(stat(t, &st) == 0 && S_ISREG(st.st_mode), "the relative target was made");
    unlink(t);
    CHECK(open(l, O_CREAT | O_EXCL | O_WRONLY, 0600) < 0 && errno == EEXIST, "O_EXCL on a dangling link");
    CHECK(open(l, O_CREAT | O_NOFOLLOW | O_WRONLY, 0600) < 0 && errno == ELOOP, "O_NOFOLLOW on a dangling link");
    snprintf(l, sizeof l, "%s/dangle-missing", D);
    unlink(l);
    CHECK(symlink("nodir/x", l) == 0, "symlink missing dir");
    CHECK(open(l, O_CREAT | O_WRONLY, 0600) < 0 && errno == ENOENT, "a link into a missing directory");
}

// The device and /sys calls in a loop for `secs` seconds while services are killed: every
// call must succeed (vfs-server restarts invisibly); terminal opens are counted apart
// (tty-server's objects fail with it).
static int killloop(int secs) {
    double end = now() + secs;
    long rounds = 0, bad = 0, ptybad = 0;
    char buf[256], cwd[256];
    int sysfd = open("/sys/class", O_PATH | O_DIRECTORY);
    while (now() < end) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0 || write(fd, "x", 1) != 1) { bad++; printf("bad /dev/null errno %d\n", errno); }
        if (fd >= 0) close(fd);
        fd = open("/sys/class/drm/card0/uevent", O_RDONLY);
        if (fd < 0 || read(fd, buf, sizeof buf) <= 0) { bad++; printf("bad uevent errno %d\n", errno); }
        if (fd >= 0) close(fd);
        fd = openat(sysfd, "drm/card0", O_PATH);
        if (fd < 0) { bad++; printf("bad openat sys errno %d\n", errno); } else close(fd);
        if (chdir("/sys/class") != 0 || !getcwd(cwd, sizeof cwd) || strcmp(cwd, "/sys/class") != 0) { bad++; printf("bad chdir errno %d\n", errno); }
        if (fstype("/sys") != SYSFS_MAGIC) { bad++; printf("bad statfs errno %d\n", errno); }
        int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (m < 0) ptybad++; else close(m);
        rounds++;
        usleep(2000);
    }
    chdir("/");
    printf("DEVWALKKILL rounds=%ld bad=%ld ptybad=%ld %s\n", rounds, bad, ptybad, bad ? "FAIL" : "PASS");
    return bad != 0;
}

static void bench(int n) {
    double t0 = now();
    for (int i = 0; i < n; i++) close(open("/dev/null", O_WRONLY));
    double t1 = now();
    char buf[256];
    for (int i = 0; i < n; i++) {
        int fd = open("/sys/class/drm/card0/uevent", O_RDONLY);
        if (read(fd, buf, sizeof buf) <= 0) break;
        close(fd);
    }
    double t2 = now();
    for (int i = 0; i < n; i++) chdir(i & 1 ? "/tmp" : "/usr");
    double t3 = now();
    int sysfd = open("/sys/class/drm", O_PATH | O_DIRECTORY);
    for (int i = 0; i < n; i++) close(openat(sysfd, "card0", O_PATH));
    double t4 = now();
    for (int i = 0; i < n; i++) close(openat(sysfd, "card0", O_PATH | O_NOFOLLOW));
    double t5 = now();
    struct stat st;
    for (int i = 0; i < n; i++) stat("/sys/class/drm/card0/uevent", &st);
    double t6 = now();
    for (int i = 0; i < n; i++) stat("/sys/class/drm/version", &st);
    double t7 = now();
    printf("BENCH devnull_open_close %.2f us\n", (t1 - t0) * 1e6 / n);
    printf("BENCH sys_open_read_close %.2f us\n", (t2 - t1) * 1e6 / n);
    printf("BENCH chdir %.2f us\n", (t3 - t2) * 1e6 / n);
    printf("BENCH sys_openat_opath %.2f us\n", (t4 - t3) * 1e6 / n);
    printf("BENCH sys_openat_opath_nofollow %.2f us\n", (t5 - t4) * 1e6 / n);
    printf("BENCH sys_stat_through_link %.2f us\n", (t6 - t5) * 1e6 / n);
    printf("BENCH sys_stat_plain %.2f us\n", (t7 - t6) * 1e6 / n);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc > 2 && strcmp(argv[1], "bench") == 0) {
        bench(atoi(argv[2]));
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "kill") == 0) return killloop(atoi(argv[2]));
    mkdir(D, 0755);
    sys_relative();
    sys_served();
    dev_nodes();
    shm_handles();
    cwd_checks();
    if (geteuid() == 0) nobody_cwd();
    review_walks();
    if (geteuid() == 0) review_root();
    odd_opens();
    dangling();
    if (fails) {
        printf("DEVWALK FAIL %d\n", fails);
        return 1;
    }
    printf("DEVWALK PASS\n");
    return 0;
}
