// vfschange: the change calls vfs-server serves since wave 10 (Group V1).
//
//   vfschange          checks (prints FAIL lines, then VFSCHANGE PASS / VFSCHANGE FAIL n);
//                      run as root (mount namespace, device nodes, other users by setresuid)
//   vfschange bench N  N rounds of each change call, microseconds per call
//
// Covers: O_CREAT|O_EXCL races, creat's mode and umask, truncating opens, truncate of an
// mmap'd file, O_TMPFILE + linkat, xattrs round trip, POSIX ACLs (set, chmod, inheritance),
// utimensat with UTIME_NOW / UTIME_OMIT, utime(s), mknod (FIFO, socket, regular, device),
// link, O_PATH, statfs/fstatfs (pool and tmpfs), fchmodat2, EROFS on a read-only bind mount.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

#ifndef O_TMPFILE
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); fflush(stdout); } } while (0)

static const char *D = "/tmp/vfschange.d";

static void path(char *out, const char *name) { snprintf(out, 256, "%s/%s", D, name); }

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// Runs f in a child as user/group 65534 (nobody); returns its exit status.
static int as_nobody(void (*f)(const char *), const char *arg) {
    pid_t p = fork();
    if (p == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(99);
        fails = 0;
        f(arg);
        _exit(fails);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 98;
}

// --- O_CREAT | O_EXCL: of several racing creators exactly one wins --------------------------
static void excl_race(void) {
    char p[256];
    path(p, "race");
    for (int round = 0; round < 20; round++) {
        unlink(p);
        int go[2];
        if (pipe(go)) return;
        const int N = 6;
        pid_t kids[6];
        for (int i = 0; i < N; i++) {
            kids[i] = fork();
            if (kids[i] == 0) {
                char b;
                close(go[1]);
                if (read(go[0], &b, 1) != 0) _exit(3);
                int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0600);
                if (fd >= 0) _exit(0);
                _exit(errno == EEXIST ? 1 : 2);
            }
        }
        close(go[0]);
        close(go[1]); // everyone starts at once
        int won = 0, lost = 0, other = 0;
        for (int i = 0; i < N; i++) {
            int st;
            waitpid(kids[i], &st, 0);
            int r = WIFEXITED(st) ? WEXITSTATUS(st) : 9;
            if (r == 0) won++; else if (r == 1) lost++; else other++;
        }
        CHECK(won == 1 && lost == N - 1 && other == 0, "round %d: won %d lost %d other %d", round, won, lost, other);
    }
    // O_CREAT without O_EXCL on an existing file opens it (no truncation)
    int fd = open(p, O_WRONLY | O_TRUNC);
    CHECK(fd >= 0 && write(fd, "abc", 3) == 3, "write");
    close(fd);
    fd = open(p, O_CREAT | O_RDWR, 0600);
    struct stat st;
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 3, "O_CREAT of an existing file kept its size");
    close(fd);
    CHECK(open(p, O_CREAT | O_EXCL | O_RDWR, 0600) < 0 && errno == EEXIST, "EEXIST");
    // O_EXCL does not follow a symbolic link, even a dangling one
    char l[256];
    path(l, "dangling");
    unlink(l);
    CHECK(symlink("/tmp/vfschange.d/nothere", l) == 0, "symlink");
    CHECK(open(l, O_CREAT | O_EXCL | O_RDWR, 0600) < 0 && errno == EEXIST, "O_EXCL on a dangling link");
    // A trailing slash: EISDIR
    char t[256];
    path(t, "slash/");
    CHECK(open(t, O_CREAT | O_RDWR, 0600) < 0 && errno == EISDIR, "O_CREAT name/: EISDIR");
    // A missing directory on the way: ENOENT
    path(t, "nodir/file");
    CHECK(open(t, O_CREAT | O_RDWR, 0600) < 0 && errno == ENOENT, "ENOENT");
}

// --- creat's mode, the umask, and the access a new file opens with ---------------------------
static void create_mode(void) {
    char p[256];
    path(p, "mode");
    unlink(p);
    mode_t old = umask(022);
    int fd = creat(p, 0666);
    struct stat st;
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0644 && S_ISREG(st.st_mode), "creat 0666 umask 022: %o", st.st_mode);
    CHECK(st.st_uid == geteuid() && st.st_gid == getegid(), "owner");
    close(fd);
    unlink(p);
    // creat(path, 0444): the descriptor is writable all the same
    fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0444);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1, "write to a new 0444 file");
    close(fd);
    // ... but a second open for writing is refused (for a user that is not root)
    umask(old);
}

static void nobody_open_ro(const char *p) {
    CHECK(open(p, O_WRONLY) < 0 && errno == EACCES, "EACCES for nobody on 0444");
    CHECK(open("/tmp/vfschange.d/nobody-new", O_CREAT | O_WRONLY, 0600) < 0 && errno == EACCES, "create in a 0755 root dir: EACCES");
}

// --- truncating opens, truncate and ftruncate; the page cache of an mmap'd file -------------
static sigjmp_buf jb;
static void on_bus(int s) { (void)s; siglongjmp(jb, 1); }

static void truncs(void) {
    char p[256];
    path(p, "trunc");
    unlink(p);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    char buf[10000];
    memset(buf, 'a', sizeof buf);
    CHECK(fd >= 0 && write(fd, buf, sizeof buf) == (ssize_t)sizeof buf, "write");
    close(fd);
    fd = open(p, O_WRONLY | O_TRUNC);
    struct stat st;
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0, "O_TRUNC: size %ld", (long)st.st_size);
    CHECK(stat(p, &st) == 0 && st.st_size == 0, "stat after O_TRUNC");
    close(fd);
    // O_RDONLY | O_TRUNC does not truncate here (as the kernel's open)
    fd = open(p, O_RDWR);
    CHECK(write(fd, "hello", 5) == 5, "write");
    close(fd);
    // truncate of an mmap'd file: the pages past the end go (SIGBUS), what is left reads 0
    long pg = sysconf(_SC_PAGESIZE);
    fd = open(p, O_RDWR);
    char *big = malloc(3 * pg);
    memset(big, 'b', 3 * pg);
    CHECK(pwrite(fd, big, 3 * pg, 0) == 3 * pg, "pwrite");
    char *m = mmap(0, 3 * pg, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED, "mmap");
    if (m != MAP_FAILED) {
        CHECK(m[2 * pg] == 'b', "mapped before");
        CHECK(ftruncate(fd, pg) == 0, "ftruncate");
        CHECK(fstat(fd, &st) == 0 && st.st_size == pg, "size after ftruncate %ld", (long)st.st_size);
        struct sigaction sa = {0}, old;
        sa.sa_handler = on_bus;
        sigaction(SIGBUS, &sa, &old);
        volatile int bus = 0;
        if (sigsetjmp(jb, 1) == 0) {
            volatile char c = m[2 * pg];
            (void)c;
        } else {
            bus = 1;
        }
        CHECK(bus, "SIGBUS past the new end");
        CHECK(m[0] == 'b', "first page kept");
        // truncate by path to 0, then grow: the mapping reads zeros
        CHECK(truncate(p, 0) == 0, "truncate");
        CHECK(ftruncate(fd, 2 * pg) == 0, "grow");
        CHECK(m[0] == 0 && m[pg] == 0, "zeros after truncate+grow: %d %d", m[0], m[pg]);
        // a truncating open while mapped
        m[0] = 'z';
        int fd2 = open(p, O_WRONLY | O_TRUNC);
        CHECK(fd2 >= 0, "O_TRUNC while mapped");
        close(fd2);
        CHECK(stat(p, &st) == 0 && st.st_size == 0, "size 0");
        bus = 0;
        if (sigsetjmp(jb, 1) == 0) {
            volatile char c = m[0];
            (void)c;
        } else {
            bus = 1;
        }
        CHECK(bus, "SIGBUS after O_TRUNC of a mapped file");
        sigaction(SIGBUS, &old, 0);
        munmap(m, 3 * pg);
    }
    free(big);
    close(fd);
    CHECK(truncate(p, -1) < 0 && errno == EINVAL, "truncate -1");
    fd = open(p, O_RDONLY);
    CHECK(ftruncate(fd, 0) < 0 && errno == EINVAL, "ftruncate of a read-only descriptor");
    close(fd);
}

// --- O_TMPFILE and linkat -------------------------------------------------------------------
static void tmpfile_link(void) {
    int fd = open(D, O_TMPFILE | O_RDWR, 0640);
    CHECK(fd >= 0, "O_TMPFILE");
    if (fd < 0) return;
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_nlink == 0 && S_ISREG(st.st_mode), "nlink %ld", (long)st.st_nlink);
    CHECK(write(fd, "tmpdata", 7) == 7, "write");
    char p[256];
    path(p, "tmplinked");
    unlink(p);
    CHECK(linkat(fd, "", AT_FDCWD, p, AT_EMPTY_PATH) == 0, "linkat AT_EMPTY_PATH");
    CHECK(stat(p, &st) == 0 && st.st_nlink == 1 && st.st_size == 7, "linked: nlink %ld size %ld", (long)st.st_nlink, (long)st.st_size);
    close(fd);
    char b[16] = {0};
    fd = open(p, O_RDONLY);
    CHECK(fd >= 0 && read(fd, b, 16) == 7 && memcmp(b, "tmpdata", 7) == 0, "content after close");
    close(fd);
    // The directory listing shows no hidden name left
    // O_TMPFILE | O_EXCL: never linked
    fd = open(D, O_TMPFILE | O_RDWR | O_EXCL, 0600);
    CHECK(fd >= 0, "O_TMPFILE|O_EXCL");
    path(p, "tmpexcl");
    unlink(p);
    CHECK(linkat(fd, "", AT_FDCWD, p, AT_EMPTY_PATH) < 0 && errno == ENOENT, "linkat of an O_EXCL tmpfile: ENOENT");
    close(fd);
    // Read-only: EINVAL; not a directory: ENOTDIR
    CHECK(open(D, O_TMPFILE | O_RDONLY, 0600) < 0 && errno == EINVAL, "O_TMPFILE|O_RDONLY");
    path(p, "tmplinked");
    CHECK(open(p, O_TMPFILE | O_RDWR, 0600) < 0 && errno == ENOTDIR, "O_TMPFILE on a file");
    // A tmpfile dropped at close: nothing named appears
    fd = open(D, O_TMPFILE | O_WRONLY, 0600);
    CHECK(fd >= 0 && write(fd, "gone", 4) == 4, "tmpfile 3");
    close(fd);
    // through /proc/self/fd with AT_SYMLINK_FOLLOW (the kernel's path)
    fd = open(D, O_TMPFILE | O_RDWR, 0600);
    char pfd[64];
    snprintf(pfd, sizeof pfd, "/proc/self/fd/%d", fd);
    path(p, "tmpproc");
    unlink(p);
    CHECK(fd >= 0 && linkat(AT_FDCWD, pfd, AT_FDCWD, p, AT_SYMLINK_FOLLOW) == 0, "linkat /proc/self/fd");
    CHECK(stat(p, &st) == 0 && st.st_nlink == 1, "proc link nlink");
    close(fd);
    CHECK(stat(p, &st) == 0, "proc link survives close");
}

// --- xattrs --------------------------------------------------------------------------------
static void nobody_xattr(const char *p) {
    CHECK(setxattr(p, "trusted.x", "1", 1, 0) < 0 && errno == EPERM, "trusted.* as nobody: EPERM");
    CHECK(setxattr(p, "user.n", "1", 1, 0) < 0 && errno == EACCES, "user.* without write: EACCES");
    char b[8];
    CHECK(getxattr(p, "user.test", b, sizeof b) == 4, "user.* read by nobody");
}

static void xattrs(void) {
    char p[256], l[256];
    path(p, "xa");
    path(l, "xalink");
    unlink(p);
    unlink(l);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    close(fd);
    CHECK(setxattr(p, "user.test", "abc", 3, 0) == 0, "setxattr");
    char b[64];
    CHECK(getxattr(p, "user.test", 0, 0) == 3, "size query");
    CHECK(getxattr(p, "user.test", b, sizeof b) == 3 && memcmp(b, "abc", 3) == 0, "getxattr");
    CHECK(getxattr(p, "user.test", b, 2) < 0 && errno == ERANGE, "ERANGE");
    CHECK(setxattr(p, "user.test", "x", 1, XATTR_CREATE) < 0 && errno == EEXIST, "XATTR_CREATE");
    CHECK(setxattr(p, "user.none", "x", 1, XATTR_REPLACE) < 0 && errno == ENODATA, "XATTR_REPLACE");
    CHECK(setxattr(p, "user.test", "defg", 4, XATTR_REPLACE) == 0, "replace");
    CHECK(getxattr(p, "user.test", b, sizeof b) == 4 && memcmp(b, "defg", 4) == 0, "replaced");
    CHECK(setxattr(p, "nonamespace", "x", 1, 0) < 0 && errno == EOPNOTSUPP, "no namespace");
    CHECK(setxattr(p, "user.", "x", 1, 0) < 0 && errno == EINVAL, "prefix alone");
    ssize_t n = listxattr(p, b, sizeof b);
    CHECK(n > 0 && memmem(b, n, "user.test", 10) != 0, "listxattr %ld", (long)n);
    CHECK(listxattr(p, 0, 0) == n, "list size query");
    CHECK(setxattr(p, "trusted.t", "1", 1, 0) == 0, "trusted as root");
    // fsetxattr / fgetxattr / flistxattr / fremovexattr
    fd = open(p, O_RDONLY);
    CHECK(fsetxattr(fd, "user.f", "ff", 2, 0) == 0, "fsetxattr");
    CHECK(fgetxattr(fd, "user.f", b, sizeof b) == 2, "fgetxattr");
    CHECK(flistxattr(fd, b, sizeof b) > 0, "flistxattr");
    CHECK(fremovexattr(fd, "user.f") == 0, "fremovexattr");
    CHECK(fgetxattr(fd, "user.f", b, sizeof b) < 0 && errno == ENODATA, "gone");
    close(fd);
    // user.* on a symbolic link: EPERM (lsetxattr), ENODATA (lgetxattr)
    CHECK(symlink("xa", l) == 0, "symlink");
    CHECK(lsetxattr(l, "user.l", "1", 1, 0) < 0 && errno == EPERM, "lsetxattr user.* on a link");
    CHECK(lgetxattr(l, "user.l", b, sizeof b) < 0 && errno == ENODATA, "lgetxattr");
    CHECK(getxattr(l, "user.test", b, sizeof b) == 4, "getxattr follows");
    // security.capability: validated
    CHECK(setxattr(p, "security.capability", "bad", 3, 0) < 0 && errno == EINVAL, "bad fcaps");
    if (as_nobody(nobody_xattr, p) != 0) {
        fails++;
        printf("FAIL xattrs: nobody's checks\n");
    }
    CHECK(removexattr(p, "user.test") == 0, "removexattr");
    CHECK(getxattr(p, "user.test", b, sizeof b) < 0 && errno == ENODATA, "removed");
    CHECK(removexattr(p, "user.test") < 0 && errno == ENODATA, "remove again");
}

// --- POSIX ACLs ------------------------------------------------------------------------------
struct acl_e { uint16_t tag, perm; uint32_t id; };
static size_t acl_make(char *out, const struct acl_e *e, int n) {
    uint32_t v = 2;
    memcpy(out, &v, 4);
    memcpy(out + 4, e, n * sizeof *e);
    return 4 + n * sizeof *e;
}

static void acls(void) {
    char p[256], dir[256], child[256], sub[256];
    path(p, "aclfile");
    unlink(p);
    close(open(p, O_CREAT | O_RDWR, 0640));
    // user::rw- user:1000:r-- group::r-- mask::r-x other::---
    struct acl_e e[] = {{1, 6, 0}, {2, 4, 1000}, {4, 4, 0}, {0x10, 5, 0}, {0x20, 0, 0}};
    char b[256];
    size_t n = acl_make(b, e, 5);
    CHECK(setxattr(p, "system.posix_acl_access", b, n, 0) == 0, "set access ACL");
    struct stat st;
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0650, "mode from the ACL: %o", st.st_mode & 0777);
    // chmod 0600: mask::---
    CHECK(chmod(p, 0600) == 0, "chmod");
    char r[256];
    ssize_t k = getxattr(p, "system.posix_acl_access", r, sizeof r);
    CHECK(k == (ssize_t)n, "ACL kept: %ld", (long)k);
    if (k == (ssize_t)n) {
        struct acl_e *x = (struct acl_e *)(r + 4);
        CHECK(x[3].tag == 0x10 && x[3].perm == 0 && x[0].perm == 6 && x[4].perm == 0, "mask after chmod 0600: %d", x[3].perm);
    }
    // An invalid ACL (no mask with a named user): EINVAL
    struct acl_e bad[] = {{1, 6, 0}, {2, 4, 1000}, {4, 4, 0}, {0x20, 0, 0}};
    n = acl_make(b, bad, 4);
    CHECK(setxattr(p, "system.posix_acl_access", b, n, 0) < 0 && errno == EINVAL, "invalid ACL");
    // A default ACL on a directory: new files inherit it (no umask), directories also the default
    path(dir, "acldir");
    snprintf(child, sizeof child, "%s/f", dir);
    snprintf(sub, sizeof sub, "%s/sub", dir);
    unlink(child);
    rmdir(sub);
    rmdir(dir);
    CHECK(mkdir(dir, 0755) == 0, "mkdir");
    struct acl_e d[] = {{1, 7, 0}, {2, 5, 1000}, {4, 5, 0}, {0x10, 7, 0}, {0x20, 0, 0}};
    n = acl_make(b, d, 5);
    CHECK(setxattr(dir, "system.posix_acl_default", b, n, 0) == 0, "set default ACL");
    CHECK(setxattr(p, "system.posix_acl_default", b, n, 0) < 0 && errno == EACCES, "default ACL on a file: EACCES");
    mode_t old = umask(077);
    int fd = open(child, O_CREAT | O_RDWR, 0666);
    CHECK(fd >= 0, "create in a dir with a default ACL");
    close(fd);
    CHECK(stat(child, &st) == 0 && (st.st_mode & 0777) == 0660, "inherited mode %o (umask not applied)", st.st_mode & 0777);
    k = getxattr(child, "system.posix_acl_access", r, sizeof r);
    CHECK(k == (ssize_t)n, "access ACL inherited: %ld", (long)k);
    CHECK(getxattr(child, "system.posix_acl_default", r, sizeof r) < 0, "a file gets no default ACL");
    CHECK(mkdir(sub, 0777) == 0, "mkdir in it");
    CHECK(getxattr(sub, "system.posix_acl_default", r, sizeof r) == (ssize_t)n, "subdirectory inherits the default ACL");
    CHECK(stat(sub, &st) == 0 && (st.st_mode & 0777) == 0770, "sub mode %o", st.st_mode & 0777);
    umask(old);
    // removing: the mode stays
    CHECK(removexattr(p, "system.posix_acl_access") == 0, "remove ACL");
    CHECK(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600, "mode after removing %o", st.st_mode & 0777);
}

// --- utimensat, utimes, utime --------------------------------------------------------------
static void nobody_times(const char *p) {
    // p is 0666 root's: "now" allowed (write access), explicit times not
    CHECK(utimensat(AT_FDCWD, p, 0, 0) == 0, "nobody: now on a writable file");
    struct timespec ts[2] = {{1000, 0}, {2000, 0}};
    CHECK(utimensat(AT_FDCWD, p, ts, 0) < 0 && errno == EPERM, "nobody: explicit times EPERM");
    CHECK(utimes(p, 0) == 0, "nobody: utimes NULL");
    CHECK(chmod(p, 0600) < 0 && errno == EPERM, "nobody: chmod EPERM");
}

static void nobody_times_ro(const char *p) {
    CHECK(utimensat(AT_FDCWD, p, 0, 0) < 0 && errno == EACCES, "nobody: now on a 0644 root file: EACCES");
}

static void times(void) {
    char p[256];
    path(p, "times");
    unlink(p);
    close(open(p, O_CREAT | O_RDWR, 0666));
    chmod(p, 0666);
    struct timespec ts[2] = {{1000, 5}, {2000, 7}};
    struct stat st;
    CHECK(utimensat(AT_FDCWD, p, ts, 0) == 0, "utimensat explicit");
    CHECK(stat(p, &st) == 0 && st.st_atim.tv_sec == 1000 && st.st_mtim.tv_sec == 2000 && st.st_mtim.tv_nsec == 7, "times %ld %ld", (long)st.st_atim.tv_sec, (long)st.st_mtim.tv_sec);
    // UTIME_OMIT keeps atime, UTIME_NOW sets mtime
    struct timespec ts2[2] = {{0, UTIME_OMIT}, {0, UTIME_NOW}};
    time_t t0 = time(0);
    CHECK(utimensat(AT_FDCWD, p, ts2, 0) == 0, "OMIT/NOW");
    CHECK(stat(p, &st) == 0 && st.st_atim.tv_sec == 1000 && st.st_mtim.tv_sec >= t0 - 2 && st.st_mtim.tv_sec <= t0 + 5, "omit kept atime %ld, now mtime %ld (t0 %ld)", (long)st.st_atim.tv_sec, (long)st.st_mtim.tv_sec, (long)t0);
    struct timespec ts3[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    CHECK(utimensat(AT_FDCWD, p, ts3, 0) == 0, "both omitted");
    struct timespec badns[2] = {{0, 2000000000L}, {0, 0}};
    CHECK(utimensat(AT_FDCWD, p, badns, 0) < 0 && errno == EINVAL, "bad nsec");
    // futimens (empty path on a descriptor)
    int fd = open(p, O_RDONLY);
    struct timespec ts4[2] = {{3000, 0}, {4000, 0}};
    CHECK(futimens(fd, ts4) == 0, "futimens");
    CHECK(fstat(fd, &st) == 0 && st.st_mtim.tv_sec == 4000, "futimens mtime");
    close(fd);
    // utimes / utime / futimesat
    struct timeval tv[2] = {{5000, 1}, {6000, 2}};
    CHECK(utimes(p, tv) == 0, "utimes");
    CHECK(stat(p, &st) == 0 && st.st_mtim.tv_sec == 6000 && st.st_mtim.tv_nsec == 2000, "utimes mtime %ld.%ld", (long)st.st_mtim.tv_sec, (long)st.st_mtim.tv_nsec);
    struct utimbuf ub = {7000, 8000};
    CHECK(utime(p, &ub) == 0, "utime");
    CHECK(stat(p, &st) == 0 && st.st_mtim.tv_sec == 8000 && st.st_atim.tv_sec == 7000, "utime times");
    CHECK(futimesat(AT_FDCWD, p, tv) == 0, "futimesat");
    t0 = time(0);
    CHECK(utime(p, 0) == 0, "utime NULL");
    CHECK(stat(p, &st) == 0 && st.st_mtim.tv_sec >= t0 - 2, "utime NULL = now");
    if (as_nobody(nobody_times, p) != 0) {
        fails++;
        printf("FAIL times: nobody's checks\n");
    }
    chmod(p, 0644);
    if (as_nobody(nobody_times_ro, p) != 0) {
        fails++;
        printf("FAIL times: nobody on 0644\n");
    }
}

// --- mknod, link, fchmodat2 ------------------------------------------------------------------
static void nobody_mknod(const char *p) {
    CHECK(mknod(p, S_IFCHR | 0600, makedev(1, 3)) < 0 && (errno == EPERM || errno == EACCES), "device node as nobody");
}

static void nodes(void) {
    char p[256];
    struct stat st;
    path(p, "fifo");
    unlink(p);
    CHECK(mkfifo(p, 0600) == 0 && stat(p, &st) == 0 && S_ISFIFO(st.st_mode), "mkfifo");
    path(p, "sock");
    unlink(p);
    CHECK(mknod(p, S_IFSOCK | 0600, 0) == 0 && stat(p, &st) == 0 && S_ISSOCK(st.st_mode), "mknod S_IFSOCK");
    path(p, "reg");
    unlink(p);
    CHECK(mknod(p, S_IFREG | 0640, 0) == 0 && stat(p, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 0, "mknod S_IFREG");
    path(p, "null");
    unlink(p);
    CHECK(mknod(p, S_IFCHR | 0666, makedev(1, 3)) == 0, "mknod S_IFCHR");
    CHECK(stat(p, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 1 && minor(st.st_rdev) == 3, "rdev %d:%d", major(st.st_rdev), minor(st.st_rdev));
    int fd = open(p, O_WRONLY);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1, "write to the node /dev/null");
    close(fd);
    CHECK(mknod(p, S_IFIFO | 0600, 0) < 0 && errno == EEXIST, "mknod EEXIST");
    path(p, "nobody-null");
    // nobody cannot make device nodes (nor anything in a root 0755 dir)
    if (as_nobody(nobody_mknod, "/tmp/vfschange.d/pub/nnode") != 0) {
        fails++;
        printf("FAIL nodes: nobody's checks\n");
    }
    // link
    char a[256], b[256];
    path(a, "linka");
    path(b, "linkb");
    unlink(a);
    unlink(b);
    close(open(a, O_CREAT | O_RDWR, 0600));
    CHECK(link(a, b) == 0, "link");
    CHECK(stat(a, &st) == 0 && st.st_nlink == 2, "nlink 2: %ld", (long)st.st_nlink);
    CHECK(link(a, b) < 0 && errno == EEXIST, "link EEXIST");
    CHECK(link(D, b) < 0 && (errno == EPERM || errno == EEXIST), "link of a directory");
    path(b, "linkc");
    unlink(b);
    CHECK(link(D, b) < 0 && errno == EPERM, "link of a directory: EPERM");
    int dfd = open(D, O_RDONLY | O_DIRECTORY);
    CHECK(linkat(dfd, "linka", dfd, "linkd", 0) == 0, "linkat with dirfds");
    unlinkat(dfd, "linkd", 0);
    close(dfd);
    CHECK(unlink(a) == 0 && stat(b, &st) < 0, "unlink");
    // fchmodat2
#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif
    path(p, "reg");
    CHECK(syscall(SYS_fchmodat2, AT_FDCWD, p, 0604, 0) == 0 && stat(p, &st) == 0 && (st.st_mode & 0777) == 0604, "fchmodat2");
    CHECK(syscall(SYS_fchmodat2, AT_FDCWD, p, 0604, 0x8000) < 0 && errno == EINVAL, "fchmodat2 bad flags");
}

// --- O_PATH ----------------------------------------------------------------------------------
static void opath(void) {
    char p[256], l[256];
    path(p, "opath");
    path(l, "opathlink");
    unlink(p);
    unlink(l);
    close(open(p, O_CREAT | O_RDWR, 0000));
    symlink("opath", l);
    int fd = open(p, O_PATH);
    struct stat st;
    char b[4];
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode), "O_PATH of a 0000 file");
    CHECK(read(fd, b, 1) < 0 && errno == EBADF, "read on O_PATH: EBADF");
    close(fd);
    fd = open(l, O_PATH | O_NOFOLLOW);
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && S_ISLNK(st.st_mode), "O_PATH|O_NOFOLLOW of a link");
    close(fd);
    fd = open(D, O_PATH | O_DIRECTORY);
    CHECK(fd >= 0, "O_PATH dir");
    struct stat st2;
    CHECK(fstatat(fd, "opath", &st2, 0) == 0 && S_ISREG(st2.st_mode), "O_PATH dir as dirfd");
    close(fd);
    CHECK(open(p, O_PATH | O_DIRECTORY) < 0 && errno == ENOTDIR, "O_PATH|O_DIRECTORY on a file");
}

// --- statfs ----------------------------------------------------------------------------------
static void statfss(void) {
    struct statfs s1, s2;
    CHECK(statfs(D, &s1) == 0 && s1.f_type == 0x2fc12fc1 && s1.f_blocks > 0, "statfs pool type %lx", (long)s1.f_type);
    int fd = open(D, O_RDONLY);
    CHECK(fstatfs(fd, &s2) == 0 && s2.f_type == s1.f_type && s2.f_bsize == 4096, "fstatfs");
    close(fd);
}

// --- a mount namespace: EROFS on a read-only bind mount, a tmpfs's statfs ---------------------
static void in_ns(void) {
    char ro[256], f[256], g[256];
    path(ro, "ro");
    snprintf(f, sizeof f, "%s/file", ro);
    snprintf(g, sizeof g, "%s/new", ro);
    if (unshare(CLONE_NEWNS) != 0) {
        fails++;
        printf("FAIL in_ns: unshare (errno %d)\n", errno);
        return;
    }
    mount("none", "/", 0, MS_REC | MS_PRIVATE, 0);
    CHECK(mount(ro, ro, 0, MS_BIND, 0) == 0, "bind");
    CHECK(mount(0, ro, 0, MS_REMOUNT | MS_BIND | MS_RDONLY, 0) == 0, "remount ro");
    struct stat st;
    CHECK(stat(f, &st) == 0, "stat in ro");
    int fd = open(f, O_RDONLY);
    CHECK(fd >= 0, "read-only open in ro");
    close(fd);
    CHECK(open(f, O_WRONLY) < 0 && errno == EROFS, "open for writing: EROFS");
    CHECK(open(f, O_RDONLY | O_TRUNC) < 0 && errno == EROFS, "O_TRUNC: EROFS");
    CHECK(open(g, O_CREAT | O_RDWR, 0600) < 0 && errno == EROFS, "create: EROFS");
    CHECK(mkdir(g, 0700) < 0 && errno == EROFS, "mkdir: EROFS");
    CHECK(mknod(g, S_IFIFO | 0600, 0) < 0 && errno == EROFS, "mknod: EROFS");
    CHECK(link(f, g) < 0 && errno == EROFS, "link: EROFS");
    CHECK(truncate(f, 0) < 0 && errno == EROFS, "truncate: EROFS");
    CHECK(chmod(f, 0600) < 0 && errno == EROFS, "chmod: EROFS");
    CHECK(utimensat(AT_FDCWD, f, 0, 0) < 0 && errno == EROFS, "utimensat: EROFS");
    CHECK(setxattr(f, "user.x", "1", 1, 0) < 0 && errno == EROFS, "setxattr: EROFS");
    CHECK(unlink(f) < 0 && errno == EROFS, "unlink: EROFS");
    CHECK(access(f, W_OK) < 0 && errno == EROFS, "access W_OK: EROFS");
    CHECK(access(f, R_OK) == 0, "access R_OK");
    CHECK(open(ro, O_TMPFILE | O_RDWR, 0600) < 0 && errno == EROFS, "O_TMPFILE: EROFS");
    // a tmpfs: its own statfs, files made there are in-memory ones
    char t[256], tf[256];
    path(t, "tmpfs");
    snprintf(tf, sizeof tf, "%s/f", t);
    CHECK(mount("tmpfs", t, "tmpfs", 0, "size=4m") == 0, "mount tmpfs");
    struct statfs sf;
    CHECK(statfs(t, &sf) == 0 && sf.f_type == 0x01021994, "tmpfs statfs type %lx", (long)sf.f_type);
    CHECK(sf.f_blocks == 1024, "tmpfs f_blocks %ld (size=4m)", (long)sf.f_blocks);
    fd = open(tf, O_CREAT | O_RDWR | O_EXCL, 0600);
    char buf[8192];
    memset(buf, 'q', sizeof buf);
    CHECK(fd >= 0 && write(fd, buf, sizeof buf) == (ssize_t)sizeof buf, "write tmpfs file");
    CHECK(fstat(fd, &st) == 0 && st.st_size == 8192, "tmpfs file size %ld", (long)st.st_size);
    struct statfs sf2;
    CHECK(fstatfs(fd, &sf2) == 0 && sf2.f_type == 0x01021994 && sf2.f_bfree < sf.f_bfree, "fstatfs: used %ld -> %ld", (long)sf.f_bfree, (long)sf2.f_bfree);
    CHECK(ftruncate(fd, 100) == 0 && fstat(fd, &st) == 0 && st.st_size == 100, "tmpfs ftruncate: %ld", (long)st.st_size);
    close(fd);
    fd = open(tf, O_RDWR | O_TRUNC);
    CHECK(fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0, "tmpfs O_TRUNC: %ld", (long)st.st_size);
    close(fd);
    struct timespec ts[2] = {{1000, 0}, {2000, 0}};
    CHECK(utimensat(AT_FDCWD, tf, ts, 0) == 0 && stat(tf, &st) == 0 && st.st_mtim.tv_sec == 2000, "tmpfs utimensat %ld", (long)st.st_mtim.tv_sec);
    char tf2[256];
    snprintf(tf2, sizeof tf2, "%s/g", t);
    CHECK(rename(tf, tf2) == 0 && stat(tf2, &st) == 0, "rename in tmpfs");
    CHECK(link(tf2, f) < 0 && (errno == EXDEV || errno == EROFS), "link across mounts");
    char tf3[256];
    path(tf3, "fromtmpfs");
    CHECK(rename(tf2, tf3) < 0 && errno == EXDEV, "rename across mounts: EXDEV");
    CHECK(unlink(tf2) == 0, "unlink in tmpfs");
    umount(t);
}

static void ns_test(void) {
    pid_t p = fork();
    if (p == 0) {
        fails = 0;
        in_ns();
        _exit(fails);
    }
    int st;
    waitpid(p, &st, 0);
    int r = WIFEXITED(st) ? WEXITSTATUS(st) : 99;
    if (r) {
        fails += r;
        printf("FAIL ns_test: %d\n", r);
    }
}

static void setup(void) {
    char p[256];
    system("rm -rf /tmp/vfschange.d");
    mkdir(D, 0755);
    chmod(D, 0755);
    path(p, "ro");
    mkdir(p, 0755);
    path(p, "ro/file");
    close(open(p, O_CREAT | O_RDWR, 0644));
    path(p, "tmpfs");
    mkdir(p, 0755);
    path(p, "pub");
    mkdir(p, 0777);
    chmod(p, 0777);
}

static void bench(int n) {
    char p[256], q[256];
    path(p, "bench");
    path(q, "benchq");
    double t;
    unlink(p);
    close(open(p, O_CREAT | O_RDWR, 0644));
#define RUN(name, body) do { t = now(); for (int i = 0; i < n; i++) { body; } printf("%-22s %8.2f us\n", name, (now() - t) * 1e6 / n); } while (0)
    RUN("create+unlink", { int fd = open(q, O_CREAT | O_EXCL | O_WRONLY, 0600); close(fd); unlink(q); });
    RUN("open O_TRUNC", { int fd = open(p, O_WRONLY | O_TRUNC); close(fd); });
    int fd = open(p, O_RDWR);
    RUN("ftruncate", { if (ftruncate(fd, i & 1 ? 4096 : 0)) {} });
    close(fd);
    RUN("truncate", { if (truncate(p, i & 1 ? 4096 : 0)) {} });
    struct timespec ts[2] = {{1000, 0}, {0, UTIME_NOW}};
    RUN("utimensat", { utimensat(AT_FDCWD, p, ts, 0); });
    RUN("setxattr", { setxattr(p, "user.b", "v", 1, 0); });
    char b[8];
    RUN("getxattr", { getxattr(p, "user.b", b, sizeof b); });
    RUN("chmod", { chmod(p, i & 1 ? 0600 : 0644); });
    RUN("stat", { struct stat st; stat(p, &st); });
    RUN("open+close", { int f2 = open(p, O_RDONLY); close(f2); });
    RUN("link+unlink", { link(p, q); unlink(q); });
    RUN("mknod fifo+unlink", { mknod(q, S_IFIFO | 0600, 0); unlink(q); });
    RUN("O_PATH open+close", { int f2 = open(p, O_PATH); close(f2); });
    RUN("O_TMPFILE+close", { int f2 = open(D, O_TMPFILE | O_RDWR, 0600); close(f2); });
}

// --- kill mode: the change calls in a loop while vfs-server is killed ------------------------
// A change in flight when vfs-server dies may fail with EIO (it may or may not have
// happened); any other error, or a result that does not hold, is a failure.
struct kk { const char *name; long ok, eio, bad; int last; };
static struct kk KK[8] = {{"create"}, {"trunc"}, {"tmpfile"}, {"xattr"}, {"utimens"}, {"mknod"}, {"link"}, {"chmod"}};

static void note(int k, int ok) {
    if (ok) KK[k].ok++;
    else if (errno == EIO) KK[k].eio++;
    else {
        KK[k].bad++;
        KK[k].last = errno;
    }
}

static int kill_loop(int secs) {
    char a[256], b[256], c[256];
    path(a, "ka");
    path(b, "kb");
    path(c, "kc");
    double end = now() + secs;
    long round = 0;
    while (now() < end) {
        round++;
        unlink(a);
        int fd = open(a, O_CREAT | O_EXCL | O_RDWR, 0644);
        note(0, fd >= 0 || errno == EEXIST);
        if (fd >= 0) {
            if (write(fd, "0123456789", 10) != 10) {}
            close(fd);
        }
        fd = open(a, O_WRONLY | O_TRUNC);
        struct stat st;
        note(1, fd >= 0 && fstat(fd, &st) == 0 && st.st_size == 0);
        if (fd >= 0) close(fd);
        fd = open(D, O_TMPFILE | O_RDWR, 0600);
        // (an unlink that failed with EIO in a kill leaves the name: EEXIST then is no failure)
        int gone = unlink(c) == 0 || errno == ENOENT;
        int ok = fd >= 0 && write(fd, "t", 1) == 1 && (linkat(fd, "", AT_FDCWD, c, AT_EMPTY_PATH) == 0 || (!gone && errno == EEXIST));
        note(2, ok);
        if (fd >= 0) close(fd);
        char v[8];
        note(3, setxattr(a, "user.k", "vv", 2, 0) == 0 && getxattr(a, "user.k", v, sizeof v) == 2);
        note(4, utimensat(AT_FDCWD, a, 0, 0) == 0);
        unlink(b);
        note(5, mknod(b, S_IFIFO | 0600, 0) == 0 || errno == EEXIST);
        unlink(b);
        note(6, link(a, b) == 0 || errno == EEXIST);
        note(7, chmod(a, round & 1 ? 0600 : 0644) == 0);
    }
    int bad = 0;
    for (int k = 0; k < 8; k++) {
        printf("%-8s ok %6ld eio %4ld bad %4ld%s", KK[k].name, KK[k].ok, KK[k].eio, KK[k].bad, KK[k].bad ? "" : "\n");
        if (KK[k].bad) printf(" (last errno %d)\n", KK[k].last);
        bad += KK[k].bad != 0;
    }
    printf(bad ? "VFSCHANGEKILL FAIL\n" : "VFSCHANGEKILL PASS\n");
    return bad != 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 2 && strcmp(argv[1], "bench") == 0) {
        setup();
        bench(atoi(argv[2]));
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "kill") == 0) {
        setup();
        return kill_loop(atoi(argv[2]));
    }
    setup();
    excl_race();
    create_mode();
    {
        char p[256];
        path(p, "ro0444");
        close(open(p, O_CREAT | O_RDWR, 0444));
        chmod(p, 0444);
        if (as_nobody(nobody_open_ro, p) != 0) {
            fails++;
            printf("FAIL nobody_open_ro\n");
        }
    }
    truncs();
    tmpfile_link();
    xattrs();
    acls();
    times();
    nodes();
    opath();
    statfss();
    ns_test();
    if (fails) {
        printf("VFSCHANGE FAIL %d\n", fails);
        return 1;
    }
    printf("VFSCHANGE PASS\n");
    return 0;
}
