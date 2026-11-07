// The new mount API: fsopen/fsconfig/fsmount/move_mount (a tmpfs), open_tree with
// OPEN_TREE_CLONE (a bind), mount_setattr (read-only), move_mount of an attached mount,
// fspick + reconfigure, open_tree without CLONE (a path descriptor), and errors.
// Runs in a user + mount namespace of its own.
// Build: gcc -O1 -w -o mountapi mountapi_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FSCONFIG_SET_FLAG 0
#define FSCONFIG_SET_STRING 1
#define FSCONFIG_CMD_CREATE 6
#define FSCONFIG_CMD_RECONFIGURE 7
#define MOUNT_ATTR_RDONLY 1
#define MOUNT_ATTR_NOSUID 2
#define OPEN_TREE_CLONE 1
#define MOVE_MOUNT_F_EMPTY_PATH 4

struct mount_attr { uint64_t attr_set, attr_clr, propagation, userns_fd; };

static int fails;
// A failed step inside the namespace: report it with errno at the time
#define BAD(bit) do { if (!(bad & (bit))) printf("     step %#x failed: errno %d (%s)\n", bit, errno, strerror(errno)); bad |= (bit); } while (0)
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long fsopen(const char *fs, unsigned f) { return syscall(430, fs, f); }
static long fsconfig(int fd, unsigned cmd, const char *k, const void *v, int aux) { return syscall(431, fd, cmd, k, v, aux); }
static long fsmount(int fd, unsigned f, unsigned attr) { return syscall(432, fd, f, attr); }
static long open_tree(int dfd, const char *p, unsigned f) { return syscall(428, dfd, p, f); }
static long move_mount(int fd, const char *fp, int td, const char *tp, unsigned f) { return syscall(429, fd, fp, td, tp, f); }
static long fspick(int dfd, const char *p, unsigned f) { return syscall(433, dfd, p, f); }
static long mount_setattr(int dfd, const char *p, unsigned f, struct mount_attr *a, size_t s) { return syscall(442, dfd, p, f, a, s); }

static void put(const char *path, const char *text) {
    char f[256];
    snprintf(f, sizeof f, "%s", path);
    int fd = open(f, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, text, strlen(text));
        close(fd);
    }
}

static int exists(const char *p) { return access(p, F_OK) == 0; }

// The mount options field of the mountinfo line for `path`, or "" if not mounted
static void mount_opts(const char *path, char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen("/proc/self/mountinfo", "r");
    char line[1024];
    while (f && fgets(line, sizeof line, f)) {
        char mp[512], opts[256];
        if (sscanf(line, "%*s %*s %*s %*s %511s %255s", mp, opts) == 2 && !strcmp(mp, path)) snprintf(out, n, "%s", opts);
    }
    if (f) fclose(f);
}

static int in_ns(void) {
    int bad = 0;
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) return 0x7fff;
    char m[64];
    int fd = open("/proc/self/setgroups", O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }
    snprintf(m, sizeof m, "0 %d 1", uid);
    put("/proc/self/uid_map", m);
    snprintf(m, sizeof m, "0 %d 1", gid);
    put("/proc/self/gid_map", m);

    char base[64], a[96], b[96], c[96], src[96], p[160], opts[256];
    snprintf(base, sizeof base, "/tmp/mapi.%d.%ld", getpid(), (long)time(NULL));   // PIDs repeat across boots
    snprintf(a, sizeof a, "%s/a", base);
    snprintf(b, sizeof b, "%s/b", base);
    snprintf(c, sizeof c, "%s/c", base);
    snprintf(src, sizeof src, "%s/src", base);
    mkdir(base, 0755);
    mkdir(a, 0755);
    mkdir(b, 0755);
    mkdir(c, 0755);
    mkdir(src, 0755);
    snprintf(p, sizeof p, "%s/marker", src);
    put(p, "m");

    // A tmpfs through a context
    errno = 0;
    if (fsopen("nosuchfs", 0) != -1 || errno != ENODEV) BAD(1);
    int ctx = fsopen("tmpfs", 1);
    if (ctx < 0) return 0x7ffe;
    errno = 0;
    if (fsmount(ctx, 0, 0) != -1 || errno != EINVAL) BAD(2);   // not created yet
    if (fsconfig(ctx, FSCONFIG_SET_STRING, "source", "apitmp", 0) != 0) BAD(4);
    if (fsconfig(ctx, FSCONFIG_SET_STRING, "mode", "0700", 0) != 0) BAD(4);
    if (fsconfig(ctx, FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) BAD(4);
    int mfd = fsmount(ctx, 1, MOUNT_ATTR_NOSUID);
    if (mfd < 0) BAD(8);
    if (move_mount(mfd, "", AT_FDCWD, a, MOVE_MOUNT_F_EMPTY_PATH) != 0) BAD(8);
    struct stat st;
    stat(a, &st);
    snprintf(p, sizeof p, "%s/in-tmpfs", a);
    put(p, "t");
    mount_opts(a, opts, sizeof opts);
    if ((st.st_mode & 07777) != 0700 || !exists(p) || !strstr(opts, "nosuid")) BAD(16);

    // A bind made from a clone of src
    int tfd = open_tree(AT_FDCWD, src, OPEN_TREE_CLONE | O_CLOEXEC);
    if (tfd < 0 || move_mount(tfd, "", AT_FDCWD, b, MOVE_MOUNT_F_EMPTY_PATH) != 0) BAD(32);
    snprintf(p, sizeof p, "%s/marker", b);
    if (!exists(p)) BAD(32);

    // Read-only by mount_setattr
    struct mount_attr ma = {MOUNT_ATTR_RDONLY, 0, 0, 0};
    if (mount_setattr(AT_FDCWD, b, 0, &ma, sizeof ma) != 0) BAD(64);
    snprintf(p, sizeof p, "%s/new", b);
    errno = 0;
    int w = open(p, O_CREAT | O_WRONLY, 0644);
    mount_opts(b, opts, sizeof opts);
    if (w >= 0 || errno != EROFS || strncmp(opts, "ro", 2) != 0) BAD(64);
    struct mount_attr badattr = {1ull << 40, 0, 0, 0};
    errno = 0;
    if (mount_setattr(AT_FDCWD, b, 0, &badattr, sizeof badattr) != -1 || errno != EINVAL) BAD(128);
    errno = 0;
    if (mount_setattr(AT_FDCWD, b, 0, &ma, 8) != -1 || errno != EINVAL) BAD(128);

    // Moving the attached bind to c
    if (move_mount(AT_FDCWD, b, AT_FDCWD, c, 0) != 0) BAD(256);
    char pc[160];
    snprintf(pc, sizeof pc, "%s/marker", c);
    snprintf(p, sizeof p, "%s/marker", b);
    if (!exists(pc) || exists(p)) BAD(256);

    // fspick: the tmpfs becomes read-only
    int pk = fspick(AT_FDCWD, a, 1);
    if (pk < 0 || fsconfig(pk, FSCONFIG_SET_FLAG, "ro", NULL, 0) != 0 || fsconfig(pk, FSCONFIG_CMD_RECONFIGURE, NULL, NULL, 0) != 0) BAD(512);
    snprintf(p, sizeof p, "%s/after-ro", a);
    errno = 0;
    w = open(p, O_CREAT | O_WRONLY, 0644);
    if (w >= 0 || errno != EROFS) BAD(512);

    // open_tree without CLONE: a path descriptor
    int pfd = open_tree(AT_FDCWD, src, O_CLOEXEC);
    char x;
    errno = 0;
    if (pfd < 0 || fstat(pfd, &st) != 0 || !S_ISDIR(st.st_mode) || read(pfd, &x, 1) != -1 || errno != EBADF) BAD(1024);
    return bad;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getuid() != 0) {
        errno = 0;
        check(fsopen("tmpfs", 0) == -1 && errno == EPERM, "fsopen without CAP_SYS_ADMIN: EPERM");
    }
    int pp[2];
    pipe(pp);
    pid_t ch = fork();
    if (ch == 0) {
        int r = in_ns();
        write(pp[1], &r, sizeof r);
        _exit(0);
    }
    int r = -1;
    read(pp[0], &r, sizeof r);
    waitpid(ch, NULL, 0);
    if (r == 0x7fff) {
        printf("skip: no user namespaces\n");
        return 0;
    }
    if (r == 0x7ffe) {
        printf("skip: fsopen unavailable\n");
        return 0;
    }
    check(!(r & 1), "fsopen of an unknown file system: ENODEV");
    check(!(r & 2), "fsmount before FSCONFIG_CMD_CREATE: EINVAL");
    check(!(r & 4), "fsconfig: source, mode, create");
    check(!(r & 8), "fsmount + move_mount attach a tmpfs");
    check(!(r & 16), "the tmpfs has its mode, takes files, and is nosuid");
    check(!(r & 32), "open_tree(OPEN_TREE_CLONE) + move_mount bind src");
    check(!(r & 64), "mount_setattr makes the bind read-only (EROFS, listed ro)");
    check(!(r & 128), "mount_setattr: unknown attribute or short size: EINVAL");
    check(!(r & 256), "move_mount moves an attached mount");
    check(!(r & 512), "fspick + reconfigure ro");
    check(!(r & 1024), "open_tree without CLONE gives a path descriptor");
    printf(fails ? "MOUNTAPI TEST FAILED (%d)\n" : "MOUNTAPI TEST PASSED\n", fails);
    return fails != 0;
}
