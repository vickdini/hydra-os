// Mount namespaces: bind mounts, recursive binds, tmpfs, read-only remount, noexec,
// symlinks and ".." across mounts, an mqueue mount in mountinfo, propagation flags,
// pivot_root and detaching the old root; the parent namespace sees none of it.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

#define TMPFS_MAGIC 0x01021994

static void put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd >= 0) {
        if (write(fd, text, strlen(text))) {}
        close(fd);
    }
}

static int exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static void map_ids(uid_t uid, gid_t gid) {
    char b[64];
    put("/proc/self/setgroups", "deny");
    snprintf(b, sizeof b, "%u %u 1\n", uid, uid);
    put("/proc/self/uid_map", b);
    snprintf(b, sizeof b, "%u %u 1\n", gid, gid);
    put("/proc/self/gid_map", b);
}

static int in_namespace(uid_t uid, gid_t gid) {
    map_ids(uid, gid);
    CHECK(mount(0, "/", 0, MS_REC | MS_PRIVATE, 0) == 0, "make / private (propagation)");
    CHECK(mount("/tmp/mt/a", "/tmp/mt/b", 0, MS_BIND, 0) == 0, "bind a onto b");
    CHECK(exists("/tmp/mt/b/file"), "b shows a's file");
    put("/tmp/mt/b/via-b", "x");
    CHECK(exists("/tmp/mt/a/via-b"), "a write through b lands in a");
    struct stat up, dir;
    CHECK(stat("/tmp/mt/b/..", &up) == 0 && stat("/tmp/mt", &dir) == 0 && up.st_ino == dir.st_ino, ".. from the bind's root leaves the mount");
    CHECK(mount("tmpfs", "/tmp/mt/t", "tmpfs", 0, "mode=0755") == 0, "mount tmpfs");
    struct statfs sf;
    CHECK(statfs("/tmp/mt/t", &sf) == 0 && sf.f_type == TMPFS_MAGIC, "statfs reports tmpfs (%#lx)", (long)sf.f_type);
    put("/tmp/mt/t/scratch", "y");
    CHECK(exists("/tmp/mt/t/scratch"), "file created in the tmpfs");
    CHECK(exists("/tmp/mt/a/lnk/scratch"), "a symbolic link into the tmpfs crosses the mount");
    mkdir("/tmp/mt/a/sub", 0755);
    CHECK(mount("tmpfs", "/tmp/mt/a/sub", "tmpfs", 0, 0) == 0, "tmpfs on a/sub");
    CHECK(mount("/tmp/mt/a", "/tmp/mt/c", 0, MS_BIND | MS_REC, 0) == 0 && statfs("/tmp/mt/c/sub", &sf) == 0 && sf.f_type == TMPFS_MAGIC, "recursive bind carries the submount");
    CHECK(mount(0, "/tmp/mt/b", 0, MS_REMOUNT | MS_BIND | MS_RDONLY, 0) == 0, "remount b read-only");
    errno = 0;
    CHECK(open("/tmp/mt/b/new", O_CREAT | O_WRONLY, 0644) == -1 && errno == EROFS, "create in the read-only bind: EROFS");
    errno = 0;
    CHECK(mkdir("/tmp/mt/b/d", 0755) == -1 && errno == EROFS, "mkdir in the read-only bind: EROFS");
    put("/tmp/mt/a/still", "z");
    CHECK(exists("/tmp/mt/a/still"), "a itself stays writable");
    CHECK(mount("tmpfs", "/tmp/mt/x", "tmpfs", MS_NOEXEC, 0) == 0, "noexec tmpfs");
    int src = open("/proc/self/exe", O_RDONLY), dst = open("/tmp/mt/x/prog", O_WRONLY | O_CREAT, 0755);
    char buf[65536];
    long n;
    while ((n = read(src, buf, sizeof buf)) > 0) {
        if (write(dst, buf, n)) {}
    }
    close(src);
    close(dst);
    pid_t c = fork();
    if (c == 0) {
        execl("/tmp/mt/x/prog", "prog", (char *)0);
        _exit(errno == EACCES ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "exec from the noexec mount: EACCES");
    CHECK(mount("mqueue", "/tmp/mt/p", "mqueue", 0, 0) == 0, "mount mqueue (errno %d)", errno);
    static char info[262144];
    int fd = open("/proc/self/mountinfo", O_RDONLY);
    long got = 0;
    while ((n = read(fd, info + got, sizeof info - 1 - got)) > 0) got += n;
    info[got] = 0;
    n = got;
    close(fd);
    CHECK(n > 0 && strstr(info, "/tmp/mt/p") && strstr(info, "/tmp/mt/t") && strstr(info, " - tmpfs "), "mountinfo lists the new mounts");
    CHECK(umount2("/tmp/mt/t", 0) == 0 && !exists("/tmp/mt/t/scratch"), "umount the tmpfs: its files go with it");
    // pivot_root into a tmpfs
    CHECK(mount("tmpfs", "/tmp/mt/nr", "tmpfs", 0, 0) == 0, "tmpfs for the new root");
    mkdir("/tmp/mt/nr/old", 0755);
    put("/tmp/mt/nr/marker", "m");
    CHECK(syscall(SYS_pivot_root, "/tmp/mt/nr", "/tmp/mt/nr/old") == 0, "pivot_root");
    if (chdir("/")) {}
    CHECK(exists("/marker") && exists("/old/tmp/mt/a/file"), "new root, old root under /old");
    CHECK(umount2("/old", MNT_DETACH) == 0 && !exists("/old/tmp"), "detach the old root");
    return fails;
}

int main(void) {
    mkdir("/tmp/mt", 0755);
    const char *dirs[] = {"a", "b", "c", "t", "x", "p", "nr"};
    for (int i = 0; i < 7; i++) {
        char p[64];
        snprintf(p, sizeof p, "/tmp/mt/%s", dirs[i]);
        mkdir(p, 0755);
    }
    put("/tmp/mt/a/file", "hello");
    unlink("/tmp/mt/a/lnk");
    if (symlink("/tmp/mt/t", "/tmp/mt/a/lnk")) {}
    unlink("/tmp/mt/a/via-b");
    errno = 0;
    if (getuid() != 0) CHECK(mount("tmpfs", "/tmp/mt/t", "tmpfs", 0, 0) == -1 && errno == EPERM, "mount without privileges: EPERM");
    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t c = fork();
    if (c == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWIPC)) {
            printf("unshare: %s\n", strerror(errno));
            _exit(99);
        }
        _exit(in_namespace(uid, gid) ? 1 : 0);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "namespace checks (exit %d)", WEXITSTATUS(st));
    CHECK(!exists("/tmp/mt/b/file") && !exists("/tmp/mt/t/scratch"), "the parent namespace sees none of the mounts");
    printf(fails ? "MOUNT TEST FAILED (%d)\n" : "MOUNT TEST PASSED\n", fails);
    return fails != 0;
}
