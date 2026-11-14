// File system calls, checked against Linux (run it there first, as root): open flags and
// their errors, directories, rename/link/unlink rules, symlinks, permissions (a child
// drops to uid 65534), the sticky bit, offsets shared by dup, O_APPEND, truncate, lseek,
// fcntl flags, umask and access().
// Build: gcc -O1 -w -o vfs vfs_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static char base[64];

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int err(long r) {
    return r < 0 ? errno : 0;
}

static void expect_err(long r, int want, const char *what) {
    char line[220];
    int got = err(r);
    snprintf(line, sizeof line, "%s: want %s, got %s", what, want ? strerror(want) : "0", got ? strerror(got) : "0");
    check(got == want, line);
}

static const char *P(const char *rel) {
    static char bufs[8][512];
    static int i;
    char *b = bufs[i++ & 7];
    snprintf(b, 512, "%s/%s", base, rel);
    return b;
}

static void put(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, data, strlen(data));
    close(fd);
}

// Runs `f` in a child running as uid/gid 65534; returns its exit code (an errno or 0)
static int as_nobody(int (*f)(void)) {
    pid_t p = fork();
    if (p == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(200);
        _exit(f());
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 201;
}

static int open_private(void) { return err(open(P("private"), O_RDONLY)); }
static int write_readonly(void) { return err(open(P("ro"), O_WRONLY)); }
static int create_in_rootdir(void) { return err(open(P("rootdir/new"), O_WRONLY | O_CREAT, 0644)); }
static int unlink_others_in_sticky(void) { return err(unlink(P("sticky/roots"))); }
static int unlink_own_in_sticky(void) {
    int fd = open(P("sticky/mine"), O_WRONLY | O_CREAT, 0644);
    close(fd);
    return err(unlink(P("sticky/mine")));
}
static int chmod_others(void) { return err(chmod(P("ro"), 0777)); }
static int chown_own(void) {
    int fd = open(P("sticky/own2"), O_WRONLY | O_CREAT, 0644);
    close(fd);
    return err(chown(P("sticky/own2"), 0, -1));
}
static int access_private(void) { return err(access(P("private"), R_OK)); }
static int search_noexec_dir(void) { return err(open(P("noexec/file"), O_RDONLY)); }
static int create_below_noexec(void) { return err(open(P("noexec/sub/new"), O_WRONLY | O_CREAT, 0644)); }
static int stat_below_noexec(void) {
    struct stat st;
    return err(stat(P("noexec/sub"), &st));
}

int main(void) {
    if (geteuid() != 0) {
        printf("vfs: needs root\nVFS TEST FAILED (1)\n");
        return 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(base, sizeof base, "/tmp/vfs_test.%d", getpid());
    mkdir(base, 0755);
    umask(022);

    // ---- open flags and errors
    expect_err(open(P("missing"), O_RDONLY), ENOENT, "open of a missing file");
    expect_err(open(P("missing/x"), O_RDONLY), ENOENT, "open below a missing directory");
    put(P("file"), "hello");
    expect_err(open(P("file/x"), O_RDONLY), ENOTDIR, "open below a regular file");
    expect_err(open(P("file"), O_RDONLY | O_DIRECTORY), ENOTDIR, "O_DIRECTORY on a regular file");
    expect_err(open(P("file"), O_WRONLY | O_CREAT | O_EXCL, 0644), EEXIST, "O_CREAT|O_EXCL on an existing file");
    expect_err(open(base, O_WRONLY), EISDIR, "open a directory for writing");
    expect_err(open(base, O_RDWR), EISDIR, "open a directory read-write");
    expect_err(open(P("newdir/"), O_WRONLY | O_CREAT, 0644), EISDIR, "O_CREAT with a trailing slash");
    char longname[300];
    memset(longname, 'a', 299);
    longname[299] = 0;
    expect_err(open(P(longname), O_RDONLY), ENAMETOOLONG, "a 299-byte name");
    expect_err(open("", O_RDONLY), ENOENT, "open of an empty path");
    int fd = open(P("file"), O_RDWR | O_TRUNC);
    struct stat st;
    fstat(fd, &st);
    check(st.st_size == 0, "O_TRUNC empties the file");
    close(fd);
    fd = open(P("created"), O_WRONLY | O_CREAT, 0777);
    fstat(fd, &st);
    check((st.st_mode & 0777) == 0755, "O_CREAT applies the umask (0777 & ~022)");
    close(fd);

    // ---- symlinks
    symlink("file", P("link"));
    symlink("loop2", P("loop1"));
    symlink("loop1", P("loop2"));
    expect_err(open(P("loop1"), O_RDONLY), ELOOP, "open through a symlink loop");
    expect_err(open(P("link"), O_RDONLY | O_NOFOLLOW), ELOOP, "O_NOFOLLOW on a symlink");
    char buf[64];
    ssize_t n = readlink(P("link"), buf, sizeof buf);
    check(n == 4 && memcmp(buf, "file", 4) == 0, "readlink returns the target without a NUL");
    n = readlink(P("link"), buf, 2);
    check(n == 2 && memcmp(buf, "fi", 2) == 0, "readlink truncates to the buffer");
    expect_err(readlink(P("file"), buf, sizeof buf), EINVAL, "readlink of a regular file");
    symlink("missing", P("dangling"));
    expect_err(open(P("dangling"), O_RDONLY), ENOENT, "open of a dangling symlink");
    fd = open(P("dangling"), O_WRONLY | O_CREAT, 0644);
    check(fd >= 0 && access(P("missing"), F_OK) == 0, "O_CREAT through a dangling symlink creates its target");
    close(fd);
    expect_err(open(P("link"), O_WRONLY | O_CREAT | O_EXCL, 0644), EEXIST, "O_CREAT|O_EXCL on a symlink (not followed)");

    // ---- directories
    mkdir(P("d"), 0755);
    expect_err(mkdir(P("d"), 0755), EEXIST, "mkdir of an existing directory");
    expect_err(mkdir(P("file"), 0755), EEXIST, "mkdir over a file");
    put(P("d/inside"), "x");
    expect_err(rmdir(P("d")), ENOTEMPTY, "rmdir of a non-empty directory");
    expect_err(rmdir(P("file")), ENOTDIR, "rmdir of a file");
    expect_err(unlink(P("d")), EISDIR, "unlink of a directory");
    expect_err(rmdir(P("d/.")), EINVAL, "rmdir of '.'");
    expect_err(link(P("d"), P("dlink")), EPERM, "hard link to a directory");

    // ---- rename rules
    mkdir(P("r1"), 0755);
    mkdir(P("r1/sub"), 0755);
    expect_err(rename(P("r1"), P("r1/sub/r1")), EINVAL, "rename a directory into itself");
    mkdir(P("r2"), 0755);
    put(P("r2/x"), "x");
    expect_err(rename(P("r1"), P("r2")), ENOTEMPTY, "rename a directory over a non-empty one");
    expect_err(rename(P("file"), P("r1")), EISDIR, "rename a file over a directory");
    expect_err(rename(P("r1"), P("file")), ENOTDIR, "rename a directory over a file");
    mkdir(P("r3"), 0755);
    expect_err(rename(P("r1"), P("r3")), 0, "rename a directory over an empty one");
    put(P("a"), "A");
    put(P("b"), "B");
    expect_err(rename(P("a"), P("b")), 0, "rename a file over a file");
    fd = open(P("b"), O_RDONLY);
    n = read(fd, buf, 1);
    close(fd);
    check(n == 1 && buf[0] == 'A' && access(P("a"), F_OK) < 0, "the target is replaced and the source gone");
    expect_err(rename(P("b"), P("b")), 0, "rename a file onto itself");
    link(P("b"), P("b2"));
    expect_err(rename(P("b"), P("b2")), 0, "rename onto another link of the same file: nothing happens");
    check(access(P("b"), F_OK) == 0 && access(P("b2"), F_OK) == 0, "both names remain");
    stat(P("b"), &st);
    check(st.st_nlink == 2, "a hard link counts in st_nlink");

    // ---- offsets, O_APPEND, dup
    put(P("off"), "0123456789");
    fd = open(P("off"), O_RDWR);
    int fd2 = dup(fd);
    lseek(fd, 4, SEEK_SET);
    check(lseek(fd2, 0, SEEK_CUR) == 4, "dup shares the file offset");
    int fd3 = open(P("off"), O_RDONLY);
    check(lseek(fd3, 0, SEEK_CUR) == 0, "a second open has its own offset");
    check(lseek(fd, 0, SEEK_END) == 10, "SEEK_END");
    expect_err(lseek(fd, -20, SEEK_CUR), EINVAL, "seeking before the start");
    expect_err(lseek(fd, 0, 7), EINVAL, "lseek with a bad whence");
    check(lseek(fd, 100, SEEK_SET) == 100 && write(fd, "x", 1) == 1, "writing past the end");
    fstat(fd, &st);
    check(st.st_size == 101, "leaves a hole and extends the file");
    pread(fd, buf, 1, 50);
    check(buf[0] == 0, "the hole reads as zeros");
    close(fd);
    close(fd2);
    close(fd3);
    fd = open(P("off"), O_WRONLY | O_APPEND);
    lseek(fd, 0, SEEK_SET);
    write(fd, "Z", 1);
    fstat(fd, &st);
    check(st.st_size == 102, "O_APPEND writes at the end whatever the offset");
    expect_err(pwrite(fd, "y", 1, 0) < 0 ? -1 : 0, 0, "pwrite on O_APPEND succeeds");
    fstat(fd, &st);
    check(st.st_size == 103, "and appends too (Linux ignores the offset)");
    close(fd);
    expect_err(truncate(P("off"), -1), EINVAL, "truncate to a negative length");
    expect_err(truncate(base, 0), EISDIR, "truncate of a directory");
    fd = open(P("off"), O_RDONLY);
    expect_err(ftruncate(fd, 0), EINVAL, "ftruncate of a read-only descriptor");
    expect_err(write(fd, "x", 1), EBADF, "write to a read-only descriptor");
    expect_err(pwrite(fd, "x", 1, 0), EBADF, "pwrite to a read-only descriptor");
    expect_err(pread(fd, buf, 1, -1), EINVAL, "pread at a negative offset");
    close(fd);
    fd = open(P("off"), O_WRONLY);
    expect_err(read(fd, buf, 1), EBADF, "read from a write-only descriptor");
    close(fd);

    // ---- fcntl flags
    fd = open(P("off"), O_RDWR | O_APPEND);
    int fl = fcntl(fd, F_GETFL);
    check((fl & O_ACCMODE) == O_RDWR && (fl & O_APPEND), "F_GETFL reports the access mode and O_APPEND");
    fcntl(fd, F_SETFL, (fl & ~O_APPEND) | O_NONBLOCK);
    fl = fcntl(fd, F_GETFL);
    check(!(fl & O_APPEND) && (fl & O_NONBLOCK), "F_SETFL changes O_APPEND and O_NONBLOCK");
    fcntl(fd, F_SETFL, O_RDONLY);
    check((fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDWR, "F_SETFL cannot change the access mode");
    check(fcntl(fd, F_GETFD) == 0, "no FD_CLOEXEC by default");
    int fdc = fcntl(fd, F_DUPFD_CLOEXEC, 50);
    check(fdc >= 50 && fcntl(fdc, F_GETFD) == FD_CLOEXEC, "F_DUPFD_CLOEXEC: lowest free >= 50, close-on-exec");
    expect_err(fcntl(1000, F_GETFL), EBADF, "F_GETFL on a closed descriptor");
    close(fd);
    close(fdc);

    // ---- permissions (a child running as uid 65534)
    put(P("private"), "secret");
    chmod(P("private"), 0600);
    put(P("ro"), "read only");
    chmod(P("ro"), 0644);
    mkdir(P("rootdir"), 0755);
    mkdir(P("sticky"), 0755);
    chmod(P("sticky"), 01777); // (mkdir applies the umask)
    put(P("sticky/roots"), "r");
    mkdir(P("noexec"), 0744);
    put(P("noexec/file"), "f");
    mkdir(P("noexec/sub"), 0755);
    chmod(P("noexec/sub"), 0777);
    chmod(base, 0755);
    check(as_nobody(open_private) == EACCES, "another user's 0600 file: EACCES");
    check(as_nobody(write_readonly) == EACCES, "writing a 0644 file of root's: EACCES");
    check(as_nobody(create_in_rootdir) == EACCES, "creating in root's 0755 directory: EACCES");
    check(as_nobody(unlink_others_in_sticky) == EPERM, "deleting another user's file in a sticky directory: EPERM");
    check(as_nobody(unlink_own_in_sticky) == 0, "deleting one's own file in a sticky directory");
    check(as_nobody(chmod_others) == EPERM, "chmod of another user's file: EPERM");
    check(as_nobody(chown_own) == EPERM, "giving one's file to root: EPERM");
    check(as_nobody(access_private) == EACCES, "access(R_OK) of another user's 0600 file: EACCES");
    check(as_nobody(search_noexec_dir) == EACCES, "a file in a directory without search (x) permission: EACCES");
    check(as_nobody(create_below_noexec) == EACCES, "creating below a directory without search permission: EACCES");
    check(as_nobody(stat_below_noexec) == EACCES, "stat through a directory without search permission: EACCES");
    // root: the setgid bit is cleared when a non-member chowns... (root passes everything)
    expect_err(access(P("private"), R_OK | W_OK), 0, "root may read and write any file");
    chmod(P("ro"), 0644);
    expect_err(access(P("ro"), X_OK), EACCES, "even root needs an x bit to execute");

    // ---- cleanup
    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", base);
    system(cmd);
    printf(fails ? "VFS TEST FAILED (%d)\n" : "VFS TEST PASSED\n", fails);
    return fails != 0;
}
