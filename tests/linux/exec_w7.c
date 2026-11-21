// Wave 7, Group 7-5: execve's front half, Unix socket names and FIFOs as programs see them.
// Must pass the same with the services (forwarded) and with lx=kernel / lx.vfs=kernel.
// Prints "EXEC_W7 PASS" or "FAIL ..." lines. Build: gcc -O1 -w -pthread exec_w7.c -o exec_w7.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

static char self[4096];
#define D "/tmp/e75"

static void put(const char *path, const char *text, int mode) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) { printf("FAIL cannot make %s: %d\n", path, errno); fails++; return; }
    write(fd, text, strlen(text));
    close(fd);
    chmod(path, mode);
}

static void copy_self(const char *to) {
    int in = open(self, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) write(out, buf, n);
    close(in);
    close(out);
}

// Runs path (argv) in a child with E75_DUMP set; the child's output (its argv joined with
// '|', then ' exe=' and its /proc/self/exe) into out. Returns 0, or -errno of the exec.
static int run(int dirfd, const char *path, char *const argv[], int flags, char *out, size_t cap) {
    int p[2], e[2];
    pipe(p);
    pipe2(e, O_CLOEXEC);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        char *envp[] = {"E75_DUMP=1", NULL};
        if (dirfd == AT_FDCWD && !flags) execve(path, argv, envp);
        else syscall(SYS_execveat, dirfd, path, argv, envp, flags);
        int err = errno;
        write(e[1], &err, sizeof err);
        _exit(127);
    }
    close(p[1]);
    close(e[1]);
    int err = 0;
    if (read(e[0], &err, sizeof err) != sizeof err) err = 0;
    close(e[0]);
    size_t n = 0;
    ssize_t k;
    while (n + 1 < cap && (k = read(p[0], out + n, cap - 1 - n)) > 0) n += k;
    out[n] = 0;
    close(p[0]);
    waitpid(pid, NULL, 0);
    return err ? -err : 0;
}

static void exec_tests(void) {
    char out[8192], want[8192];
    char line[4200];
    mkdir(D, 0755);
    mkdir(D "/sub", 0755);
    copy_self(D "/sub/real");
    // a. a script with an argument (kept whole), argv[1..] after the script's path
    snprintf(line, sizeof line, "#!%s x y\n", D "/sub/real");
    put(D "/s1", line, 0755);
    char *a1[] = {"s1", "A", "B", NULL};
    CHECK(run(AT_FDCWD, D "/s1", a1, 0, out, sizeof out) == 0, "script s1 did not run");
    snprintf(want, sizeof want, "%s|x y|%s|A|B exe=%s", D "/sub/real", D "/s1", D "/sub/real");
    CHECK(strcmp(out, want) == 0, "script argv: got [%s] want [%s]", out, want);
    // b. nested scripts
    put(D "/s2", "#!" D "/s1\n", 0755);
    char *a2[] = {"s2", "C", NULL};
    CHECK(run(AT_FDCWD, D "/s2", a2, 0, out, sizeof out) == 0, "script s2 did not run");
    snprintf(want, sizeof want, "%s|x y|%s|%s|C exe=%s", D "/sub/real", D "/s1", D "/s2", D "/sub/real");
    CHECK(strcmp(out, want) == 0, "nested argv: got [%s] want [%s]", out, want);
    // c. four levels run, five are ELOOP
    put(D "/s3", "#!" D "/s2\n", 0755);
    put(D "/s4", "#!" D "/s3\n", 0755);
    put(D "/s5", "#!" D "/s4\n", 0755);
    char *a4[] = {"s4", NULL};
    CHECK(run(AT_FDCWD, D "/s4", a4, 0, out, sizeof out) == 0, "4 levels must run");
    // (Hydra's limit is Linux 4.x's: four levels; Linux 5.x runs five)
    put(D "/s6", "#!" D "/s5\n", 0755);
    put(D "/s7", "#!" D "/s6\n", 0755);
    CHECK(run(AT_FDCWD, D "/s7", a4, 0, out, sizeof out) == -ELOOP, "7 levels must be ELOOP");
    // d. a relative path through a symbolic link: /proc/self/exe has the link resolved
    unlink(D "/lnk");
    symlink("sub/real", D "/lnk");
    chdir(D);
    char *a5[] = {"lnk", NULL};
    CHECK(run(AT_FDCWD, "./lnk", a5, 0, out, sizeof out) == 0, "./lnk did not run");
    snprintf(want, sizeof want, "lnk exe=%s", D "/sub/real");
    CHECK(strcmp(out, want) == 0, "relative link exe: got [%s] want [%s]", out, want);
    // relative script, relative interpreter's argv shows the script as given
    snprintf(line, sizeof line, "#!sub/real\n");
    put(D "/rs", line, 0755);
    char *a6[] = {"rs", NULL};
    CHECK(run(AT_FDCWD, "rs", a6, 0, out, sizeof out) == 0, "relative script did not run");
    snprintf(want, sizeof want, "sub/real|rs exe=%s", D "/sub/real");
    CHECK(strcmp(out, want) == 0, "relative script: got [%s] want [%s]", out, want);
    chdir("/");
    // e. execveat with a directory descriptor, and AT_SYMLINK_NOFOLLOW on a link (ELOOP)
    int dfd = open(D, O_RDONLY | O_DIRECTORY);
    CHECK(run(dfd, "sub/real", a5, 0, out, sizeof out) == 0, "execveat(dirfd) failed");
    {
        int r = (int)syscall(SYS_execveat, dfd, "nonexistent", a5, NULL, 0);
        CHECK(r == -1 && errno == ENOENT, "execveat missing: %d %d", r, errno);
    }
    {
        int r = run(dfd, "lnk", a5, 0x100, out, sizeof out);
        CHECK(r == -ELOOP, "AT_SYMLINK_NOFOLLOW on a link must be ELOOP: %d [%s]", r, out);
    }
    char *a7[] = {"real", NULL};
    CHECK(run(dfd, "sub/real", a7, 0x100, out, sizeof out) == 0, "execveat NOFOLLOW on a file failed");
    snprintf(want, sizeof want, "real exe=%s", D "/sub/real");
    CHECK(strcmp(out, want) == 0, "execveat exe: got [%s] want [%s]", out, want);
    close(dfd);
    // f. errors
    CHECK(run(AT_FDCWD, D "/missing", a5, 0, out, sizeof out) == -ENOENT, "missing must be ENOENT");
    put(D "/nox", "#!/bin/sh\n", 0644);
    CHECK(run(AT_FDCWD, D "/nox", a5, 0, out, sizeof out) == -EACCES, "no x bit must be EACCES");
    CHECK(run(AT_FDCWD, D "/sub", a5, 0, out, sizeof out) == -EACCES, "a directory must be EACCES");
    put(D "/junk", "this is not a program\n", 0755);
    CHECK(run(AT_FDCWD, D "/junk", a5, 0, out, sizeof out) == -ENOEXEC, "junk must be ENOEXEC");
    put(D "/noint", "#!/nonexistent/interp\n", 0755);
    CHECK(run(AT_FDCWD, D "/noint", a5, 0, out, sizeof out) == -ENOENT, "missing interpreter must be ENOENT");
    put(D "/noxint", "#!" D "/nox\n", 0755);
    CHECK(run(AT_FDCWD, D "/noxint", a5, 0, out, sizeof out) == -EACCES, "interpreter without x must be EACCES");
    CHECK(run(AT_FDCWD, D "/s1/x", a5, 0, out, sizeof out) == -ENOTDIR, "file as directory must be ENOTDIR");
    // a dynamic program found through PATH-like absolute name, its interpreter loaded
    char *a8[] = {"true", NULL};
    CHECK(run(AT_FDCWD, "/usr/bin/true", a8, 0, out, sizeof out) == 0, "/usr/bin/true failed");
}

static void unix_tests(void) {
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    unlink(D "/sock");
    strcpy(a.sun_path, D "/sock");
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(s, (void *)&a, sizeof a) == 0, "bind: %d", errno);
    struct stat st;
    CHECK(stat(D "/sock", &st) == 0 && S_ISSOCK(st.st_mode), "no socket node");
    CHECK((st.st_mode & 0777) == (0777 & ~022), "socket mode %o", st.st_mode & 0777);
    CHECK(listen(s, 4) == 0, "listen");
    int s2 = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(s2, (void *)&a, sizeof a) == -1 && errno == EADDRINUSE, "second bind: %d", errno);
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(c, (void *)&a, sizeof a) == 0, "connect: %d", errno);
    int acc = accept(s, NULL, NULL);
    CHECK(acc >= 0, "accept");
    CHECK(write(c, "hi", 2) == 2, "write");
    char b[4] = {0};
    CHECK(read(acc, b, 2) == 2 && !strcmp(b, "hi"), "read");
    close(acc);
    close(c);
    int c2 = socket(AF_UNIX, SOCK_STREAM, 0);
    strcpy(a.sun_path, D "/s1");
    CHECK(connect(c2, (void *)&a, sizeof a) == -1 && errno == ECONNREFUSED, "connect to a file: %d", errno);
    strcpy(a.sun_path, D "/nosock");
    CHECK(connect(c2, (void *)&a, sizeof a) == -1 && errno == ENOENT, "connect to nothing: %d", errno);
    strcpy(a.sun_path, D "/missingdir/x");
    CHECK(bind(s2, (void *)&a, sizeof a) == -1 && errno == ENOENT, "bind in a missing dir: %d", errno);
    // relative names, from the working directory
    chdir(D);
    unlink("rel.sock");
    strcpy(a.sun_path, "rel.sock");
    int r = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(bind(r, (void *)&a, sizeof a) == 0, "relative bind: %d", errno);
    CHECK(stat(D "/rel.sock", &st) == 0 && S_ISSOCK(st.st_mode), "relative node");
    listen(r, 1);
    int rc = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(connect(rc, (void *)&a, sizeof a) == 0, "relative connect: %d", errno);
    chdir("/");
    close(rc);
    close(r);
    close(c2);
    close(s2);
    close(s);
    unlink(D "/sock");
    unlink(D "/rel.sock");
}

static void fifo_tests(void) {
    unlink(D "/ff");
    CHECK(mkfifo(D "/ff", 0600) == 0, "mkfifo");
    int w0 = open(D "/ff", O_WRONLY | O_NONBLOCK);
    CHECK(w0 == -1 && errno == ENXIO, "writer without reader must be ENXIO: %d %d", w0, errno);
    int r = open(D "/ff", O_RDONLY | O_NONBLOCK);
    CHECK(r >= 0, "nonblocking reader: %d", errno);
    int w = open(D "/ff", O_WRONLY | O_NONBLOCK);
    CHECK(w >= 0, "writer with reader: %d", errno);
    struct stat st;
    CHECK(fstat(r, &st) == 0 && S_ISFIFO(st.st_mode), "fstat of a FIFO end");
    CHECK(write(w, "data", 4) == 4, "write");
    char b[8] = {0};
    CHECK(read(r, b, 8) == 4 && !memcmp(b, "data", 4), "read");
    close(w);
    CHECK(read(r, b, 8) == 0, "EOF after the writer");
    close(r);
    int rw = open(D "/ff", O_RDWR);
    CHECK(rw >= 0, "O_RDWR: %d", errno);
    // (wave7 G7-7: lx=kernel's in-kernel O_RDWR end writes too now)
    CHECK(write(rw, "x", 1) == 1 && read(rw, b, 1) == 1 && b[0] == 'x', "O_RDWR round trip");
    CHECK(fstat(rw, &st) == 0 && S_ISFIFO(st.st_mode), "fstat of the O_RDWR end");
    close(rw);
    // a blocking reader waits for the writer
    pid_t pid = fork();
    if (pid == 0) {
        usleep(100000);
        int fw = open(D "/ff", O_WRONLY);
        write(fw, "late", 4);
        close(fw);
        _exit(0);
    }
    int br = open(D "/ff", O_RDONLY);
    CHECK(br >= 0, "blocking reader: %d", errno);
    memset(b, 0, sizeof b);
    CHECK(read(br, b, 4) == 4 && !memcmp(b, "late", 4), "blocking read [%s]", b);
    close(br);
    waitpid(pid, NULL, 0);
    // permissions: no rights for the caller (root: as nobody on a 0600 FIFO; otherwise the
    // owner on a 0000 one)
    int stv = 0;
    if (geteuid() == 0) {
        chmod(D "/ff", 0600);
        pid = fork();
        if (pid == 0) {
            if (setgid(65534)) _exit(110 + (errno & 15));
            if (setuid(65534)) _exit(130 + (errno & 15));
            int f = open(D "/ff", O_RDONLY | O_NONBLOCK);
            _exit(f == -1 && errno == EACCES ? 0 : f >= 0 ? 100 : errno);
        }
        waitpid(pid, &stv, 0);
    } else {
        chmod(D "/ff", 0);
        int f = open(D "/ff", O_RDONLY | O_NONBLOCK);
        stv = f == -1 && errno == EACCES ? 0 : 0x6400;
        if (f >= 0) close(f);
    }
    CHECK(WIFEXITED(stv) && WEXITSTATUS(stv) == 0, "a FIFO without rights must be EACCES (status %#x)", stv);
    unlink(D "/ff");
}

int main(int argc, char **argv) {
    if (getenv("E75_DUMP")) {
        char exe[4096] = {0};
        readlink("/proc/self/exe", exe, sizeof exe - 1);
        for (int i = 0; i < argc; i++) printf("%s%s", i ? "|" : "", argv[i]);
        printf(" exe=%s", exe);
        return 0;
    }
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) { printf("FAIL no /proc/self/exe\n"); return 1; }
    umask(022);
    printf("uid %d euid %d\n", getuid(), geteuid());
    fflush(stdout);
    exec_tests();
    printf("STEP exec done\n");
    fflush(stdout);
    unix_tests();
    printf("STEP unix done\n");
    fflush(stdout);
    fifo_tests();
    if (fails) { printf("EXEC_W7 FAIL (%d)\n", fails); return 1; }
    printf("EXEC_W7 PASS\n");
    return 0;
}
