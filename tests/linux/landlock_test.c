// Landlock: rulesets, path-beneath and port rules, restrict_self, stacking, inheritance.
// Adapts to the ABI the kernel offers (WSL 5.15 has 1, Hydra 4).
// Build: gcc -static-pie -O1 -w -o landlock landlock_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define A_EXEC (1ULL << 0)
#define A_WRITE (1ULL << 1)
#define A_READ (1ULL << 2)
#define A_READDIR (1ULL << 3)
#define A_REFER (1ULL << 13)
#define A_TRUNC (1ULL << 14)
#define LANDLOCK_CREATE_RULESET_VERSION 1
#define R_PATH 1
#define R_PORT 2

struct ruleset_attr { uint64_t fs, net; };
struct path_rule { uint64_t allowed; int32_t fd; } __attribute__((packed));
struct port_rule { uint64_t allowed, port; };

static int fails, abi;
static char T[64];

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long ll_create(void *attr, size_t size, unsigned flags) { return syscall(444, attr, size, flags); }
static long ll_add(int fd, int type, void *attr) { return syscall(445, fd, type, attr, 0); }
static long ll_restrict(int fd) { return syscall(446, fd, 0); }

static uint64_t fs_all(void) {
    uint64_t m = (1ULL << 13) - 1;
    if (abi >= 2) m |= A_REFER;
    if (abi >= 3) m |= A_TRUNC;
    return m;
}

static char *at(const char *rel) {
    static char buf[4][128];
    static int n;
    char *b = buf[n++ & 3];
    snprintf(b, 128, "%s/%s", T, rel);
    return b;
}

static int add_path(int rs, const char *path, uint64_t allowed) {
    int fd = open(path, O_PATH | O_CLOEXEC);
    struct path_rule r = {allowed, fd};
    int ret = ll_add(rs, R_PATH, &r);
    close(fd);
    return ret;
}

static int errno_of(long r) { return r < 0 ? errno : 0; }

static void touch(const char *p) {
    int fd = open(p, O_CREAT | O_WRONLY, 0755);
    write(fd, "data", 4);
    close(fd);
}

// Copies this program to `dst` (to try running it from there)
static void copy_self(const char *dst) {
    int in = open("/proc/self/exe", O_RDONLY), out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    char b[65536];
    ssize_t n;
    while ((n = read(in, b, sizeof b)) > 0) write(out, b, n);
    close(in);
    close(out);
}

// Runs `f` in a child; returns its exit status (0 = all good, else failure bits)
static int in_child(int (*f)(void)) {
    pid_t c = fork();
    if (c == 0) _exit(f());
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 0xff;
}

static int fs_case(void) {
    int bad = 0;
    struct ruleset_attr a = {fs_all(), 0};
    int rs = ll_create(&a, 8, 0);
    if (rs < 0) return 0x80;
    // Read and list everything; full access beneath rw/ (truncation only on rw/t)
    add_path(rs, "/", A_READ | A_READDIR | A_EXEC);
    add_path(rs, at("rw"), fs_all() & ~A_TRUNC);
    if (abi >= 3) add_path(rs, at("rw/t"), A_TRUNC);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ll_restrict(rs) != 0) return 0x81;
    close(rs);

    int fd = open(at("ro/f"), O_RDONLY);
    if (fd < 0) bad |= 1;
    close(fd);
    if (errno_of(open(at("ro/f"), O_WRONLY)) != EACCES) bad |= 2;
    fd = open(at("rw/g"), O_WRONLY);
    if (fd < 0) bad |= 4;
    close(fd);
    if (errno_of(open(at("ro/new"), O_CREAT | O_WRONLY, 0644)) != EACCES) bad |= 8;
    fd = open(at("rw/new"), O_CREAT | O_WRONLY, 0644);
    if (fd < 0) bad |= 8;
    close(fd);
    if (errno_of(mkdir(at("ro/d"), 0755)) != EACCES || mkdir(at("rw/d"), 0755) != 0) bad |= 16;
    if (errno_of(unlink(at("ro/f"))) != EACCES || unlink(at("rw/new")) != 0) bad |= 32;
    if (errno_of(symlink("x", at("ro/s"))) != EACCES || symlink("x", at("rw/s")) != 0) bad |= 64;
    // ABI 1 kernels (5.13-5.18) refuse any change of directory with EXDEV first
    if (errno_of(rename(at("rw/g"), at("ro/g"))) != (abi == 1 ? EXDEV : EACCES)) bad |= 128;
    touch(at("rw/a"));
    if (rename(at("rw/a"), at("rw/b")) != 0) bad |= 256;
    // Moving to another directory needs REFER (never granted under ABI 1)
    int mv = errno_of(rename(at("rw/b"), at("rw/d/b")));
    if (abi >= 2 ? mv != 0 : mv != EXDEV) bad |= 512;
    if (abi >= 3) {
        if (errno_of(truncate(at("rw/g"), 0)) != EACCES || truncate(at("rw/t"), 0) != 0) bad |= 1024;
        if (errno_of(open(at("rw/g"), O_WRONLY | O_TRUNC)) != EACCES) bad |= 1024;
        fd = open(at("rw/g"), O_WRONLY);
        if (errno_of(ftruncate(fd, 0)) != EACCES) bad |= 2048;
        close(fd);
        fd = open(at("rw/t"), O_WRONLY);
        if (ftruncate(fd, 0) != 0) bad |= 2048;
        close(fd);
    }
    // Inherited by children
    pid_t c = fork();
    if (c == 0) _exit(errno_of(open(at("ro/f"), O_WRONLY)) == EACCES ? 0 : 1);
    int st;
    waitpid(c, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) bad |= 4096;
    // A second layer that refuses reading beneath ro/
    struct ruleset_attr a2 = {A_READ, 0};
    int rs2 = ll_create(&a2, 8, 0);
    add_path(rs2, at("rw"), A_READ);
    add_path(rs2, "/proc", A_READ);
    if (ll_restrict(rs2) != 0) bad |= 8192;
    if (errno_of(open(at("ro/f"), O_RDONLY)) != EACCES) bad |= 8192;
    fd = open(at("rw/t"), O_RDONLY);
    if (fd < 0) bad |= 8192;
    close(fd);
    // No mount changes (when this kernel lets an unprivileged user try)
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0 && errno_of(mount("none", "/tmp", "tmpfs", 0, NULL)) != EPERM) bad |= 16384;
    if (bad) {
        printf("     fs_case failed bits %#x\n", bad);
        fflush(stdout);
    }
    return bad != 0;
}

static int exec_case(void) {
    struct ruleset_attr a = {A_EXEC, 0};
    int rs = ll_create(&a, 8, 0);
    add_path(rs, at("rw"), A_EXEC);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ll_restrict(rs) != 0) return 1;
    char *argv[] = {"me", "--exit0", NULL};
    execv(at("ro/me"), argv);
    if (errno != EACCES) return 2;
    execv(at("rw/me"), argv);
    return 4;
}

static int net_case(void) {
    struct ruleset_attr a = {0, 3};
    int rs = ll_create(&a, 16, 0);
    if (rs < 0) return 1;
    struct port_rule p = {2, 8443};   // connect to 8443 only
    if (ll_add(rs, R_PORT, &p) != 0) return 2;
    struct port_rule bad_port = {2, 70000};
    if (errno_of(ll_add(rs, R_PORT, &bad_port)) != EINVAL) return 4;
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (ll_restrict(rs) != 0) return 8;
    int r = 0;
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(9999)};
    if (errno_of(bind(s, (void *)&sa, sizeof sa)) != EACCES) r |= 16;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (errno_of(connect(s, (void *)&sa, sizeof sa)) != EACCES) r |= 32;
    close(s);
    s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sa.sin_port = htons(8443);
    if (errno_of(connect(s, (void *)&sa, sizeof sa)) == EACCES) r |= 64;
    close(s);
    return r;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--exit0")) return 0;
    abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) {
        printf("skip: no Landlock (%s)\n", strerror(errno));
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("Landlock ABI %d\n", abi);
    snprintf(T, sizeof T, "/tmp/ll.%d", getpid());
    mkdir(T, 0755);
    mkdir(at("ro"), 0755);
    mkdir(at("rw"), 0755);
    touch(at("ro/f"));
    touch(at("rw/g"));
    touch(at("rw/t"));
    copy_self(at("ro/me"));
    copy_self(at("rw/me"));

    // Ruleset creation and rules
    struct ruleset_attr none = {0, 0}, unknown = {1ULL << 40, 0}, fsr = {A_READ | A_READDIR, 0};
    check(errno_of(ll_create(&none, 8, 0)) == ENOMSG, "empty ruleset: ENOMSG");
    check(errno_of(ll_create(&unknown, 8, 0)) == EINVAL, "unknown right: EINVAL");
    check(errno_of(ll_create(&fsr, 8, 4)) == EINVAL, "unknown flag: EINVAL");
    check(errno_of(ll_create(&fsr, 4, 0)) == EINVAL, "short attribute: EINVAL");
    int rs = ll_create(&fsr, 8, 0);
    check(rs >= 0 && (fcntl(rs, F_GETFD) & FD_CLOEXEC), "ruleset descriptor is close-on-exec");
    char link[64] = {0}, p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", rs);
    readlink(p, link, sizeof link - 1);
    check(!strcmp(link, "anon_inode:[landlock-ruleset]"), "ruleset shows as anon_inode:[landlock-ruleset]");
    struct path_rule zero = {0, -1};
    check(errno_of(ll_add(rs, R_PATH, &zero)) == ENOMSG, "rule granting nothing: ENOMSG");
    check(errno_of(add_path(rs, T, A_WRITE)) == EINVAL, "rule granting an unhandled right: EINVAL");
    check(errno_of(add_path(rs, at("ro/f"), A_READDIR)) == EINVAL, "directory right on a file: EINVAL");
    check(add_path(rs, at("ro/f"), A_READ) == 0, "file right on a file");
    struct path_rule badfd = {A_READ, 9999};
    check(errno_of(ll_add(rs, R_PATH, &badfd)) == EBADF, "rule on a closed descriptor: EBADF");
    int pf[2];
    pipe(pf);
    check(errno_of(ll_add(pf[0], R_PATH, &zero)) == EBADFD, "add_rule on a pipe: EBADFD");
    if (getuid() != 0) check(errno_of(ll_restrict(9999)) == EPERM, "restrict_self without no_new_privs: EPERM before the descriptor is looked at");
    if (getuid() != 0) {
        pid_t c = fork();
        if (c == 0) _exit(errno_of(ll_restrict(rs)) == EPERM ? 0 : 1);
        int st;
        waitpid(c, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "restrict_self without no_new_privs: EPERM");
    }
    close(rs);

    int f = in_child(fs_case);
    check(f == 0, "file system rules (open, create, mkdir, unlink, symlink, rename, refer, truncate, inheritance, stacking, mount)");
    if (f) printf("     fs_case status %#x\n", f);
    pid_t c = fork();
    if (c == 0) {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        _exit(errno_of(ll_restrict(9999)) == EBADF ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "restrict_self on a closed descriptor: EBADF");
    int e = in_child(exec_case);
    check(e == 0, "exec allowed beneath rw/, refused beneath ro/");
    if (e) printf("     exec_case status %#x\n", e);
    if (abi >= 4) {
        int n = in_child(net_case);
        check(n == 0, "TCP bind and connect limited to granted ports");
        if (n) printf("     net_case status %#x\n", n);
    } else {
        printf("skip: TCP rules need ABI 4\n");
    }
    printf(fails ? "LANDLOCK TEST FAILED (%d)\n" : "LANDLOCK TEST PASSED\n", fails);
    return fails != 0;
}
