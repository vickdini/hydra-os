// Extended attributes and file capabilities.
// As any user: user.* get/set/list/remove (sizes, ERANGE, XATTR_CREATE/REPLACE, ENODATA),
// the f*/l* variants, name and size limits, permissions (EACCES without write access,
// EPERM on symlinks), trusted.* and security.* rules, hard links sharing attributes, many
// attributes, a deleted file's attributes not reaching a new file.
// As root, additionally: security.capability (header validation), a program given
// cap_net_raw+ep run by uid 1000 gets CAP_NET_RAW (effective) and AT_SECURE; no_new_privs
// blocks it; writing to or chowning the file drops the capability; trusted.* is hidden
// from unprivileged lists.
// Build: gcc -O1 -w -o xattr xattr_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static char dir[128];
static char *path(const char *name) {
    static char b[4][256];
    static int i;
    i = (i + 1) % 4;
    snprintf(b[i], sizeof b[i], "%s/%s", dir, name);
    return b[i];
}

static int touch(const char *p, int mode) {
    int fd = open(p, O_RDWR | O_CREAT | O_TRUNC, mode);
    if (fd >= 0) close(fd);
    return fd >= 0;
}

// Child mode: report CAP_NET_RAW (effective), AT_SECURE and whether a raw socket opens
static int child(void) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    syscall(SYS_capget, &h, d);
    int eff = (d[0].effective >> CAP_NET_RAW) & 1;
    int raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) >= 0;
    printf("child uid=%d eff_net_raw=%d at_secure=%lu raw_socket=%d\n", getuid(), eff, getauxval(AT_SECURE), raw);
    return (eff ? 1 : 0) | (getauxval(AT_SECURE) ? 2 : 0) | (raw ? 4 : 0);
}

// Runs `prog` as uid/gid 1000 (optionally with no_new_privs); returns the child's code
static int run_as_user(const char *prog, int nnp) {
    pid_t p = fork();
    if (p == 0) {
        if (setgid(1000) || setuid(1000)) _exit(99);
        if (nnp) prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        execl(prog, prog, "child", NULL);
        _exit(98);
    }
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void set_net_raw(const char *p) {
    // struct vfs_cap_data, revision 2: effective flag, permitted = CAP_NET_RAW
    unsigned int cap[5] = {0x02000000 | 1, 1u << CAP_NET_RAW, 0, 0, 0};
    setxattr(p, "security.capability", cap, sizeof cap, 0);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "child")) return child();
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(dir, sizeof dir, "/tmp/xattr.%d.%ld", getpid(), (long)time(NULL));
    mkdir(dir, 0755);
    char *f = path("f");
    touch(f, 0644);
    char buf[256];

    check(setxattr(f, "user.test", "hello", 5, 0) == 0, "setxattr user.test");
    check(getxattr(f, "user.test", NULL, 0) == 5, "getxattr with size 0 gives the length");
    memset(buf, 0, sizeof buf);
    check(getxattr(f, "user.test", buf, sizeof buf) == 5 && !memcmp(buf, "hello", 5), "getxattr gives the value");
    errno = 0;
    check(getxattr(f, "user.test", buf, 2) == -1 && errno == ERANGE, "a small buffer: ERANGE");
    errno = 0;
    check(setxattr(f, "user.test", "x", 1, XATTR_CREATE) == -1 && errno == EEXIST, "XATTR_CREATE on an existing name: EEXIST");
    errno = 0;
    check(setxattr(f, "user.none", "x", 1, XATTR_REPLACE) == -1 && errno == ENODATA, "XATTR_REPLACE on a missing name: ENODATA");
    check(setxattr(f, "user.test", "bye", 3, XATTR_REPLACE) == 0 && getxattr(f, "user.test", buf, sizeof buf) == 3, "XATTR_REPLACE replaces");
    check(setxattr(f, "user.empty", "", 0, 0) == 0 && getxattr(f, "user.empty", buf, sizeof buf) == 0, "an empty value");
    ssize_t n = listxattr(f, buf, sizeof buf);
    int seen = 0;
    for (char *p = buf; p < buf + n; p += strlen(p) + 1) seen += !strcmp(p, "user.test") || !strcmp(p, "user.empty");
    check(seen == 2 && listxattr(f, NULL, 0) == n, "listxattr names both, size 0 gives the length");
    check(removexattr(f, "user.empty") == 0, "removexattr");
    errno = 0;
    check(getxattr(f, "user.empty", buf, sizeof buf) == -1 && errno == ENODATA, "a removed name: ENODATA");
    errno = 0;
    check(removexattr(f, "user.empty") == -1 && errno == ENODATA, "removing it again: ENODATA");
    int fd = open(f, O_RDWR);
    check(fsetxattr(fd, "user.fd", "1", 1, 0) == 0 && fgetxattr(fd, "user.fd", buf, sizeof buf) == 1, "fsetxattr / fgetxattr");
    check(write(fd, "data", 4) == 4 && getxattr(f, "user.fd", buf, sizeof buf) == 1, "user attributes survive writes");
    close(fd);
    char *l = path("link");
    symlink(f, l);
    check(getxattr(l, "user.test", buf, sizeof buf) == 3, "getxattr follows a symlink");
    errno = 0;
    check(lsetxattr(l, "user.x", "1", 1, 0) == -1 && errno == EPERM, "user.* on a symlink itself: EPERM");
    errno = 0;
    check(lgetxattr(l, "user.test", buf, sizeof buf) == -1 && errno == ENODATA, "lgetxattr on the symlink: ENODATA");
    check(setxattr(dir, "user.dir", "d", 1, 0) == 0 && getxattr(dir, "user.dir", buf, sizeof buf) == 1, "attributes on a directory");

    // Names and sizes
    errno = 0;
    check(setxattr(f, "other.x", "1", 1, 0) == -1 && errno == EOPNOTSUPP, "an unknown namespace: EOPNOTSUPP");
    errno = 0;
    check(setxattr(f, "user.", "1", 1, 0) == -1 && errno == EINVAL, "a bare prefix: EINVAL");
    char longname[300] = "user.";
    memset(longname + 5, 'a', 260);
    errno = 0;
    check(setxattr(f, longname, "1", 1, 0) == -1 && errno == ERANGE, "a name over 255 bytes: ERANGE");
    char *big = calloc(1, 70000);
    errno = 0;
    check(setxattr(f, "user.big", big, 65537, 0) == -1 && errno == E2BIG, "a value over 64 KiB: E2BIG");
    check(setxattr(f, "user.big", big, 4000, 0) == 0 && getxattr(f, "user.big", NULL, 0) == 4000, "a 4000-byte value");
    removexattr(f, "user.big");
    errno = 0;
    check(setxattr(f, "user.x", "1", 1, 7) == -1 && errno == EINVAL, "unknown flags: EINVAL");

    // Many attributes, hard links
    char *m = path("many");
    touch(m, 0644);
    int ok = 1;
    for (int i = 0; i < 50 && ok; i++) {
        char nm[32];
        snprintf(nm, sizeof nm, "user.n%02d", i);
        ok = setxattr(m, nm, nm, strlen(nm), 0) == 0;
    }
    char list[2048];
    n = listxattr(m, list, sizeof list);
    int count = 0;
    for (char *p = list; p < list + n; p += strlen(p) + 1) count++;
    check(ok && count == 50, "50 attributes");
    char *h = path("hard");
    link(m, h);
    check(getxattr(h, "user.n07", buf, sizeof buf) == 8, "a hard link shares them");
    // A deleted file's attributes do not reach a new one
    for (int i = 0; i < 5; i++) {
        char nm[16];
        snprintf(nm, sizeof nm, "tmp%d", i);
        char *t = path(nm);
        touch(t, 0644);
        setxattr(t, "user.ghost", "boo", 3, 0);
        unlink(t);
    }
    ok = 1;
    for (int i = 0; i < 5; i++) {
        char nm[16];
        snprintf(nm, sizeof nm, "new%d", i);
        char *t = path(nm);
        touch(t, 0644);
        ok &= listxattr(t, NULL, 0) == 0;
    }
    check(ok, "new files start without attributes");

    // Permissions and namespaces
    char *ro = path("ro");
    touch(ro, 0444);
    if (geteuid() != 0) {
        errno = 0;
        check(setxattr(ro, "user.x", "1", 1, 0) == -1 && errno == EACCES, "user.* without write permission: EACCES");
        errno = 0;
        check(setxattr(f, "trusted.x", "1", 1, 0) == -1 && errno == EPERM, "trusted.* unprivileged: EPERM");
        errno = 0;
        unsigned int valid[5] = {0x02000000 | 1, 1u << CAP_NET_RAW, 0, 0, 0};
        check(setxattr(f, "security.capability", valid, sizeof valid, 0) == -1 && errno == EPERM, "security.capability unprivileged: EPERM");
        errno = 0;
        check(setxattr(f, "security.other", "1", 1, 0) == -1 && errno == EPERM, "other security.* unprivileged: EPERM");
    }
    errno = 0;
    check(getxattr(f, "system.posix_acl_access", buf, sizeof buf) == -1 && (errno == ENODATA || errno == EOPNOTSUPP), "no ACL: ENODATA");

    if (geteuid() == 0) {
        // trusted.*
        check(setxattr(f, "trusted.secret", "s", 1, 0) == 0 && getxattr(f, "trusted.secret", buf, sizeof buf) == 1, "trusted.* as root");
        chmod(dir, 0777);
        chmod(f, 0666);
        pid_t p = fork();
        if (p == 0) {
            setgid(1000);
            setuid(1000);
            char lb[512];
            ssize_t k = listxattr(f, lb, sizeof lb);
            int hidden = 1;
            for (char *q = lb; q < lb + k; q += strlen(q) + 1) hidden &= strncmp(q, "trusted.", 8) != 0;
            errno = 0;
            int r = getxattr(f, "trusted.secret", lb, sizeof lb);
            _exit(hidden && r == -1 && errno == ENODATA ? 0 : 1);
        }
        int st;
        waitpid(p, &st, 0);
        check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "trusted.* hidden from unprivileged users");

        // security.capability header checks
        unsigned int bad[3] = {0x01000000, 1, 0};
        errno = 0;
        check(setxattr(f, "security.capability", bad, sizeof bad, 0) == -1 && errno == EINVAL, "a revision 1 capability: EINVAL");
        unsigned int badflags[5] = {0x02000000 | 4, 1, 0, 0, 0};
        errno = 0;
        check(setxattr(f, "security.capability", badflags, sizeof badflags, 0) == -1 && errno == EINVAL, "unknown capability flags: EINVAL");

        // A copy of this program with cap_net_raw+ep, run as uid 1000
        char *prog = path("capprog");
        int in = open("/proc/self/exe", O_RDONLY), out = open(prog, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        char cb[65536];
        ssize_t r;
        while ((r = read(in, cb, sizeof cb)) > 0) write(out, cb, r);
        close(in);
        close(out);
        chmod(prog, 0755);
        int plain = run_as_user(prog, 0);
        check(plain == 0, "without capabilities: no CAP_NET_RAW, no AT_SECURE, no raw socket");
        set_net_raw(prog);
        unsigned int got[5] = {0};
        check(getxattr(prog, "security.capability", got, sizeof got) == 20 && got[1] == 1u << CAP_NET_RAW, "security.capability reads back");
        int with = run_as_user(prog, 0);
        check(with == 7, "cap_net_raw+ep: CAP_NET_RAW effective, AT_SECURE, a raw socket opens");
        check(run_as_user(prog, 1) == 2, "no_new_privs: the file capability is not granted (AT_SECURE still set)");
        unsigned int noeff[5] = {0x02000000, 1u << CAP_NET_RAW, 0, 0, 0};
        setxattr(prog, "security.capability", noeff, sizeof noeff, 0);
        check(run_as_user(prog, 0) == 2, "without the effective bit: permitted only (not effective)");
        // Writing to the file drops the capability
        set_net_raw(prog);
        int wfd = open(prog, O_WRONLY | O_APPEND);
        write(wfd, "", 0);
        write(wfd, "\0", 1);
        close(wfd);
        errno = 0;
        check(getxattr(prog, "security.capability", got, sizeof got) == -1 && errno == ENODATA, "a write drops security.capability");
        set_net_raw(prog);
        chown(prog, 1000, 1000);
        errno = 0;
        check(getxattr(prog, "security.capability", got, sizeof got) == -1 && errno == ENODATA, "chown drops it too");
    }

    printf(fails ? "XATTR TEST FAILED (%d)\n" : "XATTR TEST PASSED\n", fails);
    return fails != 0;
}
