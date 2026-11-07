// POSIX ACLs and set-ID clearing. Run as root (children take other uids and groups).
// ACLs: validation (EINVAL, EOPNOTSUPP for another version), only the owner sets them
// (EPERM), default ACLs only on directories (EACCES), the mode follows the ACL, an ACL
// equal to the mode is not kept, named users and groups with the mask, chmod rewriting
// the ACL, removal, default ACL inheritance (umask ignored, mode limited, directories
// inheriting the default ACL).
// Set-ID: chown clears set-user-ID (and set-group-ID with group execute) even for root, a
// write or truncate by a non-root writer clears them, root keeps them, set-group-ID
// without group execute stays only for a writer in the file's group.
// Build: gcc -O1 -w -o acl acl_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define UO 0x01
#define US 0x02
#define GO 0x04
#define GR 0x08
#define MK 0x10
#define OT 0x20

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

struct ent { unsigned short tag, perm; unsigned int id; };

static int setacl(const char *p, const char *name, const struct ent *e, int n) {
    unsigned char b[4 + 8 * 32];
    unsigned int v = 2;
    memcpy(b, &v, 4);
    memcpy(b + 4, e, 8 * n);
    return setxattr(p, name, b, 4 + 8 * n, 0);
}

static int getacl(const char *p, const char *name, struct ent *e) {
    unsigned char b[4 + 8 * 32];
    ssize_t n = getxattr(p, name, b, sizeof b);
    if (n < 4) return -1;
    memcpy(e, b + 4, n - 4);
    return (n - 4) / 8;
}

// Can uid (with gid and an optional supplementary group) open p for `flags`?
static int can(const char *p, int uid, int gid, int sup, int flags) {
    pid_t c = fork();
    if (c == 0) {
        gid_t g[1] = {sup};
        setgroups(sup ? 1 : 0, g);
        setgid(gid);
        setuid(uid);
        int fd = open(p, flags);
        _exit(fd >= 0 ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static mode_t mode_of(const char *p) {
    struct stat s;
    stat(p, &s);
    return s.st_mode & 07777;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (geteuid() != 0) {
        printf("run as root\n");
        return 1;
    }
    char dir[128], f[160], g[160], d2[160], nf[200], nd[200];
    snprintf(dir, sizeof dir, "/tmp/acl.%d.%ld", getpid(), (long)time(NULL));
    mkdir(dir, 0777);
    chmod(dir, 0777);
    snprintf(f, sizeof f, "%s/f", dir);
    int fd = open(f, O_RDWR | O_CREAT, 0640);
    write(fd, "x", 1);
    close(fd);
    chown(f, 1000, 1000);
    chmod(f, 0640);

    // Validation and permissions to set
    struct ent named[] = {{UO, 6, 0}, {US, 4, 1001}, {GO, 0, 0}, {MK, 4, 0}, {OT, 0, 0}};
    struct ent nomask[] = {{UO, 6, 0}, {US, 4, 1001}, {GO, 0, 0}, {OT, 0, 0}};
    errno = 0;
    check(setacl(f, "system.posix_acl_access", nomask, 4) == -1 && errno == EINVAL, "a named user without a mask: EINVAL");
    struct ent unordered[] = {{GO, 0, 0}, {UO, 6, 0}, {OT, 0, 0}};
    errno = 0;
    check(setacl(f, "system.posix_acl_access", unordered, 3) == -1 && errno == EINVAL, "entries out of order: EINVAL");
    unsigned char badver[12] = {1, 0, 0, 0, UO, 0, 6, 0, 0, 0, 0, 0};
    errno = 0;
    check(setxattr(f, "system.posix_acl_access", badver, 12, 0) == -1 && (errno == EOPNOTSUPP || errno == EINVAL), "another version: EOPNOTSUPP");
    pid_t c = fork();
    if (c == 0) {
        setgid(1001);
        setuid(1001);
        errno = 0;
        _exit(setacl(f, "system.posix_acl_access", named, 5) == -1 && errno == EPERM ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "only the owner (or CAP_FOWNER) sets an ACL: EPERM");
    errno = 0;
    check(setacl(f, "system.posix_acl_default", named, 5) == -1 && errno == EACCES, "a default ACL on a file: EACCES");

    // Named users, the mask, the mode
    check(setacl(f, "system.posix_acl_access", named, 5) == 0, "set user::rw- user:1001:r-- group::--- mask::r-- other::---");
    check(mode_of(f) == 0640, "the mode follows: 0640 (group bits = mask)");
    struct ent got[32];
    int n = getacl(f, "system.posix_acl_access", got);
    check(n == 5 && got[1].tag == US && got[1].id == 1001 && got[1].perm == 4, "the ACL reads back");
    check(can(f, 1000, 1000, 0, O_RDWR), "the owner reads and writes");
    check(can(f, 1001, 1001, 0, O_RDONLY) && !can(f, 1001, 1001, 0, O_WRONLY), "user 1001 reads, cannot write");
    check(!can(f, 1002, 1002, 0, O_RDONLY), "user 1002 (other ---) cannot read");
    struct ent masked[] = {{UO, 6, 0}, {US, 6, 1001}, {GO, 0, 0}, {GR, 4, 2000}, {MK, 4, 0}, {OT, 0, 0}};
    setacl(f, "system.posix_acl_access", masked, 6);
    check(!can(f, 1001, 1001, 0, O_WRONLY), "user:1001:rw- under mask::r--: no write");
    check(can(f, 1002, 1002, 2000, O_RDONLY) && !can(f, 1002, 1002, 0, O_RDONLY), "a member of group 2000 reads");
    chmod(f, 0600);
    n = getacl(f, "system.posix_acl_access", got);
    int mk = -1;
    for (int i = 0; i < n; i++) if (got[i].tag == MK) mk = got[i].perm;
    check(mk == 0 && !can(f, 1001, 1001, 0, O_RDONLY), "chmod 0600 sets mask::--- (user 1001 loses read)");
    struct ent minimal[] = {{UO, 6, 0}, {GO, 4, 0}, {OT, 4, 0}};
    errno = 0;
    check(setacl(f, "system.posix_acl_access", minimal, 3) == 0 && getxattr(f, "system.posix_acl_access", NULL, 0) == -1 && errno == ENODATA && mode_of(f) == 0644,
          "an ACL equal to the mode: only the mode (0644) is kept");
    setacl(f, "system.posix_acl_access", named, 5);
    check(removexattr(f, "system.posix_acl_access") == 0 && can(f, 1002, 1002, 0, O_RDONLY) == ((mode_of(f) & 4) != 0), "removing the ACL: the mode decides");

    // Default ACL inheritance
    snprintf(d2, sizeof d2, "%s/inherit", dir);
    mkdir(d2, 0777);
    struct ent def[] = {{UO, 7, 0}, {US, 7, 1001}, {GO, 5, 0}, {MK, 7, 0}, {OT, 5, 0}};
    check(setacl(d2, "system.posix_acl_default", def, 5) == 0, "a default ACL on a directory");
    umask(077);
    snprintf(nf, sizeof nf, "%s/new", d2);
    fd = open(nf, O_RDWR | O_CREAT, 0666);
    close(fd);
    check(mode_of(nf) == 0664, "a new file: umask ignored, mode limited by the request (0664)");
    n = getacl(nf, "system.posix_acl_access", got);
    int u1001 = -1;
    mk = -1;
    for (int i = 0; i < n; i++) {
        if (got[i].tag == US && got[i].id == 1001) u1001 = got[i].perm;
        if (got[i].tag == MK) mk = got[i].perm;
    }
    check(n == 5 && u1001 == 7 && mk == 6, "it inherits user:1001:rwx with mask::rw-");
    check(can(nf, 1001, 1001, 0, O_RDWR), "so user 1001 reads and writes it");
    snprintf(nd, sizeof nd, "%s/sub", d2);
    mkdir(nd, 0777);
    check(getacl(nd, "system.posix_acl_default", got) == 5 && getacl(nd, "system.posix_acl_access", got) == 5, "a new directory inherits the default ACL too");
    umask(022);

    // Set-ID clearing
    snprintf(g, sizeof g, "%s/suid", dir);
    fd = open(g, O_RDWR | O_CREAT, 0755);
    close(fd);
    chmod(g, 06755);
    chown(g, 1000, 1000);
    check(mode_of(g) == 0755, "chown clears set-user-ID and set-group-ID (even root's)");
    chmod(g, 06777);
    fd = open(g, O_WRONLY | O_APPEND);
    write(fd, "r", 1);
    close(fd);
    check(mode_of(g) == 06777, "root's write keeps them (CAP_FSETID)");
    check(can(g, 1002, 1002, 0, O_WRONLY), "(another user may write the file)");
    c = fork();
    if (c == 0) {
        setgid(1002);
        setuid(1002);
        int w = open(g, O_WRONLY | O_APPEND);
        write(w, "u", 1);
        _exit(0);
    }
    waitpid(c, &st, 0);
    check(mode_of(g) == 0777, "another user's write clears them");
    // Set-group-ID without group execute: kept for a writer in the file's group (1000),
    // dropped for anyone else
    for (int member = 1; member >= 0; member--) {
        chmod(g, 02747);
        c = fork();
        if (c == 0) {
            gid_t sup[1] = {1000};
            setgroups(member, sup);
            setgid(1002);
            setuid(1002);
            int w = open(g, O_WRONLY | O_APPEND);
            write(w, "u", 1);
            _exit(0);
        }
        waitpid(c, &st, 0);
        if (member)
            check(mode_of(g) == 02747, "set-group-ID without group execute stays for a group member's write");
        else
            check(mode_of(g) == 0747, "and goes for a non-member's write");
    }
    chmod(g, 04777);
    c = fork();
    if (c == 0) {
        setgid(1002);
        setuid(1002);
        _exit(truncate(g, 1));
    }
    waitpid(c, &st, 0);
    check(mode_of(g) == 0777, "a truncate by another user clears set-user-ID");

    printf(fails ? "ACL TEST FAILED (%d)\n" : "ACL TEST PASSED\n", fails);
    return fails != 0;
}
