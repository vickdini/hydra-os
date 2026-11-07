// Clock and host setting, pkey_mprotect, memfd_secret, map_shadow_stack, the *xattrat
// calls, the LSM attribute calls, statmount and listmount. Calls a kernel lacks (ENOSYS)
// are skipped. Run as a user and as root.
// Build: gcc -O1 -w -o batch3 batch3_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int fails, skipped;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}
static void skip(const char *what) {
    printf("skip %s\n", what);
    skipped++;
}

static long now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return t.tv_sec;
}

static void clocks(int root) {
    struct timespec t = {now_s() + 3600, 0};
    errno = 0;
    int r = clock_settime(CLOCK_MONOTONIC, &t);
    check(r == -1 && errno == EINVAL, "clock_settime(CLOCK_MONOTONIC): EINVAL");
    struct timex tx = {0};
    int state = adjtimex(&tx);
    check(state >= 0 && labs(tx.time.tv_sec - now_s()) <= 2, "adjtimex reads the clock state and time");
    if (!root) {
        errno = 0;
        check(clock_settime(CLOCK_REALTIME, &t) == -1 && errno == EPERM, "clock_settime without CAP_SYS_TIME: EPERM");
        struct timeval tv = {now_s(), 0};
        errno = 0;
        check(settimeofday(&tv, NULL) == -1 && errno == EPERM, "settimeofday without CAP_SYS_TIME: EPERM");
        return;
    }
    long before = now_s();
    check(clock_settime(CLOCK_REALTIME, &t) == 0 && labs(now_s() - (before + 3600)) <= 2, "clock_settime moves the wall clock");
    struct timeval tv = {before, 0};
    check(settimeofday(&tv, NULL) == 0 && labs(now_s() - before) <= 2, "settimeofday sets it back");
    struct timex step = {.modes = ADJ_SETOFFSET | ADJ_NANO};
    step.time.tv_sec = 100;
    long b2 = now_s();
    check(adjtimex(&step) >= 0 && labs(now_s() - (b2 + 100)) <= 2, "adjtimex ADJ_SETOFFSET steps the clock");
    tv.tv_sec = now_s() - 100;
    settimeofday(&tv, NULL);
}

static void hostname(void) {
    struct utsname u0;
    uname(&u0);
    if (getuid() != 0) {
        errno = 0;
        check(sethostname("x", 1) == -1 && errno == EPERM, "sethostname without CAP_SYS_ADMIN: EPERM");
    }
    int p[2];
    pipe(p);
    pid_t c = fork();
    if (c == 0) {
        int r = 0;
        if (unshare(CLONE_NEWUSER | CLONE_NEWUTS) != 0) r = 100;
        else {
            if (sethostname("testhost", 8) != 0) r |= 1;
            if (setdomainname("testdom", 7) != 0) r |= 2;
            struct utsname u;
            uname(&u);
            if (strcmp(u.nodename, "testhost") != 0) r |= 4;
            if (strcmp(u.domainname, "testdom") != 0) r |= 8;
            errno = 0;
            if (sethostname("x", 65) != -1 || errno != EINVAL) r |= 16;
        }
        write(p[1], &r, sizeof r);
        _exit(0);
    }
    int r = -1;
    read(p[0], &r, sizeof r);
    waitpid(c, NULL, 0);
    if (r == 100) {
        skip("UTS namespaces (unshare refused)");
        return;
    }
    check(r == 0, "sethostname and setdomainname in a new UTS namespace show in uname");
    struct utsname u1;
    uname(&u1);
    check(!strcmp(u0.nodename, u1.nodename) && !strcmp(u0.domainname, u1.domainname), "the parent's names are unchanged");
}

static void memory(void) {
    char *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(syscall(SYS_pkey_mprotect, m, 4096, PROT_READ, -1) == 0, "pkey_mprotect with key -1 is mprotect");
    errno = 0;
    check(syscall(SYS_pkey_mprotect, m, 4096, PROT_READ, 15) == -1 && errno == EINVAL, "pkey_mprotect with an unallocated key: EINVAL");
    int s = syscall(447, 0);
    if (s < 0 && (errno == ENOSYS)) skip("memfd_secret");
    else {
        int ok = s >= 0 && ftruncate(s, 4096) == 0;
        char *p = ok ? mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, s, 0) : MAP_FAILED;
        ok = ok && p != MAP_FAILED;
        if (ok) {
            strcpy(p, "secret");
            ok = !strcmp(p, "secret");
        }
        check(ok, "memfd_secret: size, map, use");
    }
    errno = 0;
    long r = syscall(453, 0, 4096, 0);
    check(r == -1 && (errno == EOPNOTSUPP || errno == ENOSYS), "map_shadow_stack: no shadow stacks (EOPNOTSUPP)");
}

struct xattr_args { uint64_t value; uint32_t size, flags; };

static void xattrs(void) {
    char f[64];
    snprintf(f, sizeof f, "/tmp/b3.%d", getpid());
    close(open(f, O_CREAT | O_WRONLY, 0644));
    char v[16];
    errno = 0;
    check(getxattr("/nonexistent-b3", "user.x", v, sizeof v) == -1 && errno == ENOENT, "getxattr on a missing file: ENOENT");
    errno = 0;
    check(getxattr(f, "user.missing", v, sizeof v) == -1 && (errno == ENODATA || errno == EOPNOTSUPP), "getxattr of an absent attribute: ENODATA");
    struct xattr_args a = {(uint64_t)v, sizeof v, 0};
    errno = 0;
    long r = syscall(464, AT_FDCWD, f, 0, "user.missing", &a, sizeof a);
    if (r == -1 && errno == ENOSYS) {
        skip("*xattrat");
    } else {
        check(r == -1 && (errno == ENODATA || errno == EOPNOTSUPP), "getxattrat of an absent attribute: ENODATA");
        errno = 0;
        check(syscall(464, AT_FDCWD, "/nonexistent-b3", 0, "user.x", &a, sizeof a) == -1 && errno == ENOENT, "getxattrat on a missing file: ENOENT");
        errno = 0;
        check(syscall(465, AT_FDCWD, f, 0, v, sizeof v) >= 0, "listxattrat");
        errno = 0;
        check(syscall(464, AT_FDCWD, f, 0, "user.x", &a, 8) == -1 && errno == EINVAL, "getxattrat with a short argument size: EINVAL");
    }
    unlink(f);
}

static void lsm(void) {
    uint64_t ids[8];
    uint32_t size = sizeof ids;
    errno = 0;
    long n = syscall(461, ids, &size, 0);
    if (n == -1 && errno == ENOSYS) {
        skip("LSM attribute calls");
        return;
    }
    int has_cap = 0;
    for (int i = 0; i < n; i++) has_cap |= ids[i] == 100;
    check(n >= 1 && has_cap && size == n * 8, "lsm_list_modules lists the capability module");
    uint32_t tiny = 0;
    errno = 0;
    check(syscall(461, ids, &tiny, 0) == -1 && errno == E2BIG && tiny >= 8, "lsm_list_modules with no room: E2BIG and the size needed");
}

struct mnt_id_req { uint32_t size, spare; uint64_t mnt_id, param; };

static void mounts(void) {
    uint64_t ids[256];
    struct mnt_id_req req = {24, 0, ~0ull, 0};
    errno = 0;
    long n = syscall(458, &req, ids, 256, 0);
    if (n == -1 && errno == ENOSYS) {
        skip("statmount/listmount");
        return;
    }
    check(n >= 1, "listmount(LSMT_ROOT) lists the namespace's mounts");
    // The root mount: its mount point is "/"
    int root_found = 0;
    static char buf[8192];
    for (int i = 0; i < n && !root_found; i++) {
        struct mnt_id_req q = {24, 0, ids[i], 0x2 | 0x10 | 0x20};
        if (syscall(457, &q, buf, sizeof buf, 0) != 0) continue;
        uint32_t point = *(uint32_t *)(buf + 108), fstype = *(uint32_t *)(buf + 36);
        uint64_t mask = *(uint64_t *)(buf + 8);
        if ((mask & 0x30) == 0x30 && !strcmp(buf + 512 + point, "/")) root_found = strlen(buf + 512 + fstype) > 0;
    }
    check(root_found, "statmount gives a mount point and file system type (the root is \"/\")");
    struct mnt_id_req bad = {24, 0, 12345, 2};
    errno = 0;
    check(syscall(457, &bad, buf, sizeof buf, 0) == -1 && errno == ENOENT, "statmount of an unknown mount: ENOENT");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int root = geteuid() == 0;
    printf("running as %s\n", root ? "root" : "a user");
    clocks(root);
    hostname();
    memory();
    xattrs();
    lsm();
    mounts();
    printf(fails ? "BATCH3 TEST FAILED (%d)\n" : "BATCH3 TEST PASSED (%d skipped)\n", fails ? fails : skipped);
    return fails != 0;
}
