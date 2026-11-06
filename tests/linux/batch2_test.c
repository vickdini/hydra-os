// setns, NUMA policy, readahead, cachestat, mseal, kcmp, sched_setattr/getattr,
// process_vm_readv/writev. Calls missing from the running kernel (ENOSYS) are skipped.
// Build: gcc -static-pie -O1 -w -o batch2 batch2_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails, skips;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}
static int skipped(long r, const char *what) {
    if (r == -1 && errno == ENOSYS) {
        printf("skip %s (ENOSYS)\n", what);
        skips++;
        return 1;
    }
    return 0;
}

#define MPOL_DEFAULT 0
#define MPOL_BIND 2
#define KCMP_FILE 0
#define KCMP_VM 1
#define KCMP_FILES 2

struct sched_attr_ {
    uint32_t size, policy;
    uint64_t flags;
    int32_t nice;
    uint32_t priority;
    uint64_t runtime, deadline, period;
    uint32_t util_min, util_max;
};

static void ns_link(pid_t pid, const char *kind, char *out) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/ns/%s", pid, kind);
    ssize_t n = readlink(p, out, 63);
    out[n > 0 ? n : 0] = 0;
}

static void test_setns(void) {
    int go[2], ready[2];
    pipe(go);
    pipe(ready);
    pid_t c = fork();
    if (c == 0) {
        int ok = unshare(CLONE_NEWUSER | CLONE_NEWUTS) == 0;
        write(ready[1], &ok, sizeof ok);
        char b;
        read(go[0], &b, 1);
        _exit(0);
    }
    int ok = 0;
    read(ready[0], &ok, sizeof ok);
    check(ok, "child unshares user and uts namespaces");
    char want_user[64], want_uts[64], mine[64];
    ns_link(c, "user", want_user);
    ns_link(c, "uts", want_uts);

    // Join from a helper process so this one keeps its namespaces
    pid_t h = fork();
    if (h == 0) {
        char p[64];
        int bad = 0;
        snprintf(p, sizeof p, "/proc/%d/ns/uts", c);
        int uts = open(p, O_RDONLY);
        snprintf(p, sizeof p, "/proc/%d/ns/user", c);
        int user = open(p, O_RDONLY);
        if (setns(9999, 0) != -1 || errno != EBADF) bad |= 1;
        int reg = open("/proc/self/stat", O_RDONLY);
        if (setns(reg, 0) != -1 || errno != EINVAL) bad |= 2;
        if (setns(uts, CLONE_NEWNET) != -1 || errno != EINVAL) bad |= 4;
        if (setns(user, CLONE_NEWUSER) != 0) bad |= 8;
        if (setns(uts, CLONE_NEWUTS) != 0) bad |= 16;
        ns_link(getpid(), "user", mine);
        if (strcmp(mine, want_user) != 0) bad |= 32;
        ns_link(getpid(), "uts", mine);
        if (strcmp(mine, want_uts) != 0) bad |= 64;
        _exit(bad);
    }
    int st;
    waitpid(h, &st, 0);
    int bad = WEXITSTATUS(st);
    check(!(bad & 1), "setns bad fd: EBADF");
    check(!(bad & 2), "setns non-namespace file: EINVAL");
    check(!(bad & 4), "setns wrong type: EINVAL");
    check(!(bad & 8), "setns joins the user namespace");
    check(!(bad & 16), "setns joins the uts namespace");
    check(!(bad & 96), "namespace links match after setns");

    // The same through a pidfd
    h = fork();
    if (h == 0) {
        int pfd = syscall(SYS_pidfd_open, c, 0);
        int b = 0;
        if (setns(pfd, CLONE_NEWUSER | CLONE_NEWUTS) != 0) b |= 1;
        ns_link(getpid(), "uts", mine);
        if (strcmp(mine, want_uts) != 0) b |= 2;
        _exit(b);
    }
    waitpid(h, &st, 0);
    check(WEXITSTATUS(st) == 0, "setns through a pidfd");
    write(go[1], "x", 1);
    waitpid(c, NULL, 0);
}

static void test_numa(void) {
    char *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    m[0] = 1;
    unsigned long node0 = 1, node1 = 2;
    long r0 = syscall(SYS_mbind, m, 8192, MPOL_BIND, &node0, 64, 0);
    if (skipped(r0, "NUMA calls")) return;
    check(r0 == 0, "mbind to node 0");
    check(syscall(SYS_mbind, m, 8192, MPOL_BIND, &node1, 64, 0) == -1 && errno == EINVAL, "mbind to node 1: EINVAL");
    check(syscall(SYS_mbind, m + 1, 4096, MPOL_DEFAULT, NULL, 0, 0) == -1 && errno == EINVAL,
          "mbind unaligned: EINVAL");
    check(syscall(SYS_set_mempolicy, MPOL_BIND, &node0, 64) == 0, "set_mempolicy bind node 0");
    check(syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0) == 0, "set_mempolicy default");
    check(syscall(SYS_set_mempolicy, 99, NULL, 0) == -1 && errno == EINVAL, "set_mempolicy bad mode: EINVAL");
    void *pages[1] = {m};
    int status[1] = {-1}, nodes[1] = {1};
    check(syscall(SYS_move_pages, 0, 1, pages, NULL, status, 0) == 0 && status[0] == 0, "move_pages query: node 0");
    check(syscall(SYS_move_pages, 0, 1, pages, nodes, status, 0) == -1 && errno == ENODEV,
          "move_pages to node 1: ENODEV");
    check(syscall(SYS_migrate_pages, 0, 64, &node0, &node0) == 0, "migrate_pages");
    long r = syscall(450, m, 8192, 0, 0);
    if (!skipped(r, "set_mempolicy_home_node")) check(r == 0, "set_mempolicy_home_node");
    munmap(m, 8192);
}

static void test_files(void) {
    char path[] = "/tmp/b2XXXXXX";
    int fd = mkstemp(path);
    char buf[10000];
    memset(buf, 'a', sizeof buf);
    write(fd, buf, sizeof buf);
    check(syscall(SYS_readahead, fd, 0, 4096) == 0, "readahead regular file");
    int p[2];
    pipe(p);
    check(syscall(SYS_readahead, p[0], 0, 4096) == -1 && errno == EINVAL, "readahead pipe: EINVAL");
    check(syscall(SYS_readahead, 999, 0, 4096) == -1 && errno == EBADF, "readahead bad fd: EBADF");
    struct { uint64_t off, len; } range = {0, 0};
    uint64_t cs[5] = {99, 99, 99, 99, 99};
    long r = syscall(451, fd, &range, cs, 0);
    if (!skipped(r, "cachestat")) {
        check(r == 0 && cs[0] == 3, "cachestat counts the file's 3 pages");
        range.off = 4096;
        range.len = 4096;
        check(syscall(451, fd, &range, cs, 0) == 0 && cs[0] == 1, "cachestat of one page");
        check(syscall(451, fd, &range, cs, 1) == -1 && errno == EINVAL, "cachestat flags: EINVAL");
    }
    unlink(path);
    close(fd);
}

static void test_mseal(void) {
    char *m = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    long r = syscall(462, m, 8192, 0);
    if (skipped(r, "mseal")) return;
    check(r == 0, "mseal a mapping");
    check(syscall(462, m + 1, 4096, 0) == -1 && errno == EINVAL, "mseal unaligned: EINVAL");
    check(syscall(462, m, 4096, 1) == -1 && errno == EINVAL, "mseal flags: EINVAL");
    char *hole = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(hole, 4096);
    check(syscall(462, hole, 4096, 0) == -1 && errno == ENOMEM, "mseal unmapped: ENOMEM");
}

static void test_kcmp(void) {
    int a = open("/proc/self/stat", O_RDONLY);
    int b = dup(a);
    int c = open("/proc/self/stat", O_RDONLY);
    pid_t me = getpid();
    long r = syscall(SYS_kcmp, me, me, KCMP_FILE, a, b);
    if (skipped(r, "kcmp")) return;
    check(r == 0, "kcmp dup'd descriptors equal");
    r = syscall(SYS_kcmp, me, me, KCMP_FILE, a, c);
    check(r == 1 || r == 2, "kcmp separate opens differ");
    check(syscall(SYS_kcmp, me, me, KCMP_VM, 0, 0) == 0, "kcmp same address space");
    int go[2];
    pipe(go);
    pid_t ch = fork();
    if (ch == 0) {
        char x;
        read(go[0], &x, 1);
        _exit(0);
    }
    r = syscall(SYS_kcmp, me, ch, KCMP_VM, 0, 0);
    check(r == 1 || r == 2, "kcmp forked address spaces differ");
    r = syscall(SYS_kcmp, me, ch, KCMP_FILES, 0, 0);
    check(r == 1 || r == 2, "kcmp forked descriptor tables differ");
    check(syscall(SYS_kcmp, me, ch, KCMP_FILE, a, a) == 0, "kcmp inherited descriptor equal");
    check(syscall(SYS_kcmp, me, me, KCMP_FILE, a, 999) == -1 && errno == EBADF, "kcmp bad fd: EBADF");
    write(go[1], "x", 1);
    waitpid(ch, NULL, 0);
}

static void test_sched(void) {
    struct sched_attr_ at;
    memset(&at, 0, sizeof at);
    at.size = 48;
    at.policy = SCHED_OTHER;
    at.nice = 5;
    check(syscall(SYS_sched_setattr, 0, &at, 0) == 0, "sched_setattr nice 5");
    memset(&at, 0xff, sizeof at);
    check(syscall(SYS_sched_getattr, 0, &at, sizeof at, 0) == 0 && at.policy == SCHED_OTHER && at.nice == 5,
          "sched_getattr reads it back");
    check(at.size == sizeof at, "sched_getattr size");
    check(syscall(SYS_sched_getattr, 0, &at, 16, 0) == -1 && errno == EINVAL, "sched_getattr small: EINVAL");
    memset(&at, 0, sizeof at);
    at.size = 48;
    at.policy = 77;
    check(syscall(SYS_sched_setattr, 0, &at, 0) == -1 && errno == EINVAL, "bad policy: EINVAL");
    at.size = 20;
    at.policy = 0;
    check(syscall(SYS_sched_setattr, 0, &at, 0) == -1 && errno == E2BIG, "short size: E2BIG");
    if (geteuid() != 0) {
        memset(&at, 0, sizeof at);
        at.size = 48;
        at.policy = SCHED_FIFO;
        at.priority = 10;
        check(syscall(SYS_sched_setattr, 0, &at, 0) == -1 && errno == EPERM, "FIFO unprivileged: EPERM");
        at.policy = SCHED_OTHER;
        at.priority = 0;
        at.nice = 0;
        check(syscall(SYS_sched_setattr, 0, &at, 0) == -1 && errno == EPERM, "lowering nice unprivileged: EPERM");
    }
}

static char shared[64] = "parent-initial";

static void test_process_vm(void) {
    int go[2], back[2];
    pipe(go);
    pipe(back);
    pid_t c = fork();
    if (c == 0) {
        strcpy(shared, "child-data");
        write(back[1], "r", 1);
        char x;
        read(go[0], &x, 1);
        _exit(strcmp(shared, "written-by-parent") == 0 ? 0 : 1);
    }
    char x;
    read(back[0], &x, 1);
    char buf[64] = {0};
    struct iovec l = {buf, 10}, r = {shared, 10};
    long n = syscall(SYS_process_vm_readv, c, &l, 1, &r, 1, 0);
    check(n == 10 && memcmp(buf, "child-data", 10) == 0, "process_vm_readv");
    // Scatter across two local buffers
    char p1[4] = {0}, p2[6] = {0};
    struct iovec l2[2] = {{p1, 4}, {p2, 6}};
    n = syscall(SYS_process_vm_readv, c, l2, 2, &r, 1, 0);
    check(n == 10 && memcmp(p1, "chil", 4) == 0 && memcmp(p2, "d-data", 6) == 0, "process_vm_readv scatter");
    const char *msg = "written-by-parent";
    struct iovec wl = {(void *)msg, strlen(msg) + 1}, wr = {shared, strlen(msg) + 1};
    n = syscall(SYS_process_vm_writev, c, &wl, 1, &wr, 1, 0);
    check(n == (long)strlen(msg) + 1, "process_vm_writev");
    struct iovec badr = {(void *)8, 10};
    check(syscall(SYS_process_vm_readv, c, &l, 1, &badr, 1, 0) == -1 && errno == EFAULT, "remote fault: EFAULT");
    check(syscall(SYS_process_vm_readv, c, &l, 1, &r, 1, 1) == -1 && errno == EINVAL, "flags: EINVAL");
    write(go[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child saw the written data");
    check(syscall(SYS_process_vm_readv, c, &l, 1, &r, 1, 0) == -1 && errno == ESRCH, "reaped child: ESRCH");
}

int main(void) {
    test_setns();
    test_numa();
    test_files();
    test_mseal();
    test_kcmp();
    test_sched();
    test_process_vm();
    if (fails)
        printf("BATCH2 TEST FAILED (%d)\n", fails);
    else
        printf("BATCH2 TEST PASSED (%d skipped)\n", skips);
    return fails != 0;
}
