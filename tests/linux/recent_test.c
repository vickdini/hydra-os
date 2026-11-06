// Newer system calls: openat2 (RESOLVE_*), epoll_pwait2, pidfd_getfd, process_madvise,
// process_mrelease, futex_waitv, futex_wake/futex_wait (futex2). Calls the running kernel
// lacks (ENOSYS) are reported as skipped.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)
#define SKIP(...) do { printf("skip " __VA_ARGS__); printf(" (not in this kernel)\n"); } while (0)

struct open_how { unsigned long long flags, mode, resolve; };
#define RESOLVE_NO_XDEV 0x01
#define RESOLVE_NO_MAGICLINKS 0x02
#define RESOLVE_NO_SYMLINKS 0x04
#define RESOLVE_BENEATH 0x08
#define RESOLVE_IN_ROOT 0x10
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif
#ifndef SYS_process_madvise
#define SYS_process_madvise 440
#endif
#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif
#ifndef SYS_process_mrelease
#define SYS_process_mrelease 448
#endif
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif
#define SYS_futex_wake_ 454
#define SYS_futex_wait_ 455
struct waitv { uint64_t val, uaddr; uint32_t flags, reserved; };

static long o2(int dirfd, const char *path, int flags, unsigned long long resolve) {
    struct open_how how = {.flags = flags, .resolve = resolve};
    return syscall(SYS_openat2, dirfd, path, &how, sizeof how);
}

static void msleep(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, 0);
}

static uint32_t fw[3];
static void *waker(void *a) {
    (void)a;
    msleep(100);
    fw[1] = 1;
    syscall(SYS_futex, &fw[1], FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    return 0;
}

int main(void) {
    // ---- openat2
    mkdir("/tmp/o2", 0755);
    mkdir("/tmp/o2/d", 0755);
    close(open("/tmp/o2/d/f", O_CREAT | O_WRONLY, 0644));
    unlink("/tmp/o2/d/up");
    symlink("../d/f", "/tmp/o2/d/up");
    unlink("/tmp/o2/d/abs");
    symlink("/tmp/o2/d/f", "/tmp/o2/d/abs");
    int root = open("/tmp/o2", O_RDONLY | O_DIRECTORY);
    long fd = o2(root, "d/f", O_RDONLY, 0);
    CHECK(fd >= 0, "openat2 without restrictions");
    close(fd);
    fd = o2(root, "d/up", O_RDONLY, RESOLVE_BENEATH);
    CHECK(fd >= 0, "BENEATH: a relative link that stays inside");
    close(fd);
    errno = 0;
    CHECK(o2(root, "../o2/d/f", O_RDONLY, RESOLVE_BENEATH) == -1 && errno == EXDEV, "BENEATH: .. out of the directory -> EXDEV");
    errno = 0;
    CHECK(o2(root, "/tmp/o2/d/f", O_RDONLY, RESOLVE_BENEATH) == -1 && errno == EXDEV, "BENEATH: absolute path -> EXDEV");
    errno = 0;
    CHECK(o2(root, "d/abs", O_RDONLY, RESOLVE_BENEATH) == -1 && errno == EXDEV, "BENEATH: absolute link -> EXDEV");
    fd = o2(root, "/d/f", O_RDONLY, RESOLVE_IN_ROOT);
    CHECK(fd >= 0, "IN_ROOT: / is the directory");
    close(fd);
    fd = o2(root, "../../d/f", O_RDONLY, RESOLVE_IN_ROOT);
    CHECK(fd >= 0, "IN_ROOT: .. stops at the directory");
    close(fd);
    errno = 0;
    CHECK(o2(root, "d/up", O_RDONLY, RESOLVE_NO_SYMLINKS) == -1 && errno == ELOOP, "NO_SYMLINKS -> ELOOP");
    int self = open("/tmp/o2/d/f", O_RDONLY);
    char magic[64];
    snprintf(magic, sizeof magic, "/proc/self/fd/%d", self);
    fd = o2(AT_FDCWD, magic, O_RDONLY, 0);
    CHECK(fd >= 0, "magic link without restrictions");
    close(fd);
    struct stat lst, fst;
    char self_link[32] = {0};
    CHECK(lstat("/proc/self", &lst) == 0 && S_ISLNK(lst.st_mode) && stat("/proc/self", &fst) == 0 && S_ISDIR(fst.st_mode) && readlink("/proc/self", self_link, 31) > 0 && atoi(self_link) == getpid(), "/proc/self links to /proc/%s", self_link);
    errno = 0;
    CHECK(o2(AT_FDCWD, magic, O_RDONLY, RESOLVE_NO_MAGICLINKS) == -1 && errno == ELOOP, "NO_MAGICLINKS -> ELOOP (errno %d)", errno);
    struct open_how cr = {.flags = O_CREAT | O_WRONLY, .mode = 0644, .resolve = RESOLVE_BENEATH};
    unlink("/tmp/o2/d/new");
    fd = syscall(SYS_openat2, root, "d/new", &cr, sizeof cr);
    CHECK(fd >= 0, "O_CREAT under BENEATH");
    close(fd);
    struct open_how bad = {.flags = O_RDONLY, .mode = 0644};
    errno = 0;
    CHECK(syscall(SYS_openat2, root, "d/f", &bad, sizeof bad) == -1 && errno == EINVAL, "mode without O_CREAT -> EINVAL");
    errno = 0;
    CHECK(o2(root, "d/f", O_RDONLY, RESOLVE_BENEATH | RESOLVE_IN_ROOT) == -1 && errno == EINVAL, "BENEATH with IN_ROOT -> EINVAL");

    // ---- epoll_pwait2
    int ep = epoll_create1(0);
    int p[2];
    pipe(p);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = p[0]};
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
    struct timespec t50 = {0, 50000000};
    struct epoll_event out;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    long n = syscall(SYS_epoll_pwait2, ep, &out, 1, &t50, 0, 8);
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    CHECK(n == 0 && ms >= 40 && ms < 500, "epoll_pwait2 times out after %ld ms", ms);
    write(p[1], "x", 1);
    CHECK(syscall(SYS_epoll_pwait2, ep, &out, 1, &t50, 0, 8) == 1 && out.data.fd == p[0], "epoll_pwait2 reports a ready pipe");
    char drain;
    read(p[0], &drain, 1); // the child below waits on this pipe

    // ---- pidfd_getfd, process_madvise, process_mrelease
    int pp[2];
    pipe(pp);
    pid_t c = fork();
    if (c == 0) {
        close(pp[0]);
        char go;
        read(p[0], &go, 1); // wait to be told to exit
        _exit(0);
    }
    int pidfd = syscall(SYS_pidfd_open, c, 0);
    long got = syscall(SYS_pidfd_getfd, pidfd, pp[1], 0);
    CHECK(got >= 0 && (fcntl(got, F_GETFD) & FD_CLOEXEC), "pidfd_getfd: a close-on-exec copy");
    close(pp[1]);
    CHECK(write(got, "hi", 2) == 2, "the copy writes into the child's pipe");
    char hb[3] = {0};
    CHECK(read(pp[0], hb, 2) == 2 && !strcmp(hb, "hi"), "data arrives");
    errno = 0;
    CHECK(syscall(SYS_pidfd_getfd, pidfd, 999, 0) == -1 && errno == EBADF, "pidfd_getfd of a closed descriptor -> EBADF");
    char *mem = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec iv = {mem, 8192};
    long adv = syscall(SYS_process_madvise, pidfd, &iv, 1, MADV_COLD, 0);
    if (getuid() != 0) CHECK(adv == -1 && errno == EPERM, "process_madvise needs CAP_SYS_NICE (%ld errno %d)", adv, errno);
    errno = 0;
    long mr = syscall(SYS_process_mrelease, pidfd, 0);
    CHECK((mr == -1 && errno == EINVAL) || errno == ENOSYS, "process_mrelease on a live process -> EINVAL (%ld errno %d)", mr, errno);
    write(p[1], "q", 1);
    write(p[1], "q", 1);
    waitpid(c, 0, 0);
    close(got);

    // ---- futex_waitv
    struct waitv wv[3];
    for (int i = 0; i < 3; i++) wv[i] = (struct waitv){0, (uintptr_t)&fw[i], 2 | 128, 0};
    errno = 0;
    wv[0].val = 5; // a value that differs: returns at once where the call exists
    long r = syscall(SYS_futex_waitv, wv, 3, 0, 0, CLOCK_MONOTONIC);
    wv[0].val = 0;
    if (r == -1 && errno == ENOSYS) {
        SKIP("futex_waitv");
    } else {
        pthread_t th;
        pthread_create(&th, 0, waker, 0);
        fw[0] = fw[1] = fw[2] = 0;
        r = syscall(SYS_futex_waitv, wv, 3, 0, 0, CLOCK_MONOTONIC);
        pthread_join(th, 0);
        CHECK(r == 1, "futex_waitv returns the woken futex (%ld)", r);
        wv[0].val = 5;
        errno = 0;
        CHECK(syscall(SYS_futex_waitv, wv, 3, 0, 0, CLOCK_MONOTONIC) == -1 && errno == EAGAIN, "futex_waitv: a value differs -> EAGAIN");
        wv[0].val = 0;
        wv[1].val = 1;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        now.tv_nsec += 50000000;
        if (now.tv_nsec >= 1000000000) {
            now.tv_sec++;
            now.tv_nsec -= 1000000000;
        }
        errno = 0;
        CHECK(syscall(SYS_futex_waitv, wv, 3, 0, &now, CLOCK_MONOTONIC) == -1 && errno == ETIMEDOUT, "futex_waitv times out");
    }
    errno = 0;
    r = syscall(SYS_futex_wake_, &fw[0], ~0UL, 1, 2 | 128);
    if (r == -1 && errno == ENOSYS) {
        SKIP("futex_wake / futex_wait");
    } else {
        CHECK(r == 0, "futex_wake with no waiters");
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        now.tv_nsec += 50000000;
        if (now.tv_nsec >= 1000000000) {
            now.tv_sec++;
            now.tv_nsec -= 1000000000;
        }
        errno = 0;
        CHECK(syscall(SYS_futex_wait_, &fw[0], 0, ~0UL, 2 | 128, &now, CLOCK_MONOTONIC) == -1 && errno == ETIMEDOUT, "futex_wait times out");
    }

    printf(fails ? "RECENT TEST FAILED (%d)\n" : "RECENT TEST PASSED\n", fails);
    return fails != 0;
}
