// userfaultfd: API handshake, MISSING registration, faults handled by a thread with
// UFFDIO_COPY (the message names the faulting thread), UFFDIO_ZEROPAGE, EEXIST, kernel
// accesses (EFAULT with UFFD_USER_MODE_ONLY; waited for otherwise, as root), unregister by
// close. Build: gcc -O1 -w -pthread -o uffd userfaultfd_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif
#define PG 4096

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int uffd;
static char *area;
static volatile int handled, fault_tid_ok, handler_stop;
static pid_t main_tid;

// Answers faults: page i gets bytes i + 1 (page 3 is left alone: the main thread zeroes it)
static void *handler(void *arg) {
    (void)arg;
    while (!handler_stop) {
        struct pollfd p = {uffd, POLLIN, 0};
        if (poll(&p, 1, 100) <= 0) continue;
        struct uffd_msg m;
        if (read(uffd, &m, sizeof m) != sizeof m) continue;
        if (m.event != UFFD_EVENT_PAGEFAULT) continue;
        unsigned long page = m.arg.pagefault.address & ~(unsigned long)(PG - 1);
        int idx = (page - (unsigned long)area) / PG;
        if (m.arg.pagefault.feat.ptid == main_tid) fault_tid_ok = 1;
        static char src[PG];
        if (idx == 5) {
            struct uffdio_zeropage z = {{page, PG}, 0, 0};
            ioctl(uffd, UFFDIO_ZEROPAGE, &z);
        } else {
            memset(src, idx + 1, PG);
            struct uffdio_copy c = {page, (unsigned long)src, PG, 0, 0};
            ioctl(uffd, UFFDIO_COPY, &c);
        }
        handled++;
    }
    return NULL;
}

static int make(int flags) {
    int fd = syscall(SYS_userfaultfd, flags);
    if (fd < 0) return -1;
    struct uffdio_api api = {UFFD_API, UFFD_FEATURE_THREAD_ID, 0};
    if (ioctl(fd, UFFDIO_API, &api) != 0) return -2;
    return fd;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    main_tid = syscall(SYS_gettid);
    int priv = syscall(SYS_userfaultfd, O_CLOEXEC);
    int priv_errno = errno;
    if (priv < 0 && priv_errno == ENOSYS) {
        printf("skip: no userfaultfd\nUFFD TEST PASSED\n");
        return 0;
    }
    if (getuid() != 0) check(priv >= 0 || priv_errno == EPERM, "full userfaultfd unprivileged: EPERM (unless allowed)");
    if (priv >= 0) close(priv);

    int raw = syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
    struct uffdio_register early = {{0x10000, PG}, UFFDIO_REGISTER_MODE_MISSING, 0};
    errno = 0;
    check(raw >= 0 && ioctl(raw, UFFDIO_REGISTER, &early) == -1 && errno == EINVAL, "ioctl before UFFDIO_API: EINVAL");
    close(raw);

    uffd = make(O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
    check(uffd >= 0, "UFFD_USER_MODE_ONLY descriptor with UFFDIO_API (THREAD_ID)");
    area = mmap(0, 8 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct uffdio_register reg = {{(unsigned long)area, 8 * PG}, UFFDIO_REGISTER_MODE_MISSING, 0};
    check(ioctl(uffd, UFFDIO_REGISTER, &reg) == 0 && (reg.ioctls & (1ull << _UFFDIO_COPY)), "register 8 pages (COPY offered)");
    struct uffdio_register wp = {{(unsigned long)area, PG}, 4, 0};   // MINOR: not offered
    errno = 0;
    ioctl(uffd, UFFDIO_REGISTER, &wp);

    pthread_t t;
    pthread_create(&t, NULL, handler, NULL);
    int good = area[0] == 1 && area[PG] == 2 && area[2 * PG + 100] == 3;
    check(good && handled == 3, "three faults handled by the thread with UFFDIO_COPY");
    check(fault_tid_ok, "the fault message names the faulting thread");
    // Writing faults too
    area[4 * PG] = 9;
    check(area[4 * PG] == 9 && handled == 4, "a write fault is handled, then the write lands");
    check(area[5 * PG + 7] == 0 && handled == 5, "UFFDIO_ZEROPAGE gives a zeroed page");
    // A system call touching an unfilled page: refused for a user-mode-only descriptor
    int pp[2];
    pipe(pp);
    errno = 0;
    check(write(pp[1], area + 6 * PG, 16) == -1 && errno == EFAULT, "kernel access with UFFD_USER_MODE_ONLY: EFAULT");
    static char src[PG];
    struct uffdio_copy again = {(unsigned long)area, (unsigned long)src, PG, 0, 0};
    errno = 0;
    check(ioctl(uffd, UFFDIO_COPY, &again) == -1 && errno == EEXIST, "UFFDIO_COPY over a present page: EEXIST");
    handler_stop = 1;
    pthread_join(t, NULL);
    close(uffd);
    check(area[7 * PG] == 0, "after close the range faults normally (zeroed page)");

    // As root: a full descriptor; a system call's access waits for the handler
    if (getuid() == 0) {
        handler_stop = 0;
        handled = 0;
        uffd = make(O_CLOEXEC | O_NONBLOCK);
        area = mmap(0, 8 * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        struct uffdio_register r2 = {{(unsigned long)area, 8 * PG}, UFFDIO_REGISTER_MODE_MISSING, 0};
        ioctl(uffd, UFFDIO_REGISTER, &r2);
        pthread_create(&t, NULL, handler, NULL);
        write(pp[1], "kernel!", 7);
        ssize_t n = read(pp[0], area + 2 * PG, 7);   // the kernel writes into a missing page
        check(n == 7 && !memcmp(area + 2 * PG, "kernel!", 7) && handled >= 1, "kernel access waits for the handler, then completes");
        handler_stop = 1;
        pthread_join(t, NULL);
    }
    printf(fails ? "UFFD TEST FAILED (%d)\n" : "UFFD TEST PASSED\n", fails);
    return fails != 0;
}
