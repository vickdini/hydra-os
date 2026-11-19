/* srvmap_test: mmap of a service's object (wave 6, Group 23: memory objects).
 *
 * linux-server's test object (LX_NULL_OBJ) has 64 KiB of memory, a memory object the
 * server makes on first use. The program maps it; the server reads and writes the same
 * memory through ioctls on the object (0x4D50 peek, 0x4D51 poke, 0x4D52 drop its handle,
 * 0x4D53 share it with a second handle and write through that, 0x4D54 info).
 *
 *   srvmap               the checks; prints "SRVMAP TEST PASSED" or "SRVMAP TEST FAILED (n)"
 *   srvmap keep-write    a kept object (survives a restart of linux-server): writes a stamp
 *   srvmap keep-check    after the restart: the stamp must still be there
 *   srvmap hold N        maps the object and keeps using it for N seconds (kill-test load)
 *
 * With the forwarding switched back to the kernel (lx=kernel) there is no server: the test
 * says so and passes.
 * Build: gcc -O1 -w -pthread srvmap_test.c -o srvmap
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL 0x6710
#define LX_NULL_OBJ 3
#define LX_NULL_OBJ_CLOSES 4
#define KEPT_FLAG (1ULL << 32)
#define MEM (64 * 1024)
#define PEEK 0x4D50
#define POKE 0x4D51
#define DROP 0x4D52
#define SHARE 0x4D53
#define INFO 0x4D54
#define STAMP 0x5354414D50ULL

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static long closes(void) { return syscall(LX_NULL, LX_NULL_OBJ_CLOSES, 0, 0); }
static int newobj(unsigned long long flags) { return syscall(LX_NULL, LX_NULL_OBJ, flags, 0); }
static long peek(int fd, unsigned off) { return syscall(SYS_ioctl, fd, PEEK, (unsigned long)off); }
static long poke(int fd, unsigned off, uint32_t v) { return syscall(SYS_ioctl, fd, POKE, (unsigned long)off | (unsigned long)v << 32); }

static int keep(int write) {
    int fd = newobj(KEPT_FLAG);
    if (fd <= 2) {
        printf("no server object (%d): SRVMAP KEEP SKIPPED\n", fd);
        return 0;
    }
    long info = syscall(SYS_ioctl, fd, INFO, 0UL);
    check(info >= 0 && (info >> 48 & 1), "the kept object says it is kept");
    volatile uint64_t *p = mmap(0, MEM, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        check(0, "mmap of the kept object");
        return 1;
    }
    if (write) {
        uint64_t gen = p[0] == STAMP ? p[1] + 1 : 1;
        p[0] = STAMP;
        p[1] = gen;
        for (int i = 0; i < MEM / 8; i += 512) p[i + 2] = gen * 1000 + i;
        printf("kept stamp written, generation %llu\n", (unsigned long long)gen);
        check(peek(fd, 8) == (long)(uint32_t)gen, "the server sees the stamp");
    } else {
        int good = p[0] == STAMP;
        for (int i = 0; good && i < MEM / 8; i += 512) good = p[i + 2] == p[1] * 1000 + i;
        printf("kept memory: stamp %s, generation %llu\n", p[0] == STAMP ? "present" : "MISSING", (unsigned long long)p[1]);
        check(good, "the kept memory still holds the stamp after the restart");
    }
    munmap((void *)p, MEM);
    close(fd);
    printf(fails ? "SRVMAP KEEP FAILED (%d)\n" : "SRVMAP KEEP PASSED\n", fails);
    return fails != 0;
}

static int hold(int secs) {
    int fd = newobj(0);
    if (fd <= 2) return 1;
    volatile uint32_t *p = mmap(0, MEM, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return 1;
    printf("HOLDING\n");
    fflush(stdout);
    time_t end = time(0) + secs;
    unsigned long n = 0;
    while (time(0) < end) {
        for (int i = 0; i < MEM / 4; i += 1024) p[i] = n;
        for (int i = 0; i < MEM / 4; i += 1024)
            if (p[i] != n) {
                printf("FAIL memory changed under us\n");
                return 1;
            }
        n++;
        if (n % 1000 == 0) peek(fd, 0);
    }
    printf("held %lu rounds\n", n);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "keep-write")) return keep(1);
    if (argc > 1 && !strcmp(argv[1], "keep-check")) return keep(0);
    if (argc > 1 && !strcmp(argv[1], "hold")) return hold(argc > 2 ? atoi(argv[2]) : 30);

    int fd = newobj(0);
    if (fd <= 2) { /* lx=kernel: the kernel answers the test call with 0 */
        printf("no server test object (%d; lx=kernel?): SRVMAP TEST PASSED (skipped)\n", fd);
        return 0;
    }
    long closes0 = closes();

    /* 1. map it, write from both sides */
    volatile uint32_t *p = mmap(0, MEM, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(p != MAP_FAILED, "mmap of a server object (MAP_SHARED, 64 KiB)");
    if (p == MAP_FAILED) {
        printf("errno %d\nSRVMAP TEST FAILED (%d)\n", errno, fails);
        return 1;
    }
    check(p[0] == 0 && p[MEM / 4 - 1] == 0, "the new memory reads as zeros");
    p[0] = 0x11111111;
    check(peek(fd, 0) == 0x11111111, "the server sees the program's write");
    check(poke(fd, 4, 0x22222222) == 0, "the server writes (poke)");
    check(p[1] == 0x22222222, "the program sees the server's write");
    p[MEM / 4 - 1] = 0x5a5a5a5a;
    check(peek(fd, MEM - 4) == 0x5a5a5a5a, "the last word is shared too");

    /* 2. a second mapping at an offset: the same pages */
    volatile uint32_t *q = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
    check(q != MAP_FAILED, "a second mapping at offset 4096");
    if (q != MAP_FAILED) {
        q[0] = 0x33333333;
        check(p[1024] == 0x33333333 && peek(fd, 4096) == 0x33333333, "both mappings and the server see one page");
    }

    /* 3. a private mapping: copy-on-write of the object */
    volatile uint32_t *r = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    check(r != MAP_FAILED, "a private mapping");
    if (r != MAP_FAILED) {
        check(r[0] == 0x11111111, "the private mapping starts with the object's contents");
        r[0] = 0x44444444;
        check(p[0] == 0x11111111 && peek(fd, 0) == 0x11111111, "a private write stays private");
        munmap((void *)r, 4096);
    }

    /* 4. bad ranges, a read-only mapping */
    void *bad = mmap(0, 8192, PROT_READ, MAP_SHARED, fd, MEM - 4096);
    check(bad == MAP_FAILED && errno == EINVAL, "a range past the end fails with EINVAL");
    volatile uint32_t *ro = mmap(0, 4096, PROT_READ, MAP_SHARED, fd, 0);
    check(ro != MAP_FAILED && ro[0] == 0x11111111, "a read-only mapping reads the object");
    if (ro != MAP_FAILED) munmap((void *)ro, 4096);

    /* 5. fork: the child shares the mapping */
    pid_t pid = fork();
    if (pid == 0) {
        int ok = p[0] == 0x11111111;
        p[2] = 0x55555555;
        _exit(ok ? 0 : 3);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child sees the parent's data");
    check(p[2] == 0x55555555 && peek(fd, 8) == 0x55555555, "the parent and the server see the child's write");

    /* 6. LX_MEM_SHARE: the server writes through a second handle of the same object */
    long h = syscall(SYS_ioctl, fd, SHARE, 12UL | 0x66666666UL << 32);
    check(h > 0, "the server shares the object to a second handle");
    check(p[3] == 0x66666666, "a write through the shared handle reaches the program");
    long info = syscall(SYS_ioctl, fd, INFO, 0UL);
    check(info >= 0 && (info & 0xFFFFFFFFFFFFL) == MEM / 4096 && !(info >> 48 & 1), "info: 16 pages, not kept");

    /* 7. an object without memory */
    int efd = eventfd(0, 0);
    if (efd >= 0) {
        void *e = mmap(0, 4096, PROT_READ, MAP_SHARED, efd, 0);
        check(e == MAP_FAILED && errno == ENODEV, "mmap of an eventfd fails with ENODEV");
        close(efd);
    }

    /* 8. unmap one, close the descriptor: the other mapping keeps the memory */
    if (q != MAP_FAILED) check(munmap((void *)q, 8192) == 0, "munmap of the second mapping");
    check(close(fd) == 0, "close of the descriptor");
    usleep(100000);
    check(closes() == closes0 + 1, "the server saw the close");
    check(p[0] == 0x11111111 && p[1] == 0x22222222 && p[3] == 0x66666666, "the mapping still holds the memory after the close");
    p[4] = 0x77777777;
    check(p[4] == 0x77777777, "and can still be written");
    check(munmap((void *)p, MEM) == 0, "munmap of the last mapping");

    /* 9. the server lets go first: the program's mapping alone keeps the object */
    int fd2 = newobj(0);
    volatile uint32_t *p2 = mmap(0, MEM, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    check(p2 != MAP_FAILED, "map a second object");
    if (p2 != MAP_FAILED) {
        p2[0] = 0x88888888;
        check(syscall(SYS_ioctl, fd2, DROP, 0UL) == 0, "the server drops its handle and its view");
        close(fd2);
        check(p2[0] == 0x88888888, "the mapping outlives the server's handle");
        p2[100] = 0x99999999;
        check(p2[100] == 0x99999999, "and stays writable");
        munmap((void *)p2, MEM);
    }

    /* 10. DMA memory (obj_dma): contiguous, pinned; mapped like any other */
    int fd3 = newobj(1ULL << 33);
    volatile uint32_t *p3 = mmap(0, MEM, PROT_READ | PROT_WRITE, MAP_SHARED, fd3, 0);
    check(p3 != MAP_FAILED, "map a DMA object");
    if (p3 != MAP_FAILED) {
        long di = syscall(SYS_ioctl, fd3, INFO, 0UL);
        check(di >= 0 && (di >> 49 & 1) && (di & 0xFFFFFFFFFFFFL) == MEM / 4096, "info: DMA memory, 16 pages");
        check(p3[0] == 0 && p3[MEM / 4 - 1] == 0, "DMA memory starts zeroed");
        p3[MEM / 4 - 1] = 0xabcdef01;
        check(peek(fd3, MEM - 4) == (long)0xabcdef01, "the server sees a write to DMA memory");
        munmap((void *)p3, MEM);
    }
    close(fd3);

    /* 11. many objects, mapped and dropped (no leak of handles) */
    int ok = 1;
    for (int i = 0; i < 300 && ok; i++) {
        int f = newobj(0);
        volatile uint32_t *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, f, 0);
        if (f < 0 || m == MAP_FAILED) {
            ok = 0;
            printf("round %d: fd %d errno %d\n", i, f, errno);
            break;
        }
        m[0] = i;
        ok = peek(f, 0) == i;
        munmap((void *)m, 4096);
        close(f);
    }
    check(ok, "300 objects mapped, written and closed");

    printf(fails ? "SRVMAP TEST FAILED (%d)\n" : "SRVMAP TEST PASSED\n", fails);
    return fails != 0;
}
