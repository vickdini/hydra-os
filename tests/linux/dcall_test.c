/* dcall_test: calls between services (wave 6, group 20). Run as root inside the chroot.
 *
 * linux-server makes the calls for us (Hydra's test call 0x6710, ops 5-7), so this checks
 * the kernel's SYS_SVC_DCALL / SYS_SVC_CALL direct paths end to end:
 *   - a null direct call to linux-server itself (another worker) and, if it runs, to the
 *     test service (id 11);
 *   - an echo through the test service (input in, output back);
 *   - delegation: the callee sees this process's id;
 *   - an edge that is not allowed fails with EPERM (echo from linux-server to itself);
 *   - linux-server -> net-server null calls (the classic direct path) work;
 *   - a loop of calls from two threads at once (no lost wake-ups).
 * Prints "DCALL-OK" at the end, or "FAIL ..." lines. Build: gcc -O1 -w -pthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define LX_NULL_NR 0x6710
#define OP_SVC_RTT 5
#define OP_DCALL_RTT 6
#define OP_DCALL 7
#define DOP_NULL 0
#define DOP_ECHO 1
#define DOP_WHO 2
#define LXS_LINUX 1
#define LXS_TEST 11

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static long dc(long svc, long op, long arg) {
    long r = syscall(LX_NULL_NR, OP_DCALL, svc, op, arg);
    return r < 0 ? -errno : r;
}

static void *loop_thread(void *x) {
    long svc = (long)x;
    for (int i = 0; i < 20000; i++) {
        long r = syscall(LX_NULL_NR, OP_DCALL_RTT, 1, svc);
        if (r < 0 && errno == EAGAIN) { i--; continue; } /* no idle worker of its own pool */
        if (r < 0) { printf("FAIL thread dcall %d: errno %d\n", i, errno); fails++; return 0; }
        r = syscall(LX_NULL_NR, OP_SVC_RTT, 1, 0);
        if (r < 0) { printf("FAIL thread svc call %d: errno %d\n", i, errno); fails++; return 0; }
    }
    return 0;
}

int main(int argc, char **argv) {
    long r = dc(LXS_LINUX, DOP_NULL, 0);
    CHECK(r == 0, "null dcall to linux-server: %ld", r);
    r = dc(LXS_LINUX, DOP_ECHO, 0x1234);
    CHECK(r == -EPERM, "echo linux-server -> itself should be EPERM: %ld", r);
    r = dc(0, DOP_NULL, 0);
    CHECK(r == -EINVAL, "dcall to service 0 should be EINVAL: %ld", r);
    r = dc(99, DOP_NULL, 0);
    CHECK(r == -EINVAL, "dcall to service 99 should be EINVAL: %ld", r);
    long t = dc(LXS_TEST, DOP_NULL, 0);
    int test_svc = t == 0;
    printf("test service: %s (%ld)\n", test_svc ? "running" : "absent", t);
    if (test_svc) {
        r = dc(LXS_TEST, DOP_ECHO, 0x1122334455667788L);
        CHECK(r == 0x1122334455667788L, "echo through the test service: %#lx", r);
        r = dc(LXS_TEST, DOP_WHO, 0);
        CHECK(r == getpid(), "delegation: callee saw process %ld, we are %d", r, getpid());
    } else {
        r = dc(LXS_LINUX, DOP_WHO, 0);
        /* the null op is the only one allowed to itself */
        CHECK(r == -EPERM, "who linux-server -> itself should be EPERM: %ld", r);
    }
    long ns = syscall(LX_NULL_NR, OP_SVC_RTT, 2000, 0);
    CHECK(ns > 0, "linux-server -> net-server calls: errno %d", errno);
    if (ns > 0) printf("svc call round trip %.0f ns\n", (double)ns / 2000);
    ns = syscall(LX_NULL_NR, OP_DCALL_RTT, 2000, test_svc ? LXS_TEST : LXS_LINUX);
    CHECK(ns > 0, "dcall loop: errno %d", errno);
    if (ns > 0) printf("dcall round trip %.0f ns\n", (double)ns / 2000);
    pthread_t a, b;
    long svc = test_svc ? LXS_TEST : LXS_LINUX;
    pthread_create(&a, 0, loop_thread, (void *)svc);
    pthread_create(&b, 0, loop_thread, (void *)svc);
    pthread_join(a, 0);
    pthread_join(b, 0);
    printf(fails ? "DCALL-FAILED %d\n" : "DCALL-OK\n", fails);
    return fails != 0;
}
