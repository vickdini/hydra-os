// Futex operations on two futexes and under concurrency: FUTEX_WAKE_OP, FUTEX_CMP_REQUEUE
// (and its EAGAIN), a requeued waiter timing out, and eight pairs of threads exchanging
// turns through their own futexes at once (no wake may be lost).
// Build: gcc -O1 -w -pthread -o futexops futexops_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long futex(int *uaddr, int op, int val, const struct timespec *t, int *uaddr2, int val3) {
    return syscall(SYS_futex, uaddr, op, val, t, uaddr2, val3);
}

static int f1, f2, arrived, woke_count;

// Waits on f1 while it is 0; counts its wakeup
static void *wait_f1(void *x) {
    __atomic_add_fetch(&arrived, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&f1, __ATOMIC_SEQ_CST) == 0) futex(&f1, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    __atomic_add_fetch(&woke_count, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

// Waits once on f1 (no loop): returns how the wait ended
static long once_result[8];
static void *wait_f1_once(void *x) {
    long i = (long)x;
    __atomic_add_fetch(&arrived, 1, __ATOMIC_SEQ_CST);
    once_result[i] = futex(&f1, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    __atomic_add_fetch(&woke_count, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void *wait_f2_once(void *x) {
    long i = (long)x;
    __atomic_add_fetch(&arrived, 1, __ATOMIC_SEQ_CST);
    once_result[i] = futex(&f2, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0);
    __atomic_add_fetch(&woke_count, 1, __ATOMIC_SEQ_CST);
    return NULL;
}

static void wait_arrivals(int n) {
    while (__atomic_load_n(&arrived, __ATOMIC_SEQ_CST) < n) usleep(1000);
    usleep(50000); // into the kernel's wait
}

// A requeued waiter with a timeout
static long timed_result;
static void *wait_f1_timed(void *x) {
    struct timespec t = {0, 300 * 1000 * 1000};
    __atomic_add_fetch(&arrived, 1, __ATOMIC_SEQ_CST);
    timed_result = futex(&f1, FUTEX_WAIT_PRIVATE, 0, &t, NULL, 0) == -1 ? -errno : 0;
    return NULL;
}

// Ping-pong pairs, each through its own futex word
#define PAIRS 8
#define ROUNDS 500
static int turns[PAIRS * 16]; // spaced out (different cache lines and keys)
static void pass(int *t, int mine, int theirs) {
    while (__atomic_load_n(t, __ATOMIC_ACQUIRE) != mine) futex(t, FUTEX_WAIT_PRIVATE, theirs, NULL, NULL, 0);
    __atomic_store_n(t, theirs, __ATOMIC_RELEASE);
    futex(t, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}
static void *ponger(void *x) {
    int *t = &turns[(long)x * 16];
    for (int i = 0; i < ROUNDS; i++) pass(t, 1, 0);
    return NULL;
}
static void *pinger(void *x) {
    int *t = &turns[(long)x * 16];
    for (int i = 0; i < ROUNDS; i++) pass(t, 0, 1);
    return NULL;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t t[8];

    // FUTEX_WAKE_OP: wake f1's waiter; set f2 = 1 and, as its old value was 0, wake f2's too
    f1 = f2 = 0;
    arrived = woke_count = 0;
    pthread_create(&t[0], NULL, wait_f1_once, (void *)0);
    pthread_create(&t[1], NULL, wait_f2_once, (void *)1);
    wait_arrivals(2);
    int op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0);
    long r = futex(&f1, FUTEX_WAKE_OP_PRIVATE, 1, (const struct timespec *)1, &f2, op);
    pthread_join(t[0], NULL);
    pthread_join(t[1], NULL);
    check(r == 2 && f2 == 1 && once_result[0] == 0 && once_result[1] == 0, "FUTEX_WAKE_OP wakes on both futexes and applies the operation");

    // FUTEX_CMP_REQUEUE: a wrong expected value fails; then 1 woken, 3 moved to f2
    f1 = 0, f2 = 0;
    arrived = woke_count = 0;
    for (long i = 0; i < 4; i++) pthread_create(&t[i], NULL, wait_f1_once, (void *)i);
    wait_arrivals(4);
    r = futex(&f1, FUTEX_CMP_REQUEUE_PRIVATE, 1, (const struct timespec *)8, &f2, 5);
    check(r == -1 && errno == EAGAIN, "FUTEX_CMP_REQUEUE with a changed value -> EAGAIN");
    r = futex(&f1, FUTEX_CMP_REQUEUE_PRIVATE, 1, (const struct timespec *)8, &f2, 0);
    usleep(50000);
    int after_requeue = __atomic_load_n(&woke_count, __ATOMIC_SEQ_CST);
    long w1 = futex(&f1, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0); // nobody left on f1
    long w2 = futex(&f2, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0); // the 3 moved there
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    printf("     requeue: %ld (1 woken + 3 moved), then %d awake, %ld more on f1, %ld on f2\n", r, after_requeue, w1, w2);
    check(r == 4 && after_requeue == 1 && w1 == 0 && w2 == 3 && woke_count == 4, "FUTEX_CMP_REQUEUE wakes one and moves the rest");

    // A requeued waiter whose timeout expires leaves the queue
    f1 = 0, f2 = 0;
    arrived = 0;
    pthread_create(&t[0], NULL, wait_f1_timed, NULL);
    wait_arrivals(1);
    r = futex(&f1, FUTEX_CMP_REQUEUE_PRIVATE, 0, (const struct timespec *)8, &f2, 0);
    pthread_join(t[0], NULL);
    long left = futex(&f2, FUTEX_WAKE_PRIVATE, 10, NULL, NULL, 0);
    check(r == 1 && timed_result == -ETIMEDOUT && left == 0, "a requeued waiter times out and leaves the queue");

    // Eight ping-pong pairs at once
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    pthread_t p[PAIRS * 2];
    for (long i = 0; i < PAIRS; i++) {
        pthread_create(&p[2 * i], NULL, ponger, (void *)i);
        pthread_create(&p[2 * i + 1], NULL, pinger, (void *)i);
    }
    for (int i = 0; i < PAIRS * 2; i++) pthread_join(p[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double s = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    printf("     %d pairs x %d exchanges in %.2f s\n", PAIRS, ROUNDS, s);
    check(1, "eight futex ping-pong pairs at once (no lost wake)");
    printf(fails ? "FUTEXOPS TEST FAILED (%d)\n" : "FUTEXOPS TEST PASSED\n", fails);
    return fails != 0;
}
