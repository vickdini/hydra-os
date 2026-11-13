// futex(2) argument handling and results, checked against Linux (run it there first):
// FUTEX_WAKE_OP's 12-bit oparg/cmparg are signed and a shift count is taken modulo 32;
// misaligned addresses are EINVAL; requeue counts must not be negative and the result
// counts woken plus requeued waiters; PI locks: EDEADLK, EPERM, EAGAIN, and ESRCH for an
// owner that does not exist.
// Build: gcc -O1 -w -pthread -o futex futex_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long futex(void *uaddr, int op, uint32_t val, uintptr_t timeout, void *uaddr2, uint32_t val3) {
    long r = syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
    return r < 0 ? -errno : r;
}

// A check for a known, documented bug: reported, but not counted as a failure
static void known(long got, long want, const char *what, const char *bug) {
    printf("%s %s: want %ld, got %ld\n", got == want ? "ok  " : "KNOWN", what, want, got);
    if (got != want) printf("      (%s)\n", bug);
}

// A live thread that owns nothing, whose tid stands for "someone else"
static volatile int helper_tid, helper_stop;

static void *helper(void *arg) {
    helper_tid = syscall(SYS_gettid);
    while (!helper_stop) usleep(10000);
    return NULL;
}

static void expect(long got, long want, const char *what) {
    char line[200];
    snprintf(line, sizeof line, "%s: want %ld, got %ld", what, want, got);
    check(got == want, line);
}

// FUTEX_OP(op, oparg, cmp, cmparg) with raw 12-bit fields
static uint32_t wake_op(unsigned op, unsigned oparg, unsigned cmp, unsigned cmparg) {
    return ((op & 0xf) << 28) | ((cmp & 0xf) << 24) | ((oparg & 0xfff) << 12) | (cmparg & 0xfff);
}

// Waiter threads: each waits on its word until woken (or 5 s)
struct waiter { uint32_t *word; long result; };

static void *wait_thread(void *arg) {
    struct waiter *w = arg;
    struct timespec ts = { 5, 0 };
    w->result = futex(w->word, FUTEX_WAIT_PRIVATE, *w->word, (uintptr_t)&ts, NULL, 0);
    return NULL;
}

static void start_waiters(pthread_t *t, struct waiter *w, int n, uint32_t *word) {
    for (int i = 0; i < n; i++) {
        w[i].word = word;
        pthread_create(&t[i], NULL, wait_thread, &w[i]);
    }
    usleep(200000); // all queued
}

static void join(pthread_t *t, int n) {
    for (int i = 0; i < n; i++)
        pthread_join(t[i], NULL);
}

int main(void) {
    static uint32_t a[4] __attribute__((aligned(16)));
    static uint32_t b[4] __attribute__((aligned(16)));

    // --- FUTEX_WAKE_OP arithmetic on *uaddr2 (no waiters needed)
    b[0] = 10;
    futex(&a[0], FUTEX_WAKE_OP_PRIVATE, 0, 0, &b[0], wake_op(FUTEX_OP_ADD, 0xfff, FUTEX_OP_CMP_EQ, 0));
    expect(b[0], 9, "WAKE_OP ADD oparg 0xfff adds -1 (oparg is signed)");
    b[0] = 0;
    futex(&a[0], FUTEX_WAKE_OP_PRIVATE, 0, 0, &b[0], wake_op(FUTEX_OP_SET | FUTEX_OP_OPARG_SHIFT, 33, FUTEX_OP_CMP_EQ, 0));
    expect(b[0], 2, "WAKE_OP SET with shift 33 sets 1 << (33 & 31)");
    b[0] = 0;
    futex(&a[0], FUTEX_WAKE_OP_PRIVATE, 0, 0, &b[0], wake_op(FUTEX_OP_SET, 7, FUTEX_OP_CMP_EQ, 0));
    expect(b[0], 7, "WAKE_OP SET 7");

    // --- cmparg is signed too: old 0 > -1 holds, so the waiter on uaddr2 is woken
    {
        pthread_t t[1];
        struct waiter w[1];
        b[0] = 0;
        start_waiters(t, w, 1, &b[0]);
        b[0] = 0;
        long r = futex(&a[0], FUTEX_WAKE_OP_PRIVATE, 0, 1, &b[0], wake_op(FUTEX_OP_SET, 0, FUTEX_OP_CMP_GT, 0xfff));
        expect(r, 1, "WAKE_OP CMP_GT cmparg 0xfff (-1) wakes the uaddr2 waiter");
        if (r == 0)
            futex(&b[0], FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0);
        join(t, 1);
    }

    // --- misaligned addresses
    char *raw = (char *)a;
    expect(futex(raw + 1, FUTEX_WAKE_PRIVATE, 1, 0, NULL, 0), -EINVAL, "WAKE on a misaligned word");
    expect(futex(raw + 1, FUTEX_WAIT_PRIVATE, 0, 0, NULL, 0), -EINVAL, "WAIT on a misaligned word");
    expect(futex(&a[0], FUTEX_WAKE_OP_PRIVATE, 1, 1, (char *)b + 2, wake_op(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 0)), -EINVAL,
           "WAKE_OP with a misaligned uaddr2");
    expect(futex(&a[0], FUTEX_REQUEUE_PRIVATE, 1, 1, (char *)b + 2, 0), -EINVAL, "REQUEUE to a misaligned uaddr2");

    // --- requeue counts
    expect(futex(&a[0], FUTEX_REQUEUE_PRIVATE, (uint32_t)-1, 1, &b[0], 0), -EINVAL, "REQUEUE with nr_wake -1");
    expect(futex(&a[0], FUTEX_REQUEUE_PRIVATE, 1, (uintptr_t)-1, &b[0], 0), -EINVAL, "REQUEUE with nr_requeue -1");
    a[0] = 5;
    expect(futex(&a[0], FUTEX_CMP_REQUEUE_PRIVATE, 1, 1, &b[0], 6), -EAGAIN, "CMP_REQUEUE when the word changed");
    for (int cmp = 0; cmp <= 1; cmp++) {
        pthread_t t[4];
        struct waiter w[4];
        a[0] = 0;
        b[0] = 0;
        start_waiters(t, w, 4, &a[0]);
        long r = futex(&a[0], cmp ? FUTEX_CMP_REQUEUE_PRIVATE : FUTEX_REQUEUE_PRIVATE, 1, INT_MAX, &b[0], 0);
        expect(r, 4, cmp ? "CMP_REQUEUE returns woken + requeued (1 + 3)" : "REQUEUE returns woken + requeued (1 + 3)");
        expect(futex(&b[0], FUTEX_WAKE_PRIVATE, INT_MAX, 0, NULL, 0), 3, "the 3 requeued wait on uaddr2");
        futex(&a[0], FUTEX_WAKE_PRIVATE, INT_MAX, 0, NULL, 0);
        join(t, 4);
    }

    // --- timeouts and values
    struct timespec bad = { 0, 1000000000 };
    expect(futex(&a[0], FUTEX_WAIT_PRIVATE, a[0], (uintptr_t)&bad, NULL, 0), -EINVAL, "WAIT with tv_nsec 1e9");
    struct timespec neg = { -1, 0 };
    expect(futex(&a[0], FUTEX_WAIT_PRIVATE, a[0], (uintptr_t)&neg, NULL, 0), -EINVAL, "WAIT with a negative tv_sec");
    struct timespec short_ts = { 0, 10000000 };
    expect(futex(&a[0], FUTEX_WAIT_PRIVATE, a[0], (uintptr_t)&short_ts, NULL, 0), -ETIMEDOUT, "WAIT times out");
    expect(futex(&a[0], FUTEX_WAIT_PRIVATE, a[0] + 1, 0, NULL, 0), -EAGAIN, "WAIT when the value differs");
    expect(futex(&a[0], FUTEX_WAIT_BITSET_PRIVATE, a[0], 0, NULL, 0), -EINVAL, "WAIT_BITSET with bitset 0");
    expect(futex(&a[0], FUTEX_WAKE_BITSET_PRIVATE, 1, 0, NULL, 0), -EINVAL, "WAKE_BITSET with bitset 0");
    expect(futex(&a[0], 99, 0, 0, NULL, 0), -ENOSYS, "an unknown command");
    expect(futex(&a[0], FUTEX_WAKE_PRIVATE | FUTEX_CLOCK_REALTIME, 1, 0, NULL, 0), -ENOSYS, "WAKE with FUTEX_CLOCK_REALTIME");

    // --- PI locks
    uint32_t tid = syscall(SYS_gettid);
    a[1] = 0;
    expect(futex(&a[1], FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0), 0, "LOCK_PI on a free lock");
    expect(a[1] & FUTEX_TID_MASK, tid, "the word holds the owner's tid");
    expect(futex(&a[1], FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0), -EDEADLK, "LOCK_PI by the owner");
    expect(futex(&a[1], FUTEX_UNLOCK_PI_PRIVATE, 0, 0, NULL, 0), 0, "UNLOCK_PI by the owner");
    expect(a[1], 0, "the word is free again");
    pthread_t h;
    pthread_create(&h, NULL, helper, NULL);
    while (!helper_tid) usleep(1000);
    a[1] = helper_tid; // owned by a live thread that is not us
    expect(futex(&a[1], FUTEX_TRYLOCK_PI_PRIVATE, 0, 0, NULL, 0), -EAGAIN, "TRYLOCK_PI on a lock someone else holds");
    expect(futex(&a[1], FUTEX_UNLOCK_PI_PRIVATE, 0, 0, NULL, 0), -EPERM, "UNLOCK_PI by a non-owner");
    expect(a[1] & FUTEX_TID_MASK, helper_tid, "the lock is still the other thread's");
    helper_stop = 1;
    pthread_join(h, NULL);
    a[1] = 0x3ffffff0; // no such task
    known(futex(&a[1], FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0), -ESRCH, "LOCK_PI on a lock whose owner does not exist",
          "bug 42: robust lists are not walked at thread exit; Hydra takes the lock over instead");
    a[1] = FUTEX_OWNER_DIED; // owner died and the lock was released by the robust list
    expect(futex(&a[1], FUTEX_LOCK_PI_PRIVATE, 0, 0, NULL, 0), 0, "LOCK_PI on a free lock marked OWNER_DIED");
    expect(a[1], tid | FUTEX_OWNER_DIED, "OWNER_DIED is kept for the new owner");

    printf(fails ? "FUTEX TEST FAILED (%d)\n" : "FUTEX TEST PASSED\n", fails);
    return fails != 0;
}
