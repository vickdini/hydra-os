/* wakeop_test: FUTEX_WAKE_OP must change its second word atomically (wave 4, group 9).
 *
 * Qt's QSemaphore keeps a 64-bit counter whose upper half is a futex word that waking
 * threads change with FUTEX_WAKE_OP while other threads change the same word with their own
 * atomic instructions. Hydra's kernel used to read the word, compute, and write it back:
 * updates made in between were lost, and a stale value could land after the word's owner
 * had moved on (kwin_wayland crashed with the upper half of a stack pointer zeroed).
 *
 * Threads add 1 to a shared word with atomic instructions while other threads apply
 * FUTEX_WAKE_OP to it (OR 0: no change; ADD 1: counted). The final value must be exactly
 * the number of additions.
 *   wakeop_test [seconds]     prints "WAKEOP TEST PASSED" or "WAKEOP TEST FAILED"
 * Build: gcc -O1 -w -pthread wakeop_test.c -o wakeop
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint32_t word1, word2;
static volatile int stop;
static long adds[4], kadds[4];

static long wake_op(uint32_t *u1, uint32_t *u2, int op, int arg) {
    /* FUTEX_OP(op, oparg, cmp, cmparg): cmp EQ 0 */
    uint32_t enc = ((op & 0xf) << 28) | ((FUTEX_OP_CMP_EQ & 0xf) << 24) | ((arg & 0xfff) << 12);
    return syscall(SYS_futex, u1, FUTEX_WAKE_OP_PRIVATE, 1, (void *)1, u2, enc);
}

static void *adder(void *x) {
    long i = (long)x;
    while (!stop) {
        __atomic_fetch_add(&word2, 1, __ATOMIC_SEQ_CST);
        adds[i]++;
    }
    return 0;
}

static void *waker(void *x) {
    long i = (long)x;
    while (!stop) {
        /* OR 0: changes nothing, but a non-atomic kernel write loses concurrent adds */
        if (wake_op(&word1, &word2, FUTEX_OP_OR, 0) < 0) {
            perror("FUTEX_WAKE_OP");
            exit(2);
        }
        if (wake_op(&word1, &word2, FUTEX_OP_ADD, 1) >= 0) kadds[i]++;
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int secs = argc > 1 ? atoi(argv[1]) : 5;
    pthread_t t[4];
    for (long i = 0; i < 2; i++) pthread_create(&t[i], 0, adder, (void *)i);
    for (long i = 2; i < 4; i++) pthread_create(&t[i], 0, waker, (void *)i);
    sleep(secs);
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    long want = adds[0] + adds[1] + kadds[2] + kadds[3];
    printf("%ld atomic adds, %ld FUTEX_WAKE_OP adds, word %u, expected %ld (lost %ld)\n", adds[0] + adds[1], kadds[2] + kadds[3], word2,
           (uint32_t)want, (long)(uint32_t)want - (long)word2);
    int ok = word2 == (uint32_t)want;
    printf(ok ? "WAKEOP TEST PASSED\n" : "WAKEOP TEST FAILED\n");
    return ok ? 0 : 1;
}
