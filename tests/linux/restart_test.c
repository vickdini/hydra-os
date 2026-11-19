/* restart_test: what Linux programs see when a Linux service restarts (wave 6, Group 21).
 *
 *   restart_test SECONDS   8 threads make forwarded calls for SECONDS seconds while the
 *                          service is killed from the console (hydra-shell `service kill`);
 *                          each kind of call is counted: ok, EIO, other errors; and the
 *                          longest call. Prints one line per kind every 2 s and a summary.
 *
 * The calls (Hydra's test call 0x6710 = LX_NULL_NR, keys, a test object, a pipe):
 *   null   op 0 (return 0)          idempotent: a Transparent restart re-sends it -> never EIO
 *   pend   op 1 (42 after 300 ms)   pending: always re-sent -> never EIO, always 42
 *   copy   op 2 (changes a buffer)  NOT idempotent: EIO if the crash hits while it is served
 *   keyid  keyctl(GET_KEYRING_ID, process keyring, create)
 *   obj    read of a test object made at start (an object of the old instance: a service that
 *          does not adopt its objects makes it stale -> EBADF from then on)
 *   pipe   write+read on a pipe made at start (stale after a restart: EPIPE)
 *
 * Expected, linux-server as Transparent (fw_cfg opt/hydra/restart.linux=transparent), one kill:
 *   null: 0 EIO 0 other; pend: 0 EIO, all 42; copy: at most a few EIO; keyid: 0 errors;
 *   obj/pipe: errors after the kill (the server does not adopt); the program lives.
 *   The longest call is about the restart time (1-3 s).
 * FailObjects (a second kill within 30 s): calls in flight get EIO, then new calls work.
 * Build: gcc -O1 -w -pthread restart_test.c -o restart
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL 0x6710
#define KEYCTL_GET_KEYRING_ID 0
#define KEY_SPEC_PROCESS_KEYRING -2

enum { K_NULL, K_PEND, K_COPY, K_KEYID, K_OBJ, K_PIPE, K_N };
static const char *names[K_N] = { "null", "pend", "copy", "keyid", "obj", "pipe" };

struct counts {
    volatile long ok, eio, other, wrong, last_err;
    volatile uint64_t max_ms;
};
static struct counts cnt[K_N];
static volatile int stop;
static int objfd = -1, pipefd[2] = { -1, -1 };

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void count(int k, long r, int good, uint64_t t0) {
    uint64_t d = now_ms() - t0;
    if (d > cnt[k].max_ms) cnt[k].max_ms = d;
    if (r >= 0 && good) __sync_fetch_and_add(&cnt[k].ok, 1);
    else if (r >= 0) __sync_fetch_and_add(&cnt[k].wrong, 1);
    else if (errno == EIO) __sync_fetch_and_add(&cnt[k].eio, 1);
    else { __sync_fetch_and_add(&cnt[k].other, 1); cnt[k].last_err = errno; }
}

static void *thr(void *arg) {
    int k = (int)(long)arg;
    unsigned char buf[64];
    while (!stop) {
        uint64_t t0 = now_ms();
        long r;
        switch (k) {
        case K_NULL:
            r = syscall(LX_NULL, 0, 0, 0);
            count(k, r, r == 0, t0);
            break;
        case K_PEND:
            r = syscall(LX_NULL, 1, 300, 0);
            count(k, r, r == 42, t0);
            break;
        case K_COPY:
            memset(buf, 7, sizeof buf);
            r = syscall(LX_NULL, 2, buf, sizeof buf);
            count(k, r, r == (long)sizeof buf && buf[0] == 8 && buf[63] == 8, t0);
            break;
        case K_KEYID:
            r = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 1);
            count(k, r, r > 0, t0);
            break;
        case K_OBJ:
            r = read(objfd, buf, sizeof buf);
            count(k, r, r > 0, t0);
            usleep(20000);
            break;
        case K_PIPE:
            r = write(pipefd[1], "x", 1);
            if (r == 1) r = read(pipefd[0], buf, 1);
            count(k, r, r == 1, t0);
            usleep(5000);
            break;
        }
        if (k == K_OBJ || k == K_PIPE) {
            /* once stale, stays stale: do not spin */
            if (cnt[k].other > 0) usleep(100000);
        }
    }
    return 0;
}

static void report(const char *tag) {
    for (int k = 0; k < K_N; k++)
        printf("%s %-5s ok %ld eio %ld other %ld (last errno %ld) wrong %ld max %llu ms\n", tag, names[k], cnt[k].ok, cnt[k].eio, cnt[k].other, cnt[k].last_err,
               cnt[k].wrong, (unsigned long long)cnt[k].max_ms);
    fflush(stdout);
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 30;
    setvbuf(stdout, 0, _IOLBF, 0);
    objfd = syscall(LX_NULL, 3, 0, 0);
    if (objfd < 0) printf("no test object (errno %d)\n", errno);
    else write(objfd, "r", 1); /* readable */
    if (pipe(pipefd) < 0) printf("no pipe (errno %d)\n", errno);
    printf("RESTART TEST START pid %d, %d s\n", getpid(), secs);
    pthread_t t[8];
    /* two threads each for the null and pending calls, one for each other kind */
    int kinds[8] = { K_NULL, K_NULL, K_PEND, K_PEND, K_COPY, K_KEYID, K_OBJ, K_PIPE };
    for (int i = 0; i < 8; i++) pthread_create(&t[i], 0, thr, (void *)(long)kinds[i]);
    uint64_t end = now_ms() + (uint64_t)secs * 1000;
    while (now_ms() < end) {
        sleep(2);
        report("tick");
    }
    stop = 1;
    for (int i = 0; i < 8; i++) pthread_join(t[i], 0);
    report("final");
    int bad = cnt[K_NULL].eio + cnt[K_NULL].other + cnt[K_NULL].wrong + cnt[K_PEND].eio + cnt[K_PEND].other + cnt[K_PEND].wrong + cnt[K_KEYID].other + cnt[K_KEYID].eio
              + cnt[K_COPY].wrong;
    printf("RESTART TEST DONE: %s (null/pend/keyid errors %d)\n", bad ? "ERRORS" : "CLEAN", bad);
    return 0;
}
