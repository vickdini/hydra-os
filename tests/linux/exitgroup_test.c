/* exit_group must stop every other thread of the process at once: none may run user code
 * or make system calls after it (Linux kills them before the process is reaped). Hydra
 * used to mark them dead but let those running on another CPU go on until their next
 * scheduling point, in a process already torn down (descriptors closed: EBADF; signal
 * state gone: abort() fell through to `hlt`), which made Wine's services crash on exit.
 * Build: gcc -O1 -w -pthread exitgroup_test.c -o exitgroup_test.elf */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

struct shared {
    volatile unsigned long spins;
    volatile int started;
    volatile int saw_ebadf;
};
static struct shared *sh;
static int devnull;

static void *spinner(void *p) {
    __sync_fetch_and_add(&sh->started, 1);
    for (;;) sh->spins++;
    return NULL;
}

static void *writer(void *p) {
    __sync_fetch_and_add(&sh->started, 1);
    for (;;) {
        if (write(devnull, "x", 1) < 0 && errno == EBADF) sh->saw_ebadf = 1;
    }
    return NULL;
}

static void sleep_ms(int ms) {
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

int main(void) {
    sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    int rounds = 40, moved = 0, ebadf = 0;
    for (int r = 0; r < rounds; r++) {
        memset((void *)sh, 0, sizeof *sh);
        pid_t pid = fork();
        if (pid == 0) {
            devnull = open("/dev/null", O_WRONLY);
            pthread_t t;
            pthread_create(&t, NULL, spinner, NULL);
            pthread_create(&t, NULL, writer, NULL);
            while (sh->started < 2) sched_yield();
            sleep_ms(5);
            _exit(0); /* exit_group */
        }
        int st;
        waitpid(pid, &st, 0);
        unsigned long a = sh->spins;
        sleep_ms(20);
        unsigned long b = sh->spins;
        if (a != b) moved++;
        if (sh->saw_ebadf) ebadf++;
    }
    char what[160];
    snprintf(what, sizeof what, "no thread runs after its process was reaped (%d of %d rounds had one)", moved, rounds);
    check(moved == 0, what);
    snprintf(what, sizeof what, "no thread makes system calls after exit_group (%d of %d rounds saw EBADF)", ebadf, rounds);
    check(ebadf == 0, what);
    printf(fails ? "EXITGROUP TEST: %d FAILED\n" : "EXITGROUP TEST PASSED\n", fails);
    return fails != 0;
}
