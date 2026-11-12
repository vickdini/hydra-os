/* abort() must end the process with SIGABRT in every case glibc handles: no handler, a
 * handler that returns, SIGABRT blocked, from a second thread, with a handler installed
 * by sigaction with SA_SIGINFO|SA_ONSTACK (as Wine does). glibc falls back to a `hlt`
 * instruction (SIGSEGV) only if raising SIGABRT failed to kill the process.
 * Build: gcc -O1 -w -pthread abort_test.c -o abort_test.elf */
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static volatile int handler_runs;
static void returning_handler(int sig) { handler_runs++; }
static void info_handler(int sig, siginfo_t *si, void *uc) { handler_runs++; }

static void *thread_abort(void *p) { abort(); return NULL; }

static int run(int variant) {
    pid_t pid = fork();
    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        switch (variant) {
        case 0:
            break;
        case 1:
            sa.sa_handler = returning_handler;
            sigaction(SIGABRT, &sa, NULL);
            break;
        case 2: {
            sigset_t s;
            sigemptyset(&s);
            sigaddset(&s, SIGABRT);
            sigprocmask(SIG_BLOCK, &s, NULL);
            break;
        }
        case 3: {
            static char stack[65536];
            stack_t ss = {.ss_sp = stack, .ss_size = sizeof stack};
            sigaltstack(&ss, NULL);
            sa.sa_sigaction = info_handler;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
            sigfillset(&sa.sa_mask);
            sigaction(SIGABRT, &sa, NULL);
            break;
        }
        case 4: {
            sa.sa_handler = returning_handler;
            sigaction(SIGABRT, &sa, NULL);
            pthread_t t;
            pthread_create(&t, NULL, thread_abort, NULL);
            pthread_join(t, NULL);
            _exit(99);
        }
        }
        abort();
        _exit(98);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    return st;
}

static const char *describe(int st) {
    static char b[64];
    if (WIFSIGNALED(st)) snprintf(b, sizeof b, "killed by signal %d", WTERMSIG(st));
    else snprintf(b, sizeof b, "exited %d", WEXITSTATUS(st));
    return b;
}

/* A signal unblocked by sigprocmask must be delivered when that call returns, also while
 * other threads keep the kernel's signal tables busy (abort() relies on it: the next
 * instruction after its last sigprocmask is `hlt`). */
static volatile int usr1_seen, stop_busy;
static void usr1_handler(int sig) { usr1_seen = 1; }
static void *busy_masks(void *p) {
    sigset_t s, old;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR2);
    while (!stop_busy) {
        pthread_sigmask(SIG_BLOCK, &s, &old);
        pthread_sigmask(SIG_SETMASK, &old, NULL);
    }
    return NULL;
}
static int unblock_delivery_misses(int rounds) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = usr1_handler;
    sigaction(SIGUSR1, &sa, NULL);
    pthread_t t[3];
    for (int i = 0; i < 3; i++) pthread_create(&t[i], NULL, busy_masks, NULL);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    int misses = 0;
    for (int i = 0; i < rounds; i++) {
        pthread_sigmask(SIG_BLOCK, &s, NULL);
        usr1_seen = 0;
        raise(SIGUSR1);
        pthread_sigmask(SIG_UNBLOCK, &s, NULL);
        if (!usr1_seen) misses++;
    }
    stop_busy = 1;
    for (int i = 0; i < 3; i++) pthread_join(t[i], NULL);
    return misses;
}

int main(void) {
    int misses = unblock_delivery_misses(20000);
    char what0[128];
    snprintf(what0, sizeof what0, "signal delivered on return from the unblocking sigprocmask (%d of 20000 late)", misses);
    check(misses == 0, what0);
    const char *names[] = {"no handler", "a handler that returns", "SIGABRT blocked",
                           "SA_SIGINFO|SA_ONSTACK handler, all blocked in it", "from a second thread"};
    for (int v = 0; v < 5; v++) {
        int st = run(v);
        char what[160];
        snprintf(what, sizeof what, "abort() with %s: %s", names[v], describe(st));
        check(WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT, what);
    }
    printf(fails ? "ABORT TEST: %d FAILED\n" : "ABORT TEST PASSED\n", fails);
    return fails != 0;
}
