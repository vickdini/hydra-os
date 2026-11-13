// Robust mutexes (bug 42 of tests/host/TEST_REPORT.md): when a thread or process dies
// holding one, the kernel walks its robust list (set_robust_list) and marks the mutex
// FUTEX_OWNER_DIED, waking a waiter; the next locker gets EOWNERDEAD and can make it
// consistent. Hydra accepted set_robust_list but never walked the list: the mutex stayed
// locked forever (a waiter hung). Also: get_robust_list returns what set_robust_list
// stored, and a PI futex whose owner never existed is ESRCH.
// Build: gcc -O1 -w -pthread -o robust robust_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static void init_robust(pthread_mutex_t *m, int pi, int shared) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    if (pi) pthread_mutexattr_setprotocol(&a, PTHREAD_PRIO_INHERIT);
    if (shared) pthread_mutexattr_setpshared(&a, PTHREAD_PROCESS_SHARED);
    pthread_mutex_init(m, &a);
    pthread_mutexattr_destroy(&a);
}

static void *lock_and_exit(void *m) {
    pthread_mutex_lock(m);
    return NULL; // dies holding it
}

struct slow { pthread_mutex_t *m; int locked; };

static void *lock_wait_exit(void *arg) {
    struct slow *s = arg;
    pthread_mutex_lock(s->m);
    __atomic_store_n(&s->locked, 1, __ATOMIC_SEQ_CST);
    usleep(300000); // the main thread is blocked on the mutex by now
    return NULL;
}

// Locks with a 5 s limit, so a hang becomes a failure
static int lock5(pthread_mutex_t *m) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 5;
    return pthread_mutex_timedlock(m, &ts);
}

static void owner_dies(int pi) {
    const char *kind = pi ? "PI " : "";
    char line[160];
    pthread_mutex_t m;
    init_robust(&m, pi, 0);

    // 1. The owner thread exits; a later lock gets EOWNERDEAD
    pthread_t t;
    pthread_create(&t, NULL, lock_and_exit, &m);
    pthread_join(t, NULL);
    int r = lock5(&m);
    snprintf(line, sizeof line, "robust %smutex: lock after the owner thread exited: EOWNERDEAD (got %s)", kind, strerror(r));
    check(r == EOWNERDEAD, line);
    if (r == EOWNERDEAD) {
        check(pthread_mutex_consistent(&m) == 0, "pthread_mutex_consistent");
        pthread_mutex_unlock(&m);
        snprintf(line, sizeof line, "robust %smutex: usable again", kind);
        check(lock5(&m) == 0, line);
    }
    pthread_mutex_unlock(&m);

    // 2. The owner exits while this thread waits: the waiter is woken with EOWNERDEAD
    struct slow s = { &m, 0 };
    pthread_create(&t, NULL, lock_wait_exit, &s);
    while (!__atomic_load_n(&s.locked, __ATOMIC_SEQ_CST)) usleep(1000);
    r = lock5(&m);
    snprintf(line, sizeof line, "robust %smutex: a waiter is woken when the owner exits: EOWNERDEAD (got %s)", kind, strerror(r));
    check(r == EOWNERDEAD, line);
    if (r == EOWNERDEAD) pthread_mutex_consistent(&m);
    if (r == 0 || r == EOWNERDEAD) pthread_mutex_unlock(&m);
    pthread_join(t, NULL);
}

int main(void) {
    // get/set_robust_list
    struct robust_list_head *head = NULL;
    size_t len = 0;
    long r = syscall(SYS_get_robust_list, 0, &head, &len);
    check(r == 0 && head != NULL && len == sizeof(struct robust_list_head),
          "get_robust_list(0) returns the head glibc registered (24 bytes)");
    check(syscall(SYS_set_robust_list, head, 23) < 0 && errno == EINVAL, "set_robust_list with a wrong length: EINVAL");

    owner_dies(0);
    owner_dies(1);

    // A process-shared robust mutex: the child process dies holding it
    pthread_mutex_t *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    init_robust(m, 0, 1);
    pid_t p = fork();
    if (p == 0) {
        pthread_mutex_lock(m);
        _exit(0);
    }
    waitpid(p, NULL, 0);
    int e = lock5(m);
    char line[160];
    snprintf(line, sizeof line, "shared robust mutex: lock after the owner process died: EOWNERDEAD (got %s)", strerror(e));
    check(e == EOWNERDEAD, line);

    // A PI futex word naming a thread that does not exist
    static uint32_t w = 0x3ffffff0;
    r = syscall(SYS_futex, &w, FUTEX_LOCK_PI_PRIVATE, 0, 0, 0, 0);
    check(r < 0 && errno == ESRCH, "LOCK_PI on a word whose owner does not exist: ESRCH");

    printf(fails ? "ROBUST TEST FAILED (%d)\n" : "ROBUST TEST PASSED\n", fails);
    return fails != 0;
}
