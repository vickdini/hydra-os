// POSIX timers: one-shot and periodic expiry, SI_TIMER siginfo, overruns, absolute
// CLOCK_REALTIME, SIGEV_NONE, SIGEV_THREAD_ID, glibc SIGEV_THREAD, CPU-time timers and
// clocks, timer_delete, and no inheritance across fork.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
typedef int ktimer;
static int k_create(clockid_t c, struct sigevent *ev, ktimer *id) { return syscall(SYS_timer_create, c, ev, id); }
static int k_settime(ktimer id, int f, const struct itimerspec *n, struct itimerspec *o) { return syscall(SYS_timer_settime, id, f, n, o); }
static int k_gettime(ktimer id, struct itimerspec *c) { return syscall(SYS_timer_gettime, id, c); }
static int k_getoverrun(ktimer id) { return syscall(SYS_timer_getoverrun, id); }
static int k_delete(ktimer id) { return syscall(SYS_timer_delete, id); }
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static volatile int hits, last_code, last_value, last_timerid, last_tid, overrun;
static ktimer ovt;
static void on_sig(int s, siginfo_t *si, void *c) {
    (void)c;
    hits++;
    last_code = si->si_code;
    last_value = si->si_value.sival_int;
    last_timerid = si->si_timerid;
    last_tid = syscall(SYS_gettid);
    if (s == SIGUSR2) overrun = k_getoverrun(ovt);
}

static void msleep(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

static ktimer make(clockid_t clk, int sig, int value) {
    struct sigevent ev = {0};
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = sig;
    ev.sigev_value.sival_int = value;
    ktimer t = -1;
    if (k_create(clk, &ev, &t)) printf("timer_create: %s\n", strerror(errno));
    return t;
}

static void arm(ktimer t, long value_ms, long interval_ms, int flags) {
    struct itimerspec its = {{interval_ms / 1000, (interval_ms % 1000) * 1000000}, {value_ms / 1000, (value_ms % 1000) * 1000000}};
    k_settime(t, flags, &its, 0);
}

static volatile int thread_ready, thread_tid, cb_runs;
static void *waiter(void *a) {
    (void)a;
    thread_tid = syscall(SYS_gettid);
    thread_ready = 1;
    for (int i = 0; i < 100 && !hits; i++) msleep(10);
    return 0;
}
static void callback(union sigval v) {
    (void)v;
    cb_runs++;
}

int main(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = on_sig;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &sa, 0);
    sigaction(SIGUSR2, &sa, 0);

    // One-shot
    ktimer t1 = make(CLOCK_MONOTONIC, SIGUSR1, 77);
    arm(t1, 50, 0, 0);
    struct itimerspec cur;
    CHECK(k_gettime(t1, &cur) == 0 && cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 50000000, "timer_gettime while armed (%ld ns)", cur.it_value.tv_nsec);
    msleep(200);
    CHECK(hits == 1 && last_code == SI_TIMER && last_value == 77 && last_timerid == t1, "one-shot fired once (%d): code %d value %d timerid %d", hits, last_code, last_value, last_timerid);
    CHECK(k_gettime(t1, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0, "disarmed after firing");

    // Periodic
    hits = 0;
    arm(t1, 20, 20, 0);
    msleep(300);
    arm(t1, 0, 0, 0);
    int periodic = hits;
    CHECK(periodic >= 8 && periodic <= 16, "periodic 20 ms over 300 ms: %d signals", periodic);

    // Overruns while the signal is blocked
    ovt = make(CLOCK_MONOTONIC, SIGUSR2, 5);
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    sigprocmask(SIG_BLOCK, &set, 0);
    hits = 0;
    arm(ovt, 10, 10, 0);
    msleep(200);
    sigprocmask(SIG_UNBLOCK, &set, 0);
    arm(ovt, 0, 0, 0);
    CHECK(hits == 1 && overrun >= 5, "blocked periodic timer: 1 signal, overrun %d", overrun);

    // Absolute CLOCK_REALTIME
    ktimer t2 = make(CLOCK_REALTIME, SIGUSR1, 9);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct itimerspec abs = {{0, 0}, {now.tv_sec, now.tv_nsec + 100000000}};
    if (abs.it_value.tv_nsec >= 1000000000) {
        abs.it_value.tv_sec++;
        abs.it_value.tv_nsec -= 1000000000;
    }
    hits = 0;
    CHECK(k_settime(t2, TIMER_ABSTIME, &abs, 0) == 0, "absolute realtime timer armed");
    msleep(300);
    CHECK(hits == 1 && last_value == 9, "absolute realtime timer fired");

    // SIGEV_NONE
    struct sigevent none = {0};
    none.sigev_notify = SIGEV_NONE;
    ktimer t3;
    CHECK(k_create(CLOCK_MONOTONIC, &none, &t3) == 0, "SIGEV_NONE timer");
    arm(t3, 1000, 0, 0);
    msleep(100);
    CHECK(k_gettime(t3, &cur) == 0 && cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec < 950000000, "SIGEV_NONE counts down (%ld ns left)", cur.it_value.tv_nsec);

    // SIGEV_THREAD_ID
    pthread_t th;
    hits = 0;
    pthread_create(&th, 0, waiter, 0);
    while (!thread_ready) msleep(5);
    struct sigevent tid_ev = {0};
    tid_ev.sigev_notify = SIGEV_THREAD_ID;
    tid_ev.sigev_signo = SIGUSR1;
    tid_ev._sigev_un._tid = thread_tid;
    ktimer t4;
    hits = 0;
    CHECK(k_create(CLOCK_MONOTONIC, &tid_ev, &t4) == 0, "SIGEV_THREAD_ID timer (errno %d)", errno);
    arm(t4, 30, 0, 0);
    pthread_join(th, 0);
    CHECK(hits == 1 && last_tid == thread_tid, "signal went to thread %d (got %d)", thread_tid, last_tid);

    // glibc SIGEV_THREAD
    struct sigevent cb = {0};
    cb.sigev_notify = SIGEV_THREAD;
    cb.sigev_notify_function = callback;
    timer_t t5;
    CHECK(timer_create(CLOCK_MONOTONIC, &cb, &t5) == 0, "SIGEV_THREAD timer (errno %d)", errno);
    struct itimerspec in30 = {{0, 0}, {0, 30000000}};
    timer_settime(t5, 0, &in30, 0);
    for (int i = 0; i < 50 && !cb_runs; i++) msleep(10);
    CHECK(cb_runs == 1, "SIGEV_THREAD callback ran");

    // CPU-time timer and clocks
    struct timespec c0, c1, th0, th1;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &th0);
    ktimer t6 = make(CLOCK_PROCESS_CPUTIME_ID, SIGUSR1, 6);
    hits = 0;
    arm(t6, 50, 0, 0);
    for (volatile long i = 0; !hits && i < 2000000000L; i++) {
    }
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &th1);
    long used = (c1.tv_sec - c0.tv_sec) * 1000 + (c1.tv_nsec - c0.tv_nsec) / 1000000;
    long tused = (th1.tv_sec - th0.tv_sec) * 1000 + (th1.tv_nsec - th0.tv_nsec) / 1000000;
    CHECK(hits == 1 && last_value == 6 && used >= 40, "CPU-time timer fired after %ld ms of CPU (thread clock %ld ms)", used, tused);

    // Delete; fork does not inherit
    CHECK(k_delete(t2) == 0, "timer_delete");
    errno = 0;
    CHECK(k_settime(t2, 0, &abs, 0) == -1 && errno == EINVAL, "deleted timer -> EINVAL");
    pid_t c = fork();
    if (c == 0) _exit(k_gettime(t1, &cur) == -1 && errno == EINVAL ? 0 : 1);
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child has no timers");

    printf(fails ? "PTIMER TEST FAILED (%d)\n" : "PTIMER TEST PASSED\n", fails);
    return fails != 0;
}
