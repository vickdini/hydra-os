// Several CPUs: CPU-bound processes, and threads of one process, run in parallel (four
// take about as long as one when four CPUs are online); nproc/sched_getaffinity report the
// CPUs; a mapping another thread is reading on another CPU stops working at once when it
// is protected (TLB shootdown). With one CPU it reports and skips the timing checks.
// Build: gcc -O1 -w -pthread -o smp smp_test.c
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static volatile unsigned long sink;
static void work(unsigned long n) {
    unsigned long x = 1;
    for (unsigned long i = 0; i < n; i++) x = x * 6364136223846793005UL + 1442695040888963407UL;
    sink = x;
}

// Runs `procs` processes each doing `n` iterations; returns the wall time
static double run(int procs, unsigned long n) {
    double t0 = now();
    for (int i = 0; i < procs; i++)
        if (fork() == 0) {
            work(n);
            _exit(0);
        }
    for (int i = 0; i < procs; i++) wait(NULL);
    return now() - t0;
}

static void *thread_work(void *n) {
    work((unsigned long)n);
    return NULL;
}

// Runs `threads` threads of this process each doing `n` iterations; returns the wall time
static double run_threads(int threads, unsigned long n) {
    pthread_t t[8];
    double t0 = now();
    for (int i = 0; i < threads; i++) pthread_create(&t[i], NULL, thread_work, (void *)n);
    for (int i = 0; i < threads; i++) pthread_join(t[i], NULL);
    return now() - t0;
}

// `clock_gettime` called 100000 times by each of `threads` threads at once: nanoseconds
// of wall time per call (in each thread)
static void *clock_work(void *x) {
    struct timespec t;
    for (int i = 0; i < 100000; i++) clock_gettime(CLOCK_MONOTONIC, &t);
    return NULL;
}
static double run_clock(int threads) {
    pthread_t t[8];
    double t0 = now();
    for (int i = 0; i < threads; i++) pthread_create(&t[i], NULL, clock_work, NULL);
    for (int i = 0; i < threads; i++) pthread_join(t[i], NULL);
    return (now() - t0) / 100000 * 1e9;
}

// A cheap system call that takes the kernel lock (getppid), 50000 times in each of
// `threads` threads at once: nanoseconds of wall time per call
static void *ppid_work(void *x) {
    for (int i = 0; i < 50000; i++) getppid();
    return NULL;
}
static double run_ppid(int threads) {
    pthread_t t[8];
    double t0 = now();
    for (int i = 0; i < threads; i++) pthread_create(&t[i], NULL, ppid_work, NULL);
    for (int i = 0; i < threads; i++) pthread_join(t[i], NULL);
    return (now() - t0) / 50000 * 1e9;
}

// stat of a file (a request to the file server), 2000 times in each of `procs` processes
// at once: microseconds of wall time per call
static double run_stat(int procs) {
    double t0 = now();
    for (int i = 0; i < procs; i++)
        if (fork() == 0) {
            struct stat st;
            for (int k = 0; k < 2000; k++) stat("/etc/passwd", &st);
            _exit(0);
        }
    for (int i = 0; i < procs; i++) wait(NULL);
    return (now() - t0) / 2000 * 1e6;
}

// A thread reading a page until it faults
static volatile char *page;
static volatile int reading, faulted;
static sigjmp_buf out;
static void on_segv(int s) { siglongjmp(out, 1); }
static void *reader(void *x) {
    if (sigsetjmp(out, 1)) {
        faulted = 1;
        return NULL;
    }
    reading = 1;
    for (;;) (void)page[0];
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    cpu_set_t set;
    CPU_ZERO(&set);
    int aff = sched_getaffinity(0, sizeof set, &set) == 0 ? CPU_COUNT(&set) : -1;
    printf("     %ld CPUs online, affinity %d\n", n, aff);
    check(n >= 1 && aff == n, "sysconf and sched_getaffinity agree");
    // About half a second of work for one process
    unsigned long iters = 1000000;
    while (run(1, iters) < 0.25) iters *= 2;
    double one = run(1, iters);
    int k = n > 4 ? 4 : (int)n;
    double many = run(k, iters);
    printf("     1 process: %.3f s; %d at once: %.3f s (speedup %.2f)\n", one, k, many, k * one / many);
    if (k > 1) check(many < one * k * 0.75, "processes run in parallel");
    double tmany = run_threads(k, iters);
    printf("     %d threads at once: %.3f s (speedup %.2f)\n", k, tmany, k * one / tmany);
    if (k > 1) check(tmany < one * k * 0.75, "threads of one process run in parallel");

    // Protecting a page another thread keeps reading (on another CPU) takes effect at once
    page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    page[0] = 1;
    struct sigaction sa = {0};
    sa.sa_handler = on_segv;
    sigaction(SIGSEGV, &sa, NULL);
    pthread_t r;
    pthread_create(&r, NULL, reader, NULL);
    while (!reading) sched_yield();
    usleep(50000);
    mprotect((void *)page, 4096, PROT_NONE);
    double t0 = now();
    while (!faulted && now() - t0 < 2) usleep(1000);
    check(faulted, "a page protected while another thread reads it faults there");
    if (faulted) pthread_join(r, NULL);

    // Measurements (no pass/fail): wakeups across processes, and a cheap system call on
    // every CPU at once
    int ab[2], ba[2];
    pipe(ab);
    pipe(ba);
    int rounds = 2000;
    pid_t c = fork();
    if (c == 0) {
        char b;
        for (int i = 0; i < rounds; i++) {
            read(ab[0], &b, 1);
            write(ba[1], &b, 1);
        }
        _exit(0);
    }
    char b = 'x';
    double p0 = now();
    for (int i = 0; i < rounds; i++) {
        write(ab[1], &b, 1);
        read(ba[0], &b, 1);
    }
    double pp = now() - p0;
    waitpid(c, NULL, 0);
    printf("     pipe ping-pong: %.1f us per round trip\n", pp / rounds * 1e6);
    double g1 = run_clock(1), gk = run_clock(k);
    printf("     clock_gettime: %.0f ns per call on 1 thread, %.0f ns per call on %d at once\n", g1, gk, k);
    double q1 = run_ppid(1), qk = run_ppid(k);
    printf("     getppid: %.0f ns per call on 1 thread, %.0f ns per call on %d at once\n", q1, qk, k);
    double s1 = run_stat(1), sk = run_stat(k);
    printf("     stat: %.1f us per call in 1 process, %.1f us per call in %d at once\n", s1, sk, k);
    printf(fails ? "SMP TEST FAILED (%d)\n" : "SMP TEST PASSED\n", fails);
    return fails != 0;
}
