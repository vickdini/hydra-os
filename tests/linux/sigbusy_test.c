/* sigbusy: timer signals must reach a thread that never makes a system call.
 *
 * Linux delivers a pending signal on every return to user mode, also from a timer
 * interrupt. Hydra once delivered them only at system calls and at the rare tick that did
 * not switch tasks (wave 5, Group 17): a busy loop got ~5 of ~300 signals in 3 s.
 *
 * For each timer kind (setitimer ITIMER_REAL, ITIMER_PROF, timer_create SIGEV_SIGNAL) the
 * test counts the signals of a 1 ms periodic timer while the main thread sleeps in
 * sigsuspend (reference count), then while it spins without any system call (the TSC
 * measures the time). The busy count must be at least 70 % of the reference (50 % for ITIMER_PROF) (both are
 * limited by the kernel's timer resolution: ~100/s on Hydra, ~1000/s on Linux). alarm(1)
 * must interrupt a busy loop within 2 s.
 *
 *   sigbusy [ms per phase, default 1000] [threads spinning besides main, default 0] [sys: they call umask]
 * Build: gcc -O1 -w -pthread sigbusy_test.c -o sigbusy.elf -lrt
 */
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile long seen;
static volatile int spin_stop;
static void on_sig(int s) { (void)s; seen++; }

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}
static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double tsc_per_ns;

static void calibrate(void) {
    uint64_t t0 = now_ns(), c0 = rdtsc();
    struct timespec d = {0, 200000000};
    while (nanosleep(&d, &d) != 0) {}
    uint64_t t1 = now_ns(), c1 = rdtsc();
    tsc_per_ns = (double)(c1 - c0) / (double)(t1 - t0);
}

/* Spins for ms milliseconds without a system call. */
static void spin_ms(int ms) {
    uint64_t end = rdtsc() + (uint64_t)(tsc_per_ns * 1e6 * ms);
    while (rdtsc() < end) __asm__ volatile("pause");
}

/* Sleeps ms milliseconds in sigsuspend (signals unblocked). */
static void sleep_ms(int ms) {
    uint64_t end = now_ns() + (uint64_t)ms * 1000000ull;
    while (now_ns() < end) {
        struct timespec d = {0, 5000000};
        nanosleep(&d, 0);
    }
}

enum { K_REAL, K_PROF, K_POSIX };
static const char *names[] = {"setitimer ITIMER_REAL", "setitimer ITIMER_PROF", "timer_create SIGEV_SIGNAL"};
static timer_t ptimer;

static void arm(int kind, int on) {
    long us = on ? 1000 : 0;
    if (kind == K_POSIX) {
        struct itimerspec its = {{0, us * 1000}, {0, us * 1000}};
        timer_settime(ptimer, 0, &its, 0);
    } else {
        struct itimerval it = {{0, us}, {0, us}};
        setitimer(kind == K_REAL ? ITIMER_REAL : ITIMER_PROF, &it, 0);
    }
}

static int sys_mode; /* the extra threads make system calls instead of spinning */
static void *spinner(void *a) {
    (void)a;
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, 0); /* the main thread takes the signals */
    while (!spin_stop) {
        if (sys_mode) syscall(SYS_umask, 022);
        else __asm__ volatile("pause");
    }
    return 0;
}

/* Calls umask for ms milliseconds (a thread busy in system calls). */
static void syscall_ms(int ms) {
    uint64_t end = rdtsc() + (uint64_t)(tsc_per_ns * 1e6 * ms);
    while (rdtsc() < end) syscall(SYS_umask, 022);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int ms = argc > 1 ? atoi(argv[1]) : 1000;
    int nspin = argc > 2 ? atoi(argv[2]) : 0;
    sys_mode = argc > 3 && !strcmp(argv[3], "sys");
    int fails = 0;
    calibrate();
    printf("sigbusy: %d ms per phase, %d extra spinning threads, TSC %.3f GHz\n", ms, nspin, tsc_per_ns);
    pthread_t th[8];
    for (int i = 0; i < nspin && i < 8; i++) pthread_create(&th[i], 0, spinner, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, 0);
    sigaction(SIGPROF, &sa, 0);
    sigaction(SIGRTMIN, &sa, 0);
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGRTMIN;
    if (timer_create(CLOCK_MONOTONIC, &sev, &ptimer) != 0) {
        perror("timer_create");
        fails++;
    }

    long ref_real = 0;
    for (int kind = K_REAL; kind <= K_POSIX; kind++) {
        long idle = 0;
        /* A CPU-time timer does not run while the process sleeps: compare with the
         * real-time reference instead */
        if (kind != K_PROF) {
            seen = 0;
            arm(kind, 1);
            sleep_ms(ms);
            arm(kind, 0);
            idle = seen;
            if (kind == K_REAL) ref_real = idle;
        } else {
            idle = ref_real;
        }
        seen = 0;
        arm(kind, 1);
        spin_ms(ms);
        long busy = seen; /* read before the next system call delivers more */
        arm(kind, 0);
        /* CPU time is sampled at ticks and loses what the host steals from the virtual CPU:
         * the CPU-time timer, compared with real time, gets a lower bar (the bug gave 0-10 %) */
        int bar = kind == K_PROF ? 5 : 7;
        int ok = idle > 0 && busy * 10 >= idle * bar;
        printf("%s %s: %ld signals while sleeping, %ld while spinning (%ld %%)\n", ok ? "PASS" : "FAIL", names[kind], idle,
               busy, idle ? busy * 100 / idle : 0);
        if (!ok) fails++;
        sleep_ms(30);
    }

    /* A thread busy in system calls (umask, under the kernel lock): the timer daemon must
     * still get the CPU to post (a tick during a call is not a preemption point) */
    {
        seen = 0;
        arm(K_REAL, 1);
        syscall_ms(ms);
        long busy = seen;
        arm(K_REAL, 0);
        int ok = ref_real > 0 && busy * 10 >= ref_real * 7;
        printf("%s setitimer ITIMER_REAL, busy in system calls: %ld signals (%ld %% of %ld)\n", ok ? "PASS" : "FAIL", busy,
               ref_real ? busy * 100 / ref_real : 0, ref_real);
        if (!ok) fails++;
        sleep_ms(30);
    }

    /* alarm(1) during a 3 s busy loop: the handler must run during the loop */
    {
        seen = 0;
        alarm(1);
        uint64_t c0 = rdtsc();
        uint64_t end = c0 + (uint64_t)(tsc_per_ns * 3e9);
        uint64_t got = 0;
        while (rdtsc() < end) {
            if (seen && !got) got = rdtsc();
            __asm__ volatile("pause");
        }
        double at = got ? (double)(got - c0) / tsc_per_ns / 1e6 : -1;
        int ok = got && at < 2000;
        printf("%s alarm(1) in a busy loop: handler ran after %.0f ms\n", ok ? "PASS" : "FAIL", at);
        if (!ok) fails++;
    }

    spin_stop = 1;
    for (int i = 0; i < nspin && i < 8; i++) pthread_join(th[i], 0);
    printf(fails ? "SIGBUSY TEST FAILED (%d)\n" : "SIGBUSY TEST PASSED\n", fails);
    return fails != 0;
}
