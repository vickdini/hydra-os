/* forktear_test: a thread's stack writes and registers while another thread of the same
 * process forks (copy-on-write) and the kernel switches tasks (wave 4, group 9 follow-up:
 * kwin_wayland crashed with the upper half of a saved stack pointer lost).
 *
 * The main thread loops over a stack array: it stores 64-bit stack addresses into it and
 * reads them back, and keeps one in a callee-saved register (r12) through a busy loop; other
 * threads fork children that exit at once, and map/unmap memory (TLB shootdowns). A torn or
 * lost store, or a changed register, is reported.
 *
 *   forktear_test [seconds] [forking threads]   prints "FORKTEAR TEST PASSED" or "... FAILED"
 * Build: gcc -O1 -w -pthread forktear_test.c -o forktear
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile int stop;
static volatile long forks;

static void *forker(void *x) {
    (void)x;
    while (!stop) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        if (c > 0) waitpid(c, 0, 0);
        forks++;
        void *m = mmap(0, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) {
            ((volatile char *)m)[0] = 1;
            munmap(m, 65536);
        }
    }
    return 0;
}

/* r12 = a stack address through a busy loop of `n` iterations (preemptions, interrupts) */
static long reg_spin(long n) {
    volatile long local = 0;
    long out;
    __asm__ volatile(
        "mov %1, %%r12\n\t"
        "mov %2, %%rcx\n\t"
        "1: pause\n\t"
        "dec %%rcx\n\t"
        "jnz 1b\n\t"
        "mov %%r12, %0\n\t"
        : "=r"(out)
        : "r"((long)&local), "r"(n)
        : "rcx", "r12", "memory");
    return out == (long)&local ? 0 : out;
}

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int secs = argc > 1 ? atoi(argv[1]) : 20;
    int nth = argc > 2 ? atoi(argv[2]) : 2;
    pthread_t th[8];
    for (int i = 0; i < nth && i < 8; i++) pthread_create(&th[i], 0, forker, 0);
    volatile uint64_t arr[8192]; /* 64 KiB of stack: 16 pages */
    int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    long torn = 0, regs = 0, rounds = 0;
    uint64_t end = now_ms() + secs * 1000;
    while (now_ms() < end) {
        for (int i = 0; i < 8192; i++) arr[i] = (uint64_t)&arr[i] ^ (rounds << 1);
        /* Move to another CPU (and let the forkers run): a write kept only in a stale TLB
         * entry of the old CPU, or lost by a copy-on-write, shows up after the move */
        if (ncpu > 1) {
            cpu_set_t s;
            CPU_ZERO(&s);
            CPU_SET(rounds % ncpu, &s);
            sched_setaffinity(0, sizeof s, &s);
        }
        sched_yield();
        for (int i = 0; i < 8192; i++) {
            uint64_t want = (uint64_t)&arr[i] ^ (rounds << 1);
            if (arr[i] != want) {
                if (torn < 10) printf("FAIL torn store: arr[%d] = %#llx, expected %#llx\n", i, (unsigned long long)arr[i], (unsigned long long)want);
                torn++;
            }
        }
        long r = reg_spin(20000);
        if (r) {
            if (regs < 10) printf("FAIL r12 = %#lx after a busy loop\n", r);
            regs++;
        }
        rounds++;
    }
    stop = 1;
    for (int i = 0; i < nth && i < 8; i++) pthread_join(th[i], 0);
    printf("%ld rounds, %ld forks, %ld torn stores, %ld register changes\n", rounds, forks, torn, regs);
    printf(torn || regs ? "FORKTEAR TEST FAILED\n" : "FORKTEAR TEST PASSED\n");
    return torn || regs ? 1 : 0;
}
