// AVX state is enabled by the OS and preserved: CPUID's OSXSAVE and XGETBV show the YMM
// registers on; their upper halves survive system calls, task switches between threads
// running at once, and a signal handler that overwrites them (sigreturn restores the
// interrupted code's); the signal frame's FPU area is XSAVE state in Linux's layout
// (UC_FP_XSTATE, FP_XSTATE_MAGIC1/2). Windows programs use AVX after checking only that
// the CPU has it, so Hydra must have it on: an installer died on vmovups ymm before.
#define _GNU_SOURCE
#include <cpuid.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

typedef struct { uint64_t q[4]; } ymm_t;

static inline void ymm_set(int which, const ymm_t *v) {
    if (which == 0) __asm__ volatile("vmovdqu %0, %%ymm7" :: "m"(*v) : "xmm7");
    else __asm__ volatile("vmovdqu %0, %%ymm7" :: "m"(*v) : "xmm7");
}
static inline void ymm_get(ymm_t *v) { __asm__ volatile("vmovdqu %%ymm7, %0" : "=m"(*v)); }

static volatile int handler_saw_xstate, handler_ran;

static void handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig; (void)si;
    ucontext_t *uc = ctx;
    // Clobber ymm7 completely in the handler
    ymm_t junk = {{0x1111111111111111ull, 0x2222222222222222ull, 0x3333333333333333ull, 0x4444444444444444ull}};
    ymm_set(0, &junk);
    const uint8_t *fp = (const uint8_t *)uc->uc_mcontext.fpregs;
    uint32_t magic1, ext;
    memcpy(&magic1, fp + 464, 4);
    memcpy(&ext, fp + 468, 4);
    uint32_t magic2 = 0;
    if (magic1 == 0x46505853 && ext > 4 && ext < 8192) memcpy(&magic2, fp + ext - 4, 4);
    handler_saw_xstate = (uc->uc_flags & 1) && magic1 == 0x46505853 && magic2 == 0x46505845;
    handler_ran = 1;
}

static volatile int stop;
static int thread_bad;
static void *worker(void *arg) {
    uint64_t seed = (uint64_t)(uintptr_t)arg * 0x9E3779B97F4A7C15ull;
    ymm_t v = {{seed, seed + 1, seed + 2, seed + 3}}, got;
    ymm_set(0, &v);
    while (!stop) {
        for (volatile int i = 0; i < 20000; i++) {}
        syscall(SYS_getpid);            // a system call
        sched_yield();                  // a task switch
        ymm_get(&got);
        if (memcmp(&got, &v, sizeof v)) { thread_bad = 1; break; }
    }
    return NULL;
}

int main(void) {
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    int cpu_avx = (c >> 28) & 1, osxsave = (c >> 27) & 1;
    printf("cpu AVX %d, OSXSAVE %d\n", cpu_avx, osxsave);
    if (!cpu_avx) {
        printf("no AVX on this CPU: nothing to test\nAVX TEST PASSED\n");
        return 0;
    }
    CHECK(osxsave, "the OS enabled XSAVE (CPUID.1:ECX.OSXSAVE)");
    if (!osxsave) { printf("AVX TEST FAILED\n"); return 1; }
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    CHECK((lo & 6) == 6, "XCR0 enables SSE and AVX (XCR0 = %#x)", lo);

    // Across system calls and task switches, several threads at once
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], NULL, worker, (void *)(uintptr_t)(i + 1));
    ymm_t v = {{0xA5A5A5A5A5A5A5A5ull, 0x0123456789ABCDEFull, 0xFEDCBA9876543210ull, 0x5A5A5A5A5A5A5A5Aull}}, got;
    ymm_set(0, &v);
    int main_bad = 0;
    for (int k = 0; k < 2000; k++) {
        syscall(SYS_getpid);
        sched_yield();
        ymm_get(&got);
        if (memcmp(&got, &v, sizeof v)) { main_bad = 1; break; }
    }
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
    CHECK(!main_bad && !thread_bad, "ymm7 kept across system calls and task switches (5 threads)");

    // Across a signal whose handler overwrites ymm7
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    ymm_set(0, &v);
    raise(SIGUSR1);
    ymm_get(&got);
    CHECK(handler_ran, "the handler ran");
    CHECK(!memcmp(&got, &v, sizeof v), "sigreturn restored ymm7 the handler overwrote (%016llx %016llx)",
          (unsigned long long)got.q[2], (unsigned long long)got.q[3]);
    CHECK(handler_saw_xstate, "the signal frame holds XSAVE state (UC_FP_XSTATE, magic 1 and 2)");

    printf("%s\n", fails ? "AVX TEST FAILED" : "AVX TEST PASSED");
    return fails != 0;
}
