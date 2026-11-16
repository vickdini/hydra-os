// Register-state stress test: every general register (all 64 bits), the stack pointer,
// ymm0-15, MXCSR, the x87 control word and two x87 stack values must survive
//  - system calls (fast identity calls, calls under the kernel lock, blocking calls that
//    may resume on another CPU), where Linux keeps everything but rax, rcx and r11;
//  - timer preemption and task switches in user mode (spin loops: rcx and r11 kept too);
//  - asynchronous signals at any point, with handlers that clobber every register, use
//    AVX, x87 and SSE, make system calls, and raise nested signals (SA_NODEFER), some on
//    an alternate signal stack;
// while other threads create and join threads (whose initial FPU state must be the
// creator's, not another thread's), fork, and map and unmap memory (TLB shootdowns).
// A signal that interrupts the test loop also checks the interrupted registers in its
// ucontext against the values loaded.
//
// Motivation: KWin once died writing to 0xffff8ae4, a main-thread stack address
// (0x7fffffff8ae4) with its upper 32 bits lost.
//
// Usage: regstress [seconds] [workers]   (default 10 s, 6 workers plus the main thread)
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

// Layout used by the assembly below
struct regset {
    uint64_t g[15];      // 0: rbx rbp r12 r13 r14 r15 rdi rsi rdx r8 r9 r10 rcx r11 rsp
    uint64_t pad;        // 120
    uint8_t ymm[16][32]; // 128
    uint32_t mxcsr;      // 640
    uint16_t fcw;        // 644
    uint16_t pad2;       // 646
    double f0, f1;       // 648, 656
};
_Static_assert(__builtin_offsetof(struct regset, ymm) == 128, "layout");
_Static_assert(__builtin_offsetof(struct regset, mxcsr) == 640, "layout");
_Static_assert(__builtin_offsetof(struct regset, f0) == 648, "layout");

static const char *gname[15] = {"rbx", "rbp", "r12", "r13", "r14", "r15", "rdi", "rsi", "rdx", "r8", "r9", "r10", "rcx", "r11", "rsp"};

// void regtest_avx(const struct regset *in, struct regset *out, long nr, long count)
// nr >= 0: `count` system calls nr with the registers loaded; nr < 0: a spin loop of
// `count` iterations (only rax changes). Then every register is stored to *out.
// regtest_sse: the same with xmm only (no AVX).
#define REGTEST(name, LOADV, STOREV)                                                          \
    __asm__(".text\n.globl " #name "\n" #name ":\n"                                         \
            ".intel_syntax noprefix\n"                                                    \
            "push rbx\npush rbp\npush r12\npush r13\npush r14\npush r15\n"                \
            "push rsi\n" /* [rsp+16] out */                                               \
            "push rdx\n" /* [rsp+8]  nr */                                                \
            "push rcx\n" /* [rsp]    count */                                             \
            "mov [rsi + 14*8], rsp\n" /* the stack pointer the test runs with */           \
            "mov rax, rdi\n"                                                              \
            LOADV                                                                         \
            "ldmxcsr [rax + 640]\n"                                                       \
            "fninit\nfldcw [rax + 644]\n"                                                 \
            "fld qword ptr [rax + 648]\nfld qword ptr [rax + 656]\n"                      \
            "mov rbx, [rax + 0*8]\nmov rbp, [rax + 1*8]\nmov r12, [rax + 2*8]\n"          \
            "mov r13, [rax + 3*8]\nmov r14, [rax + 4*8]\nmov r15, [rax + 5*8]\n"          \
            "mov rdi, [rax + 6*8]\nmov rsi, [rax + 7*8]\nmov rdx, [rax + 8*8]\n"          \
            "mov r8, [rax + 9*8]\nmov r9, [rax + 10*8]\nmov r10, [rax + 11*8]\n"          \
            "mov rcx, [rax + 12*8]\nmov r11, [rax + 13*8]\n"                              \
            "cmp qword ptr [rsp + 8], 0\n"                                                \
            "jl 3f\n"                                                                     \
            ".globl " #name "_sys\n" #name "_sys:\n"                                      \
            "2: mov rax, [rsp + 8]\n"                                                     \
            "syscall\n"                                                                   \
            ".globl " #name "_sysret\n" #name "_sysret:\n"                                \
            "dec qword ptr [rsp]\n"                                                       \
            "jg 2b\n"                                                                     \
            "jmp 4f\n"                                                                    \
            "3: mov rax, [rsp]\n"                                                         \
            ".globl " #name "_spin\n" #name "_spin:\n"                                    \
            "5: dec rax\n"                                                                \
            "jg 5b\n"                                                                     \
            ".globl " #name "_spin_end\n" #name "_spin_end:\n"                            \
            "4: push rax\n" /* [rsp+24] out now */                                        \
            "mov rax, [rsp + 24]\n"                                                       \
            "mov [rax + 0*8], rbx\nmov [rax + 1*8], rbp\nmov [rax + 2*8], r12\n"          \
            "mov [rax + 3*8], r13\nmov [rax + 4*8], r14\nmov [rax + 5*8], r15\n"          \
            "mov [rax + 6*8], rdi\nmov [rax + 7*8], rsi\nmov [rax + 8*8], rdx\n"          \
            "mov [rax + 9*8], r8\nmov [rax + 10*8], r9\nmov [rax + 11*8], r10\n"          \
            "mov [rax + 12*8], rcx\nmov [rax + 13*8], r11\n"                              \
            "pop rcx\n"                                                                   \
            "mov rdx, [rax + 14*8]\n" /* rsp expected */                                  \
            "mov [rax + 15*8], rsp\n" /* pad: rsp seen now */                             \
            STOREV                                                                        \
            "stmxcsr [rax + 640]\n"                                                       \
            "fnstcw [rax + 644]\n"                                                        \
            "fstp qword ptr [rax + 656]\nfstp qword ptr [rax + 648]\n"                    \
            "add rsp, 24\n"                                                               \
            "pop r15\npop r14\npop r13\npop r12\npop rbp\npop rbx\n"                      \
            "ret\n"                                                                       \
            ".att_syntax prefix\n")

#define LOAD_YMM                                                                                  \
    "vmovdqu ymm0, [rax+128+0*32]\nvmovdqu ymm1, [rax+128+1*32]\nvmovdqu ymm2, [rax+128+2*32]\n"     \
    "vmovdqu ymm3, [rax+128+3*32]\nvmovdqu ymm4, [rax+128+4*32]\nvmovdqu ymm5, [rax+128+5*32]\n"     \
    "vmovdqu ymm6, [rax+128+6*32]\nvmovdqu ymm7, [rax+128+7*32]\nvmovdqu ymm8, [rax+128+8*32]\n"     \
    "vmovdqu ymm9, [rax+128+9*32]\nvmovdqu ymm10, [rax+128+10*32]\nvmovdqu ymm11, [rax+128+11*32]\n" \
    "vmovdqu ymm12, [rax+128+12*32]\nvmovdqu ymm13, [rax+128+13*32]\nvmovdqu ymm14, [rax+128+14*32]\n" \
    "vmovdqu ymm15, [rax+128+15*32]\n"
#define STORE_YMM                                                                                 \
    "vmovdqu [rax+128+0*32], ymm0\nvmovdqu [rax+128+1*32], ymm1\nvmovdqu [rax+128+2*32], ymm2\n"     \
    "vmovdqu [rax+128+3*32], ymm3\nvmovdqu [rax+128+4*32], ymm4\nvmovdqu [rax+128+5*32], ymm5\n"     \
    "vmovdqu [rax+128+6*32], ymm6\nvmovdqu [rax+128+7*32], ymm7\nvmovdqu [rax+128+8*32], ymm8\n"     \
    "vmovdqu [rax+128+9*32], ymm9\nvmovdqu [rax+128+10*32], ymm10\nvmovdqu [rax+128+11*32], ymm11\n" \
    "vmovdqu [rax+128+12*32], ymm12\nvmovdqu [rax+128+13*32], ymm13\nvmovdqu [rax+128+14*32], ymm14\n" \
    "vmovdqu [rax+128+15*32], ymm15\nvzeroupper\n"
#define LOAD_XMM                                                                                  \
    "movdqu xmm0, [rax+128+0*32]\nmovdqu xmm1, [rax+128+1*32]\nmovdqu xmm2, [rax+128+2*32]\n"        \
    "movdqu xmm3, [rax+128+3*32]\nmovdqu xmm4, [rax+128+4*32]\nmovdqu xmm5, [rax+128+5*32]\n"        \
    "movdqu xmm6, [rax+128+6*32]\nmovdqu xmm7, [rax+128+7*32]\nmovdqu xmm8, [rax+128+8*32]\n"        \
    "movdqu xmm9, [rax+128+9*32]\nmovdqu xmm10, [rax+128+10*32]\nmovdqu xmm11, [rax+128+11*32]\n"    \
    "movdqu xmm12, [rax+128+12*32]\nmovdqu xmm13, [rax+128+13*32]\nmovdqu xmm14, [rax+128+14*32]\n"  \
    "movdqu xmm15, [rax+128+15*32]\n"
#define STORE_XMM                                                                                 \
    "movdqu [rax+128+0*32], xmm0\nmovdqu [rax+128+1*32], xmm1\nmovdqu [rax+128+2*32], xmm2\n"        \
    "movdqu [rax+128+3*32], xmm3\nmovdqu [rax+128+4*32], xmm4\nmovdqu [rax+128+5*32], xmm5\n"        \
    "movdqu [rax+128+6*32], xmm6\nmovdqu [rax+128+7*32], xmm7\nmovdqu [rax+128+8*32], xmm8\n"        \
    "movdqu [rax+128+9*32], xmm9\nmovdqu [rax+128+10*32], xmm10\nmovdqu [rax+128+11*32], xmm11\n"    \
    "movdqu [rax+128+12*32], xmm12\nmovdqu [rax+128+13*32], xmm13\nmovdqu [rax+128+14*32], xmm14\n"  \
    "movdqu [rax+128+15*32], xmm15\n"

REGTEST(regtest_avx, LOAD_YMM, STORE_YMM);
REGTEST(regtest_sse, LOAD_XMM, STORE_XMM);
void regtest_avx(const struct regset *, struct regset *, long, long);
void regtest_sse(const struct regset *, struct regset *, long, long);
extern char regtest_avx_sys[], regtest_avx_spin[], regtest_avx_spin_end[], regtest_sse_sys[], regtest_sse_spin[], regtest_sse_spin_end[];
extern char regtest_avx_sysret[], regtest_sse_sysret[];

static int have_avx;
static volatile int stop;
static volatile long failures;
static long n_signals, n_nested, n_ctx_checked, n_threads_made, n_forks;
static pthread_mutex_t print_lock = PTHREAD_MUTEX_INITIALIZER;

// What the thread loaded (for the signal handler's ucontext check)
static __thread const struct regset *cur_in;
static __thread volatile int in_test;
static __thread uint64_t rng;
static __thread int tidx;

static uint64_t next(void) {
    uint64_t z = (rng += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static void report(const char *what, int idx, const char *reg, uint64_t want, uint64_t got, long nr) {
    pthread_mutex_lock(&print_lock);
    __atomic_add_fetch(&failures, 1, __ATOMIC_RELAXED);
    if (failures < 40)
        printf("FAIL [%s] worker %d nr %ld %s: want %016llx got %016llx\n", what, idx, nr, reg, (unsigned long long)want,
               (unsigned long long)got);
    fflush(stdout);
    pthread_mutex_unlock(&print_lock);
}

static void fill(struct regset *r, long nr) {
    for (int i = 0; i < 14; i++) r->g[i] = next() | 0x8000000000000000ull >> (i & 7); // high bits set
    // A main-stack-like pointer in some registers (0x7fffffffxxxx)
    r->g[1] = 0x00007fffffff0000ull | (next() & 0xfff8);
    r->g[3] = 0x00007fffffff0000ull | (next() & 0xfff8);
    for (int i = 0; i < 16; i++)
        for (int k = 0; k < 4; k++) {
            uint64_t v = next();
            memcpy(&r->ymm[i][k * 8], &v, 8);
        }
    r->mxcsr = 0x1f80 | ((next() & 3) << 13);         // rounding modes
    r->fcw = (uint16_t)(0x037f & ~(next() & 0x300)); // precision control
    r->f0 = (double)(int64_t)(next() >> 12);
    r->f1 = (double)(int64_t)(next() >> 12) + 0.5;
    if (nr == SYS_nanosleep) {
        static const struct timespec ts = {0, 30000};
        r->g[6] = (uint64_t)&ts; // rdi
        r->g[7] = 0;             // rsi
    } else if (nr == SYS_poll) {
        r->g[6] = 0; // rdi: no fds
        r->g[7] = 0; // rsi
        r->g[8] = 1; // rdx: 1 ms
    }
}

static void compare(const struct regset *in, const struct regset *out, long nr, int sse_only) {
    int n = nr >= 0 ? 12 : 14; // a syscall may change rcx and r11
    for (int i = 0; i < n; i++)
        if (in->g[i] != out->g[i]) report(nr >= 0 ? "syscall" : "spin", tidx, gname[i], in->g[i], out->g[i], nr);
    if (out->g[14] != out->pad) report("rsp", tidx, "rsp", out->g[14], out->pad, nr);
    int len = sse_only ? 16 : 32;
    for (int i = 0; i < 16; i++)
        if (memcmp(in->ymm[i], out->ymm[i], len)) {
            uint64_t w[4], g[4];
            memcpy(w, in->ymm[i], 32);
            memcpy(g, out->ymm[i], 32);
            int k = 0;
            while (k < 3 && w[k] == g[k]) k++;
            char name[16];
            snprintf(name, sizeof name, "ymm%d.q%d", i, k);
            report(nr >= 0 ? "syscall" : "spin", tidx, name, w[k], g[k], nr);
        }
    if (in->mxcsr != (out->mxcsr & ~0x3f)) report("fpu", tidx, "mxcsr", in->mxcsr, out->mxcsr, nr);
    if (in->fcw != (out->fcw | 0x40)) report("fpu", tidx, "fcw", in->fcw, out->fcw, nr);
    if (in->f0 != out->f0 || in->f1 != out->f1) {
        uint64_t a, b;
        memcpy(&a, &in->f0, 8);
        memcpy(&b, &out->f0, 8);
        report("fpu", tidx, "st", a, b, nr);
    }
}

static const long calls[] = {SYS_getpid, SYS_gettid, SYS_getppid, SYS_sched_yield, SYS_getuid, SYS_nanosleep, SYS_poll, SYS_getpriority};

static void run_one(void) {
    struct regset in, out;
    int pick = (int)(next() % 10);
    long nr = pick < 8 ? calls[pick] : -1;
    long count = nr < 0 ? (long)(next() % 200000) + 1 : (long)(next() % 4) + 1;
    fill(&in, nr);
    memset(&out, 0, sizeof out);
    int sse = !have_avx || (next() & 1);
    cur_in = &in;
    in_test = 1;
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    if (sse)
        regtest_sse(&in, &out, nr, count);
    else
        regtest_avx(&in, &out, nr, count);
    __atomic_signal_fence(__ATOMIC_SEQ_CST);
    in_test = 0;
    compare(&in, &out, nr, sse);
}

// ---- signal handlers: clobber everything, use FP, make calls, nest ----

static void clobber(void) {
    // Every vector register and the x87 stack, MXCSR and FCW changed
    if (have_avx)
        __asm__ volatile("vpcmpeqb %%ymm0, %%ymm0, %%ymm0\n"
                         "vmovdqa %%ymm0, %%ymm1\nvmovdqa %%ymm0, %%ymm2\nvmovdqa %%ymm0, %%ymm3\nvmovdqa %%ymm0, %%ymm4\n"
                         "vmovdqa %%ymm0, %%ymm5\nvmovdqa %%ymm0, %%ymm6\nvmovdqa %%ymm0, %%ymm7\nvmovdqa %%ymm0, %%ymm8\n"
                         "vmovdqa %%ymm0, %%ymm9\nvmovdqa %%ymm0, %%ymm10\nvmovdqa %%ymm0, %%ymm11\nvmovdqa %%ymm0, %%ymm12\n"
                         "vmovdqa %%ymm0, %%ymm13\nvmovdqa %%ymm0, %%ymm14\nvmovdqa %%ymm0, %%ymm15\n" ::
                             : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11",
                               "xmm12", "xmm13", "xmm14", "xmm15");
    else
        __asm__ volatile("pcmpeqb %%xmm0, %%xmm0\nmovdqa %%xmm0, %%xmm8\nmovdqa %%xmm0, %%xmm15\n" ::: "xmm0", "xmm8", "xmm15");
    uint32_t m = 0x7f80;
    uint16_t c = 0x0c7f;
    __asm__ volatile("ldmxcsr %0\nfninit\nfldcw %1\nfldpi\nfldpi\nfldpi" ::"m"(m), "m"(c));
    __asm__ volatile("fstp %%st(0)\nfstp %%st(0)\nfstp %%st(0)" ::);
    // General registers: callee-saved ones are restored by the compiler; caller-saved
    // ones are clobbered by these calls
    volatile double x = 1.0;
    for (int i = 0; i < 20; i++) x = x * 1.0001 + 0.5;
}

static void check_ctx(ucontext_t *uc, const char *what) {
    // A signal that interrupted the test loop: its registers must be the loaded ones
    if (!in_test || !cur_in) return;
    uint64_t rip = uc->uc_mcontext.gregs[REG_RIP];
    int spin = (rip >= (uint64_t)regtest_avx_spin && rip <= (uint64_t)regtest_avx_spin_end) ||
               (rip >= (uint64_t)regtest_sse_spin && rip <= (uint64_t)regtest_sse_spin_end);
    int sys = rip == (uint64_t)regtest_avx_sysret || rip == (uint64_t)regtest_sse_sysret; // after `syscall`
    if (!spin && !sys) return;
    static const int map[14] = {REG_RBX, REG_RBP, REG_R12, REG_R13, REG_R14, REG_R15, REG_RDI,
                                REG_RSI, REG_RDX, REG_R8,  REG_R9,  REG_R10, REG_RCX, REG_R11};
    int n = spin ? 14 : 12;
    for (int i = 0; i < n; i++)
        if ((uint64_t)uc->uc_mcontext.gregs[map[i]] != cur_in->g[i])
            report(what, tidx, gname[i], cur_in->g[i], uc->uc_mcontext.gregs[map[i]], spin ? -1 : 0);
    // xmm state in the frame
    struct _libc_fpstate *fp = uc->uc_mcontext.fpregs;
    if (fp) {
        for (int i = 0; i < 16; i++)
            if (memcmp(&fp->_xmm[i], cur_in->ymm[i], 16)) {
                char name[16];
                snprintf(name, sizeof name, "ctx xmm%d", i);
                uint64_t w, g;
                memcpy(&w, cur_in->ymm[i], 8);
                memcpy(&g, &fp->_xmm[i], 8);
                report(what, tidx, name, w, g, spin ? -1 : 0);
            }
        if ((fp->mxcsr & ~0x3f) != cur_in->mxcsr) report(what, tidx, "ctx mxcsr", cur_in->mxcsr, fp->mxcsr, 0);
    }
    __atomic_add_fetch(&n_ctx_checked, 1, __ATOMIC_RELAXED);
}

static void on_usr2(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    (void)si;
    (void)ctx;
    __atomic_add_fetch(&n_nested, 1, __ATOMIC_RELAXED);
    clobber();
    syscall(SYS_getppid);
}

static void on_usr1(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    (void)si;
    int saved = errno;
    check_ctx(ctx, "signal ctx");
    __atomic_add_fetch(&n_signals, 1, __ATOMIC_RELAXED);
    clobber();
    syscall(SYS_getpid);
    if ((rng & 7) == 0) syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2); // nested, at this call's return
    if ((rng & 15) == 1) sched_yield();
    clobber();
    errno = saved;
}

// ---- threads ----

static pid_t tids[64];
static int nworkers;

static void *worker(void *arg) {
    tidx = (int)(intptr_t)arg;
    rng = 0x1234567ull * (tidx + 1);
    tids[tidx] = (pid_t)syscall(SYS_gettid);
    if (tidx & 1) {
        // An alternate signal stack (SIGUSR1 has SA_ONSTACK)
        stack_t ss = {.ss_sp = malloc(65536), .ss_size = 65536, .ss_flags = 0};
        sigaltstack(&ss, NULL);
    }
    while (!stop) run_one();
    return NULL;
}

static void *fresh_thread(void *arg) {
    // A new thread starts with its creator's FPU control state (the creator never
    // changes it from the defaults): MXCSR 0x1f80, FCW 0x037f
    (void)arg;
    uint32_t m;
    uint16_t c;
    __asm__ volatile("stmxcsr %0\nfnstcw %1" : "=m"(m), "=m"(c));
    if ((m & ~0x3f) != 0x1f80) report("new thread", -1, "mxcsr", 0x1f80, m, 0);
    if (c != 0x037f) report("new thread", -1, "fcw", 0x037f, c, 0);
    return NULL;
}

static void *churn(void *arg) {
    (void)arg;
    unsigned k = 0;
    while (!stop) {
        // Thread creation, memory map changes (TLB shootdowns), fork
        pthread_t t;
        if (pthread_create(&t, NULL, fresh_thread, NULL) == 0) {
            pthread_join(t, NULL);
            __atomic_add_fetch(&n_threads_made, 1, __ATOMIC_RELAXED);
        }
        void *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            memset(p, (int)k, 65536);
            mprotect(p, 4096, PROT_READ);
            munmap(p, 65536);
        }
        if (++k % 16 == 0) {
            pid_t c = fork();
            if (c == 0) _exit(0);
            if (c > 0) waitpid(c, NULL, 0);
            __atomic_add_fetch(&n_forks, 1, __ATOMIC_RELAXED);
        }
    }
    return NULL;
}

static void *killer(void *arg) {
    (void)arg;
    uint64_t r = 99;
    pid_t pid = getpid();
    while (!stop) {
        r = r * 6364136223846793005ull + 1442695040888963407ull;
        int w = (int)((r >> 33) % (nworkers + 1));
        if (tids[w]) syscall(SYS_tgkill, pid, tids[w], (r >> 40) % 5 == 0 ? SIGUSR2 : SIGUSR1);
        struct timespec ts = {0, 20000 + (long)((r >> 20) % 200000)};
        nanosleep(&ts, NULL);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 10;
    nworkers = argc > 2 ? atoi(argv[2]) : 6;
    if (nworkers > 60) nworkers = 60;
    unsigned a, b, c, d;
    __cpuid(1, a, b, c, d);
    have_avx = (c >> 28) & 1 && (c >> 27) & 1;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("regstress: %d s, %d workers + main, AVX %d, main stack near %p\n", secs, nworkers, have_avx, (void *)&secs);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    sa.sa_sigaction = on_usr2;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);

    tidx = nworkers; // the main thread is a worker too (its stack is the 0x7fff_ffff_xxxx one)
    rng = 42;
    tids[nworkers] = (pid_t)syscall(SYS_gettid);
    pthread_t w[64], k, ch;
    for (int i = 0; i < nworkers; i++) pthread_create(&w[i], NULL, worker, (void *)(intptr_t)i);
    pthread_create(&k, NULL, killer, NULL);
    pthread_create(&ch, NULL, churn, NULL);
    time_t end = time(NULL) + secs;
    long rounds = 0;
    while (time(NULL) < end && failures < 40) {
        run_one();
        rounds++;
    }
    stop = 1;
    for (int i = 0; i < nworkers; i++) pthread_join(w[i], NULL);
    pthread_join(k, NULL);
    pthread_join(ch, NULL);
    printf("regstress: main rounds %ld, signals %ld, nested %ld, contexts checked %ld, threads %ld, forks %ld\n", rounds,
           n_signals, n_nested, n_ctx_checked, n_threads_made, n_forks);
    printf("%s (%ld failures)\n", failures ? "REGSTRESS FAILED" : "REGSTRESS PASSED", failures);
    return failures != 0;
}
