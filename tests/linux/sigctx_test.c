// The signal frame's machine context as glibc's mcontext_t reads it: for a fault, the CPU
// exception in gregs[REG_TRAPNO] (14 page fault, 0 divide error), its error code in
// gregs[REG_ERR] (bit 1: a write) and the address in gregs[REG_CR2]; uc_mcontext.fpregs
// pointing at the FPU state (MXCSR readable). Wine turns Linux signals into Windows
// exceptions from exactly these: with them one slot off (Hydra before), an access
// violation looked like a divide error and fpregs was NULL.
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static sigjmp_buf back;
static volatile long trapno, err, cr2, mxcsr_ok, fpregs_set, fault_addr;

static void handler(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    ucontext_t *uc = ctx;
    trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
    err = uc->uc_mcontext.gregs[REG_ERR];
    cr2 = uc->uc_mcontext.gregs[REG_CR2];
    fault_addr = (long)si->si_addr;
    fpregs_set = uc->uc_mcontext.fpregs != NULL;
    mxcsr_ok = fpregs_set && (uc->uc_mcontext.fpregs->mxcsr & 0x1f80) == 0x1f80;
    siglongjmp(back, 1);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    // A write to a read-only page
    volatile char *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!sigsetjmp(back, 1)) ro[100] = 1;
    CHECK(trapno == 14, "write fault: trapno 14 (page fault), got %ld", trapno);
    CHECK((err & 2) != 0, "write fault: err has the write bit (err %#lx)", err);
    CHECK(cr2 == (long)(ro + 100) && fault_addr == cr2, "write fault: cr2 and si_addr are the address (%#lx)", cr2);
    CHECK(fpregs_set && mxcsr_ok, "write fault: fpregs points at the FPU state (MXCSR readable)");

    // An integer division by zero
    volatile int zero = 0, x = 7;
    trapno = -1;
    if (!sigsetjmp(back, 1)) x = x / zero;
    CHECK(trapno == 0, "divide error: trapno 0, got %ld", trapno);

    // A signal that is not a fault still has its FPU state
    fpregs_set = 0;
    if (!sigsetjmp(back, 1)) raise(SIGUSR1);
    CHECK(fpregs_set && mxcsr_ok, "raise: fpregs set");

    printf("%s\n", fails ? "SIGCTX TEST FAILED" : "SIGCTX TEST PASSED");
    return fails != 0;
}
