/* Segments for 32-bit code in a 64-bit process, as Wine's WoW64 mode uses them:
 * Linux's selector layout, set_thread_area/get_thread_area, modify_ldt, arch_prctl FS/GS,
 * MAP_32BIT, far jumps to the 32-bit code segment, and the per-thread state surviving
 * context switches and signals. Runs on Linux too (expected results are Linux's).
 * Build: gcc -O1 -w -pthread segtest.c -o segtest.elf */
#define _GNU_SOURCE
#include <asm/ldt.h>
#include <asm/prctl.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

#define RD(seg) ({ unsigned short v; __asm__ volatile("mov %%" #seg ", %0" : "=r"(v)); v; })

static long arch_prctl_(int code, unsigned long addr) { return syscall(SYS_arch_prctl, code, addr); }
/* set_thread_area and get_thread_area exist only in the 32-bit table: int $0x80 with the
 * i386 numbers, as Wine calls them. The descriptor must be below 4 GiB (ebx). */
static struct user_desc *ud;          /* in low memory */
static int int80_at(int nr, struct user_desc *d, struct user_desc *lowbuf) {
    int ret;
    *lowbuf = *d;
    __asm__ volatile("int $0x80" : "=a"(ret) : "0"(nr), "b"(lowbuf) : "memory");
    *d = *lowbuf;
    if (ret < 0) { errno = -ret; return -1; }
    return ret;
}
static int set_ta(struct user_desc *d) { return int80_at(243, d, ud); }
static int get_ta(struct user_desc *d) { return int80_at(244, d, ud); }
/* modify_ldt returns an int in the low half of rax (errors too), as on Linux */
static int mldt(int f, void *p, unsigned long n) { return (int)syscall(SYS_modify_ldt, f, p, n); }

static struct user_desc data32(unsigned entry, uint32_t base, uint32_t limit) {
    struct user_desc d;
    memset(&d, 0, sizeof d);
    d.entry_number = entry;
    d.base_addr = base;
    d.limit = limit;
    d.seg_32bit = 1;
    d.useable = 1;
    return d;
}

/* ---- 32-bit code, copied below 2 GiB before use ----
 * go32(area): rdi = area (below 2 GiB). Saves rsp in area[0], switches to a stack at
 * area+0x1000, loads ds/es = ss, far-returns into the 32-bit segment 0x23, and there:
 *   mode 0 (area[16]): eax = gs:[0] + 5, stored at area[8] through ds
 *   mode 1: spin until area[12] != 0 (a signal handler sets it), eax = 0x77
 *   mode 2: syscall from 32-bit code (Intel: #UD; AMD: -ENOSYS)
 * then far-returns to 64-bit code (0x33) and returns eax. */
__asm__(".text\n"
        ".globl go32_begin, go32_end, go32_in32\n"
        ".code64\n"
        "go32_begin:\n"
        "  push %rbx\n"
        "  push %rbp\n"
        "  mov %rsp, (%rdi)\n"
        "  lea 0x1000(%rdi), %rsp\n"
        "  mov %ss, %ax\n"
        "  mov %ax, %ds\n"
        "  mov %ax, %es\n"
        "  lea go32_in32(%rip), %rax\n"
        "  lea 9f(%rip), %rbx\n"
        "  pushq $0x23\n"
        "  push %rax\n"
        "  lretq\n"
        ".code32\n"
        "go32_in32:\n"
        "  movl 16(%edi), %ecx\n"
        "  cmpl $1, %ecx\n"
        "  je 2f\n"
        "  cmpl $2, %ecx\n"
        "  je 3f\n"
        "  movl %gs:0, %eax\n"
        "  addl $5, %eax\n"
        "  movl %eax, 8(%edi)\n"
        "  jmp 4f\n"
        "2:\n"
        "  cmpl $0, 12(%edi)\n"
        "  je 2b\n"
        "  movl $0x77, %eax\n"
        "  jmp 4f\n"
        "3:\n"
        "  movl $39, %eax\n"
        "  syscall\n"
        "4:\n"
        "  pushl $0x33\n"
        "  pushl %ebx\n"
        "  lretl\n"
        ".code64\n"
        "9:\n"
        "  mov %edi, %edi\n"
        "  mov (%rdi), %rsp\n"
        "  pop %rbp\n"
        "  pop %rbx\n"
        "  ret\n"
        "go32_end:\n");
extern char go32_begin[], go32_end[], go32_in32[];

static char *low;                     /* MAP_32BIT region: code at +0, areas after */
typedef int (*go32_fn)(void *area);
static go32_fn go32;

static int run32(void *area, int mode) {
    ((volatile int *)area)[4] = mode;
    ((volatile int *)area)[3] = 0;
    return go32(area);
}

/* ---- Signal interrupting 32-bit code ---- */
static volatile unsigned short sig_cs, sig_ss;
static volatile char *sig_area;
static void on_alarm(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    unsigned long csgsfs = uc->uc_mcontext.gregs[REG_CSGSFS];
    sig_cs = csgsfs & 0xffff;
    sig_ss = csgsfs >> 48;
    ((volatile int *)sig_area)[3] = 1;
}

/* ---- Threads: each its own TLS descriptor and GS selector, across switches ---- */
struct worker { int id; uint32_t *cell; int ok; };
static void *worker(void *p) {
    struct worker *w = p;
    struct user_desc d = data32(-1, (uint32_t)(uintptr_t)w->cell, 0xfff);
    if (int80_at(243, &d, ud + 1 + w->id) != 0) return NULL;
    unsigned short sel = d.entry_number << 3 | 3;
    __asm__ volatile("mov %0, %%gs" ::"r"(sel));
    w->ok = 1;
    for (int i = 0; i < 2000; i++) {
        uint32_t v;
        __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
        if (v != (uint32_t)(0x1000 + w->id) || RD(gs) != sel) { w->ok = 0; break; }
        if (i % 50 == 0) usleep(200);
        else sched_yield();
    }
    unsigned short zero = 0;
    __asm__ volatile("mov %0, %%gs" ::"r"(zero));
    return NULL;
}

/* ---- Hostile frames: the kernel must not fault on its way back to user mode ---- */
static void on_usr1_bad_rip(int sig, siginfo_t *si, void *uc_) {
    ucontext_t *uc = uc_;
    /* "return" to 32-bit code at an address above 4 GiB */
    uc->uc_mcontext.gregs[REG_CSGSFS] = (uc->uc_mcontext.gregs[REG_CSGSFS] & ~0xffffull) | 0x23;
    uc->uc_mcontext.gregs[REG_RIP] = 0x100001000ull;
}
static int child_status(void (*fn)(void)) {
    pid_t pid = fork();
    if (pid == 0) { fn(); _exit(0); }
    int st = 0;
    waitpid(pid, &st, 0);
    return st;
}
static int survived_or_segv(int st) {
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) || (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
}
static void bad_sigreturn(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_usr1_bad_rip;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
}
static void ss_tls_cleared(void) {
    struct user_desc d = data32(-1, 0x10000, 0xfffff);
    d.limit_in_pages = 1;
    if (set_ta(&d) != 0) _exit(3);
    unsigned short sel = d.entry_number << 3 | 3;
    __asm__ volatile("mov %0, %%ss" ::"r"(sel));
    struct user_desc clr;
    memset(&clr, 0, sizeof clr);
    clr.entry_number = d.entry_number;
    clr.read_exec_only = 1;
    clr.seg_not_present = 1;
    set_ta(&clr);                     /* int $0x80 returns with ss naming a deleted entry */
    unsigned short ds = 0x2b;
    __asm__ volatile("mov %0, %%ss" ::"r"(ds));
}
static volatile int spin_go;
static void *ldt_deleter(void *p) {
    usleep(30000);
    struct user_desc clr;
    memset(&clr, 0, sizeof clr);
    clr.entry_number = 5;
    clr.read_exec_only = 1;
    clr.seg_not_present = 1;
    mldt(0x11, &clr, sizeof clr);
    spin_go = 1;
    return NULL;
}
static void ss_ldt_deleted(void) {
    struct user_desc l = data32(5, 0x10000, 0xfffff);
    l.limit_in_pages = 1;
    if (mldt(0x11, &l, sizeof l) != 0) _exit(3);
    pthread_t t;
    pthread_create(&t, NULL, ldt_deleter, NULL);
    unsigned short sel = 5 << 3 | 7, ds = 0x2b;
    /* spin in user mode (preempted by ticks) with ss naming the entry being deleted */
    __asm__ volatile("mov %0, %%ss\n1: cmpl $0, %1\n je 1b\n mov %2, %%ss"
                     ::"r"(sel), "m"(spin_go), "r"(ds));
    for (volatile long i = 0; i < 50000000; i++) {}
}

int main(void) {
    char buf[64];

    /* Selector layout */
    check(RD(cs) == 0x33, "64-bit code segment is 0x33");
    check(RD(ss) == 0x2b, "stack segment is 0x2b");

    /* MAP_32BIT */
    low = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    check(low != MAP_FAILED && (uintptr_t)low < 0x80000000u, "MAP_32BIT mapping below 2 GiB");
    if (low == MAP_FAILED || (uintptr_t)low >= 0x80000000u) {
        low = mmap((void *)0x20000000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (low == MAP_FAILED) { printf("FAIL no low memory\n"); return 1; }
    }
    memcpy(low, go32_begin, go32_end - go32_begin);
    go32 = (go32_fn)low;
    ud = (struct user_desc *)(low + 0x9000);
    char *area = low + 0x2000;        /* one 0x1000 stack below area+0x1000 each */
    uint32_t *cells = (uint32_t *)(low + 0x8000);

    /* arch_prctl GS */
    unsigned long base = 0;
    check(arch_prctl_(ARCH_SET_GS, (unsigned long)cells) == 0, "arch_prctl(ARCH_SET_GS)");
    check(arch_prctl_(ARCH_GET_GS, (unsigned long)&base) == 0 && base == (unsigned long)cells, "ARCH_GET_GS returns it");
    cells[0] = 0xabcd;
    uint32_t v;
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0xabcd, "gs:0 reads through the GS base");
    usleep(20000);
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0xabcd, "GS base survives a sleep (context switches)");
    errno = 0;
    check(arch_prctl_(ARCH_SET_GS, 0x800000000000ul) == -1 && errno == EPERM, "ARCH_SET_GS outside user space: EPERM");
    errno = 0;
    check(arch_prctl_(ARCH_SET_FS, 0xffff800000000000ul) == -1 && errno == EPERM, "ARCH_SET_FS outside user space: EPERM");
    arch_prctl_(ARCH_SET_GS, 0);

    /* set_thread_area / get_thread_area: not in the 64-bit table */
    struct user_desc probe = data32(-1, 0, 0xfff);
    errno = 0;
    check(syscall(SYS_set_thread_area, &probe) == -1 && errno == ENOSYS, "64-bit set_thread_area: ENOSYS (as Linux)");
    errno = 0;
    check(syscall(SYS_get_thread_area, &probe) == -1 && errno == ENOSYS, "64-bit get_thread_area: ENOSYS (as Linux)");
    struct user_desc d = data32(-1, (uint32_t)(uintptr_t)&cells[4], 0xfff);
    check(set_ta(&d) == 0 && d.entry_number >= 12 && d.entry_number <= 14, "set_thread_area(-1) picks entry 12-14");
    unsigned ent = d.entry_number;
    struct user_desc g;
    memset(&g, 0, sizeof g);
    g.entry_number = ent;
    check(get_ta(&g) == 0 && g.base_addr == d.base_addr && g.limit == 0xfff && g.seg_32bit && g.useable && !g.seg_not_present,
          "get_thread_area returns it");
    cells[4] = 0x5150;
    unsigned short tsel = ent << 3 | 3;
    __asm__ volatile("mov %0, %%gs" ::"r"(tsel));
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0x5150, "gs = TLS selector reads at its base");
    usleep(20000);
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0x5150 && RD(gs) == tsel, "TLS selector and base survive a sleep");
    /* changing the descriptor refreshes gs at once */
    cells[5] = 0x6160;
    d.base_addr = (uint32_t)(uintptr_t)&cells[5];
    check(set_ta(&d) == 0, "set_thread_area on the entry in use");
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0x6160, "gs follows the changed descriptor");
    unsigned short zero = 0;
    __asm__ volatile("mov %0, %%gs" ::"r"(zero));
    struct user_desc bad = data32(11, 0, 0);
    errno = 0;
    check(set_ta(&bad) == -1 && errno == EINVAL, "set_thread_area entry 11: EINVAL");
    bad = data32(ent, 0, 0);
    bad.seg_32bit = 0;
    bad.limit = 1;
    errno = 0;
    check(set_ta(&bad) == -1 && errno == EINVAL, "16-bit TLS segment: EINVAL");
    bad = data32(ent, 0, 0);
    bad.contents = 2;
    errno = 0;
    check(set_ta(&bad) == -1 && errno == EINVAL, "code TLS segment: EINVAL");
    memset(&g, 0, sizeof g);
    g.entry_number = 15;
    errno = 0;
    check(get_ta(&g) == -1 && errno == EINVAL, "get_thread_area entry 15: EINVAL");
    struct user_desc clr;
    memset(&clr, 0, sizeof clr);
    clr.entry_number = ent;
    clr.read_exec_only = 1;
    clr.seg_not_present = 1;
    check(set_ta(&clr) == 0, "set_thread_area with an empty descriptor clears");
    memset(&g, 0, sizeof g);
    g.entry_number = ent;
    check(get_ta(&g) == 0 && g.base_addr == 0 && g.seg_not_present && g.read_exec_only, "cleared entry reads back empty");

    /* modify_ldt */
    check(mldt(2, buf, sizeof buf) == sizeof buf, "modify_ldt(2) reads the default LDT");
    check(mldt(0, buf, sizeof buf) == 0, "modify_ldt(0) without an LDT reads nothing");
    cells[8] = 0x7170;
    struct user_desc l = data32(3, (uint32_t)(uintptr_t)&cells[8], 0xfff);
    check(mldt(0x11, &l, sizeof l) == 0, "modify_ldt(0x11) sets entry 3");
    memset(buf, 0xff, sizeof buf);
    check(mldt(0, buf, sizeof buf) == sizeof buf, "modify_ldt(0) reads bytecount bytes");
    uint64_t e3;
    memcpy(&e3, buf + 24, 8);
    check((e3 >> 16 & 0xffffff | (e3 >> 56) << 24) == l.base_addr && (e3 >> 45 & 3) == 3 && buf[32] == 0,
          "entry 3 has the base, DPL 3, zero-filled after");
    unsigned short lsel = 3 << 3 | 7;
    __asm__ volatile("mov %0, %%gs" ::"r"(lsel));
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0x7170, "gs = LDT selector reads at its base");
    usleep(20000);
    __asm__ volatile("movl %%gs:0, %0" : "=r"(v));
    check(v == 0x7170 && RD(gs) == lsel, "LDT selector survives a sleep");
    errno = 0;
    check(mldt(0x11, &l, 15) == -EINVAL, "modify_ldt write with bytecount 15: EINVAL");
    l.entry_number = 8192;
    check(mldt(0x11, &l, sizeof l) == -EINVAL, "modify_ldt entry 8192: EINVAL");
    check(mldt(7, &l, sizeof l) == -ENOSYS, "modify_ldt function 7: ENOSYS");

    /* 32-bit code: far jump to 0x23, ds through 0x2b, gs through the LDT, back to 0x33 */
    int r = run32(area, 0);
    check(r == 0x7170 + 5 && *(uint32_t *)(area + 8) == 0x7170 + 5, "32-bit code runs and returns (cs 0x23)");
    check(RD(cs) == 0x33, "back in 64-bit code");
    int all = 1;
    for (int i = 0; i < 300 && all; i++) {
        all = run32(area, 0) == 0x7170 + 5;
        if (i % 30 == 0) usleep(100);
    }
    check(all, "300 round trips through 32-bit code with sleeps between");

    /* A signal while in 32-bit code: the handler runs in 64-bit mode, sees cs 0x23,
     * and the 32-bit code resumes after it */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_alarm;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGALRM, &sa, NULL);
    sig_area = area;
    struct itimerval it = {{0, 0}, {0, 20000}};
    setitimer(ITIMER_REAL, &it, NULL);
    r = run32(area, 1);
    check(r == 0x77, "32-bit code resumes after a signal handler");
    check(sig_cs == 0x23, "signal frame records cs 0x23");
    check(sig_ss == 0x2b, "signal frame records ss 0x2b");

    /* Threads with their own TLS descriptors under the same selector */
    pthread_t th[6];
    struct worker w[6];
    for (int i = 0; i < 6; i++) {
        cells[16 + i] = 0x1000 + i;
        w[i] = (struct worker){i, &cells[16 + i], 0};
        pthread_create(&th[i], NULL, worker, &w[i]);
    }
    all = 1;
    for (int i = 0; i < 6; i++) {
        pthread_join(th[i], NULL);
        all &= w[i].ok;
    }
    check(all, "6 threads keep their own TLS descriptor and gs across switches");

    /* ds survives a context switch (32-bit code needs it) */
    unsigned short uds = 0x2b;
    __asm__ volatile("mov %0, %%ds" ::"r"(uds));
    usleep(20000);
    check(RD(ds) == 0x2b, "ds survives a sleep");

    /* SYSCALL from 32-bit code: Intel raises #UD (SIGILL); AMD returns -ENOSYS */
    pid_t pid = fork();
    if (pid == 0) {
        signal(SIGILL, SIG_DFL);
        _exit(run32(area, 2) == -ENOSYS ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check((WIFSIGNALED(st) && WTERMSIG(st) == SIGILL) || (WIFEXITED(st) && WEXITSTATUS(st) == 0),
          "SYSCALL from 32-bit code: SIGILL or -ENOSYS, kernel unharmed");

    /* A fork keeps the LDT and the TLS descriptors; execve-free child reads them */
    pid = fork();
    if (pid == 0) {
        unsigned short s = 3 << 3 | 7;
        uint32_t x;
        __asm__ volatile("mov %0, %%gs" ::"r"(s));
        __asm__ volatile("movl %%gs:0, %0" : "=r"(x));
        _exit(x == 0x7170 ? 0 : 1);
    }
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork child inherits the LDT");

    check(survived_or_segv(child_status(bad_sigreturn)), "sigreturn to 32-bit code above 4 GiB: SIGSEGV, kernel unharmed");
    check(survived_or_segv(child_status(ss_tls_cleared)), "int $0x80 deleting the TLS entry ss uses: kernel unharmed");
    check(survived_or_segv(child_status(ss_ldt_deleted)), "LDT entry ss uses deleted by another thread: kernel unharmed");

    printf(fails ? "SEGTEST: %d FAILED\n" : "SEGTEST PASSED\n", fails);
    return fails != 0;
}
