/*
 * fbhook: the personality hook's FreeBSD test (microkernel wave 5, Group 14).
 *
 * A static FreeBSD/amd64 program without a C library, run on Hydra's FreeBSD stub table
 * (boot switch persona=fbsd-stub; tests/linux/persona_test.c drives it). It checks what the
 * hook promises a FreeBSD program:
 *   - the entry: rdi = &argc (FreeBSD's exec layout), argv and envp from it;
 *   - the result convention: carry flag clear + value on success, set + POSITIVE FreeBSD
 *     errno on failure (EBADF 9; ENOSYS 78, not Linux's 38);
 *   - the second result in rdx (getpid: the parent's pid), and rdx kept by calls without one;
 *   - FreeBSD numbers (getppid is 39, Linux's getpid), indirect syscall(0)/__syscall(198);
 *   - signals: FreeBSD numbers in sigaction/kill, FreeBSD's signal frame (handler gets
 *     signal 30 = SIGUSR1, a siginfo and a ucontext with mc_len 800) and sigreturn back;
 *   - SIGSYS ignored: an unknown call just fails with ENOSYS.
 * Modes (argv[1]): none = the checks above, then "FBHOOK-DONE" and exit 0 (else exit N at the
 * first failed check N); "nosys" = an unknown call with SIGSYS at its default (killed by
 * SIGSYS); "usr2" = kill(self, 31 SIGUSR2) at its default; "exec" = execve /bin/echo (a
 * Linux program) with "LINUX-AFTER-FREEBSD"; "eintr" = a 3 s nanosleep with a SIGUSR1 handler
 * (the driver sends SIGUSR1): must end with carry + EINTR 4 after the handler ran;
 * "restart" = a 1 s nanosleep (the driver stops and continues the program): must be restarted
 * with FreeBSD's number and end with success.
 *
 * Build (Group 11's build root, clang 15): see tools/personality/build-fbhook.sh.
 */

#define SYS_syscall    0
#define SYS_exit       1
#define SYS_write      4
#define SYS_close      6
#define SYS_getpid     20
#define SYS_kill       37
#define SYS_getppid    39
#define SYS_execve     59
#define SYS___syscall  198
#define SYS_nanosleep  240
#define SYS_sigaction  416
#define SYS_thr_self   432
#define FBSD_EBADF  9
#define FBSD_ENOSYS 78
#define FBSD_SIGSYS  12
#define FBSD_SIGUSR1 30
#define FBSD_SIGUSR2 31
#define SA_SIGINFO 0x40

__attribute__((section(".note.tag"), aligned(4), used))
static const struct {
    unsigned namesz, descsz, type;
    char name[8];
    unsigned desc;
} abi_tag = { 8, 4, 1, "FreeBSD", 1501000 };

struct res { long val; long rdx; long rdi; int carry; };

static struct res sys(long nr, long a, long b, long c, long d, long e)
{
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = 0;
    long rax = nr;
    unsigned char cf;
    __asm__ volatile("syscall; setc %1"
                     : "+a"(rax), "=r"(cf), "+D"(a), "+S"(b), "+d"(c), "+r"(r10), "+r"(r8), "+r"(r9)
                     :
                     : "rcx", "r11", "memory", "cc");
    struct res r = { rax, c, a, cf };
    return r;
}

static long slen(const char *s) { long n = 0; while (s[n]) n++; return n; }
static void say(const char *s) { sys(SYS_write, 1, (long)s, slen(s), 0, 0); }
static void __attribute__((noreturn)) die(int code)
{
    for (;;) sys(SYS_exit, code, 0, 0, 0, 0);
}
static int streq(const char *a, const char *b) { while (*a && *a == *b) a++, b++; return *a == *b; }

struct fsigaction { void *handler; int flags; unsigned mask[4]; };

static volatile int got, gotsig, gotsi;
static volatile long gotlen;

static void handler(int sig, void *si, void *uc)
{
    got++;
    gotsig = sig;
    gotsi = *(int *)si;                            /* si_signo */
    gotlen = *(long *)((char *)uc + 16 + 200);     /* uc_mcontext.mc_len */
}

static void check(int ok, int n, const char *what)
{
    say(ok ? "fbhook: ok   " : "fbhook: FAIL ");
    say(what);
    say("\n");
    if (!ok) die(n);
}

void _start(long *ap) __attribute__((noreturn));
void _start(long *ap)
{
    long argc = ap[0];
    char **argv = (char **)(ap + 1);
    char **envp = argv + argc + 1;
    const char *mode = argc > 1 ? argv[1] : "";

    if (streq(mode, "nosys")) {
        sys(555, 0, 0, 0, 0, 0);
        say("fbhook: still alive after an unknown call (expected SIGSYS)\n");
        die(90);
    }
    if (streq(mode, "usr2")) {
        struct res p = sys(SYS_getpid, 0, 0, 0, 0, 0);
        sys(SYS_kill, p.val, FBSD_SIGUSR2, 0, 0, 0);
        say("fbhook: still alive after SIGUSR2\n");
        die(91);
    }
    if (streq(mode, "exec")) {
        char *nargv[] = { "echo", "LINUX-AFTER-FREEBSD", 0 };
        struct res r = sys(SYS_execve, (long)"/bin/echo", (long)nargv, (long)envp, 0, 0);
        say("fbhook: execve failed\n");
        die(r.carry ? 92 : 93);
    }

    if (streq(mode, "eintr")) {
        struct fsigaction sa = { (void *)handler, SA_SIGINFO, { 0, 0, 0, 0 } };
        sys(SYS_sigaction, FBSD_SIGUSR1, (long)&sa, 0, 0, 0);
        long ts[2] = { 3, 0 };
        struct res r = sys(SYS_nanosleep, (long)ts, 0, 0, 0, 0);
        if (r.carry && r.val == 4 && got == 1 && gotsig == FBSD_SIGUSR1) { say("fbhook: EINTR-OK\n"); die(0); }
        say("fbhook: nanosleep interrupted by a handler did not end with carry + EINTR 4\n");
        die(94);
    }
    if (streq(mode, "restart")) {
        long ts[2] = { 1, 0 };
        struct res r = sys(SYS_nanosleep, (long)ts, 0, 0, 0, 0);
        if (!r.carry && r.val == 0) { say("fbhook: RESTART-OK\n"); die(0); }
        say("fbhook: nanosleep across a stop did not succeed\n");
        die(95);
    }

    check(argc >= 1 && argv[0] != 0 && slen(argv[0]) > 0, 1, "entry: rdi = &argc, argv[0] there");

    const char msg[] = "fbhook: write ok\n";
    struct res r = sys(SYS_write, 1, (long)msg, sizeof msg - 1, 0, 0);
    check(!r.carry && r.val == (long)sizeof msg - 1, 2, "write: carry clear, byte count");

    struct res pid = sys(SYS_getpid, 0, 0, 0x5555, 0, 0);
    struct res ppid = sys(SYS_getppid, 0, 0, 0x7777, 0, 0);
    check(!pid.carry && pid.val > 0, 3, "getpid (20)");
    check(!ppid.carry && ppid.val > 0 && ppid.val != pid.val, 4, "getppid is 39 (Linux's 39 is getpid)");
    check(pid.rdx == ppid.val, 5, "getpid's second result in rdx = the parent");
    check(ppid.rdx == 0x7777, 6, "rdx kept by a call without a second result");

    r = sys(SYS_close, -1, 0, 0, 0, 0);
    check(r.carry && r.val == FBSD_EBADF, 7, "close(-1): carry set, positive EBADF 9");

    r = sys(SYS_syscall, SYS_getpid, 0, 0, 0, 0);
    check(!r.carry && r.val == pid.val && r.rdi == SYS_getpid, 8, "syscall(0) indirect getpid; rdi kept");
    r = sys(SYS___syscall, SYS_getppid, 0, 0, 0, 0);
    check(!r.carry && r.val == ppid.val, 9, "__syscall(198) indirect getppid");

    struct fsigaction ign = { (void *)1, 0, { 0, 0, 0, 0 } };
    r = sys(SYS_sigaction, FBSD_SIGSYS, (long)&ign, 0, 0, 0);
    check(!r.carry && r.val == 0, 10, "sigaction(SIGSYS 12, SIG_IGN)");
    r = sys(555, 1, 2, 3, 4, 5);
    check(r.carry && r.val == FBSD_ENOSYS, 11, "unknown call 555: carry set, FreeBSD ENOSYS 78 (Linux's is 38)");

    long tid = 0;
    r = sys(SYS_thr_self, (long)&tid, 0, 0, 0, 0);
    check(!r.carry && r.val == 0 && tid > 0, 12, "thr_self");

    struct fsigaction sa = { (void *)handler, SA_SIGINFO, { 0, 0, 0, 0 } }, old = { 0, 0, { 0, 0, 0, 0 } };
    r = sys(SYS_sigaction, FBSD_SIGUSR1, (long)&sa, 0, 0, 0);
    check(!r.carry && r.val == 0, 13, "sigaction(SIGUSR1 30, handler, SA_SIGINFO)");
    r = sys(SYS_sigaction, FBSD_SIGUSR1, 0, (long)&old, 0, 0);
    check(!r.carry && old.handler == (void *)handler && (old.flags & SA_SIGINFO), 14, "sigaction reads the action back in FreeBSD's layout");

    r = sys(SYS_kill, pid.val, FBSD_SIGUSR1, 0, 0, 0);
    check(got == 1, 15, "kill(self, 30): the handler ran once (FreeBSD frame, trampoline, sigreturn)");
    check(gotsig == FBSD_SIGUSR1 && gotsi == FBSD_SIGUSR1, 16, "the handler got FreeBSD's number 30 (Linux's SIGUSR1 is 10) in rdi and si_signo");
    check(gotlen == 800, 17, "the ucontext holds FreeBSD's mcontext (mc_len 800)");
    check(!r.carry && r.val == 0, 18, "kill returned 0 with the carry clear after sigreturn");

    long ts[2] = { 0, 1000000 };
    r = sys(SYS_nanosleep, (long)ts, 0, 0, 0, 0);
    check(!r.carry && r.val == 0, 19, "nanosleep (240)");

    say("FBHOOK-DONE\n");
    die(0);
}
