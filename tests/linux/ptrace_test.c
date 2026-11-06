// ptrace: TRACEME + exec, syscall stops (changing and cancelling calls), signal stops
// (suppressing and passing), int3, POKEDATA, a breakpoint planted in read-only text,
// single-step, fork/exit events with the child traced too, ATTACH/DETACH with TracerPid,
// SEIZE/INTERRUPT, errors.
// Build: gcc -static-pie -O1 -w -o ptrace_test ptrace_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef __WALL
#define __WALL 0x40000000
#endif

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long pt(long req, pid_t pid, long addr, long data) { return syscall(SYS_ptrace, req, pid, addr, data); }
static long peek(pid_t pid, long addr) {
    long w = 0;
    if (pt(PTRACE_PEEKDATA, pid, addr, (long)&w) != 0) return -1;
    return w;
}

// ---------------------------------------------------------------- the traced child
static volatile long magic = 1;
static volatile int hits;
static void on_sig(int s) { hits |= s == SIGUSR1 ? 1 : 2; }
static int __attribute__((noinline)) target(int x) {
    __asm__ volatile("");
    return x * 3;
}

static int child_main(void) {
    signal(SIGUSR1, on_sig);
    signal(SIGUSR2, on_sig);
    long a = syscall(SYS_getppid);   // the tracer makes this getpid
    long b = syscall(SYS_gettid);    // the tracer cancels this one: 4242
    raise(SIGUSR1);                  // suppressed by the tracer
    raise(SIGUSR2);                  // passed on
    __asm__ volatile("int3" ::"a"(&magic), "b"(target) : "memory");   // tracer: magic = 99, breakpoint in target
    int t = target(5);               // stops at the planted breakpoint; the tracer undoes it
    int bad = 0;
    if (a != getpid()) bad |= 1;
    if (b != 4242) bad |= 2;
    if (hits != 2) bad |= 4;
    if (magic != 99) bad |= 8;
    if (t != 15) bad |= 16;
    pid_t g = fork();
    if (g == 0) _exit(7);
    int st;
    waitpid(g, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) bad |= 32;
    return bad;
}

// ---------------------------------------------------------------- the tracer
static int syscall_op(pid_t p) {
    unsigned char info[88] = {0};
    if (pt(PTRACE_GET_SYSCALL_INFO, p, sizeof info, (long)info) <= 0) return -1;
    return info[0];
}

static void main_trace(void) {
    pid_t c = fork();
    if (c == 0) {
        pt(PTRACE_TRACEME, 0, 0, 0);
        char *argv[] = {"ptrace_test", "--child", NULL};
        execv("/proc/self/exe", argv);
        _exit(127);
    }
    int st;
    pid_t w = waitpid(c, &st, 0);
    check(w == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP, "TRACEME: SIGTRAP stop after exec");
    struct user_regs_struct r;
    check(pt(PTRACE_GETREGS, c, 0, (long)&r) == 0 && r.rip != 0, "GETREGS at the exec stop");
    check(peek(c, r.rsp) == 2, "PEEKDATA reads argc at the new stack");
    check(pt(PTRACE_SETOPTIONS, c, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXIT) == 0, "SETOPTIONS");

    int saw_entry = 0, saw_exit_op = 0, changed = 0, cancelled = 0, cancel_exit = 0, usr1 = 0, usr2 = 0, traps = 0;
    int stepped = 0, bp = 0, fork_ev = 0, gstop = 0, gexit = -1, exit_ev = 0, child_code = -1;
    long target_addr = 0, orig_text = 0;
    pid_t g = 0;
    pid_t resume = c;
    int sig = 0;
    for (int n = 0; n < 5000; n++) {
        // Resume what stopped last (nothing after an exit), then take the next event
        if (resume > 0 && pt(PTRACE_SYSCALL, resume, 0, sig) != 0) break;
        sig = 0;
        resume = 0;
        w = waitpid(-1, &st, __WALL);
        if (w < 0) break;
        if (WIFEXITED(st) || WIFSIGNALED(st)) {
            if (w == c) {
                child_code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                break;
            }
            if (w == g) gexit = WIFEXITED(st) ? WEXITSTATUS(st) : -2;
            continue;
        }
        resume = w;
        int ss = WSTOPSIG(st), ev = st >> 16;
        if (ss == (SIGTRAP | 0x80)) {
            ptrace(PTRACE_GETREGS, w, 0, &r);
            int op = syscall_op(w);
            if (op == 1) saw_entry = 1;
            if (op == 2) saw_exit_op = 1;
            if (w == c && op == 1 && !changed && r.orig_rax == SYS_getppid) {
                r.orig_rax = SYS_getpid;
                ptrace(PTRACE_SETREGS, w, 0, &r);
                changed = 1;
            } else if (w == c && op == 1 && !cancelled && r.orig_rax == SYS_gettid) {
                r.orig_rax = -1;
                ptrace(PTRACE_SETREGS, w, 0, &r);
                cancelled = 1;
            } else if (w == c && op == 2 && cancelled && !cancel_exit) {
                r.rax = 4242;
                ptrace(PTRACE_SETREGS, w, 0, &r);
                cancel_exit = 1;
            }
        } else if (ev == PTRACE_EVENT_FORK) {
            unsigned long m = 0;
            ptrace(PTRACE_GETEVENTMSG, w, 0, &m);
            g = m;
            fork_ev = 1;
        } else if (ev == PTRACE_EVENT_EXIT) {
            unsigned long m = 0;
            ptrace(PTRACE_GETEVENTMSG, w, 0, &m);
            if (w == c) exit_ev = (int)(m >> 8) + 1;
        } else if (ss == SIGSTOP && w != c) {
            gstop = 1;
        } else if (ss == SIGUSR1) {
            siginfo_t si;
            ptrace(PTRACE_GETSIGINFO, w, 0, &si);
            usr1 = si.si_signo == SIGUSR1 ? 1 : -1;
        } else if (ss == SIGUSR2) {
            usr2 = 1;
            sig = SIGUSR2;
        } else if (ss == SIGTRAP && w == c) {
            ptrace(PTRACE_GETREGS, w, 0, &r);
            if (traps++ == 0) {
                // The int3: poke magic, plant a breakpoint in target, then single-step
                ptrace(PTRACE_POKEDATA, w, r.rax, 99);
                target_addr = r.rbx;
                orig_text = peek(w, target_addr);
                ptrace(PTRACE_POKETEXT, w, target_addr, (orig_text & ~0xffL) | 0xcc);
                unsigned long rip0 = r.rip;
                ptrace(PTRACE_SINGLESTEP, w, 0, 0);
                waitpid(w, &st, 0);
                struct user_regs_struct r2;
                ptrace(PTRACE_GETREGS, w, 0, &r2);
                stepped = WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP && r2.rip != rip0;
            } else if (r.rip == (unsigned long)target_addr + 1) {
                // Hit: put the instruction back and run it
                ptrace(PTRACE_POKETEXT, w, target_addr, orig_text);
                r.rip = target_addr;
                ptrace(PTRACE_SETREGS, w, 0, &r);
                bp = 1;
            }
        } else {
            sig = ss == SIGTRAP ? 0 : ss;
        }
    }
    check(saw_entry && saw_exit_op, "syscall entry and exit stops (GET_SYSCALL_INFO)");
    check(changed, "syscall changed at entry (getppid -> getpid)");
    check(cancelled && cancel_exit, "syscall cancelled at entry, result set at exit");
    check(usr1 == 1 && usr2, "signal stops with GETSIGINFO");
    check(stepped, "PTRACE_SINGLESTEP stops after one instruction");
    check(bp, "breakpoint planted in read-only text is hit");
    check(fork_ev && gstop, "fork event; the new child is traced and starts stopped");
    check(gexit == 7, "tracer sees the traced grandchild exit");
    check(exit_ev == 1, "exit event (status 0)");
    check(child_code == 0, "child saw the changed call, the cancelled call, the signals, the poke and the breakpoint");
    if (child_code) printf("     child status %d\n", child_code);
}

static int tracer_pid_of(pid_t p) {
    char path[64], buf[2048];
    snprintf(path, sizeof path, "/proc/%d/status", p);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int t = -1;
    while (fgets(buf, sizeof buf, f))
        if (!strncmp(buf, "TracerPid:", 10)) t = atoi(buf + 10);
    fclose(f);
    return t;
}

static void attach_and_seize(void) {
    pid_t c = fork();
    if (c == 0) {
        for (;;) usleep(1000);
    }
    usleep(20000);
    check(tracer_pid_of(c) == 0, "TracerPid 0 before attaching");
    check(pt(PTRACE_ATTACH, c, 0, 0) == 0, "PTRACE_ATTACH");
    int st;
    pid_t w = waitpid(c, &st, __WALL);
    check(w == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP, "attach stop is SIGSTOP");
    check(tracer_pid_of(c) == getpid(), "TracerPid names the tracer");
    errno = 0;
    check(pt(PTRACE_ATTACH, c, 0, 0) == -1 && errno == EPERM, "second attach: EPERM");
    check(pt(PTRACE_DETACH, c, 0, 0) == 0, "PTRACE_DETACH");
    usleep(20000);
    check(tracer_pid_of(c) == 0, "TracerPid 0 after detaching");

    check(pt(PTRACE_SEIZE, c, 0, PTRACE_O_TRACESYSGOOD) == 0, "PTRACE_SEIZE");
    check(pt(PTRACE_INTERRUPT, c, 0, 0) == 0, "PTRACE_INTERRUPT");
    w = waitpid(c, &st, __WALL);
    check(w == c && WIFSTOPPED(st) && (st >> 16) == PTRACE_EVENT_STOP, "interrupt stop is PTRACE_EVENT_STOP");
    kill(c, SIGKILL);
    w = waitpid(c, &st, __WALL);
    check(w == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "killed tracee is reaped");
}

static void errors(void) {
    errno = 0;
    check(pt(PTRACE_PEEKDATA, getppid(), 0, 0) == -1 && errno == ESRCH, "PEEKDATA on an untraced process: ESRCH");
    errno = 0;
    check(pt(PTRACE_ATTACH, getpid(), 0, 0) == -1 && errno == EPERM, "attaching to oneself: EPERM");
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) return child_main();
    setvbuf(stdout, NULL, _IONBF, 0);
    main_trace();
    attach_and_seize();
    errors();
    printf(fails ? "PTRACE TEST FAILED (%d)\n" : "PTRACE TEST PASSED\n", fails);
    return fails != 0;
}
