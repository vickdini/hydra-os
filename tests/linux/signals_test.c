// Signals and process groups, checked against Linux (run it there first, as root): kill
// permissions and errors, setsid/setpgid rules, sigaction/sigprocmask rules, delivery
// order, queued real-time signals, SA_RESETHAND/SA_NODEFER/sa_mask, the alternate stack,
// sigqueue/rt_sigqueueinfo, and SIGCHLD's no-zombie settings.
// Build: gcc -O1 -w -o signals signals_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int err(long r) {
    return r < 0 ? errno : 0;
}

static void expect_err(long r, int want, const char *what) {
    char line[200];
    int got = err(r);
    snprintf(line, sizeof line, "%s: want %s, got %s", what, want ? strerror(want) : "0", got ? strerror(got) : "0");
    check(got == want, line);
}

// A child that sleeps until killed (as root, in its own process group)
static pid_t sleeper(int own_group) {
    pid_t p = fork();
    if (p == 0) {
        if (own_group) setpgid(0, 0);
        for (;;) pause();
    }
    if (own_group) setpgid(p, p);
    return p;
}

static void reap(pid_t p) {
    kill(p, SIGKILL);
    waitpid(p, NULL, 0);
}

// Runs `f` in a child dropped to uid/gid 65534 (same session); returns its exit code
static int as_nobody(int (*f)(void *), void *arg) {
    pid_t p = fork();
    if (p == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(200);
        _exit(f(arg));
    }
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 201;
}

static int kill_errno(void *arg) {
    pid_t target = *(pid_t *)arg;
    return err(kill(target, SIGTERM));
}

static int cont_errno(void *arg) {
    pid_t target = *(pid_t *)arg;
    return err(kill(target, SIGCONT));
}

static int group_kill_errno(void *arg) {
    pid_t target = *(pid_t *)arg;
    return err(kill(-target, SIGTERM));
}

static int sigqueue_errno(void *arg) {
    pid_t target = *(pid_t *)arg;
    union sigval v = { .sival_int = 1 };
    return err(sigqueue(target, SIGUSR1, v));
}

// ---------------------------------------------------------------- handlers

static volatile int order[8], norder;
static volatile int count_rt;
static volatile int blocked_in_handler;
static volatile int mask_in_handler;
static volatile siginfo_t last_info;
static volatile uintptr_t handler_sp;

static void record(int sig) {
    if (norder < 8) order[norder++] = sig;
}

static void on_rt(int sig) {
    count_rt++;
}

static void on_check_self_blocked(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    blocked_in_handler = sigismember(&cur, sig);
    mask_in_handler = sigismember(&cur, SIGUSR2);
}

static void on_info(int sig, siginfo_t *si, void *uc) {
    memcpy((void *)&last_info, si, sizeof *si);
}

static void on_stack(int sig) {
    int here;
    handler_sp = (uintptr_t)&here;
}

static void on_nothing(int sig) {}

static void set_handler(int sig, void (*h)(int), int flags, int also_mask) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    if (also_mask) sigaddset(&sa.sa_mask, also_mask);
    sigaction(sig, &sa, NULL);
}

int main(void) {
    if (geteuid() != 0) {
        printf("signals: needs root\nSIGNALS TEST FAILED (1)\n");
        return 1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    // ---- kill: arguments
    expect_err(kill(getpid(), 0), 0, "kill(self, 0)");
    expect_err(kill(0x3ffffff0, 0), ESRCH, "kill of a pid that does not exist");
    expect_err(kill(getpid(), 65), EINVAL, "kill with signal 65");
    expect_err(kill(getpid(), -1), EINVAL, "kill with signal -1");
    expect_err(syscall(SYS_tgkill, 0x3ffffff0, getpid(), 0), ESRCH, "tgkill with a wrong tgid");
    expect_err(syscall(SYS_tgkill, getpid(), getpid(), 65), EINVAL, "tgkill with signal 65");
    expect_err(syscall(SYS_tgkill, 0, getpid(), 0), EINVAL, "tgkill with tgid 0");

    // ---- kill: permissions (a process of another user)
    pid_t victim = sleeper(1);
    check(as_nobody(kill_errno, &victim) == EPERM, "an unprivileged user cannot SIGTERM root's process: EPERM");
    check(as_nobody(group_kill_errno, &victim) == EPERM, "nor its process group: EPERM");
    check(as_nobody(cont_errno, &victim) == 0, "SIGCONT to a process in the same session is allowed");
    check(as_nobody(sigqueue_errno, &victim) == EPERM, "sigqueue to root's process: EPERM");
    int st = 0;
    check(waitpid(victim, &st, WNOHANG) == 0, "root's process is still alive");
    reap(victim);

    // A zombie can still be signalled
    pid_t z = fork();
    if (z == 0) _exit(0);
    usleep(100000);
    expect_err(kill(z, 0), 0, "kill(zombie, 0)");
    waitpid(z, NULL, 0);

    // ---- process groups and sessions
    expect_err(getpgid(0x3ffffff0), ESRCH, "getpgid of a pid that does not exist");
    expect_err(setpgid(0, -1), EINVAL, "setpgid with a negative pgid");
    expect_err(setpgid(0x3ffffff0, 0), ESRCH, "setpgid of a process that is not a child");
    pid_t leader = fork();
    if (leader == 0) {
        setpgid(0, 0); // now a group leader
        int r1 = err(setsid());
        _exit(r1);
    }
    waitpid(leader, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == EPERM, "setsid in a process group leader: EPERM");
    // A child in a new session cannot be moved into this session's groups
    int pipefd[2];
    pipe(pipefd);
    pid_t sess = fork();
    if (sess == 0) {
        setsid();
        write(pipefd[1], "x", 1);
        for (;;) pause();
    }
    char c;
    read(pipefd[0], &c, 1);
    expect_err(setpgid(sess, getpgrp()), EPERM, "setpgid of a child that is in another session");
    expect_err(getsid(sess), 0, "getsid of the child");
    check(getsid(sess) == sess, "the child leads its own session");
    reap(sess);

    // ---- sigaction / sigprocmask rules
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_nothing;
    expect_err(sigaction(SIGKILL, &sa, NULL), EINVAL, "sigaction(SIGKILL)");
    expect_err(sigaction(SIGSTOP, &sa, NULL), EINVAL, "sigaction(SIGSTOP)");
    expect_err(syscall(SYS_rt_sigaction, 0, NULL, NULL, 8), EINVAL, "rt_sigaction(0)");
    expect_err(syscall(SYS_rt_sigaction, 65, NULL, NULL, 8), EINVAL, "rt_sigaction(65)");
    expect_err(syscall(SYS_rt_sigaction, SIGUSR1, NULL, NULL, 4), EINVAL, "rt_sigaction with sigsetsize 4");
    expect_err(syscall(SYS_rt_sigprocmask, SIG_BLOCK, NULL, NULL, 4), EINVAL, "rt_sigprocmask with sigsetsize 4");
    expect_err(syscall(SYS_rt_sigprocmask, 7, NULL, NULL, 8), 0, "rt_sigprocmask with a bad how but no set: ignored");
    sigset_t all, cur;
    sigfillset(&all);
    expect_err(syscall(SYS_rt_sigprocmask, 7, &all, NULL, 8), EINVAL, "rt_sigprocmask with a bad how");
    sigprocmask(SIG_SETMASK, &all, &cur);
    sigset_t now;
    sigprocmask(SIG_BLOCK, NULL, &now);
    check(!sigismember(&now, SIGKILL) && !sigismember(&now, SIGSTOP), "SIGKILL and SIGSTOP cannot be blocked");
    sigprocmask(SIG_SETMASK, &cur, NULL);

    // ---- delivery order: lowest number first, standard signals not queued twice
    set_handler(SIGUSR1, record, 0, 0);
    set_handler(SIGUSR2, record, 0, 0);
    sigset_t two;
    sigemptyset(&two);
    sigaddset(&two, SIGUSR1);
    sigaddset(&two, SIGUSR2);
    sigprocmask(SIG_BLOCK, &two, NULL);
    raise(SIGUSR2);
    raise(SIGUSR1);
    raise(SIGUSR1);
    sigset_t pend;
    sigpending(&pend);
    check(sigismember(&pend, SIGUSR1) && sigismember(&pend, SIGUSR2), "sigpending shows both");
    norder = 0;
    sigprocmask(SIG_UNBLOCK, &two, NULL);
    printf("     handler order: %d %d (%d calls)\n", order[0], order[1], norder);
    // (Linux takes SIGUSR1 first but sets up SIGUSR2's frame on top before returning, so
    // SIGUSR2's handler runs first: 12 10. Only "once each" is checked.)
    check(norder == 2 && order[0] != order[1] && (order[0] == SIGUSR1 || order[0] == SIGUSR2) &&
              (order[1] == SIGUSR1 || order[1] == SIGUSR2),
          "two pending standard signals are delivered once each (raised three times)");

    // ---- real-time signals queue
    set_handler(SIGRTMIN, on_rt, 0, 0);
    sigset_t rt;
    sigemptyset(&rt);
    sigaddset(&rt, SIGRTMIN);
    sigprocmask(SIG_BLOCK, &rt, NULL);
    for (int i = 0; i < 3; i++) raise(SIGRTMIN);
    count_rt = 0;
    sigprocmask(SIG_UNBLOCK, &rt, NULL);
    int at_once = count_rt;
    for (int i = 0; i < 4; i++) getppid();
    printf("     SIGRTMIN deliveries: %d before sigprocmask returned, %d after 4 more calls\n", at_once, count_rt);
    check(count_rt == 3, "three SIGRTMIN raised while blocked are delivered three times");

    // ---- queued real-time values, read back in order by sigtimedwait and signalfd
    sigprocmask(SIG_BLOCK, &rt, NULL);
    for (int i = 1; i <= 3; i++) {
        union sigval qv = { .sival_int = 100 + i };
        sigqueue(getpid(), SIGRTMIN, qv);
    }
    int seen_ok = 1;
    for (int i = 1; i <= 3; i++) {
        siginfo_t si;
        struct timespec zero = { 0, 0 };
        int s = sigtimedwait(&rt, &si, &zero);
        seen_ok &= s == SIGRTMIN && si.si_value.sival_int == 100 + i && si.si_code == SI_QUEUE;
    }
    struct timespec zero = { 0, 0 };
    check(seen_ok && sigtimedwait(&rt, NULL, &zero) < 0 && errno == EAGAIN,
          "sigtimedwait takes three queued SIGRTMIN in order, each with its own value, then EAGAIN");
    for (int i = 1; i <= 3; i++) {
        union sigval qv = { .sival_int = 200 + i };
        sigqueue(getpid(), SIGRTMIN, qv);
    }
    int sfd = signalfd(-1, &rt, SFD_NONBLOCK);
    struct signalfd_siginfo recs[4];
    long got = read(sfd, recs, sizeof recs);
    int recs_ok = got == 3 * (long)sizeof recs[0];
    for (int i = 0; recs_ok && i < 3; i++)
        recs_ok = recs[i].ssi_signo == (uint32_t)SIGRTMIN && recs[i].ssi_int == 201 + i && recs[i].ssi_code == SI_QUEUE &&
                  recs[i].ssi_pid == (uint32_t)getpid();
    check(recs_ok, "signalfd reads three queued SIGRTMIN records, each with its value, code and pid");
    close(sfd);
    sigprocmask(SIG_UNBLOCK, &rt, NULL);

    // ---- an ignored pending signal is discarded
    sigprocmask(SIG_BLOCK, &two, NULL);
    raise(SIGUSR1);
    signal(SIGUSR1, SIG_IGN);
    sigpending(&pend);
    check(!sigismember(&pend, SIGUSR1), "setting SIG_IGN discards a pending signal");
    sigprocmask(SIG_UNBLOCK, &two, NULL);

    // ---- handler masks
    set_handler(SIGUSR1, on_check_self_blocked, 0, SIGUSR2);
    raise(SIGUSR1);
    check(blocked_in_handler == 1, "a signal is blocked in its own handler");
    check(mask_in_handler == 1, "sa_mask is blocked in the handler");
    set_handler(SIGUSR1, on_check_self_blocked, SA_NODEFER, 0);
    raise(SIGUSR1);
    check(blocked_in_handler == 0, "SA_NODEFER: not blocked in its own handler");
    set_handler(SIGUSR1, on_nothing, SA_RESETHAND, 0);
    raise(SIGUSR1);
    struct sigaction old;
    sigaction(SIGUSR1, NULL, &old);
    check(old.sa_handler == SIG_DFL, "SA_RESETHAND: back to SIG_DFL after one delivery");
    sigprocmask(SIG_BLOCK, NULL, &now);
    check(!sigismember(&now, SIGUSR1), "the mask is restored after the handler");

    // ---- siginfo from sigqueue
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_info;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &sa, NULL);
    union sigval v = { .sival_int = 4242 };
    sigqueue(getpid(), SIGUSR2, v);
    check(last_info.si_signo == SIGUSR2 && last_info.si_code == SI_QUEUE, "sigqueue: si_code SI_QUEUE");
    check(last_info.si_value.sival_int == 4242, "sigqueue: the value arrives");
    check(last_info.si_pid == getpid() && last_info.si_uid == getuid(), "sigqueue: si_pid and si_uid");
    // rt_sigqueueinfo may not forge a kernel si_code (>= 0) for another process
    pid_t other = sleeper(0);
    siginfo_t fake;
    memset(&fake, 0, sizeof fake);
    fake.si_signo = SIGUSR2;
    fake.si_code = SI_USER;
    expect_err(syscall(SYS_rt_sigqueueinfo, other, SIGUSR2, &fake), EPERM, "rt_sigqueueinfo with si_code SI_USER to another process");
    fake.si_code = SI_QUEUE;
    expect_err(syscall(SYS_rt_sigqueueinfo, other, SIGCONT, &fake), 0, "rt_sigqueueinfo with SI_QUEUE");
    reap(other);

    // ---- alternate signal stack
    stack_t ss;
    memset(&ss, 0, sizeof ss);
    ss.ss_sp = malloc(65536);
    ss.ss_size = 1024;
    expect_err(sigaltstack(&ss, NULL), ENOMEM, "sigaltstack smaller than MINSIGSTKSZ");
    ss.ss_size = 65536;
    ss.ss_flags = 0x1234;
    expect_err(sigaltstack(&ss, NULL), EINVAL, "sigaltstack with bad flags");
    ss.ss_flags = 0;
    expect_err(sigaltstack(&ss, NULL), 0, "sigaltstack");
    set_handler(SIGUSR1, on_stack, SA_ONSTACK, 0);
    raise(SIGUSR1);
    check(handler_sp >= (uintptr_t)ss.ss_sp && handler_sp < (uintptr_t)ss.ss_sp + ss.ss_size, "SA_ONSTACK handler runs on the alternate stack");
    stack_t back;
    sigaltstack(NULL, &back);
    check(back.ss_sp == ss.ss_sp && back.ss_size == ss.ss_size && !(back.ss_flags & SS_ONSTACK), "sigaltstack reads back, not on it now");

    // ---- SIGCHLD settings that prevent zombies
    set_handler(SIGCHLD, on_nothing, SA_NOCLDWAIT, 0);
    pid_t c1 = fork();
    if (c1 == 0) _exit(0);
    usleep(200000);
    expect_err(waitpid(c1, NULL, 0), ECHILD, "SA_NOCLDWAIT: no zombie to wait for");
    signal(SIGCHLD, SIG_IGN);
    pid_t c2 = fork();
    if (c2 == 0) _exit(0);
    usleep(200000);
    expect_err(waitpid(c2, NULL, 0), ECHILD, "SIGCHLD ignored: no zombie to wait for");
    signal(SIGCHLD, SIG_DFL);

    // ---- sigsuspend
    set_handler(SIGUSR1, on_nothing, 0, 0);
    sigprocmask(SIG_BLOCK, &two, NULL);
    raise(SIGUSR1);
    sigset_t none;
    sigemptyset(&none);
    expect_err(sigsuspend(&none), EINTR, "sigsuspend returns EINTR after a handler");
    sigprocmask(SIG_BLOCK, NULL, &now);
    check(sigismember(&now, SIGUSR1), "sigsuspend restores the old mask");

    printf(fails ? "SIGNALS TEST FAILED (%d)\n" : "SIGNALS TEST PASSED\n", fails);
    return fails != 0;
}
