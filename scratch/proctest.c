// Hydra M2 process & signal conformance test.
// Build (WSL): gcc -static-pie -O1 -o esp/bin/proctest.elf scratch/proctest.c
// Run in Hydra: linux run proctest.elf
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static int failures;

static void check(const char *name, int ok) {
    printf("[proctest] %-48s %s\n", name, ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) failures++;
}

static volatile sig_atomic_t usr1_count, chld_count, last_sig;
static volatile double fp_in_handler;
static sigjmp_buf segv_env;

static void on_usr1(int sig, siginfo_t *info, void *uc) {
    (void)info; (void)uc;
    usr1_count++;
    last_sig = sig;
    fp_in_handler = 1.5 * sig; // uses SSE inside the handler
}
static void on_chld(int sig) { (void)sig; chld_count++; }
static void on_segv(int sig) { (void)sig; siglongjmp(segv_env, 1); }
static void on_alrm(int sig) { (void)sig; }

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child-exit") == 0) return atoi(argv[2]);

    printf("[proctest] pid=%d ppid=%d\n", getpid(), getppid());

    // 1. Handler delivery with SA_SIGINFO, FPU state preserved around it
    struct sigaction sa = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);
    volatile double x = 3.25;
    kill(getpid(), SIGUSR1);
    check("SIGUSR1 handler runs (kill to self)", usr1_count == 1 && last_sig == SIGUSR1);
    check("FPU state survives handler", x * 2 == 6.5 && fp_in_handler == 15.0);

    // 2. Blocked signal stays pending, delivered on unblock
    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);
    raise(SIGUSR1);
    sigset_t pend;
    sigpending(&pend);
    check("blocked signal is pending, not delivered", usr1_count == 1 && sigismember(&pend, SIGUSR1));
    sigprocmask(SIG_SETMASK, &old, NULL);
    check("unblocking delivers it", usr1_count == 2);

    // 3. SIGSEGV handler recovers with siglongjmp
    signal(SIGSEGV, on_segv);
    int recovered = 0;
    if (sigsetjmp(segv_env, 1) == 0) {
        *(volatile int *)16 = 1;
    } else {
        recovered = 1;
    }
    check("SIGSEGV handler + siglongjmp recovery", recovered);
    char *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    recovered = 0;
    if (sigsetjmp(segv_env, 1) == 0) {
        ro[0] = 1;
    } else {
        recovered = 1;
    }
    check("write to PROT_READ page raises SIGSEGV", recovered);
    signal(SIGSEGV, SIG_DFL);

    // 4. fork + exit status + SIGCHLD + COW isolation
    signal(SIGCHLD, on_chld);
    int shared = 7;
    pid_t c = fork();
    if (c == 0) {
        shared = 99;
        _exit(shared == 99 ? 42 : 1);
    }
    int st = 0;
    pid_t w = waitpid(c, &st, 0);
    check("fork + waitpid exit status 42", w == c && WIFEXITED(st) && WEXITSTATUS(st) == 42);
    check("child writes are copy-on-write", shared == 7);
    check("SIGCHLD delivered to parent", chld_count >= 1);

    // 5. Child killed by a signal
    c = fork();
    if (c == 0) {
        raise(SIGTERM);
        _exit(0);
    }
    waitpid(c, &st, 0);
    check("child killed by SIGTERM reported", WIFSIGNALED(st) && WTERMSIG(st) == SIGTERM);

    // 6. Pipe between processes, EOF when the writer exits
    int p[2];
    pipe(p);
    c = fork();
    if (c == 0) {
        close(p[0]);
        for (int i = 0; i < 1000; i++) write(p[1], "0123456789", 10);
        _exit(0);
    }
    close(p[1]);
    char buf[512];
    long total = 0, n;
    while ((n = read(p[0], buf, sizeof buf)) > 0) total += n;
    close(p[0]);
    waitpid(c, &st, 0);
    check("10000 bytes through a pipe, then EOF", total == 10000 && n == 0);

    // 7. Writing to a pipe with no reader: EPIPE (SIGPIPE ignored)
    signal(SIGPIPE, SIG_IGN);
    pipe(p);
    close(p[0]);
    errno = 0;
    check("write without readers -> EPIPE", write(p[1], "x", 1) == -1 && errno == EPIPE);
    close(p[1]);

    // 8. execve of ourselves with an exit code
    c = fork();
    if (c == 0) {
        char *args[] = {argv[0], "child-exit", "7", NULL};
        execve("/proc/self/exe", args, environ);
        _exit(100 + errno);
    }
    waitpid(c, &st, 0);
    check("fork + execve(/proc/self/exe) exit status 7", WIFEXITED(st) && WEXITSTATUS(st) == 7);

    // 9. vfork-based posix_spawn
    char *args2[] = {argv[0], "child-exit", "9", NULL};
    pid_t sp;
    int rc = posix_spawn(&sp, "/proc/self/exe", NULL, NULL, args2, environ);
    waitpid(sp, &st, 0);
    check("posix_spawn exit status 9", rc == 0 && WIFEXITED(st) && WEXITSTATUS(st) == 9);

    // 10. ECHILD when no children remain
    errno = 0;
    check("wait with no children -> ECHILD", wait(&st) == -1 && errno == ECHILD);

    // 11. Interrupted blocking read: EINTR without SA_RESTART
    struct sigaction al = {0};
    al.sa_handler = on_alrm;
    sigaction(SIGUSR2, &al, NULL);
    pipe(p);
    c = fork();
    if (c == 0) {
        usleep(100000);
        kill(getppid(), SIGUSR2);
        usleep(100000);
        _exit(0);
    }
    errno = 0;
    n = read(p[0], buf, 1);
    check("signal interrupts blocking read with EINTR", n == -1 && errno == EINTR);
    waitpid(c, &st, 0);

    // 12. Job control: stop, continue and kill a child, observed through waitpid
    c = fork();
    if (c == 0) {
        for (;;) pause();
    }
    usleep(100000);
    kill(c, SIGSTOP);
    w = waitpid(c, &st, WUNTRACED);
    check("SIGSTOP: waitpid(WUNTRACED) reports stopped", w == c && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP);
    kill(c, SIGCONT);
    w = waitpid(c, &st, WCONTINUED);
    check("SIGCONT: waitpid(WCONTINUED) reports continued", w == c && WIFCONTINUED(st));
    kill(c, SIGSTOP);
    waitpid(c, &st, WUNTRACED);
    kill(c, SIGKILL);
    w = waitpid(c, &st, 0);
    check("SIGKILL ends a stopped child", w == c && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);

    // 13. A sleep interrupted by a stop resumes and still lasts its full duration
    c = fork();
    if (c == 0) {
        struct timespec t0, t1, req = {1, 0};
        clock_gettime(CLOCK_MONOTONIC, &t0);
        nanosleep(&req, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
        _exit(ms >= 950 ? 0 : 1);
    }
    usleep(200000);
    kill(c, SIGSTOP);
    usleep(300000);
    kill(c, SIGCONT);
    waitpid(c, &st, 0);
    check("stopped nanosleep restarts for the remaining time", WIFEXITED(st) && WEXITSTATUS(st) == 0);

    printf("[proctest] %s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED", failures, failures == 1 ? "" : "s");
    return failures;
}
