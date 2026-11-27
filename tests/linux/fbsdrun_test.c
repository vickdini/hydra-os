/*
 * fbsdrun: FreeBSD programs in the FreeBSD root (microkernel wave 12, Group FK): the
 * milestones of docs/personality-design.md 4.6 that the kernel side reaches.
 *
 *   fbsdrun [DIR]    (as root: it chroots; DIR holds fbrawsys and fbsdthr, default /tmp)
 *
 * The FreeBSD root is /freebsd of the Ubuntu root (tools/personality/install-freebsd-root.sh).
 * Without it every check is skipped ("SKIP"), so the suite passes on a pool that has none.
 * Each program runs in a child that chroots into /freebsd, with its output in a pipe:
 *   M1  /tmp/fbrawsys          (static, no C library: raw calls, carry flag)  -> RAWSYS-DONE
 *   M2  /rescue/echo hi        (static, FreeBSD's C library)                  -> "hi"
 *   M3  /bin/echo hi           (dynamic, through /libexec/ld-elf.so.1)        -> "hi"
 *   thr /tmp/fbsdthr           (libthr: threads, mutexes, condition variables, semaphores,
 *                               TLS, SA_SIGINFO + ucontext, sigaltstack, pthread_cancel)
 *                                                                          -> FBSDTHR-DONE 0
 *   M4 (information only, not a failure): /bin/sh -c 'echo $((1+2))'      -> "3"
 * Prints "ok NAME" / "FAIL NAME ..."; last line "FBSDRUN-DONE fails=N" (or "... skipped").
 * Build: gcc -O1 -w -o fbsdrun.elf fbsdrun_test.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ROOT "/freebsd"
static int fails;

/* Runs argv[0] inside ROOT with a timeout; its stdout+stderr in out (NUL-terminated).
 * Returns the wait status, or -1. */
static int run(char *const argv[], char *out, size_t cap, int timeout)
{
    int p[2];
    if (pipe(p) < 0)
        return -1;
    pid_t c = fork();
    if (c == 0) {
        dup2(p[1], 1);
        dup2(p[1], 2);
        close(p[0]);
        close(p[1]);
        if (chroot(ROOT) < 0 || chdir("/") < 0) {
            perror("chroot");
            _exit(126);
        }
        char *envp[] = { "PATH=/sbin:/bin:/usr/sbin:/usr/bin", "HOME=/root", "TERM=dumb", NULL };
        execve(argv[0], argv, envp);
        fprintf(stderr, "execve %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(p[1]);
    size_t n = 0;
    time_t end = time(NULL) + timeout;
    fcntl(p[0], F_SETFL, O_NONBLOCK);
    int st = -1;
    for (;;) {
        ssize_t r = read(p[0], out + n, cap - 1 - n);
        if (r > 0) {
            n += r;
            if (n >= cap - 1)
                n = cap - 2;
            continue;
        }
        if (r == 0)
            break;
        if (time(NULL) > end) {
            kill(c, SIGKILL);
            break;
        }
        usleep(20000);
    }
    out[n] = 0;
    close(p[0]);
    waitpid(c, &st, 0);
    return st;
}

static const char *desc(int st, char *b)
{
    if (st == -1)
        snprintf(b, 64, "not run");
    else if (WIFEXITED(st))
        snprintf(b, 64, "exit %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st))
        snprintf(b, 64, "signal %d", WTERMSIG(st));
    else
        snprintf(b, 64, "status %#x", st);
    return b;
}

static void check(const char *name, int ok, int st, const char *out)
{
    char b[64];
    if (ok) {
        printf("ok %s\n", name);
    } else {
        fails++;
        printf("FAIL %s: %s; output:\n%s\n", name, desc(st, b), out);
    }
}

static int copy(const char *from, const char *to)
{
    int in = open(from, O_RDONLY), out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (in < 0 || out < 0)
        return -1;
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0)
        write(out, buf, n);
    close(in);
    close(out);
    return 0;
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    static char out[65536];
    char path[512];
    setvbuf(stdout, NULL, _IONBF, 0);
    if (access(ROOT "/libexec/ld-elf.so.1", X_OK) != 0) {
        printf("SKIP: no FreeBSD root at " ROOT " (tools/personality/install-freebsd-root.sh)\n");
        printf("FBSDRUN-DONE skipped\n");
        return 0;
    }
    mkdir(ROOT "/tmp", 01777);
    snprintf(path, sizeof path, "%s/fbrawsys", dir);
    copy(path, ROOT "/tmp/fbrawsys");
    snprintf(path, sizeof path, "%s/fbsdthr", dir);
    copy(path, ROOT "/tmp/fbsdthr");

    char *m1[] = { "/tmp/fbrawsys", NULL };
    int st = run(m1, out, sizeof out, 20);
    check("M1 rawsys (static, raw calls)", st == 0 && strstr(out, "RAWSYS-DONE"), st, out);

    char *m2[] = { "/rescue/echo", "hi", NULL };
    st = run(m2, out, sizeof out, 20);
    check("M2 /rescue/echo hi (static, libc)", st == 0 && strcmp(out, "hi\n") == 0, st, out);

    char *m3[] = { "/bin/echo", "hi", NULL };
    st = run(m3, out, sizeof out, 30);
    check("M3 /bin/echo hi (dynamic, rtld)", st == 0 && strcmp(out, "hi\n") == 0, st, out);

    char *th[] = { "/tmp/fbsdthr", NULL };
    st = run(th, out, sizeof out, 60);
    check("threads: fbsdthr (libthr)", st == 0 && strstr(out, "FBSDTHR-DONE 0"), st, out);
    if (st == 0 && strstr(out, "FBSDTHR-DONE 0"))
        printf("%s", out);

    char *m4[] = { "/bin/sh", "-c", "echo $((1+2))", NULL };
    st = run(m4, out, sizeof out, 30);
    char b[64];
    printf("info M4 /bin/sh -c 'echo $((1+2))': %s, output: %s%s", desc(st, b), out, strchr(out, '\n') ? "" : "\n");

    printf("FBSDRUN-DONE fails=%d\n", fails);
    return fails != 0;
}
