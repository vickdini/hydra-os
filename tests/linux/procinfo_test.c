// SIGCHLD siginfo (CLD_EXITED with pid and status even after the child was reaped,
// CLD_KILLED, CLD_STOPPED, CLD_CONTINUED) and the /proc directory (it lists the processes,
// self, and another process's descriptors under /proc/<pid>/fd).
// Build: gcc -O1 -w -o procinfo procinfo_test.c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static volatile int got_code, got_status, got_n;
static volatile pid_t got_pid;
static void on_chld(int s, siginfo_t *si, void *u) {
    got_code = si->si_code;
    got_pid = si->si_pid;
    got_status = si->si_status;
    got_n++;
}

// Unblocks SIGCHLD so a pending one is delivered now
static void deliver(void) {
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &s, NULL);
    sigprocmask(SIG_BLOCK, &s, NULL);
}

static int dir_has(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) found |= !strcmp(e->d_name, name);
    closedir(d);
    return found;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = on_chld;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGCHLD, &sa, NULL);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGCHLD);
    sigprocmask(SIG_BLOCK, &s, NULL);

    // Exit, reaped before the handler runs
    pid_t c = fork();
    if (c == 0) _exit(7);
    int st;
    waitpid(c, &st, 0);
    got_n = 0;
    deliver();
    check(got_n == 1 && got_code == CLD_EXITED && got_pid == c && got_status == 7, "SIGCHLD after reaping: CLD_EXITED, the child's pid, status 7");

    // Killed
    c = fork();
    if (c == 0) {
        pause();
        _exit(0);
    }
    usleep(50000);
    kill(c, SIGKILL);
    waitpid(c, &st, 0);
    got_n = 0;
    deliver();
    check(got_code == CLD_KILLED && got_pid == c && got_status == SIGKILL, "a killed child: CLD_KILLED, status SIGKILL");

    // Stopped and continued
    c = fork();
    if (c == 0) {
        raise(SIGSTOP);
        pause();
        _exit(3);
    }
    waitpid(c, &st, WUNTRACED);
    got_n = 0;
    deliver();
    check(got_code == CLD_STOPPED && got_pid == c && got_status == SIGSTOP, "a stopped child: CLD_STOPPED, status SIGSTOP");
    kill(c, SIGCONT);
    waitpid(c, &st, WCONTINUED);
    usleep(50000); // Linux notifies the parent when the continued child next runs
    got_n = 0;
    deliver();
    if (got_code != CLD_CONTINUED) printf("     (continued: n=%d code=%d pid=%d/%d status=%d)\n", got_n, got_code, got_pid, c, got_status);
    check(got_code == CLD_CONTINUED && got_pid == c && got_status == SIGCONT, "a continued child: CLD_CONTINUED");
    kill(c, SIGKILL);
    waitpid(c, &st, 0);
    deliver();

    // /proc lists processes
    char me[16], ch[16];
    snprintf(me, sizeof me, "%d", getpid());
    int p[2];
    pipe(p);
    c = fork();
    if (c == 0) {
        int fd = open("/dev/null", O_RDONLY);
        dup2(fd, 42);
        close(p[0]);
        write(p[1], "r", 1);
        pause();
        _exit(0);
    }
    char x;
    read(p[0], &x, 1);
    snprintf(ch, sizeof ch, "%d", c);
    check(dir_has("/proc", me) && dir_has("/proc", ch), "readdir(/proc) lists this process and its child");
    check(dir_has("/proc", "self"), "and self");
    char fddir[64];
    snprintf(fddir, sizeof fddir, "/proc/%d/fd", c);
    check(dir_has(fddir, "42"), "/proc/<child>/fd lists the child's own descriptors");
    kill(c, SIGKILL);
    waitpid(c, &st, 0);

    printf(fails ? "PROCINFO TEST FAILED (%d)\n" : "PROCINFO TEST PASSED\n", fails);
    return fails != 0;
}
