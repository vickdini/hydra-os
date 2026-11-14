// clone(CLONE_PARENT) makes the new process a sibling of its creator: its parent is the
// creator's parent, which waits for it and gets its SIGCHLD. Firefox's fork server starts
// content processes this way and the main process waits for them; Hydra used to make them
// the fork server's children, so the main process got ECHILD. The init of a PID namespace
// may not use CLONE_PARENT (EINVAL).
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static long raw_clone(unsigned long flags) {
    return syscall(SYS_clone, flags, 0, 0, 0, 0); // fork-like: same stack, copied memory
}

static volatile sig_atomic_t chld;
static void on_chld(int s) { (void)s; chld++; }

int main(void) {
    pid_t me = getpid();
    signal(SIGCHLD, on_chld);
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); return 1; }

    pid_t creator = fork();
    if (creator == 0) {
        // The creator starts a sibling and tells us its pid, then exits
        long sib = raw_clone(CLONE_PARENT | SIGCHLD);
        if (sib == 0) {
            pid_t pp = getppid();
            usleep(300 * 1000); // outlive the creator
            _exit(pp == me ? 42 : 43);
        }
        int v = (int)sib;
        if (write(pipefd[1], &v, sizeof v) != sizeof v) _exit(2);
        // The sibling is not our child
        int st;
        pid_t w = waitpid((pid_t)sib, &st, WNOHANG);
        _exit(sib > 0 && w == -1 && errno == ECHILD ? 0 : 1);
    }
    close(pipefd[1]);
    int sib = 0;
    CHECK(read(pipefd[0], &sib, sizeof sib) == sizeof sib && sib > 0, "the creator made a sibling (%d)", sib);

    int st = 0;
    CHECK(waitpid(creator, &st, 0) == creator && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "the creator cannot wait for its sibling (ECHILD)");
    pid_t w = waitpid(sib, &st, 0);
    CHECK(w == sib, "we wait for the sibling as our child (waitpid %d, errno %d)", (int)w, w < 0 ? errno : 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 42, "the sibling saw us as its parent (status %d)", WEXITSTATUS(st));
    CHECK(chld >= 2, "SIGCHLD for the creator and the sibling (%d)", (int)chld);

    // waitid(P_PID, WEXITED | WNOHANG | WNOWAIT), as Firefox's process watcher asks
    pid_t creator2 = fork();
    if (creator2 == 0) {
        if (raw_clone(CLONE_PARENT | SIGCHLD) == 0) _exit(7);
        _exit(0);
    }
    waitpid(creator2, &st, 0);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    int r = waitid(P_ALL, 0, &si, WEXITED | WNOWAIT);
    pid_t sib2 = si.si_pid;
    CHECK(r == 0 && sib2 > 0 && si.si_status == 7, "waitid sees the second sibling (pid %d status %d)", (int)sib2, si.si_status);
    memset(&si, 0, sizeof si);
    r = waitid(P_PID, sib2, &si, WEXITED | WNOHANG | WNOWAIT);
    CHECK(r == 0 && si.si_pid == sib2, "waitid(P_PID, WNOHANG | WNOWAIT) finds it (r %d errno %d)", r, r ? errno : 0);
    CHECK(waitpid(sib2, &st, 0) == sib2 && WEXITSTATUS(st) == 7, "and waitpid reaps it");

    // A PID namespace's init may not use CLONE_PARENT (needs a user namespace when unprivileged)
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) == 0 || unshare(CLONE_NEWPID) == 0) {
        pid_t init = fork(); // pid 1 of the new namespace
        if (init == 0) {
            long x = raw_clone(CLONE_PARENT | SIGCHLD);
            if (x == 0) _exit(0);
            _exit(x == -1 && errno == EINVAL ? 0 : 1);
        }
        CHECK(waitpid(init, &st, 0) == init && WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "a PID namespace's init gets EINVAL for CLONE_PARENT");
    } else {
        printf("skip PID namespace case: unshare: %s\n", strerror(errno));
    }

    printf("%s\n", fails ? "CLONE_PARENT TEST FAILED" : "CLONE_PARENT TEST PASSED");
    return fails != 0;
}
