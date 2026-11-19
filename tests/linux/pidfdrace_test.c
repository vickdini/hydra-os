// pidfd of a process that ends at once (wave 5, Group 13 follow-up): the pidfd must become
// readable however close the exit comes to pidfd_open, also while other threads fork and
// reap (the process table busy).
// Two bugs made such a pidfd stay unreadable for ever (a GLib child watch on it then waits
// without end):
// - linux-server read the process's state before listing the new pidfd: an exit in
//   between found no pidfd to mark;
// - the kernel answered "still running" for an exited process whenever the process table
//   was busy (`has_exited` gave up at once on a contended lock).
// Build: gcc -O1 -w -pthread -o pidfdrace pidfdrace_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static volatile int stop;

/// Keeps the process table busy: forks children that exit at once and reaps them.
static void *churn(void *arg) {
    (void)arg;
    while (!stop) {
        pid_t c = fork();
        if (c == 0) _exit(0);
        if (c > 0) waitpid(c, NULL, 0);
    }
    return NULL;
}

/// `rounds` children that exit after `spin` loop iterations; each one's pidfd, opened at
/// once, must be readable within 3 s. Returns how many were not.
static int round_of(int rounds, int spin, int *opened) {
    int lost = 0;
    for (int i = 0; i < rounds; i++) {
        pid_t c = fork();
        if (c < 0) {
            perror("fork");
            return lost + 1;
        }
        if (c == 0) {
            for (volatile int k = 0; k < spin; k++) {}
            _exit(7);
        }
        int fd = syscall(SYS_pidfd_open, c, 0);
        if (fd < 0) {
            // (reaped by nobody yet, so it must still exist as a zombie)
            printf("pidfd_open(%d): %s\n", c, strerror(errno));
            lost++;
            waitpid(c, NULL, 0);
            continue;
        }
        (*opened)++;
        struct pollfd p = {fd, POLLIN, 0};
        int r = poll(&p, 1, 3000);
        if (r != 1 || !(p.revents & POLLIN)) {
            printf("child %d: pidfd not readable 3 s after its exit (poll %d revents %#x)\n", c, r, p.revents);
            lost++;
        }
        int st = 0;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 7) {
            printf("child %d: status %#x\n", c, st);
            lost++;
        }
        close(fd);
    }
    return lost;
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 400;
    pthread_t t[2];
    for (int i = 0; i < 2; i++) pthread_create(&t[i], NULL, churn, NULL);
    int opened = 0, lost = 0;
    // From an exit before pidfd_open to one well after it
    int spins[] = {0, 200, 2000, 20000, 200000};
    for (unsigned s = 0; s < sizeof spins / sizeof spins[0]; s++) {
        int l = round_of(rounds, spins[s], &opened);
        printf("spin %d: %d of %d lost\n", spins[s], l, rounds);
        lost += l;
    }
    stop = 1;
    for (int i = 0; i < 2; i++) pthread_join(t[i], NULL);
    char what[96];
    snprintf(what, sizeof what, "every pidfd became readable (%d opened, %d lost)", opened, lost);
    check(lost == 0, what);
    // A zombie's pidfd: readable at once
    pid_t c = fork();
    if (c == 0) _exit(0);
    usleep(100000);
    int fd = syscall(SYS_pidfd_open, c, 0);
    struct pollfd p = {fd, POLLIN, 0};
    check(fd >= 0 && poll(&p, 1, 0) == 1, "a zombie's pidfd is readable at once");
    waitpid(c, NULL, 0);
    close(fd);
    printf("%s\n", fails ? "PIDFDRACE FAILED" : "PIDFDRACE PASSED");
    return fails != 0;
}
