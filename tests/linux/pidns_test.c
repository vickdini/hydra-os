// PID namespaces: unshare(CLONE_NEWPID) moves later children into the new namespace,
// the first one is its init, init's death empties it, and setns joins one for children.
// Build: gcc -static-pie -O1 -w -o pidns pidns_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static void link_of(pid_t pid, const char *kind, char *out) {
    char p[64];
    // pid 0: the caller itself (its own PID may be an inner one /proc does not show)
    if (pid == 0)
        snprintf(p, sizeof p, "/proc/self/ns/%s", kind);
    else
        snprintf(p, sizeof p, "/proc/%d/ns/%s", pid, kind);
    ssize_t n = readlink(p, out, 63);
    out[n > 0 ? n : 0] = 0;
}

// Runs in a process of its own; the result is its exit status bits
static int unshare_case(void) {
    int bad = 0;
    pid_t me = getpid();
    char pid0[64], pfc[64], now[64];
    link_of(0, "pid", pid0);
    if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0) return 0x7fff;
    link_of(0, "pid", now);
    // Until its init exists the namespace for children cannot be named
    link_of(0, "pid_for_children", pfc);
    if (strcmp(now, pid0) != 0) bad |= 1;    // the caller stays where it is
    if (pfc[0] != 0) bad |= 2;
    if (getpid() != me) bad |= 4;

    int p[2];
    pipe(p);
    pid_t init = fork();
    if (init == 0) {
        // init of the new namespace
        int r = 0;
        if (getpid() != 1) r |= 1;
        if (getppid() != 0) r |= 2;
        pid_t g = fork();
        if (g == 0) _exit(getppid() == 1 && getpid() != 1 ? 0 : 1);
        int st;
        waitpid(g, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) r |= 4;
        char self[68];
        memcpy(self, &r, 4);
        link_of(0, "pid", self + 4);
        write(p[1], self, 68);
        // Stay until told to go (the parent reads before killing)
        pause();
        _exit(r);
    }
    char got[68] = {0};
    read(p[0], got, 68);
    int init_bad;
    memcpy(&init_bad, got, 4);
    const char *inner = got + 4;
    if (init_bad) bad |= 512;                         // init's own checks
    link_of(0, "pid_for_children", pfc);
    if (init <= 1) bad |= 8;                          // the parent sees a real PID
    if (strcmp(inner, pfc) != 0 || strcmp(pfc, pid0) == 0) bad |= 16;  // init lives in pid_for_children
    pid_t second = fork();                            // joins the same namespace
    if (second == 0) _exit(getpid() != 1 && getppid() == 0 ? 0 : 1);
    int st;
    waitpid(second, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) bad |= 32;
    kill(init, SIGKILL);
    waitpid(init, &st, 0);
    if (!WIFSIGNALED(st)) bad |= 64;
    // With its init gone the namespace takes no new processes
    errno = 0;
    pid_t late = fork();
    if (late == 0) _exit(0);
    if (late > 0) {
        waitpid(late, NULL, 0);
        bad |= 128;
    } else if (errno != ENOMEM) {
        bad |= 256;
    }
    return bad;
}

static int setns_case(void) {
    int bad = 0;
    int ready[2], go[2];
    pipe(ready);
    pipe(go);
    pid_t holder = fork();
    if (holder == 0) {
        // Make a namespace with an init in it and keep it alive
        if (unshare(CLONE_NEWUSER | CLONE_NEWPID) != 0) _exit(1);
        pid_t init = fork();
        if (init == 0) {
            char x;
            read(go[0], &x, 1);
            _exit(0);
        }
        write(ready[1], &init, sizeof init);
        waitpid(init, NULL, 0);
        _exit(0);
    }
    pid_t init = 0;
    read(ready[0], &init, sizeof init);
    char p[64], want[64], mine[64];
    link_of(init, "pid", want);
    snprintf(p, sizeof p, "/proc/%d/ns/user", init);
    int ufd = open(p, O_RDONLY);
    snprintf(p, sizeof p, "/proc/%d/ns/pid", init);
    int pfd = open(p, O_RDONLY);
    pid_t h = fork();
    if (h == 0) {
        int r = 0;
        if (setns(ufd, CLONE_NEWUSER) != 0) r |= 1;
        if (setns(pfd, CLONE_NEWPID) != 0) r |= 2;
        link_of(0, "pid", mine);
        char pfc[64];
        link_of(0, "pid_for_children", pfc);
        if (strcmp(pfc, want) != 0) r |= 4;           // children go to the joined namespace
        if (strcmp(mine, want) == 0) r |= 8;          // the caller does not move
        pid_t c = fork();
        if (c == 0) {
            char cl[64];
            link_of(0, "pid", cl);
            _exit(strcmp(cl, want) == 0 && getpid() != 1 && getppid() == 0 ? 0 : 1);
        }
        int st;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) r |= 16;
        _exit(r);
    }
    int st;
    waitpid(h, &st, 0);
    bad = WIFEXITED(st) ? WEXITSTATUS(st) : 0xff;
    write(go[1], "x", 1);
    waitpid(holder, NULL, 0);
    return bad;
}

// Runs `f` in a child process and returns its result bits
static int in_child(int (*f)(void)) {
    int p[2];
    pipe(p);
    pid_t c = fork();
    if (c == 0) {
        int r = f();
        write(p[1], &r, sizeof r);
        _exit(0);
    }
    int r = 0x7fffffff;
    read(p[0], &r, sizeof r);
    waitpid(c, NULL, 0);
    return r;
}

int main(void) {
    int u = in_child(unshare_case);
    if (u == 0x7fff) {
        printf("skip: unshare(CLONE_NEWUSER | CLONE_NEWPID) refused\n");
        return 0;
    }
    check(!(u & 1), "unshare leaves the caller in its PID namespace");
    check(!(u & 2), "pid_for_children unreadable until the namespace has an init");
    check(!(u & 512), "init is PID 1 with parent 0; its child sees parent 1");
    check(!(u & 4), "getpid unchanged after unshare");
    check(!(u & 8), "parent sees the child's outer PID");
    check(!(u & 16), "first child lives in pid_for_children");
    check(!(u & 32), "second child joins the namespace (not init, parent outside)");
    check(!(u & 64), "init killed");
    check(!(u & 128) && !(u & 256), "fork after init died: ENOMEM");
    int s = in_child(setns_case);
    check(!(s & 1), "setns user namespace");
    check(!(s & 2), "setns PID namespace");
    check(!(s & 4), "pid_for_children is the joined namespace");
    check(!(s & 8), "setns leaves the caller's own PID namespace");
    check(!(s & 16), "child created after setns lives in the joined namespace");
    printf(fails ? "PIDNS TEST FAILED (%d)\n" : "PIDNS TEST PASSED\n", fails);
    return fails != 0;
}
