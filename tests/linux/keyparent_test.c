// KEYCTL_SESSION_TO_PARENT only reaches a parent running as exactly the caller
// (finding 30 of tests/host/TEST_REPORT.md). Run as root, so the child can become
// another user. Linux: the parent's uid, euid and suid must all equal the caller's
// euid (and gids its egid), or EPERM.
// Build: gcc -static-pie -O1 -w -o keyparent keyparent_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define KEY_SPEC_SESSION_KEYRING -3
#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_SESSION_TO_PARENT 18

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long keyctl(int op, unsigned long a, unsigned long b) {
    return syscall(SYS_keyctl, op, a, b, 0, 0);
}

static long session_id(void) {
    return keyctl(KEYCTL_GET_KEYRING_ID, (unsigned long)KEY_SPEC_SESSION_KEYRING, 1);
}

// Child: become uid/gid `id` (all of real, effective and saved), join a fresh session
// keyring and push it to the parent. Exits with 0 on success, else the errno.
static void child_pushes(uid_t id) {
    if (setresgid(id, id, id) || setresuid(id, id, id)) _exit(100);
    if (keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0) < 0) _exit(101);
    _exit(keyctl(KEYCTL_SESSION_TO_PARENT, 0, 0) == 0 ? 0 : errno);
}

static int run_child(uid_t id) {
    pid_t p = fork();
    if (p == 0) child_pushes(id);
    int st = 0;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

int main(void) {
    if (geteuid() != 0) {
        printf("keyparent: needs root (to make a child of another user)\n");
        printf("KEYPARENT TEST FAILED (1)\n");
        return 1;
    }
    keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0);
    long before = session_id();

    // 1. A child running as another user may not replace root's session keyring
    int r = run_child(65534);
    check(r == EPERM, "a child running as another user gets EPERM");
    check(session_id() == before, "root's session keyring is unchanged");

    // 2. Same for a set-uid parent: real and effective uid 1000, saved uid 0
    pid_t mid = fork();
    if (mid == 0) {
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 0)) _exit(100);
        _exit(run_child(1000));
    }
    int st = 0;
    waitpid(mid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == EPERM, "a set-uid parent (saved uid 0) is refused");

    // 3. A child running as the parent's own user succeeds
    mid = fork();
    if (mid == 0) {
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) _exit(100);
        keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0);
        long mine = session_id();
        int rc = run_child(1000);
        // The parent sees the child's keyring once it next returns to user mode
        _exit(rc == 0 && session_id() != mine ? 0 : 1);
    }
    waitpid(mid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a child of the same user replaces the parent's session keyring");

    printf(fails ? "KEYPARENT TEST FAILED (%d)\n" : "KEYPARENT TEST PASSED\n", fails);
    return fails != 0;
}
