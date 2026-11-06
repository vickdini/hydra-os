// Kernel key retention service: add_key, request_key, keyctl.
// Build: gcc -static-pie -O1 -w -o keys keys_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int key_serial_t;

#define KEY_SPEC_THREAD_KEYRING -1
#define KEY_SPEC_PROCESS_KEYRING -2
#define KEY_SPEC_SESSION_KEYRING -3
#define KEY_SPEC_USER_KEYRING -4
#define KEY_SPEC_USER_SESSION_KEYRING -5

#define KEYCTL_GET_KEYRING_ID 0
#define KEYCTL_JOIN_SESSION_KEYRING 1
#define KEYCTL_UPDATE 2
#define KEYCTL_REVOKE 3
#define KEYCTL_SETPERM 5
#define KEYCTL_DESCRIBE 6
#define KEYCTL_CLEAR 7
#define KEYCTL_LINK 8
#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define KEYCTL_SET_TIMEOUT 15
#define KEYCTL_INVALIDATE 21
#define KEYCTL_MOVE 30
#define KEYCTL_CAPABILITIES 31

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long add_key(const char *type, const char *desc, const void *p, size_t len, key_serial_t ring) {
    return syscall(SYS_add_key, type, desc, p, len, ring);
}
static long request_key(const char *type, const char *desc, const char *info, key_serial_t dest) {
    return syscall(SYS_request_key, type, desc, info, dest);
}
static long keyctl(int op, unsigned long a, unsigned long b, unsigned long c, unsigned long d) {
    return syscall(SYS_keyctl, op, a, b, c, d);
}

int main(void) {
    char buf[512];
    // A fresh anonymous session keyring makes the test independent of the login session
    long ses = keyctl(KEYCTL_JOIN_SESSION_KEYRING, 0, 0, 0, 0);
    check(ses > 0, "join anonymous session keyring");
    check(keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0, 0) == ses, "session keyring id matches");
    check(keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_THREAD_KEYRING, 0, 0, 0) == -1 && errno == ENOKEY,
          "no thread keyring without create: ENOKEY");
    long thr = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_THREAD_KEYRING, 1, 0, 0);
    long proc = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 1, 0, 0);
    check(thr > 0 && proc > 0 && thr != proc, "thread and process keyrings created");
    long usr = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_KEYRING, 0, 0, 0);
    long usrses = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_USER_SESSION_KEYRING, 0, 0, 0);
    check(usr > 0 && usrses > 0 && usr != usrses, "user and user-session keyrings");

    long k = add_key("user", "test:a", "hello", 5, KEY_SPEC_SESSION_KEYRING);
    check(k > 0, "add_key user");
    long n = keyctl(KEYCTL_READ, k, (unsigned long)buf, sizeof buf, 0);
    check(n == 5 && memcmp(buf, "hello", 5) == 0, "read payload");
    check(keyctl(KEYCTL_READ, k, (unsigned long)buf, 2, 0) == 5, "short buffer returns full length");
    check(keyctl(KEYCTL_READ, k, 0, 0, 0) == 5, "null buffer returns length");
    n = keyctl(KEYCTL_DESCRIBE, k, (unsigned long)buf, sizeof buf, 0);
    char want[128];
    snprintf(want, sizeof want, "user;%d;%d;3f010000;test:a", getuid(), getgid());
    check(n > 0 && strcmp(buf, want) == 0, "describe");
    if (n > 0 && strcmp(buf, want) != 0) printf("     got '%s' want '%s'\n", buf, want);

    long k2 = add_key("user", "test:a", "world!", 6, KEY_SPEC_SESSION_KEYRING);
    n = keyctl(KEYCTL_READ, k, (unsigned long)buf, sizeof buf, 0);
    check(k2 == k && n == 6 && memcmp(buf, "world!", 6) == 0, "add_key again updates in place");
    check(keyctl(KEYCTL_UPDATE, k, (unsigned long)"upd", 3, 0) == 0, "update");
    n = keyctl(KEYCTL_READ, k, (unsigned long)buf, sizeof buf, 0);
    check(n == 3 && memcmp(buf, "upd", 3) == 0, "read updated payload");

    check(request_key("user", "test:a", NULL, 0) == k, "request_key finds the key");
    check(request_key("user", "test:none", NULL, 0) == -1 && errno == ENOKEY, "request_key missing: ENOKEY");
    check(keyctl(KEYCTL_SEARCH, KEY_SPEC_SESSION_KEYRING, (unsigned long)"user", (unsigned long)"test:a", 0) == k,
          "search session keyring");
    n = keyctl(KEYCTL_READ, ses, (unsigned long)buf, sizeof buf, 0);
    int found = 0;
    for (int i = 0; i + 4 <= n; i += 4) found |= *(int *)(buf + i) == k;
    check(found, "keyring read lists the key");

    // Nested keyring
    long ring = add_key("keyring", "myring", NULL, 0, KEY_SPEC_SESSION_KEYRING);
    check(ring > 0, "add_key keyring");
    long k3 = add_key("user", "inner", "x", 1, ring);
    check(k3 > 0, "add key into nested keyring");
    check(request_key("user", "inner", NULL, 0) == k3, "request_key searches nested keyrings");
    check(keyctl(KEYCTL_LINK, k3, proc, 0, 0) == 0, "link into process keyring");
    check(keyctl(KEYCTL_UNLINK, k3, ring, 0, 0) == 0, "unlink from nested keyring");
    check(keyctl(KEYCTL_UNLINK, k3, ring, 0, 0) == -1 && errno == ENOENT, "unlink again: ENOENT");
    check(keyctl(KEYCTL_SEARCH, ring, (unsigned long)"user", (unsigned long)"inner", 0) == -1 && errno == ENOKEY,
          "search after unlink: ENOKEY");
    check(request_key("user", "inner", NULL, 0) == k3, "still found through the process keyring");
    check(keyctl(KEYCTL_LINK, ring, ring, 0, 0) == -1 && errno == EDEADLK, "keyring into itself: EDEADLK");
    check(keyctl(KEYCTL_MOVE, k3, proc, ring, 0) == 0, "move between keyrings");
    check(keyctl(KEYCTL_SEARCH, ring, (unsigned long)"user", (unsigned long)"inner", 0) == k3, "moved key found");
    check(keyctl(KEYCTL_CLEAR, ring, 0, 0, 0) == 0, "clear keyring");
    check(keyctl(KEYCTL_READ, ring, (unsigned long)buf, sizeof buf, 0) == 0, "cleared keyring is empty");

    // logon keys
    check(add_key("logon", "nocolon", "p", 1, KEY_SPEC_SESSION_KEYRING) == -1 && errno == EINVAL,
          "logon description needs a prefix");
    long lk = add_key("logon", "svc:pw", "secret", 6, KEY_SPEC_SESSION_KEYRING);
    check(lk > 0, "add logon key");
    check(keyctl(KEYCTL_READ, lk, (unsigned long)buf, sizeof buf, 0) == -1 && errno == EOPNOTSUPP,
          "logon key unreadable: EOPNOTSUPP");
    check(add_key("nosuchtype", "d", "p", 1, KEY_SPEC_SESSION_KEYRING) == -1 && errno == ENODEV,
          "unknown type: ENODEV");
    check(add_key(".internal", "d", "p", 1, KEY_SPEC_SESSION_KEYRING) == -1 && errno == EPERM,
          "dot type: EPERM");

    // Revoke, invalidate, timeout
    long rk = add_key("user", "rev", "r", 1, KEY_SPEC_SESSION_KEYRING);
    check(keyctl(KEYCTL_REVOKE, rk, 0, 0, 0) == 0, "revoke");
    check(keyctl(KEYCTL_READ, rk, (unsigned long)buf, sizeof buf, 0) == -1 && errno == EKEYREVOKED,
          "read revoked: EKEYREVOKED");
    long ik = add_key("user", "inv", "i", 1, KEY_SPEC_SESSION_KEYRING);
    check(keyctl(KEYCTL_INVALIDATE, ik, 0, 0, 0) == 0, "invalidate");
    check(request_key("user", "inv", NULL, 0) == -1 && errno == ENOKEY, "invalidated key gone");
    long tk = add_key("user", "tmo", "t", 1, KEY_SPEC_SESSION_KEYRING);
    check(keyctl(KEYCTL_SET_TIMEOUT, tk, 1, 0, 0) == 0, "set timeout");
    sleep(2);
    check(keyctl(KEYCTL_READ, tk, (unsigned long)buf, sizeof buf, 0) == -1 && errno == EKEYEXPIRED,
          "read expired: EKEYEXPIRED");

    // Permissions: without possessor or user read the key can still be read when possessed
    long pk = add_key("user", "perm", "pp", 2, KEY_SPEC_SESSION_KEYRING);
    check(keyctl(KEYCTL_SETPERM, pk, 0x3d010000, 0, 0) == 0, "setperm");
    check(keyctl(KEYCTL_READ, pk, (unsigned long)buf, sizeof buf, 0) == 2, "possessed key readable");
    check(keyctl(KEYCTL_SETPERM, pk, 0x3f3f3f3f + 0x40, 0, 0) == -1 && errno == EINVAL, "bad perm: EINVAL");

    // Fork: the child shares the session keyring but not the process keyring
    int pfd[2];
    pipe(pfd);
    pid_t c = fork();
    if (c == 0) {
        long r[3];
        r[0] = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0, 0, 0);
        r[1] = keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0, 0, 0);
        r[2] = request_key("user", "test:a", NULL, 0);
        write(pfd[1], r, sizeof r);
        _exit(0);
    }
    long r[3] = {0};
    read(pfd[0], r, sizeof r);
    waitpid(c, NULL, 0);
    check(r[0] == ses, "child inherits the session keyring");
    check(r[1] == -1, "child has no process keyring");
    check(r[2] == k, "child finds the session key");

    // Named session keyring
    long named = keyctl(KEYCTL_JOIN_SESSION_KEYRING, (unsigned long)"hydra-test-ses", 0, 0, 0);
    check(named > 0 && named != ses, "join named session keyring");
    check(request_key("user", "test:a", NULL, 0) == -1 && errno == ENOKEY, "old session's keys out of reach");

    unsigned char caps[4] = {0};
    n = keyctl(KEYCTL_CAPABILITIES, (unsigned long)caps, sizeof caps, 0, 0);
    check(n >= 2, "capabilities");

    FILE *f = fopen("/proc/keys", "r");
    int seen = 0;
    if (f) {
        char line[512], hex[16];
        snprintf(hex, sizeof hex, "%08lx", named);
        while (fgets(line, sizeof line, f)) seen |= strncmp(line, hex, 8) == 0;
        fclose(f);
    }
    check(seen, "/proc/keys lists the session keyring");

    printf(fails ? "KEYS TEST FAILED (%d)\n" : "KEYS TEST PASSED\n", fails);
    return fails != 0;
}
