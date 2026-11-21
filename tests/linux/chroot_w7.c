// chroot_w7: chroot(2) as vfs-server serves it (wave 7, Group 7-3). Run as root (sudo).
//   chroot_w7      prints "CHROOT PASS" or "CHROOT FAIL ..."
// Build: gcc -O1 -w -pthread tests/linux/chroot_w7.c -o esp/bin/chroot_w7.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { printf("FAIL " __VA_ARGS__); fails++; } printf("\n"); } while (0)

// Runs f in a child; its exit status (0: passed).
static int child(int (*f)(void)) {
    pid_t p = fork();
    if (p == 0) _exit(f());
    int st;
    waitpid(p, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

static int into_jail(void) {
    if (chroot("/tmp/w7jail") != 0) return 1;
    if (chdir("/") != 0) return 2;
    struct stat st;
    if (stat("/inside", &st) != 0) return 3;        // the jail's file
    if (stat("/w7jail", &st) == 0) return 4;        // the outside is gone
    if (stat("/../../inside", &st) != 0) return 5;  // .. stops at the new root
    return 0;
}

static int without_cap(void) {
    if (setuid(65534) != 0) return 10;
    return chroot("/tmp/w7jail") == -1 && errno == EPERM ? 0 : 11;
}

static int no_search(void) {
    if (setuid(65534) != 0) return 10;
    return 0;
}

int main(void) {
    mkdir("/tmp/w7jail", 0755);
    int fd = open("/tmp/w7jail/inside", O_CREAT | O_WRONLY, 0644);
    close(fd);
    mkdir("/tmp/w7jail/closed", 0700);
    CHECK(child(into_jail) == 0, "chroot into a directory: its files seen, the outside not, .. stays (%d)", child(into_jail));
    CHECK(child(without_cap) == 0, "chroot without CAP_SYS_CHROOT: EPERM");
    CHECK(chroot("/tmp/w7jail/inside") == -1 && errno == ENOTDIR, "chroot to a file: ENOTDIR");
    CHECK(chroot("/tmp/w7jail/none") == -1 && errno == ENOENT, "chroot to nothing: ENOENT");
    CHECK(chroot("") == -1 && errno == ENOENT, "chroot to an empty path: ENOENT");
    CHECK(chroot((char *)1) == -1 && errno == EFAULT, "chroot to a bad pointer: EFAULT");
    // Relative to the working directory
    chdir("/tmp");
    pid_t p = fork();
    if (p == 0) {
        if (chroot("w7jail") != 0) _exit(1);
        struct stat st;
        _exit(stat("/inside", &st) == 0 ? 0 : 2);
    }
    int st;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a relative chroot path");
    (void)no_search;
    printf("CHROOT %s fails=%d\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}
