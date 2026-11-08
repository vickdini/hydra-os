// The devices Hydra serves by name report their numbers, so glibc's check of a setuid
// program's standard descriptors passes: a closed one is reopened on /dev/null (or
// /dev/full when write-only) and must come back as a character device with the right
// number, or the dynamic loader spins on hlt (the AppImage runtime starts fusermount3 so).
// Build: gcc -O1 -w -o stdfd stdfd_test.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int is_dev(const char *p, unsigned maj, unsigned min) {
    struct stat st;
    int fd = open(p, O_RDONLY);
    int ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == maj && minor(st.st_rdev) == min;
    if (fd >= 0) close(fd);
    struct stat st2;
    return ok && stat(p, &st2) == 0 && st2.st_rdev == st.st_rdev;
}

// A setuid program started with standard descriptor `which` closed
static int setuid_with_closed(const char *prog, int which) {
    pid_t c = fork();
    if (c == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (which != 1) dup2(devnull, 1);
        if (which != 2) dup2(devnull, 2);
        close(devnull);
        close(which);
        execl(prog, prog, "--version", (char *)NULL);
        _exit(9);
    }
    int st = 0;
    waitpid(c, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    check(is_dev("/dev/null", 1, 3), "/dev/null is char 1:3 (fstat and stat)");
    check(is_dev("/dev/zero", 1, 5), "/dev/zero is char 1:5");
    check(is_dev("/dev/full", 1, 7), "/dev/full is char 1:7");
    check(is_dev("/dev/urandom", 1, 9), "/dev/urandom is char 1:9");
    const char *prog = "/usr/bin/fusermount3";
    struct stat st;
    if (stat(prog, &st) == 0 && (st.st_mode & S_ISUID)) {
        for (int i = 0; i < 3; i++) {
            char what[96];
            snprintf(what, sizeof what, "a setuid program starts with descriptor %d closed", i);
            check(setuid_with_closed(prog, i), what);
        }
    } else {
        printf("skip (no setuid %s)\n", prog);
    }
    printf(fails ? "STDFD TEST FAILED (%d)\n" : "STDFD TEST PASSED\n", fails);
    return fails != 0;
}
