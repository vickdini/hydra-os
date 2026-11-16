// /proc/<pid>/cmdline is read from the process's memory, as Linux does: a program that
// rewrites its argument strings is shown with the new ones. Wine puts the Windows program's
// path there (KDE's taskbar tells programs apart by it: all Wine windows were one button);
// setproctitle overwrites the final NUL and runs on into the environment.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static int read_file(const char *path, char *buf, int size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = 0, r;
    while (n < size && (r = read(fd, buf + n, size - n)) > 0) n += r;
    close(fd);
    return n;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        // Re-run with arguments to rewrite
        execl("/proc/self/exe", argv[0], "first-argument", "second", (char *)NULL);
        perror("exec");
        return 1;
    }
    char buf[8192];
    int n = read_file("/proc/self/cmdline", buf, sizeof buf);
    CHECK(n > 0 && strcmp(buf + strlen(buf) + 1, "first-argument") == 0, "cmdline before: the original arguments");

    // Wine: the new text over the old area, the rest zeroed
    char *area = argv[0];
    size_t len = (size_t)(argv[argc - 1] + strlen(argv[argc - 1]) + 1 - area);
    const char newargs[] = "Z:\\home\\user\\putty.exe";
    memset(area, 0, len);
    memcpy(area, newargs, sizeof newargs);
    n = read_file("/proc/self/cmdline", buf, sizeof buf);
    CHECK(n == (int)len, "cmdline is the whole argument area (%d bytes, want %zu)", n, len);
    CHECK(n > 0 && strcmp(buf, newargs) == 0, "cmdline shows the rewritten text (%s)", n > 0 ? buf : "");

    // Another process reads it the same way
    pid_t parent = getpid();
    pid_t c = fork();
    if (c == 0) {
        char path[64], b[512];
        snprintf(path, sizeof path, "/proc/%d/cmdline", parent);
        int m = read_file(path, b, sizeof b);
        _exit(m > 0 && strcmp(b, newargs) == 0 ? 0 : 1);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "another process reads the rewritten cmdline");

    // A forked child has the same arguments until it changes them
    c = fork();
    if (c == 0) {
        int m = read_file("/proc/self/cmdline", buf, sizeof buf);
        _exit(m > 0 && strcmp(buf, newargs) == 0 ? 0 : 1);
    }
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a forked child shows the parent's rewritten arguments");

    // setproctitle: the final NUL overwritten, the title runs on into the environment
    memset(area, 'x', len);
    n = read_file("/proc/self/cmdline", buf, sizeof buf);
    CHECK(n >= (int)len && memchr(buf, 0, n) == buf + n - 1, "without the final NUL: the text up to the first NUL (%d bytes)", n);

    printf("%s\n", fails ? "CMDLINE TEST FAILED" : "CMDLINE TEST PASSED");
    return fails != 0;
}
