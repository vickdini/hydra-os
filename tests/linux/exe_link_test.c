// /proc/self/exe names the program file itself, every symlink resolved, however the program
// was run: through a link to the file, a link to a directory on the way, a chain of links,
// or a path with "..". Firefox's launcher (/usr/bin/firefox -> ../lib/firefox/firefox) execs
// firefox-bin from the directory /proc/self/exe names.
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

// Runs `path child`, which prints its /proc/self/exe, and returns what it printed
static int run_via(const char *path, char *out, size_t cap) {
    int p[2];
    if (pipe(p)) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[1], 1);
        close(p[0]);
        execl(path, path, "child", (char *)0);
        _exit(127);
    }
    close(p[1]);
    ssize_t n = 0, r;
    while (n < (ssize_t)cap - 1 && (r = read(p[0], out + n, cap - 1 - n)) > 0) n += r;
    out[n] = 0;
    close(p[0]);
    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int main(int argc, char **argv) {
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0) { perror("readlink"); return 1; }
    self[n] = 0;
    if (argc > 1 && !strcmp(argv[1], "child")) {
        fputs(self, stdout);
        return 0;
    }

    // A copy of this program in a directory of its own, reached through links
    char base[] = "/tmp/exelinkXXXXXX";
    if (!mkdtemp(base)) { perror("mkdtemp"); return 1; }
    char real_dir[PATH_MAX], prog[PATH_MAX], cmd[3 * PATH_MAX];
    snprintf(real_dir, sizeof real_dir, "%s/lib/app", base);
    snprintf(cmd, sizeof cmd, "mkdir -p %s %s/bin && cp %s %s/prog", real_dir, base, self, real_dir);
    if (system(cmd)) { printf("FAIL setup\n"); return 1; }
    snprintf(prog, sizeof prog, "%s/prog", real_dir);

    char link[PATH_MAX], got[PATH_MAX];
    // Relative link to the file, as Debian packages install /usr/bin/<program>
    snprintf(link, sizeof link, "%s/bin/prog", base);
    CHECK(symlink("../lib/app/prog", link) == 0, "symlink relative");
    CHECK(run_via(link, got, sizeof got) == 0 && !strcmp(got, prog), "relative link: %s", got);

    // A link to a directory on the way
    snprintf(link, sizeof link, "%s/applink", base);
    CHECK(symlink("lib/app", link) == 0, "symlink dir");
    strcat(link, "/prog");
    CHECK(run_via(link, got, sizeof got) == 0 && !strcmp(got, prog), "directory link: %s", got);

    // A chain: absolute link to a relative one
    snprintf(link, sizeof link, "%s/chain", base);
    char target[PATH_MAX];
    snprintf(target, sizeof target, "%s/bin/prog", base);
    CHECK(symlink(target, link) == 0, "symlink chain");
    CHECK(run_via(link, got, sizeof got) == 0 && !strcmp(got, prog), "chain of links: %s", got);

    // ".." in the path, no link at all
    snprintf(link, sizeof link, "%s/bin/../lib/app/prog", base);
    CHECK(run_via(link, got, sizeof got) == 0 && !strcmp(got, prog), "dot-dot path: %s", got);

    // The plain path
    CHECK(run_via(prog, got, sizeof got) == 0 && !strcmp(got, prog), "plain path: %s", got);

    snprintf(cmd, sizeof cmd, "rm -rf %s", base);
    system(cmd);
    printf("%s\n", fails ? "SOME FAILED" : "ALL PASSED");
    return fails != 0;
}
