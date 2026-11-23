// llbench: the cost of path calls under Landlock (wave 9, Group 6b-3 budget).
//
//   llbench N     times N rounds of each call, plain and then landlocked (read and write
//                 beneath the test folder, read and execute beneath /usr, /lib), five times
//                 each; prints the best and median ns per call.
//
// Calls: open+close (read), open+close (write), access, mkdir+rmdir, create+unlink,
// rename (there and back).
//
// Build: gcc -O1 -w -pthread tests/linux/llbench.c -o esp/bin/llbench.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct ruleset_attr { uint64_t fs, net; };
struct path_rule { uint64_t allowed; int32_t fd; } __attribute__((packed));

static char T[64];
static int N;

static const char *at(const char *rel) {
    static char b[4][160];
    static int i;
    i = (i + 1) & 3;
    snprintf(b[i], sizeof b[i], "%s/%s", T, rel);
    return b[i];
}

static uint64_t ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

typedef void (*op_fn)(void);
static void op_open_r(void) { close(open(at("f"), O_RDONLY)); }
static void op_open_w(void) { close(open(at("f"), O_WRONLY)); }
static void op_access(void) { access(at("f"), R_OK); }
static void op_mkdir(void) { mkdir(at("d"), 0755); rmdir(at("d")); }
static void op_create(void) { close(open(at("n"), O_CREAT | O_WRONLY, 0644)); unlink(at("n")); }
static void op_rename(void) { rename(at("f"), at("g")); rename(at("g"), at("f")); }

static const struct { const char *name; op_fn f; int calls; } OPS[] = {
    {"open-r", op_open_r, 2}, {"open-w", op_open_w, 2}, {"access", op_access, 1},
    {"mkdir+rmdir", op_mkdir, 2}, {"create+unlink", op_create, 3}, {"rename x2", op_rename, 2},
};

static void run(const char *phase) {
    for (unsigned k = 0; k < sizeof OPS / sizeof OPS[0]; k++) {
        uint64_t t[5];
        for (int r = 0; r < 5; r++) {
            uint64_t a = ns();
            for (int i = 0; i < N; i++) OPS[k].f();
            t[r] = (ns() - a) / ((uint64_t)N * OPS[k].calls);
        }
        qsort(t, 5, sizeof t[0], cmp);
        printf("LLBENCH %s %s best %llu median %llu ns/call\n", phase, OPS[k].name, (unsigned long long)t[0], (unsigned long long)t[2]);
    }
}

static void add(int rs, const char *path, uint64_t rights) {
    struct path_rule pr = {rights, open(path, O_PATH)};
    syscall(445, rs, 1, &pr, 0);
    close(pr.fd);
}

int main(int argc, char **argv) {
    N = argc > 1 ? atoi(argv[1]) : 2000;
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(T, sizeof T, "/tmp/llb.%d", getpid());
    mkdir(T, 0755);
    close(open(at("f"), O_CREAT | O_WRONLY, 0644));
    run("plain");
    uint64_t fs = (1ULL << 15) - 1;
    struct ruleset_attr ra = {fs, 0};
    int rs = syscall(444, &ra, sizeof ra, 0);
    add(rs, T, fs);
    add(rs, "/usr", (1 << 0) | (1 << 2) | (1 << 3));
    add(rs, "/lib", (1 << 0) | (1 << 2) | (1 << 3));
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall(446, rs, 0) < 0) {
        printf("restrict_self: %s\n", strerror(errno));
        return 1;
    }
    run("landlocked");
    unlink(at("f"));
    rmdir(T);
    printf("LLBENCH DONE\n");
    return 0;
}
