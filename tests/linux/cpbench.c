/* cpbench: the cost of pointer arguments of forwarded calls, measured so that host noise
 * hits every case alike (wave 6, Group 22). Each round times a short burst of every case in
 * turn; per case it prints the minimum and the median over the rounds (ns per call), and the
 * same for its difference to the null forwarded call of the same round.
 *
 *   cpbench [ROUNDS] [BURST]       (defaults 300 rounds of 500 calls)
 *
 * Cases: getpgrp (not forwarded), lx_null (forwarded, no pointer), keyctl (no pointer),
 * keyctl_describe (256-byte buffer out), add_key (two strings and 16 bytes in), and Group
 * 16's VFS-shaped stub calls of a prototype build (stat: a path in, 144 bytes out; read 256
 * and 4096 bytes out), skipped when the kernel does not answer them.
 * Build: gcc -O1 -w cpbench.c -o cpbench
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL_NR 0x6710
static char buf[8192];
static long key;

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static void c_getpgrp(void) { syscall(SYS_getpgrp); }
static void c_lx_null(void) { syscall(LX_NULL_NR, 0); }
static void c_keyctl(void) { syscall(SYS_keyctl, 0, -3, 0); }
static void c_describe(void) { syscall(SYS_keyctl, 6, key, buf, 256); }
static void c_add_key(void) { syscall(SYS_add_key, "user", "cpbench", "0123456789abcdef", 16, -2); }
static void c_stat_stub(void) { syscall(LX_NULL_NR, 0x1605, "/usr/bin/bash", buf); }
static void c_read256_stub(void) { syscall(LX_NULL_NR, 0x1607, buf, 256); }
static void c_read4k_stub(void) { syscall(LX_NULL_NR, 0x1607, buf, 4096); }

struct c { const char *name; void (*fn)(void); int stub; };
static struct c cases[] = {
    {"getpgrp", c_getpgrp, 0}, {"lx_null", c_lx_null, 0}, {"keyctl", c_keyctl, 0},
    {"keyctl_describe", c_describe, 0}, {"add_key", c_add_key, 0},
    {"stat_stub", c_stat_stub, 1}, {"read256_stub", c_read256_stub, 1}, {"read4k_stub", c_read4k_stub, 1},
};
#define NC (sizeof cases / sizeof *cases)

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 300, burst = argc > 2 ? atoi(argv[2]) : 500;
    key = syscall(SYS_add_key, "user", "cpbench", "0123456789abcdef", 16, -2);
    int stubs = syscall(LX_NULL_NR, 0x1605, "/usr/bin/bash", buf) == 0;
    double *t = calloc((size_t)rounds * NC, sizeof(double));
    for (int r = 0; r < rounds; r++)
        for (unsigned k = 0; k < NC; k++) {
            if (cases[k].stub && !stubs) continue;
            uint64_t a = now();
            for (int i = 0; i < burst; i++) cases[k].fn();
            t[r * NC + k] = (double)(now() - a) / burst;
        }
    printf("cpbench: %d rounds of %d calls, stubs %s\n", rounds, burst, stubs ? "on" : "off");
    double *col = calloc(rounds, sizeof(double)), *dif = calloc(rounds, sizeof(double));
    for (unsigned k = 0; k < NC; k++) {
        if (cases[k].stub && !stubs) continue;
        for (int r = 0; r < rounds; r++) {
            col[r] = t[r * NC + k];
            dif[r] = t[r * NC + k] - t[r * NC + 1];
        }
        qsort(col, rounds, sizeof(double), cmp);
        qsort(dif, rounds, sizeof(double), cmp);
        printf("CPB %-16s min %7.0f med %7.0f | minus lx_null: p10 %6.0f med %6.0f\n", cases[k].name, col[0], col[rounds / 2],
               dif[rounds / 10], dif[rounds / 2]);
    }
    printf("CPBENCH-DONE\n");
    return 0;
}
