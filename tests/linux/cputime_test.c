// CPU-time accounting: user and system time of the process (getrusage, times,
// /proc/self/stat, CLOCK_PROCESS_CPUTIME_ID) including threads that exited; children's
// time after wait; another process's time in /proc/<pid>/stat; /proc/stat, /proc/uptime
// and /proc/loadavg in the format top and system monitors read.
// Build: gcc -O1 -w -pthread -o cputime cputime_test.c
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static volatile unsigned long sink;
// Spins in user mode for `secs` of wall time
static void burn(double secs) {
    double end = now() + secs;
    unsigned long x = 1;
    while (now() < end)
        for (int i = 0; i < 100000; i++) x = x * 6364136223846793005UL + 1;
    sink = x;
}

static double tv(struct timeval t) { return t.tv_sec + t.tv_usec / 1e6; }

static double self_user(void) {
    struct rusage r;
    getrusage(RUSAGE_SELF, &r);
    return tv(r.ru_utime);
}

// The CPU time a thread or process measured for itself
static double own_cpu(clockid_t clk) {
    struct timespec t;
    clock_gettime(clk, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static double thread_cpu;
static void *thread_burn(void *x) {
    burn(0.4);
    // What it ran (less than 0.4 s if another task shared its CPU meanwhile)
    thread_cpu = own_cpu(CLOCK_THREAD_CPUTIME_ID);
    return NULL;
}

// Fields 14 and 15 of /proc/<pid>/stat (clock ticks)
static int stat_times(int pid, long *ut, long *st) {
    char path[64], buf[1024];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    // After ") ": field 3 onwards; utime is field 14
    long v[20];
    int got = sscanf(p + 2, "%*c %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld", &v[4], &v[5], &v[6], &v[7], &v[8], &v[9],
                     &v[10], &v[11], &v[12], &v[13], &v[14], &v[15], &v[16]);
    if (got < 13) return -1;
    *ut = v[14];
    *st = v[15];
    return 0;
}

// Sums of the "cpu " line of /proc/stat: total and idle
static int proc_stat(long long *total, long long *idle, int *cpus) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    char line[512];
    long long v[10] = {0};
    *cpus = 0;
    int ok = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "cpu ", 4)) {
            ok = sscanf(line + 4, "%lld %lld %lld %lld %lld %lld %lld %lld", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7]) == 8;
        } else if (!strncmp(line, "cpu", 3)) {
            (*cpus)++;
        }
    }
    fclose(f);
    *total = v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7];
    *idle = v[3];
    return ok ? 0 : -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long hz = sysconf(_SC_CLK_TCK);

    // User time of this process
    double u0 = self_user();
    burn(0.5);
    double u1 = self_user();
    printf("     0.5 s of spinning: %.2f s user\n", u1 - u0);
    check(u1 - u0 > 0.3 && u1 - u0 < 0.8, "getrusage(RUSAGE_SELF) counts user time");

    // System time: a system-call-heavy loop
    struct rusage r0, r1;
    getrusage(RUSAGE_SELF, &r0);
    double end = now() + 0.5;
    struct utsname u;
    while (now() < end)
        for (int i = 0; i < 1000; i++) uname(&u);
    getrusage(RUSAGE_SELF, &r1);
    printf("     0.5 s of uname: %.2f s system, %.2f s user\n", tv(r1.ru_stime) - tv(r0.ru_stime), tv(r1.ru_utime) - tv(r0.ru_utime));
    check(tv(r1.ru_stime) - tv(r0.ru_stime) > 0.1, "getrusage counts system time");

    // A thread's time stays with the process after it exits
    double before = self_user();
    pthread_t t;
    pthread_create(&t, NULL, thread_burn, NULL);
    pthread_join(t, NULL);
    double after = self_user();
    printf("     a thread spinning 0.4 s: %.2f s user (it ran %.2f s)\n", after - before, thread_cpu);
    check(thread_cpu > 0.05 && after - before > thread_cpu - 0.05, "an exited thread's time counts for the process");

    // CLOCK_PROCESS_CPUTIME_ID agrees with getrusage
    struct timespec pc;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &pc);
    struct rusage rs;
    getrusage(RUSAGE_SELF, &rs);
    double clk = pc.tv_sec + pc.tv_nsec / 1e9, ru = tv(rs.ru_utime) + tv(rs.ru_stime);
    printf("     CLOCK_PROCESS_CPUTIME_ID %.2f s, getrusage %.2f s\n", clk, ru);
    check(clk > 0.5 && clk - ru < 0.1 && ru - clk < 0.1, "CLOCK_PROCESS_CPUTIME_ID matches getrusage");

    // /proc/self/stat
    long ut = -1, st = -1;
    check(stat_times(getpid(), &ut, &st) == 0 && ut >= (long)(0.6 * hz) && st >= (long)(0.1 * hz), "/proc/self/stat utime and stime");
    printf("     /proc/self/stat: utime %ld, stime %ld (%ld per second)\n", ut, st, hz);

    // Another process's time, while it runs and after; children's time after wait
    pid_t c = fork();
    if (c == 0) {
        burn(0.6);
        // What it ran, in hundredths of a second, as its exit status
        int cs = (int)(own_cpu(CLOCK_PROCESS_CPUTIME_ID) * 100);
        _exit(cs > 255 ? 255 : cs);
    }
    usleep(400000);
    long cut = -1, cst = -1;
    stat_times(c, &cut, &cst);
    printf("     child at 0.4 s: utime %ld\n", cut);
    check(cut >= (long)(0.2 * hz), "another process's /proc/<pid>/stat utime");
    int status = 0;
    waitpid(c, &status, 0);
    double child_cpu = WEXITSTATUS(status) / 100.0;
    struct rusage rc;
    getrusage(RUSAGE_CHILDREN, &rc);
    struct tms tm;
    times(&tm);
    printf("     children: getrusage %.2f s user, times %ld ticks (the child ran %.2f s)\n", tv(rc.ru_utime), (long)tm.tms_cutime, child_cpu);
    check(child_cpu > 0.05 && tv(rc.ru_utime) + tv(rc.ru_stime) > child_cpu - 0.05, "getrusage(RUSAGE_CHILDREN) after wait");
    check(tm.tms_cutime + tm.tms_cstime >= (long)((child_cpu - 0.05) * hz) && tm.tms_utime >= (long)(0.6 * hz), "times(): utime and cutime");

    // /proc/stat: the CPUs, and idle time while sleeping
    long long t0, i0, t1, i1;
    int cpus = 0;
    double w0 = now();
    int ok = proc_stat(&t0, &i0, &cpus) == 0;
    sleep(1);
    ok = ok && proc_stat(&t1, &i1, &cpus) == 0;
    double wall = now() - w0;
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    // The ticks of every CPU over the wall time measured (the sleep may run long)
    double expect = wall * hz * online;
    printf("     /proc/stat: %d CPUs, %lld of %lld ticks idle over %.2f s (%.0f expected)\n", cpus, i1 - i0, t1 - t0, wall, expect);
    check(ok && cpus == online, "/proc/stat has a line per CPU");
    check(ok && t1 - t0 >= (long long)(0.8 * expect) && t1 - t0 <= (long long)(1.2 * expect + online), "/proc/stat advances by CPUs x seconds");
    check(ok && i1 - i0 >= (long long)(0.5 * hz), "/proc/stat counts idle time");

    // /proc/uptime and /proc/loadavg
    double up = 0, idle = 0;
    FILE *f = fopen("/proc/uptime", "r");
    check(f && fscanf(f, "%lf %lf", &up, &idle) == 2 && up > 1, "/proc/uptime");
    if (f) fclose(f);
    double l1, l5, l15;
    int run, tot, last;
    f = fopen("/proc/loadavg", "r");
    check(f && fscanf(f, "%lf %lf %lf %d/%d %d", &l1, &l5, &l15, &run, &tot, &last) == 6 && tot > 0 && run >= 1, "/proc/loadavg");
    if (f) fclose(f);
    printf(fails ? "CPUTIME TEST FAILED (%d)\n" : "CPUTIME TEST PASSED\n", fails);
    return fails != 0;
}
