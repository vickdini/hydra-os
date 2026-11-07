// perf_event_open software counters: task clock, context switches, page faults, groups,
// disable/reset, and perf stat's way (enable_on_exec + inherit on a child that execs and
// forks). Build: gcc -O1 -w -o perf perf_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int excl = 1;
static int open_ev(uint32_t type, uint64_t config, pid_t pid, int group, uint64_t fmt, int disabled, int inherit, int on_exec) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.size = sizeof a;
    a.type = type;
    a.config = config;
    a.read_format = fmt;
    a.disabled = disabled;
    a.inherit = inherit;
    a.enable_on_exec = on_exec;
    a.exclude_kernel = excl;
    a.exclude_hv = 1;
    return syscall(SYS_perf_event_open, &a, pid, -1, group, PERF_FLAG_FD_CLOEXEC);
}

static uint64_t rd(int fd) {
    uint64_t v = 0;
    read(fd, &v, sizeof v);
    return v;
}

static void burn_ms(int ms) {
    struct timespec t0, t;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t0);
    do clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
    while ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000 < ms);
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--burn")) {
        // The exec'd child: burn, and a grandchild burns too
        pid_t g = fork();
        burn_ms(200);
        if (g == 0) _exit(0);
        waitpid(g, NULL, 0);
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    int hw = open_ev(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 0, -1, 0, 0, 0, 0);
    check(hw >= 0 || errno == ENOENT || errno == EOPNOTSUPP, "hardware cycles: counted, or ENOENT without a PMU");
    if (hw >= 0) close(hw);

    int tc = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, 0, -1, PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING, 0, 0, 0);
    check(tc >= 0, "software task clock counter");
    burn_ms(200);
    uint64_t r[3];
    read(tc, r, sizeof r);
    check(r[0] >= 100000000ull && r[0] < 2000000000ull && r[1] >= r[0] / 2 && r[2] > 0, "task clock counts the 200 ms burn (with times enabled/running)");

    // Context switches happen in the kernel: counted with kernel counting (root), not in
    // a user-space-only counter
    excl = geteuid() != 0;
    int cs = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, 0, -1, 0, 0, 0, 0);
    excl = 1;
    for (int i = 0; i < 10; i++) usleep(2000);
    if (geteuid() == 0) check(rd(cs) >= 10, "context switches count sleeps (kernel counting, root)");
    else check(cs >= 0 && rd(cs) == 0, "context switches in a user-space-only counter: 0");

    int pf = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS, 0, -1, 0, 0, 0, 0);
    char *m = mmap(0, 100 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 100; i++) m[i * 4096] = 1;
    check(rd(pf) >= 100, "page faults count 100 touched pages");

    // Disable, reset
    ioctl(pf, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t a = rd(pf);
    for (int i = 0; i < 100; i++) m[i * 4096 + 50 * 4096 * 0] = 2;
    char *m2 = mmap(0, 20 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 20; i++) m2[i * 4096] = 1;
    check(rd(pf) == a, "a disabled counter stays put");
    ioctl(pf, PERF_EVENT_IOC_RESET, 0);
    check(rd(pf) == 0, "reset zeroes it");

    // A group read
    int lead = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, 0, -1, PERF_FORMAT_GROUP | PERF_FORMAT_ID, 1, 0, 0);
    int mem = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS, 0, lead, PERF_FORMAT_GROUP | PERF_FORMAT_ID, 1, 0, 0);
    uint64_t id_lead = 0, id_mem = 0;
    ioctl(lead, PERF_EVENT_IOC_ID, &id_lead);
    ioctl(mem, PERF_EVENT_IOC_ID, &id_mem);
    ioctl(lead, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    char *m3 = mmap(0, 10 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    for (int i = 0; i < 10; i++) m3[i * 4096] = 1;
    burn_ms(50);
    uint64_t g[5] = {0};
    read(lead, g, sizeof g);
    check(g[0] == 2 && g[2] == id_lead && g[4] == id_mem && g[3] >= 10 && id_lead != id_mem, "group read: both members with their IDs");

    // perf stat's way: a counter on a child, started at its exec, counting descendants
    int go[2];
    pipe(go);
    pid_t c = fork();
    if (c == 0) {
        char x;
        read(go[0], &x, 1);
        execl("/proc/self/exe", "perf_test", "--burn", (char *)NULL);
        _exit(127);
    }
    int ce = open_ev(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, c, -1, 0, 1, 1, 1);
    check(ce >= 0 && rd(ce) == 0, "counter on a child: disabled until its exec");
    write(go[1], "x", 1);
    int st;
    waitpid(c, &st, 0);
    uint64_t v = rd(ce);
    check(WIFEXITED(st) && v >= 300000000ull, "enable_on_exec + inherit: the child's and its child's time");
    if (v < 300000000ull) printf("     counted %llu ns\n", (unsigned long long)v);

    // Sampling, and kernel counting without privilege
    struct perf_event_attr sa;
    memset(&sa, 0, sizeof sa);
    sa.size = sizeof sa;
    sa.type = PERF_TYPE_SOFTWARE;
    sa.config = PERF_COUNT_SW_CPU_CLOCK;
    sa.sample_period = 100000;
    sa.exclude_kernel = 1;
    int s = syscall(SYS_perf_event_open, &sa, 0, -1, -1, 0);
    check(s >= 0 || errno == EOPNOTSUPP, "sampling: supported, or EOPNOTSUPP");
    FILE *f = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    int paranoid = 2;
    if (f) {
        fscanf(f, "%d", &paranoid);
        fclose(f);
    }
    if (geteuid() != 0 && paranoid >= 2) {
        struct perf_event_attr k;
        memset(&k, 0, sizeof k);
        k.size = sizeof k;
        k.type = PERF_TYPE_SOFTWARE;
        k.config = PERF_COUNT_SW_TASK_CLOCK;
        errno = 0;
        check(syscall(SYS_perf_event_open, &k, 0, -1, -1, 0) == -1 && errno == EACCES, "kernel counting unprivileged (paranoid >= 2): EACCES");
    }
    printf(fails ? "PERF TEST FAILED (%d)\n" : "PERF TEST PASSED\n", fails);
    return fails != 0;
}
