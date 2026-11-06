// Checks for the interfaces Brave's logs showed missing: rt_sigtimedwait, oom_score_adj,
// per-thread /proc status with NSpid, Yama ptrace_scope, and NETLINK_ROUTE (getifaddrs).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static int read_file(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, cap - 1);
    close(fd);
    if (n >= 0) buf[n] = 0;
    return n;
}

static int write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, text, strlen(text));
    close(fd);
    return n == (int)strlen(text) ? 0 : -1;
}

int main(void) {
    // rt_sigtimedwait
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, 0);
    kill(getpid(), SIGUSR1);
    siginfo_t si;
    struct timespec ts = {1, 0};
    int sig = sigtimedwait(&set, &si, &ts);
    CHECK(sig == SIGUSR1 && si.si_signo == SIGUSR1 && si.si_pid == getpid(), "sigtimedwait takes a pending signal (%d, pid %d)", sig, si.si_pid);
    ts.tv_sec = 0;
    ts.tv_nsec = 200000000;
    time_t t0 = time(0);
    errno = 0;
    CHECK(sigtimedwait(&set, &si, &ts) == -1 && errno == EAGAIN && time(0) - t0 < 3, "sigtimedwait times out with EAGAIN");

    // oom_score_adj
    char buf[4096];
    CHECK(read_file("/proc/self/oom_score_adj", buf, sizeof buf) > 0 && atoi(buf) == 0, "oom_score_adj reads 0");
    CHECK(write_file("/proc/self/oom_score_adj", "300") == 0, "raise oom_score_adj");
    CHECK(read_file("/proc/self/oom_score_adj", buf, sizeof buf) > 0 && atoi(buf) == 300, "oom_score_adj reads 300 (%s)", buf);
    CHECK(write_file("/proc/self/oom_score_adj", "100") == 0, "lower it back above 0");
    if (getuid() != 0) CHECK(write_file("/proc/self/oom_score_adj", "-1") != 0, "below 0 needs CAP_SYS_RESOURCE");
    CHECK(read_file("/proc/self/oom_score", buf, sizeof buf) > 0, "oom_score readable");

    // per-thread status
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/task/%d/status", getpid(), (int)syscall(SYS_gettid));
    CHECK(read_file(path, buf, sizeof buf) > 0 && strstr(buf, "NSpid:") && strstr(buf, "Tgid:"), "%s has NSpid", path);

    // Yama
    buf[0] = '-';
    int y = read_file("/proc/sys/kernel/yama/ptrace_scope", buf, sizeof buf);
    CHECK(y < 0 || (buf[0] >= '0' && buf[0] <= '3'), "yama ptrace_scope = %c", y < 0 ? '-' : buf[0]);

    // NETLINK_ROUTE via getifaddrs
    struct ifaddrs *ifs;
    int lo = 0, v4 = 0;
    CHECK(getifaddrs(&ifs) == 0, "getifaddrs (errno %d)", errno);
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!strcmp(i->ifa_name, "lo") && (i->ifa_flags & IFF_LOOPBACK)) lo = 1;
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET) {
            char a[32];
            inet_ntop(AF_INET, &((struct sockaddr_in *)i->ifa_addr)->sin_addr, a, sizeof a);
            printf("     %s %s\n", i->ifa_name, a);
            v4++;
        }
    }
    CHECK(lo && v4 >= 1, "interfaces listed (lo, %d IPv4 addresses)", v4);
    CHECK(if_nametoindex("lo") > 0, "if_nametoindex(lo)");

    printf(fails ? "GAPS TEST FAILED (%d)\n" : "GAPS TEST PASSED\n", fails);
    return fails != 0;
}
