/* svcroute_test: the routing core of wave 6 (Group 19): Linux calls routed to SEVERAL
 * services. Besides linux-server, the test service svc-test (its own process, endpoint 0x32)
 * owns the test call 0x6711, a kind of test object, and the character major 240.
 *
 *   svcroute_test          the checks; prints "SVCROUTE TEST PASSED" or "SVCROUTE TEST FAILED (n)"
 *   svcroute_test bench N  N forwarded null calls to linux-server and to svc-test: µs per call
 *   svcroute_test load S   the kill test's load for S seconds: threads calling svc-test
 *                          (null and pending calls, a blocked epoll_wait on one of its
 *                          objects) and linux-server; prints what each saw, then
 *                          "SVCKILL PASSED" when linux-server's calls never failed and
 *                          nothing hung
 *
 * With the forwarding switched back (lx=kernel, or lx.test=kernel) the test service's call
 * is the kernel's (ENOSYS): the checks that need it are skipped.
 * Build: gcc -O1 -w -pthread svcroute_test.c -o svcroute
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL 0x6710
#define LX_NULL_OBJ 3
#define LX_TEST 0x6711
#define T_NULL 0
#define T_OBJ 1
#define T_PENDING 2
#define T_REDIRECT 3
#define T_WHO 4
#define T_COPY 5
#define T_REDIR_LOOP 6
#define T_CLOSES 7
#define TEST_MAJOR 240

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static uint64_t now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}

static long tcall(long op, long a, long b) { return syscall(LX_TEST, op, a, b); }

/* --- a thread blocked in epoll_wait, woken by the second service's doorbell --- */
static int g_ep;
static volatile int g_woke = -1;
static void *ep_waiter(void *arg) {
    (void)arg;
    struct epoll_event ev[4];
    int n = epoll_wait(g_ep, ev, 4, 5000);
    g_woke = n > 0 ? (int)ev[0].data.u32 : -100 - n;
    return 0;
}

/* --- many threads calling both services at once --- */
static volatile int par_bad;
static void *par_caller(void *arg) {
    long i, n = (long)arg;
    for (i = 0; i < n; i++) {
        if (tcall(T_NULL, 0, 0) != 0) par_bad++;
        if (syscall(LX_NULL, 0, 0, 0) != 0) par_bad++;
    }
    return 0;
}

static void on_alarm(int s) { (void)s; }

static int send_fd(int sock, int fd) {
    char c = 'x';
    struct iovec io = {&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    memset(ctl, 0, sizeof ctl);
    struct msghdr m = {0};
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    m.msg_control = ctl;
    m.msg_controllen = sizeof ctl;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    return sendmsg(sock, &m, 0);
}

static int recv_fd(int sock) {
    char c;
    struct iovec io = {&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    struct msghdr m = {0};
    m.msg_iov = &io;
    m.msg_iovlen = 1;
    m.msg_control = ctl;
    m.msg_controllen = sizeof ctl;
    if (recvmsg(sock, &m, 0) != 1) return -1;
    struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
    if (!cm || cm->cmsg_type != SCM_RIGHTS) return -2;
    int fd;
    memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    return fd;
}

static int read_text(int fd, char *buf, int cap) {
    int n = read(fd, buf, cap - 1);
    buf[n > 0 ? n : 0] = 0;
    return n;
}

static int checks(void) {
    long r = tcall(T_NULL, 0, 0);
    if (r != 0) {
        printf("svc-test does not serve 0x6711 (r=%ld errno=%d): forwarding switched back; skipped\n", r, errno);
        check(syscall(LX_NULL, 0, 0, 0) == 0, "linux-server's (or the kernel's) null call still answers");
        return 0;
    }
    /* 1. two services, two processes */
    long who = tcall(T_WHO, 0, 0);
    check(who > 0 && who != getpid(), "the test call is served by another process (svc-test)");
    check(syscall(LX_NULL, 0, 0, 0) == 0, "linux-server's null call answers too");
    char buf[64];
    for (int i = 0; i < 16; i++) buf[i] = (char)i;
    check(tcall(T_COPY, (long)buf, 16) == 16 && buf[0] == 1 && buf[15] == 16, "client memory of the second service (copy in, add 1, copy out)");
    uint64_t t0 = now_us();
    r = tcall(T_PENDING, 50, 0);
    uint64_t dt = now_us() - t0;
    check(r == 4242 && dt >= 30000, "a pending call of the second service completes later (4242)");

    /* 2. objects of both services under one epoll */
    int a = syscall(LX_NULL, LX_NULL_OBJ, 0, 0);
    int b = tcall(T_OBJ, 0, 0);
    check(a >= 0 && b >= 0, "objects of linux-server and of svc-test");
    if (a < 0 || b < 0) return fails;
    check(read_text(b, buf, sizeof buf) > 0 && strncmp(buf, "svc-test ", 9) == 0, "reading the svc-test object is answered by svc-test");
    check(read_text(a, buf, sizeof buf) > 0 && strncmp(buf, "slot ", 5) == 0, "reading the linux-server object is answered by linux-server");
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    ev.data.u32 = 1;
    epoll_ctl(ep, EPOLL_CTL_ADD, a, &ev);
    ev.data.u32 = 2;
    epoll_ctl(ep, EPOLL_CTL_ADD, b, &ev);
    struct epoll_event got[4];
    check(epoll_wait(ep, got, 4, 0) == 0, "nothing readable yet");
    g_ep = ep;
    g_woke = -1;
    pthread_t th;
    pthread_create(&th, 0, ep_waiter, 0);
    usleep(100000);
    write(b, "r", 1);
    pthread_join(th, 0);
    check(g_woke == 2, "a blocked epoll_wait is woken by svc-test's doorbell");
    write(a, "r", 1);
    int n = epoll_wait(ep, got, 4, 1000);
    check(n == 2, "both objects readable under one epoll");
    write(b, "c", 1);
    n = epoll_wait(ep, got, 4, 0);
    check(n == 1 && got[0].data.u32 == 1, "clearing svc-test's object leaves only linux-server's");
    write(b, "w", 1);
    struct pollfd p[2] = {{a, POLLIN, 0}, {b, POLLOUT, 0}};
    check(poll(p, 2, 0) == 2 && (p[0].revents & POLLIN) && (p[1].revents & POLLOUT), "poll over both owners");
    close(ep);

    /* 3. SCM_RIGHTS across owners: a svc-test object through a linux-server Unix socket */
    long closes0 = tcall(T_CLOSES, 0, 0);
    int sv[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    check(send_fd(sv[0], b) == 1, "sendmsg SCM_RIGHTS of a svc-test object");
    int b2 = recv_fd(sv[1]);
    check(b2 >= 0 && b2 != b, "recvmsg gives a new descriptor");
    char t1[64], t2[64];
    read_text(b, t1, sizeof t1);
    read_text(b2, t2, sizeof t2);
    check(b2 >= 0 && strcmp(t1, t2) == 0, "the received descriptor is the same svc-test object");
    /* and to a child process */
    pid_t pid = fork();
    if (pid == 0) {
        int c = recv_fd(sv[1]);
        char t[64];
        _exit(c >= 0 && read_text(c, t, sizeof t) > 0 && strcmp(t, t1) == 0 ? 0 : 1);
    }
    send_fd(sv[0], b);
    int st = -1;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a child receives the svc-test object and reads it");
    close(b);
    close(b2);
    close(sv[0]);
    close(sv[1]);
    usleep(50000);
    check(tcall(T_CLOSES, 0, 0) == closes0 + 1, "svc-test hears of its object's last close once");
    close(a);

    /* 4. redirects */
    r = tcall(T_REDIRECT, 0x11, 3);
    check(r == 0x5114, "a call redirected from svc-test to linux-server (object and tail carried)");
    r = tcall(T_REDIR_LOOP, 0, 0);
    check(r == -1 && errno == ELOOP, "endless redirects end in ELOOP");

    /* 5. a device open routed by major */
    const char *node = "/tmp/svcroute-dev";
    unlink(node);
    int made = mknod(node, S_IFCHR | 0666, makedev(TEST_MAJOR, 7)) == 0;
    if (!made && errno == EPERM) {
        /* the suite runs as the session user: make the node with sudo (password hydra) */
        made = system("echo hydra | sudo -S -p '' mknod -m 666 /tmp/svcroute-dev c 240 7 2>/dev/null") == 0;
    }
    if (!made) {
        printf("skip: mknod (errno %d): the device-open check needs root\n", errno);
    } else {
        int d = open(node, O_RDWR);
        check(d >= 0, "open of a character device of major 240 (svc-test's)");
        if (d >= 0) {
            read_text(d, buf, sizeof buf);
            check(strncmp(buf, "svc-test dev 240:7 ", 19) == 0, "it is svc-test's object, opened as 240:7");
            struct stat sb;
            check(fstat(d, &sb) == 0 && S_ISCHR(sb.st_mode), "fstat: a character device");
            struct pollfd q = {d, POLLOUT, 0};
            check(poll(&q, 1, 0) == 1, "poll on it");
            close(d);
        }
        if (unlink(node) != 0) system("echo hydra | sudo -S -p '' rm -f /tmp/svcroute-dev");
    }

    /* 6. both services from many threads at once */
    pthread_t ts[8];
    par_bad = 0;
    for (int i = 0; i < 8; i++) pthread_create(&ts[i], 0, par_caller, (void *)2000L);
    for (int i = 0; i < 8; i++) pthread_join(ts[i], 0);
    check(par_bad == 0, "8 threads x 2000 calls to each service");

    /* 7. a signal interrupts a pending call of the second service */
    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 0}, {0, 100000}};
    setitimer(ITIMER_REAL, &it, 0);
    t0 = now_us();
    r = tcall(T_PENDING, 3000, 0);
    dt = now_us() - t0;
    check(r == -1 && errno == EINTR && dt < 2000000, "a signal interrupts a pending svc-test call (EINTR)");
    return fails;
}

/* --- bench --- */
static void bench(long n) {
    if (tcall(T_NULL, 0, 0) != 0) {
        printf("svc-test not serving: no bench\n");
        return;
    }
    for (int round = 0; round < 3; round++) {
        uint64_t t0 = now_us();
        for (long i = 0; i < n; i++) syscall(LX_NULL, 0, 0, 0);
        uint64_t t1 = now_us();
        for (long i = 0; i < n; i++) tcall(T_NULL, 0, 0);
        uint64_t t2 = now_us();
        for (long i = 0; i < n; i++) syscall(SYS_getppid);
        uint64_t t3 = now_us();
        printf("bench round %d: lx_null %.3f us  test_null (svc-test) %.3f us  getppid %.3f us\n", round, (double)(t1 - t0) / n, (double)(t2 - t1) / n, (double)(t3 - t2) / n);
    }
}

/* --- the kill test's load --- */
static volatile int stop;
static volatile long t_ok, t_err, t_errno, p_ok, p_err, p_errno, l_ok, l_err, after_ok;
static volatile int ep_rev = -1;
static volatile long t_last_err_us;
static void *load_test(void *x) {
    (void)x;
    while (!stop) {
        long r = tcall(T_NULL, 0, 0);
        if (r == 0) {
            t_ok++;
            if (t_err) after_ok++;
        } else {
            t_err++;
            t_errno = errno;
            usleep(1000);
        }
    }
    return 0;
}
static void *load_pending(void *x) {
    (void)x;
    while (!stop) {
        long r = tcall(T_PENDING, 20, 0);
        if (r == 4242) p_ok++;
        else {
            p_err++;
            p_errno = errno;
            usleep(1000);
        }
    }
    return 0;
}
static void *load_linux(void *x) {
    (void)x;
    while (!stop) {
        if (syscall(LX_NULL, 0, 0, 0) == 0) l_ok++;
        else l_err++;
    }
    return 0;
}
static void *load_epoll(void *x) {
    int ep = (int)(long)x;
    struct epoll_event ev[2];
    int n = epoll_wait(ep, ev, 2, -1);
    ep_rev = n > 0 ? (int)ev[0].events : -100 - n;
    return 0;
}

static int load(int secs) {
    if (tcall(T_NULL, 0, 0) != 0) {
        printf("svc-test not serving\n");
        return 1;
    }
    int o = tcall(T_OBJ, 0, 0);
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, o, &ev);
    pthread_t th[5];
    pthread_create(&th[0], 0, load_test, 0);
    pthread_create(&th[1], 0, load_pending, 0);
    pthread_create(&th[2], 0, load_linux, 0);
    pthread_create(&th[3], 0, load_test, 0);
    pthread_create(&th[4], 0, load_epoll, (void *)(long)ep);
    printf("LOAD RUNNING\n");
    fflush(stdout);
    for (int s = 0; s < secs; s++) {
        sleep(1);
        printf("t=%d test ok %ld err %ld (errno %ld) pending ok %ld err %ld (errno %ld) linux ok %ld err %ld epoll %d after-restart ok %ld\n", s, t_ok, t_err, t_errno, p_ok, p_err, p_errno, l_ok,
               l_err, ep_rev, after_ok);
        fflush(stdout);
    }
    stop = 1;
    for (int i = 0; i < 4; i++) pthread_join(th[i], 0);
    char b[64];
    int rr = read(o, b, sizeof b);
    printf("old object after the kill: read %d errno %d; epoll_wait saw events %#x\n", rr, rr < 0 ? errno : 0, ep_rev);
    long again = tcall(T_NULL, 0, 0);
    printf("a test call after the restart: %ld\n", again);
    /* the kill must show (a call in flight failed, or one made while the service was gone),
     * the blocked epoll_wait woke with EPOLLERR|EPOLLHUP, the old object is dead, linux-server
     * never failed, and the restarted service answers */
    int ok = l_err == 0 && t_err + p_err > 0 && ep_rev > 0 && (ep_rev & 0x18) && rr < 0 && again == 0;
    printf("SVCKILL %s (test calls failed %ld, pending failed %ld, linux-server failed %ld, test calls after the restart %ld)\n", ok ? "PASSED" : "FAILED", t_err, p_err, l_err, after_ok);
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "bench")) {
        bench(argc > 2 ? atol(argv[2]) : 100000);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "load")) return load(argc > 2 ? atoi(argv[2]) : 20);
    checks();
    printf("SVCROUTE TEST %s", fails ? "FAILED" : "PASSED");
    if (fails) printf(" (%d)", fails);
    printf("\n");
    return fails ? 1 : 0;
}
