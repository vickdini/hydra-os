/* lxbench: Linux system call micro-benchmarks for the Linux-server design (wave 2,
 * group 6, step 0). Each test runs a loop, five times; the line printed per test is
 *   BENCH <name> min <ns> med <ns> max <ns> ns/op (<iterations per run>)
 * Optional arguments name the tests to run (default: all). The "probe_*" tests need a
 * kernel built with `--features g6-probe` (src/compat/linux/g6_probe.rs) and are skipped
 * on a normal kernel. Build: gcc -O1 -w -pthread lxbench.c -o lxbench
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REPS 5
#define PROBE_NR 0x6706
/* Hydra's test call (wave 3, group 7): a forwarded null call, answered by linux-server, or
 * in the kernel when the forwarding is switched off (ENOSYS on kernels before it) */
#define LX_NULL_NR 0x6710

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

typedef double (*bench_fn)(long n);

static char buf[65536];
static long probe_ep = 0x20;

/* --- system calls without work --- */
static double b_getpid(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(SYS_getpid);
    return (double)(now() - t) / n;
}
static double b_getpgrp(long n) { /* not on the lock-free fast path: the normal locked path */
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(SYS_getpgrp);
    return (double)(now() - t) / n;
}
static double b_clock(long n) {
    struct timespec ts;
    uint64_t t = now();
    for (long i = 0; i < n; i++) clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)(now() - t) / n;
}

/* --- files --- */
static double b_read_cached(long n) {
    int fd = open("/usr/bin/bash", O_RDONLY);
    if (fd < 0) return -1;
    pread(fd, buf, 4096, 0);
    uint64_t t = now();
    for (long i = 0; i < n; i++) pread(fd, buf, 4096, 0);
    double r = (double)(now() - t) / n;
    close(fd);
    return r;
}
static double b_read_64k(long n) {
    int fd = open("/usr/bin/bash", O_RDONLY);
    if (fd < 0) return -1;
    pread(fd, buf, 65536, 0);
    uint64_t t = now();
    for (long i = 0; i < n; i++) pread(fd, buf, 65536, 0);
    double r = (double)(now() - t) / n;
    close(fd);
    return r;
}
static double b_write_null(long n) {
    int fd = open("/dev/null", O_WRONLY);
    uint64_t t = now();
    for (long i = 0; i < n; i++) write(fd, buf, 64);
    double r = (double)(now() - t) / n;
    close(fd);
    return r;
}
static double b_open_close(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        int fd = open("/etc/passwd", O_RDONLY);
        if (fd < 0) return -1;
        close(fd);
    }
    return (double)(now() - t) / n;
}
static double b_stat(long n) {
    struct stat st;
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (stat("/usr/bin/bash", &st)) return -1;
    return (double)(now() - t) / n;
}
static double b_fstat(long n) {
    struct stat st;
    int fd = open("/etc/passwd", O_RDONLY);
    uint64_t t = now();
    for (long i = 0; i < n; i++) fstat(fd, &st);
    double r = (double)(now() - t) / n;
    close(fd);
    return r;
}

/* --- round trips between two processes or threads --- */
static double pingpong(int a[2], int b[2], long n) {
    char c = 0;
    pid_t p = fork();
    if (p == 0) {
        for (long i = 0; i < n; i++) {
            if (read(a[0], &c, 1) != 1) _exit(1);
            write(b[1], &c, 1);
        }
        _exit(0);
    }
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        write(a[1], &c, 1);
        if (read(b[0], &c, 1) != 1) return -1;
    }
    double r = (double)(now() - t) / n;
    waitpid(p, 0, 0);
    return r;
}
static double b_pipe_rtt(long n) {
    int a[2], b[2];
    pipe(a);
    pipe(b);
    double r = pingpong(a, b, n);
    close(a[0]); close(a[1]); close(b[0]); close(b[1]);
    return r;
}
static double b_unix_rtt(long n) {
    int s[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s)) return -1;
    /* parent writes s[0] -> child reads s[1]; child writes s[1] -> parent reads s[0] */
    int a[2] = {s[1], s[0]}, b[2] = {s[0], s[1]};
    double r = pingpong(a, b, n);
    close(s[0]); close(s[1]);
    return r;
}

static _Atomic int fword;
static long fcount;
static long futex(void *a, int op, int v) { return syscall(SYS_futex, a, op, v, 0, 0, 0); }
static void *fpartner(void *x) {
    for (long i = 0; i < fcount; i++) {
        while (atomic_load(&fword) == 0) futex(&fword, FUTEX_WAIT_PRIVATE, 0);
        atomic_store(&fword, 0);
        futex(&fword, FUTEX_WAKE_PRIVATE, 1);
    }
    return 0;
}
static double b_futex_rtt(long n) {
    pthread_t th;
    fcount = n;
    atomic_store(&fword, 0);
    pthread_create(&th, 0, fpartner, 0);
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        atomic_store(&fword, 1);
        futex(&fword, FUTEX_WAKE_PRIVATE, 1);
        while (atomic_load(&fword) == 1) futex(&fword, FUTEX_WAIT_PRIVATE, 1);
    }
    double r = (double)(now() - t) / n;
    pthread_join(th, 0);
    return r;
}
static double b_futex_wake_none(long n) { /* a wake nobody waits for (the lock-free fast path) */
    uint64_t t = now();
    for (long i = 0; i < n; i++) futex(&fword, FUTEX_WAKE_PRIVATE, 1);
    return (double)(now() - t) / n;
}

/* --- the same round trips with everything on CPU 0 (no cross-CPU wake-up: the cost of the
 * switches themselves, the floor for a direct-switch forward) --- */
static void pin(int all) {
    cpu_set_t s;
    CPU_ZERO(&s);
    if (all) for (int i = 0; i < 2; i++) CPU_SET(i, &s);
    else CPU_SET(0, &s);
    sched_setaffinity(0, sizeof s, &s);
}
static double b_yield(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) sched_yield();
    return (double)(now() - t) / n;
}
static double b_yield_pingpong_1cpu(long n) { /* two processes yielding to each other: per switch */
    pin(0);
    pid_t p = fork();
    if (p == 0) {
        for (long i = 0; i < n; i++) sched_yield();
        _exit(0);
    }
    uint64_t t = now();
    for (long i = 0; i < n; i++) sched_yield();
    waitpid(p, 0, 0);
    double r = (double)(now() - t) / (2 * n);
    pin(1);
    return r;
}
static double b_pipe_rtt_1cpu(long n) { pin(0); double r = b_pipe_rtt(n); pin(1); return r; }
static double b_futex_rtt_1cpu(long n) { pin(0); double r = b_futex_rtt(n); pin(1); return r; }

/* --- processes --- */
static double b_fork_wait(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        waitpid(p, 0, 0);
    }
    return (double)(now() - t) / n;
}
static double b_fork_exec_wait(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) {
            execl("/bin/true", "true", (char *)0);
            _exit(127);
        }
        int st;
        waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) return -1;
    }
    return (double)(now() - t) / n;
}

/* --- memory --- */
static double b_mmap_munmap(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        void *p = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return -1;
        munmap(p, 1 << 20);
    }
    return (double)(now() - t) / n;
}
static double b_fault_anon(long n) { /* per page: mmap 1 MiB, touch its 256 pages, munmap */
    long pages = 0;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        char *p = mmap(0, 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return -1;
        for (long o = 0; o < (1 << 20); o += 4096, pages++) p[o] = 1;
        munmap(p, 1 << 20);
    }
    return (double)(now() - t) / pages;
}

/* --- forwarding to linux-server (wave 3, group 7) --- */
static double b_lx_null(long n) { /* the forwarded null call */
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(LX_NULL_NR);
    return (double)(now() - t) / n;
}
static double b_keyctl(long n) { /* keyctl(KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 0) */
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(SYS_keyctl, 0, -3, 0);
    return (double)(now() - t) / n;
}
static double b_add_key(long n) { /* add_key("user", "lxbench", 16-byte payload, process keyring): two strings and a buffer in */
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (syscall(SYS_add_key, "user", "lxbench", "0123456789abcdef", 16, -2) < 0) return -1;
    return (double)(now() - t) / n;
}
static double b_keyctl_describe(long n) { /* keyctl(KEYCTL_DESCRIBE, key, buf, 256): a buffer out */
    char buf[256];
    long id = syscall(SYS_add_key, "user", "lxbench", "0123456789abcdef", 16, -2);
    if (id < 0) return -1;
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (syscall(SYS_keyctl, 6, id, buf, sizeof buf) < 0) return -1;
    return (double)(now() - t) / n;
}
static long par_n; static long par_nr;
static void *par_worker(void *x) {
    for (long i = 0; i < par_n; i++) {
        if (par_nr == LX_NULL_NR) syscall(LX_NULL_NR); else syscall(SYS_keyctl, 0, -3, 0);
    }
    return 0;
}
/* Two threads making n calls each at once: time per call over both (no global serialization:
 * this must not be slower than one thread making all 2n calls) */
static double par2(long nr, long n) {
    pthread_t a, b;
    par_n = n; par_nr = nr;
    uint64_t t = now();
    pthread_create(&a, 0, par_worker, 0);
    pthread_create(&b, 0, par_worker, 0);
    pthread_join(a, 0);
    pthread_join(b, 0);
    return (double)(now() - t) / (2 * n);
}
static double b_lx_null_par2(long n) { return par2(LX_NULL_NR, n); }
static double b_keyctl_par2(long n) { return par2(SYS_keyctl, n); }

/* --- step 2 (wave 4, group 9): calls moved to linux-server, and readiness without a call --- */
static double b_mq_rtt(long n) { /* mq_send + mq_receive of 16 bytes, per pair */
    struct mq_attr a = {.mq_maxmsg = 10, .mq_msgsize = 64};
    mq_unlink("/lxbench");
    mqd_t q = mq_open("/lxbench", O_CREAT | O_RDWR, 0600, &a);
    if (q < 0) return -1;
    char m[64];
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        mq_send(q, buf, 16, 0);
        mq_receive(q, m, 64, 0);
    }
    double r = (double)(now() - t) / n;
    mq_close(q);
    mq_unlink("/lxbench");
    return r;
}
static double b_semop(long n) { /* one uncontended semop (alternately +1 and -1) */
    int s = semget(IPC_PRIVATE, 1, 0600);
    if (s < 0) return -1;
    struct sembuf up = {0, 1, 0}, down = {0, -1, 0};
    uint64_t t = now();
    for (long i = 0; i < n; i++) semop(s, i & 1 ? &down : &up, 1);
    double r = (double)(now() - t) / n;
    semctl(s, 0, IPC_RMID);
    return r;
}
static double b_msg_rtt(long n) { /* msgsnd + msgrcv of 16 bytes, per pair */
    int q = msgget(IPC_PRIVATE, 0600);
    if (q < 0) return -1;
    struct { long type; char text[64]; } m = {1, {0}};
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        msgsnd(q, &m, 16, 0);
        msgrcv(q, &m, 64, 0, 0);
    }
    double r = (double)(now() - t) / n;
    msgctl(q, IPC_RMID, 0);
    return r;
}
static double b_bpf_lookup(long n) { /* BPF_MAP_LOOKUP_ELEM on an array map (root only) */
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_ARRAY;
    a.key_size = 4;
    a.value_size = 8;
    a.max_entries = 4;
    int fd = syscall(SYS_bpf, BPF_MAP_CREATE, &a, sizeof a);
    if (fd < 0) return -1;
    uint32_t k = 1;
    uint64_t v;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uint64_t)&k;
    a.value = (uint64_t)&v;
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &a, sizeof a);
    double r = (double)(now() - t) / n;
    close(fd);
    return r;
}
static double poll_one(int fd, long n) {
    struct pollfd p = {fd, POLLIN, 0};
    uint64_t t = now();
    for (long i = 0; i < n; i++) poll(&p, 1, 0);
    return (double)(now() - t) / n;
}
static double b_poll_pipe(long n) { /* poll on a readable pipe (not a server object) */
    int p[2];
    pipe(p);
    write(p[1], "x", 1);
    double r = poll_one(p[0], n);
    close(p[0]);
    close(p[1]);
    return r;
}
static double b_epoll_pipe(long n) { /* epoll_wait on a readable pipe (not a server object) */
    int p[2];
    pipe(p);
    write(p[1], "x", 1);
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &e);
    uint64_t t = now();
    for (long i = 0; i < n; i++) epoll_wait(ep, &e, 1, 0);
    double r = (double)(now() - t) / n;
    close(ep);
    close(p[0]);
    close(p[1]);
    return r;
}
static double b_poll_mq(long n) { /* poll on a readable message queue (a server object's readiness word) */
    struct mq_attr a = {.mq_maxmsg = 10, .mq_msgsize = 64};
    mq_unlink("/lxbench-p");
    mqd_t q = mq_open("/lxbench-p", O_CREAT | O_RDWR, 0600, &a);
    if (q < 0) return -1;
    mq_send(q, buf, 16, 0);
    double r = poll_one(q, n);
    mq_close(q);
    mq_unlink("/lxbench-p");
    return r;
}

/* --- Internet sockets (wave 5, Group 12: forwarded to linux-server, net-server's client) --- */
static int lo_listener(int *port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (l < 0 || bind(l, (void *)&a, sizeof a) || listen(l, 64)) return -1;
    socklen_t n = sizeof a;
    getsockname(l, (void *)&a, &n);
    *port = ntohs(a.sin_port);
    return l;
}
static int lo_connect(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (s < 0 || connect(s, (void *)&a, sizeof a)) return -1;
    return s;
}
/* a connected loopback TCP pair: c (client end), s (accepted end) */
static int tcp_pair(int *c, int *s) {
    int port, l = lo_listener(&port);
    if (l < 0) return -1;
    *c = lo_connect(port);
    *s = accept(l, 0, 0);
    close(l);
    return *c < 0 || *s < 0 ? -1 : 0;
}
static double b_tcp_rtt(long n) { /* 1 byte each way between two processes over 127.0.0.1 */
    int c, s;
    if (tcp_pair(&c, &s)) return -1;
    int a[2] = {s, c}, b[2] = {c, s};
    double r = pingpong(a, b, n);
    close(c); close(s);
    return r;
}
static double b_tcp_sendrecv(long n) { /* send 16 bytes and receive them, one thread (2 calls) */
    int c, s;
    if (tcp_pair(&c, &s)) return -1;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        send(c, buf, 16, 0);
        if (recv(s, buf, 16, MSG_WAITALL) != 16) return -1;
    }
    double r = (double)(now() - t) / n;
    close(c); close(s);
    return r;
}
static double b_tcp_connect(long n) { /* socket + connect + accept + 2 close on 127.0.0.1 */
    int port, l = lo_listener(&port);
    if (l < 0) return -1;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        int c = lo_connect(port);
        int s = accept(l, 0, 0);
        if (c < 0 || s < 0) return -1;
        close(c);
        close(s);
    }
    double r = (double)(now() - t) / n;
    close(l);
    return r;
}
static double b_udp_rtt(long n) { /* 16-byte datagram each way between two processes */
    int x = socket(AF_INET, SOCK_DGRAM, 0), y = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)}, b = a;
    socklen_t k = sizeof a;
    bind(x, (void *)&a, sizeof a);
    bind(y, (void *)&b, sizeof b);
    getsockname(x, (void *)&a, &k);
    k = sizeof b;
    getsockname(y, (void *)&b, &k);
    connect(x, (void *)&b, sizeof b);
    connect(y, (void *)&a, sizeof a);
    int p[2] = {y, x}, q[2] = {x, y};
    double r = pingpong(p, q, n);
    close(x); close(y);
    return r;
}
static double b_getsockopt(long n) { /* getsockopt(SO_RCVBUF) on a TCP socket */
    int s = socket(AF_INET, SOCK_STREAM, 0), v;
    socklen_t l;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        l = sizeof v;
        getsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, &l);
    }
    double r = (double)(now() - t) / n;
    close(s);
    return r;
}
static double b_poll_tcp(long n) { /* poll on a readable TCP socket (its readiness word) */
    int c, s;
    if (tcp_pair(&c, &s)) return -1;
    send(c, "x", 1, 0);
    usleep(20000);
    double r = poll_one(s, n);
    close(c); close(s);
    return r;
}

/* --- calls between services (wave 6, group 20): linux-server times n calls itself --- */
static double svc_inside(long op, long n, long arg) {
    long ns = syscall(LX_NULL_NR, op, n, arg);
    return ns < 0 ? -1 : (double)ns / n;
}
/* linux-server -> net-server null call (its heartbeat): queued (the direct path when
 * net-server waits), and as wave 5's hand-off call */
static double b_svc_rtt(long n) { return svc_inside(5, n, 0); }
static double b_svc_rtt_handoff(long n) { return svc_inside(5, n, 1); }
/* SYS_SVC_DCALL null call from a linux-server worker to service 11 (the test service; 1 =
 * linux-server itself, another worker, when no test service runs) */
static double b_dcall_rtt(long n) {
    const char *e = getenv("DCALL_SVC");
    if (e) return svc_inside(6, n, strtol(e, 0, 0));
    double r = svc_inside(6, n, 11);
    return r >= 0 ? r : svc_inside(6, n, 1);
}

/* --- forwarding probe (kernel built with --features g6-probe) --- */
static int probe_ok(void) { return syscall(PROBE_NR, 0, 0, 0) == 0; }
static double b_probe_null(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) syscall(PROBE_NR, 0, 0, 0);
    return (double)(now() - t) / n;
}
static double probe_user(int op, long n) { /* one forwarded call per system call */
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (syscall(PROBE_NR, op, probe_ep, 1) < 0) return -1;
    return (double)(now() - t) / n;
}
static double probe_kernel(int op, long n) { /* n calls inside one system call */
    long ns = syscall(PROBE_NR, op, probe_ep, n);
    return ns < 0 ? -1 : (double)ns / n;
}
static double b_probe_handoff(long n) { return probe_user(1, n); }
static double b_probe_queued(long n) { return probe_user(2, n); }
static double b_probe_handoff_k(long n) { return probe_kernel(1, n); }
static double b_probe_queued_k(long n) { return probe_kernel(2, n); }

/* --- Group 13 (wave 5, step 4): eventfd, pipes and Unix sockets without a wake-up --- */
static double b_eventfd_rw(long n) { /* write 1 then read it back, one thread */
    int e = eventfd(0, 0);
    uint64_t v = 1;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        write(e, &v, 8);
        read(e, &v, 8);
    }
    double r = (double)(now() - t) / n;
    close(e);
    return r;
}
static double b_pipe_rw(long n) { /* write 64 bytes then read them, one thread */
    int p[2];
    char buf[64] = {0};
    pipe(p);
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        write(p[1], buf, 64);
        read(p[0], buf, 64);
    }
    double r = (double)(now() - t) / n;
    close(p[0]);
    close(p[1]);
    return r;
}
static double b_unix_rw(long n) { /* send 64 bytes then receive them, one thread */
    int s[2];
    char buf[64] = {0};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s)) return -1;
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        send(s[0], buf, 64, 0);
        recv(s[1], buf, 64, 0);
    }
    double r = (double)(now() - t) / n;
    close(s[0]);
    close(s[1]);
    return r;
}
static double b_unix_msg_fd(long n) { /* sendmsg with one descriptor + recvmsg (Wayland-like) */
    int s[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s)) return -1;
    int e = eventfd(0, 0);
    char byte = 'x', cb[CMSG_SPACE(sizeof(int))];
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        struct iovec iov = {&byte, 1};
        struct msghdr m = {0};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = cb;
        m.msg_controllen = sizeof cb;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        c->cmsg_level = SOL_SOCKET;
        c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(c), &e, sizeof(int));
        sendmsg(s[0], &m, 0);
        m.msg_controllen = sizeof cb;
        if (recvmsg(s[1], &m, 0) != 1) return -1;
        int got;
        memcpy(&got, CMSG_DATA(CMSG_FIRSTHDR(&m)), sizeof(int));
        close(got);
    }
    double r = (double)(now() - t) / n;
    close(e);
    close(s[0]);
    close(s[1]);
    return r;
}
static double b_poll_eventfd(long n) { /* poll on a readable eventfd */
    int e = eventfd(1, 0);
    struct pollfd p = {e, POLLIN, 0};
    uint64_t t = now();
    for (long i = 0; i < n; i++) poll(&p, 1, 0);
    double r = (double)(now() - t) / n;
    close(e);
    return r;
}
static double b_timerfd_set(long n) { /* timerfd_settime (arm 1 s ahead) */
    int f = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{0, 0}, {1, 0}};
    uint64_t t = now();
    for (long i = 0; i < n; i++) timerfd_settime(f, 0, &its, 0);
    double r = (double)(now() - t) / n;
    close(f);
    return r;
}
static double b_eventfd_rtt(long n) { /* two processes ping-pong through two eventfds */
    int a = eventfd(0, 0), b = eventfd(0, 0);
    uint64_t v = 1;
    pid_t p = fork();
    if (p == 0) {
        for (long i = 0; i < n; i++) {
            if (read(a, &v, 8) != 8) _exit(1);
            write(b, &v, 8);
        }
        _exit(0);
    }
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        write(a, &v, 8);
        if (read(b, &v, 8) != 8) return -1;
    }
    double r = (double)(now() - t) / n;
    waitpid(p, 0, 0);
    close(a);
    close(b);
    return r;
}

struct bench { const char *name; bench_fn fn; long n; int probe; };
static struct bench benches[] = {
    {"getpid", b_getpid, 200000, 0},
    {"getpgrp", b_getpgrp, 200000, 0},
    {"clock_gettime", b_clock, 200000, 0},
    {"pread_4k_cached", b_read_cached, 50000, 0},
    {"pread_64k_cached", b_read_64k, 5000, 0},
    {"write_devnull_64", b_write_null, 100000, 0},
    {"open_close", b_open_close, 20000, 0},
    {"stat_3level", b_stat, 20000, 0},
    {"fstat", b_fstat, 100000, 0},
    {"pipe_rtt", b_pipe_rtt, 20000, 0},
    {"unix_rtt", b_unix_rtt, 20000, 0},
    {"futex_rtt", b_futex_rtt, 20000, 0},
    {"futex_wake_none", b_futex_wake_none, 200000, 0},
    {"sched_yield", b_yield, 200000, 0},
    {"yield_switch_1cpu", b_yield_pingpong_1cpu, 50000, 0},
    {"pipe_rtt_1cpu", b_pipe_rtt_1cpu, 20000, 0},
    {"futex_rtt_1cpu", b_futex_rtt_1cpu, 20000, 0},
    {"mmap_munmap_1m", b_mmap_munmap, 20000, 0},
    {"fault_anon_page", b_fault_anon, 200, 0},
    {"fork_wait", b_fork_wait, 200, 0},
    {"fork_exec_wait", b_fork_exec_wait, 100, 0},
    {"lx_null", b_lx_null, 200000, 0},
    {"lx_null_par2", b_lx_null_par2, 100000, 0},
    {"keyctl", b_keyctl, 100000, 0},
    {"keyctl_par2", b_keyctl_par2, 50000, 0},
    {"add_key", b_add_key, 50000, 0},
    {"keyctl_describe", b_keyctl_describe, 100000, 0},
    {"mq_rtt", b_mq_rtt, 50000, 0},
    {"semop", b_semop, 100000, 0},
    {"msg_rtt", b_msg_rtt, 50000, 0},
    {"bpf_lookup", b_bpf_lookup, 100000, 0},
    {"poll_pipe", b_poll_pipe, 100000, 0},
    {"epoll_pipe", b_epoll_pipe, 100000, 0},
    {"poll_mq", b_poll_mq, 100000, 0},
    {"eventfd_rw", b_eventfd_rw, 100000, 0},
    {"eventfd_rtt", b_eventfd_rtt, 20000, 0},
    {"pipe_rw", b_pipe_rw, 100000, 0},
    {"unix_rw", b_unix_rw, 100000, 0},
    {"unix_msg_fd", b_unix_msg_fd, 50000, 0},
    {"poll_eventfd", b_poll_eventfd, 100000, 0},
    {"timerfd_set", b_timerfd_set, 100000, 0},
    {"tcp_rtt", b_tcp_rtt, 10000, 0},
    {"tcp_sendrecv", b_tcp_sendrecv, 20000, 0},
    {"tcp_connect", b_tcp_connect, 200, 0},
    {"udp_rtt", b_udp_rtt, 10000, 0},
    {"getsockopt", b_getsockopt, 100000, 0},
    {"poll_tcp", b_poll_tcp, 100000, 0},
    {"svc_rtt", b_svc_rtt, 20000, 0},
    {"svc_rtt_handoff", b_svc_rtt_handoff, 20000, 0},
    {"dcall_rtt", b_dcall_rtt, 20000, 0},
    {"probe_null", b_probe_null, 200000, 1},
    {"probe_handoff", b_probe_handoff, 20000, 1},
    {"probe_queued", b_probe_queued, 20000, 1},
    {"probe_handoff_k", b_probe_handoff_k, 20000, 1},
    {"probe_queued_k", b_probe_queued_k, 20000, 1},
};

int main(int argc, char **argv) {
    const char *e = getenv("PROBE_EP");
    if (e) probe_ep = strtol(e, 0, 0);
    int probe = probe_ok();
    printf("lxbench: probe %s, endpoint %#lx\n", probe ? "available" : "absent", probe_ep);
    for (unsigned k = 0; k < sizeof benches / sizeof *benches; k++) {
        struct bench *b = &benches[k];
        if (argc > 1) {
            int want = 0;
            for (int a = 1; a < argc; a++) want |= !strcmp(argv[a], b->name);
            if (!want) continue;
        }
        if (b->probe && !probe) continue;
        double r[REPS];
        b->fn(b->n / 10 + 1); /* warm-up */
        for (int i = 0; i < REPS; i++) r[i] = b->fn(b->n);
        qsort(r, REPS, sizeof *r, cmp);
        printf("BENCH %-18s min %10.0f med %10.0f max %10.0f ns/op (%ld)\n", b->name, r[0], r[REPS / 2], r[REPS - 1], b->n);
        fflush(stdout);
    }
    printf("LXBENCH-DONE\n");
    return 0;
}
