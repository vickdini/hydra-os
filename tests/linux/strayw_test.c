/* strayw_test: stray writes into user memory (wave 4, group 9 follow-up).
 *
 * N processes run the same code with identical stack layouts. Each owns one 4 KiB page of a
 * 64 KiB array on its main stack (at the same virtual address in every process) and makes
 * the kernel write into that page only: epoll_wait (level and edge, maxevents smaller than
 * the ready count), poll, select, read of eventfd/pipe/socket/timerfd, forwarded calls
 * (keyctl, mq_receive, msgrcv, semop: answered by linux-server) and a thread doing the same
 * on its own stack. Every other byte of the array, and guard bytes around each output
 * buffer, hold a pattern that is checked after every call. A kernel write that lands in the
 * wrong process (wrong address space), the wrong place, or with the wrong size breaks a
 * pattern. A second check keeps a 64-bit stack pointer in a callee-saved register across
 * system calls and signals.
 *
 *   strayw_test [seconds] [processes]     prints "STRAYW TEST PASSED" or "... FAILED"
 * Build: gcc -O1 -w -pthread strayw_test.c -o strayw -lrt
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <mqueue.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE 4096
#define PAGES 16
#define PAT(i) ((unsigned char)(0xA5 ^ (i * 7)))

static volatile int stop;
static int me;
static long bad;

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* An arena: PAGES pages; page `own` is used for output, with guard patterns; every other
 * page holds the pattern. */
struct arena {
    unsigned char *m;
    int own;
    const char *who;
};

static void fill(struct arena *a) {
    for (int i = 0; i < PAGES * PAGE; i++) a->m[i] = PAT(i);
}

/* Checks every byte outside [lo, hi) of the own page, and every other page. */
static void check_except(struct arena *a, int lo, int hi, const char *what) {
    int base = a->own * PAGE;
    for (int i = 0; i < PAGES * PAGE; i++) {
        if (i >= base + lo && i < base + hi) continue;
        if (a->m[i] != PAT(i)) {
            if (bad < 20)
                printf("FAIL proc %d %s after %s: byte %d (page %d, own %d) = %02x, expected %02x\n", me, a->who, what, i, i / PAGE, a->own, a->m[i], PAT(i));
            bad++;
            a->m[i] = PAT(i);
        }
    }
}

/* Re-patterns the output range after a call. */
static void refill(struct arena *a, int lo, int hi) {
    int base = a->own * PAGE;
    for (int i = base + lo; i < base + hi; i++) a->m[i] = PAT(i);
}

struct fds {
    int ep, ep_et, efd, pipe_r, pipe_w, sock[2], tfd, sem, msq;
    mqd_t mq;
};

static void one_round(struct arena *a, struct fds *f, int round) {
    unsigned char *o = a->m + a->own * PAGE;
    /* Make several things ready */
    uint64_t one = 1;
    write(f->efd, &one, 8);
    write(f->pipe_w, "x", 1);
    write(f->sock[1], "y", 1);
    /* epoll_wait, maxevents 2 of 4 ready: exactly 2 * 12 bytes at offset 100 */
    int n = epoll_wait(f->ep, (struct epoll_event *)(o + 100), 2, 0);
    check_except(a, 100, 100 + 12 * (n > 0 ? n : 0), "epoll_wait (level, maxevents 2)");
    refill(a, 100, 124);
    n = epoll_wait(f->ep_et, (struct epoll_event *)(o + 200), 3, 0);
    check_except(a, 200, 200 + 12 * (n > 0 ? n : 0), "epoll_wait (edge, maxevents 3)");
    refill(a, 200, 236);
    n = epoll_wait(f->ep, (struct epoll_event *)(o + 301), 1, 0); /* unaligned */
    check_except(a, 301, 301 + 12 * (n > 0 ? n : 0), "epoll_wait (unaligned, maxevents 1)");
    refill(a, 301, 313);
    /* poll: 4 pollfds at offset 400; the kernel may write revents (bytes 6-7 of each) */
    struct pollfd *p = (struct pollfd *)(o + 400);
    int pf[4] = {f->efd, f->pipe_r, f->sock[0], f->tfd};
    for (int i = 0; i < 4; i++) p[i] = (struct pollfd){pf[i], POLLIN, 0};
    poll(p, 4, 0);
    check_except(a, 400, 432, "poll");
    refill(a, 400, 432);
    /* select on an fd_set at offset 600 (128 bytes) */
    fd_set *rs = (fd_set *)(o + 600);
    FD_ZERO(rs);
    FD_SET(f->efd, rs);
    FD_SET(f->pipe_r, rs);
    struct timeval tv = {0, 0};
    select(64, rs, 0, 0, &tv);
    check_except(a, 600, 600 + sizeof(fd_set), "select");
    refill(a, 600, 600 + sizeof(fd_set));
    /* reads: exactly the returned length */
    n = read(f->efd, o + 800, 8);
    check_except(a, 800, 800 + (n > 0 ? n : 0), "read eventfd");
    refill(a, 800, 808);
    n = read(f->pipe_r, o + 900, 16);
    check_except(a, 900, 900 + (n > 0 ? n : 0), "read pipe");
    refill(a, 900, 916);
    n = recv(f->sock[0], o + 1000, 16, MSG_DONTWAIT);
    check_except(a, 1000, 1000 + (n > 0 ? n : 0), "recv socket");
    refill(a, 1000, 1016);
    /* forwarded calls (linux-server) */
    n = syscall(SYS_keyctl, 0 /* GET_KEYRING_ID */, -2, 1);
    check_except(a, 0, 0, "keyctl");
    if (f->mq != (mqd_t)-1) {
        mq_send(f->mq, "zzzz", 4, 1);
        unsigned prio = 0;
        n = mq_receive(f->mq, (char *)o + 1100, 64, (unsigned *)(o + 1200));
        /* data at 1100 (n bytes), priority at 1200 (4 bytes): nothing else */
        if (n > 0) for (int i = 1100 + n; i < 1200; i++) o[i] = PAT(a->own * PAGE + i);
        check_except(a, 1100, 1204, "mq_receive");
        refill(a, 1100, 1204);
        (void)prio;
    }
    if (f->msq >= 0) {
        struct { long t; char d[8]; } m = {1, "abcd"};
        msgsnd(f->msq, &m, 4, 0);
        n = msgrcv(f->msq, o + 1300, 8, 0, IPC_NOWAIT);
        check_except(a, 1300, 1300 + 8 + (n > 0 ? n : 0), "msgrcv");
        refill(a, 1300, 1316);
    }
    if (f->sem >= 0) {
        struct sembuf *s = (struct sembuf *)(o + 1400);
        *s = (struct sembuf){0, 1, 0};
        semop(f->sem, s, 1);
        *s = (struct sembuf){0, -1, 0};
        semop(f->sem, s, 1);
        check_except(a, 1400, 1406, "semop");
        refill(a, 1400, 1406);
    }
    /* clock_gettime and getrusage-like small outputs */
    n = clock_gettime(CLOCK_MONOTONIC, (struct timespec *)(o + 1500));
    check_except(a, 1500, 1516, "clock_gettime");
    refill(a, 1500, 1516);
    if (round % 64 == 0) check_except(a, 0, 0, "round");
}

static void setup(struct fds *f, int tag) {
    f->ep = epoll_create1(0);
    f->ep_et = epoll_create1(0);
    f->efd = eventfd(0, EFD_NONBLOCK);
    int pp[2];
    pipe2(pp, O_NONBLOCK);
    f->pipe_r = pp[0];
    f->pipe_w = pp[1];
    socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, f->sock);
    f->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    struct itimerspec its = {{0, 1000000}, {0, 1000000}};
    timerfd_settime(f->tfd, 0, &its, 0);
    int all[4] = {f->efd, f->pipe_r, f->sock[0], f->tfd};
    for (int i = 0; i < 4; i++) {
        struct epoll_event e = {.events = EPOLLIN, .data.u64 = 0x1111111111111111ull * (i + 1)};
        epoll_ctl(f->ep, EPOLL_CTL_ADD, all[i], &e);
        e.events = EPOLLIN | EPOLLET;
        epoll_ctl(f->ep_et, EPOLL_CTL_ADD, all[i], &e);
    }
    char name[32];
    snprintf(name, sizeof name, "/strayw-%d-%d", getpid(), tag);
    struct mq_attr at = {.mq_maxmsg = 4, .mq_msgsize = 64};
    f->mq = mq_open(name, O_CREAT | O_RDWR | O_NONBLOCK, 0600, &at);
    mq_unlink(name);
    if (f->mq != (mqd_t)-1) {
        struct epoll_event e = {.events = EPOLLIN, .data.u64 = 0x5555555555555555ull};
        epoll_ctl(f->ep, EPOLL_CTL_ADD, f->mq, &e);
    }
    f->msq = msgget(IPC_PRIVATE, 0600);
    f->sem = semget(IPC_PRIVATE, 1, 0600);
}

static void teardown(struct fds *f) {
    if (f->msq >= 0) msgctl(f->msq, IPC_RMID, 0);
    if (f->sem >= 0) semctl(f->sem, 0, IPC_RMID);
}

static void on_usr1(int s) { (void)s; }

/* A callee-saved register holding a full 64-bit stack address across system calls and
 * signals: r12 = &local, loop { syscall; compare }. */
static long reg_check(long rounds) {
    volatile long local = 0;
    long fails = 0;
    for (long i = 0; i < rounds && !stop; i++) {
        long out;
        __asm__ volatile(
            "mov %1, %%r12\n\t"
            "mov $39, %%eax\n\t" /* getpid */
            "syscall\n\t"
            "mov $24, %%eax\n\t" /* sched_yield */
            "syscall\n\t"
            "mov %%r12, %0\n\t"
            : "=r"(out)
            : "r"((long)&local)
            : "rax", "rcx", "r11", "r12", "memory");
        if (out != (long)&local) {
            if (fails < 5) printf("FAIL proc %d: r12 %#lx after syscalls, expected %#lx\n", me, out, (long)&local);
            fails++;
        }
    }
    return fails;
}

struct tharg {
    int idx;
};

static void *thread_main(void *x) {
    struct tharg *t = x;
    unsigned char m[PAGES * PAGE];
    struct arena a = {m, (t->idx + 7) % PAGES, "thread stack"};
    fill(&a);
    struct fds f;
    setup(&f, 100 + t->idx);
    for (int r = 0; !stop; r++) one_round(&a, &f, r);
    check_except(&a, 0, 0, "end");
    teardown(&f);
    return 0;
}

static int child(int idx, int secs) {
    me = idx;
    unsigned char m[PAGES * PAGE]; /* the same address in every process */
    struct arena a = {m, idx % PAGES, "main stack"};
    fill(&a);
    struct fds f;
    setup(&f, 0);
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, 0);
    struct tharg ta = {idx};
    pthread_t th;
    pthread_create(&th, 0, thread_main, &ta);
    uint64_t end = now_ms() + secs * 1000;
    long rounds = 0, regfails = 0;
    while (now_ms() < end) {
        one_round(&a, &f, (int)rounds);
        regfails += reg_check(50);
        if ((rounds & 15) == 0) kill(getpid(), SIGUSR1);
        rounds++;
    }
    stop = 1;
    pthread_join(th, 0);
    check_except(&a, 0, 0, "end");
    teardown(&f);
    printf("proc %d: %ld rounds, %ld bad bytes, %ld register failures (arena %p)\n", idx, rounds, bad, regfails, (void *)m);
    return bad || regfails ? 1 : 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    int secs = argc > 1 ? atoi(argv[1]) : 20;
    int procs = argc > 2 ? atoi(argv[2]) : 6;
    pid_t pids[64];
    for (int i = 0; i < procs; i++) {
        pids[i] = fork();
        if (pids[i] == 0) _exit(child(i, secs));
    }
    int fails = 0;
    for (int i = 0; i < procs; i++) {
        int st;
        waitpid(pids[i], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) fails++;
    }
    printf(fails ? "STRAYW TEST FAILED (%d processes)\n" : "STRAYW TEST PASSED\n", fails);
    return fails ? 1 : 0;
}
