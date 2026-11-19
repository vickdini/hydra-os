/* srvobj_test: server-object descriptors (wave 4, group 9): descriptors whose object lives
 * in the ring-3 linux-server (POSIX message queues, the test object), their readiness
 * words (poll/select/epoll without a call to the server), reference counting, and blocking
 * calls that do not tie up the server's workers.
 *
 *   srvobj_test          the checks; prints "SRVOBJ TEST PASSED" or "SRVOBJ TEST FAILED (n)"
 *   srvobj_test block    the kill test's load: threads blocked in mq_receive, semop and
 *                        epoll_wait (on a queue descriptor); prints "BLOCKED" and waits;
 *                        each call that returns prints its result
 *
 * With the forwarding switched back to the kernel (lx=kernel) the message-queue checks run
 * against the in-kernel code and the test-object checks (which need the server) are
 * skipped.
 * Build: gcc -O1 -w -pthread srvobj_test.c -o srvobj -lrt
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
#include <sys/ipc.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL 0x6710
#define LX_NULL_OBJ 3
#define LX_NULL_OBJ_CLOSES 4

static int fails;
static int server;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void msleep(int ms) { usleep(ms * 1000); }
static long closes(void) { return syscall(LX_NULL, LX_NULL_OBJ_CLOSES, 0, 0); }

static mqd_t newq(const char *name, int flags) {
    struct mq_attr a = {.mq_maxmsg = 10, .mq_msgsize = 64};
    mq_unlink(name);
    return mq_open(name, O_CREAT | O_EXCL | O_RDWR | flags, 0600, &a);
}

/* --- poll from another thread --- */
static mqd_t g_q;
static volatile int g_revents = -1;
static void *poller(void *arg) {
    (void)arg;
    struct pollfd p = {g_q, POLLIN, 0};
    int n = poll(&p, 1, 5000);
    g_revents = n == 1 ? p.revents : -100 - n;
    return 0;
}

/* --- many blocked receivers --- */
static volatile int got_msgs;
static void *receiver(void *arg) {
    mqd_t q = (mqd_t)(long)arg;
    char buf[64];
    if (mq_receive(q, buf, sizeof buf, 0) > 0) __sync_fetch_and_add(&got_msgs, 1);
    return 0;
}

/* --- the test object --- */
static void *obj_waiter(void *arg) {
    int ep = (int)(long)arg;
    struct epoll_event e;
    int n = epoll_wait(ep, &e, 1, 5000);
    return (void *)(long)(n == 1 && (e.events & EPOLLIN) ? 1 : 0);
}

static void test_object(void) {
    long before = closes();
    int fd = syscall(LX_NULL, LX_NULL_OBJ, 0, 0);
    check(fd > 2, "test object: a descriptor from the server");
    if (fd <= 2) return;
    char buf[64] = {0};
    long n = read(fd, buf, sizeof buf - 1);
    check(n > 5 && !strncmp(buf, "slot ", 5), "read is forwarded to the server");
    struct pollfd p = {fd, POLLIN | POLLOUT, 0};
    check(poll(&p, 1, 0) == 0, "poll: not ready (readiness word 0)");
    /* An epoll waiter in another thread is woken by the server's doorbell */
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN, .data.fd = fd};
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &e);
    pthread_t t;
    pthread_create(&t, 0, obj_waiter, (void *)(long)ep);
    msleep(100);
    write(fd, "r", 1);
    void *woke;
    pthread_join(t, &woke);
    check(woke == (void *)1, "epoll_wait in another thread woken when the word changes");
    check(poll(&p, 1, 0) == 1 && p.revents == POLLIN, "poll: readable");
    write(fd, "w", 1);
    check(poll(&p, 1, 0) == 1 && p.revents == (POLLIN | POLLOUT), "poll: readable and writable");
    /* Edge-triggered: reported once per new readiness */
    int ep2 = epoll_create1(0);
    struct epoll_event e2 = {.events = EPOLLIN | EPOLLET, .data.fd = fd};
    epoll_ctl(ep2, EPOLL_CTL_ADD, fd, &e2);
    check(epoll_wait(ep2, &e, 1, 0) == 1, "EPOLLET: ready at once");
    check(epoll_wait(ep2, &e, 1, 50) == 0, "EPOLLET: not again without a change");
    write(fd, "c", 1);
    write(fd, "r", 1);
    check(epoll_wait(ep2, &e, 1, 0) == 1, "EPOLLET: again after it became readable again");
    close(ep2);
    write(fd, "c", 1);
    close(ep);
    /* Reference counting: the server hears of the last close exactly once */
    int d = dup(fd);
    int d2 = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    close(fd);
    close(d2);
    msleep(20);
    check(closes() == before, "closing two of three descriptors: not closed yet");
    pid_t c = fork();
    if (c == 0) {
        close(d);
        _exit(0);
    }
    waitpid(c, 0, 0);
    msleep(50);
    check(closes() == before, "a child closing its copy: not closed yet");
    c = fork();
    if (c == 0) _exit(0); /* exits holding it */
    waitpid(c, 0, 0);
    msleep(50);
    check(closes() == before, "a child exiting with a copy: not closed yet");
    close(d);
    long after = before;
    for (int i = 0; i < 50 && (after = closes()) == before; i++) msleep(20);
    check(after == before + 1, "last close: closed once");
    msleep(100);
    check(closes() == before + 1, "...and only once");
    /* Close-on-exec: a child exec'ing drops its copy, the parent's stays */
    before = closes();
    fd = syscall(LX_NULL, LX_NULL_OBJ, O_CLOEXEC, 0);
    int keep = syscall(LX_NULL, LX_NULL_OBJ, 0, 0);
    c = fork();
    if (c == 0) {
        execl("/bin/true", "true", (char *)0);
        _exit(1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    msleep(50);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0 && closes() == before, "exec in a child: the parent's objects stay open");
    close(fd);
    close(keep);
    for (int i = 0; i < 50 && closes() < before + 2; i++) msleep(20);
    check(closes() == before + 2, "both closed by the parent: two closes");
    /* Many objects at once (slots are reused) */
    int fds[300], ok = 1;
    for (int i = 0; i < 300; i++) ok &= (fds[i] = syscall(LX_NULL, LX_NULL_OBJ, 0, 0)) > 2;
    for (int i = 0; i < 300; i++) close(fds[i]);
    check(ok, "300 objects at once");
}

static void test_mqueue(void) {
    const char *name = "/srvobj-q";
    mqd_t q = newq(name, 0);
    check(q >= 0, "mq_open");
    if (q < 0) return;
    struct pollfd p = {q, POLLIN | POLLOUT, 0};
    check(poll(&p, 1, 0) == 1 && p.revents == POLLOUT, "poll: empty queue is writable only");
    /* poll in another thread, woken by a send */
    g_q = q;
    pthread_t t;
    pthread_create(&t, 0, poller, 0);
    msleep(100);
    mq_send(q, "a", 2, 1);
    pthread_join(t, 0);
    check(g_revents == POLLIN, "poll in another thread wakes on mq_send");
    /* select */
    fd_set r;
    FD_ZERO(&r);
    FD_SET(q, &r);
    struct timeval tv = {0, 0};
    check(select(q + 1, &r, 0, 0, &tv) == 1 && FD_ISSET(q, &r), "select: readable");
    /* Edge-triggered epoll: one report per message */
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN | EPOLLET, .data.fd = q};
    epoll_ctl(ep, EPOLL_CTL_ADD, q, &e);
    check(epoll_wait(ep, &e, 1, 0) == 1, "EPOLLET: readable at once");
    /* (The in-kernel queues, lx=kernel, are level-triggered: more reports than Linux) */
    /* (Hydra's routing query 0x6713: whether mq_open goes to a service, or the kernel) */
    if (server && syscall(0x6713, 240, 0) > 0) check(epoll_wait(ep, &e, 1, 50) == 0, "EPOLLET: no second report without a new message");
    mq_send(q, "b", 2, 1);
    check(epoll_wait(ep, &e, 1, 0) == 1, "EPOLLET: reported again for a new message");
    char buf[64];
    mq_receive(q, buf, 64, 0);
    mq_receive(q, buf, 64, 0);
    check(epoll_wait(ep, &e, 1, 0) == 0, "EPOLLET: empty again: nothing");
    /* Level-triggered epoll in a child process (an inherited descriptor) */
    pid_t c = fork();
    if (c == 0) {
        int ep2 = epoll_create1(0);
        struct epoll_event e2 = {.events = EPOLLIN, .data.fd = q};
        epoll_ctl(ep2, EPOLL_CTL_ADD, q, &e2);
        int n = epoll_wait(ep2, &e2, 1, 5000);
        _exit(n == 1 && (e2.events & EPOLLIN) ? 0 : 1);
    }
    msleep(150);
    mq_send(q, "c", 2, 1);
    int st = 0;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "epoll_wait in a child process wakes on the parent's send");
    mq_receive(q, buf, 64, 0);
    close(ep);
    /* fstat: the size word */
    mq_send(q, "12345", 6, 0);
    struct stat sb;
    check(fstat(q, &sb) == 0 && S_ISREG(sb.st_mode) && sb.st_size == 6, "fstat: size from the readiness word");
    mq_receive(q, buf, 64, 0);
    /* fcntl O_NONBLOCK reaches the call */
    fcntl(q, F_SETFL, O_NONBLOCK);
    check(mq_receive(q, buf, 64, 0) == -1 && errno == EAGAIN, "fcntl(O_NONBLOCK): mq_receive EAGAIN");
    struct mq_attr a;
    check(mq_getattr(q, &a) == 0 && (a.mq_flags & O_NONBLOCK), "mq_getattr sees O_NONBLOCK");
    fcntl(q, F_SETFL, 0);
    /* More blocked callers than the server has workers: other calls go on */
    got_msgs = 0;
    pthread_t rt[16];
    for (int i = 0; i < 16; i++) pthread_create(&rt[i], 0, receiver, (void *)(long)q);
    msleep(300);
    uint64_t t0 = now_ms();
    int good = 1;
    for (int i = 0; i < 200; i++) good &= syscall(SYS_keyctl, 0 /* KEYCTL_GET_KEYRING_ID */, -2 /* process keyring */, 1) > 0;
    uint64_t dt = now_ms() - t0;
    printf("     (200 keyctl calls with 16 receivers blocked: %llu ms)\n", (unsigned long long)dt);
    check(good && dt < 3000, "16 threads blocked in mq_receive: keyctl calls are not held up");
    for (int i = 0; i < 16; i++) mq_send(q, "m", 2, 0);
    for (int i = 0; i < 16; i++) pthread_join(rt[i], 0);
    check(got_msgs == 16, "the 16 receivers each got a message");
    mq_close(q);
    mq_unlink(name);
}

static void on_alrm(int s) { (void)s; }

static void test_interrupt(void) {
    mqd_t q = newq("/srvobj-int", 0);
    struct sigaction sa = {0};
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 0}, {0, 200000}};
    setitimer(ITIMER_REAL, &it, 0);
    char buf[64];
    uint64_t t0 = now_ms();
    long r = mq_receive(q, buf, 64, 0);
    check(r == -1 && errno == EINTR && now_ms() - t0 < 2000, "blocked mq_receive: a signal gives EINTR");
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 150000000;
    if (ts.tv_nsec >= 1000000000) ts.tv_sec++, ts.tv_nsec -= 1000000000;
    t0 = now_ms();
    r = mq_timedreceive(q, buf, 64, 0, &ts);
    uint64_t dt = now_ms() - t0;
    check(r == -1 && errno == ETIMEDOUT && dt >= 100 && dt < 1500, "mq_timedreceive times out (pending, completed by the server)");
    mq_close(q);
    mq_unlink("/srvobj-int");
}

/* --- the kill test's load --- */
static mqd_t bq;
static int bsem;
static void *b_recv(void *a) {
    (void)a;
    char buf[64];
    long r = mq_receive(bq, buf, 64, 0);
    printf("mq_receive returned %ld errno %d\n", r, errno);
    return 0;
}
static void *b_sem(void *a) {
    (void)a;
    struct sembuf op = {0, -1, 0};
    long r = semop(bsem, &op, 1);
    printf("semop returned %ld errno %d\n", r, errno);
    return 0;
}
static void *b_epoll(void *a) {
    (void)a;
    int ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN, .data.fd = bq};
    epoll_ctl(ep, EPOLL_CTL_ADD, bq, &e);
    long r = epoll_wait(ep, &e, 1, -1);
    printf("epoll_wait returned %ld errno %d events %#x\n", r, errno, e.events);
    return 0;
}

static void block(void) {
    bq = newq("/srvobj-block", 0);
    bsem = semget(IPC_PRIVATE, 1, 0600);
    pthread_t t[3];
    pthread_create(&t[0], 0, b_recv, 0);
    pthread_create(&t[1], 0, b_sem, 0);
    pthread_create(&t[2], 0, b_epoll, 0);
    msleep(300);
    printf("BLOCKED (mq %d, sem %d)\n", bq, bsem);
    for (int i = 0; i < 3; i++) pthread_join(t[i], 0);
    printf("all three returned\n");
    exit(0);
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "block")) block();
    int fd = syscall(LX_NULL, LX_NULL_OBJ, 0, 0);
    server = fd > 2;
    if (server) close(fd);
    printf("server objects: %s\n", server ? "on (linux-server)" : "off (in the kernel: test-object checks skipped)");
    if (server) test_object();
    test_mqueue();
    test_interrupt();
    if (fails) printf("SRVOBJ TEST FAILED (%d)\n", fails);
    else printf("SRVOBJ TEST PASSED\n");
    return fails ? 1 : 0;
}
