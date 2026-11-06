// POSIX message queues and Linux native AIO.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <mqueue.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static void msleep(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, 0);
}

static volatile int sig_code, sig_value, thread_ran;
static void on_usr1(int s, siginfo_t *si, void *c) {
    (void)s; (void)c;
    sig_code = si->si_code;
    sig_value = si->si_value.sival_int;
}
static void on_thread(union sigval v) {
    (void)v;
    thread_ran = 1;
}

static struct timespec in_ms(long ms) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_nsec += ms * 1000000;
    t.tv_sec += t.tv_nsec / 1000000000;
    t.tv_nsec %= 1000000000;
    return t;
}

int main(void) {
    char name[32];
    snprintf(name, sizeof name, "/hydra-mq-%d", getpid());
    mq_unlink(name);

    // ---- POSIX message queues
    struct mq_attr attr = {.mq_maxmsg = 4, .mq_msgsize = 64};
    mqd_t q = mq_open(name, O_CREAT | O_RDWR | O_EXCL, 0600, &attr);
    CHECK(q >= 0, "mq_open O_CREAT");
    errno = 0;
    CHECK(mq_open(name, O_CREAT | O_EXCL | O_RDWR, 0600, &attr) == -1 && errno == EEXIST, "O_EXCL on an existing queue");
    struct mq_attr got;
    CHECK(mq_getattr(q, &got) == 0 && got.mq_maxmsg == 4 && got.mq_msgsize == 64 && got.mq_curmsgs == 0, "mq_getattr");
    unsigned prios[4] = {1, 5, 3, 5};
    const char *texts[4] = {"low", "high-a", "mid", "high-b"};
    for (int i = 0; i < 4; i++) mq_send(q, texts[i], strlen(texts[i]) + 1, prios[i]);
    struct pollfd pf = {q, POLLIN | POLLOUT, 0};
    CHECK(poll(&pf, 1, 0) == 1 && (pf.revents & POLLIN) && !(pf.revents & POLLOUT), "poll: readable, full");
    char status[128] = {0};
    CHECK(read(q, status, sizeof status - 1) > 0 && !strncmp(status, "QSIZE:", 6), "reading the descriptor: %.20s", status);
    struct mq_attr nb = {.mq_flags = O_NONBLOCK};
    mq_setattr(q, &nb, 0);
    errno = 0;
    CHECK(mq_send(q, "x", 2, 0) == -1 && errno == EAGAIN, "full queue, non-blocking: EAGAIN");
    char buf[64];
    unsigned prio;
    const char *order[4] = {"high-a", "high-b", "mid", "low"};
    unsigned order_p[4] = {5, 5, 3, 1};
    int good = 1;
    for (int i = 0; i < 4; i++) good &= mq_receive(q, buf, 64, &prio) > 0 && !strcmp(buf, order[i]) && prio == order_p[i];
    CHECK(good, "highest priority first, oldest first within one");
    errno = 0;
    CHECK(mq_receive(q, buf, 64, 0) == -1 && errno == EAGAIN, "empty, non-blocking: EAGAIN");
    nb.mq_flags = 0;
    mq_setattr(q, &nb, 0);
    errno = 0;
    CHECK(mq_receive(q, buf, 32, 0) == -1 && errno == EMSGSIZE, "buffer smaller than mq_msgsize: EMSGSIZE");
    char big[100] = {0};
    errno = 0;
    CHECK(mq_send(q, big, 100, 0) == -1 && errno == EMSGSIZE, "message larger than mq_msgsize: EMSGSIZE");
    struct timespec t = in_ms(100);
    errno = 0;
    CHECK(mq_timedreceive(q, buf, 64, 0, &t) == -1 && errno == ETIMEDOUT, "mq_timedreceive times out");
    pid_t c = fork();
    if (c == 0) _exit(mq_receive(q, buf, 64, &prio) == 6 && !strcmp(buf, "later") && prio == 7 ? 0 : 1);
    msleep(100);
    mq_send(q, "later", 6, 7);
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "a blocked receiver gets a later message");

    struct sigaction sa = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, 0);
    struct sigevent ev = {.sigev_notify = SIGEV_SIGNAL, .sigev_signo = SIGUSR1};
    ev.sigev_value.sival_int = 21;
    CHECK(mq_notify(q, &ev) == 0, "mq_notify SIGEV_SIGNAL");
    c = fork();
    if (c == 0) _exit(mq_notify(q, &ev) == -1 && errno == EBUSY ? 0 : 1);
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "another process: EBUSY");
    mq_send(q, "n", 2, 0);
    msleep(20);
    CHECK(sig_code == SI_MESGQ && sig_value == 21, "notified: code %d value %d", sig_code, sig_value);
    mq_receive(q, buf, 64, 0);
    struct sigevent tev = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = on_thread};
    CHECK(mq_notify(q, &tev) == 0, "mq_notify SIGEV_THREAD");
    mq_send(q, "t", 2, 0);
    for (int i = 0; i < 50 && !thread_ran; i++) msleep(10);
    CHECK(thread_ran, "SIGEV_THREAD callback ran");
    CHECK(mq_unlink(name) == 0, "mq_unlink");
    errno = 0;
    CHECK(mq_open(name, O_RDWR) == -1 && errno == ENOENT, "unlinked: ENOENT");
    CHECK(mq_receive(q, buf, 64, 0) == 2, "the open descriptor still works");
    mq_close(q);

    // ---- AIO
    aio_context_t ctx = 0;
    CHECK(syscall(SYS_io_setup, 8, &ctx) == 0 && ctx != 0, "io_setup");
    aio_context_t bad = 1;
    errno = 0;
    CHECK(syscall(SYS_io_setup, 8, &bad) == -1 && errno == EINVAL, "io_setup with a non-zero context: EINVAL");
    int fd = open("/tmp/aio-test", O_RDWR | O_CREAT | O_TRUNC, 0644);
    int efd = eventfd(0, 0);
    char wbuf[16] = "async hello", rbuf[16] = {0};
    struct iocb w = {.aio_data = 11, .aio_lio_opcode = IOCB_CMD_PWRITE, .aio_fildes = fd, .aio_buf = (uintptr_t)wbuf, .aio_nbytes = 12, .aio_offset = 100,
                     .aio_flags = IOCB_FLAG_RESFD, .aio_resfd = efd};
    struct iocb r = {.aio_data = 22, .aio_lio_opcode = IOCB_CMD_PREAD, .aio_fildes = fd, .aio_buf = (uintptr_t)rbuf, .aio_nbytes = 12, .aio_offset = 100};
    struct iocb *list[2] = {&w, &r};
    CHECK(syscall(SYS_io_submit, ctx, 2, list) == 2, "io_submit write + read");
    struct io_event evs[4];
    struct timespec tmo = {1, 0};
    long n = syscall(SYS_io_getevents, ctx, 2, 4, evs, &tmo);
    CHECK(n == 2 && evs[0].data == 11 && evs[0].res == 12 && evs[1].data == 22 && evs[1].res == 12 && !strcmp(rbuf, "async hello"), "both completed (%ld)", n);
    uint64_t cnt = 0;
    CHECK(read(efd, &cnt, 8) == 8 && cnt == 1, "IOCB_FLAG_RESFD signalled the eventfd");
    int p[2];
    pipe(p);
    struct iocb pl = {.aio_data = 33, .aio_lio_opcode = IOCB_CMD_POLL, .aio_fildes = p[0], .aio_buf = POLLIN};
    struct iocb *one[1] = {&pl};
    CHECK(syscall(SYS_io_submit, ctx, 1, one) == 1, "io_submit poll");
    struct timespec t100 = {0, 100000000};
    CHECK(syscall(SYS_io_getevents, ctx, 1, 4, evs, &t100) == 0, "poll not ready: no event after 100 ms");
    write(p[1], "x", 1);
    n = syscall(SYS_io_getevents, ctx, 1, 4, evs, &tmo);
    CHECK(n == 1 && evs[0].data == 33 && (evs[0].res & POLLIN), "poll completes when the pipe is readable");
    int q2[2];
    pipe(q2);
    struct iocb pl2 = {.aio_data = 44, .aio_lio_opcode = IOCB_CMD_POLL, .aio_fildes = q2[0], .aio_buf = POLLIN};
    one[0] = &pl2;
    syscall(SYS_io_submit, ctx, 1, one);
    struct io_event cev;
    errno = 0;
    long cr = syscall(SYS_io_cancel, ctx, &pl2, &cev);
    n = syscall(SYS_io_getevents, ctx, 1, 4, evs, &tmo);
    CHECK((cr == 0 || (cr == -1 && errno == EINPROGRESS)) && n == 1 && evs[0].data == 44 && evs[0].res == 0, "io_cancel of a pending poll (cr %ld errno %d n %ld data %lld res %lld)", cr, errno, n, (long long)evs[0].data, (long long)evs[0].res);
    struct iocb bad_op = {.aio_lio_opcode = 99, .aio_fildes = fd};
    one[0] = &bad_op;
    errno = 0;
    CHECK(syscall(SYS_io_submit, ctx, 1, one) == -1 && errno == EINVAL, "unknown opcode: EINVAL");
    CHECK(syscall(SYS_io_destroy, ctx) == 0, "io_destroy");
    one[0] = &r;
    errno = 0;
    CHECK(syscall(SYS_io_submit, ctx, 1, one) == -1 && errno == EINVAL, "destroyed context: EINVAL");

    printf(fails ? "MQAIO TEST FAILED (%d)\n" : "MQAIO TEST PASSED\n", fails);
    return fails != 0;
}
