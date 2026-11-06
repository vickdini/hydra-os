// io_uring through the raw system calls (no liburing): rings, file I/O, requests that wait
// (pipe reads, polls, receives) finished by the kernel while the program is elsewhere,
// eventfd notification, timeouts, links and link timeouts, cancellation, registered files,
// provided buffers, open/statx/close, the probe, and errors.
// Build: gcc -O1 -w -o io_uring_test io_uring_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct sqring_off { uint32_t head, tail, ring_mask, ring_entries, flags, dropped, array, resv1; uint64_t resv2; };
struct cqring_off { uint32_t head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1; uint64_t resv2; };
struct params {
    uint32_t sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle, features, wq_fd, resv[3];
    struct sqring_off sq_off;
    struct cqring_off cq_off;
};
struct sqe {
    uint8_t opcode, flags;
    uint16_t ioprio;
    int32_t fd;
    uint64_t off, addr;
    uint32_t len, op_flags;
    uint64_t user_data;
    uint16_t buf_index, personality;
    int32_t file_index;
    uint64_t addr3, pad;
};
struct cqe { uint64_t user_data; int32_t res; uint32_t flags; };
struct kts { int64_t s, ns; };

enum { NOP = 0, READV = 1, WRITEV = 2, POLL_ADD = 6, TIMEOUT = 11, ASYNC_CANCEL = 14, LINK_TIMEOUT = 15, OPENAT = 18, CLOSE = 19,
       STATX = 21, READ = 22, WRITE = 23, SEND = 26, RECV = 27, PROVIDE_BUFFERS = 31 };
#define F_FIXED 1
#define F_LINK 4
#define F_BUFSEL 32

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int ring_fd;
static struct params p;
static uint8_t *sq_ring, *cq_ring;
static struct sqe *sqes;
static uint32_t *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
static struct cqe *cqes;
static uint32_t local_tail;

static int setup(unsigned entries) {
    memset(&p, 0, sizeof p);
    ring_fd = syscall(425, entries, &p);
    if (ring_fd < 0) return -1;
    size_t sq_sz = p.sq_off.array + p.sq_entries * 4, cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
    size_t sz = sq_sz > cq_sz ? sq_sz : cq_sz;
    sq_ring = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, 0);
    cq_ring = sq_ring;   // IORING_FEAT_SINGLE_MMAP
    sqes = mmap(0, p.sq_entries * sizeof(struct sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, 0x10000000);
    if (sq_ring == MAP_FAILED || sqes == MAP_FAILED) return -2;
    sq_tail = (uint32_t *)(sq_ring + p.sq_off.tail);
    sq_mask = (uint32_t *)(sq_ring + p.sq_off.ring_mask);
    sq_array = (uint32_t *)(sq_ring + p.sq_off.array);
    cq_head = (uint32_t *)(cq_ring + p.cq_off.head);
    cq_tail = (uint32_t *)(cq_ring + p.cq_off.tail);
    cq_mask = (uint32_t *)(cq_ring + p.cq_off.ring_mask);
    cqes = (struct cqe *)(cq_ring + p.cq_off.cqes);
    local_tail = *sq_tail;
    return 0;
}

static struct sqe *get_sqe(void) {
    uint32_t idx = local_tail & *sq_mask;
    struct sqe *s = &sqes[idx];
    memset(s, 0, sizeof *s);
    sq_array[idx] = idx;
    local_tail++;
    return s;
}

static int enter(unsigned submit, unsigned wait) {
    __atomic_store_n(sq_tail, local_tail, __ATOMIC_RELEASE);
    return syscall(426, ring_fd, submit, wait, wait ? 1 : 0, 0, 0);
}

static int pending_cqes(void) { return __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) - *cq_head; }

// Takes the next completion (waiting for one through the kernel if needed)
static struct cqe take(void) {
    if (pending_cqes() == 0) syscall(426, ring_fd, 0, 1, 1, 0, 0);
    struct cqe c = {~0ull, -9999, 0};
    if (pending_cqes() > 0) {
        c = cqes[*cq_head & *cq_mask];
        __atomic_store_n(cq_head, *cq_head + 1, __ATOMIC_RELEASE);
    }
    return c;
}

static struct sqe *prep(struct sqe *s, int op, int fd, uint64_t addr, uint32_t len, uint64_t off, uint64_t ud) {
    s->opcode = op;
    s->fd = fd;
    s->addr = addr;
    s->len = len;
    s->off = off;
    s->user_data = ud;
    return s;
}

static int supported(int op) {
    unsigned char probe[16 + 256 * 8] = {0};
    if (syscall(427, ring_fd, 8, probe, 256) != 0) return 0;
    return op <= probe[0] && (probe[16 + op * 8 + 2] & 1);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    errno = 0;
    check(syscall(425, 0, &p) == -1 && errno == EINVAL, "setup with 0 entries: EINVAL");
    int r = setup(8);
    if (r == -1 && (errno == ENOSYS || errno == EPERM)) {
        printf("skip: io_uring unavailable (%s)\n", strerror(errno));
        return 0;
    }
    check(r == 0 && p.sq_entries == 8 && p.cq_entries == 16, "setup: 8 SQ entries, 16 CQ entries, rings mapped");
    check(p.features & 1, "IORING_FEAT_SINGLE_MMAP");
    check(supported(NOP) && supported(READ) && supported(TIMEOUT), "probe lists NOP, READ, TIMEOUT");
    errno = 0;
    check(syscall(426, 0, 0, 0, 0, 0, 0) == -1 && errno == EOPNOTSUPP, "enter on a non-ring descriptor: EOPNOTSUPP");

    // NOP
    prep(get_sqe(), NOP, -1, 0, 0, 0, 42);
    check(enter(1, 1) == 1, "submit one");
    struct cqe c = take();
    check(c.user_data == 42 && c.res == 0, "NOP completes with its user_data");

    // File write and read
    char path[64];
    snprintf(path, sizeof path, "/tmp/iou.%d", getpid());
    int f = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    prep(get_sqe(), WRITE, f, (uint64_t)"hello uring", 11, 0, 1);
    enter(1, 1);
    c = take();
    char buf[64] = {0};
    prep(get_sqe(), READ, f, (uint64_t)buf, 5, 6, 2);
    enter(1, 1);
    struct cqe c2 = take();
    check(c.res == 11 && c2.res == 5 && !memcmp(buf, "uring", 5), "WRITE then READ at an offset");
    struct iovec iv[2] = {{buf, 2}, {buf + 10, 3}};
    memset(buf, 0, sizeof buf);
    prep(get_sqe(), READV, f, (uint64_t)iv, 2, 0, 3);
    enter(1, 1);
    c = take();
    check(c.res == 5 && !memcmp(buf, "he", 2) && !memcmp(buf + 10, "llo", 3), "READV");

    // A read that waits: the pipe is empty
    int pp[2];
    pipe(pp);
    char pbuf[16] = {0};
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, sizeof pbuf, -1, 10);
    check(enter(1, 0) == 1 && pending_cqes() == 0, "read on an empty pipe stays pending");
    write(pp[1], "ping", 4);
    c = take();
    check(c.user_data == 10 && c.res == 4 && !memcmp(pbuf, "ping", 4), "pending read finishes once data arrives");

    // Completion while the program sleeps in epoll on a registered eventfd
    int efd = eventfd(0, EFD_NONBLOCK);
    check(syscall(427, ring_fd, 4, &efd, 1) == 0, "register eventfd");
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    char rbuf[16] = {0};
    prep(get_sqe(), RECV, sv[0], (uint64_t)rbuf, sizeof rbuf, 0, 11);
    enter(1, 0);
    if (fork() == 0) {
        usleep(30000);
        write(sv[1], "sock", 4);
        _exit(0);
    }
    struct epoll_event out;
    // Linux may interrupt the wait to post the completion (task work): EINTR, try again
    int n;
    do n = epoll_wait(ep, &out, 1, 2000); while (n < 0 && errno == EINTR);
    check(n == 1, "eventfd fires while the program sleeps in epoll");
    c = take();
    check(c.user_data == 11 && c.res == 4 && !memcmp(rbuf, "sock", 4), "RECV on a socket finished by the kernel");
    uint64_t cnt;
    read(efd, &cnt, 8);
    check(syscall(427, ring_fd, 5, 0, 0) == 0, "unregister eventfd");

    // poll on the ring itself
    prep(get_sqe(), NOP, -1, 0, 0, 0, 12);
    enter(1, 0);
    struct pollfd pf = {ring_fd, POLLIN, 0};
    check(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLIN), "ring descriptor polls readable with a completion queued");
    take();

    // POLL_ADD
    prep(get_sqe(), POLL_ADD, pp[0], 0, 0, 0, 13)->op_flags = POLLIN;
    enter(1, 0);
    check(pending_cqes() == 0, "POLL_ADD on an empty pipe waits");
    write(pp[1], "x", 1);
    c = take();
    check(c.user_data == 13 && (c.res & POLLIN), "POLL_ADD completes with POLLIN");
    read(pp[0], pbuf, 1);

    // TIMEOUT
    struct kts ts = {0, 20 * 1000 * 1000};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    prep(get_sqe(), TIMEOUT, -1, (uint64_t)&ts, 1, 0, 14);
    enter(1, 1);
    c = take();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    check(c.user_data == 14 && c.res == -ETIME && ms >= 15 && ms < 1000, "TIMEOUT expires with -ETIME after about 20 ms");
    struct kts longts = {10, 0};
    prep(get_sqe(), TIMEOUT, -1, (uint64_t)&longts, 1, 1, 15);   // or after 1 completion
    prep(get_sqe(), NOP, -1, 0, 0, 0, 16);
    enter(2, 2);
    int got_t = 0, got_n = 0;
    for (int i = 0; i < 2; i++) {
        c = take();
        if (c.user_data == 15 && c.res == 0) got_t = 1;
        if (c.user_data == 16 && c.res == 0) got_n = 1;
    }
    check(got_t && got_n, "TIMEOUT with a count completes after that many completions");

    // Links: a failed request cancels the rest of its chain
    struct sqe *s = get_sqe();
    prep(s, READ, 9999, (uint64_t)buf, 4, 0, 17);
    s->flags = F_LINK;
    prep(get_sqe(), NOP, -1, 0, 0, 0, 18);
    enter(2, 2);
    struct cqe a = take(), b = take();
    check(a.user_data == 17 && a.res == -EBADF && b.user_data == 18 && b.res == -ECANCELED, "link: failure cancels the next request");
    s = get_sqe();
    prep(s, WRITE, pp[1], (uint64_t)"ab", 2, -1, 19);
    s->flags = F_LINK;
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, 2, -1, 20);
    enter(2, 2);
    a = take(), b = take();
    check(a.user_data == 19 && a.res == 2 && b.user_data == 20 && b.res == 2, "link: write then read run in order");

    // LINK_TIMEOUT cancels a request that takes too long
    s = get_sqe();
    prep(s, READ, pp[0], (uint64_t)pbuf, 4, -1, 21);
    s->flags = F_LINK;
    prep(get_sqe(), LINK_TIMEOUT, -1, (uint64_t)&ts, 1, 0, 22);
    enter(2, 2);
    a = take(), b = take();
    int lt_ok = (a.user_data == 21 && a.res == -ECANCELED && b.user_data == 22 && b.res == -ETIME) ||
                (b.user_data == 21 && b.res == -ECANCELED && a.user_data == 22 && a.res == -ETIME);
    check(lt_ok, "LINK_TIMEOUT: the read is cancelled, the timeout reports -ETIME");

    // ASYNC_CANCEL
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, 4, -1, 23);
    enter(1, 0);
    prep(get_sqe(), ASYNC_CANCEL, -1, 23, 0, 0, 24);
    enter(1, 2);
    a = take(), b = take();
    int cancel_ok = (a.user_data == 23 && a.res == -ECANCELED && b.user_data == 24 && b.res == 0) ||
                    (b.user_data == 23 && b.res == -ECANCELED && a.user_data == 24 && a.res == 0);
    check(cancel_ok, "ASYNC_CANCEL cancels a pending read");

    // Registered files
    check(syscall(427, ring_fd, 2, &f, 1) == 0, "register files");
    memset(buf, 0, sizeof buf);
    s = get_sqe();
    prep(s, READ, 0, (uint64_t)buf, 5, 0, 25);
    s->flags = F_FIXED;
    enter(1, 1);
    c = take();
    check(c.res == 5 && !memcmp(buf, "hello", 5), "READ through a registered file");
    check(syscall(427, ring_fd, 3, 0, 0) == 0, "unregister files");

    // Provided buffers and buffer selection
    static char pool[2][32];
    prep(get_sqe(), PROVIDE_BUFFERS, 2, (uint64_t)pool, 32, 0, 26)->buf_index = 7;
    enter(1, 1);
    c = take();
    check(c.res >= 0, "PROVIDE_BUFFERS");
    s = get_sqe();
    prep(s, READ, f, 0, 5, 0, 27);
    s->flags = F_BUFSEL;
    s->buf_index = 7;
    enter(1, 1);
    c = take();
    int bid = c.flags >> 16;
    check(c.res == 5 && (c.flags & 1) && bid < 2 && !memcmp(pool[bid], "hello", 5), "READ into a selected buffer (IORING_CQE_F_BUFFER)");

    // Open, statx and close through the ring
    prep(get_sqe(), OPENAT, AT_FDCWD, (uint64_t)path, 0644, 0, 28)->op_flags = O_RDONLY;
    enter(1, 1);
    c = take();
    int of = c.res;
    struct statx stx;
    s = get_sqe();
    prep(s, STATX, AT_FDCWD, (uint64_t)path, STATX_SIZE, (uint64_t)&stx, 29);
    enter(1, 1);
    c2 = take();
    prep(get_sqe(), CLOSE, of, 0, 0, 0, 30);
    enter(1, 1);
    struct cqe c3 = take();
    check(of >= 0 && c2.res == 0 && stx.stx_size == 11 && c3.res == 0 && fcntl(of, F_GETFD) == -1, "OPENAT, STATX and CLOSE");

    // SEND then RECV on a socket pair
    prep(get_sqe(), SEND, sv[1], (uint64_t)"data", 4, 0, 31);
    enter(1, 1);
    c = take();
    memset(rbuf, 0, sizeof rbuf);
    prep(get_sqe(), RECV, sv[0], (uint64_t)rbuf, sizeof rbuf, 0, 32);
    enter(1, 1);
    c2 = take();
    check(c.res == 4 && c2.res == 4 && !memcmp(rbuf, "data", 4), "SEND and RECV");

    unlink(path);
    printf(fails ? "IO_URING TEST FAILED (%d)\n" : "IO_URING TEST PASSED\n", fails);
    return fails != 0;
}
