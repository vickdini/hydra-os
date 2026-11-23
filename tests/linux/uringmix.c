// wave9 G6b-4: io_uring requests on descriptors of every owner in one ring: files (vfs-server
// paths, kernel file handles), a TCP loopback socket (lx-net), a pipe (lx-ipc); opens, stats,
// renames, unlinks and closes through the ring. Modes:
//   uringmix            the mixed test (ok/FAIL lines, "uringmix: N failures")
//   uringmix bench MB   throughput: ring READ/WRITE 64 KiB on an MB-MiB file, pipe round trips
//   uringmix kill SECS  parks a pipe READ, a socket RECV and an ACCEPT, prints PARKED, reports
//                       every completion for SECS seconds (a service is killed meanwhile),
//                       wakes what is left, and checks that the ring still works
// Build: gcc -O1 -w -pthread -o uringmix uringmix.c
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


#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum { FSYNC = 3, ACCEPT = 13, CONNECT = 16, RENAMEAT = 35, UNLINKAT = 36, MKDIRAT = 37 };

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// Waits up to ms for a completion; 1 = one is there
static int wait_cqe(int ms) {
    if (pending_cqes() > 0) return 1;
    struct pollfd pf = {ring_fd, POLLIN, 0};
    poll(&pf, 1, ms);
    return pending_cqes() > 0;
}

static int listener(int *port) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    if (bind(l, (void *)&a, sizeof a) || listen(l, 4) || getsockname(l, (void *)&a, &al)) return -1;
    *port = ntohs(a.sin_port);
    return l;
}

static struct sockaddr_in to_port(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    return a;
}

// Takes completions until the one with user_data ud (others are kept aside)
static struct cqe got[32];
static int ngot;
static struct cqe take_ud(uint64_t ud) {
    for (int i = 0; i < ngot; i++)
        if (got[i].user_data == ud) {
            struct cqe c = got[i];
            got[i] = got[--ngot];
            return c;
        }
    for (int tries = 0; tries < 50; tries++) {
        if (!wait_cqe(100)) continue;
        struct cqe c = take();
        if (c.user_data == ud) return c;
        if (ngot < 32) got[ngot++] = c;
    }
    struct cqe none = {ud, -9999, 0};
    return none;
}

static int has_ud(uint64_t ud) {
    for (int i = 0; i < ngot; i++)
        if (got[i].user_data == ud) return 1;
    while (pending_cqes() > 0 && ngot < 32) got[ngot++] = take();
    for (int i = 0; i < ngot; i++)
        if (got[i].user_data == ud) return 1;
    return 0;
}

static void mix(void) {
    char buf[256];
    struct cqe c;
    // --- files: a path in the Ubuntu tree (vfs-server) and in /tmp
    const char *dirs[2] = {"/var/tmp", "/tmp"};
    for (int d = 0; d < 2; d++) {
        char path[96], path2[96], sub[96], what[128];
        snprintf(path, sizeof path, "%s/um.%d", dirs[d], getpid());
        snprintf(path2, sizeof path2, "%s/um2.%d", dirs[d], getpid());
        snprintf(sub, sizeof sub, "%s/umd.%d", dirs[d], getpid());
        prep(get_sqe(), OPENAT, AT_FDCWD, (uint64_t)path, 0644, 0, 100)->op_flags = O_CREAT | O_RDWR | O_TRUNC;
        enter(1, 1);
        c = take_ud(100);
        int f = c.res;
        snprintf(what, sizeof what, "%s: OPENAT O_CREAT", dirs[d]);
        check(f >= 0, what);
        prep(get_sqe(), WRITE, f, (uint64_t)"mixed ring data", 15, 0, 101)->flags = F_LINK;
        prep(get_sqe(), FSYNC, f, 0, 0, 0, 102)->flags = F_LINK;
        prep(get_sqe(), READ, f, (uint64_t)buf, 5, 6, 103);
        memset(buf, 0, sizeof buf);
        enter(3, 3);
        struct cqe w = take_ud(101), s = take_ud(102), r = take_ud(103);
        snprintf(what, sizeof what, "%s: linked WRITE, FSYNC, READ on the opened file", dirs[d]);
        check(w.res == 15 && s.res == 0 && r.res == 5 && !memcmp(buf, "ring ", 5), what);
        struct { uint32_t mask, blksize; uint64_t attrs; uint32_t nlink, uid, gid; uint16_t mode, pad; uint64_t ino, size; char rest[200]; } sx;
        memset(&sx, 0, sizeof sx);
        struct sqe *q = prep(get_sqe(), STATX, AT_FDCWD, (uint64_t)path, 0x7ff, (uint64_t)&sx, 104);
        enter(1, 1);
        c = take_ud(104);
        snprintf(what, sizeof what, "%s: STATX by path: size 15, regular file", dirs[d]);
        check(c.res == 0 && sx.size == 15 && (sx.mode & 0170000) == 0100000, what);
        prep(get_sqe(), CLOSE, f, 0, 0, 0, 105);
        enter(1, 1);
        c = take_ud(105);
        snprintf(what, sizeof what, "%s: CLOSE through the ring", dirs[d]);
        check(c.res == 0 && fcntl(f, F_GETFD) == -1, what);
        if (supported(RENAMEAT) && supported(UNLINKAT) && supported(MKDIRAT)) {
            q = prep(get_sqe(), RENAMEAT, AT_FDCWD, (uint64_t)path, AT_FDCWD, (uint64_t)path2, 106);
            prep(get_sqe(), MKDIRAT, AT_FDCWD, (uint64_t)sub, 0755, 0, 107);
            enter(2, 2);
            struct cqe rn = take_ud(106), mk = take_ud(107);
            struct stat st;
            snprintf(what, sizeof what, "%s: RENAMEAT seen by stat", dirs[d]);
            check(rn.res == 0 && stat(path2, &st) == 0 && st.st_size == 15 && stat(path, &st) == -1, what);
            snprintf(what, sizeof what, "%s: MKDIRAT seen by stat", dirs[d]);
            check(mk.res == 0 && stat(sub, &st) == 0 && S_ISDIR(st.st_mode), what);
            prep(get_sqe(), UNLINKAT, AT_FDCWD, (uint64_t)path2, 0, 0, 108);
            prep(get_sqe(), UNLINKAT, AT_FDCWD, (uint64_t)sub, 0, 0, 109)->op_flags = AT_REMOVEDIR;
            enter(2, 2);
            struct cqe u1 = take_ud(108), u2 = take_ud(109);
            snprintf(what, sizeof what, "%s: UNLINKAT file and directory", dirs[d]);
            check(u1.res == 0 && u2.res == 0 && stat(path2, &st) == -1 && stat(sub, &st) == -1, what);
        } else {
            printf("note: RENAMEAT/UNLINKAT/MKDIRAT not offered\n");
            unlink(path);
        }
    }

    // --- one ring, three owners: a pipe READ, a socket ACCEPT and RECV waiting together
    int pp[2];
    check(pipe(pp) == 0, "pipe");
    int port, l = listener(&port);
    check(l >= 0, "TCP listener on 127.0.0.1");
    char pbuf[16] = {0}, sbuf[16] = {0};
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, sizeof pbuf, 0, 200);
    prep(get_sqe(), ACCEPT, l, 0, 0, 0, 201);
    enter(2, 0);
    usleep(20000);
    check(!has_ud(200) && !has_ud(201), "pipe READ and ACCEPT wait");
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = to_port(port);
    prep(get_sqe(), CONNECT, cl, (uint64_t)&a, 0, sizeof a, 202);
    enter(1, 0);
    struct cqe ac = take_ud(201), cn = take_ud(202);
    check(ac.res >= 0 && cn.res == 0, "ACCEPT finished by a CONNECT through the ring");
    int sv = ac.res;
    prep(get_sqe(), RECV, sv, (uint64_t)sbuf, sizeof sbuf, 0, 203);
    enter(1, 0);
    usleep(20000);
    check(!has_ud(203), "socket RECV waits");
    prep(get_sqe(), SEND, cl, (uint64_t)"tcp!", 4, 0, 204);
    prep(get_sqe(), WRITE, pp[1], (uint64_t)"pipe", 4, 0, 205);
    enter(2, 0);
    struct cqe sd = take_ud(204), wr = take_ud(205), rc = take_ud(203), rd = take_ud(200);
    check(sd.res == 4 && rc.res == 4 && !memcmp(sbuf, "tcp!", 4), "SEND then RECV over TCP loopback");
    check(wr.res == 4 && rd.res == 4 && !memcmp(pbuf, "pipe", 4), "pipe WRITE wakes the waiting pipe READ");
    if (rd.res != 4) printf("  (pipe WRITE %d, READ %d '%.4s')\n", wr.res, rd.res, pbuf);
    // A large send and receive on the socket (more than one copy area)
    static char big[200000], big2[200000];
    for (int i = 0; i < (int)sizeof big; i++) big[i] = i * 7;
    size_t sent = 0, have = 0;
    for (int k = 0; k < 400 && (sent < sizeof big || have < sizeof big2); k++) {
        int nsub = 0;
        if (sent < sizeof big) { prep(get_sqe(), SEND, cl, (uint64_t)big + sent, sizeof big - sent, 0, 206); nsub++; }
        if (have < sizeof big2) { prep(get_sqe(), RECV, sv, (uint64_t)big2 + have, sizeof big2 - have, 0, 207); nsub++; }
        enter(nsub, 0);
        if (sent < sizeof big) { c = take_ud(206); if (c.res <= 0) break; sent += c.res; }
        if (have < sizeof big2) { c = take_ud(207); if (c.res <= 0) break; have += c.res; }
    }
    check(sent == sizeof big && have == sizeof big2 && !memcmp(big, big2, sizeof big), "200 KB SEND/RECV over TCP through the ring");
    // the same on the pipe
    sent = have = 0;
    for (int k = 0; k < 400 && (sent < 60000 || have < 60000); k++) {
        int nsub = 0;
        if (sent < 60000) { prep(get_sqe(), WRITE, pp[1], (uint64_t)big + sent, 60000 - sent, 0, 208); nsub++; }
        if (have < 60000) { prep(get_sqe(), READ, pp[0], (uint64_t)big2 + have, 60000 - have, 0, 209); nsub++; }
        enter(nsub, 0);
        if (sent < 60000) { c = take_ud(208); if (c.res <= 0) break; sent += c.res; }
        if (have < 60000) { c = take_ud(209); if (c.res <= 0) break; have += c.res; }
    }
    if (have != 60000) printf("  (pipe sent %zu, read %zu, last res %d)\n", sent, have, c.res);
    check(sent == 60000 && have == 60000 && !memcmp(big, big2, 60000), "60 KB WRITE/READ on the pipe through the ring");
    // Peer closed: RECV 0, pipe READ 0
    close(cl);
    close(pp[1]);
    prep(get_sqe(), RECV, sv, (uint64_t)sbuf, sizeof sbuf, 0, 210);
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, sizeof pbuf, 0, 211);
    enter(2, 2);
    struct cqe e1 = take_ud(210), e2 = take_ud(211);
    if (e1.res || e2.res) printf("  (RECV %d, READ %d)\n", e1.res, e2.res);
    check(e1.res == 0 && e2.res == 0, "end of stream on socket and pipe");
    prep(get_sqe(), READ, 9999, (uint64_t)buf, 4, 0, 212);
    enter(1, 1);
    check(take_ud(212).res == -EBADF, "READ on a bad descriptor: -EBADF");
    close(sv);
    close(l);
    close(pp[0]);
}

static void bench(int mb) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/umb.%d", getpid());
    int f = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    static char blk[8][65536];
    memset(blk, 'x', sizeof blk);
    size_t total = (size_t)mb << 20;
    double t0 = now();
    for (size_t off = 0; off < total; off += 8 * 65536) {
        for (int i = 0; i < 8; i++) prep(get_sqe(), WRITE, f, (uint64_t)blk[i], 65536, off + i * 65536, 300 + i);
        enter(8, 8);
        for (int i = 0; i < 8; i++) take();
    }
    double tw = now() - t0;
    t0 = now();
    for (int pass = 0; pass < 2; pass++)
        for (size_t off = 0; off < total; off += 8 * 65536) {
            for (int i = 0; i < 8; i++) prep(get_sqe(), READ, f, (uint64_t)blk[i], 65536, off + i * 65536, 400 + i);
            enter(8, 8);
            for (int i = 0; i < 8; i++) take();
        }
    double tr = now() - t0;
    int pp[2];
    pipe(pp);
    int n = 2000;
    t0 = now();
    for (int i = 0; i < n; i++) {
        prep(get_sqe(), WRITE, pp[1], (uint64_t)blk[0], 4096, (uint64_t)-1, 500)->flags = F_LINK;
        prep(get_sqe(), READ, pp[0], (uint64_t)blk[1], 4096, (uint64_t)-1, 501);
        enter(2, 2);
        take();
        take();
    }
    double tp = now() - t0;
    // the same with plain system calls, and a ring NOP (the ring's own cost)
    t0 = now();
    for (int i = 0; i < n; i++) {
        write(pp[1], blk[0], 4096);
        read(pp[0], blk[1], 4096);
    }
    double tq = now() - t0;
    t0 = now();
    for (int i = 0; i < n; i++) {
        prep(get_sqe(), NOP, -1, 0, 0, 0, 502);
        enter(1, 1);
        take();
    }
    double tn = now() - t0;
    printf("bench: pipe 4K write+read plain %.1f us, ring NOP %.1f us\n", tq / n * 1e6, tn / n * 1e6);
    t0 = now();
    for (int i = 0; i < 4000; i++) {
        prep(get_sqe(), READ, f, (uint64_t)blk[0], 512, (i * 4096) % total, 600);
        enter(1, 1);
        take();
    }
    double ts = now() - t0;
    printf("bench: write %.1f MB/s, read %.1f MB/s, pipe 4K round trip %.1f us, 512 B file read %.2f us\n", mb / tw, 2 * mb / tr, tp / n * 1e6,
           ts / 4000 * 1e6);
    close(f);
    unlink(path);
}

static void kill_test(int secs) {
    int pp[2];
    pipe(pp);
    int port, l = listener(&port), port2, l2 = listener(&port2);
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = to_port(port);
    connect(cl, (void *)&a, sizeof a);
    int sv = accept(l, 0, 0);
    char pbuf[16] = {0}, sbuf[16] = {0};
    prep(get_sqe(), READ, pp[0], (uint64_t)pbuf, sizeof pbuf, 0, 1);
    prep(get_sqe(), RECV, sv, (uint64_t)sbuf, sizeof sbuf, 0, 2);
    prep(get_sqe(), ACCEPT, l2, 0, 0, 0, 3);
    enter(3, 0);
    printf("PARKED pipe READ (1), socket RECV (2), ACCEPT (3)\n");
    int seen = 0;
    double t0 = now(), end = t0 + secs;
    while (now() < end && seen < 3) {
        if (!wait_cqe(500)) continue;
        struct cqe c = take();
        printf("cqe %llu res %d (%s) at +%.1f s\n", (unsigned long long)c.user_data, c.res, c.res < 0 ? strerror(-c.res) : "ok", now() - t0);
        seen++;
    }
    if (seen < 3) {
        printf("waking the rest\n");
        errno = 0;
        int w1 = write(pp[1], "late", 4);
        int e1 = errno;
        int w2 = send(cl, "late", 4, 0);
        int e2 = errno;
        int c3 = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in b = to_port(port2);
        int w3 = connect(c3, (void *)&b, sizeof b);
        printf("write %d (%d) send %d (%d) connect %d (%d)\n", w1, e1, w2, e2, w3, errno);
        double e = now() + 5;
        while (now() < e && seen < 3) {
            if (!wait_cqe(500)) continue;
            struct cqe c = take();
            printf("cqe %llu res %d (%s)\n", (unsigned long long)c.user_data, c.res, c.res < 0 ? strerror(-c.res) : "ok");
            seen++;
        }
    }
    printf("completions: %d of 3\n", seen);
    int q[2];
    pipe(q);
    char bb[8] = {0};
    prep(get_sqe(), NOP, -1, 0, 0, 0, 9);
    prep(get_sqe(), WRITE, q[1], (uint64_t)"ok", 2, 0, 10)->flags = F_LINK;
    prep(get_sqe(), READ, q[0], (uint64_t)bb, 2, 0, 11);
    enter(3, 3);
    struct cqe n1 = take_ud(9), n2 = take_ud(10), n3 = take_ud(11);
    check(n1.res == 0 && n2.res == 2 && n3.res == 2 && !memcmp(bb, "ok", 2), "ring works after the kill (NOP, new pipe WRITE/READ)");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (setup(32) != 0) {
        printf("skip: io_uring unavailable (%s)\n", strerror(errno));
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "bench")) {
        bench(atoi(argv[2]));
        return 0;
    }
    if (argc > 2 && !strcmp(argv[1], "kill"))
        kill_test(atoi(argv[2]));
    else
        mix();
    printf("uringmix: %d failures\n", fails);
    return fails ? 1 : 0;
}
