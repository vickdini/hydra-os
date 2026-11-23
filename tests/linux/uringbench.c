// uringbench: per-request cost of io_uring against the plain system call (wave 10, Group N).
// Raw system calls, no liburing. Each line: BENCH-shaped "URB name med ns/op".
//   nop32      32 NOPs per io_uring_enter (ring overhead per SQE)
//   read1      one 4 KiB pread of a file per enter (submit + wait for 1)
//   read32     32 x 4 KiB preads per enter
//   pread      the plain pread64 system call (4 KiB)
//   pipe32     32 x (write 64 B to a pipe + read 64 B back), linked pairs, per enter
//   pipe_sys   the plain write+read pair on the pipe
// Build: gcc -O1 -w -o uringbench uringbench.c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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
enum { NOP = 0, READ = 22, WRITE = 23 };

static int ring_fd;
static struct params p;
static uint8_t *ring;
static struct sqe *sqes;
static uint32_t *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
static struct cqe *cqes;
static uint32_t tail;

static uint64_t now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static int setup(unsigned entries) {
    memset(&p, 0, sizeof p);
    ring_fd = syscall(425, entries, &p);
    if (ring_fd < 0) return -1;
    size_t sq_sz = p.sq_off.array + p.sq_entries * 4, cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct cqe);
    size_t sz = sq_sz > cq_sz ? sq_sz : cq_sz;
    ring = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, 0);
    sqes = mmap(0, p.sq_entries * sizeof(struct sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, 0x10000000);
    if (ring == MAP_FAILED || sqes == MAP_FAILED) return -2;
    sq_tail = (uint32_t *)(ring + p.sq_off.tail);
    sq_mask = (uint32_t *)(ring + p.sq_off.ring_mask);
    sq_array = (uint32_t *)(ring + p.sq_off.array);
    cq_head = (uint32_t *)(ring + p.cq_off.head);
    cq_tail = (uint32_t *)(ring + p.cq_off.tail);
    cq_mask = (uint32_t *)(ring + p.cq_off.ring_mask);
    cqes = (struct cqe *)(ring + p.cq_off.cqes);
    tail = *sq_tail;
    return 0;
}

static struct sqe *get(void) {
    uint32_t i = tail & *sq_mask;
    struct sqe *s = &sqes[i];
    memset(s, 0, sizeof *s);
    sq_array[i] = i;
    tail++;
    return s;
}

static int enter(unsigned submit, unsigned wait) {
    __atomic_store_n(sq_tail, tail, __ATOMIC_RELEASE);
    return syscall(426, ring_fd, submit, wait, wait ? 1 : 0, 0, 0);
}

static int reap(unsigned n) {
    int bad = 0;
    for (unsigned k = 0; k < n; k++) {
        uint32_t h = *cq_head;
        while (h == __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) syscall(426, ring_fd, 0, 1, 1, 0, 0);
        if (cqes[h & *cq_mask].res < 0) bad++;
        __atomic_store_n(cq_head, h + 1, __ATOMIC_RELEASE);
    }
    return bad;
}

static int cmpd(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static char buf[32][4096];
static int fd, pfd[2];

static double b_nop32(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        for (int k = 0; k < 32; k++) get()->opcode = NOP;
        enter(32, 32);
        reap(32);
    }
    return (double)(now() - t) / (n * 32);
}
static double b_readk(long n, int k0) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        for (int k = 0; k < k0; k++) {
            struct sqe *s = get();
            s->opcode = READ; s->fd = fd; s->addr = (uint64_t)buf[k]; s->len = 4096; s->off = 4096 * k;
        }
        enter(k0, k0);
        if (reap(k0)) return -1;
    }
    return (double)(now() - t) / (n * k0);
}
static double b_read1(long n) { return b_readk(n, 1); }
static double b_read32(long n) { return b_readk(n, 32); }
static double b_pread(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (pread(fd, buf[0], 4096, 4096 * (i & 31)) != 4096) return -1;
    return (double)(now() - t) / n;
}
static double b_pipe32(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++) {
        for (int k = 0; k < 16; k++) {
            struct sqe *s = get();
            s->opcode = WRITE; s->fd = pfd[1]; s->addr = (uint64_t)buf[k]; s->len = 64; s->off = -1; s->flags = 4; /* IO_LINK */
            s = get();
            s->opcode = READ; s->fd = pfd[0]; s->addr = (uint64_t)buf[16 + k]; s->len = 64; s->off = -1;
        }
        enter(32, 32);
        if (reap(32)) return -1;
    }
    return (double)(now() - t) / (n * 16);
}
static double b_pipe_sys(long n) {
    uint64_t t = now();
    for (long i = 0; i < n; i++)
        if (write(pfd[1], buf[0], 64) != 64 || read(pfd[0], buf[1], 64) != 64) return -1;
    return (double)(now() - t) / n;
}

struct bench { const char *name; double (*fn)(long); long n; } benches[] = {
    {"nop32", b_nop32, 2000}, {"read1", b_read1, 20000}, {"read32", b_read32, 1000}, {"pread", b_pread, 20000},
    {"pipe32", b_pipe32, 1000}, {"pipe_sys", b_pipe_sys, 20000},
};

int main(int argc, char **argv) {
    if (setup(64)) { printf("URB setup failed\n"); return 1; }
    char path[] = "/tmp/uringbench.XXXXXX";
    fd = mkstemp(path);
    unlink(path);
    static char blk[32 * 4096];
    memset(blk, 'x', sizeof blk);
    if (fd < 0 || write(fd, blk, sizeof blk) != sizeof blk || pipe(pfd)) { printf("URB file/pipe failed\n"); return 1; }
    for (unsigned b = 0; b < sizeof benches / sizeof *benches; b++) {
        if (argc > 1) {
            int want = 0;
            for (int a = 1; a < argc; a++) want |= !strcmp(argv[a], benches[b].name);
            if (!want) continue;
        }
        double r[5];
        benches[b].fn(benches[b].n / 10 + 1);
        for (int i = 0; i < 5; i++) r[i] = benches[b].fn(benches[b].n);
        qsort(r, 5, sizeof *r, cmpd);
        printf("URB %-10s min %8.0f med %8.0f ns/op\n", benches[b].name, r[0], r[2]);
        fflush(stdout);
    }
    printf("URB-DONE\n");
    return 0;
}
