// TLB coherence stress test (wave 3 group 8, PCID): stale translations must never be used.
//
// With PCID, a CPU keeps the TLB entries of an address space it switched away from. Any
// page table change made meanwhile (on another CPU) must be flushed before that CPU runs
// the address space again. This test makes such changes all the time while threads of
// several processes run on all CPUs and switch among each other:
//
//  - remap: a writer thread replaces pages of a region with new frames (mremap of a
//    prepared page over the old one, MAP_FIXED mmap, madvise(DONTNEED)) and publishes a
//    version number; reader threads read the published version, then the page (one of
//    them gives the CPU to other processes after every read). A stale
//    translation shows an older version, or a freed frame's garbage;
//  - fork: a thread keeps writing a counter while the main thread forks; the child's copy
//    must stay frozen (a stale writable entry would let the parent's writes reach the
//    child's page, copy-on-write broken);
//  - mprotect: a page made read-only must fault on the next write from any thread.
//
// Usage: tlbstress [seconds] [processes]   (default 10 s, 2 processes)
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NPAGES 16
#define PG 4096

static char *region;
static volatile uint64_t pub[NPAGES];
static volatile int stop;
static volatile uint64_t failures, reads, remaps, forks, protects;
static volatile uint64_t *counter_page;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void fail(const char *what, uint64_t a, uint64_t b) {
    __sync_fetch_and_add(&failures, 1);
    if (failures < 10)
        printf("tlbstress[%d]: FAIL %s (%llu vs %llu)\n", getpid(), what, (unsigned long long)a, (unsigned long long)b);
}

// A page's version word: the version in the low half, a hash of it in the high half (one
// aligned 8-byte load is atomic: a reader sees one whole word, old or new)
static uint64_t word_of(uint64_t ver) {
    uint32_t v = (uint32_t)ver;
    return ((uint64_t)((v * 2654435761u) ^ 0x5a17c0deu) << 32) | v;
}

static int word_ok(uint64_t w) {
    return word_of(w & 0xffffffffu) == w;
}

static void fill(uint64_t *p, uint64_t ver) {
    p[0] = word_of(ver);
    p[511] = word_of(ver);
}

static void *writer(void *arg) {
    unsigned seed = (unsigned)(uintptr_t)arg;
    uint64_t ver = 0;
    while (!stop) {
        int j = rand_r(&seed) % NPAGES;
        char *dst = region + (size_t)j * PG;
        uint64_t v = ++ver;
        int how = rand_r(&seed) % 3;
        if (how == 0) {
            // A prepared page moved over the old one: readers see old or new, never neither
            char *s = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (s == MAP_FAILED) { fail("mmap staging", errno, 0); continue; }
            fill((uint64_t *)s, v);
            if (mremap(s, PG, PG, MREMAP_MAYMOVE | MREMAP_FIXED, dst) == MAP_FAILED) { fail("mremap", errno, 0); continue; }
        } else {
            // A new frame in place (MAP_FIXED or a discard): readers may see 0 meanwhile
            __atomic_store_n(&pub[j], 0, __ATOMIC_SEQ_CST);
            if (how == 1) {
                if (mmap(dst, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) { fail("mmap fixed", errno, 0); continue; }
            } else {
                madvise(dst, PG, MADV_DONTNEED);
            }
            fill((uint64_t *)dst, v);
        }
        // Publish: from now on every reader must see version >= v in page j
        __atomic_store_n(&pub[j], v, __ATOMIC_SEQ_CST);
        __sync_fetch_and_add(&remaps, 1);
        if ((v & 4095) == 0) sched_yield();
    }
    return NULL;
}

static void read_loop(unsigned seed, uint64_t yield_mask) {
    uint64_t n = 0;
    while (!stop) {
        int j = rand_r(&seed) % NPAGES;
        uint64_t p = __atomic_load_n(&pub[j], __ATOMIC_SEQ_CST);
        volatile uint64_t *q = (volatile uint64_t *)(region + (size_t)j * PG);
        uint64_t w = q[(n & 1) ? 511 : 0];
        // Checked only if the published version did not change meanwhile (it is zeroed
        // before a replacement that leaves the page empty or half filled for a while)
        if (p != 0 && __atomic_load_n(&pub[j], __ATOMIC_SEQ_CST) == p) {
            if (!word_ok(w)) fail("garbage in page (a freed frame?)", w, p);
            else if ((w & 0xffffffffu) < p) fail("stale page version (read older than published)", w & 0xffffffffu, p);
        }
        if ((++n & yield_mask) == 0) sched_yield();
    }
    __sync_fetch_and_add(&reads, n);
}

static void *reader(void *arg) {
    read_loop((unsigned)(uintptr_t)arg, 0xfffff);
    return NULL;
}

// Gives the CPU away after every read: with the yielder processes, the CPU switches to
// another address space and back between two reads, with no timer interrupt in between
// (the case where a CPU keeps a switched-away address space's entries under PCID)
static void *yield_reader(void *arg) {
    read_loop((unsigned)(uintptr_t)arg, 0);
    return NULL;
}

static void *counter(void *arg) {
    (void)arg;
    uint64_t i = 0;
    while (!stop) {
        counter_page[0] = ++i;
        counter_page[1] = i;
        if ((i & 0xfffff) == 0) sched_yield();
    }
    return NULL;
}

static sigjmp_buf segv_jmp;
static __thread volatile int expect_segv;
static void on_segv(int sig) {
    (void)sig;
    if (expect_segv) siglongjmp(segv_jmp, 1);
    _exit(99);
}

static volatile char *prot_page;
// Read-only rounds: the main thread makes the page read-only, then asks (prot_req = n);
// the writer's next write must fault; it answers (prot_ack = n); then the page is writable
static volatile int prot_req, prot_ack;

static void *prot_writer(void *arg) {
    (void)arg;
    // Any write may fault (the protection changes at any time); only the first write
    // after a request was seen must
    expect_segv = 1;
    int done = 0;
    while (!stop) {
        int r = __atomic_load_n(&prot_req, __ATOMIC_SEQ_CST);
        if (sigsetjmp(segv_jmp, 1) == 0) {
            prot_page[r != done ? 8 : 0]++;
            if (r != done) fail("write to a read-only page did not fault (stale writable entry)", r, 0);
        }
        if (r != done) {
            done = r;
            __atomic_store_n(&prot_ack, r, __ATOMIC_SEQ_CST);
        }
    }
    return NULL;
}

static int run_process(int secs, int id) {
    srand(getpid());
    region = mmap(NULL, NPAGES * PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    counter_page = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    prot_page = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED || counter_page == MAP_FAILED || prot_page == MAP_FAILED) { printf("tlbstress: mmap failed\n"); return 1; }
    for (int j = 0; j < NPAGES; j++) fill((uint64_t *)(region + (size_t)j * PG), 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_segv;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);

    pthread_t th[6];
    pthread_create(&th[0], NULL, writer, (void *)(uintptr_t)(id * 7 + 1));
    pthread_create(&th[1], NULL, reader, (void *)(uintptr_t)(id * 7 + 2));
    pthread_create(&th[2], NULL, yield_reader, (void *)(uintptr_t)(id * 7 + 3));
    pthread_create(&th[3], NULL, counter, NULL);
    pthread_create(&th[4], NULL, prot_writer, NULL);
    double end = now() + secs;
    while (now() < end) {
        // fork: the child's copy of the counter page must stay as it was at the fork
        pid_t c = fork();
        if (c == 0) {
            // For 3 ms (the parent's counter thread keeps writing its copy meanwhile)
            uint64_t a = counter_page[0], b = counter_page[1];
            double until = now() + 0.003;
            while (now() < until)
                if (counter_page[0] != a || counter_page[1] != b) _exit(3);
            _exit(0);
        }
        if (c < 0) { fail("fork", errno, 0); continue; }
        int st = 0;
        waitpid(c, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            fail("child's copy-on-write page changed after the fork (or the child died)", WIFEXITED(st) ? WEXITSTATUS(st) : 1000 + WTERMSIG(st), 0);
        forks++;
        // mprotect round: read-only, publish, give the writer time, writable again
        mprotect((void *)prot_page, PG, PROT_READ);
        int n = prot_req + 1;
        __atomic_store_n(&prot_req, n, __ATOMIC_SEQ_CST);
        while (__atomic_load_n(&prot_ack, __ATOMIC_SEQ_CST) != n) sched_yield();
        mprotect((void *)prot_page, PG, PROT_READ | PROT_WRITE);
        protects++;
    }
    stop = 1;
    for (int i = 0; i < 5; i++) pthread_join(th[i], NULL);
    printf("tlbstress[%d]: remaps %llu, reads %llu, forks %llu, mprotect rounds %llu, failures %llu\n", id,
           (unsigned long long)remaps, (unsigned long long)reads, (unsigned long long)forks,
           (unsigned long long)protects, (unsigned long long)failures);
    return failures ? 1 : 0;
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 10;
    int procs = argc > 2 ? atoi(argv[2]) : 2;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tlbstress: %d s, %d processes x (writer, reader, yielding reader, counter, mprotect writer, forking main) + yielders, %ld CPUs\n", secs, procs,
           sysconf(_SC_NPROCESSORS_ONLN));
    pid_t pids[64], yielders[64];
    for (int i = 0; i < procs && i < 64; i++) {
        pids[i] = fork();
        if (pids[i] == 0) _exit(run_process(secs, i));
    }
    // Processes that only give the CPU away: other address spaces to switch to
    for (int i = 0; i < procs && i < 64; i++) {
        yielders[i] = fork();
        if (yielders[i] == 0) {
            double end = now() + secs;
            while (now() < end) sched_yield();
            _exit(0);
        }
    }
    int bad = 0;
    for (int i = 0; i < procs && i < 64; i++) {
        int st = 0;
        waitpid(pids[i], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            printf("tlbstress: process %d failed (status %#x)\n", i, st);
            bad++;
        }
    }
    for (int i = 0; i < procs && i < 64; i++) waitpid(yielders[i], NULL, 0);
    printf(bad ? "TLBSTRESS FAILED (%d processes)\n" : "TLBSTRESS PASSED%.0d\n", bad);
    return bad ? 1 : 0;
}
