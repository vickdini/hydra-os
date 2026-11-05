// Hydra M1 virtual-memory conformance test.
// Build (WSL): gcc -static-pie -O1 -pthread -o esp/bin/vmtest.elf scratch/vmtest.c
// Run in Hydra: linux run vmtest.elf
// Exercises glibc static-PIE startup plus mmap/munmap/mprotect/mremap/brk, MAP_FIXED,
// memfd shared mappings, threads sharing one address space, and SSE state preservation
// across syscalls and task switches. Prints one PASS/FAIL line per check.
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("[vmtest] %-44s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) failures++;
}

static double sse_spin(double seed) {
    // Keeps live values in XMM registers across syscalls and yields
    double a = seed, b = seed * 1.5, c = seed / 3.0;
    for (int i = 0; i < 200; i++) {
        a = a * 1.0000001 + b;
        syscall(SYS_getpid);
        if (i % 50 == 0) sched_yield();
        b = b - c * 0.5;
        c = c + a * 1e-9;
    }
    return a + b + c;
}

static double sse_reference(double seed) {
    double a = seed, b = seed * 1.5, c = seed / 3.0;
    for (int i = 0; i < 200; i++) {
        a = a * 1.0000001 + b;
        b = b - c * 0.5;
        c = c + a * 1e-9;
    }
    return a + b + c;
}

static volatile int shared_counter;
static double thread_results[4];

static void *worker(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < 1000; i++) __sync_fetch_and_add(&shared_counter, 1);
    thread_results[id] = sse_spin(10.0 + id);
    return NULL;
}

int main(int argc, char **argv) {
    printf("[vmtest] Hydra VM test starting (argc=%d, argv[0]=%s)\n", argc, argv[0]);

    // 1. Heap through brk (small) and mmap (large) malloc paths
    char *small = malloc(1000);
    memset(small, 'a', 1000);
    char *big = malloc(8 * 1024 * 1024);
    memset(big, 'b', 8 * 1024 * 1024);
    check("malloc small (brk) + large (mmap)", small[999] == 'a' && big[8 * 1024 * 1024 - 1] == 'b');
    char *grown = realloc(big, 32 * 1024 * 1024);
    check("realloc 8 MiB -> 32 MiB keeps contents (mremap)", grown && grown[4096] == 'b' && grown[8 * 1024 * 1024 - 1] == 'b');
    free(grown);
    free(small);

    // 2. Anonymous mapping is zero-filled and demand-paged
    size_t len = 64 * 4096;
    unsigned char *anon = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int zero = anon != MAP_FAILED;
    for (size_t i = 0; zero && i < len; i += 4096) zero = anon[i] == 0;
    check("anonymous mmap is zero-filled", zero);
    for (size_t i = 0; i < len; i++) anon[i] = (unsigned char)i;
    check("anonymous mmap read-back", anon[len - 1] == (unsigned char)(len - 1));

    // 3. MAP_FIXED replaces part of an existing mapping
    unsigned char *fixed = mmap(anon + 4 * 4096, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    check("MAP_FIXED lands at requested address", fixed == anon + 4 * 4096);
    check("MAP_FIXED page replaced (zero), neighbours kept", fixed[0] == 0 && anon[3 * 4096] == (unsigned char)(3 * 4096));

    // 4. MAP_FIXED_NOREPLACE refuses to clobber
    void *nr = mmap(anon, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    check("MAP_FIXED_NOREPLACE fails on overlap", nr == MAP_FAILED);

    // 5. mprotect to read-only and back
    check("mprotect read-only", mprotect(anon, 4096, PROT_READ) == 0);
    check("mprotect read-write again", mprotect(anon, 4096, PROT_READ | PROT_WRITE) == 0);
    anon[0] = 42;
    check("write after re-enabling PROT_WRITE", anon[0] == 42);

    // 6. munmap a hole, then remap something there
    check("munmap middle page", munmap(anon + 10 * 4096, 4096) == 0);
    void *refill = mmap(anon + 10 * 4096, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    check("hole is free after munmap", refill == anon + 10 * 4096);

    // 7. mremap with MREMAP_MAYMOVE
    unsigned char *moved = mremap(anon, len, len * 4, MREMAP_MAYMOVE);
    check("mremap grow (may move)", moved != MAP_FAILED && moved[len - 1] == (unsigned char)(len - 1) && moved[0] == 42);
    moved[len * 4 - 1] = 7;
    check("mremap grown tail is writable", moved[len * 4 - 1] == 7);
    munmap(moved, len * 4);

    // 8. memfd + MAP_SHARED: two mappings see the same pages
    int fd = memfd_create("vmtest", 0);
    check("memfd_create", fd >= 0);
    check("ftruncate memfd to 3 pages", ftruncate(fd, 3 * 4096) == 0);
    char *m1 = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    char *m2 = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    strcpy(m1 + 4096, "shared-pages");
    check("two MAP_SHARED mappings alias", m1 != m2 && strcmp(m2 + 4096, "shared-pages") == 0);
    char rb[16] = {0};
    check("pread sees mapped writes", pread(fd, rb, 12, 4096) == 12 && memcmp(rb, "shared-pages", 12) == 0);
    char *priv = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    priv[4096] = 'X';
    check("MAP_PRIVATE write is copy-on-write", priv[4096] == 'X' && m1[4096] == 's');

    // 9. SSE registers survive syscalls and task switches
    check("SSE state preserved across syscalls/yields", sse_spin(3.25) == sse_reference(3.25));

    // 10. Threads share the address space
    pthread_t th[4];
    for (long i = 0; i < 4; i++) pthread_create(&th[i], NULL, worker, (void *)i);
    for (int i = 0; i < 4; i++) pthread_join(th[i], NULL);
    int fp_ok = 1;
    for (int i = 0; i < 4; i++) fp_ok &= thread_results[i] == sse_reference(10.0 + i);
    check("4 threads share memory (counter == 4000)", shared_counter == 4000);
    check("per-thread SSE state isolated", fp_ok);

    printf("[vmtest] %s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED", failures, failures == 1 ? "" : "s");
    return failures;
}
