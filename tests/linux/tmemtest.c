// tmemtest: tmpfs / /dev/shm files whose data lives in memory (wave 9, Group M).
//
//   tmemtest            correctness checks + numbers (prints TMEMTEST PASS / FAIL lines)
//   tmemtest bench DIR  throughput and create/unlink rate in DIR only
//   tmemtest put        writes /dev/shm/tmemkeep (8 MiB pattern) for a kill test
//   tmemtest check      checks /dev/shm/tmemkeep
//   tmemtest hold SECS  keeps a /dev/shm file open + mapped, checks it every 50 ms (kills)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static int pool_mode; // tmpfs data in the pool (lx=kernel, lx.vfs=kernel, lx.tmpfs=pool): no size=
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", __func__, __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); } } while (0)

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static uint8_t pat(size_t i, int seed) { return (uint8_t)(i * 131 + seed + (i >> 12)); }

// Two processes share a /dev/shm file by mmap; read/write and the mappings agree.
static void shared_mmap(void) {
    const char *p = "/dev/shm/tmemtest.shared";
    const size_t sz = 1 << 20;
    unlink(p);
    int fd = open(p, O_CREAT | O_RDWR | O_EXCL, 0600);
    CHECK(fd >= 0, "create %s", p);
    if (fd < 0) return;
    CHECK(ftruncate(fd, sz) == 0, "ftruncate");
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == (off_t)sz, "fstat size %ld", (long)st.st_size);
    CHECK(stat(p, &st) == 0 && st.st_size == (off_t)sz, "stat size %ld", (long)st.st_size);
    uint8_t *m = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED, "mmap");
    if (m == MAP_FAILED) return;
    int to_child[2], to_parent[2];
    pipe(to_child);
    pipe(to_parent);
    pid_t pid = fork();
    if (pid == 0) {
        // The child opens the file by name (another open file description) and maps it
        int cfd = open(p, O_RDWR);
        uint8_t *cm = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_SHARED, cfd, 0);
        if (cfd < 0 || cm == MAP_FAILED) _exit(10);
        for (size_t i = 0; i < sz; i++) cm[i] = pat(i, 1);
        char c = 'w';
        write(to_parent[1], &c, 1);
        read(to_child[0], &c, 1);
        // The parent wrote through write(): the child's mapping sees it
        for (size_t i = 0; i < sz; i += 4093)
            if (cm[i] != pat(i, 2)) _exit(11);
        _exit(0);
    }
    char c;
    read(to_parent[0], &c, 1);
    // The child's mapping writes: our mapping and read() see them
    size_t bad = 0;
    for (size_t i = 0; i < sz; i += 997)
        if (m[i] != pat(i, 1)) bad++;
    CHECK(bad == 0, "parent mapping sees child's writes (%zu bad)", bad);
    uint8_t *buf = malloc(sz);
    CHECK(pread(fd, buf, sz, 0) == (ssize_t)sz, "pread");
    bad = 0;
    for (size_t i = 0; i < sz; i++)
        if (buf[i] != pat(i, 1)) bad++;
    CHECK(bad == 0, "read() sees the mapping's writes (%zu bad)", bad);
    for (size_t i = 0; i < sz; i++) buf[i] = pat(i, 2);
    CHECK(pwrite(fd, buf, sz, 0) == (ssize_t)sz, "pwrite");
    bad = 0;
    for (size_t i = 0; i < sz; i += 991)
        if (m[i] != pat(i, 2)) bad++;
    CHECK(bad == 0, "own mapping sees write() (%zu bad)", bad);
    write(to_child[1], &c, 1);
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child status %x", status);
    munmap(m, sz);
    free(buf);
    close(fd);
    unlink(p);
    printf("shared mmap across two processes: done\n");
}

static sigjmp_buf jb;
static void on_bus(int s) { (void)s; siglongjmp(jb, 1); }

// Sizes, holes, appends, truncation, unlink while open, rename rules.
static void semantics(void) {
    const char *p = "/dev/shm/tmemtest.sem";
    unlink(p);
    int fd = open(p, O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0, "create");
    if (fd < 0) return;
    char b[8192];
    CHECK(pwrite(fd, "hello", 5, 10000) == 5, "pwrite past end");
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && st.st_size == 10005, "size after sparse write %ld", (long)st.st_size);
    CHECK(pread(fd, b, 16, 0) == 16 && b[0] == 0 && b[15] == 0, "hole reads zeros");
    CHECK(pread(fd, b, 10, 10000) == 5 && memcmp(b, "hello", 5) == 0, "data after hole");
    CHECK(pread(fd, b, 10, 20000) == 0, "read past end = 0");
    int afd = open(p, O_WRONLY | O_APPEND);
    CHECK(afd >= 0 && write(afd, "XY", 2) == 2, "append");
    close(afd);
    CHECK(stat(p, &st) == 0 && st.st_size == 10007, "stat size after append %ld", (long)st.st_size);
    CHECK(ftruncate(fd, 3) == 0, "shrink");
    CHECK(fstat(fd, &st) == 0 && st.st_size == 3, "size after shrink %ld", (long)st.st_size);
    CHECK(ftruncate(fd, 10007) == 0 && pread(fd, b, 5, 10000) == 5 && memcmp(b, "\0\0\0\0\0", 5) == 0, "regrow reads zeros");
    CHECK(truncate(p, 4096 * 3) == 0 && stat(p, &st) == 0 && st.st_size == 4096 * 3, "truncate by path");
    // SIGBUS past the end of a mapping
    uint8_t *m = mmap(0, 4096 * 4, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(m != MAP_FAILED, "mmap");
    struct sigaction sa = {0}, old;
    sa.sa_handler = on_bus;
    sigaction(SIGBUS, &sa, &old);
    volatile int got = 0;
    if (sigsetjmp(jb, 1) == 0) {
        volatile uint8_t x = m[4096 * 3 + 5];
        (void)x;
    } else {
        got = 1;
    }
    sigaction(SIGBUS, &old, 0);
    CHECK(got, "SIGBUS past the end");
    munmap(m, 4096 * 4);
    // mtime moves with writes
    struct stat s1, s2;
    fstat(fd, &s1);
    usleep(20000);
    pwrite(fd, "z", 1, 0);
    fstat(fd, &s2);
    CHECK(s2.st_mtim.tv_sec > s1.st_mtim.tv_sec || (s2.st_mtim.tv_sec == s1.st_mtim.tv_sec && s2.st_mtim.tv_nsec > s1.st_mtim.tv_nsec), "mtime moves");
    CHECK(stat(p, &s1) == 0 && s1.st_mtim.tv_nsec == s2.st_mtim.tv_nsec, "stat and fstat agree on mtime");
    // Rename inside /dev/shm keeps the data
    CHECK(rename(p, "/dev/shm/tmemtest.sem2") == 0, "rename in /dev/shm");
    CHECK(pread(fd, b, 1, 0) == 1 && b[0] == 'z', "data after rename");
    int r = rename("/dev/shm/tmemtest.sem2", "/var/tmp/tmemtest.out");
    printf("rename /dev/shm -> /var/tmp: %s\n", r == 0 ? "allowed (pool data)" : strerror(errno));
    if (r == 0) { pool_mode = 1; rename("/var/tmp/tmemtest.out", "/dev/shm/tmemtest.sem2"); }
    // Unlink while open: still readable and writable until the close
    CHECK(unlink("/dev/shm/tmemtest.sem2") == 0, "unlink");
    CHECK(pwrite(fd, "q", 1, 1) == 1 && pread(fd, b, 2, 0) == 2 && b[0] == 'z' && b[1] == 'q', "open after unlink");
    close(fd);
    printf("semantics: done\n");
}

// size= of a tmpfs mount in a namespace of our own: ENOSPC past it.
static void size_limit(void) {
    if (unshare(CLONE_NEWNS) != 0) {
        printf("size limit: SKIP (unshare: %s)\n", strerror(errno));
        return;
    }
    mkdir("/var/tmp/tmemmnt", 0755);
    if (mount("tmpfs", "/var/tmp/tmemmnt", "tmpfs", 0, "size=1m,mode=1777") != 0) {
        printf("size limit: SKIP (mount: %s)\n", strerror(errno));
        return;
    }
    int fd = open("/var/tmp/tmemmnt/big", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0, "create in tmpfs");
    char b[65536];
    memset(b, 7, sizeof b);
    long total = 0;
    int err = 0;
    for (int i = 0; i < 64; i++) {
        ssize_t n = write(fd, b, sizeof b);
        if (n < 0) { err = errno; break; }
        total += n;
        if (n < (ssize_t)sizeof b) { err = ENOSPC; }
    }
    printf("tmpfs size=1m: wrote %ld bytes, then %s\n", total, err ? strerror(err) : "no error");
    CHECK(err == ENOSPC && total >= 900000 && total <= (1 << 20), "ENOSPC at size= (wrote %ld)", total);
    CHECK(ftruncate(fd, 0) == 0 && pwrite(fd, b, sizeof b, 0) == (ssize_t)sizeof b, "room again after truncate");
    close(fd);
    struct statfs sf;
    CHECK(statfs("/var/tmp/tmemmnt", &sf) == 0 && sf.f_type == 0x01021994 && sf.f_blocks == 256 && sf.f_bfree == 256 - 16, "statfs blocks %ld free %ld", (long)sf.f_blocks, (long)sf.f_bfree);
    struct stat st;
    CHECK(stat("/var/tmp/tmemmnt/big", &st) == 0 && st.st_size == (off_t)sizeof b, "size in tmpfs %ld", (long)st.st_size);
    unlink("/var/tmp/tmemmnt/big");
    umount("/var/tmp/tmemmnt");
    printf("size limit: done\n");
}

static void bench(const char *dir) {
    char p[256];
    snprintf(p, sizeof p, "%s/tmemtest.bench", dir);
    const size_t total = 64 << 20, chunk = 64 << 10;
    char *b = malloc(chunk);
    memset(b, 0x5a, chunk);
    unlink(p);
    int fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { printf("bench %s: open: %s\n", dir, strerror(errno)); return; }
    double t0 = now();
    for (size_t o = 0; o < total; o += chunk) write(fd, b, chunk);
    double t1 = now();
    lseek(fd, 0, SEEK_SET);
    for (size_t o = 0; o < total; o += chunk) read(fd, b, chunk);
    double t2 = now();
    uint8_t *m = mmap(0, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    double t3 = now(), t4 = t3;
    if (m != MAP_FAILED) {
        for (size_t o = 0; o < total; o += 4096) m[o]++;
        t4 = now();
        munmap(m, total);
    }
    close(fd);
    unlink(p);
    const int N = 1000;
    double t5 = now();
    for (int i = 0; i < N; i++) {
        snprintf(p, sizeof p, "%s/tmemtest.c%d", dir, i);
        int f = open(p, O_CREAT | O_WRONLY, 0644);
        write(f, b, 100);
        close(f);
    }
    double t6 = now();
    for (int i = 0; i < N; i++) {
        snprintf(p, sizeof p, "%s/tmemtest.c%d", dir, i);
        unlink(p);
    }
    double t7 = now();
    printf("BENCH %s: write %.0f MB/s, read %.0f MB/s, mmap touch %.0f MB/s, create+write+close %.1f us, unlink %.1f us\n", dir,
           total / 1e6 / (t1 - t0), total / 1e6 / (t2 - t1), m == MAP_FAILED ? 0.0 : total / 1e6 / (t4 - t3), (t6 - t5) / N * 1e6, (t7 - t6) / N * 1e6);
    free(b);
}

#define KEEP "/dev/shm/tmemkeep"
#define KEEP_SZ (8 << 20)

static int put(void) {
    int fd = open(KEEP, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) { perror("put"); return 1; }
    uint8_t *b = malloc(KEEP_SZ);
    for (size_t i = 0; i < KEEP_SZ; i++) b[i] = pat(i, 7);
    ssize_t n = write(fd, b, KEEP_SZ);
    close(fd);
    printf("TMEMKEEP put %zd\n", n);
    return n != KEEP_SZ;
}

static int check(void) {
    int fd = open(KEEP, O_RDONLY);
    if (fd < 0) { printf("TMEMKEEP FAIL open: %s\n", strerror(errno)); return 1; }
    uint8_t *b = malloc(KEEP_SZ);
    ssize_t n = 0, k;
    while (n < KEEP_SZ && (k = read(fd, b + n, KEEP_SZ - n)) > 0) n += k;
    struct stat st;
    stat(KEEP, &st);
    size_t bad = 0;
    for (ssize_t i = 0; i < n; i++)
        if (b[i] != pat(i, 7)) bad++;
    int ok = n == KEEP_SZ && bad == 0 && st.st_size == KEEP_SZ;
    printf("TMEMKEEP %s read %zd stat %ld bad %zu\n", ok ? "PASS" : "FAIL", n, (long)st.st_size, bad);
    return !ok;
}

// Open + mapped across service kills: every 50 ms write a counter by write(), read it
// back through the mapping, and stat the name.
static int hold(int secs) {
    const char *p = "/dev/shm/tmemhold";
    int fd = open(p, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, 4096) != 0) { perror("hold"); return 1; }
    volatile uint32_t *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    long rounds = 0, errs = 0;
    double end = now() + secs;
    while (now() < end) {
        uint32_t v = (uint32_t)rounds * 2654435761u;
        if (pwrite(fd, &v, 4, 0) != 4) errs++;
        if (m[0] != v) errs++;
        m[1] = v;
        uint32_t r = 0;
        if (pread(fd, &r, 4, 4) != 4 || r != v) errs++;
        struct stat st;
        if (stat(p, &st) != 0 || st.st_size != 4096) errs++;
        rounds++;
        usleep(50000);
    }
    close(fd);
    unlink(p);
    printf("TMEMHOLD %s rounds %ld errors %ld\n", errs ? "FAIL" : "PASS", rounds, errs);
    return errs != 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc > 1 && !strcmp(argv[1], "put")) return put();
    if (argc > 1 && !strcmp(argv[1], "check")) return check();
    if (argc > 2 && !strcmp(argv[1], "hold")) return hold(atoi(argv[2]));
    if (argc > 2 && !strcmp(argv[1], "bench")) { bench(argv[2]); return 0; }
    shared_mmap();
    semantics();
    bench("/dev/shm");
    bench("/var/tmp");
    if (pool_mode) {
        printf("size limit: SKIP (pool data mode)\n");
    } else if (geteuid() == 0) {
        pid_t pid = fork();
        if (pid == 0) { size_limit(); _exit(fails ? 1 : 0); }
        int st = 0;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) fails++;
    } else {
        printf("size limit: SKIP (not root)\n");
    }
    printf(fails ? "TMEMTEST FAIL (%d)\n" : "TMEMTEST PASS\n", fails);
    return fails != 0;
}
