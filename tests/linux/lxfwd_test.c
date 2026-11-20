/* lxfwd_test: the forwarding of Linux system calls to linux-server (wave 3, group 7).
 *
 *   lxfwd_test           checks, then the concurrency test (4 processes x 8 threads making
 *                        key calls and forwarded test calls at once); prints
 *                        "LXFWD TEST PASSED" or "LXFWD TEST FAILED (n)"
 *   lxfwd_test hammer N  N processes x 4 threads making forwarded calls until killed (the
 *                        kill test: linux-server is killed meanwhile); prints a line per
 *                        process every 2 s with its calls and errors
 *
 * Hydra's test call 0x6710 (LX_NULL_NR in the kernel's ipc/protocol.rs): op 0 returns 0,
 * op 1 answers 42 after arg1 ms ("pending", completed by another server thread), op 2 adds
 * 1 to each of arg2 bytes at arg1 through the client memory primitives. With the forwarding
 * switched back to the kernel (fw_cfg opt/hydra/lx=kernel) every op returns 0 and only the
 * key calls are checked.
 * Build: gcc -O1 -w -pthread lxfwd_test.c -o lxfwd
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_NULL 0x6710
#define KEYCTL_READ 11
#define KEYCTL_UNLINK 9
#define THREAD_KEYRING -1

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long lx(long op, long a1, long a2) { return syscall(LX_NULL, op, a1, a2); }
static void on_alarm(int s) { (void)s; }

/* --- one thread of the concurrency test --- */
#define ROUNDS 300
static void *worker(void *arg) {
    long me = (long)arg;
    long bad = 0;
    char desc[64], payload[96], back[128];
    unsigned char buf[300];
    for (int i = 0; i < ROUNDS; i++) {
        int n = snprintf(desc, sizeof desc, "lxfwd-%d-%ld-%d", getpid(), me, i);
        int plen = snprintf(payload, sizeof payload, "payload of %s / %ld", desc, (long)gettid());
        long id = syscall(SYS_add_key, "user", desc, payload, plen, THREAD_KEYRING);
        if (id <= 0) { bad++; continue; }
        long r = syscall(SYS_keyctl, KEYCTL_READ, id, back, sizeof back);
        if (r != plen || memcmp(back, payload, plen)) bad++;
        if (syscall(SYS_keyctl, KEYCTL_UNLINK, id, THREAD_KEYRING) != 0) bad++;
        if (lx(0, 0, 0) != 0) bad++;
        /* The client memory primitives see this thread's own buffer */
        memset(buf, (unsigned char)(me * 7 + i), sizeof buf);
        long c = lx(2, (long)buf, sizeof buf);
        if (c == sizeof buf) {
            for (unsigned k = 0; k < sizeof buf; k++)
                if (buf[k] != (unsigned char)(me * 7 + i + 1)) { bad++; break; }
        } else if (c != 0) {
            bad++;
        }
        (void)n;
    }
    return (void *)bad;
}

static int concurrency(int procs, int threads) {
    uint64_t t0 = now_ms();
    for (int p = 0; p < procs; p++) {
        if (fork() == 0) {
            pthread_t t[16];
            long bad = 0;
            for (long i = 0; i < threads; i++) pthread_create(&t[i], 0, worker, (void *)i);
            for (int i = 0; i < threads; i++) {
                void *r;
                pthread_join(t[i], &r);
                bad += (long)r;
            }
            if (bad) printf("process %d: %ld bad results\n", getpid(), bad);
            _exit(bad ? 1 : 0);
        }
    }
    int ok = 1;
    for (int p = 0; p < procs; p++) {
        int st;
        if (wait(&st) < 0 || !WIFEXITED(st) || WEXITSTATUS(st) != 0) ok = 0;
    }
    printf("concurrency: %d processes x %d threads x %d rounds (5 forwarded calls each) in %llu ms\n", procs, threads, ROUNDS,
           (unsigned long long)(now_ms() - t0));
    return ok;
}

/* --- the kill test's load --- */
static volatile long h_calls, h_errs;
static void *hammer_thread(void *arg) {
    (void)arg;
    char desc[64];
    for (long i = 0;; i++) {
        snprintf(desc, sizeof desc, "hammer-%d-%ld", gettid(), i);
        long id = syscall(SYS_add_key, "user", desc, "x", 1, THREAD_KEYRING);
        if (id > 0) syscall(SYS_keyctl, KEYCTL_UNLINK, id, THREAD_KEYRING); else __sync_fetch_and_add(&h_errs, 1);
        if (lx(1, 20, 0) < 0) __sync_fetch_and_add(&h_errs, 1); /* a pending call, 20 ms */
        __sync_fetch_and_add(&h_calls, 3);
    }
    return 0;
}

static void hammer(int procs) {
    for (int p = 0; p < procs; p++) {
        if (fork() == 0) {
            pthread_t t;
            for (int i = 0; i < 4; i++) pthread_create(&t, 0, hammer_thread, 0);
            for (;;) {
                sleep(2);
                printf("HAMMER pid %d calls %ld errors %ld\n", getpid(), h_calls, h_errs);
                fflush(stdout);
            }
        }
    }
    printf("HAMMER-RUNNING %d processes\n", procs);
    fflush(stdout);
    for (;;) pause();
}

/* --- signals arriving during forwarded calls (wave 4): a 1 ms timer while 4 threads call --- */
static volatile long sig_seen;
static volatile int sig_stop;
static void on_tick(int s) { (void)s; __sync_fetch_and_add(&sig_seen, 1); }
static void *sig_worker(void *arg) {
    long bad = 0, n = 0;
    (void)arg;
    while (!sig_stop) {
        if (lx(0, 0, 0) != 0) bad++;
        long r = syscall(SYS_keyctl, 0, -3, 0);
        if (r < 0 && errno != EINTR) bad++;
        n++;
    }
    return (void *)(bad * 1000000000L + n);
}
static int sigstress(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_tick;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it = {{0, 1000}, {0, 1000}};
    pthread_t t[4];
    sig_stop = 0; sig_seen = 0;
    for (long i = 0; i < 4; i++) pthread_create(&t[i], 0, sig_worker, 0);
    setitimer(ITIMER_REAL, &it, 0);
    uint64_t t0 = now_ms();
    while (now_ms() - t0 < 3000) usleep(10000);
    struct itimerval off = {{0, 0}, {0, 0}};
    setitimer(ITIMER_REAL, &off, 0);
    sig_stop = 1;
    long bad = 0, calls = 0;
    for (int i = 0; i < 4; i++) {
        void *r;
        pthread_join(t[i], &r);
        bad += (long)r / 1000000000L;
        calls += (long)r % 1000000000L;
    }
    printf("sigstress: %ld call pairs, %ld signals delivered, %ld bad answers\n", calls, sig_seen, bad);
    /* A 1 ms timer for 3 s: Hydra's timers have the 10 ms tick's resolution, so ~300 at
     * most (Linux: ~3000). Wave 4 saw 4-5 with lx=kernel (the timer daemon starved while
     * the threads were in system calls; fixed in wave 5): at least two thirds now */
    return bad == 0 && sig_seen >= 200 && calls > 1000;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 1 && !strcmp(argv[1], "hammer")) hammer(argc > 2 ? atoi(argv[2]) : 2);

    long r = lx(0, 0, 0);
    check(r == 0, "the test call returns 0");
    long p = lx(1, 50, 0);
    int forwarded = p == 42;
    printf("forwarding: %s\n", forwarded ? "on (linux-server)" : "off (in the kernel)");
    if (forwarded) {
        /* Client memory: a buffer across a page boundary, then bad addresses */
        unsigned char *m = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 300; i++) m[4096 - 150 + i] = (unsigned char)i;
        check(lx(2, (long)(m + 4096 - 150), 300) == 300, "copy across a page boundary");
        int same = 1;
        for (int i = 0; i < 300; i++) same &= m[4096 - 150 + i] == (unsigned char)(i + 1);
        check(same, "the server changed the caller's bytes");
        check(lx(2, 0x10, 16) == -1 && errno == EFAULT, "unmapped address: EFAULT");
        check(lx(2, (long)0xffff800000000000ul, 16) == -1 && errno == EFAULT, "kernel address: EFAULT");
        munmap(m + 4096, 4096);
        check(lx(2, (long)(m + 4096 - 8), 16) == -1 && errno == EFAULT, "half-mapped range: EFAULT");
        mprotect(m, 4096, PROT_READ);
        check(lx(2, (long)m, 16) == -1 && errno == EFAULT, "read-only page written: EFAULT");
        /* A pending call answered later by another server thread */
        uint64_t t0 = now_ms();
        long v = lx(1, 200, 0);
        uint64_t dt = now_ms() - t0;
        check(v == 42 && dt >= 150, "pending call answered later (lx_complete)");
        printf("     (took %llu ms)\n", (unsigned long long)dt);
        /* A signal while a pending call waits: the server answers EINTR */
        struct sigaction sa = {0};
        sa.sa_handler = on_alarm;
        sigaction(SIGALRM, &sa, 0);
        struct itimerval it = {{0, 0}, {0, 100000}};
        setitimer(ITIMER_REAL, &it, 0);
        t0 = now_ms();
        v = lx(1, 5000, 0);
        dt = now_ms() - t0;
        check(v == -1 && errno == EINTR && dt < 3000, "signal during a pending call: EINTR");
        printf("     (took %llu ms)\n", (unsigned long long)dt);
    }
    /* The copy-in/copy-out table (wave 4): strings and buffers at page edges, bad pointers,
     * more than fits in the syscall page. Linux's answers, forwarded or not. */
    {
        char *m = mmap(0, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        munmap(m + 4096, 4096);
        strcpy(m + 4096 - 5, "user"); /* the NUL is the page's last byte */
        strcpy(m + 2000, "lxfwd-edge");
        long k = syscall(SYS_add_key, m + 4096 - 5, m + 2000, "abc", 3, THREAD_KEYRING);
        check(k > 0, "copy table: a string ending at an unmapped page");
        check(syscall(SYS_add_key, "user", "lxfwd-bad", (void *)0x10, 4, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: bad payload pointer: EFAULT");
        check(syscall(SYS_add_key, (void *)0x10, "x", "a", 1, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: bad string pointer: EFAULT");
        check(syscall(SYS_keyctl, KEYCTL_READ, k, m + 4093, 3) == 3 && !memcmp(m + 4093, "abc", 3),
              "copy table: output ending at the end of a page");
        check(syscall(SYS_keyctl, KEYCTL_READ, k, m + 4094, 3) == -1 && errno == EFAULT,
              "copy table: output crossing into an unmapped page: EFAULT");
        char *huge = malloc(65536);
        check(syscall(SYS_keyctl, KEYCTL_READ, k, huge, 65536) == 3 && !memcmp(huge, "abc", 3),
              "copy table: a short answer into a 64 KiB buffer");
        static char big[3500], back[4000];
        for (int i = 0; i < (int)sizeof big; i++) big[i] = (char)(i * 13 + 1);
        long kb = syscall(SYS_add_key, "user", "lxfwd-big", big, sizeof big, THREAD_KEYRING);
        long nb = syscall(SYS_keyctl, KEYCTL_READ, kb, back, sizeof back);
        check(kb > 0 && nb == (long)sizeof big && !memcmp(back, big, sizeof big),
              "copy table: a payload larger than the syscall page's copy area");
        mprotect(m, 4096, PROT_READ);
        check(syscall(SYS_keyctl, KEYCTL_READ, k, m + 100, 16) == -1 && errno == EFAULT,
              "copy table: read-only output buffer: EFAULT");
        syscall(SYS_keyctl, KEYCTL_UNLINK, k, THREAD_KEYRING);
        syscall(SYS_keyctl, KEYCTL_UNLINK, kb, THREAD_KEYRING);
        free(huge);
        munmap(m, 4096);
    }
    /* Wave 6 (Group 22): the copies go straight through the caller's address space with
     * fault fix-ups. Pages not faulted in yet (anonymous, file, copy-on-write after fork),
     * faults in the middle of a copy, bad and kernel pointers. Linux's answers, forwarded or
     * not. */
    {
        char *m = mmap(0, 4 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        static char back[4000], zero[3000];
        /* Input from two pages never touched (they read as zeros) */
        long k = syscall(SYS_add_key, "user", "g22-fresh", m + 4096 - 1000, 3000, THREAD_KEYRING);
        check(k > 0 && syscall(SYS_keyctl, KEYCTL_READ, k, back, sizeof back) == 3000 && !memcmp(back, zero, 3000),
              "copy table: input from pages not faulted in yet");
        /* Output into two pages never touched */
        memset(back, 1, sizeof back);
        long n = syscall(SYS_keyctl, KEYCTL_READ, k, m + 3 * 4096 - 1500, 3000);
        check(n == 3000 && !memcmp(m + 3 * 4096 - 1500, zero, 3000), "copy table: output into pages not faulted in yet");
        /* Strings from a page never touched (empty: refused) and from one written */
        char *s = mmap(0, 2 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(syscall(SYS_add_key, s, "x", "a", 1, THREAD_KEYRING) == -1 && errno == EINVAL,
              "copy table: an empty type from a page never touched: EINVAL");
        memset(s + 4096 - 4, 'q', 10);
        s[4096 + 6] = 0;
        check(syscall(SYS_add_key, s + 4096 - 4, "x", "a", 1, THREAD_KEYRING) == -1 && errno == ENODEV,
              "copy table: a string across two pages (unknown type: ENODEV)");
        /* Faults in the middle of a copy: input and output crossing into an unmapped page, a
         * string running into one without its NUL; kernel and non-canonical pointers */
        munmap(m + 2 * 4096, 4096);
        m[2 * 4096 - 200] = 1;
        check(syscall(SYS_add_key, "user", "g22-cross", m + 2 * 4096 - 100, 200, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: input crossing into an unmapped page: EFAULT");
        check(syscall(SYS_keyctl, KEYCTL_READ, k, m + 2 * 4096 - 100, 3000) == -1 && errno == EFAULT,
              "copy table: output crossing into an unmapped page after 100 bytes: EFAULT");
        memset(m + 2 * 4096 - 64, 'z', 64);
        check(syscall(SYS_add_key, "user", m + 2 * 4096 - 64, "a", 1, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: a string running into an unmapped page: EFAULT");
        check(syscall(SYS_add_key, "user", (void *)0xffff800000001000ul, "a", 1, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: a kernel string pointer: EFAULT");
        check(syscall(SYS_add_key, "user", "g22-k", (void *)0xffff800000001000ul, 16, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: a kernel payload pointer: EFAULT");
        check(syscall(SYS_add_key, "user", "g22-nc", (void *)0x8000000000000000ul, 16, THREAD_KEYRING) == -1 && errno == EFAULT,
              "copy table: a non-canonical pointer: EFAULT");
        check(syscall(SYS_keyctl, KEYCTL_READ, k, (void *)0xffff800000001000ul, 16) == -1 && errno == EFAULT,
              "copy table: a kernel output pointer: EFAULT");
        /* Output into a copy-on-write page after fork: the child keeps its own bytes */
        char *c = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        memset(c, 'p', 4096);
        int pfd[2];
        pipe(pfd);
        pid_t pid = fork();
        if (pid == 0) {
            char x;
            read(pfd[0], &x, 1);
            _exit(c[10] == 'p' ? 0 : 1);
        }
        long kc = syscall(SYS_add_key, "user", "g22-cow", "COWCOWCOW", 9, THREAD_KEYRING);
        n = syscall(SYS_keyctl, KEYCTL_READ, kc, c + 5, 9);
        write(pfd[1], "x", 1);
        int st = 0;
        waitpid(pid, &st, 0);
        check(n == 9 && !memcmp(c + 5, "COWCOWCOW", 9) && WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "copy table: output into a copy-on-write page after fork");
        /* Input from a file mapping not read yet; output into a private file mapping */
        int fd = open("/tmp/g22-map", O_RDWR | O_CREAT | O_TRUNC, 0644);
        char line[64];
        memset(line, 'f', sizeof line);
        for (int i = 0; i < 64; i++) write(fd, line, sizeof line);
        char *f = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
        long kf = syscall(SYS_add_key, "user", "g22-file", f + 100, 64, THREAD_KEYRING);
        check(kf > 0 && syscall(SYS_keyctl, KEYCTL_READ, kf, back, 64) == 64 && !memcmp(back, line, 64),
              "copy table: input from a file page not read yet");
        n = syscall(SYS_keyctl, KEYCTL_READ, kc, f + 200, 9);
        char disk[9];
        pread(fd, disk, 9, 200);
        check(n == 9 && !memcmp(f + 200, "COWCOWCOW", 9) && !memcmp(disk, line, 9),
              "copy table: output into a private file mapping (the file unchanged)");
        close(fd);
        unlink("/tmp/g22-map");
        long ids[] = {k, kc, kf};
        for (int i = 0; i < 3; i++)
            if (ids[i] > 0) syscall(SYS_keyctl, KEYCTL_UNLINK, ids[i], THREAD_KEYRING);
        munmap(m, 4 * 4096);
        munmap(s, 2 * 4096);
        munmap(c, 4096);
        munmap(f, 4096);
    }
    check(concurrency(4, 8), "4 processes x 8 threads: every forwarded call answered correctly");
    check(sigstress(), "signals every millisecond during forwarded calls: no hang, no wrong answer");
    printf(fails ? "LXFWD TEST FAILED (%d)\n" : "LXFWD TEST PASSED\n", fails);
    return fails != 0;
}
