// Syscall batch 1: preadv/pwritev(2), sendfile, copy_file_range, splice, tee, vmsplice,
// times, utime/utimes/futimesat, getdents, getcpu, membarrier, rt_sigqueueinfo,
// rt_tgsigqueueinfo, personality, sched_rr_get_interval, restart_syscall.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/membarrier.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utime.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static volatile int got_value, got_code;
static void on_usr1(int s, siginfo_t *si, void *c) {
    (void)s; (void)c;
    got_value = si->si_value.sival_int;
    got_code = si->si_code;
}

static int fill(const char *path, int size) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    char *b = malloc(size);
    for (int i = 0; i < size; i++) b[i] = 'a' + i % 26;
    int ok = write(fd, b, size) == size;
    free(b);
    return ok ? fd : -1;
}

static int same(int a, int b, int size) {
    char *x = malloc(size), *y = malloc(size);
    int r = pread(a, x, size, 0) == size && pread(b, y, size, 0) == size && !memcmp(x, y, size);
    free(x); free(y);
    return r;
}

int main(void) {
    mkdir("/tmp/sb1", 0755);
    // preadv / pwritev / preadv2 / pwritev2
    int fd = open("/tmp/sb1/v", O_RDWR | O_CREAT | O_TRUNC, 0644);
    char a[] = "hello ", b[] = "world";
    struct iovec w[2] = {{a, 6}, {b, 5}};
    CHECK(pwritev(fd, w, 2, 5) == 11, "pwritev at offset 5");
    char r1[7] = {0}, r2[6] = {0};
    struct iovec rv[2] = {{r1, 6}, {r2, 5}};
    CHECK(preadv(fd, rv, 2, 5) == 11 && !strcmp(r1, "hello ") && !strcmp(r2, "world"), "preadv reads it back");
    lseek(fd, 11, SEEK_SET);
    memset(r2, 0, 6);
    struct iovec one = {r2, 5};
    CHECK(preadv2(fd, &one, 1, -1, 0) == 5 && !strcmp(r2, "world") && lseek(fd, 0, SEEK_CUR) == 16, "preadv2 at the current position");
    struct iovec ap = {"!", 1};
    CHECK(pwritev2(fd, &ap, 1, 0, RWF_APPEND) == 1 && lseek(fd, 0, SEEK_END) == 17, "pwritev2 RWF_APPEND");
    close(fd);

    // sendfile, copy_file_range
    int src = fill("/tmp/sb1/src", 200000);
    int dst = open("/tmp/sb1/dst", O_RDWR | O_CREAT | O_TRUNC, 0644);
    off_t off = 0;
    CHECK(sendfile(dst, src, &off, 200000) == 200000 && off == 200000 && same(src, dst, 200000), "sendfile copies 200000 bytes, offset updated");
    int dst2 = open("/tmp/sb1/dst2", O_RDWR | O_CREAT | O_TRUNC, 0644);
    loff_t in = 1000, out = 0;
    CHECK(copy_file_range(src, &in, dst2, &out, 5000, 0) == 5000 && in == 6000 && out == 5000, "copy_file_range with offsets");
    char x[10], y[10];
    pread(src, x, 10, 1000);
    pread(dst2, y, 10, 0);
    CHECK(!memcmp(x, y, 10), "copy_file_range data");
    errno = 0;
    CHECK(copy_file_range(src, 0, dst2, 0, 10, 1) == -1 && errno == EINVAL, "copy_file_range flags -> EINVAL");

    // splice file -> pipe -> file, tee, vmsplice
    int p[2], q[2];
    pipe(p);
    pipe(q);
    loff_t so = 0;
    CHECK(splice(src, &so, p[1], 0, 4096, 0) == 4096 && so == 4096, "splice file -> pipe");
    CHECK(tee(p[0], q[1], 4096, 0) == 4096, "tee pipe -> pipe");
    int dst3 = open("/tmp/sb1/dst3", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(splice(p[0], 0, dst3, 0, 4096, 0) == 4096, "splice pipe -> file");
    char t[4096], s[4096];
    CHECK(read(q[0], t, 4096) == 4096 && pread(src, s, 4096, 0) == 4096 && !memcmp(t, s, 4096), "tee copy matches");
    errno = 0;
    CHECK(splice(src, 0, dst3, 0, 10, 0) == -1 && errno == EINVAL, "splice without a pipe -> EINVAL");
    struct iovec vi = {"vmsplice!", 9};
    char vb[10] = {0};
    CHECK(vmsplice(p[1], &vi, 1, 0) == 9 && read(p[0], vb, 9) == 9 && !strcmp(vb, "vmsplice!"), "vmsplice into a pipe");

    // times
    struct tms tm;
    for (volatile long i = 0; i < 20000000; i++) {
    }
    clock_t now = times(&tm);
    CHECK(now != (clock_t)-1 && now > 0, "times returns %ld ticks (utime %ld)", (long)now, (long)tm.tms_utime);

    // utime / utimes / futimesat
    struct utimbuf ub = {1000000000, 1100000000};
    struct stat st;
    CHECK(utime("/tmp/sb1/v", &ub) == 0 && stat("/tmp/sb1/v", &st) == 0 && st.st_mtime == 1100000000, "utime sets mtime");
    struct timeval tv[2] = {{1200000000, 0}, {1300000000, 500000}};
    CHECK(utimes("/tmp/sb1/v", tv) == 0 && stat("/tmp/sb1/v", &st) == 0 && st.st_mtime == 1300000000 && st.st_mtim.tv_nsec == 500000000, "utimes sets mtime with microseconds");
    int dfd = open("/tmp/sb1", O_RDONLY | O_DIRECTORY);
    tv[1].tv_sec = 1400000000;
    CHECK(syscall(SYS_futimesat, dfd, "v", tv) == 0 && stat("/tmp/sb1/v", &st) == 0 && st.st_mtime == 1400000000, "futimesat relative to a directory");

    // getdents (old format: type in the last byte of each record)
    char db[4096];
    lseek(dfd, 0, SEEK_SET);
    long n = syscall(SYS_getdents, dfd, db, sizeof db);
    int found = 0, typed = 0;
    for (long o = 0; o < n;) {
        unsigned short rl = *(unsigned short *)(db + o + 16);
        if (!strcmp(db + o + 18, "src")) {
            found = 1;
            typed = db[o + rl - 1] == DT_REG;
        }
        o += rl;
    }
    CHECK(n > 0 && found && typed, "getdents lists src as a regular file");

    // getcpu, sched_rr_get_interval, restart_syscall
    unsigned cpu = 99, node = 99;
    CHECK(syscall(SYS_getcpu, &cpu, &node, 0) == 0 && cpu < 1024 && node < 64, "getcpu (cpu %u node %u)", cpu, node);
    struct timespec rr;
    CHECK(sched_rr_get_interval(0, &rr) == 0 && (rr.tv_sec > 0 || rr.tv_nsec > 0), "sched_rr_get_interval %ld ns", rr.tv_nsec);
    errno = 0;
    CHECK(syscall(SYS_restart_syscall) == -1 && errno == EINTR, "restart_syscall -> EINTR");

    // membarrier
    long mask = syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
    CHECK(mask > 0 && (mask & MEMBARRIER_CMD_PRIVATE_EXPEDITED), "membarrier query %#lx", mask);
    errno = 0;
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == -1 && errno == EPERM, "private expedited needs registration");
    CHECK(syscall(SYS_membarrier, MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) == 0 && syscall(SYS_membarrier, MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) == 0, "registered private expedited barrier");

    // sigqueue / rt_tgsigqueueinfo
    struct sigaction sa = {0};
    sa.sa_sigaction = on_usr1;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, 0);
    union sigval v = {.sival_int = 42};
    CHECK(sigqueue(getpid(), SIGUSR1, v) == 0 && got_value == 42 && got_code == SI_QUEUE, "sigqueue delivers value %d code %d", got_value, got_code);
    siginfo_t si;
    memset(&si, 0, sizeof si);
    si.si_signo = SIGUSR1;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    si.si_uid = getuid();
    si.si_value.sival_int = 7;
    got_value = 0;
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), syscall(SYS_gettid), SIGUSR1, &si) == 0 && got_value == 7, "rt_tgsigqueueinfo to own thread");
    si.si_code = SI_USER;
    errno = 0;
    CHECK(syscall(SYS_rt_sigqueueinfo, getppid(), SIGUSR1, &si) == -1 && errno == EPERM, "faking SI_USER to another process -> EPERM");

    // personality
    CHECK(personality(0xffffffff) == PER_LINUX, "personality is PER_LINUX");
    personality(PER_LINUX | ADDR_NO_RANDOMIZE);
    pid_t c = fork();
    if (c == 0) _exit(personality(0xffffffff) == (PER_LINUX | ADDR_NO_RANDOMIZE) ? 0 : 1);
    int ws;
    waitpid(c, &ws, 0);
    CHECK(personality(0xffffffff) == (PER_LINUX | ADDR_NO_RANDOMIZE) && WEXITSTATUS(ws) == 0, "personality set and inherited");
    personality(PER_LINUX);

    printf(fails ? "BATCH1 TEST FAILED (%d)\n" : "BATCH1 TEST PASSED\n", fails);
    return fails != 0;
}
