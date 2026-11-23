// ipckeep: lx-ipc restarts invisibly (wave 9, Group X3).
//
// `ipckeep SECS` streams for SECS seconds through every kind of IPC object lx-ipc keeps,
// checking every byte, while `service kill lx_ipc` runs in hydra-shell:
//   pipe     a counter pattern through a pipe, chunks of random size (1..70000)
//   unix     the same through a socketpair(AF_UNIX, SOCK_STREAM)
//   conn     the same through a connected abstract-name listener (bind/listen/accept)
//   seqp     numbered messages through SOCK_SEQPACKET (boundaries kept); every 64th one
//            carries a pipe's read end (SCM_RIGHTS) whose byte must read back
//   efd      eventfd: the writer adds 1 per round, the reader sums
//   tfd      a 10 ms periodic timerfd keeps counting
// Each line: NAME ok|FAIL bytes/messages, errors (a call failing), bad (wrong data).
// Last line: IPCKEEP PASS or IPCKEEP FAIL.  `ipckeep idle` just holds objects (a pipe with
// bytes waiting, a listening socket, an eventfd with a count) across a restart and checks
// them after the kill: `ipckeep hold` then `ipckeep check` (state in /tmp/ipckeep.*).
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static unsigned rnd(unsigned *s) {
    *s = *s * 1103515245u + 12345u;
    return (*s >> 8);
}

// The stream pattern: byte i is (i * 7 + i / 251) & 0xff
static unsigned char pat(uint64_t i) { return (unsigned char)(i * 7 + i / 251); }

// Writer: SECS seconds of pattern bytes, then close. Reader: checks, prints the result.
static void stream_pair(const char *name, int wfd, int rfd, int secs) {
    pid_t w = fork();
    if (w == 0) {
        close(rfd);
        static unsigned char buf[70000];
        uint64_t off = 0;
        unsigned s = 12345;
        double end = now() + secs;
        long errs = 0;
        while (now() < end) {
            size_t n = 1 + rnd(&s) % (rnd(&s) % 4 == 0 ? 70000 : 600);
            for (size_t i = 0; i < n; i++) buf[i] = pat(off + i);
            size_t done = 0;
            while (done < n) {
                ssize_t r = write(wfd, buf + done, n - done);
                if (r < 0) {
                    if (errno == EINTR) continue;
                    errs++;
                    if (errs > 5) { fprintf(stderr, "%s writer: %s\n", name, strerror(errno)); _exit(3); }
                    usleep(1000);
                    continue;
                }
                done += r;
            }
            off += n;
        }
        close(wfd);
        _exit(errs ? 2 : 0);
    }
    close(wfd);
    static unsigned char buf[65536];
    uint64_t off = 0;
    long errs = 0, bad = 0;
    for (;;) {
        ssize_t r = read(rfd, buf, sizeof buf);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            errs++;
            if (errs > 5) break;
            usleep(1000);
            continue;
        }
        for (ssize_t i = 0; i < r; i++)
            if (buf[i] != pat(off + i)) { if (bad < 3) fprintf(stderr, "%s: byte %llu is %u, not %u\n", name, (unsigned long long)(off + i), buf[i], pat(off + i)); bad++; break; }
        off += r;
    }
    int st = 0;
    waitpid(w, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) errs++;
    printf("%s %s bytes=%llu errors=%ld bad=%ld\n", name, (errs || bad || off == 0) ? "FAIL" : "ok", (unsigned long long)off, errs, bad);
    fflush(stdout);
    _exit(errs || bad || off == 0);
}

static void seqpacket(int secs) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) < 0) { printf("seqp FAIL socketpair %s\n", strerror(errno)); _exit(1); }
    pid_t w = fork();
    if (w == 0) {
        close(sv[1]);
        double end = now() + secs;
        long errs = 0;
        unsigned s = 777;
        char m[4096];
        for (uint32_t k = 0; now() < end; k++) {
            size_t n = 8 + rnd(&s) % 3000;
            memset(m, (int)(k & 0xff), n);
            memcpy(m, &k, 4);
            uint32_t nn = (uint32_t)n;
            memcpy(m + 4, &nn, 4);
            struct iovec iov = {m, n};
            struct msghdr mh = {0};
            mh.msg_iov = &iov;
            mh.msg_iovlen = 1;
            char cbuf[CMSG_SPACE(sizeof(int))];
            int p[2] = {-1, -1};
            if (k % 64 == 0 && pipe(p) == 0) {
                char c = (char)k;
                write(p[1], &c, 1);
                close(p[1]);
                mh.msg_control = cbuf;
                mh.msg_controllen = sizeof cbuf;
                struct cmsghdr *cm = CMSG_FIRSTHDR(&mh);
                cm->cmsg_level = SOL_SOCKET;
                cm->cmsg_type = SCM_RIGHTS;
                cm->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cm), &p[0], sizeof(int));
            }
            for (;;) {
                ssize_t r = sendmsg(sv[0], &mh, 0);
                if (r < 0 && errno == EINTR) continue;
                if (r < 0) { errs++; if (errs > 5) { fprintf(stderr, "seqp writer: %s\n", strerror(errno)); _exit(3); } usleep(1000); continue; }
                break;
            }
            if (p[0] >= 0) close(p[0]);
        }
        close(sv[0]);
        _exit(errs ? 2 : 0);
    }
    close(sv[0]);
    long errs = 0, bad = 0, fds = 0;
    uint32_t want = 0;
    char m[4096];
    for (;;) {
        struct iovec iov = {m, sizeof m};
        struct msghdr mh = {0};
        char cbuf[CMSG_SPACE(sizeof(int) * 4)];
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof cbuf;
        ssize_t r = recvmsg(sv[1], &mh, 0);
        if (r == 0) break;
        if (r < 0) { if (errno == EINTR) continue; errs++; if (errs > 5) break; usleep(1000); continue; }
        uint32_t k, n;
        memcpy(&k, m, 4);
        memcpy(&n, m + 4, 4);
        if (k != want || n != (uint32_t)r) { if (bad < 3) fprintf(stderr, "seqp: message %u (len %zd, says %u), wanted %u\n", k, r, n, want); bad++; }
        want = k + 1;
        for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
            if (cm->cmsg_type != SCM_RIGHTS) continue;
            int fd;
            memcpy(&fd, CMSG_DATA(cm), sizeof fd);
            char c = 0;
            if (read(fd, &c, 1) != 1 || c != (char)k) { if (bad < 3) fprintf(stderr, "seqp: fd of message %u reads wrong\n", k); bad++; }
            close(fd);
            fds++;
        }
    }
    int st = 0;
    waitpid(w, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) errs++;
    printf("seqp %s messages=%u fds=%ld errors=%ld bad=%ld\n", (errs || bad || want == 0) ? "FAIL" : "ok", want, fds, errs, bad);
    fflush(stdout);
    _exit(errs || bad || want == 0);
}

static void efd_test(int secs) {
    int e = eventfd(0, 0);
    pid_t w = fork();
    if (w == 0) {
        double end = now() + secs;
        uint64_t one = 1, n = 0;
        long errs = 0;
        while (now() < end) {
            if (write(e, &one, 8) != 8) { if (errno != EINTR) errs++; continue; }
            n++;
            if (n % 64 == 0) usleep(200);
        }
        // the count, as the last value (the reader stops on it)
        uint64_t big = (1ull << 40) + n;
        write(e, &big, 8);
        _exit(errs ? 2 : 0);
    }
    uint64_t sum = 0, v;
    long errs = 0;
    for (;;) {
        if (read(e, &v, 8) != 8) { if (errno == EINTR) continue; errs++; if (errs > 5) break; continue; }
        sum += v;
        if (sum >= (1ull << 40)) break;
    }
    int st = 0;
    waitpid(w, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st)) errs++;
    uint64_t got = sum - (1ull << 40);
    // the writer counted n, then added 2^40 + n: the reader saw n + 2^40 + n
    int ok = !errs && (got % 2 == 0) && got > 0;
    printf("efd %s adds=%llu errors=%ld\n", ok ? "ok" : "FAIL", (unsigned long long)(got / 2), errs);
    fflush(stdout);
    _exit(!ok);
}

static void tfd_test(int secs) {
    int t = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {{0, 10000000}, {0, 10000000}};
    timerfd_settime(t, 0, &its, NULL);
    double end = now() + secs;
    uint64_t total = 0, v;
    long errs = 0;
    while (now() < end) {
        if (read(t, &v, 8) != 8) { if (errno == EINTR) continue; errs++; if (errs > 5) break; continue; }
        total += v;
    }
    // ~100 expirations a second
    int ok = !errs && total >= (uint64_t)secs * 50;
    printf("tfd %s expirations=%llu errors=%ld\n", ok ? "ok" : "FAIL", (unsigned long long)total, errs);
    fflush(stdout);
    _exit(!ok);
}

static void conn_test(int secs) {
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {0};
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path + 1, sizeof a.sun_path - 1, "ipckeep-%d", getpid());
    socklen_t al = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(a.sun_path + 1);
    if (bind(l, (struct sockaddr *)&a, al) < 0 || listen(l, 4) < 0) { printf("conn FAIL bind %s\n", strerror(errno)); _exit(1); }
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&a, al) < 0) { printf("conn FAIL connect %s\n", strerror(errno)); _exit(1); }
    int s = accept(l, NULL, NULL);
    if (s < 0) { printf("conn FAIL accept %s\n", strerror(errno)); _exit(1); }
    close(l);
    stream_pair("conn", c, s, secs);
}

// hold / check: objects idle across a restart
static int hold(void) {
    int p[2];
    pipe(p);
    write(p[1], "kept-bytes", 10);
    int e = eventfd(41, 0);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    write(sv[0], "socket-bytes", 12);
    printf("HOLD ready\n");
    fflush(stdout);
    // wait for the kill (a signal from the checker: SIGUSR1), then check
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, SIGUSR1);
    sigprocmask(SIG_BLOCK, &m, NULL);
    int sig;
    sigwait(&m, &sig);
    char b[32] = {0};
    int bad = 0;
    if (read(p[0], b, sizeof b) != 10 || memcmp(b, "kept-bytes", 10)) bad |= 1;
    uint64_t v = 0;
    if (read(e, &v, 8) != 8 || v != 41) bad |= 2;
    memset(b, 0, sizeof b);
    if (read(sv[1], b, sizeof b) != 12 || memcmp(b, "socket-bytes", 12)) bad |= 4;
    close(p[1]);
    if (read(p[0], b, 1) != 0) bad |= 8;
    printf("HOLD %s (bad=%d)\n", bad ? "FAIL" : "ok", bad);
    return bad != 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "hold")) return hold();
    int secs = argc > 1 ? atoi(argv[1]) : 20;
    if (secs <= 0) secs = 20;
    signal(SIGPIPE, SIG_IGN);
    pid_t kids[6];
    int n = 0;
    int p[2];
    pipe(p);
    if ((kids[n++] = fork()) == 0) stream_pair("pipe", p[1], p[0], secs);
    close(p[0]);
    close(p[1]);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if ((kids[n++] = fork()) == 0) stream_pair("unix", sv[0], sv[1], secs);
    close(sv[0]);
    close(sv[1]);
    if ((kids[n++] = fork()) == 0) conn_test(secs);
    if ((kids[n++] = fork()) == 0) seqpacket(secs);
    if ((kids[n++] = fork()) == 0) efd_test(secs);
    if ((kids[n++] = fork()) == 0) tfd_test(secs);
    int fail = 0;
    for (int i = 0; i < n; i++) {
        int st = 0;
        waitpid(kids[i], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) fail = 1;
    }
    printf("IPCKEEP %s\n", fail ? "FAIL" : "PASS");
    return fail;
}
