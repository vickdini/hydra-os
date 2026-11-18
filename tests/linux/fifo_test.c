// FIFOs (mkfifo nodes) open as pipes (wave 5, Group 13): before, a FIFO opened as an empty
// regular file and GNU make's jobserver FIFO busy-looped (every make -j burned a CPU).
// - a reader's open waits for a writer (and the other way round), data passes, end of file
//   when the writer closes; O_NONBLOCK: a reader goes on, a writer without reader: ENXIO;
// - O_RDWR never waits and reads what it wrote (linux-server's FIFOs; lx=kernel: skipped);
// - poll on a FIFO with nothing in it waits (no busy loop);
// - a jobserver as make -j runs it on a FIFO (3 tokens, 6 jobs) does not spin.
// Build: gcc -O1 -w -o fifo fifo_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}
static long long ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

int main(void) {
    const char *f = "/tmp/fifo_test.fifo";
    unlink(f);
    check(mkfifo(f, 0600) == 0, "mkfifo");
    struct stat st;
    check(stat(f, &st) == 0 && S_ISFIFO(st.st_mode), "the node is a FIFO");

    // A reader waits for the writer, which comes 300 ms later
    pid_t w = fork();
    if (w == 0) {
        usleep(300000);
        int fd = open(f, O_WRONLY);
        write(fd, "hello", 5);
        usleep(100000);
        close(fd);
        _exit(0);
    }
    long long t0 = ms();
    int r = open(f, O_RDONLY);
    long long waited = ms() - t0;
    check(r >= 0 && waited >= 200, "a reader's open waits for a writer");
    struct stat fs;
    check(r >= 0 && fstat(r, &fs) == 0 && S_ISFIFO(fs.st_mode), "the descriptor is a pipe (S_IFIFO)");
    char buf[16] = {0};
    check(read(r, buf, sizeof buf) == 5 && !memcmp(buf, "hello", 5), "the writer's bytes arrive");
    check(read(r, buf, sizeof buf) == 0, "end of file once the writer closed");
    close(r);
    waitpid(w, 0, 0);

    // A writer waits for a reader
    pid_t rd = fork();
    if (rd == 0) {
        usleep(300000);
        int fd = open(f, O_RDONLY);
        char b[8];
        int n = read(fd, b, sizeof b);
        _exit(n == 3 ? 0 : 1);
    }
    t0 = ms();
    int wr = open(f, O_WRONLY);
    waited = ms() - t0;
    check(wr >= 0 && waited >= 200, "a writer's open waits for a reader");
    check(write(wr, "abc", 3) == 3, "the writer writes");
    close(wr);
    int status;
    waitpid(rd, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the reader read it");

    // O_NONBLOCK
    errno = 0;
    check(open(f, O_WRONLY | O_NONBLOCK) < 0 && errno == ENXIO, "a non-blocking writer without reader: ENXIO");
    int nr = open(f, O_RDONLY | O_NONBLOCK);
    check(nr >= 0, "a non-blocking reader opens at once");
    int nw = open(f, O_WRONLY | O_NONBLOCK);
    check(nw >= 0, "then a non-blocking writer opens");
    // poll with nothing to read waits for its timeout (no busy loop)
    struct pollfd p = {nr, POLLIN, 0};
    t0 = ms();
    int pr = poll(&p, 1, 200);
    check(pr == 0 && ms() - t0 >= 150, "poll on an empty FIFO waits");
    write(nw, "x", 1);
    check(poll(&p, 1, 1000) == 1 && (p.revents & POLLIN), "poll sees the byte");
    close(nr);
    close(nw);

    // O_RDWR (linux-server's FIFOs)
    long srv = syscall(0x6710, 3, 0);
    if (srv > 2) {
        close(srv);
        int rw = open(f, O_RDWR);
        check(rw >= 0 && write(rw, "rw", 2) == 2 && read(rw, buf, 2) == 2 && !memcmp(buf, "rw", 2), "O_RDWR does not wait and reads what it wrote");
        close(rw);
    } else {
        puts("skip O_RDWR (FIFOs in the kernel: lx=kernel)");
    }
    unlink(f);

    // A jobserver as GNU make -j4 runs it on a FIFO: 3 tokens, 6 jobs that each take one
    // (a blocking read), work 0.3 s, and give it back; the waits must sleep, not spin
    {
        const char *js = "/tmp/fifo_test.jobs";
        unlink(js);
        mkfifo(js, 0600);
        int jr = open(js, O_RDONLY | O_NONBLOCK);
        int jw = open(js, O_WRONLY);
        fcntl(jr, F_SETFL, 0);
        write(jw, "+++", 3);
        struct rusage before;
        getrusage(RUSAGE_CHILDREN, &before);
        t0 = ms();
        for (int i = 0; i < 6; i++) {
            if (fork() == 0) {
                char tok;
                int fd = open(js, O_RDONLY);
                int wfd = open(js, O_WRONLY);
                if (read(fd, &tok, 1) != 1) _exit(1);
                struct timespec ts = {0, 300000000};
                nanosleep(&ts, 0);
                write(wfd, &tok, 1);
                _exit(0);
            }
        }
        int ok = 1;
        for (int i = 0; i < 6; i++) {
            int st2;
            wait(&st2);
            ok &= WIFEXITED(st2) && WEXITSTATUS(st2) == 0;
        }
        long long el = ms() - t0;
        struct rusage after;
        getrusage(RUSAGE_CHILDREN, &after);
        double cpu = (after.ru_utime.tv_sec - before.ru_utime.tv_sec) + (after.ru_utime.tv_usec - before.ru_utime.tv_usec) / 1e6 +
                     (after.ru_stime.tv_sec - before.ru_stime.tv_sec) + (after.ru_stime.tv_usec - before.ru_stime.tv_usec) / 1e6;
        printf("     jobserver: 6 jobs of 0.3 s with 3 tokens took %lld ms, %.2f s CPU%c", el, cpu, 10);
        check(ok && el >= 550 && el < 3000, "a FIFO jobserver runs 6 jobs 3 at a time");
        check(cpu < 0.5, "the jobs wait for tokens without spinning");
        close(jr);
        close(jw);
        unlink(js);
    }

    // (GNU make itself is not in the test image; make 4.4.1 -j4 with its fifo, pipe and
    // default jobservers was checked by hand: scratch/t7.sh)

    printf(fails ? "FIFO TEST FAILED (%d)\n" : "FIFO TEST PASSED\n", fails);
    return fails != 0;
}
