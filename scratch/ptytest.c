// Hydra pseudo-terminal and shared descriptor table conformance test.
// Build (WSL): gcc -static-pie -O1 -pthread -o esp/bin/ptytest.elf scratch/ptytest.c
// Run in Hydra: linux run ptytest.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("[ptytest] %-50s %s\n", name, ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) failures++;
}

// Reads what is available within ~1 s (the master side returns what has been echoed).
static int read_avail(int fd, char *buf, int cap) {
    int n = 0;
    struct pollfd p = {fd, POLLIN, 0};
    while (n < cap - 1 && poll(&p, 1, n ? 100 : 1000) > 0) {
        int r = read(fd, buf + n, cap - 1 - n);
        if (r <= 0) break;
        n += r;
    }
    buf[n] = 0;
    return n;
}

// --- shared descriptor tables ---
static int thread_fd = -1;
static int pipe_fds[2];

static void *open_in_thread(void *arg) {
    (void)arg;
    thread_fd = open("/proc/self/exe", O_RDONLY);
    return NULL;
}

static void *close_in_thread(void *arg) {
    close(*(int *)arg);
    return NULL;
}

static void *pipe_in_thread(void *arg) {
    (void)arg;
    if (pipe(pipe_fds) != 0) pipe_fds[0] = pipe_fds[1] = -1;
    return NULL;
}

static void fd_table_tests(void) {
    pthread_t t;
    pthread_create(&t, NULL, open_in_thread, NULL);
    pthread_join(t, NULL);
    char magic[4] = {0};
    check("fd opened by a thread is usable by main thread",
          thread_fd >= 0 && pread(thread_fd, magic, 4, 0) == 4 && memcmp(magic, "\x7f" "ELF", 4) == 0);

    pthread_create(&t, NULL, pipe_in_thread, NULL);
    pthread_join(t, NULL);
    char b = 0;
    check("pipe created by a thread works in main thread",
          pipe_fds[0] >= 0 && write(pipe_fds[1], "z", 1) == 1 && read(pipe_fds[0], &b, 1) == 1 && b == 'z');

    int fd = thread_fd;
    pthread_create(&t, NULL, close_in_thread, &fd);
    pthread_join(t, NULL);
    check("fd closed by a thread is closed for main thread", fcntl(fd, F_GETFD) == -1 && errno == EBADF);

    // fork copies the table: the child's close does not affect the parent
    pid_t c = fork();
    if (c == 0) {
        close(pipe_fds[0]);
        _exit(fcntl(pipe_fds[0], F_GETFD) == -1 ? 0 : 1);
    }
    int st = 0;
    waitpid(c, &st, 0);
    check("fork child closing an fd leaves the parent's open",
          WIFEXITED(st) && WEXITSTATUS(st) == 0 && fcntl(pipe_fds[0], F_GETFD) != -1);
    close(pipe_fds[0]);
    close(pipe_fds[1]);
}

// --- pseudo-terminals ---
static void pty_tests(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    check("posix_openpt opens /dev/ptmx", m >= 0);
    if (m < 0) return;
    check("grantpt + unlockpt", grantpt(m) == 0 && unlockpt(m) == 0);
    char *name = ptsname(m);
    check("ptsname is /dev/pts/N", name && strncmp(name, "/dev/pts/", 9) == 0);
    struct stat st;
    check("stat(ptsname) is a character device", name && stat(name, &st) == 0 && S_ISCHR(st.st_mode));

    int s = open(name, O_RDWR | O_NOCTTY);
    check("open slave", s >= 0);
    check("isatty(slave) and isatty(master)", isatty(s) && isatty(m));
    char *tn = ttyname(s);
    check("ttyname(slave) == ptsname", tn && strcmp(tn, name) == 0);

    // Canonical input with echo
    char buf[256];
    write(m, "hello\n", 6);
    int n = read(s, buf, sizeof buf - 1);
    buf[n > 0 ? n : 0] = 0;
    check("master write -> slave reads a line", n == 6 && strcmp(buf, "hello\n") == 0);
    n = read_avail(m, buf, sizeof buf);
    check("master reads the echo (with CR LF)", strcmp(buf, "hello\r\n") == 0);

    // Line editing: erase (DEL) before newline
    write(m, "abx\x7f" "c\n", 6);
    n = read(s, buf, sizeof buf - 1);
    buf[n > 0 ? n : 0] = 0;
    check("erase character edits the line", strcmp(buf, "abc\n") == 0);
    read_avail(m, buf, sizeof buf);

    // Output processing
    write(s, "out\n", 4);
    n = read_avail(m, buf, sizeof buf);
    check("slave write -> master reads with ONLCR", strcmp(buf, "out\r\n") == 0);

    // Raw mode
    struct termios t;
    tcgetattr(s, &t);
    cfmakeraw(&t);
    check("tcsetattr raw mode", tcsetattr(s, TCSANOW, &t) == 0);
    write(m, "x", 1);
    struct pollfd p = {s, POLLIN, 0};
    check("poll(slave) readable in raw mode", poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
    n = read(s, buf, 10);
    check("raw read returns single byte", n == 1 && buf[0] == 'x');
    n = read_avail(m, buf, sizeof buf);
    check("no echo in raw mode", n == 0);

    // Window size
    struct winsize ws = {.ws_row = 33, .ws_col = 101};
    struct winsize got = {0};
    check("TIOCSWINSZ on master, TIOCGWINSZ on slave",
          ioctl(m, TIOCSWINSZ, &ws) == 0 && ioctl(s, TIOCGWINSZ, &got) == 0 && got.ws_row == 33 && got.ws_col == 101);

    // Non-blocking master read with nothing pending
    int fl = fcntl(m, F_GETFL);
    fcntl(m, F_SETFL, fl | O_NONBLOCK);
    check("O_NONBLOCK master read -> EAGAIN", read(m, buf, 10) == -1 && errno == EAGAIN);
    fcntl(m, F_SETFL, fl);

    // Hang-up: closing the master gives the slave end-of-file / EIO
    close(m);
    check("slave read after master close -> EOF", read(s, buf, 10) == 0);
    check("slave write after master close -> EIO", write(s, "q", 1) == -1 && errno == EIO);
    close(s);
}

// Ctrl+C through a pty reaches the foreground process group of its session.
static void pty_signal_test(void) {
    int m, s;
    if (openpty(&m, &s, NULL, NULL, NULL) != 0) {
        check("openpty", 0);
        return;
    }
    check("openpty", 1);
    pid_t c = fork();
    if (c == 0) {
        close(m);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        tcsetpgrp(s, getpid());
        write(s, "R", 1); // ready
        for (;;) pause();
    }
    close(s);
    char r;
    int ok = read(m, &r, 1) == 1 && r == 'R';
    write(m, "\x03", 1); // VINTR
    int st = 0;
    alarm(5);
    waitpid(c, &st, 0);
    alarm(0);
    check("^C on master sends SIGINT to the slave's foreground", ok && WIFSIGNALED(st) && WTERMSIG(st) == SIGINT);

    // forkpty: a child shell-like process writing to its terminal
    int fm;
    pid_t k = forkpty(&fm, NULL, NULL, NULL);
    if (k == 0) {
        printf("child on %s\n", ttyname(0));
        fflush(stdout);
        _exit(isatty(0) && isatty(1) ? 3 : 4);
    }
    char buf[128];
    read_avail(fm, buf, sizeof buf);
    waitpid(k, &st, 0);
    check("forkpty child sees a terminal on stdio", WIFEXITED(st) && WEXITSTATUS(st) == 3 && strstr(buf, "child on /dev/pts/"));
    close(fm);
    close(m);
}

int main(void) {
    signal(SIGALRM, SIG_DFL);
    fd_table_tests();
    pty_tests();
    pty_signal_test();
    if (failures == 0)
        printf("[ptytest] ALL PASSED (0 failures)\n");
    else
        printf("[ptytest] %d FAILURES\n", failures);
    return failures != 0;
}
