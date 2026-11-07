// File locks: flock (shared/exclusive, per open file description, inherited, blocking,
// conversion), POSIX record locks (ranges, F_GETLK, split on unlock, released by any close
// and by exit, F_SETLKW), OFD locks, the families' independence, /proc/locks, EBADF.
// Build: gcc -O1 -w -o locks locks_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef F_OFD_GETLK
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#endif

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static char path[64];

static int lk(int fd, int cmd, short type, off_t start, off_t len) {
    struct flock f = {.l_type = type, .l_whence = SEEK_SET, .l_start = start, .l_len = len};
    return fcntl(fd, cmd, &f);
}

// Runs f in a child; returns its exit status
static int in_child(int (*f)(void)) {
    pid_t c = fork();
    if (c == 0) _exit(f());
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : 255;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int child_read_50_60(void) {
    int fd = open(path, O_RDWR);
    errno = 0;
    int r = lk(fd, F_SETLK, F_RDLCK, 50, 10);
    if (r != -1 || (errno != EAGAIN && errno != EACCES)) return 1;
    struct flock g = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 50, .l_len = 10};
    fcntl(fd, F_GETLK, &g);
    if (g.l_type != F_WRLCK || g.l_pid != getppid() || g.l_start != 0 || g.l_len != 100) return 2;
    if (lk(fd, F_SETLK, F_WRLCK, 200, 100) != 0) return 3;
    return 0;
}

static int child_after_split(void) {
    int fd = open(path, O_RDWR);
    if (lk(fd, F_SETLK, F_WRLCK, 10, 10) != 0) return 1;      // unlocked part
    errno = 0;
    if (lk(fd, F_SETLK, F_WRLCK, 60, 10) != -1) return 2;     // still locked part
    return 0;
}

static int child_can_lock_all(void) {
    int fd = open(path, O_RDWR);
    return lk(fd, F_SETLK, F_WRLCK, 0, 0) == 0 ? 0 : 1;
}

static int child_waits(void) {
    int fd = open(path, O_RDWR);
    long t0 = now_ms();
    if (lk(fd, F_SETLKW, F_WRLCK, 0, 0) != 0) return 1;
    return now_ms() - t0 >= 50 ? 0 : 2;
}

static int child_flock_nb(void) {
    int fd = open(path, O_RDONLY);
    errno = 0;
    return flock(fd, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK ? 0 : 1;
}

static int child_lock_and_exit(void) {
    int fd = open(path, O_RDWR);
    return lk(fd, F_SETLK, F_WRLCK, 0, 0) == 0 ? 0 : 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(path, sizeof path, "/tmp/locks.%d.%ld", getpid(), (long)time(NULL));
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    write(fd, "0123456789", 10);

    // flock
    int a = open(path, O_RDWR), b = open(path, O_RDWR);
    check(flock(a, LOCK_EX) == 0, "flock LOCK_EX");
    errno = 0;
    check(flock(b, LOCK_EX | LOCK_NB) == -1 && errno == EWOULDBLOCK, "another open: LOCK_EX | LOCK_NB fails (EWOULDBLOCK)");
    errno = 0;
    check(flock(b, LOCK_SH | LOCK_NB) == -1 && errno == EWOULDBLOCK, "another open: LOCK_SH | LOCK_NB fails too");
    int d = dup(a);
    check(flock(d, LOCK_EX | LOCK_NB) == 0, "a duplicate shares the lock");
    check(in_child(child_flock_nb) == 0, "another process's open is refused");
    close(a);
    errno = 0;
    check(flock(b, LOCK_EX | LOCK_NB) == -1, "the lock stays while a duplicate is open");
    close(d);
    check(flock(b, LOCK_EX | LOCK_NB) == 0, "closing the last duplicate releases it");
    check(flock(b, LOCK_SH) == 0, "conversion to shared");
    int c2 = open(path, O_RDONLY);
    check(flock(c2, LOCK_SH | LOCK_NB) == 0, "two shared locks together");
    flock(c2, LOCK_UN);
    // A blocking flock waits for the holder
    pid_t h = fork();
    if (h == 0) {
        int x = open(path, O_RDWR);
        flock(x, LOCK_EX);
        usleep(150000);
        _exit(0);
    }
    flock(b, LOCK_UN);
    usleep(50000);
    long t0 = now_ms();
    int r = flock(b, LOCK_EX);
    check(r == 0 && now_ms() - t0 >= 50, "blocking flock waits for the holder to go");
    waitpid(h, NULL, 0);
    flock(b, LOCK_UN);

    // POSIX record locks
    check(lk(fd, F_SETLK, F_WRLCK, 0, 100) == 0, "F_SETLK write lock on [0, 100)");
    check(in_child(child_read_50_60) == 0, "another process: conflict (EAGAIN), F_GETLK names us and the range, other ranges free");
    check(lk(fd, F_SETLK, F_RDLCK, 0, 100) == 0, "our own lock changes type without conflict");
    lk(fd, F_SETLK, F_WRLCK, 0, 100);
    check(lk(fd, F_SETLK, F_UNLCK, 0, 50) == 0 && in_child(child_after_split) == 0, "unlocking part splits the range");
    // Any close of the file drops the process's locks
    int other = open(path, O_RDONLY);
    close(other);
    check(in_child(child_can_lock_all) == 0, "closing any descriptor of the file releases our POSIX locks");
    // F_SETLKW waits
    lk(fd, F_SETLK, F_WRLCK, 0, 0);
    h = fork();
    if (h == 0) _exit(child_waits());
    usleep(100000);
    lk(fd, F_SETLK, F_UNLCK, 0, 0);
    int st;
    waitpid(h, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "F_SETLKW waits for the unlock");
    // A lock goes with its process
    check(in_child(child_lock_and_exit) == 0 && lk(fd, F_SETLK, F_WRLCK, 0, 0) == 0, "an exited process's locks are gone");
    lk(fd, F_SETLK, F_UNLCK, 0, 0);
    int ro = open(path, O_RDONLY);
    errno = 0;
    check(lk(ro, F_SETLK, F_WRLCK, 0, 1) == -1 && errno == EBADF, "write lock on a read-only descriptor: EBADF");

    // OFD locks
    int o1 = open(path, O_RDWR), o2 = open(path, O_RDWR);
    check(lk(o1, F_OFD_SETLK, F_WRLCK, 0, 10) == 0, "OFD write lock");
    errno = 0;
    check(lk(o2, F_OFD_SETLK, F_WRLCK, 0, 10) == -1 && errno == EAGAIN, "another description in the same process: EAGAIN");
    errno = 0;
    check(lk(fd, F_SETLK, F_WRLCK, 5, 1) == -1 && errno == EAGAIN, "a POSIX lock conflicts with it");
    struct flock g = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1, .l_pid = 0};
    fcntl(o2, F_OFD_GETLK, &g);
    check(g.l_type == F_WRLCK && g.l_pid == -1, "F_OFD_GETLK reports the holder with pid -1");
    struct flock bad = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1, .l_pid = 1};
    errno = 0;
    check(fcntl(o2, F_OFD_SETLK, &bad) == -1 && errno == EINVAL, "OFD lock with l_pid set: EINVAL");
    // flock and record locks are independent
    check(flock(o2, LOCK_EX | LOCK_NB) == 0, "flock is independent of record locks");

    // /proc/locks
    FILE *pl = fopen("/proc/locks", "r");
    char line[256];
    int ofd_seen = 0, flock_seen = 0;
    while (pl && fgets(line, sizeof line, pl)) {
        ofd_seen |= strstr(line, "OFDLCK") != NULL;
        flock_seen |= strstr(line, "FLOCK") != NULL;
    }
    if (pl) fclose(pl);
    check(ofd_seen && flock_seen, "/proc/locks lists them");
    unlink(path);
    printf(fails ? "LOCKS TEST FAILED (%d)\n" : "LOCKS TEST PASSED\n", fails);
    return fails != 0;
}
