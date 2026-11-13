// fsync, fdatasync, syncfs and sync check their descriptor as Linux does:
//   - a descriptor that is not open: EBADF (fsync, fdatasync, syncfs);
//   - a pipe, socket, eventfd or terminal (no fsync method on Linux): EINVAL;
//   - a regular file, a directory or a memfd: 0;
//   - syncfs works on any open descriptor; sync() always succeeds.
// Hydra used to answer 0 to all of them, so a program could not tell that it synced
// nothing.
// Build: gcc -O1 -w -o fsync fsync_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

// 0, or -errno
static int rc(int r) {
    return r == 0 ? 0 : -errno;
}

static void expect(int got, int want, const char *what) {
    char line[160];
    snprintf(line, sizeof line, "%s: %s (got %s)", what, want ? strerror(-want) : "0", got ? strerror(-got) : "0");
    check(got == want, line);
}

int main(void) {
    int file = open("/tmp/fsync_test.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
    write(file, "data\n", 5);
    expect(rc(fsync(file)), 0, "fsync of a regular file");
    expect(rc(fdatasync(file)), 0, "fdatasync of a regular file");
    expect(rc(syncfs(file)), 0, "syncfs of a regular file");
    int dir = open("/tmp", O_RDONLY | O_DIRECTORY);
    expect(rc(fsync(dir)), 0, "fsync of a directory");
    int mem = memfd_create("fsync", 0);
    expect(rc(fsync(mem)), 0, "fsync of a memfd");

    int closed = dup(file);
    close(closed);
    expect(rc(fsync(closed)), -EBADF, "fsync of a closed descriptor");
    expect(rc(fdatasync(-1)), -EBADF, "fdatasync(-1)");
    expect(rc(syncfs(closed)), -EBADF, "syncfs of a closed descriptor");

    int p[2];
    pipe(p);
    expect(rc(fsync(p[0])), -EINVAL, "fsync of a pipe");
    expect(rc(fdatasync(p[1])), -EINVAL, "fdatasync of a pipe");
    expect(rc(syncfs(p[0])), 0, "syncfs of a pipe (any open descriptor)");
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    expect(rc(fsync(sv[0])), -EINVAL, "fsync of a socket");
    int ev = eventfd(0, 0);
    expect(rc(fsync(ev)), -EINVAL, "fsync of an eventfd");
    if (isatty(0))
        expect(rc(fsync(0)), -EINVAL, "fsync of a terminal");

    sync(); // void: always succeeds
    check(1, "sync returns");

    unlink("/tmp/fsync_test.tmp");
    printf(fails ? "FSYNC TEST FAILED (%d)\n" : "FSYNC TEST PASSED\n", fails);
    return fails != 0;
}
