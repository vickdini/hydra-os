// Unix sockets in flight in each other's queues must not live forever (finding 35 of
// tests/host/TEST_REPORT.md). Hydra refuses the send that would close such a cycle
// (ETOOMANYREFS) instead of collecting it as Linux's unix_gc does; either way the
// sockets go away once closed. Counts live sockets in /proc/net/unix.
// Build: gcc -static-pie -O1 -w -o unixgc unixgc_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

// Sends descriptor `fd` over socket `via`; returns 0 or -errno
static int send_fd(int via, int fd) {
    char byte = 'x';
    struct iovec iov = { &byte, 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
    struct msghdr m = { 0 };
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(via, &m, 0) == 1 ? 0 : -errno;
}

// Receives one descriptor from `via`, or -1
static int recv_fd(int via) {
    char byte;
    struct iovec iov = { &byte, 1 };
    union { char buf[CMSG_SPACE(sizeof(int))]; struct cmsghdr align; } u;
    struct msghdr m = { 0 };
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = sizeof u.buf;
    if (recvmsg(via, &m, 0) != 1) return -1;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    if (!c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(c), sizeof(int));
    return fd;
}

static int live_sockets(void) {
    FILE *f = fopen("/proc/net/unix", "r");
    if (!f) return -1;
    int n = -1; // header line
    char line[512];
    while (fgets(line, sizeof line, f)) n++;
    fclose(f);
    return n;
}

int main(void) {
    // Passing a socket still works when nothing is in flight in it
    int sv[2], other[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    socketpair(AF_UNIX, SOCK_STREAM, 0, other);
    check(send_fd(sv[0], other[0]) == 0, "a socket with an empty queue can be sent");
    int got = recv_fd(sv[1]);
    check(got >= 0 && write(got, "hi", 2) == 2, "the received socket works");
    char buf[2];
    check(read(other[1], buf, 2) == 2 && memcmp(buf, "hi", 2) == 0, "its peer reads what was written");
    close(got); close(other[0]); close(other[1]); close(sv[0]); close(sv[1]);

    // The crossed case: a into b's queue, then b into a's queue; close both. Repeated, it
    // used to keep every pair alive.
    int before = live_sockets();
    // The count must see sockets at all, or "none left" below proves nothing
    int probe[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, probe);
    int open_now = live_sockets();
    check(open_now >= before + 2, "/proc/net/unix lists an open pair");
    close(probe[0]);
    close(probe[1]);
    int refused = 0;
    for (int i = 0; i < 2000; i++) {
        int p[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p)) break;
        send_fd(p[0], p[0]);              // p[0] waits in p[1]'s queue
        if (send_fd(p[1], p[1]) == -ETOOMANYREFS) refused++; // p[1] into p[0]'s queue
        close(p[0]);
        close(p[1]);
    }
    int after = live_sockets();
    printf("     live sockets before %d, after 2000 crossed pairs %d (%d sends refused)\n", before, after, refused);
    check(after >= 0 && after <= before + 4, "the crossed pairs are gone once closed");

    printf(fails ? "UNIXGC TEST FAILED (%d)\n" : "UNIXGC TEST PASSED\n", fails);
    return fails != 0;
}
