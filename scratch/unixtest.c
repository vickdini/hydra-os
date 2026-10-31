// Hydra AF_UNIX socket conformance test.
// Build (WSL): gcc -static-pie -O1 -o esp/bin/unixtest.elf scratch/unixtest.c
// Run in Hydra: linux run unixtest.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *name, int ok) {
    printf("[unixtest] %-52s %s\n", name, ok ? "PASS" : "FAIL");
    fflush(stdout);
    if (!ok) failures++;
}

static int send_fd(int sock, int fd, const char *data, size_t len) {
    char ctrl[CMSG_SPACE(sizeof(int))];
    memset(ctrl, 0, sizeof ctrl);
    struct iovec iov = {(void *)data, len};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctrl, .msg_controllen = sizeof ctrl};
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    return sendmsg(sock, &m, 0);
}

// Receives into buf; returns bytes and stores a passed descriptor (or -1) in *fd.
static int recv_fd(int sock, char *buf, size_t cap, int *fd, int flags) {
    char ctrl[CMSG_SPACE(sizeof(int) * 4)];
    struct iovec iov = {buf, cap};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctrl, .msg_controllen = sizeof ctrl};
    int n = recvmsg(sock, &m, flags);
    *fd = -1;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) memcpy(fd, CMSG_DATA(c), sizeof(int));
    return n;
}

static void pair_tests(void) {
    int sv[2];
    check("socketpair(SOCK_STREAM)", socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0);
    char buf[64] = {0};
    check("stream write/read", write(sv[0], "hello", 5) == 5 && read(sv[1], buf, sizeof buf) == 5 && memcmp(buf, "hello", 5) == 0);

    // Stream bytes from separate writes merge in one read
    write(sv[0], "ab", 2);
    write(sv[0], "cd", 2);
    memset(buf, 0, sizeof buf);
    check("stream reads merge writes", read(sv[1], buf, sizeof buf) == 4 && strcmp(buf, "abcd") == 0);

    // MSG_PEEK leaves the data
    write(sv[0], "xyz", 3);
    check("MSG_PEEK", recv(sv[1], buf, 3, MSG_PEEK) == 3 && recv(sv[1], buf, 3, 0) == 3 && memcmp(buf, "xyz", 3) == 0);

    // Non-blocking empty read
    check("MSG_DONTWAIT on empty -> EAGAIN", recv(sv[1], buf, 3, MSG_DONTWAIT) == -1 && errno == EAGAIN);

    // poll readiness
    struct pollfd p = {sv[1], POLLIN, 0};
    check("poll: not readable when empty", poll(&p, 1, 0) == 0);
    write(sv[0], "q", 1);
    check("poll: readable after write", poll(&p, 1, 1000) == 1 && (p.revents & POLLIN));
    read(sv[1], buf, 1);

    // Descriptor passing; data after the message is not merged with it
    int pfd[2];
    pipe(pfd);
    write(pfd[1], "via-pipe", 8);
    check("sendmsg SCM_RIGHTS", send_fd(sv[0], pfd[0], "F", 1) == 1);
    write(sv[0], "tail", 4);
    int got = -1;
    int n = recv_fd(sv[1], buf, sizeof buf, &got, 0);
    check("recvmsg delivers the descriptor with its byte", n == 1 && buf[0] == 'F' && got >= 0);
    memset(buf, 0, sizeof buf);
    check("passed descriptor refers to the same pipe", got >= 0 && read(got, buf, 8) == 8 && memcmp(buf, "via-pipe", 8) == 0);
    memset(buf, 0, sizeof buf);
    check("following data arrives separately", read(sv[1], buf, sizeof buf) == 4 && memcmp(buf, "tail", 4) == 0);
    close(got);
    close(pfd[0]);
    close(pfd[1]);

    // Credentials
    struct ucred cr;
    socklen_t len = sizeof cr;
    check("SO_PEERCRED on a pair is ourselves",
          getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &cr, &len) == 0 && cr.pid == getpid() && cr.uid == geteuid());
    int one = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    write(sv[0], "c", 1);
    char ctrl[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec iov = {buf, 1};
    struct msghdr m = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctrl, .msg_controllen = sizeof ctrl};
    int okc = 0;
    if (recvmsg(sv[1], &m, 0) == 1)
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
            if (c->cmsg_type == SCM_CREDENTIALS) {
                struct ucred u;
                memcpy(&u, CMSG_DATA(c), sizeof u);
                okc = u.pid == getpid();
            }
    check("SO_PASSCRED adds SCM_CREDENTIALS", okc);

    // EOF and EPIPE
    close(sv[0]);
    check("read after peer close -> EOF", read(sv[1], buf, sizeof buf) == 0);
    check("send after peer close -> EPIPE (MSG_NOSIGNAL)", send(sv[1], "x", 1, MSG_NOSIGNAL) == -1 && errno == EPIPE);
    close(sv[1]);

    // SEQPACKET keeps boundaries and truncates
    check("socketpair(SOCK_SEQPACKET)", socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) == 0);
    write(sv[0], "one", 3);
    write(sv[0], "two!", 4);
    n = read(sv[1], buf, sizeof buf);
    check("seqpacket keeps message boundaries", n == 3 && memcmp(buf, "one", 3) == 0);
    struct iovec iov2 = {buf, 2};
    struct msghdr m2 = {.msg_iov = &iov2, .msg_iovlen = 1};
    n = recvmsg(sv[1], &m2, 0);
    check("seqpacket short read sets MSG_TRUNC", n == 2 && (m2.msg_flags & MSG_TRUNC));
    close(sv[0]);
    close(sv[1]);
}

static void server_tests(const struct sockaddr_un *addr, socklen_t alen, const char *what) {
    char name[96];
    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    snprintf(name, sizeof name, "bind + listen (%s)", what);
    check(name, srv >= 0 && bind(srv, (const struct sockaddr *)addr, alen) == 0 && listen(srv, 8) == 0);
    int again = socket(AF_UNIX, SOCK_STREAM, 0);
    snprintf(name, sizeof name, "second bind -> EADDRINUSE (%s)", what);
    check(name, bind(again, (const struct sockaddr *)addr, alen) == -1 && errno == EADDRINUSE);
    close(again);

    pid_t c = fork();
    if (c == 0) {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(s, (const struct sockaddr *)addr, alen) != 0) _exit(10);
        if (write(s, "ping", 4) != 4) _exit(11);
        char b[8] = {0};
        if (read(s, b, 4) != 4 || memcmp(b, "pong", 4) != 0) _exit(12);
        _exit(0);
    }
    struct sockaddr_un peer;
    socklen_t plen = sizeof peer;
    int conn = accept4(srv, (struct sockaddr *)&peer, &plen, SOCK_CLOEXEC);
    snprintf(name, sizeof name, "accept (%s)", what);
    check(name, conn >= 0);
    struct ucred cr;
    socklen_t len = sizeof cr;
    snprintf(name, sizeof name, "SO_PEERCRED is the client (%s)", what);
    check(name, getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &cr, &len) == 0 && cr.pid == c);
    char b[8] = {0};
    snprintf(name, sizeof name, "client/server exchange (%s)", what);
    int ok = read(conn, b, 4) == 4 && memcmp(b, "ping", 4) == 0 && write(conn, "pong", 4) == 4;
    int st = 0;
    waitpid(c, &st, 0);
    check(name, ok && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    struct sockaddr_un local;
    socklen_t llen = sizeof local;
    snprintf(name, sizeof name, "getsockname returns the bound name (%s)", what);
    check(name, getsockname(srv, (struct sockaddr *)&local, &llen) == 0 && llen == alen &&
                    memcmp(local.sun_path, addr->sun_path, alen - offsetof(struct sockaddr_un, sun_path)) == 0);

    // Non-blocking accept with nothing pending
    fcntl(srv, F_SETFL, O_NONBLOCK);
    snprintf(name, sizeof name, "non-blocking accept -> EAGAIN (%s)", what);
    check(name, accept(srv, NULL, NULL) == -1 && errno == EAGAIN);
    close(conn);
    close(srv);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    pair_tests();

    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, "/tmp/unixtest.sock");
    unlink(a.sun_path);
    server_tests(&a, offsetof(struct sockaddr_un, sun_path) + strlen(a.sun_path) + 1, "path");
    struct stat st;
    check("bound path is a socket node", stat(a.sun_path, &st) == 0 && S_ISSOCK(st.st_mode));
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    check("connect after the listener closed -> ECONNREFUSED",
          connect(s, (struct sockaddr *)&a, sizeof a) == -1 && errno == ECONNREFUSED);
    close(s);
    unlink(a.sun_path);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    check("connect to a missing path -> ENOENT", connect(s, (struct sockaddr *)&a, sizeof a) == -1 && errno == ENOENT);
    close(s);

    struct sockaddr_un ab = {.sun_family = AF_UNIX};
    memcpy(ab.sun_path, "\0hydra-unixtest", 15);
    server_tests(&ab, offsetof(struct sockaddr_un, sun_path) + 15, "abstract");

    if (failures == 0)
        printf("[unixtest] ALL PASSED (0 failures)\n");
    else
        printf("[unixtest] %d FAILURES\n", failures);
    return failures != 0;
}
