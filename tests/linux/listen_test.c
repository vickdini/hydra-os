// TCP server sockets over loopback: bind (address checks, privileged ports, EADDRINUSE,
// SO_REUSEADDR/SO_REUSEPORT), listen, accept/accept4 (peer address, flags, nonblocking,
// poll and epoll readiness), data both ways, a 1 MiB transfer, ECONNREFUSED, a closed
// listener resetting unaccepted connections, UDP over loopback. Run unprivileged.
// Build: gcc -O1 -w -o listen listen_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static struct sockaddr_in addr(const char *ip, int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, ip, &a.sin_addr);
    return a;
}

static int port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &l);
    return ntohs(a.sin_port);
}

static int server(const char *ip, int port, int backlog) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = addr(ip, port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, backlog)) {
        close(s);
        return -1;
    }
    return s;
}

static int dial(int port) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = addr("127.0.0.1", port);
    if (connect(c, (struct sockaddr *)&a, sizeof a)) {
        int e = errno;
        close(c);
        errno = e;
        return -1;
    }
    return c;
}

static ssize_t read_full(int fd, char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return got ? (ssize_t)got : r;
        got += r;
    }
    return got;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int s = server("127.0.0.1", 0, 5);
    check(s >= 0, "bind 127.0.0.1:0 and listen");
    int port = port_of(s);
    check(port > 0, "getsockname gives the chosen port");
    int v = 0;
    socklen_t vl = sizeof v;
    check(getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &v, &vl) == 0 && v == 1, "SO_ACCEPTCONN");

    // Nonblocking accept with nothing waiting
    fcntl(s, F_SETFL, O_NONBLOCK);
    errno = 0;
    check(accept(s, NULL, NULL) == -1 && errno == EAGAIN, "nonblocking accept with none waiting: EAGAIN");
    fcntl(s, F_SETFL, 0);

    // A client in a child: sends hello, expects world, then closes
    pid_t c = fork();
    if (c == 0) {
        int fd = dial(port);
        if (fd < 0) _exit(1);
        write(fd, "hello", 5);
        char b[8] = "";
        if (read_full(fd, b, 5) != 5 || memcmp(b, "world", 5)) _exit(2);
        close(fd);
        _exit(0);
    }
    struct pollfd pf = {.fd = s, .events = POLLIN};
    check(poll(&pf, 1, 3000) == 1 && (pf.revents & POLLIN), "poll: the listener becomes readable");
    struct sockaddr_in peer;
    socklen_t pl = sizeof peer;
    int a = accept4(s, (struct sockaddr *)&peer, &pl, SOCK_CLOEXEC);
    check(a >= 0, "accept4");
    char ip[32];
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
    check(!strcmp(ip, "127.0.0.1") && ntohs(peer.sin_port) != port && pl == sizeof peer, "accept reports the peer");
    check(port_of(a) == port, "the accepted socket's local port is the listener's");
    check(fcntl(a, F_GETFD) & FD_CLOEXEC, "SOCK_CLOEXEC");
    char b[16] = "";
    check(read_full(a, b, 5) == 5 && !memcmp(b, "hello", 5), "data client to server");
    check(write(a, "world", 5) == 5, "data server to client");
    check(read(a, b, sizeof b) == 0, "EOF when the client closes");
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the client got its answer");
    close(a);

    // 1 MiB through loopback
    c = fork();
    if (c == 0) {
        int fd = dial(port);
        char *buf = malloc(1 << 20);
        for (int i = 0; i < (1 << 20); i++) buf[i] = (char)(i * 7 + i / 4096);
        size_t off = 0;
        while (off < (1 << 20)) {
            ssize_t w = write(fd, buf + off, (1 << 20) - off);
            if (w <= 0) _exit(1);
            off += w;
        }
        close(fd);
        _exit(0);
    }
    a = accept(s, NULL, NULL);
    char *buf = malloc(1 << 20);
    ssize_t n = read_full(a, buf, 1 << 20);
    int good = n == (1 << 20);
    for (int i = 0; good && i < (1 << 20); i++) good = buf[i] == (char)(i * 7 + i / 4096);
    check(good, "1 MiB arrives intact");
    waitpid(c, &st, 0);
    close(a);

    // epoll on a listener, accept4 SOCK_NONBLOCK
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = s};
    epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
    int cl = dial(port);
    struct epoll_event out;
    check(epoll_wait(ep, &out, 1, 3000) == 1 && out.data.fd == s, "epoll reports a connection to accept");
    a = accept4(s, NULL, NULL, SOCK_NONBLOCK);
    check(a >= 0 && (fcntl(a, F_GETFL) & O_NONBLOCK), "accept4 SOCK_NONBLOCK");
    errno = 0;
    check(read(a, b, 1) == -1 && errno == EAGAIN, "nonblocking read on the accepted socket: EAGAIN");
    close(a);
    close(cl);
    errno = 0;
    check(accept4(s, NULL, NULL, 0x1234) == -1 && errno == EINVAL, "accept4 with unknown flags: EINVAL");

    // bind rules
    int d = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in same = addr("127.0.0.1", port);
    errno = 0;
    check(bind(d, (struct sockaddr *)&same, sizeof same) == -1 && errno == EADDRINUSE, "binding a listening port again: EADDRINUSE");
    close(d);
    d = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in far = addr("10.255.255.1", 0);
    errno = 0;
    check(bind(d, (struct sockaddr *)&far, sizeof far) == -1 && errno == EADDRNOTAVAIL, "binding an address not ours: EADDRNOTAVAIL");
    close(d);
    if (geteuid() != 0) {
        d = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in low = addr("127.0.0.1", 80);
        errno = 0;
        check(bind(d, (struct sockaddr *)&low, sizeof low) == -1 && errno == EACCES, "port 80 unprivileged: EACCES");
        close(d);
    }
    int one = 1;
    int r1 = socket(AF_INET, SOCK_STREAM, 0), r2 = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(r1, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    setsockopt(r2, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in any = addr("127.0.0.1", 0);
    bind(r1, (struct sockaddr *)&any, sizeof any);
    struct sockaddr_in rp = addr("127.0.0.1", port_of(r1));
    check(bind(r2, (struct sockaddr *)&rp, sizeof rp) == 0 && listen(r1, 1) == 0 && listen(r2, 1) == 0, "SO_REUSEPORT: two listeners on one port");
    close(r1);
    close(r2);
    // SO_REUSEADDR (on both servers) lets a new one take the port while old connections remain
    int s2 = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in lo0 = addr("127.0.0.1", 0);
    bind(s2, (struct sockaddr *)&lo0, sizeof lo0);
    listen(s2, 1);
    int p2 = port_of(s2);
    int k = dial(p2);
    int ka = accept(s2, NULL, NULL);
    close(s2);
    d = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in again = addr("127.0.0.1", p2);
    errno = 0;
    check(bind(d, (struct sockaddr *)&again, sizeof again) == -1 && errno == EADDRINUSE, "a port with live connections: EADDRINUSE");
    setsockopt(d, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    check(bind(d, (struct sockaddr *)&again, sizeof again) == 0 && listen(d, 1) == 0, "with SO_REUSEADDR it binds");
    close(d);
    close(k);
    close(ka);

    // Refused, and reset by a closed listener
    int dead = server("127.0.0.1", 0, 1);
    int dp = port_of(dead);
    close(dead);
    errno = 0;
    check(dial(dp) == -1 && errno == ECONNREFUSED, "no listener: ECONNREFUSED");
    int s3 = server("127.0.0.1", 0, 4);
    int c3 = dial(port_of(s3));
    usleep(100000);
    close(s3);  // the connection was never accepted
    usleep(100000);
    errno = 0;
    n = read(c3, b, 1);
    check(n == -1 && errno == ECONNRESET, "closing the listener resets connections not accepted");
    close(c3);

    // listen on UDP, accept on a socket not listening
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    errno = 0;
    check(listen(u, 1) == -1 && errno == EOPNOTSUPP, "listen on UDP: EOPNOTSUPP");
    int nl = socket(AF_INET, SOCK_STREAM, 0);
    errno = 0;
    check(accept(nl, NULL, NULL) == -1 && errno == EINVAL, "accept without listen: EINVAL");

    // UDP over loopback
    int u2 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ul = addr("127.0.0.1", 0);
    bind(u2, (struct sockaddr *)&ul, sizeof ul);
    struct sockaddr_in to = addr("127.0.0.1", port_of(u2));
    sendto(u, "ping", 4, 0, (struct sockaddr *)&to, sizeof to);
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    struct pollfd up = {.fd = u2, .events = POLLIN};
    poll(&up, 1, 3000);
    n = recvfrom(u2, b, sizeof b, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
    inet_ntop(AF_INET, &from.sin_addr, ip, sizeof ip);
    check(n == 4 && !memcmp(b, "ping", 4) && !strcmp(ip, "127.0.0.1") && ntohs(from.sin_port) == port_of(u), "UDP over loopback, with the source address");

    close(s);
    printf(fails ? "LISTEN TEST FAILED (%d)\n" : "LISTEN TEST PASSED\n", fails);
    return fails != 0;
}
