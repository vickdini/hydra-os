// AF_INET socket options: kept and read back as Linux reports them (booleans, doubled
// buffer sizes, IP_TTL defaults, linger, TCP keepalive ranges, congestion control),
// errors (ENOPROTOOPT, EINVAL, EDOM, EPERM), optlen handling, and SO_RCVTIMEO/SO_SNDTIMEO
// timing out UDP and TCP receives and a TCP connect. Needs network access for the TCP part.
// Build: gcc -O1 -w -o sockopt sockopt_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int geti(int fd, int level, int name) {
    int v = -12345;
    socklen_t l = sizeof v;
    if (getsockopt(fd, level, name, &v, &l) != 0) return -99999;
    return v;
}

static int seti(int fd, int level, int name, int v) { return setsockopt(fd, level, name, &v, sizeof v); }

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void set_timeo(int fd, int name, long ms) {
    struct timeval tv = {ms / 1000, (ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, name, &tv, sizeof tv);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int t = socket(AF_INET, SOCK_STREAM, 0), u = socket(AF_INET, SOCK_DGRAM, 0);

    // Booleans
    check(geti(t, SOL_SOCKET, SO_REUSEADDR) == 0, "SO_REUSEADDR defaults to 0");
    check(seti(t, SOL_SOCKET, SO_REUSEADDR, 5) == 0 && geti(t, SOL_SOCKET, SO_REUSEADDR) == 1, "SO_REUSEADDR 5 reads back as 1");
    check(seti(t, SOL_SOCKET, SO_KEEPALIVE, 1) == 0 && geti(t, SOL_SOCKET, SO_KEEPALIVE) == 1, "SO_KEEPALIVE");
    check(seti(t, IPPROTO_TCP, TCP_NODELAY, 1) == 0 && geti(t, IPPROTO_TCP, TCP_NODELAY) == 1, "TCP_NODELAY");
    check(seti(t, IPPROTO_TCP, TCP_NODELAY, 0) == 0 && geti(t, IPPROTO_TCP, TCP_NODELAY) == 0, "TCP_NODELAY off again");
    check(seti(u, SOL_SOCKET, SO_BROADCAST, 1) == 0 && geti(u, SOL_SOCKET, SO_BROADCAST) == 1, "SO_BROADCAST");

    // Buffer sizes: doubled, clamped to the maximum, at least the minimum
    check(seti(u, SOL_SOCKET, SO_RCVBUF, 65536) == 0 && geti(u, SOL_SOCKET, SO_RCVBUF) == 131072, "SO_RCVBUF is doubled");
    check(seti(u, SOL_SOCKET, SO_SNDBUF, 1) == 0 && geti(u, SOL_SOCKET, SO_SNDBUF) == 4608, "SO_SNDBUF has a minimum");
    seti(u, SOL_SOCKET, SO_RCVBUF, 1 << 30);
    int big = geti(u, SOL_SOCKET, SO_RCVBUF);
    check(big > 0 && big < (1 << 30), "SO_RCVBUF is capped");

    // IP options
    check(geti(t, IPPROTO_IP, IP_TTL) == 64, "IP_TTL defaults to 64");
    check(seti(t, IPPROTO_IP, IP_TTL, 10) == 0 && geti(t, IPPROTO_IP, IP_TTL) == 10, "IP_TTL is kept");
    check(seti(t, IPPROTO_IP, IP_TTL, -1) == 0 && geti(t, IPPROTO_IP, IP_TTL) == 64, "IP_TTL -1 restores the default");
    errno = 0;
    check(seti(t, IPPROTO_IP, IP_TTL, 300) == -1 && errno == EINVAL, "IP_TTL 300: EINVAL");
    check(seti(u, IPPROTO_IP, IP_TOS, 0x10) == 0 && geti(u, IPPROTO_IP, IP_TOS) == 0x10, "IP_TOS");
    errno = 0;
    check(geti(t, IPPROTO_IP, IP_MTU) == -99999 && errno == ENOTCONN, "IP_MTU unconnected: ENOTCONN");

    // TCP options
    check(geti(t, IPPROTO_TCP, TCP_KEEPIDLE) == 7200 && geti(t, IPPROTO_TCP, TCP_KEEPINTVL) == 75 && geti(t, IPPROTO_TCP, TCP_KEEPCNT) == 9, "keepalive defaults");
    check(seti(t, IPPROTO_TCP, TCP_KEEPIDLE, 30) == 0 && geti(t, IPPROTO_TCP, TCP_KEEPIDLE) == 30, "TCP_KEEPIDLE is kept");
    errno = 0;
    check(seti(t, IPPROTO_TCP, TCP_KEEPCNT, 200) == -1 && errno == EINVAL, "TCP_KEEPCNT 200: EINVAL");
    char cc[16] = "";
    socklen_t cl = sizeof cc;
    check(getsockopt(t, IPPROTO_TCP, TCP_CONGESTION, cc, &cl) == 0 && cc[0], "TCP_CONGESTION has a name");
    check(setsockopt(t, IPPROTO_TCP, TCP_CONGESTION, "reno", 4) == 0, "TCP_CONGESTION reno");
    errno = 0;
    check(setsockopt(t, IPPROTO_TCP, TCP_CONGESTION, "nonesuch", 8) == -1 && errno == ENOENT, "unknown congestion control: ENOENT");
    errno = 0;
    check(seti(u, IPPROTO_TCP, TCP_NODELAY, 1) == -1 && errno == ENOPROTOOPT, "TCP option on UDP: ENOPROTOOPT");

    // Linger
    struct linger lg = {7, 3}, lo = {0, 0};
    socklen_t ll = sizeof lo;
    check(setsockopt(t, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0 && getsockopt(t, SOL_SOCKET, SO_LINGER, &lo, &ll) == 0 && lo.l_onoff == 1 && lo.l_linger == 3, "SO_LINGER");
    errno = 0;
    check(setsockopt(t, SOL_SOCKET, SO_LINGER, &lg, 4) == -1 && errno == EINVAL, "SO_LINGER too short: EINVAL");

    // Errors and read-only options
    errno = 0;
    check(seti(t, SOL_SOCKET, 9999, 1) == -1 && errno == ENOPROTOOPT, "unknown option: ENOPROTOOPT");
    errno = 0;
    check(seti(t, 9999, 1, 1) == -1 && errno == ENOPROTOOPT, "unknown level: ENOPROTOOPT");
    errno = 0;
    check(seti(t, SOL_SOCKET, SO_TYPE, 2) == -1 && errno == ENOPROTOOPT, "SO_TYPE is read-only");
    check(geti(t, SOL_SOCKET, SO_TYPE) == SOCK_STREAM && geti(u, SOL_SOCKET, SO_PROTOCOL) == IPPROTO_UDP && geti(t, SOL_SOCKET, SO_DOMAIN) == AF_INET, "SO_TYPE, SO_PROTOCOL, SO_DOMAIN");
    errno = 0;
    check(seti(t, SOL_SOCKET, SO_PRIORITY, 7) == -1 && errno == EPERM, "SO_PRIORITY 7 unprivileged: EPERM");
    check(seti(t, SOL_SOCKET, SO_PRIORITY, 4) == 0 && geti(t, SOL_SOCKET, SO_PRIORITY) == 4, "SO_PRIORITY 4");
    struct timeval bad = {1, 2000000};
    errno = 0;
    check(setsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &bad, sizeof bad) == -1 && errno == EDOM, "SO_RCVTIMEO with 2e6 usec: EDOM");
    errno = 0;
    check(setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &lg, 2) == -1 && errno == EINVAL, "short optlen: EINVAL");
    unsigned char one = 0xaa;
    socklen_t ol = 1;
    check(getsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, &ol) == 0 && ol == 1 && one == 1, "getsockopt with optlen 1 copies 1 byte");

    // Timeouts
    struct timeval tv = {0, 0};
    socklen_t tl = sizeof tv;
    set_timeo(u, SO_RCVTIMEO, 250);
    check(getsockopt(u, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl) == 0 && tv.tv_sec == 0 && tv.tv_usec == 250000, "SO_RCVTIMEO reads back");
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_ANY), .sin_port = 0};
    bind(u, (struct sockaddr *)&a, sizeof a);
    char buf[64];
    long t0 = now_ms();
    errno = 0;
    ssize_t r = recv(u, buf, sizeof buf, 0);
    long dt = now_ms() - t0;
    check(r == -1 && errno == EAGAIN && dt >= 200 && dt < 2000, "UDP recv times out with EAGAIN");

    // TCP: a connection that sends nothing
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *ai = NULL;
    if (getaddrinfo("example.com", "80", &hints, &ai) == 0) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(c, ai->ai_addr, ai->ai_addrlen) == 0) {
            check(geti(c, IPPROTO_IP, IP_MTU) > 0, "IP_MTU connected");
            struct tcp_info ti;
            socklen_t il = sizeof ti;
            check(getsockopt(c, IPPROTO_TCP, TCP_INFO, &ti, &il) == 0 && ti.tcpi_state == TCP_ESTABLISHED, "TCP_INFO: established");
            set_timeo(c, SO_RCVTIMEO, 300);
            t0 = now_ms();
            errno = 0;
            r = read(c, buf, sizeof buf);
            dt = now_ms() - t0;
            check(r == -1 && errno == EAGAIN && dt >= 250 && dt < 3000, "TCP read times out with EAGAIN");
        } else {
            printf("skip TCP read timeout (connect: %s)\n", strerror(errno));
        }
        close(c);
        freeaddrinfo(ai);
    } else {
        printf("skip TCP read timeout (no DNS)\n");
    }
    // Connect to an address that never answers
    int b = socket(AF_INET, SOCK_STREAM, 0);
    set_timeo(b, SO_SNDTIMEO, 300);
    struct sockaddr_in blk = {.sin_family = AF_INET, .sin_port = htons(81)};
    inet_pton(AF_INET, "10.255.255.1", &blk.sin_addr);
    t0 = now_ms();
    errno = 0;
    r = connect(b, (struct sockaddr *)&blk, sizeof blk);
    dt = now_ms() - t0;
    if (r == -1 && (errno == ENETUNREACH || errno == EHOSTUNREACH))
        printf("skip connect timeout (%s)\n", strerror(errno));
    else
        check(r == -1 && errno == EINPROGRESS && dt >= 250 && dt < 3000, "connect times out with EINPROGRESS");

    printf(fails ? "SOCKOPT TEST FAILED (%d)\n" : "SOCKOPT TEST PASSED\n", fails);
    return fails != 0;
}
