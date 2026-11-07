// AF_INET6 sockets: ::1 servers and clients, dual-stack [::] listeners taking IPv4 peers
// as ::ffff:a.b.c.d, IPV6_V6ONLY (default, effect on bind conflicts and mapped
// addresses, fixed once bound), unreachable non-loopback IPv6, UDP over ::1,
// /proc/net/tcp6, getaddrinfo("localhost") fallback to an IPv4-only server.
// Build: gcc -O1 -w -o ipv6 ipv6_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static struct sockaddr_in6 a6(const char *ip, int port) {
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    inet_pton(AF_INET6, ip, &a.sin6_addr);
    return a;
}

static int port6(int fd) {
    struct sockaddr_in6 a;
    socklen_t l = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &l);
    return ntohs(a.sin6_port);
}

static int listen6(const char *ip, int v6only) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if (v6only >= 0) setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
    struct sockaddr_in6 a = a6(ip, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 4)) return -1;
    return s;
}

static int dial4(int port) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(c, (struct sockaddr *)&a, sizeof a)) {
        int e = errno;
        close(c);
        errno = e;
        return -1;
    }
    return c;
}

static int dial6(const char *ip, int port) {
    int c = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 a = a6(ip, port);
    if (connect(c, (struct sockaddr *)&a, sizeof a)) {
        int e = errno;
        close(c);
        errno = e;
        return -1;
    }
    return c;
}

static const char *peer_of(int fd, int local) {
    static char buf[64];
    struct sockaddr_in6 a;
    socklen_t l = sizeof a;
    (local ? getsockname : getpeername)(fd, (struct sockaddr *)&a, &l);
    if (l != sizeof a || a.sin6_family != AF_INET6) return "?";
    inet_ntop(AF_INET6, &a.sin6_addr, buf, sizeof buf);
    return buf;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int t = socket(AF_INET6, SOCK_STREAM, 0);
    check(t >= 0, "socket(AF_INET6, SOCK_STREAM)");
    int v = -1;
    socklen_t vl = sizeof v;
    check(getsockopt(t, SOL_SOCKET, SO_DOMAIN, &v, &vl) == 0 && v == AF_INET6, "SO_DOMAIN is AF_INET6");
    vl = sizeof v;
    check(getsockopt(t, IPPROTO_IPV6, IPV6_V6ONLY, &v, &vl) == 0 && v == 0, "IPV6_V6ONLY defaults to 0");
    vl = sizeof v;
    check(getsockopt(t, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, &vl) == 0 && v == 64, "IPV6_UNICAST_HOPS defaults to 64");
    close(t);

    // A server on ::1
    int s = listen6("::1", -1);
    check(s >= 0, "bind [::1]:0 and listen");
    int p = port6(s);
    int c = dial6("::1", p);
    check(c >= 0, "connect to [::1]");
    int a = accept(s, NULL, NULL);
    check(a >= 0 && !strcmp(peer_of(a, 0), "::1") && !strcmp(peer_of(a, 1), "::1"), "the accepted end: peer and local ::1");
    char b[8] = "";
    check(write(c, "v6!", 3) == 3 && read(a, b, sizeof b) == 3 && !memcmp(b, "v6!", 3), "data over ::1");
    errno = 0;
    check(dial4(p) == -1 && errno == ECONNREFUSED, "IPv4 to a port only ::1 listens on: ECONNREFUSED");
    FILE *f = fopen("/proc/net/tcp6", "r");
    char line[512], want[64];
    snprintf(want, sizeof want, "00000000000000000000000001000000:%04X", p);
    int seen = 0;
    while (f && fgets(line, sizeof line, f)) seen |= strstr(line, want) && strstr(line, " 0A ");
    if (f) fclose(f);
    check(seen, "/proc/net/tcp6 lists the ::1 listener");
    close(a);
    close(c);
    close(s);

    // A dual-stack server on [::]
    s = listen6("::", -1);
    p = port6(s);
    c = dial4(p);
    check(c >= 0, "IPv4 client to a [::] listener");
    a = accept(s, NULL, NULL);
    check(!strcmp(peer_of(a, 0), "::ffff:127.0.0.1"), "its peer shows as ::ffff:127.0.0.1");
    check(!strcmp(peer_of(a, 1), "::ffff:127.0.0.1"), "and its local address too");
    close(a);
    close(c);
    c = dial6("::1", p);
    a = accept(s, NULL, NULL);
    check(c >= 0 && !strcmp(peer_of(a, 0), "::1"), "an IPv6 client to the same listener");
    close(a);
    close(c);
    close(s);

    // Bind conflicts between families
    int l4 = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in any4 = {.sin_family = AF_INET};
    bind(l4, (struct sockaddr *)&any4, sizeof any4);
    listen(l4, 1);
    struct sockaddr_in g;
    socklen_t gl = sizeof g;
    getsockname(l4, (struct sockaddr *)&g, &gl);
    int p4 = ntohs(g.sin_port);
    int d = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 same = a6("::", p4);
    errno = 0;
    check(bind(d, (struct sockaddr *)&same, sizeof same) == -1 && errno == EADDRINUSE, "[::] dual-stack on an IPv4 port in use: EADDRINUSE");
    close(d);
    d = socket(AF_INET6, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(d, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    check(bind(d, (struct sockaddr *)&same, sizeof same) == 0, "with IPV6_V6ONLY it binds");
    errno = 0;
    check(setsockopt(d, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == -1 && errno == EINVAL, "IPV6_V6ONLY after bind: EINVAL");
    close(d);
    close(l4);
    d = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(d, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_in6 mapped = a6("::ffff:127.0.0.1", 9);
    errno = 0;
    check(connect(d, (struct sockaddr *)&mapped, sizeof mapped) == -1 && errno == ENETUNREACH, "IPV6_V6ONLY to an IPv4-mapped address: ENETUNREACH");
    close(d);

    // Beyond loopback
    d = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 far = a6("2001:db8::1", 80);
    errno = 0;
    int r = connect(d, (struct sockaddr *)&far, sizeof far);
    check(r == -1 && (errno == ENETUNREACH || errno == EHOSTUNREACH || errno == EINPROGRESS || errno == ETIMEDOUT || errno == ECONNREFUSED || errno == EACCES), "a global IPv6 address fails without a route");
    close(d);
    d = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 far0 = a6("2001:db8::1", 0);
    errno = 0;
    check(bind(d, (struct sockaddr *)&far0, sizeof far0) == -1 && errno == EADDRNOTAVAIL, "binding an IPv6 address not ours: EADDRNOTAVAIL");
    errno = 0;
    check(bind(d, (struct sockaddr *)&far, sizeof far) == -1 && errno == (geteuid() ? EACCES : EADDRNOTAVAIL), "with port 80 unprivileged: EACCES first");
    close(d);
    d = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in6 lo = a6("::1", 9);
    errno = 0;
    check(connect(d, (struct sockaddr *)&lo, sizeof lo) == -1 && (errno == EAFNOSUPPORT || errno == EINVAL), "an IPv6 address on an IPv4 socket fails");
    close(d);

    // UDP over ::1
    int u1 = socket(AF_INET6, SOCK_DGRAM, 0), u2 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 ul = a6("::1", 0);
    check(bind(u1, (struct sockaddr *)&ul, sizeof ul) == 0, "UDP bind [::1]");
    struct sockaddr_in6 to = a6("::1", port6(u1));
    check(sendto(u2, "dgram", 5, 0, (struct sockaddr *)&to, sizeof to) == 5, "UDP sendto [::1]");
    struct sockaddr_in6 from;
    socklen_t fl = sizeof from;
    char ip[64];
    ssize_t n = recvfrom(u1, b, sizeof b, 0, (struct sockaddr *)&from, &fl);
    inet_ntop(AF_INET6, &from.sin6_addr, ip, sizeof ip);
    check(n == 5 && fl == sizeof from && !strcmp(ip, "::1") && ntohs(from.sin6_port) == port6(u2), "recvfrom gives the ::1 sender");

    // A client resolving "localhost" reaches an IPv4-only server (trying each address)
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in lo4 = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(l, (struct sockaddr *)&lo4, sizeof lo4);
    listen(l, 2);
    gl = sizeof g;
    getsockname(l, (struct sockaddr *)&g, &gl);
    char ps[8];
    snprintf(ps, sizeof ps, "%d", ntohs(g.sin_port));
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res = NULL, *ai;
    int ok = 0;
    if (getaddrinfo("localhost", ps, &hints, &res) == 0) {
        for (ai = res; ai && !ok; ai = ai->ai_next) {
            int k = socket(ai->ai_family, ai->ai_socktype, 0);
            if (k >= 0 && connect(k, ai->ai_addr, ai->ai_addrlen) == 0) ok = 1;
            if (k >= 0) close(k);
        }
        freeaddrinfo(res);
    }
    check(ok, "getaddrinfo(localhost) clients reach an IPv4-only server");

    printf(fails ? "IPV6 TEST FAILED (%d)\n" : "IPV6 TEST PASSED\n", fails);
    return fails != 0;
}
