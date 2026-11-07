// ICMP: ping sockets (IPv4 and IPv6 echo over loopback, identifier = bound "port",
// IP_RECVTTL, only echo requests accepted), raw ICMP sockets (CAP_NET_RAW, IP header on
// receive, ICMP_FILTER), /proc/net/dev counters, /proc/net/unix entries.
// Build: gcc -O1 -w -o icmp icmp_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/sockios.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int wait_in(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 3000) == 1;
}

static long lo_rx_packets(void) {
    FILE *f = fopen("/proc/net/dev", "r");
    char line[256];
    long v = -1;
    while (f && fgets(line, sizeof line, f)) {
        char *c = strstr(line, "lo:");
        if (c) sscanf(c + 3, "%*lu %ld", &v);
    }
    if (f) fclose(f);
    return v;
}

static unsigned long inode_of(int fd) {
    char p[64], l[64] = "";
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    readlink(p, l, sizeof l - 1);
    unsigned long n = 0;
    sscanf(l, "socket:[%lu]", &n);
    return n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    long rx0 = lo_rx_packets();
    check(rx0 >= 0, "/proc/net/dev has lo");

    // Ping socket, IPv4
    int p = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (p < 0 && errno == EACCES) {
        printf("skip ping sockets (net.ipv4.ping_group_range excludes us)\n");
    } else {
        check(p >= 0, "ping socket (SOCK_DGRAM, IPPROTO_ICMP)");
        int v = 0;
        socklen_t vl = sizeof v;
        getsockopt(p, SOL_SOCKET, SO_PROTOCOL, &v, &vl);
        check(v == IPPROTO_ICMP, "SO_PROTOCOL is IPPROTO_ICMP");
        struct sockaddr_in me = {.sin_family = AF_INET, .sin_port = htons(4321)};
        check(bind(p, (struct sockaddr *)&me, sizeof me) == 0, "bind sets the echo identifier");
        int on = 1;
        setsockopt(p, IPPROTO_IP, IP_RECVTTL, &on, sizeof on);
        struct timeval st;
        errno = 0;
        check(ioctl(p, SIOCGSTAMP, &st) == -1 && errno == ENOENT, "SIOCGSTAMP before any packet: ENOENT");
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        unsigned char req[16] = {ICMP_ECHO, 0, 0, 0, 0, 0, 0, 7, 'h', 'y', 'd', 'r', 'a', '!', '!', '!'};
        check(sendto(p, req, sizeof req, 0, (struct sockaddr *)&to, sizeof to) == sizeof req, "send an echo request to 127.0.0.1");
        unsigned char rep[64];
        char ctl[64];
        struct sockaddr_in from;
        struct iovec iov = {rep, sizeof rep};
        struct msghdr m = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctl, .msg_controllen = sizeof ctl};
        ssize_t n = wait_in(p) ? recvmsg(p, &m, 0) : -1;
        check(n == sizeof req && rep[0] == ICMP_ECHOREPLY && rep[6] == 0 && rep[7] == 7 && !memcmp(rep + 8, "hydra!!!", 8), "an echo reply comes back with our sequence and data");
        check(n >= 8 && ntohs(*(unsigned short *)(rep + 4)) == 4321, "with our identifier");
        check(from.sin_addr.s_addr == htonl(INADDR_LOOPBACK), "from 127.0.0.1");
        int ttl = -1;
        for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c))
            if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TTL) ttl = *(int *)CMSG_DATA(c);
        check(ttl > 0, "IP_RECVTTL gives the TTL");
        struct timeval now;
        gettimeofday(&now, NULL);
        check(ioctl(p, SIOCGSTAMP, &st) == 0 && labs(now.tv_sec - st.tv_sec) <= 2, "SIOCGSTAMP gives the arrival time");
        unsigned char bad[8] = {ICMP_TIMESTAMP, 0};
        errno = 0;
        check(sendto(p, bad, sizeof bad, 0, (struct sockaddr *)&to, sizeof to) == -1 && errno == EINVAL, "a ping socket only sends echo requests");
        close(p);
        check(lo_rx_packets() > rx0, "/proc/net/dev counts the loopback packets");

        // Ping socket, IPv6
        int p6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
        check(p6 >= 0, "ping socket (AF_INET6, IPPROTO_ICMPV6)");
        struct sockaddr_in6 to6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        unsigned char req6[12] = {ICMP6_ECHO_REQUEST, 0, 0, 0, 0, 0, 0, 9, 'v', '6', 'o', 'k'};
        sendto(p6, req6, sizeof req6, 0, (struct sockaddr *)&to6, sizeof to6);
        n = wait_in(p6) ? recv(p6, rep, sizeof rep, 0) : -1;
        check(n == sizeof req6 && rep[0] == ICMP6_ECHO_REPLY && rep[7] == 9 && !memcmp(rep + 8, "v6ok", 4), "an ICMPv6 echo reply from ::1");
        close(p6);
    }

    // Raw sockets
    int r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (geteuid() != 0) {
        check(r == -1 && errno == EPERM, "raw ICMP socket unprivileged: EPERM");
    } else {
        check(r >= 0, "raw ICMP socket as root");
        struct icmp_filter { unsigned int data; } filt = {~(1U << ICMP_ECHOREPLY)};
        check(setsockopt(r, SOL_RAW, ICMP_FILTER, &filt, sizeof filt) == 0, "ICMP_FILTER: echo replies only");
        struct sockaddr_in to = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        unsigned char req[12] = {ICMP_ECHO, 0, 0, 0, 0x12, 0x34, 0, 3, 'r', 'a', 'w', '!'};
        // The kernel does not fill in a raw socket's checksum
        unsigned sum = 0;
        for (int i = 0; i < 12; i += 2) sum += (req[i] << 8) | req[i + 1];
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        sum = ~sum & 0xffff;
        req[2] = sum >> 8;
        req[3] = sum & 0xff;
        sendto(r, req, sizeof req, 0, (struct sockaddr *)&to, sizeof to);
        unsigned char rep[128];
        ssize_t n = wait_in(r) ? recv(r, rep, sizeof rep, 0) : -1;
        check(n == 20 + 12 && (rep[0] >> 4) == 4 && rep[9] == IPPROTO_ICMP, "a raw socket reads the IP header too");
        check(n == 32 && rep[20] == ICMP_ECHOREPLY && rep[24] == 0x12 && rep[25] == 0x34 && !memcmp(rep + 28, "raw!", 4), "and the filtered stream has only the echo reply");
        close(r);
    }

    // /proc/net/unix
    int l = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un ua = {.sun_family = AF_UNIX};
    char name[64];
    snprintf(name, sizeof name, "hydra-icmp-test-%d", getpid());
    strcpy(ua.sun_path + 1, name);
    bind(l, (struct sockaddr *)&ua, sizeof(sa_family_t) + 1 + strlen(name));
    listen(l, 1);
    int sp[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sp);
    FILE *f = fopen("/proc/net/unix", "r");
    char line[512];
    int listen_ok = 0, pair_ok = 0, header = 0;
    char want[80];
    snprintf(want, sizeof want, "@%s", name);
    if (f && fgets(line, sizeof line, f)) header = !strncmp(line, "Num ", 4);
    while (f && fgets(line, sizeof line, f)) {
        unsigned flags, type, st;
        unsigned long ino;
        if (sscanf(line, "%*[0-9a-fA-F]: %*X %*X %X %X %X %lu", &flags, &type, &st, &ino) != 4) continue;
        if (ino == inode_of(l)) listen_ok = flags == 0x10000 && type == 1 && st == 1 && strstr(line, want);
        if (ino == inode_of(sp[0])) pair_ok = type == 2 && st == 3;
    }
    if (f) fclose(f);
    check(header, "/proc/net/unix has its header");
    check(listen_ok, "a listening abstract socket: __SO_ACCEPTCON, stream, @name");
    check(pair_ok, "a socketpair end: datagram, connected");

    printf(fails ? "ICMP TEST FAILED (%d)\n" : "ICMP TEST PASSED\n", fails);
    return fails != 0;
}
