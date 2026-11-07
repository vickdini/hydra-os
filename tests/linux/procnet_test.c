// /proc/net/tcp and /proc/net/udp: a listener, both ends of a loopback connection and a
// bound UDP socket appear with the right addresses, states, uid and inode (the number in
// /proc/self/fd/N -> socket:[N]); tcp6/udp6 exist; /proc/self/net/tcp is the same table.
// Build: gcc -O1 -w -o procnet procnet_test.c
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static unsigned long inode_of(int fd) {
    char p[64], l[64] = "";
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    readlink(p, l, sizeof l - 1);
    unsigned long n = 0;
    sscanf(l, "socket:[%lu]", &n);
    return n;
}

static int port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &l);
    return ntohs(a.sin_port);
}

// Finds a row with local port `lport` (and remote port `rport` unless -1) in `file`;
// returns its state, filling uid and inode
static int find(const char *file, int lport, int rport, unsigned *uid, unsigned long *inode, unsigned *lip) {
    FILE *f = fopen(file, "r");
    if (!f) return -1;
    char line[512];
    fgets(line, sizeof line, f);
    int st = -1;
    while (fgets(line, sizeof line, f)) {
        unsigned la, lp, ra, rp, s, u;
        unsigned long ino;
        if (sscanf(line, " %*d: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %u %*d %lu", &la, &lp, &ra, &rp, &s, &u, &ino) != 7) continue;
        if ((int)lp == lport && (rport < 0 || (int)rp == rport)) {
            st = s;
            *uid = u;
            *inode = ino;
            *lip = la;
            break;
        }
    }
    fclose(f);
    return st;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    int l = socket(AF_INET, SOCK_STREAM, 0);
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 3);
    int port = port_of(l);
    a.sin_port = htons(port);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (struct sockaddr *)&a, sizeof a);
    int s = accept(l, NULL, NULL);
    int cport = port_of(c) == port ? -1 : port_of(c);
    {
        struct sockaddr_in me;
        socklen_t ml = sizeof me;
        getsockname(c, (struct sockaddr *)&me, &ml);
        cport = ntohs(me.sin_port);
    }
    write(c, "abc", 3);
    usleep(50000);

    unsigned uid;
    unsigned long ino;
    unsigned lip;
    int st = find("/proc/net/tcp", port, 0, &uid, &ino, &lip);
    check(st == 0x0A, "the listener is in /proc/net/tcp (state 0A)");
    check(lip == 0x0100007F, "with its address 127.0.0.1");
    check(uid == getuid() && ino == inode_of(l), "with our uid and its inode");
    st = find("/proc/net/tcp", cport, port, &uid, &ino, &lip);
    check(st == 0x01 && ino == inode_of(c), "the client end: established, its inode");
    st = find("/proc/net/tcp", port, cport, &uid, &ino, &lip);
    check(st == 0x01 && ino == inode_of(s), "the accepted end: established, its inode");
    FILE *f = fopen("/proc/net/tcp", "r");
    char line[512];
    int rxq_seen = 0;
    while (f && fgets(line, sizeof line, f)) {
        unsigned lp, rp, rx;
        if (sscanf(line, " %*d: %*X:%X %*X:%X %*X %*X:%X", &lp, &rp, &rx) == 3 && (int)lp == port && (int)rp == cport) rxq_seen = rx == 3;
    }
    if (f) fclose(f);
    check(rxq_seen, "rx_queue shows the 3 unread bytes");
    check(find("/proc/self/net/tcp", port, 0, &uid, &ino, &lip) == 0x0A, "/proc/self/net/tcp is the same table");

    int u = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ua = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(u, (struct sockaddr *)&ua, sizeof ua);
    st = find("/proc/net/udp", port_of(u), -1, &uid, &ino, &lip);
    check(st == 0x07 && ino == inode_of(u) && lip == 0x0100007F, "a bound UDP socket is in /proc/net/udp");

    FILE *t6 = fopen("/proc/net/tcp6", "r"), *u6 = fopen("/proc/net/udp6", "r");
    check(t6 && u6, "tcp6 and udp6 exist");
    if (t6) fclose(t6);
    if (u6) fclose(u6);

    close(c);
    close(s);
    close(l);
    usleep(50000);
    check(find("/proc/net/tcp", port, 0, &uid, &ino, &lip) != 0x0A, "a closed listener is gone");
    printf(fails ? "PROCNET TEST FAILED (%d)\n" : "PROCNET TEST PASSED\n", fails);
    return fails != 0;
}
