// Load for the step-3 kill tests (wave 5, Group 12): threads blocked on Internet sockets.
//
//   sockblock            three threads block in accept, recv and epoll_wait on loopback
//                        TCP sockets (and the main thread in recv on a UDP socket); prints
//                        READY, then what each call returned when it ends. Killing
//                        linux-server must end the process (crash policy); killing
//                        net-server must make every call return an error (nothing hangs).
//
// Build: gcc -O1 -w -pthread sockblock_test.c -o sockblock.elf
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

static int lst, cli, srv, ep, udp;

static void *t_accept(void *x) {
    int r = accept(lst, 0, 0);
    printf("accept returned %d (%s)\n", r, r < 0 ? strerror(errno) : "ok");
    fflush(stdout);
    return 0;
}
static void *t_recv(void *x) {
    char b[16];
    int r = recv(srv, b, sizeof b, 0);
    printf("recv returned %d (%s)\n", r, r < 0 ? strerror(errno) : "ok");
    fflush(stdout);
    return 0;
}
static void *t_epoll(void *x) {
    struct epoll_event e;
    int r = epoll_wait(ep, &e, 1, -1);
    printf("epoll_wait returned %d (%s) events %#x\n", r, r < 0 ? strerror(errno) : "ok", r > 0 ? e.events : 0);
    fflush(stdout);
    return 0;
}

int main(void) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t n = sizeof a;
    lst = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(lst, (void *)&a, sizeof a) || listen(lst, 4) || getsockname(lst, (void *)&a, &n)) { perror("listen"); return 1; }
    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(cli, (void *)&a, sizeof a)) { perror("connect"); return 1; }
    srv = accept(lst, 0, 0);
    if (srv < 0) { perror("accept"); return 1; }
    ep = epoll_create1(0);
    struct epoll_event e = {.events = EPOLLIN | EPOLLET};
    epoll_ctl(ep, EPOLL_CTL_ADD, cli, &e);
    udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in u = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    bind(udp, (void *)&u, sizeof u);
    pthread_t t1, t2, t3;
    pthread_create(&t1, 0, t_accept, 0);
    pthread_create(&t2, 0, t_recv, 0);
    pthread_create(&t3, 0, t_epoll, 0);
    usleep(200000);
    printf("READY\n");
    fflush(stdout);
    char b[16];
    int r = recv(udp, b, sizeof b, 0);
    printf("udp recv returned %d (%s)\n", r, r < 0 ? strerror(errno) : "ok");
    fflush(stdout);
    pthread_join(t1, 0);
    pthread_join(t2, 0);
    pthread_join(t3, 0);
    printf("ALL RETURNED\n");
    return 0;
}
