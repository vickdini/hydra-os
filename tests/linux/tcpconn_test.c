/* tcpconn HOST PORT N [PINGMS]: connect latency (ms) of N new TCP connections to HOST:PORT,
 * 300 ms apart; with PINGMS > 0 a thread pings HOST every PINGMS ms meanwhile (ICMP ping
 * socket). Group 25: is the 500 ms stall QEMU's slirp main loop sleeping? */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static struct sockaddr_in dst;
static volatile int stop;
static int pingms;
static double now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1e3 + t.tv_nsec / 1e6; }
static void *pinger(void *a) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) { perror("ping socket"); return 0; }
    struct sockaddr_in d = dst; d.sin_port = 0;
    int seq = 0, got = 0; char buf[128];
    while (!stop) {
        struct icmphdr h = {0}; h.type = ICMP_ECHO; h.un.echo.sequence = htons(++seq);
        sendto(s, &h, sizeof h, 0, (struct sockaddr *)&d, sizeof d);
        usleep(pingms * 1000);
        while (recv(s, buf, sizeof buf, MSG_DONTWAIT) > 0) got++;
    }
    printf("pings sent %d, replies %d\n", seq, got);
    return 0;
}
int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    dst.sin_family = AF_INET; dst.sin_port = htons(atoi(argv[2])); inet_pton(AF_INET, argv[1], &dst.sin_addr);
    int n = atoi(argv[3]); pingms = argc > 4 ? atoi(argv[4]) : 0;
    pthread_t t;
    if (pingms > 0) pthread_create(&t, 0, pinger, 0);
    usleep(200000);
    double sum = 0, mx = 0, v[1000]; int ok = 0;
    for (int i = 0; i < n; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        double t0 = now_ms();
        int r = connect(s, (struct sockaddr *)&dst, sizeof dst);
        double d = now_ms() - t0;
        if (r == 0) { v[ok++] = d; sum += d; if (d > mx) mx = d; }
        else perror("connect");
        close(s);
        usleep(300000);
    }
    stop = 1;
    if (pingms > 0) pthread_join(t, 0);
    for (int i = 0; i < ok; i++) for (int j = i + 1; j < ok; j++) if (v[j] < v[i]) { double x = v[i]; v[i] = v[j]; v[j] = x; }
    printf("TCPCONN ping=%d n=%d ok=%d mean %.1f median %.1f max %.1f ms:", pingms, n, ok, ok ? sum / ok : 0, ok ? v[ok / 2] : 0, mx);
    for (int i = 0; i < ok; i++) printf(" %.0f", v[i]);
    printf("\n");
    return 0;
}
