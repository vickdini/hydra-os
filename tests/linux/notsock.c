#define _GNU_SOURCE
/* wave12 GV: socket calls on descriptors that are no sockets must fail with ENOTSOCK (Linux),
 * never ENOSYS: PulseAudio's pa_write() tries send() first and falls back to write() only on
 * ENOTSOCK (its mainloop wake-up pipe; Firefox's audio stalled on "loading"). */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>
#include <signal.h>

static int bad = 0;
static void check(const char *what, int fd) {
    char b[4] = "x";
    struct msghdr mh; struct iovec io = { b, 1 };
    memset(&mh, 0, sizeof mh); mh.msg_iov = &io; mh.msg_iovlen = 1;
    struct sockaddr_storage sa; socklen_t sl = sizeof sa; int v; socklen_t vl = sizeof v;
    struct { const char *n; long r; } c[] = {
        { "send", send(fd, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT) },
        { "recv", recv(fd, b, 1, MSG_DONTWAIT) },
        { "sendmsg", sendmsg(fd, &mh, MSG_DONTWAIT) },
        { "recvmsg", recvmsg(fd, &mh, MSG_DONTWAIT) },
        { "getsockname", getsockname(fd, (struct sockaddr *)&sa, &sl) },
        { "getpeername", getpeername(fd, (struct sockaddr *)&sa, &sl) },
        { "getsockopt", getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &vl) },
        { "setsockopt", setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) },
        { "shutdown", shutdown(fd, SHUT_RDWR) },
        { "listen", listen(fd, 1) },
        { "accept", accept(fd, 0, 0) },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        /* errno of each call is checked right after it in the initializer order is not
         * guaranteed: call again for the errno */
        (void)c[i];
    }
    const char *names[] = { "send", "recv", "sendmsg", "recvmsg", "getsockname", "getpeername", "getsockopt", "setsockopt", "shutdown", "listen", "accept" };
    for (int i = 0; i < 11; i++) {
        long r; errno = 0;
        switch (i) {
        case 0: r = send(fd, b, 1, MSG_NOSIGNAL | MSG_DONTWAIT); break;
        case 1: r = recv(fd, b, 1, MSG_DONTWAIT); break;
        case 2: r = sendmsg(fd, &mh, MSG_DONTWAIT); break;
        case 3: r = recvmsg(fd, &mh, MSG_DONTWAIT); break;
        case 4: sl = sizeof sa; r = getsockname(fd, (struct sockaddr *)&sa, &sl); break;
        case 5: sl = sizeof sa; r = getpeername(fd, (struct sockaddr *)&sa, &sl); break;
        case 6: vl = sizeof v; r = getsockopt(fd, SOL_SOCKET, SO_TYPE, &v, &vl); break;
        case 7: v = 4096; r = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v); break;
        case 8: r = shutdown(fd, SHUT_RDWR); break;
        case 9: r = listen(fd, 1); break;
        default: r = accept(fd, 0, 0); break;
        }
        if (r != -1 || errno != ENOTSOCK) {
            printf("NOTSOCK-BAD %s %s: r=%ld errno=%d (%s)\n", what, names[i], r, errno, strerror(errno));
            bad++;
        }
    }
}

int main(void) {
    int p[2];
    if (pipe(p) == 0) { check("pipe-r", p[0]); check("pipe-w", p[1]); }
    check("eventfd", eventfd(0, EFD_NONBLOCK));
    check("timerfd", timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK));
    sigset_t s; sigemptyset(&s); sigaddset(&s, SIGUSR1);
    check("signalfd", signalfd(-1, &s, SFD_NONBLOCK));
    check("file", open("/etc/hostname", O_RDONLY));
    check("tmpfile", open("/tmp", O_TMPFILE | O_RDWR, 0600));
    check("devnull", open("/dev/null", O_RDWR));
    check("memfd", memfd_create("x", 0));
    check("dir", open("/", O_RDONLY | O_DIRECTORY));
    check("proc", open("/proc/self/stat", O_RDONLY));
    check("tty", open("/dev/tty", O_RDWR | O_NOCTTY));
    printf(bad ? "NOTSOCK FAIL %d\n" : "NOTSOCK OK\n", bad);
    return bad != 0;
}
