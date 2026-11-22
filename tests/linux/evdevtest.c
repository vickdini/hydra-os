/* evdevtest (wave 8, Group I): the event devices as libinput and logind use them, served by
 * the input service (or the kernel's copy with lx.input=kernel): names, ids, capability
 * bits, fstat's device numbers, an empty queue (EAGAIN, poll 0), a blocking read ended by a
 * signal (EINTR), EVIOCREVOKE (ENODEV, POLLERR|POLLHUP) and close.
 * Build: gcc -O1 -w -pthread -o evdevtest evdevtest.c
 * Prints "evdevtest OK" (rc 0) or FAIL lines (rc 1). With an argument N it also waits up
 * to N seconds for one event on event0..2 and prints it ("event dev type code value"). */
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf(" (errno %d)\n", errno); fails++; } } while (0)

static void on_alarm(int s) { (void)s; }

static int bit(const unsigned char *m, int b) { return (m[b / 8] >> (b % 8)) & 1; }

int main(int argc, char **argv) {
    static const char *names[3] = {"AT Translated Set 2 keyboard", "ImPS/2 Generic Wheel Mouse", "VirtualPS/2 VMware VMMouse"};
    int n_open = 0;
    for (int d = 0; d < 3; d++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/input/event%d", d);
        int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            CHECK(d == 2, "open %s", path); /* the absolute pointer exists only under a hypervisor */
            continue;
        }
        n_open++;
        char name[256] = {0};
        int r = ioctl(fd, EVIOCGNAME(sizeof name), name);
        CHECK(r == (int)strlen(names[d]) + 1 && strcmp(name, names[d]) == 0, "%s: EVIOCGNAME r=%d '%s'", path, r, name);
        struct input_id id;
        CHECK(ioctl(fd, EVIOCGID, &id) == 0 && id.bustype == 0x11, "%s: EVIOCGID", path);
        int ver = 0;
        CHECK(ioctl(fd, EVIOCGVERSION, &ver) == 0 && ver == 0x10001, "%s: EVIOCGVERSION %x", path, ver);
        unsigned char types[8] = {0}, keys[96] = {0};
        CHECK(ioctl(fd, EVIOCGBIT(0, sizeof types), types) == 8 && bit(types, EV_KEY), "%s: EVIOCGBIT(0)", path);
        CHECK(ioctl(fd, EVIOCGBIT(EV_KEY, sizeof keys), keys) == 96, "%s: EVIOCGBIT(EV_KEY)", path);
        if (d == 0) CHECK(bit(keys, KEY_A) && bit(keys, KEY_ENTER) && bit(types, EV_REP), "keyboard bits");
        if (d == 1) CHECK(bit(keys, BTN_LEFT) && bit(types, EV_REL), "mouse bits");
        if (d == 2) {
            struct input_absinfo ai;
            CHECK(ioctl(fd, EVIOCGABS(ABS_X), &ai) == 0 && ai.maximum == 0xFFFF, "EVIOCGABS max %d", ai.maximum);
        }
        struct stat st, nst;
        CHECK(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode), "%s: fstat mode %o", path, st.st_mode);
        CHECK(stat(path, &nst) == 0, "stat %s", path);
        CHECK(major(st.st_rdev) == 13 && minor(st.st_rdev) == 64 + d && st.st_rdev == nst.st_rdev, "%s: st_rdev %u:%u (node %u:%u)", path, major(st.st_rdev), minor(st.st_rdev),
              major(nst.st_rdev), minor(nst.st_rdev));
        CHECK(ioctl(fd, EVIOCGRAB, 1) == 0 && ioctl(fd, EVIOCGRAB, 0) == 0, "%s: EVIOCGRAB", path);
        CHECK(ioctl(fd, EVIOCSCLOCKID, &(int){CLOCK_MONOTONIC}) == 0, "%s: EVIOCSCLOCKID", path);
        close(fd);
    }
    CHECK(n_open >= 2, "opened %d devices", n_open);

    if (argc > 1) {
        /* Wait for one event (the harness types or moves the pointer meanwhile) */
        struct pollfd p[3];
        int nf = 0;
        for (int d = 0; d < 3; d++) {
            char path[32];
            snprintf(path, sizeof path, "/dev/input/event%d", d);
            p[nf].fd = open(path, O_RDONLY | O_NONBLOCK);
            p[nf].events = POLLIN;
            if (p[nf].fd >= 0) nf++;
        }
        int r = poll(p, nf, atoi(argv[1]) * 1000);
        for (int i = 0; r > 0 && i < nf; i++) {
            struct input_event ev;
            if ((p[i].revents & POLLIN) && read(p[i].fd, &ev, sizeof ev) == sizeof ev)
                printf("event %d type %d code %d value %d\n", i, ev.type, ev.code, ev.value);
        }
        if (r <= 0) printf("no event within %s s\n", argv[1]);
    }

    int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
    CHECK(fd >= 0, "open event0");
    if (fd >= 0) {
        struct input_event ev[4];
        /* The console owns the keyboard here: nothing queued */
        errno = 0;
        CHECK(read(fd, ev, sizeof ev) < 0 && errno == EAGAIN, "empty read: expected EAGAIN");
        CHECK(read(fd, ev, 10) < 0 && errno == EINVAL, "short read: expected EINVAL");
        struct pollfd p = {fd, POLLIN, 0};
        CHECK(poll(&p, 1, 0) == 0, "poll on an empty queue");
        /* A blocking read waits until a signal ends it */
        int fl = fcntl(fd, F_GETFL);
        fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_alarm; /* no SA_RESTART */
        sigaction(SIGALRM, &sa, NULL);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        alarm(1);
        errno = 0;
        ssize_t r = read(fd, ev, sizeof ev);
        int e = errno;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double s = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        errno = e;
        CHECK(r < 0 && e == EINTR && s > 0.8 && s < 5, "blocking read: r=%zd after %.2f s", r, s);
        /* A second file of the same device, revoked: it stops for good, the first lives */
        int fd2 = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
        CHECK(fd2 >= 0, "second open");
        CHECK(ioctl(fd2, EVIOCREVOKE, NULL) == 0, "EVIOCREVOKE");
        errno = 0;
        CHECK(read(fd2, ev, sizeof ev) < 0 && errno == ENODEV, "read after revoke: expected ENODEV");
        struct pollfd p2 = {fd2, POLLIN, 0};
        CHECK(poll(&p2, 1, 0) == 1 && (p2.revents & (POLLERR | POLLHUP)), "poll after revoke: revents %x", p2.revents);
        fcntl(fd, F_SETFL, fl);
        errno = 0;
        CHECK(read(fd, ev, sizeof ev) < 0 && errno == EAGAIN, "first file after the revoke: expected EAGAIN");
        close(fd2);
        close(fd);
    }
    printf(fails ? "evdevtest: %d FAILED\n" : "evdevtest OK\n", fails);
    return fails ? 1 : 0;
}
