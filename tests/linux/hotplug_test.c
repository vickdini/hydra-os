// hotplug_test: device announcements around a device service's restart (wave 8, Group H).
//
//   hotplug_test watch SECS [input|sound]
//        listens SECS seconds on the uevent netlink socket, three ways: a raw socket bound
//        to the kernel's group (1), a raw socket bound to udev's group (2), and a libudev
//        monitor (libudev.so.1, as libinput and PipeWire use it; subsystem filter). Kill the
//        service meanwhile, twice within 30 s (`service kill input_server` / `sound_server`
//        in hydra-shell): its objects fail, the kernel announces "remove", and "add" when
//        the next instance is online. Prints each message and one line per check, then
//        "HOTPLUG PASS" (remove then add seen by all three; for libudev with the udev
//        database's properties: ID_INPUT=1 / SOUND_INITIALIZED=1, and a device node) or
//        "HOTPLUG FAIL".
//   hotplug_test
//        quick check without a kill: the sockets bind, getsockname reports the groups,
//        nothing is pending; libudev's monitor can be made. "HOTPLUG OK".
//
// Build: gcc -O1 -w -pthread tests/linux/hotplug_test.c -o esp/bin/hotplug_test.elf -ldl
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int raw_socket(unsigned groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    if (fd < 0) {
        printf("socket: %s\n", strerror(errno));
        return -1;
    }
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
    struct sockaddr_nl a = {.nl_family = AF_NETLINK, .nl_groups = groups};
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        printf("bind: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    struct sockaddr_nl b;
    socklen_t bl = sizeof b;
    if (getsockname(fd, (struct sockaddr *)&b, &bl) < 0 || b.nl_groups != groups) {
        printf("getsockname: groups %u (want %u)\n", b.nl_groups, groups);
        close(fd);
        return -1;
    }
    return fd;
}

// libudev, loaded at run time (no headers needed)
struct udev;
struct udev_monitor;
struct udev_device;
static struct udev *(*u_new)(void);
static struct udev_monitor *(*u_mon_new)(struct udev *, const char *);
static int (*u_mon_filter)(struct udev_monitor *, const char *, const char *);
static int (*u_mon_enable)(struct udev_monitor *);
static int (*u_mon_fd)(struct udev_monitor *);
static struct udev_device *(*u_mon_recv)(struct udev_monitor *);
static const char *(*u_dev_action)(struct udev_device *);
static const char *(*u_dev_sysname)(struct udev_device *);
static const char *(*u_dev_prop)(struct udev_device *, const char *);
static const char *(*u_dev_node)(struct udev_device *);
static const char *(*u_dev_subsys)(struct udev_device *);
static struct udev_device *(*u_dev_unref)(struct udev_device *);

static struct udev_monitor *udev_monitor(const char *subsys) {
    void *h = dlopen("libudev.so.1", RTLD_NOW);
    if (!h) {
        printf("libudev: %s\n", dlerror());
        return NULL;
    }
#define L(v, n)                  \
    if (!(*(void **)&v = dlsym(h, n))) { \
        printf("libudev: no %s\n", n);   \
        return NULL;                     \
    }
    L(u_new, "udev_new");
    L(u_mon_new, "udev_monitor_new_from_netlink");
    L(u_mon_filter, "udev_monitor_filter_add_match_subsystem_devtype");
    L(u_mon_enable, "udev_monitor_enable_receiving");
    L(u_mon_fd, "udev_monitor_get_fd");
    L(u_mon_recv, "udev_monitor_receive_device");
    L(u_dev_action, "udev_device_get_action");
    L(u_dev_sysname, "udev_device_get_sysname");
    L(u_dev_prop, "udev_device_get_property_value");
    L(u_dev_node, "udev_device_get_devnode");
    L(u_dev_subsys, "udev_device_get_subsystem");
    L(u_dev_unref, "udev_device_unref");
    struct udev *u = u_new();
    struct udev_monitor *m = u ? u_mon_new(u, "udev") : NULL;
    if (!m) {
        printf("libudev: no monitor\n");
        return NULL;
    }
    if (subsys)
        u_mon_filter(m, subsys, NULL);
    if (u_mon_enable(m) < 0) {
        printf("libudev: enable_receiving failed\n");
        return NULL;
    }
    return m;
}

// What one listener saw for the watched subsystem
struct seen {
    double remove_at, add_at;
    int removes, adds, changes, props_ok, bad;
};

static const char *prop_of(const char *buf, int n, const char *key) {
    size_t kl = strlen(key);
    for (int i = 0; i < n;) {
        const char *p = buf + i;
        if (!strncmp(p, key, kl) && p[kl] == '=')
            return p + kl + 1;
        i += strlen(p) + 1;
    }
    return NULL;
}

// A raw datagram: kernel format (group 1) or libudev's (group 2)
static void raw_message(const char *tag, char *buf, int n, int udev, const char *want, struct seen *s, double t0) {
    if (n <= 0)
        return;
    buf[n] = 0;
    int off = 0;
    if (udev) {
        if (n < 40 || memcmp(buf, "libudev", 8) || buf[8] != (char)0xfe || buf[9] != (char)0xed) {
            printf("%s: not a libudev message (%d bytes)\n", tag, n);
            s->bad++;
            return;
        }
        unsigned po = *(unsigned *)(buf + 16);
        if (po > (unsigned)n) {
            s->bad++;
            return;
        }
        off = po;
    } else {
        if (!strchr(buf, '@')) {
            printf("%s: no ACTION@DEVPATH header\n", tag);
            s->bad++;
            return;
        }
        off = strlen(buf) + 1;
    }
    const char *action = prop_of(buf + off, n - off, "ACTION");
    const char *sub = prop_of(buf + off, n - off, "SUBSYSTEM");
    const char *path = prop_of(buf + off, n - off, "DEVPATH");
    const char *seq = prop_of(buf + off, n - off, "SEQNUM");
    printf("%s %+.3f s: %s %s %s seq %s\n", tag, now_s() - t0, action ? action : "?", sub ? sub : "?", path ? path : "?", seq ? seq : "?");
    if (!action || !sub || !path || !seq) {
        s->bad++;
        return;
    }
    if (strcmp(sub, want))
        return;
    if (!strcmp(action, "remove")) {
        if (!s->removes++)
            s->remove_at = now_s();
    } else if (!strcmp(action, "add")) {
        if (!s->adds++)
            s->add_at = now_s();
    } else if (!strcmp(action, "change")) {
        s->changes++;
    }
}

static int recv_raw(int fd, char *buf, size_t cap, int *cred_ok) {
    struct sockaddr_nl from;
    char ctrl[64];
    struct iovec iov = {buf, cap - 1};
    struct msghdr m = {.msg_name = &from, .msg_namelen = sizeof from, .msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctrl, .msg_controllen = sizeof ctrl};
    int n = recvmsg(fd, &m, 0);
    if (n < 0)
        return n;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    *cred_ok = c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS && ((struct ucred *)CMSG_DATA(c))->uid == 0 && from.nl_pid == 0;
    return n;
}

int main(int argc, char **argv) {
    int watch = argc > 1 && !strcmp(argv[1], "watch");
    int secs = watch && argc > 2 ? atoi(argv[2]) : 0;
    const char *want = watch && argc > 3 ? argv[3] : "input";
    int k = raw_socket(1), u = raw_socket(2);
    struct udev_monitor *mon = udev_monitor(want);
    if (k < 0 || u < 0 || !mon) {
        printf("HOTPLUG FAIL (set-up)\n");
        return 1;
    }
    if (!watch) {
        char buf[64];
        int pend = recv(k, buf, sizeof buf, MSG_DONTWAIT) >= 0 || recv(u, buf, sizeof buf, MSG_DONTWAIT) >= 0;
        printf("sockets bound (groups 1 and 2), libudev monitor fd %d, %s\n", u_mon_fd(mon), pend ? "a message pending" : "nothing pending");
        printf("HOTPLUG OK\n");
        return 0;
    }
    printf("HOTPLUG-WATCHING %d s for %s\n", secs, want);
    fflush(stdout);
    struct seen sk = {0}, su = {0}, sl = {0};
    int creds_bad = 0;
    double t0 = now_s(), end = t0 + secs;
    static char buf[16384];
    while (now_s() < end) {
        struct pollfd p[3] = {{k, POLLIN}, {u, POLLIN}, {u_mon_fd(mon), POLLIN}};
        int r = poll(p, 3, 500);
        if (r < 0 && errno != EINTR)
            break;
        int ok;
        if (p[0].revents & POLLIN) {
            int n;
            while ((n = recv_raw(k, buf, sizeof buf, &ok)) > 0) {
                creds_bad += !ok;
                raw_message("kernel", buf, n, 0, want, &sk, t0);
            }
        }
        if (p[1].revents & POLLIN) {
            int n;
            while ((n = recv_raw(u, buf, sizeof buf, &ok)) > 0) {
                creds_bad += !ok;
                raw_message("udev  ", buf, n, 1, want, &su, t0);
            }
        }
        if (p[2].revents & POLLIN) {
            struct udev_device *d;
            while ((d = u_mon_recv(mon))) {
                const char *a = u_dev_action(d), *node = u_dev_node(d);
                const char *key = !strcmp(want, "input") ? "ID_INPUT" : "SOUND_INITIALIZED";
                const char *v = u_dev_prop(d, key), *tags = u_dev_prop(d, "TAGS");
                printf("libudev %+.3f s: %s %s %s node %s %s=%s TAGS=%s\n", now_s() - t0, a ? a : "?", u_dev_subsys(d) ? u_dev_subsys(d) : "?", u_dev_sysname(d), node ? node : "-", key, v ? v : "-",
                       tags ? tags : "-");
                if (a && !strcmp(a, "remove") && !sl.removes++)
                    sl.remove_at = now_s();
                if (a && !strcmp(a, "add") && !sl.adds++)
                    sl.add_at = now_s();
                if (a && !strcmp(a, "change"))
                    sl.changes++;
                // the card has no node; its nodes and input devices do; the card carries
                // SOUND_INITIALIZED, input devices ID_INPUT
                int is_card = !strcmp(want, "sound") && !strncmp(u_dev_sysname(d), "card", 4);
                if ((is_card || !strcmp(want, "input")) && v && !strcmp(v, "1") && (is_card || node))
                    sl.props_ok++;
                u_dev_unref(d);
            }
        }
        fflush(stdout);
        // done early once every listener saw remove then add (and the card's change)
        int need_change = !strcmp(want, "sound");
        if (sl.adds && su.adds && sk.adds && (!need_change || sl.changes) && now_s() > sl.add_at + 1)
            break;
    }
    int pass = 1;
    struct {
        const char *name;
        struct seen *s;
    } all[] = {{"kernel", &sk}, {"udev", &su}, {"libudev", &sl}};
    for (int i = 0; i < 3; i++) {
        struct seen *s = all[i].s;
        int ok = s->removes > 0 && s->adds > 0 && s->remove_at <= s->add_at && !s->bad;
        printf("%-8s removes %d adds %d changes %d bad %d: remove->add %.2f s %s\n", all[i].name, s->removes, s->adds, s->changes, s->bad, s->adds && s->removes ? s->add_at - s->remove_at : 0.0, ok ? "ok" : "MISSING");
        pass &= ok;
    }
    printf("libudev messages with the database's properties: %d; raw messages without credentials: %d\n", sl.props_ok, creds_bad);
    if (!sl.props_ok || creds_bad)
        pass = 0;
    if (!strcmp(want, "sound") && !sl.changes)
        pass = 0;
    printf("HOTPLUG %s\n", pass ? "PASS" : "FAIL");
    return !pass;
}
