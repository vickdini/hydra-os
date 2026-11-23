// notifykill: inotify watches and a fanotify mark kept across vfs-server restarts
// (wave 9, Group 6b-1).
//
// usage: notifykill DIR SECONDS
// Makes DIR and DIR/sub, an inotify instance watching DIR (IN_CREATE | IN_DELETE) and a
// fanotify group (file handles, DIR marked for FAN_CREATE), prints "WATCHING", then one
// line per event: "EV <mask> <name>" (inotify, blocking reads) and "FAN <mask>" (fanotify,
// read whenever poll says so). An entry named "add2" makes it add a watch on DIR/sub
// ("ADDED <wd>"); "stop" ends it ("DONE inotify=<n> fanotify=<n>"). Read errors are printed
// ("READERR <errno>") and the read is retried.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID 0x400
#endif
#ifndef FAN_REPORT_NAME
#define FAN_REPORT_NAME 0x800
#endif

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: notifykill DIR SECONDS\n");
        return 2;
    }
    const char *dir = argv[1];
    char sub[512];
    snprintf(sub, sizeof sub, "%s/sub", dir);
    mkdir(dir, 0755);
    mkdir(sub, 0755);
    setvbuf(stdout, NULL, _IONBF, 0);
    int in = inotify_init1(IN_NONBLOCK);
    int wd = inotify_add_watch(in, dir, IN_CREATE | IN_DELETE);
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_NONBLOCK, O_RDONLY);
    int fm = fan >= 0 ? fanotify_mark(fan, FAN_MARK_ADD, FAN_CREATE, AT_FDCWD, dir) : -1;
    printf("WATCHING in=%d wd=%d fan=%d mark=%d\n", in, wd, fan, fm);
    if (in < 0 || wd < 0)
        return 1;
    alarm(atoi(argv[2]));
    int nin = 0, nfan = 0;
    char buf[8192] __attribute__((aligned(8)));
    for (;;) {
        struct pollfd p[2] = {{in, POLLIN, 0}, {fan, POLLIN, 0}};
        int r = poll(p, fan >= 0 ? 2 : 1, 5000);
        if (r < 0) {
            printf("POLLERR %d\n", errno);
            if (errno == EINTR)
                continue;
            return 1;
        }
        if ((p[0].revents | p[1].revents) & (POLLERR | POLLHUP | POLLNVAL)) {
            // (the descriptors went stale: a restart that did not keep them)
            char b1[8];
            printf("STALE revents=%x,%x read=%zd errno=%d\n", p[0].revents, p[1].revents, read(in, b1, 0), errno);
            return 3;
        }
        if (fan >= 0 && (p[1].revents & POLLIN)) {
            ssize_t n = read(fan, buf, sizeof buf);
            for (ssize_t off = 0; n > 0 && off < n;) {
                struct fanotify_event_metadata *m = (void *)(buf + off);
                printf("FAN %llx\n", (unsigned long long)m->mask);
                nfan++;
                off += m->event_len;
            }
        }
        if (!(p[0].revents & POLLIN))
            continue;
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0) {
            if (errno != EAGAIN)
                printf("READERR %d\n", errno);
            continue;
        }
        for (ssize_t off = 0; off < n;) {
            struct inotify_event *e = (void *)(buf + off);
            printf("EV %x %s\n", e->mask, e->len ? e->name : "");
            nin++;
            if (e->len && !strcmp(e->name, "add2")) {
                int w2 = inotify_add_watch(in, sub, IN_CREATE);
                printf("ADDED %d\n", w2);
            }
            if (e->len && !strcmp(e->name, "stop")) {
                printf("DONE inotify=%d fanotify=%d\n", nin, nfan);
                return 0;
            }
            off += sizeof *e + e->len;
        }
    }
}
