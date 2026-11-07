// fanotify: unprivileged file-handle groups (directory entry events with names, handles
// matching name_to_handle_at, fsid matching statfs, modify/close events), and as root:
// descriptor events (open, access, close) and permission events (deny, allow).
// Build: gcc -O1 -w -o fanotify fanotify_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef FAN_REPORT_DIR_FID
#define FAN_REPORT_DIR_FID 0x400
#define FAN_REPORT_NAME 0x800
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#endif

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static char base[64];
static char *at(const char *rel) {
    static char b[4][160];
    static int n;
    char *s = b[n++ & 3];
    snprintf(s, 160, "%s/%s", base, rel);
    return s;
}

struct seen { uint64_t mask; char name[64]; int fd; int pid; uint64_t handle; int32_t fsid[2]; int info_type; };

// Reads what is queued (non-blocking group) into `out`; returns the count
static int drain(int fan, struct seen *out, int max) {
    char buf[8192];
    int n = 0;
    for (;;) {
        ssize_t len = read(fan, buf, sizeof buf);
        if (len <= 0) break;
        for (char *p = buf; p < buf + len && n < max;) {
            struct fanotify_event_metadata *m = (void *)p;
            struct seen *s = &out[n++];
            memset(s, 0, sizeof *s);
            s->mask = m->mask;
            s->fd = m->fd;
            s->pid = m->pid;
            if (m->event_len > m->metadata_len) {
                unsigned char *i = (unsigned char *)p + m->metadata_len;
                s->info_type = i[0];
                memcpy(s->fsid, i + 4, 8);
                memcpy(&s->handle, i + 20, 8);   // after handle_bytes and handle_type
                if (i[0] == FAN_EVENT_INFO_TYPE_DFID_NAME) snprintf(s->name, sizeof s->name, "%s", (char *)(i + 28));
            }
            p += m->event_len;
        }
    }
    return n;
}

static uint64_t handle_of(const char *path) {
    struct { unsigned int bytes; int type; unsigned char h[128]; } fh = {128};
    int mnt;
    if (name_to_handle_at(AT_FDCWD, path, (void *)&fh, &mnt, 0) != 0) return 0;
    uint64_t v = 0;
    memcpy(&v, fh.h, fh.bytes < 8 ? fh.bytes : 8);
    return v;
}

static int find(struct seen *s, int n, uint64_t bit, const char *name) {
    for (int i = 0; i < n; i++)
        if ((s[i].mask & bit) && (!name || !strcmp(s[i].name, name))) return i;
    return -1;
}

static void unprivileged_part(void) {
    if (geteuid() != 0) {
        errno = 0;
        check(fanotify_init(FAN_CLASS_NOTIF, O_RDONLY) == -1 && errno == EPERM, "unprivileged group without file handles: EPERM");
    }
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_DIR_FID | FAN_REPORT_NAME | FAN_NONBLOCK, O_RDONLY);
    check(fan >= 0, "fanotify_init with FAN_REPORT_DIR_FID | FAN_REPORT_NAME");
    if (fan < 0) return;
    if (geteuid() != 0) {
        errno = 0;
        check(fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CREATE, AT_FDCWD, base) == -1 && errno == EPERM, "unprivileged file system mark: EPERM");
    }
    check(fanotify_mark(fan, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ONDIR, AT_FDCWD, base) == 0, "mark the directory for entry events");
    int f = open(at("a"), O_CREAT | O_WRONLY, 0644);
    close(f);
    mkdir(at("sub"), 0755);
    rename(at("a"), at("b"));
    unlink(at("b"));
    struct seen s[64];
    int n = drain(fan, s, 64);
    int c = find(s, n, FAN_CREATE, "a"), d = find(s, n, FAN_CREATE, "sub"), mf = find(s, n, FAN_MOVED_FROM, "a"), mt = find(s, n, FAN_MOVED_TO, "b"),
        dl = find(s, n, FAN_DELETE, "b");
    check(c >= 0 && d >= 0 && mf >= 0 && mt >= 0 && dl >= 0, "CREATE a, CREATE sub, MOVED_FROM a, MOVED_TO b, DELETE b");
    check(d >= 0 && (s[d].mask & FAN_ONDIR) && c >= 0 && !(s[c].mask & FAN_ONDIR), "FAN_ONDIR marks the directory's events");
    struct statfs sf;
    statfs(base, &sf);
    int fsid[2];
    memcpy(fsid, &sf.f_fsid, 8);
    check(c >= 0 && s[c].fd == FAN_NOFD && s[c].info_type == FAN_EVENT_INFO_TYPE_DFID_NAME && s[c].pid == getpid(), "file handle record, no descriptor, our pid");
    check(c >= 0 && s[c].handle == handle_of(base) && s[c].handle != 0, "the directory handle matches name_to_handle_at");
    check(c >= 0 && !memcmp(s[c].fsid, fsid, 8) && (fsid[0] || fsid[1]), "fsid matches statfs and is not zero");

    // Writes to a marked file
    f = open(at("w"), O_CREAT | O_WRONLY, 0644);
    close(f);
    int fan2 = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_NONBLOCK, O_RDONLY);
    check(fanotify_mark(fan2, FAN_MARK_ADD, FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD, at("w")) == 0, "mark a file for modify and close-write");
    f = open(at("w"), O_WRONLY);
    write(f, "data", 4);
    close(f);
    n = drain(fan2, s, 64);
    uint64_t all = 0;
    for (int i = 0; i < n; i++) all |= s[i].mask;
    check((all & FAN_MODIFY) && (all & FAN_CLOSE_WRITE) && n > 0 && s[0].handle == handle_of(at("w")), "FAN_MODIFY and FAN_CLOSE_WRITE with the file's handle");
    errno = 0;
    check(fanotify_mark(fan2, FAN_MARK_REMOVE, FAN_ACCESS, AT_FDCWD, at("sub")) == -1 && errno == ENOENT, "removing a mark that is not there: ENOENT");
    close(fan);
    close(fan2);
}

static void privileged_part(void) {
    int fan = fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC);
    check(fan >= 0, "root: descriptor group");
    int f = open(at("r"), O_CREAT | O_WRONLY, 0644);
    write(f, "hello", 5);
    close(f);
    check(fanotify_mark(fan, FAN_MARK_ADD, FAN_OPEN | FAN_ACCESS | FAN_CLOSE_NOWRITE, AT_FDCWD, at("r")) == 0, "mark open, access, close");
    char b[8];
    f = open(at("r"), O_RDONLY);
    read(f, b, 5);
    close(f);
    int q = 0;
    ioctl(fan, FIONREAD, &q);
    check(q >= (int)sizeof(struct fanotify_event_metadata), "FIONREAD counts the queued bytes");
    struct seen s[16];
    int n = drain(fan, s, 16);
    uint64_t all = 0;
    char link[4096] = {0}, want[4096], lp[64];
    for (int i = 0; i < n; i++) {
        all |= s[i].mask;
        if (s[i].fd >= 0 && !link[0]) {
            snprintf(lp, sizeof lp, "/proc/self/fd/%d", s[i].fd);
            readlink(lp, link, sizeof link - 1);
        }
        if (s[i].fd >= 0) close(s[i].fd);
    }
    realpath(at("r"), want);
    check((all & FAN_OPEN) && (all & FAN_ACCESS) && (all & FAN_CLOSE_NOWRITE), "FAN_OPEN, FAN_ACCESS, FAN_CLOSE_NOWRITE");
    check(!strcmp(link, want), "the event descriptor names the file");
    close(fan);

    // Permission events: deny, then allow
    int pf = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY);
    check(pf >= 0 && fanotify_mark(pf, FAN_MARK_ADD, FAN_OPEN_PERM, AT_FDCWD, at("r")) == 0, "FAN_OPEN_PERM mark");
    pid_t c = fork();
    if (c == 0) {
        int r1 = open(at("r"), O_RDONLY);
        int e1 = errno;
        int r2 = open(at("r"), O_RDONLY);
        _exit((r1 == -1 && e1 == EPERM ? 0 : 1) | (r2 >= 0 ? 0 : 2));
    }
    for (int round = 0; round < 2; round++) {
        char buf[512];
        ssize_t len = read(pf, buf, sizeof buf);
        if (len <= 0) break;
        struct fanotify_event_metadata *m = (void *)buf;
        struct fanotify_response resp = {m->fd, round == 0 ? FAN_DENY : FAN_ALLOW};
        write(pf, &resp, sizeof resp);
        close(m->fd);
    }
    int st;
    waitpid(c, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "permission event: denied open fails with EPERM, allowed one succeeds");
    close(pf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(base, sizeof base, "/tmp/fan.%d.%ld", getpid(), (long)time(NULL));
    mkdir(base, 0777);
    chmod(base, 0777);
    unprivileged_part();
    if (geteuid() == 0) privileged_part();
    else printf("skip: descriptor and permission events need root\n");
    printf(fails ? "FANOTIFY TEST FAILED (%d)\n" : "FANOTIFY TEST PASSED\n", fails);
    return fails != 0;
}
