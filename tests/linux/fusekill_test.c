// FUSE under load and crashes (wave 9, Group 6b-2): a tiny raw-protocol daemon (no libfuse)
// serving /d/f and /big, mounted at /tmp/fk.mnt, and three modes:
//   fusekill load SECONDS   stat + open/read + pread on a long-open descriptor in a loop,
//                           one line per second with the errors seen (kill vfs_server meanwhile)
//   fusekill daemonkill     the daemon is killed: calls answer ENOTCONN, umount still works
//   fusekill bench MB       sequential write then read of MB megabytes (128 KiB calls): MB/s
// Run as root. Build: gcc -O1 -w -o fusekill fusekill_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct in_header { uint32_t len, opcode; uint64_t unique, nodeid; uint32_t uid, gid, pid; uint16_t extlen, pad; };
struct out_header { uint32_t len; int32_t error; uint64_t unique; };
struct attr {
    uint64_t ino, size, blocks, atime, mtime, ctime;
    uint32_t atimensec, mtimensec, ctimensec, mode, nlink, uid, gid, rdev, blksize, flags;
};
struct entry_out { uint64_t nodeid, generation, entry_valid, attr_valid; uint32_t entry_valid_nsec, attr_valid_nsec; struct attr attr; };
struct attr_out { uint64_t attr_valid; uint32_t attr_valid_nsec, dummy; struct attr attr; };

static int fd;
static const char *MNT = "/tmp/fk.mnt";
static char hello[] = "hello world\n";
static char *big;
static size_t big_size, big_cap = 64u << 20;

// nodes: 1 root, 2 d, 3 d/f, 4 big
static uint32_t mode_of(int n) { return n <= 2 ? S_IFDIR | 0755 : S_IFREG | 0644; }
static uint64_t size_of(int n) { return n == 3 ? sizeof hello - 1 : n == 4 ? big_size : 0; }

static void fill(int n, struct attr *a) {
    memset(a, 0, sizeof *a);
    a->ino = 500 + n;
    a->mode = mode_of(n);
    a->nlink = n <= 2 ? 2 : 1;
    a->size = size_of(n);
    a->blksize = 4096;
}

static void reply(uint64_t unique, int err, const void *body, size_t n) {
    struct out_header h = {sizeof h + (err ? 0 : n), err, unique};
    struct iovec v[2] = {{&h, sizeof h}, {(void *)body, err ? 0 : n}};
    writev(fd, v, err || !n ? 1 : 2);
}

static void serve(void) {
    static char buf[(1 << 20) + 4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == ENOENT)) continue;
        if (n <= 0) {
            fprintf(stderr, "daemon: read ends: %s\n", n < 0 ? strerror(errno) : "EOF");
            exit(n < 0 && errno == ENODEV ? 0 : 3);
        }
        struct in_header *h = (void *)buf;
        char *arg = buf + sizeof *h;
        int me = h->nodeid;
        switch (h->opcode) {
        case 26: { uint32_t out[6] = {7, 12, 128 * 1024, 0, 0, 128 * 1024}; reply(h->unique, 0, out, sizeof out); break; }
        case 1: {
            int i = me == 1 && !strcmp(arg, "d") ? 2 : me == 2 && !strcmp(arg, "f") ? 3 : me == 1 && !strcmp(arg, "big") ? 4 : -1;
            if (i < 0) { reply(h->unique, -ENOENT, 0, 0); break; }
            struct entry_out e = {0};
            e.nodeid = i;
            fill(i, &e.attr);
            reply(h->unique, 0, &e, sizeof e);
            break;
        }
        case 2: case 42: break;
        case 3: case 4: {
            if (h->opcode == 4 && (*(uint32_t *)arg & 8) && me == 4) big_size = *(uint64_t *)(arg + 16) < big_cap ? *(uint64_t *)(arg + 16) : big_cap;
            struct attr_out a = {0};
            fill(me, &a.attr);
            reply(h->unique, 0, &a, sizeof a);
            break;
        }
        case 14: case 27: { uint64_t out[2] = {me + 100, 0}; reply(h->unique, 0, out, sizeof out); break; }
        case 15: {
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            const char *src = me == 3 ? hello : big;
            size_t have = off < size_of(me) ? size_of(me) - off : 0;
            reply(h->unique, 0, src + (have ? off : 0), have < size ? have : size);
            break;
        }
        case 16: {
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            if (me != 4 || off + size > big_cap) { reply(h->unique, -EFBIG, 0, 0); break; }
            memcpy(big + off, arg + 40, size);
            if (off + size > big_size) big_size = off + size;
            uint32_t out[2] = {size, 0};
            reply(h->unique, 0, out, sizeof out);
            break;
        }
        case 18: case 25: case 29: case 20: case 30: case 36: if (h->opcode != 36) reply(h->unique, 0, 0, 0); break;
        default: reply(h->unique, -ENOSYS, 0, 0);
        }
    }
}

static pid_t start(void) {
    mkdir(MNT, 0755);
    umount2(MNT, MNT_DETACH);
    fd = open("/dev/fuse", O_RDWR);
    if (fd < 0) { perror("open /dev/fuse"); exit(1); }
    big = malloc(big_cap);
    char opts[128];
    snprintf(opts, sizeof opts, "fd=%d,rootmode=40000,user_id=0,group_id=0", fd);
    if (mount("fusekill", MNT, "fuse.fusekill", MS_NOSUID | MS_NODEV, opts)) { perror("mount"); exit(1); }
    pid_t p = fork();
    if (p == 0) serve();
    close(fd);
    return p;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int load(int secs) {
    char path[64], b[64];
    snprintf(path, sizeof path, "%s/d/f", MNT);
    int keep = open(path, O_RDONLY);
    // paths (stat, open + read of a fresh descriptor) and the descriptor opened before (pread)
    long ok = 0, err = 0, errs[256] = {0}, kok = 0, kerr = 0, kerrs[256] = {0};
    double t0 = now(), next = t0 + 1;
    while (now() - t0 < secs) {
        struct stat st;
        int e = 0;
        errno = 0;
        if (stat(path, &st) || st.st_size != 12) e = errno ? errno : 255;
        int f = open(path, O_RDONLY);
        if (f < 0) e = errno;
        else {
            if (read(f, b, sizeof b) != 12) e = errno ? errno : 254;
            close(f);
        }
        if (e) { err++; errs[e & 255]++; } else ok++;
        errno = 0;
        if (keep < 0 || pread(keep, b, sizeof b, 0) != 12) { kerr++; kerrs[(errno ? errno : 253) & 255]++; } else kok++;
        if (now() >= next) {
            printf("t=%.0f paths ok=%ld err=%ld", now() - t0, ok, err);
            for (int i = 0; i < 256; i++) if (errs[i]) printf(" e%d:%ld", i, errs[i]);
            printf("; old fd ok=%ld err=%ld", kok, kerr);
            for (int i = 0; i < 256; i++) if (kerrs[i]) printf(" e%d:%ld", i, kerrs[i]);
            printf("\n");
            next += 1;
        }
        usleep(2000);
    }
    printf("FUSEKILL paths ok=%ld err=%ld", ok, err);
    for (int i = 0; i < 256; i++) if (errs[i]) printf(" e%d:%ld", i, errs[i]);
    printf("; old fd ok=%ld err=%ld", kok, kerr);
    for (int i = 0; i < 256; i++) if (kerrs[i]) printf(" e%d:%ld", i, kerrs[i]);
    printf("\n");
    return err == 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *m = argc > 1 ? argv[1] : "load";
    pid_t d = start();
    int good = 1;
    if (!strcmp(m, "load")) {
        good = load(argc > 2 ? atoi(argv[2]) : 20);
    } else if (!strcmp(m, "daemonkill")) {
        char path[64], b[64];
        snprintf(path, sizeof path, "%s/d/f", MNT);
        int keep = open(path, O_RDONLY);
        int r0 = read(keep, b, sizeof b);
        kill(d, SIGKILL);
        waitpid(d, 0, 0);
        struct stat st;
        int s = stat(path, &st), se = errno;
        int r = pread(keep, b, sizeof b, 0), re = errno;
        int u = umount2(MNT, 0), ue = errno;
        printf("read before %d; after the kill: stat %d (%s), read %d (%s); umount %d (%s)\n", r0, s, strerror(se), r, strerror(re), u, strerror(ue));
        good = r0 == 12 && s < 0 && se == ENOTCONN && r < 0 && re == ENOTCONN && u == 0;
        printf("DAEMONKILL %s\n", good ? "PASS" : "FAIL");
        return !good;
    } else if (!strcmp(m, "bench")) {
        int mb = argc > 2 ? atoi(argv[2]) : 32;
        char path[64];
        snprintf(path, sizeof path, "%s/big", MNT);
        static char chunk[128 * 1024];
        memset(chunk, 'x', sizeof chunk);
        int f = open(path, O_RDWR);
        double t = now();
        for (int i = 0; i < mb * 8; i++) if (write(f, chunk, sizeof chunk) != sizeof chunk) { perror("write"); good = 0; break; }
        double w = now() - t;
        lseek(f, 0, SEEK_SET);
        t = now();
        long got = 0;
        for (;;) { ssize_t n = read(f, chunk, sizeof chunk); if (n <= 0) break; got += n; }
        double rd = now() - t;
        close(f);
        printf("FUSEBENCH write %d MB %.1f MB/s, read %ld MB %.1f MB/s\n", mb, mb / w, got >> 20, (got >> 20) / rd);
        good = good && got == (long)mb << 20;
    }
    umount2(MNT, 0);
    waitpid(d, 0, 0);
    return !good;
}
