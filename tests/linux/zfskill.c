// zfskill: no acknowledged change is lost when zfs-server is killed (wave 8, Group Z).
//
//   zfskill run SECS [DIR]   for SECS seconds make files (with data), append to them,
//                            truncate, rename, link, unlink, mkdir and rmdir in DIR (default
//                            /tmp/zk), keeping a model of every change that was answered;
//                            meanwhile the test kills zfs-server (`service kill zfs_server`)
//                            as often as it likes. Then checks every name of the model: it
//                            exists, has its size, its data and the inode number it was made
//                            with, and no removed name came back.
//
// A change answered EIO (in flight at the kill) may or may not have happened: that name is
// taken out of the model (it is not checked). Any other error is counted.
// Prints "ZFSKILL ops=... lost=... PASS" or "... FAIL".
//
// Build: gcc -O1 -w -pthread tests/linux/zfskill.c -o esp/bin/zfskill.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NAMES 64
#define MAXLEN (96 * 1024)

enum { NONE, FILE_, DIR_ };

struct ent {
    int kind;        // NONE (absent, known), FILE_, DIR_, or -1 unknown (after EIO)
    uint32_t seed;   // data: byte i = pat(seed, i)
    long len;
    ino_t ino;
};

static struct ent model[NAMES];
static char dir[256];
static long ops, eio, errs, lost, wrong_data, wrong_size, wrong_ino, back, unknown;
static char first_err[256];

static void note(const char *what, const char *name, int e) {
    errs++;
    if (!first_err[0]) snprintf(first_err, sizeof first_err, "%s %s: %s", what, name, strerror(e));
}

static uint8_t pat(uint32_t seed, long i) { return (uint8_t)(seed * 131 + i * 7 + (i >> 8)); }

static void path(char *out, int i) { snprintf(out, 300, "%s/n%02d", dir, i); }

static uint32_t rnd_state = 12345;
static uint32_t rnd(void) {
    rnd_state = rnd_state * 1103515245 + 12345;
    return rnd_state >> 8;
}

static uint8_t buf[MAXLEN];

// One change's outcome: 0 done, 1 EIO (unknown), -1 other error (counted)
static int outcome(int r, const char *what, const char *name, int i) {
    if (r == 0) return 0;
    if (errno == EIO) {
        eio++;
        model[i].kind = -1;
        return 1;
    }
    note(what, name, errno);
    model[i].kind = -1;
    return -1;
}

static void step(void) {
    int i = rnd() % NAMES;
    char p[300], q[300];
    path(p, i);
    struct ent *e = &model[i];
    ops++;
    if (e->kind == -1) {
        // Unknown after an EIO: find out what is there now and continue from that
        struct stat st;
        if (lstat(p, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (rmdir(p) == 0) e->kind = NONE;
            } else if (unlink(p) == 0) {
                e->kind = NONE;
            }
        } else if (errno == ENOENT) {
            e->kind = NONE;
        }
        return;
    }
    if (e->kind == NONE) {
        if (rnd() % 4 == 0) {
            if (outcome(mkdir(p, 0755), "mkdir", p, i) == 0) {
                struct stat st;
                // (a stat that fails, e.g. EIO at a kill: the inode is not known)
                e->kind = stat(p, &st) == 0 ? DIR_ : -1;
                e->ino = st.st_ino;
            }
            return;
        }
        uint32_t seed = rnd();
        long len = rnd() % MAXLEN;
        for (long k = 0; k < len; k++) buf[k] = pat(seed, k);
        int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0) {
            outcome(-1, "create", p, i);
            return;
        }
        struct stat st;
        if (fstat(fd, &st)) {
            close(fd);
            outcome(-1, "fstat", p, i);
            return;
        }
        // The file exists from here on (with whatever data got written)
        e->kind = FILE_;
        e->ino = st.st_ino;
        e->seed = seed;
        e->len = 0;
        ssize_t w = write(fd, buf, len);
        int we = errno;
        close(fd);
        if (w != len) {
            errno = w < 0 ? we : EIO;
            outcome(-1, "write", p, i);
            return;
        }
        e->len = len;
        return;
    }
    if (e->kind == DIR_) {
        if (outcome(rmdir(p), "rmdir", p, i) == 0) e->kind = NONE;
        return;
    }
    // A file: append, truncate, rename onto a free name, hard link + unlink, or unlink
    switch (rnd() % 5) {
    case 0: {
        long add = rnd() % 8192;
        if (e->len + add > MAXLEN) add = MAXLEN - e->len;
        for (long k = 0; k < add; k++) buf[k] = pat(e->seed, e->len + k);
        int fd = open(p, O_WRONLY | O_APPEND);
        if (fd < 0) { outcome(-1, "open append", p, i); return; }
        ssize_t w = write(fd, buf, add);
        int we = errno;
        close(fd);
        if (w != add) { errno = w < 0 ? we : EIO; outcome(-1, "append", p, i); return; }
        e->len += add;
        return;
    }
    case 1: {
        long nl = e->len ? rnd() % e->len : 0;
        if (outcome(truncate(p, nl), "truncate", p, i) == 0) e->len = nl;
        return;
    }
    case 2:
    case 3: {
        int j = rnd() % NAMES;
        if (j == i || model[j].kind != NONE) return;
        path(q, j);
        int hard = rnd() % 2;
        if (hard) {
            if (link(p, q)) { outcome(-1, "link", q, j); return; }
            model[j] = *e;
            if (outcome(unlink(p), "unlink old", p, i) == 0) e->kind = NONE;
            return;
        }
        if (rename(p, q)) {
            int er = errno;
            // Either name may hold it now
            model[j].kind = -1;
            errno = er;
            outcome(-1, "rename", p, i);
            return;
        }
        model[j] = *e;
        e->kind = NONE;
        return;
    }
    default:
        if (outcome(unlink(p), "unlink", p, i) == 0) e->kind = NONE;
        return;
    }
}

static void check(void) {
    static uint8_t got[MAXLEN + 1];
    for (int i = 0; i < NAMES; i++) {
        char p[300];
        path(p, i);
        struct ent *e = &model[i];
        struct stat st;
        int r = lstat(p, &st);
        if (e->kind == -1) { unknown++; continue; }
        if (e->kind == NONE) {
            if (r == 0) { back++; if (!first_err[0]) snprintf(first_err, sizeof first_err, "removed name is back: %s", p); }
            continue;
        }
        if (r) {
            lost++;
            if (!first_err[0]) snprintf(first_err, sizeof first_err, "lost %s %s: %s", e->kind == DIR_ ? "dir" : "file", p, strerror(errno));
            continue;
        }
        if (st.st_ino != e->ino) {
            wrong_ino++;
            if (!first_err[0]) snprintf(first_err, sizeof first_err, "inode of %s: %lu, made as %lu", p, (unsigned long)st.st_ino, (unsigned long)e->ino);
        }
        if (e->kind == DIR_) {
            if (!S_ISDIR(st.st_mode)) wrong_data++;
            continue;
        }
        if (st.st_size != e->len) {
            wrong_size++;
            if (!first_err[0]) snprintf(first_err, sizeof first_err, "size of %s: %ld, expected %ld", p, (long)st.st_size, e->len);
            continue;
        }
        int fd = open(p, O_RDONLY);
        long n = fd < 0 ? -1 : 0;
        while (fd >= 0 && n < (long)sizeof got) {
            ssize_t k = read(fd, got + n, sizeof got - n);
            if (k <= 0) break;
            n += k;
        }
        if (fd >= 0) close(fd);
        int ok = n == e->len;
        for (long k = 0; ok && k < n; k++) ok = got[k] == pat(e->seed, k);
        if (!ok) {
            wrong_data++;
            if (!first_err[0]) snprintf(first_err, sizeof first_err, "data of %s (%ld bytes read)", p, n);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "run")) {
        fprintf(stderr, "usage: zfskill run SECS [DIR]\n");
        return 2;
    }
    int secs = atoi(argv[2]);
    snprintf(dir, sizeof dir, "%s", argc > 3 ? argv[3] : "/tmp/zk");
    char cmd[300];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    system(cmd);
    if (mkdir(dir, 0755)) { perror("mkdir"); return 1; }
    rnd_state = (uint32_t)time(0);
    printf("ZFSKILL-STARTED %d s in %s\n", secs, dir);
    fflush(stdout);
    time_t end = time(0) + secs;
    long last_print = 0;
    while (time(0) < end) {
        step();
        if (time(0) - last_print >= 10) {
            last_print = time(0);
            printf("ZFSKILL progress ops=%ld eio=%ld errs=%ld\n", ops, eio, errs);
            fflush(stdout);
        }
    }
    check();
    printf("ZFSKILL ops=%ld eio=%ld change_err=%ld lost=%ld wrong_size=%ld wrong_data=%ld wrong_ino=%ld back=%ld unknown=%ld%s%s\n", ops, eio, errs, lost, wrong_size,
           wrong_data, wrong_ino, back, unknown, first_err[0] ? " first_err=" : "", first_err);
    int ok = errs == 0 && lost == 0 && wrong_size == 0 && wrong_data == 0 && wrong_ino == 0 && back == 0 && ops > 0;
    printf("ZFSKILL %s\n", ok ? "PASS" : "FAIL");
    if (ok) system(cmd);
    return !ok;
}
