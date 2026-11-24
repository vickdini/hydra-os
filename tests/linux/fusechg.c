// FUSE changes (wave 11, Group F): every change inside a FUSE mount through a small raw-protocol
// daemon (no libfuse): create (O_EXCL, O_TRUNC), mkdir, mknod, symlink, link, unlink, rmdir,
// rename (over a name, RENAME_NOREPLACE, EXDEV), chmod/fchmod/chown/truncate/ftruncate/utimensat,
// the xattr calls (path and descriptor), statfs/fstatfs, *at() relative to a FUSE directory
// descriptor, a working directory in the mount, O_PATH, and the permission rules for a user
// (search/write on the directory, the sticky bit). Run as root.
//   fusechg             the checks
//   fusechg ns ...      the same in a mount namespace of its own
//   fusechg bench N     microseconds per create+close, rename, unlink, chmod, stat (N rounds)
//   fusechg loop SECS   creates, writes, renames, reads back and unlinks for SECS seconds
//                       (for `service kill vfs_server` meanwhile); counts the failed rounds
// Build: gcc -O1 -w -o fusechg fusechg.c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

// ---------------------------------------------------------------- the daemon

struct in_header { uint32_t len, opcode; uint64_t unique, nodeid; uint32_t uid, gid, pid; uint16_t extlen, pad; };
struct out_header { uint32_t len; int32_t error; uint64_t unique; };
struct attr {
    uint64_t ino, size, blocks, atime, mtime, ctime;
    uint32_t atimensec, mtimensec, ctimensec, mode, nlink, uid, gid, rdev, blksize, flags;
};
struct entry_out { uint64_t nodeid, generation, entry_valid, attr_valid; uint32_t entry_valid_nsec, attr_valid_nsec; struct attr attr; };
struct attr_out { uint64_t attr_valid; uint32_t attr_valid_nsec, dummy; struct attr attr; };

#define MAXN 512
// A name: `target` is the object it names (itself, or another name's object for a hard link)
struct node {
    int used, parent, target;
    char name[64];
    uint32_t mode, uid, gid;
    uint64_t mtime;
    char *data;
    size_t size;
    char xname[64], xval[64];
    int xlen, xhas;
};
static struct node nodes[MAXN]; // node ID = index + 1 (1: the root)
static int fd;

static int add(int parent, const char *name, uint32_t mode, const char *data, uint32_t uid, uint32_t gid) {
    for (int i = 1; i < MAXN; i++)
        if (!nodes[i].used) {
            nodes[i] = (struct node){1, parent, i, "", mode, uid, gid};
            snprintf(nodes[i].name, sizeof nodes[i].name, "%s", name);
            if (data) {
                nodes[i].size = strlen(data);
                nodes[i].data = malloc(nodes[i].size + 1);
                memcpy(nodes[i].data, data, nodes[i].size);
            }
            return i;
        }
    return -1;
}

static int find(int dir, const char *name) {
    for (int i = 1; i < MAXN; i++)
        if (nodes[i].used && nodes[i].parent == dir && !strcmp(nodes[i].name, name)) return i;
    return -1;
}

static int links_of(int t) {
    int n = 0;
    for (int i = 0; i < MAXN; i++) n += nodes[i].used && nodes[i].target == t;
    return n;
}

static void fill(int i, struct attr *a) {
    int t = nodes[i].target;
    memset(a, 0, sizeof *a);
    a->ino = 1000 + t;
    a->mode = nodes[t].mode;
    a->nlink = S_ISDIR(nodes[t].mode) ? 2 : links_of(t);
    a->size = nodes[t].size;
    a->uid = nodes[t].uid;
    a->gid = nodes[t].gid;
    a->mtime = nodes[t].mtime;
    a->blksize = 4096;
}

static void reply(uint64_t unique, int err, const void *body, size_t n) {
    struct out_header h = {sizeof h + (err ? 0 : n), err, unique};
    struct iovec v[2] = {{&h, sizeof h}, {(void *)body, err ? 0 : n}};
    writev(fd, v, err || !n ? 1 : 2);
}

static void reply_entry(uint64_t unique, int i) {
    if (i < 0) { reply(unique, -ENOSPC, 0, 0); return; }
    struct entry_out e = {0};
    e.nodeid = nodes[i].target + 1;
    fill(i, &e.attr);
    reply(unique, 0, &e, sizeof e);
}

static void serve(void) {
    static char buf[1 << 20 | 4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) exit(n < 0 && errno == ENODEV ? 0 : 3);
        struct in_header *h = (void *)buf;
        char *arg = buf + sizeof *h;
        int me = h->nodeid - 1;
        switch (h->opcode) {
        case 26: { // INIT
            uint32_t out[6] = {7, 12, 128 * 1024, 0, 0, 1 << 16};
            reply(h->unique, 0, out, sizeof out);
            break;
        }
        case 1: { // LOOKUP
            int i = find(me, arg);
            if (i < 0) reply(h->unique, -ENOENT, 0, 0);
            else reply_entry(h->unique, i);
            break;
        }
        case 2: case 42: break; // FORGET, BATCH_FORGET: no reply
        case 3: { // GETATTR
            struct attr_out a = {0};
            fill(me, &a.attr);
            reply(h->unique, 0, &a, sizeof a);
            break;
        }
        case 4: { // SETATTR
            uint32_t valid = *(uint32_t *)arg;
            uint64_t size = *(uint64_t *)(arg + 16), mtime = *(uint64_t *)(arg + 40);
            uint32_t mode = *(uint32_t *)(arg + 68), uid = *(uint32_t *)(arg + 76), gid = *(uint32_t *)(arg + 80);
            struct node *t = &nodes[nodes[me].target];
            if (valid & 8) {
                t->data = realloc(t->data, size + 1);
                if (size > t->size) memset(t->data + t->size, 0, size - t->size);
                t->size = size;
            }
            if (valid & 1) t->mode = (t->mode & S_IFMT) | (mode & 07777);
            if (valid & 2) t->uid = uid;
            if (valid & 4) t->gid = gid;
            if (valid & 32) t->mtime = mtime;
            struct attr_out a = {0};
            fill(me, &a.attr);
            reply(h->unique, 0, &a, sizeof a);
            break;
        }
        case 5: // READLINK
            if (!S_ISLNK(nodes[me].mode)) reply(h->unique, -EINVAL, 0, 0);
            else reply(h->unique, 0, nodes[me].data, nodes[me].size);
            break;
        case 6: { // SYMLINK: name, target
            char *to = arg + strlen(arg) + 1;
            reply_entry(h->unique, add(me, arg, S_IFLNK | 0777, to, h->uid, h->gid));
            break;
        }
        case 9: // MKDIR
            reply_entry(h->unique, add(me, arg + 8, S_IFDIR | (*(uint32_t *)arg & 07777), NULL, h->uid, h->gid));
            break;
        case 35: { // CREATE
            int i = add(me, arg + 16, S_IFREG | (*(uint32_t *)(arg + 4) & 07777), "", h->uid, h->gid);
            if (i < 0) { reply(h->unique, -ENOSPC, 0, 0); break; }
            struct { struct entry_out e; uint64_t fh; uint32_t flags, pad; } r = {0};
            r.e.nodeid = i + 1;
            fill(i, &r.e.attr);
            r.fh = 77;
            reply(h->unique, 0, &r, sizeof r);
            break;
        }
        case 8: // MKNOD
            reply_entry(h->unique, add(me, arg + 16, *(uint32_t *)arg, "", h->uid, h->gid));
            break;
        case 13: { // LINK: oldnodeid, name
            int old = *(uint64_t *)arg - 1;
            int i = add(me, arg + 8, 0, NULL, 0, 0);
            if (i >= 0) nodes[i].target = nodes[old].target;
            reply_entry(h->unique, i);
            break;
        }
        case 10: case 11: { // UNLINK, RMDIR
            int i = find(me, arg);
            if (i < 0) { reply(h->unique, -ENOENT, 0, 0); break; }
            if (h->opcode == 11) {
                for (int k = 1; k < MAXN; k++)
                    if (nodes[k].used && nodes[k].parent == i) { i = -2; break; }
                if (i == -2) { reply(h->unique, -ENOTEMPTY, 0, 0); break; }
            }
            // (an object with other names stays: the name goes to one of them)
            int t = nodes[i].target;
            if (t == i && links_of(t) > 1) {
                for (int k = 1; k < MAXN; k++)
                    if (k != i && nodes[k].used && nodes[k].target == t) {
                        int parent = nodes[k].parent;
                        char name[64];
                        memcpy(name, nodes[k].name, 64);
                        nodes[k] = nodes[i];
                        nodes[k].parent = parent;
                        memcpy(nodes[k].name, name, 64);
                        nodes[k].target = k;
                        for (int j = 1; j < MAXN; j++)
                            if (nodes[j].used && nodes[j].target == i) nodes[j].target = k;
                        break;
                    }
            }
            nodes[i].used = 0;
            reply(h->unique, 0, 0, 0);
            break;
        }
        case 12: case 45: { // RENAME, RENAME2
            uint64_t newdir = *(uint64_t *)arg;
            char *old = arg + (h->opcode == 12 ? 8 : 16), *new = old + strlen(old) + 1;
            int i = find(me, old);
            if (i < 0) { reply(h->unique, -ENOENT, 0, 0); break; }
            int j = find(newdir - 1, new);
            if (j >= 0 && j != i) nodes[j].used = 0;
            nodes[i].parent = newdir - 1;
            snprintf(nodes[i].name, sizeof nodes[i].name, "%s", new);
            reply(h->unique, 0, 0, 0);
            break;
        }
        case 14: case 27: { // OPEN, OPENDIR
            uint64_t out[2] = {me + 100, 0};
            reply(h->unique, 0, out, sizeof out);
            break;
        }
        case 15: { // READ
            struct node *t = &nodes[nodes[me].target];
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            size_t have = off < t->size ? t->size - off : 0;
            reply(h->unique, 0, t->data + (have ? off : 0), have < size ? have : size);
            break;
        }
        case 16: { // WRITE
            struct node *t = &nodes[nodes[me].target];
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            char *data = arg + 40;
            if (off + size > t->size) {
                t->data = realloc(t->data, off + size + 1);
                if (off > t->size) memset(t->data + t->size, 0, off - t->size);
                t->size = off + size;
            }
            memcpy(t->data + off, data, size);
            uint32_t out[2] = {size, 0};
            reply(h->unique, 0, out, sizeof out);
            break;
        }
        case 28: { // READDIR: offset = index of the next entry
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            static char out[65536];
            size_t len = 0;
            int idx = 0;
            static const char *names[MAXN + 2];
            static int inos[MAXN + 2];
            names[idx] = "."; inos[idx++] = me;
            names[idx] = ".."; inos[idx++] = nodes[me].parent;
            for (int i = 1; i < MAXN; i++)
                if (nodes[i].used && nodes[i].parent == me) { names[idx] = nodes[i].name; inos[idx++] = i; }
            for (int k = off; k < idx; k++) {
                size_t nl = strlen(names[k]), rec = (24 + nl + 7) & ~7;
                if (len + rec > size || len + rec > sizeof out) break;
                memset(out + len, 0, rec);
                *(uint64_t *)(out + len) = 1000 + nodes[inos[k]].target;
                *(uint64_t *)(out + len + 8) = k + 1;
                *(uint32_t *)(out + len + 16) = nl;
                *(uint32_t *)(out + len + 20) = (nodes[nodes[inos[k]].target].mode & S_IFMT) >> 12;
                memcpy(out + len + 24, names[k], nl);
                len += rec;
            }
            reply(h->unique, 0, out, len);
            break;
        }
        case 18: case 25: case 29: case 20: case 30: reply(h->unique, 0, 0, 0); break; // RELEASE, FLUSH, RELEASEDIR, FSYNC(DIR)
        case 17: { // STATFS
            uint64_t st[10] = {1000, 500, 500, 100, 50};
            ((uint32_t *)st)[10] = 4096;
            ((uint32_t *)st)[11] = 255;
            reply(h->unique, 0, st, 80);
            break;
        }
        case 21: { // SETXATTR: size, flags, name, value
            struct node *t = &nodes[nodes[me].target];
            uint32_t size = *(uint32_t *)arg, flags = *(uint32_t *)(arg + 4);
            char *name = arg + 8, *val = name + strlen(name) + 1;
            int same = t->xhas && !strcmp(t->xname, name);
            if ((flags & XATTR_CREATE) && same) { reply(h->unique, -EEXIST, 0, 0); break; }
            if ((flags & XATTR_REPLACE) && !same) { reply(h->unique, -ENODATA, 0, 0); break; }
            if (size > sizeof t->xval) { reply(h->unique, -E2BIG, 0, 0); break; }
            snprintf(t->xname, sizeof t->xname, "%s", name);
            memcpy(t->xval, val, size);
            t->xlen = size;
            t->xhas = 1;
            reply(h->unique, 0, 0, 0);
            break;
        }
        case 22: case 23: { // GETXATTR (size, pad, name), LISTXATTR (size, pad)
            struct node *t = &nodes[nodes[me].target];
            uint32_t size = *(uint32_t *)arg;
            const char *v;
            uint32_t len;
            if (h->opcode == 22) {
                if (!t->xhas || strcmp(t->xname, arg + 8)) { reply(h->unique, -ENODATA, 0, 0); break; }
                v = t->xval;
                len = t->xlen;
            } else {
                v = t->xname;
                len = t->xhas ? strlen(t->xname) + 1 : 0;
            }
            if (size == 0) {
                uint32_t out[2] = {len, 0};
                reply(h->unique, 0, out, sizeof out);
            } else if (len > size) {
                reply(h->unique, -ERANGE, 0, 0);
            } else {
                reply(h->unique, 0, v, len);
            }
            break;
        }
        case 24: { // REMOVEXATTR
            struct node *t = &nodes[nodes[me].target];
            if (!t->xhas || strcmp(t->xname, arg)) { reply(h->unique, -ENODATA, 0, 0); break; }
            t->xhas = 0;
            reply(h->unique, 0, 0, 0);
            break;
        }
        default: reply(h->unique, -ENOSYS, 0, 0);
        }
    }
}

// ---------------------------------------------------------------- the test

static const char *mnt = "/tmp/fusechg.mnt";

static int read_file(const char *p, char *buf, size_t n) {
    int f = open(p, O_RDONLY);
    if (f < 0) return -errno;
    int r = read(f, buf, n - 1);
    close(f);
    if (r >= 0) buf[r] = 0;
    return r;
}

static int write_file(const char *p, const char *s, int flags) {
    int f = open(p, O_WRONLY | flags, 0644);
    if (f < 0) return -errno;
    int r = write(f, s, strlen(s));
    close(f);
    return r;
}

static int dir_has(const char *dir, const char *name) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) found |= !strcmp(e->d_name, name);
    closedir(d);
    return found;
}

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static char P[4][256];
static int pi;
static const char *at(const char *rel) {
    char *p = P[pi++ & 3];
    snprintf(p, 256, "%s/%s", mnt, rel);
    return p;
}

static void checks(void) {
    struct stat st;
    char buf[256], b2[256];
    // making and opening
    check(mkdir(at("d"), 0755) == 0 && stat(at("d"), &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755, "mkdir (mode, umask 0)");
    int f = open(at("d/f"), O_CREAT | O_EXCL | O_RDWR, 0644);
    check(f >= 0 && write(f, "hello", 5) == 5, "create (O_EXCL) and write");
    check(f >= 0 && fstat(f, &st) == 0 && st.st_size == 5 && S_ISREG(st.st_mode), "fstat of the new descriptor");
    close(f);
    check(open(at("d/f"), O_CREAT | O_EXCL | O_RDWR, 0644) < 0 && errno == EEXIST, "O_CREAT|O_EXCL of an existing name: EEXIST");
    f = open(at("d/f"), O_CREAT | O_RDWR, 0644);
    check(f >= 0 && read(f, buf, 5) == 5 && !memcmp(buf, "hello", 5), "O_CREAT of an existing name opens it");
    close(f);
    check(write_file(at("d/f"), "abc", O_TRUNC) == 3 && read_file(at("d/f"), buf, sizeof buf) == 3 && !strcmp(buf, "abc"), "O_TRUNC open truncates");
    umask(022);
    check(mkdir(at("d/um"), 0777) == 0 && stat(at("d/um"), &st) == 0 && (st.st_mode & 0777) == 0755, "mkdir applies the umask");
    f = open(at("d/um/c"), O_CREAT | O_WRONLY, 0666);
    check(f >= 0 && fstat(f, &st) == 0 && (st.st_mode & 0777) == 0644, "create applies the umask");
    close(f);
    umask(0);
    check(mknod(at("d/n"), S_IFREG | 0600, 0) == 0 && stat(at("d/n"), &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600, "mknod of a regular file");
    check(mkfifo(at("d/p"), 0644) == 0 && stat(at("d/p"), &st) == 0 && S_ISFIFO(st.st_mode), "mkfifo (the daemon's node)");
    // attributes
    check(chmod(at("d/f"), 0600) == 0 && stat(at("d/f"), &st) == 0 && (st.st_mode & 07777) == 0600, "chmod");
    f = open(at("d/f"), O_RDWR);
    check(f >= 0 && fchmod(f, 0640) == 0 && fstat(f, &st) == 0 && (st.st_mode & 07777) == 0640, "fchmod of a FUSE descriptor");
    check(ftruncate(f, 2) == 0 && fstat(f, &st) == 0 && st.st_size == 2, "ftruncate");
    struct statfs sf;
    check(fstatfs(f, &sf) == 0 && sf.f_type == 0x65735546 && sf.f_bsize == 4096 && sf.f_blocks == 1000, "fstatfs of a FUSE descriptor: the daemon's figures");
    check(fsetxattr(f, "user.k", "fv", 2, 0) == 0 && fgetxattr(f, "user.k", buf, sizeof buf) == 2 && !memcmp(buf, "fv", 2), "fsetxattr, fgetxattr");
    check(fchown(f, 1000, 1000) == 0 && fstat(f, &st) == 0 && st.st_uid == 1000 && st.st_gid == 1000, "fchown");
    close(f);
    check(truncate(at("d/f"), 10) == 0 && stat(at("d/f"), &st) == 0 && st.st_size == 10, "truncate (longer)");
    check(chown(at("d/f"), 0, 0) == 0 && stat(at("d/f"), &st) == 0 && st.st_uid == 0, "chown");
    struct timespec ts[2] = {{1000, 0}, {123456789, 0}};
    check(utimensat(AT_FDCWD, at("d/f"), ts, 0) == 0 && stat(at("d/f"), &st) == 0 && st.st_mtime == 123456789, "utimensat");
    check(statfs(at("d/f"), &sf) == 0 && sf.f_type == 0x65735546 && sf.f_bfree == 500, "statfs of a path");
    // names
    check(symlink("f", at("d/l")) == 0 && readlink(at("d/l"), buf, sizeof buf) == 1 && buf[0] == 'f', "symlink, readlink");
    check(stat(at("d/l"), &st) == 0 && st.st_size == 10, "stat through it");
    check(link(at("d/f"), at("d/h")) == 0 && stat(at("d/h"), &st) == 0 && st.st_nlink == 2 && st.st_size == 10, "link (two names)");
    check(write_file(at("d/h"), "XY", 0) == 2 && read_file(at("d/f"), buf, 3) == 2 && !memcmp(buf, "XY", 2), "one object behind both names");
    check(rename(at("d/h"), at("d/h2")) == 0 && access(at("d/h"), F_OK) < 0 && access(at("d/h2"), F_OK) == 0, "rename");
    check(rename(at("d/h2"), at("d/n")) == 0 && stat(at("d/n"), &st) == 0 && st.st_size == 10, "rename over an existing name");
    check(syscall(SYS_renameat2, AT_FDCWD, at("d/n"), AT_FDCWD, at("d/l"), 1) < 0 && errno == EEXIST, "renameat2 RENAME_NOREPLACE: EEXIST");
    check(rename(at("d/n"), "/tmp/fusechg.out") < 0 && errno == EXDEV, "rename out of the mount: EXDEV");
    check(link(at("d/n"), "/tmp/fusechg.out") < 0 && errno == EXDEV, "link out of the mount: EXDEV");
    check(mkdir(at("d/sub"), 0700) == 0 && rename(at("d/n"), at("d/sub/n")) == 0 && access(at("d/sub/n"), F_OK) == 0, "rename into another directory");
    check(rmdir(at("d/sub")) < 0 && errno == ENOTEMPTY, "rmdir of a full directory: ENOTEMPTY");
    check(unlink(at("d/sub/n")) == 0 && rmdir(at("d/sub")) == 0 && !dir_has(at("d"), "sub"), "unlink, rmdir");
    check(unlink(at("d")) < 0 && (errno == EISDIR || errno == EPERM), "unlink of a directory refused");
    check(rmdir(at("d/f")) < 0 && errno == ENOTDIR, "rmdir of a file: ENOTDIR");
    check(mkdir(at("d/x"), 0755) == 0 && rename(at("d/x"), at("d/x/y")) < 0 && errno == EINVAL, "rename of a directory below itself: EINVAL");
    check(rename(at("d/x"), at("d/f")) < 0 && errno == ENOTDIR, "rename of a directory over a file: ENOTDIR");
    check(rename(at("d/f"), at("d/x")) < 0 && errno == EISDIR, "rename of a file over a directory: EISDIR");
    check(rename(at("d/f"), at("d/f")) == 0 && access(at("d/f"), F_OK) == 0, "rename onto itself: nothing happens");
    check(rmdir(at("d/x")) == 0 && mkdir(at("d/."), 0755) < 0 && errno == EEXIST, "mkdir of \".\": EEXIST");
    check(mkdir(at("d/f"), 0755) < 0 && errno == EEXIST, "mkdir of an existing name: EEXIST");
    check(unlink(at("d/missing")) < 0 && errno == ENOENT, "unlink of a missing name: ENOENT");
    // xattrs by path
    check(setxattr(at("d/f"), "user.t", "v1", 2, 0) == 0, "setxattr");
    check(getxattr(at("d/f"), "user.t", NULL, 0) == 2, "getxattr size");
    check(getxattr(at("d/f"), "user.t", buf, sizeof buf) == 2 && !memcmp(buf, "v1", 2), "getxattr value");
    check(getxattr(at("d/f"), "user.t", buf, 1) < 0 && errno == ERANGE, "getxattr into a short buffer: ERANGE");
    check(setxattr(at("d/f"), "user.t", "v2", 2, XATTR_CREATE) < 0 && errno == EEXIST, "XATTR_CREATE of an existing one: EEXIST");
    ssize_t ln = listxattr(at("d/f"), buf, sizeof buf);
    check(ln == 7 && !strcmp(buf, "user.t"), "listxattr");
    check(listxattr(at("d/f"), NULL, 0) == 7, "listxattr size");
    check(removexattr(at("d/f"), "user.t") == 0 && getxattr(at("d/f"), "user.t", buf, sizeof buf) < 0 && errno == ENODATA, "removexattr");
    {
        int r = setxattr(at("d/f"), "system.posix_acl_access", "x", 1, 0);
        // (Linux 5.15 passes the name to a daemon without posix_acl; newer ones refuse it)
        check(r == 0 || errno == EOPNOTSUPP, "POSIX ACL names: the daemon's xattrs (or EOPNOTSUPP)");
    }
    // relative to a FUSE directory descriptor
    int dfd = open(at("d"), O_RDONLY | O_DIRECTORY);
    check(dfd >= 0, "open the directory");
    f = openat(dfd, "g", O_CREAT | O_WRONLY, 0644);
    check(f >= 0 && write(f, "gg", 2) == 2, "openat(O_CREAT) relative to it");
    close(f);
    check(fstatat(dfd, "g", &st, 0) == 0 && st.st_size == 2, "fstatat relative to it");
    check(mkdirat(dfd, "md", 0700) == 0 && fchmodat(dfd, "md", 0750, 0) == 0 && fstatat(dfd, "md", &st, 0) == 0 && (st.st_mode & 0777) == 0750, "mkdirat, fchmodat");
    check(renameat(dfd, "g", dfd, "md/g") == 0 && unlinkat(dfd, "md/g", 0) == 0 && unlinkat(dfd, "md", AT_REMOVEDIR) == 0, "renameat, unlinkat");
    check(symlinkat("f", dfd, "l2") == 0 && readlinkat(dfd, "l2", buf, sizeof buf) == 1 && unlinkat(dfd, "l2", 0) == 0, "symlinkat, readlinkat");
    check(linkat(dfd, "f", dfd, "f2", 0) == 0 && unlinkat(dfd, "f2", 0) == 0, "linkat");
    // a working directory in the mount
    check(fchdir(dfd) == 0, "fchdir into the mount");
    check(getcwd(buf, sizeof buf) && !strcmp(buf, at("d")), "getcwd there");
    check(write_file("rel", "r", O_CREAT) == 1 && read_file("rel", b2, sizeof b2) == 1 && unlink("rel") == 0, "relative create, read, unlink from there");
    check(mkdir("rd", 0755) == 0 && chdir("rd") == 0 && getcwd(buf, sizeof buf) && !strcmp(buf, at("d/rd")) && chdir("..") == 0 && rmdir("rd") == 0, "chdir by path inside it");
    chdir("/");
    close(dfd);
    // O_PATH
    f = open(at("d/f"), O_PATH);
    check(f >= 0 && fstat(f, &st) == 0 && st.st_size == 10, "O_PATH open, fstat");
    close(f);
    // an open file whose name goes
    f = open(at("d/f"), O_RDONLY);
    check(f >= 0 && unlink(at("d/l")) == 0, "unlink while another file is open");
    close(f);
    // a user's rights
    check(mkdir(at("t"), 01777) == 0 && chmod(at("t"), 01777) == 0, "a sticky world-writable directory");
    check(write_file(at("t/rootf"), "x", O_CREAT) == 1, "root's file in it");
    pid_t p = fork();
    if (p == 0) {
        setgid(1000);
        setuid(1000);
        int bad = 0;
        if (mkdir(at("d/u"), 0755) == 0 || errno != EACCES) bad |= 1;             // d is root's 0755
        if (open(at("d/u2"), O_CREAT | O_WRONLY, 0644) >= 0 || errno != EACCES) bad |= 2;
        if (unlink(at("d/f")) == 0 || errno != EACCES) bad |= 4;
        if (unlink(at("t/rootf")) == 0 || errno != EPERM) bad |= 8;               // sticky
        if (write_file(at("t/mine"), "m", O_CREAT) != 1 || unlink(at("t/mine")) != 0) bad |= 16;
        if (chmod(at("d/f"), 0777) == 0 || errno != EPERM) bad |= 32;              // not the owner
        if (setxattr(at("d/f"), "user.u", "1", 1, 0) == 0 || errno != EACCES) bad |= 64; // no write right
        if (truncate(at("d/f"), 0) == 0 || errno != EACCES) bad |= 128;
        _exit(bad);
    }
    int status = -1;
    waitpid(p, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status)) printf("     (user: status %#x)\n", status);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "a user: EACCES without write right, EPERM in a sticky directory and for chmod, own files fine");
    unlink(at("t/rootf"));
    rmdir(at("t"));
}

static void bench(int n) {
    double t0, tc = 0, tr = 0, tu = 0, tm = 0, ts = 0;
    char a[64], b[64];
    struct stat st;
    mkdir(at("b"), 0755);
    for (int i = 0; i < n; i++) {
        snprintf(a, sizeof a, "%s/b/x%d", mnt, i);
        snprintf(b, sizeof b, "%s/b/y%d", mnt, i);
        t0 = now_us();
        int f = open(a, O_CREAT | O_WRONLY | O_EXCL, 0644);
        close(f);
        tc += now_us() - t0;
        t0 = now_us();
        chmod(a, 0600);
        tm += now_us() - t0;
        t0 = now_us();
        rename(a, b);
        tr += now_us() - t0;
        t0 = now_us();
        stat(b, &st);
        ts += now_us() - t0;
        t0 = now_us();
        unlink(b);
        tu += now_us() - t0;
    }
    rmdir(at("b"));
    printf("FUSECHG BENCH n=%d create+close %.2f rename %.2f unlink %.2f chmod %.2f stat %.2f us\n", n, tc / n, tr / n, tu / n, tm / n, ts / n);
}

static void loop(int secs) {
    double end = now_us() + secs * 1e6;
    long rounds = 0, bad = 0;
    char a[64], b[64], buf[64];
    mkdir(at("k"), 0755);
    while (now_us() < end) {
        snprintf(a, sizeof a, "%s/k/a%ld", mnt, rounds % 8);
        snprintf(b, sizeof b, "%s/k/b%ld", mnt, rounds % 8);
        int ok = write_file(a, "payload", O_CREAT | O_TRUNC) == 7 && rename(a, b) == 0 && read_file(b, buf, sizeof buf) == 7 && !strcmp(buf, "payload") && chmod(b, 0600) == 0 && unlink(b) == 0;
        if (!ok) {
            if (bad < 10) printf("     round %ld failed: errno %d\n", rounds, errno);
            bad++;
            unlink(a);
            unlink(b);
        }
        rounds++;
    }
    printf("FUSECHG LOOP rounds %ld failed %ld\n", rounds, bad);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    umask(0);
    mkdir(mnt, 0755);
    // `fusechg ns`: the same checks with the file system mounted in a mount namespace of the
    // test's own (bubblewrap's and flatpak's case)
    int ns = argc > 1 && !strcmp(argv[1], "ns");
    if (ns) {
        check(unshare(CLONE_NEWNS) == 0 && mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "a mount namespace of its own");
        argc--;
        argv++;
    }
    fd = open("/dev/fuse", O_RDWR);
    check(fd >= 0, "open /dev/fuse");
    if (fd < 0) return 1;
    nodes[0] = (struct node){1, 0, 0, "", S_IFDIR | 0755};
    char opts[128];
    snprintf(opts, sizeof opts, "fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other,default_permissions", fd);
    int m = mount("fusechg", mnt, "fuse.fusechg", MS_NOSUID | MS_NODEV, opts);
    check(m == 0, "mount fuse.fusechg");
    if (m) { perror("mount"); return 1; }
    pid_t daemon = fork();
    if (daemon == 0) serve();
    close(fd);
    if (argc > 2 && !strcmp(argv[1], "bench")) bench(atoi(argv[2]));
    else if (argc > 2 && !strcmp(argv[1], "loop")) loop(atoi(argv[2]));
    else checks();
    check(umount2(mnt, 0) == 0, "umount");
    int status = -1;
    waitpid(daemon, &status, 0);
    rmdir(mnt);
    printf(fails ? "FUSECHG TEST FAILED (%d)\n" : "FUSECHG TEST PASSED\n", fails);
    return fails != 0;
}
