// FUSE: a small in-memory file system served through /dev/fuse with the raw protocol (no
// libfuse), mounted with mount(2), then used through ordinary system calls: lookup, stat,
// read, readdir, symbolic links, create and write, rename, mkdir/rmdir, truncate, mmap,
// ".." out of the mount, /proc/mounts, and unmounting (the daemon's read ends with ENODEV).
// Run as root. Build: gcc -O1 -w -o fuse_test fuse_test.c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
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

#define MAXN 64
struct node { int used, parent; char name[64]; uint32_t mode; char *data; size_t size; };
static struct node nodes[MAXN]; // node ID = index + 1 (1: the root)
static int fd;

static int add(int parent, const char *name, uint32_t mode, const char *data) {
    for (int i = 1; i < MAXN; i++)
        if (!nodes[i].used) {
            nodes[i] = (struct node){1, parent, "", mode, NULL, 0};
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

static void fill(int i, struct attr *a) {
    memset(a, 0, sizeof *a);
    a->ino = 1000 + i;
    a->mode = nodes[i].mode;
    a->nlink = S_ISDIR(nodes[i].mode) ? 2 : 1;
    a->size = nodes[i].size;
    a->blksize = 4096;
}

static void reply(uint64_t unique, int err, const void *body, size_t n) {
    struct out_header h = {sizeof h + (err ? 0 : n), err, unique};
    struct iovec v[2] = {{&h, sizeof h}, {(void *)body, err ? 0 : n}};
    writev(fd, v, err || !n ? 1 : 2);
}

static void reply_entry(uint64_t unique, int i) {
    struct entry_out e = {0};
    e.nodeid = i + 1;
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
            uint64_t size = *(uint64_t *)(arg + 16);
            uint32_t mode = *(uint32_t *)(arg + 68);
            if (valid & 8) {
                nodes[me].data = realloc(nodes[me].data, size + 1);
                if (size > nodes[me].size) memset(nodes[me].data + nodes[me].size, 0, size - nodes[me].size);
                nodes[me].size = size;
            }
            if (valid & 1) nodes[me].mode = (nodes[me].mode & S_IFMT) | (mode & 07777);
            struct attr_out a = {0};
            fill(me, &a.attr);
            reply(h->unique, 0, &a, sizeof a);
            break;
        }
        case 5: // READLINK (the kernel asks only of links)
            if (!S_ISLNK(nodes[me].mode)) reply(h->unique, -EPERM, 0, 0);
            else reply(h->unique, 0, nodes[me].data, nodes[me].size);
            break;
        case 9: { // MKDIR
            int i = add(me, arg + 8, S_IFDIR | (*(uint32_t *)arg & 07777), NULL);
            reply_entry(h->unique, i);
            break;
        }
        case 35: { // CREATE
            int i = add(me, arg + 16, S_IFREG | (*(uint32_t *)(arg + 4) & 07777), "");
            struct { struct entry_out e; uint64_t fh; uint32_t flags, pad; } r = {0};
            r.e.nodeid = i + 1;
            fill(i, &r.e.attr);
            r.fh = 77;
            reply(h->unique, 0, &r, sizeof r);
            break;
        }
        case 8: { // MKNOD
            int i = add(me, arg + 16, *(uint32_t *)arg, "");
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
            if (j >= 0) nodes[j].used = 0;
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
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            size_t have = off < nodes[me].size ? nodes[me].size - off : 0;
            reply(h->unique, 0, nodes[me].data + (have ? off : 0), have < size ? have : size);
            break;
        }
        case 16: { // WRITE
            uint64_t off = *(uint64_t *)(arg + 8);
            uint32_t size = *(uint32_t *)(arg + 16);
            char *data = arg + 40;
            if (off + size > nodes[me].size) {
                nodes[me].data = realloc(nodes[me].data, off + size + 1);
                if (off > nodes[me].size) memset(nodes[me].data + nodes[me].size, 0, off - nodes[me].size);
                nodes[me].size = off + size;
            }
            memcpy(nodes[me].data + off, data, size);
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
            const char *names[MAXN + 2];
            int inos[MAXN + 2];
            names[idx] = "."; inos[idx++] = me;
            names[idx] = ".."; inos[idx++] = nodes[me].parent;
            for (int i = 1; i < MAXN; i++)
                if (nodes[i].used && nodes[i].parent == me) { names[idx] = nodes[i].name; inos[idx++] = i; }
            for (int k = off; k < idx; k++) {
                size_t nl = strlen(names[k]), rec = (24 + nl + 7) & ~7;
                if (len + rec > size || len + rec > sizeof out) break;
                memset(out + len, 0, rec);
                *(uint64_t *)(out + len) = 1000 + inos[k];
                *(uint64_t *)(out + len + 8) = k + 1;
                *(uint32_t *)(out + len + 16) = nl;
                *(uint32_t *)(out + len + 20) = (nodes[inos[k]].mode & S_IFMT) >> 12;
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
        default: reply(h->unique, -ENOSYS, 0, 0);
        }
    }
}

// ---------------------------------------------------------------- the test

static int read_file(const char *p, char *buf, size_t n) {
    int f = open(p, O_RDONLY);
    if (f < 0) return -errno;
    int r = read(f, buf, n - 1);
    close(f);
    if (r >= 0) buf[r] = 0;
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

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *mnt = "/tmp/fusetest.mnt";
    mkdir(mnt, 0755);
    struct stat under, tmp;
    stat(mnt, &under);
    stat("/tmp", &tmp);

    fd = open("/dev/fuse", O_RDWR);
    check(fd >= 0, "open /dev/fuse");
    if (fd < 0) return 1;
    nodes[0] = (struct node){1, 0, "", S_IFDIR | 0755, NULL, 0};
    add(0, "hello", S_IFREG | 0644, "Hello FUSE\n");
    int d = add(0, "d", S_IFDIR | 0755, NULL);
    add(d, "l", S_IFLNK | 0777, "../hello");

    char opts[128];
    snprintf(opts, sizeof opts, "fd=%d,rootmode=40000,user_id=0,group_id=0", fd);
    int m = mount("fusetest", mnt, "fuse.fusetest", MS_NOSUID | MS_NODEV, opts);
    check(m == 0, "mount fuse.fusetest");
    if (m) { perror("mount"); return 1; }
    pid_t daemon = fork();
    if (daemon == 0) serve();
    close(fd);

    struct stat st;
    check(stat(mnt, &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev != tmp.st_dev, "the mount point is the daemon's root (another device)");
    char buf[256];
    check(read_file("/tmp/fusetest.mnt/hello", buf, sizeof buf) == 11 && !strcmp(buf, "Hello FUSE\n"), "read a file");
    check(stat("/tmp/fusetest.mnt/hello", &st) == 0 && st.st_size == 11 && st.st_ino == 1001, "stat: size and the daemon's inode number");
    check(dir_has(mnt, "hello") && dir_has(mnt, "d"), "readdir lists the files");
    check(read_file("/tmp/fusetest.mnt/d/l", buf, sizeof buf) == 11, "a relative symbolic link inside");
    check(readlink("/tmp/fusetest.mnt/d/l", buf, sizeof buf) == 8 && !memcmp(buf, "../hello", 8), "readlink");
    check(stat("/tmp/fusetest.mnt/nope", &st) < 0 && errno == ENOENT, "a missing name: ENOENT");
    check(readlink("/tmp/fusetest.mnt/hello", buf, sizeof buf) < 0 && errno == EINVAL && readlink(mnt, buf, sizeof buf) < 0 && errno == EINVAL, "readlink of a file or the root: EINVAL");
    char *rp = realpath("/tmp/fusetest.mnt/d/l", NULL);
    check(rp && !strcmp(rp, "/tmp/fusetest.mnt/hello"), "realpath through the mount");
    free(rp);
    check(stat("/tmp/fusetest.mnt/d/..", &st) == 0 && st.st_ino == 1000, "\"..\" inside");
    check(stat("/tmp/fusetest.mnt/..", &st) == 0 && st.st_ino == tmp.st_ino && st.st_dev == tmp.st_dev, "\"..\" from the root leaves the mount");

    int f = open("/tmp/fusetest.mnt/new", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    check(f >= 0 && write(f, "abc", 3) == 3, "create and write");
    close(f);
    check(read_file("/tmp/fusetest.mnt/new", buf, sizeof buf) == 3 && !strcmp(buf, "abc"), "read it back");
    f = open("/tmp/fusetest.mnt/new", O_WRONLY | O_APPEND);
    check(f >= 0 && write(f, "def", 3) == 3, "append");
    close(f);
    check(read_file("/tmp/fusetest.mnt/new", buf, sizeof buf) == 6 && !strcmp(buf, "abcdef"), "appended");
    check(truncate("/tmp/fusetest.mnt/new", 2) == 0 && stat("/tmp/fusetest.mnt/new", &st) == 0 && st.st_size == 2, "truncate");
    check(rename("/tmp/fusetest.mnt/new", "/tmp/fusetest.mnt/d/moved") == 0, "rename");
    check(access("/tmp/fusetest.mnt/new", F_OK) < 0 && read_file("/tmp/fusetest.mnt/d/moved", buf, sizeof buf) == 2, "renamed");
    check(rename("/tmp/fusetest.mnt/d/moved", "/tmp/moved") < 0 && errno == EXDEV, "rename out of the mount: EXDEV");
    check(mkdir("/tmp/fusetest.mnt/sub", 0700) == 0 && stat("/tmp/fusetest.mnt/sub", &st) == 0 && S_ISDIR(st.st_mode), "mkdir");
    check(rmdir("/tmp/fusetest.mnt/d") < 0 && errno == ENOTEMPTY, "rmdir of a full directory: the daemon's ENOTEMPTY");
    check(rmdir("/tmp/fusetest.mnt/sub") == 0 && unlink("/tmp/fusetest.mnt/d/moved") == 0, "rmdir and unlink");

    check(chdir("/tmp/fusetest.mnt/d") == 0, "chdir into the mount");
    check(read_file("../hello", buf, sizeof buf) == 11, "relative paths from there");
    check(read_file("l", buf, sizeof buf) == 11, "and through the link");
    int dfd = open("/tmp/fusetest.mnt", O_RDONLY | O_DIRECTORY);
    check(dfd >= 0 && fstatat(dfd, "hello", &st, 0) == 0 && st.st_size == 11, "*at() relative to a directory descriptor");
    close(dfd);
    chdir("/");

    f = open("/tmp/fusetest.mnt/hello", O_RDONLY);
    char *p = f >= 0 ? mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f, 0) : MAP_FAILED;
    check(p != MAP_FAILED && !memcmp(p, "Hello FUSE", 10), "mmap");
    if (p != MAP_FAILED) munmap(p, 4096);
    close(f);

    FILE *mf = fopen("/proc/mounts", "r");
    int listed = 0;
    while (mf && fgets(buf, sizeof buf, mf)) listed |= strstr(buf, "fusetest /tmp/fusetest.mnt fuse.fusetest") != NULL;
    if (mf) fclose(mf);
    check(listed, "/proc/mounts lists it");

    check(umount2(mnt, 0) == 0, "umount");
    int status = -1;
    waitpid(daemon, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "the daemon's read ends with ENODEV");
    check(stat(mnt, &st) == 0 && st.st_ino == under.st_ino && st.st_dev == under.st_dev, "the directory below shows again");
    rmdir(mnt);

    printf(fails ? "FUSE TEST FAILED (%d)\n" : "FUSE TEST PASSED\n", fails);
    return fails != 0;
}
