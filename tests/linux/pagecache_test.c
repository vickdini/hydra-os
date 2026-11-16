// The kernel's page cache stays coherent: whatever path a change takes (write, pwrite on
// another descriptor, a shared mapping, ftruncate, rename over the file, unlink), the next
// read sees the file as it is now. Hydra keeps recently used files' pages in the kernel
// (each read was a request to the file server before) and must update or drop them.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static char dir[256];

static void path(char *out, const char *name) { snprintf(out, 512, "%s/%s", dir, name); }

static int read_all(const char *p, char *buf, int size) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    int n = 0, r;
    while (n < size && (r = read(fd, buf + n, size - n)) > 0) n += r;
    close(fd);
    return n;
}

int main(int argc, char **argv) {
    snprintf(dir, sizeof dir, "%s/pagecache.%d", argc > 1 ? argv[1] : "/tmp", getpid());
    mkdir(dir, 0700);
    char a[512], b[512], buf[1 << 20];

    // 1 MiB of known data, read twice (the second time from the cache)
    path(a, "data");
    int fd = open(a, O_RDWR | O_CREAT | O_TRUNC, 0600);
    static char data[1 << 20];
    for (int i = 0; i < (int)sizeof data; i++) data[i] = (char)(i * 7 + i / 4096);
    write(fd, data, sizeof data);
    int n1 = read_all(a, buf, sizeof buf), same1 = n1 == (int)sizeof data && !memcmp(buf, data, sizeof data);
    int n2 = read_all(a, buf, sizeof buf), same2 = n2 == (int)sizeof data && !memcmp(buf, data, sizeof data);
    CHECK(same1 && same2, "1 MiB read twice: the data written");

    // pwrite through another descriptor, across a page boundary
    int fd2 = open(a, O_RDWR);
    pwrite(fd2, "ABCDEFGH", 8, 4096 - 4);
    char small[8];
    pread(fd, small, 8, 4096 - 4);
    CHECK(!memcmp(small, "ABCDEFGH", 8), "pwrite on another descriptor is read at once");
    close(fd2);

    // In another process too (the cache is the kernel's, not the process's)
    pid_t c = fork();
    if (c == 0) {
        char s[8];
        int f = open(a, O_RDONLY);
        pread(f, s, 8, 4096 - 4);
        _exit(memcmp(s, "ABCDEFGH", 8) != 0);
    }
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "another process reads the new data");

    // A shared mapping's writes are seen by read, and write's by the mapping
    char *m = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memcpy(m + 100, "mapped!", 7);
    pread(fd, small, 7, 100);
    CHECK(!memcmp(small, "mapped!", 7), "read sees a shared mapping's write");
    pwrite(fd, "written", 7, 200);
    CHECK(!memcmp(m + 200, "written", 7), "the mapping sees write's data");
    munmap(m, 8192);
    pread(fd, small, 7, 100);
    CHECK(!memcmp(small, "mapped!", 7), "after munmap the mapping's write stays");

    // Truncate, then extend: the old data does not come back
    ftruncate(fd, 5000);
    ftruncate(fd, 12000);
    int n = read_all(a, buf, sizeof buf);
    int zeros = 1;
    for (int i = 5000; i < 12000; i++) if (buf[i]) { zeros = 0; break; }
    CHECK(n == 12000 && zeros && buf[4999] == data[4999], "truncated and extended: zeros past the cut (%d bytes)", n);
    close(fd);

    // Replaced by rename: the name reads the new file
    path(b, "new");
    fd = open(b, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    write(fd, "replacement", 11);
    close(fd);
    rename(b, a);
    n = read_all(a, buf, sizeof buf);
    CHECK(n == 11 && !memcmp(buf, "replacement", 11), "renamed over: the new contents");

    // Unlinked and created again under the same name
    unlink(a);
    fd = open(a, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    write(fd, "fresh", 5);
    close(fd);
    n = read_all(a, buf, sizeof buf);
    CHECK(n == 5 && !memcmp(buf, "fresh", 5), "unlinked and created again: the new contents");

    // O_TRUNC on open empties what was cached
    fd = open(a, O_WRONLY | O_TRUNC);
    write(fd, "xy", 2);
    close(fd);
    n = read_all(a, buf, sizeof buf);
    CHECK(n == 2 && !memcmp(buf, "xy", 2), "O_TRUNC then write: just that");

    // An append is seen
    fd = open(a, O_WRONLY | O_APPEND);
    write(fd, "z", 1);
    close(fd);
    n = read_all(a, buf, sizeof buf);
    CHECK(n == 3 && !memcmp(buf, "xyz", 3), "append seen");

    unlink(a);
    rmdir(dir);
    printf("%s\n", fails ? "PAGECACHE TEST FAILED" : "PAGECACHE TEST PASSED");
    return fails != 0;
}
