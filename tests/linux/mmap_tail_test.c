// A file mapping whose length is not a whole number of pages covers whole pages: the tail
// of its last page (after the end of the file) reads as zeros and a private mapping may
// write it. Hydra named the mapping (for /proc/self/maps) over the exact length, which
// split it in the middle of a page; a write there raised SIGBUS (Wine's first run).
// Pages written through a shared mapping reach the file (Hydra used to drop them).
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

// Lines of /proc/self/maps that overlap [a, a + len), and whether each starts and ends on a page
static int maps_lines(unsigned long a, unsigned long len, int *aligned) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    int n = 0;
    *aligned = 1;
    while (f && fgets(line, sizeof line, f)) {
        unsigned long s, e;
        if (sscanf(line, "%lx-%lx", &s, &e) == 2 && s < a + len && e > a) {
            n++;
            if ((s | e) & 0xfff) *aligned = 0;
        }
    }
    if (f) fclose(f);
    return n;
}

int main(void) {
    char path[] = "/tmp/mmaptailXXXXXX";
    int fd = mkstemp(path);
    const size_t size = 139278; // 34 pages and 14 bytes, the size Wine mapped
    char *data = malloc(size);
    for (size_t i = 0; i < size; i++) data[i] = (char)(i * 7 + 1);
    CHECK(write(fd, data, size) == (ssize_t)size, "wrote %zu bytes", size);

    unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED, "mmap of the exact file size");
    int aligned;
    int lines = maps_lines((unsigned long)p, size, &aligned);
    CHECK(lines == 1 && aligned, "one page-aligned mapping in /proc/self/maps (%d lines, aligned %d)", lines, aligned);
    CHECK(memcmp(p, data, size) == 0, "the file's bytes read back");
    CHECK(p[size] == 0 && p[(size | 0xfff)] == 0, "the tail of the last page reads as zeros");
    p[size + 0x1f0] = 0x5a;        // after the end of the file, in the last page
    p[size - 1] = 0x33;            // the last byte of the file
    CHECK(p[size + 0x1f0] == 0x5a && p[size - 1] == 0x33, "a private mapping writes the tail of the last page");
    CHECK(munmap(p, size) == 0, "munmap of the exact size");
    lines = maps_lines((unsigned long)p, size, &aligned);
    CHECK(lines == 0, "nothing left mapped (%d lines)", lines);

    // A read-only shared mapping through a read-only descriptor (marked never writable)
    int ro = open(path, O_RDONLY);
    unsigned char *q = mmap(NULL, size, PROT_READ, MAP_SHARED, ro, 0);
    CHECK(q != MAP_FAILED && q[size - 1] == data[size - 1] && q[size] == 0, "read-only shared mapping reads to the end");
    lines = maps_lines((unsigned long)q, size, &aligned);
    CHECK(lines == 1 && aligned, "one page-aligned read-only mapping (%d lines, aligned %d)", lines, aligned);
    CHECK(mprotect(q, size, PROT_READ | PROT_WRITE) == -1, "it cannot become writable");
    munmap(q, size);
    close(ro);
    // Wine's sections: write through a shared mapping, unmap, map again and read it back;
    // read() sees it too, and msync writes while still mapped
    unsigned char *w = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(w != MAP_FAILED, "shared writable mapping");
    memcpy(w + 8192 + 3, "SNAPSHOT", 8);
    w[size - 1] = 0x77;
    CHECK(munmap(w, size) == 0, "unmapped");
    w = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(w != MAP_FAILED && memcmp(w + 8192 + 3, "SNAPSHOT", 8) == 0 && w[size - 1] == 0x77,
          "a new mapping sees what the old one wrote");
    char back[8];
    CHECK(pread(fd, back, 8, 8192 + 3) == 8 && memcmp(back, "SNAPSHOT", 8) == 0, "read() sees it");
    CHECK(lseek(fd, 0, SEEK_END) == (off_t)size, "the file did not grow (%ld)", (long)lseek(fd, 0, SEEK_END));
    munmap(w, size);
    w = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    memcpy(w + 3, "MSYNC", 5);
    CHECK(msync(w, size, MS_SYNC) == 0 && pread(fd, back, 5, 3) == 5 && memcmp(back, "MSYNC", 5) == 0,
          "msync writes it while still mapped");
    munmap(w, size);
    close(fd);
    unlink(path);

    printf("%s\n", fails ? "MMAP TAIL TEST FAILED" : "MMAP TAIL TEST PASSED");
    return fails != 0;
}
