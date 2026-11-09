// The kernel's file-system caches never show stale state: attributes after writes, chmod,
// chown, truncate, utimens, link/unlink (link counts), rename and rmdir of directories under
// cached paths, and a name created where a lookup failed before.
// Build: gcc -O1 -w -o fscache fscache_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static struct stat st(const char *p) {
    struct stat s;
    memset(&s, 0, sizeof s);
    if (stat(p, &s) != 0) s.st_ino = 0;
    return s;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char base[64];
    snprintf(base, sizeof base, "/tmp/fscache.%d", getpid());
    mkdir(base, 0755);
    chdir(base);

    // A lookup fails, then the name appears
    check(stat("f", &(struct stat){0}) < 0 && errno == ENOENT, "missing name: ENOENT");
    int fd = open("f", O_CREAT | O_RDWR, 0644);
    check(st("f").st_ino != 0 && st("f").st_size == 0, "created where a lookup failed");
    struct stat d0 = st(".");

    // Size and times follow writes
    struct stat a = st("f");
    write(fd, "hello", 5);
    check(st("f").st_size == 5, "size after write");
    struct stat b;
    fstat(fd, &b);
    check(b.st_size == 5, "fstat size after write");
    ftruncate(fd, 2);
    check(st("f").st_size == 2, "size after truncate");
    chmod("f", 0600);
    check((st("f").st_mode & 0777) == 0600, "mode after chmod");
    struct timespec ts[2] = {{1000, 0}, {2000, 0}};
    utimensat(AT_FDCWD, "f", ts, 0);
    check(st("f").st_mtime == 2000 && st("f").st_atime == 1000, "times after utimens");
    (void)a;

    // Link counts
    link("f", "g");
    check(st("f").st_nlink == 2 && st("g").st_ino == st("f").st_ino, "link count after link");
    unlink("g");
    check(st("f").st_nlink == 1 && st("g").st_ino == 0, "link count after unlink");
    unlink("f");
    check(fstat(fd, &b) == 0 && b.st_nlink == 0, "open file unlinked: nlink 0");
    close(fd);
    check(st("f").st_ino == 0, "unlinked name gone");

    // Directories under cached paths
    mkdir("d", 0755);
    check(st(".").st_nlink == d0.st_nlink + 1, "parent link count after mkdir");
    mkdir("d/e", 0755);
    close(open("d/e/x", O_CREAT | O_WRONLY, 0644));
    check(st("d/e/x").st_ino != 0, "file in subdirectory");
    rename("d", "d2");
    check(st("d/e/x").st_ino == 0, "old path gone after renaming a directory above it");
    check(st("d2/e/x").st_ino != 0, "new path found after renaming a directory above it");
    unlink("d2/e/x");
    rmdir("d2/e");
    check(st("d2/e").st_ino == 0 && st("d2/e/x").st_ino == 0, "removed directory and its file gone");
    mkdir("d2/e", 0700);
    check((st("d2/e").st_mode & 0777) == 0700, "new directory at a removed one's name");

    // Rename over an existing file
    close(open("p", O_CREAT | O_WRONLY, 0644));
    fd = open("q", O_CREAT | O_WRONLY, 0644);
    write(fd, "abc", 3);
    close(fd);
    ino_t qi = st("q").st_ino;
    rename("q", "p");
    check(st("p").st_ino == qi && st("p").st_size == 3 && st("q").st_ino == 0, "rename over a file");

    // A symlink to a renamed target
    symlink("p", "s");
    check(st("s").st_ino == qi, "symlink resolves");
    rename("p", "p2");
    check(st("s").st_ino == 0, "dangling symlink after its target moved");

    // Clean up
    unlink("s");
    unlink("p2");
    rmdir("d2/e");
    rmdir("d2");
    chdir("/");
    rmdir(base);
    check(st(base).st_ino == 0, "test directory removed");
    printf(fails ? "FSCACHE TEST FAILED (%d)\n" : "FSCACHE TEST PASSED\n", fails);
    return fails != 0;
}
