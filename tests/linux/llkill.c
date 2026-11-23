// llkill: Landlock rules while vfs-server is killed (wave 9, Group 6b-3).
//
//   llkill run SECS   sets up /tmp/llk.PID/{ro,rw}, restricts itself (read-only beneath ro/,
//                     everything beneath rw/), then for SECS seconds tries allowed and
//                     refused opens, creates, renames, truncates and removes while the test
//                     kills vfs-server (`service kill vfs_server`) as often as it likes.
//                     Prints one summary line and "LLKILL PASS" or "LLKILL FAIL".
//
// Expected: a refused operation is never allowed (0 violations), before, during and after a
// restart (vfs-server fetches the domain again, or the kernel answers while it is down); an
// allowed one succeeds, except a change in flight that may fail with EIO.
//
// Build: gcc -O1 -w -pthread tests/linux/llkill.c -o esp/bin/llkill.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// Landlock's interface (the build machine's headers predate it)
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define NR_create_ruleset 444
#define NR_add_rule 445
#define NR_restrict_self 446
struct landlock_ruleset_attr { uint64_t handled_access_fs, handled_access_net; };
struct landlock_path_beneath_attr { uint64_t allowed_access; int32_t parent_fd; } __attribute__((packed));
typedef uint64_t __u64x;

static char T[64];
static long ops, violations, errs, eio;

static const char *at(const char *rel) {
    static char b[4][160];
    static int i;
    i = (i + 1) & 3;
    snprintf(b[i], sizeof b[i], "%s/%s", T, rel);
    return b[i];
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

// An operation that must be refused: r is its result (errno set when -1)
static void refused(const char *what, int r) {
    ops++;
    if (r >= 0) {
        violations++;
        printf("VIOLATION: %s allowed\n", what);
    } else if (errno != EACCES && errno != EXDEV && errno != EPERM) {
        errs++;
        if (errno == EIO) eio++;
        else printf("odd error: %s: %s\n", what, strerror(errno));
    }
}

// An operation that must work
static void allowed(const char *what, int r) {
    ops++;
    if (r < 0) {
        errs++;
        if (errno == EIO) eio++;
        else printf("error: %s: %s\n", what, strerror(errno));
    }
}

static int add(int rs, const char *path, __u64x rights) {
    struct landlock_path_beneath_attr pb = {.allowed_access = rights, .parent_fd = open(path, O_PATH)};
    int r = syscall(NR_add_rule, rs, LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    close(pb.parent_fd);
    return r;
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "run")) {
        fprintf(stderr, "usage: llkill run SECS\n");
        return 2;
    }
    int secs = atoi(argv[2]);
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(T, sizeof T, "/tmp/llk.%d.%ld", getpid(), (long)time(NULL));
    mkdir(T, 0755);
    mkdir(at("ro"), 0755);
    mkdir(at("rw"), 0755);
    close(open(at("ro/f"), O_CREAT | O_WRONLY, 0644));
    close(open(at("rw/g"), O_CREAT | O_WRONLY, 0644));
    __u64x fs = (1ULL << 15) - 1; // ABI 3: up to TRUNCATE
    struct landlock_ruleset_attr ra = {.handled_access_fs = fs};
    int rs = syscall(NR_create_ruleset, &ra, sizeof ra, 0);
    if (rs < 0) {
        printf("no Landlock: %s\nLLKILL FAIL\n", strerror(errno));
        return 1;
    }
    // Read beneath ro/, everything beneath rw/; the system for the program itself
    add(rs, at("ro"), LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    add(rs, at("rw"), fs);
    add(rs, "/usr", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE);
    add(rs, "/lib", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE);
    add(rs, "/proc", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (syscall(NR_restrict_self, rs, 0) < 0) {
        printf("restrict_self: %s\nLLKILL FAIL\n", strerror(errno));
        return 1;
    }
    close(rs);
    printf("LLKILL RUNNING %s\n", T);
    double end = now() + secs;
    long rounds = 0;
    while (now() < end) {
        int fd;
        // Allowed
        fd = open(at("ro/f"), O_RDONLY);
        allowed("read ro/f", fd);
        if (fd >= 0) close(fd);
        fd = open(at("ro"), O_RDONLY | O_DIRECTORY);
        allowed("list ro", fd);
        if (fd >= 0) close(fd);
        fd = open(at("rw/g"), O_RDWR);
        allowed("write rw/g", fd);
        if (fd >= 0) {
            allowed("ftruncate rw/g", ftruncate(fd, 0));
            close(fd);
        }
        fd = open(at("rw/n"), O_CREAT | O_WRONLY, 0644);
        allowed("create rw/n", fd);
        if (fd >= 0) close(fd);
        allowed("rename rw/n rw/m", rename(at("rw/n"), at("rw/m")));
        allowed("unlink rw/m", unlink(at("rw/m")));
        allowed("mkdir rw/d", mkdir(at("rw/d"), 0755));
        allowed("rmdir rw/d", rmdir(at("rw/d")));
        // Refused
        fd = open(at("ro/f"), O_WRONLY);
        refused("write ro/f", fd);
        if (fd >= 0) close(fd);
        refused("truncate ro/f", truncate(at("ro/f"), 0));
        fd = open(at("ro/n"), O_CREAT | O_WRONLY, 0644);
        refused("create ro/n", fd);
        if (fd >= 0) close(fd);
        refused("mkdir ro/d", mkdir(at("ro/d"), 0755));
        refused("symlink ro/s", symlink("f", at("ro/s")));
        refused("unlink ro/f", unlink(at("ro/f")));
        refused("rename ro/f rw/f", rename(at("ro/f"), at("rw/f")));
        refused("open /etc/hostname", open("/etc/hostname", O_RDONLY));
        rounds++;
    }
    printf("llkill: %ld rounds, %ld operations, %ld violations, %ld errors (%ld EIO)\n", rounds, ops, violations, errs, eio);
    int ok = violations == 0 && errs == eio && rounds > 0;
    printf(ok ? "LLKILL PASS\n" : "LLKILL FAIL\n");
    return !ok;
}
