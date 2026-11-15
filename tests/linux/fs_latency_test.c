// Latency of single file-system operations and of starting a process, for finding where
// Hydra spends its time on many small operations (unpacking archives, installers).
// Prints microseconds per operation; on Linux they are all a few microseconds, except
// fork+exec (about 0.5-1 ms). Exits 0: it measures, it does not judge.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

#define BENCH(name, n, body) do { \
    double t0 = now_us(); \
    for (int i = 0; i < (n); i++) { body; } \
    double dt = now_us() - t0; \
    printf("%-34s %8.1f us/op  (%d ops, %.0f ms)\n", name, dt / (n), (n), dt / 1000); \
    fflush(stdout); \
} while (0)

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "/tmp";
    char path[256], p2[256];
    snprintf(path, sizeof path, "%s/fslat.dat", dir);
    static char buf[65536];
    memset(buf, 'x', sizeof buf);

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    for (int i = 0; i < 64; i++) write(fd, buf, sizeof buf); // 4 MiB
    fsync(fd);

    BENCH("getpid (baseline syscall)", 20000, syscall(SYS_getpid));
    BENCH("fstat", 5000, { struct stat st; fstat(fd, &st); });
    BENCH("stat (path lookup)", 2000, { struct stat st; stat(path, &st); });
    BENCH("pread 4 KiB (cached)", 5000, pread(fd, buf, 4096, (i % 1024) * 4096L));
    BENCH("pread 64 KiB (cached)", 1000, pread(fd, buf, 65536, (i % 64) * 65536L));
    BENCH("pwrite 4 KiB (overwrite)", 2000, pwrite(fd, buf, 4096, (i % 1024) * 4096L));
    BENCH("write 10 KiB (append, tar record)", 2000, write(fd, buf, 10240));
    BENCH("open+close", 2000, close(open(path, O_RDONLY)));
    BENCH("create+write 1 B+close+unlink", 500, {
        snprintf(p2, sizeof p2, "%s/fslat.%d", dir, i);
        int f = open(p2, O_WRONLY | O_CREAT | O_TRUNC, 0644); write(f, "x", 1); close(f); unlink(p2);
    });
    BENCH("mkdir+rmdir", 500, { snprintf(p2, sizeof p2, "%s/fslat.d%d", dir, i); mkdir(p2, 0755); rmdir(p2); });
    BENCH("fork+exit+wait", 200, { pid_t p = fork(); if (p == 0) _exit(0); waitpid(p, NULL, 0); });
    BENCH("fork+exec /bin/true+wait", 100, {
        pid_t p = fork();
        if (p == 0) { execl("/bin/true", "true", (char *)NULL); _exit(127); }
        waitpid(p, NULL, 0);
    });
    close(fd);
    unlink(path);
    printf("FSLAT DONE\n");
    return 0;
}
