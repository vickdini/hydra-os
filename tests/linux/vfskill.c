// vfskill: what programs see while vfs-server is killed (wave 7, Group 7-6).
//
//   vfskill run SECS     set up, then for SECS seconds read and change files from two
//                        threads while a lock checker runs in a child; meanwhile the test
//                        kills vfs-server (`service kill vfs_server`) as often as it likes.
//                        Prints one summary line and "VFSKILL PASS" or "VFSKILL FAIL".
//   vfskill put / get    the kept-state test hook alone (LX_VFS_KTEST): put writes a pattern
//                        into vfs-server's test tmpfs file, get checks it (after a restart).
//
// What it holds across the kills: an open file and a shared mapping of it (pool), an open
// directory and a working directory in it, a flock and a POSIX record lock (checked from
// another process), a tmpfs file (/dev/shm), and vfs-server's own test tmpfs file.
// Expected: every read, getcwd, fstat, stat, open and the lock checks keep working (the
// kernel answers while vfs-server is down; calls in flight are sent again); a change in
// flight may fail with EIO, never with another error; the test tmpfs file keeps its data
// (unless the restart ladder reset the kept state: a second crash within 30 s).
//
// Build: gcc -O1 -w -pthread tests/linux/vfskill.c -o esp/bin/vfskill.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LX_VFS_WALK_NR 0x6714
#define LX_VFS_KTEST 0x100
#define DATA_LEN (256 * 1024)
#define BASE "/tmp/vk"

static volatile int stop;
static long reads, read_err, changes, change_eio, change_err, lock_err, after_eio_ok;
static long max_stat_us;
static char first_err[256];

static void note_err(const char *what, int e) {
    if (!first_err[0]) snprintf(first_err, sizeof first_err, "%s: %s", what, strerror(e));
}

static uint8_t pat(long i) { return (uint8_t)(i * 7 + (i >> 9) + 3); }

static long now_us(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static int fd_data, fd_dir, fd_shm;
static const uint8_t *map;

static void *reader(void *a) {
    char buf[4096], cwd[256], link[64];
    long n = 0;
    while (!stop) {
        long off = (n * 4093) % (DATA_LEN - sizeof buf);
        int bad = 0;
        if (pread(fd_data, buf, sizeof buf, off) != sizeof buf) { note_err("pread", errno); bad = 1; }
        else for (int i = 0; i < (int)sizeof buf; i += 97) if ((uint8_t)buf[i] != pat(off + i)) { note_err("pread data", EIO); bad = 1; break; }
        if (map[off] != pat(off)) { note_err("mapping data", EIO); bad = 1; }
        if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, BASE "/d")) { note_err("getcwd", errno ? errno : EINVAL); bad = 1; }
        struct stat st;
        if (fstat(fd_dir, &st) || !S_ISDIR(st.st_mode)) { note_err("fstat dir", errno); bad = 1; }
        long t0 = now_us();
        if (stat("x", &st) || st.st_size != 5) { note_err("stat relative", errno); bad = 1; }
        long dt = now_us() - t0;
        if (dt > max_stat_us) max_stat_us = dt;
        int fd = open(BASE "/data", O_RDONLY);
        if (fd < 0) { note_err("open", errno); bad = 1; } else close(fd);
        ssize_t l = readlink(BASE "/link", link, sizeof link);
        if (l != 4 || memcmp(link, "data", 4)) { note_err("readlink", errno); bad = 1; }
        if (access(BASE "/data", R_OK)) { note_err("access", errno); bad = 1; }
        if (pread(fd_shm, buf, 64, 0) != 64 || memcmp(buf, "shm-data", 8)) { note_err("tmpfs read", errno); bad = 1; }
        read_err += bad;
        reads++;
        n++;
    }
    return 0;
}

static void *changer(void *a) {
    char p1[64], p2[64];
    int prev_eio = 0;
    long n = 0;
    while (!stop) {
        snprintf(p1, sizeof p1, BASE "/c/a%ld", n % 8);
        snprintf(p2, sizeof p2, BASE "/c/b%ld", n % 8);
        int steps[3];
        steps[0] = mkdir(p1, 0755) ? errno : 0;
        steps[1] = steps[0] == 0 && rename(p1, p2) ? errno : 0;
        steps[2] = rmdir(steps[0] == 0 && steps[1] == 0 ? p2 : p1) ? errno : 0;
        for (int i = 0; i < 3; i++) {
            int e = steps[i];
            if (!e) continue;
            if (e == EIO) { change_eio++; prev_eio = 2; continue; }
            // After an EIO the change may or may not have happened: one EEXIST/ENOENT is fine
            if (prev_eio && (e == EEXIST || e == ENOENT)) { after_eio_ok++; continue; }
            change_err++;
            note_err("change", e);
        }
        if (prev_eio) prev_eio--;
        // Clean up leftovers of a change that failed with EIO but happened
        if (steps[0] || steps[1] || steps[2]) { rmdir(p1); rmdir(p2); }
        changes++;
        n++;
    }
    return 0;
}

static long ktest(int op, uint8_t *buf) {
    long r = syscall(LX_VFS_WALK_NR, op, "/", LX_VFS_KTEST, buf);
    return r < 0 ? -errno : r;
}

static void fill_ktest(uint8_t *b, unsigned seed) {
    for (int i = 0; i < 64; i++) b[i] = (uint8_t)(seed * 31 + i * 13);
}

static int put_get(const char *how) {
    uint8_t buf[128] = {0};
    unsigned seed = 0x5eed;
    if (!strcmp(how, "put")) {
        fill_ktest(buf, seed);
        long r = ktest(1, buf);
        printf("KTEST put: %ld (restarts so far)\n", r);
        return r < 0;
    }
    long r = ktest(2, buf);
    uint8_t want[64];
    fill_ktest(want, seed);
    int ok = r >= 0 && !memcmp(buf, want, 64);
    printf("KTEST get: %ld (restarts), data %s\n", r, r < 0 ? "-" : ok ? "kept" : "LOST");
    return !ok;
}

int main(int argc, char **argv) {
    if (argc >= 2 && (!strcmp(argv[1], "put") || !strcmp(argv[1], "get"))) return put_get(argv[1]);
    if (argc < 3 || strcmp(argv[1], "run")) {
        fprintf(stderr, "usage: vfskill run SECS | put | get\n");
        return 2;
    }
    int secs = atoi(argv[2]);
    // Set up
    system("rm -rf " BASE);
    if (mkdir(BASE, 0755) || mkdir(BASE "/d", 0755) || mkdir(BASE "/c", 0755)) { perror("mkdir"); return 1; }
    uint8_t *d = malloc(DATA_LEN);
    for (long i = 0; i < DATA_LEN; i++) d[i] = pat(i);
    int w = open(BASE "/data", O_CREAT | O_WRONLY, 0644);
    if (w < 0 || write(w, d, DATA_LEN) != DATA_LEN) { perror("write data"); return 1; }
    fsync(w);
    close(w);
    w = open(BASE "/d/x", O_CREAT | O_WRONLY, 0644);
    write(w, "hello", 5);
    close(w);
    symlink("data", BASE "/link");
    fd_data = open(BASE "/data", O_RDONLY);
    map = mmap(0, DATA_LEN, PROT_READ, MAP_SHARED, fd_data, 0);
    fd_dir = open(BASE "/d", O_RDONLY | O_DIRECTORY);
    if (fd_data < 0 || map == MAP_FAILED || fd_dir < 0 || chdir(BASE "/d")) { perror("open/mmap/chdir"); return 1; }
    fd_shm = open("/dev/shm/vk", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd_shm < 0 || write(fd_shm, "shm-data-0123456789abcdef0123456789abcdef0123456789abcdef0123456", 64) != 64) { perror("tmpfs"); return 1; }
    // Locks: flock on the data file, a POSIX lock on bytes 0..99 of a lock file
    if (flock(fd_data, LOCK_EX)) { perror("flock"); return 1; }
    int fd_lock = open(BASE "/lock", O_CREAT | O_RDWR, 0644);
    struct flock fl = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 100 };
    if (fd_lock < 0 || fcntl(fd_lock, F_SETLK, &fl)) { perror("F_SETLK"); return 1; }
    // vfs-server's own test tmpfs file
    uint8_t kt[128] = {0};
    fill_ktest(kt, 0x5eed);
    long kr = ktest(1, kt);
    pid_t parent = getpid();
    int pfd[2];
    pipe(pfd);
    pid_t child = fork();
    if (child == 0) {
        // The lock checker: the parent's locks must hold all the time
        long errs = 0, checks = 0;
        int f = open(BASE "/data", O_RDONLY), l = open(BASE "/lock", O_RDWR);
        time_t end = time(0) + secs;
        while (time(0) < end) {
            if (flock(f, LOCK_EX | LOCK_NB) == 0 || errno != EWOULDBLOCK) errs++;
            struct flock q = { .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 10, .l_len = 1 };
            if (fcntl(l, F_GETLK, &q) || q.l_type != F_WRLCK || q.l_pid != parent) errs++;
            checks++;
            usleep(20000);
        }
        long out[2] = { errs, checks };
        write(pfd[1], out, sizeof out);
        _exit(0);
    }
    pthread_t a, b;
    pthread_create(&a, 0, reader, 0);
    pthread_create(&b, 0, changer, 0);
    printf("VFSKILL-STARTED %d s (ktest put %ld)\n", secs, kr);
    fflush(stdout);
    sleep(secs);
    stop = 1;
    pthread_join(a, 0);
    pthread_join(b, 0);
    long out[2] = { -1, 0 };
    read(pfd[0], out, sizeof out);
    waitpid(child, 0, 0);
    lock_err = out[0];
    // The locks still unlock
    if (flock(fd_data, LOCK_UN)) lock_err++;
    fl.l_type = F_UNLCK;
    if (fcntl(fd_lock, F_SETLK, &fl)) lock_err++;
    // vfs-server's test tmpfs file
    uint8_t got[128] = {0};
    long kg = ktest(2, got);
    const char *kts = kr < 0 ? "n/a" : kg < 0 ? "ERR" : memcmp(got, kt, 64) ? "LOST" : "kept";
    printf("VFSKILL reads=%ld read_err=%ld changes=%ld eio=%ld after_eio=%ld change_err=%ld lock_checks=%ld lock_err=%ld max_stat_us=%ld ktest=%s restarts=%ld%s%s\n", reads, read_err, changes,
           change_eio, after_eio_ok, change_err, out[1], lock_err, max_stat_us, kts, kg, first_err[0] ? " first_err=" : "", first_err);
    int ok = read_err == 0 && change_err == 0 && lock_err == 0 && out[0] == 0 && reads > 0 && changes > 0;
    printf("VFSKILL %s\n", ok ? "PASS" : "FAIL");
    unlink("/dev/shm/vk");
    system("rm -rf " BASE);
    return !ok;
}
