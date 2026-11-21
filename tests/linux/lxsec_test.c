/*
 * lx-sec (wave 6, Group 24): keys and bpf in their own service, and what programs see when
 * it is killed and restarted.
 *
 *   lxsec keep        adds kept keys to the user keyring (@u): a "user" key with a known
 *                     payload and a keyring holding a second key; prints their serials
 *   lxsec check       finds them again (search, read): run after a kill of lx-sec, the
 *                     keyrings must be intact ("KEPT OK" / "KEPT FAIL")
 *   lxsec hammer N S  N threads for S seconds: add_key to the thread keyring, read it back,
 *                     unlink it, and a search of @u for the kept key; one line per second with
 *                     calls, errors and the longest call (a restart shows as a pause); at the
 *                     end "HAMMER-END calls C errors E longest-ms L in-flight-EIO F" (F: unlinks
 *                     being served when lx-sec died: EIO by design)
 *   lxsec bpfhold S   a hash map with one element, then waits up to S seconds for
 *                     /tmp/lxsec.go; after it, the old map descriptor must fail (EBADF after a
 *                     restart, "STALE OK"), a new map must work ("NEWMAP OK")
 *   lxsec devset      a device program refusing /dev/null attached (BPF_PROG_ATTACH) to the
 *                     cgroup /sys/fs/cgroup/lxsec; checks it works
 *   lxsec devcheck    a child in that cgroup: /dev/null still refused after a restart
 *                     ("DEV KEPT OK"), then the program is detached and /dev/null opens again
 *                     ("DEV DETACH OK"); the cgroup is removed
 *
 * Build: gcc -O1 -w -pthread lxsec_test.c -o lxsec
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define KEYCTL_UNLINK 9
#define KEYCTL_SEARCH 10
#define KEYCTL_READ 11
#define THREAD_KEYRING -1
#define USER_KEYRING -4

static uint64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static long add_key(const char *type, const char *desc, const void *p, size_t n, long ring) {
    return syscall(SYS_add_key, type, desc, p, n, ring);
}

static int keep(void) {
    long k = add_key("user", "lxsec-kept", "kept-payload-123", 16, USER_KEYRING);
    long r = add_key("keyring", "lxsec-ring", 0, 0, USER_KEYRING);
    long k2 = r > 0 ? add_key("user", "lxsec-inner", "inner", 5, r) : -1;
    printf("KEEP key %ld ring %ld inner %ld\n", k, r, k2);
    return k > 0 && r > 0 && k2 > 0 ? 0 : 1;
}

static int check(void) {
    char buf[64];
    int bad = 0;
    long k = syscall(SYS_keyctl, KEYCTL_SEARCH, USER_KEYRING, "user", "lxsec-kept", 0);
    long n = k > 0 ? syscall(SYS_keyctl, KEYCTL_READ, k, buf, sizeof buf) : -1;
    if (!(n == 16 && memcmp(buf, "kept-payload-123", 16) == 0)) {
        printf("FAIL kept key: serial %ld read %ld (%s)\n", k, n, strerror(errno));
        bad++;
    }
    long r = syscall(SYS_keyctl, KEYCTL_SEARCH, USER_KEYRING, "keyring", "lxsec-ring", 0);
    long i = r > 0 ? syscall(SYS_keyctl, KEYCTL_SEARCH, r, "user", "lxsec-inner", 0) : -1;
    n = i > 0 ? syscall(SYS_keyctl, KEYCTL_READ, i, buf, sizeof buf) : -1;
    if (!(n == 5 && memcmp(buf, "inner", 5) == 0)) {
        printf("FAIL kept keyring: ring %ld inner %ld read %ld (%s)\n", r, i, n, strerror(errno));
        bad++;
    }
    printf("KEPT %s key %ld ring %ld inner %ld\n", bad ? "FAIL" : "OK", k, r, i);
    return bad != 0;
}

static volatile long h_calls, h_errs, h_long, h_stop, h_inflight;

/* The first errors, one line each (which call, its result and errno): tells a call lost in
 * a restart (EIO) from a key the restart lost (ENOKEY) */
static void herr(const char *what, long r, int e) {
    static volatile long n;
    /* (a call that returned a value, not -1, set no errno) */
    if (r != -1) e = 0;
    if (__sync_fetch_and_add(&n, 1) < 16) printf("HAMMER-ERR %s r=%ld errno=%d (%s) at %lu ms\n", what, r, e, strerror(e), (unsigned long)now_ms());
}

static void *hammer_thread(void *arg) {
    (void)arg;
    char desc[64], buf[16];
    for (long i = 0; !h_stop; i++) {
        uint64_t t0 = now_ms();
        snprintf(desc, sizeof desc, "lxsec-h-%d-%ld", gettid(), i);
        long id = add_key("user", desc, "hammer", 6, THREAD_KEYRING);
        int err = id <= 0;
        if (err) herr("add_key", id, errno);
        if (!err) {
            long r = syscall(SYS_keyctl, KEYCTL_READ, id, buf, sizeof buf);
            if (r != 6) { err = 1; herr("read", r, errno); }
            r = syscall(SYS_keyctl, KEYCTL_UNLINK, id, THREAD_KEYRING);
            /* An unlink being served when lx-sec dies gets EIO: a change in flight is not
             * sent again (it may have happened; linux-services-design 5.1, Transparent:
             * "EIO only for a change in flight"). Counted apart: expected across a kill.
             * (add_key is sent again since wave 7: lx-sec updates the key in place.) */
            if (r != 0 && errno == EIO) { __sync_fetch_and_add(&h_inflight, 1); herr("unlink (in flight)", r, errno); }
            else if (r != 0) { err = 1; herr("unlink", r, errno); }
        }
        long s = syscall(SYS_keyctl, KEYCTL_SEARCH, USER_KEYRING, "user", "lxsec-kept", 0);
        if (s <= 0) { err = 1; herr("search", s, errno); }
        if (err) __sync_fetch_and_add(&h_errs, 1);
        __sync_fetch_and_add(&h_calls, 4);
        long d = (long)(now_ms() - t0);
        long l;
        while ((l = h_long) < d && !__sync_bool_compare_and_swap(&h_long, l, d)) {
        }
    }
    return 0;
}

static int hammer(int threads, int secs) {
    pthread_t t[64];
    if (threads > 64) threads = 64;
    for (int i = 0; i < threads; i++) pthread_create(&t[i], 0, hammer_thread, 0);
    for (int s = 0; s < secs; s++) {
        sleep(1);
        printf("HAMMER t=%d calls %ld errors %ld longest-ms %ld\n", s + 1, h_calls, h_errs, h_long);
        fflush(stdout);
    }
    h_stop = 1;
    for (int i = 0; i < threads; i++) pthread_join(t[i], 0);
    printf("HAMMER-END calls %ld errors %ld longest-ms %ld in-flight-EIO %ld\n", h_calls, h_errs, h_long, h_inflight);
    return 0;
}

static long bpf(int cmd, union bpf_attr *a) { return syscall(SYS_bpf, cmd, a, sizeof *a); }

static int new_map(void) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = BPF_MAP_TYPE_HASH;
    a.key_size = 4;
    a.value_size = 8;
    a.max_entries = 16;
    return bpf(BPF_MAP_CREATE, &a);
}

static long elem(int cmd, int fd, uint32_t key, uint64_t *val) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uint64_t)&key;
    a.value = (uint64_t)val;
    return bpf(cmd, &a);
}

static int bpfhold(int secs) {
    int fd = new_map();
    uint64_t v = 77, out = 0;
    long u = elem(BPF_MAP_UPDATE_ELEM, fd, 5, &v);
    long l = elem(BPF_MAP_LOOKUP_ELEM, fd, 5, &out);
    printf("BPFHOLD map %d update %ld lookup %ld value %lu\n", fd, u, l, (unsigned long)out);
    fflush(stdout);
    for (int i = 0; i < secs * 10 && access("/tmp/lxsec.go", F_OK) != 0; i++) usleep(100000);
    out = 0;
    l = elem(BPF_MAP_LOOKUP_ELEM, fd, 5, &out);
    int e = errno;
    printf("%s old map after the restart: lookup %ld (%s)\n", l == -1 && e == EBADF ? "STALE OK" : "STALE FAIL", l, strerror(e));
    int fd2 = new_map();
    v = 99;
    out = 0;
    u = elem(BPF_MAP_UPDATE_ELEM, fd2, 1, &v);
    l = elem(BPF_MAP_LOOKUP_ELEM, fd2, 1, &out);
    printf("%s new map %d update %ld lookup %ld value %lu\n", fd2 >= 0 && u == 0 && l == 0 && out == 99 ? "NEWMAP OK" : "NEWMAP FAIL", fd2, u, l, (unsigned long)out);
    return 0;
}

#define I(c, d, s, o, i) ((struct bpf_insn){c, d, s, o, i})
#define MOV64_IMM(d, i) I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define ALU64_IMM(op, d, i) I(BPF_ALU64 | op | BPF_K, d, 0, 0, i)
#define LDX(sz, d, s, o) I(BPF_LDX | sz | BPF_MEM, d, s, o, 0)
#define JMP_IMM(op, d, i, o) I(BPF_JMP | op | BPF_K, d, 0, o, i)
#define EXIT() I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define CG "/sys/fs/cgroup/lxsec"

/* A child in the cgroup: 1 if /dev/null was refused (EPERM), plus 2 if /dev/zero opened. */
static int in_cgroup(void) {
    pid_t c = fork();
    if (c == 0) {
        char pid[16];
        int pf = open(CG "/cgroup.procs", O_WRONLY);
        snprintf(pid, sizeof pid, "%d", getpid());
        write(pf, pid, strlen(pid));
        close(pf);
        int n = open("/dev/null", O_RDWR), e = errno;
        int z = open("/dev/zero", O_RDONLY);
        _exit((n == -1 && e == EPERM ? 1 : 0) | (z >= 0 ? 2 : 0));
    }
    int st;
    waitpid(c, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int devset(void) {
    mkdir(CG, 0755);
    int cgfd = open(CG, O_RDONLY | O_DIRECTORY);
    struct bpf_insn dev[] = {
        LDX(BPF_W, 2, 1, 0), ALU64_IMM(BPF_AND, 2, 0xffff), JMP_IMM(BPF_JNE, 2, BPF_DEVCG_DEV_CHAR, 6),
        LDX(BPF_W, 3, 1, 4), JMP_IMM(BPF_JNE, 3, 1, 4), LDX(BPF_W, 4, 1, 8), JMP_IMM(BPF_JNE, 4, 3, 2),
        MOV64_IMM(0, 0), EXIT(), MOV64_IMM(0, 1), EXIT()};
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE;
    a.insns = (uint64_t)dev;
    a.insn_cnt = sizeof dev / 8;
    a.license = (uint64_t)"GPL";
    a.expected_attach_type = BPF_CGROUP_DEVICE;
    int dp = bpf(BPF_PROG_LOAD, &a);
    memset(&a, 0, sizeof a);
    a.target_fd = cgfd;
    a.attach_bpf_fd = dp;
    a.attach_type = BPF_CGROUP_DEVICE;
    long r = bpf(BPF_PROG_ATTACH, &a);
    int c = in_cgroup();
    printf("%s device program %d attached %ld; in the cgroup %d\n", dp >= 0 && r == 0 && c == 3 ? "DEVSET OK" : "DEVSET FAIL", dp, r, c);
    return 0;
}

static int devcheck(void) {
    int c = in_cgroup();
    printf("%s in the cgroup after the restart: %d\n", c == 3 ? "DEV KEPT OK" : "DEV KEPT FAIL", c);
    int cgfd = open(CG, O_RDONLY | O_DIRECTORY);
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.target_fd = cgfd;
    a.attach_bpf_fd = 0;
    a.attach_type = BPF_CGROUP_DEVICE;
    long r = bpf(BPF_PROG_DETACH, &a);
    c = in_cgroup();
    printf("%s detach %ld; in the cgroup %d\n", r == 0 && c == 2 ? "DEV DETACH OK" : "DEV DETACH FAIL", r, c);
    close(cgfd);
    rmdir(CG);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    const char *m = argc > 1 ? argv[1] : "";
    if (!strcmp(m, "keep")) return keep();
    if (!strcmp(m, "check")) return check();
    if (!strcmp(m, "hammer")) return hammer(argc > 2 ? atoi(argv[2]) : 4, argc > 3 ? atoi(argv[3]) : 10);
    if (!strcmp(m, "bpfhold")) return bpfhold(argc > 2 ? atoi(argv[2]) : 60);
    if (!strcmp(m, "devset")) return devset();
    if (!strcmp(m, "devcheck")) return devcheck();
    fprintf(stderr, "usage: lxsec keep|check|hammer N S|bpfhold S|devset|devcheck\n");
    return 2;
}
