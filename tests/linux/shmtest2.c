// System V shared memory in lx-ipc (wave 10, Group 8-2): attachment counts across fork,
// exit and execve, IPC_RMID while attached, a second program attaching by key, the times and
// pids of IPC_STAT, SHM_LOCK, SHM_RDONLY, limits (a segment beyond 1 GiB), IPC namespaces,
// /proc/sysvipc/shm.
//
//   shmtest2              the checks; last line "SHMTEST2 PASS" or "SHMTEST2 FAIL <n>"
//   shmtest2 bench        shmat+shmdt latency, shmget+IPC_RMID latency, page-fault rate
//   shmtest2 kill SECS    a writer and two readers share segments for SECS seconds (lx-ipc
//                         may be killed meanwhile): data and counts must hold; also new
//                         segments, attaches and IPC_STATs keep working. Last line
//                         "SHMKILL PASS ..." or "SHMKILL FAIL ..."
//   shmtest2 attach KEY   (internal: the second program attaching by key)
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

#ifndef SHM_DEST
#define SHM_DEST 01000
#endif
#ifndef SHM_LOCKED
#define SHM_LOCKED 02000
#endif

static void msleep(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000};
    nanosleep(&ts, 0);
}

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int child_status(pid_t c) {
    int st;
    if (waitpid(c, &st, 0) < 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

static long nattch(int id) {
    struct shmid_ds ds;
    return shmctl(id, IPC_STAT, &ds) == 0 ? (long)ds.shm_nattch : -1;
}

// The /proc/sysvipc/shm line of segment `id`: its nattch column, -1 if no line, -2 if no file
static long proc_nattch(int id, int *mode_out) {
    FILE *f = fopen("/proc/sysvipc/shm", "r");
    if (!f)
        return -2;
    char line[512];
    long r = -1;
    if (!fgets(line, sizeof line, f) || !strstr(line, "shmid")) {
        fclose(f);
        return -3;
    }
    while (fgets(line, sizeof line, f)) {
        long key, sid, size, cpid, lpid, na;
        unsigned mode;
        if (sscanf(line, "%ld %ld %o %ld %ld %ld %ld", &key, &sid, &mode, &size, &cpid, &lpid, &na) == 7 && sid == id) {
            r = na;
            if (mode_out)
                *mode_out = mode;
        }
    }
    fclose(f);
    return r;
}

static int attach_by_key(const char *arg) {
    key_t key = (key_t)strtol(arg, 0, 0);
    int id = shmget(key, 0, 0);
    if (id < 0) {
        perror("attach: shmget");
        return 2;
    }
    char *p = shmat(id, 0, 0);
    if (p == (void *)-1) {
        perror("attach: shmat");
        return 3;
    }
    if (strcmp(p, "from the parent")) {
        fprintf(stderr, "attach: data '%.20s'\n", p);
        return 4;
    }
    long n = nattch(id);
    strcpy(p + 4096, "second program was here");
    shmdt(p);
    return n == 2 ? 0 : 10 + (int)n;
}

static int checks(const char *self) {
    int forwarded = access("/proc/sysvipc/shm", R_OK) == 0;
    printf("info /proc/sysvipc/shm %s\n", forwarded ? "present (IPC service)" : "absent (in-kernel copy)");
    pid_t me = getpid();

    // ---- one segment, fork, exit, shmdt in a child
    int id = shmget(IPC_PRIVATE, 1 << 20, 0600);
    char *p = shmat(id, 0, 0);
    CHECK(id >= 0 && p != (void *)-1, "shmget + shmat");
    strcpy(p, "parent");
    struct shmid_ds ds;
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 1 && ds.shm_segsz == 1 << 20 && ds.shm_cpid == me && ds.shm_lpid == me && ds.shm_atime > 0 && ds.shm_dtime == 0,
          "IPC_STAT after shmat: nattch 1, size, cpid, lpid, atime set, dtime 0");
    pid_t c = fork();
    if (c == 0) {
        int ok = !strcmp(p, "parent") && nattch(id) == 2;
        strcpy(p, "child");
        ok &= shmdt(p) == 0;
        struct shmid_ds d;
        ok &= shmctl(id, IPC_STAT, &d) == 0 && d.shm_nattch == 1 && d.shm_lpid == getpid() && d.shm_dtime > 0;
        _exit(ok ? 0 : 1);
    }
    CHECK(child_status(c) == 0, "fork inherits the attachment (nattch 2); the child's shmdt: nattch 1, lpid, dtime");
    CHECK(!strcmp(p, "child") && nattch(id) == 1, "the child's write is seen; nattch 1");
    c = fork();
    if (c == 0)
        _exit(nattch(id) == 2 ? 0 : 1);
    CHECK(child_status(c) == 0 && nattch(id) == 1, "a child exiting without shmdt: its attachment goes (nattch 2 -> 1)");
    c = fork();
    if (c == 0) {
        execl("/bin/sleep", "sleep", "2", (char *)0);
        _exit(99);
    }
    msleep(700);
    long during = nattch(id);
    CHECK(child_status(c) == 0 && during == 1, "execve drops the attachment (nattch %ld while the child sleeps)", during);
    // Many children at once
    pid_t kids[8];
    int pfd[2];
    pipe(pfd);
    for (int i = 0; i < 8; i++) {
        kids[i] = fork();
        if (kids[i] == 0) {
            char b;
            close(pfd[1]);
            read(pfd[0], &b, 1);
            _exit(0);
        }
    }
    msleep(200);
    long many = nattch(id);
    close(pfd[1]);
    int all = 0;
    for (int i = 0; i < 8; i++)
        all |= child_status(kids[i]);
    close(pfd[0]);
    CHECK(many == 9 && all == 0 && nattch(id) == 1, "8 children attached at once: nattch %ld, back to 1", many);
    if (forwarded) {
        int mode = 0;
        long pn = proc_nattch(id, &mode);
        CHECK(pn == 1 && (mode & 0777) == 0600, "/proc/sysvipc/shm lists it (nattch %ld, mode %o)", pn, mode);
    }

    // ---- SHM_LOCK, SHM_RDONLY, permissions
    CHECK(shmctl(id, SHM_LOCK, 0) == 0, "SHM_LOCK");
    if (forwarded)
        CHECK(shmctl(id, IPC_STAT, &ds) == 0 && (ds.shm_perm.mode & SHM_LOCKED), "SHM_LOCKED in the mode");
    CHECK(shmctl(id, SHM_UNLOCK, 0) == 0 && shmctl(id, IPC_STAT, &ds) == 0 && !(ds.shm_perm.mode & SHM_LOCKED), "SHM_UNLOCK");
    char *ro = shmat(id, 0, SHM_RDONLY);
    CHECK(ro != (void *)-1 && !strcmp(ro, "child") && mprotect(ro, 4096, PROT_READ | PROT_WRITE) == -1 && errno == EACCES, "SHM_RDONLY: readable, mprotect to writable refused");
    CHECK(nattch(id) == 2 && shmdt(ro) == 0 && nattch(id) == 1, "read-only attachment counted and dropped");
    if (getuid() != 0) {
        int r4 = shmget(IPC_PRIVATE, 4096, 0400);
        errno = 0;
        void *w = shmat(r4, 0, 0);
        CHECK(w == (void *)-1 && errno == EACCES, "mode 0400: read-write shmat refused (EACCES)");
        void *r = shmat(r4, 0, SHM_RDONLY);
        CHECK(r != (void *)-1 && nattch(r4) == 1, "mode 0400: read-only shmat allowed; the refused one left no count");
        shmdt(r);
        shmctl(r4, IPC_RMID, 0);
    }
    CHECK(shmdt(p + 4096) == -1 && errno == EINVAL, "shmdt of an address inside, not the start: EINVAL");

    // ---- a second program attaching by key, IPC_RMID while attached
    key_t key = 0x82820000 + me % 0xffff;
    int k = shmget(key, 2 * 4096, IPC_CREAT | IPC_EXCL | 0600);
    char *kp = shmat(k, 0, 0);
    CHECK(k >= 0 && kp != (void *)-1, "shmget by key (IPC_CREAT|IPC_EXCL)");
    strcpy(kp, "from the parent");
    char keytext[32];
    snprintf(keytext, sizeof keytext, "%d", key);
    c = fork();
    if (c == 0) {
        execl(self, self, "attach", keytext, (char *)0);
        _exit(98);
    }
    int st = child_status(c);
    CHECK(st == 0 && !strcmp(kp + 4096, "second program was here") && nattch(k) == 1, "a second program attaches by key, sees the data, nattch 2 there (rc %d)", st);
    pipe(pfd);
    int back[2];
    pipe(back);
    c = fork();
    if (c == 0) {
        char b;
        close(pfd[1]);
        read(pfd[0], &b, 1);
        // removed by the parent: still attached here; can attach again by id (Linux allows)
        char *again = shmat(k, 0, 0);
        int ok = again != (void *)-1 && !strcmp(again, "from the parent");
        ok &= shmdt(again) == 0;
        write(back[1], &ok, sizeof ok);
        read(pfd[0], &b, 1);
        _exit(0);
    }
    msleep(100);
    CHECK(nattch(k) == 2, "two attachments (parent, forked child)");
    CHECK(shmctl(k, IPC_RMID, 0) == 0, "IPC_RMID while attached by two processes");
    CHECK(shmget(key, 0, 0) == -1 && errno == ENOENT, "removed: no longer found by key");
    CHECK(shmctl(k, IPC_STAT, &ds) == 0 && (ds.shm_perm.mode & SHM_DEST) && ds.shm_perm.__key == IPC_PRIVATE && ds.shm_nattch == 2, "removed: IPC_STAT still works, SHM_DEST, key private, nattch 2");
    if (forwarded)
        CHECK(proc_nattch(k, 0) == 2, "removed: /proc/sysvipc/shm still lists it");
    write(pfd[1], "x", 1);
    int ok = 0;
    read(back[0], &ok, sizeof ok);
    CHECK(ok, "removed: the child attaches again by id and detaches");
    write(pfd[1], "x", 1);
    close(pfd[1]);
    child_status(c);
    close(pfd[0]);
    close(back[0]);
    close(back[1]);
    CHECK(nattch(k) == 1 && !strcmp(kp, "from the parent"), "the child's exit leaves the parent's attachment and data");
    CHECK(shmdt(kp) == 0, "last shmdt");
    CHECK(shmctl(k, IPC_STAT, &ds) == -1 && errno == EINVAL, "gone after the last detach");
    if (forwarded)
        CHECK(proc_nattch(k, 0) == -1, "gone from /proc/sysvipc/shm");
    // removed with no attachment: gone at once
    int z = shmget(IPC_PRIVATE, 4096, 0600);
    CHECK(shmctl(z, IPC_RMID, 0) == 0 && shmctl(z, IPC_STAT, &ds) == -1 && errno == EINVAL, "IPC_RMID with no attachment: gone at once");

    // ---- limits
    struct shminfo si;
    CHECK(shmctl(0, IPC_INFO, (struct shmid_ds *)&si) >= 0 && si.shmmax == (1UL << 40) && si.shmmni == 4096, "IPC_INFO: shmmax 1 TiB, shmmni 4096");
    struct shm_info sinfo;
    CHECK(shmctl(0, SHM_INFO, (struct shmid_ds *)&sinfo) >= 0 && sinfo.used_ids >= 1, "SHM_INFO: used_ids %d", sinfo.used_ids);
    CHECK(shmget(IPC_PRIVATE, 0, 0600) == -1 && errno == EINVAL, "size 0: EINVAL");
    CHECK(shmget(IPC_PRIVATE, (1UL << 40) + 1, 0600) == -1 && errno == EINVAL, "size above SHMMAX: EINVAL");
    int big = shmget(IPC_PRIVATE, 3UL << 29, 0600);
    char *bp = big >= 0 ? shmat(big, 0, 0) : (void *)-1;
    if (bp != (void *)-1) {
        bp[0] = 1;
        bp[(3UL << 29) - 1] = 2;
    }
    CHECK(bp != (void *)-1 && bp[0] == 1 && bp[(3UL << 29) - 1] == 2, "a 1.5 GiB segment (pages on touch): first and last byte");
    if (bp != (void *)-1)
        shmdt(bp);
    shmctl(big, IPC_RMID, 0);

    // ---- IPC namespaces: a new one sees none of ours
    int nk = shmget(key + 1, 4096, IPC_CREAT | 0600);
    c = fork();
    if (c == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWIPC) != 0)
            _exit(77);
        int r = shmget(key + 1, 0, 0) == -1 && errno == ENOENT;
        int mine = shmget(key + 1, 4096, IPC_CREAT | 0600);
        r &= mine >= 0 && mine != nk;
        r &= shmctl(nk, IPC_STAT, &ds) == -1;
        _exit(r ? 0 : 1);
    }
    st = child_status(c);
    if (st == 77)
        printf("info unshare(CLONE_NEWUSER|CLONE_NEWIPC) refused: namespace check skipped\n");
    else
        CHECK(st == 0, "a new IPC namespace sees none of ours (by key or id) and makes its own");
    shmctl(nk, IPC_RMID, 0);

    shmdt(p);
    CHECK(shmctl(id, IPC_STAT, &ds) == 0 && ds.shm_nattch == 0, "nattch 0 after the last shmdt (not removed: stays)");
    shmctl(id, IPC_RMID, 0);
    if (fails)
        printf("SHMTEST2 FAIL %d\n", fails);
    else
        printf("SHMTEST2 PASS\n");
    return fails != 0;
}

static int bench(void) {
    int id = shmget(IPC_PRIVATE, 1 << 20, 0600);
    int n = 20000;
    for (int i = 0; i < 200; i++)
        shmdt(shmat(id, 0, 0));
    double best_at = 1e9, best_dt = 1e9;
    for (int round = 0; round < 5; round++) {
        double at = 0, dt = 0;
        for (int i = 0; i < n; i++) {
            double t0 = now_s();
            void *p = shmat(id, 0, 0);
            double t1 = now_s();
            shmdt(p);
            double t2 = now_s();
            at += t1 - t0;
            dt += t2 - t1;
        }
        if (at / n < best_at)
            best_at = at / n;
        if (dt / n < best_dt)
            best_dt = dt / n;
    }
    shmctl(id, IPC_RMID, 0);
    // the round trip alone: shmat of an id that is not there (answered by the service)
    double best_bad = 1e9;
    for (int round = 0; round < 3; round++) {
        double t0 = now_s();
        for (int i = 0; i < n; i++)
            shmat(0x7ffffffe, 0, 0);
        double t = (now_s() - t0) / n;
        if (t < best_bad)
            best_bad = t;
    }
    double t0 = now_s();
    for (int i = 0; i < 5000; i++) {
        int s = shmget(IPC_PRIVATE, 65536, 0600);
        shmctl(s, IPC_RMID, 0);
    }
    double getrm = (now_s() - t0) / 5000;
    t0 = now_s();
    struct shmid_ds ds;
    int s = shmget(IPC_PRIVATE, 65536, 0600);
    for (int i = 0; i < 20000; i++)
        shmctl(s, IPC_STAT, &ds);
    double stat = (now_s() - t0) / 20000;
    shmctl(s, IPC_RMID, 0);
    // page faults: 256 MiB touched page by page, 3 rounds (a new segment each)
    size_t sz = 256UL << 20;
    double best_pf = 1e9;
    for (int round = 0; round < 3; round++) {
        int b = shmget(IPC_PRIVATE, sz, 0600);
        volatile char *bp = shmat(b, 0, 0);
        t0 = now_s();
        for (size_t o = 0; o < sz; o += 4096)
            bp[o] = 1;
        double t = now_s() - t0;
        if (t < best_pf)
            best_pf = t;
        shmdt((void *)bp);
        shmctl(b, IPC_RMID, 0);
    }
    printf("SHMBENCH shmat_bad_us %.2f\n", best_bad * 1e6);
    printf("SHMBENCH shmat_us %.2f shmdt_us %.2f shmget_rmid_us %.2f ipc_stat_us %.2f fault_us_per_page %.3f faults_per_s %.0f\n", best_at * 1e6, best_dt * 1e6, getrm * 1e6, stat * 1e6,
           best_pf * 1e6 / (sz / 4096), (sz / 4096) / best_pf);
    return 0;
}

#define CERR(what) do { cerr++; printf("worker %d: %s failed: errno %d\n", k, what, errno); fflush(stdout); } while (0)

// The kill test: one big segment with a counter area the writer advances and the readers
// check; small segments made, attached, checked and removed all the time.
static int kill_test(int secs) {
    size_t sz = 64UL << 20;
    int id = shmget(IPC_PRIVATE, sz, 0600);
    volatile uint64_t *p = shmat(id, 0, 0);
    if (id < 0 || p == (void *)-1) {
        printf("SHMKILL FAIL setup\n");
        return 1;
    }
    // a pattern over the whole segment: page i holds i
    for (size_t i = 0; i < sz / 4096; i++)
        p[i * 512] = i;
    double end = now_s() + secs;
    pid_t kids[3];
    for (int k = 0; k < 3; k++) {
        kids[k] = fork();
        if (kids[k] == 0) {
            long errs = 0, ops = 0, calls = 0, cerr = 0;
            if (k == 0) {
                // writer: the counter at word 1 goes up; word 2 = its square (low bits)
                for (uint64_t n = 1; now_s() < end; n++) {
                    p[1] = n;
                    p[2] = n * n;
                    ops++;
                    if ((n & 0xfffff) == 0) {
                        // and a fresh segment cycle now and then
                        int s = shmget(IPC_PRIVATE, 1 << 16, 0600);
                        char *q = s >= 0 ? shmat(s, 0, 0) : (void *)-1;
                        calls++;
                        if (s < 0) {
                            CERR("shmget");
                        } else if (q == (void *)-1) {
                            CERR("shmat");
                        } else {
                            q[100] = 7;
                            if (nattch(s) != 1 || q[100] != 7)
                                CERR("nattch of the new segment");
                            shmdt(q);
                        }
                        if (s >= 0 && shmctl(s, IPC_RMID, 0) != 0)
                            CERR("IPC_RMID");
                    }
                }
            } else {
                uint64_t last = 0;
                while (now_s() < end) {
                    uint64_t n = p[1];
                    if (n < last)
                        errs++;
                    last = n;
                    size_t i = (ops * 7919) % (sz / 4096);
                    if (p[i * 512] != i && i != 0)
                        errs++;
                    ops++;
                    if ((ops & 0xffff) == 0) {
                        calls++;
                        long na = nattch(id);
                        if (na < 2)
                            CERR("IPC_STAT nattch");
                        void *q = shmat(id, 0, SHM_RDONLY);
                        if (q == (void *)-1 || ((volatile uint64_t *)q)[512] != 1)
                            CERR("shmat RDONLY");
                        if (q != (void *)-1)
                            shmdt(q);
                    }
                }
            }
            printf("worker %d: ops %ld errors %ld calls %ld call_errors %ld\n", k, ops, errs, calls, cerr);
            fflush(stdout);
            _exit(errs || cerr ? 1 : 0);
        }
    }
    int bad = 0;
    for (int k = 0; k < 3; k++)
        bad |= child_status(kids[k]) != 0;
    long n = nattch(id);
    size_t wrong = 0;
    for (size_t i = 1; i < sz / 4096; i++)
        wrong += p[i * 512] != i;
    shmdt((void *)p);
    shmctl(id, IPC_RMID, 0);
    if (bad || n != 1 || wrong)
        printf("SHMKILL FAIL workers %d nattch %ld wrong pages %zu\n", bad, n, wrong);
    else
        printf("SHMKILL PASS nattch %ld, 64 MiB intact\n", n);
    return bad || n != 1 || wrong;
}

int main(int argc, char **argv) {
    setvbuf(stdout, 0, _IOLBF, 0);
    if (argc > 2 && !strcmp(argv[1], "attach"))
        return attach_by_key(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "bench"))
        return bench();
    if (argc > 2 && !strcmp(argv[1], "kill"))
        return kill_test(atoi(argv[2]));
    return checks(argv[0]);
}
