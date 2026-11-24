// procid: the process-identity calls lx-proc serves (wave 10, Group 7b-1), the same in
// every mode (forwarded to lx-proc, `lx.proc=kernel`, `lx=kernel`). Run as root (sudo).
//
//   setuid family with capabilities, setgroups, setfsuid; prctl names (thread and process,
//   /proc/<pid>/comm and task/<tid>/comm), dumpable (inherited by fork), pdeathsig,
//   keepcaps, no_new_privs, subreaper; setsid/setpgid rules and races (threads racing for
//   one setsid, parent and child racing setpgid); getpgid/getsid; limits and prlimit64 of
//   another process; uname; unshare/setns of UTS (sethostname seen by a child and by a
//   process that joins with setns), mount and network namespaces; an unprivileged user
//   namespace with its own host name; syslog and acct permissions.
//
//   gcc -O1 -w -pthread procid.c -o procid.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/capability.h>

static int fails;
#define CHECK(c, ...)                                                       \
    do {                                                                    \
        if (!(c)) {                                                         \
            printf("FAIL %s:%d: ", __func__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf(" (errno %d)\n", errno);                                 \
            fflush(stdout);                                                 \
            fails++;                                                        \
        }                                                                   \
    } while (0)

// Raw calls (glibc's setuid family broadcasts to every thread; these are one thread's)
static long rsetresuid(uid_t r, uid_t e, uid_t s) { return syscall(SYS_setresuid, r, e, s); }
static long rsetuid(uid_t u) { return syscall(SYS_setuid, u); }
static long rsetreuid(uid_t r, uid_t e) { return syscall(SYS_setreuid, r, e); }
static long rsetgid(gid_t g) { return syscall(SYS_setgid, g); }

static unsigned long long cap_eff(void) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    memset(d, 0, sizeof d);
    if (syscall(SYS_capget, &h, d) != 0) return ~0ULL;
    return d[0].effective | (unsigned long long)d[1].effective << 32;
}

// Runs f in a child; its failures count here
static void in_child(const char *name, void (*f)(void)) {
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        fails = 0;
        f();
        fflush(stdout);
        _exit(fails ? 1 : 0);
    }
    int st = 0;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("FAIL %s (status %#x)\n", name, st);
        fails++;
    } else {
        printf("ok   %s\n", name);
    }
}

static void t_setuid(void) {
    uid_t r, e, s;
    // root keeps saved 0: may come back, and the capabilities come back with euid 0
    CHECK(rsetresuid(1000, 1000, 0) == 0, "setresuid(1000,1000,0)");
    getresuid(&r, &e, &s);
    CHECK(r == 1000 && e == 1000 && s == 0, "ids %u %u %u", r, e, s);
    CHECK(cap_eff() == 0, "effective caps after euid 1000: %llx", cap_eff());
    CHECK(rsetreuid(-1, 0) == 0, "seteuid(0) from saved 0");
    CHECK(geteuid() == 0, "euid %u", geteuid());
    CHECK(cap_eff() != 0, "effective caps back with euid 0");
    // setuid as privileged sets all three
    CHECK(rsetuid(1001) == 0, "setuid(1001)");
    getresuid(&r, &e, &s);
    CHECK(r == 1001 && e == 1001 && s == 1001, "ids %u %u %u", r, e, s);
    CHECK(cap_eff() == 0, "no caps after setuid(1001)");
    // unprivileged: only to the real or saved id
    errno = 0;
    CHECK(rsetuid(0) == -1 && errno == EPERM, "setuid(0) unprivileged");
    CHECK(rsetuid(1001) == 0, "setuid(own)");
    errno = 0;
    CHECK(rsetresuid(1002, -1, -1) == -1 && errno == EPERM, "setresuid to a foreign id");
    errno = 0;
    CHECK(rsetgid(5) == -1 && errno == EPERM, "setgid unprivileged");
    // setfsuid answers the current (effective) id
    CHECK(syscall(SYS_setfsuid, -1) == 1001, "setfsuid(-1) = %ld", syscall(SYS_setfsuid, -1));
}

static void t_setreuid(void) {
    // setreuid(r, e) with e != r: the saved id follows e
    CHECK(rsetreuid(1000, 1001) == 0, "setreuid(1000,1001)");
    uid_t r, e, s;
    getresuid(&r, &e, &s);
    CHECK(r == 1000 && e == 1001 && s == 1001, "ids %u %u %u", r, e, s);
    // unprivileged swap of real and effective
    CHECK(rsetreuid(1001, 1000) == 0, "swap");
    getresuid(&r, &e, &s);
    CHECK(r == 1001 && e == 1000 && s == 1000, "ids after swap %u %u %u", r, e, s);
}

static void t_setgroups(void) {
    gid_t g[3] = {10, 20, 30}, out[8];
    CHECK(setgroups(3, g) == 0, "setgroups(3)");
    int n = getgroups(8, out);
    CHECK(n == 3 && out[0] == 10 && out[2] == 30, "getgroups %d", n);
    CHECK(setgroups(0, NULL) == 0, "setgroups(0)");
    CHECK(getgroups(8, out) == 0, "no groups");
    errno = 0;
    CHECK(syscall(SYS_setgroups, 65537, g) == -1 && errno == EINVAL, "setgroups(65537)");
    errno = 0;
    CHECK(syscall(SYS_setgroups, 2, (void *)8) == -1 && errno == EFAULT, "setgroups bad pointer");
    CHECK(rsetresuid(1000, 1000, 1000) == 0, "drop root");
    errno = 0;
    CHECK(syscall(SYS_setgroups, 1, g) == -1 && errno == EPERM, "setgroups unprivileged");
}

static char comm_file[64];
static void read_comm(const char *path, char *out) {
    out[0] = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return;
    int n = read(fd, out, 31);
    close(fd);
    if (n > 0 && out[n - 1] == '\n') n--;
    out[n > 0 ? n : 0] = 0;
}

static void *thr_name(void *arg) {
    char got[32], path[64];
    CHECK(prctl(PR_SET_NAME, "procid-thread") == 0, "thread PR_SET_NAME");
    prctl(PR_GET_NAME, got);
    CHECK(strcmp(got, "procid-thread") == 0, "thread name %s", got);
    snprintf(path, sizeof path, "/proc/self/task/%ld/comm", syscall(SYS_gettid));
    read_comm(path, got);
    CHECK(strcmp(got, "procid-thread") == 0, "task comm %s", got);
    return NULL;
}

static void t_prctl(void) {
    char got[32];
    CHECK(prctl(PR_SET_NAME, "procid-main-long-name") == 0, "PR_SET_NAME");
    memset(got, 'x', sizeof got);
    CHECK(prctl(PR_GET_NAME, got) == 0, "PR_GET_NAME");
    CHECK(strcmp(got, "procid-main-lo") == 0 || strcmp(got, "procid-main-lon") == 0, "name cut to 15: %s", got);
    read_comm("/proc/self/comm", got);
    CHECK(strcmp(got, "procid-main-lon") == 0, "/proc/self/comm %s", got);
    pthread_t t;
    pthread_create(&t, NULL, thr_name, NULL);
    pthread_join(t, NULL);
    read_comm("/proc/self/comm", got);
    CHECK(strcmp(got, "procid-main-lon") == 0, "main comm unchanged by thread: %s", got);
    // dumpable: 0/1 only; inherited by a child
    CHECK(prctl(PR_GET_DUMPABLE) == 1, "dumpable 1 by default");
    CHECK(prctl(PR_SET_DUMPABLE, 0) == 0 && prctl(PR_GET_DUMPABLE) == 0, "dumpable 0");
    errno = 0;
    CHECK(prctl(PR_SET_DUMPABLE, 2) == -1 && errno == EINVAL, "dumpable 2");
    pid_t p = fork();
    if (p == 0) _exit(prctl(PR_GET_DUMPABLE) == 0 ? 0 : 1);
    int st;
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child inherits dumpable 0");
    // the child also starts with the parent thread's name
    p = fork();
    if (p == 0) {
        char n[32];
        prctl(PR_GET_NAME, n);
        _exit(strcmp(n, "procid-main-lon") == 0 ? 0 : 1);
    }
    waitpid(p, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child inherits the name");
    CHECK(prctl(PR_SET_DUMPABLE, 1) == 0 && prctl(PR_GET_DUMPABLE) == 1, "dumpable 1");
    // parent-death signal
    int sig = -1;
    CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1) == 0, "PR_SET_PDEATHSIG");
    CHECK(prctl(PR_GET_PDEATHSIG, &sig) == 0 && sig == SIGUSR1, "PR_GET_PDEATHSIG %d", sig);
    errno = 0;
    CHECK(prctl(PR_SET_PDEATHSIG, 65) == -1 && errno == EINVAL, "pdeathsig 65");
    // keepcaps
    CHECK(prctl(PR_SET_KEEPCAPS, 1) == 0 && prctl(PR_GET_KEEPCAPS) == 1, "keepcaps");
    errno = 0;
    CHECK(prctl(PR_SET_KEEPCAPS, 2) == -1 && errno == EINVAL, "keepcaps 2");
    // subreaper
    int sr = -1;
    CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0, "subreaper");
    CHECK(prctl(PR_GET_CHILD_SUBREAPER, &sr) == 0 && sr == 1, "subreaper read %d", sr);
    // no_new_privs: set once, never cleared
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0, "nnp 0");
    errno = 0;
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == -1 && errno == EINVAL, "nnp set 0");
    CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "nnp 1");
    // an option of the kernel's mechanism still works (seccomp mode)
    CHECK(prctl(PR_GET_SECCOMP) == 0, "PR_GET_SECCOMP");
}

static volatile int go;
static int won, lost;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static void *thr_setsid(void *arg) {
    while (!go) ;
    long r = syscall(SYS_setsid);
    pthread_mutex_lock(&mu);
    if (r > 0) won++;
    else if (errno == EPERM) lost++;
    pthread_mutex_unlock(&mu);
    return NULL;
}

static void t_sessions(void) {
    // getpgid/getsid of no process
    errno = 0;
    CHECK(getpgid(999999) == -1 && errno == ESRCH, "getpgid(999999)");
    errno = 0;
    CHECK(getsid(999999) == -1 && errno == ESRCH, "getsid(999999)");
    // a non-leader makes a session; a leader may not again, nor change its group
    pid_t me = getpid();
    long s = syscall(SYS_setsid);
    CHECK(s == me, "setsid = %ld", s);
    CHECK(getsid(0) == me && getpgid(0) == me, "leader of session and group");
    errno = 0;
    CHECK(syscall(SYS_setsid) == -1 && errno == EPERM, "setsid twice");
    errno = 0;
    CHECK(setpgid(0, 0) == -1 && errno == EPERM, "session leader setpgid");
    // parent and child race for the child's group (as a shell does): both succeed
    for (int i = 0; i < 20; i++) {
        int pfd[2];
        pipe(pfd);
        pid_t c = fork();
        if (c == 0) {
            long r = setpgid(0, 0);
            char b;
            read(pfd[0], &b, 1);
            _exit(r == 0 && getpgid(0) == getpid() ? 0 : 1);
        }
        long r = setpgid(c, c);
        CHECK(r == 0 || errno == ESRCH, "parent setpgid(child) %ld", r);
        write(pfd[1], "x", 1);
        int st;
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "child's own setpgid");
        close(pfd[0]);
        close(pfd[1]);
    }
    // setpgid of a process that is not a child: ESRCH
    errno = 0;
    CHECK(setpgid(1, 1) == -1 && errno == ESRCH, "setpgid(1)");
}

static void t_setsid_race(void) {
    // a group member (not a leader) whose threads race for setsid: one wins
    pthread_t t[6];
    for (int i = 0; i < 6; i++) pthread_create(&t[i], NULL, thr_setsid, NULL);
    go = 1;
    for (int i = 0; i < 6; i++) pthread_join(t[i], NULL);
    CHECK(won == 1 && lost == 5, "setsid race: %d won, %d lost", won, lost);
}

static void t_limits(void) {
    struct rlimit r, old;
    CHECK(getrlimit(RLIMIT_NOFILE, &r) == 0, "getrlimit");
    struct rlimit n = {64, r.rlim_max};
    CHECK(setrlimit(RLIMIT_NOFILE, &n) == 0, "setrlimit soft 64");
    CHECK(getrlimit(RLIMIT_NOFILE, &r) == 0 && r.rlim_cur == 64, "soft %llu", (unsigned long long)r.rlim_cur);
    n.rlim_cur = n.rlim_max + 1;
    errno = 0;
    CHECK(n.rlim_max == RLIM_INFINITY || (setrlimit(RLIMIT_NOFILE, &n) == -1 && errno == EINVAL), "soft above hard");
    errno = 0;
    CHECK(syscall(SYS_setrlimit, 99, &n) == -1 && errno == EINVAL, "resource 99");
    errno = 0;
    CHECK(syscall(SYS_setrlimit, RLIMIT_CORE, (void *)8) == -1 && errno == EFAULT, "bad pointer");
    // prlimit64 of itself returns the old value
    struct rlimit c = {4096, 8192};
    CHECK(prlimit(0, RLIMIT_CORE, &c, NULL) == 0, "prlimit set core");
    struct rlimit c2 = {1024, 8192};
    CHECK(prlimit(getpid(), RLIMIT_CORE, &c2, &old) == 0 && old.rlim_cur == 4096 && old.rlim_max == 8192, "prlimit old %llu", (unsigned long long)old.rlim_cur);
    // another process: root may, an unprivileged user on root's may not
    int pfd[2];
    pipe(pfd);
    pid_t k = fork();
    if (k == 0) {
        char b;
        read(pfd[0], &b, 1);
        _exit(0);
    }
    CHECK(prlimit(k, RLIMIT_CORE, &c, &old) == 0, "root prlimit of a child");
    pid_t u = fork();
    if (u == 0) {
        rsetresuid(1000, 1000, 1000);
        struct rlimit o;
        errno = 0;
        int bad = !(prlimit(k, RLIMIT_CORE, NULL, &o) == -1 && errno == EPERM);
        // raising the hard limit without CAP_SYS_RESOURCE
        struct rlimit g;
        getrlimit(RLIMIT_CORE, &g);
        if (g.rlim_max != RLIM_INFINITY) {
            g.rlim_max++;
            errno = 0;
            bad |= !(setrlimit(RLIMIT_CORE, &g) == -1 && errno == EPERM) << 1;
        }
        errno = 0;
        bad |= !(prlimit(999999, RLIMIT_CORE, NULL, &o) == -1 && errno == ESRCH) << 2;
        _exit(bad);
    }
    int st;
    waitpid(u, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "unprivileged prlimit checks %d", WEXITSTATUS(st));
    write(pfd[1], "x", 1);
    waitpid(k, &st, 0);
}

static void t_uname(void) {
    struct utsname u;
    CHECK(uname(&u) == 0, "uname");
    CHECK(strcmp(u.sysname, "Linux") == 0 && strcmp(u.machine, "x86_64") == 0, "uname %s %s", u.sysname, u.machine);
    CHECK(strlen(u.release) > 0 && strlen(u.nodename) > 0, "release and node");
    errno = 0;
    CHECK(syscall(SYS_uname, (void *)8) == -1 && errno == EFAULT, "uname bad pointer");
}

static void t_uts(void) {
    struct utsname before;
    uname(&before);
    int sync1[2], sync2[2];
    pipe(sync1);
    pipe(sync2);
    pid_t c = fork();
    if (c == 0) {
        // a UTS namespace of its own with a new name
        int bad = 0;
        if (unshare(CLONE_NEWUTS) != 0) bad |= 1;
        if (sethostname("procid-uts", 10) != 0) bad |= 2;
        if (setdomainname("procid.dom", 10) != 0) bad |= 4;
        struct utsname u;
        uname(&u);
        if (strcmp(u.nodename, "procid-uts") || strcmp(u.domainname, "procid.dom")) bad |= 8;
        // a child of it sees the name
        pid_t g = fork();
        if (g == 0) {
            struct utsname v;
            uname(&v);
            _exit(strcmp(v.nodename, "procid-uts") ? 1 : 0);
        }
        int st;
        waitpid(g, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) bad |= 16;
        // too long
        errno = 0;
        char big[70];
        memset(big, 'a', sizeof big);
        if (!(sethostname(big, 65) == -1 && errno == EINVAL)) bad |= 32;
        write(sync1[1], "r", 1);
        char b;
        read(sync2[0], &b, 1);
        _exit(bad);
    }
    char b;
    read(sync1[0], &b, 1);
    // our name is unchanged
    struct utsname now;
    uname(&now);
    CHECK(strcmp(now.nodename, before.nodename) == 0, "parent's name kept: %s", now.nodename);
    // another process joins the namespace with setns and sees the name
    pid_t j = fork();
    if (j == 0) {
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/ns/uts", c);
        int fd = open(path, O_RDONLY);
        if (fd < 0) _exit(1);
        if (setns(fd, CLONE_NEWUTS) != 0) _exit(2);
        struct utsname v;
        uname(&v);
        if (strcmp(v.nodename, "procid-uts")) _exit(3);
        // the wrong kind for this file
        errno = 0;
        if (!(setns(fd, CLONE_NEWNET) == -1 && errno == EINVAL)) _exit(4);
        _exit(0);
    }
    int st;
    waitpid(j, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "setns into the UTS namespace: %d", WEXITSTATUS(st));
    write(sync2[1], "g", 1);
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "unshare+sethostname child: %d", WEXITSTATUS(st));
    // setns on things that are not namespaces
    errno = 0;
    CHECK(setns(999, 0) == -1 && errno == EBADF, "setns bad fd");
    int fd = open("/proc/self/comm", O_RDONLY);
    errno = 0;
    CHECK(setns(fd, 0) == -1 && errno == EINVAL, "setns of a plain file");
    close(fd);
}

static void t_mnt_net(void) {
    char a[64] = "", b[64] = "";
    readlink("/proc/self/ns/net", a, sizeof a - 1);
    CHECK(unshare(CLONE_NEWNS) == 0, "unshare(CLONE_NEWNS)");
    CHECK(unshare(CLONE_NEWNET) == 0, "unshare(CLONE_NEWNET)");
    readlink("/proc/self/ns/net", b, sizeof b - 1);
    CHECK(strcmp(a, b) != 0, "new net namespace %s %s", a, b);
    CHECK(access("/etc/passwd", R_OK) == 0, "files still there in the new mount namespace");
    errno = 0;
    CHECK(unshare(0x80000000) == -1 && errno == EINVAL, "unshare of an unknown flag");
}

static void t_unpriv(void) {
    CHECK(rsetresuid(1000, 1000, 1000) == 0, "drop root");
    errno = 0;
    CHECK(unshare(CLONE_NEWUTS) == -1 && errno == EPERM, "unprivileged unshare(UTS)");
    errno = 0;
    CHECK(sethostname("x", 1) == -1 && errno == EPERM, "unprivileged sethostname");
    errno = 0;
    char buf[16];
    CHECK(klogctl(3, buf, sizeof buf) == -1 && errno == EPERM, "unprivileged syslog");
    errno = 0;
    CHECK(syscall(SYS_acct, NULL) == -1 && errno == EPERM, "unprivileged acct");
    // a user namespace gives a host name of its own
    if (unshare(CLONE_NEWUSER | CLONE_NEWUTS) == 0) {
        CHECK(sethostname("procid-user", 11) == 0, "sethostname in a user namespace");
        struct utsname u;
        uname(&u);
        CHECK(strcmp(u.nodename, "procid-user") == 0, "name %s", u.nodename);
    } else {
        CHECK(0, "unshare(CLONE_NEWUSER|CLONE_NEWUTS)");
    }
}

static void t_admin(void) {
    CHECK(klogctl(10, NULL, 0) > 0, "syslog SIZE_BUFFER");
    char buf[256];
    CHECK(klogctl(3, buf, sizeof buf) >= 0, "syslog READ_ALL");
    CHECK(syscall(SYS_acct, NULL) == 0, "acct(NULL) as root");
}

// `procid loop SECONDS [THREADS]`: lx-proc's calls in a loop (for kill tests): each thread
// makes prctl name set/get, uname, getsid, setpgid(0, own group), setrlimit to the same
// value, setresuid to the same ids; any error is counted and the first few are printed.
static volatile int stop;
static long calls[16], errs[16];
static void *loop_thr(void *arg) {
    long i = (long)arg;
    struct utsname u;
    struct rlimit r;
    char name[16];
    getrlimit(RLIMIT_CORE, &r);
    while (!stop) {
        long bad = 0;
        bad |= prctl(PR_SET_NAME, "procloop") != 0;
        bad |= (prctl(PR_GET_NAME, name) != 0 || strcmp(name, "procloop")) << 1;
        bad |= (uname(&u) != 0) << 2;
        bad |= (getsid(0) <= 0) << 3;
        bad |= (setrlimit(RLIMIT_CORE, &r) != 0) << 4;
        bad |= (syscall(SYS_setresuid, -1, -1, -1) != 0) << 5;
        bad |= (setpgid(0, getpgid(0)) != 0 && errno != EPERM) << 6;
        calls[i] += 7;
        if (bad) {
            if (errs[i] < 5) printf("loop error: thread %ld mask %#lx errno %d\n", i, bad, errno);
            errs[i]++;
        }
    }
    return NULL;
}

static int loop_main(int secs, int n) {
    pthread_t t[16];
    if (n > 16) n = 16;
    for (long i = 0; i < n; i++) pthread_create(&t[i], NULL, loop_thr, (void *)i);
    sleep(secs);
    stop = 1;
    long c = 0, e = 0;
    for (int i = 0; i < n; i++) {
        pthread_join(t[i], NULL);
        c += calls[i];
        e += errs[i];
    }
    printf("PROCLOOP calls %ld errors %ld\n", c, e);
    return e ? 1 : 0;
}


// setns while another thread swaps the descriptor (review F1): the check and the join must
// be of the same namespace. In a user namespace of its own (all capabilities there), with a
// second thread, setns of its own UTS namespace is allowed; joining init's user namespace
// is not (more than one thread; not below its own). A thread swaps descriptor 50 between
// the two while the main thread calls setns(50, 0): the user namespace must never change.
static volatile int swap_stop;
static int swap_ok, swap_bad;
static void *thr_swap(void *arg) {
    while (!swap_stop) {
        dup2(swap_bad, 50);
        dup2(swap_ok, 50);
    }
    return NULL;
}

static void t_setns_race(void) {
    CHECK(rsetresuid(1000, 1000, 1000) == 0, "drop root");
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/ns/user", getppid());
    swap_bad = open("/proc/1/ns/user", O_RDONLY);
    if (swap_bad < 0) swap_bad = open(path, O_RDONLY);
    if (swap_bad < 0) {
        printf("     (no outside user namespace file to open: skipped)\n");
        return;
    }
    if (unshare(CLONE_NEWUSER) != 0) {
        CHECK(0, "unshare(CLONE_NEWUSER)");
        return;
    }
    char mine[64] = "", now[64] = "";
    readlink("/proc/self/ns/user", mine, sizeof mine - 1);
    swap_ok = open("/proc/self/ns/uts", O_RDONLY);
    CHECK(swap_ok >= 0, "open own uts");
    dup2(swap_ok, 50);
    pthread_t t;
    pthread_create(&t, NULL, thr_swap, NULL);
    int joined = 0, ok = 0, refused = 0;
    for (int i = 0; i < 3000 && !joined; i++) {
        long r = setns(50, 0);
        if (r == 0) ok++;
        else refused++;
        memset(now, 0, sizeof now);
        readlink("/proc/self/ns/user", now, sizeof now - 1);
        if (strcmp(now, mine)) joined = 1;
    }
    swap_stop = 1;
    pthread_join(t, NULL);
    printf("     setns race: %d allowed (own uts), %d refused, joined another user namespace: %s\n", ok, refused, joined ? "YES" : "no");
    CHECK(!joined, "setns joined the swapped-in namespace without its checks");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc > 2 && !strcmp(argv[1], "loop")) return loop_main(atoi(argv[2]), argc > 3 ? atoi(argv[3]) : 2);
    if (geteuid() != 0) {
        printf("procid: run as root\n");
        return 2;
    }
    in_child("setuid", t_setuid);
    in_child("setreuid", t_setreuid);
    in_child("setgroups", t_setgroups);
    in_child("prctl", t_prctl);
    in_child("sessions", t_sessions);
    in_child("setsid race", t_setsid_race);
    in_child("limits", t_limits);
    in_child("uname", t_uname);
    in_child("uts namespaces", t_uts);
    in_child("mount and net namespaces", t_mnt_net);
    in_child("unprivileged", t_unpriv);
    in_child("syslog and acct", t_admin);
    in_child("setns descriptor race", t_setns_race);
    printf(fails ? "procid FAIL (%d)\n" : "procid PASS\n", fails);
    return fails ? 1 : 0;
}
