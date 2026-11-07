// Administration calls: syslog, sysfs, ustat, vhangup, acct, swapon/swapoff, quotactl.
// Run as a user and as root. Build: gcc -O1 -w -o admin admin_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int on_hydra(void) {
    struct utsname u;
    uname(&u);
    return strstr(u.release, "hydra") != NULL;
}

static int read_int(const char *path, int dflt) {
    FILE *f = fopen(path, "r");
    int v = dflt;
    if (f) {
        fscanf(f, "%d", &v);
        fclose(f);
    }
    return v;
}

static void common(void) {
    // sysfs: count, index of "proc", and back
    int n = syscall(SYS_sysfs, 3);
    int i = syscall(SYS_sysfs, 1, "proc");
    char name[64] = {0};
    int r = syscall(SYS_sysfs, 2, i, name);
    check(n > 0 && i >= 0 && r == 0 && !strcmp(name, "proc"), "sysfs: count, index of proc, name of that index");
    errno = 0;
    check(syscall(SYS_sysfs, 1, "nosuchfs") == -1 && errno == EINVAL, "sysfs of an unknown type: EINVAL");
    // ustat of the root file system's device
    struct stat st;
    stat("/", &st);
    unsigned char us[32];
    errno = 0;
    long u = syscall(SYS_ustat, (unsigned)st.st_dev, us);
    check(u == 0 || errno == EINVAL, "ustat of the root device answers");
}

static int hup;
static void on_hup(int s) { hup = s; }

static void privileged(void) {
    char tmp[64];
    snprintf(tmp, sizeof tmp, "/tmp/adm.%d.%ld", getpid(), (long)time(NULL));
    mkdir(tmp, 0755);

    // syslog
    int size = syscall(SYS_syslog, 10, 0, 0);
    static char log[1 << 17];
    int got = syscall(SYS_syslog, 3, log, sizeof log);
    check(size > 0 && got > 0 && log[0] == '<', "syslog: buffer size and the log read back");
    if (on_hydra()) {
        check(syscall(SYS_syslog, 5, 0, 0) == 0, "syslog clear");
        got = syscall(SYS_syslog, 3, log, sizeof log);
        check(got >= 0 && got < size, "after clearing, reading all gives only newer output");
    }

    // acct
    char acctf[96];
    snprintf(acctf, sizeof acctf, "%s/pacct", tmp);
    close(open(acctf, O_CREAT | O_WRONLY | O_TRUNC, 0600));
    check(acct(acctf) == 0, "acct on");
    pid_t c1 = fork();
    if (c1 == 0) {
        execl("/bin/true", "true", (char *)NULL);
        _exit(127);
    }
    waitpid(c1, NULL, 0);
    pid_t c2 = fork();
    if (c2 == 0) _exit(3);
    waitpid(c2, NULL, 0);
    getpid();
    usleep(100000);
    acct(NULL);
    int fd = open(acctf, O_RDONLY);
    unsigned char rec[64 * 64];
    int len = read(fd, rec, sizeof rec);
    close(fd);
    // Version 2 records (Ubuntu's): exit code at 32, command at 36; no PIDs
    extern char *program_invocation_short_name;
    int saw_true = 0, saw_fork = 0;
    for (int o = 0; o + 64 <= len; o += 64) {
        unsigned char *r = rec + o;
        uint32_t code;
        memcpy(&code, r + 32, 4);
        if (r[1] != 2) continue;
        if (!strncmp((char *)r + 36, "true", 5) && code == 0 && !(r[0] & 1)) saw_true = 1;
        if (!strncmp((char *)r + 36, program_invocation_short_name, 15) && (r[0] & 1) && code == (3 << 8)) saw_fork = 1;
    }
    check(saw_true, "acct record: the exec'd true, exit 0");
    check(saw_fork, "acct record: the child that did not exec (AFORK), exit 3");

    // swap
    char swapf[96];
    snprintf(swapf, sizeof swapf, "%s/swapfile", tmp);
    fd = open(swapf, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    static char page[4096];
    for (int p = 0; p < 256; p++) write(fd, page, sizeof page);
    uint32_t hdr[3] = {1, 255, 0};   // version, last_page, nr_badpages
    pwrite(fd, hdr, sizeof hdr, 1024);
    pwrite(fd, "SWAPSPACE2", 10, 4086);
    close(fd);
    int on = swapon(swapf, 0);
    if (on != 0 && !on_hydra() && (errno == EINVAL || errno == EPERM)) {
        printf("skip swap (this file system refuses swap files: %s)\n", strerror(errno));
    } else {
        FILE *f = fopen("/proc/swaps", "r");
        char line[512];
        int listed = 0;
        while (f && fgets(line, sizeof line, f)) listed |= strstr(line, "swapfile") != NULL;
        if (f) fclose(f);
        check(on == 0 && listed, "swapon: the file is listed in /proc/swaps");
        errno = 0;
        check(swapon(swapf, 0) == -1 && errno == EBUSY, "swapon of an active area: EBUSY");
        check(swapoff(swapf) == 0, "swapoff");
        errno = 0;
        check(swapoff(swapf) == -1 && errno == EINVAL, "swapoff of an inactive area: EINVAL");
    }
    unlink(swapf);

    // quotactl
    check(quotactl(QCMD(Q_SYNC, USRQUOTA), NULL, 0, NULL) == 0, "quotactl Q_SYNC of every file system");
    errno = 0;
    check(quotactl(QCMD(Q_GETFMT, USRQUOTA), tmp, 0, (caddr_t)page) == -1 && errno == ENOTBLK, "quotactl on a directory: ENOTBLK");

    // vhangup: a session of our own on a pseudo-terminal
    int pp[2];
    pipe(pp);
    pid_t c = fork();
    if (c == 0) {
        int r = 0;
        setsid();
        int m = posix_openpt(O_RDWR | O_NOCTTY);
        grantpt(m);
        unlockpt(m);
        int s = open(ptsname(m), O_RDWR);   // our controlling terminal now
        signal(SIGHUP, on_hup);
        if (syscall(SYS_vhangup) != 0) r |= 1;
        usleep(50000);
        if (hup != SIGHUP) r |= 2;
        char b[4];
        if (read(s, b, sizeof b) != 0) r |= 4;
        errno = 0;
        if (write(s, "x", 1) != -1 || errno != EIO) r |= 8;
        write(pp[1], &r, sizeof r);
        _exit(0);
    }
    int r = -1;
    read(pp[0], &r, sizeof r);
    waitpid(c, NULL, 0);
    check(r == 0, "vhangup: SIGHUP, then old terminal descriptors read EOF and fail writes (EIO)");
    if (r) printf("     vhangup bits %#x\n", r);

    unlink(acctf);
    rmdir(tmp);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    common();
    if (geteuid() != 0) {
        if (read_int("/proc/sys/kernel/dmesg_restrict", 0) == 1) {
            errno = 0;
            check(syscall(SYS_syslog, 3, (char[16]){0}, 16) == -1 && errno == EPERM, "syslog read unprivileged (dmesg_restrict): EPERM");
        }
        errno = 0;
        check(syscall(SYS_vhangup) == -1 && errno == EPERM, "vhangup unprivileged: EPERM");
        errno = 0;
        check(acct("/tmp/x") == -1 && errno == EPERM, "acct unprivileged: EPERM");
        errno = 0;
        check(swapon("/tmp/x", 0) == -1 && errno == EPERM, "swapon unprivileged: EPERM");
    } else {
        privileged();
    }
    printf(fails ? "ADMIN TEST FAILED (%d)\n" : "ADMIN TEST PASSED\n", fails);
    return fails != 0;
}
