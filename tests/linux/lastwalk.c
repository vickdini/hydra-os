// The last walks (wave 11, Group F): what vfs-server and the Linux services serve now that
// the kernel's walk did before: the /dev/pts directory listed (tty-server), UEFI variables
// written and deleted through efivarfs (linux-server), and bubblewrap's sandbox (device nodes
// bound into its /dev, proc and devpts mounted in its namespace). Run as root (the efivars
// and bwrap parts are skipped when the files are not there).
// Build: gcc -O1 -w -o lastwalk lastwalk.c
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static int listed(const char *dir, const char *name, int *count) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 0, n = 0;
    while ((e = readdir(d))) {
        n++;
        found |= !strcmp(e->d_name, name);
    }
    closedir(d);
    if (count) *count = n;
    return found;
}

static void pts(void) {
    int m1 = posix_openpt(O_RDWR | O_NOCTTY), m2 = posix_openpt(O_RDWR | O_NOCTTY);
    check(m1 >= 0 && m2 >= 0 && !grantpt(m1) && !unlockpt(m1) && !grantpt(m2) && !unlockpt(m2), "two pseudo-terminals");
    char a[64], b[64];
    snprintf(a, sizeof a, "%s", ptsname(m1));
    snprintf(b, sizeof b, "%s", ptsname(m2));
    const char *na = strrchr(a, '/') + 1, *nb = strrchr(b, '/') + 1;
    int n = 0;
    check(listed("/dev/pts", na, &n) == 1 && listed("/dev/pts", nb, NULL) == 1, "/dev/pts lists both slaves");
    check(listed("/dev/pts", "ptmx", NULL) == 1 && listed("/dev/pts", ".", NULL) == 1 && listed("/dev/pts", "..", NULL) == 1, "and ptmx, . and ..");
    DIR *d = opendir("/dev/pts");
    int k = 0;
    while (d && readdir(d)) k++;
    if (d) rewinddir(d);
    int k2 = 0;
    while (d && readdir(d)) k2++;
    check(d && k == n && k2 == k, "rewinddir lists it again");
    struct stat st;
    check(d && fstat(dirfd(d), &st) == 0 && S_ISDIR(st.st_mode), "fstat of the directory");
    check(d && fstatat(dirfd(d), na, &st, 0) == 0 && S_ISCHR(st.st_mode), "fstatat of a slave relative to it");
    if (d) closedir(d);
    check(open("/dev/pts", O_WRONLY) < 0 && errno == EISDIR, "open for writing: EISDIR");
    close(m2);
    check(listed("/dev/pts", nb, NULL) == 0, "a closed pair's slave goes from the list");
    close(m1);
}

#define GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
static const char *var = "/sys/firmware/efi/efivars/HydraLastwalk-12345678-1234-4234-8234-123456789abc";

static void efivars(void) {
    if (access("/sys/firmware/efi/efivars", F_OK) != 0) {
        printf("     (no efivarfs: skipped)\n");
        return;
    }
    int f = open(var, O_WRONLY | O_CREAT, 0644);
    char data[] = {7, 0, 0, 0, 'h', 'y', 'd', 'r', 'a'};
    check(f >= 0 && write(f, data, sizeof data) == sizeof data, "a new variable written (attributes and data in one write)");
    if (f >= 0) close(f);
    char buf[64];
    f = open(var, O_RDONLY);
    int n = f >= 0 ? read(f, buf, sizeof buf) : -1;
    if (f >= 0) close(f);
    check(n == 9 && buf[0] == 7 && !memcmp(buf + 4, "hydra", 5), "read back");
    check(listed("/sys/firmware/efi/efivars", strrchr(var, '/') + 1, NULL) == 1, "listed in efivars");
    pid_t p = fork();
    if (p == 0) {
        setgid(1000);
        setuid(1000);
        int bad = 0;
        if (open(var, O_WRONLY) >= 0 || errno != EACCES) bad |= 1;
        if (unlink(var) == 0 || errno != EACCES) bad |= 2;
        _exit(bad);
    }
    int status = -1;
    waitpid(p, &status, 0);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "a user may neither write nor delete it");
    check(open(var, O_WRONLY | O_CREAT | O_EXCL, 0644) < 0 && errno == EEXIST, "O_CREAT|O_EXCL of an existing variable: EEXIST");
    check(unlink(var) == 0, "unlink deletes the variable");
    // Linux's efivarfs rules: a global variable it does not know as removable is immutable;
    // BootOrder's value is checked (nothing reaches the firmware in these two)
    unsigned int fl = 0;
    f = open("/sys/firmware/efi/efivars/SecureBoot-" GUID, O_RDONLY);
    check(f < 0 || (ioctl(f, FS_IOC_GETFLAGS, &fl) == 0 && (fl & FS_IMMUTABLE_FL)), "SecureBoot is immutable");
    if (f >= 0) close(f);
    check(f < 0 || (unlink("/sys/firmware/efi/efivars/SecureBoot-" GUID) < 0 && errno == EPERM), "an immutable variable is not deleted: EPERM");
    f = open("/sys/firmware/efi/efivars/BootOrder-" GUID, O_WRONLY);
    char odd[] = {7, 0, 0, 0, 1, 0, 2};
    check(f >= 0 && write(f, odd, sizeof odd) < 0 && errno == EINVAL, "a BootOrder of odd length: EINVAL");
    if (f >= 0) close(f);
    check(open(var, O_RDONLY) < 0 && errno == ENOENT, "gone");
    check(listed("/sys/firmware/efi/efivars", strrchr(var, '/') + 1, NULL) == 0, "and from the list");
    f = open("/sys/firmware/efi/efivars/BootOrder-" GUID, O_RDONLY);
    check(f >= 0 && read(f, buf, sizeof buf) >= 4, "BootOrder still reads");
    if (f >= 0) close(f);
}

/// Runs `cmd` as user 1000 and returns its output (at most `n` bytes).
static int run_as_user(const char *cmd, char *out, size_t n) {
    int pfd[2];
    if (pipe(pfd)) return -1;
    pid_t p = fork();
    if (p == 0) {
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        close(pfd[0]);
        setgid(1000);
        setuid(1000);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(pfd[1]);
    size_t got = 0;
    ssize_t r;
    while (got + 1 < n && (r = read(pfd[0], out + got, n - 1 - got)) > 0) got += r;
    out[got] = 0;
    close(pfd[0]);
    int status;
    waitpid(p, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void bwrap(void) {
    if (access("/usr/bin/bwrap", X_OK) != 0) {
        printf("     (no bwrap: skipped)\n");
        return;
    }
    static char out[8192];
    // A terminal of the system while the sandbox runs: its own devpts must not show it
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    grantpt(m);
    unlockpt(m);
    const char *host = m >= 0 ? strrchr(ptsname(m), '/') + 1 : "999";
    char cmd[1024];
    snprintf(cmd, sizeof cmd, "bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp sh -c '"
             "ls -l /dev/null /dev/zero /dev/full /dev/random /dev/urandom /dev/tty; "
             "head -c 4 /dev/zero | od -An -tx1; echo hi > /dev/null && echo NULL-OK; "
             "test -e /dev/pts/ptmx && echo PTMX-OK; test -e /dev/pts/%s || echo NOHOST-OK; "
             "readlink /proc/self/fd/1 >/dev/null && echo FD-OK; "
             "grep -c Name /proc/self/status'", host);
    int rc = run_as_user(cmd, out, sizeof out);
    if (m >= 0) close(m);
    printf("%s", out);
    check(rc == 0, "bwrap --dev --proc ran");
    check(strstr(out, "crw-rw-rw-") && strstr(out, "/dev/null"), "its /dev/null is a character device");
    check(strstr(out, "00 00 00 00") != NULL, "/dev/zero reads zeros");
    check(strstr(out, "NULL-OK") != NULL, "/dev/null takes writes");
    check(strstr(out, "PTMX-OK") && strstr(out, "NOHOST-OK"), "its own /dev/pts (devpts): ptmx, and not the system's terminals");
    check(strstr(out, "FD-OK") != NULL, "proc in the sandbox: /proc/self/fd/1");
    rc = run_as_user("bwrap --dev-bind / / --unshare-pid --proc /proc sh -c 'ls /proc | grep -c ^1$; head -c 2 /dev/urandom > /dev/null && echo URANDOM-OK'", out, sizeof out);
    printf("%s", out);
    check(rc == 0 && strstr(out, "URANDOM-OK") != NULL, "bwrap --dev-bind --unshare-pid --proc ran");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    pts();
    if (geteuid() == 0) efivars();
    if (geteuid() == 0) bwrap();
    printf(fails ? "LASTWALK TEST FAILED (%d)\n" : "LASTWALK TEST PASSED\n", fails);
    return fails != 0;
}
