// reboot(2) guards, without ever restarting anything: the capability is checked first
// (EPERM without CAP_SYS_BOOT, whatever the arguments), then the magic numbers (EINVAL),
// then the command (EINVAL for an unknown one); LINUX_REBOOT_CMD_CAD_ON/OFF only set how
// Ctrl+Alt+Del behaves and return 0 (in the initial PID namespace; inside another one,
// as under WSL2, Linux answers EINVAL for them). Run as root: a child drops to another
// user for the EPERM checks.
// Build: gcc -O1 -w -o reboot reboot_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/reboot.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long rb(unsigned magic, unsigned magic2, unsigned cmd) {
    long r = syscall(SYS_reboot, magic, magic2, cmd, NULL);
    return r < 0 ? -errno : r;
}

static void expect(long got, long want, const char *what) {
    char line[160];
    snprintf(line, sizeof line, "%s: want %ld, got %ld", what, want, got);
    check(got == want, line);
}

int main(void) {
    if (geteuid() != 0) {
        printf("reboot: needs root\nREBOOT TEST FAILED (1)\n");
        return 1;
    }
    const unsigned M1 = LINUX_REBOOT_MAGIC1, M2 = LINUX_REBOOT_MAGIC2;
    expect(rb(0x12345678, M2, LINUX_REBOOT_CMD_CAD_OFF), -EINVAL, "root, wrong magic1");
    expect(rb(M1, 0x12345678, LINUX_REBOOT_CMD_CAD_OFF), -EINVAL, "root, wrong magic2");
    expect(rb(M1, M2, 0x1), -EINVAL, "root, unknown command");
    expect(rb(M1, LINUX_REBOOT_MAGIC2A, LINUX_REBOOT_CMD_CAD_ON), 0, "root, CAD_ON (any of the magic2 values)");
    expect(rb(M1, M2, LINUX_REBOOT_CMD_CAD_OFF), 0, "root, CAD_OFF");

    // Without CAP_SYS_BOOT: EPERM before anything else is looked at
    pid_t p = fork();
    if (p == 0) {
        if (setresgid(65534, 65534, 65534) || setresuid(65534, 65534, 65534)) _exit(100);
        int bad = 0;
        bad |= rb(M1, M2, LINUX_REBOOT_CMD_POWER_OFF) != -EPERM;
        bad |= (rb(0x12345678, M2, LINUX_REBOOT_CMD_CAD_OFF) != -EPERM) << 1;
        bad |= (rb(M1, M2, 0x1) != -EPERM) << 2;
        _exit(bad);
    }
    int st = 0;
    waitpid(p, &st, 0);
    int bad = WIFEXITED(st) ? WEXITSTATUS(st) : 255;
    check(bad != 100 && !(bad & 1), "unprivileged, POWER_OFF: EPERM");
    check(bad != 100 && !(bad & 2), "unprivileged, wrong magic: EPERM (the capability is checked first)");
    check(bad != 100 && !(bad & 4), "unprivileged, unknown command: EPERM");

    printf(fails ? "REBOOT TEST FAILED (%d)\n" : "REBOOT TEST PASSED\n", fails);
    return fails != 0;
}
