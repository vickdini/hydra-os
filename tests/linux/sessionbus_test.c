// The user's session bus runs where polkit can tie what it starts to the user's desktop
// session (the KDE shutdown hang fixed in 750ea1a). plasma-shutdown is started by D-Bus
// activation and inherits the bus daemon's cgroup; polkit maps a process in no session to
// the user's graphical session only when that cgroup is under user-UID.slice (systemd
// runs the bus in user@UID.service there). Otherwise PowerOff/Reboot need a password
// that nobody is left to type.
//
// Run as the desktop user, from a console, while that user's desktop session is active.
// Build: gcc -O1 -w -o sessionbus sessionbus_test.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

// The pid of the daemon listening on the session bus socket, or -1
static int bus_pid(void) {
    const char *dir = getenv("XDG_RUNTIME_DIR");
    if (!dir) return -1;
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s/bus", dir);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, (struct sockaddr *)&a, sizeof a) < 0) return -1;
    struct ucred c;
    socklen_t len = sizeof c;
    int r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &c, &len) == 0 ? c.pid : -1;
    close(fd);
    return r;
}

int main(void) {
    int pid = bus_pid();
    check(pid > 0, "the session bus answers on $XDG_RUNTIME_DIR/bus");
    if (pid <= 0) {
        printf("SESSIONBUS TEST FAILED (%d)\n", fails);
        return 1;
    }

    char path[64], group[512] = "";
    snprintf(path, sizeof path, "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (!fgets(group, sizeof group, f)) group[0] = 0;
        fclose(f);
    }
    group[strcspn(group, "\n")] = 0;
    printf("     bus daemon %d is in %s\n", pid, group);
    char slice[64];
    snprintf(slice, sizeof slice, "/user.slice/user-%u.slice/", getuid());
    check(strstr(group, slice) != NULL, "the bus daemon's cgroup is under the user's slice");
    check(strstr(group, "/session-") == NULL, "it is not inside a login session's scope (as with systemd)");

    // polkit's answer for what the bus starts: 0 authorized, 2 needs a password
    char cmd[160];
    snprintf(cmd, sizeof cmd, "pkcheck --action-id org.freedesktop.login1.power-off --process %d >/dev/null 2>&1", pid);
    int st = system(cmd);
    int rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    printf("     pkcheck power-off for the bus daemon: exit %d\n", rc);
    check(rc == 0, "polkit lets what the bus starts power off without a password");
    snprintf(cmd, sizeof cmd, "pkcheck --action-id org.freedesktop.login1.reboot --process %d >/dev/null 2>&1", pid);
    st = system(cmd);
    rc = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    check(rc == 0, "and restart");

    printf(fails ? "SESSIONBUS TEST FAILED (%d)\n" : "SESSIONBUS TEST PASSED\n", fails);
    return fails != 0;
}
