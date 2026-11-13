// Terminal requests on descriptors that are not terminals fail with ENOTTY, also on the
// standard descriptors 0-2 (bug 41 of tests/host/TEST_REPORT.md). Hydra's old ioctl
// fallback answered every request on fds 0-2 with success, so /dev/null or a file
// redirected onto stdin/stdout looked like a terminal to isatty(), and TIOCGWINSZ wrote
// to the caller's pointer without checking it.
// Build: gcc -O1 -w -o notty notty_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

// Puts `fd` on descriptor `slot` (0, 1 or 2) and asks it terminal questions
static void not_a_tty(int fd, int slot, const char *what) {
    int saved = dup(slot);
    dup2(fd, slot);
    struct termios t;
    struct winsize w;
    int tty = isatty(slot);
    int e1 = tcgetattr(slot, &t) < 0 ? errno : 0;
    int e2 = ioctl(slot, TIOCGWINSZ, &w) < 0 ? errno : 0;
    int e3 = ioctl(slot, TIOCGWINSZ, (void *)8) < 0 ? errno : 0; // bad pointer: still ENOTTY first
    dup2(saved, slot);
    close(saved);
    char line[128];
    snprintf(line, sizeof line, "%s on fd %d: isatty false", what, slot);
    check(!tty, line);
    snprintf(line, sizeof line, "%s on fd %d: TCGETS ENOTTY (got %d)", what, slot, e1);
    check(e1 == ENOTTY, line);
    snprintf(line, sizeof line, "%s on fd %d: TIOCGWINSZ ENOTTY (got %d)", what, slot, e2);
    check(e2 == ENOTTY, line);
    snprintf(line, sizeof line, "%s on fd %d: TIOCGWINSZ to a bad pointer ENOTTY (got %d)", what, slot, e3);
    check(e3 == ENOTTY, line);
}

int main(void) {
    // Results go to a log descriptor, since 0-2 are borrowed by the checks
    setvbuf(stdout, NULL, _IONBF, 0);
    int null = open("/dev/null", O_RDWR);
    int file = open("/tmp/notty_test.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
    for (int slot = 0; slot <= 2; slot += 2) { // 0 and 2 (stdout carries the report)
        not_a_tty(null, slot, "/dev/null");
        not_a_tty(file, slot, "a regular file");
    }
    // FIONBIO is not a terminal request: it works on any descriptor
    int on = 1;
    check(ioctl(null, FIONBIO, &on) == 0, "FIONBIO on /dev/null succeeds");
    // A descriptor that is not open
    struct termios t;
    check(tcgetattr(1000, &t) < 0 && errno == EBADF, "TCGETS on a closed descriptor: EBADF");
    unlink("/tmp/notty_test.tmp");
    printf(fails ? "NOTTY TEST FAILED (%d)\n" : "NOTTY TEST PASSED\n", fails);
    return fails != 0;
}
