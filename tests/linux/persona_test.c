/*
 * persona: the personality hook (microkernel wave 5, Group 14).
 *
 *   persona DIR      (DIR holds fbrawsys, fbhook, fbinfo: Group 11's and Group 14's FreeBSD
 *                     test programs; the Mach-O file, Group 11's tests/macos/rawmac, is built
 *                     in: Hydra's boot import takes only ELF files)
 * Build: gcc -O1 -w -pthread -DRAWMAC_H='"rawmac_bin.h"' (xxd -i rawmac > rawmac_bin.h), as
 * tools/personality/build-fbhook.sh does; without it a bare Mach-O header stands in.
 *
 * Two modes, found by trying FreeBSD's rawsys:
 * - default (no switch): FreeBSD programs, Mach-O files and ELF files of other systems are
 *   refused with ENOEXEC; Linux programs (OS/ABI 0 and 3) run.
 * - the test switch persona=fbsd-stub: FreeBSD programs run on the FreeBSD stub table;
 *   rawsys and fbhook pass their own checks (carry flag, positive errno, rdx, FreeBSD
 *   numbers, signal numbers and frame), an unknown FreeBSD call ends the program with
 *   SIGSYS, and a FreeBSD program can exec a Linux one.
 * Prints "PERSONA-DONE mode=... fails=N"; exit status 0 when nothing failed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef RAWMAC_H
#include RAWMAC_H
#else
static unsigned char rawmac[] = { 0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1, 3, 0, 0, 0, 2, 0, 0, 0 };
static unsigned int rawmac_len = sizeof rawmac;
#endif

static int fails;
static char dir[256];

#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { printf("FAIL " __VA_ARGS__); fails++; } printf("\n"); } while (0)

/* Runs path with argv in a child, stdout to out (if not NULL). Returns the wait status, or
 * 0x10000 | errno when execve failed (the child reports it). */
static int run(const char *path, char *const argv[], const char *out)
{
    int p[2];
    if (pipe2(p, O_CLOEXEC) < 0) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        if (out) {
            int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { dup2(fd, 1); close(fd); }
        }
        char *env[] = { NULL };
        execve(path, argv, env);
        int e = errno;
        write(p[1], &e, sizeof e);
        _exit(127);
    }
    close(p[1]);
    int e = 0;
    ssize_t n = read(p[0], &e, sizeof e);
    close(p[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    return n == sizeof e ? (0x10000 | e) : st;
}

/* Starts path with argv in a child (no wait); returns its pid */
static pid_t spawn(const char *path, char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        char *env[] = { NULL };
        execve(path, argv, env);
        _exit(127);
    }
    return pid;
}

static const char *desc(int st, char *buf)
{
    if (st & 0x10000) sprintf(buf, "execve failed, errno %d (%s)", st & 0xffff, strerror(st & 0xffff));
    else if (WIFEXITED(st)) sprintf(buf, "exit %d", WEXITSTATUS(st));
    else if (WIFSIGNALED(st)) sprintf(buf, "signal %d", WTERMSIG(st));
    else sprintf(buf, "status %#x", st);
    return buf;
}

/* A copy of /bin/true with its OS/ABI byte set to b (and, when nonzero, its interpreter left) */
static const char *patched_true(int b)
{
    static char name[300];
    snprintf(name, sizeof name, "/tmp/persona_true_%d", b);
    int in = open("/bin/true", O_RDONLY), out = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (in < 0 || out < 0) return name;
    char buf[65536];
    ssize_t n;
    int first = 1;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        if (first) { buf[7] = (char)b; first = 0; }
        write(out, buf, n);
    }
    close(in); close(out);
    return name;
}

static int file_has(const char *f, const char *s)
{
    FILE *fp = fopen(f, "r");
    if (!fp) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, fp)) if (strstr(line, s)) found = 1;
    fclose(fp);
    return found;
}

int main(int argc, char **argv)
{
    char b[128], path[300];
    snprintf(dir, sizeof dir, "%s", argc > 1 ? argv[1] : "/tmp");
    setvbuf(stdout, NULL, _IONBF, 0);

    snprintf(path, sizeof path, "%s/fbrawsys", dir);
    char *rawargv[] = { "rawsys", NULL };
    int st = run(path, rawargv, "/tmp/persona_rawsys.out");
    int stub = !(st & 0x10000);
    int raw_st = st;
    printf("mode: %s (rawsys: %s)\n", stub ? "fbsd-stub" : "default", desc(st, b));

    /* Linux programs: OS/ABI 0 (as built) and 3 (GNU) run */
    char *targv[] = { "true", NULL };
    st = run("/bin/true", targv, NULL);
    CHECK(st == 0, "Linux program (OS/ABI 0) runs: %s", desc(st, b));
    st = run(patched_true(3), targv, NULL);
    CHECK(st == 0, "Linux program (OS/ABI 3, GNU) runs: %s", desc(st, b));
    /* Another system's ELF (Solaris 6, NetBSD 2): ENOEXEC */
    st = run(patched_true(6), targv, NULL);
    CHECK(st == (0x10000 | ENOEXEC), "Solaris-marked ELF refused with ENOEXEC: %s", desc(st, b));
    st = run(patched_true(2), targv, NULL);
    CHECK(st == (0x10000 | ENOEXEC), "NetBSD-marked ELF refused with ENOEXEC: %s", desc(st, b));
    /* Mach-O: ENOEXEC in both modes */
    snprintf(path, sizeof path, "/tmp/persona_rawmac");
    {
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
        write(fd, rawmac, rawmac_len);
        close(fd);
    }
    st = run(path, rawargv, NULL);
    CHECK(st == (0x10000 | ENOEXEC), "Mach-O refused with ENOEXEC: %s", desc(st, b));
    /* A Linux program marked FreeBSD (OS/ABI 9): ENOEXEC in both modes (by default as a
     * FreeBSD program; with the stub table because its interpreter is Linux's ld.so) */
    st = run(patched_true(9), targv, NULL);
    CHECK(st == (0x10000 | ENOEXEC), "FreeBSD-marked program with Linux's ld.so refused with ENOEXEC: %s", desc(st, b));

    snprintf(path, sizeof path, "%s/fbinfo", dir);
    char *infoargv[] = { "fbsdinfo", NULL };
    if (!stub) {
        printf("-- default mode: FreeBSD programs refused --\n");
        CHECK(raw_st == (0x10000 | ENOEXEC), "static FreeBSD rawsys refused with ENOEXEC: %s", desc(raw_st, b));
        st = run(path, infoargv, NULL);
        CHECK(st == (0x10000 | ENOEXEC), "dynamic FreeBSD fbsdinfo refused with ENOEXEC (not ENOENT): %s", desc(st, b));
        snprintf(path, sizeof path, "%s/fbhook", dir);
        char *hookargv[] = { "fbhook", NULL };
        st = run(path, hookargv, NULL);
        CHECK(st == (0x10000 | ENOEXEC), "static FreeBSD fbhook refused with ENOEXEC: %s", desc(st, b));
    } else {
        printf("-- stub mode: FreeBSD programs on the stub table --\n");
        st = run(strcat(strcpy(path, dir), "/fbrawsys"), rawargv, "/tmp/persona_rawsys.out");
        CHECK(st == 0 && file_has("/tmp/persona_rawsys.out", "RAWSYS-DONE"), "rawsys: write, getpid/getppid by FreeBSD numbers, close(-1) = carry + EBADF 9: %s", desc(st, b));
        snprintf(path, sizeof path, "%s/fbinfo", dir);
        st = run(path, infoargv, NULL);
        CHECK(st == (0x10000 | ENOENT), "dynamic fbsdinfo: ENOENT (no /libexec/ld-elf.so.1 in /ubuntu): %s", desc(st, b));
        snprintf(path, sizeof path, "%s/fbhook", dir);
        char *hookargv[] = { "fbhook", NULL };
        st = run(path, hookargv, "/tmp/persona_fbhook.out");
        CHECK(st == 0 && file_has("/tmp/persona_fbhook.out", "FBHOOK-DONE"), "fbhook: carry flag, errno map, rdx, indirect calls, signals, frame: %s", desc(st, b));
        system("cat /tmp/persona_fbhook.out");
        char *sysargv[] = { "fbhook", "nosys", NULL };
        st = run(path, sysargv, NULL);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, "unknown FreeBSD call without SIGSYS ignored: killed by SIGSYS: %s", desc(st, b));
        char *killargv[] = { "fbhook", "usr2", NULL };
        st = run(path, killargv, NULL);
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGUSR2, "FreeBSD kill(self, 31 SIGUSR2) arrives as Linux SIGUSR2 (12): %s", desc(st, b));
        /* A signal with a handler during a FreeBSD nanosleep: EINTR in FreeBSD's convention,
         * saved in the signal frame's context and returned by sigreturn */
        char *eintrargv[] = { "fbhook", "eintr", NULL };
        pid_t c = spawn(path, eintrargv);
        usleep(400000);
        kill(c, SIGUSR1);
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "FreeBSD nanosleep + handler: carry + EINTR 4: %s", desc(st, b));
        /* A stop and continue during a FreeBSD nanosleep: restarted with FreeBSD's number (a
         * Linux number left in rax would be another FreeBSD call: SIGSYS) */
        char *restartargv[] = { "fbhook", "restart", NULL };
        c = spawn(path, restartargv);
        usleep(300000);
        kill(c, SIGSTOP);
        usleep(300000);
        kill(c, SIGCONT);
        waitpid(c, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "FreeBSD nanosleep restarted after SIGSTOP/SIGCONT: %s", desc(st, b));
        char *execargv[] = { "fbhook", "exec", NULL };
        st = run(path, execargv, "/tmp/persona_exec.out");
        CHECK(st == 0 && file_has("/tmp/persona_exec.out", "LINUX-AFTER-FREEBSD"), "FreeBSD program execs a Linux one (/bin/echo): %s", desc(st, b));
    }
    printf("PERSONA-DONE mode=%s fails=%d\n", stub ? "fbsd-stub" : "default", fails);
    return fails != 0;
}
