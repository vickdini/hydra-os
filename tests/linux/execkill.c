// Wave 7, Group 7-5: execve, Unix socket names and FIFO opens in a loop while services are
// killed (`service kill vfs_server`, `service kill linux_server`). Usage: execkill SECONDS.
// Prints per kind: done and failed (with the errnos seen), then "EXECKILL-END".
// Build: gcc -O1 -w -pthread execkill.c -o execkill.elf
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct kind { const char *name; long ok, bad; int errs[8]; int nerr; };
static struct kind K[4] = {{"exec"}, {"script"}, {"unix"}, {"fifo"}};

static void bad(struct kind *k, int e) {
    k->bad++;
    for (int i = 0; i < k->nerr; i++) if (k->errs[i] == e) return;
    if (k->nerr < 8) k->errs[k->nerr++] = e;
}

static int run(const char *path) {
    pid_t p = fork();
    if (p == 0) {
        char *argv[] = {(char *)path, NULL};
        execv(path, argv);
        _exit(100 + (errno & 0x3f));
    }
    int st;
    if (waitpid(p, &st, 0) < 0) return errno;
    if (!WIFEXITED(st)) return 1000;
    int c = WEXITSTATUS(st);
    return c == 0 ? 0 : c >= 100 ? c - 100 : 2000 + c;
}

int main(int argc, char **argv) {
    int secs = argc > 1 ? atoi(argv[1]) : 30;
    mkdir("/tmp/ek", 0755);
    int fd = open("/tmp/ek/s.sh", O_WRONLY | O_CREAT | O_TRUNC, 0755);
    write(fd, "#!/bin/true\n", 12);
    close(fd);
    unlink("/tmp/ek/ff");
    mkfifo("/tmp/ek/ff", 0600);
    time_t end = time(NULL) + secs, next = time(NULL) + 5;
    long round = 0;
    while (time(NULL) < end) {
        round++;
        int e = run("/bin/true");
        if (e) bad(&K[0], e); else K[0].ok++;
        e = run("/tmp/ek/s.sh");
        if (e) bad(&K[1], e); else K[1].ok++;
        // A Unix socket name: bind, connect, unlink
        struct sockaddr_un a = {.sun_family = AF_UNIX};
        snprintf(a.sun_path, sizeof a.sun_path, "/tmp/ek/s%ld", round % 4);
        unlink(a.sun_path);
        int s = socket(AF_UNIX, SOCK_STREAM, 0), c = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s < 0 || c < 0) bad(&K[2], errno);
        else if (bind(s, (void *)&a, sizeof a) || listen(s, 1)) bad(&K[2], errno);
        else if (connect(c, (void *)&a, sizeof a)) bad(&K[2], 10000 + errno);
        else K[2].ok++;
        close(s);
        close(c);
        unlink(a.sun_path);
        // A FIFO: both ends without waiting
        int r = open("/tmp/ek/ff", O_RDONLY | O_NONBLOCK);
        int w = r >= 0 ? open("/tmp/ek/ff", O_WRONLY | O_NONBLOCK) : -1;
        if (r < 0 || w < 0) bad(&K[3], errno);
        else if (write(w, "x", 1) != 1) bad(&K[3], 20000 + errno);
        else K[3].ok++;
        if (r >= 0) close(r);
        if (w >= 0) close(w);
        if (time(NULL) >= next) {
            next += 5;
            printf("EK t=%ld rounds=%ld\n", (long)(time(NULL) - (end - secs)), round);
            fflush(stdout);
        }
    }
    for (int i = 0; i < 4; i++) {
        printf("EXECKILL %-6s ok %ld failed %ld errnos", K[i].name, K[i].ok, K[i].bad);
        for (int j = 0; j < K[i].nerr; j++) printf(" %d", K[i].errs[j]);
        printf("\n");
    }
    printf("EXECKILL-END\n");
    return 0;
}
