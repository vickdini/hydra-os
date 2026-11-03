/*
 * hydra-socket-activate -- socket activation for services that systemd starts per
 * connection (a .socket unit with Accept=yes), on Hydra, which has no systemd.
 *
 * Usage: hydra-socket-activate SOCKET-PATH PROGRAM [ARGS...]
 *
 * Listens on the Unix stream socket SOCKET-PATH (mode 0666, as systemd's default
 * SocketMode) and, for each connection, runs PROGRAM with the connection as its standard
 * input and output (StandardInput=socket, StandardOutput=socket); standard error is
 * inherited. It runs as root, like the services it stands in for.
 *
 * Used for polkit's authentication helper (polkit-agent-helper.socket): since polkit 127
 * the helper is no longer setuid root, and desktop agents reach it through this socket.
 *
 * Build: gcc -O2 -o hydra-socket-activate hydra-socket-activate.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s SOCKET-PATH PROGRAM [ARGS...]\n", argv[0]);
        return 2;
    }
    const char *path = argv[1];
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    if (strlen(path) >= sizeof addr.sun_path) {
        fprintf(stderr, "hydra-socket-activate: %s: path too long\n", path);
        return 1;
    }
    strcpy(addr.sun_path, path);

    /* The socket's directory, as systemd creates it (0755, root's) */
    char dir[sizeof addr.sun_path];
    strcpy(dir, path);
    mkdir(dirname(dir), 0755);

    /* Children are not waited for: the kernel reaps them */
    struct sigaction sa = {.sa_handler = SIG_IGN, .sa_flags = SA_NOCLDWAIT};
    sigaction(SIGCHLD, &sa, NULL);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    unlink(path);
    if (s < 0 || bind(s, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(s, 16) < 0) {
        fprintf(stderr, "hydra-socket-activate: %s: %s\n", path, strerror(errno));
        return 1;
    }
    chmod(path, 0666);

    for (;;) {
        int c = accept4(s, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            fprintf(stderr, "hydra-socket-activate: accept: %s\n", strerror(errno));
            return 1;
        }
        pid_t pid = fork();
        if (pid == 0) {
            /* dup2 clears close-on-exec on the copies */
            if (dup2(c, 0) < 0 || dup2(c, 1) < 0)
                _exit(127);
            umask(0077);
            execv(argv[2], argv + 2);
            fprintf(stderr, "hydra-socket-activate: %s: %s\n", argv[2], strerror(errno));
            _exit(127);
        }
        if (pid < 0)
            fprintf(stderr, "hydra-socket-activate: fork: %s\n", strerror(errno));
        close(c);
    }
}
