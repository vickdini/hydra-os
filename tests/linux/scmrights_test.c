// Descriptor passing over Unix sockets between processes (wave 5, Group 13: the sockets
// live in linux-server, the descriptors they carry may be the kernel's or the server's).
// - a regular file, a memfd (with a mapping), a pipe end and an eventfd, sent from a child
//   to its parent, each used on the other side;
// - MSG_CTRUNC: a control buffer too small for the descriptors sent (the rest are closed);
// - MSG_CMSG_CLOEXEC; SO_PEERCRED; SCM_CREDENTIALS with SO_PASSCRED; SO_PEERPIDFD;
// - a socket sent through itself, closed: it goes away (counted in /proc/net/unix);
// - a socket bound to a path: connect finds it, refused for a non-socket, EACCES without
//   write permission (when not root), the node is removed again if bind fails.
// Build: gcc -O1 -w -o scmrights scmrights_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

// Sends `n` descriptors with one byte
static int send_fds(int via, const int *fds, int n) {
    char byte = 'x';
    struct iovec iov = { &byte, 1 };
    union { char buf[CMSG_SPACE(sizeof(int) * 8)]; struct cmsghdr align; } u;
    struct msghdr m = { 0 };
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = u.buf;
    m.msg_controllen = CMSG_SPACE(sizeof(int) * n);
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int) * n);
    memcpy(CMSG_DATA(c), fds, sizeof(int) * n);
    return sendmsg(via, &m, 0) == 1 ? 0 : -errno;
}

// Receives up to `max` descriptors into `out` with a control buffer of `cap` bytes;
// returns how many, -1 on error; *flags gets msg_flags
static int recv_fds(int via, int *out, int max, size_t cap, int rflags, int *flags) {
    char byte;
    struct iovec iov = { &byte, 1 };
    char buf[512];
    struct msghdr m = { 0 };
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = buf;
    m.msg_controllen = cap;
    if (recvmsg(via, &m, rflags) != 1) return -1;
    *flags = m.msg_flags;
    int n = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS) {
            int k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (int i = 0; i < k && n < max; i++) memcpy(&out[n++], CMSG_DATA(c) + i * sizeof(int), sizeof(int));
        }
    }
    return n;
}

static int live_sockets(void) {
    FILE *f = fopen("/proc/net/unix", "r");
    if (!f) return -1;
    int n = -1;
    char line[512];
    while (fgets(line, sizeof line, f)) n++;
    fclose(f);
    return n;
}

static int fd_open(int fd) { return fcntl(fd, F_GETFD) >= 0; }

int main(void) {
    int sv[2];
    check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");

    // ---- four kinds of descriptors from a child to its parent
    pid_t child = fork();
    if (child == 0) {
        close(sv[0]);
        char path[] = "/tmp/scmrights.XXXXXX";
        int file = mkstemp(path);
        write(file, "file-data", 9);
        unlink(path);
        int mem = memfd_create("scm", 0);
        ftruncate(mem, 4096);
        char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mem, 0);
        strcpy(p, "memfd-data");
        int pp[2];
        pipe(pp);
        write(pp[1], "pipe-data", 9);
        int efd = eventfd(5, 0);
        int fds[4] = { file, mem, pp[0], efd };
        int r = send_fds(sv[1], fds, 4);
        // The pipe's write end stays here: the parent reads what is written after
        char ack;
        read(sv[1], &ack, 1);
        write(pp[1], "more", 4);
        close(pp[1]);
        _exit(r == 0 ? 0 : 1);
    }
    close(sv[1]);
    int got[8], flags = 0;
    int n = recv_fds(sv[0], got, 8, 512, MSG_CMSG_CLOEXEC, &flags);
    check(n == 4 && !(flags & MSG_CTRUNC), "four descriptors arrive (file, memfd, pipe, eventfd)");
    if (n == 4) {
        char buf[32] = { 0 };
        check(pread(got[0], buf, 9, 0) == 9 && !memcmp(buf, "file-data", 9), "the regular file reads the child's data");
        char *p = mmap(0, 4096, PROT_READ, MAP_SHARED, got[1], 0);
        check(p != MAP_FAILED && !strcmp(p, "memfd-data"), "the memfd maps the child's data");
        memset(buf, 0, sizeof buf);
        check(read(got[2], buf, 9) == 9 && !memcmp(buf, "pipe-data", 9), "the pipe end reads what was in the pipe");
        uint64_t v = 0;
        check(read(got[3], &v, 8) == 8 && v == 5, "the eventfd has the child's count");
        check((fcntl(got[0], F_GETFD) & FD_CLOEXEC) != 0, "MSG_CMSG_CLOEXEC sets close-on-exec");
        write(sv[0], "k", 1);
        memset(buf, 0, sizeof buf);
        check(read(got[2], buf, 8) == 4 && !memcmp(buf, "more", 4), "the pipe works across processes after the send");
        check(read(got[2], buf, 8) == 0, "end of file once the child closed the write end");
        for (int i = 0; i < 4; i++) close(got[i]);
    }
    int st;
    waitpid(child, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "the child's sendmsg succeeded");
    close(sv[0]);

    // ---- MSG_CTRUNC: room for one descriptor of three
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    int e[3] = { eventfd(1, 0), eventfd(2, 0), eventfd(3, 0) };
    check(send_fds(sv[0], e, 3) == 0, "three eventfds sent");
    for (int i = 0; i < 3; i++) close(e[i]);
    int before_fd = dup(0); // the lowest free number now
    close(before_fd);
    // (Linux's room: (controllen - sizeof(struct cmsghdr)) / sizeof(int) descriptors)
    n = recv_fds(sv[1], got, 8, CMSG_LEN(sizeof(int)), 0, &flags);
    check(n == 1 && (flags & MSG_CTRUNC), "a short control buffer gets one descriptor and MSG_CTRUNC");
    if (n == 1) {
        uint64_t v = 0;
        check(read(got[0], &v, 8) == 8 && v == 1, "the one received is the first sent");
        close(got[0]);
    }
    // The two that did not fit were closed, not installed: the next free number is the same
    int probe = dup(0);
    check(probe == before_fd, "the descriptors that did not fit were not installed");
    close(probe);

    // ---- credentials
    struct ucred uc;
    socklen_t ul = sizeof uc;
    check(getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &uc, &ul) == 0 && uc.pid == getpid() && uc.uid == geteuid() && uc.gid == getegid(), "SO_PEERCRED gives the peer's pid, uid and gid");
    int on = 1;
    setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &on, sizeof on);
    write(sv[0], "c", 1);
    {
        char byte;
        struct iovec iov = { &byte, 1 };
        char buf[64];
        struct msghdr m = { 0 };
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = buf;
        m.msg_controllen = sizeof buf;
        int ok = recvmsg(sv[1], &m, 0) == 1;
        struct cmsghdr *c = CMSG_FIRSTHDR(&m);
        struct ucred r = { 0 };
        if (c && c->cmsg_type == SCM_CREDENTIALS) memcpy(&r, CMSG_DATA(c), sizeof r);
        check(ok && c && c->cmsg_type == SCM_CREDENTIALS && r.pid == getpid() && r.uid == geteuid(), "SCM_CREDENTIALS with SO_PASSCRED");
    }
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
    int pfd = -1;
    socklen_t pl = sizeof pfd;
    int pr = getsockopt(sv[0], SOL_SOCKET, SO_PEERPIDFD, &pfd, &pl);
    check(pr == 0 && pfd >= 0 && syscall(SYS_pidfd_send_signal, pfd, 0, NULL, 0) == 0, "SO_PEERPIDFD gives a pidfd of the peer");
    if (pfd >= 0) close(pfd);
    close(sv[0]);
    close(sv[1]);

    // ---- a socket sent through itself goes away once closed
    int base = live_sockets();
    for (int i = 0; i < 200; i++) {
        int p[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p)) break;
        send_fds(p[0], &p[1], 1); // p[1] waits in its own queue
        close(p[0]);
        close(p[1]);
    }
    int after = live_sockets();
    printf("     live sockets before %d, after 200 self-sent %d\n", base, after);
    // (the in-kernel code, lx=kernel, never collected them: only the server's sockets)
    long srv = syscall(0x6710, 3, 0); // Hydra's test call: a server object if forwarding is on
    if (srv > 2) {
        close(srv);
        check(after >= 0 && after <= base + 4, "sockets sent through themselves are gone once closed");
    } else {
        puts("skip sockets sent through themselves (Unix sockets in the kernel: lx=kernel)");
    }

    // ---- path names
    const char *path = "/tmp/scmrights.sock";
    unlink(path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    strcpy(a.sun_path, path);
    check(bind(ls, (struct sockaddr *)&a, sizeof a) == 0 && listen(ls, 4) == 0, "bind and listen on a path");
    struct stat sb;
    check(stat(path, &sb) == 0 && S_ISSOCK(sb.st_mode), "the path is a socket node");
    int again = socket(AF_UNIX, SOCK_STREAM, 0);
    check(bind(again, (struct sockaddr *)&a, sizeof a) < 0 && errno == EADDRINUSE, "binding the same path again: EADDRINUSE");
    close(again);
    int cs = socket(AF_UNIX, SOCK_STREAM, 0);
    check(connect(cs, (struct sockaddr *)&a, sizeof a) == 0, "connect finds the listener by its path");
    int as = accept(ls, 0, 0);
    check(as >= 0 && write(cs, "hi", 2) == 2, "accept gives the connection");
    char hb[2];
    check(as >= 0 && read(as, hb, 2) == 2 && !memcmp(hb, "hi", 2), "bytes go through");
    // A renamed node still finds the socket (it is attached to the node)
    rename(path, "/tmp/scmrights2.sock");
    struct sockaddr_un b = { .sun_family = AF_UNIX };
    strcpy(b.sun_path, "/tmp/scmrights2.sock");
    int cs2 = socket(AF_UNIX, SOCK_STREAM, 0);
    check(connect(cs2, (struct sockaddr *)&b, sizeof b) == 0, "connect through the renamed node");
    struct sockaddr_un f = { .sun_family = AF_UNIX };
    strcpy(f.sun_path, "/tmp/scmrights.notasock");
    close(open(f.sun_path, O_CREAT | O_WRONLY, 0666));
    int cs3 = socket(AF_UNIX, SOCK_STREAM, 0);
    check(connect(cs3, (struct sockaddr *)&f, sizeof f) < 0 && errno == ECONNREFUSED, "connect to a regular file: ECONNREFUSED");
    strcpy(f.sun_path, "/tmp/scmrights.missing");
    check(connect(cs3, (struct sockaddr *)&f, sizeof f) < 0 && errno == ENOENT, "connect to a missing path: ENOENT");
    unlink("/tmp/scmrights.notasock");
    // bind of a bound socket fails and leaves no node behind
    struct sockaddr_un g = { .sun_family = AF_UNIX };
    strcpy(g.sun_path, "/tmp/scmrights.second");
    unlink(g.sun_path);
    check(bind(ls, (struct sockaddr *)&g, sizeof g) < 0 && errno == EINVAL && access(g.sun_path, F_OK) != 0, "a second bind fails and its node is removed");
    if (geteuid() != 0) {
        chmod("/tmp/scmrights2.sock", 0);
        int cs4 = socket(AF_UNIX, SOCK_STREAM, 0);
        check(connect(cs4, (struct sockaddr *)&b, sizeof b) < 0 && errno == EACCES, "connect without write permission: EACCES");
        close(cs4);
    }
    // Abstract names
    struct sockaddr_un ab = { .sun_family = AF_UNIX };
    memcpy(ab.sun_path, "\0scmrights-abstract", 19);
    int al = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 19;
    check(bind(al, (struct sockaddr *)&ab, alen) == 0 && listen(al, 1) == 0, "bind an abstract name");
    int ac = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    check(connect(ac, (struct sockaddr *)&ab, alen) == 0, "connect to it");
    int aa = accept4(al, 0, 0, SOCK_CLOEXEC);
    char rec[8];
    check(aa >= 0 && send(ac, "record", 6, 0) == 6 && recv(aa, rec, 3, 0) == 3 && recv(aa, rec, 8, MSG_DONTWAIT) < 0 && errno == EAGAIN, "seqpacket: a short read drops the rest of the record");
    close(aa); close(ac); close(al);
    unlink("/tmp/scmrights2.sock");
    close(cs); close(cs2); close(cs3); close(as); close(ls);

    printf(fails ? "SCMRIGHTS TEST FAILED (%d)\n" : "SCMRIGHTS TEST PASSED\n", fails);
    return fails != 0;
}
