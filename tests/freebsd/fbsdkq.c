/*
 * fbsdkq: kqueue/kevent, the FreeBSD readiness interface the BSD core must provide
 * (Group 11, step 0). Prints "ok NAME" / "FAIL NAME ..."; last line FBSDKQ-DONE <failures>.
 *
 * Covers: EVFILT_READ/EVFILT_WRITE on a pipe (data = bytes available), EV_ONESHOT, EV_CLEAR,
 * EVFILT_TIMER (one-shot, 50 ms), EVFILT_PROC NOTE_EXIT for a child, EVFILT_SIGNAL, EVFILT_USER,
 * a socketpair, and kqueue descriptors not inherited by fork's child (FreeBSD semantics).
 *
 * Build: clang-15 --target=x86_64-unknown-freebsd15.1 --sysroot=$SYSROOT -fuse-ld=lld -O1 -o fbsdkq fbsdkq.c
 */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails;
#define CHECK(name, cond, ...) do { if (cond) printf("ok %s\n", name); \
    else { fails++; printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void)
{
    int kq = kqueue();
    CHECK("kqueue", kq >= 0, "errno %d", errno);
    int p[2];
    pipe(p);
    struct kevent ch[2], ev[4];
    struct timespec zero = {0, 0}, sec = {2, 0};

    EV_SET(&ch[0], p[0], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    EV_SET(&ch[1], p[1], EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, NULL);
    CHECK("kevent register", kevent(kq, ch, 2, NULL, 0, NULL) == 0, "errno %d", errno);
    int n = kevent(kq, NULL, 0, ev, 4, &zero);
    CHECK("pipe writable, not readable", n == 1 && ev[0].filter == EVFILT_WRITE && ev[0].ident == (uintptr_t)p[1],
          "n %d filter %d", n, n > 0 ? ev[0].filter : 0);
    write(p[1], "hello", 5);
    n = kevent(kq, NULL, 0, ev, 4, &zero);
    CHECK("pipe readable, data=5, oneshot write gone", n == 1 && ev[0].filter == EVFILT_READ && ev[0].data == 5,
          "n %d data %ld", n, n > 0 ? (long)ev[0].data : -1L);
    n = kevent(kq, NULL, 0, ev, 4, &zero);
    CHECK("EV_CLEAR: no repeat until new data", n == 0, "n %d", n);

    EV_SET(&ch[0], 42, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 50, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);
    n = kevent(kq, NULL, 0, ev, 4, &sec);
    CHECK("EVFILT_TIMER 50 ms", n == 1 && ev[0].filter == EVFILT_TIMER && ev[0].ident == 42, "n %d", n);

    signal(SIGUSR1, SIG_IGN);
    EV_SET(&ch[0], SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);
    kill(getpid(), SIGUSR1);
    n = kevent(kq, NULL, 0, ev, 4, &sec);
    CHECK("EVFILT_SIGNAL SIGUSR1 (30)", n == 1 && ev[0].filter == EVFILT_SIGNAL && ev[0].ident == SIGUSR1 && SIGUSR1 == 30,
          "n %d", n);

    EV_SET(&ch[0], 7, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);
    EV_SET(&ch[0], 7, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);
    n = kevent(kq, NULL, 0, ev, 4, &zero);
    CHECK("EVFILT_USER trigger", n == 1 && ev[0].filter == EVFILT_USER && ev[0].ident == 7, "n %d", n);

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    EV_SET(&ch[0], sv[1], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);
    send(sv[0], "abc", 3, 0);
    n = kevent(kq, NULL, 0, ev, 4, &zero);
    CHECK("socketpair readable", n >= 1 && ev[0].ident == (uintptr_t)sv[1] && ev[0].data == 3, "n %d", n);
    EV_SET(&ch[0], sv[1], EVFILT_READ, EV_DELETE, 0, 0, NULL);
    kevent(kq, ch, 1, NULL, 0, NULL);

    pid_t pid = fork();
    if (pid == 0) {
        /* FreeBSD: the kqueue is not inherited; kevent on it must fail with EBADF */
        struct kevent e;
        int r = kevent(kq, NULL, 0, &e, 1, &zero);
        _exit(r == -1 && errno == EBADF ? 7 : 8);
    }
    EV_SET(&ch[0], pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
    int r = kevent(kq, ch, 1, NULL, 0, NULL);
    n = kevent(kq, NULL, 0, ev, 4, &sec);
    /* The child may already have exited when registering: then kevent returns ESRCH */
    CHECK("EVFILT_PROC NOTE_EXIT", (r == 0 && n == 1 && ev[0].filter == EVFILT_PROC && (ev[0].fflags & NOTE_EXIT))
          || (r == -1 && errno == ESRCH), "r %d n %d errno %d", r, n, errno);
    int st;
    waitpid(pid, &st, 0);
    CHECK("kqueue not inherited across fork", WIFEXITED(st) && WEXITSTATUS(st) == 7, "status %#x", st);

    printf("FBSDKQ-DONE %d\n", fails);
    return fails != 0;
}
