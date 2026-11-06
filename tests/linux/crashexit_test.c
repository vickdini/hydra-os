// Processes set up like Chromium's sandboxed renderers (init of new user + PID namespaces,
// ID maps, open pool files and a directory, descriptors in flight in a socketpair, chroot
// into an empty /proc directory via a CLONE_FS helper, a seccomp filter) die from a CPU
// fault, 60 times. Prints CRASHEXIT DONE if the kernel survives.
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void send_fd(int sock, int fd) {
    char byte = 'x';
    struct iovec iov = {&byte, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    memset(ctl, 0, sizeof ctl);
    struct msghdr m = {0};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl;
    m.msg_controllen = sizeof ctl;
    struct cmsghdr *c = CMSG_FIRSTHDR(&m);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c), &fd, sizeof(int));
    sendmsg(sock, &m, 0);
}

static void write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        if (write(fd, text, strlen(text))) {}
        close(fd);
    }
}

static int chroot_helper(void *a) {
    (void)a;
    if (chroot("/proc/self/fdinfo/") || chdir("/")) _exit(1);
    _exit(0);
}

static void renderer(unsigned uid, unsigned gid, int crash) {
    char buf[64];
    write_file("/proc/self/setgroups", "deny");
    snprintf(buf, sizeof buf, "%u %u 1\n", uid, uid);
    write_file("/proc/self/uid_map", buf);
    snprintf(buf, sizeof buf, "%u %u 1\n", gid, gid);
    write_file("/proc/self/gid_map", buf);
    int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY);
    int sv[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
    for (int k = 0; k < 3; k++) {
        int f = open(k ? "/bin" : "/bin/sh", O_RDONLY);
        send_fd(sv[0], f);
        close(f);
    }
    static char stack[65536] __attribute__((aligned(16)));
    pid_t h = clone(chroot_helper, stack + sizeof stack, CLONE_FS | SIGCHLD, 0);
    waitpid(h, 0, 0);
    struct sock_filter allow[] = {BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)};
    struct sock_fprog p = {1, allow};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &p);
    (void)proc_fd;
    if (crash) *(volatile int *)8 = 1; // SIGSEGV
    _exit(0);
}

int main(void) {
    unsigned uid = getuid(), gid = getgid();
    int gone = 0;
    for (int i = 0; i < 60; i++) {
        pid_t c = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
        if (c == 0) renderer(uid, gid, i % 2);
        int st;
        waitpid(c, &st, 0);
        gone += WIFSIGNALED(st) || WIFEXITED(st);
    }
    printf("CRASHEXIT DONE: %d/60 renderers gone\n", gone);
    return 0;
}
