// Namespace test, following Chromium's namespace sandbox: user namespace + ID maps,
// nested unshare, PID/net namespaces, chroot to /proc/self/fdinfo via a CLONE_FS helper,
// and no system-wide privilege from capabilities held inside a user namespace.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (c) printf("ok   " __VA_ARGS__); else { fails++; printf("FAIL " __VA_ARGS__); } printf("\n"); fflush(stdout); } while (0)

static int write_file(const char *path, const char *text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int n = write(fd, text, strlen(text));
    close(fd);
    return n == (int)strlen(text) ? 0 : -1;
}

static int map_ids(uid_t uid, gid_t gid) {
    char buf[64];
    if (write_file("/proc/self/setgroups", "deny")) return -1;
    snprintf(buf, sizeof buf, "%u %u 1\n", uid, uid);
    if (write_file("/proc/self/uid_map", buf)) return -2;
    snprintf(buf, sizeof buf, "%u %u 1\n", gid, gid);
    if (write_file("/proc/self/gid_map", buf)) return -3;
    return 0;
}

static unsigned long long cap_effective(void) {
    struct __user_cap_header_struct h = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2];
    if (syscall(SYS_capget, &h, d)) return 0;
    return d[0].effective | ((unsigned long long)d[1].effective << 32);
}

static int chroot_helper(void *a) {
    (void)a;
    if (chroot("/proc/self/fdinfo/")) _exit(1);
    if (chdir("/")) _exit(2);
    _exit(0);
}

static volatile int idle_up;
static void *idle(void *a) { (void)a; idle_up = 1; pause(); return 0; }

// Runs in the child of clone(CLONE_NEWUSER)
static int in_userns(uid_t uid, gid_t gid, const char *parent_ns) {
    char link[64] = {0};
    CHECK(getuid() == 65534, "unmapped uid reads 65534 (%d)", getuid());
    CHECK(readlink("/proc/self/ns/user", link, sizeof link - 1) > 0 && strcmp(link, parent_ns), "own user namespace %s", link);
    CHECK(cap_effective() != 0, "full capabilities inside (%#llx)", cap_effective());
    char bad[64];
    snprintf(bad, sizeof bad, "0 %u 1\n", uid + 1);
    CHECK(write_file("/proc/self/uid_map", bad) != 0, "mapping someone else's uid refused");
    CHECK(map_ids(uid, gid) == 0, "setgroups deny + uid_map + gid_map");
    CHECK(getuid() == uid && getgid() == gid, "mapped ids %d/%d", getuid(), getgid());
    CHECK(write_file("/proc/self/uid_map", "0 0 1\n") != 0, "uid_map written only once");
    CHECK(setuid(0) != 0, "namespace caps grant no setuid(0) in the system");
    CHECK(syscall(SYS_reboot, 0xfee1dead, 672274793, 0x4321fedc, 0) != 0, "namespace caps grant no reboot");

    // Chromium's MoveToNewUserNS: unshare again, map again
    CHECK(unshare(CLONE_NEWUSER) == 0, "nested unshare(CLONE_NEWUSER)");
    CHECK(map_ids(uid, gid) == 0, "maps in nested namespace");
    CHECK(unshare(CLONE_NEWNET | CLONE_NEWPID) == 0, "unshare net + pid");
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(80)};
    sa.sin_addr.s_addr = htonl(0x01010101);
    errno = 0;
    CHECK(s < 0 || (connect(s, (void *)&sa, sizeof sa) != 0 && errno == ENETUNREACH), "no network in new net namespace (errno %d)", errno);
    if (s >= 0) close(s);

    // Chromium's DropFileSystemAccess
    int proc_fd = open("/proc", O_DIRECTORY | O_RDONLY);
    CHECK(proc_fd >= 0, "open /proc (errno %d)", errno);
    static char stack[65536] __attribute__((aligned(16)));
    pid_t h = clone(chroot_helper, stack + sizeof stack, CLONE_FS | SIGCHLD, 0);
    int st = -1;
    waitpid(h, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "chroot helper (status %#x)", st);
    struct stat sb;
    CHECK(stat("/proc", &sb) != 0 && stat("/etc/passwd", &sb) != 0, "no file system after chroot");
    CHECK(open("/etc/hostname", O_RDONLY) < 0, "open by absolute path fails");
    int fd = openat(proc_fd, "self/status", O_RDONLY);
    CHECK(fd >= 0, "pre-opened /proc fd still usable (errno %d)", errno);

    struct __user_cap_header_struct hd = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct d[2] = {{0}};
    CHECK(syscall(SYS_capset, &hd, d) == 0 && cap_effective() == 0, "drop all capabilities");
    return fails;
}

int main(void) {
    struct stat sb;
    char parent_ns[64] = {0};
    CHECK(stat("/proc/self/ns/user", &sb) == 0 && stat("/proc/self/ns/pid", &sb) == 0 && stat("/proc/self/ns/net", &sb) == 0, "/proc/self/ns/{user,pid,net} exist");
    CHECK(readlink("/proc/self/ns/user", parent_ns, sizeof parent_ns - 1) > 0, "initial user ns %s", parent_ns);
    CHECK(access("/proc/self/setgroups", F_OK) == 0, "/proc/self/setgroups exists");
    errno = 0;
    CHECK(unshare(CLONE_NEWNET) != 0 && errno == EPERM, "unshare(CLONE_NEWNET) without caps -> EPERM");

    pthread_t th;
    pthread_create(&th, 0, idle, 0);
    while (!idle_up) usleep(1000); // glibc's setuid() waits for threads still starting
    errno = 0;
    CHECK(unshare(CLONE_NEWUSER) != 0 && errno == EINVAL, "unshare(CLONE_NEWUSER) multithreaded -> EINVAL");

    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t c = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
    if (c == 0) _exit(in_userns(uid, gid, parent_ns) ? 1 : 0);
    int st;
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "user namespace child (status %#x)", st);
    CHECK((getuid() == uid && cap_effective() == 0) || uid == 0, "parent unaffected");

    // PID namespace: init sees itself as 1, its child sees it as parent 1, and the
    // namespace dies with init
    int p[2];
    if (pipe(p)) return 1;
    c = syscall(SYS_clone, CLONE_NEWUSER | CLONE_NEWPID | SIGCHLD, 0, 0, 0, 0);
    if (c == 0) {
        int code = (getpid() == 1 ? 0 : 1) | (getppid() == 0 ? 0 : 2) | (kill(1, 0) == 0 ? 0 : 4);
        if (fork() == 0) {
            close(p[0]);
            if (getppid() != 1) { if (write(p[1], "x", 1)) {} }
            sleep(30);
            _exit(0);
        }
        _exit(code);
    }
    close(p[1]);
    waitpid(c, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "pid namespace init: getpid 1, getppid 0, kill(1) (code %d)", WEXITSTATUS(st));
    time_t t0 = time(0);
    char ch;
    int n = read(p[0], &ch, 1);
    CHECK(n == 0, "init's child saw parent 1");
    CHECK(time(0) - t0 < 10, "namespace members killed with init (%ds)", (int)(time(0) - t0));

    printf(fails ? "NS TEST FAILED (%d)\n" : "NS TEST PASSED\n", fails);
    return fails != 0;
}
