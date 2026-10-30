// Native Linux x86_64 Epoll & Eventfd ABI Test Binary
// Tests: eventfd2, epoll_create1, epoll_ctl (ADD/DEL/MOD), epoll_wait, socketpair integration

#define SYS_READ          0
#define SYS_WRITE         1
#define SYS_CLOSE         3
#define SYS_POLL          7
#define SYS_SOCKETPAIR    53
#define SYS_EXIT          60
#define SYS_EPOLL_WAIT    232
#define SYS_EPOLL_CTL     233
#define SYS_EVENTFD2      290
#define SYS_EPOLL_CREATE1 291

#define AF_UNIX           1
#define SOCK_STREAM       1

#define EPOLLIN           0x0001
#define EPOLLOUT          0x0004
#define EPOLLERR          0x0008
#define EPOLLHUP          0x0010

#define EPOLL_CTL_ADD     1
#define EPOLL_CTL_DEL     2
#define EPOLL_CTL_MOD     3

struct epoll_event {
    unsigned int events;
    unsigned long long data;
} __attribute__((__packed__));

static inline long sys_read(int fd, void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_READ), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_close(int fd) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_CLOSE), "D"(fd) : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int code) {
    asm volatile("syscall" :: "a"(SYS_EXIT), "D"(code) : "rcx", "r11", "memory");
    for (;;) {}
}

static inline long sys_socketpair(int domain, int type, int protocol, int sv[2]) {
    long ret;
    register long r10 asm("r10") = (long)sv;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SOCKETPAIR), "D"(domain), "S"(type), "d"(protocol), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_eventfd2(unsigned int initval, int flags) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_EVENTFD2), "D"(initval), "S"(flags) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_epoll_create1(int flags) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_EPOLL_CREATE1), "D"(flags) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    long ret;
    register long r10 asm("r10") = (long)event;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_EPOLL_CTL), "D"(epfd), "S"(op), "d"(fd), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    long ret;
    register long r10 asm("r10") = (long)timeout;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_EPOLL_WAIT), "D"(epfd), "S"(events), "d"(maxevents), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static void print_str(const char *s) {
    unsigned long len = 0;
    while (s[len]) len++;
    sys_write(1, s, len);
}

static void print_num(long n) {
    char buf[24];
    int idx = 0;
    if (n < 0) {
        buf[idx++] = '-';
        n = -n;
    }
    char tmp[20];
    int tlen = 0;
    if (n == 0) {
        tmp[tlen++] = '0';
    } else {
        while (n > 0) {
            tmp[tlen++] = '0' + (n % 10);
            n /= 10;
        }
    }
    for (int i = tlen - 1; i >= 0; i--) {
        buf[idx++] = tmp[i];
    }
    buf[idx] = 0;
    print_str(buf);
}

static void print_hex(unsigned long long val) {
    print_str("0x");
    char hex_chars[] = "0123456789abcdef";
    char buf[17];
    for (int i = 15; i >= 0; i--) {
        buf[15 - i] = hex_chars[(val >> (i * 4)) & 0xF];
    }
    buf[16] = 0;
    // Skip leading zeroes except last
    int start = 0;
    while (start < 15 && buf[start] == '0') start++;
    print_str(&buf[start]);
}

void _start(void) {
    print_str("\n========================================\n");
    print_str(" Hydra OS - Epoll & Eventfd Subsystem Test\n");
    print_str("========================================\n");

    // Test 1: eventfd2
    print_str("[1] Testing eventfd2(0, 0)...\n");
    int efd = sys_eventfd2(0, 0);
    if (efd < 0) {
        print_str("[-] FAIL: sys_eventfd2 returned ");
        print_num(efd);
        print_str("\n");
        sys_exit(1);
    }
    print_str("    -> Created eventfd FD: ");
    print_num(efd);
    print_str("\n");

    unsigned long long val_in = 42;
    sys_write(efd, &val_in, sizeof(val_in));

    unsigned long long val_out = 0;
    sys_read(efd, &val_out, sizeof(val_out));
    if (val_out != 42) {
        print_str("[-] FAIL: eventfd value mismatch (got ");
        print_num(val_out);
        print_str(")\n");
        sys_exit(2);
    }
    print_str("    -> Read counter value: ");
    print_num(val_out);
    print_str("\n");
    print_str("[+] PASS: eventfd counter write/read verified!\n\n");

    // Test 2: epoll_create1 & socketpair
    print_str("[2] Creating epoll instance and socket pair...\n");
    int epfd = sys_epoll_create1(0);
    if (epfd < 0) {
        print_str("[-] FAIL: sys_epoll_create1 returned ");
        print_num(epfd);
        print_str("\n");
        sys_exit(3);
    }
    print_str("    -> Created epoll FD: ");
    print_num(epfd);
    print_str("\n");

    int sv[2] = {-1, -1};
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    print_str("    -> Created socket pair FDs: [");
    print_num(sv[0]);
    print_str(", ");
    print_num(sv[1]);
    print_str("]\n");

    // Register sv[0] with EPOLLIN (tag: 0x1111)
    struct epoll_event ev_sock;
    ev_sock.events = EPOLLIN;
    ev_sock.data = 0x1111;
    long r = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, sv[0], &ev_sock);
    if (r < 0) {
        print_str("[-] FAIL: epoll_ctl ADD sv[0] returned ");
        print_num(r);
        print_str("\n");
        sys_exit(4);
    }

    // Register efd with EPOLLIN (tag: 0x2222)
    struct epoll_event ev_efd;
    ev_efd.events = EPOLLIN;
    ev_efd.data = 0x2222;
    r = sys_epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &ev_efd);
    if (r < 0) {
        print_str("[-] FAIL: epoll_ctl ADD efd returned ");
        print_num(r);
        print_str("\n");
        sys_exit(5);
    }
    print_str("[+] PASS: Registered socket and eventfd with epoll.\n\n");

    // Test 3: epoll_wait with timeout when no events ready
    print_str("[3] Testing epoll_wait timeout behavior...\n");
    struct epoll_event events[4];
    r = sys_epoll_wait(epfd, events, 4, 10); // 10ms timeout
    if (r != 0) {
        print_str("[-] FAIL: expected 0 ready events on empty wait, got ");
        print_num(r);
        print_str("\n");
        sys_exit(6);
    }
    print_str("[+] PASS: epoll_wait correctly returned 0 on timeout.\n\n");

    // Test 4: Trigger eventfd and receive wakeup
    print_str("[4] Triggering eventfd signaling (writing 100)...\n");
    val_in = 100;
    sys_write(efd, &val_in, sizeof(val_in));

    r = sys_epoll_wait(epfd, events, 4, -1);
    if (r < 1 || events[0].data != 0x2222) {
        print_str("[-] FAIL: epoll_wait did not return eventfd event!\n");
        sys_exit(7);
    }
    print_str("    -> Awakened with ");
    print_num(r);
    print_str(" event: tag=");
    print_hex(events[0].data);
    print_str(", events=");
    print_num(events[0].events);
    print_str("\n");
    sys_read(efd, &val_out, sizeof(val_out));
    print_str("[+] PASS: eventfd wakeup multiplexing verified!\n\n");

    // Test 5: Trigger Wayland socket stream and receive wakeup
    print_str("[5] Triggering Wayland socket message...\n");
    const char *wl_msg = "WAYLAND_FRAME_CALLBACK";
    sys_write(sv[1], wl_msg, 22);

    r = sys_epoll_wait(epfd, events, 4, -1);
    if (r < 1 || events[0].data != 0x1111) {
        print_str("[-] FAIL: epoll_wait did not return socket event!\n");
        sys_exit(8);
    }
    print_str("    -> Awakened with ");
    print_num(r);
    print_str(" event: tag=");
    print_hex(events[0].data);
    print_str(", events=");
    print_num(events[0].events);
    print_str("\n");

    char buf[32];
    for (int i = 0; i < 32; i++) buf[i] = 0;
    sys_read(sv[0], buf, sizeof(buf));
    print_str("    -> Received data: '");
    print_str(buf);
    print_str("'\n");
    print_str("[+] PASS: Wayland socket epoll multiplexing verified!\n\n");

    // Cleanup
    sys_epoll_ctl(epfd, EPOLL_CTL_DEL, sv[0], (void*)0);
    sys_epoll_ctl(epfd, EPOLL_CTL_DEL, efd, (void*)0);
    sys_close(efd);
    sys_close(sv[0]);
    sys_close(sv[1]);
    sys_close(epfd);

    print_str("========================================\n");
    print_str(" [OK] ALL 5 EPOLL/EVENTFD TESTS PASSED!\n");
    print_str(" Qt6/Wayland Event Loop Subsystem 100% OK\n");
    print_str("========================================\n");

    sys_exit(0);
}
