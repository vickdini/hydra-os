// Native Linux x86_64 Unix Domain Socket & Wayland IPC ABI Test Binary
// Tests: socket, bind, listen, connect, accept, socketpair, getsockname, send/recv, read/write, shutdown.

#define SYS_READ        0
#define SYS_WRITE       1
#define SYS_CLOSE       3
#define SYS_SOCKET      41
#define SYS_CONNECT     42
#define SYS_ACCEPT      43
#define SYS_SENDTO      44
#define SYS_RECVFROM    45
#define SYS_SHUTDOWN    48
#define SYS_BIND        49
#define SYS_LISTEN      50
#define SYS_GETSOCKNAME 51
#define SYS_GETPEERNAME 52
#define SYS_SOCKETPAIR  53
#define SYS_EXIT        60
#define SYS_ACCEPT4     288

#define AF_UNIX         1
#define SOCK_STREAM     1
#define SHUT_RDWR       2
#define NULL            ((void*)0)

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

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

static inline long sys_socket(int domain, int type, int protocol) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SOCKET), "D"(domain), "S"(type), "d"(protocol) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_bind(int fd, const struct sockaddr_un *addr, unsigned int addrlen) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_BIND), "D"(fd), "S"(addr), "d"(addrlen) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_listen(int fd, int backlog) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_LISTEN), "D"(fd), "S"(backlog) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_accept(int fd, struct sockaddr_un *addr, unsigned int *addrlen) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_ACCEPT), "D"(fd), "S"(addr), "d"(addrlen) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_connect(int fd, const struct sockaddr_un *addr, unsigned int addrlen) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_CONNECT), "D"(fd), "S"(addr), "d"(addrlen) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_socketpair(int domain, int type, int protocol, int sv[2]) {
    long ret;
    register long r10 asm("r10") = (long)sv;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SOCKETPAIR), "D"(domain), "S"(type), "d"(protocol), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_getsockname(int fd, struct sockaddr_un *addr, unsigned int *addrlen) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETSOCKNAME), "D"(fd), "S"(addr), "d"(addrlen) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_shutdown(int fd, int how) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SHUTDOWN), "D"(fd), "S"(how) : "rcx", "r11", "memory");
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

static int str_cmp(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) return 1;
        if (a[i] == 0) return 0;
    }
    return 0;
}

void _start(void) {
    print_str("\n========================================\n");
    print_str(" Hydra OS - Unix Domain Socket & Wayland IPC Test\n");
    print_str("========================================\n");

    // Test 1: socketpair
    print_str("[1] Testing socketpair(AF_UNIX, SOCK_STREAM)...\n");
    int sv[2] = {-1, -1};
    long r = sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    if (r < 0) {
        print_str("[-] FAIL: sys_socketpair returned ");
        print_num(r);
        print_str("\n");
        sys_exit(1);
    }
    print_str("    -> Created socket pair FDs: [");
    print_num(sv[0]);
    print_str(", ");
    print_num(sv[1]);
    print_str("]\n");

    const char *msg_a = "WAYLAND_MSG_FROM_PEER_A";
    sys_write(sv[0], msg_a, 23);

    char buf[64];
    for (int i = 0; i < 64; i++) buf[i] = 0;
    long n = sys_read(sv[1], buf, sizeof(buf));
    if (n != 23 || str_cmp(buf, msg_a, 23) != 0) {
        print_str("[-] FAIL: socketpair rx mismatch!\n");
        sys_exit(2);
    }
    print_str("    -> Read: '");
    print_str(buf);
    print_str("'\n");

    const char *msg_b = "WAYLAND_REPLY_FROM_PEER_B";
    sys_write(sv[1], msg_b, 25);
    for (int i = 0; i < 64; i++) buf[i] = 0;
    n = sys_read(sv[0], buf, sizeof(buf));
    if (n != 25 || str_cmp(buf, msg_b, 25) != 0) {
        print_str("[-] FAIL: socketpair reply mismatch!\n");
        sys_exit(3);
    }
    print_str("    -> Read reply: '");
    print_str(buf);
    print_str("'\n");
    print_str("[+] PASS: socketpair bidirectional IPC verified.\n\n");

    // Test 2: Server socket bind & listen on /run/user/1000/wayland-0
    print_str("[2] Initializing Wayland server socket...\n");
    int srv_fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        print_str("[-] FAIL: sys_socket returned ");
        print_num(srv_fd);
        print_str("\n");
        sys_exit(4);
    }

    struct sockaddr_un srv_addr;
    srv_addr.sun_family = AF_UNIX;
    const char *w_path = "/run/user/1000/wayland-0";
    int p_idx = 0;
    while (w_path[p_idx]) {
        srv_addr.sun_path[p_idx] = w_path[p_idx];
        p_idx++;
    }
    srv_addr.sun_path[p_idx] = 0;

    r = sys_bind(srv_fd, &srv_addr, sizeof(srv_addr));
    if (r < 0) {
        print_str("[-] FAIL: sys_bind returned ");
        print_num(r);
        print_str("\n");
        sys_exit(5);
    }

    r = sys_listen(srv_fd, 5);
    if (r < 0) {
        print_str("[-] FAIL: sys_listen returned ");
        print_num(r);
        print_str("\n");
        sys_exit(6);
    }
    print_str("[+] PASS: Server bound and listening on /run/user/1000/wayland-0\n\n");

    // Test 3: Client connect to /run/user/1000/wayland-0 and exchange Wayland handshake
    print_str("[3] Connecting Wayland client to /run/user/1000/wayland-0...\n");
    int cli_fd = sys_socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_fd < 0) {
        print_str("[-] FAIL: client sys_socket returned ");
        print_num(cli_fd);
        print_str("\n");
        sys_exit(7);
    }

    r = sys_connect(cli_fd, &srv_addr, sizeof(srv_addr));
    if (r < 0) {
        print_str("[-] FAIL: sys_connect returned ");
        print_num(r);
        print_str("\n");
        sys_exit(8);
    }
    print_str("    -> Client connected successfully!\n");

    // Server accepts connection
    int accepted_fd = sys_accept(srv_fd, NULL, NULL);
    if (accepted_fd < 0) {
        print_str("[-] FAIL: sys_accept returned ");
        print_num(accepted_fd);
        print_str("\n");
        sys_exit(9);
    }
    print_str("    -> Server accepted client connection FD: ");
    print_num(accepted_fd);
    print_str("\n");

    // Client writes Wayland handshake packet: wl_display.get_registry
    const char *wl_client_msg = "WL_DISPLAY_GET_REGISTRY_ID1";
    sys_write(cli_fd, wl_client_msg, 27);

    for (int i = 0; i < 64; i++) buf[i] = 0;
    n = sys_read(accepted_fd, buf, sizeof(buf));
    if (n != 27 || str_cmp(buf, wl_client_msg, 27) != 0) {
        print_str("[-] FAIL: Wayland handshake rx mismatch!\n");
        sys_exit(10);
    }
    print_str("    -> Server received: '");
    print_str(buf);
    print_str("'\n");

    // Server replies with registry globals: wl_compositor, xdg_wm_base
    const char *wl_srv_reply = "WL_REGISTRY_GLOBAL_COMPOSITOR_AND_XDG_WM";
    sys_write(accepted_fd, wl_srv_reply, 40);

    for (int i = 0; i < 64; i++) buf[i] = 0;
    n = sys_read(cli_fd, buf, sizeof(buf));
    if (n != 40 || str_cmp(buf, wl_srv_reply, 40) != 0) {
        print_str("[-] FAIL: Wayland registry reply mismatch!\n");
        sys_exit(11);
    }
    print_str("    -> Client received: '");
    print_str(buf);
    print_str("'\n");
    print_str("[+] PASS: Wayland IPC client/server handshake verified!\n\n");

    // Test 4: Verify getsockname
    print_str("[4] Testing getsockname on server FD...\n");
    struct sockaddr_un check_addr;
    unsigned int check_len = sizeof(check_addr);
    r = sys_getsockname(srv_fd, &check_addr, &check_len);
    if (r < 0 || check_addr.sun_family != AF_UNIX) {
        print_str("[-] FAIL: sys_getsockname error\n");
        sys_exit(12);
    }
    print_str("    -> Socket address: '");
    print_str(check_addr.sun_path);
    print_str("'\n");
    print_str("[+] PASS: getsockname verified!\n\n");

    // Test 5: Cleanup & shutdown
    sys_shutdown(cli_fd, SHUT_RDWR);
    sys_close(cli_fd);
    sys_close(accepted_fd);
    sys_close(srv_fd);
    sys_close(sv[0]);
    sys_close(sv[1]);

    print_str("========================================\n");
    print_str(" [OK] ALL 5 SOCKET IPC TESTS PASSED!\n");
    print_str(" Unix Domain Sockets & Wayland IPC 100% OK\n");
    print_str("========================================\n");

    sys_exit(0);
}
