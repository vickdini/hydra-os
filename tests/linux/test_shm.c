// Native Linux x86_64 Wayland Shared Memory & FD Passing ABI Test Binary
// Tests: memfd_create, ftruncate, mmap, socketpair, sendmsg/recvmsg with SCM_RIGHTS

#define SYS_READ          0
#define SYS_WRITE         1
#define SYS_CLOSE         3
#define SYS_MMAP          9
#define SYS_MUNMAP        11
#define SYS_SENDMSG       46
#define SYS_RECVMSG       47
#define SYS_SOCKETPAIR    53
#define SYS_EXIT          60
#define SYS_FTRUNCATE     77
#define SYS_MEMFD_CREATE  319

#define AF_UNIX           1
#define SOCK_STREAM       1
#define SOL_SOCKET        1
#define SCM_RIGHTS        1

#define PROT_READ         0x1
#define PROT_WRITE        0x2
#define MAP_SHARED        0x01

struct iovec {
    void  *iov_base;
    unsigned long iov_len;
};

struct msghdr {
    void          *msg_name;
    unsigned int   msg_namelen;
    struct iovec  *msg_iov;
    unsigned long  msg_iovlen;
    void          *msg_control;
    unsigned long  msg_controllen;
    int            msg_flags;
};

struct cmsghdr {
    unsigned long  cmsg_len;
    int            cmsg_level;
    int            cmsg_type;
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

static inline long sys_socketpair(int domain, int type, int protocol, int sv[2]) {
    long ret;
    register long r10 asm("r10") = (long)sv;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SOCKETPAIR), "D"(domain), "S"(type), "d"(protocol), "r"(r10) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_memfd_create(const char *name, unsigned int flags) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_MEMFD_CREATE), "D"(name), "S"(flags) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_ftruncate(int fd, unsigned long length) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_FTRUNCATE), "D"(fd), "S"(length) : "rcx", "r11", "memory");
    return ret;
}

static inline void *sys_mmap(void *addr, unsigned long length, int prot, int flags, int fd, unsigned long offset) {
    long ret;
    register long r10 asm("r10") = flags;
    register long r8 asm("r8") = fd;
    register long r9 asm("r9") = offset;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_MMAP), "D"(addr), "S"(length), "d"(prot), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return (void*)ret;
}

static inline long sys_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SENDMSG), "D"(sockfd), "S"(msg), "d"(flags) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_RECVMSG), "D"(sockfd), "S"(msg), "d"(flags) : "rcx", "r11", "memory");
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
    print_str(" Hydra OS - Wayland Shm & SCM_RIGHTS Test\n");
    print_str("========================================\n");

    // Test 1: memfd_create & ftruncate
    print_str("[1] Creating anonymous shared memory buffer (memfd_create)...\n");
    int shm_fd = sys_memfd_create("wayland_shm_pool", 0);
    if (shm_fd < 0) {
        print_str("[-] FAIL: sys_memfd_create returned ");
        print_num(shm_fd);
        print_str("\n");
        sys_exit(1);
    }
    print_str("    -> Created memfd FD: ");
    print_num(shm_fd);
    print_str("\n");

    long r = sys_ftruncate(shm_fd, 4096);
    if (r < 0) {
        print_str("[-] FAIL: sys_ftruncate returned ");
        print_num(r);
        print_str("\n");
        sys_exit(2);
    }
    print_str("    -> Resized shm pool to 4096 bytes\n");

    char *client_ptr = (char*)sys_mmap((void*)0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if ((long)client_ptr < 0) {
        print_str("[-] FAIL: sys_mmap returned error\n");
        sys_exit(3);
    }
    print_str("    -> Mapped shared buffer into client space\n");

    const char *pixel_hdr = "WAYLAND_PIXEL_BUFFER_HEADER";
    for (int i = 0; i < 27; i++) {
        client_ptr[i] = pixel_hdr[i];
    }
    client_ptr[27] = 0;
    print_str("[+] PASS: memfd_create, ftruncate & mmap verified!\n\n");

    // Test 2: Create Wayland IPC socket pair
    print_str("[2] Initializing Wayland client/server IPC socket pair...\n");
    int sv[2] = {-1, -1};
    sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    print_str("    -> Socket pair FDs: [");
    print_num(sv[0]);
    print_str(", ");
    print_num(sv[1]);
    print_str("]\n\n");

    // Test 3: Send shm_fd over socket using SCM_RIGHTS ancillary data
    print_str("[3] Sending wl_shm buffer FD via sendmsg(SCM_RIGHTS)...\n");
    char cmsg_buf[32];
    for (int i = 0; i < 32; i++) cmsg_buf[i] = 0;

    struct cmsghdr *cmsg = (struct cmsghdr*)cmsg_buf;
    cmsg->cmsg_len = 20; // 16 bytes header + 4 bytes int FD
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    int *fd_payload = (int*)(cmsg_buf + 16);
    *fd_payload = shm_fd;

    const char *wl_cmd = "WL_SHM_CREATE_POOL_REQ";
    struct iovec iov;
    iov.iov_base = (void*)wl_cmd;
    iov.iov_len = 22;

    struct msghdr msg;
    msg.msg_name = (void*)0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)cmsg_buf;
    msg.msg_controllen = 20;
    msg.msg_flags = 0;

    long sent = sys_sendmsg(sv[0], &msg, 0);
    if (sent < 0) {
        print_str("[-] FAIL: sys_sendmsg returned ");
        print_num(sent);
        print_str("\n");
        sys_exit(4);
    }
    print_str("    -> Transmitted ");
    print_num(sent);
    print_str(" payload bytes + FD ");
    print_num(shm_fd);
    print_str(" across socket.\n");
    print_str("[+] PASS: sendmsg SCM_RIGHTS transmission verified!\n\n");

    // Test 4: Server receives FD via recvmsg(SCM_RIGHTS)
    print_str("[4] Server receiving FD via recvmsg(SCM_RIGHTS)...\n");
    char recv_payload[32];
    for (int i = 0; i < 32; i++) recv_payload[i] = 0;

    char recv_cmsg_buf[32];
    for (int i = 0; i < 32; i++) recv_cmsg_buf[i] = 0;

    struct iovec recv_iov;
    recv_iov.iov_base = (void*)recv_payload;
    recv_iov.iov_len = sizeof(recv_payload);

    struct msghdr recv_msg;
    recv_msg.msg_name = (void*)0;
    recv_msg.msg_namelen = 0;
    recv_msg.msg_iov = &recv_iov;
    recv_msg.msg_iovlen = 1;
    recv_msg.msg_control = (void*)recv_cmsg_buf;
    recv_msg.msg_controllen = sizeof(recv_cmsg_buf);
    recv_msg.msg_flags = 0;

    long recvd = sys_recvmsg(sv[1], &recv_msg, 0);
    if (recvd < 0) {
        print_str("[-] FAIL: sys_recvmsg returned ");
        print_num(recvd);
        print_str("\n");
        sys_exit(5);
    }

    struct cmsghdr *r_cmsg = (struct cmsghdr*)recv_cmsg_buf;
    if (r_cmsg->cmsg_level != SOL_SOCKET || r_cmsg->cmsg_type != SCM_RIGHTS) {
        print_str("[-] FAIL: ancillary data type mismatch\n");
        sys_exit(6);
    }

    int received_shm_fd = *(int*)(recv_cmsg_buf + 16);
    print_str("    -> Received payload: '");
    print_str(recv_payload);
    print_str("'\n");
    print_str("    -> Successfully received passed FD: ");
    print_num(received_shm_fd);
    print_str("\n");
    print_str("[+] PASS: recvmsg SCM_RIGHTS reception verified!\n\n");

    // Test 5: Verify zero-copy shared memory synchronization
    print_str("[5] Testing zero-copy shared memory synchronization...\n");
    char *server_ptr = (char*)sys_mmap((void*)0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, received_shm_fd, 0);
    if ((long)server_ptr < 0) {
        print_str("[-] FAIL: server sys_mmap returned error\n");
        sys_exit(7);
    }

    print_str("    -> Server inspected buffer: '");
    print_str(server_ptr);
    print_str("'\n");
    if (str_cmp(server_ptr, pixel_hdr, 27) != 0) {
        print_str("[-] FAIL: shared memory content mismatch on server!\n");
        sys_exit(8);
    }

    // Server modifies buffer in place (compositor drawing)
    const char *composited = "SERVER_COMPOSITED_SURFACE";
    for (int i = 0; i < 25; i++) {
        server_ptr[64 + i] = composited[i];
    }
    server_ptr[64 + 25] = 0;

    // Client verifies modification
    print_str("    -> Client inspected buffer at offset 64: '");
    print_str(&client_ptr[64]);
    print_str("'\n");
    if (str_cmp(&client_ptr[64], composited, 25) != 0) {
        print_str("[-] FAIL: client did not observe server modifications!\n");
        sys_exit(9);
    }
    print_str("[+] PASS: Zero-copy bidirectional synchronization verified!\n\n");

    // Teardown
    sys_close(shm_fd);
    sys_close(received_shm_fd);
    sys_close(sv[0]);
    sys_close(sv[1]);

    print_str("========================================\n");
    print_str(" [OK] ALL 5 SHM & SCM_RIGHTS TESTS PASSED!\n");
    print_str(" Wayland Shared Memory Subsystem 100% OK\n");
    print_str("========================================\n");

    sys_exit(0);
}
