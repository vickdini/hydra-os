// Native Linux x86_64 userland test binary
// Uses direct Linux syscall instruction (x86_64 ABI)

static inline long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(1), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_getpid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(39) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_open(const char *path, int flags, int mode) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(2), "D"(path), "S"(flags), "d"(mode) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_read(int fd, void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(0), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_close(int fd) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(3), "D"(fd) : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int code) {
    asm volatile("syscall" :: "a"(60), "D"(code) : "rcx", "r11", "memory");
    for (;;) {}
}

static unsigned long simple_strlen(const char *s) {
    unsigned long len = 0;
    while (*s++) len++;
    return len;
}

static void print_str(const char *s) {
    sys_write(1, s, simple_strlen(s));
}

void _start(void) {
    print_str("\n[LINUX PROCESS STARTED]\n");
    print_str("Hello from genuine Linux x86_64 userspace on Hydra OS!\n");

    // Test PID syscall
    long pid = sys_getpid();
    if (pid >= 0) {
        print_str("[LINUX SYSCALL] sys_getpid() returned task ID\n");
    }

    // Test /proc/version reading via sys_open / sys_read / sys_close
    int fd = (int)sys_open("/proc/version", 0, 0);
    if (fd >= 0) {
        char buf[128];
        long n = sys_read(fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            print_str("[LINUX SYSCALL] Read from /proc/version: ");
            sys_write(1, buf, n);
        }
        sys_close(fd);
    }

    print_str("[LINUX PROCESS COMPLETED] Exiting with status 0...\n\n");
    sys_exit(0);
}
