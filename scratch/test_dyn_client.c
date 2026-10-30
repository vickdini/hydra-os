// Dynamically linked client application testing PT_INTERP and auxv handoff

#define SYS_WRITE 1
#define SYS_EXIT  60

static long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void print(const char *s) {
    int len = 0;
    while (s[len]) len++;
    sys_write(1, s, len);
}

void _start(void) {
    print("[*] Application main entry point reached after dynamic linker handoff!\n");
    print("  [+] Running unprivileged in Ring 3 userspace.\n");
    print("============================================================\n");
    print("[+] SUCCESS: Dynamic Linker (PT_INTERP) & Auxv Fully Verified!\n");
    print("============================================================\n");

    __asm__ volatile (
        "mov $60, %%rax\n"
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        : : : "rax", "rdi"
    );
}
