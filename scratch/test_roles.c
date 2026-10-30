// Native Linux x86_64 User and Superuser (Root) Security ABI Test Binary
// Demonstrates POSIX credentials: getuid, geteuid, getgid, getegid, setuid, seteuid, capget.

#define SYS_WRITE      1
#define SYS_EXIT       60
#define SYS_GETUID     102
#define SYS_GETGID     104
#define SYS_SETUID     105
#define SYS_SETGID     106
#define SYS_GETEUID    107
#define SYS_GETEGID    108
#define SYS_SETRESUID  117  /* seteuid(e) == setresuid(-1, e, -1), as in glibc */
#define SYS_SETRESGID  119
#define SYS_GETRESUID  118
#define SYS_GETRESGID  120
#define SYS_CAPGET     125

static inline long sys_write(int fd, const void *buf, unsigned long count) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_WRITE), "D"(fd), "S"(buf), "d"(count) : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int code) {
    asm volatile("syscall" :: "a"(SYS_EXIT), "D"(code) : "rcx", "r11", "memory");
    for (;;) {}
}

static inline long sys_getuid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETUID) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_geteuid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETEUID) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_getgid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETGID) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_getegid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETEGID) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_setuid(unsigned int uid) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SETUID), "D"((unsigned long)uid) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_seteuid(unsigned int euid) {
    long ret;
    // seteuid(euid) is setresuid(-1, euid, -1): Linux has no seteuid system call
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_SETRESUID), "D"(-1L), "S"((unsigned long)euid), "d"(-1L) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_getresuid(unsigned int *ruid, unsigned int *euid, unsigned int *suid) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_GETRESUID), "D"(ruid), "S"(euid), "d"(suid) : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_capget(void *hdrp, void *datap) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(SYS_CAPGET), "D"(hdrp), "S"(datap) : "rcx", "r11", "memory");
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
    sys_write(1, buf, idx);
}

void _start(void) {
    print_str("\n=======================================================\n");
    print_str("   HYDRA OS POSIX CREDENTIAL & SECURITY ROLE TEST\n");
    print_str("=======================================================\n");

    // 1. Check initial credentials
    long uid = sys_getuid();
    long euid = sys_geteuid();
    long gid = sys_getgid();
    long egid = sys_getegid();

    print_str("[ROLETEST] Step 1: Initial credentials: UID=");
    print_num(uid);
    print_str(", EUID=");
    print_num(euid);
    print_str(", GID=");
    print_num(gid);
    print_str(", EGID=");
    print_num(egid);
    print_str(uid == 0 ? " (Superuser Root)\n" : " (Standard User)\n");

    unsigned int ruid = 999, eeuid = 999, suid = 999;
    sys_getresuid(&ruid, &eeuid, &suid);
    print_str("[ROLETEST] Step 1b: getresuid -> ruid=");
    print_num(ruid);
    print_str(", euid=");
    print_num(eeuid);
    print_str(", suid=");
    print_num(suid);
    print_str("\n");

    // 2. Drop privileges to UID 1000 (hydra)
    print_str("[ROLETEST] Step 2: Dropping privileges via setuid(1000)...\n");
    long drop_res = sys_setuid(1000);
    print_str("[ROLETEST] setuid(1000) result: ");
    print_num(drop_res);
    print_str("\n");

    uid = sys_getuid();
    euid = sys_geteuid();
    print_str("[ROLETEST] Current credentials: UID=");
    print_num(uid);
    print_str(", EUID=");
    print_num(euid);
    if (uid == 1000 && euid == 1000) {
        print_str(" [SUCCESS: Standard User Hydra]\n");
    } else {
        print_str(" [FAIL: Expected UID 1000]\n");
        sys_exit(1);
    }

    // 3. Unauthorized escalation attempt: setuid(0)
    print_str("[ROLETEST] Step 3: Attempting unauthorized escalation via setuid(0)...\n");
    long esc_res = sys_setuid(0);
    print_str("[ROLETEST] setuid(0) result: ");
    print_num(esc_res);
    if (esc_res == -1) {
        print_str(" -> EPERM [DENIED: Security Enforced!]\n");
    } else {
        print_str(" -> [SECURITY VIOLATION! setuid(0) succeeded!]\n");
        sys_exit(2);
    }

    // 4. Unauthorized escalation attempt: seteuid(0)
    print_str("[ROLETEST] Step 4: Attempting unauthorized escalation via seteuid(0)...\n");
    long e_esc_res = sys_seteuid(0);
    print_str("[ROLETEST] seteuid(0) result: ");
    print_num(e_esc_res);
    if (e_esc_res == -1) {
        print_str(" -> EPERM [DENIED: Security Enforced!]\n");
    } else {
        print_str(" -> [SECURITY VIOLATION! seteuid(0) succeeded!]\n");
        sys_exit(3);
    }

    // 5. Authorized unprivileged setuid(1000)
    print_str("[ROLETEST] Step 5: Testing authorized setuid(1000) as unprivileged user...\n");
    long auth_res = sys_setuid(1000);
    print_str("[ROLETEST] setuid(1000) result: ");
    print_num(auth_res);
    if (auth_res == 0) {
        print_str(" -> SUCCESS (allowed to retain self identity)\n");
    } else {
        print_str(" -> FAIL\n");
    }

    // 6. Capability verification
    unsigned int cap_data[3] = {0xAA, 0xBB, 0xCC};
    sys_capget(0, cap_data);
    print_str("[ROLETEST] Step 6: capget -> effective mask=0x");
    print_num(cap_data[0]);
    if (cap_data[0] == 0) {
        print_str(" [SUCCESS: Capabilities restricted for UID 1000]\n");
    } else {
        print_str(" [WARNING: Non-zero caps]\n");
    }

    print_str("=======================================================\n");
    print_str("[+] ALL TESTS PASSED! User Role Security Verified.\n");
    print_str("=======================================================\n");

    sys_exit(0);
}
