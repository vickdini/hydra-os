// Native Linux x86_64 Multi-Threading & Futex Test Binary
// Demonstrates raw sys_clone, sys_futex, and thread synchronization.

#define CLONE_VM             0x00000100
#define CLONE_FS             0x00000200
#define CLONE_FILES          0x00000400
#define CLONE_SIGHAND        0x00000800
#define CLONE_THREAD         0x00010000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID   0x01000000

#define FUTEX_WAIT           0
#define FUTEX_WAKE           1

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

static inline long sys_gettid(void) {
    long ret;
    asm volatile("syscall" : "=a"(ret) : "a"(186) : "rcx", "r11", "memory");
    return ret;
}

static inline void sys_exit(int code) {
    asm volatile("syscall" :: "a"(60), "D"(code) : "rcx", "r11", "memory");
    for (;;) {}
}

static inline long sys_clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls) {
    long ret;
    register int *r10 asm("r10") = ctid;
    register unsigned long r8 asm("r8") = newtls;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(56), "D"(flags), "S"(child_stack), "d"(ptid), "r"(r10), "r"(r8)
                 : "rcx", "r11", "memory");
    return ret;
}

static inline long sys_futex(int *uaddr, int op, int val, const void *timeout, int *uaddr2, int val3) {
    long ret;
    register int *r10 asm("r10") = (int*)timeout;
    register int *r8 asm("r8") = uaddr2;
    register int r9 asm("r9") = val3;
    asm volatile("syscall"
                 : "=a"(ret)
                 : "a"(202), "D"(uaddr), "S"(op), "d"(val), "r"(r10), "r"(r8), "r"(r9)
                 : "rcx", "r11", "memory");
    return ret;
}

static unsigned long simple_strlen(const char *s) {
    unsigned long len = 0;
    while (*s++) len++;
    return len;
}

static void print_str(const char *s) {
    sys_write(1, s, simple_strlen(s));
}

static void print_num(long val) {
    char buf[32];
    int pos = 0;
    if (val == 0) {
        buf[pos++] = '0';
    } else {
        if (val < 0) {
            buf[pos++] = '-';
            val = -val;
        }
        char temp[32];
        int tpos = 0;
        while (val > 0) {
            temp[tpos++] = '0' + (val % 10);
            val /= 10;
        }
        for (int i = tpos - 1; i >= 0; i--) {
            buf[pos++] = temp[i];
        }
    }
    buf[pos] = '\0';
    print_str(buf);
}

// Dedicated stack for child thread (4096 bytes, 16-byte aligned)
static char __attribute__((aligned(16))) thread_stack[4096];
static volatile int child_tid = 0;
static volatile int shared_counter = 0;

void child_thread_entry(void) {
    print_str("  [CHILD THREAD] Running in parallel! TID: ");
    print_num(sys_gettid());
    print_str(", TGID: ");
    print_num(sys_getpid());
    print_str("\n");

    shared_counter += 42;
    print_str("  [CHILD THREAD] Incremented shared counter to 42. Terminating thread...\n");
    sys_exit(0);
}

void _start(void) {
    print_str("\n[LINUX THREAD TEST STARTED]\n");
    print_str("  [MAIN] Initial Process PID (TGID): ");
    print_num(sys_getpid());
    print_str(", TID: ");
    print_num(sys_gettid());
    print_str("\n");

    // Point top of stack
    void *stack_top = &thread_stack[4096 - 16];

    // Put child_thread_entry function pointer at top of stack for ret or direct branch
    unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                          CLONE_THREAD | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;

    print_str("  [MAIN] Spawning POSIX thread via sys_clone()...\n");
    long ret = sys_clone(flags, stack_top, 0, (int*)&child_tid, 0);

    if (ret == 0) {
        // We are in child thread!
        child_thread_entry();
    } else if (ret > 0) {
        // We are in parent main thread
        print_str("  [MAIN] Child thread cloned with TID ");
        print_num(ret);
        print_str(". Waiting on futex join...\n");

        // Wait until child thread exits (child_tid will be cleared to 0 by on_thread_exit futex wake)
        while (child_tid != 0) {
            sys_futex((int*)&child_tid, FUTEX_WAIT, child_tid, 0, 0, 0);
        }

        print_str("  [MAIN] Futex join completed! Shared counter = ");
        print_num(shared_counter);
        print_str("\n");

        if (shared_counter == 42) {
            print_str("[+] LINUX MULTI-THREADING & FUTEX VERIFIED SUCCESSFULLY!\n\n");
        } else {
            print_str("[!] Error: shared counter mismatch!\n\n");
        }
        sys_exit(0);
    } else {
        print_str("[!] sys_clone failed with error code: ");
        print_num(ret);
        print_str("\n");
        sys_exit(1);
    }
}
