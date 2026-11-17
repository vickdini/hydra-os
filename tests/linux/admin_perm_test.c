// A Linux process cannot reach the kernel's admin interface (wave 2, group 4).
// The admin interface is native system call 40 (SYS_ADMIN), only for the console shell.
// For a Linux process, 40 is sendfile: the call block below must be taken as sendfile's
// arguments (a bad descriptor), and nothing may be written to the answer buffer.
// Build: gcc -O1 -w -o adminlinux admin_perm_test.c
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct admin_call {
    uint32_t op, flags;
    uint64_t args[4];
    uint64_t in_ptr, in_len, out_ptr, out_cap, err_len;
};

int main(void) {
    unsigned char out[64];
    memset(out, 0xAA, sizeof out);
    struct admin_call c = {0};
    c.op = 0x01; // ADMIN_VERSION
    c.out_ptr = (uint64_t)(uintptr_t)out;
    c.out_cap = sizeof out;
    errno = 0;
    // sendfile(out_fd = the block's address as an int, in_fd = 0, NULL, 1)
    long r = syscall(40, (long)(uintptr_t)&c, 0L, 0L, 1L);
    int e = errno;
    int untouched = 1;
    for (unsigned i = 0; i < sizeof out; i++)
        if (out[i] != 0xAA) untouched = 0;
    // The admin interface would answer 4 (the version's size) and write it to out[]
    int ok = r != 4 && untouched && c.err_len == 0;
    printf("ADMIN-LINUX: syscall 40 from a Linux process = %ld, errno %d (%s), answer buffer untouched: %s: %s\n",
           r, e, strerror(e), untouched ? "yes" : "no", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
