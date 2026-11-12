/* The address space Windows programs need under Wine: fixed mappings at the addresses
 * Windows uses, all below 4 GiB but 0x140000000. Each must map, be usable by system calls
 * (the kernel copying to and from it), survive fork (copy-on-write) and exec-free children,
 * and be released by munmap. Runs on Linux too.
 * Build: gcc -O1 -w lowmem_test.c -o lowmem_test.elf */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

struct place { uintptr_t addr; size_t len; const char *what; };

int main(void) {
    static const struct place places[] = {
        {0x00010000, 0x10000, "0x10000: lowest Windows allocation"},
        {0x00400000, 0x100000, "0x400000: 32-bit .exe base"},
        {0x10000000, 0x100000, "0x10000000: 32-bit DLL bases"},
        {0x40000000, 0x200000, "0x40000000: second GiB"},
        {0x7ffe0000, 0x1000, "0x7ffe0000: KUSER_SHARED_DATA"},
        {0x7fff0000, 0x10000, "0x7fff0000: top of the 2 GiB user space"},
        {0x140000000ull, 0x200000, "0x140000000: 64-bit .exe base"},
        {0x180000000ull, 0x200000, "0x180000000: 64-bit DLL bases"},
    };
    int n = sizeof places / sizeof places[0];
    int pipefd[2];
    pipe(pipefd);
    for (int i = 0; i < n; i++) {
        const struct place *p = &places[i];
        char *m = mmap((void *)p->addr, p->len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        char what[128];
        snprintf(what, sizeof what, "map %s", p->what);
        check(m == (char *)p->addr, what);
        if (m != (char *)p->addr) continue;
        /* the program writes, the kernel copies out of it and into it */
        memset(m, 0x5a, p->len);
        m[p->len - 1] = (char)i;
        write(pipefd[1], m + p->len - 16, 16);
        char back[16];
        read(pipefd[0], back, 16);
        snprintf(what, sizeof what, "  kernel reads it (write) %s", p->what);
        check(back[0] == 0x5a && back[15] == (char)i, what);
        int fd = open("/proc/self/stat", O_RDONLY);
        ssize_t r = read(fd, m, 64);
        close(fd);
        snprintf(what, sizeof what, "  kernel writes it (read) %s", p->what);
        check(r > 0 && m[0] >= '0' && m[0] <= '9', what);
    }
    /* KUSER_SHARED_DATA is read-only in Windows: mprotect works there */
    check(mprotect((void *)0x7ffe0000, 0x1000, PROT_READ) == 0, "mprotect read-only at 0x7ffe0000");

    /* fork: the child sees its copy, its writes stay its own */
    char *low = (char *)0x40000000;
    low[0] = 'p';
    pid_t pid = fork();
    if (pid == 0) {
        /* 0x7ffe0000 starts with what /proc/self/stat wrote there */
        char k = ((char *)0x7ffe0000)[0];
        int ok = low[0] == 'p' && k >= '0' && k <= '9';
        low[0] = 'c';
        _exit(ok ? 0 : 1);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "fork child sees the low mappings");
    check(low[0] == 'p', "child's write stayed in the child (copy-on-write)");

    for (int i = 0; i < n; i++) munmap((void *)places[i].addr, places[i].len);
    /* unmapped again: the same fixed mapping succeeds a second time */
    char *again = mmap((void *)0x7ffe0000, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    check(again == (char *)0x7ffe0000, "0x7ffe0000 maps again after munmap");

    /* MAP_32BIT lands below 2 GiB */
    char *m32 = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    check(m32 != MAP_FAILED && (uintptr_t)m32 < 0x80000000u, "MAP_32BIT below 2 GiB");

    printf(fails ? "LOWMEM TEST: %d FAILED\n" : "LOWMEM TEST PASSED\n", fails);
    return fails != 0;
}
