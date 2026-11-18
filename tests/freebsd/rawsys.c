/*
 * rawsys: the smallest FreeBSD/amd64 program, with no C library (Group 11, step 0).
 *
 * It makes raw FreeBSD system calls and checks the BSD result convention: success clears
 * the carry flag and returns the value in rax; failure sets the carry flag and returns a
 * POSITIVE FreeBSD errno in rax. This is the shape of the wave 5 personality-hook test: a
 * static binary marked FreeBSD (EI_OSABI 9, .note.tag "FreeBSD"), whose calls must reach the
 * FreeBSD table and come back in the BSD convention.
 *
 * Build (in Group 11's build root):
 *   clang-15 --target=x86_64-unknown-freebsd15.1 -static -nostdlib -ffreestanding -fno-stack-protector \
 *       -fuse-ld=lld -O1 -o rawsys rawsys.c
 * Expected output on FreeBSD (and on Hydra once FreeBSD write/getpid/close/exit exist):
 *   rawsys: write ok
 *   rawsys: getpid ok
 *   rawsys: EBADF ok
 *   rawsys: ENOSYS-free ok
 *   RAWSYS-DONE
 * exit status 0 (or the number of the first failed check).
 */

/* FreeBSD system call numbers (sys/kern/syscalls.master) */
#define SYS_exit    1
#define SYS_write   4
#define SYS_close   6
#define SYS_getpid  20
#define SYS_getppid 39
#define FBSD_EBADF  9

/* The ABI note FreeBSD's kernel looks for (the linker adds EI_OSABI 9 for this target, and
 * crt1.o normally provides this note; with -nostdlib we write it ourselves).
 * namesz 8 "FreeBSD\0", descsz 4, type 1 (NT_FREEBSD_ABI_TAG), desc = __FreeBSD_version. */
__attribute__((section(".note.tag"), aligned(4), used))
static const struct {
    unsigned namesz, descsz, type;
    char name[8];
    unsigned desc;
} abi_tag = { 8, 4, 1, "FreeBSD", 1501000 };

struct res { long val; int carry; };

static struct res sys3(long nr, long a, long b, long c)
{
    long rax = nr;
    unsigned char cf;
    __asm__ volatile("syscall; setc %1"
                     : "+a"(rax), "=r"(cf), "+D"(a), "+S"(b), "+d"(c)
                     :
                     : "rcx", "r8", "r9", "r10", "r11", "memory", "cc");
    struct res r = { rax, cf };
    return r;
}

static long slen(const char *s) { long n = 0; while (s[n]) n++; return n; }
static void say(const char *s) { sys3(SYS_write, 1, (long)s, slen(s)); }
static void __attribute__((noreturn)) die(int code)
{
    for (;;) sys3(SYS_exit, code, 0, 0);
}

void _start(void) __attribute__((noreturn));
void _start(void)
{
    const char msg[] = "rawsys: write ok\n";
    struct res r = sys3(SYS_write, 1, (long)msg, sizeof msg - 1);
    if (r.carry || r.val != (long)sizeof msg - 1) die(1);

    r = sys3(SYS_getpid, 0, 0, 0);
    if (r.carry || r.val <= 0) die(2);
    struct res pp = sys3(SYS_getppid, 0, 0, 0);
    if (pp.carry || pp.val < 0 || pp.val == r.val) die(3);
    say("rawsys: getpid ok\n");

    /* close(-1): must fail with the carry flag and a positive EBADF (9), not -9 */
    r = sys3(SYS_close, -1, 0, 0);
    if (!r.carry || r.val != FBSD_EBADF) die(4);
    say("rawsys: EBADF ok\n");

    /* A Linux-numbered call must not be taken as Linux: Linux 39 is getpid, FreeBSD 39 is
     * getppid; checked above (pp != pid). */
    say("rawsys: ENOSYS-free ok\n");
    say("RAWSYS-DONE\n");
    die(0);
}
