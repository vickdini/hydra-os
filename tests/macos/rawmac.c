/*
 * rawmac: the smallest macOS/x86_64 program, with no libSystem (Group 11, step 0).
 *
 * It makes raw XNU system calls and checks the macOS conventions the wave 12 kernel work
 * must provide: the call class in rax's top byte (2 = BSD, 1 = Mach trap), the BSD result
 * convention (carry flag + positive errno), and a Mach trap's kern_return_t / port name
 * result. Marked as macOS by being a Mach-O file (magic 0xFEEDFACF).
 *
 * Build (in Group 11's build root, with Darling's cctools ld64 and clang 15):
 *   clang-15 -target x86_64-apple-macos11 -ffreestanding -fno-stack-protector -nostdlib -O1 -c rawmac.c
 *   x86_64-apple-darwin20-ld -static -e _start -arch x86_64 -platform_version macos 11.0 11.0 -o rawmac rawmac.o
 * Expected output (on macOS, or on Hydra after wave 12's kernel part):
 *   rawmac: write ok
 *   rawmac: getpid ok
 *   rawmac: EBADF ok
 *   rawmac: task_self ok
 *   RAWMAC-DONE
 * exit status 0 (or the number of the first failed check).
 */

#define BSD(n)  (0x2000000L | (n))   /* SYSCALL_CLASS_UNIX */
#define MACH(n) (0x1000000L | (n))   /* SYSCALL_CLASS_MACH */
#define SYS_exit    1
#define SYS_write   4
#define SYS_close   6
#define SYS_getpid  20
#define SYS_getppid 39
#define MACH_task_self_trap 28
#define MAC_EBADF   9

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
static void say(const char *s) { sys3(BSD(SYS_write), 1, (long)s, slen(s)); }
static void __attribute__((noreturn)) die(int code)
{
    for (;;) sys3(BSD(SYS_exit), code, 0, 0);
}

void start(void) __asm__("start");
void __attribute__((noreturn)) start(void)
{
    const char msg[] = "rawmac: write ok\n";
    struct res r = sys3(BSD(SYS_write), 1, (long)msg, sizeof msg - 1);
    if (r.carry || r.val != (long)sizeof msg - 1) die(1);

    r = sys3(BSD(SYS_getpid), 0, 0, 0);
    struct res pp = sys3(BSD(SYS_getppid), 0, 0, 0);
    if (r.carry || r.val <= 0 || pp.carry || pp.val == r.val) die(2);
    say("rawmac: getpid ok\n");

    r = sys3(BSD(SYS_close), -1, 0, 0);
    if (!r.carry || r.val != MAC_EBADF) die(3);
    say("rawmac: EBADF ok\n");

    /* A Mach trap: returns a port name (non-zero) in rax, no carry-flag convention */
    r = sys3(MACH(MACH_task_self_trap), 0, 0, 0);
    if (r.val == 0) die(4);
    say("rawmac: task_self ok\n");

    say("RAWMAC-DONE\n");
    die(0);
}
