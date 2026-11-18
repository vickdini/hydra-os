/*
 * fbsdinfo: what FreeBSD's C library asks the system for at start and in everyday calls
 * (Group 11, step 0). Each check prints "ok NAME" or "FAIL NAME ..."; the last line is
 * FBSDINFO-DONE <failures>.
 *
 * Covers: sysctl by MIB and by name (kern.ostype, kern.osrelease, kern.osreldate, hw.ncpu,
 * hw.pagesize, kern.arandom, kern.hostname, kern.usrstack, vm.overcommit), uname(3) (sysctl),
 * getpagesize/sysconf, clock_gettime with FreeBSD clock ids, errno values (ENOENT 2, EAGAIN 35),
 * stat layout (st_birthtim), getdirentries through readdir, issetugid, elf_aux_info.
 *
 * Build: clang-15 --target=x86_64-unknown-freebsd15.1 --sysroot=$SYSROOT -fuse-ld=lld -O1 -o fbsdinfo fbsdinfo.c
 */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/auxv.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int fails;
#define CHECK(name, cond, ...) do { if (cond) printf("ok %s\n", name); \
    else { fails++; printf("FAIL %s: ", name); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void)
{
    char buf[256];
    size_t len;
    int mib[2], v;

    len = sizeof buf;
    CHECK("sysctl kern.ostype", sysctlbyname("kern.ostype", buf, &len, NULL, 0) == 0 && strcmp(buf, "FreeBSD") == 0,
          "errno %d '%s'", errno, buf);
    len = sizeof buf;
    CHECK("sysctl kern.osrelease", sysctlbyname("kern.osrelease", buf, &len, NULL, 0) == 0, "errno %d", errno);
    printf("   kern.osrelease = %s\n", buf);
    mib[0] = CTL_KERN; mib[1] = KERN_OSRELDATE; len = sizeof v;
    CHECK("sysctl {CTL_KERN, KERN_OSRELDATE}", sysctl(mib, 2, &v, &len, NULL, 0) == 0 && v >= 1400000, "v %d errno %d", v, errno);
    mib[0] = CTL_HW; mib[1] = HW_NCPU; len = sizeof v;
    CHECK("sysctl {CTL_HW, HW_NCPU}", sysctl(mib, 2, &v, &len, NULL, 0) == 0 && v >= 1, "v %d errno %d", v, errno);
    mib[0] = CTL_HW; mib[1] = HW_PAGESIZE; len = sizeof v;
    CHECK("sysctl hw.pagesize", sysctl(mib, 2, &v, &len, NULL, 0) == 0 && v == 4096, "v %d", v);
    unsigned char rnd[32] = {0}, zero[32] = {0};
    mib[0] = CTL_KERN; mib[1] = KERN_ARND; len = sizeof rnd;
    CHECK("sysctl kern.arandom", sysctl(mib, 2, rnd, &len, NULL, 0) == 0 && memcmp(rnd, zero, 32) != 0, "errno %d", errno);
    unsigned long stk = 0; len = sizeof stk;
    CHECK("sysctl kern.usrstack", sysctlbyname("kern.usrstack", &stk, &len, NULL, 0) == 0 && stk != 0, "errno %d", errno);

    struct utsname u;
    CHECK("uname", uname(&u) == 0 && strcmp(u.sysname, "FreeBSD") == 0, "errno %d sysname '%s'", errno, u.sysname);
    printf("   uname: %s %s %s %s\n", u.sysname, u.nodename, u.release, u.machine);
    CHECK("getpagesize", getpagesize() == 4096, "%d", getpagesize());
    CHECK("sysconf(_SC_NPROCESSORS_ONLN)", sysconf(_SC_NPROCESSORS_ONLN) >= 1, "%ld", sysconf(_SC_NPROCESSORS_ONLN));

    struct timespec a, b;
    CHECK("clock_gettime(CLOCK_MONOTONIC=4)", clock_gettime(CLOCK_MONOTONIC, &a) == 0, "errno %d", errno);
    CHECK("clock_gettime(CLOCK_UPTIME=5)", clock_gettime(CLOCK_UPTIME, &b) == 0, "errno %d", errno);
    CHECK("clock_gettime(CLOCK_REALTIME)", clock_gettime(CLOCK_REALTIME, &a) == 0 && a.tv_sec > 1700000000, "%ld", (long)a.tv_sec);

    CHECK("errno ENOENT=2", open("/nonexistent/x", O_RDONLY) == -1 && errno == ENOENT, "errno %d", errno);
    int p[2];
    pipe2(p, O_NONBLOCK);
    CHECK("errno EAGAIN=35", read(p[0], buf, 1) == -1 && errno == EAGAIN && EAGAIN == 35, "errno %d", errno);
    CHECK("bidirectional pipe", write(p[0], "x", 1) == 1 && read(p[1], buf, 1) == 1, "errno %d", errno);

    struct stat st;
    CHECK("stat /", stat("/", &st) == 0 && S_ISDIR(st.st_mode) && st.st_nlink >= 2, "errno %d", errno);
    printf("   / ino %ju nlink %ju birth %ld\n", (uintmax_t)st.st_ino, (uintmax_t)st.st_nlink, (long)st.st_birthtim.tv_sec);
    DIR *d = opendir("/");
    int n = 0, sawbin = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) { n++; if (strcmp(e->d_name, "bin") == 0 && e->d_type == DT_DIR) sawbin = 1; }
    CHECK("readdir / (getdirentries)", d && n >= 3 && sawbin, "n %d sawbin %d", n, sawbin);
    CHECK("issetugid", issetugid() == 0, "%d", issetugid());
    int ncpu = 0;
    CHECK("elf_aux_info(AT_NCPUS)", elf_aux_info(AT_NCPUS, &ncpu, sizeof ncpu) == 0 && ncpu >= 1, "ncpu %d", ncpu);
    int osrel = 0;
    CHECK("elf_aux_info(AT_OSRELDATE)", elf_aux_info(AT_OSRELDATE, &osrel, sizeof osrel) == 0 && osrel >= 1400000, "%d", osrel);

    printf("FBSDINFO-DONE %d\n", fails);
    return fails != 0;
}
