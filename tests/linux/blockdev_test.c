// Linux block devices (/dev/sdX): partitioning, formatting and raw I/O on a second disk,
// and the pool's disk refusing writes. Needs a blank second disk (the suite attaches one);
// without one it only checks the pool disk and passes.
//
// gcc -O1 -w blockdev_test.c -o blockdev.elf
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int fails;
#define CHECK(c, ...) do { if (!(c)) { printf("  FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static int read_file(const char *path, char *buf, int len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = read(fd, buf, len - 1);
    close(fd);
    if (n < 0) n = 0;
    buf[n] = 0;
    return n;
}

static long long sys_num(const char *path) {
    char b[64];
    if (read_file(path, b, sizeof b) <= 0) return -1;
    return atoll(b);
}

// Runs a shell command, returns its output (static buffer) and exit status
static char out[16384];
static int run(const char *cmd) {
    out[0] = 0;
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    int n = fread(out, 1, sizeof out - 1, p);
    out[n < 0 ? 0 : n] = 0;
    int st = pclose(p);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int has_tool(const char *t) {
    char c[128];
    snprintf(c, sizeof c, "command -v %s >/dev/null 2>&1", t);
    return system(c) == 0;
}

// The pool's disk: written over the pool, re-read tables: refused
static void pool_disk(const char *dev) {
    int fd = open(dev, O_RDWR);
    CHECK(fd >= 0, "open %s: %s", dev, strerror(errno));
    if (fd < 0) return;
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && S_ISBLK(st.st_mode), "%s is not a block device", dev);
    uint64_t size = 0;
    CHECK(ioctl(fd, BLKGETSIZE64, &size) == 0 && size > 0, "BLKGETSIZE64 on %s", dev);
    CHECK(ioctl(fd, BLKRRPART) < 0 && errno == EBUSY, "BLKRRPART on the pool disk should be EBUSY (errno %d)", errno);
    // Write back what is there (harmless if it were allowed): must be refused
    char buf[4096];
    off_t at = size / 2 / 4096 * 4096;
    CHECK(pread(fd, buf, sizeof buf, at) == sizeof buf, "read of the pool disk");
    errno = 0;
    CHECK(pwrite(fd, buf, sizeof buf, at) < 0 && errno == EBUSY, "write to the pool should be EBUSY (errno %d)", errno);
    close(fd);
    printf("  pool disk %s: %llu MiB, readable, writes refused\n", dev, (unsigned long long)(size >> 20));
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("blockdev: Linux block devices\n");
    char disk[16] = "", pool[16] = "";
    for (char c = 'a'; c <= 'h'; c++) {
        char p[64], rec[4096];
        snprintf(p, sizeof p, "/sys/block/sd%c/dev", c);
        if (read_file(p, rec, sizeof rec) <= 0) continue;
        int minor = atoi(strchr(rec, ':') + 1);
        snprintf(p, sizeof p, "/run/udev/data/b8:%d", minor);
        read_file(p, rec, sizeof rec);
        if (strstr(rec, "UDISKS_SYSTEM=1")) {
            if (!pool[0]) snprintf(pool, sizeof pool, "/dev/sd%c", c);
        } else if (!disk[0]) {
            snprintf(disk, sizeof disk, "sd%c", c);
        }
    }
    CHECK(pool[0], "no disk marked as the pool's");
    if (pool[0]) pool_disk(pool);
    if (!disk[0]) {
        printf("  no second disk: skipping the partitioning part\n");
        printf(fails ? "blockdev: FAILED (%d)\n" : "blockdev: PASSED\n", fails);
        return fails ? 1 : 0;
    }
    char dev[32], p[128];
    snprintf(dev, sizeof dev, "/dev/%s", disk);
    snprintf(p, sizeof p, "/sys/block/%s/size", disk);
    long long sectors = sys_num(p);
    int fd = open(dev, O_RDWR);
    CHECK(fd >= 0, "open %s: %s", dev, strerror(errno));
    if (fd < 0) return 1;
    uint64_t size = 0;
    int ssz = 0;
    unsigned long secs = 0;
    CHECK(ioctl(fd, BLKGETSIZE64, &size) == 0 && size == (uint64_t)sectors * 512, "BLKGETSIZE64 %llu vs sysfs %lld sectors", (unsigned long long)size, sectors);
    CHECK(ioctl(fd, BLKGETSIZE, &secs) == 0 && secs == size / 512, "BLKGETSIZE");
    CHECK(ioctl(fd, BLKSSZGET, &ssz) == 0 && ssz == 512, "BLKSSZGET %d", ssz);
    printf("  test disk %s: %llu MiB\n", dev, (unsigned long long)(size >> 20));
    // Unaligned I/O near the end of the disk
    char a[3000], b[3000];
    for (int i = 0; i < (int)sizeof a; i++) a[i] = (char)(i * 7 + 3);
    off_t at = size - 9000 + 1;
    CHECK(pwrite(fd, a, sizeof a, at) == sizeof a, "unaligned pwrite: %s", strerror(errno));
    CHECK(pread(fd, b, sizeof b, at) == sizeof b && memcmp(a, b, sizeof a) == 0, "unaligned read back differs");
    CHECK(lseek(fd, 0, SEEK_END) == (off_t)size, "SEEK_END");
    CHECK(fsync(fd) == 0, "fsync: %s", strerror(errno));
    // A blank start (an old table would be kept by sfdisk)
    memset(b, 0, sizeof b);
    for (int i = 0; i < 12; i++) pwrite(fd, b, 2048, i * 2048);
    pwrite(fd, b, 2048, size - 2048 * 20);
    close(fd);

    // Partition with sfdisk: a 64 MiB EFI system partition and a Hydra pool partition
    snprintf(p, sizeof p, "printf 'label: gpt\\nsize=64MiB, type=uefi, name=EFI\\ntype=7685A0B8-DF41-47EB-AF4F-02CE6FB01879, name=Hydra\\n' | sfdisk -q %s 2>&1", dev);
    int rc = run(p);
    CHECK(rc == 0, "sfdisk exited %d: %s", rc, out);
    char s1[64], s2[64];
    snprintf(s1, sizeof s1, "/dev/%s1", disk);
    snprintf(s2, sizeof s2, "/dev/%s2", disk);
    struct stat st;
    CHECK(stat(s1, &st) == 0 && S_ISBLK(st.st_mode), "%s missing after sfdisk", s1);
    CHECK(stat(s2, &st) == 0 && S_ISBLK(st.st_mode), "%s missing after sfdisk", s2);
    snprintf(p, sizeof p, "/sys/block/%s/%s1/start", disk, disk);
    CHECK(sys_num(p) == 2048, "partition 1 start %lld", sys_num(p));
    snprintf(p, sizeof p, "/sys/block/%s/%s1/size", disk, disk);
    CHECK(sys_num(p) == 64 * 2048, "partition 1 size %lld", sys_num(p));
    // The partition device: its size, and raw data through it lands at its offset
    fd = open(s2, O_RDWR);
    CHECK(fd >= 0, "open %s", s2);
    uint64_t psize = 0;
    ioctl(fd, BLKGETSIZE64, &psize);
    snprintf(p, sizeof p, "/sys/block/%s/%s2/size", disk, disk);
    CHECK(psize == (uint64_t)sys_num(p) * 512 && psize > 0, "partition 2 size %llu", (unsigned long long)psize);
    close(fd);

    // dd a MiB of data into partition 2 and read it back through the whole disk
    rc = run("head -c 1048576 /dev/urandom > /tmp/blockdev_data && echo ok");
    snprintf(p, sizeof p, "dd if=/tmp/blockdev_data of=%s bs=64K seek=80 conv=fsync status=none 2>&1", s2);
    rc = run(p);
    CHECK(rc == 0, "dd write: %s", out);
    snprintf(p, sizeof p, "dd if=%s bs=64K skip=80 count=16 status=none 2>/dev/null | cmp - /tmp/blockdev_data 2>&1", s2);
    rc = run(p);
    CHECK(rc == 0, "dd read back differs: %s", out);
    snprintf(p, sizeof p, "dd if=%s bs=512 skip=$((2048 + 64*2048 + 80*128)) count=2048 status=none 2>/dev/null | cmp - /tmp/blockdev_data 2>&1", dev);
    rc = run(p);
    CHECK(rc == 0, "data not at the partition's offset on the disk: %s", out);
    // O_DIRECT
    fd = open(s2, O_RDONLY | O_DIRECT);
    CHECK(fd >= 0, "O_DIRECT open: %s", strerror(errno));
    if (fd >= 0) close(fd);

    // FAT32 on the EFI partition
    if (has_tool("mkfs.vfat")) {
        snprintf(p, sizeof p, "mkfs.vfat -F 32 -n HYDRAESP %s 2>&1", s1);
        rc = run(p);
        CHECK(rc == 0, "mkfs.vfat exited %d: %s", rc, out);
        if (has_tool("blkid")) {
            snprintf(p, sizeof p, "blkid -p %s 2>&1", s1);
            rc = run(p);
            CHECK(strstr(out, "TYPE=\"vfat\"") != NULL, "blkid sees no vfat: %s", out);
        }
        if (has_tool("mcopy")) {
            snprintf(p, sizeof p, "echo hello-esp > /tmp/blockdev_f && mmd -i %s ::/hydra && mcopy -i %s /tmp/blockdev_f ::/hydra/f && mtype -i %s ::/hydra/f 2>&1", s1, s1, s1);
            rc = run(p);
            CHECK(rc == 0 && strstr(out, "hello-esp"), "mtools on the ESP: %s", out);
        } else {
            printf("  (no mtools: skipped)\n");
        }
    } else {
        printf("  (no mkfs.vfat: skipped)\n");
    }
    // lsblk sees the disk, its partitions and the FAT
    snprintf(p, sizeof p, "lsblk -n -o NAME,TYPE,SIZE,PARTTYPE,FSTYPE %s 2>&1", dev);
    rc = run(p);
    printf("%s", out);
    CHECK(rc == 0 && strstr(out, "part") && strstr(out, "disk"), "lsblk: %s", out);
    CHECK(strstr(out, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b") && strstr(out, "7685a0b8-df41-47eb-af4f-02ce6fb01879"), "lsblk part types");
    if (has_tool("mkfs.vfat")) CHECK(strstr(out, "vfat") != NULL, "lsblk shows no vfat");

    // Delete partition 2 with sfdisk: the device goes away
    snprintf(p, sizeof p, "sfdisk -q --delete %s 2 2>&1", dev);
    rc = run(p);
    CHECK(rc == 0, "sfdisk --delete: %s", out);
    CHECK(stat(s2, &st) != 0, "%s still there after deleting it", s2);
    CHECK(stat(s1, &st) == 0, "%s gone after deleting partition 2", s1);
    // sgdisk, if installed: the Hydra layout again
    if (has_tool("sgdisk")) {
        snprintf(p, sizeof p, "sgdisk -Z %s >/dev/null 2>&1; sgdisk -n 1:1MiB:+64MiB -t 1:EF00 -c 1:EFI -n 2:0:0 -t 2:7685A0B8-DF41-47EB-AF4F-02CE6FB01879 -c 2:Hydra %s 2>&1", dev, dev);
        rc = run(p);
        CHECK(rc == 0, "sgdisk exited %d: %s", rc, out);
        CHECK(stat(s2, &st) == 0, "%s missing after sgdisk", s2);
    } else {
        printf("  (no sgdisk: skipped)\n");
    }
    printf(fails ? "blockdev: FAILED (%d)\n" : "blockdev: PASSED\n", fails);
    return fails ? 1 : 0;
}
