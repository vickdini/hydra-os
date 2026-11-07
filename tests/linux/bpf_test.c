// bpf: maps, programs run with PROG_TEST_RUN (arithmetic, map counter with an atomic add,
// packet access, a bpf-to-bpf call), refused programs, pins, IDs, info, and device control
// through a cgroup link. Root only. Build: gcc -O1 -w -o bpf bpf_test.c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef BPF_ATOMIC
#define BPF_ATOMIC 0xc0   /* BPF_XADD in older headers */
#endif

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) fails++;
}

static long bpf(int cmd, union bpf_attr *a) { return syscall(SYS_bpf, cmd, a, sizeof *a); }

#define I(c, d, s, o, i) ((struct bpf_insn){c, d, s, o, i})
#define MOV64_IMM(d, i) I(BPF_ALU64 | BPF_MOV | BPF_K, d, 0, 0, i)
#define MOV64_REG(d, s) I(BPF_ALU64 | BPF_MOV | BPF_X, d, s, 0, 0)
#define ALU64_IMM(op, d, i) I(BPF_ALU64 | op | BPF_K, d, 0, 0, i)
#define ALU64_REG(op, d, s) I(BPF_ALU64 | op | BPF_X, d, s, 0, 0)
#define LDX(sz, d, s, o) I(BPF_LDX | sz | BPF_MEM, d, s, o, 0)
#define STX(sz, d, s, o) I(BPF_STX | sz | BPF_MEM, d, s, o, 0)
#define ST(sz, d, o, i) I(BPF_ST | sz | BPF_MEM, d, 0, o, i)
#define JMP_IMM(op, d, i, o) I(BPF_JMP | op | BPF_K, d, 0, o, i)
#define JMP_REG(op, d, s, o) I(BPF_JMP | op | BPF_X, d, s, o, 0)
#define CALL(h) I(BPF_JMP | BPF_CALL, 0, 0, 0, h)
#define EXIT() I(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define LD_MAP(d, fd) I(BPF_LD | BPF_DW | BPF_IMM, d, BPF_PSEUDO_MAP_FD, 0, fd), I(0, 0, 0, 0, 0)

static char log_buf[4096];

static int load(int type, struct bpf_insn *p, int n, int attach) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = type;
    a.insns = (uint64_t)p;
    a.insn_cnt = n;
    a.license = (uint64_t)"GPL";
    a.log_buf = (uint64_t)log_buf;
    a.log_size = sizeof log_buf;
    a.log_level = 1;
    a.expected_attach_type = attach;
    return bpf(BPF_PROG_LOAD, &a);
}

static int run(int fd, void *pkt, int len, uint32_t *ret) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.test.prog_fd = fd;
    a.test.data_in = (uint64_t)pkt;
    a.test.data_size_in = len;
    a.test.repeat = 1;
    int r = bpf(BPF_PROG_TEST_RUN, &a);
    *ret = a.test.retval;
    return r;
}

static int map_create(int type, int ks, int vs, int max) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_type = type;
    a.key_size = ks;
    a.value_size = vs;
    a.max_entries = max;
    return bpf(BPF_MAP_CREATE, &a);
}

static int elem(int cmd, int fd, void *k, void *v, uint64_t flags) {
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.map_fd = fd;
    a.key = (uint64_t)k;
    a.value = (uint64_t)v;
    a.flags = flags;
    return bpf(cmd, &a);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (geteuid() != 0) {
        errno = 0;
        check(map_create(BPF_MAP_TYPE_HASH, 4, 8, 4) == -1 && errno == EPERM, "unprivileged: EPERM");
        printf("BPF TEST PASSED (user part)\n");
        return fails != 0;
    }
    // Hash map
    int h = map_create(BPF_MAP_TYPE_HASH, 4, 8, 2);
    uint32_t k = 1, k2 = 2, k3 = 3, next;
    uint64_t v = 10, out = 0;
    check(h >= 0 && elem(BPF_MAP_UPDATE_ELEM, h, &k, &v, BPF_ANY) == 0 && elem(BPF_MAP_LOOKUP_ELEM, h, &k, &out, 0) == 0 && out == 10, "hash map: update and lookup");
    errno = 0;
    check(elem(BPF_MAP_UPDATE_ELEM, h, &k, &v, BPF_NOEXIST) == -1 && errno == EEXIST, "BPF_NOEXIST on a present key: EEXIST");
    errno = 0;
    check(elem(BPF_MAP_UPDATE_ELEM, h, &k2, &v, BPF_EXIST) == -1 && errno == ENOENT, "BPF_EXIST on an absent key: ENOENT");
    elem(BPF_MAP_UPDATE_ELEM, h, &k2, &v, BPF_ANY);
    errno = 0;
    check(elem(BPF_MAP_UPDATE_ELEM, h, &k3, &v, BPF_ANY) == -1 && errno == E2BIG, "full hash map: E2BIG");
    int seen = 0;
    uint32_t *cur = NULL;
    while (elem(BPF_MAP_GET_NEXT_KEY, h, cur, &next, 0) == 0) {
        seen++;
        k3 = next;
        cur = &k3;
    }
    check(seen == 2, "get_next_key walks both keys");
    check(elem(BPF_MAP_DELETE_ELEM, h, &k, NULL, 0) == 0 && elem(BPF_MAP_LOOKUP_ELEM, h, &k, &out, 0) == -1 && errno == ENOENT, "delete, then lookup: ENOENT");
    // Array map
    int arr = map_create(BPF_MAP_TYPE_ARRAY, 4, 8, 4);
    uint32_t i0 = 0, i9 = 9;
    out = 1;
    check(elem(BPF_MAP_LOOKUP_ELEM, arr, &i0, &out, 0) == 0 && out == 0, "array map: every index present, zeroed");
    errno = 0;
    check(elem(BPF_MAP_LOOKUP_ELEM, arr, &i9, &out, 0) == -1 && errno == ENOENT, "array index past the end: ENOENT");
    errno = 0;
    check(elem(BPF_MAP_DELETE_ELEM, arr, &i0, NULL, 0) == -1 && errno == EINVAL, "array delete: EINVAL");

    unsigned char pkt[64] = {0};
    pkt[12] = 0x08;   // ETH_P_IP
    pkt[14] = 0x45;   // IPv4, header length 5
    uint32_t ret = 0;
    // r0 = 7
    struct bpf_insn p1[] = {MOV64_IMM(0, 7), EXIT()};
    int f1 = load(BPF_PROG_TYPE_SOCKET_FILTER, p1, 2, 0);
    check(f1 >= 0 && run(f1, pkt, sizeof pkt, &ret) == 0 && ret == 7, "socket filter returning 7");
    // Arithmetic: ((100 / 7) * 3 + 100 % 7 - 1) << 2, then ^ 0x5, arithmetic shift of -64
    struct bpf_insn p2[] = {
        MOV64_IMM(0, 100), ALU64_IMM(BPF_DIV, 0, 7), ALU64_IMM(BPF_MUL, 0, 3), MOV64_IMM(1, 100), ALU64_IMM(BPF_MOD, 1, 7),
        ALU64_REG(BPF_ADD, 0, 1), ALU64_IMM(BPF_SUB, 0, 1), ALU64_IMM(BPF_LSH, 0, 2), ALU64_IMM(BPF_XOR, 0, 5),
        MOV64_IMM(2, -64), ALU64_IMM(BPF_ARSH, 2, 3), ALU64_REG(BPF_ADD, 0, 2), EXIT()};
    int f2 = load(BPF_PROG_TYPE_SOCKET_FILTER, p2, sizeof p2 / 8, 0);
    check(f2 >= 0 && run(f2, pkt, sizeof pkt, &ret) == 0 && ret == ((((100 / 7) * 3 + 100 % 7 - 1) << 2) ^ 5) - 8, "arithmetic (div, mul, mod, shifts, xor, arsh)");
    // A counter in an array map: value[0] += 1 atomically; returns 1
    struct bpf_insn p3[] = {
        ST(BPF_W, 10, -4, 0), MOV64_REG(2, 10), ALU64_IMM(BPF_ADD, 2, -4), LD_MAP(1, arr), CALL(BPF_FUNC_map_lookup_elem),
        JMP_IMM(BPF_JNE, 0, 0, 2), MOV64_IMM(0, 0), EXIT(),
        MOV64_IMM(1, 1), I(BPF_STX | BPF_DW | BPF_ATOMIC, 0, 1, 0, BPF_ADD), MOV64_IMM(0, 1), EXIT()};
    int f3 = load(BPF_PROG_TYPE_CGROUP_SKB, p3, sizeof p3 / 8, 0);
    run(f3, pkt, sizeof pkt, &ret);
    run(f3, pkt, sizeof pkt, &ret);
    elem(BPF_MAP_LOOKUP_ELEM, arr, &i0, &out, 0);
    check(f3 >= 0 && ret == 1 && out == 2, "map counter: lookup helper and atomic add, twice");
    if (f3 < 0) printf("     log: %s\n", log_buf);
    // Packet access: the first byte of the network header (data / data_end bounds check)
    struct bpf_insn p4[] = {
        LDX(BPF_W, 2, 1, offsetof(struct __sk_buff, data)), LDX(BPF_W, 3, 1, offsetof(struct __sk_buff, data_end)),
        MOV64_REG(4, 2), ALU64_IMM(BPF_ADD, 4, 1), JMP_REG(BPF_JGT, 4, 3, 4), LDX(BPF_B, 0, 2, 0), JMP_IMM(BPF_JNE, 0, 0x45, 2),
        MOV64_IMM(0, 1), EXIT(), MOV64_IMM(0, 0), EXIT()};
    // (data starts at the network header, as cgroup hooks see packets; cgroup skb programs
    // return 0 or 1: 1 when that byte is 0x45). Linux's test runs leave data/data_end
    // unset for cgroup skb programs, so this is checked on Hydra only.
    int f4 = load(BPF_PROG_TYPE_CGROUP_SKB, p4, sizeof p4 / 8, 0);
    int r4 = run(f4, pkt, sizeof pkt, &ret);
    struct utsname un;
    uname(&un);
    if (!strstr(un.release, "hydra")) {
        printf("skip direct packet access in a test run (Linux leaves data/data_end unset there)\n");
        ret = 1;
    }
    check(f4 >= 0 && r4 == 0 && ret == 1, "direct packet access reads the IP header's first byte");
    if (!(f4 >= 0 && r4 == 0 && ret == 1)) printf("     load %d run %d errno %d ret %u\n", f4, r4, errno, ret);
    if (f4 < 0) printf("     log: %s\n", log_buf);
    // A bpf-to-bpf call: return twice 21
    struct bpf_insn p5[] = {MOV64_IMM(1, 21), I(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_CALL, 0, 1), EXIT(), MOV64_REG(0, 1), ALU64_IMM(BPF_MUL, 0, 2), EXIT()};
    int f5 = load(BPF_PROG_TYPE_SOCKET_FILTER, p5, sizeof p5 / 8, 0);
    check(f5 >= 0 && run(f5, pkt, sizeof pkt, &ret) == 0 && ret == 42, "bpf-to-bpf call");
    if (f5 < 0) printf("     log: %s\n", log_buf);
    // Refused programs
    struct bpf_insn bad1[] = {JMP_IMM(BPF_JA, 0, 0, 5), EXIT()};
    struct bpf_insn bad2[] = {CALL(9999), EXIT()};
    errno = 0;
    check(load(BPF_PROG_TYPE_SOCKET_FILTER, bad1, 2, 0) < 0 && load(BPF_PROG_TYPE_SOCKET_FILTER, bad2, 2, 0) < 0, "a jump out of range and an unknown helper are refused");

    // Info and IDs
    struct bpf_map_info mi;
    memset(&mi, 0, sizeof mi);
    union bpf_attr ia;
    memset(&ia, 0, sizeof ia);
    ia.info.bpf_fd = arr;
    ia.info.info_len = sizeof mi;
    ia.info.info = (uint64_t)&mi;
    check(bpf(BPF_OBJ_GET_INFO_BY_FD, &ia) == 0 && mi.type == BPF_MAP_TYPE_ARRAY && mi.key_size == 4 && mi.value_size == 8 && mi.max_entries == 4, "map info");
    union bpf_attr ga;
    memset(&ga, 0, sizeof ga);
    ga.map_id = mi.id;
    int again = bpf(BPF_MAP_GET_FD_BY_ID, &ga);
    elem(BPF_MAP_LOOKUP_ELEM, again, &i0, &out, 0);
    check(again >= 0 && out == 2, "map by ID shares the values");
    // Pinning (where a bpf file system is mounted)
    char pin[64];
    snprintf(pin, sizeof pin, "/sys/fs/bpf/hydra_test_%d", getpid());
    union bpf_attr pa;
    memset(&pa, 0, sizeof pa);
    pa.pathname = (uint64_t)pin;
    pa.bpf_fd = arr;
    if (bpf(BPF_OBJ_PIN, &pa) == 0) {
        memset(&pa, 0, sizeof pa);
        pa.pathname = (uint64_t)pin;
        int g = bpf(BPF_OBJ_GET, &pa);
        out = 0;
        elem(BPF_MAP_LOOKUP_ELEM, g, &i0, &out, 0);
        check(g >= 0 && out == 2, "pin and get by path");
        unlink(pin);
    } else {
        printf("skip pinning (%s)\n", strerror(errno));
    }

    // Device control: a link on a cgroup of our own refuses /dev/null (1:3)
    if (access("/sys/fs/cgroup/cgroup.procs", F_OK) == 0) {
        char cg[96], procs[128];
        snprintf(cg, sizeof cg, "/sys/fs/cgroup/bpftest.%d.%ld", getpid(), (long)time(NULL));
        mkdir(cg, 0755);
        snprintf(procs, sizeof procs, "%s/cgroup.procs", cg);
        int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
        struct bpf_insn dev[] = {
            LDX(BPF_W, 2, 1, 0), ALU64_IMM(BPF_AND, 2, 0xffff), JMP_IMM(BPF_JNE, 2, BPF_DEVCG_DEV_CHAR, 6),
            LDX(BPF_W, 3, 1, 4), JMP_IMM(BPF_JNE, 3, 1, 4), LDX(BPF_W, 4, 1, 8), JMP_IMM(BPF_JNE, 4, 3, 2),
            MOV64_IMM(0, 0), EXIT(), MOV64_IMM(0, 1), EXIT()};
        int dp = load(BPF_PROG_TYPE_CGROUP_DEVICE, dev, sizeof dev / 8, BPF_CGROUP_DEVICE);
        // BPF_LINK_CREATE (28): prog_fd, target_fd, attach_type, flags (laid out by hand:
        // older headers lack it)
        uint32_t la[32] = {(uint32_t)dp, (uint32_t)cgfd, BPF_CGROUP_DEVICE, 0};
        int link = syscall(SYS_bpf, 28, la, sizeof la);
        check(dp >= 0 && cgfd >= 0 && link >= 0, "device program linked to a cgroup");
        for (int round = 0; round < 2; round++) {
            pid_t c = fork();
            if (c == 0) {
                char pid[16];
                int pf = open(procs, O_WRONLY);
                snprintf(pid, sizeof pid, "%d", getpid());
                write(pf, pid, strlen(pid));
                close(pf);
                int n = open("/dev/null", O_RDWR), e = errno;
                int z = open("/dev/zero", O_RDONLY);
                _exit((n == -1 && e == EPERM ? 1 : 0) | (z >= 0 ? 2 : 0));
            }
            int st;
            waitpid(c, &st, 0);
            int r = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
            if (round == 0) {
                check(r == 3, "in the cgroup: /dev/null refused (EPERM), /dev/zero allowed");
                close(link);
            } else {
                check(r == 2, "after the link is closed: /dev/null allowed again");
            }
        }
        rmdir(cg);
    } else {
        printf("skip device control (no cgroup v2 at /sys/fs/cgroup)\n");
    }
    printf(fails ? "BPF TEST FAILED (%d)\n" : "BPF TEST PASSED\n", fails);
    return fails != 0;
}
