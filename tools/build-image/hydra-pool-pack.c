/*
 * hydra-pool-pack: copies a Hydra pool image into a new, compact pool image.
 *
 *   hydra-pool-pack [--size BYTES | --headroom BYTES] [--keep-guid] [--drop-object N]... IN.raw OUT.raw
 *
 * Only the blocks the newest uberblock can reach are copied (the dnode array, every live
 * object's indirect and data blocks), one after another from the start of the data area.
 * Everything else is left out: blocks of deleted files (their old contents would otherwise
 * stay readable in the image's free space), older uberblocks and snapshots' extra blocks.
 * Every block read is checked against its checksum; block pointers are rewritten to the new
 * places and the checksums of the blocks holding them computed again.
 *
 * The new pool is BYTES long (--size), or as long as its data plus --headroom (default
 * 1 GiB), rounded up to a MiB. It gets a new pool GUID unless --keep-guid.
 * --drop-object N (repeatable) leaves object N out, freed, if it has damaged blocks: for an
 * object no directory names any more (an orphan; otherwise a damaged pool is refused).
 * The on-disk format is the one of src/fs/zfs/types.rs (label "HYDRAZF2", version 2).
 *
 * Build: gcc -O2 -Wall -o hydra-pool-pack hydra-pool-pack.c
 */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLOCK 4096u
#define UB_RING 32u
#define BP_PER_BLOCK 64u
#define DN_TOP_PTRS 3u
#define DNODE_SIZE 512u
#define LABEL_MAGIC 0x32465a4152445948ull /* "HYDRAZF2" little-endian */
#define UB_MAGIC 0xbab10cull
#define POOL_VERSION 2u

typedef struct { uint64_t a, b, c, d; } fletcher4;

typedef struct {
    uint64_t block, birth_txg;
    fletcher4 checksum;
    uint32_t lsize;
    uint8_t level, pad[3];
    uint64_t reserved;
} blkptr;

typedef struct {
    uint32_t mode, nlink, uid, gid;
    uint64_t size;
    int64_t atime, mtime, ctime;
    uint32_t atime_ns, mtime_ns, ctime_ns;
    uint8_t nlevels, flags, obj_type, pad;
    uint64_t parent, generation, rdev, next_free, birth_txg;
    blkptr bp[DN_TOP_PTRS];
    uint8_t bonus[216];
} dnode;

typedef struct {
    uint64_t magic, version, pool_guid, total_blocks, bitmap_start, bitmap_blocks, ub_start, ub_count, data_start;
    uint8_t pool_name[32];
    fletcher4 checksum;
} label_t;

typedef struct {
    uint64_t magic, version, txg, timestamp;
    dnode meta;
    uint64_t next_obj, free_obj_head, root_obj, datasets_obj, allocated_blocks, snapshot_txg;
    fletcher4 checksum;
} uberblock;

_Static_assert(sizeof(blkptr) == 64, "blkptr");
_Static_assert(sizeof(dnode) == DNODE_SIZE, "dnode");
_Static_assert(offsetof(dnode, bp) == 104, "dnode.bp");
_Static_assert(sizeof(label_t) == 136, "label");
_Static_assert(offsetof(uberblock, next_obj) == 544, "ub.next_obj");
_Static_assert(sizeof(uberblock) == 624, "uberblock");

static fletcher4 fl4(const void *data, size_t len) {
    const uint8_t *p = data;
    fletcher4 f = {0, 0, 0, 0};
    size_t i;
    for (i = 0; i + 4 <= len; i += 4) {
        uint32_t w;
        memcpy(&w, p + i, 4);
        f.a += w; f.b += f.a; f.c += f.b; f.d += f.c;
    }
    if (i < len) {
        uint32_t w = 0;
        memcpy(&w, p + i, len - i);
        f.a += w; f.b += f.a; f.c += f.b; f.d += f.c;
    }
    return f;
}

static int fl_eq(fletcher4 x, fletcher4 y) { return x.a == y.a && x.b == y.b && x.c == y.c && x.d == y.d; }

static int in_fd = -1, out_fd = -1;
static uint64_t in_blocks;
static uint32_t *remap;        /* old block -> new block (0: not copied yet) */
static uint64_t next_new;      /* next free block of the new pool (when writing) */
static uint64_t counted;       /* blocks reached (counting pass) */
static int writing;            /* 0: counting pass, 1: copying pass */
static uint64_t bad;           /* checksum or range errors */
static uint64_t shared;        /* blocks reached twice */

static void die(const char *msg) {
    fprintf(stderr, "hydra-pool-pack: %s%s%s\n", msg, errno ? ": " : "", errno ? strerror(errno) : "");
    exit(1);
}

static void rd(uint64_t block, void *buf) {
    if (pread(in_fd, buf, BLOCK, (off_t)(block * BLOCK)) != BLOCK) die("read failed");
}

static void wr(uint64_t block, const void *buf) {
    if (pwrite(out_fd, buf, BLOCK, (off_t)(block * BLOCK)) != BLOCK) die("write failed");
}

/* Reads the block `bp` points to into buf, checking it. Returns 0 on failure. */
static uint64_t cur_obj, cur_blkid;
static uint64_t drop[16];      /* --drop-object: objects left out (orphans no directory names) */
static int ndrop;
static uint64_t free_head;     /* head of the free object list of the new uberblock */
static int read_bp(const blkptr *bp, uint8_t *buf) {
    if (bp->block >= in_blocks || bp->lsize == 0 || bp->lsize > BLOCK) {
        fprintf(stderr, "bad block pointer: block %" PRIu64 " lsize %u\n", bp->block, bp->lsize);
        bad++;
        return 0;
    }
    rd(bp->block, buf);
    if (!fl_eq(fl4(buf, bp->lsize), bp->checksum)) {
        fprintf(stderr, "checksum mismatch at block %" PRIu64 " (level %u) of object %" PRIu64 " (block %" PRIu64 " of it)\n", bp->block, bp->level, cur_obj, cur_blkid);
        bad++;
        return 0;
    }
    return 1;
}

static void relocate(blkptr *bp, int level, int is_meta, uint64_t blkid);

static uint64_t span(int level) { return 1ull << (6 * level); }

/* The top pointers of a dnode (object tree of nlevels levels). */
static void relocate_dnode(dnode *dn, int is_meta) {
    int top = (dn->nlevels ? dn->nlevels : 1) - 1;
    for (unsigned i = 0; i < DN_TOP_PTRS; i++) relocate(&dn->bp[i], top, is_meta, i * span(top));
}

/* Copies the subtree of bp (expected level `level`) and points bp at the copy. */
static void relocate(blkptr *bp, int level, int is_meta, uint64_t blkid) {
    if (bp->block == 0) return;
    if (bp->level != level) {
        fprintf(stderr, "block %" PRIu64 ": level %u, expected %d\n", bp->block, bp->level, level);
        bad++;
    }
    if (bp->block < in_blocks && remap[bp->block]) {
        shared++;
        if (writing) bp->block = remap[bp->block];
        return;
    }
    uint8_t buf[BLOCK];
    cur_blkid = blkid;
    int ok = read_bp(bp, buf);
    if (!ok) memset(buf, 0, BLOCK);
    int changes = 0;
    if (ok && level > 0) {
        blkptr *e = (blkptr *)buf;
        for (unsigned i = 0; i < BP_PER_BLOCK; i++) relocate(&e[i], level - 1, is_meta, blkid + i * span(level - 1));
        changes = 1;
    } else if (ok && is_meta) {
        /* A block of the dnode array: the trees of the objects it holds */
        dnode *d = (dnode *)buf;
        for (unsigned i = 0; i < BLOCK / DNODE_SIZE; i++)
            if (d[i].obj_type != 0 || d[i].bp[0].block || d[i].bp[1].block || d[i].bp[2].block) {
                cur_obj = blkid * (BLOCK / DNODE_SIZE) + i;
                int dropped = 0;
                for (int k = 0; k < ndrop; k++) dropped |= drop[k] == cur_obj;
                if (dropped && !writing) {
                    /* Only an object that really is damaged is left out */
                    uint64_t before = bad;
                    relocate_dnode(&d[i], 0);
                    if (bad == before) {
                        fprintf(stderr, "object %" PRIu64 " (--drop-object) is not damaged: not leaving it out\n", cur_obj);
                        exit(1);
                    }
                    bad = before;
                    continue;
                }
                if (dropped) {
                    /* Freed as the kernel frees an object: an empty dnode on the free list */
                    uint64_t gen = d[i].generation;
                    memset(&d[i], 0, sizeof d[i]);
                    d[i].nlevels = 1;
                    d[i].generation = gen;
                    d[i].next_free = free_head;
                    if (writing) {
                        free_head = cur_obj;
                        fprintf(stderr, "object %" PRIu64 " left out (--drop-object)\n", cur_obj);
                    }
                    continue;
                }
                uint64_t before = bad;
                relocate_dnode(&d[i], 0);
                if (bad != before)
                    fprintf(stderr, "  object %" PRIu64 ": mode %o, %" PRIu64 " bytes, %u links, uid %u, parent %" PRIu64 ", mtime %" PRId64 "\n",
                            cur_obj, d[i].mode, d[i].size, d[i].nlink, d[i].uid, d[i].parent, d[i].mtime);
            }
        changes = 1;
    }
    if (!writing) {
        remap[bp->block] = 1; /* reached (the real number comes in the copying pass) */
        counted++;
        return;
    }
    uint64_t nb = next_new++;
    remap[bp->block] = (uint32_t)nb;
    if (changes) bp->checksum = fl4(buf, bp->lsize);
    wr(nb, buf);
    bp->block = nb;
}

static uint64_t parse_size(const char *s) {
    char *end;
    double v = strtod(s, &end);
    uint64_t m = 1;
    if (*end == 'K' || *end == 'k') m = 1ull << 10;
    else if (*end == 'M' || *end == 'm') m = 1ull << 20;
    else if (*end == 'G' || *end == 'g') m = 1ull << 30;
    return (uint64_t)(v * (double)m);
}

int main(int argc, char **argv) {
    uint64_t size = 0, headroom = 1ull << 30;
    int keep_guid = 0, i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "--size") && i + 1 < argc) size = parse_size(argv[++i]);
        else if (!strcmp(argv[i], "--headroom") && i + 1 < argc) headroom = parse_size(argv[++i]);
        else if (!strcmp(argv[i], "--keep-guid")) keep_guid = 1;
        else if (!strcmp(argv[i], "--drop-object") && i + 1 < argc && ndrop < 16) drop[ndrop++] = strtoull(argv[++i], 0, 10);
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 2; }
    }
    if (argc - i != 2) {
        fprintf(stderr, "usage: hydra-pool-pack [--size BYTES | --headroom BYTES] [--keep-guid] [--drop-object N]... IN.raw OUT.raw\n");
        return 2;
    }
    in_fd = open(argv[i], O_RDONLY);
    if (in_fd < 0) die("cannot open the input");
    struct stat st;
    fstat(in_fd, &st);
    in_blocks = (uint64_t)st.st_size / BLOCK;

    uint8_t buf[BLOCK];
    rd(0, buf);
    label_t lab;
    memcpy(&lab, buf, sizeof lab);
    if (lab.magic != LABEL_MAGIC || lab.version != POOL_VERSION || !fl_eq(fl4(&lab, offsetof(label_t, checksum)), lab.checksum))
        die("the input is not a Hydra pool (label)");
    if (lab.total_blocks > in_blocks) die("the input is shorter than its pool");
    in_blocks = lab.total_blocks;

    uberblock ub;
    int found = 0;
    for (uint64_t s = 0; s < lab.ub_count; s++) {
        uberblock u;
        rd(lab.ub_start + s, buf);
        memcpy(&u, buf, sizeof u);
        if (u.magic == UB_MAGIC && u.version == POOL_VERSION && fl_eq(fl4(&u, offsetof(uberblock, checksum)), u.checksum))
            if (!found || u.txg > ub.txg) { ub = u; found = 1; }
    }
    if (!found) die("no valid uberblock");
    fprintf(stderr, "input: pool '%.32s', %" PRIu64 " blocks (%.2f GiB), txg %" PRIu64 ", %" PRIu64 " objects, %" PRIu64
                    " blocks in use, snapshot txg %" PRIu64 "\n",
            (char *)lab.pool_name, lab.total_blocks, lab.total_blocks * (double)BLOCK / (1 << 30), ub.txg, ub.next_obj,
            ub.allocated_blocks, ub.snapshot_txg);

    remap = calloc(in_blocks, sizeof *remap);
    if (!remap) die("out of memory");
    if (in_blocks >= (1ull << 32)) die("pool too large for this tool");

    /* Pass 1: what is reachable, and every checksum */
    dnode meta = ub.meta;
    writing = 0;
    relocate_dnode(&meta, 1);
    if (bad) { fprintf(stderr, "%" PRIu64 " damaged blocks: not packing a damaged pool\n", bad); return 1; }
    fprintf(stderr, "reachable: %" PRIu64 " blocks (%.2f GiB)%s\n", counted, counted * (double)BLOCK / (1 << 30),
            shared ? " (some reached twice)" : "");

    /* The new geometry */
    uint64_t total;
    if (size) total = size / BLOCK;
    else {
        uint64_t need = 1 + UB_RING + (counted + headroom / BLOCK) / (BLOCK * 8) + 1 + counted + headroom / BLOCK;
        total = (need + 255) / 256 * 256; /* a whole MiB */
    }
    label_t nl = lab;
    nl.total_blocks = total;
    nl.ub_start = 1;
    nl.ub_count = UB_RING;
    nl.bitmap_start = 1 + UB_RING;
    nl.bitmap_blocks = (total + BLOCK * 8 - 1) / (BLOCK * 8);
    nl.data_start = 1 + UB_RING + nl.bitmap_blocks;
    if (nl.data_start + counted > total) die("--size is smaller than the data");
    if (!keep_guid) {
        int r = open("/dev/urandom", O_RDONLY);
        if (r < 0 || read(r, &nl.pool_guid, 8) != 8) die("no random GUID");
        close(r);
    }
    nl.checksum = fl4(&nl, offsetof(label_t, checksum));

    /* Pass 2: copy */
    out_fd = open(argv[i + 1], O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) die("cannot create the output");
    if (ftruncate(out_fd, (off_t)(total * BLOCK))) die("cannot size the output");
    memset(remap, 0, in_blocks * sizeof *remap);
    writing = 1;
    next_new = nl.data_start;
    shared = 0;
    meta = ub.meta;
    cur_obj = 0;
    free_head = ub.free_obj_head;
    relocate_dnode(&meta, 1);
    if (bad) die("the input changed while packing");
    uint64_t used = next_new;

    /* Allocation bitmap: blocks [0, used) */
    for (uint64_t b = 0; b < nl.bitmap_blocks; b++) {
        uint64_t words[BLOCK / 8];
        for (unsigned w = 0; w < BLOCK / 8; w++) {
            uint64_t first = (b * (BLOCK / 8) + w) * 64;
            if (first + 64 <= used) words[w] = ~0ull;
            else if (first >= used) words[w] = 0;
            else words[w] = (1ull << (used - first)) - 1;
        }
        wr(nl.bitmap_start + b, words);
    }
    /* Uberblock ring: one uberblock */
    memset(buf, 0, BLOCK);
    for (uint64_t s = 0; s < UB_RING; s++) wr(nl.ub_start + s, buf);
    ub.meta = meta;
    ub.allocated_blocks = used;
    ub.snapshot_txg = 0;
    ub.free_obj_head = free_head;
    ub.checksum = fl4(&ub, offsetof(uberblock, checksum));
    memcpy(buf, &ub, sizeof ub);
    wr(nl.ub_start + ub.txg % UB_RING, buf);
    /* Label last */
    memset(buf, 0, BLOCK);
    memcpy(buf, &nl, sizeof nl);
    wr(0, buf);
    if (fsync(out_fd)) die("fsync");
    close(out_fd);
    printf("pool_bytes=%" PRIu64 "\nused_bytes=%" PRIu64 "\ndata_blocks=%" PRIu64 "\npool_guid=%016" PRIx64 "\ntxg=%" PRIu64 "\n",
           total * BLOCK, used * BLOCK, counted, nl.pool_guid, ub.txg);
    return 0;
}
