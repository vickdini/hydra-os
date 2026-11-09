// Hydra's vDSO: clock_gettime, gettimeofday, time and clock_getres without entering the
// kernel, as on Linux. The kernel keeps the clock's anchor in the [vvar] page mapped just
// below this image; the time is computed exactly as the kernel's pit::now_ns does (the
// anchor plus the time stamp counter's progress since, in 32.32 fixed point), so both
// always agree. Other clocks (CPU time) and errors go to the system call.
//
// Build: see build.sh (a shared object with no relocations, linked at 0).

typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;

struct timespec_ {
    i64 tv_sec;
    i64 tv_nsec;
};
struct timeval_ {
    i64 tv_sec;
    i64 tv_usec;
};

// The [vvar] page (layout shared with the kernel's arch::vdso)
struct vvar {
    volatile u64 seq;       // odd while the kernel updates the page
    volatile u64 base_ns;   // nanoseconds since boot at the anchor
    volatile u64 base_frac; // and their 32-bit fraction
    volatile u64 base_tsc;  // time stamp counter at the anchor
    volatile u64 mult;      // nanoseconds per cycle, 32.32 fixed point (0: not measured yet)
    volatile i64 wall_ns;   // nanoseconds of the wall clock at boot (plus adjustments)
};

extern const char __ehdr_start[] __attribute__((visibility("hidden")));

static inline const struct vvar *vvar(void) {
    return (const struct vvar *)(__ehdr_start - 4096);
}

static inline u64 rdtsc(void) {
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((u64)hi << 32) | lo;
}

static inline long sys2(long nr, long a, long b) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b) : "rcx", "r11", "memory");
    return r;
}

// Nanoseconds since boot and the wall clock's base, read consistently
static void now(u64 *mono, i64 *wall) {
    const struct vvar *v = vvar();
    for (;;) {
        u64 s = v->seq;
        if (s & 1) {
            __asm__ volatile("pause");
            continue;
        }
        __asm__ volatile("" ::: "memory");
        u64 base = v->base_ns, frac = v->base_frac, base_tsc = v->base_tsc, mult = v->mult;
        i64 w = v->wall_ns;
        u64 tsc = rdtsc();
        __asm__ volatile("" ::: "memory");
        if (v->seq != s) continue;
        if (mult == 0) {
            *mono = base;
        } else {
            // A 64x64 -> 128-bit multiply (no division: no helper from libgcc)
            u64 delta = tsc > base_tsc ? tsc - base_tsc : 0;
            unsigned __int128 total = (unsigned __int128)delta * mult + frac;
            *mono = base + (u64)(total >> 32);
        }
        *wall = w;
        return;
    }
}

// CLOCK_REALTIME, _COARSE, _ALARM, TAI: the wall clock; MONOTONIC, _RAW, _COARSE, BOOTTIME,
// BOOTTIME_ALARM: since boot (as the kernel's clock_gettime treats them)
static int kind(int clk) {
    switch (clk) {
    case 0: case 5: case 8: case 11: return 1;
    case 1: case 4: case 6: case 7: case 9: return 2;
    default: return 0;
    }
}

int __vdso_clock_gettime(int clk, struct timespec_ *ts) {
    int k = kind(clk);
    if (k == 0 || ts == 0) return (int)sys2(228, clk, (long)ts);
    u64 mono;
    i64 wall;
    now(&mono, &wall);
    i64 t = k == 1 ? wall + (i64)mono : (i64)mono;
    if (t < 0) t = 0;
    ts->tv_sec = t / 1000000000;
    ts->tv_nsec = t % 1000000000;
    return 0;
}

int __vdso_gettimeofday(struct timeval_ *tv, void *tz) {
    if (tz) return (int)sys2(96, (long)tv, (long)tz);
    if (tv) {
        u64 mono;
        i64 wall;
        now(&mono, &wall);
        i64 t = wall + (i64)mono;
        if (t < 0) t = 0;
        tv->tv_sec = t / 1000000000;
        tv->tv_usec = (t % 1000000000) / 1000;
    }
    return 0;
}

long __vdso_time(long *t) {
    u64 mono;
    i64 wall;
    now(&mono, &wall);
    long s = (wall + (i64)mono) / 1000000000;
    if (t) *t = s;
    return s;
}

int __vdso_clock_getres(int clk, struct timespec_ *res) {
    // The precise clocks: 1 ns (as the kernel reports); the coarse ones and the others:
    // the system call
    if (clk == 0 || clk == 1 || clk == 4 || clk == 7) {
        if (res) {
            res->tv_sec = 0;
            res->tv_nsec = 1;
        }
        return 0;
    }
    return (int)sys2(229, clk, (long)res);
}

int __vdso_getcpu(unsigned *cpu, unsigned *node) {
    return (int)sys2(309, (long)cpu, (long)node);
}

// The names glibc also accepts without the prefix
int clock_gettime(int, struct timespec_ *) __attribute__((weak, alias("__vdso_clock_gettime")));
int gettimeofday(struct timeval_ *, void *) __attribute__((weak, alias("__vdso_gettimeofday")));
long time(long *) __attribute__((weak, alias("__vdso_time")));
int clock_getres(int, struct timespec_ *) __attribute__((weak, alias("__vdso_clock_getres")));
int getcpu(unsigned *, unsigned *) __attribute__((weak, alias("__vdso_getcpu")));
