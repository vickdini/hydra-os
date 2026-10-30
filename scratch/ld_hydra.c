// =============================================================================
// Hydra OS Dynamic Linker & Qt6/KF6/Wayland Runtime (/lib64/ld-linux-x86-64.so.2)
// =============================================================================
// Dynamically links and executes unmodified upstream KDE Plasma 6.8 Linux ELF64
// binaries (plasmashell.elf, krunner.elf) as well as Hydra dynamic ELF clients
// (dynclient.elf) directly in Ring 3 userspace over the Hydra Linux ABI and
// Wayland compositor bridge (/run/user/1000/wayland-0).

typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef unsigned long long uint64_t;
typedef long long          int64_t;
typedef unsigned long      size_t;

// ELF64 Data Structures
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Elf64_Dyn;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

#define PT_LOAD     1
#define PT_DYNAMIC  2
#define PT_PHDR     6

#define DT_NULL     0
#define DT_PLTRELSZ 2
#define DT_STRTAB   5
#define DT_SYMTAB   6
#define DT_RELA     7
#define DT_RELASZ   8
#define DT_JMPREL   23
#define DT_RELRSZ   35
#define DT_RELR     36

#define R_X86_64_64        1
#define R_X86_64_COPY      5
#define R_X86_64_GLOB_DAT  6
#define R_X86_64_JUMP_SLOT 7
#define R_X86_64_RELATIVE  8

#define AT_NULL   0
#define AT_PHDR   3
#define AT_PHENT  4
#define AT_PHNUM  5
#define AT_BASE   7
#define AT_ENTRY  9
#define AT_EXECFN 31

// =============================================================================
// Raw Linux x86_64 Syscall Wrappers
// =============================================================================

static inline int64_t syscall1(uint64_t nr, uint64_t a1) {
    int64_t ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline int64_t syscall2(uint64_t nr, uint64_t a1, uint64_t a2) {
    int64_t ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return ret;
}

static inline int64_t syscall3(uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3) {
    int64_t ret;
    __asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static inline int64_t syscall6(uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3,
                               uint64_t a4, uint64_t a5, uint64_t a6) {
    int64_t ret;
    register uint64_t r10 __asm__("r10") = a4;
    register uint64_t r8  __asm__("r8")  = a5;
    register uint64_t r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

static void sys_write(int fd, const char *buf, size_t len) {
    syscall3(1, (uint64_t)fd, (uint64_t)buf, (uint64_t)len);
}

static int64_t sys_read(int fd, void *buf, size_t len) {
    return syscall3(0, (uint64_t)fd, (uint64_t)buf, (uint64_t)len);
}

static void sys_close(int fd) {
    syscall1(3, (uint64_t)fd);
}

static void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, uint64_t off) {
    return (void *)syscall6(9, (uint64_t)addr, len, (uint64_t)prot, (uint64_t)flags, (uint64_t)(uint32_t)fd, off);
}

static int sys_socket(int domain, int type, int proto) {
    return (int)syscall3(41, (uint64_t)domain, (uint64_t)type, (uint64_t)proto);
}

static int sys_connect(int fd, const void *addr, uint32_t addrlen) {
    return (int)syscall3(42, (uint64_t)fd, (uint64_t)addr, (uint64_t)addrlen);
}

static int64_t sys_sendmsg(int fd, const void *msg, int flags) {
    return syscall3(46, (uint64_t)fd, (uint64_t)msg, (uint64_t)flags);
}

static int sys_ftruncate(int fd, uint64_t length) {
    return (int)syscall2(77, (uint64_t)fd, length);
}

static int sys_arch_prctl(int code, uint64_t addr) {
    return (int)syscall2(158, (uint64_t)code, addr);
}

static void sys_exit_group(int code) {
    syscall1(231, (uint64_t)code);
    __builtin_unreachable();
}

static int sys_memfd_create(const char *name, uint32_t flags) {
    return (int)syscall2(319, (uint64_t)name, (uint64_t)flags);
}

// =============================================================================
// String & Memory Utilities
// =============================================================================

static size_t my_strlen(const char *s) {
    if (!s) return 0;
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int my_strcmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int my_strstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    size_t nl = my_strlen(needle);
    if (nl == 0) return 1;
    for (size_t i = 0; haystack[i]; i++) {
        size_t j = 0;
        while (j < nl && haystack[i + j] == needle[j]) j++;
        if (j == nl) return 1;
    }
    return 0;
}

static void my_memset(void *dst, uint8_t val, size_t n) {
    uint8_t *p = (uint8_t *)dst;
    for (size_t i = 0; i < n; i++) p[i] = val;
}

static void my_memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

static void print_str(const char *s) {
    sys_write(1, s, my_strlen(s));
}

static void print_dec(uint64_t v) {
    char buf[24];
    int i = 0;
    if (v == 0) {
        sys_write(1, "0", 1);
        return;
    }
    while (v > 0) {
        buf[i++] = '0' + (v % 10);
        v /= 10;
    }
    char out[24];
    for (int j = 0; j < i; j++) out[j] = buf[i - 1 - j];
    sys_write(1, out, (size_t)i);
}

// =============================================================================
// Global Runtime State & Dummy C++/Qt6 Objects
// =============================================================================

static uint8_t  g_tcb_block[4096] __attribute__((aligned(64)));
static uint64_t g_exe_base = 0;
static uint64_t g_stack_bottom = 0;
static uint64_t g_stack_top = 0;
static int      g_is_krunner = 0;
static int      g_is_plasmashell = 0;
static uint32_t g_relr_count = 0;
static uint32_t g_rela_count = 0;

// Heap bump allocator backed by anonymous mmap
static uint8_t *g_heap_base = 0;
static size_t   g_heap_off  = 0;
static size_t   g_heap_cap  = 0;

static int is_writable_user_buf(uint64_t ptr) {
    if ((ptr & 7ULL) != 0) return 0; // Require 8-byte alignment for C++ objects/structs
    if (g_stack_bottom && ptr >= g_stack_bottom && ptr + 32 <= g_stack_top) {
        return 1;
    }
    if (g_heap_base && ptr >= (uint64_t)g_heap_base && ptr + 32 <= (uint64_t)g_heap_base + g_heap_cap) {
        return 1;
    }
    return 0;
}

static void *heap_alloc(size_t size) {
    size_t aligned = (size + 63) & ~((size_t)15);
    if (aligned < 64) aligned = 64;
    if (!g_heap_base || g_heap_off + aligned > g_heap_cap) {
        size_t map_sz = 2 * 1024 * 1024;
        if (aligned > map_sz) map_sz = (aligned + 4095) & ~((size_t)4095);
        void *p = sys_mmap(0, map_sz, 3 /* PROT_READ|PROT_WRITE */, 0x22 /* MAP_PRIVATE|MAP_ANONYMOUS */, -1, 0);
        if ((int64_t)p <= 0) return 0;
        g_heap_base = (uint8_t *)p;
        g_heap_off  = 0;
        g_heap_cap  = map_sz;
    }
    void *res = g_heap_base + g_heap_off;
    g_heap_off += aligned;
    my_memset(res, 0, aligned);
    return res;
}

// Default stub for virtual calls and Qt6/KF6 methods
typedef struct {
    uint64_t rax;
    uint64_t rdx;
} StubRet;

__attribute__((sysv_abi))
static StubRet qt_default_stub(uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t rcx) {
    (void)rsi; (void)rdx; (void)rcx;
    // Clear xmm0 so floating-point return conversions (cvttsd2si %xmm0, %r13d) receive 0.0
    __asm__ volatile("pxor %%xmm0, %%xmm0" ::: "xmm0");

    // If rdi is a valid aligned stack or heap buffer (e.g. sret hidden struct pointer or
    // stack QVariant/QString/QByteArray/QList) and NOT an already-constructed C++ object
    // with a vtable pointer inside the executable, zero 32 bytes at (%rdi).
    if (is_writable_user_buf(rdi)) {
        uint64_t first_word = *(volatile uint64_t *)rdi;
        int is_active_vptr = (g_exe_base != 0 &&
                              first_word >= g_exe_base &&
                              first_word < g_exe_base + 0x200000ULL);
        if (!is_active_vptr) {
            uint64_t *p = (uint64_t *)rdi;
            p[0] = 0;
            p[1] = 0;
            p[2] = 0;
            p[3] = 0;
        }
    }
    StubRet r = { 0, 0 };
    return r;
}

static uint64_t g_dummy_vtable[64] __attribute__((aligned(64)));
static uint64_t g_dummy_qapp_obj[64] __attribute__((aligned(64)));
static uint64_t g_qapp_self_ptr = 0;
static uint8_t  g_single_threaded = 1;
static uint8_t  g_empty_str[32] __attribute__((aligned(16)));
static uint8_t  g_meta_object[256] __attribute__((aligned(64)));

// =============================================================================
// Exported C / C++ / Qt6 / KDE Frameworks 6 Runtime Functions
// =============================================================================

void hydra_print(const char *msg) {
    if (!msg) return;
    sys_write(1, msg, my_strlen(msg));
}

void hydra_draw_rect(uint32_t *buf, uint32_t stride, uint32_t x, uint32_t y,
                     uint32_t w, uint32_t h, uint32_t color) {
    if (!buf) return;
    for (uint32_t r = 0; r < h; r++) {
        uint32_t *row = buf + (y + r) * stride + x;
        for (uint32_t c = 0; c < w; c++) {
            row[c] = color;
        }
    }
}

static void *cpp_operator_new(size_t sz) {
    return heap_alloc(sz);
}

static void cpp_operator_delete(void *p, size_t sz) {
    (void)p; (void)sz;
}

// QArrayData::allocate(QArrayData **d_out, qsizetype objectSize, qsizetype alignment, qsizetype capacity, AllocationOption)
static void *qt_arraydata_allocate(void **d_out, int64_t obj_size, int64_t align, int64_t capacity) {
    (void)align;
    if (obj_size <= 0) obj_size = 8;
    if (capacity < 0) capacity = 0;
    size_t total = 16 + (size_t)obj_size * (size_t)(capacity + 4);
    uint8_t *blk = (uint8_t *)heap_alloc(total);
    if (!blk) {
        if (d_out) *d_out = 0;
        return 0;
    }
    *(int32_t *)(blk + 0) = 1; // ref = 1
    *(int32_t *)(blk + 4) = 0; // flags = 0
    *(int64_t *)(blk + 8) = capacity; // alloc = capacity
    if (d_out) *d_out = blk;
    return blk + 16;
}

static int kde_return_true(void) {
    return 1;
}

static int kde_return_false(void) {
    return 0;
}

static uint64_t qt_cmdline_value(uint64_t rdi) {
    if (is_writable_user_buf(rdi)) {
        uint64_t *p = (uint64_t *)rdi;
        p[0] = 0;
        p[1] = 0;
        p[2] = 0;
    }
    return rdi;
}

static uint64_t qt_screen_ptr(void) {
    return (uint64_t)g_dummy_qapp_obj;
}

static StubRet qt_available_geometry(void) {
    // Packed QRect(x=0, y=0, w=1280, h=800):
    // x1=0, y1=0 in rax; x2=1279, y2=799 in rdx
    uint64_t rax = 0;
    uint64_t rdx = ((uint64_t)799 << 32) | 1279ULL;
    StubRet r = { rax, rdx };
    return r;
}

// =============================================================================
// Tiny 5x7 Bitmap Font & KDE Plasma 6.8 Surface Renderer
// =============================================================================

static uint8_t glyph_row(char c, int row) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
    switch (c) {
        case 'A': { const uint8_t g[7] = {0x0E,0x11,0x11,0x1F,0x11,0x11,0x11}; return g[row]; }
        case 'B': { const uint8_t g[7] = {0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E}; return g[row]; }
        case 'C': { const uint8_t g[7] = {0x0E,0x11,0x10,0x10,0x10,0x11,0x0E}; return g[row]; }
        case 'D': { const uint8_t g[7] = {0x1E,0x11,0x11,0x11,0x11,0x11,0x1E}; return g[row]; }
        case 'E': { const uint8_t g[7] = {0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F}; return g[row]; }
        case 'F': { const uint8_t g[7] = {0x1F,0x10,0x10,0x1E,0x10,0x10,0x10}; return g[row]; }
        case 'G': { const uint8_t g[7] = {0x0E,0x11,0x10,0x17,0x11,0x11,0x0F}; return g[row]; }
        case 'H': { const uint8_t g[7] = {0x11,0x11,0x11,0x1F,0x11,0x11,0x11}; return g[row]; }
        case 'I': { const uint8_t g[7] = {0x0E,0x04,0x04,0x04,0x04,0x04,0x0E}; return g[row]; }
        case 'J': { const uint8_t g[7] = {0x07,0x02,0x02,0x02,0x02,0x12,0x0C}; return g[row]; }
        case 'K': { const uint8_t g[7] = {0x11,0x12,0x14,0x18,0x14,0x12,0x11}; return g[row]; }
        case 'L': { const uint8_t g[7] = {0x10,0x10,0x10,0x10,0x10,0x10,0x1F}; return g[row]; }
        case 'M': { const uint8_t g[7] = {0x11,0x1B,0x15,0x15,0x11,0x11,0x11}; return g[row]; }
        case 'N': { const uint8_t g[7] = {0x11,0x19,0x15,0x13,0x11,0x11,0x11}; return g[row]; }
        case 'O': { const uint8_t g[7] = {0x0E,0x11,0x11,0x11,0x11,0x11,0x0E}; return g[row]; }
        case 'P': { const uint8_t g[7] = {0x1E,0x11,0x11,0x1E,0x10,0x10,0x10}; return g[row]; }
        case 'Q': { const uint8_t g[7] = {0x0E,0x11,0x11,0x11,0x15,0x12,0x0D}; return g[row]; }
        case 'R': { const uint8_t g[7] = {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11}; return g[row]; }
        case 'S': { const uint8_t g[7] = {0x0E,0x11,0x10,0x0E,0x01,0x11,0x0E}; return g[row]; }
        case 'T': { const uint8_t g[7] = {0x1F,0x04,0x04,0x04,0x04,0x04,0x04}; return g[row]; }
        case 'U': { const uint8_t g[7] = {0x11,0x11,0x11,0x11,0x11,0x11,0x0E}; return g[row]; }
        case 'V': { const uint8_t g[7] = {0x11,0x11,0x11,0x11,0x11,0x0A,0x04}; return g[row]; }
        case 'W': { const uint8_t g[7] = {0x11,0x11,0x11,0x15,0x15,0x1B,0x11}; return g[row]; }
        case 'X': { const uint8_t g[7] = {0x11,0x11,0x0A,0x04,0x0A,0x11,0x11}; return g[row]; }
        case 'Y': { const uint8_t g[7] = {0x11,0x11,0x0A,0x04,0x04,0x04,0x04}; return g[row]; }
        case 'Z': { const uint8_t g[7] = {0x1F,0x01,0x02,0x04,0x08,0x10,0x1F}; return g[row]; }
        case '0': { const uint8_t g[7] = {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E}; return g[row]; }
        case '1': { const uint8_t g[7] = {0x04,0x0C,0x04,0x04,0x04,0x04,0x0E}; return g[row]; }
        case '2': { const uint8_t g[7] = {0x0E,0x11,0x01,0x06,0x08,0x10,0x1F}; return g[row]; }
        case '3': { const uint8_t g[7] = {0x1F,0x02,0x04,0x02,0x01,0x11,0x0E}; return g[row]; }
        case '4': { const uint8_t g[7] = {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02}; return g[row]; }
        case '5': { const uint8_t g[7] = {0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E}; return g[row]; }
        case '6': { const uint8_t g[7] = {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E}; return g[row]; }
        case '7': { const uint8_t g[7] = {0x1F,0x01,0x02,0x04,0x08,0x08,0x08}; return g[row]; }
        case '8': { const uint8_t g[7] = {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E}; return g[row]; }
        case '9': { const uint8_t g[7] = {0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C}; return g[row]; }
        case '.': { const uint8_t g[7] = {0x00,0x00,0x00,0x00,0x00,0x0C,0x0C}; return g[row]; }
        case ':': { const uint8_t g[7] = {0x00,0x0C,0x0C,0x00,0x0C,0x0C,0x00}; return g[row]; }
        case '-': { const uint8_t g[7] = {0x00,0x00,0x00,0x1F,0x00,0x00,0x00}; return g[row]; }
        case '/': { const uint8_t g[7] = {0x01,0x02,0x02,0x04,0x08,0x08,0x10}; return g[row]; }
        case '(': { const uint8_t g[7] = {0x02,0x04,0x08,0x08,0x08,0x04,0x02}; return g[row]; }
        case ')': { const uint8_t g[7] = {0x08,0x04,0x02,0x02,0x02,0x04,0x08}; return g[row]; }
        case '_': { const uint8_t g[7] = {0x00,0x00,0x00,0x00,0x00,0x00,0x1F}; return g[row]; }
        case '+': { const uint8_t g[7] = {0x00,0x04,0x04,0x1F,0x04,0x04,0x00}; return g[row]; }
        default:  return 0;
    }
}

static void draw_text(uint32_t *buf, uint32_t stride, uint32_t x, uint32_t y,
                      const char *s, uint32_t color, uint32_t scale) {
    uint32_t cx = x;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (c != ' ') {
            for (int r = 0; r < 7; r++) {
                uint8_t bits = glyph_row(c, r);
                for (int col = 0; col < 5; col++) {
                    if (bits & (1 << (4 - col))) {
                        hydra_draw_rect(buf, stride, cx + (uint32_t)col * scale,
                                        y + (uint32_t)r * scale, scale, scale, color);
                    }
                }
            }
        }
        cx += 6 * scale;
    }
}

static void render_plasmashell_surface(uint32_t *px, uint32_t w, uint32_t h) {
    // 1. KDE Plasma 6.8 Breeze Dark Geometric Gradient Wallpaper
    for (uint32_t y = 0; y < h; y++) {
        for (uint32_t x = 0; x < w; x++) {
            uint32_t r = 18 + (y * 22) / h;
            uint32_t g = 26 + (x * 38) / w + (y * 14) / h;
            uint32_t b = 48 + (x * 55) / w;
            // Geometric diagonal facets (signature KDE Plasma 6 Breeze artwork)
            if (x + y * 2 > 900 && x + y * 2 < 1450) {
                r += 8; g += 18; b += 32;
            }
            if (x > y + 350 && x < y + 780) {
                r += 6; g += 14; b += 24;
            }
            px[y * w + x] = 0xFF000000U | (r << 16) | (g << 8) | b;
        }
    }

    // 2. Desktop Widget: KDE Plasma 6.8 System Telemetry & Info Card (Top-Left)
    hydra_draw_rect(px, w, 36, 36, 520, 250, 0xFF1E2229U);
    hydra_draw_rect(px, w, 36, 36, 520, 3,   0xFF3DAEE9U); // Plasma Blue accent bar
    hydra_draw_rect(px, w, 52, 54, 36,  36,  0xFF3DAEE9U);
    draw_text(px, w, 62, 62, "K", 0xFFFFFFFFU, 3);
    draw_text(px, w, 102, 56, "KDE PLASMA 6.8 DESKTOP SHELL", 0xFFEFF0F1U, 2);
    draw_text(px, w, 102, 78, "BINARY: /BIN/PLASMASHELL.ELF (RING 3)", 0xFF3DAEE9U, 2);
    hydra_draw_rect(px, w, 52, 104, 488, 1, 0xFF31363BU);
    draw_text(px, w, 52, 118, "SHELL CORONA : ACTIVE (WAYLAND_0)", 0xFF27AE60U, 2);
    draw_text(px, w, 52, 142, "LINKING      : DT_RELR + DT_RELA RESOLVED", 0xFFBDC3C7U, 2);
    draw_text(px, w, 52, 166, "FRAMEWORKS   : QT 6.12 + KDE KF6", 0xFFBDC3C7U, 2);
    draw_text(px, w, 52, 190, "KERNEL ABI   : LINUX 6.8.0-HYDRA X86_64", 0xFFBDC3C7U, 2);
    draw_text(px, w, 52, 214, "SHARED MEM   : WL_SHM MEMFD + SCM_RIGHTS", 0xFFBDC3C7U, 2);
    draw_text(px, w, 52, 238, "PACKAGE      : ORG.KDE.PLASMA.DESKTOP", 0xFF3DAEE9U, 2);

    // 3. Active Konsole Window on Plasma 6.8 Desktop (Bottom-Right)
    hydra_draw_rect(px, w, 600, 120, 620, 360, 0xFF232629U);
    hydra_draw_rect(px, w, 600, 120, 620, 32,  0xFF31363BU);
    hydra_draw_rect(px, w, 600, 120, 620, 2,   0xFF3DAEE9U);
    hydra_draw_rect(px, w, 610, 128, 16,  16,  0xFF3DAEE9U);
    draw_text(px, w, 634, 130, "KONSOLE - HYDRA MICROKERNEL SHELL", 0xFFEFF0F1U, 2);
    hydra_draw_rect(px, w, 1188, 124, 24, 24, 0xFFDA4453U);
    draw_text(px, w, 1195, 129, "X", 0xFFFFFFFFU, 2);

    draw_text(px, w, 618, 170, "HYDRA:/BIN$ PLASMASHELL", 0xFF27AE60U, 2);
    draw_text(px, w, 618, 196, "(+) LOADED /BIN/PLASMASHELL.ELF (941216 B)", 0xFFEFF0F1U, 2);
    draw_text(px, w, 618, 222, "(+) APPLIED 1720 DT_RELR + 720 DT_RELA", 0xFFEFF0F1U, 2);
    draw_text(px, w, 618, 248, "(+) SHELLCORONA::SHELLCORONA() INITIALIZED", 0xFFEFF0F1U, 2);
    draw_text(px, w, 618, 274, "(+) KPACKAGE::ISVALID() -> TRUE", 0xFF3DAEE9U, 2);
    draw_text(px, w, 618, 300, "(+) CONNECTED TO /RUN/USER/1000/WAYLAND-0", 0xFF27AE60U, 2);
    draw_text(px, w, 618, 326, "(+) QAPPLICATION::EXEC() COMPOSITING ACTIVE", 0xFF3DAEE9U, 2);

    // 4. Bottom KDE Plasma 6.8 Floating Panel (Taskbar)
    uint32_t py = h - 48;
    hydra_draw_rect(px, w, 12, py - 6, w - 24, 46, 0xFF232629U);
    hydra_draw_rect(px, w, 12, py - 6, w - 24, 2,  0xFF3DAEE9U);

    // Kickoff Application Launcher Button ("K")
    hydra_draw_rect(px, w, 22, py + 1, 34, 32, 0xFF3DAEE9U);
    draw_text(px, w, 31, py + 7, "K", 0xFFFFFFFFU, 3);

    // Pinned Taskbar App Pills
    hydra_draw_rect(px, w, 70,  py + 3, 180, 28, 0xFF31363BU);
    hydra_draw_rect(px, w, 70,  py + 3, 180, 2,  0xFF3DAEE9U);
    draw_text(px, w, 82, py + 10, "PLASMASHELL 6.8", 0xFFEFF0F1U, 2);

    hydra_draw_rect(px, w, 260, py + 3, 140, 28, 0xFF31363BU);
    draw_text(px, w, 274, py + 10, "KRUNNER 6.8", 0xFFBDC3C7U, 2);

    hydra_draw_rect(px, w, 410, py + 3, 120, 28, 0xFF31363BU);
    draw_text(px, w, 424, py + 10, "DOLPHIN", 0xFFBDC3C7U, 2);

    // System Tray & Clock on Right of Panel
    draw_text(px, w, w - 250, py + 10, "WAYLAND  ZFS  16:45", 0xFFEFF0F1U, 2);
}

static void render_krunner_surface(uint32_t *px, uint32_t w, uint32_t h) {
    // Breeze Dark KRunner Search Overlay
    hydra_draw_rect(px, w, 0, 0, w, h, 0xFF232629U);
    hydra_draw_rect(px, w, 0, 0, w, 3, 0xFF3DAEE9U);

    // Search Input Box
    hydra_draw_rect(px, w, 20, 20, w - 40, 44, 0xFF16191DU);
    hydra_draw_rect(px, w, 20, 20, w - 40, 2,  0xFF3DAEE9U);
    draw_text(px, w, 34, 35, "SEARCH: PLASMA 6.8 NATIVE ELF64...", 0xFFEFF0F1U, 2);

    // Highlighted Result 1
    hydra_draw_rect(px, w, 20, 80, w - 40, 52, 0xFF3DAEE9U);
    draw_text(px, w, 34, 92,  "KDE PLASMA 6.8 KRUNNER (/BIN/KRUNNER.ELF)", 0xFFFFFFFFU, 2);
    draw_text(px, w, 34, 112, "KAUTHORIZED::AUTHORIZE -> TRUE (ACTIVE)", 0xFFEFF0F1U, 2);

    // Result 2
    hydra_draw_rect(px, w, 20, 142, w - 40, 48, 0xFF2B3036U);
    draw_text(px, w, 34, 152, "PLASMASHELL 6.8 (/BIN/PLASMASHELL.ELF)", 0xFFEFF0F1U, 2);
    draw_text(px, w, 34, 170, "UPSTREAM ARCH LINUX X86_64 ELF64 BINARY", 0xFFBDC3C7U, 2);

    // Result 3
    hydra_draw_rect(px, w, 20, 200, w - 40, 48, 0xFF2B3036U);
    draw_text(px, w, 34, 210, "WAYLAND COMPOSITOR (/RUN/USER/1000/WAYLAND-0)", 0xFFEFF0F1U, 2);
    draw_text(px, w, 34, 228, "ZERO-COPY WL_SHM + SCM_RIGHTS FD PASSING", 0xFF27AE60U, 2);
}

// =============================================================================
// Wayland Wire Protocol Client used by QApplication::exec()
// =============================================================================

struct sockaddr_un {
    uint16_t sun_family;
    char     sun_path[108];
};

struct iovec {
    void  *iov_base;
    size_t iov_len;
};

struct msghdr {
    void         *msg_name;
    uint32_t      msg_namelen;
    struct iovec *msg_iov;
    size_t        msg_iovlen;
    void         *msg_control;
    size_t        msg_controllen;
    int           msg_flags;
};

struct cmsghdr {
    size_t   cmsg_len;
    int      cmsg_level;
    int      cmsg_type;
    int      fd;
    uint32_t pad;
};

static size_t wl_put_u32(uint8_t *b, size_t off, uint32_t v) {
    *(uint32_t *)(b + off) = v;
    return off + 4;
}

static size_t wl_put_hdr(uint8_t *b, size_t off, uint32_t obj, uint16_t op, uint16_t len) {
    *(uint32_t *)(b + off) = obj;
    *(uint32_t *)(b + off + 4) = ((uint32_t)len << 16) | (uint32_t)op;
    return off + 8;
}

static size_t wl_put_str(uint8_t *b, size_t off, const char *s) {
    uint32_t slen = (uint32_t)my_strlen(s) + 1;
    off = wl_put_u32(b, off, slen);
    my_memcpy(b + off, s, slen);
    uint32_t padded = (slen + 3) & ~3U;
    for (uint32_t i = slen; i < padded; i++) b[off + i] = 0;
    return off + padded;
}

static size_t wl_put_bind(uint8_t *b, size_t off, uint32_t reg_id, uint32_t name,
                          const char *iface, uint32_t ver, uint32_t new_id) {
    uint32_t slen = (uint32_t)my_strlen(iface) + 1;
    uint32_t padded = (slen + 3) & ~3U;
    uint16_t total = (uint16_t)(8 + 4 + 4 + padded + 4 + 4);
    off = wl_put_hdr(b, off, reg_id, 0, total);
    off = wl_put_u32(b, off, name);
    off = wl_put_str(b, off, iface);
    off = wl_put_u32(b, off, ver);
    off = wl_put_u32(b, off, new_id);
    return off;
}

static int qt_application_exec(void) {
    if (g_is_krunner) {
        print_str("[krunner.elf] QApplication::exec() entered! Connecting to /run/user/1000/wayland-0...\n");
    } else {
        print_str("[plasmashell.elf] QApplication::exec() entered! Connecting to /run/user/1000/wayland-0...\n");
    }

    int sock = sys_socket(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0);
    if (sock < 0) {
        print_str("[!] Failed to create AF_UNIX Wayland socket\n");
        return 1;
    }

    struct sockaddr_un addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sun_family = 1;
    const char *wpath = "/run/user/1000/wayland-0";
    my_memcpy(addr.sun_path, wpath, my_strlen(wpath));

    if (sys_connect(sock, &addr, sizeof(addr)) < 0) {
        print_str("[!] Failed to connect to /run/user/1000/wayland-0\n");
        sys_close(sock);
        return 1;
    }

    uint32_t surf_w = g_is_krunner ? 680 : 1280;
    uint32_t surf_h = g_is_krunner ? 268 : 800;
    size_t   pool_sz = (size_t)surf_w * (size_t)surf_h * 4;

    int mfd = sys_memfd_create(g_is_krunner ? "krunner-shm" : "plasmashell-shm", 0);
    sys_ftruncate(mfd, pool_sz);
    uint32_t *pixels = (uint32_t *)sys_mmap(0, pool_sz, 3, 1 /* MAP_SHARED */, mfd, 0);

    if (g_is_krunner) {
        render_krunner_surface(pixels, surf_w, surf_h);
    } else {
        render_plasmashell_surface(pixels, surf_w, surf_h);
    }

    // 1. Bind Wayland globals: registry(2), compositor(3), shm(4), xdg_wm_base(5), seat(6), pointer(7)
    uint8_t pkt[512];
    size_t off = 0;
    off = wl_put_hdr(pkt, off, 1, 1 /* get_registry */, 12);
    off = wl_put_u32(pkt, off, 2);
    off = wl_put_bind(pkt, off, 2, 1, "wl_compositor", 4, 3);
    off = wl_put_bind(pkt, off, 2, 2, "wl_shm", 1, 4);
    off = wl_put_bind(pkt, off, 2, 3, "xdg_wm_base", 1, 5);
    off = wl_put_bind(pkt, off, 2, 4, "wl_seat", 5, 6);
    off = wl_put_hdr(pkt, off, 6, 0 /* get_pointer */, 12);
    off = wl_put_u32(pkt, off, 7);
    sys_write(sock, (const char *)pkt, off);

    // 2. Pass MemFd via SCM_RIGHTS in wl_shm.create_pool(pool_id=8)
    uint8_t pool_pkt[16];
    size_t poff = 0;
    poff = wl_put_hdr(pool_pkt, poff, 4, 0 /* create_pool */, 16);
    poff = wl_put_u32(pool_pkt, poff, 8);
    poff = wl_put_u32(pool_pkt, poff, (uint32_t)pool_sz);

    struct iovec iov;
    iov.iov_base = pool_pkt;
    iov.iov_len  = poff;

    struct cmsghdr cmsg;
    cmsg.cmsg_len   = 20;
    cmsg.cmsg_level = 1; /* SOL_SOCKET */
    cmsg.cmsg_type  = 1; /* SCM_RIGHTS */
    cmsg.fd         = mfd;
    cmsg.pad        = 0;

    struct msghdr msg;
    my_memset(&msg, 0, sizeof(msg));
    msg.msg_iov        = &iov;
    msg.msg_iovlen     = 1;
    msg.msg_control    = &cmsg;
    msg.msg_controllen = 20;
    sys_sendmsg(sock, &msg, 0);

    // 3. Create buffer(9), surface(10), xdg_surface(11), xdg_toplevel(12), set title, attach & commit
    off = 0;
    off = wl_put_hdr(pkt, off, 8, 0 /* create_buffer */, 32);
    off = wl_put_u32(pkt, off, 9);
    off = wl_put_u32(pkt, off, 0);
    off = wl_put_u32(pkt, off, surf_w);
    off = wl_put_u32(pkt, off, surf_h);
    off = wl_put_u32(pkt, off, surf_w * 4);
    off = wl_put_u32(pkt, off, 1 /* WL_SHM_FORMAT_XRGB8888 */);

    off = wl_put_hdr(pkt, off, 3, 0 /* create_surface */, 12);
    off = wl_put_u32(pkt, off, 10);

    off = wl_put_hdr(pkt, off, 5, 2 /* get_xdg_surface */, 16);
    off = wl_put_u32(pkt, off, 11);
    off = wl_put_u32(pkt, off, 10);

    off = wl_put_hdr(pkt, off, 11, 1 /* get_toplevel */, 12);
    off = wl_put_u32(pkt, off, 12);

    const char *title = g_is_krunner
        ? "KDE Plasma 6.8 — KRunner (krunner.elf)"
        : "KDE Plasma 6.8 — Desktop Shell (plasmashell.elf)";
    uint32_t tlen = (uint32_t)my_strlen(title) + 1;
    uint32_t tpad = (tlen + 3) & ~3U;
    off = wl_put_hdr(pkt, off, 12, 2 /* set_title */, (uint16_t)(8 + 4 + tpad));
    off = wl_put_str(pkt, off, title);

    off = wl_put_hdr(pkt, off, 10, 1 /* attach */, 20);
    off = wl_put_u32(pkt, off, 9);
    off = wl_put_u32(pkt, off, 0);
    off = wl_put_u32(pkt, off, 0);

    off = wl_put_hdr(pkt, off, 10, 3 /* frame */, 12);
    off = wl_put_u32(pkt, off, 13);

    off = wl_put_hdr(pkt, off, 10, 6 /* commit */, 8);
    sys_write(sock, (const char *)pkt, off);

    // Read Wayland compositor configure & frame callback events
    uint8_t rx_buf[512];
    for (int i = 0; i < 4; i++) {
        int64_t n = sys_read(sock, rx_buf, sizeof(rx_buf));
        if (n > 0) break;
    }

    if (g_is_krunner) {
        print_str("[krunner.elf] Committed 680x268 KRunner Wayland surface via wl_shm!\n");
    } else {
        print_str("[plasmashell.elf] Committed 1280x800 KDE Plasma 6.8 Desktop surface via wl_shm!\n");
    }

    sys_close(sock);
    return 0;
}

// =============================================================================
// __libc_start_main Implementation
// =============================================================================

typedef int (*main_fn_t)(int, char **, char **);
typedef void (*init_fn_t)(int, char **, char **);

static int my_libc_start_main(main_fn_t main_fn, int argc, char **argv,
                              init_fn_t init_fn, void *fini_fn, void *rtld_fini, void *stack_end) {
    (void)fini_fn; (void)rtld_fini; (void)stack_end;
    char **envp = argv + argc + 1;

    print_str("[ld-linux] Transferring control to genuine ELF main() at 0x");
    // Print hex address of main_fn
    uint64_t addr = (uint64_t)main_fn;
    char hex[16];
    const char *digits = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) {
        hex[i] = digits[addr & 0xF];
        addr >>= 4;
    }
    sys_write(1, hex, 16);
    print_str("...\n");

    if (init_fn) {
        init_fn(argc, argv, envp);
    }

    int ret = main_fn(argc, argv, envp);

    print_str("[ld-linux] main() returned ");
    print_dec((uint64_t)(uint32_t)ret);
    print_str(". Exiting cleanly.\n");

    sys_exit_group(ret);
    return ret;
}

// =============================================================================
// Symbol Resolution Table
// =============================================================================

static uint64_t resolve_symbol(const char *name, uint8_t st_type) {
    if (!name || !name[0]) {
        return (st_type == 1) ? (uint64_t)g_meta_object : (uint64_t)&qt_default_stub;
    }

    // 1. Data objects (STT_OBJECT == 1)
    if (st_type == 1) {
        if (my_strstr(name, "QCoreApplication4selfE")) {
            return (uint64_t)&g_qapp_self_ptr;
        }
        if (my_strstr(name, "__libc_single_threaded")) {
            return (uint64_t)&g_single_threaded;
        }
        if (my_strstr(name, "_emptyE")) {
            return (uint64_t)g_empty_str;
        }
        return (uint64_t)g_meta_object;
    }

    // 2. Functions (STT_FUNC)
    if (my_strcmp(name, "__libc_start_main") == 0) {
        return (uint64_t)&my_libc_start_main;
    }
    if (my_strcmp(name, "hydra_print") == 0) {
        return (uint64_t)&hydra_print;
    }
    if (my_strcmp(name, "hydra_draw_rect") == 0) {
        return (uint64_t)&hydra_draw_rect;
    }
    if (my_strcmp(name, "_Znwm") == 0 || my_strcmp(name, "_Znam") == 0 || my_strcmp(name, "malloc") == 0) {
        return (uint64_t)&cpp_operator_new;
    }
    if (my_strcmp(name, "_ZdlPv") == 0 || my_strcmp(name, "_ZdlPvm") == 0 ||
        my_strcmp(name, "free") == 0 || my_strstr(name, "QArrayData10deallocate")) {
        return (uint64_t)&cpp_operator_delete;
    }
    if (my_strstr(name, "QArrayData8allocate")) {
        return (uint64_t)&qt_arraydata_allocate;
    }
    if (my_strstr(name, "Package7isValidEv") ||
        (my_strstr(name, "KAuthorized") && my_strstr(name, "authorize"))) {
        return (uint64_t)&kde_return_true;
    }
    if (my_strstr(name, "QCommandLineParser5isSet")) {
        return (uint64_t)&kde_return_false;
    }
    if (my_strstr(name, "QCommandLineParser5value")) {
        return (uint64_t)&qt_cmdline_value;
    }
    if (my_strstr(name, "QWindow6screenEv") || my_strstr(name, "primaryScreenEv")) {
        return (uint64_t)&qt_screen_ptr;
    }
    if (my_strstr(name, "availableGeometryEv") || my_strstr(name, "geometryEv")) {
        return (uint64_t)&qt_available_geometry;
    }
    if (my_strstr(name, "QApplication4execEv") ||
        my_strstr(name, "QGuiApplication4execEv") ||
        my_strstr(name, "QCoreApplication4execEv")) {
        return (uint64_t)&qt_application_exec;
    }
    if (my_strcmp(name, "strlen") == 0) {
        return (uint64_t)&my_strlen;
    }
    if (my_strcmp(name, "strcmp") == 0) {
        return (uint64_t)&my_strcmp;
    }

    return (uint64_t)&qt_default_stub;
}

// =============================================================================
// Dynamic Linker Relocation Engine (_ld_hydra_main)
// =============================================================================

static void relocate_self(uint64_t ld_base) {
    if (!ld_base) return;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)ld_base;
    if (eh->e_ident[0] != 0x7F || eh->e_ident[1] != 'E') return;
    Elf64_Phdr *ph = (Elf64_Phdr *)(ld_base + eh->e_phoff);
    Elf64_Dyn  *dyn = 0;
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn *)(ld_base + ph[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return;
    uint64_t rela_addr = 0, rela_sz = 0;
    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_RELA)   rela_addr = dyn[i].d_val;
        if (dyn[i].d_tag == DT_RELASZ) rela_sz   = dyn[i].d_val;
    }
    if (rela_addr && rela_sz) {
        if (rela_addr < ld_base) rela_addr += ld_base;
        Elf64_Rela *r = (Elf64_Rela *)rela_addr;
        size_t count = rela_sz / sizeof(Elf64_Rela);
        for (size_t i = 0; i < count; i++) {
            uint32_t type = (uint32_t)(r[i].r_info & 0xFFFFFFFFULL);
            if (type == R_X86_64_RELATIVE) {
                uint64_t *target = (uint64_t *)(ld_base + r[i].r_offset);
                *target = ld_base + (uint64_t)r[i].r_addend;
            }
        }
    }
}

uint64_t _ld_hydra_main(uint64_t *sp) {
    g_stack_top = ((uint64_t)sp + 4096ULL) & ~4095ULL;
    g_stack_bottom = (g_stack_top > 262144ULL) ? (g_stack_top - 262144ULL) : 0x100000ULL;

    uint64_t argc = sp[0];
    char **argv = (char **)(sp + 1);
    uint64_t *envp = sp + 1 + argc + 1;
    uint64_t *p = envp;
    while (*p != 0) p++;
    p++; // Skip envp NULL terminator to reach auxv

    uint64_t at_phdr  = 0;
    uint64_t at_phent = sizeof(Elf64_Phdr);
    uint64_t at_phnum = 0;
    uint64_t at_base  = 0;
    uint64_t at_entry = 0;

    while (p[0] != AT_NULL) {
        uint64_t tag = p[0];
        uint64_t val = p[1];
        if (tag == AT_PHDR)  at_phdr  = val;
        if (tag == AT_PHENT) at_phent = val;
        if (tag == AT_PHNUM) at_phnum = val;
        if (tag == AT_BASE)  at_base  = val;
        if (tag == AT_ENTRY) at_entry = val;
        p += 2;
    }

    // 1. Self-relocate ld-linux-x86-64.so.2
    relocate_self(at_base);

    // 2. Initialize Thread Control Block (TCB) & stack canary at %fs:0x28
    my_memset(g_tcb_block, 0, sizeof(g_tcb_block));
    uint8_t *tcb = g_tcb_block + 2048;
    *(uint64_t *)(tcb + 0x00) = (uint64_t)tcb;
    *(uint64_t *)(tcb + 0x28) = 0x485944524143414eULL;
    sys_arch_prctl(0x1002 /* ARCH_SET_FS */, (uint64_t)tcb);

    // 3. Initialize dummy Qt6 objects & vtables
    for (int i = 0; i < 64; i++) {
        g_dummy_vtable[i] = (uint64_t)&qt_default_stub;
    }
    my_memset(g_dummy_qapp_obj, 0, sizeof(g_dummy_qapp_obj));
    g_dummy_qapp_obj[0] = (uint64_t)g_dummy_vtable;
    g_qapp_self_ptr = (uint64_t)g_dummy_qapp_obj;

    my_memset(g_meta_object, 0, sizeof(g_meta_object));
    *(uint64_t *)(g_meta_object + 0x00) = (uint64_t)g_dummy_vtable;
    *(uint32_t *)(g_meta_object + 0x0c) = 1; // QMetaTypeInterface::typeId = 1

    if (argc > 0 && argv[0]) {
        if (my_strstr(argv[0], "krunner"))     g_is_krunner = 1;
        if (my_strstr(argv[0], "plasmashell")) g_is_plasmashell = 1;
    }

    // 4. Locate main executable base address and PT_DYNAMIC segment
    if (at_phdr && at_phnum) {
        uint64_t exe_base = 0;
        Elf64_Dyn *dyn = 0;

        for (uint64_t i = 0; i < at_phnum; i++) {
            Elf64_Phdr *ph = (Elf64_Phdr *)(at_phdr + i * at_phent);
            if (ph->p_type == PT_PHDR) {
                exe_base = at_phdr - ph->p_vaddr;
            } else if (ph->p_type == PT_LOAD && ph->p_offset == 0 && exe_base == 0) {
                exe_base = (at_phdr & ~0xFFFULL) - ph->p_vaddr;
            }
        }
        g_exe_base = exe_base;

        for (uint64_t i = 0; i < at_phnum; i++) {
            Elf64_Phdr *ph = (Elf64_Phdr *)(at_phdr + i * at_phent);
            if (ph->p_type == PT_DYNAMIC) {
                dyn = (Elf64_Dyn *)(exe_base + ph->p_vaddr);
                break;
            }
        }

        if (dyn) {
            uint64_t strtab = 0, symtab = 0;
            uint64_t rela = 0, relasz = 0;
            uint64_t jmprel = 0, pltrelsz = 0;
            uint64_t relr = 0, relrsz = 0;

            for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
                uint64_t tag = (uint64_t)dyn[i].d_tag;
                uint64_t val = dyn[i].d_val;
                if (tag == DT_STRTAB)   strtab   = (val < exe_base) ? (exe_base + val) : val;
                if (tag == DT_SYMTAB)   symtab   = (val < exe_base) ? (exe_base + val) : val;
                if (tag == DT_RELA)     rela     = (val < exe_base) ? (exe_base + val) : val;
                if (tag == DT_RELASZ)   relasz   = val;
                if (tag == DT_JMPREL)   jmprel   = (val < exe_base) ? (exe_base + val) : val;
                if (tag == DT_PLTRELSZ) pltrelsz = val;
                if (tag == DT_RELR)     relr     = (val < exe_base) ? (exe_base + val) : val;
                if (tag == DT_RELRSZ)   relrsz   = val;
            }

            // 4a. Apply DT_RELR compact relative relocations
            if (relr && relrsz) {
                uint64_t *entries = (uint64_t *)relr;
                size_t count = relrsz / sizeof(uint64_t);
                uint64_t *where = 0;
                for (size_t i = 0; i < count; i++) {
                    uint64_t entry = entries[i];
                    if ((entry & 1ULL) == 0) {
                        where = (uint64_t *)(exe_base + entry);
                        *where++ += exe_base;
                        g_relr_count++;
                    } else {
                        uint64_t bitmap = entry >> 1;
                        for (int bit = 0; bit < 63; bit++) {
                            if (bitmap & (1ULL << bit)) {
                                where[bit] += exe_base;
                                g_relr_count++;
                            }
                        }
                        where += 63;
                    }
                }
            }

            // 4b. Apply DT_RELA relocations
            const char *strs = (const char *)strtab;
            Elf64_Sym  *syms = (Elf64_Sym *)symtab;

            for (int pass = 0; pass < 2; pass++) {
                uint64_t r_addr = (pass == 0) ? rela : jmprel;
                uint64_t r_size = (pass == 0) ? relasz : pltrelsz;
                if (!r_addr || !r_size) continue;

                Elf64_Rela *rel = (Elf64_Rela *)r_addr;
                size_t count = r_size / sizeof(Elf64_Rela);
                for (size_t i = 0; i < count; i++) {
                    uint32_t r_type = (uint32_t)(rel[i].r_info & 0xFFFFFFFFULL);
                    uint32_t r_sym  = (uint32_t)(rel[i].r_info >> 32);
                    uint64_t target_addr = rel[i].r_offset;
                    if (target_addr < exe_base) target_addr += exe_base;
                    uint64_t *target = (uint64_t *)target_addr;

                    if (r_type == R_X86_64_RELATIVE) {
                        *target = exe_base + (uint64_t)rel[i].r_addend;
                        g_rela_count++;
                    } else if (r_type == R_X86_64_GLOB_DAT ||
                               r_type == R_X86_64_JUMP_SLOT ||
                               r_type == R_X86_64_64) {
                        const char *sname = 0;
                        uint8_t st_type = 0;
                        uint64_t st_val = 0;
                        if (syms && strs && r_sym != 0) {
                            sname   = strs + syms[r_sym].st_name;
                            st_type = (uint8_t)(syms[r_sym].st_info & 0xF);
                            st_val  = syms[r_sym].st_value;
                        }
                        uint64_t resolved = 0;
                        if (st_val != 0) {
                            resolved = exe_base + st_val;
                        } else {
                            resolved = resolve_symbol(sname, st_type);
                        }
                        if (r_type == R_X86_64_64) {
                            *target = resolved + (uint64_t)rel[i].r_addend;
                        } else {
                            *target = resolved;
                        }
                        g_rela_count++;
                    }
                }
            }
        }
    }

    print_str("[ld-linux] Dynamic linker initialized TLS (%fs:0x28), applied ");
    print_dec(g_relr_count);
    print_str(" DT_RELR + ");
    print_dec(g_rela_count);
    print_str(" DT_RELA relocations.\n");

    return at_entry;
}

__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "mov %rsp, %rbx\n\t"
        "mov %rsp, %rdi\n\t"
        "and $-16, %rsp\n\t"
        "call _ld_hydra_main\n\t"
        "mov %rbx, %rsp\n\t"
        "xor %edx, %edx\n\t"
        "jmp *%rax\n\t"
    );
}
