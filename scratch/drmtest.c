/* drmtest: the KMS and evdev interfaces Hydra offers to compositors (static, no libdrm). */
#define _GNU_SOURCE
#include <drm/drm.h>
#include <drm/drm_mode.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/netlink.h>

static int failures;
#define CHECK(cond, what) do { int ok_ = (cond); printf("[drmtest] %-52s %s\n", what, ok_ ? "PASS" : "FAIL"); if (!ok_) { failures++; printf("           errno=%d (%s)\n", errno, strerror(errno)); } } while (0)

int main(void) {
    int fd = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0, "open /dev/dri/card0");
    if (fd < 0) return 1;
    struct stat st;
    CHECK(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 226, "fstat: char device 226:0");
    CHECK(access("/sys/dev/char/226:0/device/drm", F_OK) == 0, "sysfs /sys/dev/char/226:0/device/drm");

    char name[64] = {0};
    struct drm_version v = {.name_len = sizeof name - 1, .name = name};
    CHECK(ioctl(fd, DRM_IOCTL_VERSION, &v) == 0 && strcmp(name, "hydradrm") == 0, "DRM_IOCTL_VERSION name hydradrm");

    struct drm_get_cap cap = {.capability = DRM_CAP_DUMB_BUFFER};
    CHECK(ioctl(fd, DRM_IOCTL_GET_CAP, &cap) == 0 && cap.value == 1, "GET_CAP DUMB_BUFFER = 1");
    struct drm_set_client_cap cc = {.capability = DRM_CLIENT_CAP_ATOMIC, .value = 1};
    CHECK(ioctl(fd, DRM_IOCTL_SET_CLIENT_CAP, &cc) != 0, "SET_CLIENT_CAP ATOMIC refused");
    cc.capability = DRM_CLIENT_CAP_UNIVERSAL_PLANES;
    CHECK(ioctl(fd, DRM_IOCTL_SET_CLIENT_CAP, &cc) == 0, "SET_CLIENT_CAP UNIVERSAL_PLANES");

    struct drm_mode_card_res res = {0};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0 && res.count_crtcs == 1 && res.count_connectors == 1, "GETRESOURCES counts");
    uint32_t crtc_id, conn_id, enc_id;
    res.crtc_id_ptr = (uintptr_t)&crtc_id;
    res.connector_id_ptr = (uintptr_t)&conn_id;
    res.encoder_id_ptr = (uintptr_t)&enc_id;
    res.count_fbs = 0;
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) == 0, "GETRESOURCES ids");

    struct drm_mode_get_connector conn = {.connector_id = conn_id};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) == 0 && conn.count_modes == 1 && conn.connection == 1, "GETCONNECTOR connected, 1 mode");
    struct drm_mode_modeinfo mode;
    uint32_t props[8];
    uint64_t vals[8];
    uint32_t encs[2];
    conn.modes_ptr = (uintptr_t)&mode;
    conn.props_ptr = (uintptr_t)props;
    conn.prop_values_ptr = (uintptr_t)vals;
    conn.encoders_ptr = (uintptr_t)encs;
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) == 0 && mode.hdisplay > 0, "GETCONNECTOR mode");
    printf("[drmtest] mode %s %ux%u@%u, %u props\n", mode.name, mode.hdisplay, mode.vdisplay, mode.vrefresh, conn.count_props);
    struct drm_mode_get_property gp = {.prop_id = props[0]};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETPROPERTY, &gp) == 0 && strcmp(gp.name, "DPMS") == 0, "GETPROPERTY DPMS");

    struct drm_mode_create_dumb cd = {.width = mode.hdisplay, .height = mode.vdisplay, .bpp = 32};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) == 0 && cd.pitch >= cd.width * 4, "CREATE_DUMB");
    struct drm_mode_map_dumb md = {.handle = cd.handle};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &md) == 0, "MAP_DUMB");
    uint32_t *px = mmap(NULL, cd.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, md.offset);
    CHECK(px != MAP_FAILED, "mmap dumb buffer");
    for (uint32_t y = 0; y < cd.height; y++)
        for (uint32_t x = 0; x < cd.width; x++)
            px[y * (cd.pitch / 4) + x] = 0xff000000 | ((x * 255 / cd.width) << 16) | ((y * 255 / cd.height) << 8) | 0x40;
    /* A second mapping sees the same pages */
    uint32_t *px2 = mmap(NULL, cd.size, PROT_READ, MAP_SHARED, fd, md.offset);
    CHECK(px2 != MAP_FAILED && px2[1234] == px[1234], "second mapping shares pages");

    struct drm_mode_fb_cmd2 fb = {.width = cd.width, .height = cd.height, .pixel_format = 0x34325258};
    fb.handles[0] = cd.handle;
    fb.pitches[0] = cd.pitch;
    CHECK(ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &fb) == 0 && fb.fb_id != 0, "ADDFB2 XRGB8888");

    struct drm_mode_crtc crtc = {.crtc_id = crtc_id, .fb_id = fb.fb_id, .set_connectors_ptr = (uintptr_t)&conn_id, .count_connectors = 1, .mode = mode, .mode_valid = 1};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0, "SETCRTC (gradient on screen)");
    struct drm_mode_crtc got = {.crtc_id = crtc_id};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_GETCRTC, &got) == 0 && got.fb_id == fb.fb_id && got.mode_valid, "GETCRTC reports the framebuffer");

    /* Cursor: a 64x64 white square with a black border */
    struct drm_mode_create_dumb cur = {.width = 64, .height = 64, .bpp = 32};
    ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &cur);
    struct drm_mode_map_dumb cm = {.handle = cur.handle};
    ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &cm);
    uint32_t *cp = mmap(NULL, cur.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, cm.offset);
    for (int i = 0; i < 64 * 64; i++) {
        int x = i % 64, y = i / 64;
        cp[i] = (x < 24 && y < 24) ? ((x == 0 || y == 0 || x == 23 || y == 23) ? 0xff000000 : 0xffffffff) : 0;
    }
    struct drm_mode_cursor2 c2 = {.flags = DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE, .crtc_id = crtc_id, .x = 100, .y = 100, .width = 64, .height = 64, .handle = cur.handle};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_CURSOR2, &c2) == 0, "MODE_CURSOR2 set + move");

    struct drm_mode_crtc_page_flip pf = {.crtc_id = crtc_id, .fb_id = fb.fb_id, .flags = DRM_MODE_PAGE_FLIP_EVENT, .user_data = 0x1234};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_PAGE_FLIP, &pf) == 0, "PAGE_FLIP with event");
    struct pollfd p = {.fd = fd, .events = POLLIN};
    CHECK(poll(&p, 1, 1000) == 1, "poll: flip event ready");
    char evbuf[64];
    ssize_t n = read(fd, evbuf, sizeof evbuf);
    struct drm_event_vblank *ev = (void *)evbuf;
    CHECK(n == 32 && ev->base.type == DRM_EVENT_FLIP_COMPLETE && ev->user_data == 0x1234, "read FLIP_COMPLETE event");

    /* evdev */
    int kbd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    CHECK(kbd >= 0, "open /dev/input/event0");
    char kname[128] = {0};
    CHECK(ioctl(kbd, EVIOCGNAME(sizeof kname), kname) > 0 && strstr(kname, "keyboard"), "EVIOCGNAME keyboard");
    unsigned long evbits[1] = {0};
    CHECK(ioctl(kbd, EVIOCGBIT(0, sizeof evbits), evbits) > 0 && (evbits[0] & (1 << EV_KEY)), "EVIOCGBIT EV_KEY");
    unsigned char keys[KEY_MAX / 8 + 1] = {0};
    CHECK(ioctl(kbd, EVIOCGBIT(EV_KEY, sizeof keys), keys) > 0 && (keys[KEY_A / 8] & (1 << (KEY_A % 8))), "EVIOCGBIT has KEY_A");
    struct input_event ie;
    CHECK(read(kbd, &ie, sizeof ie) < 0 && errno == EAGAIN, "nonblocking read: EAGAIN");
    int mouse = open("/dev/input/event1", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    unsigned long relbits[1] = {0};
    CHECK(mouse >= 0 && ioctl(mouse, EVIOCGBIT(EV_REL, sizeof relbits), relbits) > 0 && (relbits[0] & 3) == 3, "event1: REL_X and REL_Y");
    struct input_id id;
    CHECK(ioctl(mouse, EVIOCGID, &id) == 0 && id.bustype == BUS_I8042, "EVIOCGID bus i8042");

    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
    struct sockaddr_nl sa = {.nl_family = AF_NETLINK, .nl_groups = 2};
    CHECK(nl >= 0 && bind(nl, (void *)&sa, sizeof sa) == 0, "netlink uevent socket binds");
    CHECK(recv(nl, evbuf, sizeof evbuf, 0) < 0 && errno == EAGAIN, "netlink recv: EAGAIN");
    CHECK(access("/run/udev/data/c13:64", R_OK) == 0, "udev db c13:64");

    printf("[drmtest] showing the gradient for 3 s (move the mouse to see the cursor)\n");
    fflush(stdout);
    for (int i = 0; i < 30; i++) {
        struct input_event me[16];
        ssize_t r = read(mouse, me, sizeof me);
        for (int k = 0; r > 0 && k < r / (int)sizeof me[0]; k++) {
            if (me[k].type == EV_REL && me[k].code == REL_X) c2.x += me[k].value;
            if (me[k].type == EV_REL && me[k].code == REL_Y) c2.y += me[k].value;
            if (me[k].type == EV_KEY) printf("[drmtest] mouse key %u = %d\n", me[k].code, me[k].value);
        }
        r = read(kbd, me, sizeof me);
        for (int k = 0; r > 0 && k < r / (int)sizeof me[0]; k++)
            if (me[k].type == EV_KEY) printf("[drmtest] key %u = %d\n", me[k].code, me[k].value);
        c2.flags = DRM_MODE_CURSOR_MOVE;
        ioctl(fd, DRM_IOCTL_MODE_CURSOR2, &c2);
        usleep(100000);
    }
    printf("[drmtest] cursor ended at %d,%d\n", c2.x, c2.y);
    printf(failures ? "[drmtest] %d FAILED\n" : "[drmtest] ALL PASSED (%d failures)\n", failures);
    return failures != 0;
}
