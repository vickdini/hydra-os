// ALSA kernel interface as libasound, PipeWire and Wine use it, with raw ioctls on
// /dev/snd/controlC0 and /dev/snd/pcmC0D0p (pcmC0D0c when present):
// - control: version, card info, element list/info/read/write, the dB scale (TLV),
//   change events (subscribe, poll, read), PCM device enumeration and info;
// - playback: exclusive open, HW_REFINE narrows to what the device takes, HW_PARAMS,
//   SW_PARAMS, PREPARE, WRITEI_FRAMES (starts at the start threshold), the hardware
//   pointer advancing in real time, poll for room, DELAY, DRAIN;
// - mmap access: the ring maps at offset 0, the status page does not (SYNC_PTR then),
//   appl_ptr through SYNC_PTR, START, DROP; an underrun gives XRUN and -EPIPE;
// - /proc/asound/card0/pcm0p/sub0/status says "closed" only when nobody has it open;
// - capture: READI_FRAMES returns frames in real time.
// Without a sound card it prints SKIP and passes. Sound goes out (a 440 Hz tone, about
// 1.5 s): run under QEMU with -audiodev wav to record it.
// Passes on Linux (snd-hda-intel, 48 kHz S16_LE stereo; device busy if PipeWire holds it).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <sound/asound.h>
#ifndef SNDRV_CTL_TLVT_DB_SCALE
#define SNDRV_CTL_TLVT_DB_SCALE 1
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static int fails;
static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    fflush(stdout);
    if (!ok) fails++;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static struct snd_mask *mask(struct snd_pcm_hw_params *p, int n) { return &p->masks[n - SNDRV_PCM_HW_PARAM_FIRST_MASK]; }
static struct snd_interval *iv(struct snd_pcm_hw_params *p, int n) { return &p->intervals[n - SNDRV_PCM_HW_PARAM_FIRST_INTERVAL]; }

static void any_params(struct snd_pcm_hw_params *p) {
    memset(p, 0, sizeof *p);
    for (int n = SNDRV_PCM_HW_PARAM_FIRST_MASK; n <= SNDRV_PCM_HW_PARAM_LAST_MASK; n++) memset(mask(p, n), 0xff, sizeof(struct snd_mask));
    for (int n = SNDRV_PCM_HW_PARAM_FIRST_INTERVAL; n <= SNDRV_PCM_HW_PARAM_LAST_INTERVAL; n++) {
        iv(p, n)->min = 0;
        iv(p, n)->max = ~0u;
    }
    p->rmask = ~0u;
    p->info = ~0u;
}

static void set_mask(struct snd_pcm_hw_params *p, int n, unsigned bit) {
    memset(mask(p, n), 0, sizeof(struct snd_mask));
    mask(p, n)->bits[bit / 32] = 1u << (bit % 32);
}

static void set_iv(struct snd_pcm_hw_params *p, int n, unsigned v) {
    iv(p, n)->min = iv(p, n)->max = v;
    iv(p, n)->openmin = iv(p, n)->openmax = 0;
    iv(p, n)->integer = 1;
}

static int single(struct snd_pcm_hw_params *p, int n) { return iv(p, n)->min == iv(p, n)->max; }

static int setup(int fd, int access, unsigned period, unsigned periods) {
    struct snd_pcm_hw_params p;
    any_params(&p);
    set_mask(&p, SNDRV_PCM_HW_PARAM_ACCESS, access);
    set_mask(&p, SNDRV_PCM_HW_PARAM_FORMAT, SNDRV_PCM_FORMAT_S16_LE);
    set_iv(&p, SNDRV_PCM_HW_PARAM_CHANNELS, 2);
    set_iv(&p, SNDRV_PCM_HW_PARAM_RATE, 48000);
    set_iv(&p, SNDRV_PCM_HW_PARAM_PERIOD_SIZE, period);
    set_iv(&p, SNDRV_PCM_HW_PARAM_PERIODS, periods);
    if (ioctl(fd, SNDRV_PCM_IOCTL_HW_PARAMS, &p) < 0) return -errno;
    if (iv(&p, SNDRV_PCM_HW_PARAM_BUFFER_SIZE)->min != period * periods) return -1000;
    if (!single(&p, SNDRV_PCM_HW_PARAM_PERIOD_TIME) && iv(&p, SNDRV_PCM_HW_PARAM_PERIOD_TIME)->max - iv(&p, SNDRV_PCM_HW_PARAM_PERIOD_TIME)->min > 1) return -1001;
    if (p.rate_num != 48000 || p.rate_den != 1 || p.msbits != 16) return -1002;
    struct snd_pcm_sw_params sw;
    memset(&sw, 0, sizeof sw);
    sw.avail_min = period;
    sw.start_threshold = period * periods;
    sw.stop_threshold = period * periods;
    sw.boundary = 0;
    sw.proto = SNDRV_PCM_VERSION;
    if (ioctl(fd, SNDRV_PCM_IOCTL_SW_PARAMS, &sw) < 0) return -errno;
    if (sw.boundary < period * periods) return -1003;
    return 0;
}

static int state(int fd) {
    struct snd_pcm_status st;
    memset(&st, 0, sizeof st);
    if (ioctl(fd, SNDRV_PCM_IOCTL_STATUS, &st) < 0) return -errno;
    return st.state;
}

static unsigned long hw_ptr(int fd) {
    struct snd_pcm_status st;
    memset(&st, 0, sizeof st);
    ioctl(fd, SNDRV_PCM_IOCTL_STATUS, &st);
    return st.hw_ptr;
}

static void proc_status(char *out, size_t n) {
    out[0] = 0;
    int f = open("/proc/asound/card0/pcm0p/sub0/status", O_RDONLY);
    if (f < 0) return;
    ssize_t r = read(f, out, n - 1);
    out[r > 0 ? r : 0] = 0;
    close(f);
}

// Fills `frames` stereo frames of a 440 Hz tone at 48 kHz, continuing phase `*ph`.
static void tone(short *buf, int frames, double *ph) {
    for (int i = 0; i < frames; i++) {
        short v = (short)(12000 * sin(*ph));
        buf[2 * i] = buf[2 * i + 1] = v;
        *ph += 2 * M_PI * 440 / 48000;
    }
}

static int find_elem(int ctl, const char *name, struct snd_ctl_elem_id *out) {
    struct snd_ctl_elem_id ids[64];
    struct snd_ctl_elem_list list;
    memset(&list, 0, sizeof list);
    list.space = 64;
    list.pids = ids;
    if (ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_LIST, &list) < 0) return -1;
    for (unsigned i = 0; i < list.used; i++)
        if (!strcmp((char *)ids[i].name, name)) {
            *out = ids[i];
            return list.count;
        }
    return -1;
}

static void control_tests(int ctl) {
    int ver = 0;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_PVERSION, &ver) == 0 && ver >= SNDRV_PROTOCOL_VERSION(2, 0, 0), "control: PVERSION");
    struct snd_ctl_card_info ci;
    memset(&ci, 0, sizeof ci);
    check(ioctl(ctl, SNDRV_CTL_IOCTL_CARD_INFO, &ci) == 0 && ci.card == 0 && ci.driver[0] && ci.name[0], "control: CARD_INFO");
    printf("     card: id '%s' driver '%s' name '%s' mixer '%s'\n", ci.id, ci.driver, ci.name, ci.mixername);

    int dev = -1;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE, &dev) == 0 && dev == 0, "control: PCM_NEXT_DEVICE finds device 0");
    check(ioctl(ctl, SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE, &dev) == 0 && dev == -1, "control: PCM_NEXT_DEVICE ends after it");
    struct snd_pcm_info pi;
    memset(&pi, 0, sizeof pi);
    pi.stream = SNDRV_PCM_STREAM_PLAYBACK;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_PCM_INFO, &pi) == 0 && pi.subdevices_count == 1 && pi.id[0], "control: PCM_INFO playback");

    struct snd_ctl_elem_id id;
    int count = find_elem(ctl, "Master Playback Volume", &id);
    check(count >= 2, "control: ELEM_LIST has Master Playback Volume");
    if (count < 2) return;
    struct snd_ctl_elem_info info;
    memset(&info, 0, sizeof info);
    info.id.numid = id.numid;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_INFO, &info) == 0 && info.type == SNDRV_CTL_ELEM_TYPE_INTEGER && info.count == 2 && info.value.integer.max > 0,
          "control: ELEM_INFO volume (integer, 2 channels)");
    // By name, as libasound's mixer looks elements up
    struct snd_ctl_elem_info byname;
    memset(&byname, 0, sizeof byname);
    byname.id.iface = SNDRV_CTL_ELEM_IFACE_MIXER;
    strcpy((char *)byname.id.name, "Master Playback Switch");
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_INFO, &byname) == 0 && byname.type == SNDRV_CTL_ELEM_TYPE_BOOLEAN && byname.id.numid != 0,
          "control: ELEM_INFO by name (Master Playback Switch)");

    struct {
        struct snd_ctl_tlv hdr;
        unsigned int data[8];
    } tlv;
    memset(&tlv, 0, sizeof tlv);
    tlv.hdr.numid = id.numid;
    tlv.hdr.length = sizeof tlv.data;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_TLV_READ, &tlv) == 0 && tlv.data[0] == SNDRV_CTL_TLVT_DB_SCALE && tlv.data[1] == 8 && (int)tlv.data[2] < 0,
          "control: TLV_READ gives a dB scale");

    struct snd_ctl_elem_value v;
    memset(&v, 0, sizeof v);
    v.id.numid = id.numid;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_READ, &v) == 0 && v.value.integer.value[0] >= 0, "control: ELEM_READ");
    long old = v.value.integer.value[0];
    int sub = 1;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS, &sub) == 0, "control: SUBSCRIBE_EVENTS");
    long want = old > 0 ? old - 1 : old + 1;
    v.value.integer.value[0] = v.value.integer.value[1] = want;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_WRITE, &v) >= 0, "control: ELEM_WRITE");
    memset(&v.value, 0, sizeof v.value);
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_READ, &v) == 0 && v.value.integer.value[0] == want && v.value.integer.value[1] == want, "control: the value written reads back");
    struct pollfd pfd = {ctl, POLLIN, 0};
    check(poll(&pfd, 1, 1000) == 1, "control: poll reports the change event");
    struct snd_ctl_event ev;
    check(read(ctl, &ev, sizeof ev) == sizeof ev && ev.type == SNDRV_CTL_EVENT_ELEM && (ev.data.elem.mask & SNDRV_CTL_EVENT_MASK_VALUE) &&
              ev.data.elem.id.numid == id.numid,
          "control: read gives the value event");
    v.value.integer.value[0] = info.value.integer.max + 1;
    check(ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_WRITE, &v) < 0 && errno == EINVAL, "control: a value out of range is refused");
    v.value.integer.value[0] = v.value.integer.value[1] = old;
    ioctl(ctl, SNDRV_CTL_IOCTL_ELEM_WRITE, &v);
}

static void playback_tests(void) {
    int fd = open("/dev/snd/pcmC0D0p", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    check(fd >= 0, "playback: open pcmC0D0p");
    if (fd < 0) {
        printf("     open: %s\n", strerror(errno));
        return;
    }
    int fd2 = open("/dev/snd/pcmC0D0p", O_RDWR | O_NONBLOCK);
    check(fd2 < 0 && errno == EBUSY, "playback: a second open is busy");
    if (fd2 >= 0) close(fd2);
    char text[256];
    proc_status(text, sizeof text);
    check(strncmp(text, "closed", 6) != 0, "playback: /proc/asound status shows it open");

    int ver = 0;
    check(ioctl(fd, SNDRV_PCM_IOCTL_PVERSION, &ver) == 0 && ver >= SNDRV_PROTOCOL_VERSION(2, 0, 12), "playback: PVERSION");
    struct snd_pcm_info pi;
    memset(&pi, 0, sizeof pi);
    check(ioctl(fd, SNDRV_PCM_IOCTL_INFO, &pi) == 0 && pi.stream == SNDRV_PCM_STREAM_PLAYBACK, "playback: INFO");
    int tt = SNDRV_PCM_TSTAMP_TYPE_MONOTONIC;
    check(ioctl(fd, SNDRV_PCM_IOCTL_TTSTAMP, &tt) == 0, "playback: TTSTAMP monotonic");

    struct snd_pcm_hw_params p;
    any_params(&p);
    check(ioctl(fd, SNDRV_PCM_IOCTL_HW_REFINE, &p) == 0, "playback: HW_REFINE of everything");
    struct snd_interval *ch = iv(&p, SNDRV_PCM_HW_PARAM_CHANNELS), *rate = iv(&p, SNDRV_PCM_HW_PARAM_RATE);
    printf("     refined: channels %u-%u rate %u-%u period bytes %u-%u periods %u-%u buffer bytes %u-%u info %#x\n", ch->min, ch->max, rate->min,
           rate->max, iv(&p, SNDRV_PCM_HW_PARAM_PERIOD_BYTES)->min, iv(&p, SNDRV_PCM_HW_PARAM_PERIOD_BYTES)->max, iv(&p, SNDRV_PCM_HW_PARAM_PERIODS)->min,
           iv(&p, SNDRV_PCM_HW_PARAM_PERIODS)->max, iv(&p, SNDRV_PCM_HW_PARAM_BUFFER_BYTES)->min, iv(&p, SNDRV_PCM_HW_PARAM_BUFFER_BYTES)->max, p.info);
    check(rate->min <= 48000 && rate->max >= 48000 && ch->min <= 2 && ch->max >= 2 && (mask(&p, SNDRV_PCM_HW_PARAM_FORMAT)->bits[0] & (1u << SNDRV_PCM_FORMAT_S16_LE)) &&
              (p.info & SNDRV_PCM_INFO_MMAP) && p.cmask != 0,
          "playback: the refined space has 48 kHz S16_LE stereo and mmap");
    // A rate between two the device takes refines to the next one up
    any_params(&p);
    iv(&p, SNDRV_PCM_HW_PARAM_RATE)->min = 46000;
    iv(&p, SNDRV_PCM_HW_PARAM_RATE)->max = 50000;
    check(ioctl(fd, SNDRV_PCM_IOCTL_HW_REFINE, &p) == 0 && iv(&p, SNDRV_PCM_HW_PARAM_RATE)->min == 48000 && iv(&p, SNDRV_PCM_HW_PARAM_RATE)->max == 48000,
          "playback: HW_REFINE snaps a rate range to 48000");
    any_params(&p);
    set_iv(&p, SNDRV_PCM_HW_PARAM_CHANNELS, 7);
    check(ioctl(fd, SNDRV_PCM_IOCTL_HW_REFINE, &p) < 0 && errno == EINVAL, "playback: HW_REFINE refuses 7 channels");

    check(ioctl(fd, SNDRV_PCM_IOCTL_PREPARE) < 0 && errno == EBADFD, "playback: PREPARE before HW_PARAMS is EBADFD");
    int r = setup(fd, SNDRV_PCM_ACCESS_RW_INTERLEAVED, 1024, 8);
    check(r == 0, "playback: HW_PARAMS + SW_PARAMS (RW, 1024 x 8 frames)");
    if (r) printf("     setup: %d\n", r);
    check(state(fd) == SNDRV_PCM_STATE_SETUP, "playback: state SETUP");
    proc_status(text, sizeof text);
    check(ioctl(fd, SNDRV_PCM_IOCTL_PREPARE) == 0 && state(fd) == SNDRV_PCM_STATE_PREPARED, "playback: PREPARE");

    // Fill the buffer: the stream starts at the start threshold (the whole buffer)
    static short buf[48000 * 2];
    double ph = 0;
    tone(buf, 8192, &ph);
    struct snd_xferi x = {0, buf, 8192};
    check(ioctl(fd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &x) == 0 && x.result == 8192, "playback: WRITEI_FRAMES fills the buffer");
    check(state(fd) == SNDRV_PCM_STATE_RUNNING, "playback: running after the start threshold");

    // One second of tone, written as room appears
    double t0 = now();
    unsigned long h0 = hw_ptr(fd);
    long written = 0, polls = 0;
    while (written < 48000) {
        struct pollfd pfd = {fd, POLLOUT, 0};
        if (poll(&pfd, 1, 1000) != 1 || !(pfd.revents & POLLOUT)) break;
        polls++;
        tone(buf, 1024, &ph);
        x.buf = buf;
        x.frames = 1024;
        x.result = 0;
        if (ioctl(fd, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &x) < 0) {
            printf("     write: %s\n", strerror(errno));
            break;
        }
        written += x.result;
    }
    double dt = now() - t0;
    unsigned long played = hw_ptr(fd) - h0;
    printf("     wrote %ld frames in %.2f s (%ld polls), hardware advanced %lu frames\n", written, dt, polls, played);
    check(written >= 48000, "playback: poll + WRITEI_FRAMES kept the stream fed for a second");
    check(dt > 0.6 && dt < 1.6 && played > 48000 * dt * 0.7 && played < 48000 * dt * 1.3, "playback: the hardware pointer advances at 48 kHz");
    snd_pcm_sframes_t delay = -1;
    check(ioctl(fd, SNDRV_PCM_IOCTL_DELAY, &delay) == 0 && delay >= 0 && delay <= 8192, "playback: DELAY within the buffer");
    struct snd_pcm_status st;
    memset(&st, 0, sizeof st);
    check(ioctl(fd, SNDRV_PCM_IOCTL_STATUS, &st) == 0 && st.state == SNDRV_PCM_STATE_RUNNING && st.avail <= 8192 && st.tstamp.tv_sec > 0, "playback: STATUS");
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    t0 = now();
    check(ioctl(fd, SNDRV_PCM_IOCTL_DRAIN) == 0 && state(fd) == SNDRV_PCM_STATE_SETUP, "playback: DRAIN plays out and stops");
    dt = now() - t0;
    check(dt < 0.6, "playback: DRAIN took less than the buffer and a bit");
    fcntl(fd, F_SETFL, fl);

    // mmap access, as PipeWire uses it
    r = setup(fd, SNDRV_PCM_ACCESS_MMAP_INTERLEAVED, 4096, 4);
    check(r == 0, "mmap: HW_PARAMS with MMAP_INTERLEAVED");
    void *st_page = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, SNDRV_PCM_MMAP_OFFSET_STATUS);
    check(st_page == MAP_FAILED, "mmap: the status page is not mappable (SYNC_PTR instead)");
    short *ring = mmap(NULL, 16384 * 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    check(ring != MAP_FAILED, "mmap: the ring maps at offset 0");
    struct snd_pcm_channel_info ci = {.channel = 1};
    check(ioctl(fd, SNDRV_PCM_IOCTL_CHANNEL_INFO, &ci) == 0 && ci.first == 16 && ci.step == 32, "mmap: CHANNEL_INFO (interleaved)");
    check(ioctl(fd, SNDRV_PCM_IOCTL_PREPARE) == 0, "mmap: PREPARE");
    if (ring != MAP_FAILED) {
        tone(ring, 16384, &ph);
        struct snd_pcm_sync_ptr sp;
        memset(&sp, 0, sizeof sp);
        sp.c.control.appl_ptr = 16384;
        sp.c.control.avail_min = 1024;
        check(ioctl(fd, SNDRV_PCM_IOCTL_SYNC_PTR, &sp) == 0 && sp.s.status.state == SNDRV_PCM_STATE_PREPARED && sp.c.control.appl_ptr == 16384,
              "mmap: SYNC_PTR sets appl_ptr");
        check(ioctl(fd, SNDRV_PCM_IOCTL_START) == 0, "mmap: START");
        unsigned long appl = 16384;
        double start = now(), end = start + 0.5;
        int iters = 0;
        // Keep it fed for half a second through the mapping
        while (now() < end) {
            usleep(10000);
            memset(&sp, 0, sizeof sp);
            sp.flags = SNDRV_PCM_SYNC_PTR_HWSYNC | SNDRV_PCM_SYNC_PTR_APPL | SNDRV_PCM_SYNC_PTR_AVAIL_MIN;
            iters++;
            if (ioctl(fd, SNDRV_PCM_IOCTL_SYNC_PTR, &sp) < 0 || sp.s.status.state != SNDRV_PCM_STATE_RUNNING) {
                printf("     mmap: stopped after %d iterations, %.3f s: hw_ptr %lu state %d\n", iters, now() - start, (unsigned long)sp.s.status.hw_ptr, sp.s.status.state);
                break;
            }
            unsigned long room = sp.s.status.hw_ptr + 16384 - appl;
            while (room >= 512) {
                tone(ring + 2 * (appl % 16384), 512, &ph);
                appl += 512;
                room -= 512;
            }
            memset(&sp, 0, sizeof sp);
            sp.c.control.appl_ptr = appl;
            sp.c.control.avail_min = 4096;
            ioctl(fd, SNDRV_PCM_IOCTL_SYNC_PTR, &sp);
        }
        memset(&sp, 0, sizeof sp);
        sp.flags = SNDRV_PCM_SYNC_PTR_HWSYNC | SNDRV_PCM_SYNC_PTR_APPL | SNDRV_PCM_SYNC_PTR_AVAIL_MIN;
        ioctl(fd, SNDRV_PCM_IOCTL_SYNC_PTR, &sp);
        printf("     mmap: hw_ptr %lu appl_ptr %lu state %d\n", (unsigned long)sp.s.status.hw_ptr, (unsigned long)sp.c.control.appl_ptr, sp.s.status.state);
        check(sp.s.status.state == SNDRV_PCM_STATE_RUNNING && sp.s.status.hw_ptr > 48000 / 4 && sp.c.control.appl_ptr == appl,
              "mmap: fed through the mapping for 0.5 s without an underrun");
        // Stop feeding: the stream runs dry
        usleep(600000);
        check(state(fd) == SNDRV_PCM_STATE_XRUN, "mmap: an underrun stops the stream (XRUN)");
        check(ioctl(fd, SNDRV_PCM_IOCTL_HWSYNC) < 0 && errno == EPIPE, "mmap: HWSYNC reports the underrun (EPIPE)");
        check(ioctl(fd, SNDRV_PCM_IOCTL_DROP) == 0 && state(fd) == SNDRV_PCM_STATE_SETUP, "mmap: DROP");
        munmap(ring, 16384 * 4);
    }
    // PAUSE is not offered (QEMU restarts a stream from the start of its ring)
    check(ioctl(fd, SNDRV_PCM_IOCTL_PAUSE, 1) < 0 && errno == ENOSYS, "playback: PAUSE is not supported (ENOSYS)");
    check(ioctl(fd, SNDRV_PCM_IOCTL_HW_FREE) == 0 && state(fd) == SNDRV_PCM_STATE_OPEN, "playback: HW_FREE");
    close(fd);
    proc_status(text, sizeof text);
    check(strncmp(text, "closed", 6) == 0, "playback: /proc/asound status says closed after close");
}

static void capture_tests(void) {
    int fd = open("/dev/snd/pcmC0D0c", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        printf("     no capture device (%s)\n", strerror(errno));
        return;
    }
    check(setup(fd, SNDRV_PCM_ACCESS_RW_INTERLEAVED, 1024, 8) == 0, "capture: HW_PARAMS + SW_PARAMS");
    check(ioctl(fd, SNDRV_PCM_IOCTL_PREPARE) == 0, "capture: PREPARE");
    static short buf[9600 * 2];
    struct snd_xferi x = {0, buf, 1024};
    // The first read starts the stream (nothing to read yet)
    check(ioctl(fd, SNDRV_PCM_IOCTL_READI_FRAMES, &x) < 0 && errno == EAGAIN && state(fd) == SNDRV_PCM_STATE_RUNNING, "capture: the first read starts it");
    double t0 = now();
    long got = 0;
    while (got < 9600 && now() < t0 + 1.0) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, 300) != 1) continue;
        x.buf = buf;
        x.frames = 9600 - got;
        if (ioctl(fd, SNDRV_PCM_IOCTL_READI_FRAMES, &x) == 0) got += x.result;
    }
    double dt = now() - t0;
    printf("     capture: %ld frames in %.3f s\n", got, dt);
    if (got == 0)
        printf("     capture: the hardware delivered nothing (QEMU audio backend without input?)\n");
    else
        check(got == 9600 && dt > 0.12 && dt < 0.6, "capture: frames arrive in real time");
    ioctl(fd, SNDRV_PCM_IOCTL_DROP);
    close(fd);
}

int main(void) {
    int ctl = open("/dev/snd/controlC0", O_RDWR | O_CLOEXEC);
    if (ctl < 0) {
        printf("SKIP: no sound card (%s)\n", strerror(errno));
        return 0;
    }
    control_tests(ctl);
    playback_tests();
    capture_tests();
    close(ctl);
    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}
