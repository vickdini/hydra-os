//! THROWAWAY measurement hooks for Group 15 (wave 5): display, input, sound and terminal
//! call rates, page-flip cost, input latency. Never merged: tools/displaybench/instrument.py
//! copies it into a tree for a measurement build. From the first DRM or PCM call on, a
//! kernel task prints one `[dstat]` block on the serial port every 5 s.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};

pub static DRM_IOCTL: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
pub static DRM_READ: AtomicU64 = AtomicU64::new(0);
pub static DRM_POLL: AtomicU64 = AtomicU64::new(0);
pub static EV_READ: AtomicU64 = AtomicU64::new(0);
pub static EV_READ_EMPTY: AtomicU64 = AtomicU64::new(0);
pub static EV_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static EV_IOCTL: AtomicU64 = AtomicU64::new(0);
pub static EV_POLL: AtomicU64 = AtomicU64::new(0);
pub static RAW_IN: AtomicU64 = AtomicU64::new(0);
pub static PCM_IOCTL: [AtomicU64; 256] = [const { AtomicU64::new(0) }; 256];
pub static PCM_POLL: AtomicU64 = AtomicU64::new(0);
pub static CTL_IOCTL: AtomicU64 = AtomicU64::new(0);
pub static CTL_READ: AtomicU64 = AtomicU64::new(0);
pub static XRUNS: AtomicU64 = AtomicU64::new(0);
pub static POS_WAKES: AtomicU64 = AtomicU64::new(0);
pub static TTY_OPS: AtomicU64 = AtomicU64::new(0);
pub static PTY_OPS: AtomicU64 = AtomicU64::new(0);

/// Page flips (PAGE_FLIP, SETCRTC with a framebuffer, DIRTYFB on the scanout), and the
/// time spent copying the picture to the screen (`present`), total and max.
pub static FLIPS: AtomicU64 = AtomicU64::new(0);
pub static PRESENT_NS: AtomicU64 = AtomicU64::new(0);
pub static PRESENT_MAX: AtomicU64 = AtomicU64::new(0);
pub static PRESENTS: AtomicU64 = AtomicU64::new(0);
pub static CURSOR_NS: AtomicU64 = AtomicU64::new(0);
pub static CURSORS: AtomicU64 = AtomicU64::new(0);
static LAST_FLIP: AtomicU64 = AtomicU64::new(0);
/// Intervals between page flips: <10, <17, <20, <34, <50, <100, <1000 ms, more.
pub static FLIP_GAP: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];

/// Input latency: the time of the oldest raw input not yet read by an evdev reader, and
/// of the oldest input read but not yet followed by a flip / a cursor update.
static PENDING_IN: AtomicU64 = AtomicU64::new(0);
static PENDING_FLIP: AtomicU64 = AtomicU64::new(0);
static PENDING_CUR: AtomicU64 = AtomicU64::new(0);
/// [count, sum ns, max ns] for irq->read, irq->flip, irq->cursor.
pub static LAT: [[AtomicU64; 3]; 3] = [const { [const { AtomicU64::new(0) }; 3] }; 3];
/// Histogram per kind: <100us, <1ms, <5ms, <17ms, <34ms, <100ms, more.
pub static LAT_H: [[AtomicU64; 7]; 3] = [const { [const { AtomicU64::new(0) }; 7] }; 3];

static STARTED: AtomicBool = AtomicBool::new(false);

fn now() -> u64 {
    crate::arch::pit::now_ns()
}

fn lat(kind: usize, t0: u64) {
    let d = now().saturating_sub(t0);
    LAT[kind][0].fetch_add(1, Relaxed);
    LAT[kind][1].fetch_add(d, Relaxed);
    LAT[kind][2].fetch_max(d, Relaxed);
    let us = d / 1000;
    let b = [100, 1000, 5000, 17000, 34000, 100000].iter().position(|&l| us < l).unwrap_or(6);
    LAT_H[kind][b].fetch_add(1, Relaxed);
}

/// Raw input arrived (interrupt context: atomics only).
pub fn raw_input() {
    RAW_IN.fetch_add(1, Relaxed);
    let _ = PENDING_IN.compare_exchange(0, now().max(1), Relaxed, Relaxed);
}

/// An evdev read returned `n` events.
pub fn ev_read(n: u64) {
    EV_READ.fetch_add(1, Relaxed);
    if n == 0 {
        EV_READ_EMPTY.fetch_add(1, Relaxed);
        return;
    }
    EV_EVENTS.fetch_add(n, Relaxed);
    let t = PENDING_IN.swap(0, Relaxed);
    if t != 0 {
        lat(0, t);
        let _ = PENDING_FLIP.compare_exchange(0, t, Relaxed, Relaxed);
        let _ = PENDING_CUR.compare_exchange(0, t, Relaxed, Relaxed);
    }
}

/// A new picture went to the screen.
pub fn flip() {
    FLIPS.fetch_add(1, Relaxed);
    let t = now();
    let last = LAST_FLIP.swap(t, Relaxed);
    if last != 0 {
        let ms = (t - last) / 1_000_000;
        let b = [10, 17, 20, 34, 50, 100, 1000].iter().position(|&l| ms < l).unwrap_or(7);
        FLIP_GAP[b].fetch_add(1, Relaxed);
    }
    let p = PENDING_FLIP.swap(0, Relaxed);
    if p != 0 {
        lat(1, p);
    }
    start();
}

/// The cursor plane moved or changed.
pub fn cursor(ns: u64) {
    CURSORS.fetch_add(1, Relaxed);
    CURSOR_NS.fetch_add(ns, Relaxed);
    let p = PENDING_CUR.swap(0, Relaxed);
    if p != 0 {
        lat(2, p);
    }
}

pub fn present(ns: u64) {
    PRESENTS.fetch_add(1, Relaxed);
    PRESENT_NS.fetch_add(ns, Relaxed);
    PRESENT_MAX.fetch_max(ns, Relaxed);
}

pub fn pcm_ioctl(cmd: u64) {
    PCM_IOCTL[(cmd & 0xFF) as usize].fetch_add(1, Relaxed);
    start();
}

/// Starts the reporter task once.
pub fn start() {
    if !STARTED.swap(true, Relaxed) {
        crate::task::spawn("dstat", reporter, crate::task::TaskPriority::Normal);
    }
}

fn take(a: &AtomicU64) -> u64 {
    a.swap(0, Relaxed)
}

fn reporter() {
    use core::fmt::Write;
    let mut prev_calls = [0u64; 512];
    let mut t_prev = now();
    loop {
        crate::task::sleep_ms(5000);
        let t = now();
        let dt_ms = ((t - t_prev) / 1_000_000).max(1);
        t_prev = t;
        let mut s = alloc::string::String::new();
        let _ = write!(s, "[dstat] dt={}ms", dt_ms);
        // Linux system calls in this period (needs `linux prof on`)
        let mut total = 0u64;
        let mut per = [0u64; 512];
        for i in 0..512 {
            let c = super::prof::calls(i);
            per[i] = c.saturating_sub(prev_calls[i]);
            prev_calls[i] = c;
            total += per[i];
        }
        let _ = write!(s, " sys={} ioctl={} read={} write={} epoll_wait={} epoll_pwait={} poll={} ppoll={} recvmsg={} sendmsg={} futex={} writev={} timerfd_set={}",
            total, per[16], per[0], per[1], per[232], per[281], per[7], per[271], per[47], per[46], per[202], per[20], per[286]);
        crate::console::serial_write(&s);
        crate::console::serial_write("\n");
        let mut s = alloc::string::String::new();
        let _ = write!(s, "[dstat] drm:");
        let mut drm_total = 0;
        for i in 0..256 {
            let n = take(&DRM_IOCTL[i]);
            if n != 0 {
                drm_total += n;
                let _ = write!(s, " {:02x}={}", i, n);
            }
        }
        let presents = take(&PRESENTS);
        let pns = take(&PRESENT_NS);
        let pmax = PRESENT_MAX.swap(0, Relaxed);
        let curs = take(&CURSORS);
        let cns = take(&CURSOR_NS);
        let _ = write!(s, " ioctls={} read={} poll={} flips={} presents={} present_avg_us={} present_max_us={} cursors={} cursor_avg_us={} gaps[<10,<17,<20,<34,<50,<100,<1000,more ms]=",
            drm_total, take(&DRM_READ), take(&DRM_POLL), take(&FLIPS), presents, if presents > 0 { pns / presents / 1000 } else { 0 }, pmax / 1000,
            curs, if curs > 0 { cns / curs / 1000 } else { 0 });
        for g in FLIP_GAP.iter() {
            let _ = write!(s, "{},", take(g));
        }
        crate::console::serial_write(&s);
        crate::console::serial_write("\n");
        let mut s = alloc::string::String::new();
        let _ = write!(s, "[dstat] input: raw={} ev_read={} (empty {}) events={} ev_ioctl={} ev_poll={}",
            take(&RAW_IN), take(&EV_READ), take(&EV_READ_EMPTY), take(&EV_EVENTS), take(&EV_IOCTL), take(&EV_POLL));
        for (k, name) in ["irq->read", "irq->flip", "irq->cursor"].iter().enumerate() {
            let n = take(&LAT[k][0]);
            let sum = take(&LAT[k][1]);
            let max = LAT[k][2].swap(0, Relaxed);
            let _ = write!(s, " {} n={} avg_us={} max_us={} h[<0.1,<1,<5,<17,<34,<100,more ms]=", name, n, if n > 0 { sum / n / 1000 } else { 0 }, max / 1000);
            for h in LAT_H[k].iter() {
                let _ = write!(s, "{},", take(h));
            }
        }
        crate::console::serial_write(&s);
        crate::console::serial_write("\n");
        let mut s = alloc::string::String::new();
        let _ = write!(s, "[dstat] snd: pcm");
        let mut pcm_total = 0;
        for i in 0..256 {
            let n = take(&PCM_IOCTL[i]);
            if n != 0 {
                pcm_total += n;
                let _ = write!(s, " {:02x}={}", i, n);
            }
        }
        let _ = write!(s, " pcm_ioctls={} pcm_poll={} ctl_ioctl={} ctl_read={} xruns={} pos_wakes={} | tty_ops={} pty_ops={}",
            pcm_total, take(&PCM_POLL), take(&CTL_IOCTL), take(&CTL_READ), take(&XRUNS), take(&POS_WAKES), take(&TTY_OPS), take(&PTY_OPS));
        crate::console::serial_write(&s);
        crate::console::serial_write("\n");
    }
}
