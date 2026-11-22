//! # Hydra's display service (display-server, wave 8, Group D)
//!
//! `/dev/dri/card0` out of the kernel (`docs/display-input-design.md`, option B; decision
//! 28): a Linux service on the service runtime (`hydra_rt::svcrt`), service `LXS_DISPLAY`,
//! endpoint 0x23. The kernel routes `open` of character major 226 here (the major this
//! service claims) and every call on its descriptors: `ioctl`, `read` of events, `mmap` of
//! dumb buffers and DMA-BUFs.
//!
//! Two layers in one program:
//! - **the native core** (`native.rs`, and the screen here): the screen the kernel lends
//!   (`SYS_SCREEN`, `src/ipc/screen.rs`), the picture copy, the cursor, the emulated
//!   60 Hz vertical blank;
//! - **the Linux DRM layer** (`kms.rs`, moved from the kernel's `drm.rs`).
//!
//! Threads: the runtime's workers serve the calls; the **screen thread** waits in
//! `SCREEN_WAIT` for the kernel's state changes (Ctrl+Alt+F1/F2: repaint, hold completions
//! back) and the next vertical blank (flip completions); the main thread serves the
//! endpoint, the notifications (closes, interrupted reads) and prints a `[display]` line
//! every 5 s while the desktop draws.
//!
//! **Crash policy** (FailObjects, decision 28): the kernel takes the screen back at once;
//! every descriptor of this service fails with `ENODEV` (kwin exits, the desktop session
//! ends); the supervisor restarts the service and SDDM comes back on the console's screen.
//! `lx.display=kernel` / `lx=kernel`: the first `SYS_SCREEN` answers `ENODEV` and the
//! service exits unregistered; the kernel's `drm.rs` serves as before.

#![no_std]
#![no_main]

extern crate alloc;

mod kms;
mod native;

/// The kernel's protocol (one source: `src/ipc/protocol.rs`).
pub mod proto {
    pub use hydra_rt::protocol::*;
}

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use hydra_rt::mem::{MemObj, PROT_RW};
use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, objs, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

use crate::kms::{BoMem, Env, Kms};

hydra_rt::entry!(main);

const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ENOSYS: i64 = -38;
const ENODEV: i64 = -19;
const ENXIO: i64 = -6;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;

/// Character major of DRM.
const DRM_MAJOR: u64 = 226;
/// `O_CLOEXEC | O_NONBLOCK`: the flags an installed descriptor takes from the caller.
const FD_FLAGS: u32 = 0o2004000;

/// The device (`None` until the screen is mapped).
static KMS: spin::Mutex<Option<Kms>> = spin::Mutex::new(None);
/// Per live object slot: its kind (`LX_OBJ_KIND_DRM` or `LX_OBJ_KIND_DMABUF`).
static KINDS: spin::Mutex<alloc::collections::BTreeMap<u32, u32>> = spin::Mutex::new(alloc::collections::BTreeMap::new());
/// Blocking reads of DRM files waiting for an event: (request id, slot, buffer, length).
static READS: spin::Mutex<Vec<(u64, u32, u64, usize)>> = spin::Mutex::new(Vec::new());
/// Buffers named by the latest `mmap` answers (kept a little: the kernel reads an answer's
/// handle after the call returned).
static RECENT: spin::Mutex<Vec<alloc::sync::Arc<kms::Bo>>> = spin::Mutex::new(Vec::new());

/// The screen mapping: the framebuffer's first byte and the status page.
static FB: AtomicU64 = AtomicU64::new(0);
static STATUS: AtomicU64 = AtomicU64::new(0);

// ----------------------------------------------------------------------
// The screen the kernel lends (the native core's hardware side)
// ----------------------------------------------------------------------

/// The firmware framebuffer through `SYS_SCREEN`.
struct FbScreen {
    info: ScreenInfo,
}

fn status_word(i: usize) -> &'static AtomicU32 {
    // SAFETY: the status page is mapped for the service's life; words are aligned
    unsafe { &*((STATUS.load(Ordering::Acquire) as *const AtomicU32).add(i)) }
}

/// The screen's state, from the status page the kernel writes.
fn screen_state() -> u32 {
    status_word(SCREEN_ST_STATE).load(Ordering::SeqCst)
}

impl crate::native::Screen for FbScreen {
    fn size(&self) -> (u32, u32) {
        (self.info.width, self.info.height)
    }

    fn take(&mut self) -> i64 {
        sys::screen(SCREEN_TAKE, 0, 0)
    }

    fn give(&mut self) {
        sys::screen(SCREEN_GIVE, 0, 0);
    }

    fn state(&self) -> u32 {
        screen_state()
    }

    fn begin(&mut self) -> Option<crate::native::Target> {
        // Raise "copying", then look at the state: the kernel's panic path sets the state,
        // then waits for "copying" to drop (the hot keys and a crash zap the mapping)
        let copying = status_word(SCREEN_ST_COPYING);
        copying.store(1, Ordering::SeqCst);
        if screen_state() != SCREEN_SHOWN {
            copying.store(0, Ordering::SeqCst);
            return None;
        }
        Some(crate::native::Target { ptr: FB.load(Ordering::Acquire) as *mut u8, stride: self.info.stride as usize, width: self.info.width, height: self.info.height, bgr: self.info.bgr != 0 })
    }

    fn end(&mut self) {
        status_word(SCREEN_ST_COPYING).store(0, Ordering::SeqCst);
    }

    fn now_ns(&self) -> u64 {
        now_ns()
    }
}

fn now_ns() -> u64 {
    sys::screen(SCREEN_NOW, 0, 0).max(0) as u64
}

// ----------------------------------------------------------------------
// Buffers: memory objects mapped into the service
// ----------------------------------------------------------------------

/// A dumb buffer's memory: an anonymous memory object, mapped here for the copies; programs
/// map the same object through the `mmap` answer (their mappings outlive the service).
struct MemBo {
    obj: MemObj,
    addr: *mut u8,
    len: u64,
}

// SAFETY: the mapping is shared memory; the service's access is serialized by KMS
unsafe impl Send for MemBo {}
unsafe impl Sync for MemBo {}

impl BoMem for MemBo {
    fn ptr(&self) -> *mut u8 {
        self.addr
    }
    fn handle(&self) -> u32 {
        self.obj.handle()
    }
}

impl Drop for MemBo {
    fn drop(&mut self) {
        let _ = hydra_rt::mem::unmap(self.addr, self.len);
    }
}

// ----------------------------------------------------------------------
// The call's environment for the DRM layer
// ----------------------------------------------------------------------

struct CxEnv<'a> {
    cx: &'a Cx,
}

impl Env for CxEnv<'_> {
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        self.cx.copy_in(ptr, len)
    }

    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        self.cx.copy_out(ptr, data)
    }

    fn new_mem(&self, size: u64) -> Result<Box<dyn BoMem>, i64> {
        let obj = MemObj::anon(size)?;
        let addr = obj.map(0, size, PROT_RW)?;
        Ok(Box::new(MemBo { obj, addr, len: size }))
    }

    fn install_dmabuf(&self, flags: u32, size: u64) -> Result<(i64, u32), i64> {
        let slot = objs::alloc()?;
        KINDS.lock().insert(slot, LX_OBJ_KIND_DMABUF);
        match objs::install_keyed(self.cx, slot, LX_OBJ_KIND_DMABUF, flags & FD_FLAGS, 0o100600, b"/dmabuf:", 0, 0) {
            Ok(fd) => {
                // No fences: always readable and writable; the size is what fstat reports
                objs::set(slot, 0x5, size);
                Ok((fd, slot))
            }
            Err(e) => {
                KINDS.lock().remove(&slot);
                objs::free(slot);
                Err(e)
            }
        }
    }

    fn dmabuf_slot(&self, fd: u32) -> Result<u32, i64> {
        let r = sys::lx_obj(LX_OBJ_FD, self.cx.id, fd as u64, 0).map_err(|e| if e == EINVAL { EINVAL } else { EBADF })?;
        if (r >> 32) as u32 & 0x3FFF_FFFF != LX_OBJ_KIND_DMABUF {
            return Err(EINVAL);
        }
        Ok(r as u32)
    }
}

// ----------------------------------------------------------------------
// Start
// ----------------------------------------------------------------------

fn main(args: &[&str]) {
    // `lx.display=kernel` / `lx=kernel` (or no service id names the endpoint): the kernel's
    // drm.rs serves; exiting without registering, the supervisor does not restart us
    let mut info = ScreenInfo::default();
    let r = sys::screen(SCREEN_INFO, &mut info as *mut ScreenInfo as u64, 0);
    if r == ENODEV || sys::lx_svc(LX_SVC_WHOAMI, 0, 0, 0).is_err() {
        println!("[display] the kernel serves the display (lx.display=kernel): not started");
        sys::exit(0);
    }
    if r < 0 {
        println!("[display] no screen ({}): not started", r);
        sys::exit(0);
    }
    let cfg = svcrt::Config { name: "display", endpoint: ENDPOINT_DISPLAY_DEV, workers: svcrt::workers_arg(args, 2), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[display] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    objs::init(svc.area, ENDPOINT_DISPLAY_DEV);
    let base = sys::screen(SCREEN_MAP, 0, 0);
    if base < 0 {
        println!("[display] cannot map the screen: {}", base);
        sys::exit_group(1);
    }
    FB.store(base as u64, Ordering::Release);
    STATUS.store(base as u64 + info.fb_bytes, Ordering::Release);
    let slot_len = info.slot.iter().position(|&c| c == 0).unwrap_or(info.slot.len());
    let slot = alloc::string::String::from_utf8_lossy(&info.slot[..slot_len]).into_owned();
    *KMS.lock() = Some(Kms::new(Box::new(FbScreen { info }), slot, info.refresh_mhz));
    if let Err(e) = svc.online() {
        println!("[display] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // Opens of /dev/dri/card0 come here (after online: the kernel routes them only to a
    // service that serves)
    if let Err(e) = sys::lx_svc(LX_SVC_CLAIM_MAJOR, DRM_MAJOR, 0, 0) {
        println!("[display] cannot claim major {}: {}", DRM_MAJOR, e);
    }
    start_screen_thread();
    println!("[display] serving /dev/dri/card0: {}x{} (stride {}, {}), {} Hz", info.width, info.height, info.stride, if info.bgr != 0 { "BGR" } else { "RGB" }, info.refresh_mhz / 1000);
    let mut last_report = sys::uptime_ticks();
    let mut last = kms::Stats::default();
    loop {
        match svc.recv(100) {
            Event::Request(id, _) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        objs::flush();
        let now = sys::uptime_ticks();
        if now >= last_report + 500 {
            last_report = now;
            last = report(last);
        }
    }
}

/// The `[display]` line for the last 5 s, when anything happened.
fn report(last: kms::Stats) -> kms::Stats {
    let (s, hidden) = match KMS.lock().as_ref() {
        Some(k) => (k.stats, k.hidden()),
        None => return last,
    };
    let d = |a: u64, b: u64| a.wrapping_sub(b);
    if d(s.ioctls, last.ioctls) == 0 && d(s.held, last.held) == 0 && d(s.presents, last.presents) == 0 {
        return s;
    }
    let presents = d(s.presents, last.presents);
    let avg = if presents > 0 { d(s.copy_ns, last.copy_ns) / presents / 1000 } else { 0 };
    println!(
        "[display] 5s: ioctls {} ({} behind the console), flips {}, pictures {}, completions {}, held {}, copy avg {} us max {} us, cursor {}{}",
        d(s.ioctls, last.ioctls),
        d(s.ioctls_hidden, last.ioctls_hidden),
        d(s.flips, last.flips),
        presents,
        d(s.completions, last.completions),
        d(s.held, last.held),
        avg,
        s.copy_max_ns / 1000,
        d(s.cursor_updates, last.cursor_updates),
        if hidden { " [console shown]" } else { "" }
    );
    if let Some(k) = KMS.lock().as_mut() {
        k.stats.copy_max_ns = 0;
    }
    let mut s = s;
    s.copy_max_ns = 0;
    s
}

// ----------------------------------------------------------------------
// The screen thread: state changes and the vertical blank
// ----------------------------------------------------------------------

const SCREEN_STACK: usize = 128 * 1024;

fn start_screen_thread() {
    let Ok(stack) = sys::map_anon(SCREEN_STACK) else {
        println!("[display] no stack for the screen thread");
        sys::exit_group(1);
    };
    // SAFETY: a fresh stack of its own (16-byte aligned, minus a return address)
    if unsafe { sys::thread_create(screen_thread, stack + SCREEN_STACK as u64 - 8, 0) }.is_err() {
        println!("[display] cannot start the screen thread");
        sys::exit_group(1);
    }
}

extern "C" fn screen_thread(_arg: u64) -> ! {
    let mut gen = 0u64;
    let mut state = screen_state();
    loop {
        let due = KMS.lock().as_ref().and_then(|k| k.next_due(now_ns()));
        let r = sys::screen(SCREEN_WAIT, gen, due.unwrap_or(0));
        if r < 0 {
            sys::sleep_ms(10);
            continue;
        }
        let (st, g) = ((r & 0xFF) as u32, (r as u64) >> 8);
        let now = now_ns();
        let mut guard = KMS.lock();
        let Some(k) = guard.as_mut() else { continue };
        if g != gen {
            gen = g;
            if st != state {
                state = st;
                k.state_changed(st);
            }
        }
        if due.is_some_and(|d| now >= d) || k.next_due(now).is_some_and(|d| now >= d) {
            k.vblank_tick(now);
        }
        k.check_gone(now);
        let woke = core::mem::take(&mut k.woke);
        drop(guard);
        deliver(&woke);
        objs::flush();
    }
}

/// Files whose event queue grew: their readiness, and the reads waiting for them.
fn deliver(woke: &[u32]) {
    if woke.is_empty() {
        return;
    }
    for &slot in woke {
        let waiting: Vec<(u64, u64, usize)> = {
            let mut r = READS.lock();
            let mine = r.iter().filter(|x| x.1 == slot).map(|x| (x.0, x.2, x.3)).collect();
            r.retain(|x| x.1 != slot);
            mine
        };
        for (id, buf, len) in waiting {
            let got = KMS.lock().as_mut().and_then(|k| k.take_events(slot, len));
            let res = match got {
                Some(Ok(bytes)) => match sys::lx_write(id, buf, &bytes) {
                    Ok(()) => bytes.len() as i64,
                    Err(e) => e,
                },
                Some(Err(e)) => e,
                // Taken by another reader meanwhile: wait again
                None => {
                    READS.lock().push((id, slot, buf, len));
                    continue;
                }
            };
            let _ = sys::lx_complete(id, res);
        }
        let bits = KMS.lock().as_ref().map_or(0x4, |k| k.poll_bits(slot));
        objs::set(slot, bits, 0);
    }
}

// ----------------------------------------------------------------------
// Calls
// ----------------------------------------------------------------------

/// A notification from the kernel.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_CLOSE if b == LX_OBJ_KIND_DRM as u64 || b == LX_OBJ_KIND_DMABUF as u64 => {
            let slot = a as u32;
            if KINDS.lock().remove(&slot).is_none() {
                return;
            }
            READS.lock().retain(|x| x.1 != slot);
            if let Some(k) = KMS.lock().as_mut() {
                if b == LX_OBJ_KIND_DRM as u64 {
                    k.close(slot);
                } else {
                    k.dmabuf_closed(slot);
                }
            }
            objs::set(slot, 0, 0);
            objs::free(slot);
        }
        LX_NOTE_INTERRUPT => {
            let found = {
                let mut r = READS.lock();
                let before = r.len();
                r.retain(|x| x.0 != a);
                r.len() != before
            };
            if found {
                let _ = sys::lx_complete(a, EINTR);
            }
        }
        _ => {}
    }
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    svcrt::notes::drain_to(c.note_seq);
    let cx = Cx::from_call(c, page);
    let r = match c.nr {
        LX_KCALL_DEVOPEN => (open_file(&cx), 0),
        _ if c.obj == LX_OBJ_NONE => (ENOSYS, 0),
        n => {
            let slot = c.obj as u32;
            // (the guard must not live through the call: PRIME_HANDLE_TO_FD takes KINDS)
            let kind = KINDS.lock().get(&slot).copied();
            match kind {
                Some(LX_OBJ_KIND_DRM) => drm_call(&cx, slot, n),
                Some(LX_OBJ_KIND_DMABUF) => (dmabuf_call(&cx, slot, n), 0),
                _ => (EBADF, 0),
            }
        }
    };
    objs::flush();
    r
}

/// `open("/dev/dri/card0")`: a new DRM file.
fn open_file(cx: &Cx) -> i64 {
    let minor = (cx.c.dev & 0xFF) | ((cx.c.dev >> 12) & 0xFFF00);
    if minor != 0 {
        return ENXIO;
    }
    let slot = match objs::alloc() {
        Ok(s) => s,
        Err(e) => return e,
    };
    KINDS.lock().insert(slot, LX_OBJ_KIND_DRM);
    let opened = KMS.lock().as_mut().map(|k| k.open(slot)).is_some();
    if !opened {
        KINDS.lock().remove(&slot);
        objs::free(slot);
        return ENODEV;
    }
    match objs::install_keyed(cx, slot, LX_OBJ_KIND_DRM, cx.args[1] as u32 & FD_FLAGS, 0o020666, b"/dev/dri/card0", 0, cx.c.dev) {
        Ok(fd) => {
            objs::set(slot, 0x4, 0);
            fd
        }
        Err(e) => {
            KINDS.lock().remove(&slot);
            if let Some(k) = KMS.lock().as_mut() {
                k.close(slot);
            }
            objs::free(slot);
            e
        }
    }
}

/// A call on DRM file `slot`.
fn drm_call(cx: &Cx, slot: u32, nr: u64) -> Answer {
    match nr {
        16 => {
            let env = CxEnv { cx };
            let (r, flip, woke) = {
                let mut g = KMS.lock();
                let Some(k) = g.as_mut() else { return (ENODEV, 0) };
                let before = k.pending.len();
                let r = k.ioctl(&env, slot, cx.args[1], cx.args[2]);
                (r, k.pending.len() > before, core::mem::take(&mut k.woke))
            };
            deliver(&woke);
            if flip {
                // The screen thread waits for the next blank now
                sys::screen(SCREEN_KICK, 0, 0);
            }
            (r, 0)
        }
        0 => {
            let (buf, len) = (cx.args[1], cx.args[2] as usize);
            let got = KMS.lock().as_mut().and_then(|k| k.take_events(slot, len));
            let r = match got {
                Some(Ok(bytes)) => match cx.copy_out(buf, &bytes) {
                    Ok(()) => bytes.len() as i64,
                    Err(e) => e,
                },
                Some(Err(e)) => e,
                None if cx.nonblock() => EAGAIN,
                None => {
                    READS.lock().push((cx.id, slot, buf, len));
                    return (0, LX_REPLY_PENDING);
                }
            };
            let bits = KMS.lock().as_ref().map_or(0x4, |k| k.poll_bits(slot));
            objs::set(slot, bits, 0);
            (r, 0)
        }
        9 => {
            let (len, offset) = (cx.args[1], cx.args[5]);
            let found = KMS.lock().as_ref().map(|k| k.mmap_file(offset, len));
            let bo = match found {
                Some(Ok(bo)) => bo,
                Some(Err(e)) => return (e, 0),
                None => return (ENODEV, 0),
            };
            let pgoff = offset / 4096 - bo.map_pgoff;
            let ans = hydra_rt::mem::lx_mmap_answer(bo.mem.handle(), pgoff, false);
            keep(bo);
            (ans, 0)
        }
        1 => (EINVAL, 0),
        _ => (ENOSYS, 0),
    }
}

/// A call on DMA-BUF `slot`.
fn dmabuf_call(cx: &Cx, slot: u32, nr: u64) -> i64 {
    match nr {
        16 => match cx.args[1] {
            0x4008_6200 => 0,                // DMA_BUF_IOCTL_SYNC: memory is always coherent
            0x4008_6201 | 0x4004_6201 => 0, // DMA_BUF_SET_NAME
            _ => ENOTTY,                     // no sync files
        },
        9 => {
            let (len, offset) = (cx.args[1], cx.args[5]);
            let found = KMS.lock().as_ref().map(|k| k.mmap_dmabuf(slot, offset, len));
            let bo = match found {
                Some(Ok(bo)) => bo,
                Some(Err(e)) => return e,
                None => return ENODEV,
            };
            let ans = hydra_rt::mem::lx_mmap_answer(bo.mem.handle(), offset / 4096, false);
            keep(bo);
            ans
        }
        0 | 1 => EINVAL,
        _ => ENOSYS,
    }
}

/// Keeps `bo` alive past the answer that names its memory object.
fn keep(bo: alloc::sync::Arc<kms::Bo>) {
    let mut r = RECENT.lock();
    if r.len() >= 16 {
        r.remove(0);
    }
    r.push(bo);
}

