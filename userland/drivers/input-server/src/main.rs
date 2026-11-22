//! # input-server: Hydra's input service (wave 8, Group I)
//!
//! Serves the Linux event devices `/dev/input/event0..2` (the keyboard, the relative mouse,
//! the absolute pointer) on its own endpoint ([`ENDPOINT_INPUT_SERVER`], service
//! [`LXS_INPUT`]), on the service runtime (`hydra_rt::svcrt`). Moved from the kernel's
//! `compat/linux/evdev.rs`, which stays as the switch back (`lx.input=kernel`, `lx=kernel`).
//!
//! - **Input** comes from the kernel's raw input ring (`src/ipc/input.rs`), a memory object
//!   this service maps (`SYS_LX_OBJ` [`LX_OBJ_INPUT_RING`]); the interrupt paths append to
//!   it and raise [`NOTIFY_INPUT`]. The main thread then translates the new records
//!   ([`xlate`]), appends the events to every open file's queue, completes waiting reads and
//!   sets the files' readiness words (`poll`/`epoll` in the kernel read them).
//! - **Opens** of character major 13 come here (`LX_SVC_CLAIM_MAJOR`); `read`, `write` and
//!   `ioctl` on the objects are forwarded here by descriptor.
//! - **Restart** (Transparent, `docs/linux-services-design.md` section 5): the new instance
//!   adopts the open files of the old one (their key is the device number; the revoked ones
//!   are listed in the kept state), so programs' descriptors keep working; input typed
//!   meanwhile waits in the kernel's ring.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::protocol;
use hydra_rt::protocol::*;
use hydra_rt::svcrt::{self, objs, Answer, Cx, Event};
use hydra_rt::{println, sys, Message};

#[allow(dead_code)] // (the producer half is the kernel's)
#[path = "../../../../src/ipc/input_ring.rs"]
mod input_ring;
#[allow(dead_code)] // (some helpers serve the host tests)
mod xlate;

use input_ring::RingView;
use xlate::{Queue, Translator};

hydra_rt::entry!(main);

const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;
const ERESTARTSYS: i64 = -512;

/// Readiness: readable (`POLLIN | POLLRDNORM`).
const READABLE: u32 = 0x41;
/// Readiness of a revoked file (`POLLERR | POLLHUP`).
const GONE: u32 = 0x18;
/// Largest read served at once (bytes).
const READ_MAX: usize = 24 * 256;

/// A read waiting for events: its request, buffer and length.
struct Waiting {
    id: u64,
    buf: u64,
    len: usize,
}

/// One open event device.
struct File {
    dev: usize,
    queue: Queue,
    revoked: bool,
    reads: Vec<Waiting>,
}

/// Everything the workers and the main thread share.
struct State {
    tr: Translator,
    files: BTreeMap<u32, File>,
}

static STATE: spin::Mutex<State> = spin::Mutex::new(State { tr: Translator::new(), files: BTreeMap::new() });
/// Where the ring is mapped.
static RING: AtomicU64 = AtomicU64::new(0);
/// Records translated since start.
static RECORDS: AtomicU64 = AtomicU64::new(0);

/// The kept-state area: record 0 lists the revoked files' slots (u32 each).
static KEPT: spin::Mutex<Option<hydra_rt::kept::Kept>> = spin::Mutex::new(None);
const KEPT_LAYOUT: u32 = 1;
const KEPT_REC: usize = 512;

fn ring() -> Option<RingView> {
    let a = RING.load(Ordering::Acquire);
    // SAFETY: the ring object stays mapped for the life of the process
    (a != 0).then(|| unsafe { RingView::new(a as *mut u8) })
}

fn main(args: &[&str]) {
    // With lx.input=kernel (or lx=kernel) the kernel's own copy serves the devices: nothing
    // to do (exiting before registering: the supervisor does not restart it)
    match sys::lx_obj(LX_OBJ_INPUT_CTL, 0, 0, 0) {
        Ok(1) => {}
        r => {
            println!("[input-server] input is served by the kernel ({:?}): not started", r);
            sys::exit(0);
        }
    }
    let handle = match sys::lx_obj(LX_OBJ_INPUT_RING, 0, 0, 0) {
        Ok(h) => h as u32,
        Err(e) => {
            println!("[input-server] no input ring: {}", e);
            sys::exit_group(1);
        }
    };
    let obj = hydra_rt::mem::MemObj::from_raw(handle);
    match obj.map(0, INPUT_RING_BYTES as u64, hydra_rt::mem::PROT_RW) {
        Ok(p) => {
            // SAFETY: just mapped, INPUT_RING_BYTES long, page aligned
            if !unsafe { RingView::new(p) }.valid() {
                println!("[input-server] the input ring is not set up");
                sys::exit_group(1);
            }
            RING.store(p as u64, Ordering::Release);
        }
        Err(e) => {
            println!("[input-server] cannot map the input ring: {}", e);
            sys::exit_group(1);
        }
    }
    let _ = obj.into_raw();
    let cfg = svcrt::Config { name: "input-server", endpoint: ENDPOINT_INPUT_SERVER, workers: svcrt::workers_arg(args, 2), subscribe: None };
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[input-server] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    svcrt::notes::init(svc.window().as_mut_ptr(), on_note);
    objs::init(svc.area, ENDPOINT_INPUT_SERVER);
    kept_init();
    let adopted = adopt_files();
    if let Err(e) = svc.online() {
        println!("[input-server] cannot go online: {}", e);
        sys::exit_group(1);
    }
    if let Err(e) = sys::lx_svc(LX_SVC_CLAIM_MAJOR, 13, 0, 0) {
        println!("[input-server] cannot claim major 13: {}", e);
    }
    let (h, t, d) = ring().map_or((0, 0, 0), |r| r.counters());
    println!("[input-server] online: endpoint {:#x}, {} files adopted, ring {} appended / {} taken / {} dropped", ENDPOINT_INPUT_SERVER, adopted, h, t, d);
    loop {
        match svc.recv(100) {
            Event::Request(id, _) => svc.reply(id, &Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        svcrt::notes::drain_all();
        pump();
        objs::flush();
    }
}

/// Translates the ring's new records, queues the events on the open files, completes the
/// reads that can be completed and updates readiness.
fn pump() {
    let Some(ring) = ring() else { return };
    if !ring.pending() {
        return;
    }
    let mut done: Vec<(u64, u64, Vec<u8>)> = Vec::new();
    {
        let mut st = STATE.lock();
        let st = &mut *st;
        let mut out = xlate::per_dev();
        let mut now = 0;
        let n = ring.take(|r| {
            now = r.time;
            st.tr.feed(&r, &mut out)
        });
        RECORDS.fetch_add(n as u64, Ordering::Relaxed);
        for (slot, f) in st.files.iter_mut() {
            if f.revoked || out[f.dev].is_empty() {
                continue;
            }
            f.queue.extend(&out[f.dev], now);
            complete_reads(f, &mut done);
            objs::set(*slot, if f.queue.is_empty() { 0 } else { READABLE }, 0);
        }
    }
    finish(done);
}

/// Hands queued events to `f`'s waiting reads (collected in `done`: request, buffer, bytes).
fn complete_reads(f: &mut File, done: &mut Vec<(u64, u64, Vec<u8>)>) {
    while !f.queue.is_empty() && !f.reads.is_empty() {
        let w = f.reads.remove(0);
        let mut buf = alloc::vec![0u8; w.len.min(READ_MAX)];
        let n = f.queue.take(&mut buf);
        buf.truncate(n);
        done.push((w.id, w.buf, buf));
    }
}

/// Writes the collected read results and completes their calls (outside the lock).
fn finish(done: Vec<(u64, u64, Vec<u8>)>) {
    for (id, ptr, data) in done {
        let r = if data.is_empty() {
            0
        } else {
            match sys::lx_write(id, ptr, &data) {
                Ok(()) => data.len() as i64,
                Err(e) => e,
            }
        };
        let _ = sys::lx_complete(id, r);
    }
}

/// A notification from the kernel.
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    match kind {
        LX_NOTE_CLOSE if b == LX_OBJ_KIND_EVDEV as u64 => {
            let slot = a as u32;
            let f = STATE.lock().files.remove(&slot);
            if let Some(f) = f {
                for w in f.reads {
                    let _ = sys::lx_complete(w.id, EBADF);
                }
                if f.revoked {
                    kept_revoked(slot, false);
                }
            }
            objs::set(slot, 0, 0);
            objs::free(slot);
        }
        LX_NOTE_INTERRUPT => {
            let found = {
                let mut st = STATE.lock();
                let mut found = false;
                for f in st.files.values_mut() {
                    if let Some(i) = f.reads.iter().position(|w| w.id == a) {
                        f.reads.remove(i);
                        found = true;
                        break;
                    }
                }
                found
            };
            if found {
                let _ = sys::lx_complete(a, ERESTARTSYS);
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
        LX_KCALL_DEVOPEN => (open(&cx, c.dev, c.args[1]), 0),
        0 if c.obj != LX_OBJ_NONE => read(&cx),
        1 if c.obj != LX_OBJ_NONE => {
            // Writes inject events (LED state and the like): accepted and ignored
            (((cx.args[2] as usize) / 24 * 24) as i64, 0)
        }
        16 if c.obj != LX_OBJ_NONE => (ioctl(&cx), 0),
        _ => (ENOSYS, 0),
    };
    objs::flush();
    r
}

/// `open` of `/dev/input/event*` (device number `rdev`, open flags `flags`).
fn open(cx: &Cx, rdev: u64, flags: u64) -> i64 {
    let minor = (rdev & 0xFF) | ((rdev >> 12) & 0xFFF00);
    let Some(dev) = xlate::dev_of_minor(minor) else { return -6 }; // ENXIO
    // Input from before the open is not this file's
    pump();
    let slot = match objs::alloc() {
        Ok(s) => s,
        Err(e) => return e,
    };
    STATE.lock().files.insert(slot, File { dev, queue: Queue::new(), revoked: false, reads: Vec::new() });
    let name = alloc::format!("/dev/input/event{}", dev);
    match objs::install_keyed(cx, slot, LX_OBJ_KIND_EVDEV, flags as u32 & 0o2004000, 0o020660, name.as_bytes(), 0, rdev) {
        Ok(fd) => fd,
        Err(e) => {
            STATE.lock().files.remove(&slot);
            objs::free(slot);
            e
        }
    }
}

/// `read` of an event device: whole events; waits (answered later) when none are queued.
fn read(cx: &Cx) -> Answer {
    let slot = cx.c.obj as u32;
    let (ptr, len) = (cx.args[1], cx.args[2] as usize);
    if len < 24 {
        return (EINVAL, 0);
    }
    pump();
    let data = {
        let mut st = STATE.lock();
        let Some(f) = st.files.get_mut(&slot) else { return (EBADF, 0) };
        if f.revoked {
            return (ENODEV, 0);
        }
        if f.queue.is_empty() {
            if cx.nonblock() {
                return (EAGAIN, 0);
            }
            f.reads.push(Waiting { id: cx.id, buf: ptr, len });
            return (0, LX_REPLY_PENDING);
        }
        let mut buf = alloc::vec![0u8; len.min(READ_MAX)];
        let n = f.queue.take(&mut buf);
        buf.truncate(n);
        objs::set(slot, if f.queue.is_empty() { 0 } else { READABLE }, 0);
        buf
    };
    match cx.copy_out(ptr, &data) {
        Ok(()) => (data.len() as i64, 0),
        Err(e) => (e, 0),
    }
}

/// `ioctl` of an event device.
fn ioctl(cx: &Cx) -> i64 {
    let slot = cx.c.obj as u32;
    let (cmd, arg) = (cx.args[1], cx.args[2]);
    let answer = {
        let st = STATE.lock();
        let Some(f) = st.files.get(&slot) else { return EBADF };
        xlate::ioctl(f.dev, cmd, &st.tr)
    };
    match answer {
        xlate::Answer::Val(v) => v,
        xlate::Answer::Out { data, cap, len } => {
            let n = cap.min(data.len());
            if n > 0 {
                if let Err(e) = cx.copy_out(arg, &data[..n]) {
                    return e;
                }
            }
            if len {
                n as i64
            } else {
                0
            }
        }
        xlate::Answer::Revoke => {
            // EVIOCREVOKE: the file stops working for good (logind on a session switch)
            let reads = {
                let mut st = STATE.lock();
                let Some(f) = st.files.get_mut(&slot) else { return EBADF };
                f.revoked = true;
                f.queue.clear();
                core::mem::take(&mut f.reads)
            };
            for w in reads {
                let _ = sys::lx_complete(w.id, ENODEV);
            }
            objs::set(slot, GONE, 0);
            kept_revoked(slot, true);
            0
        }
    }
}

// ----------------------------------------------------------------------
// Restart support
// ----------------------------------------------------------------------

/// Maps and checks the kept state, before going online.
fn kept_init() {
    let size = hydra_rt::kept::Kept::size_for(2, KEPT_REC);
    match sys::lx_svc_kept(size) {
        Ok(p) => {
            // SAFETY: the kernel mapped `size` bytes at `p` for this process alone
            let (k, a) = unsafe { hydra_rt::kept::Kept::open(p, size, KEPT_LAYOUT, KEPT_REC) };
            if !a.fresh {
                println!("[input-server] kept state adopted ({} bad records)", a.bad_records);
            }
            *KEPT.lock() = Some(k);
        }
        Err(e) => println!("[input-server] no kept state: {}", e),
    }
}

/// The revoked slots listed in the kept state.
fn kept_revoked_list() -> Vec<u32> {
    let g = KEPT.lock();
    let Some(k) = g.as_ref() else { return Vec::new() };
    k.get(0).map_or(Vec::new(), |b| b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).filter(|&s| s != u32::MAX).collect())
}

/// Adds (`on`) or removes slot `slot` from the kept list of revoked files.
fn kept_revoked(slot: u32, on: bool) {
    let mut list = kept_revoked_list();
    list.retain(|&s| s != slot);
    if on {
        list.push(slot);
    }
    list.truncate(KEPT_REC / 4);
    let mut rec = alloc::vec![0xFFu8; KEPT_REC];
    for (i, s) in list.iter().enumerate() {
        rec[i * 4..i * 4 + 4].copy_from_slice(&s.to_le_bytes());
    }
    if let Some(k) = KEPT.lock().as_mut() {
        k.put(0, &rec);
    }
}

/// A Transparent restart: the old instance's open files are taken again (slot, device from
/// the key, revoked from the kept list). Returns how many.
fn adopt_files() -> usize {
    let mut found: Vec<LxSvcObj> = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut start = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, start) {
        if n == 0 {
            break;
        }
        found.extend_from_slice(&buf[..n]);
        start = buf[n - 1].slot + 1;
    }
    if found.is_empty() {
        return 0;
    }
    for o in &found {
        let minor = (o.key & 0xFF) | ((o.key >> 12) & 0xFFF00);
        if o.kind != LX_OBJ_KIND_EVDEV || xlate::dev_of_minor(minor).is_none() {
            let _ = sys::lx_svc_dead(o.slot);
        }
    }
    if sys::lx_svc_adopt().is_err() {
        return 0; // not a Transparent restart: the kernel makes them stale
    }
    let revoked = kept_revoked_list();
    let mut n = 0;
    let mut st = STATE.lock();
    for o in &found {
        let minor = (o.key & 0xFF) | ((o.key >> 12) & 0xFFF00);
        let Some(dev) = xlate::dev_of_minor(minor).filter(|_| o.kind == LX_OBJ_KIND_EVDEV) else { continue };
        if objs::reserve(o.slot) {
            let gone = revoked.contains(&o.slot);
            st.files.insert(o.slot, File { dev, queue: Queue::new(), revoked: gone, reads: Vec::new() });
            objs::set(o.slot, if gone { GONE } else { 0 }, 0);
            n += 1;
        }
    }
    drop(st);
    // Forget revoked slots that no longer exist
    for s in revoked {
        if !STATE.lock().files.contains_key(&s) {
            kept_revoked(s, false);
        }
    }
    n
}
