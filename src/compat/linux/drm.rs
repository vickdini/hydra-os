//! # DRM/KMS display device (`/dev/dri/card0`)
//!
//! A kernel mode-setting driver for the boot framebuffer, in the spirit of Linux's
//! `simpledrm`: one CRTC, one encoder and one connected virtual connector whose only mode is
//! the firmware's resolution. Clients allocate "dumb" buffers, `mmap` them, wrap them in
//! framebuffers and show them with the legacy `SETCRTC`/`PAGE_FLIP` calls; page flips
//! complete at once and post a `DRM_EVENT_FLIP_COMPLETE` on the descriptor. The cursor is
//! a 64x64 ARGB buffer blended over the picture when it is shown (`MODE_CURSOR`).
//!
//! Atomic mode setting is not offered (`SET_CLIENT_CAP(ATOMIC)` fails), so compositors use
//! the legacy path. There is no render node. Buffers can be exported as DMA-BUF descriptors
//! (PRIME) that map the same pages, and imported back into a GEM handle.
//!
//! Showing a framebuffer takes the screen from the text console (as a Linux VT switch to a
//! graphical session does) and routes the keyboard and mouse to the evdev devices; when
//! the master closes the device the console gets the screen back.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec};
use crate::memory::vm::{MappedObject, PAGE_SIZE};
use crate::task::wait::{QueueRef, WaitQueue, WaitSet};

use super::chardev::{makedev, CharDevice};
use super::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EAGAIN: i64 = -11;
const ENOMEM: i64 = -12;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EBUSY: i64 = -16;
const ENXIO: i64 = -6;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EOPNOTSUPP: i64 = -95;

/// Object ids (one id space for every KMS object, as in Linux).
const CRTC_ID: u32 = 40;
const ENCODER_ID: u32 = 41;
const CONNECTOR_ID: u32 = 42;
const PRIMARY_PLANE_ID: u32 = 43;
const CURSOR_PLANE_ID: u32 = 44;

const PROP_DPMS: u32 = 1;
const PROP_EDID: u32 = 2;
const PROP_NON_DESKTOP: u32 = 3;
const PROP_TYPE: u32 = 4;

const OBJ_CRTC: u32 = 0xcccc_cccc;
const OBJ_CONNECTOR: u32 = 0xc0c0_c0c0;
const OBJ_ENCODER: u32 = 0xe0e0_e0e0;
const OBJ_PLANE: u32 = 0xeeee_eeee;

const PROP_RANGE: u32 = 1 << 1;
const PROP_IMMUTABLE: u32 = 1 << 2;
const PROP_ENUM: u32 = 1 << 3;
const PROP_BLOB: u32 = 1 << 4;

/// `DRM_FORMAT_XRGB8888` / `ARGB8888` (fourcc little-endian `XR24` / `AR24`).
const FMT_XRGB8888: u32 = 0x3432_5258;
const FMT_ARGB8888: u32 = 0x3432_5241;

const CURSOR_SIZE: u32 = 64;
/// Refresh period of the virtual mode (60 Hz), in microseconds.
const FRAME_US: u64 = 16_667;

/// One "dumb" buffer object: page frames the client maps and the display reads.
struct Bo {
    frames: Vec<PhysFrame<Size4KiB>>,
    size: u64,
    /// Page offset of the buffer in the device's `mmap` space.
    map_pgoff: u64,
}

impl Bo {
    fn new(size: u64) -> Option<Arc<Bo>> {
        let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        let mut frames = Vec::with_capacity(pages as usize);
        for _ in 0..pages {
            match alloc_user_frame() {
                Some(f) => frames.push(f),
                None => {
                    for f in frames {
                        frame_ref_dec(f);
                    }
                    return None;
                }
            }
        }
        // A guard page between buffers keeps their offset ranges apart
        let map_pgoff = NEXT_MAP_PGOFF.fetch_add(pages + 1, Ordering::Relaxed);
        let bo = Arc::new(Bo { frames, size: pages * PAGE_SIZE, map_pgoff });
        MAP_SPACE.lock().insert(map_pgoff, Arc::downgrade(&bo));
        Some(bo)
    }

    /// Copies `len` bytes at byte offset `off` to `dst`.
    fn read(&self, mut off: u64, dst: *mut u8, len: usize) {
        let mut done = 0usize;
        while done < len && off < self.size {
            let page = (off / PAGE_SIZE) as usize;
            let in_page = (off % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - in_page).min(len - done);
            unsafe {
                let src = (self.frames[page].start_address().as_u64() as *const u8).add(in_page);
                core::ptr::copy_nonoverlapping(src, dst.add(done), n);
            }
            done += n;
            off += n as u64;
        }
    }
}

impl Drop for Bo {
    fn drop(&mut self) {
        MAP_SPACE.lock().remove(&self.map_pgoff);
        for f in self.frames.drain(..) {
            frame_ref_dec(f);
        }
    }
}

/// `mmap` offsets of live buffers (page offset -> buffer), shared by every open file.
static MAP_SPACE: Mutex<BTreeMap<u64, Weak<Bo>>> = Mutex::new(BTreeMap::new());
/// Next free page offset; starts high so offsets never look like file positions.
static NEXT_MAP_PGOFF: AtomicU64 = AtomicU64::new(0x10_0000);

/// The device's `mmap` space: page `pgoff` of whichever buffer covers it.
struct MapSpace;

impl MappedObject for MapSpace {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        // Release the lock before the buffer reference: dropping the last one locks it again
        let (start, bo) = {
            let space = MAP_SPACE.lock();
            let (&start, bo) = space.range(..=pgoff).next_back()?;
            (start, bo.upgrade()?)
        };
        let frame = bo.frames.get((pgoff - start) as usize).copied();
        frame
    }
}

struct Framebuffer {
    bo: Arc<Bo>,
    width: u32,
    height: u32,
    pitch: u32,
    offset: u32,
    format: u32,
    /// The open file that created it (framebuffers die with their file).
    owner: u64,
    /// GEM handle in the owner's table (for `GETFB`).
    handle: u32,
}

#[derive(Clone, Copy)]
struct Cursor {
    x: i32,
    y: i32,
}

/// Global display state.
struct Kms {
    width: u32,
    height: u32,
    fbs: BTreeMap<u32, Arc<Framebuffer>>,
    next_fb: u32,
    /// Framebuffer on the CRTC (`None` = CRTC off).
    scanout: Option<Arc<Framebuffer>>,
    crtc_xy: (u32, u32),
    cursor_bo: Option<(Arc<Bo>, u32, u32)>,
    cursor: Cursor,
    /// Where the cursor was last drawn (to repair the picture under it).
    drawn_cursor: Option<(i32, i32, u32, u32)>,
    dpms: u64,
    master: Option<u64>,
    /// The screen while this driver shows it: (pixels, stride in pixels, bgr).
    screen: Option<(*mut u8, usize, bool)>,
    blobs: BTreeMap<u32, Vec<u8>>,
    next_blob: u32,
}

unsafe impl Send for Kms {}

static KMS: Mutex<Option<Kms>> = Mutex::new(None);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

fn with_kms<R>(f: impl FnOnce(&mut Kms) -> R) -> R {
    let mut guard = KMS.lock();
    let kms = guard.get_or_insert_with(|| {
        let (w, h) = crate::video::get_video_info().map_or((1024, 768), |i| (i.width as u32, i.height as u32));
        Kms {
            width: w,
            height: h,
            fbs: BTreeMap::new(),
            next_fb: 100,
            scanout: None,
            crtc_xy: (0, 0),
            cursor_bo: None,
            cursor: Cursor { x: 0, y: 0 },
            drawn_cursor: None,
            dpms: 0,
            master: None,
            screen: None,
            blobs: BTreeMap::new(),
            next_blob: 1000,
        }
    });
    f(kms)
}

/// True while a DRM client shows a picture (the console and other compositors are hidden).
pub fn showing() -> bool {
    with_kms(|k| k.screen.is_some())
}

impl Kms {
    fn mode(&self) -> [u8; 68] {
        let (w, h) = (self.width, self.height);
        let (hs, he, ht) = (w + 16, w + 16 + 96, w + 160);
        let (vs, ve, vt) = (h + 3, h + 9, h + 30);
        let clock = ht * vt * 60 / 1000;
        let mut m = [0u8; 68];
        m[0..4].copy_from_slice(&clock.to_le_bytes());
        for (i, v) in [w, hs, he, ht, 0, h, vs, ve, vt, 0].iter().enumerate() {
            m[4 + i * 2..6 + i * 2].copy_from_slice(&(*v as u16).to_le_bytes());
        }
        m[24..28].copy_from_slice(&60u32.to_le_bytes());
        m[28..32].copy_from_slice(&0u32.to_le_bytes()); // flags
        m[32..36].copy_from_slice(&(0x8u32 | 0x40).to_le_bytes()); // PREFERRED | DRIVER
        let name = alloc::format!("{}x{}", w, h);
        m[36..36 + name.len()].copy_from_slice(name.as_bytes());
        m
    }

    /// Takes the screen from the console (first picture of a session).
    fn take_screen(&mut self) -> Result<(), i64> {
        if self.screen.is_some() {
            return Ok(());
        }
        if crate::wayland::is_running() && crate::video::console::display_released() {
            return Err(EBUSY); // Hydra's own compositor shows
        }
        let (fb, _w, _h, stride, bgr) = crate::video::console::release_display().ok_or(ENXIO)?;
        self.screen = Some((fb, stride, bgr));
        self.drawn_cursor = None;
        super::evdev::set_routing(true);
        Ok(())
    }

    /// Gives the screen back to the console.
    fn give_screen(&mut self) {
        if self.screen.take().is_some() {
            super::evdev::set_routing(false);
            crate::video::console::reclaim_display();
        }
    }

    /// Copies rows `y0..y1`, columns `x0..x1` of the scanout framebuffer to the screen.
    fn copy_rect(&self, x0: u32, y0: u32, x1: u32, y1: u32) {
        let (screen, stride, bgr) = match self.screen {
            Some(s) => s,
            None => return,
        };
        let x1 = x1.min(self.width);
        let y1 = y1.min(self.height);
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let fb = match &self.scanout {
            Some(fb) => fb,
            None => {
                for y in y0..y1 {
                    unsafe { core::ptr::write_bytes(screen.add((y as usize * stride + x0 as usize) * 4), 0, (x1 - x0) as usize * 4) };
                }
                return;
            }
        };
        let (cx, cy) = self.crtc_xy;
        for y in y0..y1 {
            let fy = y + cy;
            if fy >= fb.height {
                break;
            }
            let fx0 = x0 + cx;
            let n = (x1 - x0).min(fb.width.saturating_sub(fx0)) as usize;
            let src = fb.offset as u64 + fy as u64 * fb.pitch as u64 + fx0 as u64 * 4;
            let dst = unsafe { screen.add((y as usize * stride + x0 as usize) * 4) };
            fb.bo.read(src, dst, n * 4);
            if !bgr {
                let px = unsafe { core::slice::from_raw_parts_mut(dst, n * 4) };
                for p in px.chunks_exact_mut(4) {
                    p.swap(0, 2);
                }
            }
        }
    }

    /// Blends the cursor image over the screen at its position.
    fn draw_cursor(&mut self) {
        let (screen, stride, bgr) = match self.screen {
            Some(s) => s,
            None => return,
        };
        let (bo, w, h) = match &self.cursor_bo {
            Some(c) => c.clone(),
            None => return,
        };
        let Cursor { x, y } = self.cursor;
        let mut row = alloc::vec![0u8; w as usize * 4];
        for r in 0..h as i32 {
            let sy = y + r;
            if sy < 0 || sy >= self.height as i32 {
                continue;
            }
            bo.read(r as u64 * w as u64 * 4, row.as_mut_ptr(), row.len());
            for c in 0..w as i32 {
                let sx = x + c;
                if sx < 0 || sx >= self.width as i32 {
                    continue;
                }
                let p = &row[c as usize * 4..c as usize * 4 + 4];
                let a = p[3] as u32;
                if a == 0 {
                    continue;
                }
                let d = unsafe { core::slice::from_raw_parts_mut(screen.add((sy as usize * stride + sx as usize) * 4), 4) };
                let (sb, sg, sr) = (p[0] as u32, p[1] as u32, p[2] as u32);
                let (bi, ri) = if bgr { (0, 2) } else { (2, 0) };
                // Premultiplied alpha: out = src + dst * (1 - a)
                d[bi] = (sb + d[bi] as u32 * (255 - a) / 255).min(255) as u8;
                d[1] = (sg + d[1] as u32 * (255 - a) / 255).min(255) as u8;
                d[ri] = (sr + d[ri] as u32 * (255 - a) / 255).min(255) as u8;
            }
        }
        self.drawn_cursor = Some((x, y, w, h));
    }

    /// Repaints the whole screen from the scanout framebuffer.
    fn present(&mut self) {
        if self.screen.is_none() || self.dpms != 0 {
            return;
        }
        self.copy_rect(0, 0, self.width, self.height);
        self.drawn_cursor = None;
        self.draw_cursor();
    }

    /// Moves or changes the cursor, repairing only the area it covered.
    fn update_cursor(&mut self) {
        if self.screen.is_none() || self.dpms != 0 {
            return;
        }
        if let Some((x, y, w, h)) = self.drawn_cursor.take() {
            let (x0, y0) = (x.max(0) as u32, y.max(0) as u32);
            let (x1, y1) = ((x + w as i32).max(0) as u32, (y + h as i32).max(0) as u32);
            self.copy_rect(x0, y0, x1, y1);
        }
        self.draw_cursor();
    }
}

/// One open file of the device.
pub struct DrmFile {
    id: u64,
    handles: Mutex<BTreeMap<u32, Arc<Bo>>>,
    next_handle: Mutex<u32>,
    events: Mutex<VecDeque<[u8; 32]>>,
    wq: Arc<WaitQueue>,
    nonblock: AtomicBool,
    universal_planes: AtomicBool,
}

/// Opens minor `minor` (`card0` only).
pub fn open(minor: u64, nonblock: bool) -> Result<Arc<dyn CharDevice>, i64> {
    if minor != 0 {
        return Err(ENXIO);
    }
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    // The first opener of an unmastered device becomes master
    with_kms(|k| {
        if k.master.is_none() {
            k.master = Some(id);
        }
    });
    Ok(Arc::new(DrmFile {
        id,
        handles: Mutex::new(BTreeMap::new()),
        next_handle: Mutex::new(1),
        events: Mutex::new(VecDeque::new()),
        wq: WaitQueue::new_shared(),
        nonblock: AtomicBool::new(nonblock),
        universal_planes: AtomicBool::new(false),
    }))
}

impl Drop for DrmFile {
    fn drop(&mut self) {
        let id = self.id;
        with_kms(|k| {
            k.fbs.retain(|_, fb| fb.owner != id);
            if k.scanout.as_ref().map_or(false, |fb| fb.owner == id) {
                k.scanout = None;
            }
            if k.master == Some(id) {
                k.master = None;
                k.cursor_bo = None;
                k.give_screen();
            }
        });
    }
}

fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn get64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Writes `items` to the user array at `ptr` if its capacity `cap` holds them all.
fn put_array<T: Copy>(ptr: u64, cap: u32, items: &[T], to_bytes: impl Fn(T) -> Vec<u8>) -> Result<(), i64> {
    if ptr == 0 || (cap as usize) < items.len() || items.is_empty() {
        return Ok(());
    }
    let mut out = Vec::new();
    for &i in items {
        out.extend_from_slice(&to_bytes(i));
    }
    copy_out(ptr, &out)
}

fn u32s(ptr: u64, cap: u32, items: &[u32]) -> Result<(), i64> {
    put_array(ptr, cap, items, |v| v.to_le_bytes().to_vec())
}

fn u64s(ptr: u64, cap: u32, items: &[u64]) -> Result<(), i64> {
    put_array(ptr, cap, items, |v| v.to_le_bytes().to_vec())
}

/// Copies a string to a `drm_version`-style (length, pointer) pair.
fn put_string(b: &mut [u8], len_off: usize, s: &str) -> Result<(), i64> {
    let cap = get64(b, len_off) as usize;
    let ptr = get64(b, len_off + 8);
    if ptr != 0 && cap > 0 {
        copy_out(ptr, &s.as_bytes()[..s.len().min(cap)])?;
    }
    put64(b, len_off, s.len() as u64);
    Ok(())
}

/// Microseconds on the monotonic clock (`CLOCK_MONOTONIC`, which libdrm assumes).
fn now_us() -> u64 {
    crate::arch::pit::ticks() * 10_000
}

/// Properties of an object: (ids, values).
fn object_props(k: &Kms, obj: u32) -> Option<(Vec<u32>, Vec<u64>)> {
    match obj {
        CONNECTOR_ID => Some((alloc::vec![PROP_DPMS, PROP_EDID, PROP_NON_DESKTOP], alloc::vec![k.dpms, 0, 0])),
        PRIMARY_PLANE_ID => Some((alloc::vec![PROP_TYPE], alloc::vec![1])),
        CURSOR_PLANE_ID => Some((alloc::vec![PROP_TYPE], alloc::vec![2])),
        CRTC_ID | ENCODER_ID => Some((Vec::new(), Vec::new())),
        _ => None,
    }
}

impl DrmFile {
    fn is_master(&self) -> bool {
        with_kms(|k| k.master == Some(self.id))
    }

    fn bo(&self, handle: u32) -> Result<Arc<Bo>, i64> {
        self.handles.lock().get(&handle).cloned().ok_or(ENOENT)
    }

    fn queue_event(&self, kind: u32, user_data: u64, crtc: u32) {
        let now = now_us();
        let mut ev = [0u8; 32];
        put32(&mut ev, 0, kind);
        put32(&mut ev, 4, 32);
        put64(&mut ev, 8, user_data);
        put32(&mut ev, 16, (now / 1_000_000) as u32);
        put32(&mut ev, 20, (now % 1_000_000) as u32);
        put32(&mut ev, 24, (now / FRAME_US) as u32);
        put32(&mut ev, 28, crtc);
        self.events.lock().push_back(ev);
        self.wq.wake_all();
    }

    fn add_fb(&self, width: u32, height: u32, format: u32, handle: u32, pitch: u32, offset: u32) -> Result<u32, i64> {
        if format != FMT_XRGB8888 && format != FMT_ARGB8888 {
            return Err(EINVAL);
        }
        let bo = self.bo(handle)?;
        if width == 0 || height == 0 || pitch < width * 4 || offset as u64 + pitch as u64 * height as u64 > bo.size {
            return Err(EINVAL);
        }
        Ok(with_kms(|k| {
            let id = k.next_fb;
            k.next_fb += 1;
            k.fbs.insert(id, Arc::new(Framebuffer { bo, width, height, pitch, offset, format, owner: self.id, handle }));
            id
        }))
    }

    fn handle(&self, nr: u64, b: &mut [u8]) -> Result<i64, i64> {
        match nr {
            0x00 => {
                // VERSION
                put32(b, 0, 1);
                put32(b, 4, 0);
                put32(b, 8, 0);
                put_string(b, 16, "hydradrm")?;
                put_string(b, 32, "20261031")?;
                put_string(b, 48, "Hydra kernel mode setting")?;
                Ok(0)
            }
            0x01 => {
                // GET_UNIQUE: the PCI slot of the display adapter
                let slot = super::devices::vga_slot();
                let cap = get64(b, 0) as usize;
                let ptr = get64(b, 8);
                if ptr != 0 && cap > 0 {
                    copy_out(ptr, &slot.as_bytes()[..slot.len().min(cap)])?;
                }
                put64(b, 0, slot.len() as u64);
                Ok(0)
            }
            0x02 => {
                // GET_MAGIC
                put32(b, 0, self.id as u32);
                Ok(0)
            }
            0x07 => {
                // SET_VERSION: interface 1.4, driver 1.0
                let di_major = get32(b, 0) as i32;
                if di_major != -1 && (di_major != 1 || get32(b, 4) as i32 > 4) {
                    return Err(EINVAL);
                }
                put32(b, 0, 1);
                put32(b, 4, 4);
                put32(b, 8, 1);
                put32(b, 12, 0);
                Ok(0)
            }
            0x09 => {
                // GEM_CLOSE
                self.handles.lock().remove(&get32(b, 0)).map(|_| 0).ok_or(EINVAL)
            }
            0x0c => {
                // GET_CAP
                let v = match get64(b, 0) {
                    0x1 => 1,          // DUMB_BUFFER
                    0x2 => 1,          // VBLANK_HIGH_CRTC
                    0x3 => 24,         // DUMB_PREFERRED_DEPTH
                    0x4 => 0,          // DUMB_PREFER_SHADOW
                    0x5 => 3,          // PRIME: import and export
                    0x6 => 1,          // TIMESTAMP_MONOTONIC
                    0x7 => 0,          // ASYNC_PAGE_FLIP
                    0x8 | 0x9 => CURSOR_SIZE as u64,
                    0x10 => 0,         // ADDFB2_MODIFIERS
                    0x11 => 0,         // PAGE_FLIP_TARGET
                    0x12 => 1,         // CRTC_IN_VBLANK_EVENT
                    0x13 | 0x14 => 0,  // SYNCOBJ(_TIMELINE)
                    0x15 => 0,         // ATOMIC_ASYNC_PAGE_FLIP
                    _ => return Err(EINVAL),
                };
                put64(b, 8, v);
                Ok(0)
            }
            0x0d => {
                // SET_CLIENT_CAP
                match (get64(b, 0), get64(b, 8)) {
                    (1, _) | (4, _) => Ok(0), // STEREO_3D, ASPECT_RATIO
                    (2, v) => {
                        self.universal_planes.store(v != 0, Ordering::Relaxed);
                        Ok(0)
                    }
                    (3, _) => Err(EOPNOTSUPP), // ATOMIC
                    _ => Err(EINVAL),
                }
            }
            0x11 => Ok(0), // AUTH_MAGIC
            0x1e => {
                // SET_MASTER
                with_kms(|k| match k.master {
                    None => {
                        k.master = Some(self.id);
                        Ok(0)
                    }
                    Some(m) if m == self.id => Ok(0),
                    Some(_) => Err(EBUSY),
                })
            }
            0x1f => {
                // DROP_MASTER
                with_kms(|k| {
                    if k.master != Some(self.id) {
                        return Err(EINVAL);
                    }
                    k.master = None;
                    Ok(0)
                })
            }
            0x3a => {
                // WAIT_VBLANK: answers at once with the current frame
                let ty = get32(b, 0);
                let now = now_us();
                if ty & 0x0400_0000 != 0 {
                    // _DRM_VBLANK_EVENT
                    self.queue_event(1, get64(b, 8), CRTC_ID);
                }
                put32(b, 4, (now / FRAME_US) as u32);
                put64(b, 8, now / 1_000_000);
                put64(b, 16, now % 1_000_000);
                Ok(0)
            }
            0x3b => {
                // CRTC_GET_SEQUENCE
                let now = now_us();
                put32(b, 4, with_kms(|k| k.scanout.is_some()) as u32);
                put64(b, 8, now / FRAME_US);
                put64(b, 16, now * 1000);
                Ok(0)
            }
            0xA0 => {
                // MODE_GETRESOURCES
                let fbs: Vec<u32> = with_kms(|k| k.fbs.iter().filter(|(_, f)| f.owner == self.id).map(|(&id, _)| id).collect());
                u32s(get64(b, 0), get32(b, 32), &fbs)?;
                u32s(get64(b, 8), get32(b, 36), &[CRTC_ID])?;
                u32s(get64(b, 16), get32(b, 40), &[CONNECTOR_ID])?;
                u32s(get64(b, 24), get32(b, 44), &[ENCODER_ID])?;
                put32(b, 32, fbs.len() as u32);
                put32(b, 36, 1);
                put32(b, 40, 1);
                put32(b, 44, 1);
                let (w, h) = with_kms(|k| (k.width, k.height));
                put32(b, 48, 1);
                put32(b, 52, w.max(4096));
                put32(b, 56, 1);
                put32(b, 60, h.max(4096));
                Ok(0)
            }
            0xA1 => {
                // MODE_GETCRTC
                if get32(b, 12) != CRTC_ID {
                    return Err(ENOENT);
                }
                with_kms(|k| {
                    let fb_id = k.scanout.as_ref().and_then(|s| k.fbs.iter().find(|(_, f)| Arc::ptr_eq(f, s)).map(|(&id, _)| id));
                    put32(b, 16, fb_id.unwrap_or(0));
                    put32(b, 20, k.crtc_xy.0);
                    put32(b, 24, k.crtc_xy.1);
                    put32(b, 28, 256); // gamma_size
                    put32(b, 32, k.scanout.is_some() as u32);
                    if k.scanout.is_some() {
                        b[36..104].copy_from_slice(&k.mode());
                    } else {
                        b[36..104].fill(0);
                    }
                });
                Ok(0)
            }
            0xA2 => {
                // MODE_SETCRTC
                if !self.is_master() {
                    return Err(EACCES);
                }
                if get32(b, 12) != CRTC_ID {
                    return Err(ENOENT);
                }
                let count = get32(b, 8);
                if count > 0 {
                    let raw = copy_in(get64(b, 0), count as usize * 4)?;
                    if raw.chunks_exact(4).any(|c| u32::from_le_bytes(c.try_into().unwrap()) != CONNECTOR_ID) {
                        return Err(ENOENT);
                    }
                }
                let fb_id = get32(b, 16);
                let (x, y) = (get32(b, 20), get32(b, 24));
                let mode_valid = get32(b, 32) != 0;
                with_kms(|k| {
                    if !mode_valid {
                        k.scanout = None;
                        k.give_screen();
                        return Ok(0);
                    }
                    let hd = u16::from_le_bytes([b[40], b[41]]) as u32;
                    let vd = u16::from_le_bytes([b[50], b[51]]) as u32;
                    if hd != k.width || vd != k.height {
                        return Err(EINVAL);
                    }
                    let fb = if fb_id == u32::MAX {
                        k.scanout.clone().ok_or(EINVAL)?
                    } else {
                        k.fbs.get(&fb_id).cloned().ok_or(ENOENT)?
                    };
                    if x + k.width > fb.width || y + k.height > fb.height {
                        return Err(ENOSPC);
                    }
                    k.take_screen()?;
                    k.scanout = Some(fb);
                    k.crtc_xy = (x, y);
                    k.present();
                    Ok(0)
                })
            }
            0xA3 | 0xBB => {
                // MODE_CURSOR / MODE_CURSOR2
                if !self.is_master() {
                    return Err(EACCES);
                }
                let flags = get32(b, 0);
                let (x, y) = (get32(b, 8) as i32, get32(b, 12) as i32);
                let (w, h, handle) = (get32(b, 16), get32(b, 20), get32(b, 24));
                let new_bo = if flags & 1 != 0 && handle != 0 {
                    if w > CURSOR_SIZE || h > CURSOR_SIZE {
                        return Err(EINVAL);
                    }
                    Some(self.bo(handle)?)
                } else {
                    None
                };
                with_kms(|k| {
                    if flags & 1 != 0 {
                        k.cursor_bo = new_bo.map(|bo| (bo, w, h));
                    }
                    if flags & 2 != 0 {
                        k.cursor = Cursor { x, y };
                    }
                    k.update_cursor();
                });
                Ok(0)
            }
            0xA4 | 0xA5 => {
                // GET/SETGAMMA: a 256-entry ramp that is accepted but not applied
                if get32(b, 0) != CRTC_ID {
                    return Err(ENOENT);
                }
                if get32(b, 4) != 256 {
                    return Err(EINVAL);
                }
                if nr == 0xA4 {
                    let ramp: Vec<u8> = (0..256u32).flat_map(|i| ((i * 0x101) as u16).to_le_bytes()).collect();
                    for off in [8, 16, 24] {
                        copy_out(get64(b, off), &ramp)?;
                    }
                }
                Ok(0)
            }
            0xA6 => {
                // MODE_GETENCODER
                if get32(b, 0) != ENCODER_ID {
                    return Err(ENOENT);
                }
                put32(b, 4, 5); // DRM_MODE_ENCODER_VIRTUAL
                put32(b, 8, CRTC_ID);
                put32(b, 12, 1);
                put32(b, 16, 0);
                Ok(0)
            }
            0xA7 => {
                // MODE_GETCONNECTOR
                if get32(b, 48) != CONNECTOR_ID {
                    return Err(ENOENT);
                }
                let (mode, w, h, props) = with_kms(|k| (k.mode(), k.width, k.height, object_props(k, CONNECTOR_ID).unwrap()));
                put_array(get64(b, 8), get32(b, 32), &[mode], |m| m.to_vec())?;
                u32s(get64(b, 16), get32(b, 36), &props.0)?;
                u64s(get64(b, 24), get32(b, 36), &props.1)?;
                u32s(get64(b, 0), get32(b, 40), &[ENCODER_ID])?;
                put32(b, 32, 1);
                put32(b, 36, props.0.len() as u32);
                put32(b, 40, 1);
                put32(b, 44, ENCODER_ID);
                put32(b, 52, 15); // DRM_MODE_CONNECTOR_VIRTUAL
                put32(b, 56, 1);
                put32(b, 60, 1); // connected
                put32(b, 64, w * 254 / 960); // 96 dpi
                put32(b, 68, h * 254 / 960);
                put32(b, 72, 1); // subpixel unknown
                Ok(0)
            }
            0xAA => {
                // MODE_GETPROPERTY
                let id = get32(b, 16);
                let (name, flags, values, enums): (&str, u32, Vec<u64>, Vec<(u64, &str)>) = match id {
                    PROP_DPMS => ("DPMS", PROP_ENUM, alloc::vec![0, 1, 2, 3], alloc::vec![(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")]),
                    PROP_EDID => ("EDID", PROP_BLOB | PROP_IMMUTABLE, Vec::new(), Vec::new()),
                    PROP_NON_DESKTOP => ("non-desktop", PROP_RANGE | PROP_IMMUTABLE, alloc::vec![0, 1], Vec::new()),
                    PROP_TYPE => ("type", PROP_ENUM | PROP_IMMUTABLE, alloc::vec![0, 1, 2], alloc::vec![(0, "Overlay"), (1, "Primary"), (2, "Cursor")]),
                    _ => return Err(ENOENT),
                };
                put32(b, 20, flags);
                b[24..56].fill(0);
                b[24..24 + name.len()].copy_from_slice(name.as_bytes());
                u64s(get64(b, 0), get32(b, 56), &values)?;
                put_array(get64(b, 8), get32(b, 60), &enums, |(v, n)| {
                    let mut e = alloc::vec![0u8; 40];
                    e[0..8].copy_from_slice(&v.to_le_bytes());
                    e[8..8 + n.len()].copy_from_slice(n.as_bytes());
                    e
                })?;
                put32(b, 56, values.len() as u32);
                put32(b, 60, enums.len() as u32);
                Ok(0)
            }
            0xAB => {
                // MODE_SETPROPERTY (connector)
                if get32(b, 12) != CONNECTOR_ID {
                    return Err(ENOENT);
                }
                self.set_property(get32(b, 8), get64(b, 0))
            }
            0xAC => {
                // MODE_GETPROPBLOB
                let data = with_kms(|k| k.blobs.get(&get32(b, 0)).cloned()).ok_or(ENOENT)?;
                let cap = get32(b, 4) as usize;
                if cap >= data.len() && get64(b, 8) != 0 {
                    copy_out(get64(b, 8), &data)?;
                }
                put32(b, 4, data.len() as u32);
                Ok(0)
            }
            0xAD => {
                // MODE_GETFB
                let fb = with_kms(|k| k.fbs.get(&get32(b, 0)).cloned()).ok_or(ENOENT)?;
                put32(b, 4, fb.width);
                put32(b, 8, fb.height);
                put32(b, 12, fb.pitch);
                put32(b, 16, 32);
                put32(b, 20, if fb.format == FMT_ARGB8888 { 32 } else { 24 });
                put32(b, 24, if fb.owner == self.id { fb.handle } else { 0 });
                Ok(0)
            }
            0xAE => {
                // MODE_ADDFB (legacy bpp/depth)
                let (w, h, pitch, bpp, depth, handle) = (get32(b, 4), get32(b, 8), get32(b, 12), get32(b, 16), get32(b, 20), get32(b, 24));
                let format = match (bpp, depth) {
                    (32, 24) => FMT_XRGB8888,
                    (32, 32) => FMT_ARGB8888,
                    _ => return Err(EINVAL),
                };
                let id = self.add_fb(w, h, format, handle, pitch, 0)?;
                put32(b, 0, id);
                Ok(0)
            }
            0xAF => {
                // MODE_RMFB: a framebuffer being shown is turned off first
                let id = get32(b, 0);
                with_kms(|k| {
                    let fb = k.fbs.get(&id).cloned().ok_or(ENOENT)?;
                    if fb.owner != self.id {
                        return Err(ENOENT);
                    }
                    k.fbs.remove(&id);
                    if k.scanout.as_ref().map_or(false, |s| Arc::ptr_eq(s, &fb)) {
                        k.scanout = None;
                        k.present();
                    }
                    Ok(0)
                })
            }
            0xB0 => {
                // MODE_PAGE_FLIP: shown at once; the event follows immediately
                if !self.is_master() {
                    return Err(EACCES);
                }
                if get32(b, 0) != CRTC_ID {
                    return Err(ENOENT);
                }
                let (fb_id, flags, user_data) = (get32(b, 4), get32(b, 8), get64(b, 16));
                if flags & !0x3 != 0 {
                    return Err(EINVAL);
                }
                with_kms(|k| {
                    if k.scanout.is_none() {
                        return Err(EINVAL);
                    }
                    let fb = k.fbs.get(&fb_id).cloned().ok_or(ENOENT)?;
                    k.scanout = Some(fb);
                    k.present();
                    Ok(())
                })?;
                if flags & 1 != 0 {
                    self.queue_event(2, user_data, CRTC_ID); // DRM_EVENT_FLIP_COMPLETE
                }
                Ok(0)
            }
            0xB1 => {
                // MODE_DIRTYFB
                with_kms(|k| {
                    let fb = k.fbs.get(&get32(b, 0)).cloned().ok_or(ENOENT)?;
                    if k.scanout.as_ref().map_or(false, |s| Arc::ptr_eq(s, &fb)) {
                        k.present();
                    }
                    Ok(0)
                })
            }
            0xB2 => {
                // MODE_CREATE_DUMB
                let (h, w, bpp) = (get32(b, 0), get32(b, 4), get32(b, 8));
                if w == 0 || h == 0 || bpp == 0 || bpp > 32 || w > 8192 || h > 8192 {
                    return Err(EINVAL);
                }
                let pitch = (w * ((bpp + 7) / 8) + 63) & !63;
                let size = (pitch as u64 * h as u64 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let bo = Bo::new(size).ok_or(ENOMEM)?;
                let handle = {
                    let mut next = self.next_handle.lock();
                    let h = *next;
                    *next += 1;
                    h
                };
                self.handles.lock().insert(handle, bo);
                put32(b, 16, handle);
                put32(b, 20, pitch);
                put64(b, 24, size);
                Ok(0)
            }
            0xB3 => {
                // MODE_MAP_DUMB
                let bo = self.bo(get32(b, 0))?;
                put64(b, 8, bo.map_pgoff * PAGE_SIZE);
                Ok(0)
            }
            0xB4 => {
                // MODE_DESTROY_DUMB
                self.handles.lock().remove(&get32(b, 0)).map(|_| 0).ok_or(ENOENT)
            }
            0xB5 => {
                // MODE_GETPLANERESOURCES
                let planes: &[u32] = if self.universal_planes.load(Ordering::Relaxed) { &[PRIMARY_PLANE_ID, CURSOR_PLANE_ID] } else { &[] };
                u32s(get64(b, 0), get32(b, 8), planes)?;
                put32(b, 8, planes.len() as u32);
                Ok(0)
            }
            0xB6 => {
                // MODE_GETPLANE
                let id = get32(b, 0);
                let formats: &[u32] = match id {
                    PRIMARY_PLANE_ID => &[FMT_XRGB8888, FMT_ARGB8888],
                    CURSOR_PLANE_ID => &[FMT_ARGB8888],
                    _ => return Err(ENOENT),
                };
                put32(b, 4, if id == PRIMARY_PLANE_ID && showing() { CRTC_ID } else { 0 });
                put32(b, 8, 0);
                put32(b, 12, 1);
                put32(b, 16, 0);
                u32s(get64(b, 24), get32(b, 20), formats)?;
                put32(b, 20, formats.len() as u32);
                Ok(0)
            }
            0xB7 => Err(EINVAL), // MODE_SETPLANE
            0xB8 => {
                // MODE_ADDFB2
                let (w, h, format, flags) = (get32(b, 4), get32(b, 8), get32(b, 12), get32(b, 16));
                if flags & 2 != 0 && get64(b, 72) != 0 {
                    return Err(EINVAL); // only linear buffers
                }
                let id = self.add_fb(w, h, format, get32(b, 20), get32(b, 36), get32(b, 52))?;
                put32(b, 0, id);
                Ok(0)
            }
            0xB9 => {
                // MODE_OBJ_GETPROPERTIES
                let (ids, values) = with_kms(|k| object_props(k, get32(b, 20))).ok_or(ENOENT)?;
                u32s(get64(b, 0), get32(b, 16), &ids)?;
                u64s(get64(b, 8), get32(b, 16), &values)?;
                put32(b, 16, ids.len() as u32);
                Ok(0)
            }
            0xBA => {
                // MODE_OBJ_SETPROPERTY
                match (get32(b, 12), get32(b, 16)) {
                    (CONNECTOR_ID, OBJ_CONNECTOR) | (CONNECTOR_ID, 0) => self.set_property(get32(b, 8), get64(b, 0)),
                    (CRTC_ID, OBJ_CRTC) | (ENCODER_ID, OBJ_ENCODER) | (PRIMARY_PLANE_ID, OBJ_PLANE) | (CURSOR_PLANE_ID, OBJ_PLANE) => Err(EINVAL),
                    _ => Err(ENOENT),
                }
            }
            0xBC => Err(EINVAL), // MODE_ATOMIC (the client cap is refused)
            0xBD => {
                // MODE_CREATEPROPBLOB
                let len = get32(b, 8) as usize;
                if len == 0 || len > 1 << 20 {
                    return Err(EINVAL);
                }
                let data = copy_in(get64(b, 0), len)?;
                let id = with_kms(|k| {
                    let id = k.next_blob;
                    k.next_blob += 1;
                    k.blobs.insert(id, data);
                    id
                });
                put32(b, 12, id);
                Ok(0)
            }
            0xBE => with_kms(|k| k.blobs.remove(&get32(b, 0)).map(|_| 0).ok_or(ENOENT)), // DESTROYPROPBLOB
            0xCE => {
                // MODE_GETFB2
                let fb = with_kms(|k| k.fbs.get(&get32(b, 0)).cloned()).ok_or(ENOENT)?;
                put32(b, 4, fb.width);
                put32(b, 8, fb.height);
                put32(b, 12, fb.format);
                put32(b, 16, 0);
                b[20..104].fill(0);
                put32(b, 20, if fb.owner == self.id { fb.handle } else { 0 });
                put32(b, 36, fb.pitch);
                put32(b, 52, fb.offset);
                Ok(0)
            }
            0x2d => {
                // PRIME_HANDLE_TO_FD: a DMA-BUF descriptor for the buffer
                let bo = self.bo(get32(b, 0))?;
                let flags = get32(b, 4);
                let buf: Arc<dyn CharDevice> = Arc::new(DmaBuf { bo, nonblock: AtomicBool::new(false) });
                let fd = crate::task::with_current_fds_mut(|fds| {
                    let fd = fds.alloc_fd(crate::fs::FileDescriptor::Device(buf)).map_err(|_| -24i64)?;
                    fds.set_cloexec(fd, flags & 0o2000000 != 0);
                    Ok::<usize, i64>(fd)
                })?;
                put32(b, 8, fd as u32);
                Ok(0)
            }
            0x2e => {
                // PRIME_FD_TO_HANDLE: the same handle again for a buffer this file knows
                let fd = get32(b, 8) as usize;
                let dev = crate::task::with_current_fds_mut(|fds| match fds.get(fd) {
                    Some(crate::fs::FileDescriptor::Device(d)) => Some(d.clone()),
                    _ => None,
                })
                .ok_or(-9i64)?;
                let bo = dev.dma_buf().and_then(|a| a.downcast::<Bo>().ok()).ok_or(EINVAL)?;
                let mut handles = self.handles.lock();
                let handle = match handles.iter().find(|(_, h)| Arc::ptr_eq(h, &bo)) {
                    Some((&h, _)) => h,
                    None => {
                        let mut next = self.next_handle.lock();
                        let h = *next;
                        *next += 1;
                        handles.insert(h, bo);
                        h
                    }
                };
                put32(b, 0, handle);
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }

    fn set_property(&self, prop: u32, value: u64) -> Result<i64, i64> {
        if !self.is_master() {
            return Err(EACCES);
        }
        match prop {
            PROP_DPMS if value <= 3 => {
                with_kms(|k| {
                    k.dpms = value;
                    if value == 0 {
                        k.present();
                    }
                });
                Ok(0)
            }
            PROP_DPMS => Err(EINVAL),
            PROP_EDID | PROP_NON_DESKTOP => Err(EPERM),
            _ => Err(ENOENT),
        }
    }
}

impl CharDevice for DrmFile {
    fn read(&self, buf: &mut [u8]) -> i64 {
        let mut waits = WaitSet::new();
        waits.add(QueueRef::Shared(self.wq.clone()));
        loop {
            waits.register();
            {
                let mut events = self.events.lock();
                let mut n = 0;
                while let Some(ev) = events.front() {
                    if buf.len() - n < ev.len() {
                        break;
                    }
                    buf[n..n + ev.len()].copy_from_slice(ev);
                    n += ev.len();
                    events.pop_front();
                }
                if n > 0 {
                    return n as i64;
                }
                if !events.is_empty() {
                    return EINVAL; // buffer too small for one event
                }
            }
            if self.nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            waits.wait(None);
        }
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        if (cmd >> 8) & 0xFF != 0x64 {
            return -25; // ENOTTY: not a DRM request
        }
        let nr = cmd & 0xFF;
        let size = ((cmd >> 16) & 0x3FFF) as usize;
        let dir = cmd >> 30;
        let mut b = alloc::vec![0u8; size.max(128)];
        if dir & 1 != 0 && size > 0 {
            match copy_in(arg, size) {
                Ok(v) => b[..size].copy_from_slice(&v),
                Err(_) => return EFAULT,
            }
        }
        match self.handle(nr, &mut b) {
            Ok(r) => {
                if dir & 2 != 0 && size > 0 && copy_out(arg, &b[..size]).is_err() {
                    return EFAULT;
                }
                r
            }
            Err(e) => e,
        }
    }

    fn poll_events(&self) -> u32 {
        0x0004 | if self.events.lock().is_empty() { 0 } else { 0x0001 }
    }

    fn add_wait_queues(&self, waits: &mut WaitSet) {
        waits.add(QueueRef::Shared(self.wq.clone()));
    }

    fn rdev(&self) -> u64 {
        makedev(226, 0)
    }

    fn path(&self) -> String {
        String::from("/dev/dri/card0")
    }

    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Ok(Arc::new(MapSpace))
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }
}

/// A buffer exported as a DMA-BUF descriptor: mapping it maps the buffer's pages.
struct DmaBuf {
    bo: Arc<Bo>,
    nonblock: AtomicBool,
}

/// The pages of one buffer, from offset 0 (a DMA-BUF mapping).
struct BoPages(Arc<Bo>);

impl MappedObject for BoPages {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        self.0.frames.get(pgoff as usize).copied()
    }
}

impl CharDevice for DmaBuf {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }

    fn ioctl(&self, cmd: u64, _arg: u64) -> i64 {
        match cmd {
            0x4008_6200 => 0,                // DMA_BUF_IOCTL_SYNC: memory is always coherent
            0x4008_6201 | 0x4004_6201 => 0, // DMA_BUF_SET_NAME
            _ => -25,                        // ENOTTY: no sync files
        }
    }

    fn poll_events(&self) -> u32 {
        0x0001 | 0x0004 // no fences: always ready
    }

    fn add_wait_queues(&self, _waits: &mut WaitSet) {}

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        String::from("/dmabuf:")
    }

    fn mmap_object(&self) -> Result<Arc<dyn MappedObject>, i64> {
        Ok(Arc::new(BoPages(self.bo.clone())))
    }

    fn dma_buf(&self) -> Option<Arc<dyn core::any::Any + Send + Sync>> {
        Some(self.bo.clone())
    }

    fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    fn stat(&self) -> super::types::LinuxStat {
        let mut st = super::types::LinuxStat::default();
        st.st_dev = 0xd;
        st.st_ino = self.bo.map_pgoff;
        st.st_mode = 0o100600;
        st.st_nlink = 1;
        st.st_size = self.bo.size as i64;
        st.st_blksize = 4096;
        st
    }
}
