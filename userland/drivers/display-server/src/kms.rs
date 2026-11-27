//! # The Linux DRM layer (`/dev/dri/card0`), moved from the kernel's `drm.rs`
//!
//! A kernel mode-setting device for the firmware framebuffer, in the spirit of Linux's
//! `simpledrm`: one CRTC, one encoder and one connected virtual connector whose only mode is
//! the screen's resolution. Clients allocate dumb buffers (memory objects the service
//! makes; programs map them through the `mmap` answer), wrap them in framebuffers and show
//! them with the legacy `SETCRTC` / `PAGE_FLIP` calls. Atomic mode setting is refused, so
//! compositors use the legacy path. Buffers can be exported as DMA-BUF descriptors (PRIME:
//! server objects of this service) and imported back.
//!
//! What changed from the kernel copy (`docs/display-input-design.md`, decision 28):
//! - **Flips complete at the emulated vertical blank** ([`Kms::vblank`]), not at once: a
//!   compositor draws at most 60 pictures a second.
//! - **Completions are held back while the console shows** (Ctrl+Alt+F1): the compositor
//!   waits for its flip event and stops drawing; the picture and the event come when the
//!   session shows again.
//! - The picture copy runs in this service, outside the kernel (the native core,
//!   [`crate::native`]).
//!
//! Everything here is plain logic over the [`Env`] (the caller's memory, buffers, DMA-BUF
//! descriptors) and the [`Screen`]; `main.rs` provides both, the host tests fakes.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::native::{self as dcore, Screen, Src};
use crate::proto::{SCREEN_HIDDEN, SCREEN_SHOWN};

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const ENXIO: i64 = -6;
pub const EINVAL: i64 = -22;
pub const ENOTTY: i64 = -25;
pub const ENOSPC: i64 = -28;
pub const EOPNOTSUPP: i64 = -95;

/// Object ids (one id space for every KMS object, as in Linux).
pub const CRTC_ID: u32 = 40;
pub const ENCODER_ID: u32 = 41;
pub const CONNECTOR_ID: u32 = 42;
pub const PRIMARY_PLANE_ID: u32 = 43;
pub const CURSOR_PLANE_ID: u32 = 44;

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

/// `DRM_FORMAT_XRGB8888` / `ARGB8888`.
pub const FMT_XRGB8888: u32 = 0x3432_5258;
pub const FMT_ARGB8888: u32 = 0x3432_5241;

pub const CURSOR_SIZE: u32 = 64;
/// wave11 GD: rows the screen thread copies per band (1920-pixel rows: about 0.2 ms a band
/// on the NUC).
pub const BAND_ROWS: u32 = 64;

/// wave11 GD: the smallest rectangle holding `a` and `b` (`x0, y0, x1, y1`).
pub fn union_rect(a: (u32, u32, u32, u32), b: (u32, u32, u32, u32)) -> (u32, u32, u32, u32) {
    (a.0.min(b.0), a.1.min(b.1), a.2.max(b.2), a.3.max(b.3))
}
const PAGE: u64 = 4096;
/// `DRM_EVENT_VBLANK`, `DRM_EVENT_FLIP_COMPLETE`.
pub const EV_VBLANK: u32 = 1;
pub const EV_FLIP: u32 = 2;
/// How long the screen stays with a desktop that closed its last DRM file without a master
/// before the console takes it back: the next session (SDDM after a logout) opens sooner.
pub const GONE_GRACE_NS: u64 = 10_000_000_000;
/// Most completions one file may have waiting (held back behind the console they would
/// otherwise grow without bound): more vblank events are refused with `EBUSY`.
pub const PENDING_MAX: usize = 64;
/// Most bytes of dumb buffers one file may have made and still alive (a desktop uses a few
/// screen-sized buffers: 4 MiB each at 1280x800); past it `CREATE_DUMB` is `ENOMEM`.
pub const FILE_BYTES_MAX: u64 = 512 << 20;
/// Most bytes of dumb buffers alive in the whole service (every buffer is also mapped into
/// the service: one client must not exhaust it and end everyone's session).
pub const TOTAL_BYTES_MAX: u64 = 1536 << 20;
/// Most GEM handles one file may hold.
pub const HANDLES_MAX: usize = 4096;

/// A buffer's memory: the service's view of a memory object.
pub trait BoMem: Send + Sync {
    /// The first byte, in this service.
    fn ptr(&self) -> *mut u8;
    /// The memory object's handle (for the `mmap` answer).
    fn handle(&self) -> u32;
}

/// What a call needs from its caller and the system.
pub trait Env {
    /// `len` bytes at `ptr` of the caller.
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64>;
    /// Writes `data` to `ptr` of the caller.
    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64>;
    /// New zeroed buffer memory of `size` bytes.
    fn new_mem(&self, size: u64) -> Result<Box<dyn BoMem>, i64>;
    /// A new DMA-BUF descriptor of `size` bytes in the caller's table (`O_CLOEXEC` in
    /// `flags`): `(fd, slot)`.
    fn install_dmabuf(&self, flags: u32, size: u64) -> Result<(i64, u32), i64>;
    /// The slot of this service's DMA-BUF object behind the caller's descriptor `fd`.
    fn dmabuf_slot(&self, fd: u32) -> Result<u32, i64>;
    /// Whether the caller holds `CAP_SYS_ADMIN` (Linux's test for `SET_MASTER`).
    fn privileged(&self) -> bool;
}

/// One dumb buffer.
pub struct Bo {
    pub mem: Box<dyn BoMem>,
    pub size: u64,
    /// Page offset of the buffer in the device's `mmap` space.
    pub map_pgoff: u64,
    /// The byte counts it is charged to (its creator file's, the service's): given back
    /// when the last reference goes.
    charged: [Arc<AtomicU64>; 2],
}

impl Drop for Bo {
    fn drop(&mut self) {
        for c in &self.charged {
            c.fetch_sub(self.size, Ordering::Relaxed);
        }
    }
}

impl Bo {
    fn src(&self, offset: u64, pitch: u32, width: u32, height: u32) -> Src {
        Src { base: self.mem.ptr(), len: self.size, offset, pitch, width, height }
    }
}

/// A framebuffer.
pub struct Fb {
    pub bo: Arc<Bo>,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub offset: u32,
    pub format: u32,
    /// The open file that created it (framebuffers die with their file).
    pub owner: u32,
    /// GEM handle in the owner's table (for `GETFB`).
    pub handle: u32,
}

impl Fb {
    fn src(&self) -> Src {
        self.bo.src(self.offset as u64, self.pitch, self.width, self.height)
    }
}

/// One open file of the device (by its server object's slot).
pub struct File {
    pub handles: BTreeMap<u32, Arc<Bo>>,
    pub next_handle: u32,
    pub events: VecDeque<[u8; 32]>,
    pub universal_planes: bool,
    last_scanout: Option<Arc<Fb>>,
    last_crtc_xy: (u32, u32),
    last_cursor_bo: Option<(Arc<Bo>, u32, u32)>,
    last_cursor: (i32, i32),
    /// It was master once (Linux: it may take mastership back without `CAP_SYS_ADMIN`).
    was_master: bool,
    /// Bytes of the live dumb buffers it made.
    bytes: Arc<AtomicU64>,
}

impl File {
    fn new() -> Self {
        Self {
            handles: BTreeMap::new(),
            next_handle: 1,
            events: VecDeque::new(),
            universal_planes: false,
            last_scanout: None,
            last_crtc_xy: (0, 0),
            last_cursor_bo: None,
            last_cursor: (0, 0),
            was_master: false,
            bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    fn add_handle(&mut self, bo: Arc<Bo>) -> Result<u32, i64> {
        if self.handles.len() >= HANDLES_MAX {
            return Err(ENOSPC);
        }
        Ok(self.add_handle_unchecked(bo))
    }

    fn add_handle_unchecked(&mut self, bo: Arc<Bo>) -> u32 {
        let h = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(h, bo);
        h
    }
}

/// A completion waiting for a vertical blank: (file, event kind, user data).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub file: u32,
    pub kind: u32,
    pub user_data: u64,
}

/// Counters (the service's `[display]` lines; the waste findings' measurements).
#[derive(Default, Clone, Copy, Debug)]
pub struct Stats {
    pub ioctls: u64,
    /// `ioctl`s made while the console showed (the desktop should make none).
    pub ioctls_hidden: u64,
    pub flips: u64,
    /// Pictures copied to the screen (whole or damaged parts).
    pub presents: u64,
    pub completions: u64,
    /// Vertical blanks at which completions were held back (console shown).
    pub held: u64,
    pub copy_ns: u64,
    pub copy_max_ns: u64,
    pub cursor_updates: u64,
    // wave11 GG begin
    /// Time spent on cursor updates (the screen's part of the pointer's latency).
    pub cursor_ns: u64,
    pub cursor_max_ns: u64,
    /// Pixels composed and pixels actually written to the framebuffer.
    pub composed_px: u64,
    pub written_px: u64,
    // wave11 GG end
    /// wave11 GD: the longest wait from a flip to the end of its picture's copy (the copy
    /// runs in bands on the screen thread, cursor moves served in between).
    pub lat_max_ns: u64,
}

/// The device's state.
pub struct Kms {
    pub width: u32,
    pub height: u32,
    fbs: BTreeMap<u32, Arc<Fb>>,
    next_fb: u32,
    scanout: Option<Arc<Fb>>,
    crtc_xy: (u32, u32),
    cursor_bo: Option<(Arc<Bo>, u32, u32)>,
    cursor: (i32, i32),
    drawn_cursor: Option<(i32, i32, u32, u32)>,
    /// wave11 GG: what the screen shows (rows are written only where they change).
    shown: dcore::Shadow,
    dpms: u64,
    master: Option<u32>,
    blobs: BTreeMap<u32, Vec<u8>>,
    next_blob: u32,
    pub files: BTreeMap<u32, File>,
    pub dmabufs: BTreeMap<u32, Arc<Bo>>,
    map_space: BTreeMap<u64, Weak<Bo>>,
    next_map_pgoff: u64,
    /// The screen was taken for a session (until given back).
    taken: bool,
    pub pending: Vec<Pending>,
    /// wave11 GD: the part of the screen (`x0, y0, x1, y1`) a flip changed and the screen
    /// thread has not copied yet ([`Kms::copy_band`]), when that began, and the copy's time
    /// so far.
    dirty: Option<(u32, u32, u32, u32)>,
    dirty_since: u64,
    dirty_ns: u64,
    /// wave11 GD: flip completions waiting for that copy to end (then for the next blank).
    flip_wait: Vec<Pending>,
    /// Since when no file is open, no master, the screen still taken (the grace timer).
    gone_since: Option<u64>,
    pub screen: Box<dyn Screen>,
    pub vblank: dcore::Vblank,
    /// The adapter's PCI slot (`GET_UNIQUE`).
    pub slot: alloc::string::String,
    pub stats: Stats,
    /// Files whose event queue grew (the caller updates their readiness and wakes readers).
    pub woke: Vec<u32>,
    /// Bytes of all live dumb buffers.
    total_bytes: Arc<AtomicU64>,
    /// The byte limits: per file, whole service ([`FILE_BYTES_MAX`], [`TOTAL_BYTES_MAX`]).
    pub limits: (u64, u64),
}

pub fn get32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

pub fn get64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

pub fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Writes `items` to the caller's array at `ptr` if its capacity `cap` holds them all.
fn put_array<T: Copy>(env: &dyn Env, ptr: u64, cap: u32, items: &[T], to_bytes: impl Fn(T) -> Vec<u8>) -> Result<(), i64> {
    if ptr == 0 || (cap as usize) < items.len() || items.is_empty() {
        return Ok(());
    }
    let mut out = Vec::new();
    for &i in items {
        out.extend_from_slice(&to_bytes(i));
    }
    env.copy_out(ptr, &out)
}

fn u32s(env: &dyn Env, ptr: u64, cap: u32, items: &[u32]) -> Result<(), i64> {
    put_array(env, ptr, cap, items, |v| v.to_le_bytes().to_vec())
}

fn u64s(env: &dyn Env, ptr: u64, cap: u32, items: &[u64]) -> Result<(), i64> {
    put_array(env, ptr, cap, items, |v| v.to_le_bytes().to_vec())
}

/// A string into a `drm_version`-style (length, pointer) pair at `len_off`.
fn put_string(env: &dyn Env, b: &mut [u8], len_off: usize, s: &str) -> Result<(), i64> {
    let cap = get64(b, len_off) as usize;
    let ptr = get64(b, len_off + 8);
    if ptr != 0 && cap > 0 {
        env.copy_out(ptr, &s.as_bytes()[..s.len().min(cap)])?;
    }
    put64(b, len_off, s.len() as u64);
    Ok(())
}

/// A 68-byte `drm_mode_modeinfo` for `w` x `h` at 60 Hz.
pub fn mode_info(w: u32, h: u32) -> [u8; 68] {
    let (hs, he, ht) = (w + 16, w + 16 + 96, w + 160);
    let (vs, ve, vt) = (h + 3, h + 9, h + 30);
    let clock = ht * vt * 60 / 1000;
    let mut m = [0u8; 68];
    m[0..4].copy_from_slice(&clock.to_le_bytes());
    for (i, v) in [w, hs, he, ht, 0, h, vs, ve, vt, 0].iter().enumerate() {
        m[4 + i * 2..6 + i * 2].copy_from_slice(&(*v as u16).to_le_bytes());
    }
    m[24..28].copy_from_slice(&60u32.to_le_bytes());
    m[32..36].copy_from_slice(&(0x8u32 | 0x40).to_le_bytes()); // PREFERRED | DRIVER
    let name = alloc::format!("{}x{}", w, h);
    m[36..36 + name.len()].copy_from_slice(name.as_bytes());
    m
}

impl Kms {
    /// A device for `screen` with the adapter at PCI `slot`, flips paced at `refresh_mhz`.
    pub fn new(screen: Box<dyn Screen>, slot: alloc::string::String, refresh_mhz: u32) -> Self {
        let (width, height) = screen.size();
        Self {
            width,
            height,
            fbs: BTreeMap::new(),
            next_fb: 100,
            scanout: None,
            crtc_xy: (0, 0),
            cursor_bo: None,
            cursor: (0, 0),
            drawn_cursor: None,
            shown: dcore::Shadow::new(width, height),
            dpms: 0,
            master: None,
            blobs: BTreeMap::new(),
            next_blob: 1000,
            files: BTreeMap::new(),
            dmabufs: BTreeMap::new(),
            map_space: BTreeMap::new(),
            next_map_pgoff: 0x10_0000,
            taken: false,
            pending: Vec::new(),
            dirty: None,
            dirty_since: 0,
            dirty_ns: 0,
            flip_wait: Vec::new(),
            gone_since: None,
            screen,
            vblank: dcore::Vblank::new(refresh_mhz),
            slot,
            stats: Stats::default(),
            woke: Vec::new(),
            total_bytes: Arc::new(AtomicU64::new(0)),
            limits: (FILE_BYTES_MAX, TOTAL_BYTES_MAX),
        }
    }

    // ------------------------------------------------------------------
    // Files and buffers
    // ------------------------------------------------------------------

    /// A new open file (slot `id`); the first opener of an unmastered device becomes master.
    pub fn open(&mut self, id: u32) {
        let mut f = File::new();
        if self.master.is_none() {
            // The first opener of an unmastered device becomes master (as Linux)
            self.master = Some(id);
            f.was_master = true;
        }
        self.files.insert(id, f);
        self.gone_since = None;
    }

    /// File `id`'s last descriptor went.
    pub fn close(&mut self, id: u32) {
        if self.files.remove(&id).is_none() {
            return;
        }
        self.fbs.retain(|_, fb| fb.owner != id);
        if self.scanout.as_ref().is_some_and(|fb| fb.owner == id) {
            self.scanout = None;
        }
        self.pending.retain(|p| p.file != id);
        self.flip_wait.retain(|p| p.file != id);
        if self.master == Some(id) {
            self.master = None;
            self.cursor_bo = None;
            self.give_screen();
        }
        if self.files.is_empty() && self.master.is_none() && self.taken {
            self.gone_since = Some(self.screen.now_ns());
        }
    }

    /// The grace timer: the console takes the screen back 10 s after the last file of a
    /// session without a master closed. Returns `true` when it did.
    pub fn check_gone(&mut self, now_ns: u64) -> bool {
        match self.gone_since {
            Some(t) if now_ns >= t + GONE_GRACE_NS => {
                self.gone_since = None;
                if self.master.is_none() && self.files.is_empty() {
                    self.give_screen();
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// A DMA-BUF object (slot) went.
    pub fn dmabuf_closed(&mut self, slot: u32) {
        self.dmabufs.remove(&slot);
    }

    fn new_bo(&mut self, env: &dyn Env, id: u32, size: u64) -> Result<Arc<Bo>, i64> {
        let pages = size.div_ceil(PAGE);
        let bytes = pages * PAGE;
        let file = self.files.get(&id).ok_or(EBADF)?.bytes.clone();
        // Limits: per file and for the whole service
        if file.load(Ordering::Relaxed) + bytes > self.limits.0 || self.total_bytes.load(Ordering::Relaxed) + bytes > self.limits.1 {
            return Err(ENOMEM);
        }
        let mem = env.new_mem(bytes)?;
        file.fetch_add(bytes, Ordering::Relaxed);
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
        // A guard page between buffers keeps their offset ranges apart
        let map_pgoff = self.next_map_pgoff;
        self.next_map_pgoff += pages + 1;
        let bo = Arc::new(Bo { mem, size: bytes, map_pgoff, charged: [file, self.total_bytes.clone()] });
        self.map_space.insert(map_pgoff, Arc::downgrade(&bo));
        self.map_space.retain(|_, w| w.strong_count() > 0);
        Ok(bo)
    }

    /// `mmap` of file `id` at byte `offset` for `len` bytes: the buffer, which the file must
    /// hold a handle to (as Linux: another client's buffer is not mapped by its offset).
    pub fn mmap_file(&self, id: u32, offset: u64, len: u64) -> Result<Arc<Bo>, i64> {
        if offset % PAGE != 0 {
            return Err(EINVAL);
        }
        let pgoff = offset / PAGE;
        let (&start, w) = self.map_space.range(..=pgoff).next_back().ok_or(EINVAL)?;
        let bo = w.upgrade().ok_or(EINVAL)?;
        let first = pgoff - start;
        if first.checked_mul(PAGE).and_then(|b| b.checked_add(len.max(1))).map_or(true, |end| end > bo.size) {
            return Err(EINVAL);
        }
        if !self.files.get(&id).is_some_and(|f| f.handles.values().any(|h| Arc::ptr_eq(h, &bo))) {
            return Err(EACCES);
        }
        Ok(bo)
    }

    /// `mmap` of DMA-BUF `slot` at byte `offset` for `len` bytes.
    pub fn mmap_dmabuf(&self, slot: u32, offset: u64, len: u64) -> Result<Arc<Bo>, i64> {
        let bo = self.dmabufs.get(&slot).cloned().ok_or(EBADF)?;
        if offset % PAGE != 0 || offset.checked_add(len.max(1)).map_or(true, |end| end > bo.size) {
            return Err(EINVAL);
        }
        Ok(bo)
    }

    fn file(&mut self, id: u32) -> Result<&mut File, i64> {
        self.files.get_mut(&id).ok_or(EBADF)
    }

    fn bo(&self, id: u32, handle: u32) -> Result<Arc<Bo>, i64> {
        self.files.get(&id).and_then(|f| f.handles.get(&handle).cloned()).ok_or(ENOENT)
    }

    fn is_master(&self, id: u32) -> bool {
        self.master == Some(id)
    }

    // ------------------------------------------------------------------
    // The screen
    // ------------------------------------------------------------------

    /// Takes the screen from the console (a session's first picture).
    fn take_screen(&mut self) -> Result<(), i64> {
        if self.taken {
            return Ok(());
        }
        let r = self.screen.take();
        if r < 0 {
            return Err(ENXIO);
        }
        self.taken = true;
        self.drawn_cursor = None;
        // The console drew on the screen meanwhile
        self.shown.invalidate();
        Ok(())
    }

    /// Gives the screen back to the console.
    fn give_screen(&mut self) {
        if self.taken {
            self.taken = false;
            self.screen.give();
        }
        self.gone_since = None;
    }

    /// Whether the session shows (pictures reach the screen, completions are given).
    pub fn shown(&self) -> bool {
        self.taken && self.screen.state() == SCREEN_SHOWN
    }

    /// Whether the console shows in front of a session (completions held back).
    pub fn hidden(&self) -> bool {
        self.taken && self.screen.state() == SCREEN_HIDDEN
    }

    /// Copies rectangle `r` (`x0, y0, x1, y1`) of the picture, then the cursor.
    fn present_rect(&mut self, r: (u32, u32, u32, u32)) {
        if !self.shown() || self.dpms != 0 {
            return;
        }
        let dt = self.draw_part(r);
        self.stats.presents += 1;
        self.stats.copy_ns += dt;
        self.stats.copy_max_ns = self.stats.copy_max_ns.max(dt);
    }

    /// Draws rectangle `r` of the picture, then the cursor's areas; the time it took.
    fn draw_part(&mut self, r: (u32, u32, u32, u32)) -> u64 {
        let t0 = self.screen.now_ns();
        let Some(t) = self.screen.begin() else { return 0 };
        let src = self.scanout.as_ref().map(|f| f.src());
        // wave11 GG: rows composed with the cursor in RAM, only changed blocks written
        let cur = self.cursor_bo.as_ref().map(|(bo, w, h)| dcore::Cursor { base: bo.mem.ptr(), len: bo.size, w: *w, h: *h });
        let placed = cur.as_ref().map(|c| dcore::Placed { cur: c, x: self.cursor.0, y: self.cursor.1 });
        let d = dcore::draw_rect(&t, &mut self.shown, src.as_ref(), self.crtc_xy, placed.as_ref(), r.0, r.1, r.2, r.3);
        self.stats.composed_px += d.composed;
        self.stats.written_px += d.written;
        // The cursor's areas (where it was drawn, where it is) right on the screen whether
        // or not they were in `r` (unchanged blocks cost no writes)
        let now = cur.as_ref().map(|c| (self.cursor.0, self.cursor.1, c.w, c.h));
        if let Some(old) = self.drawn_cursor.take() {
            if Some(old) != now {
                self.cursor_area(&t, src.as_ref(), placed.as_ref(), old);
            }
        }
        if let Some(a) = now {
            self.cursor_area(&t, src.as_ref(), placed.as_ref(), a);
        }
        self.drawn_cursor = now;
        self.screen.end();
        self.screen.now_ns().saturating_sub(t0)
    }

    // wave11 GD begin: the flip's copy in bands
    /// A flip changed rectangle `r`: the screen thread copies it ([`Self::copy_band`]), so
    /// the flip returns at once and the compositor goes on (input, cursor moves) while the
    /// picture goes out. Nothing to copy while the session does not show (it is repainted
    /// whole when it shows again).
    fn damage(&mut self, r: (u32, u32, u32, u32)) {
        if !self.shown() || self.dpms != 0 {
            return;
        }
        self.dirty = Some(match self.dirty {
            None => {
                self.dirty_since = self.screen.now_ns();
                self.dirty_ns = 0;
                r
            }
            Some(d) => union_rect(d, r),
        });
    }

    /// Whether a copy waits for the screen thread.
    pub fn copy_pending(&self) -> bool {
        self.dirty.is_some()
    }

    /// The screen thread copies the next band of at most [`BAND_ROWS`] rows of the changed
    /// part (the lock is released between bands: a cursor move waits for one band at most,
    /// never for a whole picture). Returns whether more remains. At the end the waiting
    /// flips complete at the next blank.
    pub fn copy_band(&mut self) -> bool {
        let Some((x0, y0, x1, y1)) = self.dirty else { return false };
        if !self.shown() || self.dpms != 0 {
            self.dirty = None;
            self.flips_copied();
            return false;
        }
        let yb = y0.saturating_add(BAND_ROWS).min(y1);
        self.dirty_ns += self.draw_part((x0, y0, x1, yb));
        if yb < y1 {
            self.dirty = Some((x0, yb, x1, y1));
            return true;
        }
        self.dirty = None;
        self.stats.presents += 1;
        self.stats.copy_ns += self.dirty_ns;
        self.stats.copy_max_ns = self.stats.copy_max_ns.max(self.dirty_ns);
        let lat = self.screen.now_ns().saturating_sub(self.dirty_since);
        self.stats.lat_max_ns = self.stats.lat_max_ns.max(lat);
        self.flips_copied();
        false
    }

    /// The flips whose picture is out complete at the next blank.
    fn flips_copied(&mut self) {
        let w = core::mem::take(&mut self.flip_wait);
        self.pending.extend(w);
    }
    // wave11 GD end

    /// Repaints the whole screen from the picture.
    pub fn present(&mut self) {
        self.present_rect((0, 0, self.width, self.height));
    }

    /// Moves or changes the cursor, repairing only the area it covered.
    fn update_cursor(&mut self) {
        if !self.shown() || self.dpms != 0 {
            return;
        }
        let t0 = self.screen.now_ns();
        let Some(t) = self.screen.begin() else { return };
        let src = self.scanout.as_ref().map(|f| f.src());
        // wave11 GG: the old area and the new one, each row composed with the cursor at
        // its new place before it is written (the cursor never disappears from the screen)
        let cur = self.cursor_bo.as_ref().map(|(bo, w, h)| dcore::Cursor { base: bo.mem.ptr(), len: bo.size, w: *w, h: *h });
        let placed = cur.as_ref().map(|c| dcore::Placed { cur: c, x: self.cursor.0, y: self.cursor.1 });
        if let Some(old) = self.drawn_cursor.take() {
            self.cursor_area(&t, src.as_ref(), placed.as_ref(), old);
        }
        if let Some(c) = &cur {
            let now = (self.cursor.0, self.cursor.1, c.w, c.h);
            self.cursor_area(&t, src.as_ref(), placed.as_ref(), now);
            self.drawn_cursor = Some(now);
        }
        self.screen.end();
        self.stats.cursor_updates += 1;
        let dt = self.screen.now_ns().saturating_sub(t0);
        self.stats.cursor_ns += dt;
        self.stats.cursor_max_ns = self.stats.cursor_max_ns.max(dt);
    }

    /// wave11 GG: puts screen area `a` (`x, y, w, h`, clipped to the screen) right, with
    /// the cursor `placed` blended in.
    fn cursor_area(&mut self, t: &dcore::Target, src: Option<&dcore::Src>, placed: Option<&dcore::Placed>, a: (i32, i32, u32, u32)) {
        let (x0, y0) = (a.0.max(0) as u32, a.1.max(0) as u32);
        let (x1, y1) = ((a.0 + a.2 as i32).max(0) as u32, (a.1 + a.3 as i32).max(0) as u32);
        let d = dcore::draw_rect(t, &mut self.shown, src, self.crtc_xy, placed, x0, y0, x1, y1);
        self.stats.composed_px += d.composed;
        self.stats.written_px += d.written;
    }

    /// The kernel changed the screen's state: shown again repaints the session. The state is
    /// read again here (a worker may have taken the screen since the change was noticed).
    pub fn state_changed(&mut self) {
        let state = self.screen.state();
        if self.taken && state == SCREEN_SHOWN {
            self.drawn_cursor = None;
            // wave11 GG: the console drew on the screen meanwhile
            self.shown.invalidate();
            self.present();
        }
        if state == crate::proto::SCREEN_CONSOLE || state == crate::proto::SCREEN_PANIC {
            // Taken back (a panic): a new picture asks again
            self.taken = false;
        }
    }

    // ------------------------------------------------------------------
    // The vertical blank
    // ------------------------------------------------------------------

    /// When the next completion is due (`None`: nothing waits, or it is held back).
    pub fn next_due(&self, now_ns: u64) -> Option<u64> {
        if self.pending.is_empty() || !self.shown() {
            return None;
        }
        Some(self.vblank.time_of(self.vblank.next_after(now_ns)))
    }

    /// Blank time `now_ns` (or later) came: completes the waiting flips if the session shows;
    /// otherwise holds them back. Returns how many completed.
    pub fn vblank_tick(&mut self, now_ns: u64) -> usize {
        if self.pending.is_empty() {
            return 0;
        }
        if !self.shown() {
            self.stats.held += 1;
            return 0;
        }
        let k = self.vblank.count_at(now_ns);
        let t = self.vblank.time_of(k);
        let done: Vec<Pending> = core::mem::take(&mut self.pending);
        for p in &done {
            self.queue_event(p.file, p.kind, p.user_data, t, k);
        }
        self.stats.completions += done.len() as u64;
        done.len()
    }

    /// Queues a vblank or flip event (time `t_ns`, sequence `seq`) on file `id`.
    fn queue_event(&mut self, id: u32, kind: u32, user_data: u64, t_ns: u64, seq: u64) {
        let us = t_ns / 1000;
        let mut ev = [0u8; 32];
        put32(&mut ev, 0, kind);
        put32(&mut ev, 4, 32);
        put64(&mut ev, 8, user_data);
        put32(&mut ev, 16, (us / 1_000_000) as u32);
        put32(&mut ev, 20, (us % 1_000_000) as u32);
        put32(&mut ev, 24, seq as u32);
        put32(&mut ev, 28, CRTC_ID);
        if let Some(f) = self.files.get_mut(&id) {
            f.events.push_back(ev);
            self.woke.push(id);
        }
    }

    /// Takes up to `cap` bytes of whole events of file `id` (`None`: none queued;
    /// `Some(Err)`: `cap` holds not even one).
    pub fn take_events(&mut self, id: u32, cap: usize) -> Option<Result<Vec<u8>, i64>> {
        let f = self.files.get_mut(&id)?;
        if f.events.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        while let Some(ev) = f.events.front() {
            if cap - out.len() < ev.len() {
                break;
            }
            out.extend_from_slice(ev);
            f.events.pop_front();
        }
        Some(if out.is_empty() { Err(EINVAL) } else { Ok(out) })
    }

    /// The poll bits of file `id`: always writable, readable with events queued.
    pub fn poll_bits(&self, id: u32) -> u32 {
        0x0004 | if self.files.get(&id).is_some_and(|f| !f.events.is_empty()) { 0x0001 } else { 0 }
    }

    // ------------------------------------------------------------------
    // ioctl
    // ------------------------------------------------------------------

    /// `ioctl(cmd, arg)` on file `id`.
    pub fn ioctl(&mut self, env: &dyn Env, id: u32, cmd: u64, arg: u64) -> i64 {
        if (cmd >> 8) & 0xFF != 0x64 {
            return ENOTTY;
        }
        self.stats.ioctls += 1;
        if self.hidden() {
            self.stats.ioctls_hidden += 1;
        }
        let nr = cmd & 0xFF;
        let size = ((cmd >> 16) & 0x3FFF) as usize;
        let dir = cmd >> 30;
        let mut b = alloc::vec![0u8; size.max(128)];
        if dir & 1 != 0 && size > 0 {
            match env.copy_in(arg, size) {
                Ok(v) => b[..size].copy_from_slice(&v),
                Err(_) => return EFAULT,
            }
        }
        match self.handle(env, id, nr, &mut b) {
            Ok(r) => {
                if dir & 2 != 0 && size > 0 && env.copy_out(arg, &b[..size]).is_err() {
                    return EFAULT;
                }
                r
            }
            Err(e) => e,
        }
    }

    /// Properties of an object: (ids, values).
    fn object_props(&self, obj: u32) -> Option<(Vec<u32>, Vec<u64>)> {
        match obj {
            CONNECTOR_ID => Some((alloc::vec![PROP_DPMS, PROP_EDID, PROP_NON_DESKTOP], alloc::vec![self.dpms, 0, 0])),
            PRIMARY_PLANE_ID => Some((alloc::vec![PROP_TYPE], alloc::vec![1])),
            CURSOR_PLANE_ID => Some((alloc::vec![PROP_TYPE], alloc::vec![2])),
            CRTC_ID | ENCODER_ID => Some((Vec::new(), Vec::new())),
            _ => None,
        }
    }

    fn add_fb(&mut self, id: u32, width: u32, height: u32, format: u32, handle: u32, pitch: u32, offset: u32) -> Result<u32, i64> {
        if format != FMT_XRGB8888 && format != FMT_ARGB8888 {
            return Err(EINVAL);
        }
        let bo = self.bo(id, handle)?;
        if width == 0 || height == 0 || (pitch as u64) < width as u64 * 4 || offset as u64 + pitch as u64 * height as u64 > bo.size {
            return Err(EINVAL);
        }
        let fid = self.next_fb;
        self.next_fb += 1;
        self.fbs.insert(fid, Arc::new(Fb { bo, width, height, pitch, offset, format, owner: id, handle }));
        Ok(fid)
    }

    fn set_property(&mut self, id: u32, prop: u32, value: u64) -> Result<i64, i64> {
        if !self.is_master(id) {
            return Err(EACCES);
        }
        match prop {
            PROP_DPMS if value <= 3 => {
                self.dpms = value;
                if value == 0 {
                    self.present();
                }
                Ok(0)
            }
            PROP_DPMS => Err(EINVAL),
            PROP_EDID | PROP_NON_DESKTOP => Err(EPERM),
            _ => Err(ENOENT),
        }
    }

    /// The current vertical blank (sequence, time in ns).
    fn now_blank(&self) -> (u64, u64) {
        let now = self.screen.now_ns();
        let k = self.vblank.count_at(now);
        (k, now)
    }

    /// Makes the scanout this file's last one again (it becomes master again).
    fn restore_last(&mut self, id: u32) {
        let Some(f) = self.files.get(&id) else { return };
        let (last_fb, last_xy, last_cur_bo, last_cur) = (f.last_scanout.clone(), f.last_crtc_xy, f.last_cursor_bo.clone(), f.last_cursor);
        let _ = self.take_screen();
        if let Some(fb) = last_fb {
            self.scanout = Some(fb);
            self.crtc_xy = last_xy;
            if let Some(c) = last_cur_bo {
                self.cursor_bo = Some(c);
                self.cursor = last_cur;
            }
            self.present();
        }
    }

    fn handle(&mut self, env: &dyn Env, id: u32, nr: u64, b: &mut [u8]) -> Result<i64, i64> {
        match nr {
            0x00 => {
                // VERSION
                put32(b, 0, 1);
                put32(b, 4, 0);
                put32(b, 8, 0);
                put_string(env, b, 16, "hydradrm")?;
                put_string(env, b, 32, "20261031")?;
                put_string(env, b, 48, "Hydra kernel mode setting")?;
                Ok(0)
            }
            0x01 => {
                // GET_UNIQUE: the display adapter's PCI slot
                let cap = get64(b, 0) as usize;
                let ptr = get64(b, 8);
                let slot = self.slot.clone();
                if ptr != 0 && cap > 0 {
                    env.copy_out(ptr, &slot.as_bytes()[..slot.len().min(cap)])?;
                }
                put64(b, 0, slot.len() as u64);
                Ok(0)
            }
            0x02 => {
                // GET_MAGIC
                put32(b, 0, id);
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
                let h = get32(b, 0);
                self.file(id)?.handles.remove(&h).map(|_| 0).ok_or(EINVAL)
            }
            0x0c => {
                // GET_CAP
                let v = match get64(b, 0) {
                    0x1 => 1,         // DUMB_BUFFER
                    0x2 => 1,         // VBLANK_HIGH_CRTC
                    0x3 => 24,        // DUMB_PREFERRED_DEPTH
                    0x4 => 0,         // DUMB_PREFER_SHADOW
                    0x5 => 3,         // PRIME: import and export
                    0x6 => 1,         // TIMESTAMP_MONOTONIC
                    0x7 => 0,         // ASYNC_PAGE_FLIP
                    0x8 | 0x9 => CURSOR_SIZE as u64,
                    0x10 => 0,        // ADDFB2_MODIFIERS
                    0x11 => 0,        // PAGE_FLIP_TARGET
                    0x12 => 1,        // CRTC_IN_VBLANK_EVENT
                    0x13 | 0x14 => 0, // SYNCOBJ(_TIMELINE)
                    0x15 => 0,        // ATOMIC_ASYNC_PAGE_FLIP
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
                        self.file(id)?.universal_planes = v != 0;
                        Ok(0)
                    }
                    (3, _) => Err(EOPNOTSUPP), // ATOMIC
                    _ => Err(EINVAL),
                }
            }
            0x11 => {
                // AUTH_MAGIC needs master rights (libdrm's drmIsMaster tests exactly this)
                if self.is_master(id) {
                    Ok(0)
                } else {
                    Err(EACCES)
                }
            }
            0x1e => {
                // SET_MASTER: as Linux (drm_master_check_perm), only a file that was master
                // before or a caller with CAP_SYS_ADMIN (logind) may take it
                if !env.privileged() && !self.files.get(&id).is_some_and(|f| f.was_master) {
                    return Err(EACCES);
                }
                match self.master {
                    None => {
                        self.master = Some(id);
                        self.file(id)?.was_master = true;
                        self.restore_last(id);
                        Ok(0)
                    }
                    Some(m) if m == id => {
                        self.restore_last(id);
                        Ok(0)
                    }
                    Some(_) => Err(EBUSY),
                }
            }
            0x1f => {
                // DROP_MASTER
                if self.master != Some(id) {
                    return Err(EINVAL);
                }
                self.master = None;
                self.cursor_bo = None;
                Ok(0)
            }
            0x3a => {
                // WAIT_VBLANK: the event (if asked) at the next blank; the answer is the
                // current blank
                let ty = get32(b, 0);
                let (k, now) = self.now_blank();
                if ty & 0x0400_0000 != 0 {
                    // _DRM_VBLANK_EVENT
                    if self.pending.iter().filter(|p| p.file == id).count() >= PENDING_MAX {
                        return Err(EBUSY);
                    }
                    self.pending.push(Pending { file: id, kind: EV_VBLANK, user_data: get64(b, 8) });
                }
                let us = now / 1000;
                put32(b, 4, k as u32);
                put64(b, 8, us / 1_000_000);
                put64(b, 16, us % 1_000_000);
                Ok(0)
            }
            0x3b => {
                // CRTC_GET_SEQUENCE
                let (k, _) = self.now_blank();
                put32(b, 4, self.scanout.is_some() as u32);
                put64(b, 8, k);
                put64(b, 16, self.vblank.time_of(k));
                Ok(0)
            }
            0xA0 => {
                // MODE_GETRESOURCES
                let fbs: Vec<u32> = self.fbs.iter().filter(|(_, f)| f.owner == id).map(|(&i, _)| i).collect();
                u32s(env, get64(b, 0), get32(b, 32), &fbs)?;
                u32s(env, get64(b, 8), get32(b, 36), &[CRTC_ID])?;
                u32s(env, get64(b, 16), get32(b, 40), &[CONNECTOR_ID])?;
                u32s(env, get64(b, 24), get32(b, 44), &[ENCODER_ID])?;
                put32(b, 32, fbs.len() as u32);
                put32(b, 36, 1);
                put32(b, 40, 1);
                put32(b, 44, 1);
                put32(b, 48, 1);
                put32(b, 52, self.width.max(4096));
                put32(b, 56, 1);
                put32(b, 60, self.height.max(4096));
                Ok(0)
            }
            0xA1 => {
                // MODE_GETCRTC
                if get32(b, 12) != CRTC_ID {
                    return Err(ENOENT);
                }
                let fb_id = self.scanout.as_ref().and_then(|s| self.fbs.iter().find(|(_, f)| Arc::ptr_eq(f, s)).map(|(&i, _)| i));
                put32(b, 16, fb_id.unwrap_or(0));
                put32(b, 20, self.crtc_xy.0);
                put32(b, 24, self.crtc_xy.1);
                put32(b, 28, 256); // gamma_size
                put32(b, 32, self.scanout.is_some() as u32);
                if self.scanout.is_some() {
                    b[36..104].copy_from_slice(&mode_info(self.width, self.height));
                } else {
                    b[36..104].fill(0);
                }
                Ok(0)
            }
            0xA2 => {
                // MODE_SETCRTC
                if !self.is_master(id) {
                    return Err(EACCES);
                }
                if get32(b, 12) != CRTC_ID {
                    return Err(ENOENT);
                }
                let count = get32(b, 8);
                if count > 0 {
                    if count > 16 {
                        return Err(EINVAL);
                    }
                    let raw = env.copy_in(get64(b, 0), count as usize * 4)?;
                    if raw.chunks_exact(4).any(|c| u32::from_le_bytes(c.try_into().unwrap()) != CONNECTOR_ID) {
                        return Err(ENOENT);
                    }
                }
                let fb_id = get32(b, 16);
                let (x, y) = (get32(b, 20), get32(b, 24));
                if get32(b, 32) == 0 {
                    self.file(id)?.last_scanout = None;
                    self.scanout = None;
                    self.give_screen();
                    return Ok(0);
                }
                let hd = u16::from_le_bytes([b[40], b[41]]) as u32;
                let vd = u16::from_le_bytes([b[50], b[51]]) as u32;
                if hd != self.width || vd != self.height {
                    return Err(EINVAL);
                }
                let fb = if fb_id == u32::MAX {
                    self.scanout.clone().or_else(|| self.files.get(&id).and_then(|f| f.last_scanout.clone())).ok_or(EINVAL)?
                } else {
                    self.fbs.get(&fb_id).cloned().ok_or(ENOENT)?
                };
                if x as u64 + self.width as u64 > fb.width as u64 || y as u64 + self.height as u64 > fb.height as u64 {
                    return Err(ENOSPC);
                }
                self.take_screen()?;
                let f = self.file(id)?;
                f.last_scanout = Some(fb.clone());
                f.last_crtc_xy = (x, y);
                self.scanout = Some(fb);
                self.crtc_xy = (x, y);
                self.present();
                Ok(0)
            }
            0xA3 | 0xBB => {
                // MODE_CURSOR / MODE_CURSOR2
                if !self.is_master(id) {
                    return Err(EACCES);
                }
                let flags = get32(b, 0);
                let (x, y) = (get32(b, 8) as i32, get32(b, 12) as i32);
                let (w, h, handle) = (get32(b, 16), get32(b, 20), get32(b, 24));
                let new_bo = if flags & 1 != 0 && handle != 0 {
                    if w > CURSOR_SIZE || h > CURSOR_SIZE {
                        return Err(EINVAL);
                    }
                    let bo = self.bo(id, handle)?;
                    if (w as u64 * h as u64 * 4) > bo.size {
                        return Err(EINVAL);
                    }
                    Some(bo)
                } else {
                    None
                };
                if flags & 1 != 0 {
                    let c = new_bo.map(|bo| (bo, w, h));
                    self.file(id)?.last_cursor_bo = c.clone();
                    self.cursor_bo = c;
                }
                if flags & 2 != 0 {
                    // (far off screen is off screen: no overflow in the repairs)
                    let (x, y) = (x.clamp(-0x10000, 0x10000), y.clamp(-0x10000, 0x10000));
                    self.file(id)?.last_cursor = (x, y);
                    self.cursor = (x, y);
                }
                self.update_cursor();
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
                        env.copy_out(get64(b, off), &ramp)?;
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
                let mode = mode_info(self.width, self.height);
                let props = self.object_props(CONNECTOR_ID).unwrap_or_default();
                put_array(env, get64(b, 8), get32(b, 32), &[mode], |m| m.to_vec())?;
                u32s(env, get64(b, 16), get32(b, 36), &props.0)?;
                u64s(env, get64(b, 24), get32(b, 36), &props.1)?;
                u32s(env, get64(b, 0), get32(b, 40), &[ENCODER_ID])?;
                put32(b, 32, 1);
                put32(b, 36, props.0.len() as u32);
                put32(b, 40, 1);
                put32(b, 44, ENCODER_ID);
                put32(b, 52, 15); // DRM_MODE_CONNECTOR_VIRTUAL
                put32(b, 56, 1);
                put32(b, 60, 1); // connected
                put32(b, 64, self.width * 254 / 960); // 96 dpi
                put32(b, 68, self.height * 254 / 960);
                put32(b, 72, 1); // subpixel unknown
                Ok(0)
            }
            0xAA => {
                // MODE_GETPROPERTY
                let pid = get32(b, 16);
                let (name, flags, values, enums): (&str, u32, Vec<u64>, Vec<(u64, &str)>) = match pid {
                    PROP_DPMS => ("DPMS", PROP_ENUM, alloc::vec![0, 1, 2, 3], alloc::vec![(0, "On"), (1, "Standby"), (2, "Suspend"), (3, "Off")]),
                    PROP_EDID => ("EDID", PROP_BLOB | PROP_IMMUTABLE, Vec::new(), Vec::new()),
                    PROP_NON_DESKTOP => ("non-desktop", PROP_RANGE | PROP_IMMUTABLE, alloc::vec![0, 1], Vec::new()),
                    PROP_TYPE => ("type", PROP_ENUM | PROP_IMMUTABLE, alloc::vec![0, 1, 2], alloc::vec![(0, "Overlay"), (1, "Primary"), (2, "Cursor")]),
                    _ => return Err(ENOENT),
                };
                put32(b, 20, flags);
                b[24..56].fill(0);
                b[24..24 + name.len()].copy_from_slice(name.as_bytes());
                u64s(env, get64(b, 0), get32(b, 56), &values)?;
                put_array(env, get64(b, 8), get32(b, 60), &enums, |(v, n)| {
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
                self.set_property(id, get32(b, 8), get64(b, 0))
            }
            0xAC => {
                // MODE_GETPROPBLOB
                let data = self.blobs.get(&get32(b, 0)).cloned().ok_or(ENOENT)?;
                let cap = get32(b, 4) as usize;
                if cap >= data.len() && get64(b, 8) != 0 {
                    env.copy_out(get64(b, 8), &data)?;
                }
                put32(b, 4, data.len() as u32);
                Ok(0)
            }
            0xAD => {
                // MODE_GETFB
                let fb = self.fbs.get(&get32(b, 0)).cloned().ok_or(ENOENT)?;
                put32(b, 4, fb.width);
                put32(b, 8, fb.height);
                put32(b, 12, fb.pitch);
                put32(b, 16, 32);
                put32(b, 20, if fb.format == FMT_ARGB8888 { 32 } else { 24 });
                put32(b, 24, if fb.owner == id { fb.handle } else { 0 });
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
                let fid = self.add_fb(id, w, h, format, handle, pitch, 0)?;
                put32(b, 0, fid);
                Ok(0)
            }
            0xAF => {
                // MODE_RMFB: a framebuffer being shown is turned off first
                let fid = get32(b, 0);
                let fb = self.fbs.get(&fid).cloned().ok_or(ENOENT)?;
                if fb.owner != id {
                    return Err(ENOENT);
                }
                self.fbs.remove(&fid);
                let f = self.file(id)?;
                if f.last_scanout.as_ref().is_some_and(|s| Arc::ptr_eq(s, &fb)) {
                    f.last_scanout = None;
                }
                if self.scanout.as_ref().is_some_and(|s| Arc::ptr_eq(s, &fb)) {
                    self.scanout = None;
                    self.present();
                }
                Ok(0)
            }
            0xB0 => {
                // MODE_PAGE_FLIP: copied now, completed at the next vertical blank (held back
                // while the console shows)
                if !self.is_master(id) {
                    return Err(EACCES);
                }
                if get32(b, 0) != CRTC_ID {
                    return Err(ENOENT);
                }
                let (fb_id, flags, user_data) = (get32(b, 4), get32(b, 8), get64(b, 16));
                if flags & !0x3 != 0 {
                    return Err(EINVAL);
                }
                if self.pending.iter().chain(self.flip_wait.iter()).any(|p| p.file == id && p.kind == EV_FLIP) {
                    return Err(EBUSY);
                }
                let fb = self.fbs.get(&fb_id).cloned().ok_or(ENOENT)?;
                self.take_screen()?;
                self.file(id)?.last_scanout = Some(fb.clone());
                self.scanout = Some(fb);
                self.stats.flips += 1;
                // wave11 GD: copied by the screen thread (the caller kicks it); completed at
                // the first blank after the copy. A flip without the event flag asks for no
                // completion: it returns at once too and its picture goes out with the bands
                // (the next flip, with or without an event, takes over the copy; its own
                // completion still waits for the whole picture)
                self.damage((0, 0, self.width, self.height));
                if flags & 1 != 0 {
                    let p = Pending { file: id, kind: EV_FLIP, user_data };
                    if self.dirty.is_some() {
                        self.flip_wait.push(p);
                    } else {
                        self.pending.push(p);
                    }
                }
                Ok(0)
            }
            0xB1 => {
                // MODE_DIRTYFB: only the damaged rectangles when given
                let fb = self.fbs.get(&get32(b, 0)).cloned().ok_or(ENOENT)?;
                if !self.scanout.as_ref().is_some_and(|s| Arc::ptr_eq(s, &fb)) {
                    return Ok(0);
                }
                let n = get32(b, 12);
                let ptr = get64(b, 16);
                // (more rectangles than we look at: the whole picture)
                if n == 0 || ptr == 0 || n > 256 {
                    self.present();
                    return Ok(0);
                }
                let raw = env.copy_in(ptr, n as usize * 8)?;
                let (cx, cy) = self.crtc_xy;
                for c in raw.chunks_exact(8) {
                    let r = |i: usize| u16::from_le_bytes([c[i], c[i + 1]]) as u32;
                    // Clips are in framebuffer coordinates
                    let (x0, y0, x1, y1) = (r(0).saturating_sub(cx), r(2).saturating_sub(cy), r(4).saturating_sub(cx), r(6).saturating_sub(cy));
                    self.present_rect((x0, y0, x1, y1));
                }
                Ok(0)
            }
            0xB2 => {
                // MODE_CREATE_DUMB
                let (h, w, bpp) = (get32(b, 0), get32(b, 4), get32(b, 8));
                if w == 0 || h == 0 || bpp == 0 || bpp > 32 || w > 8192 || h > 8192 {
                    return Err(EINVAL);
                }
                let pitch = (w * bpp.div_ceil(8) + 63) & !63;
                let size = (pitch as u64 * h as u64).div_ceil(PAGE) * PAGE;
                if self.files.get(&id).is_some_and(|f| f.handles.len() >= HANDLES_MAX) {
                    return Err(ENOSPC);
                }
                let bo = self.new_bo(env, id, size).map_err(|e| if e == EINVAL { ENOMEM } else { e })?;
                let handle = self.file(id)?.add_handle(bo)?;
                put32(b, 16, handle);
                put32(b, 20, pitch);
                put64(b, 24, size);
                Ok(0)
            }
            0xB3 => {
                // MODE_MAP_DUMB
                let bo = self.bo(id, get32(b, 0))?;
                put64(b, 8, bo.map_pgoff * PAGE);
                Ok(0)
            }
            0xB4 => {
                // MODE_DESTROY_DUMB
                let h = get32(b, 0);
                self.file(id)?.handles.remove(&h).map(|_| 0).ok_or(ENOENT)
            }
            0xB5 => {
                // MODE_GETPLANERESOURCES
                let up = self.files.get(&id).is_some_and(|f| f.universal_planes);
                let planes: &[u32] = if up { &[PRIMARY_PLANE_ID, CURSOR_PLANE_ID] } else { &[] };
                u32s(env, get64(b, 0), get32(b, 8), planes)?;
                put32(b, 8, planes.len() as u32);
                Ok(0)
            }
            0xB6 => {
                // MODE_GETPLANE
                let pid = get32(b, 0);
                let formats: &[u32] = match pid {
                    PRIMARY_PLANE_ID => &[FMT_XRGB8888, FMT_ARGB8888],
                    CURSOR_PLANE_ID => &[FMT_ARGB8888],
                    _ => return Err(ENOENT),
                };
                put32(b, 4, if pid == PRIMARY_PLANE_ID && self.taken { CRTC_ID } else { 0 });
                put32(b, 8, 0);
                put32(b, 12, 1);
                put32(b, 16, 0);
                u32s(env, get64(b, 24), get32(b, 20), formats)?;
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
                let fid = self.add_fb(id, w, h, format, get32(b, 20), get32(b, 36), get32(b, 52))?;
                put32(b, 0, fid);
                Ok(0)
            }
            0xB9 => {
                // MODE_OBJ_GETPROPERTIES
                let (ids, values) = self.object_props(get32(b, 20)).ok_or(ENOENT)?;
                u32s(env, get64(b, 0), get32(b, 16), &ids)?;
                u64s(env, get64(b, 8), get32(b, 16), &values)?;
                put32(b, 16, ids.len() as u32);
                Ok(0)
            }
            0xBA => {
                // MODE_OBJ_SETPROPERTY
                match (get32(b, 12), get32(b, 16)) {
                    (CONNECTOR_ID, OBJ_CONNECTOR) | (CONNECTOR_ID, 0) => self.set_property(id, get32(b, 8), get64(b, 0)),
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
                let data = env.copy_in(get64(b, 0), len)?;
                let bid = self.next_blob;
                self.next_blob += 1;
                self.blobs.insert(bid, data);
                put32(b, 12, bid);
                Ok(0)
            }
            0xBE => self.blobs.remove(&get32(b, 0)).map(|_| 0).ok_or(ENOENT), // DESTROYPROPBLOB
            0xCE => {
                // MODE_GETFB2
                let fb = self.fbs.get(&get32(b, 0)).cloned().ok_or(ENOENT)?;
                put32(b, 4, fb.width);
                put32(b, 8, fb.height);
                put32(b, 12, fb.format);
                put32(b, 16, 0);
                b[20..104].fill(0);
                put32(b, 20, if fb.owner == id { fb.handle } else { 0 });
                put32(b, 36, fb.pitch);
                put32(b, 52, fb.offset);
                Ok(0)
            }
            0x2d => {
                // PRIME_HANDLE_TO_FD: a DMA-BUF descriptor for the buffer
                let bo = self.bo(id, get32(b, 0))?;
                let flags = get32(b, 4);
                let (fd, slot) = env.install_dmabuf(flags, bo.size)?;
                self.dmabufs.insert(slot, bo);
                put32(b, 8, fd as u32);
                Ok(0)
            }
            0x2e => {
                // PRIME_FD_TO_HANDLE: the same handle again for a buffer this file knows
                let slot = env.dmabuf_slot(get32(b, 8))?;
                let bo = self.dmabufs.get(&slot).cloned().ok_or(EINVAL)?;
                let f = self.file(id)?;
                let handle = match f.handles.iter().find(|(_, h)| Arc::ptr_eq(h, &bo)) {
                    Some((&h, _)) => h,
                    None => f.add_handle(bo)?,
                };
                put32(b, 0, handle);
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }
}
