//! # The sound service's kernel side (wave 8, Group S)
//!
//! Since wave 8 the ALSA devices (`/dev/snd/*`) are served by a ring-3 service,
//! `userland/drivers/sound-server` (endpoint [`ENDPOINT_LX_SOUND`], Linux service
//! `LXS_SOUND`), a client of the sound driver (`hda-driver`, [`ENDPOINT_SOUND_DEV`]), which
//! stays as it is. What must outlive both processes stays here
//! (`docs/display-input-design.md`, sections 3.6 and 5):
//!
//! - **The DMA memory** ([`buffers`]): the controller's position page and one ring per
//!   direction, allocated once, mapped into the sound driver's IOMMU domain, alive as long
//!   as the kernel (across restarts of the driver and of the service). The in-kernel ALSA
//!   layer (`compat/linux/snd.rs`, `lx.sound=kernel`) uses the same memory.
//! - **The status page**: one page the service writes each stream's state into
//!   ([`SndStatus`]); `/proc/asound` (kept in the kernel, `compat/linux/fs.rs`) reads it.
//! - **`LX_OBJ_SND`** ([`ctl`], `SYS_LX_OBJ` op 64, the sound service only): hands the
//!   pages to the service as memory objects (`lx::mem`, the design's `obj_dma`) with the card
//!   the kernel found at boot; raises the thread that drives a stream to high priority (the
//!   in-kernel layer's `boost_caller`); reports the sound driver's generation, so the
//!   service sets its streams up again after the driver restarted.
//! - **The service went away** ([`service_gone`]): the rings are silenced, so the
//!   controller, which keeps fetching, plays a gap and not the ring over and over until
//!   the new instance stops the stream.

use alloc::sync::Arc;


use crate::ipc::protocol::{
    LxSndInfo, SndStatus, ENDPOINT_LX_SOUND, ENDPOINT_SOUND_DEV, LXS_SOUND, LX_SND_BOOST, LX_SND_DRVGEN, LX_SND_GET, LX_SND_NOW, LX_SND_SETUP, LX_SND_UNBOOST, SND_DESC_MAX, SND_RING_BYTES, SND_STATUS_STRIDE,
};
use crate::ipc::service::ContiguousFrames;
use crate::memory::vm::MemObject;

const EPERM: i64 = -1;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;

/// Pages of each ring.
pub const RING_PAGES: u64 = SND_RING_BYTES / 4096;

/// The sound DMA memory and the status page.
pub struct Buffers {
    /// The controller's position page.
    pub pos: Arc<ContiguousFrames>,
    /// The rings, per direction (`None`: could not be allocated).
    pub rings: [Option<Arc<ContiguousFrames>>; 2],
    /// The status page (not DMA memory: the service writes it, `/proc/asound` reads it).
    pub status: Arc<ContiguousFrames>,
}

static BUFFERS: spin::Once<Option<Buffers>> = spin::Once::new();

/// The memory objects over [`BUFFERS`]: position page, status page, ring 0, ring 1.
static OBJECTS: spin::Once<[Option<Arc<MemObject>>; 4]> = spin::Once::new();

/// The sound memory, allocated (and mapped into the sound driver's IOMMU domain) the first
/// time; `None` if it could not be.
pub fn buffers() -> Option<&'static Buffers> {
    BUFFERS
        .call_once(|| {
            let pos = ContiguousFrames::allocate(1)?;
            let status = ContiguousFrames::allocate(1)?;
            let rings = [ContiguousFrames::allocate(RING_PAGES), ContiguousFrames::allocate(RING_PAGES)];
            // IOMMU (Group 1): the controller reaches the position page and the rings by DMA
            for b in core::iter::once(&pos).chain(rings.iter().flatten()) {
                if crate::arch::iommu::map_dma(ENDPOINT_SOUND_DEV, b.base, b.pages * 4096).is_err() {
                    crate::kprintln!("[snd] the sound controller's IOMMU domain could not map a buffer");
                }
            }
            Some(Buffers { pos, rings, status })
        })
        .as_ref()
}

/// Direction `dir`'s ring.
pub fn ring(dir: usize) -> Option<&'static Arc<ContiguousFrames>> {
    buffers()?.rings.get(dir)?.as_ref()
}

/// The memory objects the service gets handles to.
fn objects() -> &'static [Option<Arc<MemObject>>; 4] {
    OBJECTS.call_once(|| {
        let Some(b) = buffers() else { return [None, None, None, None] };
        // (not owned: the frames belong to `BUFFERS` for ever)
        let obj = |f: &Arc<ContiguousFrames>| Some(MemObject::frames(f.base, f.pages, false, None));
        [obj(&b.pos), obj(&b.status), b.rings[0].as_ref().and_then(obj), b.rings[1].as_ref().and_then(obj)]
    })
}

/// Direction `dir`'s record in the status page (`None`: no page).
pub fn status(dir: usize) -> Option<SndStatus> {
    let b = buffers()?;
    if dir > 1 {
        return None;
    }
    let p = crate::memory::frame_allocator::phys_to_virt(b.status.base).wrapping_add(dir * SND_STATUS_STRIDE) as *const SndStatus;
    // SAFETY: the record lies in the status page, which lives for ever
    let mut st = unsafe { crate::ipc::sound_page::read_record(p) }?;
    // The last descriptor may be gone already while the service has not taken the close
    // from its ring yet: a closed device reads "closed" at once, as on Linux
    if st.open != 0 {
        let key = 116 << 8 | (16 + 8 * dir as u64);
        if !crate::lx::obj::live_keys(LXS_SOUND, crate::ipc::protocol::LX_OBJ_KIND_SND_PCM).contains(&key) {
            st.open = 0;
        }
    }
    Some(st)
}

/// Fills `info` with the card and, through `give`, new handles of the service at
/// `endpoint` (split out so the host tests run it without the memory-object tables).
fn fill_info(info: &mut LxSndInfo, give: &mut dyn FnMut(&Arc<MemObject>) -> Result<u32, i64>) -> Result<(), i64> {
    let b = buffers().ok_or(ENODEV)?;
    let objs = objects();
    let mut h = [0u32; 4];
    for (i, o) in objs.iter().enumerate() {
        if let Some(o) = o {
            h[i] = give(o)?;
        }
    }
    info.pos_handle = h[0];
    info.status_handle = h[1];
    info.ring_handle = [h[2], h[3]];
    // (no physical addresses: the kernel programs the controller, `LX_SND_SETUP`)
    info.pos_phys = 0;
    info.ring_phys = [0; 2];
    info.ring_bytes = SND_RING_BYTES;
    if let Some(c) = crate::compat::linux::snd::card() {
        info.vendor = c.0;
        info.dirs = c.1 & ((b.rings[0].is_some() as u32) | (b.rings[1].is_some() as u32) << 1);
        info.amps = c.2;
        info.mmio = c.4;
        let n = c.3.len().min(SND_DESC_MAX - 1);
        info.desc[..n].copy_from_slice(&c.3.as_bytes()[..n]);
        info.desc_len = n as u32;
    }
    Ok(())
}

/// `SYS_LX_OBJ(LX_OBJ_SND, sub-op, x, y)` from host `h`: the sound service's operations
/// (the `LX_SND_*` sub-ops in `ipc/protocol.rs`).
pub fn ctl(h: u8, op: u64, x: u64, y: u64) -> i64 {
    if crate::lx::svc::host_of(LXS_SOUND) != h || crate::task::current_service() != Some(ENDPOINT_LX_SOUND) {
        return EPERM;
    }
    match op {
        LX_SND_GET => {
            start_guard();
            let mut info = LxSndInfo::ZERO;
            let r = fill_info(&mut info, &mut |o| crate::lx::mem::give(ENDPOINT_LX_SOUND, o.clone()));
            if let Err(e) = r {
                return e;
            }
            // SAFETY: a plain `repr(C)` record of integers
            let bytes = unsafe { core::slice::from_raw_parts(&info as *const LxSndInfo as *const u8, core::mem::size_of::<LxSndInfo>()) };
            crate::compat::linux::vfs::copy_out(x, bytes).map_or_else(|e| e, |()| 0)
        }
        LX_SND_BOOST if x < 2 => {
            crate::compat::linux::snd::boost_thread(x as usize, y);
            0
        }
        LX_SND_UNBOOST if x < 2 => {
            crate::compat::linux::snd::unboost(x as usize);
            0
        }
        LX_SND_DRVGEN => crate::ipc::service::server_of(ENDPOINT_SOUND_DEV) as i64,
        LX_SND_NOW => match x {
            0 => crate::arch::pit::now_ns() as i64,
            1 => crate::compat::linux::snd::wall_base_ns(),
            _ => EINVAL,
        },
        LX_SND_SETUP => {
            let (dir, fmt, bytes, period) = (x & 0xFF, x >> 8, y & 0xFFFF_FFFF, y >> 32);
            match crate::compat::linux::snd::program_stream(dir as usize, bytes, period, fmt) {
                Ok(slot) => slot as i64,
                Err(e) => e,
            }
        }
        _ => EINVAL,
    }
}

/// The service died: the guard task stops the streams unless a new instance is back.
static STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static STOP_WQ: crate::task::wait::WaitQueue = crate::task::wait::WaitQueue::new();
static GUARD: spin::Once<()> = spin::Once::new();

/// Starts the guard task once (the service's first `LX_SND_GET`).
fn start_guard() {
    GUARD.call_once(|| {
        crate::task::spawn("snd-guard", guard_task, crate::task::TaskPriority::Normal);
    });
}

/// After the sound service went away: if no new instance serves within a second, the
/// controller's streams are stopped (a service the ladder gave up on must not leave the
/// card looping silence and writing the capture ring for ever). A new instance stops them
/// itself before it goes online.
fn guard_task() {
    loop {
        STOP_WQ.register();
        if STOP.swap(false, core::sync::atomic::Ordering::AcqRel) {
            STOP_WQ.unregister();
            crate::task::wait::wait(Some(crate::arch::pit::ticks() + 100));
            if !crate::lx::svc::online(LXS_SOUND) {
                crate::compat::linux::snd::stop_streams();
                crate::kprintln!("[snd] the sound service is not back: the controller's streams were stopped");
            }
            continue;
        }
        crate::task::wait::wait(Some(crate::arch::pit::ticks() + 1000));
    }
}

/// The sound service went away (its memory-object handles are being dropped): silence the
/// rings, so the controller plays a gap until the new instance stops the stream; its
/// driving threads get their own priority back.
pub fn service_gone() {
    if let Some(b) = BUFFERS.get().and_then(|b| b.as_ref()) {
        // The playback ring only (the controller writes the capture ring)
        if let Some(r) = &b.rings[0] {
            // SAFETY: the ring lives for ever; the controller only reads it
            unsafe { core::ptr::write_bytes(crate::memory::frame_allocator::phys_to_virt(r.base), 0, (r.pages * 4096) as usize) };
        }
        // `/proc/asound` shows the streams closed until a new instance writes the page
        // SAFETY: the status page lives for ever; its writer is gone
        unsafe { core::ptr::write_bytes(crate::memory::frame_allocator::phys_to_virt(b.status.base), 0, 4096) };
    }
    crate::compat::linux::snd::unboost(0);
    crate::compat::linux::snd::unboost(1);
    STOP.store(true, core::sync::atomic::Ordering::Release);
    STOP_WQ.wake_all();
}
