//! # Memory objects (wave 6, Group 23: "M")
//!
//! Display, sound and the file service share memory with programs and with each other:
//! DRM dumb buffers, the ALSA ring, `tmpfs` data, bulk data between two services. A
//! **memory object** ([`MemObject`], `memory/vm.rs`) is a set of pages a service makes and
//! hands out; the kernel maps it wherever it is asked to.
//!
//! - **Anonymous objects** (`obj_anon`, [`LX_MEM_ANON`]): zeroed pages, allocated when
//!   first touched.
//! - **DMA objects** (`obj_dma`, [`LX_MEM_DMA`]): physically contiguous, pinned pages in the
//!   calling driver's IOMMU domain; the kernel makes them too ([`frames`]: a kernel
//!   driver's rings).
//! - **Handles.** A service names its objects by small numbers in a table of its own, one
//!   table per service endpoint (`task::current_service()`). [`LX_MEM_SHARE`] (the design's
//!   `LX_SVC_SHARE`) puts the same object into another service's table.
//! - **`mmap` of a service's object.** A program maps a descriptor a service owns (a
//!   [`ServerObject`]): `compat/linux/mm.rs` calls [`server_mmap`], which forwards the
//!   `mmap` to the object's owner; the owner answers with one of its handles and the page
//!   where the mapping starts ([`lx_mmap_answer`]); the kernel maps that object.
//! - **Lifetimes.** Whoever maps an object or holds a handle to it keeps it (an `Arc`).
//!   When a service goes away, [`service_gone`] drops its handle table; programs' mappings
//!   keep their pages. Objects outlive their service.
//! - **Kept objects** ([`LX_MEM_KEPT`]): owned by the service registry, keyed by
//!   `(service id, key)`, they survive a restart of their service: the new instance asks for
//!   the same key and gets the old pages. Key 0 is the kept-state object of restart support
//!   (Group 21, [`kept_get_or_create`]); [`drop_kept`] forgets a service's kept objects
//!   (the restart ladder's reset).
//!
//! Locking: the tables are spin locks taken with interrupts off, never held while an
//! object is dropped (a drop frees frames) or while user memory is touched.
//!
//! [`ServerObject`]: super::obj::ServerObject

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::ipc::protocol::{
    lx_mmap_parts, LX_MEM_ANON, LX_MEM_CLOSE, LX_MEM_DMA, LX_MEM_EXISTED, LX_MEM_HANDLES, LX_MEM_INFO, LX_MEM_KEPT, LX_MEM_MAP, LX_MEM_MAX, LX_MEM_SHARE, LX_MEM_UNKEEP,
    LX_MEM_UNMAP,
};
pub use crate::memory::vm::MemObject;
use crate::memory::vm::{Backing, MappedObject, PAGE_SIZE};

const EPERM: i64 = -1;
const EBADF: i64 = -9;
const ENOMEM: i64 = -12;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENODEV: i64 = -19;
const ENOSYS: i64 = -38;
const EACCES: i64 = -13;

/// Largest DMA object (as `SYS_DMA_ALLOC`).
const DMA_MAX: u64 = 16 * 1024 * 1024;
// wave7 G7-6 begin: vfs-server keeps one object per tmpfs file with data (its kept state)
/// Most kept objects per service: as many as a service has handles, plus room for its own
/// kept state (64 was wave 6's limit, too small for tmpfs files).
const KEPT_MAX: usize = LX_MEM_HANDLES + 64;
// wave7 G7-6 end

/// One handle: the object and what `LX_MEM_INFO` reports about it.
#[derive(Clone)]
struct Entry {
    obj: Arc<MemObject>,
    kept: bool,
    dma: bool,
}

/// One service's handles.
struct Table {
    endpoint: u32,
    /// Index = handle - 1.
    slots: Vec<Option<Entry>>,
}

static TABLES: Mutex<Vec<Table>> = Mutex::new(Vec::new());

// wave7 G7-6 begin: the kept registry by `(service id, key)` (a map: thousands per service)
/// The kept objects, by `(service id, key)`.
static KEPT: Mutex<BTreeMap<(u8, u64), Arc<MemObject>>> = Mutex::new(BTreeMap::new());

/// The keys of service `svc` in the registry.
fn svc_range(svc: u8) -> core::ops::RangeInclusive<(u8, u64)> {
    (svc, 0)..=(svc, u64::MAX)
}
// wave7 G7-6 end

fn tables<R>(f: impl FnOnce(&mut Vec<Table>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut TABLES.lock()))
}

fn kept<R>(f: impl FnOnce(&mut BTreeMap<(u8, u64), Arc<MemObject>>) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut KEPT.lock()))
}

// The two places that use Group 19's service registry (`super::svc`).

/// The service id whose kept objects a process serving `endpoint` makes: the host id of
/// that process (co-located services share their process, and its kept objects).
fn svc_of_endpoint(endpoint: u32) -> Option<u8> {
    super::svc::host_by_endpoint(endpoint)
}

/// The endpoint of the service that owns server object `dev` (whose table holds the handle
/// its `mmap` answer names): the object's host.
fn owner_endpoint(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>) -> u32 {
    dev.as_server().map_or(0, |o| super::svc::endpoint_of(o.svc()))
}

/// Puts `obj` into `endpoint`'s table; returns its handle (1..=[`LX_MEM_HANDLES`]).
pub fn give(endpoint: u32, obj: Arc<MemObject>) -> Result<u32, i64> {
    give_entry(endpoint, Entry { obj, kept: false, dma: false })
}

fn give_entry(endpoint: u32, e: Entry) -> Result<u32, i64> {
    tables(|t| {
        let i = match t.iter().position(|x| x.endpoint == endpoint) {
            Some(i) => i,
            None => {
                t.push(Table { endpoint, slots: Vec::new() });
                t.len() - 1
            }
        };
        let slots = &mut t[i].slots;
        if let Some(h) = slots.iter().position(|s| s.is_none()) {
            slots[h] = Some(e);
            return Ok(h as u32 + 1);
        }
        if slots.len() >= LX_MEM_HANDLES {
            return Err(EMFILE);
        }
        slots.push(Some(e));
        Ok(slots.len() as u32)
    })
}

fn entry(endpoint: u32, handle: u32) -> Option<Entry> {
    if handle == 0 {
        return None;
    }
    tables(|t| t.iter().find(|x| x.endpoint == endpoint)?.slots.get(handle as usize - 1)?.clone())
}

/// The object behind `endpoint`'s `handle`.
pub fn get(endpoint: u32, handle: u32) -> Option<Arc<MemObject>> {
    entry(endpoint, handle).map(|e| e.obj)
}

fn close(endpoint: u32, handle: u32) -> i64 {
    if handle == 0 {
        return EBADF;
    }
    let e = tables(|t| t.iter_mut().find(|x| x.endpoint == endpoint)?.slots.get_mut(handle as usize - 1)?.take());
    match e {
        Some(e) => {
            drop(e);
            0
        }
        None => EBADF,
    }
}

/// The service at `endpoint` went away: its handles go. Objects that something else maps
/// or holds (a program's mapping, another service, the kept registry) live on.
pub fn service_gone(endpoint: u32) {
    let table = tables(|t| t.iter().position(|x| x.endpoint == endpoint).map(|i| t.swap_remove(i)));
    let Some(table) = table else { return };
    let (mut n, mut alive, mut kept_n) = (0, 0, 0);
    for e in table.slots.iter().flatten() {
        n += 1;
        if e.kept {
            kept_n += 1;
        } else if Arc::strong_count(&e.obj) > 1 {
            alive += 1;
        }
    }
    drop(table);
    if n > 0 {
        crate::kprintln!("[lx-mem] service {:#x} went away: {} handles dropped ({} objects still mapped or shared, {} kept)", endpoint, n, alive, kept_n);
    }
}

/// A new anonymous object of `size` bytes (rounded up to pages).
pub fn anon(size: u64) -> Result<Arc<MemObject>, i64> {
    if size == 0 || size > LX_MEM_MAX {
        return Err(EINVAL);
    }
    Ok(MemObject::anon((size + PAGE_SIZE - 1) / PAGE_SIZE))
}

/// A kernel-made object over the contiguous frames at `base` (`pages` pages), which the
/// kernel keeps for as long as any mapping may exist (a kernel driver's rings).
pub fn frames(base: u64, pages: u64) -> Arc<MemObject> {
    MemObject::frames(base, pages, false, None)
}

/// New DMA memory for the driver at `endpoint`: contiguous, zeroed, in its IOMMU domain
/// (at its physical address) until the object ends.
fn dma(endpoint: u32, size: u64) -> Result<Arc<MemObject>, i64> {
    if size == 0 || size > DMA_MAX {
        return Err(EINVAL);
    }
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let base = {
        let mut fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
        let first = fa.allocate_contiguous_frames(pages as usize).ok_or(ENOMEM)?;
        let base = first.start_address().as_u64();
        for i in 0..pages {
            fa.adopt(x86_64::structures::paging::PhysFrame::containing_address(x86_64::PhysAddr::new(base + i * PAGE_SIZE)));
        }
        base
    };
    // SAFETY: the frames were just allocated and are reached through the direct map
    unsafe { core::ptr::write_bytes(crate::memory::frame_allocator::phys_to_virt(base), 0, (pages * PAGE_SIZE) as usize) };
    let unmap: alloc::boxed::Box<dyn Fn(u64, u64) + Send + Sync> = alloc::boxed::Box::new(move |b, len| crate::arch::iommu::unmap_dma(endpoint, b, len));
    // The object owns the frames from here on (dropping it frees them)
    let obj = MemObject::frames(base, pages, true, Some(unmap));
    crate::arch::iommu::map_dma(endpoint, base, pages * PAGE_SIZE).map_err(|_| ENOMEM)?;
    Ok(obj)
}

/// The kept object `idx` of service `svc`, made zeroed with `size` bytes the first time
/// (`new` = true). Index 0 is restart support's kept-state object (Group 21).
pub fn kept_get_or_create(svc: u8, idx: u64, size: u64) -> Result<(Arc<MemObject>, bool), i64> {
    let fresh = anon(size)?;
    kept(|k| {
        if let Some(o) = k.get(&(svc, idx)) {
            return Ok((o.clone(), false));
        }
        if k.range(svc_range(svc)).count() >= KEPT_MAX {
            return Err(ENOMEM);
        }
        k.insert((svc, idx), fresh.clone());
        Ok((fresh.clone(), true))
    })
}

/// Forgets every kept object of service `svc` (restart support's ladder reset: the kept
/// state is suspect). Mappings of them keep their pages until they go.
pub fn drop_kept(svc: u8) {
    let gone: Vec<Arc<MemObject>> = kept(|k| {
        let keys: Vec<(u8, u64)> = k.range(svc_range(svc)).map(|(key, _)| *key).collect();
        keys.iter().filter_map(|key| k.remove(key)).collect()
    });
    if !gone.is_empty() {
        crate::kprintln!("[lx-mem] service {}: {} kept objects dropped", svc, gone.len());
    }
}

/// Service `svc` drops its kept object `key`.
fn unkeep(svc: u8, key: u64) -> i64 {
    let gone = kept(|k| k.remove(&(svc, key)));
    match gone {
        Some(_) => 0,
        None => EINVAL,
    }
}

// wave7 G7-6 begin
/// [`LX_MEM_KEPTKEYS`](crate::ipc::protocol::LX_MEM_KEPTKEYS): the keys `>= from` of
/// service `svc`'s kept objects, at most `cap` (and 4096 per call) to `buf`.
fn kept_keys(svc: u8, buf: u64, cap: u64, from: u64) -> i64 {
    let cap = cap.min(4096) as usize;
    let keys: Vec<u64> = kept(|k| k.range((svc, from)..=(svc, u64::MAX)).take(cap).map(|(key, _)| key.1).collect());
    if keys.is_empty() {
        return 0;
    }
    let mut bytes = Vec::with_capacity(keys.len() * 8);
    for k in &keys {
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    match crate::compat::linux::vfs::copy_out(buf, &bytes) {
        Ok(()) => keys.len() as i64,
        Err(_) => EFAULT,
    }
}
// wave7 G7-6 end

/// `(key, pages, resident pages)` of each kept object of service `svc`.
pub fn kept_list(svc: u8) -> Vec<(u64, u64, u64)> {
    let objs: Vec<(u64, Arc<MemObject>)> = kept(|k| k.range(svc_range(svc)).map(|(key, o)| (key.1, o.clone())).collect());
    objs.iter().map(|(key, o)| (*key, o.pages(), o.resident())).collect()
}

/// Maps `len` bytes of `obj` from byte `offset` into the calling process, shared, with
/// `prot`; at `fixed` if given (replacing what is there), else where there is room.
pub fn map_current(obj: Arc<MemObject>, offset: u64, len: u64, prot: u32, fixed: Option<u64>) -> Result<u64, i64> {
    if offset & (PAGE_SIZE - 1) != 0 || len == 0 {
        return Err(EINVAL);
    }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if offset / PAGE_SIZE + pages > obj.pages() {
        return Err(EINVAL);
    }
    let mm = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten().ok_or(EFAULT)?;
    let mut m = mm.lock();
    let obj: Arc<dyn MappedObject> = obj;
    let a = m.mmap(fixed.unwrap_or(0), pages * PAGE_SIZE, prot & 7, true, fixed.is_some(), false, Backing::Object { obj, pgoff: offset / PAGE_SIZE })?;
    m.set_name(a, a + pages * PAGE_SIZE, Some("[hydra-mem]"));
    Ok(a)
}

/// `SYS_LX_MEM(op, a, b, c, d)` (native 64): a service's operations on memory objects (the
/// `LX_MEM_*` constants in `ipc/protocol.rs`). Only registered services may call it.
pub fn sys_mem(op: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let Some(ep) = crate::task::current_service() else { return EPERM };
    match op {
        LX_MEM_ANON => {
            if b & LX_MEM_KEPT != 0 {
                let Some(svc) = svc_of_endpoint(ep) else { return EPERM };
                if c == 0 {
                    return EINVAL;
                }
                let (obj, new) = match kept_get_or_create(svc, c, a) {
                    Ok(x) => x,
                    Err(e) => return e,
                };
                match give_entry(ep, Entry { obj, kept: true, dma: false }) {
                    Ok(h) => h as i64 | if new { 0 } else { LX_MEM_EXISTED },
                    Err(e) => e,
                }
            } else {
                match anon(a).and_then(|o| give(ep, o)) {
                    Ok(h) => h as i64,
                    Err(e) => e,
                }
            }
        }
        LX_MEM_DMA => {
            let obj = match dma(ep, a) {
                Ok(o) => o,
                Err(e) => return e,
            };
            let phys = obj.phys_base().unwrap_or(0);
            if b != 0 {
                if let Err(e) = crate::compat::linux::vfs::copy_out(b, &phys.to_le_bytes()) {
                    return e;
                }
            }
            match give_entry(ep, Entry { obj, kept: false, dma: true }) {
                Ok(h) => h as i64,
                Err(e) => e,
            }
        }
        LX_MEM_MAP => {
            let Some(obj) = get(ep, a as u32) else { return EBADF };
            map_current(obj, b, c, d as u32, None).map_or_else(|e| e, |x| x as i64)
        }
        LX_MEM_UNMAP => {
            let Some(mm) = crate::task::with_current_task_mut(|t| t.mm.clone()).flatten() else { return EFAULT };
            crate::compat::linux::mm::sys_munmap(&mm, a, b)
        }
        LX_MEM_CLOSE => close(ep, a as u32),
        LX_MEM_SHARE => {
            let Some(e) = entry(ep, a as u32) else { return EBADF };
            let peer = b as u32;
            if crate::ipc::service::service(peer).is_none() {
                return EINVAL;
            }
            // The peer's handle is not kept (it is the sharer's kept object, not the peer's)
            match give_entry(peer, Entry { kept: false, ..e }) {
                Ok(h) => h as i64,
                Err(e) => e,
            }
        }
        LX_MEM_INFO => match entry(ep, a as u32) {
            Some(e) => (e.obj.pages() | (e.kept as u64) << 48 | (e.dma as u64) << 49) as i64,
            None => EBADF,
        },
        LX_MEM_UNKEEP => match svc_of_endpoint(ep) {
            Some(svc) => unkeep(svc, a),
            None => EPERM,
        },
        // wave7 G7-6
        crate::ipc::protocol::LX_MEM_KEPTKEYS => match svc_of_endpoint(ep) {
            Some(svc) => kept_keys(svc, a, b, c),
            None => EPERM,
        },
        _ => EINVAL,
    }
}

/// `mmap` of server object `dev` (`compat/linux/mm.rs`): forwards the call (`args` as the
/// program gave them) to the object's owner, which names one of its memory objects.
/// Returns the object, what a shared writable mapping gets (0, or `-EACCES` for a
/// read-only answer) and the object page where the mapping starts.
pub fn server_mmap(dev: &Arc<dyn crate::compat::linux::chardev::CharDevice>, args: [u64; 6]) -> Result<(Arc<dyn MappedObject>, i64, u64), i64> {
    let r = super::call_obj(9, args, dev);
    if r == ENOSYS || r == 0 {
        // A service (or kind) without mmap
        return Err(ENODEV);
    }
    if r < 0 {
        return Err(r);
    }
    let (handle, pgoff, ro) = lx_mmap_parts(r);
    let obj = get(owner_endpoint(dev), handle).ok_or(ENODEV)?;
    let obj: Arc<dyn MappedObject> = obj;
    Ok((obj, if ro { EACCES } else { 0 }, pgoff))
}

/// Text for the kernel's diagnostics: handles per service, kept objects.
pub fn summary() -> alloc::string::String {
    let t: Vec<(u32, usize)> = tables(|t| t.iter().map(|x| (x.endpoint, x.slots.iter().flatten().count())).collect());
    let k = kept(|k| k.len());
    let mut s = alloc::format!("[lx-mem] kept objects: {}", k);
    for (ep, n) in t {
        s.push_str(&alloc::format!("; {:#x}: {} handles", ep, n));
    }
    s
}

// Host tests (test wave, Group 30): tests/host-t30 compiles this file with them
#[cfg(test)]
#[path = "../../tests/host-t30/unit/lx_mem.rs"]
pub(crate) mod tests;
