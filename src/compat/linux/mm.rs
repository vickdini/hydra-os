//! # Linux Memory-Management System Calls
//!
//! `mmap`, `munmap`, `mprotect`, `brk`, `mremap`, `madvise`, `msync` and `mincore` for
//! Linux processes that own a private address space ([`crate::memory::vm::Mm`]).
//! Tasks without one (legacy binaries linked into the kernel identity map) keep the
//! heap-backed fallbacks in [`super::dispatch_linux_syscall`].

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::fs::ZfsClient;
use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec};
use crate::memory::vm::{Backing, MappedObject, Mm, PAGE_SIZE};

const EPERM: i64 = 1;
const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EINVAL: i64 = 22;
const ENODEV: i64 = 19;

/// Linux `mmap` flag: share changes across processes mapping the same memory.
pub const MAP_SHARED: u64 = 0x01;
/// Linux `mmap` flag: create a private copy-on-write mapping.
pub const MAP_PRIVATE: u64 = 0x02;
/// Linux `mmap` flag: validate mapping flags strictly.
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
/// Linux `mmap` flag: place the mapping at exactly the requested address.
pub const MAP_FIXED: u64 = 0x10;
/// Linux `mmap` flag: mapping is not backed by any file (zero-initialized RAM).
pub const MAP_ANONYMOUS: u64 = 0x20;
/// Linux `mmap` flag: place at address but fail if already occupied.
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
/// Linux `MAP_32BIT`: place the mapping in the low 2 GiB.
pub const MAP_32BIT: u64 = 0x40;

/// Linux `mremap` flag: allow the kernel to relocate the mapping if needed.
pub const MREMAP_MAYMOVE: u64 = 1;
/// Linux `mremap` flag: relocate to fixed address specified in `new_addr`.
pub const MREMAP_FIXED: u64 = 2;

/// Linux `madvise` flag: hints that the specified address range will not be needed soon.
pub const MADV_DONTNEED: u64 = 4;
/// Linux `madvise` flag: hints that memory in range can be freed lazily.
pub const MADV_FREE: u64 = 8;

/// Page-cache objects for ZFS inodes, shared by every mapping and every `read` of the same
/// file. Entries are weak: an object lives while something maps it or [`RETAINED`] keeps it.
static INODE_OBJECTS: Mutex<BTreeMap<u64, Weak<InodeObject>>> = Mutex::new(BTreeMap::new());

/// Files used recently, least recently first: their pages stay cached after the last
/// mapping goes and between `read`s (each page from the file server is a request to it,
/// ~100 us even when it has the block: a Wine start read its libraries 8,000 times).
/// Bounded by [`RETAIN_MAX`] files and [`budget_pages`] pages.
static RETAINED: Mutex<Vec<Arc<InodeObject>>> = Mutex::new(Vec::new());
/// Ticks of use: an object's [`InodeObject::used`] is the tick of its last use.
static USE_CLOCK: AtomicU64 = AtomicU64::new(0);
const RETAIN_MAX: usize = 1024;
/// Pages all page-cache objects hold.
static CACHED_PAGES: AtomicUsize = AtomicUsize::new(0);
/// Files larger than this are read past the cache (unless mapped): one large file read
/// once would push out everything else.
const READ_CACHE_MAX: u64 = 32 * 1024 * 1024;

/// How many pages the cache may keep for files nothing maps: an eighth of the memory, and
/// no more than a quarter of what is free now (it gives way as memory fills).
fn budget_pages() -> usize {
    let fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
    ((fa.total_usable_memory() / 8).min(fa.free_memory() / 4) / PAGE_SIZE) as usize
}

/// A mapped ZFS file: pages are read from the pool on first fault and kept while mapped.
/// Pages written through shared mappings go back to the file on `msync` and when the last
/// mapping goes (Wine passes data between mappings of one section this way).
pub struct InodeObject {
    ino: u64,
    pages: Mutex<BTreeMap<u64, PhysFrame<Size4KiB>>>,
    /// Counts writes and truncations of the file: a page read from the pool while one
    /// happened may hold the old data, and is read again.
    wgen: AtomicU64,
    /// Live `mmap`s of the file ([`MapHandle`]s).
    maps: AtomicUsize,
    /// Whether [`RETAINED`] holds it, and when it was last used (a [`USE_CLOCK`] tick).
    retained: core::sync::atomic::AtomicBool,
    used: AtomicU64,
    /// Pages written through a shared mapping. They stay in the set after a write-back:
    /// their mappings stay writable, so later writes are not seen and each `msync` (and the
    /// last unmap) writes them again.
    dirty: Mutex<BTreeSet<u64>>,
}

impl InodeObject {
    /// Writes the dirty pages back to the file, up to its current size (a mapping never
    /// grows the file; the tail of the last page past the end stays out of it).
    fn write_back(&self) {
        let dirty: alloc::vec::Vec<u64> = self.dirty.lock().iter().copied().collect();
        if dirty.is_empty() {
            return;
        }
        let Ok(attr) = ZfsClient::getattr(self.ino) else { return };
        let mut buf = alloc::vec![0u8; PAGE_SIZE as usize];
        for p in dirty {
            let off = p * PAGE_SIZE;
            if off >= attr.size {
                continue;
            }
            let Some(frame) = self.pages.lock().get(&p).copied() else { continue };
            let n = (attr.size - off).min(PAGE_SIZE) as usize;
            // Copied out first: the page stays mapped and may change while it is written
            unsafe {
                core::ptr::copy_nonoverlapping(
                    crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()) as *const u8,
                    buf.as_mut_ptr(),
                    n,
                );
            }
            let _ = ZfsClient::write_at(self.ino, off, &buf[..n]);
        }
    }
}

/// Pages a mapped file reads from the pool at once when one is missing: the aligned window
/// around it (Linux reads ahead too). Each read is a request to the file server, which
/// costs far more than the extra pages: page by page, mapping Firefox's libraries took
/// 20,000 requests.
const READ_AHEAD_PAGES: u64 = 16;

impl MappedObject for InodeObject {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        if let Some(&f) = self.pages.lock().get(&pgoff) {
            return Some(f);
        }
        let size = ZfsClient::getattr(self.ino).ok()?.size;
        let file_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        if pgoff >= file_pages {
            return None;
        }
        // The aligned window around `pgoff`, trimmed of cached pages at its start, ending
        // before the first cached page after `pgoff` or at the end of the file. Cached
        // pages inside it are read again but kept as they are
        let window = pgoff - pgoff % READ_AHEAD_PAGES;
        let (first, end) = {
            let pages = self.pages.lock();
            let mut first = window;
            while first < pgoff && pages.contains_key(&first) {
                first += 1;
            }
            let mut end = pgoff + 1;
            while end < (window + READ_AHEAD_PAGES).min(file_pages) && !pages.contains_key(&end) {
                end += 1;
            }
            (first, end)
        };
        let mut buf = alloc::vec![0u8; ((end - first) * PAGE_SIZE) as usize];
        let gen = self.wgen.load(Ordering::Acquire);
        let t0 = super::prof::start();
        let read = ZfsClient::read_uncached(self.ino, first * PAGE_SIZE, &mut buf);
        super::prof::fault(super::prof::FILE_READ, t0);
        read.ok()?;
        let mut pages = self.pages.lock();
        if self.wgen.load(Ordering::Acquire) != gen {
            // The file changed while it was read: read it again
            drop(pages);
            return self.get_page(pgoff);
        }
        let mut wanted = None;
        for p in first..end {
            if let Some(&existing) = pages.get(&p) {
                // Another CPU read it meanwhile: keep that one
                if p == pgoff {
                    wanted = Some(existing);
                }
                continue;
            }
            let Some(frame) = alloc_user_frame() else {
                // Out of memory: the page asked for is all that matters
                if p == pgoff {
                    return None;
                }
                continue;
            };
            let off = ((p - first) * PAGE_SIZE) as usize;
            unsafe {
                core::ptr::copy_nonoverlapping(
                    buf[off..].as_ptr(),
                    crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()),
                    PAGE_SIZE as usize,
                );
            }
            pages.insert(p, frame);
            CACHED_PAGES.fetch_add(1, Ordering::Relaxed);
            if p == pgoff {
                wanted = Some(frame);
            }
        }
        wanted
    }

    fn tracks_writes(&self) -> bool {
        true
    }

    fn page_written(&self, pgoff: u64) {
        self.dirty.lock().insert(pgoff);
    }

    fn sync(&self) {
        self.write_back();
    }
}

impl Drop for InodeObject {
    fn drop(&mut self) {
        self.write_back();
        let pages = self.pages.lock();
        CACHED_PAGES.fetch_sub(pages.len(), Ordering::Relaxed);
        for (_, f) in pages.iter() {
            frame_ref_dec(*f);
        }
        ZfsClient::release(self.ino);
    }
}

/// Returns the shared page-cache object for a ZFS inode.
///
/// # Arguments
///
/// * `ino` - Inode number to find or create a page-cache object for.
///
/// # Returns
///
/// An `Arc<InodeObject>` referencing the inode's page-cache mapping.
pub fn inode_object(ino: u64) -> Arc<InodeObject> {
    let mut map = INODE_OBJECTS.lock();
    if let Some(obj) = map.get(&ino).and_then(Weak::upgrade) {
        return obj;
    }
    // A mapping keeps the inode alive after unlink, like an open descriptor
    ZfsClient::open_ref(ino);
    let obj = Arc::new(InodeObject {
        ino,
        pages: Mutex::new(BTreeMap::new()),
        wgen: AtomicU64::new(0),
        maps: AtomicUsize::new(0),
        retained: core::sync::atomic::AtomicBool::new(false),
        used: AtomicU64::new(0),
        dirty: Mutex::new(BTreeSet::new()),
    });
    map.retain(|_, w| w.strong_count() > 0);
    map.insert(ino, Arc::downgrade(&obj));
    drop(map);
    retain(&obj);
    obj
}

/// Marks `obj` as just used. A file the cache does not hold yet joins it, and the least
/// recently used ones over the limits go: only then is the list searched (a cache hit, a
/// read of a cached page, costs a store).
fn retain(obj: &Arc<InodeObject>) {
    obj.used.store(USE_CLOCK.fetch_add(1, Ordering::Relaxed), Ordering::Relaxed);
    if obj.retained.load(Ordering::Acquire) {
        return;
    }
    let budget = budget_pages();
    let victims = {
        let mut r = RETAINED.lock();
        if obj.retained.swap(true, Ordering::AcqRel) {
            return;
        }
        r.push(obj.clone());
        let mut victims = Vec::new();
        let mut projected = CACHED_PAGES.load(Ordering::Relaxed);
        if r.len() > RETAIN_MAX || projected > budget {
            // Least recently used first; files still mapped elsewhere go only when there are
            // too many files (their pages would not be freed)
            let mut order: Vec<(u64, usize)> = r.iter().enumerate().map(|(i, o)| (o.used.load(Ordering::Relaxed), i)).collect();
            order.sort_unstable();
            let mut gone = alloc::vec![false; r.len()];
            let mut count = r.len();
            for (_, i) in order {
                if count <= 1 || (count <= RETAIN_MAX && projected <= budget) {
                    break;
                }
                let o = &r[i];
                if Arc::ptr_eq(o, obj) {
                    continue;
                }
                let only_here = Arc::strong_count(o) == 1;
                if only_here || count > RETAIN_MAX {
                    if only_here {
                        projected = projected.saturating_sub(o.pages.lock().len());
                    }
                    gone[i] = true;
                    count -= 1;
                }
            }
            let mut i = 0;
            r.retain(|o| {
                let keep = !gone[i];
                i += 1;
                if !keep {
                    o.retained.store(false, Ordering::Release);
                    victims.push(o.clone());
                }
                keep
            });
        }
        victims
    };
    // Outside the lock: dropping the last reference writes back and releases the inode,
    // file-server requests
    drop(victims);
}

/// Writes back what shared mappings wrote to every cached file (for `sync` and power-off).
pub fn cache_flush() {
    let objs: alloc::vec::Vec<Arc<InodeObject>> = RETAINED.lock().iter().cloned().collect();
    for o in objs {
        o.write_back();
    }
}

/// Reads file `ino` at `offset` through the page cache (Linux's `read` of a regular file).
pub fn cached_read(ino: u64, offset: u64, buf: &mut [u8]) -> Result<usize, i64> {
    // wave9 GM: an in-memory tmpfs file is its own page cache
    if let Some(t) = crate::fs::tmem::get(ino) {
        return Ok(t.read(offset, buf));
    }
    let size = ZfsClient::getattr(ino)?.size;
    if offset >= size || buf.is_empty() {
        return Ok(0);
    }
    let existing = INODE_OBJECTS.lock().get(&ino).and_then(Weak::upgrade);
    let obj = match existing {
        Some(o) => {
            retain(&o);
            o
        }
        None if size > READ_CACHE_MAX => return ZfsClient::read_uncached(ino, offset, buf),
        None => inode_object(ino),
    };
    let total = (buf.len() as u64).min(size - offset) as usize;
    let mut done = 0;
    while done < total {
        let pos = offset + done as u64;
        let in_page = (pos % PAGE_SIZE) as usize;
        let n = (PAGE_SIZE as usize - in_page).min(total - done);
        let Some(frame) = obj.get_page(pos / PAGE_SIZE) else {
            // Shorter than its size said (truncated meanwhile) or out of memory
            return if done > 0 { Ok(done) } else { ZfsClient::read_uncached(ino, offset, buf) };
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()).add(in_page),
                buf[done..].as_mut_ptr(),
                n,
            );
        }
        done += n;
    }
    Ok(done)
}

/// After `data` was written to `ino` at `offset`: the cached pages it covers take it.
pub fn cache_written(ino: u64, offset: u64, data: &[u8]) {
    let Some(obj) = INODE_OBJECTS.lock().get(&ino).and_then(Weak::upgrade) else { return };
    obj.wgen.fetch_add(1, Ordering::AcqRel);
    let pages = obj.pages.lock();
    let mut done = 0;
    while done < data.len() {
        let pos = offset + done as u64;
        let in_page = (pos % PAGE_SIZE) as usize;
        let n = (PAGE_SIZE as usize - in_page).min(data.len() - done);
        if let Some(frame) = pages.get(&(pos / PAGE_SIZE)) {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data[done..].as_ptr(),
                    crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()).add(in_page),
                    n,
                );
            }
        }
        done += n;
    }
}

/// After `ino` was truncated or extended to `size`: pages past it go, the end of the last
/// one is zeroed (what a later extension reads there).
pub fn cache_truncated(ino: u64, size: u64) {
    let Some(obj) = INODE_OBJECTS.lock().get(&ino).and_then(Weak::upgrade) else { return };
    obj.wgen.fetch_add(1, Ordering::AcqRel);
    let first_gone = size.div_ceil(PAGE_SIZE);
    let mut pages = obj.pages.lock();
    let gone: alloc::vec::Vec<u64> = pages.range(first_gone..).map(|(&p, _)| p).collect();
    for p in gone {
        if let Some(f) = pages.remove(&p) {
            CACHED_PAGES.fetch_sub(1, Ordering::Relaxed);
            frame_ref_dec(f);
        }
    }
    if size % PAGE_SIZE != 0 {
        if let Some(frame) = pages.get(&(size / PAGE_SIZE)) {
            let keep = (size % PAGE_SIZE) as usize;
            unsafe {
                core::ptr::write_bytes(
                    crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()).add(keep),
                    0,
                    PAGE_SIZE as usize - keep,
                );
            }
        }
    }
    drop(pages);
    obj.dirty.lock().retain(|&p| p < first_gone);
}

/// The page cache's size for `/proc/meminfo`: `(pages it holds, pages of files only the
/// cache keeps)`. The second are free memory in waiting ([`cache_shrink`] lets them go),
/// Linux's reclaimable page cache.
pub fn cache_pages() -> (usize, usize) {
    let total = CACHED_PAGES.load(Ordering::Relaxed);
    // try_lock: /proc readers must not wait on (or deadlock with) a cache update
    let reclaimable = RETAINED.try_lock().map_or(0, |r| {
        r.iter().filter(|o| Arc::strong_count(o) == 1).map(|o| o.pages.try_lock().map_or(0, |p| p.len())).sum()
    });
    (total, reclaimable.min(total))
}

/// Memory is short: lets go of the least recently used files only the cache keeps until
/// `want` pages are freed (or none is left). Only tries the locks: it runs inside
/// allocations, which may hold them.
pub fn cache_shrink(want: usize) {
    let victims = {
        let Some(mut r) = RETAINED.try_lock() else { return };
        let mut order: Vec<(u64, usize)> =
            r.iter().enumerate().filter(|(_, o)| Arc::strong_count(o) == 1).map(|(i, o)| (o.used.load(Ordering::Relaxed), i)).collect();
        order.sort_unstable();
        let mut gone = alloc::vec![false; r.len()];
        let mut freed = 0;
        for (_, i) in order {
            if freed >= want {
                break;
            }
            let Some(n) = r[i].pages.try_lock().map(|p| p.len()) else { continue };
            freed += n;
            gone[i] = true;
        }
        let mut victims = Vec::new();
        let mut i = 0;
        r.retain(|o| {
            let keep = !gone[i];
            i += 1;
            if !keep {
                o.retained.store(false, Ordering::Release);
                victims.push(o.clone());
            }
            keep
        });
        victims
    };
    drop(victims);
}

/// Lets go of every cached file nothing maps (Linux's `drop_caches`); what shared mappings
/// wrote goes back first.
pub fn cache_drop_all() {
    let all: Vec<Arc<InodeObject>> = RETAINED.lock().drain(..).collect();
    for o in &all {
        o.retained.store(false, Ordering::Release);
    }
    drop(all);
}

/// One `mmap` of a file. The cache keeps files after their last mapping, so it is the
/// mappings that tell when the last one goes: what they wrote then goes back to the file
/// (as it did when the last unmap dropped the object), and its pages are clean again.
pub struct MapHandle(Arc<InodeObject>);

impl MapHandle {
    fn new(obj: Arc<InodeObject>) -> Self {
        obj.maps.fetch_add(1, Ordering::AcqRel);
        Self(obj)
    }
}

impl MappedObject for MapHandle {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        self.0.get_page(pgoff)
    }

    fn tracks_writes(&self) -> bool {
        true
    }

    fn page_written(&self, pgoff: u64) {
        self.0.page_written(pgoff);
    }

    fn sync(&self) {
        self.0.write_back();
    }
}

impl Drop for MapHandle {
    fn drop(&mut self) {
        if self.0.maps.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.write_back();
            self.0.dirty.lock().clear();
        }
    }
}

/// Lets go of `ino` (it was unlinked or replaced): the cache no longer keeps the file alive.
pub fn cache_forget(ino: u64) {
    let victim = {
        let mut r = RETAINED.lock();
        r.iter().position(|o| o.ino == ino).map(|i| r.swap_remove(i))
    };
    if let Some(v) = &victim {
        v.retained.store(false, Ordering::Release);
    }
    drop(victim);
}

/// An executable or shared object on the pool, mapped through the page cache: only the
/// headers are read now, the rest is faulted in page by page.
///
/// # Arguments
///
/// * `ino` - Target file inode number.
///
/// # Returns
///
/// * `Ok(ElfSource)` on successful header reading and object creation.
/// * `Err(errno)` on filesystem read error.
pub fn inode_source(ino: u64) -> Result<crate::task::exec::ElfSource, i64> {
    let len = ZfsClient::getattr(ino)?.size;
    let mut head = alloc::vec![0u8; len.min(64 * 1024) as usize];
    let n = ZfsClient::read_at(ino, 0, &mut head)?;
    head.truncate(n);
    // wave9 GM: an in-memory tmpfs file runs from its own object
    let obj: Arc<dyn MappedObject> = match crate::fs::tmem::get(ino) {
        Some(t) => t,
        None => inode_object(ino),
    };
    Ok(crate::task::exec::ElfSource { head, len, obj })
}

// wave9 GM begin
/// What a mapping of file `ino` maps: an in-memory tmpfs file's own object (its pages are
/// the file's: every mapper and `read`/`write` share them), else the file's page cache.
fn file_object(ino: u64) -> Arc<dyn MappedObject> {
    match crate::fs::tmem::get(ino) {
        Some(t) => t,
        None => Arc::new(MapHandle::new(inode_object(ino))),
    }
}
// wave9 GM end

/// Returns the running task's address space, if it has one.
///
/// # Returns
///
/// `Some(Arc<Mutex<Mm>>)` if the current task has an active memory manager, or `None`.
pub fn current_mm() -> Option<Arc<Mutex<Mm>>> {
    crate::task::with_current_task_mut(|t| t.mm.clone()).flatten()
}

/// Resolves the object behind a file descriptor for `mmap`.
///
/// # Arguments
///
/// * `fd` - File descriptor index.
/// * `pgoff` - The mapping's page offset in the file.
/// * `args` - The `mmap` call's arguments (a service's object gets them all).
///
/// # Returns
///
/// * `Ok((obj, write_err, pgoff))`: the object backing the descriptor, what a shared mapping
///   of it gets for asking to write: 0 if it may (Linux's `VM_MAYWRITE`), `-EACCES` if the
///   descriptor was not opened for writing, `-EPERM` for a memfd sealed against writes.
///   and the object page that maps at the mapping's start (`pgoff` but for a service's
///   object, whose service says where).
/// * `Err(-EBADF)` if descriptor is invalid.
/// * `Err(-EACCES)` if descriptor is not readable.
/// * `Err(-ENODEV)` if underlying resource does not support memory mapping.
fn fd_object(fd: usize, pgoff: u64, args: &[u64; 6]) -> Result<(Arc<dyn MappedObject>, i64, u64), i64> {
    const O_ACCMODE: u32 = 0o3;
    const O_RDONLY: u32 = 0o0;
    const F_SEAL_WRITE: u32 = 0x0008;
    const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd).cloned()).ok_or(-EBADF)?;
    match desc {
        crate::fs::FileDescriptor::MemFd { memfd, flags } => {
            let err = if flags & O_ACCMODE == O_RDONLY {
                -EACCES
            } else if memfd.lock().seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
                -EPERM
            } else {
                0
            };
            Ok((memfd, err, pgoff))
        }
        crate::fs::FileDescriptor::Vnode(f) => {
            let (ino, readable, writable) = {
                let f = f.lock();
                (f.ino, f.readable(), f.writable())
            };
            if !readable {
                return Err(-EACCES);
            }
            Ok((file_object(ino), if writable { 0 } else { -EACCES }, pgoff))
        }
        crate::fs::FileDescriptor::File { path, readable, writable, .. } => {
            if !readable {
                return Err(-EACCES);
            }
            let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| -ENODEV)?;
            Ok((file_object(ino), if writable { 0 } else { -EACCES }, pgoff))
        }
        // wave6 G23 begin: a service's object: the service names one of its memory
        // objects and where in it the mapping starts (`crate::lx::mem::server_mmap`)
        crate::fs::FileDescriptor::Device(d) if d.as_server().is_some() => crate::lx::mem::server_mmap(&d, *args),
        // wave6 G23 end
        // A device's mmap_object decides for itself what may be mapped
        crate::fs::FileDescriptor::Device(d) => Ok((d.mmap_object_at(pgoff)?, 0, pgoff)),
        _ => Err(-ENODEV),
    }
}

/// Linux `mmap` (syscall 9): maps files or anonymous memory into user address space.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `addr` - Requested virtual mapping hint or target address.
/// * `len` - Length of mapping in bytes.
/// * `prot` - Page protection flags (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
/// * `flags` - Mapping flags (`MAP_SHARED`, `MAP_PRIVATE`, `MAP_ANONYMOUS`, `MAP_FIXED`).
/// * `fd` - Backing file descriptor (if not anonymous).
/// * `offset` - Byte offset into backing file.
///
/// # Returns
///
/// Starting virtual address of the mapped range on success, or a negative Linux errno on error.
pub fn sys_mmap(mm: &Mutex<Mm>, addr: u64, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> i64 {
    let fd = fd as i32;
    if len == 0 || offset & (PAGE_SIZE - 1) != 0 {
        return -EINVAL;
    }
    // Larger than the address space (Linux: ENOMEM); the sums below must not wrap
    if len > crate::memory::vm::USER_SPACE_END {
        return -ENOMEM;
    }
    let shared = match flags & MAP_SHARED_VALIDATE {
        MAP_SHARED | MAP_SHARED_VALIDATE => true,
        MAP_PRIVATE => false,
        _ => return -EINVAL,
    };
    let mut may_write = true;
    let backing = if flags & MAP_ANONYMOUS != 0 || fd == -1 {
        Backing::Anon
    } else {
        if fd < 0 {
            return -EBADF;
        }
        match fd_object(fd as usize, offset / PAGE_SIZE, &[addr, len, prot, flags, fd as i64 as u64, offset]) {
            Ok((obj, write_err, pgoff)) => {
                // A shared mapping writes the file itself, so as Linux: only through a
                // descriptor that may write it, now (EACCES/EPERM) or after mprotect
                // (no VM_MAYWRITE). A private mapping writes its own copies.
                if shared && write_err != 0 {
                    if prot & crate::memory::vm::PROT_WRITE as u64 != 0 {
                        return write_err;
                    }
                    may_write = false;
                }
                Backing::Object { obj, pgoff }
            }
            Err(e) => return e,
        }
    };
    let fixed = flags & MAP_FIXED != 0;
    let noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    // The name /proc/<pid>/maps shows: the file's path
    let name = if matches!(backing, Backing::Object { .. }) {
        crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
            Some(crate::fs::FileDescriptor::Vnode(f)) => Some(f.lock().path.clone()),
            Some(crate::fs::FileDescriptor::MemFd { memfd, .. }) => Some(alloc::format!("/memfd:{} (deleted)", memfd.lock().name)),
            Some(crate::fs::FileDescriptor::Device(d)) => Some(d.path()),
            _ => None,
        })
    } else {
        None
    };
    let mut m = mm.lock();
    // MAP_32BIT: below 2 GiB, unless the hint is free (Linux tries the hint first). JITs
    // and Wine put what 32-bit code reaches here. Linux's window is [1 GiB, 2 GiB); Hydra's
    // is its low user window [LOW_USER_START, vm::low_user_end()).
    let mut addr = addr;
    if flags & MAP_32BIT != 0 && !fixed && !noreplace {
        let hint = addr & !(PAGE_SIZE - 1);
        let len_up = (len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let hint_free = hint != 0 && crate::memory::vm::is_user_range(hint, len_up) && !m.overlaps(hint, hint + len_up);
        if !hint_free {
            match m.find_free_in(len, crate::memory::vm::LOW_USER_START, crate::memory::vm::low_user_end()) {
                Some(a) => addr = a,
                None => return -ENOMEM,
            }
        }
    }
    match m.mmap(addr, len, prot as u32, shared, fixed, noreplace, backing) {
        Ok(a) => {
            // The mapping covers whole pages: naming only `len` bytes would split it in the
            // middle of a page (Wine maps files by their exact size), and the part after
            // the split would start at an address no page starts at
            let end = a + ((len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));
            if name.is_some() {
                m.set_name(a, end, name.as_deref());
            }
            if !may_write {
                m.deny_write(a, end);
            }
            a as i64
        }
        Err(e) => e,
    }
}

/// Linux `munmap` (syscall 11): unmaps memory in the specified address range.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `addr` - Starting virtual address to unmap (must be page-aligned).
/// * `len` - Number of bytes to unmap.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
pub fn sys_munmap(mm: &Mutex<Mm>, addr: u64, len: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 || len == 0 || !crate::memory::vm::is_user_range(addr, len) {
        return -EINVAL;
    }
    let end = (addr + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    mm.lock().unmap(addr, end);
    0
}

/// Linux `mprotect` (syscall 10): modifies access permissions for mapped memory pages.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `addr` - Starting virtual address to modify.
/// * `len` - Number of bytes to modify permissions for.
/// * `prot` - New protection bits (`PROT_READ`, `PROT_WRITE`, `PROT_EXEC`).
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
pub fn sys_mprotect(mm: &Mutex<Mm>, addr: u64, len: u64, prot: u64) -> i64 {
    match mm.lock().mprotect(addr, len, prot as u32) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Linux `brk` (syscall 12): changes the process data segment break address.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `new_brk` - Desired break address (`0` queries current break).
///
/// # Returns
///
/// Updated process break address.
pub fn sys_brk(mm: &Mutex<Mm>, new_brk: u64) -> i64 {
    mm.lock().set_brk(new_brk) as i64
}

/// Linux `mremap` (syscall 25): expands or shrinks an existing virtual memory mapping.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `old` - Old starting virtual address.
/// * `old_len` - Old mapping size in bytes.
/// * `new_len` - New mapping size in bytes.
/// * `flags` - Remap options (`MREMAP_MAYMOVE`, `MREMAP_FIXED`).
/// * `new_addr` - Target address when `MREMAP_FIXED` is specified.
///
/// # Returns
///
/// Starting virtual address of the remapped region, or a negative Linux errno on error.
pub fn sys_mremap(mm: &Mutex<Mm>, old: u64, old_len: u64, new_len: u64, flags: u64, new_addr: u64) -> i64 {
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED) != 0 {
        return -EINVAL;
    }
    let fixed_to = if flags & MREMAP_FIXED != 0 {
        if flags & MREMAP_MAYMOVE == 0 {
            return -EINVAL;
        }
        Some(new_addr)
    } else {
        None
    };
    match mm.lock().mremap(old, old_len, new_len, flags & MREMAP_MAYMOVE != 0, fixed_to) {
        Ok(a) => a as i64,
        Err(e) => e,
    }
}

/// Linux `madvise` (syscall 28): provides kernel advice regarding memory usage patterns.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `addr` - Starting virtual address.
/// * `len` - Length of memory range in bytes.
/// * `advice` - Advice code (`MADV_DONTNEED`, `MADV_FREE`, etc.).
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
pub fn sys_madvise(mm: &Mutex<Mm>, addr: u64, len: u64, advice: u64) -> i64 {
    // As Linux: the length rounds up to pages; a range that wraps is EINVAL, an empty one
    // does nothing, and one with unmapped parts (kernel addresses have no mappings at all)
    // is ENOMEM after the advice applies to the mapped parts.
    if addr & (PAGE_SIZE - 1) != 0 {
        return -EINVAL;
    }
    let Some(end) = len.checked_add(PAGE_SIZE - 1).map(|l| l & !(PAGE_SIZE - 1)).and_then(|l| addr.checked_add(l)) else {
        return -EINVAL;
    };
    if end == addr {
        return 0;
    }
    let mut m = mm.lock();
    if advice == MADV_DONTNEED || advice == MADV_FREE {
        m.discard(addr, end);
    }
    let mut cursor = addr;
    while cursor < end {
        match m.find_vma(cursor) {
            Some(v) => cursor = v.end,
            None => return -ENOMEM,
        }
    }
    0
}

/// Linux `msync` (syscall 26): writes the pages written through shared file mappings in
/// `[addr, addr + len)` back to their files. `MS_ASYNC` does it now too.
///
/// # Returns
///
/// `0`, `-EINVAL` for an unaligned address or bad flags, `-ENOMEM` if part of the range
/// is unmapped (after syncing the mapped parts), as Linux.
pub fn sys_msync(mm: &Mutex<Mm>, addr: u64, len: u64, flags: u64) -> i64 {
    const MS_ASYNC: u64 = 1;
    const MS_INVALIDATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    if addr & (PAGE_SIZE - 1) != 0 || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 || flags & (MS_ASYNC | MS_SYNC) == (MS_ASYNC | MS_SYNC) {
        return -EINVAL;
    }
    let Some(end) = len.checked_add(PAGE_SIZE - 1).map(|l| l & !(PAGE_SIZE - 1)).and_then(|l| addr.checked_add(l)) else {
        return -ENOMEM;
    };
    // The objects are collected first: writing back talks to the file server, which must
    // not happen under the address-space lock (its replies fault pages in)
    let mut objs: alloc::vec::Vec<Arc<dyn MappedObject>> = alloc::vec::Vec::new();
    let mut hole = false;
    {
        let m = mm.lock();
        let mut cursor = addr;
        while cursor < end {
            match m.find_vma(cursor) {
                Some(v) => {
                    if let (true, Backing::Object { obj, .. }) = (v.shared, &v.backing) {
                        if !objs.iter().any(|o| core::ptr::addr_eq(Arc::as_ptr(o), Arc::as_ptr(obj))) {
                            objs.push(obj.clone());
                        }
                    }
                    cursor = v.end;
                }
                None => {
                    hole = true;
                    // Skip to the next mapping
                    match m.next_vma_start(cursor) {
                        Some(n) if n < end => cursor = n,
                        _ => break,
                    }
                }
            }
        }
    }
    for o in objs {
        o.sync();
    }
    if hole { -ENOMEM } else { 0 }
}

/// `mincore`: reports every page of a mapped range as resident.
///
/// # Arguments
///
/// * `mm` - Task memory manager mutex.
/// * `addr` - Starting virtual address (must be page-aligned).
/// * `len` - Range length in bytes.
/// * `vec` - User pointer to output vector array.
///
/// # Returns
///
/// `0` on success, or a negative Linux errno on error.
pub fn sys_mincore(mm: &Mutex<Mm>, addr: u64, len: u64, vec: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return -EINVAL;
    }
    // Outside the user address space (Linux: ENOMEM); the sums below must not wrap
    if !crate::memory::vm::is_user_range(addr, len.max(1)) {
        return -ENOMEM;
    }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    {
        let guard = mm.lock();
        let mut cursor = addr;
        while cursor < addr + pages * PAGE_SIZE {
            match guard.find_vma(cursor) {
                Some(v) => cursor = v.end,
                None => return -ENOMEM,
            }
        }
    }
    if !crate::memory::vm::prefault_current(vec, pages, true) {
        return -14;
    }
    unsafe { core::ptr::write_bytes(vec as *mut u8, 1, pages as usize) };
    0
}
