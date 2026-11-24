//! # tmpfs data in memory (wave 9, Group M)
//!
//! A tmpfs tree is a hidden directory tree of the pool (wave 8 F): its names, modes and
//! owners stay there, so every walk (the kernel's, vfs-server's, the mount mirror) and every
//! call vfs-server hands back works as before. What this file adds is where the **data** of
//! a regular file in such a tree lives: in memory, never in the pool.
//!
//! - **Which files.** A regular file the kernel creates in a tmpfs mount (any mount
//!   namespace; the instance is the mount's tmpfs id) or directly in a `/dev/shm` directory
//!   ([`add_shm_dir`]; `shm_open` names have no `/`, and the initial namespace has no tmpfs
//!   mounts) gets a [`TmemFile`] ([`created`]). Its pool object stays empty.
//! - **The handle.** An open file of such an inode is the kernel's ordinary `Vnode` handle:
//!   `ZfsServer::{getattr, setattr, read, write}`, the page cache's `cached_read` and the
//!   `mmap`/exec paths find the inode here ([`get`]) and use the object, as FUSE inodes are
//!   sent to their daemon. So `read`/`write`/`pread`/`fstat`/`ftruncate` never leave the
//!   kernel, and `mmap` maps the object's own frames: every mapper and every `read`/`write`
//!   see the same pages.
//! - **Accounting** ([`Inst`]): each instance has a page limit (`size=`, default half of the
//!   memory) and a count; past it, or when free memory falls under a reserve (no swap), a
//!   write fails with `ENOSPC` and a mapping's fault with `SIGBUS` (the fault finds no page).
//! - **Lifetime.** A file lives while it has a name or an open descriptor ([`unlinked`],
//!   [`released`]); mappings keep their object (an `Arc`) after that. A tmpfs instance going
//!   away drops its files ([`drop_instance`]).
//! - **Restarts.** The table is the kernel's: a vfs-server restart (even the restart
//!   ladder's reset of its kept state) loses nothing; vfs-server asks for sizes and times
//!   with `LX_FH_TMEM` (see `lx::fileh`).
//! - **Limits** (no reverse map of mappings): a page cut by a truncation stays mapped by
//!   whoever mapped it (Linux: `SIGBUS`), as with memfd and the page cache; it stays counted
//!   against `size=` until unmapped ([`Inst`]'s held frames). `fallocate` sets the size
//!   without reserving pages; a `/dev/shm` file moved into a subdirectory gets `EXDEV`.
//! - **Switch back.** [`ENABLED`] is off with `lx=kernel`, `lx.vfs=kernel` or
//!   `lx.tmpfs=pool`: files are then created as before, with their data in the pool.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::fs::zfs::fsproto::Attr;
use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec, frame_refcount, phys_to_virt};
use crate::memory::vm::{MappedObject, PAGE_SIZE};

const ENOSPC: i64 = -28;
const EFBIG: i64 = -27;

/// The largest tmpfs file (Linux: `MAX_LFS_FILESIZE`; here 16 TiB keeps page numbers small).
pub const MAX_SIZE: u64 = 1 << 44;

/// The instance of the `/dev/shm` directories (not a tmpfs mount: no tmpfs id is 0).
pub const SHM_INST: u32 = 0;

/// Whether new files in tmpfs trees and `/dev/shm` keep their data here.
pub static ENABLED: AtomicBool = AtomicBool::new(false);

/// One tmpfs instance's accounting.
pub struct Inst {
    /// Its tmpfs id ([`SHM_INST`] for `/dev/shm`).
    pub id: u32,
    /// Most pages its files may hold.
    limit: AtomicU64,
    /// Pages its files hold.
    used: AtomicU64,
    /// Files it has.
    files: AtomicU64,
    /// Frames a truncation cut from its files while another mapping still mapped them:
    /// counted in `used` until the last mapping lets them go ([`Inst::reap`]), so mapping,
    /// truncating and growing again cannot hold more than `size=`.
    held: Mutex<Vec<PhysFrame<Size4KiB>>>,
}

impl Inst {
    /// Takes `n` pages of the instance's room; `false` if over the limit or memory is short.
    fn take(&self, n: u64) -> bool {
        let limit = self.limit.load(Ordering::Relaxed);
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            if cur + n > limit {
                return false;
            }
            match self.used.compare_exchange_weak(cur, cur + n, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }

    fn give(&self, n: u64) {
        let mut cur = self.used.load(Ordering::Relaxed);
        while let Err(c) = self.used.compare_exchange_weak(cur, cur.saturating_sub(n), Ordering::AcqRel, Ordering::Relaxed) {
            cur = c;
        }
    }

    /// Frees the held frames no mapping maps any more (only the instance's reference left).
    fn reap(&self) {
        let free: Vec<PhysFrame<Size4KiB>> = {
            let mut h = self.held.lock();
            let (free, keep): (Vec<_>, Vec<_>) = h.drain(..).partition(|&f| frame_refcount(f) <= 1);
            *h = keep;
            free
        };
        self.give(free.len() as u64);
        for f in free {
            frame_ref_dec(f);
        }
    }

    /// Frames cut from a file: freed now, or held while mapped elsewhere.
    fn cut(&self, frames: Vec<PhysFrame<Size4KiB>>) {
        let (mapped, free): (Vec<_>, Vec<_>) = frames.into_iter().partition(|&f| frame_refcount(f) > 1);
        self.held.lock().extend(mapped);
        self.give(free.len() as u64);
        for f in free {
            frame_ref_dec(f);
        }
    }

    /// `(limit, used)` in bytes.
    pub fn usage(&self) -> (u64, u64) {
        (self.limit.load(Ordering::Relaxed) * PAGE_SIZE, self.used.load(Ordering::Relaxed) * PAGE_SIZE)
    }
}

/// An in-memory regular file: its pages (sparse, as Linux's shmem), size and times.
pub struct TmemFile {
    /// The pool inode whose data this is.
    pub ino: u64,
    inst: Arc<Inst>,
    pages: Mutex<BTreeMap<u64, PhysFrame<Size4KiB>>>,
    size: AtomicU64,
    /// Data changes since the pool's times were last set (ns since the epoch; 0: none).
    mtime: AtomicU64,
    /// Writers and truncations one at a time (the size and the pages change together).
    io: Mutex<()>,
    /// No name left: goes at its last close.
    orphan: AtomicBool,
}

/// Free memory under which no page is given to tmpfs files: 1/64 of the memory, at least
/// 16 MiB (what programs need to go on; there is no swap to push tmpfs pages to).
fn memory_short() -> bool {
    let (free, total) = free_and_total();
    free < (total / 64).max(16 << 20)
}

/// `(free, total)` bytes of memory.
fn free_and_total() -> (u64, u64) {
    let fa = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
    (fa.free_memory(), fa.total_usable_memory())
}

fn now_ns() -> u64 {
    let (s, ns) = crate::arch::rtc::now();
    s.saturating_mul(1_000_000_000).saturating_add(ns as u64).max(1)
}

impl TmemFile {
    fn new(ino: u64, inst: Arc<Inst>) -> Self {
        inst.files.fetch_add(1, Ordering::Relaxed);
        Self { ino, inst, pages: Mutex::new(BTreeMap::new()), size: AtomicU64::new(0), mtime: AtomicU64::new(0), io: Mutex::new(()), orphan: AtomicBool::new(false) }
    }

    /// The file's size in bytes.
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// Pages it holds.
    pub fn resident(&self) -> u64 {
        self.pages.lock().len() as u64
    }

    /// The tmpfs instance it belongs to.
    pub fn inst(&self) -> u32 {
        self.inst.id
    }

    /// Its page `p`, made (zeroed, counted) if missing; `None`: no room.
    fn page(&self, p: u64) -> Option<PhysFrame<Size4KiB>> {
        if let Some(&f) = self.pages.lock().get(&p) {
            return Some(f);
        }
        // The reserve, page by page (no swap); frames held after truncations count against
        // the limit until their mappings go
        if memory_short() {
            return None;
        }
        if !self.inst.take(1) {
            self.inst.reap();
            if !self.inst.take(1) {
                return None;
            }
        }
        // (allocated outside the lock: a short memory makes the page cache give back files,
        // which asks the file server)
        let Some(f) = alloc_user_frame() else {
            self.inst.give(1);
            return None;
        };
        let mut pages = self.pages.lock();
        if let Some(&other) = pages.get(&p) {
            // Another CPU made it meanwhile
            drop(pages);
            self.inst.give(1);
            frame_ref_dec(f);
            return Some(other);
        }
        pages.insert(p, f);
        Some(f)
    }

    /// Reads at `offset` into `buf` (holes read as zeros); the bytes read.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let size = self.size();
        if offset >= size {
            return 0;
        }
        let total = (buf.len() as u64).min(size - offset) as usize;
        let mut done = 0;
        let pages = self.pages.lock();
        while done < total {
            let pos = offset + done as u64;
            let in_page = (pos % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - in_page).min(total - done);
            match pages.get(&(pos / PAGE_SIZE)) {
                // SAFETY: a frame of this file (it holds a reference), through the direct map
                Some(f) => unsafe { core::ptr::copy_nonoverlapping(phys_to_virt(f.start_address().as_u64()).add(in_page), buf[done..].as_mut_ptr(), n) },
                None => buf[done..done + n].fill(0),
            }
            done += n;
        }
        done
    }

    /// Writes `data` at `offset` (`None`: at the end, as `O_APPEND`); the bytes written, or
    /// `ENOSPC` if not one fitted.
    pub fn write(&self, offset: Option<u64>, data: &[u8]) -> Result<usize, i64> {
        let _io = self.io.lock();
        let offset = offset.unwrap_or_else(|| self.size());
        if offset >= MAX_SIZE {
            return Err(EFBIG);
        }
        let data = &data[..data.len().min((MAX_SIZE - offset) as usize)];
        let mut done = 0;
        while done < data.len() {
            let pos = offset + done as u64;
            let in_page = (pos % PAGE_SIZE) as usize;
            let n = (PAGE_SIZE as usize - in_page).min(data.len() - done);
            let Some(f) = self.page(pos / PAGE_SIZE) else { break };
            // SAFETY: as in `read`
            unsafe { core::ptr::copy_nonoverlapping(data[done..].as_ptr(), phys_to_virt(f.start_address().as_u64()).add(in_page), n) };
            done += n;
        }
        if done == 0 && !data.is_empty() {
            return Err(ENOSPC);
        }
        let end = offset + done as u64;
        if end > self.size() {
            self.size.store(end, Ordering::Release);
        }
        self.mtime.store(now_ns(), Ordering::Release);
        Ok(done)
    }

    /// Sets the size: pages past it go, the tail of the last page is zeroed.
    pub fn truncate(&self, size: u64) -> Result<(), i64> {
        if size > MAX_SIZE {
            return Err(EFBIG);
        }
        let _io = self.io.lock();
        let old = self.size();
        let gone: Vec<PhysFrame<Size4KiB>> = {
            let mut pages = self.pages.lock();
            // Growing: what a shared mapping wrote past the old end in its last page is not
            // file data (Linux zeroes it)
            if size > old && old % PAGE_SIZE != 0 {
                if let Some(f) = pages.get(&(old / PAGE_SIZE)) {
                    let k = (old % PAGE_SIZE) as usize;
                    // SAFETY: as in `read`
                    unsafe { core::ptr::write_bytes(phys_to_virt(f.start_address().as_u64()).add(k), 0, PAGE_SIZE as usize - k) };
                }
            }
            let keep = size.div_ceil(PAGE_SIZE);
            let gone: Vec<_> = pages.split_off(&keep).into_values().collect();
            if size % PAGE_SIZE != 0 {
                if let Some(f) = pages.get(&(size / PAGE_SIZE)) {
                    let k = (size % PAGE_SIZE) as usize;
                    // SAFETY: as in `read`
                    unsafe { core::ptr::write_bytes(phys_to_virt(f.start_address().as_u64()).add(k), 0, PAGE_SIZE as usize - k) };
                }
            }
            gone
        };
        // (a mapping that still maps a cut page keeps it, and it stays counted, until unmapped)
        let any_cut = !gone.is_empty(); // wave10 GV1
        self.inst.cut(gone);
        self.size.store(size, Ordering::Release);
        self.mtime.store(now_ns(), Ordering::Release);
        // wave10 GV1: mappings of the cut pages go (after the writers' lock: a fault holds
        // its address space's lock while it asks for a page)
        drop(_io);
        if size < old && any_cut {
            crate::compat::linux::mm::unmap_past(self.ino, size);
        }
        Ok(())
    }

    /// The pool's attributes with this file's size, blocks and data times.
    pub fn overlay(&self, a: &mut Attr) {
        a.size = self.size();
        a.blocks = self.resident() * (PAGE_SIZE / 512);
        let m = self.mtime.load(Ordering::Acquire);
        let t = ((m / 1_000_000_000) as i64, (m % 1_000_000_000) as u32);
        if m != 0 && t > a.mtime {
            a.mtime = t;
        }
        if m != 0 && t > a.ctime {
            a.ctime = t;
        }
    }

    /// The pool's times were set (`utimensat`): they are the file's again.
    pub fn times_set(&self) {
        self.mtime.store(0, Ordering::Release);
    }
}

impl Drop for Inst {
    fn drop(&mut self) {
        for f in core::mem::take(&mut *self.held.lock()) {
            frame_ref_dec(f);
        }
    }
}

impl Drop for TmemFile {
    fn drop(&mut self) {
        let pages = core::mem::take(&mut *self.pages.lock());
        self.inst.give(pages.len() as u64);
        self.inst.files.fetch_sub(1, Ordering::Relaxed);
        for f in pages.into_values() {
            frame_ref_dec(f);
        }
    }
}

impl MappedObject for TmemFile {
    fn inode(&self) -> Option<u64> {
        Some(self.ino) // wave10 GV1: a truncation unmaps the cut pages
    }

    /// A page inside the file (made if missing); `None` past its end or without room: the
    /// fault becomes `SIGBUS`, as on Linux.
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        if pgoff >= self.size().div_ceil(PAGE_SIZE) {
            return None;
        }
        self.page(pgoff)
    }
}

/// The files, by pool inode.
static FILES: Mutex<BTreeMap<u64, Arc<TmemFile>>> = Mutex::new(BTreeMap::new());
/// A quick "certainly not" for [`get`]: one bit per inode hash, set when a file is made.
static FILTER: [AtomicU64; 64] = [const { AtomicU64::new(0) }; 64];
/// The instances (made on first use, limit: [`default_limit`]).
static INSTS: Mutex<BTreeMap<u32, Arc<Inst>>> = Mutex::new(BTreeMap::new());
/// The `/dev/shm` directories (pool inodes).
static SHM_DIRS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn bit(ino: u64) -> (usize, u64) {
    let h = ino.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 52; // 12 bits
    ((h >> 6) as usize, 1u64 << (h & 63))
}

/// Linux's default tmpfs size: half of the memory.
fn default_limit() -> u64 {
    free_and_total().1 / 2 / PAGE_SIZE
}

fn inst(id: u32) -> Arc<Inst> {
    INSTS
        .lock()
        .entry(id)
        .or_insert_with(|| Arc::new(Inst { id, limit: AtomicU64::new(default_limit()), used: AtomicU64::new(0), files: AtomicU64::new(0), held: Mutex::new(Vec::new()) }))
        .clone()
}

/// The in-memory file of `ino`, if it is one.
#[inline]
pub fn get(ino: u64) -> Option<Arc<TmemFile>> {
    let (w, b) = bit(ino);
    if FILTER[w].load(Ordering::Relaxed) & b == 0 {
        return None;
    }
    FILES.lock().get(&ino).cloned()
}

/// Makes `ino` an in-memory file of instance `id` (an older entry of a reused inode goes).
pub fn make(ino: u64, id: u32) -> Arc<TmemFile> {
    let f = Arc::new(TmemFile::new(ino, inst(id)));
    let (w, b) = bit(ino);
    FILTER[w].fetch_or(b, Ordering::Relaxed);
    let old = FILES.lock().insert(ino, f.clone());
    drop(old);
    f
}

/// Forgets `ino` (its object goes with the last mapping).
pub fn forget(ino: u64) {
    let old = FILES.lock().remove(&ino);
    drop(old);
}

/// Whether `dir` is a `/dev/shm` directory.
pub fn shm_dir(dir: u64) -> bool {
    SHM_DIRS.lock().contains(&dir)
}

/// Registers a `/dev/shm` directory (at boot, by `devices.rs`).
pub fn add_shm_dir(dir: u64) {
    let mut d = SHM_DIRS.lock();
    if !d.contains(&dir) {
        d.push(dir);
    }
}

/// The kernel made regular file `ino` in directory `dir`; `tmpfs`: the tmpfs id of the mount
/// the lookup of `dir` ended in. Makes it an in-memory file when it belongs to one; any
/// older entry of the same (reused) inode number goes otherwise.
pub fn created(dir: u64, ino: u64, tmpfs: Option<u32>) {
    let id = match tmpfs {
        Some(t) if t != SHM_INST => Some(t),
        _ if shm_dir(dir) => Some(SHM_INST),
        _ => None,
    };
    match id {
        Some(id) if ENABLED.load(Ordering::Relaxed) => {
            make(ino, id);
        }
        _ => {
            if get(ino).is_some() {
                forget(ino);
            }
        }
    }
}

/// `ino` lost a name: `linked` = names left, `open` = descriptors left. Without names it
/// goes now, or at its last close.
pub fn unlinked(ino: u64, linked: bool, open: bool) {
    let Some(f) = get(ino) else { return };
    if linked {
        return;
    }
    if open {
        f.orphan.store(true, Ordering::Release);
    } else {
        forget(ino);
    }
}

/// The last descriptor of `ino` closed.
pub fn released(ino: u64) {
    if let Some(f) = get(ino) {
        if f.orphan.load(Ordering::Acquire) {
            forget(ino);
        }
    }
}

/// Whether a file of instance `inst` may get a name in directory `dir` (rename, link): a
/// `/dev/shm` file only in a `/dev/shm` directory (its data would not outlive the boot
/// elsewhere: `EXDEV`, as between two file systems). Files of tmpfs mounts are checked by
/// the mount layer (another mount is `EXDEV` already).
pub fn may_move(ino: u64, dir: u64) -> bool {
    match get(ino) {
        Some(f) if f.inst() == SHM_INST => shm_dir(dir),
        _ => true,
    }
}

/// Instance `id`'s tree is gone: its files go.
pub fn drop_instance(id: u32) {
    if id == SHM_INST {
        return;
    }
    let gone: Vec<Arc<TmemFile>> = {
        let mut files = FILES.lock();
        // (an open one lost its name with the tree: it goes at its last close)
        let keys: Vec<u64> = files.iter().filter(|(_, f)| f.inst() == id && !f.orphan.load(Ordering::Acquire)).map(|(&k, _)| k).collect();
        keys.into_iter().filter_map(|k| files.remove(&k)).collect()
    };
    drop(gone);
    INSTS.lock().remove(&id);
}

/// Sets instance `id`'s limit (`size=`, bytes; 0: the default).
pub fn set_limit(id: u32, bytes: u64) {
    let pages = if bytes == 0 { default_limit() } else { bytes.div_ceil(PAGE_SIZE) };
    inst(id).limit.store(pages, Ordering::Relaxed);
}

/// A limit as `LX_TMEM_LIMIT` gives it: bytes, or with bit 63 a percentage of the memory.
pub fn limit_bytes(v: u64) -> u64 {
    if v >> 63 != 0 {
        free_and_total().1 / 100 * (v & 0xFF).min(100)
    } else {
        v
    }
}

/// Instance `id`'s `(limit, used, files)` (bytes, bytes, count); `None`: no such instance.
pub fn usage(id: u32) -> Option<(u64, u64, u64)> {
    let i = INSTS.lock().get(&id).cloned()?;
    let (l, u) = i.usage();
    Some((l, u, i.files.load(Ordering::Relaxed)))
}

/// Total `(files, pages)` held.
pub fn totals() -> (u64, u64) {
    let files = FILES.lock();
    (files.len() as u64, files.values().map(|f| f.resident()).sum())
}

/// Parses `size=` of tmpfs mount data (`k`, `m`, `g` suffixes, or `%` of the memory);
/// `None` if absent or unreadable.
pub fn parse_size(data: &str) -> Option<u64> {
    let v = data.split(',').find_map(|o| o.strip_prefix("size="))?;
    let (num, mul) = match v.as_bytes().last()? {
        b'k' | b'K' => (&v[..v.len() - 1], 1u64 << 10),
        b'm' | b'M' => (&v[..v.len() - 1], 1 << 20),
        b'g' | b'G' => (&v[..v.len() - 1], 1 << 30),
        b'%' => {
            let pct: u64 = v[..v.len() - 1].parse().ok()?;
            return Some(free_and_total().1 / 100 * pct.min(100));
        }
        _ => (v, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mul)
}

/// `LX_FH_TMEM` sub-op `sub` (`LX_TMEM_*`) of the file service; `out` copies an answer to
/// its buffer (0 or an errno).
pub fn ctl(sub: u64, a: u64, b: u64, out: &dyn Fn(&[u8]) -> i64) -> i64 {
    use crate::ipc::protocol::{LxTmemAttr, LX_TMEM_ATTR, LX_TMEM_LIMIT, LX_TMEM_USAGE};
    const ENOENT: i64 = -2;
    const EINVAL: i64 = -22;
    match sub {
        LX_TMEM_ATTR => {
            let Some(t) = get(a) else { return ENOENT };
            let m = t.mtime.load(Ordering::Acquire);
            let r = LxTmemAttr { size: t.size(), blocks: t.resident() * (PAGE_SIZE / 512), mtime_ns: m, inst: t.inst() as u64 };
            // SAFETY: a plain `repr(C)` struct of integers
            out(unsafe { core::slice::from_raw_parts(&r as *const LxTmemAttr as *const u8, core::mem::size_of::<LxTmemAttr>()) })
        }
        LX_TMEM_LIMIT => match u32::try_from(a) {
            Ok(id) if id != SHM_INST => {
                set_limit(id, limit_bytes(b));
                0
            }
            _ => EINVAL,
        },
        LX_TMEM_USAGE => {
            let Some((l, u, f)) = u32::try_from(a).ok().and_then(usage) else { return ENOENT };
            let mut v = [0u8; 24];
            v[..8].copy_from_slice(&l.to_le_bytes());
            v[8..16].copy_from_slice(&u.to_le_bytes());
            v[16..].copy_from_slice(&f.to_le_bytes());
            out(&v)
        }
        _ => EINVAL,
    }
}
