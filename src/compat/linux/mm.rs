//! # Linux Memory-Management System Calls
//!
//! `mmap`, `munmap`, `mprotect`, `brk`, `mremap`, `madvise`, `msync` and `mincore` for
//! Linux processes that own a private address space ([`crate::memory::vm::Mm`]).
//! Tasks without one (legacy binaries linked into the kernel identity map) keep the
//! heap-backed fallbacks in [`super::dispatch_linux_syscall`].

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
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

/// Page-cache objects for mapped ZFS inodes, shared by every mapping of the same file.
/// Entries are weak so a file's cached pages are released once nothing maps it.
static INODE_OBJECTS: Mutex<BTreeMap<u64, Weak<InodeObject>>> = Mutex::new(BTreeMap::new());

/// A mapped ZFS file: pages are read from the pool on first fault and kept while mapped.
pub struct InodeObject {
    ino: u64,
    pages: Mutex<BTreeMap<u64, PhysFrame<Size4KiB>>>,
}

impl MappedObject for InodeObject {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        if let Some(&f) = self.pages.lock().get(&pgoff) {
            return Some(f);
        }
        let size = ZfsClient::getattr(self.ino).ok()?.size;
        if pgoff * PAGE_SIZE >= (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1) {
            return None;
        }
        let frame = alloc_user_frame()?;
        let buf = unsafe { core::slice::from_raw_parts_mut(crate::memory::frame_allocator::phys_to_virt(frame.start_address().as_u64()), PAGE_SIZE as usize) };
        if ZfsClient::read_at(self.ino, pgoff * PAGE_SIZE, buf).is_err() {
            frame_ref_dec(frame);
            return None;
        }
        let mut pages = self.pages.lock();
        if let Some(&existing) = pages.get(&pgoff) {
            frame_ref_dec(frame);
            return Some(existing);
        }
        pages.insert(pgoff, frame);
        Some(frame)
    }
}

impl Drop for InodeObject {
    fn drop(&mut self) {
        for (_, f) in self.pages.lock().iter() {
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
    let obj = Arc::new(InodeObject { ino, pages: Mutex::new(BTreeMap::new()) });
    map.retain(|_, w| w.strong_count() > 0);
    map.insert(ino, Arc::downgrade(&obj));
    obj
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
    Ok(crate::task::exec::ElfSource { head, len, obj: inode_object(ino) })
}

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
///
/// # Returns
///
/// * `Ok((obj, write_err))`: the object backing the descriptor, and what a shared mapping
///   of it gets for asking to write: 0 if it may (Linux's `VM_MAYWRITE`), `-EACCES` if the
///   descriptor was not opened for writing, `-EPERM` for a memfd sealed against writes.
/// * `Err(-EBADF)` if descriptor is invalid.
/// * `Err(-EACCES)` if descriptor is not readable.
/// * `Err(-ENODEV)` if underlying resource does not support memory mapping.
fn fd_object(fd: usize) -> Result<(Arc<dyn MappedObject>, i64), i64> {
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
            Ok((memfd, err))
        }
        crate::fs::FileDescriptor::Vnode(f) => {
            let (ino, readable, writable) = {
                let f = f.lock();
                (f.ino, f.readable(), f.writable())
            };
            if !readable {
                return Err(-EACCES);
            }
            Ok((inode_object(ino), if writable { 0 } else { -EACCES }))
        }
        crate::fs::FileDescriptor::File { path, readable, writable, .. } => {
            if !readable {
                return Err(-EACCES);
            }
            let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| -ENODEV)?;
            Ok((inode_object(ino), if writable { 0 } else { -EACCES }))
        }
        // A device's mmap_object decides for itself what may be mapped
        crate::fs::FileDescriptor::Device(d) => Ok((d.mmap_object()?, 0)),
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
        match fd_object(fd as usize) {
            Ok((obj, write_err)) => {
                // A shared mapping writes the file itself, so as Linux: only through a
                // descriptor that may write it, now (EACCES/EPERM) or after mprotect
                // (no VM_MAYWRITE). A private mapping writes its own copies.
                if shared && write_err != 0 {
                    if prot & crate::memory::vm::PROT_WRITE as u64 != 0 {
                        return write_err;
                    }
                    may_write = false;
                }
                Backing::Object { obj, pgoff: offset / PAGE_SIZE }
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
            if name.is_some() {
                m.set_name(a, a + len, name.as_deref());
            }
            if !may_write {
                m.deny_write(a, a + len);
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
