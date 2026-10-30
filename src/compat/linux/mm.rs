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

const EBADF: i64 = 9;
const ENOMEM: i64 = 12;
const EACCES: i64 = 13;
const EINVAL: i64 = 22;
const ENODEV: i64 = 19;

pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

pub const MREMAP_MAYMOVE: u64 = 1;
pub const MREMAP_FIXED: u64 = 2;

pub const MADV_DONTNEED: u64 = 4;
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
        let buf = unsafe { core::slice::from_raw_parts_mut(frame.start_address().as_u64() as *mut u8, PAGE_SIZE as usize) };
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

/// Returns the running task's address space, if it has one.
pub fn current_mm() -> Option<Arc<Mutex<Mm>>> {
    crate::task::with_current_task_mut(|t| t.mm.clone()).flatten()
}

/// Resolves the object behind a file descriptor for `mmap`.
fn fd_object(fd: usize) -> Result<Arc<dyn MappedObject>, i64> {
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd).cloned()).ok_or(-EBADF)?;
    match desc {
        crate::fs::FileDescriptor::MemFd(m) => Ok(m),
        crate::fs::FileDescriptor::Vnode(f) => {
            let (ino, readable) = {
                let f = f.lock();
                (f.ino, f.readable())
            };
            if !readable {
                return Err(-EACCES);
            }
            Ok(inode_object(ino))
        }
        crate::fs::FileDescriptor::File { path, readable, .. } => {
            if !readable {
                return Err(-EACCES);
            }
            let ino = ZfsClient::resolve(0, path.as_bytes(), true).map_err(|_| -ENODEV)?;
            Ok(inode_object(ino))
        }
        _ => Err(-ENODEV),
    }
}

pub fn sys_mmap(mm: &Mutex<Mm>, addr: u64, len: u64, prot: u64, flags: u64, fd: i64, offset: u64) -> i64 {
    if len == 0 || offset & (PAGE_SIZE - 1) != 0 {
        return -EINVAL;
    }
    let shared = match flags & MAP_SHARED_VALIDATE {
        MAP_SHARED | MAP_SHARED_VALIDATE => true,
        MAP_PRIVATE => false,
        _ => return -EINVAL,
    };
    let backing = if flags & MAP_ANONYMOUS != 0 {
        Backing::Anon
    } else {
        match fd_object(fd as usize) {
            Ok(obj) => Backing::Object { obj, pgoff: offset / PAGE_SIZE },
            Err(e) => return e,
        }
    };
    let fixed = flags & MAP_FIXED != 0;
    let noreplace = flags & MAP_FIXED_NOREPLACE != 0;
    match mm.lock().mmap(addr, len, prot as u32, shared, fixed, noreplace, backing) {
        Ok(a) => a as i64,
        Err(e) => e,
    }
}

pub fn sys_munmap(mm: &Mutex<Mm>, addr: u64, len: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 || len == 0 || !crate::memory::vm::is_user_range(addr, len) {
        return -EINVAL;
    }
    let end = (addr + len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    mm.lock().unmap(addr, end);
    0
}

pub fn sys_mprotect(mm: &Mutex<Mm>, addr: u64, len: u64, prot: u64) -> i64 {
    match mm.lock().mprotect(addr, len, prot as u32) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn sys_brk(mm: &Mutex<Mm>, new_brk: u64) -> i64 {
    mm.lock().set_brk(new_brk) as i64
}

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

pub fn sys_madvise(mm: &Mutex<Mm>, addr: u64, len: u64, advice: u64) -> i64 {
    if addr & (PAGE_SIZE - 1) != 0 {
        return -EINVAL;
    }
    if advice == MADV_DONTNEED || advice == MADV_FREE {
        mm.lock().discard(addr, addr + len);
    }
    0
}

/// `mincore`: reports every page of a mapped range as resident.
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
