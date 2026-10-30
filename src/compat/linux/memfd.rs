//! # Linux MemFd (Shared Memory File Descriptor) Subsystem
//!
//! Provides anonymous, resizable in-memory file descriptors (`memfd_create`)
//! supporting zero-copy shared memory mapping (`mmap`) for Wayland client buffer
//! pools (`wl_shm`).
//!
//! Contents live in reference-counted physical frames, one per page, allocated on first
//! use. A `MAP_SHARED` mapping maps those same frames into the process, so the client and
//! the in-kernel compositor see one copy of the pixels; resizing never moves existing pages.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec};
use crate::memory::vm::{MappedObject, PAGE_SIZE};

pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

/// In-kernel representation of an anonymous shared memory file descriptor.
pub struct MemFd {
    pub name: String,
    pages: Vec<Option<PhysFrame<Size4KiB>>>,
    size: usize,
    pub cursor: usize,
    pub seals: u32,
}

impl MemFd {
    /// Creates a new MemFd object wrapped in an Arc<Mutex>.
    pub fn new(name: &str) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            name: String::from(name),
            pages: Vec::new(),
            size: 0,
            cursor: 0,
            seals: 0,
        }))
    }

    /// Current size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Resizes the shared memory object (supporting `ftruncate`). Pages past the new end
    /// are released; mappings that still reference them keep their own frame references.
    pub fn truncate(&mut self, size: usize) {
        let page_count = (size + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
        if page_count < self.pages.len() {
            for frame in self.pages.drain(page_count..).flatten() {
                frame_ref_dec(frame);
            }
        } else {
            self.pages.resize(page_count, None);
        }
        // Zero the tail of a partially truncated last page
        if size < self.size && size % PAGE_SIZE as usize != 0 {
            if let Some(Some(frame)) = self.pages.last() {
                let off = size % PAGE_SIZE as usize;
                unsafe {
                    core::ptr::write_bytes(
                        (frame.start_address().as_u64() as *mut u8).add(off),
                        0,
                        PAGE_SIZE as usize - off,
                    );
                }
            }
        }
        self.size = size;
    }

    fn page(&mut self, index: usize) -> Option<PhysFrame<Size4KiB>> {
        let slot = self.pages.get_mut(index)?;
        if slot.is_none() {
            *slot = Some(alloc_user_frame()?);
        }
        *slot
    }

    /// Copies bytes starting at `offset` into `dst`, returning the count copied.
    pub fn read_at(&mut self, offset: usize, dst: &mut [u8]) -> usize {
        if offset >= self.size {
            return 0;
        }
        let total = dst.len().min(self.size - offset);
        let mut done = 0;
        while done < total {
            let pos = offset + done;
            let in_page = pos % PAGE_SIZE as usize;
            let n = (PAGE_SIZE as usize - in_page).min(total - done);
            match self.page(pos / PAGE_SIZE as usize) {
                Some(frame) => unsafe {
                    core::ptr::copy_nonoverlapping(
                        (frame.start_address().as_u64() as *const u8).add(in_page),
                        dst[done..].as_mut_ptr(),
                        n,
                    );
                },
                None => dst[done..done + n].fill(0),
            }
            done += n;
        }
        total
    }

    /// Copies `src` into the object at `offset`, growing it if needed.
    pub fn write_at(&mut self, offset: usize, src: &[u8]) -> usize {
        if offset + src.len() > self.size {
            self.truncate(offset + src.len());
        }
        let mut done = 0;
        while done < src.len() {
            let pos = offset + done;
            let in_page = pos % PAGE_SIZE as usize;
            let n = (PAGE_SIZE as usize - in_page).min(src.len() - done);
            match self.page(pos / PAGE_SIZE as usize) {
                Some(frame) => unsafe {
                    core::ptr::copy_nonoverlapping(
                        src[done..].as_ptr(),
                        (frame.start_address().as_u64() as *mut u8).add(in_page),
                        n,
                    );
                },
                None => break,
            }
            done += n;
        }
        done
    }

    /// Reads data from the shared memory buffer into `buf`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let n = self.read_at(self.cursor, buf);
        self.cursor += n;
        Ok(n)
    }

    /// Writes data into the shared memory buffer from `data`.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let n = self.write_at(self.cursor, data);
        self.cursor += n;
        Ok(n)
    }

    /// Returns the frames backing the first `length` bytes (allocating them), for mapping
    /// into tasks that share the kernel address space.
    pub fn frames_for(&mut self, length: usize) -> Option<Vec<PhysFrame<Size4KiB>>> {
        if self.size < length {
            self.truncate(length);
        }
        let count = (length + PAGE_SIZE as usize - 1) / PAGE_SIZE as usize;
        (0..count).map(|i| self.page(i)).collect()
    }
}

impl MappedObject for Mutex<MemFd> {
    fn get_page(&self, pgoff: u64) -> Option<PhysFrame<Size4KiB>> {
        self.lock().page(pgoff as usize)
    }
}

impl Drop for MemFd {
    fn drop(&mut self) {
        for frame in self.pages.drain(..).flatten() {
            frame_ref_dec(frame);
        }
    }
}
