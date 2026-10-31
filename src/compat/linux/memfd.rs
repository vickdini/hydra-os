//! # Linux Compatibility: MemFd (Shared Memory File Descriptor) Subsystem
//!
//! Provides anonymous, resizable in-memory file descriptors (`memfd_create`)
//! supporting zero-copy shared memory mapping (`mmap`) for Wayland client buffer
//! pools (`wl_shm`) and inter-process shared memory.
//!
//! ## Architectural Role & Design Rationale
//! Wayland clients render graphics into anonymous shared-memory buffers created via
//! `memfd_create(2)` and pass the descriptor over a `UNIX` domain socket (`SCM_RIGHTS`)
//! to the compositor. Contents live in reference-counted 4 KiB physical frames
//! ([`PhysFrame`]), allocated lazily on first access. A `MAP_SHARED` mapping maps those
//! exact physical frames into both processes, so the client and the in-kernel compositor
//! share a single zero-copy pixel buffer, and resizing via `ftruncate` never relocates
//! existing pages.
//!
//! ## Key Types & Interfaces
//! - [`MemFd`]: In-kernel representation of an anonymous shared memory file backed by physical frames.
//! - [`MFD_CLOEXEC`] / [`MFD_ALLOW_SEALING`]: Creation flags for `memfd_create(2)`.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Allocates and reference-counts 4 KiB physical frames via
//!   [`crate::memory::frame_allocator`].
//! - Concurrency: Protected by [`spin::Mutex`] and implements `MappedObject` for demand paging.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::memory::frame_allocator::{alloc_user_frame, frame_ref_dec};
use crate::memory::vm::{MappedObject, PAGE_SIZE};

/// `memfd_create` flag: set close-on-exec (`FD_CLOEXEC`) on the new file descriptor.
pub const MFD_CLOEXEC: u32 = 0x0001;
/// `memfd_create` flag: allow file sealing operations (`F_ADD_SEALS`) on this descriptor.
pub const MFD_ALLOW_SEALING: u32 = 0x0002;

/// In-kernel representation of an anonymous shared memory file descriptor (`memfd_create`).
///
/// # Concurrency & Thread Safety
/// Wrapped in `Arc<Mutex<MemFd>>` and shared across file descriptor tables and VM mappings
/// (`MappedObject`). Operations lock the mutex briefly to look up or allocate backing frames.
///
/// # Lifetime & Cleanup
/// When dropped, decrements the reference count of every allocated [`PhysFrame`] via
/// `frame_ref_dec`. Any active `mmap` regions retain their own frame references until unmapped.
pub struct MemFd {
    /// Diagnostic name passed to `memfd_create` (visible in `/proc/self/fd/`).
    pub name: String,
    /// Sparse array of 4 KiB physical frames backing each page offset of the file.
    pages: Vec<Option<PhysFrame<Size4KiB>>>,
    /// Logical file size in bytes (set by `ftruncate` or extending writes).
    size: usize,
    /// Current sequential read/write offset for legacy descriptor I/O.
    pub cursor: usize,
    /// Bitmask of active file seals (`F_SEAL_*`).
    pub seals: u32,
}

impl MemFd {
    /// Creates a new empty [`MemFd`] object wrapped in an `Arc<Mutex<Self>>`.
    ///
    /// # Arguments
    /// * `name` - Human-readable label for debugging (does not affect backing storage).
    ///
    /// # Returns
    /// A shared, spinlock-protected [`MemFd`] instance of size 0.
    pub fn new(name: &str) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            name: String::from(name),
            pages: Vec::new(),
            size: 0,
            cursor: 0,
            seals: 0,
        }))
    }

    /// Returns the current logical size of the shared memory object in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Resizes the shared memory object (`ftruncate(2)`).
    ///
    /// Pages past the new end are released via `frame_ref_dec`; active memory mappings
    /// that still map those frames retain their own frame references. If the size shrinks
    /// to a non-page-aligned boundary, the tail of the new last page is zeroed.
    ///
    /// # Arguments
    /// * `size` - New logical length of the memory object in bytes.
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

    /// Returns the physical frame for page `index`, lazily allocating a zeroed user frame on first access.
    fn page(&mut self, index: usize) -> Option<PhysFrame<Size4KiB>> {
        let slot = self.pages.get_mut(index)?;
        if slot.is_none() {
            *slot = Some(alloc_user_frame()?);
        }
        *slot
    }

    /// Copies bytes starting at byte `offset` into `dst` without modifying `self.cursor`.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset within the `memfd`.
    /// * `dst` - Destination buffer slice.
    ///
    /// # Returns
    /// Number of bytes copied into `dst` (`0` if `offset >= self.size`).
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

    /// Copies `src` into the shared memory object at byte `offset`, growing `self.size` if needed.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset within the `memfd`.
    /// * `src` - Source byte slice to write.
    ///
    /// # Returns
    /// Number of bytes written from `src`.
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

    /// Reads data sequentially from `self.cursor` into `buf` and advances the cursor.
    ///
    /// # Arguments
    /// * `buf` - Destination slice to read into.
    ///
    /// # Returns
    /// `Ok(n)` with the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let n = self.read_at(self.cursor, buf);
        self.cursor += n;
        Ok(n)
    }

    /// Writes data sequentially at `self.cursor` from `data` and advances the cursor.
    ///
    /// # Arguments
    /// * `data` - Source slice to write into the buffer.
    ///
    /// # Returns
    /// `Ok(n)` with the number of bytes written.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let n = self.write_at(self.cursor, data);
        self.cursor += n;
        Ok(n)
    }

    /// Returns the physical frames backing the first `length` bytes (allocating them if needed),
    /// used when mapping the `memfd` into tasks that share the kernel address space.
    ///
    /// # Arguments
    /// * `length` - Minimum byte length to cover with physical frames.
    ///
    /// # Returns
    /// `Some(Vec<PhysFrame>)` on success, or `None` if physical frame allocation fails.
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

